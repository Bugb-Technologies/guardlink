/**
 * GuardLink Blame — orchestration: model records → git history → attribution.
 *
 * Runs AFTER the model is assembled and never inside `parseProject`: the MCP
 * server and the TUI parse on every call, and git history is far more
 * expensive than a parse. `computeBlame` returns a side map keyed by record
 * and leaves the model untouched — the long-lived surfaces cache one model
 * per process, and a mutating call would leak `blame` into the next
 * `guardlink_parse`. Only `attachBlame` (CLI `--blame`) writes it back.
 *
 * Two lines are blamed per record, and they are different lines:
 *   - the SITE — the annotation line itself — answers "who declared this";
 *     for a sidecar `.gal` claim that is `origin_file:origin_line`, because
 *     `location.line` there is the `@source line:N` code line;
 *   - the SPAN — the anchor beneath the annotation — answers "who wrote the
 *     code", via the span's line history (`git log -L`), or the commit that
 *     added the file when the anchor is file-wide.
 *
 * Every degradation is per record and explicit in `status`; nothing here throws
 * for one bad file, because one pathological file must not take down `blame`
 * for the whole repository.
 *
 * @exposes #blame to #path-traversal [low] cwe:CWE-22 -- "Record locations name the files handed to git, and a sidecar @source path is author-supplied text that survives normalisation with ../ intact"
 * @mitigates #blame against #path-traversal using #path-validation -- "safeRelPath resolves each path against root and keeps it only when it is root or lies under root + sep; anything else yields status error and git never sees it"
 * @exposes #blame to #dos [low] cwe:CWE-400 -- "One blame per annotated file and one -L walk per distinct symbol span"
 * @mitigates #blame against #dos using #resource-limits -- "Files are blamed once and memoised; -L is memoised per span and skipped for dirty files and file-wide anchors; commits resolve in one batched log call"
 * @flows ThreatModel -> #blame via computeBlame -- "Record locations and anchors"
 * @flows #blame -> ThreatModel via attachBlame -- "record.blame, only on the CLI --blame paths"
 * @handles pii on #blame -- "Author identities attached to each record"
 * @comment -- "Opt-in and non-mutating by default: computeBlame returns a Map; the model is byte-identical afterwards. Attribution of an AI is only ever what a commit declared"
 */
import { existsSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import type {
  SourceLocation, ThreatModel, ThreatModelConfirmed, ThreatModelExposure, ThreatModelMitigation,
} from '../types/index.js';
import { buildCoverageIndex } from '../parser/coverage.js';
import { compileRules, readBlameConfig } from './config.js';
import { attributeCommit } from './trailers.js';
import {
  ZERO_SHA, blameFile, dirtyFiles, fileAddCommit, gitExec, headSha, isGitRepo, isShallow,
  resolveCommits, spanOldestCommit, trackedFiles, type GitExec,
} from './git.js';
import type {
  BlameComputation, BlameConfig, BlameGranularity, BlameStatus, CommitRef, Contributor,
  ExposureBlame, IntroducedBy, IntroducedMethod, MitigationBlame, RecordBlame,
} from './types.js';

export interface ComputeBlameOptions {
  config?: BlameConfig;
  /** Root-relative path: compute only records declared in, or anchored to, this file. */
  file?: string;
  exec?: GitExec;
}

type ExposureLike = ThreatModelExposure | ThreatModelConfirmed;

const DAY_MS = 86_400_000;

const norm = (p: string): string => p.replaceAll('\\', '/').replace(/^\.\//, '');

/** The path with `/` separators when it stays inside root; null otherwise. */
export function safeRelPath(root: string, file: string): string | null {
  const base = resolve(root);
  const abs = resolve(root, file);
  if (abs !== base && !abs.startsWith(base + sep)) return null;
  return norm(file);
}

// ── one warning per file per process, as structure/attach.ts does ──
const warned = new Set<string>();
function warnOnce(key: string, file: string, err: unknown): void {
  if (warned.has(key)) return;
  warned.add(key);
  const message = err instanceof Error ? err.message : String(err);
  console.error(`⚠ GuardLink: could not blame ${file}: ${message}. Its claims read as unattributed.`);
}

type FileState = 'ok' | 'missing' | 'untracked' | 'error';

/** Per-file git facts for one run: tracked/dirty in two batched calls, blame once per file. */
class FileIndex {
  private readonly tracked: Set<string>;
  private readonly dirty: Set<string>;
  private readonly blames = new Map<string, Map<number, string> | null>();
  private readonly errors = new Map<string, string>();
  private readonly spans = new Map<string, string | null>();
  private readonly adds = new Map<string, string | null>();

  constructor(
    private readonly root: string,
    files: string[],
    private readonly exec: GitExec,
    private readonly ignoreRevs: string | null,
  ) {
    this.tracked = trackedFiles(root, files, exec);
    this.dirty = dirtyFiles(root, files, exec);
  }

  state(file: string): FileState {
    if (this.errors.has(file)) return 'error';
    if (!existsSync(join(this.root, file))) return 'missing';
    if (!this.tracked.has(file)) return 'untracked';
    return this.blame(file) ? 'ok' : 'error';
  }

  error(file: string): string | undefined {
    return this.errors.get(file);
  }

  isDirty(file: string): boolean {
    return this.dirty.has(file);
  }

  /** Line → sha for the whole working file; null when git could not blame it. */
  blame(file: string): Map<number, string> | null {
    if (this.blames.has(file)) return this.blames.get(file)!;
    let result: Map<number, string> | null = null;
    try {
      result = new Map(blameFile(this.root, file, this.ignoreRevs, this.exec).map(l => [l.line, l.sha]));
    } catch (err) {
      this.errors.set(file, err instanceof Error ? err.message : String(err));
      warnOnce(join(this.root, file), file, err);
    }
    this.blames.set(file, result);
    return result;
  }

  spanOldest(file: string, start: number, end: number): string | null {
    const key = `${file}:${start}-${end}`;
    if (!this.spans.has(key)) this.spans.set(key, spanOldestCommit(this.root, file, start, end, this.exec));
    return this.spans.get(key)!;
  }

  fileAdd(file: string): string | null {
    if (!this.adds.has(file)) this.adds.set(file, fileAddCommit(this.root, file, this.exec));
    return this.adds.get(file)!;
  }
}

interface Site { file: string | null; line: number }
interface Span { file: string | null; start: number; end: number; scope: 'symbol' | 'block' | 'file' }

function siteOf(root: string, loc: SourceLocation): Site {
  const file = loc.origin_file ?? loc.file;
  return { file: safeRelPath(root, file), line: loc.origin_line ?? loc.line };
}

function spanOf(root: string, loc: SourceLocation): Span | null {
  const a = loc.anchor;
  if (!a) return null;
  return { file: safeRelPath(root, loc.file), start: a.start_line, end: a.end_line, scope: a.scope };
}

interface Draft {
  granularity: BlameGranularity;
  status: BlameStatus;
  error?: string;
  /** Sha of the annotation line. */
  siteSha: string | null;
  /** Committed line owners over the span, with line counts. */
  contributors: Map<string, number>;
  /** Introduction found precisely, or the candidates for the blame fallback. */
  introduced: { sha: string; method: IntroducedMethod; lowerBound: boolean } | null;
  introducedCandidates: string[];
}

function newDraft(granularity: BlameGranularity): Draft {
  return { granularity, status: 'ok', siteSha: null, contributors: new Map(), introduced: null, introducedCandidates: [] };
}

/** Worst status wins; `ok` is only reached when nothing degraded. */
function degrade(d: Draft, state: FileState, files: FileIndex, file: string): void {
  if (state === 'missing') d.status = 'file-missing';
  else if (state === 'untracked') d.status = 'uncommitted';
  else if (state === 'error') { d.status = 'error'; d.error = files.error(file); }
}

/**
 * Blame the site line and the span for one record. `wantIntroduced` is false
 * for mitigations, which have no "introduced" question to answer.
 */
function draftRecord(root: string, loc: SourceLocation, files: FileIndex, shallow: boolean, wantIntroduced: boolean): Draft {
  const site = siteOf(root, loc);
  const span = spanOf(root, loc);
  const d = newDraft(span?.scope ?? 'none');

  if (!site.file) {
    d.status = 'error';
    d.error = 'annotation path escapes the project root';
    return d;
  }
  const siteState = files.state(site.file);
  if (siteState !== 'ok') {
    degrade(d, siteState, files, site.file);
    return d;
  }
  const siteSha = files.blame(site.file)!.get(site.line) ?? null;
  if (siteSha === ZERO_SHA) d.status = 'uncommitted';
  else d.siteSha = siteSha;

  if (!span || !span.file) {
    if (d.status === 'ok') d.status = 'no-anchor';
    return d;
  }
  const spanState = files.state(span.file);
  if (spanState !== 'ok') {
    degrade(d, spanState, files, span.file);
    return d;
  }
  const spanBlame = files.blame(span.file)!;
  for (let line = span.start; line <= span.end; line++) {
    const sha = spanBlame.get(line);
    if (!sha) continue;
    if (sha === ZERO_SHA) { d.status = 'uncommitted'; continue; }
    d.contributors.set(sha, (d.contributors.get(sha) ?? 0) + 1);
  }

  if (wantIntroduced) {
    if (span.scope === 'file') {
      const sha = files.fileAdd(span.file);
      if (sha) d.introduced = { sha, method: 'file-add', lowerBound: shallow };
    } else if (!files.isDirty(span.file)) {
      // -L resolves line numbers against HEAD; only a clean file's anchor lines are HEAD's.
      const sha = files.spanOldest(span.file, span.start, span.end);
      if (sha) d.introduced = { sha, method: 'log-L', lowerBound: shallow };
      else d.introducedCandidates = [...d.contributors.keys()];
    } else {
      d.introducedCandidates = [...d.contributors.keys()];
    }
  }

  if (d.status === 'ok' && shallow) d.status = 'shallow';
  return d;
}

function emptyExposure(status: BlameStatus, granularity: BlameGranularity): ExposureBlame {
  return { kind: 'exposure', status, granularity, introduced_by: null, found_by: null, contributors: [], fixed_by: null, time_to_fix_days: null };
}

function emptyMitigation(status: BlameStatus, granularity: BlameGranularity): MitigationBlame {
  return { kind: 'mitigation', status, granularity, declared_by: null, contributors: [] };
}

function granularityOf(loc: SourceLocation): BlameGranularity {
  return loc.anchor?.scope ?? 'none';
}

const earliest = (refs: CommitRef[]): CommitRef | null =>
  refs.length === 0 ? null : refs.reduce((a, b) => (Date.parse(b.date) < Date.parse(a.date) ? b : a));

export function computeBlame(root: string, model: ThreatModel, opts: ComputeBlameOptions = {}): BlameComputation {
  const exec = opts.exec ?? gitExec;
  const config = opts.config ?? readBlameConfig(root);
  const rules = compileRules(config.tools);
  const mode = config.identity;
  const byRecord = new Map<object, RecordBlame>();

  const only = opts.file ? norm(opts.file) : null;
  const wanted = (loc: SourceLocation): boolean =>
    only === null || norm(loc.file) === only || (!!loc.origin_file && norm(loc.origin_file) === only);
  const exposures: ExposureLike[] = [...model.exposures, ...(model.confirmed ?? [])].filter(r => wanted(r.location));
  const mitigations: ThreatModelMitigation[] = model.mitigations.filter(r => wanted(r.location));

  if (!isGitRepo(root, exec)) {
    for (const r of exposures) byRecord.set(r, emptyExposure('no-git', granularityOf(r.location)));
    for (const r of mitigations) byRecord.set(r, emptyMitigation('no-git', granularityOf(r.location)));
    return { status: 'no-git', head: null, identity_mode: mode, byRecord };
  }

  const shallow = isShallow(root, exec);
  const head = headSha(root, exec);
  const coverage = buildCoverageIndex(model);

  // A covering mitigation may live outside the requested file; it is still the fix.
  const coveringOf = new Map<ExposureLike, ThreatModelMitigation[]>();
  for (const e of exposures) coveringOf.set(e, coverage.mitigationsFor(e));
  const mitigationSet = new Set<ThreatModelMitigation>(mitigations);
  for (const list of coveringOf.values()) for (const m of list) mitigationSet.add(m);

  const files = new Set<string>();
  const collect = (loc: SourceLocation): void => {
    const site = siteOf(root, loc);
    const span = spanOf(root, loc);
    if (site.file) files.add(site.file);
    if (span?.file) files.add(span.file);
  };
  for (const r of exposures) collect(r.location);
  for (const m of mitigationSet) collect(m.location);
  const index = new FileIndex(root, [...files], exec, config.ignore_revs);

  // Pass 1: shas only.
  const exposureDrafts = new Map<ExposureLike, Draft>();
  for (const r of exposures) exposureDrafts.set(r, draftRecord(root, r.location, index, shallow, true));
  const mitigationDrafts = new Map<ThreatModelMitigation, Draft>();
  for (const m of mitigationSet) mitigationDrafts.set(m, draftRecord(root, m.location, index, shallow, false));

  // Pass 2: one batched resolution, then attribution.
  const shas = new Set<string>();
  for (const d of [...exposureDrafts.values(), ...mitigationDrafts.values()]) {
    if (d.siteSha) shas.add(d.siteSha);
    if (d.introduced) shas.add(d.introduced.sha);
    for (const s of d.introducedCandidates) shas.add(s);
    for (const s of d.contributors.keys()) shas.add(s);
  }
  const refs = new Map<string, CommitRef>();
  for (const [sha, raw] of resolveCommits(root, [...shas], exec)) refs.set(sha, attributeCommit(raw, rules, mode));
  const ref = (sha: string | null): CommitRef | null => (sha ? refs.get(sha) ?? null : null);

  const contributorsOf = (d: Draft): Contributor[] =>
    [...d.contributors]
      .flatMap(([sha, lines]) => { const r = ref(sha); return r ? [{ ...r, lines }] : []; })
      .sort((a, b) => b.lines - a.lines || (a.sha < b.sha ? -1 : a.sha > b.sha ? 1 : 0));

  const introducedOf = (d: Draft): IntroducedBy | null => {
    if (d.introduced) {
      const r = ref(d.introduced.sha);
      if (!r) return null;
      return { ...r, method: d.introduced.method, ...(d.introduced.lowerBound ? { lower_bound: true as const } : {}) };
    }
    const first = earliest(d.introducedCandidates.flatMap(s => { const r = ref(s); return r ? [r] : []; }));
    return first ? { ...first, method: 'blame', lower_bound: true } : null;
  };

  const declaredOf = (m: ThreatModelMitigation): CommitRef | null => ref(mitigationDrafts.get(m)?.siteSha ?? null);

  for (const [m, d] of mitigationDrafts) {
    if (!mitigationSet.has(m) || !mitigations.includes(m)) continue;
    byRecord.set(m, { kind: 'mitigation', status: d.status, granularity: d.granularity, declared_by: declaredOf(m), contributors: contributorsOf(d), ...(d.error ? { error: d.error } : {}) });
  }

  for (const [e, d] of exposureDrafts) {
    const introduced_by = introducedOf(d);
    const fixed_by = earliest((coveringOf.get(e) ?? []).flatMap(m => { const r = declaredOf(m); return r ? [r] : []; }));
    let time_to_fix_days: number | null = null;
    let clamped = false;
    if (introduced_by && fixed_by) {
      const diff = (Date.parse(fixed_by.date) - Date.parse(introduced_by.date)) / DAY_MS;
      clamped = diff < 0;
      time_to_fix_days = clamped ? 0 : Math.round(diff * 10) / 10;
    }
    byRecord.set(e, {
      kind: 'exposure',
      status: d.status,
      granularity: d.granularity,
      introduced_by,
      found_by: ref(d.siteSha),
      contributors: contributorsOf(d),
      fixed_by,
      time_to_fix_days,
      ...(clamped ? { fixed_before_introduced: true as const } : {}),
      ...(d.error ? { error: d.error } : {}),
    });
  }

  return { status: shallow ? 'shallow' : 'ok', head, identity_mode: mode, byRecord };
}
