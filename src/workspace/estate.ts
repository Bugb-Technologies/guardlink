/**
 * GuardLink Workspace — `guardlink estate`, the read side of `merge` (mark 20).
 *
 * `guardlink merge` has always WRITTEN the combined model — a `--json` file and
 * an HTML dashboard — and nothing in the product ever read one back. The estate
 * answer existed on disk and had no command. So the question a platform team
 * actually asks, *what is open across all of our repositories*, was answerable
 * only by opening a dashboard in a browser or by reading JSON by hand.
 *
 * This module is that read path. It takes the file `merge` already produces and
 * answers three questions about it:
 *
 *   what is open, and in which repository
 *   what was REPRODUCED (`@confirmed`), which no acceptance ever silences
 *   how much of the estate this answer actually covers
 *
 * ── The third question is not optional ──────────────────────────────
 *
 * A merged report knows how many repos it was asked for and how many it read.
 * An estate view that prints "0 open" over a report that loaded 0 of 4 repos is
 * the vacuous green one level up, and it is reachable here by the same two
 * routes it is reachable in `merge`: an unexpanded glob, and a repo whose
 * pipeline never uploaded a report. So `read_nothing` and `partial` are fields
 * on the summary, they are the first thing the text output says, and under
 * `--strict` an estate that read nothing exits 1 rather than reporting clean.
 *
 * That check lives here and not only behind `guardlink merge --strict` (#39,
 * now on `main`): this command needs to be honest about coverage on its own,
 * because `estate` reads a file rather than producing one and may be pointed at
 * a merged report some other run wrote, under flags nobody here chose.
 *
 * ── Coverage is the merge engine's answer, not a second opinion ─────
 *
 * `openExposuresIn` is the same function `computeTotals` calls, with the same
 * owner scope, rebuilt from the `tag_registry` the report carries. A merged
 * JSON and a reader of it that disagreed about what is open would be exactly
 * the defect D36 was written to end.
 *
 * ── "Unknown" is a third state, and it is not "clean" ──────────────
 *
 * #39 gave a merged report the parse state behind each member repo, because a
 * repository can drop its `@mitigates` lines to a parse error and still report
 * zero unmitigated: the annotations that would have been counted were never
 * read, so every number looks healthier for their absence. It then split three
 * ways — a repo that reported its parse contributes its counts, a repo whose
 * report predates the field contributes to NEITHER side, and errors gate while
 * warnings do not.
 *
 * All of that was decided in `mergeVerdict`, one surface away. This module is a
 * SECOND reader of the same `repo_statuses`, and the surface a platform team
 * actually opens, so a fix that lived only in the writer would have left the
 * defect fully intact in the place it gets read. The three states are therefore
 * re-made here against the same fields, to the same split, rather than inferred
 * or assumed clean — and a repo that cannot say is marked `?`, never `✓`.
 *
 * @asset Workspace.Estate (#estate-view) -- "Estate-wide open-risk read-back over a merged report"
 * @exposes #estate-view to #vacuous-pass [high] cwe:CWE-754 -- "Ticked a repository green on open/confirmed counts alone, so a repo whose parse errored — its @mitigates lines never read — and a repo whose report cannot say either way both rendered as a clean bill of health"
 * @mitigates #estate-view against #vacuous-pass using #fail-closed -- "Per-repo parse errors and unknown parse state are read from repo_statuses and rendered as themselves; parse errors exit 1 under --strict, matching mergeVerdict's split over the same fields"
 * @flows RepoParseState -> #estate-view via estateReport -- "Each member repo's parse errors, warnings and unread annotation lines, carried from the merged report onto the estate answer"
 * @flows MergedReportFile -> #estate-view via readMergedReport -- "The JSON `guardlink merge --json` wrote, read back"
 * @flows #estate-view -> #cli via estateReport -- "Open exposures, reproduced exploits, and how much of the estate was actually read"
 * @exposes #estate-view to #insecure-deser [medium] cwe:CWE-502 -- "Parses a merged report JSON supplied by path, which may come from another team's pipeline artifact"
 * @mitigates #estate-view against #insecure-deser using #config-validation -- "readMergedReport refuses any payload missing the merged-report shape rather than answering from a partial parse"
 * @comment -- "A report written before tag_registry carried also_defined_in scopes to nothing and answers exactly as the build that wrote it did — stated rather than silently assumed"
 */

import { readFile } from 'node:fs/promises';
import type {
  ThreatModelConfirmed, ThreatModelExposure, Severity,
} from '../types/index.js';
import type { MergedReport, MergeWarning, RepoStatus } from './types.js';
import type { ReportParseState } from '../types/index.js';
import { openExposuresIn } from './merge.js';
import { buildOwnerScope, repoOfPath } from './owner-scope.js';
import { canonicaliser } from '../parser/canonical-ref.js';

/** Schema identifier carried by every `--format json` payload. */
export const ESTATE_SCHEMA = 'guardlink.estate/v1';

const SEVERITY_ORDER: Record<Severity | 'unset', number> = {
  critical: 0, high: 1, medium: 2, low: 3, unset: 4,
};

export type EstateSeverityCounts = Record<Severity | 'unset', number>;

/** One open finding, placed in the repository it was written in. */
export interface EstateFinding {
  /** The repo the record came from, read off the combined path prefix. Null when unplaceable. */
  repo: string | null;
  asset: string;
  threat: string;
  severity: Severity | 'unset';
  file: string;
  line: number;
  description?: string;
  external_refs: string[];
}

export interface EstateRepoLine {
  name: string;
  loaded: boolean;
  error?: string;
  commit_sha?: string;
  generated_at?: string;
  /** Open exposures placed in this repo. 0 for a repo that did not load — see `loaded`. */
  open: number;
  confirmed: number;
  /**
   * What this repo's parse could not read, if its report said.
   *
   * Undefined on a loaded repo means the report predates the field: unknown,
   * which is NOT zero and NOT clean. `estate` is a second reader of the same
   * `repo_statuses` `merge` gates on, so it owes the same three states —
   * otherwise a repository that silently dropped its `@mitigates` lines gets a
   * green tick here after `merge --strict` refused to give it one.
   */
  parse?: ReportParseState;
}

export interface EstateSummary {
  workspace: string;
  merged_at: string;
  repos: number;
  repos_loaded: number;
  exposures: number;
  /** Unmitigated, unaccepted exposures across the estate, owner-scoped. */
  open: number;
  confirmed: number;
  acceptances: number;
  mitigations: number;
  /** True when not one repo's report was read. The answer below covers nothing. */
  read_nothing: boolean;
  /** True when at least one repo was expected and not read. The answer is partial. */
  partial: boolean;
  /** Whether the merged report carried the ownership needed to scope the join (mark 8). */
  owner_scoped: boolean;
  /**
   * Annotation lines the loaded repos' parses could not read, summed over the
   * repositories that SAID. `repos_parse_unknown` is the rest; the two are
   * deliberately separate, because absence is not zero.
   */
  unparsed_annotations: number;
  /** Parse ERRORS across the repositories that reported their parse. */
  parse_errors: number;
  /** Loaded repositories whose report carries no parse state at all. */
  repos_parse_unknown: number;
  strict: boolean;
  exit_code: 0 | 1;
}

export interface EstateReport {
  schema: typeof ESTATE_SCHEMA;
  /** Open exposures, worst severity first, then by repo and path. */
  open: EstateFinding[];
  /** Reproduced exploits. Not filtered by acceptance anywhere in the product. */
  confirmed: EstateFinding[];
  repos: EstateRepoLine[];
  by_severity: EstateSeverityCounts;
  by_repo: Record<string, number>;
  /** The merge's own warnings, carried through — including the owner-scoping one. */
  warnings: MergeWarning[];
  summary: EstateSummary;
}

export interface EstateOptions {
  /** Report only findings at these severities. Unrated findings always count. */
  severity?: Severity[];
  /** Report only findings from these repos. */
  repo?: string[];
  /** Exit 1 when anything is open, anything is confirmed, or the estate was not fully read. */
  strict?: boolean;
}

// ─── Reading the file merge wrote ────────────────────────────────────

export class NotAMergedReport extends Error {
  constructor(path: string, why: string) {
    super(`${path} is not a merged report: ${why}. `
      + 'Produce one with `guardlink merge <reports...> --json <file>`.');
    this.name = 'NotAMergedReport';
  }
}

/**
 * Read a merged report from disk, refusing anything that is not one.
 *
 * The failure this guards is specific: a per-repo `threat-model.json` and a
 * merged report are both JSON with a `model`-shaped body, and pointed at the
 * wrong one a lenient reader would answer "0 repos, 0 open" — a clean estate
 * assembled out of a file that describes one repository. So the four fields
 * that only a merge produces are required, and a file missing any of them is
 * refused by name rather than summarised.
 */
export async function readMergedReport(path: string): Promise<MergedReport> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    throw new NotAMergedReport(path, err instanceof Error ? err.message : String(err));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new NotAMergedReport(path, `invalid JSON (${err instanceof Error ? err.message : err})`);
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new NotAMergedReport(path, 'top level is not an object');
  }
  const r = parsed as Partial<MergedReport>;
  const missing = (['repo_statuses', 'tag_registry', 'totals', 'model'] as const)
    .filter(k => r[k] === undefined || r[k] === null);
  if (missing.length > 0) {
    throw new NotAMergedReport(path, `missing ${missing.join(', ')}`);
  }
  if (!Array.isArray(r.repo_statuses) || !Array.isArray(r.tag_registry)) {
    throw new NotAMergedReport(path, 'repo_statuses and tag_registry must be arrays');
  }
  if (!Array.isArray(r.model?.exposures)) {
    throw new NotAMergedReport(path, 'model.exposures is missing');
  }

  return {
    workspace: r.workspace ?? 'workspace',
    merged_at: r.merged_at ?? '',
    schema_version: r.schema_version ?? '',
    repo_statuses: r.repo_statuses as RepoStatus[],
    tag_registry: r.tag_registry,
    unresolved_refs: r.unresolved_refs ?? [],
    warnings: r.warnings ?? [],
    totals: r.totals!,
    model: r.model!,
  };
}

// ─── The answer ──────────────────────────────────────────────────────

function toFinding(
  rec: ThreatModelExposure | ThreatModelConfirmed,
  repoNames: ReadonlySet<string>,
): EstateFinding {
  return {
    repo: repoOfPath(rec.location?.file, repoNames),
    asset: rec.asset,
    threat: rec.threat,
    severity: rec.severity ?? 'unset',
    file: rec.location?.file ?? '',
    line: rec.location?.line ?? 0,
    description: rec.description,
    external_refs: rec.external_refs ?? [],
  };
}

function bySeverityThenPath(a: EstateFinding, b: EstateFinding): number {
  return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    || (a.repo ?? '').localeCompare(b.repo ?? '')
    || a.file.localeCompare(b.file)
    || a.line - b.line;
}

/**
 * What is open across the estate, from the report `merge` wrote.
 *
 * Pure: takes the parsed report, returns the answer. `readMergedReport` does
 * the I/O and the refusal, so a caller holding a report in memory — the merge
 * command itself, a test, a server — gets the same answer without a file.
 */
export function estateReport(merged: MergedReport, opts: EstateOptions = {}): EstateReport {
  const repoNames = new Set(merged.repo_statuses.map(s => s.name));
  const scope = buildOwnerScope(merged.tag_registry, repoNames, canonicaliser(merged.model));

  const wantSeverity = opts.severity && opts.severity.length > 0 ? new Set<string>(opts.severity) : null;
  const wantRepo = opts.repo && opts.repo.length > 0 ? new Set(opts.repo) : null;
  // An unrated finding is not a low one; `--severity` must never drop it.
  const keep = (f: EstateFinding) =>
    (!wantSeverity || f.severity === 'unset' || wantSeverity.has(f.severity))
    && (!wantRepo || (f.repo !== null && wantRepo.has(f.repo)));

  const open = openExposuresIn(merged.model, scope)
    .map(e => toFinding(e, repoNames)).filter(keep).sort(bySeverityThenPath);
  const confirmed = (merged.model.confirmed ?? [])
    .map(c => toFinding(c, repoNames)).filter(keep).sort(bySeverityThenPath);

  const by_severity: EstateSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  for (const f of open) by_severity[f.severity] += 1;

  const by_repo: Record<string, number> = {};
  for (const f of open) {
    const k = f.repo ?? '(unplaced)';
    by_repo[k] = (by_repo[k] ?? 0) + 1;
  }

  const repos: EstateRepoLine[] = merged.repo_statuses.map(s => ({
    name: s.name,
    loaded: s.loaded,
    error: s.error,
    commit_sha: s.commit_sha,
    generated_at: s.generated_at,
    open: open.filter(f => f.repo === s.name).length,
    confirmed: confirmed.filter(f => f.repo === s.name).length,
    parse: s.parse,
  }));

  const repos_loaded = merged.repo_statuses.filter(s => s.loaded).length;
  const read_nothing = merged.repo_statuses.length === 0 || repos_loaded === 0;
  const partial = !read_nothing && repos_loaded < merged.repo_statuses.length;
  const owner_scoped = merged.tag_registry.some(t => (t.also_defined_in?.length ?? 0) > 0);

  // The same three states `merge` makes, over the same `repo_statuses`. A repo
  // that did not load contributes to none of them: its parse is not unknown,
  // it is simply absent, and `read_nothing`/`partial` already speak for it.
  const loadedStatuses = merged.repo_statuses.filter(s => s.loaded);
  const unparsed_annotations = loadedStatuses.reduce((n, s) => n + (s.parse?.unparsed_annotations ?? 0), 0);
  const parse_errors = loadedStatuses.reduce((n, s) => n + (s.parse?.errors ?? 0), 0);
  const repos_parse_unknown = loadedStatuses.filter(s => !s.parse).length;

  const strict = opts.strict === true;
  // Parse ERRORS gate; warnings never do. That is the split `ci` and
  // `mergeVerdict` already make about the same numbers, and a reader who gets a
  // different verdict from `estate` than from `merge --strict` over one file is
  // being told two things about one estate.
  const exit_code: 0 | 1 = strict
    && (open.length > 0 || confirmed.length > 0 || read_nothing || partial || parse_errors > 0)
    ? 1 : 0;

  return {
    schema: ESTATE_SCHEMA,
    open,
    confirmed,
    repos,
    by_severity,
    by_repo,
    warnings: merged.warnings,
    summary: {
      workspace: merged.workspace,
      merged_at: merged.merged_at,
      repos: merged.repo_statuses.length,
      repos_loaded,
      exposures: merged.model.exposures.length,
      open: open.length,
      confirmed: confirmed.length,
      acceptances: merged.model.acceptances?.length ?? 0,
      mitigations: merged.model.mitigations?.length ?? 0,
      read_nothing,
      partial,
      owner_scoped,
      unparsed_annotations,
      parse_errors,
      repos_parse_unknown,
      strict,
      exit_code,
    },
  };
}

// ─── Rendering ───────────────────────────────────────────────────────

/**
 * The text face.
 *
 * Coverage first, always. "0 open" means nothing until the reader knows how
 * many repositories that 0 was computed over, so the line that says so is
 * printed before the findings and not after them.
 */
export function formatEstateReport(r: EstateReport): string {
  const s = r.summary;
  const out: string[] = [];

  out.push(`${s.workspace} — estate risk, from ${s.repos_loaded}/${s.repos} repo report(s)`);
  if (s.merged_at) out.push(`  merged ${s.merged_at}`);
  out.push('');

  if (s.read_nothing) {
    out.push('✗ No repo report was read. This is not a clean estate — it is no estate.');
    out.push('  Every number below is computed over nothing.');
    for (const repo of r.repos.filter(x => !x.loaded)) {
      out.push(`    ${repo.name} — ${repo.error ?? 'not loaded'}`);
    }
    out.push('');
  } else if (s.partial) {
    out.push(`⚠ ${s.repos - s.repos_loaded} of ${s.repos} repo(s) were not read. This answer is partial.`);
    for (const repo of r.repos.filter(x => !x.loaded)) {
      out.push(`    ${repo.name} — ${repo.error ?? 'not loaded'}`);
    }
    out.push('');
  }

  out.push('Repositories');
  for (const repo of r.repos) {
    // A repo is only ticked when it is clean AND its report could say so. Parse
    // errors mean annotations this repo wrote are in none of the numbers beside
    // them; no parse state at all means nobody knows whether they are. Either
    // way the line must not read as a clean bill of health.
    const parseErrors = repo.parse?.errors ?? 0;
    const parseUnknown = repo.loaded && !repo.parse;
    const risky = repo.open > 0 || repo.confirmed > 0;
    const mark = !repo.loaded ? '✗' : (risky || parseErrors > 0 ? '⚠' : (parseUnknown ? '?' : '✓'));
    const parseNote = parseErrors > 0
      ? `, ${parseErrors} parse error(s) — ${repo.parse!.unparsed_annotations} annotation line(s) unread`
      : parseUnknown ? ', parse state unknown' : '';
    const detail = repo.loaded
      ? `${repo.open} open, ${repo.confirmed} confirmed${parseNote}`
      : (repo.error ?? 'not loaded');
    const sha = repo.commit_sha ? `  ${repo.commit_sha.slice(0, 7)}` : '';
    out.push(`  ${mark} ${repo.name} — ${detail}${sha}`);
  }
  out.push('');

  if (r.confirmed.length > 0) {
    out.push(`${r.confirmed.length} reproduced exploit(s) — @confirmed, which no acceptance silences:`);
    for (const f of r.confirmed) {
      out.push(`  [${f.severity}] ${f.asset} → ${f.threat}`);
      out.push(`      ${f.file}:${f.line}${f.description ? `  ${f.description}` : ''}`);
    }
    out.push('');
  }

  if (r.open.length === 0) {
    if (s.read_nothing) {
      out.push('  (no open exposures — over zero repositories)');
    } else {
      // Same rule as `formatMergeVerdict`: the tick enumerates what was checked
      // and stops there, and what could not be checked is named in the same
      // breath rather than absorbed into the word "clean".
      out.push(s.parse_errors > 0
        ? `⚠ No open exposures across ${s.repos_loaded} repo(s), but ${s.parse_errors} parse error(s)`
          + ` left ${s.unparsed_annotations} annotation line(s) unread — this is not a clean estate.`
        : `✓ No open exposures across ${s.repos_loaded} repo(s) — ${s.mitigations} mitigation(s) credited.`);
      if (s.repos_parse_unknown > 0) {
        out.push(`  ${s.repos_parse_unknown} repo(s) did not report their parse state — whether their`
          + ' annotations were all read is unknown, not clean. Re-run `guardlink report'
          + ' --format json` in them with a current GuardLink.');
      }
      const parseWarnings = s.unparsed_annotations - s.parse_errors;
      if (parseWarnings > 0) {
        out.push(`  ${s.unparsed_annotations} annotation line(s) were unreadable across the estate`
          + ' at warning level, so they are in none of the counts above. Warnings do not gate.');
      }
    }
  } else {
    const counts = (['critical', 'high', 'medium', 'low', 'unset'] as const)
      .filter(k => r.by_severity[k] > 0)
      .map(k => `${r.by_severity[k]} ${k}`)
      .join(', ');
    out.push(`${r.open.length} open exposure(s) — ${counts}`);
    out.push('');
    let lastRepo: string | null | undefined;
    for (const f of r.open) {
      if (f.repo !== lastRepo) {
        out.push(`  ${f.repo ?? '(unplaced)'}`);
        lastRepo = f.repo;
      }
      out.push(`    [${f.severity}] ${f.asset} → ${f.threat}`);
      out.push(`        ${f.file}:${f.line}${f.description ? `  ${f.description}` : ''}`);
    }
  }

  const notable = r.warnings.filter(w => w.level !== 'info');
  if (notable.length > 0) {
    out.push('');
    out.push('From the merge:');
    for (const w of notable) out.push(`  ${w.level === 'error' ? '✗' : '⚠'} ${w.message}`);
  }

  if (!s.owner_scoped && r.repos.length > 1) {
    out.push('');
    out.push('  note: this report records no duplicate tag between repos, so nothing needed');
    out.push('        owner-scoping. A report written before GuardLink recorded tag ownership');
    out.push('        cannot be scoped here and will answer as the build that wrote it did.');
  }

  out.push('');
  out.push(s.strict
    ? `strict: exit ${s.exit_code}`
    : 'advisory — nothing here sets a non-zero exit code. Use --strict to gate.');

  return out.join('\n');
}
