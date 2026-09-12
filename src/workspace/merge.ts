/**
 * GuardLink Workspace — Merge engine for multi-repo reports.
 *
 * Takes N per-repo report JSONs and produces a unified MergedReport
 * with cross-repo tag resolution, warning detection, and aggregated stats.
 *
 * ── Zero repositories is never a pass ──────────────────────────────
 *
 * `merge` is the estate-wide surface, and the path a user reaches it by is the
 * "Next steps" text `link-project` prints for them. Measured before this change:
 * `guardlink merge` given a quoted per-repo wildcard — a `*` for the repository
 * directory, then `guardlink-report.json` — loaded **0 of 1** repositories,
 * printed `0 unmitigated`, wrote a dashboard reading clean, and **exited 0** —
 * because nothing expanded the glob its own `--help` advertises, and because the
 * command had no verdict, only a summary. A user following GuardLink's own
 * printed instructions got a clean bill of health for an estate that was never
 * opened.
 *
 * Two answers, and they are separate on purpose:
 *
 *   `resolveReportPaths` makes the glob work, and says when it could not.
 *   `mergeVerdict` decides the exit code, in one place, from the merged report.
 *
 * An empty read fails whether or not `--strict` was passed, because it is not a
 * finding about the estate — it is the absence of one. `--strict` is the opt-in
 * for gating on what the estate actually says.
 *
 * @asset Workspace.Merge (#merge-engine) -- "Cross-repo threat model unification"
 * @threat Tag_Collision (#tag-collision) [medium] -- "Duplicate tag definitions across repos"
 * @mitigates #merge-engine against #tag-collision using #prefix-ownership -- "Tag prefix determines owning repo"
 * @exposes #merge-engine to #vacuous-pass [high] cwe:CWE-754 -- "A glob that expanded to nothing, or a report set that loaded nothing, produced a merged model with zero of everything — and the summary of an empty model is indistinguishable from the summary of a clean estate"
 * @mitigates #merge-engine against #vacuous-pass using #fail-closed -- "mergeVerdict fails on zero repos loaded and on any glob that matched no file, regardless of --strict; the count it reports is of repositories actually read"
 * @flows ReportJSON -> #merge-engine via mergeReports -- "Per-repo reports feed into merge"
 * @flows #merge-engine -> MergedReport via mergeReports -- "Unified output"
 * @flows #merge-engine -> #cli via mergeVerdict -- "The exit code, decided once from the merged report and the paths that produced it"
 */

import { readFile } from 'node:fs/promises';
import { basename, dirname, resolve as resolvePath } from 'node:path';
import fg from 'fast-glob';
import type {
  ThreatModel,




  SourceLocation, AnnotationVerb,
} from '../types/index.js';
import type {
  MergedReport, MergeTotals, MergeDiffSummary, TagOwnership, UnresolvedRef,
  MergeWarning, MergeWarningCode, RepoStatus,
} from './types.js';
import { REPORT_SCHEMA_VERSION } from './metadata.js';
import { buildCoverageIndex, fileCoveragePercent, annotationCount, normalizeCoverage } from '../parser/coverage.js';

// ─── Report Loading ──────────────────────────────────────────────────

/** A loaded per-repo report with its origin info */
interface LoadedReport {
  /** Repo name (from metadata.repo, or inferred from filename) */
  repo: string;
  /** The parsed ThreatModel */
  model: ThreatModel;
  /** Path we loaded from */
  source_path: string;
}

/**
 * Load a single report JSON file. Returns the parsed model + repo name.
 * Throws on missing file or invalid JSON; caller handles gracefully.
 */
export async function loadReportJson(filePath: string): Promise<LoadedReport> {
  const raw = await readFile(filePath, 'utf-8');
  // The one place a model arrives from disk instead of from the parser, so the
  // one place that has to cope with a report an older GuardLink wrote. Coverage
  // is reshaped here rather than defended against at each of the six consumers
  // downstream; see normalizeCoverage for why 0 was the wrong coalesce.
  const model: ThreatModel = normalizeCoverage(JSON.parse(raw));

  // Determine repo name: prefer metadata.repo, fall back to project, then filename
  const repo = model.metadata?.repo
    || model.project
    || basename(filePath, '.json').replace(/^guardlink-report-?/, '') || 'unknown';

  return { repo, model, source_path: filePath };
}

/**
 * What `resolveReportPaths` made of the patterns it was handed.
 *
 * `unmatched` is the field that exists because of the defect: a pattern with
 * glob syntax in it that matched no file on disk. It is kept separate from a
 * plain path that does not exist, because the two are different statements. A
 * plain path names one report and `loadAllReports` can say which one is missing;
 * a glob names *however many repositories there are*, and a glob that matched
 * nothing means the caller's description of their estate found no estate — so
 * there is no per-repo error to report, only the fact that nothing was read.
 */
export interface ResolvedReportPaths {
  /** Absolute paths, in a stable order: pattern order, then sorted within a pattern. */
  files: string[];
  /** Glob patterns that matched no file. Never a plain path — those go to `files`. */
  unmatched: string[];
  /** Patterns that were expanded rather than taken literally. For the "N reports from M pattern(s)" line. */
  globbed: string[];
}

/**
 * Expand the file arguments `merge` was given, globs included.
 *
 * `merge --help` has always said "glob supported" and nothing ever expanded
 * one. Unquoted, the shell did it and the claim looked true; quoted — which is
 * what anyone writes who has been bitten by shell expansion once, and what the
 * documentation examples show — the pattern arrived here intact, went to
 * `readFile` as a literal filename, and came back ENOENT. The command then
 * reported `0/1 repos loaded`, `0 unmitigated`, wrote a dashboard saying the
 * estate was clean, and exited 0.
 *
 * So the expansion happens here, in the library rather than in the CLI action,
 * for the same reason the rest of this module is not in the CLI: a test can call
 * it, and the MCP surface can reach it without shelling out.
 *
 * Non-dynamic arguments are passed through untouched — `fg.isDynamicPattern`
 * decides, so `reports/orders.json` is still resolved against `cwd` and still
 * reaches `loadAllReports`, which still reports it as a missing repo by name.
 * The only paths that become `unmatched` are ones that asked the filesystem a
 * question and got nothing back.
 *
 * Order is made deterministic (sorted within each pattern) because `fast-glob`
 * does not promise one, and a merged dashboard whose repo list reorders between
 * runs on identical input is a diff nobody can read.
 *
 * @flows FileSystem -> #merge-engine via resolveReportPaths -- "Report paths discovered by expanding the caller's glob patterns against cwd"
 * @comment -- "A literal filename containing glob metacharacters is read as a pattern; it lands in unmatched rather than in a false ENOENT, and the CLI's message names the pattern verbatim so the cause is visible"
 */
export async function resolveReportPaths(
  patterns: string[],
  cwd: string = process.cwd(),
): Promise<ResolvedReportPaths> {
  const files: string[] = [];
  const unmatched: string[] = [];
  const globbed: string[] = [];
  const seen = new Set<string>();

  const keep = (abs: string): void => {
    if (seen.has(abs)) return;
    seen.add(abs);
    files.push(abs);
  };

  for (const pattern of patterns) {
    if (!fg.isDynamicPattern(pattern, { cwd })) {
      keep(resolvePath(cwd, pattern));
      continue;
    }
    globbed.push(pattern);
    // fast-glob speaks POSIX separators in patterns on every platform.
    const matches = await fg(pattern.replaceAll('\\', '/'), {
      cwd, absolute: true, dot: true, onlyFiles: true, suppressErrors: true,
    });
    if (matches.length === 0) {
      unmatched.push(pattern);
      continue;
    }
    for (const m of matches.sort()) keep(resolvePath(m));
  }

  return { files, unmatched, globbed };
}

/**
 * The repository a report path belongs to, for a report that could not be opened.
 *
 * A loaded report names itself (`metadata.repo`), so this is only ever reached on
 * the failure path — which is exactly where a name matters most, because it is the
 * name the warning and the `--strict` failure print. Stripping `guardlink-report`
 * off `orders-api/guardlink-report.json` leaves nothing, so the previous fallback
 * was the whole path: a 120-character temp path where the reader wanted
 * `orders-api`. The filename carries no identity in the layout `link-project`
 * tells every repo to use, so the directory does.
 */
function repoNameFromPath(filePath: string): string {
  const fromFile = basename(filePath, '.json').replace(/^guardlink-report-?/, '');
  if (fromFile) return fromFile;
  return basename(dirname(filePath)) || filePath;
}

/**
 * Attempt to load multiple report files. Returns loaded reports + statuses.
 * Missing or invalid files produce a RepoStatus with loaded=false rather than throwing.
 */
export async function loadAllReports(
  filePaths: string[],
  expectedRepos?: string[],
): Promise<{ reports: LoadedReport[]; statuses: RepoStatus[] }> {
  const reports: LoadedReport[] = [];
  const statuses: RepoStatus[] = [];

  for (const fp of filePaths) {
    try {
      const report = await loadReportJson(fp);
      reports.push(report);
      statuses.push({
        name: report.repo,
        loaded: true,
        generated_at: report.model.metadata?.generated_at || report.model.generated_at,
        commit_sha: report.model.metadata?.commit_sha ?? undefined,
        annotation_count: report.model.annotations_parsed,
      });
    } catch (err) {
      statuses.push({
        name: repoNameFromPath(fp),
        loaded: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // Flag expected repos that had no report file at all
  if (expectedRepos) {
    const loadedNames = new Set(statuses.map(s => s.name));
    for (const repo of expectedRepos) {
      if (!loadedNames.has(repo)) {
        statuses.push({ name: repo, loaded: false, error: 'No report file provided' });
      }
    }
  }

  return { reports, statuses };
}

// ─── Tag Registry ────────────────────────────────────────────────────

/**
 * Extract all tag definitions (assets, threats, controls) from a ThreatModel.
 * Tags come from the `id` field (e.g. "#payment-svc.refund").
 */
function extractTagDefinitions(model: ThreatModel, repo: string): TagOwnership[] {
  const tags: TagOwnership[] = [];

  for (const a of model.assets) {
    if (a.id) {
      tags.push({ tag: a.id, owner_repo: repo, kind: 'asset' });
      // Also register with # prefix since relationships use #tag form
      if (!a.id.startsWith('#')) tags.push({ tag: `#${a.id}`, owner_repo: repo, kind: 'asset' });
    }
  }
  for (const t of model.threats) {
    if (t.id) {
      tags.push({ tag: t.id, owner_repo: repo, kind: 'threat' });
      if (!t.id.startsWith('#')) tags.push({ tag: `#${t.id}`, owner_repo: repo, kind: 'threat' });
    }
  }
  for (const c of model.controls) {
    if (c.id) {
      tags.push({ tag: c.id, owner_repo: repo, kind: 'control' });
      if (!c.id.startsWith('#')) tags.push({ tag: `#${c.id}`, owner_repo: repo, kind: 'control' });
    }
  }

  return tags;
}

/**
 * Build a unified tag registry from all loaded reports.
 *
 * Ownership rule: the repo whose name matches the tag prefix owns it.
 * e.g. "#payment-svc.refund" → owned by repo "payment-svc" (or "payment-service").
 * If no prefix match, first definition wins.
 *
 * Returns the registry + any duplicate-tag warnings.
 */
export function buildTagRegistry(
  reports: LoadedReport[],
): { registry: TagOwnership[]; warnings: MergeWarning[] } {
  const warnings: MergeWarning[] = [];
  const repoNames = new Set(reports.map(r => r.repo));

  // Collect all definitions grouped by tag
  const definitionsByTag = new Map<string, TagOwnership[]>();
  for (const report of reports) {
    const defs = extractTagDefinitions(report.model, report.repo);
    for (const def of defs) {
      const existing = definitionsByTag.get(def.tag) || [];
      existing.push(def);
      definitionsByTag.set(def.tag, existing);
    }
  }

  // Resolve ownership: prefix match > first definition
  const registry: TagOwnership[] = [];
  for (const [tag, defs] of definitionsByTag) {
    if (defs.length === 1) {
      registry.push(defs[0]);
      continue;
    }

    // Multiple repos define this tag — find best owner
    const prefixOwner = inferOwnerFromPrefix(tag, repoNames);
    const winner = prefixOwner
      ? defs.find(d => d.owner_repo === prefixOwner) || defs[0]
      : defs[0];

    registry.push(winner);

    // Warn about duplicates
    const otherRepos = defs
      .filter(d => d.owner_repo !== winner.owner_repo)
      .map(d => d.owner_repo);
    if (otherRepos.length > 0) {
      warnings.push({
        level: 'warning',
        code: 'duplicate_tag',
        message: `Tag "${tag}" defined in ${winner.owner_repo} (owner) and also in: ${otherRepos.join(', ')}`,
        repos: [winner.owner_repo, ...otherRepos],
        tag,
      });
    }
  }

  return { registry, warnings };
}

/**
 * Normalize a tag for comparison: strip leading '#'.
 * Asset ids are stored as "parser" but references use "#parser".
 */
function normalizeTag(tag: string): string {
  return tag.startsWith('#') ? tag.slice(1) : tag;
}

/**
 * Infer which repo owns a tag based on its prefix.
 * "#payment-svc.refund" → look for repo named "payment-svc" or "payment-service".
 * Returns null if no prefix match found.
 */
function inferOwnerFromPrefix(tag: string, repoNames: Set<string>): string | null {
  // Strip leading # if present
  const clean = tag.startsWith('#') ? tag.slice(1) : tag;
  const dotIdx = clean.indexOf('.');
  if (dotIdx === -1) return null; // no service prefix

  const prefix = clean.slice(0, dotIdx);

  // Direct match
  if (repoNames.has(prefix)) return prefix;

  // Fuzzy: "payment-svc" matches "payment-service" (prefix is substring or vice versa)
  for (const repo of repoNames) {
    if (repo.startsWith(prefix) || prefix.startsWith(repo)) return repo;
    // Also try with common suffix variations: -svc, -service, -lib, -api
    const normalized = repo.replace(/-(?:service|svc|lib|api|worker)$/, '');
    const prefixNorm = prefix.replace(/-(?:service|svc|lib|api|worker)$/, '');
    if (normalized === prefixNorm) return repo;
  }

  return null;
}

// ─── Cross-Repo Reference Resolution ─────────────────────────────────

/**
 * Collect all tag references from relationship annotations (mitigates, exposes,
 * flows, etc.) and check which ones resolve to the tag registry.
 *
 * Returns unresolved refs + additional warnings.
 */
export function resolveReferences(
  reports: LoadedReport[],
  registry: TagOwnership[],
  repoNames: Set<string>,
): { unresolved: UnresolvedRef[]; warnings: MergeWarning[] } {
  // Build tag set with both "#tag" and "tag" forms for lookup
  const tagSet = new Set<string>();
  for (const t of registry) {
    tagSet.add(t.tag);
    tagSet.add(normalizeTag(t.tag));
  }
  const unresolved: UnresolvedRef[] = [];
  const warnings: MergeWarning[] = [];

  for (const report of reports) {
    const m = report.model;

    // Gather all tag references used in relationship annotations
    const refs = collectTagReferences(m, report.repo);

    for (const ref of refs) {
      if (tagSet.has(ref.tag) || tagSet.has(normalizeTag(ref.tag))) continue; // resolved

      // Check if the tag prefix suggests a known repo (but definition is missing)
      const prefix = inferOwnerFromPrefix(ref.tag, repoNames);

      unresolved.push({
        ...ref,
        source_repo: report.repo,
        inferred_repo: prefix ?? undefined,
      });
    }
  }

  // Generate warnings for unresolved refs
  // Group by tag for cleaner output
  const byTag = new Map<string, UnresolvedRef[]>();
  for (const u of unresolved) {
    const existing = byTag.get(u.tag) || [];
    existing.push(u);
    byTag.set(u.tag, existing);
  }

  for (const [tag, refs] of byTag) {
    const repos = [...new Set(refs.map(r => r.source_repo))];
    const inferred = refs[0].inferred_repo;
    const detail = inferred
      ? ` (prefix suggests repo "${inferred}" but no definition found)`
      : '';
    warnings.push({
      level: 'warning',
      code: 'unresolved_ref',
      message: `Tag "${tag}" referenced in ${repos.join(', ')} but not defined in any repo${detail}`,
      repos,
      tag,
    });
  }

  // Also warn about tag prefixes that don't match any known repo
  for (const entry of registry) {
    const clean = entry.tag.startsWith('#') ? entry.tag.slice(1) : entry.tag;
    const dotIdx = clean.indexOf('.');
    if (dotIdx === -1) continue;
    const prefix = clean.slice(0, dotIdx);
    if (!inferOwnerFromPrefix(entry.tag, repoNames)) {
      warnings.push({
        level: 'info',
        code: 'tag_prefix_mismatch',
        message: `Tag "${entry.tag}" has prefix "${prefix}" which doesn't match any workspace repo`,
        repos: [entry.owner_repo],
        tag: entry.tag,
      });
    }
  }

  return { unresolved, warnings };
}

/** Simple ref container used during collection */
interface TagRef {
  tag: string;
  context_verb: AnnotationVerb;
  location: SourceLocation;
}

/**
 * Collect all tag references from a ThreatModel's relationship annotations.
 * These are the tags used in mitigates, exposes, flows, etc. — NOT definitions.
 */
function collectTagReferences(m: ThreatModel, _repo: string): TagRef[] {
  const refs: TagRef[] = [];

  // Helper: add tag ref only if it looks like a tag reference (starts with #)
  // Plain text like "EnvVars", "FileSystem" in flows are descriptive, not cross-repo refs
  const addRef = (tag: string | undefined, verb: AnnotationVerb, loc: SourceLocation) => {
    if (!tag) return;
    if (!tag.startsWith('#')) return; // not a tag reference
    refs.push({ tag, context_verb: verb, location: loc });
  };

  for (const mit of m.mitigations) {
    addRef(mit.asset, 'mitigates', mit.location);
    addRef(mit.threat, 'mitigates', mit.location);
    if (mit.control) addRef(mit.control, 'mitigates', mit.location);
  }
  for (const exp of m.exposures) {
    addRef(exp.asset, 'exposes', exp.location);
    addRef(exp.threat, 'exposes', exp.location);
  }
  for (const acc of m.acceptances) {
    addRef(acc.asset, 'accepts', acc.location);
    addRef(acc.threat, 'accepts', acc.location);
  }
  for (const tr of m.transfers) {
    addRef(tr.source, 'transfers', tr.location);
    addRef(tr.target, 'transfers', tr.location);
    addRef(tr.threat, 'transfers', tr.location);
  }
  for (const fl of m.flows) {
    addRef(fl.source, 'flows', fl.location);
    addRef(fl.target, 'flows', fl.location);
  }
  for (const b of m.boundaries) {
    addRef(b.asset_a, 'boundary', b.location);
    addRef(b.asset_b, 'boundary', b.location);
  }
  for (const v of m.validations) {
    addRef(v.control, 'validates', v.location);
    addRef(v.asset, 'validates', v.location);
  }

  return refs;
}

// ─── Model Merging ───────────────────────────────────────────────────

/**
 * Prefix all file paths in a SourceLocation with the repo name
 * so merged output shows "payment-service/src/routes/refund.ts:42"
 */
function prefixLocation(loc: SourceLocation, repo: string): SourceLocation {
  return {
    ...loc,
    file: `${repo}/${loc.file}`,
  };
}

/** Prefix locations on an array of items that have a `location` field */
function prefixAll<T extends { location: SourceLocation }>(items: T[], repo: string): T[] {
  return items.map(item => ({ ...item, location: prefixLocation(item.location, repo) }));
}

/**
 * Combine multiple ThreatModels into a single unified model.
 * File paths are prefixed with repo name for disambiguation.
 * Deduplication is by tag ID for definitions (assets/threats/controls).
 * Relationships are kept from all repos (no dedup — same relationship
 * stated in two repos is meaningful).
 */
export function combineModels(reports: LoadedReport[]): ThreatModel {
  const seenAssetIds = new Set<string>();
  const seenThreatIds = new Set<string>();
  const seenControlIds = new Set<string>();
  const seenActorIds = new Set<string>();

  const combined: ThreatModel = {
    version: REPORT_SCHEMA_VERSION,
    project: reports.length > 0 ? (reports[0].model.metadata?.workspace || 'workspace') : 'workspace',
    generated_at: new Date().toISOString(),
    source_files: 0,
    annotations_parsed: 0,
    annotated_files: [],
    unannotated_files: [],
    assets: [],
    threats: [],
    controls: [],
    actors: [],
    entitlements: [],
    mitigations: [],
    exposures: [],
    confirmed: [],
    acceptances: [],
    transfers: [],
    flows: [],
    boundaries: [],
    validations: [],
    audits: [],
    ownership: [],
    data_handling: [],
    assumptions: [],
    shields: [],
    features: [],
    comments: [],
    coverage: { annotation_count: 0, coverage_percent: 0 },
  };

  for (const { repo, model: m } of reports) {
    combined.source_files += m.source_files;
    combined.annotations_parsed += m.annotations_parsed;
    combined.annotated_files.push(...m.annotated_files.map(f => `${repo}/${f}`));
    combined.unannotated_files.push(...m.unannotated_files.map(f => `${repo}/${f}`));

    // Definitions: dedup by tag ID, keep first (registry determines owner)
    for (const a of m.assets) {
      if (a.id && seenAssetIds.has(a.id)) continue;
      if (a.id) seenAssetIds.add(a.id);
      combined.assets.push({ ...a, location: prefixLocation(a.location, repo) });
    }
    for (const t of m.threats) {
      if (t.id && seenThreatIds.has(t.id)) continue;
      if (t.id) seenThreatIds.add(t.id);
      combined.threats.push({ ...t, location: prefixLocation(t.location, repo) });
    }
    for (const c of m.controls) {
      if (c.id && seenControlIds.has(c.id)) continue;
      if (c.id) seenControlIds.add(c.id);
      combined.controls.push({ ...c, location: prefixLocation(c.location, repo) });
    }
    // The actor verb is a definition, so it dedups by tag ID like the three above.
    for (const ac of m.actors || []) {
      if (ac.id && seenActorIds.has(ac.id)) continue;
      if (ac.id) seenActorIds.add(ac.id);
      combined.actors!.push({ ...ac, location: prefixLocation(ac.location, repo) });
    }

    // Relationships: keep all (no dedup — cross-repo relationships are valuable)
    combined.mitigations.push(...prefixAll(m.mitigations, repo));
    combined.exposures.push(...prefixAll(m.exposures, repo));
    combined.confirmed.push(...prefixAll(m.confirmed || [], repo));
    combined.acceptances.push(...prefixAll(m.acceptances, repo));
    combined.entitlements!.push(...prefixAll(m.entitlements || [], repo));
    combined.transfers.push(...prefixAll(m.transfers, repo));
    combined.flows.push(...prefixAll(m.flows, repo));
    combined.boundaries.push(...prefixAll(m.boundaries, repo));
    combined.validations.push(...prefixAll(m.validations, repo));
    combined.audits.push(...prefixAll(m.audits, repo));
    combined.ownership.push(...prefixAll(m.ownership, repo));
    combined.data_handling.push(...prefixAll(m.data_handling, repo));
    combined.assumptions.push(...prefixAll(m.assumptions, repo));
    combined.shields.push(...prefixAll(m.shields, repo));
    combined.features.push(...prefixAll(m.features || [], repo));
    combined.comments.push(...prefixAll(m.comments, repo));

    // Aggregate coverage. Only the annotation count is additive; the percent
    // is recomputed below from the combined file totals.
    combined.coverage.annotation_count += annotationCount(m);
  }

  // D49: this recomputed percent as annotated_symbols / total_symbols. Since
  // total_symbols was never populated, the `: 0` fallback was the ONLY branch
  // that ever ran — two repos each reporting 89% merged to a workspace
  // reporting 0%, which is D14 ("a hardcoded 0 rendered as 0% on fully
  // annotated projects") reappearing on the path D14's fix never reached.
  //
  // The percent every repo actually computes is FILE coverage, and the file
  // counts are already aggregated above, so the workspace number is the same
  // division over the combined totals — through the same helper the parser uses.
  combined.coverage.coverage_percent = fileCoveragePercent(
    combined.annotated_files.length,
    combined.source_files,
  );

  return combined;
}

// ─── Totals & Unmitigated Detection ──────────────────────────────────

/**
 * Count unmitigated exposures: exposures with no corresponding mitigation
 * (same asset+threat pair) and no acceptance.
 */
function countUnmitigated(model: ThreatModel): number {
  // D36. Was a local pair set that also skipped ref normalisation, so a
  // workspace total could disagree with the per-repo `validate` it summarises.
  // Note this runs on the COMBINED model, whose locations are repo-prefixed —
  // which is what makes the same-file test correct across repos: two repos'
  // db.py are different files here, so neither can narrow the other.
  const index = buildCoverageIndex(model);
  return model.exposures.filter(e => !index.isCovered(e)).length;
}

/** Compute aggregate totals from a combined model */
export function computeTotals(
  model: ThreatModel,
  statuses: RepoStatus[],
  resolvedCount: number,
  unresolvedCount: number,
): MergeTotals {
  return {
    repos: statuses.length,
    repos_loaded: statuses.filter(s => s.loaded).length,
    annotations: model.annotations_parsed,
    assets: model.assets.length,
    threats: model.threats.length,
    controls: model.controls.length,
    mitigations: model.mitigations.length,
    exposures: model.exposures.length,
    unmitigated_exposures: countUnmitigated(model),
    confirmed: (model.confirmed || []).length,
    acceptances: model.acceptances.length,
    flows: model.flows.length,
    boundaries: model.boundaries.length,
    external_refs_resolved: resolvedCount,
    external_refs_unresolved: unresolvedCount,
  };
}

// ─── Verdict ─────────────────────────────────────────────────────────

/** Why a `merge` run failed, in the order a reader should be told. */
export type MergeFailureCode =
  | 'unmatched_pattern'   // A glob matched no file — part of the estate was never located.
  | 'nothing_loaded'      // Zero repositories read. Every count below is the empty model's.
  | 'repo_not_loaded'     // --strict: a named report could not be read, so the estate is partial.
  | 'unmitigated'         // --strict: an exposure no control, acceptance or transfer covers.
  | 'confirmed';          // --strict: a reproduced exploit. No acceptance silences one.

export interface MergeFailure {
  code: MergeFailureCode;
  message: string;
  /** Whether this failure needed `--strict` to count. */
  strict_only: boolean;
}

export interface MergeVerdict {
  /** Everything wrong with this run, worst first. Empty on a pass. */
  failures: MergeFailure[];
  /** Whether `--strict` was in effect. */
  strict: boolean;
  /** The exit code the command must use. */
  exit_code: 0 | 1;
}

export interface MergeVerdictOptions {
  /** Gate on what the estate says: unmitigated exposures, confirmed exploits, partial loads. */
  strict?: boolean;
  /** Glob patterns that matched no file, from `resolveReportPaths`. */
  unmatched?: string[];
}

/**
 * Decide whether this `merge` run passed — the only place the exit code is
 * decided, for the reason `ci`'s predicate lives in one function: two callers
 * with two copies of the rule are two commands that disagree about the same
 * estate.
 *
 * Two classes of failure, and the split is the whole point:
 *
 *   **Unconditional** — the run did not read the estate. A glob that matched
 *   nothing, or zero repositories loaded. No flag gates these, because they are
 *   not opinions about risk: the numbers printed beside them are an empty model's
 *   numbers, and a zero that means "nothing was read" must never leave the
 *   process as a 0. This is the defect, not a policy.
 *
 *   **`--strict`** — the estate was read and it says something. Unmitigated
 *   exposures, reproduced exploits, and reports that were named and could not be
 *   read. Opt-in, for the same reason `guardlink ci --strict` is opt-in: an estate
 *   mid-annotation has unmitigated exposures by construction, and a gate that
 *   fails the day the annotations land is a gate that gets deleted.
 *
 * `confirmed` gates under `--strict` alongside `unmitigated` rather than being
 * folded into it, because `@accepts` does not silence a `@confirmed` anywhere
 * else in the product: an estate can read `0 unmitigated` with reproduced
 * exploits in it, which is exactly how eight of them passed a strict gate on
 * NodeGoat before `ci` grew the same term.
 *
 * A partially loaded estate gates only under `--strict`: it is a real blind spot,
 * but it is one the summary already names per repository, and failing on it
 * unconditionally would turn a pipeline red the first week a fifth repository
 * joins the workspace and has not run `report` yet.
 */
export function mergeVerdict(
  merged: MergedReport,
  options: MergeVerdictOptions = {},
): MergeVerdict {
  const strict = options.strict === true;
  const unmatched = options.unmatched ?? [];
  const t = merged.totals;
  const failures: MergeFailure[] = [];

  for (const pattern of unmatched) {
    failures.push({
      code: 'unmatched_pattern',
      message: `No report file matched "${pattern}" — the repositories it was meant to name were never read`,
      strict_only: false,
    });
  }

  // Reported only when there was something to load. When every argument was a
  // glob that matched nothing, `unmatched_pattern` above has already said so and
  // said it more usefully; a second line adding "and therefore nothing loaded"
  // is the same fact with the cause removed.
  if (t.repos_loaded === 0 && t.repos > 0) {
    failures.push({
      code: 'nothing_loaded',
      message: `0 of ${t.repos} repositories loaded — the counts above are an empty model's, not this estate's`,
      strict_only: false,
    });
  } else if (t.repos === 0 && unmatched.length === 0) {
    failures.push({
      code: 'nothing_loaded',
      message: 'No report files to merge — nothing was read, so there is nothing to report',
      strict_only: false,
    });
  }

  if (strict) {
    const missing = merged.repo_statuses.filter(s => !s.loaded);
    // Only when something DID load: otherwise `nothing_loaded` above says it
    // better, and repeating it per repo buries the one line that matters.
    if (missing.length > 0 && t.repos_loaded > 0) {
      failures.push({
        code: 'repo_not_loaded',
        message: `${missing.length} of ${t.repos} repositories could not be read (${missing.map(s => s.name).join(', ')})`
          + ' — this estate was answered in part',
        strict_only: true,
      });
    }
    if (t.confirmed > 0) {
      failures.push({
        code: 'confirmed',
        message: `${t.confirmed} confirmed exploit(s) across the estate — reproduced, and no acceptance silences one`,
        strict_only: true,
      });
    }
    if (t.unmitigated_exposures > 0) {
      failures.push({
        code: 'unmitigated',
        message: `${t.unmitigated_exposures} unmitigated exposure(s) across ${t.repos_loaded} repositories`,
        strict_only: true,
      });
    }
  }

  return { failures, strict, exit_code: failures.length > 0 ? 1 : 0 };
}

/** The human rendering of a verdict: the reasons, then what to do about them. */
export function formatMergeVerdict(verdict: MergeVerdict): string {
  if (verdict.failures.length === 0) {
    return verdict.strict
      ? '✓ Estate clean — every repository read, nothing unmitigated, nothing confirmed.'
      : '';
  }
  const out = verdict.failures.map(f => `✗ ${f.message}`);
  if (verdict.failures.some(f => f.code === 'unmatched_pattern')) {
    out.push('  The pattern was expanded against the current directory. Check you are in the'
      + ' workspace root, and that each repo has run `guardlink report --format json`.');
  }
  return out.join('\n');
}

// ─── Top-Level Merge Orchestrator ────────────────────────────────────

export interface MergeOptions {
  /** Workspace name (used in output if no report carries workspace metadata) */
  workspace?: string;
  /** Expected repo names (from workspace.yaml). Missing repos generate warnings. */
  expectedRepos?: string[];
  /** Stale threshold in hours. Reports older than this get a warning. Default: 168 (7 days) */
  staleThresholdHours?: number;
}

/**
 * Main entry point: merge N report JSON files into a unified MergedReport.
 *
 * 1. Load all report JSONs (partial load on failure)
 * 2. Build tag registry (who owns each tag)
 * 3. Resolve cross-repo references
 * 4. Combine all ThreatModels into one
 * 5. Compute totals + warnings
 * 6. Return MergedReport
 */
export async function mergeReports(
  filePaths: string[],
  options: MergeOptions = {},
): Promise<MergedReport> {
  const staleHours = options.staleThresholdHours ?? 168;

  // 1. Load reports
  const { reports, statuses } = await loadAllReports(filePaths, options.expectedRepos);

  if (reports.length === 0) {
    // Return empty merged report with all repos marked as failed
    return emptyMergedReport(options.workspace || 'unknown', statuses);
  }

  // 2. Build tag registry
  const { registry, warnings: tagWarnings } = buildTagRegistry(reports);

  // 3. Resolve cross-repo references
  const repoNames = new Set(reports.map(r => r.repo));
  const { unresolved, warnings: refWarnings } = resolveReferences(reports, registry, repoNames);

  // Count resolved: total refs from external_refs fields minus unresolved
  const totalExternalRefs = reports.reduce(
    (sum, r) => sum + (r.model.external_refs?.length || 0), 0,
  );
  const resolvedCount = Math.max(0, totalExternalRefs - unresolved.length);

  // 4. Combine models
  const combinedModel = combineModels(reports);

  // 5. Detect stale reports
  const staleWarnings = detectStaleReports(statuses, staleHours);

  // 6. Schema mismatch warnings
  const schemaWarnings = detectSchemaMismatch(reports);

  // Determine workspace name
  const workspaceName = options.workspace
    || reports.find(r => r.model.metadata?.workspace)?.model.metadata?.workspace
    || 'workspace';

  // Assemble all warnings
  const allWarnings = [...tagWarnings, ...refWarnings, ...staleWarnings, ...schemaWarnings];

  // Missing repo warnings
  for (const s of statuses) {
    if (!s.loaded) {
      allWarnings.push({
        level: 'warning',
        code: 'missing_repo',
        message: `Repo "${s.name}" report not loaded: ${s.error || 'unknown error'}`,
        repos: [s.name],
      });
    }
  }

  return {
    workspace: workspaceName,
    merged_at: new Date().toISOString(),
    schema_version: REPORT_SCHEMA_VERSION,
    repo_statuses: statuses,
    tag_registry: registry,
    unresolved_refs: unresolved,
    warnings: allWarnings,
    totals: computeTotals(combinedModel, statuses, resolvedCount, unresolved.length),
    model: combinedModel,
  };
}

// ─── Helper Functions ─────────────────────────────────────────────────

function detectStaleReports(statuses: RepoStatus[], staleHours: number): MergeWarning[] {
  const warnings: MergeWarning[] = [];
  const now = Date.now();
  const threshold = staleHours * 60 * 60 * 1000;

  for (const s of statuses) {
    if (!s.loaded || !s.generated_at) continue;
    const age = now - new Date(s.generated_at).getTime();
    if (age > threshold) {
      const days = Math.round(age / (24 * 60 * 60 * 1000));
      warnings.push({
        level: 'warning',
        code: 'stale_report',
        message: `Repo "${s.name}" report is ${days} day(s) old (generated ${s.generated_at})`,
        repos: [s.name],
      });
    }
  }
  return warnings;
}

function detectSchemaMismatch(reports: LoadedReport[]): MergeWarning[] {
  const versions = new Set(reports.map(r => r.model.metadata?.schema_version).filter(Boolean));
  if (versions.size <= 1) return [];

  return [{
    level: 'warning',
    code: 'schema_mismatch',
    message: `Reports use different schema versions: ${[...versions].join(', ')}. Results may be inconsistent.`,
    repos: reports.map(r => r.repo),
  }];
}

function emptyMergedReport(workspace: string, statuses: RepoStatus[]): MergedReport {
  return {
    workspace,
    merged_at: new Date().toISOString(),
    schema_version: REPORT_SCHEMA_VERSION,
    repo_statuses: statuses,
    tag_registry: [],
    unresolved_refs: [],
    warnings: statuses.map(s => ({
      level: 'warning' as const,
      code: 'missing_repo' as MergeWarningCode,
      message: `Repo "${s.name}" report not loaded: ${s.error || 'unknown error'}`,
      repos: [s.name],
    })),
    totals: {
      repos: statuses.length, repos_loaded: 0, annotations: 0, assets: 0,
      threats: 0, controls: 0, mitigations: 0, exposures: 0,
      unmitigated_exposures: 0, confirmed: 0, acceptances: 0, flows: 0, boundaries: 0,
      external_refs_resolved: 0, external_refs_unresolved: 0,
    },
    model: {
      version: REPORT_SCHEMA_VERSION, project: workspace,
      generated_at: new Date().toISOString(), source_files: 0,
      annotations_parsed: 0, annotated_files: [], unannotated_files: [],
      assets: [], threats: [], controls: [], actors: [], entitlements: [],
      mitigations: [], exposures: [],
      confirmed: [], acceptances: [], transfers: [], flows: [], boundaries: [],
      validations: [], audits: [], ownership: [], data_handling: [],
      assumptions: [], shields: [], features: [], comments: [],
      coverage: { annotation_count: 0, coverage_percent: 0 },
    },
  };
}

// ─── Merge Diff (--diff-against) ─────────────────────────────────────

/**
 * Compute a diff summary between two merged reports.
 * Used for weekly "what changed" output.
 */
export function diffMergedReports(
  current: MergedReport,
  previous: MergedReport,
): MergeDiffSummary {
  const c = current.totals;
  const p = previous.totals;

  const prevRepoNames = new Set(previous.repo_statuses.map(s => s.name));
  const currRepoNames = new Set(current.repo_statuses.map(s => s.name));

  // Repos with changed annotation counts or new commits
  const reposWithChanges: string[] = [];
  for (const cs of current.repo_statuses) {
    const ps = previous.repo_statuses.find(s => s.name === cs.name);
    if (!ps) continue; // new repo, handled separately
    if (cs.annotation_count !== ps.annotation_count || cs.commit_sha !== ps.commit_sha) {
      reposWithChanges.push(cs.name);
    }
  }

  const newUnmitigated = c.unmitigated_exposures - p.unmitigated_exposures;
  const riskDelta: 'increased' | 'decreased' | 'unchanged' =
    newUnmitigated > 0 ? 'increased' : newUnmitigated < 0 ? 'decreased' : 'unchanged';

  return {
    previous_merged_at: previous.merged_at,
    current_merged_at: current.merged_at,
    assets_added: Math.max(0, c.assets - p.assets),
    assets_removed: Math.max(0, p.assets - c.assets),
    threats_added: Math.max(0, c.threats - p.threats),
    threats_removed: Math.max(0, p.threats - c.threats),
    mitigations_added: Math.max(0, c.mitigations - p.mitigations),
    mitigations_removed: Math.max(0, p.mitigations - c.mitigations),
    exposures_added: Math.max(0, c.exposures - p.exposures),
    exposures_removed: Math.max(0, p.exposures - c.exposures),
    new_unmitigated: Math.max(0, newUnmitigated),
    resolved_unmitigated: Math.max(0, -newUnmitigated),
    risk_delta: riskDelta,
    new_flows: Math.max(0, c.flows - p.flows),
    removed_flows: Math.max(0, p.flows - c.flows),
    new_unresolved_refs: Math.max(0, c.external_refs_unresolved - p.external_refs_unresolved),
    resolved_refs: Math.max(0, p.external_refs_unresolved - c.external_refs_unresolved),
    repos_added: [...currRepoNames].filter(n => !prevRepoNames.has(n)),
    repos_removed: [...prevRepoNames].filter(n => !currRepoNames.has(n)),
    repos_with_changes: reposWithChanges,
  };
}

/**
 * Format a diff summary as markdown for weekly reports / Slack / email.
 */
export function formatDiffSummary(diff: MergeDiffSummary, workspace: string): string {
  const lines: string[] = [];
  const riskIcon = diff.risk_delta === 'increased' ? '🔴'
    : diff.risk_delta === 'decreased' ? '🟢' : '⚪';

  lines.push(`# ${workspace} — Weekly Threat Model Changes`);
  lines.push('');
  lines.push(`**Period:** ${diff.previous_merged_at.slice(0, 10)} → ${diff.current_merged_at.slice(0, 10)}`);
  lines.push(`**Risk trend:** ${riskIcon} ${diff.risk_delta}`);
  lines.push('');

  // Deltas
  lines.push('## Changes');
  lines.push('');
  const deltas: string[] = [];
  if (diff.assets_added) deltas.push(`+${diff.assets_added} new asset(s)`);
  if (diff.assets_removed) deltas.push(`-${diff.assets_removed} removed asset(s)`);
  if (diff.threats_added) deltas.push(`+${diff.threats_added} new threat(s)`);
  if (diff.threats_removed) deltas.push(`-${diff.threats_removed} removed threat(s)`);
  if (diff.mitigations_added) deltas.push(`+${diff.mitigations_added} new mitigation(s)`);
  if (diff.mitigations_removed) deltas.push(`-${diff.mitigations_removed} removed mitigation(s) ⚠️`);
  if (diff.exposures_added) deltas.push(`+${diff.exposures_added} new exposure(s)`);
  if (diff.exposures_removed) deltas.push(`-${diff.exposures_removed} resolved exposure(s)`);
  if (diff.new_flows) deltas.push(`+${diff.new_flows} new data flow(s)`);
  if (diff.removed_flows) deltas.push(`-${diff.removed_flows} removed data flow(s)`);

  if (deltas.length === 0) {
    lines.push('No annotation changes this period.');
  } else {
    for (const d of deltas) lines.push(`- ${d}`);
  }
  lines.push('');

  // Risk highlights
  if (diff.new_unmitigated > 0 || diff.resolved_unmitigated > 0) {
    lines.push('## Risk');
    lines.push('');
    if (diff.new_unmitigated > 0) lines.push(`- 🔴 ${diff.new_unmitigated} new unmitigated exposure(s)`);
    if (diff.resolved_unmitigated > 0) lines.push(`- 🟢 ${diff.resolved_unmitigated} exposure(s) now mitigated`);
    lines.push('');
  }

  // Cross-repo refs
  if (diff.new_unresolved_refs > 0 || diff.resolved_refs > 0) {
    lines.push('## Cross-Repo References');
    lines.push('');
    if (diff.new_unresolved_refs > 0) lines.push(`- ⚠️ ${diff.new_unresolved_refs} new unresolved ref(s)`);
    if (diff.resolved_refs > 0) lines.push(`- ✓ ${diff.resolved_refs} ref(s) now resolved`);
    lines.push('');
  }

  // Repo changes
  if (diff.repos_added.length > 0 || diff.repos_removed.length > 0 || diff.repos_with_changes.length > 0) {
    lines.push('## Repos');
    lines.push('');
    for (const r of diff.repos_added) lines.push(`- 🆕 ${r} (new)`);
    for (const r of diff.repos_removed) lines.push(`- ❌ ${r} (removed)`);
    for (const r of diff.repos_with_changes) lines.push(`- 📝 ${r} (updated)`);
    lines.push('');
  }

  return lines.join('\n');
}

// ─── Merge Summary Markdown ──────────────────────────────────────────

/**
 * Generate a human-readable markdown summary of a merged report.
 * Used for terminal output, weekly emails, and Slack notifications.
 */
export function formatMergeSummary(merged: MergedReport): string {
  const lines: string[] = [];
  const t = merged.totals;

  lines.push(`# ${merged.workspace} — Threat Model Summary`);
  lines.push('');
  lines.push(`**Generated:** ${merged.merged_at}`);
  lines.push(`**Repos:** ${t.repos_loaded}/${t.repos} loaded`);
  lines.push('');

  // Totals
  lines.push('## Overview');
  lines.push('');
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Annotations | ${t.annotations} |`);
  lines.push(`| Assets | ${t.assets} |`);
  lines.push(`| Threats | ${t.threats} |`);
  lines.push(`| Controls | ${t.controls} |`);
  lines.push(`| Mitigations | ${t.mitigations} |`);
  lines.push(`| Exposures | ${t.exposures} |`);
  lines.push(`| Unmitigated | ${t.unmitigated_exposures} |`);
  lines.push(`| Data flows | ${t.flows} |`);
  lines.push(`| Cross-repo refs resolved | ${t.external_refs_resolved} |`);
  lines.push(`| Cross-repo refs unresolved | ${t.external_refs_unresolved} |`);
  lines.push('');

  // Repo statuses
  lines.push('## Repos');
  lines.push('');
  for (const s of merged.repo_statuses) {
    const status = s.loaded ? '✓' : '✗';
    const detail = s.loaded
      ? `${s.annotation_count || 0} annotations, commit ${(s.commit_sha || '').slice(0, 7)}`
      : `MISSING — ${s.error || 'no report'}`;
    lines.push(`- ${status} **${s.name}** — ${detail}`);
  }
  lines.push('');

  // Warnings
  const errors = merged.warnings.filter(w => w.level === 'error');
  const warns = merged.warnings.filter(w => w.level === 'warning');
  if (errors.length > 0 || warns.length > 0) {
    lines.push('## Warnings');
    lines.push('');
    for (const w of [...errors, ...warns]) {
      const icon = w.level === 'error' ? '🔴' : '⚠️';
      lines.push(`- ${icon} ${w.message}`);
    }
    lines.push('');
  }

  // Unresolved refs
  if (merged.unresolved_refs.length > 0) {
    lines.push('## Unresolved Cross-Repo References');
    lines.push('');
    for (const u of merged.unresolved_refs) {
      const inferred = u.inferred_repo ? ` (expected in ${u.inferred_repo})` : '';
      lines.push(`- \`${u.tag}\` referenced in ${u.source_repo}${inferred}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

