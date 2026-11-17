/**
 * GuardLink Workspace — Report metadata population.
 *
 * Enriches a ThreatModel with provenance metadata (git SHA, branch,
 * workspace info) for the report JSON contract.
 *
 * @asset Workspace.Metadata (#report-metadata) -- "Report provenance data"
 * @flows GitRepo -> #report-metadata via execFileSync -- "Git info extraction"
 * @flows #report-metadata -> ThreatModel via populateMetadata -- "Metadata injection"
 * @flows GitConfig -> #report-metadata via readVersionControl -- "remote.origin.url, HEAD and branch for SARIF versionControlProvenance"
 * @exposes #report-metadata to #data-exposure [low] cwe:CWE-200 -- "remote.origin.url may embed user:token@host credentials, and the SARIF it lands in is uploaded to code scanning"
 * @mitigates #report-metadata against #data-exposure using #key-redaction -- "readVersionControl keeps only linksFromRemote().web, rebuilt from hostname and path; userinfo is dropped, and a remote that is not http(s)/ssh yields no provenance at all"
 */

import { LineCounter, parseDocument, stringify } from 'yaml';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { computeAnnotationHash } from '../parser/annotation-hash.js';
import { getPackageVersion } from '../version.js';
import type { ThreatModel, ReportMetadata, ReportParseState, ParseDiagnostic } from '../types/index.js';
import type { WorkspaceConfig } from './types.js';
import { linksFromRemote } from '../dashboard/links.js';

/**
 * Current report JSON schema version.
 *
 * 1.1.0 — model version 1.2.0 reshaped `coverage`: `annotated_symbols` became
 * `annotation_count`, and the two permanently-constant fields beside it were
 * removed. `detectSchemaMismatch` compares this string across the reports being
 * merged, so leaving it at 1.0.0 made a mixed-version merge undetectable by the
 * one mechanism built to detect exactly that.
 *
 * NOT bumped for the optional `metadata.parse` field. It is purely additive —
 * every key 1.1.0 carried is present and unrenamed — and a mixed estate is
 * already handled correctly by design: a report without it counts toward
 * `repos_parse_unknown` rather than toward clean. Bumping would make every
 * estate holding one not-yet-regenerated repo emit a `schema_mismatch` warning
 * saying results may be inconsistent, which would be false, and would train
 * readers to ignore the warning that exists for real reshapes.
 */
export const REPORT_SCHEMA_VERSION = '1.1.0';

/**
 * Read HEAD straight out of `.git`.
 *
 * `populateMetadata` shells out to `git rev-parse`, which is fine once per
 * report but not once per tool call. Two small file reads cost microseconds and
 * cannot go stale the way a cached subprocess result would.
 */
export function readGitSha(root: string): string | null {
  const sha = /^[0-9a-f]{40}$/;
  try {
    const head = readFileSync(join(root, '.git', 'HEAD'), 'utf-8').trim();
    if (!head.startsWith('ref: ')) return sha.test(head) ? head : null;

    const ref = head.slice(5).trim();
    try {
      const direct = readFileSync(join(root, '.git', ref), 'utf-8').trim();
      if (sha.test(direct)) return direct;
    } catch { /* ref is packed */ }

    const packed = readFileSync(join(root, '.git', 'packed-refs'), 'utf-8');
    for (const line of packed.split('\n')) {
      const [hash, name] = line.trim().split(/\s+/);
      if (name === ref && sha.test(hash)) return hash;
    }
    return null;
  } catch {
    // Not a git checkout, or `.git` is a file (worktree / submodule). Reporting
    // null is honest; guessing would defeat the point of the field.
    return null;
  }
}

/**
 * Get git commit SHA (full) for the given directory.
 * Returns null if not a git repo.
 */
function getCommitSha(root: string): string | null {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf-8', stdio: 'pipe' }).trim();
  } catch {
    return null;
  }
}

/**
 * Get current git branch name.
 * Returns null if detached HEAD or not a git repo.
 */
function getBranch(root: string): string | null {
  try {
    const branch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: root, encoding: 'utf-8', stdio: 'pipe' }).trim();
    return branch === 'HEAD' ? null : branch; // detached HEAD
  } catch {
    return null;
  }
}

/**
 * Where a SARIF export is cut from: the repository's web URL, HEAD and branch.
 *
 * Null when the repository has no origin that `linksFromRemote` accepts — not a
 * git checkout, no `origin`, or a local-path remote. SARIF requires a
 * `repositoryUri` on every `versionControlProvenance` entry, so without one
 * there is nothing honest to write. The URL is rebuilt from hostname and path
 * only, so credentials embedded in the remote never reach the export.
 */
export function readVersionControl(root: string): { repositoryUri: string; revisionId: string | null; branch: string | null } | null {
  let remote: string;
  try {
    remote = execFileSync('git', ['config', '--get', 'remote.origin.url'], { cwd: root, encoding: 'utf-8', stdio: 'pipe' }).trim();
  } catch {
    return null;
  }
  const links = remote ? linksFromRemote(remote) : null;
  if (!links) return null;
  return { repositoryUri: links.web, revisionId: getCommitSha(root), branch: getBranch(root) };
}

/** A present manifest that could not be read or decoded, with its actionable cause. */
export class WorkspaceConfigError extends Error {
  constructor(readonly file: string, readonly problem: string, readonly line = 1) {
    super(`${file}:${line}: ${problem}`);
    this.name = 'WorkspaceConfigError';
  }
}

/**
 * Read the GuardLink-owned YAML manifest. JSON is a supported YAML representation.
 * Legacy callers get null for an invalid file; discovery asks for a named error.
 *
 * @flows ConfigFile -> #workspace-config via loadWorkspaceConfig -- "Decode workspace.yaml as YAML, including JSON-form documents"
 * @mitigates #workspace-config against #config-tamper using #yaml-validation -- "Bounded YAML alias expansion and explicit manifest shape checks; strict reads name the invalid file and its decoding or filesystem problem"
 */
export function loadWorkspaceConfig(root: string, options: { strict?: boolean } = {}): WorkspaceConfig | null {
  const yamlPath = join(root, '.guardlink', 'workspace.yaml');
  try {
    return parseWorkspaceYaml(readFileSync(yamlPath, 'utf-8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    if (options.strict) {
      const cause = error as Error & { line?: number };
      throw new WorkspaceConfigError(yamlPath, cause.message, cause.line ?? 1);
    }
    return null;
  }
}

/** Decode any YAML document with the workspace manifest shape, without executing tags. */
export function parseWorkspaceYaml(content: string): WorkspaceConfig {
  const lineCounter = new LineCounter();
  const doc = parseDocument(content, { lineCounter, prettyErrors: false });
  if (doc.errors.length) {
    const error = doc.errors[0];
    throw Object.assign(new Error(error.message), { line: lineCounter.linePos(error.pos[0]).line });
  }
  const value: unknown = doc.toJS({ maxAliasCount: 100 });
  const mapping = (v: unknown, field: string): Record<string, unknown> => {
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error(`${field} must be a mapping`);
    return v as Record<string, unknown>;
  };
  const text = (v: unknown, field: string): string => {
    if (typeof v !== 'string' || !v.trim()) throw new Error(`${field} must be a non-empty string`);
    return v;
  };
  const data = mapping(value, 'workspace manifest');
  const workspace = text(data.workspace, 'workspace');
  const this_repo = text(data.this_repo, 'this_repo');
  if (!Array.isArray(data.repos)) throw new Error('repos must be a list of member mappings');
  const repos = data.repos.map((value, i) => {
    const repo = mapping(value, `repos[${i}]`);
    return {
      name: text(repo.name, `repos[${i}].name`),
      ...(repo.registry != null ? { registry: text(repo.registry, `repos[${i}].registry`) } : {}),
    };
  });
  if (new Set(repos.map(r => r.name)).size !== repos.length) throw new Error('repos must have unique member names');
  return {
    workspace, this_repo, repos,
    ...(data.shared_definitions != null ? { shared_definitions: text(data.shared_definitions, 'shared_definitions') } : {}),
  };
}

/** Emit the canonical GuardLink-owned YAML format, quoting scalars when necessary. */
export function serializeWorkspaceYaml(config: WorkspaceConfig): string {
  return stringify({
    workspace: config.workspace,
    this_repo: config.this_repo,
    repos: config.repos.map(repo => ({ name: repo.name, ...(repo.registry ? { registry: repo.registry } : {}) })),
    ...(config.shared_definitions ? { shared_definitions: config.shared_definitions } : {}),
  }, { lineWidth: 0 });
}

/**
 * Enrich a ThreatModel with provenance metadata.
 * Call this before writing the report JSON.
 */
/**
 * The three numbers `ci` reports about a parse, in the shape a report carries.
 *
 * `unparsed_annotations` counts LINES, not diagnostics: the parser collapses
 * repeats per (file, token), so one unreadable comment convention is one
 * diagnostic standing for however many annotations were written in it.
 */
export function summarizeParse(diagnostics: ParseDiagnostic[]): ReportParseState {
  let errors = 0;
  let warnings = 0;
  let unparsed = 0;
  for (const d of diagnostics) {
    if (d.level === 'error' || d.level === 'fatal') errors += 1; else warnings += 1;
    unparsed += d.occurrences && d.occurrences > 1 ? d.occurrences : 1;
  }
  return { errors, warnings, unparsed_annotations: unparsed };
}

export function populateMetadata(
  model: ThreatModel,
  root: string,
  diagnostics?: ParseDiagnostic[],
): ThreatModel {
  const workspace = loadWorkspaceConfig(root);

  const metadata: ReportMetadata = {
    schema_version: REPORT_SCHEMA_VERSION,
    guardlink_version: getPackageVersion(),
    repo: workspace?.this_repo || model.project,
    commit_sha: getCommitSha(root),
    branch: getBranch(root),
    generated_at: model.generated_at,
    annotation_hash: computeAnnotationHash(model),
    ...(workspace?.workspace && { workspace: workspace.workspace }),
    // Omitted entirely when the caller did not pass the parse it came from.
    // Absent means UNKNOWN downstream, and a zero would mean "read cleanly" —
    // a distinction a merged estate's verdict depends on, so it must not be
    // erased by a default here.
    ...(diagnostics && { parse: summarizeParse(diagnostics) }),
  };

  return {
    ...model,
    metadata,
    external_refs: model.external_refs || [],
  };
}
