/**
 * GuardLink — `guardlink ci`, the advisory CI face over three checks that already exist.
 *
 * There is no detection logic in this file and there must never be any. Every
 * question it answers is answered elsewhere, by the one implementation the
 * rest of the product uses:
 *
 *   unmitigated exposures → `findUnmitigatedExposures` (parser/coverage.ts, D36)
 *   drifted `@source`     → `findAnchorDrift`         (parser/reanchor.ts, GL-505)
 *   stale claims          → `classifyClaims`             (parser/verification.ts)
 *   parse diagnostics     → `parseProject`              (parser/parse-project.ts)
 *
 * A second copy of any predicate would be a tool that disagrees with
 * `validate` about the same model, which is the defect D36 was written to end.
 *
 * ── Advisory, not blocking ──────────────────────────────────────────
 *
 * The default exit code is 0 with exposures present, with drift present, and
 * with both. That is deliberate: a first-run repo has unmitigated exposures by
 * construction — annotating a risk before its control exists is the intended
 * order of work — and a gate that fails the build on the day the annotations
 * land is a gate that gets deleted the same week. `--strict` is the opt-in for
 * teams who have reached zero and want to stay there.
 *
 * ── The fourth check, and why it was missing ────────────────────────
 *
 * `ci` used to answer three questions about a model and none about whether the
 * model was read correctly in the first place. That is the wrong end to be
 * silent at: an annotation the parser could not see is not an exposure, not a
 * drifted anchor and not a stale claim — it is nothing at all, and every count
 * above it looks healthier for its absence. A repository can be told it has
 * zero unmitigated exposures because six `@exposes` lines were written in a
 * comment form the parser drops.
 *
 * So the diagnostics the parse already produced are reported here, and they are
 * reported *first*, because they qualify everything after them. Warnings never
 * gate. Parse **errors** join the `--strict` predicate: a malformed annotation
 * is a claim someone wrote and nobody is holding, which is exactly what the
 * other three checks are for.
 *
 * ── Reports, never repairs ──────────────────────────────────────────
 *
 * Read-only. `applyReanchor` is deliberately not called from here: rewriting an
 * anchor inside a CI run would move an annotation onto code nobody chose for
 * it, on a machine where nobody is watching.
 *
 * @flows ThreatModel -> #cli via runCiChecks -- "Parsed model checked for uncovered exposures"
 * @flows ParseDiagnostics -> #cli via runCiChecks -- "Diagnostics from the parse are reported, never recomputed"
 * @flows SourceFiles -> #cli via findAnchorDrift -- "Recorded anchors compared against current source"
 * @flows LedgerFile -> #cli via readLedger -- "Recorded claim hashes, read only"
 * @comment -- "Exit code is a pure function of (strict, exposures, drift, demotable stale) and lives in the summary, so JSON consumers see the same verdict the shell got"
 * @comment -- "Exposures and drift are serialized as the types the parser already produces — no renamed fields, so guardlink.ci/v1 cannot drift from the model it reports"
 * @comment -- "The third check reads .guardlink/verified.json and never writes it; a corrupt ledger is reported once and treated as absent"
 */

import type {
  ThreatModel, ThreatModelExposure, Severity, ParseDiagnostic, DiagnosticCode,
} from '../types/index.js';
import { findUnmitigatedExposures } from '../parser/coverage.js';
import { findAnchorDrift, type AnchorDrift } from '../parser/reanchor.js';
import { countAnchors } from '../parser/annotation-hash.js';
import { readLedger, LEDGER_FILE, type LedgerEntry, type LedgerStatus } from '../parser/ledger.js';
import { classifyClaims, type ClaimRecord, type VerificationReport } from '../parser/verification.js';
import type { ClaimVerb } from '../parser/claim-key.js';

/** Schema identifier carried by every `--format json` payload. */
export const CI_SCHEMA = 'guardlink.ci/v1';

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const DRIFT_KINDS = ['moved', 'symbol_gone', 'file_gone', 'line_gone'] as const;

/** Severity buckets, plus `unset` for exposures written without one. */
export type SeverityCounts = Record<Severity | 'unset', number>;
export type DriftKindCounts = Record<AnchorDrift['kind'], number>;

export interface CiSummary {
  /** Unmitigated exposures — `exposures.length`. */
  exposures: number;
  /** Drifted `@source` blocks — `drift.length`. */
  drift: number;
  /**
   * Anchored `@source` blocks the drift check had to look at. Zero drift out of
   * zero anchors is not the same statement as zero drift out of sixty, and an
   * inline repo (or one whose anchors a migration discarded — D48) always
   * reports the first.
   */
  anchors: number;
  by_severity: SeverityCounts;
  by_kind: DriftKindCounts;
  /** Stale claims — `stale.length`. */
  stale: number;
  /** Claims whose hash matches the ledger. Carried as a count only. */
  verified: number;
  /** Claims with no ledger entry. Never affects the exit code. */
  unverified: number;
  /** Ledger entries with no matching claim. */
  orphans: number;
  stale_by_verb: Partial<Record<ClaimVerb, number>>;
  /** Stale mitigates + accepts — what `--strict` fails on. */
  demotable_stale: number;
  /** Whether stale mitigations were disregarded by coverage. Always false until demotion ships. */
  demote_stale: boolean;
  ledger: LedgerStatus;
  /**
   * Diagnostics the parse produced, by level. `parse_errors` gates under
   * `--strict`; `parse_warnings` never does.
   */
  parse_errors: number;
  parse_warnings: number;
  /** Every diagnostic code that occurred, with its count. Empty when the parse was clean. */
  parse_by_code: Partial<Record<DiagnosticCode | 'uncoded', number>>;
  /** Whether `--strict` was in effect for this run. */
  strict: boolean;
  /** The exit code the command used. 0 unless `strict` and something was found. */
  exit_code: 0 | 1;
}

export interface CiReport {
  schema: typeof CI_SCHEMA;
  /** `ThreatModelExposure` as the parser produced it — same fields, same names. */
  exposures: ThreatModelExposure[];
  /** `AnchorDrift` as `findAnchorDrift` produced it — same fields, same names. */
  drift: AnchorDrift[];
  stale: CiClaim[];
  unverified: CiClaim[];
  orphans: LedgerEntry[];
  /**
   * `ParseDiagnostic` as the parser produced it — same fields, same names, in
   * the order it produced them. Empty when no diagnostics were passed in, which
   * is indistinguishable in the payload from a clean parse; callers that want
   * the distinction should always pass what `parseProject` returned.
   */
  parse: ParseDiagnostic[];
  summary: CiSummary;
}

export interface CiOptions {
  /** Opt in to a non-zero exit when an exposure, a drifted anchor, a stale mitigation or acceptance, or a parse error is found. */
  strict?: boolean;
  /**
   * The diagnostics `parseProject` returned for the same model.
   *
   * Passed in rather than recomputed, for the reason at the top of this file:
   * a second parse is a second opinion, and `ci` is not allowed to hold one.
   * Optional so every existing caller keeps compiling and keeps its behaviour —
   * an omitted list reports as zero, exactly what `ci` reported before.
   */
  diagnostics?: ParseDiagnostic[];
}

/** A claim as `ci` reports it: no raw annotation text, no model record. */
export interface CiClaim {
  key: string;
  file: string;
  line: number;
  verb: ClaimVerb;
  claim: string;
  scope: 'symbol' | 'block' | 'file' | null;
  symbol: string | null;
  hint?: ClaimRecord['hint'];
  verified_by?: string;
  verified_at?: string;
}

function toCiClaim(c: ClaimRecord): CiClaim {
  const out: CiClaim = {
    key: c.key, file: c.location.file, line: c.location.line, verb: c.verb, claim: c.claim,
    scope: c.anchor?.scope ?? null, symbol: c.anchor?.symbol ?? null,
  };
  if (c.hint) out.hint = c.hint;
  if (c.entry) { out.verified_by = c.entry.verified_by; out.verified_at = c.entry.verified_at; }
  return out;
}

/** Demotable verbs first, then by file and line — the order a reviewer wants. */
function byUrgency(a: ClaimRecord, b: ClaimRecord): number {
  if (a.demotable !== b.demotable) return a.demotable ? -1 : 1;
  return a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line;
}

function countBySeverity(exposures: ThreatModelExposure[]): SeverityCounts {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 } as SeverityCounts;
  for (const e of exposures) counts[e.severity ?? 'unset'] += 1;
  return counts;
}

function countByCode(diagnostics: ParseDiagnostic[]): Partial<Record<DiagnosticCode | 'uncoded', number>> {
  const counts: Partial<Record<DiagnosticCode | 'uncoded', number>> = {};
  for (const d of diagnostics) {
    const key = d.code ?? 'uncoded';
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function countByKind(drift: AnchorDrift[]): DriftKindCounts {
  const counts = { moved: 0, symbol_gone: 0, file_gone: 0, line_gone: 0 } as DriftKindCounts;
  for (const d of drift) counts[d.kind] += 1;
  return counts;
}

/**
 * Run all three checks and describe the result. The only place the exit code
 * is decided — one flag, one predicate.
 */
export function runCiChecks(root: string, model: ThreatModel, opts: CiOptions = {}): CiReport {
  const exposures = findUnmitigatedExposures(model);
  const drift = findAnchorDrift(root, model);
  const read = readLedger(root);
  const verification: VerificationReport = classifyClaims(model, read);
  const staleRecords = verification.claims.filter(c => c.state === 'stale').sort(byUrgency);
  const unverifiedRecords = verification.claims.filter(c => c.state === 'unverified').sort(byUrgency);
  const strict = opts.strict === true;
  const parse = opts.diagnostics ?? [];
  const parseErrors = parse.filter(d => d.level === 'error' || d.level === 'fatal');
  const found = exposures.length > 0 || drift.length > 0
    || verification.summary.demotable_stale > 0 || parseErrors.length > 0;

  return {
    schema: CI_SCHEMA,
    exposures,
    drift,
    stale: staleRecords.map(toCiClaim),
    unverified: unverifiedRecords.map(toCiClaim),
    orphans: verification.orphans,
    parse,
    summary: {
      exposures: exposures.length,
      drift: drift.length,
      anchors: countAnchors(model),
      by_severity: countBySeverity(exposures),
      by_kind: countByKind(drift),
      stale: verification.summary.stale,
      verified: verification.summary.verified,
      unverified: verification.summary.unverified,
      orphans: verification.summary.orphans,
      stale_by_verb: verification.summary.stale_by_verb,
      demotable_stale: verification.summary.demotable_stale,
      demote_stale: false,
      parse_errors: parseErrors.length,
      parse_warnings: parse.length - parseErrors.length,
      parse_by_code: countByCode(parse),
      ledger: read.status,
      strict,
      exit_code: strict && found ? 1 : 0,
    },
  };
}

/** `critical 2, high 1` — only the buckets that have anything in them. */
function severityBreakdown(counts: SeverityCounts): string {
  const parts = [...SEVERITIES, 'unset' as const]
    .filter(s => counts[s] > 0)
    .map(s => `${s} ${counts[s]}`);
  return parts.length > 0 ? ` (${parts.join(', ')})` : '';
}

/** `unknown-verb 3, prose-like 1` — only the codes that occurred, commonest first. */
function codeBreakdown(counts: Partial<Record<string, number>>): string {
  const parts = Object.entries(counts)
    .filter((entry): entry is [string, number] => (entry[1] ?? 0) > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([c, n]) => `${c} ${n}`);
  return parts.length > 0 ? ` (${parts.join(', ')})` : '';
}

/** `moved 1, file_gone 2` — only the kinds that occurred. */
function kindBreakdown(counts: DriftKindCounts): string {
  const parts = DRIFT_KINDS.filter(k => counts[k] > 0).map(k => `${k} ${counts[k]}`);
  return parts.length > 0 ? ` (${parts.join(', ')})` : '';
}

/**
 * The human rendering: counts first, then the lines, in `validate`'s register.
 *
 * Returned as a string rather than printed so the same text is reachable from a
 * test without capturing a stream.
 */
export function formatCiReport(report: CiReport): string {
  const { summary, exposures, drift } = report;
  const out: string[] = [];

  // First, because it qualifies every count under it: a line the parser could
  // not read contributes to none of them.
  out.push(summary.parse_errors + summary.parse_warnings === 0
    ? 'Parse diagnostics: 0'
    : `Parse diagnostics: ${summary.parse_errors} error(s), ${summary.parse_warnings} warning(s)`
      + codeBreakdown(summary.parse_by_code));
  out.push(`Unmitigated exposures: ${summary.exposures}${severityBreakdown(summary.by_severity)}`);
  out.push(summary.anchors === 0
    ? 'Anchor drift: 0 (no anchored @source blocks to check)'
    : `Anchor drift: ${summary.drift}${kindBreakdown(summary.by_kind)}`
      + ` of ${summary.anchors} anchor(s)`);

  if (summary.ledger === 'absent') {
    out.push('Stale claims: none recorded — run `guardlink verify --all` to start tracking');
  } else if (summary.ledger === 'corrupt') {
    out.push(`Stale claims: ledger unreadable (${LEDGER_FILE}) — see guardlink validate`);
  } else {
    const verbs = Object.entries(summary.stale_by_verb).filter(([, n]) => (n ?? 0) > 0).map(([v, n]) => `${v} ${n}`);
    out.push(`Stale claims: ${summary.stale}${verbs.length > 0 ? ` (${verbs.join(', ')})` : ''}`
      + ` of ${summary.stale + summary.verified} recorded claim(s); unverified ${summary.unverified}; orphans ${summary.orphans}`);
  }

  if (report.parse.length > 0) {
    // Diagnostics are already collapsed per (file, token) by the parser, so
    // this list is bounded by distinct problems rather than by lines. Printed
    // in full for the same reason `validate` prints them in full: a parse
    // diagnostic names one line someone has to go and look at.
    out.push('', `⚠  ${report.parse.length} parse diagnostic(s) — annotations on these lines are not in the model:`);
    for (const d of report.parse) {
      out.push(`   [${d.level}] ${d.file}:${d.line}  ${d.message}`);
    }
  }

  if (exposures.length > 0) {
    out.push('', `⚠  ${exposures.length} unmitigated exposure(s):`);
    for (const e of exposures) {
      const at = `${e.location.file}:${e.location.line}`;
      out.push(`   ${e.asset} → ${e.threat} [${e.severity || 'unset'}] (${at})`);
    }
  }

  if (drift.length > 0) {
    out.push('', `⚠  ${drift.length} drifted @source block(s):`);
    for (const d of drift) {
      out.push(`   [${d.kind}] ${d.message}`);
    }
  }

  if (report.stale.length > 0) {
    out.push('', `⚠  ${report.stale.length} stale claim(s) — the code beneath them changed since verification:`);
    for (const c of report.stale) {
      const who = c.verified_at && c.verified_by ? `, verified ${c.verified_at.slice(0, 10)} by ${c.verified_by}` : '';
      const where = c.symbol ?? (c.scope === 'file' ? 'whole file' : 'block');
      const hint = c.hint === 'symbol-renamed' ? ' [symbol renamed]' : '';
      out.push(`   ${c.file}:${c.line}  @${c.verb} ${c.claim}  (${where}${who})${hint}`);
    }
  }

  const clean = exposures.length === 0 && drift.length === 0 && report.stale.length === 0
    && report.parse.length === 0;
  if (clean) {
    out.push('', `✓ No unmitigated exposures, no anchor drift.${summary.ledger === 'present' ? ' No stale claims.' : ''}`);
  } else if (!summary.strict) {
    out.push('', 'Advisory — nothing here failed the build. Run with --strict to gate on it.');
  }

  return out.join('\n');
}
