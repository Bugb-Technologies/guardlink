/**
 * GuardLink — `guardlink ci`, the advisory CI face over two checks that already exist.
 *
 * There is no detection logic in this file and there must never be any. Both
 * questions it answers are answered elsewhere, by the one implementation the
 * rest of the product uses:
 *
 *   unmitigated exposures → `findUnmitigatedExposures` (parser/coverage.ts, D36)
 *   drifted `@source`     → `findAnchorDrift`         (parser/reanchor.ts, GL-505)
 *
 * A second copy of either predicate would be a tool that disagrees with
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
 * ── Reports, never repairs ──────────────────────────────────────────
 *
 * Read-only. `applyReanchor` is deliberately not called from here: rewriting an
 * anchor inside a CI run would move an annotation onto code nobody chose for
 * it, on a machine where nobody is watching.
 *
 * @flows ThreatModel -> #cli via runCiChecks -- "Parsed model checked for uncovered exposures"
 * @flows SourceFiles -> #cli via findAnchorDrift -- "Recorded anchors compared against current source"
 * @comment -- "Exit code is a pure function of (strict, exposures, drift) and lives in the summary, so JSON consumers see the same verdict the shell got"
 * @comment -- "Exposures and drift are serialized as the types the parser already produces — no renamed fields, so guardlink.ci/v1 cannot drift from the model it reports"
 */

import type { ThreatModel, ThreatModelExposure, Severity } from '../types/index.js';
import { findUnmitigatedExposures } from '../parser/coverage.js';
import { findAnchorDrift, type AnchorDrift } from '../parser/reanchor.js';
import { countAnchors } from '../parser/annotation-hash.js';

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
  summary: CiSummary;
}

export interface CiOptions {
  /** Opt in to a non-zero exit when either check finds anything. */
  strict?: boolean;
}

function countBySeverity(exposures: ThreatModelExposure[]): SeverityCounts {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 } as SeverityCounts;
  for (const e of exposures) counts[e.severity ?? 'unset'] += 1;
  return counts;
}

function countByKind(drift: AnchorDrift[]): DriftKindCounts {
  const counts = { moved: 0, symbol_gone: 0, file_gone: 0, line_gone: 0 } as DriftKindCounts;
  for (const d of drift) counts[d.kind] += 1;
  return counts;
}

/**
 * Run both checks and describe the result. The only place the exit code is
 * decided — one flag, one predicate.
 */
export function runCiChecks(root: string, model: ThreatModel, opts: CiOptions = {}): CiReport {
  const exposures = findUnmitigatedExposures(model);
  const drift = findAnchorDrift(root, model);
  const strict = opts.strict === true;
  const found = exposures.length > 0 || drift.length > 0;

  return {
    schema: CI_SCHEMA,
    exposures,
    drift,
    summary: {
      exposures: exposures.length,
      drift: drift.length,
      anchors: countAnchors(model),
      by_severity: countBySeverity(exposures),
      by_kind: countByKind(drift),
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

  out.push(`Unmitigated exposures: ${summary.exposures}${severityBreakdown(summary.by_severity)}`);
  out.push(summary.anchors === 0
    ? 'Anchor drift: 0 (no anchored @source blocks to check)'
    : `Anchor drift: ${summary.drift}${kindBreakdown(summary.by_kind)}`
      + ` of ${summary.anchors} anchor(s)`);

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

  if (exposures.length === 0 && drift.length === 0) {
    out.push('', '✓ No unmitigated exposures, no anchor drift.');
  } else if (!summary.strict) {
    out.push('', 'Advisory — nothing here failed the build. Run with --strict to gate on it.');
  }

  return out.join('\n');
}
