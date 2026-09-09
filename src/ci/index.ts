/**
 * GuardLink — `guardlink ci`, the CI face over checks that already exist.
 *
 * There is no detection logic in this file and there must never be any. Every
 * question it answers is answered elsewhere, by the one implementation the
 * rest of the product uses:
 *
 *   unmitigated exposures → `findUnmitigatedExposures` (parser/coverage.ts, D36)
 *   drifted `@source`     → `findAnchorDrift`         (parser/reanchor.ts, GL-505)
 *   stale claims          → `classifyClaims`             (parser/verification.ts)
 *   parse diagnostics     → `parseProject`              (parser/parse-project.ts)
 *   reproduced exploits   → `model.confirmed`           (the @confirmed records themselves)
 *   acceptance quality    → `findAcceptanceDefects`     (parser/acceptance.ts)
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
 * ── The fifth and sixth checks: what a gate is bought with ──────────
 *
 * Measured on OWASP NodeGoat: one generated file of 67 blanket `@accepts` lines
 * plus `guardlink reanchor --apply` took `--strict` from exit 1 to exit 0 —
 * "✓ No unmitigated exposures, no anchor drift" — while **eight `@confirmed`
 * reproduced exploits** sat untouched in the same model, because the predicate
 * had no `@confirmed` input and no acceptance-quality input. A repository with
 * eight verified exploits on the board passed a strict gate in under a second of
 * tool time, with one text file and no code change.
 *
 * Both holes are now closed here, and they close in different ways on purpose:
 *
 *   `@confirmed` gates UNCONDITIONALLY. It is not an opinion about risk, it is
 *   a record that somebody reproduced the exploit — and `@accepts` deliberately
 *   does not silence one (`analyzer/sarif.ts` keeps emitting it), so a gate that
 *   ignored it was ignoring the one finding class nothing else can suppress. The
 *   way to clear it is to delete the annotation when the exploit no longer
 *   reproduces: a visible deletion in a diff, which is what re-verification looks
 *   like, rather than a line someone appends.
 *
 *   An UNQUALIFIED ACCEPTANCE does not count as an acceptance. Attribution,
 *   justification and a horizon are checked by `parser/acceptance.ts`, and an
 *   acceptance that fails is dropped from the coverage index — so its exposures
 *   come back into `exposures` rather than being reported in some parallel list
 *   the exit code does not read.
 *
 * ── Severity and scope: why a gate needs an off-ramp ────────────────
 *
 * `--strict` on a real repository is red on day one and green never — 111
 * exposures and 52 drifts on NodeGoat — and that is how a gate gets deleted
 * rather than adopted. `--severity` and `--scope` are the two narrowings that
 * make it adoptable, and both are additive over data the report already carried.
 *
 * They narrow different things, and the split is deliberate. `--severity` filters
 * RISK findings — unmitigated exposures and confirmed exploits — because those
 * are the ones severity means something for. It does NOT filter drift, parse
 * errors, stale claims or unqualified acceptances: those are INTEGRITY findings
 * about whether the model can be read and trusted at all, none of them carries a
 * severity, and a team that says "gate on critical only" has said nothing about
 * whether their annotations parse or whether their acceptances have names on
 * them. `--scope` filters everything, because everything has a file, and "this
 * pipeline owns services/api/" is a statement about all of it.
 *
 * ── Reports, never repairs ──────────────────────────────────────────
 *
 * Read-only. `applyReanchor` is deliberately not called from here: rewriting an
 * anchor inside a CI run would move an annotation onto code nobody chose for
 * it, on a machine where nobody is watching.
 *
 * @flows ThreatModel -> #cli via runCiChecks -- "Parsed model checked for uncovered exposures, confirmed exploits and unqualified acceptances"
 * @flows ParseDiagnostics -> #cli via runCiChecks -- "Diagnostics from the parse are reported, never recomputed"
 * @flows SourceFiles -> #cli via findAnchorDrift -- "Recorded anchors compared against current source"
 * @flows LedgerFile -> #cli via readLedger -- "Recorded claim hashes, read only"
 * @comment -- "Exit code is a pure function of (strict, exposures, confirmed, drift, demotable stale, parse errors, unqualified acceptances) and lives in the summary, so JSON consumers see the same verdict the shell got"
 * @comment -- "Exposures and drift are serialized as the types the parser already produces — no renamed fields, so guardlink.ci/v1 cannot drift from the model it reports"
 * @comment -- "The third check reads .guardlink/verified.json and never writes it; a corrupt ledger is reported once and treated as absent"
 * @comment -- "@confirmed is not filtered by acceptance state at all: @accepts does not silence a reproduced exploit anywhere else in the product and must not do so here"
 * @comment -- "--severity narrows risk findings only; drift, parse errors, stale claims and unqualified acceptances carry no severity and a severity threshold says nothing about them"
 */

import type {
  ThreatModel, ThreatModelExposure, ThreatModelConfirmed, Severity, ParseDiagnostic, DiagnosticCode,
} from '../types/index.js';
import { findUnmitigatedExposures } from '../parser/coverage.js';
import {
  findAcceptanceDefects, DEFAULT_ACCEPTANCE_POLICY,
  type AcceptanceFinding, type AcceptancePolicy,
} from '../parser/acceptance.js';
import { findAnchorDrift, type AnchorDrift } from '../parser/reanchor.js';
import { countAnchors } from '../parser/annotation-hash.js';
import { readLedger, LEDGER_FILE, type LedgerEntry, type LedgerStatus } from '../parser/ledger.js';
import { classifyClaims, type ClaimRecord, type VerificationReport } from '../parser/verification.js';
import type { ClaimVerb } from '../parser/claim-key.js';

/**
 * Schema identifier carried by every `--format json` payload.
 *
 * Still v1 after the confirmed/acceptance/severity/scope additions: every field
 * v1 carried is present, unrenamed, and means what it meant. A consumer reading
 * `summary.exposures` gets a larger number on a repo whose acceptances do not
 * qualify, which is a change in the ANSWER and not in the shape — and it is the
 * change the gate exists to make. New keys (`confirmed`, `unqualified_acceptances`,
 * `filters`) are additive.
 */
export const CI_SCHEMA = 'guardlink.ci/v1';

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const DRIFT_KINDS = ['moved', 'symbol_gone', 'file_gone', 'line_gone'] as const;

/** Severity buckets, plus `unset` for exposures written without one. */
export type SeverityCounts = Record<Severity | 'unset', number>;
export type DriftKindCounts = Record<AnchorDrift['kind'], number>;

/**
 * What a run was narrowed to. Echoed into the payload because a green gate that
 * only looked at `critical` in `services/api/` is a different claim from a green
 * gate that looked at everything, and the JSON is where a reader finds out which
 * one they have.
 */
export interface CiFilters {
  /** Severities the risk findings were narrowed to. Null when unfiltered. */
  severity: Severity[] | null;
  /** Path prefixes every finding was narrowed to. Null when unfiltered. */
  scope: string[] | null;
  /** Risk findings dropped by `--severity`. Reported, never silently gone. */
  excluded_by_severity: number;
  /** Findings of every kind dropped by `--scope`. */
  excluded_by_scope: number;
}

export interface CiSummary {
  /** Unmitigated exposures — `exposures.length`. */
  exposures: number;
  /**
   * Reproduced exploits — `confirmed.length`. Gates under `--strict` on its own,
   * and is not reduced by any acceptance: `@accepts` does not silence a
   * `@confirmed` anywhere in the product.
   */
  confirmed: number;
  /** Acceptances that do not meet the policy — `unqualified_acceptances.length`. */
  unqualified_acceptances: number;
  /** Every `@accepts` in the model, qualified or not. The denominator for the line above. */
  acceptances: number;
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
  /** What this run was narrowed to, and what that narrowing dropped. */
  filters: CiFilters;
  /** The exit code the command used. 0 unless `strict` and something was found. */
  exit_code: 0 | 1;
}

export interface CiReport {
  schema: typeof CI_SCHEMA;
  /** `ThreatModelExposure` as the parser produced it — same fields, same names. */
  exposures: ThreatModelExposure[];
  /** `ThreatModelConfirmed` as the parser produced it — reproduced exploits. */
  confirmed: ThreatModelConfirmed[];
  /** Acceptances the policy refused, each with what is wrong with it. */
  unqualified_acceptances: AcceptanceFinding[];
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
  /** Opt in to a non-zero exit when any check finds something to gate on. */
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
  /**
   * Gate only on risk findings at these severities. Omitted means all of them,
   * INCLUDING exposures written with no severity at all — an unrated risk is not
   * a low one, and dropping it by default would make `--severity` a way to hide
   * findings by forgetting a bracket.
   */
  severity?: Severity[];
  /**
   * Gate only on findings under these root-relative path prefixes.
   *
   * Prefix match on path segments, so `app` matches `app/routes/x.js` and not
   * `application.js`. A finding with no file (there are none today, but the
   * types allow one) is kept: a gate must not drop what it cannot place.
   */
  scope?: string[];
  /**
   * The acceptance policy to hold acceptances to. Defaults to the built-in one;
   * `guardlink ci` passes what `.guardlink/config.json` declares.
   */
  policy?: AcceptancePolicy;
  /** The clock. A parameter so a test can pin it and so one run uses one midnight. */
  now?: Date;
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
 * Path-prefix match on segment boundaries.
 *
 * `app` matches `app/routes/x.js`, and `app.js` does not match `application.js`.
 * A substring test would have made `--scope app` quietly gate on a file the
 * caller did not name, which is the same class of silent-wrong-answer the rest
 * of this file exists to close.
 */
function underScope(file: string | undefined, scope: string[] | null): boolean {
  if (!scope || scope.length === 0) return true;
  if (!file) return true; // Cannot be placed; must not be dropped.
  const path = file.replaceAll('\\', '/').replace(/^\.\//, '');
  return scope.some(prefix => {
    const p = prefix.replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, '');
    return p === '' || path === p || path.startsWith(p + '/');
  });
}

function atSeverity(severity: Severity | undefined, allowed: Severity[] | null): boolean {
  // An exposure with no severity is UNRATED, not low. It survives every
  // threshold, because the alternative is a gate you pass by omitting a bracket.
  if (!allowed || allowed.length === 0 || severity === undefined) return true;
  return allowed.includes(severity);
}

/**
 * Run every check and describe the result. The only place the exit code is
 * decided — one flag, one predicate.
 */
export function runCiChecks(root: string, model: ThreatModel, opts: CiOptions = {}): CiReport {
  const strict = opts.strict === true;
  const now = opts.now ?? new Date();
  const policy = opts.policy ?? DEFAULT_ACCEPTANCE_POLICY;
  const severity = opts.severity && opts.severity.length > 0 ? opts.severity : null;
  const scope = opts.scope && opts.scope.length > 0 ? opts.scope : null;

  // The acceptance policy is passed INTO coverage rather than applied after it,
  // so a refused acceptance's exposures come back in `exposures` — the number the
  // exit code already reads — instead of in a parallel list nothing gates on.
  const allExposures = findUnmitigatedExposures(model, { policy, now });
  const allConfirmed = model.confirmed || [];
  const allUnqualified = findAcceptanceDefects(model, policy, now);

  const scopedExposures = allExposures.filter(e => underScope(e.location.file, scope));
  const scopedConfirmed = allConfirmed.filter(c => underScope(c.location.file, scope));
  const exposures = scopedExposures.filter(e => atSeverity(e.severity, severity));
  const confirmed = scopedConfirmed.filter(c => atSeverity(c.severity, severity));

  // Scoped, not severity-filtered — an unqualified acceptance is an INTEGRITY
  // finding, in the same family as drift and a parse error, and severity does
  // not filter those either. It is not a statement about how bad a risk is; it
  // is a statement that a governance record in this repository is not one. A
  // team that set `--severity critical` said what risks they gate on, not that
  // they stopped caring whether their acceptances have names on them.
  //
  // It also has to keep its teeth after the exposures are fixed: without this
  // term, 67 junk `@accepts` lines could sit in a tree forever and the gate
  // would go quiet the moment the last exposure was mitigated.
  const unqualified = allUnqualified.filter(f => underScope(f.file, scope));

  const drift = findAnchorDrift(root, model).filter(d => underScope(d.file, scope));
  const read = readLedger(root);
  const verification: VerificationReport = classifyClaims(model, read);
  const staleRecords = verification.claims
    .filter(c => c.state === 'stale' && underScope(c.location.file, scope)).sort(byUrgency);
  const unverifiedRecords = verification.claims
    .filter(c => c.state === 'unverified' && underScope(c.location.file, scope)).sort(byUrgency);
  const demotableStale = staleRecords.filter(c => c.demotable).length;
  // Recomputed from the scoped records rather than taken from the whole-model
  // summary: a breakdown that does not add up to the count beside it is worse
  // than no breakdown.
  const staleByVerb: Partial<Record<ClaimVerb, number>> = {};
  for (const c of staleRecords) staleByVerb[c.verb] = (staleByVerb[c.verb] ?? 0) + 1;

  const parse = (opts.diagnostics ?? []).filter(d => underScope(d.file, scope));
  const parseErrors = parse.filter(d => d.level === 'error' || d.level === 'fatal');

  const found = exposures.length > 0
    || confirmed.length > 0
    || unqualified.length > 0
    || drift.length > 0
    || demotableStale > 0
    || parseErrors.length > 0;

  return {
    schema: CI_SCHEMA,
    exposures,
    confirmed,
    unqualified_acceptances: unqualified,
    drift,
    stale: staleRecords.map(toCiClaim),
    unverified: unverifiedRecords.map(toCiClaim),
    orphans: verification.orphans,
    parse,
    summary: {
      exposures: exposures.length,
      confirmed: confirmed.length,
      unqualified_acceptances: unqualified.length,
      acceptances: model.acceptances.length,
      drift: drift.length,
      anchors: countAnchors(model),
      by_severity: countBySeverity(exposures),
      by_kind: countByKind(drift),
      stale: staleRecords.length,
      verified: verification.summary.verified,
      unverified: unverifiedRecords.length,
      orphans: verification.summary.orphans,
      stale_by_verb: staleByVerb,
      demotable_stale: demotableStale,
      demote_stale: false,
      parse_errors: parseErrors.length,
      parse_warnings: parse.length - parseErrors.length,
      parse_by_code: countByCode(parse),
      ledger: read.status,
      strict,
      filters: {
        severity,
        scope,
        excluded_by_severity:
          (scopedExposures.length - exposures.length) + (scopedConfirmed.length - confirmed.length),
        excluded_by_scope:
          (allExposures.length - scopedExposures.length)
          + (allConfirmed.length - scopedConfirmed.length)
          + (allUnqualified.length - unqualified.length),
      },
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
  const { summary, exposures, confirmed, drift } = report;
  const out: string[] = [];

  // What this run was narrowed to, before any count — a number under a filter
  // means something different from the same number without one, and the reader
  // has to know which they are looking at before they read it.
  const { filters } = summary;
  if (filters.severity || filters.scope) {
    const parts: string[] = [];
    if (filters.severity) parts.push(`severity ${filters.severity.join(',')}`);
    if (filters.scope) parts.push(`scope ${filters.scope.join(', ')}`);
    const dropped = filters.excluded_by_severity + filters.excluded_by_scope;
    out.push(`Narrowed to ${parts.join('; ')}`
      + (dropped > 0 ? ` — ${dropped} finding(s) outside it, not gated on` : ''));
  }

  // Then, because it qualifies every count under it: a line the parser could
  // not read contributes to none of them.
  out.push(summary.parse_errors + summary.parse_warnings === 0
    ? 'Parse diagnostics: 0'
    : `Parse diagnostics: ${summary.parse_errors} error(s), ${summary.parse_warnings} warning(s)`
      + codeBreakdown(summary.parse_by_code));
  out.push(`Unmitigated exposures: ${summary.exposures}${severityBreakdown(summary.by_severity)}`);
  out.push(`Confirmed exploits: ${summary.confirmed}`);
  out.push(summary.acceptances === 0
    ? 'Acceptances: 0'
    : `Acceptances: ${summary.acceptances} in the model; `
      + `${summary.unqualified_acceptances} do not count as acceptances`
      + `${summary.filters.scope ? ' (in scope)' : ''}`);
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

  // Confirmed first, above the exposures: a reproduced exploit is the only
  // finding here that somebody has already proved, and burying it under 111
  // theoretical ones is how it went unnoticed for as long as it did.
  if (confirmed.length > 0) {
    out.push('', `✗  ${confirmed.length} CONFIRMED exploit(s) — reproduced, not theoretical:`);
    for (const c of confirmed) {
      const at = `${c.location.file}:${c.location.line}`;
      out.push(`   ${c.asset} ← ${c.threat} [${c.severity || 'unset'}] (${at})`);
      if (c.description) out.push(`      "${c.description}"`);
    }
    out.push('   No acceptance silences these. Fix the code, or delete the @confirmed');
    out.push('   line when the exploit no longer reproduces — that deletion is the claim.');
  }

  if (exposures.length > 0) {
    out.push('', `⚠  ${exposures.length} unmitigated exposure(s):`);
    for (const e of exposures) {
      const at = `${e.location.file}:${e.location.line}`;
      out.push(`   ${e.asset} → ${e.threat} [${e.severity || 'unset'}] (${at})`);
    }
  }

  if (report.unqualified_acceptances.length > 0) {
    out.push('', `⚠  ${report.unqualified_acceptances.length} acceptance(s) that do not count —`
      + ' the exposures they name are listed above as unmitigated:');
    for (const f of report.unqualified_acceptances) {
      out.push(`   ${f.file}:${f.line}  ${f.message}`);
    }
    out.push('   Re-decide them with: guardlink review . --accept <id> --by "<name>"'
      + ' --justification "<why>" --until <YYYY-MM-DD>');
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

  const clean = exposures.length === 0 && confirmed.length === 0 && drift.length === 0
    && report.unqualified_acceptances.length === 0 && report.stale.length === 0
    && report.parse.length === 0;
  if (clean) {
    out.push('', '✓ No unmitigated exposures, no confirmed exploits, no anchor drift,'
      + ` every acceptance accounted for.${summary.ledger === 'present' ? ' No stale claims.' : ''}`);
  } else if (!summary.strict) {
    out.push('', 'Advisory — nothing here failed the build. Run with --strict to gate on it.');
  }

  return out.join('\n');
}
