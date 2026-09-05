/**
 * GuardLink Dashboard — Data transformation.
 * Converts ThreatModel into dashboard-ready statistics.
 */

import type { ThreatModel } from '../types/index.js';
import { buildCoverageIndex, annotationCount } from '../parser/coverage.js';
import { entriesFromModel, summarise } from '../blame/summary.js';
import { readLedger } from '../parser/ledger.js';
import { classifyClaims, type ClaimState, type VerificationReport } from '../parser/verification.js';
import type { AgentSummaryRow, CommitCounts, CommitRef, Cohort, HotFile, HumanSummaryRow, TrendBucket } from '../blame/types.js';

// D57: a private `normalizeRef` lived here — it stripped `#` but, unlike the
// canonical one in parser/coverage.ts, did not case-fold. Even the normaliser
// had been reimplemented, and the copy was weaker. It died with the pair set.

export interface DashboardStats {
  annotations: number;
  sourceFiles: number;
  assets: number;
  threats: number;
  controls: number;
  mitigations: number;
  exposures: number;
  confirmed: number;
  acceptances: number;
  actors: number;
  entitlements: number;
  entitlementsInert: number;
  transfers: number;
  flows: number;
  boundaries: number;
  validations: number;
  ownership: number;
  audits: number;
  assumptions: number;
  shields: number;
  comments: number;
  coveragePercent: number;
  coverageAnnotated: number;
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unset: number;
}

export interface ExposureRow {
  asset: string;
  threat: string;
  severity: string;
  description: string;
  file: string;
  line: number;
  mitigated: boolean;
  accepted: boolean;
}

export interface ConfirmedRow {
  threat: string;
  asset: string;
  severity: string;
  description: string;
  file: string;
  line: number;
  external_refs: string[];
}

export interface AssetHeatmapEntry {
  /** The declared `#id` when the asset has one, else its dotted path or the reference as written. */
  name: string;
  /** Every form the model refers to this asset by (`#id`, dotted path, as written); the feature filter and the drawer match on these. */
  aliases: string[];
  exposures: number;
  mitigations: number;
  flows: number;
  dataHandling: string[];
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
}

/**
 * Counts, straight off the model — which means they describe whatever the model
 * describes. On a model narrowed by `--feature` that is one feature, and three
 * of these fields change meaning rather than value: `annotations`, `sourceFiles`
 * and `coveragePercent` come from `annotations_parsed`, `source_files` and
 * `coverage`, all of which the filter rescopes. Only `coveragePercent` is
 * rendered, and `renderCodePage`/the top bar withhold it on a slice, because
 * "annotated files over source files" measures a repository and a slice's
 * answer to it is 100% by construction. Nothing to fix here; the caller decides
 * what a number is allowed to claim.
 *
 * @comment -- "Stats mirror the model's own scope: on a --feature model these are the feature's numbers, and the dashboard suppresses the ones that only mean something project-wide"
 */
export function computeStats(model: ThreatModel): DashboardStats {
  return {
    annotations: model.annotations_parsed,
    sourceFiles: model.source_files,
    assets: model.assets.length,
    threats: model.threats.length,
    controls: model.controls.length,
    mitigations: model.mitigations.length,
    exposures: model.exposures.length,
    confirmed: model.confirmed.length,
    acceptances: model.acceptances.length,
    actors: (model.actors || []).length,
    entitlements: (model.entitlements || []).length,
    entitlementsInert: (model.entitlements || []).filter(e => e.inert).length,
    transfers: model.transfers.length,
    flows: model.flows.length,
    boundaries: model.boundaries.length,
    validations: model.validations.length,
    ownership: model.ownership.length,
    audits: model.audits.length,
    assumptions: model.assumptions.length,
    shields: model.shields.length,
    comments: model.comments.length,
    coveragePercent: model.coverage.coverage_percent,
    coverageAnnotated: annotationCount(model),
  };
}

export function computeSeverity(model: ThreatModel): SeverityBreakdown {
  const result: SeverityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  for (const e of model.exposures) {
    const sev = (e.severity || '').toLowerCase();
    if (sev === 'critical' || sev === 'p0') result.critical++;
    else if (sev === 'high' || sev === 'p1') result.high++;
    else if (sev === 'medium' || sev === 'p2') result.medium++;
    else if (sev === 'low' || sev === 'p3') result.low++;
    else result.unset++;
  }
  return result;
}

/** Severity buckets of a list of rows — the grade uses the OPEN ones, the breakdown panel uses all. */
export function computeSeverityOf(rows: { severity: string }[]): SeverityBreakdown {
  const result: SeverityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  for (const e of rows) {
    const sev = (e.severity || '').toLowerCase();
    if (sev === 'critical' || sev === 'p0') result.critical++;
    else if (sev === 'high' || sev === 'p1') result.high++;
    else if (sev === 'medium' || sev === 'p2') result.medium++;
    else if (sev === 'low' || sev === 'p3') result.low++;
    else result.unset++;
  }
  return result;
}

export function computeExposures(model: ThreatModel): ExposureRow[] {
  // D57: this normalised `#` but still keyed on the pair alone, so the dashboard
  // exposure table showed a same-file-different-symbol exposure as mitigated.
  const coverage = buildCoverageIndex(model);

  return model.exposures.map(e => {
    return {
      asset: e.asset,
      threat: e.threat,
      severity: e.severity || 'unset',
      description: e.description || '',
      file: e.location.file,
      line: e.location.line,
      mitigated: coverage.isMitigated(e),
      accepted: coverage.isAccepted(e),
    };
  });
}

/**
 * One tile per asset. A declared asset is one tile whether annotations refer
 * to it as `#id`, as its dotted path, or in another case — before this,
 * `GuardLink.Parser` and `#parser` were two tiles with the counts split
 * between them. Undeclared references stay tiles of their own.
 */
export function computeAssetHeatmap(model: ThreatModel): AssetHeatmapEntry[] {
  const canon = new Map<string, string>();
  for (const a of model.assets) {
    const path = a.path.join('.');
    const name = a.id ? `#${a.id}` : path;
    canon.set(path.toLowerCase(), name);
    if (a.id) canon.set(`#${a.id.toLowerCase()}`, name);
  }
  const of = (ref: string): string => canon.get(ref.trim().toLowerCase()) ?? ref;
  const aliases = new Map<string, Set<string>>();
  const seen = (ref: string): void => {
    const name = of(ref);
    const set = aliases.get(name) ?? new Set<string>();
    set.add(ref);
    aliases.set(name, set);
  };
  for (const a of model.assets) seen(a.path.join('.'));
  for (const e of model.exposures) seen(e.asset);
  for (const m of model.mitigations) seen(m.asset);
  for (const f of model.flows) { seen(f.source); seen(f.target); }

  return Array.from(aliases.keys()).map(name => {
    const exposures = model.exposures.filter(e => of(e.asset) === name).length;
    const mitigations = model.mitigations.filter(m => of(m.asset) === name).length;
    const flows = model.flows.filter(f => of(f.source) === name || of(f.target) === name).length;
    const dataHandling = [...new Set(model.data_handling.filter(h => h.asset && of(h.asset) === name).map(h => h.classification))];
    const unmitigated = exposures - mitigations;

    let riskLevel: AssetHeatmapEntry['riskLevel'] = 'none';
    if (unmitigated >= 3) riskLevel = 'critical';
    else if (unmitigated >= 2) riskLevel = 'high';
    else if (unmitigated >= 1) riskLevel = 'medium';
    else if (exposures > 0) riskLevel = 'low';

    return { name, aliases: [...aliases.get(name)!].sort(), exposures, mitigations, flows, dataHandling, riskLevel };
  }).sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
    return order[a.riskLevel] - order[b.riskLevel];
  });
}

export function computeConfirmed(model: ThreatModel): ConfirmedRow[] {
  return (model.confirmed || []).map(c => ({
    threat: c.threat,
    asset: c.asset,
    severity: c.severity || 'unset',
    description: c.description || '',
    file: c.location.file,
    line: c.location.line,
    external_refs: c.external_refs || [],
  }));
}

// ─── Attribution (guardlink dashboard --blame) ───────────────────────

export interface AttributionClaimRow {
  verb: string;
  asset: string;
  threat: string;
  severity: string;
  file: string;
  line: number;
  status: string;
  lowerBound: boolean;
  introducedBy: string;
  introducedSha: string;
  introducedDate: string;
  introducedAi: string[];
  declaredBy: string;
  declaredSha: string;
  fixedBy: string;
  fixedSha: string;
  fixedAi: string[];
  timeToFix: number | null;
}

export interface AttributionData {
  humans: HumanSummaryRow[];
  agents: AgentSummaryRow[];
  rows: AttributionClaimRow[];
  /** Largest `introduced` count, for scaling the bars. */
  maxIntroduced: number;
  /** Claims whose status is not `ok`, by status. */
  degraded: { status: string; count: number }[];
  /** The HEAD commit's author date — "now" for ages, so the page is deterministic per HEAD. */
  as_of: string | null;
  trends: TrendBucket[];
  comparison: { human: Cohort; ai: Cohort } | null;
  hot_files: HotFile[];
  commits: CommitCounts | null;
}

/** What attachBlame leaves on the model so the dashboard can compute rates: commit counts per identity and the as-of date. */
export interface BlameContext {
  commits: CommitCounts | null;
  as_of: string | null;
}

const aiLabels = (ref: CommitRef | null): string[] =>
  ref ? ref.assisted_by.map(a => (a.model ? `${a.tool} (${a.model})` : a.tool)) : [];
const authorLabel = (ref: CommitRef | null): string =>
  ref ? [ref.author, ...ref.co_authors].join(' + ') : '';

/**
 * The Attribution page's data, or null when no record carries `blame` — the
 * page is then not rendered at all, so a dashboard built without `--blame` is
 * byte-for-byte what it was.
 *
 * @handles pii on #dashboard -- "Author identities from git, already in the configured identity mode"
 * @comment -- "Pure projection of record.blame; the summariser is shared with the CLI and the report so every surface agrees on the numbers"
 */
export function computeAttribution(model: ThreatModel): AttributionData | null {
  const entries = entriesFromModel(model);
  if (entries.length === 0) return null;
  const context = (model as ThreatModel & { blame_context?: BlameContext }).blame_context;
  const summary = summarise(entries, { commits: context?.commits ?? null, as_of: context?.as_of ?? null });
  const { by_human, by_agent } = summary;
  const rows: AttributionClaimRow[] = entries.map(e => {
    const b = e.blame;
    const introduced = b.kind === 'exposure' ? b.introduced_by : null;
    const declared = b.kind === 'exposure' ? b.found_by : b.declared_by;
    const fixed = b.kind === 'exposure' ? b.fixed_by : null;
    return {
      verb: e.verb,
      asset: e.asset,
      threat: e.threat,
      severity: e.severity ?? '',
      file: e.file,
      line: e.line,
      status: b.status,
      lowerBound: introduced?.lower_bound === true,
      introducedBy: authorLabel(introduced),
      introducedSha: introduced?.sha ?? '',
      introducedDate: introduced?.date.slice(0, 10) ?? '',
      introducedAi: aiLabels(introduced),
      declaredBy: authorLabel(declared),
      declaredSha: declared?.sha ?? '',
      fixedBy: authorLabel(fixed),
      fixedSha: fixed?.sha ?? '',
      fixedAi: aiLabels(fixed),
      timeToFix: b.kind === 'exposure' ? b.time_to_fix_days : null,
    };
  });
  const degradedMap = new Map<string, number>();
  for (const e of entries) if (e.blame.status !== 'ok') degradedMap.set(e.blame.status, (degradedMap.get(e.blame.status) ?? 0) + 1);
  return {
    humans: by_human,
    agents: by_agent,
    rows,
    maxIntroduced: Math.max(0, ...by_human.map(r => r.introduced), ...by_agent.map(r => r.introduced)),
    degraded: [...degradedMap].map(([status, count]) => ({ status, count })).sort((a, b) => (a.status < b.status ? -1 : 1)),
    as_of: summary.as_of,
    trends: summary.trends,
    comparison: summary.comparison,
    hot_files: summary.hot_files,
    commits: summary.comparison ? (context?.commits ?? null) : null,
  };
}

// The analytics builders live in analytics.ts; re-exported so consumers keep one import.
export { computeAssetThreatMatrix, computeControlCoverage, computeSeverityStatus, computeAssetDetails, computeIntroductionHeat, computeToolSeverity, SEV_ORDER } from './analytics.js';
export type { ClaimLike, MatrixCell, AssetThreatMatrix, ControlCoverage, SeverityStatus, StatusKey, AssetDetail, HeatGrid, SevKey } from './analytics.js';

// ─── Actions: "What to do next" ──────────────────────────────────────

export type ActionLevel = 'critical' | 'high' | 'medium' | 'info';

export interface DashboardAction {
  id: string;
  level: ActionLevel;
  title: string;
  detail: string;
  count: number;
  /** A hash route into the page and filter that shows the items. */
  href?: string;
  /** A guardlink command that acts on them, offered with a copy button. */
  command?: string;
}

export interface ActionInput {
  model: ThreatModel;
  exposures: ExposureRow[];
  confirmed: ConfirmedRow[];
  verification: VerificationReport | null;
  attribution: AttributionData | null;
  scope: string[] | null;
}

const sevKey = (s: string): string => {
  const l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'critical';
  if (l === 'high' || l === 'p1') return 'high';
  return l;
};
const plural = (n: number, one: string, many = `${one}s`): string => (n === 1 ? one : many);

/**
 * The ordered list of things a reader should do, computed from what the page
 * already knows. Urgency first: confirmed findings, then open critical/high
 * exposures, then claims whose code moved (stale), then a first verify when no
 * ledger exists, then AI-introduced open exposures, then governance items,
 * then repository coverage. A slice withholds the project-wide measures
 * (coverage, first-verify) that only mean something for the whole repository.
 *
 * @comment -- "Every item points somewhere: a hash route into the filtered view, a guardlink command, or both. Nothing here is a bare number"
 */
export function computeActions(input: ActionInput): DashboardAction[] {
  const { model, exposures, confirmed, verification, attribution, scope } = input;
  const out: DashboardAction[] = [];

  if (confirmed.length > 0) {
    out.push({
      id: 'confirmed', level: 'critical', count: confirmed.length,
      title: `${confirmed.length} confirmed exploitable ${plural(confirmed.length, 'finding')}`,
      detail: 'Verified by test, scan or reproduction — not theoretical. Fix, or accept with explicit security sign-off, before anything else.',
      href: '#threats?status=confirmed',
    });
  }

  const open = exposures.filter(e => !e.mitigated && !e.accepted);
  const severe = open.filter(e => sevKey(e.severity) === 'critical' || sevKey(e.severity) === 'high');
  if (severe.length > 0) {
    const crit = severe.filter(e => sevKey(e.severity) === 'critical').length;
    out.push({
      id: 'open-severe', level: crit > 0 ? 'critical' : 'high', count: severe.length,
      title: `${severe.length} critical or high ${plural(severe.length, 'exposure')} open`,
      detail: `${crit} critical, ${severe.length - crit} high. Each needs a @mitigates with a real control, or a human @accepts with a reason.`,
      href: '#threats?sev=critical,high&status=open',
      command: 'guardlink review .',
    });
  }

  if (verification && verification.ledger === 'corrupt') {
    out.push({
      id: 'ledger-corrupt', level: 'high', count: 0,
      title: 'The verification ledger is unreadable',
      detail: '.guardlink/verified.json does not parse, so every claim reads as unverified. Validate, then rebuild it with a whole-repository verify.',
      command: 'guardlink validate .',
    });
  } else if (verification && verification.ledger !== 'absent' && verification.summary.stale > 0) {
    const s = verification.summary;
    out.push({
      id: 'stale-claims', level: s.demotable_stale > 0 ? 'high' : 'medium', count: s.stale,
      title: `${s.stale} ${plural(s.stale, 'claim')} went stale`,
      detail: `The code beneath ${s.stale === 1 ? 'it' : 'them'} changed since ${s.stale === 1 ? 'it was' : 'they were'} verified; ${s.demotable_stale} of them ${s.demotable_stale === 1 ? 'is a' : 'are'} ${plural(s.demotable_stale, 'mitigation or acceptance', 'mitigations or acceptances')} that may no longer hold. Re-check the code, then re-lock.`,
      href: '#threats?state=stale',
      command: 'guardlink verify --stale',
    });
  } else if (verification && verification.ledger === 'absent' && !scope) {
    const n = verification.summary.unverified;
    out.push({
      id: 'start-verifying', level: 'medium', count: n,
      title: 'No claim has been verified yet',
      detail: `${n} ${plural(n, 'claim')} in this model ${n === 1 ? 'has' : 'have'} never been checked against the code beneath ${n === 1 ? 'it' : 'them'}. A first whole-repository verify records the baseline; from then on a stale claim stands out.`,
      command: 'guardlink verify --all',
    });
  }

  if (attribution) {
    const aiOpen = attribution.rows.filter(r => r.verb !== 'mitigates' && r.fixedBy === '' && r.introducedAi.length > 0).length;
    if (aiOpen > 0) {
      out.push({
        id: 'ai-open', level: 'medium', count: aiOpen,
        title: `${aiOpen} open ${plural(aiOpen, 'exposure')} introduced with AI help`,
        detail: 'The introducing commit credits an AI tool. Worth a closer review, and worth knowing which tool and model.',
        href: '#attribution?who=ai',
      });
    }
  }

  const inert = (model.entitlements || []).filter(e => e.inert).length;
  if (inert > 0) {
    out.push({
      id: 'inert-entitlements', level: 'medium', count: inert,
      title: `${inert} ${plural(inert, 'entitlement')} cite${inert === 1 ? 's' : ''} no authorization code`,
      detail: 'An @entitles without a file:line citation is inert: parsed, then ignored. Add the citation or drop the claim.',
      href: '#data?q=inert',
    });
  }

  if (model.audits.length > 0) {
    const n = model.audits.length;
    out.push({
      id: 'audits', level: 'medium', count: n,
      title: `${n} audit ${plural(n, 'item')} ${n === 1 ? 'awaits' : 'await'} human review`,
      detail: 'Each @audit marks a risk with no control yet. Review it and either add a control or record a decision.',
      href: '#data?q=audit',
    });
  }

  if (!scope) {
    const unannotated = (model.unannotated_files || []).length;
    const total = (model.annotated_files?.length || 0) + unannotated;
    const pct = total > 0 ? Math.round(((total - unannotated) / total) * 100) : 100;
    if (total > 0 && pct < 70) {
      out.push({
        id: 'coverage', level: pct < 40 ? 'medium' : 'info', count: unannotated,
        title: `${unannotated} of ${total} source ${plural(total, 'file')} carry no annotations`,
        detail: `${pct}% file coverage. Not every file needs annotations, only those touching a security boundary — a coding agent can find them.`,
        href: '#code?q=unannotated',
        command: 'guardlink annotate "Add GuardLink annotations to the source files that touch a security boundary and carry none"',
      });
    }
  }

  if (out.length === 0) {
    out.push({
      id: 'none', level: 'info', count: 0,
      title: 'Nothing urgent',
      detail: 'Every exposure is mitigated or accepted, no claim is stale, and nothing awaits review.',
    });
  }
  return out;
}

// ─── Ledger state per claim ──────────────────────────────────────────

/**
 * Verified / stale / unverified per claim, keyed by the record's location
 * object — `classifyClaims` shares each location by reference with the model
 * record, so identity is the join. The map is empty when no ledger exists
 * (`report.ledger === 'absent'`), so a dashboard on a never-verified
 * repository renders no badges rather than a wall of "unverified"; the report
 * still carries the unverified count the actions list needs.
 *
 * @flows LedgerFile -> #dashboard via readLedger -- "Claim states for the badges and the stale-claims action"
 * @comment -- "Reads .guardlink/verified.json once; the classification itself is the parser's, not re-derived here"
 */
export function computeLedgerStates(model: ThreatModel, root: string): { report: VerificationReport; byLocation: Map<object, ClaimState> } {
  const read = readLedger(root);
  const report = classifyClaims(model, read);
  const byLocation = new Map<object, ClaimState>();
  if (report.ledger !== 'absent') for (const c of report.claims) byLocation.set(c.location, c.state);
  return { report, byLocation };
}
