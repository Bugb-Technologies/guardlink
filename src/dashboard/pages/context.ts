/**
 * GuardLink Dashboard — what every page renderer receives, and the unified
 * claim view the tables and the drawer share.
 *
 * `buildClaims` joins three things onto each exposure, confirmed finding and
 * mitigation: its coverage status, its ledger state (verified / stale /
 * unverified, when a ledger exists), and its attribution (when the model went
 * through `attachBlame`). Every claim gets the URL of its file on the repo
 * host when one is known, so the tables and the drawer never build links.
 *
 * @flows ThreatModel -> #dashboard via buildClaims -- "Records joined with coverage, ledger state and attribution into table rows"
 * @handles pii on #dashboard -- "Author identities from attribution, already in the configured identity mode"
 * @comment -- "Pure; every string here is raw and is escaped by the page that renders it"
 */
import type { ExposureHypothesis, ThreatModel } from '../../types/index.js';
import type { ClaimState, VerificationReport } from '../../parser/verification.js';
import { buildCoverageIndex } from '../../parser/coverage.js';
import type { CommitRef, IntroducedBy } from '../../blame/types.js';
import type { ThreatReportWithContent } from '../../analyze/index.js';
import type { RepoLinks } from '../links.js';
import { buildAssetIndex } from '../analytics.js';
import type { ChangeSummary, FileRisk } from '../analytics.js';
import type { DashboardStats, SeverityBreakdown, ExposureRow, ConfirmedRow, AssetHeatmapEntry, AttributionData, DashboardAction } from '../data.js';
import type { FileAnnotationGroup } from '../annotations.js';

export type ClaimStatus = 'open' | 'mitigated' | 'accepted' | 'confirmed' | 'control' | 'refuted';

export interface DrawerRef {
  sha: string;
  url: string | null;
  /** YYYY-MM-DD */
  date: string;
  author: string;
  co: string[];
  /** `tool (model)` labels. */
  ai: string[];
}

export interface DrawerBlame {
  status: string;
  introduced: DrawerRef | null;
  declared: DrawerRef | null;
  fixed: DrawerRef | null;
  days: number | null;
  lowerBound: boolean;
}

export interface ClaimView {
  idx: number;
  verb: 'exposes' | 'confirmed' | 'mitigates';
  status: ClaimStatus;
  statusLabel: string;
  asset: string;
  threat: string;
  severity: string;
  description: string;
  control: string | null;
  refs: string[];
  file: string;
  line: number;
  url: string | null;
  state: ClaimState | null;
  /** Teams recorded with @owns for the asset. */
  owners: string[];
  /** Data classifications recorded with @handles for the asset. */
  handles: string[];
  /** 'new' when the claim was added since the --since ref. */
  change: 'new' | null;
  /** The tested state from the hypothesis ledger, when one exists. */
  hypothesis: ExposureHypothesis | null;
  /** Who locked the claim in the ledger, and when (ISO date), when the ledger holds it. */
  verifiedBy: string | null;
  verifiedAt: string | null;
  /** Identity tokens the `who` filter matches: every person and AI credited on any of its commits, plus `ai` when any AI is. */
  who: string[];
  blame: DrawerBlame | null;
  /** Lowercased text the search box matches. */
  search: string;
}

export interface PageContext {
  model: ThreatModel;
  scope: string[] | null;
  scopeFiles: number;
  links: RepoLinks | null;
  hostLabel: string;
  stats: DashboardStats;
  severity: SeverityBreakdown;
  exposures: ExposureRow[];
  confirmed: ConfirmedRow[];
  unmitigated: ExposureRow[];
  mitigatedCount: number;
  mitigationCoveragePercent: number;
  risk: { grade: string; label: string; summary: string };
  claims: ClaimView[];
  ledger: { report: VerificationReport; byLocation: Map<object, ClaimState>; entryByLocation: Map<object, { verified_by: string; verified_at: string }> } | null;
  attribution: AttributionData | null;
  actions: DashboardAction[];
  heatmap: AssetHeatmapEntry[];
  fileAnnotations: FileAnnotationGroup[];
  diagrams: { threatGraph: string; threatGraphFull: string; dataFlow: string; attackSurface: string; focus: { name: string; src: string }[] };
  analyses: ThreatReportWithContent[];
  /** What changed since --since <ref>, or null without the flag. */
  changes: ChangeSummary | null;
  /** Per annotated file: what it carries, for the Code page order and badges. */
  fileRisk: Map<string, FileRisk>;
}

const aiLabel = (ref: CommitRef): string[] => ref.assisted_by.map(a => (a.model ? `${a.tool} (${a.model})` : a.tool));
const agentKeys = (ref: CommitRef): string[] => ref.assisted_by.flatMap(a => [a.tool, `${a.tool} ${a.model ?? ''}`.trim()]);

function toRef(ref: CommitRef | IntroducedBy | null, links: RepoLinks | null): DrawerRef | null {
  if (!ref) return null;
  return { sha: ref.sha, url: links ? links.commit(ref.sha) : null, date: ref.date.slice(0, 10), author: ref.author, co: ref.co_authors, ai: aiLabel(ref) };
}

function whoTokens(refs: (CommitRef | null | undefined)[]): string[] {
  const out = new Set<string>();
  let ai = false;
  for (const r of refs) {
    if (!r) continue;
    out.add(r.author);
    for (const c of r.co_authors) out.add(c);
    for (const k of agentKeys(r)) out.add(k);
    if (r.assisted_by.length > 0) ai = true;
  }
  if (ai) out.add('ai');
  return [...out];
}

export interface BuildClaimsOptions {
  /** `verb@file:line` keys of claims added since the --since ref. */
  newKeys?: Set<string>;
}

export function buildClaims(model: ThreatModel, links: RepoLinks | null, ledger: PageContext['ledger'], opts: BuildClaimsOptions = {}): ClaimView[] {
  const ix = buildAssetIndex(model);
  const change = (verb: string, file: string, line: number): 'new' | null => (opts.newKeys?.has(`${verb}@${file}:${line}`) ? 'new' : null);
  const coverage = buildCoverageIndex(model);
  const claims: ClaimView[] = [];
  const state = (loc: object): ClaimState | null => ledger?.byLocation.get(loc) ?? null;
  const entry = (loc: object): { verifiedBy: string | null; verifiedAt: string | null } => {
    const e = ledger?.entryByLocation.get(loc);
    return { verifiedBy: e?.verified_by ?? null, verifiedAt: e?.verified_at ?? null };
  };
  const url = (file: string, line: number): string | null => (links ? links.file(file, line) : null);

  const push = (c: Omit<ClaimView, 'idx' | 'search'>): void => {
    const search = [c.verb, c.status, c.asset, c.threat, c.severity, c.description, c.control ?? '', c.file, c.state ?? '', c.change ?? '', ...c.owners, ...c.handles, ...c.who, ...c.refs].join(' ').toLowerCase();
    claims.push({ ...c, idx: claims.length, search });
  };

  for (const e of model.exposures) {
    // Tested and not exploitable outranks 'open': the ledger holds the evidence. It never outranks a control or an acceptance.
    const status: ClaimStatus = coverage.isMitigated(e) ? 'mitigated' : coverage.isAccepted(e) ? 'accepted' : e.hypothesis?.state === 'refuted' ? 'refuted' : 'open';
    const b = e.blame;
    push({
      verb: 'exposes', status,
      statusLabel: status === 'open' ? 'Open — no mitigation' : status === 'mitigated' ? 'Mitigated' : status === 'refuted' ? 'Refuted — tested, not exploitable' : 'Accepted',
      hypothesis: e.hypothesis ?? null,
      asset: e.asset, threat: e.threat, severity: e.severity || 'unset', description: e.description || '', control: null,
      refs: e.external_refs || [], file: e.location.file, line: e.location.line, url: url(e.location.file, e.location.line),
      state: state(e.location), ...entry(e.location), owners: ix.ownersOf(e.asset), handles: ix.handlesOf(e.asset), change: change('exposes', e.location.file, e.location.line),
      who: b ? whoTokens([b.introduced_by, b.found_by, b.fixed_by]) : [],
      blame: b ? { status: b.status, introduced: toRef(b.introduced_by, links), declared: toRef(b.found_by, links), fixed: toRef(b.fixed_by, links), days: b.time_to_fix_days, lowerBound: b.introduced_by?.lower_bound === true } : null,
    });
  }
  for (const c of model.confirmed || []) {
    const b = c.blame;
    push({
      verb: 'confirmed', status: 'confirmed', statusLabel: 'Confirmed exploitable', hypothesis: null,
      asset: c.asset, threat: c.threat, severity: c.severity || 'unset', description: c.description || '', control: null,
      refs: c.external_refs || [], file: c.location.file, line: c.location.line, url: url(c.location.file, c.location.line),
      state: state(c.location), ...entry(c.location), owners: ix.ownersOf(c.asset), handles: ix.handlesOf(c.asset), change: change('confirmed', c.location.file, c.location.line),
      who: b ? whoTokens([b.introduced_by, b.found_by, b.fixed_by]) : [],
      blame: b ? { status: b.status, introduced: toRef(b.introduced_by, links), declared: toRef(b.found_by, links), fixed: toRef(b.fixed_by, links), days: b.time_to_fix_days, lowerBound: b.introduced_by?.lower_bound === true } : null,
    });
  }
  for (const m of model.mitigations) {
    const b = m.blame;
    push({
      verb: 'mitigates', status: 'control', statusLabel: 'Control declared', hypothesis: null,
      asset: m.asset, threat: m.threat, severity: 'unset', description: m.description || '', control: m.control ?? null,
      refs: [], file: m.location.file, line: m.location.line, url: url(m.location.file, m.location.line),
      state: state(m.location), ...entry(m.location), owners: ix.ownersOf(m.asset), handles: ix.handlesOf(m.asset), change: null,
      who: b ? whoTokens([b.declared_by]) : [],
      blame: b ? { status: b.status, introduced: null, declared: toRef(b.declared_by, links), fixed: null, days: null, lowerBound: false } : null,
    });
  }
  return claims;
}
