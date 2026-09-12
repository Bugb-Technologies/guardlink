/**
 * GuardLink Dashboard — analytics builders: the asset × threat matrix,
 * severity × status, control coverage, per-asset details for the drawer,
 * and the attribution grids (people × time, AI tool × severity).
 *
 * All pure over the unified claim rows and the model; nothing here reads a
 * file or the clock.
 *
 * @handles pii on #dashboard -- "Introducer identities per asset and per period, in the configured identity mode"
 * @comment -- "Asset details match a tile by any of its aliases (#id, dotted path, as written), case-insensitively; mitigations never count as exposures, they only change a pair's status"
 */
import type { ThreatModel } from '../types/index.js';
import type { ClaimState } from '../parser/verification.js';
import type { ThreatModelDiff } from '../diff/engine.js';
import type { AssetHeatmapEntry } from './data.js';

export type SevKey = 'critical' | 'high' | 'medium' | 'low' | 'unset';
export const SEV_ORDER: SevKey[] = ['critical', 'high', 'medium', 'low', 'unset'];

const sevOf = (s: string | undefined | null): SevKey => {
  const l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'critical';
  if (l === 'high' || l === 'p1') return 'high';
  if (l === 'medium' || l === 'p2') return 'medium';
  if (l === 'low' || l === 'p3') return 'low';
  return 'unset';
};
const byName = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** The claim rows the analytics read; structural so this module does not depend on the page context. */
export interface ClaimLike {
  idx: number;
  verb: 'exposes' | 'confirmed' | 'mitigates';
  status: 'open' | 'mitigated' | 'accepted' | 'confirmed' | 'control' | 'refuted';
  asset: string;
  threat: string;
  severity: string;
  file: string;
  line: number;
  state: ClaimState | null;
  /** Teams recorded with @owns for the claim's asset (any alias). */
  owners: string[];
  /** Data classifications recorded with @handles for the claim's asset. */
  handles: string[];
  /** 'new' when the claim was added since the --since ref. */
  change: 'new' | null;
  blame: { introduced: { date: string; author: string; co: string[]; ai: string[] } | null } | null;
}

/**
 * The declared assets by every name the model uses for them, with the owners
 * and classifications recorded against each. `#id`, dotted path and case all
 * fold onto one name, so `@owns platform for App.API` covers `#api`.
 */
export interface AssetIndex {
  canon: (ref: string) => string;
  ownersOf: (ref: string) => string[];
  handlesOf: (ref: string) => string[];
}

export function buildAssetIndex(model: ThreatModel): AssetIndex {
  const canon = new Map<string, string>();
  for (const a of model.assets) {
    const path = a.path.join('.');
    const name = a.id ? `#${a.id}` : path;
    canon.set(path.toLowerCase(), name);
    if (a.id) canon.set(`#${a.id.toLowerCase()}`, name);
  }
  const of = (ref: string): string => canon.get(ref.trim().toLowerCase()) ?? ref.trim();
  const owners = new Map<string, Set<string>>();
  for (const o of model.ownership) {
    const k = of(o.asset);
    if (!owners.has(k)) owners.set(k, new Set());
    owners.get(k)!.add(o.owner);
  }
  const handles = new Map<string, Set<string>>();
  for (const h of model.data_handling) {
    if (!h.asset) continue;
    const k = of(h.asset);
    if (!handles.has(k)) handles.set(k, new Set());
    handles.get(k)!.add(h.classification);
  }
  return {
    canon: of,
    ownersOf: r => [...(owners.get(of(r)) ?? [])].sort(byName),
    handlesOf: r => [...(handles.get(of(r)) ?? [])].sort(byName),
  };
}

const DAY_MS = 86_400_000;
const isOpen = (c: ClaimLike): boolean => c.status === 'open' || c.status === 'confirmed';
const worstOf = (list: ClaimLike[]): SevKey => list.reduce<SevKey>((w, c) => (SEV_ORDER.indexOf(sevOf(c.severity)) < SEV_ORDER.indexOf(w) ? sevOf(c.severity) : w), 'unset');
const asOfOf = (model: ThreatModel): number => {
  const ctx = (model as ThreatModel & { blame_context?: { as_of?: string | null } }).blame_context;
  return ctx?.as_of ? Date.parse(ctx.as_of) : Number.NaN;
};
const oldestOpen = (list: ClaimLike[], asOfMs: number): number | null => {
  if (Number.isNaN(asOfMs)) return null;
  let oldest: number | null = null;
  for (const c of list) {
    if (!isOpen(c) || !c.blame?.introduced) continue;
    const d = Math.max(0, Math.floor((asOfMs - Date.parse(c.blame.introduced.date)) / DAY_MS));
    if (oldest === null || d > oldest) oldest = d;
  }
  return oldest;
};

export interface OwnerRow {
  owner: string;
  assets: string[];
  total: number;
  open: number;
  confirmed: number;
  worstSev: SevKey;
  stale: number;
  oldestOpenDays: number | null;
}
export interface UnownedAsset { asset: string; open: number; worstSev: SevKey }

/** Open risk rolled up to the team that owns it, and the exposed assets no team owns. */
export function computeOwnership(model: ThreatModel, claims: ClaimLike[]): { owners: OwnerRow[]; unowned: UnownedAsset[] } {
  const ix = buildAssetIndex(model);
  const asOfMs = asOfOf(model);
  const exposures = claims.filter(c => c.verb !== 'mitigates');
  const byOwner = new Map<string, { assets: Set<string>; claims: ClaimLike[]; exposures: ClaimLike[] }>();
  for (const o of model.ownership) {
    if (!byOwner.has(o.owner)) byOwner.set(o.owner, { assets: new Set(), claims: [], exposures: [] });
    byOwner.get(o.owner)!.assets.add(ix.canon(o.asset));
  }
  for (const [, v] of byOwner) {
    v.claims = claims.filter(c => v.assets.has(ix.canon(c.asset)));
    v.exposures = v.claims.filter(c => c.verb !== 'mitigates');
  }
  const owners: OwnerRow[] = [...byOwner].map(([owner, v]) => ({
    owner,
    assets: [...v.assets].sort(byName),
    total: v.exposures.length,
    open: v.exposures.filter(isOpen).length,
    confirmed: v.exposures.filter(c => c.status === 'confirmed').length,
    worstSev: worstOf(v.exposures.filter(isOpen)),
    stale: v.claims.filter(c => c.state === 'stale').length,
    oldestOpenDays: oldestOpen(v.exposures, asOfMs),
  })).sort((a, b) => b.open - a.open || b.confirmed - a.confirmed || byName(a.owner, b.owner));
  const owned = new Set([...byOwner.values()].flatMap(v => [...v.assets]));
  const openByAsset = new Map<string, ClaimLike[]>();
  for (const c of exposures) {
    if (!isOpen(c)) continue;
    const k = ix.canon(c.asset);
    if (owned.has(k)) continue;
    if (!openByAsset.has(k)) openByAsset.set(k, []);
    openByAsset.get(k)!.push(c);
  }
  const unowned: UnownedAsset[] = [...openByAsset].map(([asset, list]) => ({ asset, open: list.length, worstSev: worstOf(list) }))
    .sort((a, b) => b.open - a.open || SEV_ORDER.indexOf(a.worstSev) - SEV_ORDER.indexOf(b.worstSev) || byName(a.asset, b.asset));
  return { owners, unowned };
}

export interface SensitiveRow {
  classification: string;
  /** Assets recorded as handling this class. */
  assets: number;
  /** Of those, how many carry an open or confirmed exposure. */
  exposedAssets: number;
  open: number;
  confirmed: number;
  total: number;
  worstSev: SevKey;
  assetList: { asset: string; open: number; worstSev: SevKey }[];
}

/** Open exposure per data classification: the compliance question. */
export function computeSensitiveData(model: ThreatModel, claims: ClaimLike[]): SensitiveRow[] {
  const ix = buildAssetIndex(model);
  const exposures = claims.filter(c => c.verb !== 'mitigates');
  const byClass = new Map<string, Set<string>>();
  for (const h of model.data_handling) {
    if (!h.asset) continue;
    if (!byClass.has(h.classification)) byClass.set(h.classification, new Set());
    byClass.get(h.classification)!.add(ix.canon(h.asset));
  }
  const rows: SensitiveRow[] = [...byClass].map(([classification, assets]) => {
    const list = exposures.filter(c => assets.has(ix.canon(c.asset)));
    const assetList = [...assets].map(asset => {
      const mine = list.filter(c => ix.canon(c.asset) === asset);
      const open = mine.filter(isOpen);
      return { asset, open: open.length, worstSev: worstOf(open) };
    }).sort((a, b) => b.open - a.open || byName(a.asset, b.asset));
    return {
      classification,
      assets: assets.size,
      exposedAssets: assetList.filter(a => a.open > 0).length,
      open: list.filter(isOpen).length,
      confirmed: list.filter(c => c.status === 'confirmed').length,
      total: list.length,
      worstSev: worstOf(list.filter(isOpen)),
      assetList,
    };
  });
  return rows.sort((a, b) => b.open - a.open || SEV_ORDER.indexOf(a.worstSev) - SEV_ORDER.indexOf(b.worstSev) || byName(a.classification, b.classification));
}

export interface FileRisk { open: number; confirmed: number; total: number; worst: SevKey; stale: number }

/** What each annotated file carries, so the Code page can put the riskiest first. */
export function computeFileRisk(claims: ClaimLike[]): Map<string, FileRisk> {
  const out = new Map<string, FileRisk>();
  for (const c of claims) {
    const r = out.get(c.file) ?? { open: 0, confirmed: 0, total: 0, worst: 'unset' as SevKey, stale: 0 };
    if (c.verb !== 'mitigates') {
      r.total++;
      if (isOpen(c)) {
        r.open++;
        if (SEV_ORDER.indexOf(sevOf(c.severity)) < SEV_ORDER.indexOf(r.worst)) r.worst = sevOf(c.severity);
      }
      if (c.status === 'confirmed') r.confirmed++;
    }
    if (c.state === 'stale') r.stale++;
    out.set(c.file, r);
  }
  return out;
}

/** Sort key: confirmed first, then by the worst open severity, then files with nothing open. */
export function fileRiskRank(r: FileRisk | undefined): number {
  if (!r || r.open === 0) return 6;
  if (r.confirmed > 0) return 0;
  return 1 + SEV_ORDER.indexOf(r.worst);
}

/** What `--since <ref>` loads: the diff against the model at the ref, and the ref's place in history. */
export interface SinceInput {
  ref: string;
  /** The ref's commit date (ISO), when git could answer. */
  refDate: string | null;
  /** Commits between the ref and HEAD, when git could answer. */
  commits: number | null;
  diff: ThreatModelDiff;
  /** Files changed between the ref and the working tree, repo-relative. */
  changedFiles: string[];
}

export interface ChangedClaim { asset: string; threat: string; severity: string; file: string; line: number; open: boolean }

export interface ChangeSummary {
  ref: string;
  refDate: string | null;
  commits: number | null;
  newExposures: ChangedClaim[];
  /** How many of the new exposures are still open. */
  newOpen: number;
  /** Previously unmitigated exposures that are now mitigated, accepted or gone. */
  resolved: ChangedClaim[];
  removed: number;
  newConfirmed: number;
  newMitigations: number;
  /** Claims stale now whose file changed since the ref. */
  wentStale: ChangedClaim[];
  riskDelta: 'increased' | 'decreased' | 'unchanged';
}

const claimKey = (verb: string, file: string, line: number): string => `${verb}@${file}:${line}`;

/** Keys (`verb@file:line`) of the exposures and confirmed findings a diff added; `buildClaims` marks those rows new. */
export function newClaimKeys(since: SinceInput): Set<string> {
  const keys = new Set<string>();
  for (const c of since.diff.exposures) if (c.kind === 'added') keys.add(claimKey('exposes', c.item.location.file, c.item.location.line));
  for (const c of since.diff.confirmed) if (c.kind === 'added') keys.add(claimKey('confirmed', c.item.location.file, c.item.location.line));
  return keys;
}

/** The strip on the summary: what the diff since the ref means for open risk. */
export function computeChanges(since: SinceInput, claims: ClaimLike[]): ChangeSummary {
  const now = new Map(claims.map(c => [claimKey(c.verb, c.file, c.line), c]));
  const toChanged = (e: { asset: string; threat: string; severity?: string; location: { file: string; line: number } }, verb: string): ChangedClaim => {
    const cur = now.get(claimKey(verb, e.location.file, e.location.line));
    return { asset: e.asset, threat: e.threat, severity: e.severity || 'unset', file: e.location.file, line: e.location.line, open: cur ? isOpen(cur) : false };
  };
  const newExposures = since.diff.exposures.filter(c => c.kind === 'added').map(c => toChanged(c.item, 'exposes'));
  const resolved = since.diff.resolvedExposures.map(e => ({ ...toChanged(e, 'exposes'), open: false }));
  const changed = new Set(since.changedFiles);
  const wentStale = claims.filter(c => c.state === 'stale' && changed.has(c.file))
    .map(c => ({ asset: c.asset, threat: c.threat, severity: c.severity, file: c.file, line: c.line, open: isOpen(c) }));
  return {
    ref: since.ref,
    refDate: since.refDate,
    commits: since.commits,
    newExposures,
    newOpen: newExposures.filter(e => e.open).length,
    resolved,
    removed: since.diff.exposures.filter(c => c.kind === 'removed').length,
    newConfirmed: since.diff.confirmed.filter(c => c.kind === 'added').length,
    newMitigations: since.diff.mitigations.filter(c => c.kind === 'added').length,
    wentStale,
    riskDelta: since.diff.summary.riskDelta,
  };
}

export interface MatrixCell {
  asset: string;
  threat: string;
  total: number;
  open: number;
  mitigated: number;
  accepted: number;
  confirmed: number;
  /** Tested and not exploitable (hypothesis ledger). */
  refuted: number;
  worst: 'confirmed' | 'open' | 'mitigated' | 'refuted' | 'accepted';
  maxSev: SevKey;
}

export interface AssetThreatMatrix {
  /** Most open exposures first. */
  assets: string[];
  /** Most exposures first. */
  threats: string[];
  cells: MatrixCell[];
}

const WORST: Record<MatrixCell['worst'], number> = { confirmed: 0, open: 1, mitigated: 2, refuted: 3, accepted: 4 };

/** Exposures per (asset, threat) pair with the worst status and highest severity among them. */
export function computeAssetThreatMatrix(claims: ClaimLike[]): AssetThreatMatrix {
  const cells = new Map<string, MatrixCell>();
  for (const c of claims) {
    if (c.verb === 'mitigates' || c.status === 'control') continue;
    const k = `${c.asset} ${c.threat}`;
    let cell = cells.get(k);
    if (!cell) {
      cell = { asset: c.asset, threat: c.threat, total: 0, open: 0, mitigated: 0, accepted: 0, confirmed: 0, refuted: 0, worst: 'accepted', maxSev: 'unset' };
      cells.set(k, cell);
    }
    cell.total++;
    cell[c.status]++;
    if (WORST[c.status] < WORST[cell.worst]) cell.worst = c.status;
    if (SEV_ORDER.indexOf(sevOf(c.severity)) < SEV_ORDER.indexOf(cell.maxSev)) cell.maxSev = sevOf(c.severity);
  }
  const assetOpen = new Map<string, { open: number; total: number }>();
  const threatTotal = new Map<string, number>();
  for (const cell of cells.values()) {
    const a = assetOpen.get(cell.asset) ?? { open: 0, total: 0 };
    a.open += cell.open + cell.confirmed;
    a.total += cell.total;
    assetOpen.set(cell.asset, a);
    threatTotal.set(cell.threat, (threatTotal.get(cell.threat) ?? 0) + cell.total);
  }
  const assets = [...assetOpen].sort((x, y) => y[1].open - x[1].open || y[1].total - x[1].total || byName(x[0], y[0])).map(e => e[0]);
  const threats = [...threatTotal].sort((x, y) => y[1] - x[1] || byName(x[0], y[0])).map(e => e[0]);
  return { assets, threats, cells: [...cells.values()] };
}

export interface ControlCoverage {
  control: string;
  name: string;
  mitigations: number;
  threats: string[];
  assets: string[];
  unused: boolean;
}

/** What each declared control actually mitigates; a control nothing references is flagged unused. */
export function computeControlCoverage(model: ThreatModel): ControlCoverage[] {
  const rows = new Map<string, ControlCoverage>();
  const refOf = (c: { id?: string | null; name: string }): string => (c.id ? `#${c.id}` : c.name);
  for (const c of model.controls) rows.set(refOf(c).toLowerCase(), { control: refOf(c), name: c.name, mitigations: 0, threats: [], assets: [], unused: true });
  for (const m of model.mitigations) {
    if (!m.control) continue;
    const key = m.control.toLowerCase();
    let row = rows.get(key);
    if (!row) {
      row = { control: m.control, name: m.control.replace(/^#/, ''), mitigations: 0, threats: [], assets: [], unused: true };
      rows.set(key, row);
    }
    row.mitigations++;
    row.unused = false;
    if (!row.threats.includes(m.threat)) row.threats.push(m.threat);
    if (!row.assets.includes(m.asset)) row.assets.push(m.asset);
  }
  for (const r of rows.values()) { r.threats.sort(byName); r.assets.sort(byName); }
  return [...rows.values()].sort((a, b) => Number(a.unused) - Number(b.unused) || b.mitigations - a.mitigations || byName(a.control, b.control));
}

export type StatusKey = 'open' | 'mitigated' | 'accepted' | 'confirmed' | 'refuted';

export interface SeverityStatus {
  rows: SevKey[];
  cols: StatusKey[];
  counts: Record<SevKey, Record<StatusKey, number>>;
  totals: Record<StatusKey, number>;
  bySeverity: Record<SevKey, number>;
}

export function computeSeverityStatus(claims: ClaimLike[]): SeverityStatus {
  const cols: StatusKey[] = ['open', 'mitigated', 'refuted', 'accepted', 'confirmed'];
  const blank = (): Record<StatusKey, number> => ({ open: 0, mitigated: 0, refuted: 0, accepted: 0, confirmed: 0 });
  const counts: Record<SevKey, Record<StatusKey, number>> = { critical: blank(), high: blank(), medium: blank(), low: blank(), unset: blank() };
  const totals = blank();
  const bySeverity: Record<SevKey, number> = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  for (const c of claims) {
    if (c.verb === 'mitigates' || c.status === 'control') continue;
    const s = sevOf(c.severity);
    counts[s][c.status]++;
    totals[c.status]++;
    bySeverity[s]++;
  }
  return { rows: SEV_ORDER, cols, counts, totals, bySeverity };
}

export interface AssetDetail {
  name: string;
  riskLevel: AssetHeatmapEntry['riskLevel'];
  exposures: { total: number; open: number; mitigated: number; accepted: number; confirmed: number; refuted: number };
  /** Open exposures by severity. */
  bySeverity: Record<SevKey, number>;
  threats: { threat: string; open: number; total: number }[];
  controls: { control: string; count: number }[];
  flowsIn: { from: string; via: string }[];
  flowsOut: { to: string; via: string }[];
  dataHandling: string[];
  boundaries: string[];
  owners: string[];
  audits: number;
  assumptions: number;
  validations: number;
  files: { file: string; claims: number }[];
  states: { verified: number; stale: number; unverified: number } | null;
  attribution: { introducers: { identity: string; count: number }[]; ai: number; aiTools: string[]; oldestOpenDays: number | null } | null;
  /** Indices into claimsData for this asset's claims. */
  claimIdx: number[];
}

const DAY = 86_400_000;

/** Everything the asset drawer shows, one entry per heatmap tile (same order). */
export function computeAssetDetails(model: ThreatModel, claims: ClaimLike[], heatmap: AssetHeatmapEntry[], asOf: string | null): AssetDetail[] {
  const key = (ref: string): string => ref.trim().toLowerCase();
  const asOfMs = asOf ? Date.parse(asOf) : Number.NaN;
  return heatmap.map(tile => {
    const names = new Set([tile.name, ...tile.aliases].map(key));
    const is = (ref: string | undefined | null): boolean => names.has(key(ref || ''));
    const mine = claims.filter(c => is(c.asset));
    const exp = mine.filter(c => c.verb !== 'mitigates');
    const exposures = { total: exp.length, open: 0, mitigated: 0, accepted: 0, confirmed: 0, refuted: 0 };
    const bySeverity: Record<SevKey, number> = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
    const threatMap = new Map<string, { threat: string; open: number; total: number }>();
    for (const c of exp) {
      if (c.status !== 'control') exposures[c.status]++;
      const isOpen = c.status === 'open' || c.status === 'confirmed';
      if (isOpen) bySeverity[sevOf(c.severity)]++;
      const t = threatMap.get(c.threat) ?? { threat: c.threat, open: 0, total: 0 };
      t.total++;
      if (isOpen) t.open++;
      threatMap.set(c.threat, t);
    }
    const controlMap = new Map<string, number>();
    for (const m of model.mitigations) if (is(m.asset) && m.control) controlMap.set(m.control, (controlMap.get(m.control) ?? 0) + 1);
    const fileMap = new Map<string, number>();
    for (const c of mine) fileMap.set(c.file, (fileMap.get(c.file) ?? 0) + 1);
    const states = { verified: 0, stale: 0, unverified: 0 };
    let anyState = false;
    for (const c of mine) if (c.state) { states[c.state]++; anyState = true; }
    const introducers = new Map<string, number>();
    const aiTools = new Set<string>();
    let ai = 0;
    let blamed = 0;
    let oldest: number | null = null;
    for (const c of exp) {
      const r = c.blame?.introduced;
      if (!r) continue;
      blamed++;
      for (const id of [r.author, ...r.co]) if (!id.startsWith('agent:')) introducers.set(id, (introducers.get(id) ?? 0) + 1);
      if (r.ai.length > 0) { ai++; for (const t of r.ai) aiTools.add(t); }
      if ((c.status === 'open' || c.status === 'confirmed') && !Number.isNaN(asOfMs)) {
        const days = Math.max(0, Math.floor((asOfMs - Date.parse(r.date)) / DAY));
        if (oldest === null || days > oldest) oldest = days;
      }
    }
    return {
      name: tile.name,
      riskLevel: tile.riskLevel,
      exposures,
      bySeverity,
      threats: [...threatMap.values()].sort((a, b) => b.open - a.open || b.total - a.total || byName(a.threat, b.threat)),
      controls: [...controlMap].map(([control, count]) => ({ control, count })).sort((a, b) => b.count - a.count || byName(a.control, b.control)),
      flowsIn: model.flows.filter(f => is(f.target)).map(f => ({ from: f.source, via: f.mechanism || '' })),
      flowsOut: model.flows.filter(f => is(f.source)).map(f => ({ to: f.target, via: f.mechanism || '' })),
      dataHandling: [...new Set(model.data_handling.filter(d => is(d.asset)).map(d => d.classification))],
      boundaries: model.boundaries.filter(b => is(b.asset_a) || is(b.asset_b)).map(b => (is(b.asset_a) ? b.asset_b : b.asset_a)),
      owners: model.ownership.filter(o => is(o.asset)).map(o => o.owner),
      audits: model.audits.filter(a => is(a.asset)).length,
      assumptions: model.assumptions.filter(a => is(a.asset)).length,
      validations: model.validations.filter(v => is(v.asset)).length,
      files: [...fileMap].map(([file, n]) => ({ file, claims: n })).sort((a, b) => b.claims - a.claims || byName(a.file, b.file)),
      states: anyState ? states : null,
      attribution: blamed > 0 ? {
        introducers: [...introducers].map(([identity, count]) => ({ identity, count })).sort((a, b) => b.count - a.count || byName(a.identity, b.identity)).slice(0, 5),
        ai,
        aiTools: [...aiTools].sort(byName),
        oldestOpenDays: oldest,
      } : null,
      claimIdx: mine.map(c => c.idx),
    };
  });
}

export interface HeatGrid {
  rows: string[];
  cols: string[];
  /** cells[row][col] */
  cells: number[][];
  unit: 'quarter' | 'year';
}

const quarterOf = (date: string): string => `${date.slice(0, 4)}-Q${Math.floor((Number(date.slice(5, 7)) - 1) / 3) + 1}`;

/** Exposures introduced per person per period (top ten introducers). */
export function computeIntroductionHeat(claims: ClaimLike[]): HeatGrid {
  const perPerson = new Map<string, Map<string, number>>();
  const totals = new Map<string, number>();
  const quarters = new Set<string>();
  for (const c of claims) {
    const r = c.blame?.introduced;
    if (!r || c.verb === 'mitigates') continue;
    const q = quarterOf(r.date);
    quarters.add(q);
    for (const id of [r.author, ...r.co]) {
      if (id.startsWith('agent:')) continue;
      const m = perPerson.get(id) ?? new Map<string, number>();
      m.set(q, (m.get(q) ?? 0) + 1);
      perPerson.set(id, m);
      totals.set(id, (totals.get(id) ?? 0) + 1);
    }
  }
  const unit: HeatGrid['unit'] = quarters.size > 16 ? 'year' : 'quarter';
  const period = (q: string): string => (unit === 'year' ? q.slice(0, 4) : q);
  const cols = [...new Set([...quarters].map(period))].sort();
  const rows = [...totals].sort((a, b) => b[1] - a[1] || byName(a[0], b[0])).slice(0, 10).map(e => e[0]);
  const cells = rows.map(r => cols.map(col => {
    let n = 0;
    for (const [q, v] of perPerson.get(r) ?? []) if (period(q) === col) n += v;
    return n;
  }));
  return { rows, cols, cells, unit };
}

/** Exposures introduced with each AI tool, by severity. */
export function computeToolSeverity(claims: ClaimLike[]): { rows: string[]; cols: SevKey[]; cells: number[][] } {
  const grid = new Map<string, Record<SevKey, number>>();
  for (const c of claims) {
    const r = c.blame?.introduced;
    if (!r || c.verb === 'mitigates') continue;
    for (const tool of r.ai) {
      const row = grid.get(tool) ?? { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
      row[sevOf(c.severity)]++;
      grid.set(tool, row);
    }
  }
  const sum = (r: Record<SevKey, number>): number => SEV_ORDER.reduce((n, s) => n + r[s], 0);
  const rows = [...grid].sort((a, b) => sum(b[1]) - sum(a[1]) || byName(a[0], b[0])).map(e => e[0]);
  return { rows, cols: SEV_ORDER, cells: rows.map(r => SEV_ORDER.map(s => grid.get(r)![s])) };
}
