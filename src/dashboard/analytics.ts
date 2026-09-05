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
  status: 'open' | 'mitigated' | 'accepted' | 'confirmed' | 'control';
  asset: string;
  threat: string;
  severity: string;
  file: string;
  state: ClaimState | null;
  blame: { introduced: { date: string; author: string; co: string[]; ai: string[] } | null } | null;
}

export interface MatrixCell {
  asset: string;
  threat: string;
  total: number;
  open: number;
  mitigated: number;
  accepted: number;
  confirmed: number;
  worst: 'confirmed' | 'open' | 'mitigated' | 'accepted';
  maxSev: SevKey;
}

export interface AssetThreatMatrix {
  /** Most open exposures first. */
  assets: string[];
  /** Most exposures first. */
  threats: string[];
  cells: MatrixCell[];
}

const WORST: Record<MatrixCell['worst'], number> = { confirmed: 0, open: 1, mitigated: 2, accepted: 3 };

/** Exposures per (asset, threat) pair with the worst status and highest severity among them. */
export function computeAssetThreatMatrix(claims: ClaimLike[]): AssetThreatMatrix {
  const cells = new Map<string, MatrixCell>();
  for (const c of claims) {
    if (c.verb === 'mitigates' || c.status === 'control') continue;
    const k = `${c.asset} ${c.threat}`;
    let cell = cells.get(k);
    if (!cell) {
      cell = { asset: c.asset, threat: c.threat, total: 0, open: 0, mitigated: 0, accepted: 0, confirmed: 0, worst: 'accepted', maxSev: 'unset' };
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

export type StatusKey = 'open' | 'mitigated' | 'accepted' | 'confirmed';

export interface SeverityStatus {
  rows: SevKey[];
  cols: StatusKey[];
  counts: Record<SevKey, Record<StatusKey, number>>;
  totals: Record<StatusKey, number>;
  bySeverity: Record<SevKey, number>;
}

export function computeSeverityStatus(claims: ClaimLike[]): SeverityStatus {
  const cols: StatusKey[] = ['open', 'mitigated', 'accepted', 'confirmed'];
  const blank = (): Record<StatusKey, number> => ({ open: 0, mitigated: 0, accepted: 0, confirmed: 0 });
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
  exposures: { total: number; open: number; mitigated: number; accepted: number; confirmed: number };
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
    const exposures = { total: exp.length, open: 0, mitigated: 0, accepted: 0, confirmed: 0 };
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
