/**
 * GuardLink Dashboard — the model every diagram on the page is drawn from.
 *
 * One pass over the threat model and the claim rows the tables already use,
 * folded onto canonical keys: `#api`, `api` and `App.API` are one asset, `#xss`
 * and `XSS` one threat. Each diagram module (threat graph, flow ribbons,
 * neighbourhood, shelves, matrix) reads this rather than the raw model, so the
 * pictures cannot disagree with each other or with the tables about what an
 * asset carries.
 *
 * A flow endpoint that is not a declared asset is an EXTERNAL node: outside the
 * model. It is drawn dashed, and when a `@boundary` names it, it sits in the
 * "Across a trust line" zone.
 *
 * @comment -- "Pure: no I/O, no DOM. Every string here is raw model text; the renderers escape it at the point they emit markup"
 */
import type { ThreatModel } from '../../types/index.js';
import { canonicaliser } from '../../parser/canonical-ref.js';
import type { ClaimView } from '../pages/context.js';

export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'unset';
export const SEVS: Sev[] = ['critical', 'high', 'medium', 'low', 'unset'];
export const SEV_RANK: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3, unset: 4 };

/** The state a single claim is in, as the diagrams draw it. */
export type MarkState = 'open' | 'confirmed' | 'mitigated' | 'refuted' | 'accepted';

export function sevOf(s: string | undefined | null): Sev {
  const l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'critical';
  if (l === 'high' || l === 'p1') return 'high';
  if (l === 'medium' || l === 'p2') return 'medium';
  if (l === 'low' || l === 'p3') return 'low';
  return 'unset';
}

/** Open and confirmed are the two states that still need someone to act. */
export const isOpenState = (s: MarkState): boolean => s === 'open' || s === 'confirmed';

export interface GExposure {
  /** Index into the page's claimsData. */
  claim: number;
  asset: string;
  threat: string;
  sev: Sev;
  state: MarkState;
  description: string;
  file: string;
  line: number;
}

export interface GMitigation {
  claim: number;
  asset: string;
  threat: string;
  /** Canonical control key; '' when the @mitigates names no control. */
  control: string;
  file: string;
  line: number;
}

export interface GFlow {
  i: number;
  source: string;
  target: string;
  via: string;
  description: string;
  file: string;
  line: number;
  /** The boundary this flow crosses, by label, or null. */
  boundary: string | null;
}

export interface GNode {
  key: string;
  label: string;
  external: boolean;
  /** Shelf / zone group: `path[0]` for a declared asset with a dotted path. */
  group: string;
  /** Model order (declaration order); externals sort after every asset. */
  order: number;
  description: string;
  exposures: GExposure[];
  open: number;
  worst: Sev | null;
  flowsIn: GFlow[];
  flowsOut: GFlow[];
  /** Labels of the trust boundaries this node sits on. */
  boundaries: string[];
  handles: string[];
}

export interface GThreat { key: string; label: string; sev: Sev; /** The definition's name, when one is declared. */ name: string }
export interface GControl { key: string; label: string }

export interface DiagramModel {
  nodes: Map<string, GNode>;
  /** Declared assets plus undeclared assets that carry claims, in model order. */
  assets: GNode[];
  externals: GNode[];
  threats: Map<string, GThreat>;
  controls: Map<string, GControl>;
  exposures: GExposure[];
  mitigations: GMitigation[];
  flows: GFlow[];
  /** Zone keys of externals named by a @boundary. */
  boundaryExternals: Set<string>;
  assetKey: (ref: string) => string;
  threatKey: (ref: string) => string;
  controlKey: (ref: string) => string;
}

/** `#id` when the definition has one, else the name as written. */
const refLabel = (d: { id?: string; name: string }): string => (d.id ? `#${d.id}` : d.name);

/** One key per definition, reachable by `#id`, `id`, name and canonical name. */
function definitionKeys(defs: { id?: string; name: string; canonical_name: string }[]): (ref: string) => string {
  const canon = new Map<string, string>();
  for (const d of defs) {
    const key = (d.id ?? d.canonical_name ?? d.name).toLowerCase();
    for (const alias of [d.id, d.name, d.canonical_name]) if (alias) canon.set(alias.toLowerCase(), key);
  }
  return (ref: string) => {
    const bare = (ref ?? '').trim().replace(/^#/, '').toLowerCase();
    return canon.get(bare) ?? bare;
  };
}

function stateOf(c: ClaimView): MarkState {
  if (c.verb === 'confirmed') return 'confirmed';
  if (c.status === 'mitigated' || c.status === 'accepted' || c.status === 'refuted') return c.status;
  return 'open';
}

export function buildDiagramModel(model: ThreatModel, claims: ClaimView[]): DiagramModel {
  const assetKey = canonicaliser(model);
  const threatKey = definitionKeys(model.threats);
  const controlKey = definitionKeys(model.controls);

  const nodes = new Map<string, GNode>();
  const blank = (key: string, label: string, external: boolean, group: string, order: number, description = ''): GNode => ({
    key, label, external, group, order, description, exposures: [], open: 0, worst: null, flowsIn: [], flowsOut: [], boundaries: [], handles: [],
  });
  model.assets.forEach((a, i) => {
    const key = assetKey(a.id || a.path.join('.'));
    if (nodes.has(key)) return;
    nodes.set(key, blank(key, a.id ? `#${a.id}` : a.path.join('.'), false, a.path.length > 1 ? a.path[0] : 'Model', i, a.description ?? ''));
  });
  let order = model.assets.length;
  /** An asset a claim names that no @asset declares: still an asset, in the "Model" group. */
  const ensureAsset = (ref: string): GNode => {
    const key = assetKey(ref);
    let n = nodes.get(key);
    if (!n) { n = blank(key, ref.trim(), false, 'Model', order++); nodes.set(key, n); }
    return n;
  };
  // A `#ref` names an asset even when nothing declares it — unless it names an
  // @actor, which is a principal and so sits outside the model like any other
  // undeclared endpoint (`User`, `External.Stripe`).
  const actorKeys = new Set((model.actors ?? []).flatMap(a => [a.id, a.name, a.canonical_name].filter(Boolean).map(x => String(x).toLowerCase())));
  const ensureEndpoint = (ref: string): GNode => {
    const key = assetKey(ref);
    const known = nodes.get(key);
    if (known) return known;
    if (ref.trim().startsWith('#') && !actorKeys.has(key)) return ensureAsset(ref);
    const n = blank(key, ref.trim(), true, '', 1e6 + nodes.size);
    nodes.set(key, n);
    return n;
  };

  const threats = new Map<string, GThreat>();
  for (const t of model.threats) threats.set(threatKey(refLabel(t)), { key: threatKey(refLabel(t)), label: refLabel(t), sev: sevOf(t.severity), name: t.name });
  const ensureThreat = (ref: string, sev: Sev): string => {
    const k = threatKey(ref);
    if (!threats.has(k)) threats.set(k, { key: k, label: ref.trim(), sev, name: '' });
    return k;
  };
  const controls = new Map<string, GControl>();
  for (const c of model.controls) controls.set(controlKey(refLabel(c)), { key: controlKey(refLabel(c)), label: refLabel(c) });
  const ensureControl = (ref: string): string => {
    const k = controlKey(ref);
    if (!controls.has(k)) controls.set(k, { key: k, label: ref.trim() });
    return k;
  };

  const exposures: GExposure[] = [];
  const mitigations: GMitigation[] = [];
  for (const c of claims) {
    if (c.verb === 'mitigates') {
      const asset = ensureAsset(c.asset).key;
      mitigations.push({ claim: c.idx, asset, threat: ensureThreat(c.threat, 'unset'), control: c.control ? ensureControl(c.control) : '', file: c.file, line: c.line });
      continue;
    }
    const n = ensureAsset(c.asset);
    const e: GExposure = { claim: c.idx, asset: n.key, threat: ensureThreat(c.threat, sevOf(c.severity)), sev: sevOf(c.severity), state: stateOf(c), description: c.description, file: c.file, line: c.line };
    exposures.push(e);
    n.exposures.push(e);
  }

  for (const h of model.data_handling) {
    if (!h.asset) continue;
    const n = nodes.get(assetKey(h.asset));
    if (n && !n.handles.includes(h.classification)) n.handles.push(h.classification);
  }

  const boundaryOf = new Map<string, string>();
  const boundaryExternals = new Set<string>();
  model.boundaries.forEach((b, i) => {
    const label = b.id ? `#${b.id}` : b.description ? `${b.asset_a} ↔ ${b.asset_b}` : `boundary ${i + 1}`;
    const a = ensureEndpoint(b.asset_a), z = ensureEndpoint(b.asset_b);
    for (const n of [a, z]) {
      if (!n.boundaries.includes(label)) n.boundaries.push(label);
      if (n.external) boundaryExternals.add(n.key);
    }
    boundaryOf.set(`${a.key}\u0000${z.key}`, label);
    boundaryOf.set(`${z.key}\u0000${a.key}`, label);
  });

  const flows: GFlow[] = model.flows.map((f, i) => {
    const s = ensureEndpoint(f.source), t = ensureEndpoint(f.target);
    const g: GFlow = {
      i, source: s.key, target: t.key, via: f.mechanism ?? '', description: f.description ?? '',
      file: f.location?.file ?? '', line: f.location?.line ?? 0, boundary: boundaryOf.get(`${s.key}\u0000${t.key}`) ?? null,
    };
    s.flowsOut.push(g);
    t.flowsIn.push(g);
    return g;
  });

  for (const n of nodes.values()) {
    const open = n.exposures.filter(e => isOpenState(e.state));
    n.open = open.length;
    n.worst = open.length ? open.reduce<Sev>((w, e) => (SEV_RANK[e.sev] < SEV_RANK[w] ? e.sev : w), 'unset') : null;
    n.handles.sort();
  }

  const all = [...nodes.values()];
  return {
    nodes,
    assets: all.filter(n => !n.external).sort((a, b) => a.order - b.order),
    externals: all.filter(n => n.external).sort((a, b) => a.order - b.order),
    threats, controls, exposures, mitigations, flows, boundaryExternals,
    assetKey, threatKey, controlKey,
  };
}

/** How a node's mark reads: worst open severity, all resolved, nothing declared, or outside the model. */
export type NodeMark = { kind: 'open'; sev: Sev } | { kind: 'resolved' } | { kind: 'empty' } | { kind: 'external' };

export function markOf(n: GNode): NodeMark {
  if (n.external) return { kind: 'external' };
  if (n.open > 0) return { kind: 'open', sev: n.worst ?? 'unset' };
  if (n.exposures.length > 0) return { kind: 'resolved' };
  return { kind: 'empty' };
}

export function markLabel(n: GNode): string {
  const m = markOf(n);
  if (m.kind === 'external') return n.boundaries.length ? 'outside the model · across a trust line' : 'outside the model';
  if (m.kind === 'open') return `${n.open} open · worst ${m.sev}`;
  if (m.kind === 'resolved') return `all ${n.exposures.length} mitigated or accepted`;
  return 'no exposure declared';
}
