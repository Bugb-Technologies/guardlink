/**
 * GuardLink Dashboard — Diagrams › System model: the classic threat-model
 * data-flow diagram, with the model's trust boundaries drawn as zones.
 *
 * Left to right:
 *   trust zones   every endpoint a `@boundary` fences off, in a dashed zone
 *                 labelled with its boundaries and their tested state
 *   the system    one row per declared asset (a process). An endpoint only that
 *                 asset touches sits on its row; asset ↔ asset flows are arcs
 *   shared        endpoints several assets touch, with no boundary declared
 *
 * A `@boundary` is a pair, not a region, so the zones are derived:
 *   - An undeclared endpoint a boundary names gets an outer zone; fenced
 *     endpoints joined by an undeclared flow share one.
 *   - Declared assets are one zone until a boundary between two assets splits
 *     them. An undeclared asset ↔ asset flow holds a zone together, so a
 *     boundary with a way around it cannot enclose a region: it stays a gate
 *     on the flows it names, and the result says which boundaries those are.
 *   - Split zones are ordered outer → inner: a directed boundary is a strong
 *     edge, a flow a weak one, and a zone fed from across an outer boundary
 *     comes first.
 *   - An endpoint no boundary names is drawn where the model puts it — beside
 *     what it touches, never inside a zone the model did not declare.
 *
 * Every flow is drawn. Repeat flows between one pair share a line and are
 * listed in its tooltip. A flow that leaves a fenced endpoint for an asset the
 * boundary does not name is drawn bold and dashed: the picture shows it
 * crossing the zone's edge, and no boundary says so.
 *
 * Element kinds (process, data store, external entity) are not declared in the
 * model. They are inferred here, in one place, and every tooltip says so.
 *
 * Laid out from data and estimated glyph widths; nothing is measured.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Node labels, mechanisms, descriptions and boundary text reach the SVG only through xml() and attrs()"
 */
import type { DiagramModel, GBoundary, GFlow, GNode } from './graph.js';
import { attrs, cutLeft, dotPattern, plural, r1, textWidth, tip, xml } from './text.js';

export type ElementKind = 'process' | 'store' | 'entity';
export type BoundaryState = 'unverified' | 'supported' | 'contradicted' | 'retest';

const KIND_WORD: Record<ElementKind, string> = { process: 'process', store: 'data store', entity: 'external entity' };
const STATE_GLYPH: Record<BoundaryState, string> = { unverified: '○', supported: '✓', contradicted: '✕', retest: '◐' };

const ASSET_STORE = /(^|[-_.])(db|database|store|table|bucket|queue|cache|ledger|registry)([-_.]|$)/i;
const STORE_NAME = /(file|store|db|database|ledger|log|report|config|json|sarif|html|markdown|cache|dir\b|repo|registry|state|source|trailer|annotation|suggestion|proposal|diagnostic|model|list|root|backup|disk|filesystem|table|bucket|queue|ref\b)/i;
const STORE_VIA = /(readFile|writeFile|readdir|existsSync|mkdtemp|fs\.|sqlite|pg_dump|\bquery\b|\bopen\b)/i;

/**
 * The DFD kind of a node, inferred: the model declares none. A declared asset
 * is a process unless its name says it holds data (`#orders-db`, `#outbox-queue`).
 * An undeclared endpoint is an external entity when it is an `@actor` or an
 * `External.*` name, a data store when its name or a flow's mechanism says
 * file, config, ledger, repo or database, and otherwise an external entity.
 */
export function inferKind(n: GNode): ElementKind {
  const name = n.label.replace(/^#/, '');
  if (!n.external) return ASSET_STORE.test(name) ? 'store' : 'process';
  if (n.actor || /^External\./.test(n.label)) return 'entity';
  if (STORE_NAME.test(name)) return 'store';
  if ([...n.flowsIn, ...n.flowsOut].some(f => STORE_VIA.test(f.via))) return 'store';
  return 'entity';
}

/** How a flow is drawn. */
export type FlowClass = 'cross' | 'implied' | 'arc' | 'local';

export interface SystemOptions {
  /** Tested state per boundary, keyed `file:line` (the hypothesis ledger's boundary claims). */
  states?: Map<string, BoundaryState>;
  /** Prefix for element ids, so two plots on one page never share one. */
  id?: string;
}

export interface SystemResult {
  svg: string;
  elements: number;
  processes: number;
  stores: number;
  entities: number;
  flows: number;
  lines: number;
  /** Flows a boundary names, asset ↔ endpoint or asset ↔ asset. */
  crossing: number;
  /** Flows that leave a fenced endpoint for an asset its boundary does not name. */
  implied: number;
  boundaries: number;
  outerZones: number;
  innerZones: number;
  /** Boundaries no flow crosses as declared. */
  silent: string[];
  /** Asset ↔ asset boundaries with an undeclared route around them: drawn as gates, not zones. */
  unsplit: string[];
}

interface Box { x: number; y: number; w: number; h: number }
interface Placed<T> { item: T; h: number; want: number; top: number }

/** Place boxes centred on what they want, then push apart top-down so none overlap. */
function spread<T>(items: Placed<T>[], minTop: number, gap: number): void {
  let y = minTop;
  for (const it of items) { it.top = Math.max(y, it.want - it.h / 2); y = it.top + it.h + gap; }
}

const PAIR = (a: string, b: string): string => (a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`);

export function renderSystemModel(m: DiagramModel, opts: SystemOptions = {}): SystemResult | null {
  if (m.flows.length === 0) return null;
  const pid = opts.id ?? 'sys';
  const states = opts.states ?? new Map<string, BoundaryState>();
  const nodes = [...m.assets, ...m.externals];
  const kind = new Map(nodes.map(n => [n.key, inferKind(n)] as const));
  const isAsset = (k: string): boolean => !m.nodes.get(k)!.external;
  const byPair = new Map<string, GBoundary[]>();
  for (const b of m.boundaryList) {
    const k = PAIR(b.a, b.z);
    if (!byPair.has(k)) byPair.set(k, []);
    byPair.get(k)!.push(b);
  }
  const named = (s: string, t: string): GBoundary[] => byPair.get(PAIR(s, t)) ?? [];

  // ── Zones ────────────────────────────────────────────────────────────────
  const fenced = new Set<string>();
  for (const b of m.boundaryList) for (const k of [b.a, b.z]) if (!isAsset(k)) fenced.add(k);
  const parent = new Map(nodes.map(n => [n.key, n.key] as const));
  const find = (k: string): string => { while (parent.get(k) !== k) { parent.set(k, parent.get(parent.get(k)!)!); k = parent.get(k)!; } return k; };
  const union = (a: string, b: string): void => { const x = find(a), y = find(b); if (x !== y) parent.set(x, y); };
  for (const f of m.flows) if (f.source !== f.target && !named(f.source, f.target).length && fenced.has(f.source) && fenced.has(f.target)) union(f.source, f.target);

  const assetLines = m.boundaryList.filter(b => isAsset(b.a) && isAsset(b.z) && b.a !== b.z);
  let inner: string[][];
  if (!assetLines.length) inner = [m.assets.map(a => a.key)];
  else {
    for (const f of m.flows) if (isAsset(f.source) && isAsset(f.target) && f.source !== f.target && !named(f.source, f.target).length) union(f.source, f.target);
    const comp = new Map<string, string[]>();
    for (const a of m.assets) { const r = find(a.key); if (!comp.has(r)) comp.set(r, []); comp.get(r)!.push(a.key); }
    const onLine = new Set(assetLines.flatMap(b => [b.a, b.z]));
    let zones = [...comp.values()];
    const loose = zones.filter(z => z.length === 1 && !onLine.has(z[0]));
    zones = zones.filter(z => !loose.includes(z)).sort((a, b) => b.length - a.length);
    if (!zones.length) zones = [[]];
    for (const z of loose) zones[0].push(...z);
    const zoneOf = new Map<string, number>();
    zones.forEach((z, i) => z.forEach(k => zoneOf.set(k, i)));
    const w = zones.map(() => zones.map(() => 0));
    for (const b of assetLines) { const za = zoneOf.get(b.a)!, zb = zoneOf.get(b.z)!; if (za !== zb && b.directed) w[za][zb] += 3; }
    for (const f of m.flows) {
      if (!isAsset(f.source) || !isAsset(f.target)) continue;
      const za = zoneOf.get(f.source)!, zb = zoneOf.get(f.target)!;
      if (za !== zb) w[za][zb] += 1;
    }
    const fed = zones.map(() => 0);
    for (const f of m.flows) if (fenced.has(f.source) && isAsset(f.target)) fed[zoneOf.get(f.target)!]++;
    const first = (i: number): number => Math.min(...zones[i].map(k => m.nodes.get(k)!.order));
    const left = new Set(zones.map((_, i) => i));
    const order: number[] = [];
    while (left.size) {
      const inW = (i: number): number => [...left].reduce((s, j) => s + Math.max(0, w[j][i] - w[i][j]), 0);
      const next = [...left].sort((a, b) => inW(a) - inW(b) || fed[b] - fed[a] || first(a) - first(b))[0];
      order.push(next); left.delete(next);
    }
    inner = order.map(i => zones[i]);
  }
  const innerOf = new Map<string, number>();
  inner.forEach((z, i) => z.forEach(k => innerOf.set(k, i)));
  const split = inner.length > 1;

  const outerGroups = new Map<string, string[]>();
  for (const k of fenced) { const r = find(k); if (!outerGroups.has(r)) outerGroups.set(r, []); outerGroups.get(r)!.push(k); }
  const outer = [...outerGroups.values()].map(members => ({
    members: members.sort((a, b) => m.nodes.get(a)!.order - m.nodes.get(b)!.order),
    lines: m.boundaryList.filter(b => members.includes(b.a) || members.includes(b.z)),
  }));
  const outerOf = new Map<string, number>();
  outer.forEach((o, i) => o.members.forEach(k => outerOf.set(k, i)));

  // ── Flow classes ─────────────────────────────────────────────────────────
  const cls = (f: GFlow): FlowClass => {
    const sa = isAsset(f.source), ta = isAsset(f.target);
    if (sa && ta) return 'arc';
    if (f.boundaries.length) return 'cross';
    if ((fenced.has(f.source) && ta) || (fenced.has(f.target) && sa)) return 'implied';
    return 'local';
  };

  // Endpoints no boundary names: on the row of the one asset they touch, or shared.
  const partners = new Map<string, Set<string>>();
  for (const f of m.flows) for (const [a, b] of [[f.source, f.target], [f.target, f.source]]) {
    if (!partners.has(a)) partners.set(a, new Set());
    if (a !== b) partners.get(a)!.add(b);
  }
  const onRow = new Map<string, string[]>();
  const shared: string[] = [];
  const loose: string[] = [];
  for (const n of m.externals) {
    if (fenced.has(n.key)) continue;
    const ps = [...(partners.get(n.key) ?? [])].filter(isAsset);
    if (ps.length === 1) { if (!onRow.has(ps[0])) onRow.set(ps[0], []); onRow.get(ps[0])!.push(n.key); }
    else if (ps.length > 1) shared.push(n.key);
    else loose.push(n.key);
  }

  // ── Geometry ─────────────────────────────────────────────────────────────
  const hasOuter = outer.length > 0;
  const ZX = 16, ZW = hasOuter ? 212 : 0, GUT = hasOuter ? 88 : 0;
  const FX = ZX + ZW + GUT;
  const CAPX = FX + (split ? 30 : 22), CAPW = 188, CAPH = 30;
  const PER_LINE = 2, CHIPW = 132, CHIPH = 24, CHIPGAP = 8, ARCW = 92;
  const SATX = CAPX + CAPW + ARCW;
  const rowMax = Math.max(0, ...[...onRow.values()].map(l => l.length));
  const PORTX = SATX + (rowMax ? Math.min(PER_LINE, rowMax) * (CHIPW + CHIPGAP) : 0) + 6;
  const hasShared = shared.length + loose.length > 0;
  const SHX = PORTX + (hasShared ? 104 : 0), SHW = hasShared ? 150 : 0;
  const FR = (hasShared ? SHX + SHW : PORTX) + 18;
  const W = FR + 4;
  const TOP = 54;

  // Rows: by inner zone, then by group; within a group by barycentre, six sweeps.
  const groups = inner.map(z => {
    const g = new Map<string, string[]>();
    for (const k of z.slice().sort((a, b) => m.nodes.get(a)!.order - m.nodes.get(b)!.order)) {
      const gn = m.nodes.get(k)!.group || 'Model';
      if (!g.has(gn)) g.set(gn, []);
      g.get(gn)!.push(k);
    }
    return g;
  });
  const showGroups = new Set(m.assets.map(a => a.group || 'Model')).size > 1;
  const sideOf = (k: string): string | null => (outerOf.has(k) ? `o${outerOf.get(k)}` : shared.includes(k) ? `s${k}` : null);
  let rowPos = new Map<string, number>();
  let p = 0;
  for (const g of groups) for (const list of g.values()) for (const k of list) rowPos.set(k, p++);
  for (let sweep = 0; sweep < 6; sweep++) {
    const acc = new Map<string, [number, number]>();
    for (const f of m.flows) for (const [a, b] of [[f.source, f.target], [f.target, f.source]]) {
      const s = sideOf(a);
      if (s && isAsset(b)) { const v = acc.get(s) ?? [0, 0]; v[0] += rowPos.get(b)!; v[1]++; acc.set(s, v); }
    }
    const sidePos = new Map([...acc].map(([k, [s, c]]) => [k, s / c] as const));
    const bary = new Map<string, number>();
    for (const a of m.assets) {
      let s = 0, c = 0;
      for (const f of [...a.flowsIn, ...a.flowsOut]) {
        const o = f.source === a.key ? f.target : f.source;
        const sp = sidePos.get(sideOf(o) ?? '');
        if (sp !== undefined) { s += sp; c++; } else if (isAsset(o) && o !== a.key) { s += rowPos.get(o)!; c++; }
      }
      bary.set(a.key, c ? s / c : rowPos.get(a.key)!);
    }
    p = 0;
    const next = new Map<string, number>();
    for (const g of groups) for (const [gn, list] of g) {
      list.sort((a, b) => bary.get(a)! - bary.get(b)! || rowPos.get(a)! - rowPos.get(b)!);
      g.set(gn, list);
      for (const k of list) next.set(k, p++);
    }
    rowPos = next;
  }

  const rows = new Map<string, { y: number; h: number; on: string[] }>();
  const bands: { top: number; bottom: number }[] = [];
  const heads: { y: number; label: string }[] = [];
  let y = TOP + 28;
  for (const g of groups) {
    const top = y - (split ? 6 : 0);
    if (split) y += 22;
    for (const [gn, list] of g) {
      if (showGroups) { heads.push({ y: y + 4, label: gn }); y += 22; }
      for (const k of list) {
        const on = onRow.get(k) ?? [];
        const h = Math.max(CAPH + 10, Math.ceil(Math.max(1, on.length) / PER_LINE) * (CHIPH + 6) + 4);
        rows.set(k, { y, h, on });
        y += h;
      }
      y += 6;
    }
    bands.push({ top, bottom: y + (split ? 2 : 0) });
    if (split) y += 18;
  }
  const frameBottom = y + 10;
  const rowMid = (k: string): number => rows.get(k)!.y + CAPH / 2;

  const zoneH = (o: typeof outer[number]): number => 30 + o.lines.length * 15 + o.members.length * 34 + 8;
  const ozs: Placed<number>[] = outer.map((o, i) => {
    const ys: number[] = [];
    for (const k of o.members) for (const q of partners.get(k) ?? []) if (isAsset(q)) ys.push(rowMid(q));
    return { item: i, h: zoneH(o), want: ys.length ? ys.reduce((s, v) => s + v, 0) / ys.length : TOP + 60, top: 0 };
  }).sort((a, b) => a.want - b.want || a.item - b.item);
  spread(ozs, TOP + 28, 14);

  const sideNodes = [...shared, ...loose];
  const shs: Placed<string>[] = sideNodes.map(k => {
    const ys = [...(partners.get(k) ?? [])].filter(isAsset).map(rowMid);
    return { item: k, h: CHIPH + 6, want: ys.length ? ys.reduce((s, v) => s + v, 0) / ys.length : frameBottom, top: 0 };
  }).sort((a, b) => a.want - b.want || m.nodes.get(a.item)!.order - m.nodes.get(b.item)!.order);
  spread(shs, TOP + 34, 4);

  const H = Math.ceil(Math.max(frameBottom, ...ozs.map(z => z.top + z.h), ...shs.map(s => s.top + s.h)) + 20);

  // ── Ids, lines and what each mark lights ─────────────────────────────────
  const nid = new Map(nodes.map((n, i) => [n.key, `${pid}y${i}`] as const));
  interface Line { s: string; t: string; flows: GFlow[]; cls: FlowClass; id: string }
  const lines = new Map<string, Line>();
  const rank: Record<FlowClass, number> = { cross: 0, implied: 1, arc: 2, local: 3 };
  for (const f of m.flows) {
    const k = `${f.source}\u0000${f.target}`;
    const c = cls(f);
    const l = lines.get(k);
    if (!l) lines.set(k, { s: f.source, t: f.target, flows: [f], cls: c, id: `${pid}e${lines.size}` });
    else { l.flows.push(f); if (rank[c] < rank[l.cls]) l.cls = c; }
  }
  const lights = new Map<string, Set<string>>();
  const light = (k: string, v: string): void => { if (!lights.has(k)) lights.set(k, new Set([nid.get(k)!])); lights.get(k)!.add(v); };
  for (const n of nodes) light(n.key, nid.get(n.key)!);
  for (const l of lines.values()) for (const [a, b] of [[l.s, l.t], [l.t, l.s]]) { light(a, l.id); light(a, nid.get(b)!); }

  // ── Emit ─────────────────────────────────────────────────────────────────
  const out: string[] = [];
  const crossing = m.flows.filter(f => f.boundaries.length).length;
  const implied = m.flows.filter(f => cls(f) === 'implied').length;
  out.push(`<svg${attrs({ class: 'dg sysm', 'data-plot': 'system', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': `System model: ${plural(nodes.length, 'element')}, ${plural(m.flows.length, 'flow')}, ${plural(m.boundaryList.length, 'trust boundary', 'trust boundaries')}; ${crossing} flows cross one as declared` })}>`);
  out.push(`<defs>${dotPattern(`${pid}-dots`)}<marker id="${pid}-ah" viewBox="0 0 8 6" refX="7.5" refY="3" markerWidth="7" markerHeight="5.5" orient="auto"><path d="M0 0L8 3L0 6z" class="arrowhead"/></marker><marker id="${pid}-ahx" viewBox="0 0 8 6" refX="7.5" refY="3" markerWidth="7" markerHeight="5.5" orient="auto"><path d="M0 0L8 3L0 6z" class="arrowhead strong"/></marker></defs>`);
  out.push(`<rect class="ground" width="${W}" height="${H}" fill="url(#${pid}-dots)"/>`);
  if (hasOuter) out.push(`<text class="hd" x="${ZX}" y="${TOP - 18}">ACROSS A TRUST BOUNDARY</text><text class="sub" x="${ZX}" y="${TOP - 5}">what a @boundary fences off</text>`);
  out.push(`<text class="hd" x="${FX}" y="${TOP - 18}">THE SYSTEM</text><text class="sub" x="${FX}" y="${TOP - 5}">${split ? `${inner.length} trust zones, split by a @boundary between two assets` : 'one trust zone — no @boundary separates two of its assets'}</text>`);
  out.push(`<rect class="sys-frame" x="${FX}" y="${TOP}" width="${FR - FX}" height="${r1(frameBottom - TOP)}" rx="10"/>`);
  if (hasShared) out.push(`<text class="hd" x="${SHX}" y="${TOP + 22}">SHARED · NO BOUNDARY</text>`);
  if (split) {
    bands.forEach((b, i) => {
      const edges = new Set<string>();
      for (const l of assetLines) { const za = innerOf.get(l.a), zb = innerOf.get(l.z); if (za !== zb && (za === i || zb === i)) edges.add(l.label); }
      out.push(`<rect class="tzone inner" x="${FX + 10}" y="${r1(b.top)}" width="${r1(PORTX - FX - 4)}" height="${r1(b.bottom - b.top)}" rx="8"/>`);
      out.push(`<text class="zl" x="${FX + 20}" y="${r1(b.top + 15)}">ZONE ${i + 1}</text><text class="sub" x="${FX + 66}" y="${r1(b.top + 15)}">${xml(cutLeft([...edges].join(' · '), Math.floor((PORTX - FX - 80) / (10 * 0.56))))}</text>`);
    });
  }
  for (const h of heads) out.push(`<text class="gh" x="${CAPX}" y="${r1(h.y + 6)}">${xml(h.label)}</text><line class="gh-rule" x1="${r1(CAPX + textWidth(h.label, 11.5, false) + 12)}" x2="${PORTX - 6}" y1="${r1(h.y + 2)}" y2="${r1(h.y + 2)}"/>`);
  const sharedOf = (k: string): boolean => sideNodes.some(s => partners.get(s)?.has(k));
  for (const [k, r] of rows) {
    const end = sharedOf(k) ? PORTX : r.on.length ? SATX + Math.min(PER_LINE, r.on.length) * (CHIPW + CHIPGAP) - CHIPGAP - CHIPW / 2 : 0;
    if (end) out.push(`<line class="bus" x1="${CAPX + CAPW}" x2="${r1(end)}" y1="${r1(rowMid(k))}" y2="${r1(rowMid(k))}"/>`);
  }

  // Outer zones and the endpoints in them.
  const boxes = new Map<string, Box>();
  const zoneMarks: string[] = [];
  for (const z of ozs) {
    const o = outer[z.item];
    const lit = [...new Set(o.members.flatMap(k => [...lights.get(k)!]))];
    zoneMarks.push(`<g${attrs({ class: 'tz nd', 'data-lights': lit.join(' ') })}>`);
    zoneMarks.push(`<rect class="tzone" x="${ZX}" y="${r1(z.top)}" width="${ZW}" height="${z.h}" rx="8"/><text class="zl" x="${ZX + 10}" y="${r1(z.top + 16)}">TRUST ZONE</text>`);
    o.lines.forEach((b, i) => {
      const st = states.get(`${b.file}:${b.line}`) ?? 'unverified';
      const n = m.flows.filter(f => f.boundaries.includes(b.label)).length;
      zoneMarks.push(`<text${attrs({ class: `bl st-${st}`, x: ZX + 10, y: z.top + 31 + i * 15, ...tip(b.label, [['between', `${m.nodes.get(b.a)!.label} | ${m.nodes.get(b.z)!.label}`], ['says', b.description || '—'], ['tested', st], ['flows crossing it', n], ['where', `${b.file}:${b.line}`]]) })}><tspan class="g">${STATE_GLYPH[st]}</tspan> ${xml(cutLeft(b.label, 21))}<tspan class="sub" dx="4">⊢${n}</tspan></text>`);
    });
    o.members.forEach((k, i) => boxes.set(k, { x: ZX + 12, y: z.top + 34 + o.lines.length * 15 + i * 34, w: ZW - 40, h: 26 }));
    zoneMarks.push('</g>');
  }
  for (const s of shs) boxes.set(s.item, { x: SHX, y: s.top, w: SHW, h: CHIPH });
  for (const [k, r] of rows) {
    boxes.set(k, { x: CAPX, y: r.y, w: CAPW, h: CAPH });
    r.on.forEach((e, i) => {
      const li = Math.floor(i / PER_LINE), ci = i % PER_LINE;
      boxes.set(e, { x: SATX + ci * (CHIPW + CHIPGAP), y: r.y + CAPH / 2 - CHIPH / 2 + li * (CHIPH + 6), w: CHIPW, h: CHIPH });
    });
  }

  // Lines. Crossings run in the gutter from the zone's edge to the capsule; ports spread so lines never stack.
  const extOf = (l: Line): string => (isAsset(l.s) ? l.t : l.s);
  const assetOf = (l: Line): string => (isAsset(l.s) ? l.s : l.t);
  const gutter = [...lines.values()].filter(l => l.cls === 'cross' || l.cls === 'implied');
  const exits = new Map<string, Line[]>(), entries = new Map<string, Line[]>();
  for (const l of gutter) {
    for (const [map, k] of [[exits, extOf(l)], [entries, assetOf(l)]] as const) { if (!map.has(k)) map.set(k, []); map.get(k)!.push(l); }
  }
  for (const list of exits.values()) list.sort((a, b) => rowMid(assetOf(a)) - rowMid(assetOf(b)) || a.id.localeCompare(b.id));
  for (const list of entries.values()) list.sort((a, b) => boxes.get(extOf(a))!.y - boxes.get(extOf(b))!.y || a.id.localeCompare(b.id));
  const arcs = [...lines.values()].filter(l => l.cls === 'arc' && l.s !== l.t);
  const span = (l: Line): number => Math.abs(rowMid(l.s) - rowMid(l.t));
  const depth = new Map(arcs.slice().sort((a, b) => span(a) - span(b) || a.id.localeCompare(b.id)).map((l, i, all) => [l, 14 + (ARCW - 22) * ((i + 1) / (all.length + 1))] as const));

  const under: string[] = [], over: string[] = [], gates: string[] = [];
  for (const l of lines.values()) {
    const S = m.nodes.get(l.s)!, T = m.nodes.get(l.t)!;
    const crosses = [...new Set(l.flows.flatMap(f => f.boundaries))];
    const rowsT: [string, string | number][] = [['flows', l.flows.length]];
    if (crosses.length) rowsT.push(['crosses', crosses.join(', ')]);
    if (l.cls === 'implied') rowsT.push(['crosses', 'no @boundary names this pair; the endpoint is fenced off elsewhere']);
    for (const f of l.flows) rowsT.push([f.via || '—', `${f.description ? `${f.description} · ` : ''}${f.file}:${f.line}`]);
    const base = { 'data-k': `${l.id}`, ...tip(`${S.label} → ${T.label}`, rowsT) };
    if (l.cls === 'cross' || l.cls === 'implied') {
      const eb = boxes.get(extOf(l))!, cb = boxes.get(assetOf(l))!;
      const ex = exits.get(extOf(l))!, en = entries.get(assetOf(l))!;
      const ey = eb.y + 4 + (ex.indexOf(l) + 1) * (eb.h - 8) / (ex.length + 1);
      const cy = cb.y + 4 + (en.indexOf(l) + 1) * (cb.h - 8) / (en.length + 1);
      const xa = ZX + ZW, xb = FX, mid = (xa + xb) / 2;
      const inbound = `M${r1(eb.x + eb.w)} ${r1(ey)}H${r1(xa + 6)}C${r1(mid)} ${r1(ey)} ${r1(mid)} ${r1(cy)} ${r1(xb - 6)} ${r1(cy)}H${r1(cb.x)}`;
      const outbound = `M${r1(cb.x)} ${r1(cy)}H${r1(xb - 6)}C${r1(mid)} ${r1(cy)} ${r1(mid)} ${r1(ey)} ${r1(xa + 6)} ${r1(ey)}H${r1(eb.x + eb.w + 1)}`;
      over.push(`<path${attrs({ class: `thr ${l.cls === 'cross' ? 'x-cross' : 'x-implied'}`, d: isAsset(l.s) ? outbound : inbound, 'marker-end': `url(#${pid}-ahx)`, ...base })}/>`);
      if (l.cls === 'cross') gates.push(`<line${attrs({ class: 'gate', 'data-k': l.id, x1: xa, x2: xa, y1: ey - 5, y2: ey + 5 })}/>`);
    } else if (l.cls === 'arc') {
      if (l.s === l.t) { under.push(`<g${attrs({ class: 'thr', ...base })}></g>`); continue; }
      const a = rowMid(l.s), b = rowMid(l.t), down = a < b;
      const x0 = CAPX + CAPW, d = depth.get(l)!;
      const ya = a + (down ? 5 : -5), yb = b + (down ? -5 : 5);
      (crosses.length ? over : under).push(`<path${attrs({ class: `thr ${crosses.length ? 'x-cross' : 'x-flow'}`, d: `M${r1(x0)} ${r1(ya)}C${r1(x0 + d * 1.3)} ${r1(ya)} ${r1(x0 + d * 1.3)} ${r1(yb)} ${r1(x0 + 2)} ${r1(yb)}`, 'marker-end': `url(#${pid}-${crosses.length ? 'ahx' : 'ah'})`, ...base })}/>`);
      if (crosses.length) gates.push(`<line${attrs({ class: 'gate', 'data-k': l.id, x1: x0 + d - 6, x2: x0 + d + 6, y1: (ya + yb) / 2, y2: (ya + yb) / 2 })}/>`);
    } else {
      const e = extOf(l), side = shs.find(s => s.item === e);
      // An endpoint ↔ endpoint flow has no asset row to anchor to: nothing to draw.
      if (!side || !isAsset(assetOf(l))) { under.push(`<g${attrs({ class: 'thr', ...base })}></g>`); continue; }
      const y1 = rowMid(assetOf(l)), y2 = side.top + CHIPH / 2, mx = (PORTX + SHX) / 2;
      const fwd = `M${PORTX} ${r1(y1)}C${r1(mx)} ${r1(y1)} ${r1(mx)} ${r1(y2)} ${SHX} ${r1(y2)}`;
      const back = `M${SHX} ${r1(y2)}C${r1(mx)} ${r1(y2)} ${r1(mx)} ${r1(y1)} ${PORTX} ${r1(y1)}`;
      under.push(`<path${attrs({ class: 'thr x-flow', d: isAsset(l.s) ? fwd : back, 'marker-end': `url(#${pid}-ah)`, ...base })}/>`);
    }
  }
  out.push(...zoneMarks, `<g class="edges">${under.join('')}${over.join('')}</g><g class="gates">${gates.join('')}</g><g class="nodes">`);

  const element = (n: GNode, b: Box, dir = ''): string => {
    const k = kind.get(n.key)!;
    const mit = n.exposures.filter(e => e.state === 'mitigated' || e.state === 'refuted').length;
    const acc = n.exposures.filter(e => e.state === 'accepted').length;
    const where = n.external ? (fenced.has(n.key) ? 'outside the model · across a trust boundary' : 'outside the model · no boundary declared') : 'declared asset';
    const rowsT: [string, string | number][] = [['kind', `${KIND_WORD[k]} (inferred) · ${where}`], ['flows', `${n.flowsIn.length} in · ${n.flowsOut.length} out`]];
    if (!n.external) rowsT.push(['exposures', n.exposures.length ? `${n.open} open · ${mit} mitigated${acc ? ` · ${acc} accepted` : ''}` : 'none declared']);
    if (n.boundaries.length) rowsT.push(['trust boundaries', n.boundaries.join(', ')]);
    if (n.handles.length) rowsT.push(['handles', n.handles.join(', ')]);
    const id = nid.get(n.key)!;
    const s: string[] = [`<g${attrs({
      class: `el nd k-${k}${n.external ? ' ext' : ''}`, 'data-node': id, 'data-k': id, 'data-lights': [...lights.get(n.key)!].join(' '),
      'data-key': n.key, 'data-name': n.label, 'data-asset': n.external ? undefined : n.label, 'data-claims': n.exposures.map(e => e.claim).join(' '),
      role: 'button', 'aria-label': `${n.label}: ${KIND_WORD[k]}`, ...tip(n.label, rowsT),
    })}>`];
    if (k === 'process') s.push(`<rect class="shape" x="${r1(b.x)}" y="${r1(b.y)}" width="${b.w}" height="${b.h}" rx="${b.h / 2}"/>`);
    else if (k === 'store') s.push(`<rect class="hit" x="${r1(b.x)}" y="${r1(b.y)}" width="${b.w}" height="${b.h}"/><path class="shape" d="M${r1(b.x + b.w)} ${r1(b.y + 0.5)}H${r1(b.x)}V${r1(b.y + b.h - 0.5)}H${r1(b.x + b.w)}"/><line class="shape" x1="${r1(b.x + 7)}" x2="${r1(b.x + 7)}" y1="${r1(b.y)}" y2="${r1(b.y + b.h)}"/>`);
    else s.push(`<rect class="shape" x="${r1(b.x)}" y="${r1(b.y)}" width="${b.w}" height="${b.h}" rx="1.5"/>`);
    const tx = b.x + (k === 'process' ? 22 : k === 'store' ? (n.external ? 13 : 28) : 8) + (dir ? 12 : 0);
    if (!n.external) {
      const mx = b.x + (k === 'store' ? 14 : 10), my = b.y + b.h / 2 - 4;
      if (n.open) s.push(`<rect class="sw s-${n.worst ?? 'unset'}" x="${r1(mx)}" y="${r1(my)}" width="8" height="8" rx="1.5"/>`);
      else if (n.exposures.length) s.push(`<text class="ok" x="${r1(mx - 1)}" y="${r1(my + 8)}">✓</text>`);
      else s.push(`<rect class="sw-empty" x="${r1(mx + 0.5)}" y="${r1(my + 0.5)}" width="7" height="7" rx="1.5"/>`);
    }
    const right = [n.external || !n.open ? '' : `${n.open} open`, n.external || !n.boundaries.length ? '' : `⊢${n.boundaries.length}`].filter(Boolean).join(' ');
    const room = b.x + b.w - tx - (right ? textWidth(right, 10, false) + 14 : 8);
    if (dir) s.push(`<text class="dir" x="${r1(tx - 12)}" y="${r1(b.y + b.h / 2 + 3.5)}">${dir}</text>`);
    s.push(`<text class="nm${n.external ? '' : ' hot strong'}" x="${r1(tx)}" y="${r1(b.y + b.h / 2 + 3.5)}">${xml(cutLeft(n.label, Math.max(4, Math.floor(room / (10.5 * 0.62)))))}</text>`);
    if (right) s.push(`<text class="sub" x="${r1(b.x + b.w - 14)}" y="${r1(b.y + b.h / 2 + 3.5)}" text-anchor="end">${xml(right)}</text>`);
    s.push('</g>');
    return s.join('');
  };
  for (const [k, r] of rows) {
    out.push(element(m.nodes.get(k)!, boxes.get(k)!));
    r.on.forEach((e, i) => {
      const b = boxes.get(e)!;
      if (i >= PER_LINE && i % PER_LINE === 0) out.push(`<path class="bus" d="M${r1(SATX - 10)} ${r1(rowMid(k))}V${r1(b.y + CHIPH / 2)}H${r1(b.x)}"/>`);
      const n = m.nodes.get(e)!;
      const out_ = n.flowsIn.some(f => f.source === k), in_ = n.flowsOut.some(f => f.target === k);
      out.push(element(n, b, out_ && in_ ? '⇄' : out_ ? '→' : '←'));
    });
  }
  for (const z of ozs) for (const k of outer[z.item].members) out.push(element(m.nodes.get(k)!, boxes.get(k)!));
  for (const s of shs) out.push(element(m.nodes.get(s.item)!, boxes.get(s.item)!));
  out.push('</g></svg>');

  const counts = { process: 0, store: 0, entity: 0 };
  for (const k of kind.values()) counts[k]++;
  return {
    svg: out.join(''),
    elements: nodes.length, processes: counts.process, stores: counts.store, entities: counts.entity,
    flows: m.flows.length, lines: lines.size, crossing, implied,
    boundaries: m.boundaryList.length, outerZones: outer.length, innerZones: inner.length,
    silent: m.boundaryList.filter(b => !m.flows.some(f => f.boundaries.includes(b.label))).map(b => b.label),
    unsplit: assetLines.filter(b => innerOf.get(b.a) === innerOf.get(b.z)).map(b => b.label),
  };
}

