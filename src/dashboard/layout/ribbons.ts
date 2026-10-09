/**
 * GuardLink Dashboard — Diagrams › Data flow, whole model: flow ribbons.
 *
 * FROM on the left, TO on the right, both columns listing the same zones in the
 * same order: "Across a trust line" (external endpoints a `@boundary` names),
 * "Outside the model" (every other external endpoint), then each asset group in
 * model order. Every `@flows` is one thread from its source tick to its target
 * tick; the threads between two zones run together as one ribbon.
 *
 * Stacking is deterministic and never twists a thread inside a ribbon: a
 * node's left slots are sorted by partner zone then partner position, ports by
 * zone pair, a node's right slots by source zone then port position. A thread
 * that crosses a declared trust line is drawn in stronger ink and counted in
 * its ribbon's pill as `⊢n`.
 *
 * Nothing is dropped for size. A name that would sit closer than 11 px to
 * another is folded — the tick stays, with its name on hover — and the footer
 * says how many were.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Node labels, mechanisms, descriptions and boundary labels reach the SVG only through xml() and attrs()"
 */
import type { DiagramModel, GFlow, GNode } from './graph.js';
import { markOf, markLabel } from './graph.js';
import { placeNames } from './tripartite.js';
import { attrs, fitLeft, r1, tip, xml, dotPattern, textWidth } from './text.js';

export interface Zone { key: string; label: string }

export interface RibbonsResult {
  svg: string;
  flows: number;
  drawn: number;
  nodes: number;
  ribbons: number;
  crossing: number;
  folded: number;
}

const W = 1000;
const GUT = 190;
const XL = GUT + 10;
const XR = W - GUT - 10;
const F = Math.max(26, Math.min(80, (XR - XL) * 0.12));
const PITCH = 2;
const SLOT_GAP = 3;
const ZONE_GAP = 26;
const MIN_SLOT = 7;
const PORT_GAP = 4;
const NAME_GAP = 11;

export function zonesOf(m: DiagramModel): { zones: Zone[]; zoneOf: (n: GNode) => number } {
  const groups: string[] = [];
  for (const a of m.assets) if (!groups.includes(a.group)) groups.push(a.group);
  const zones: Zone[] = [{ key: 'trust', label: 'Across a trust line' }, { key: 'local', label: 'Outside the model' }, ...groups.map(g => ({ key: `g:${g}`, label: g }))];
  const index = new Map(zones.map((z, i) => [z.key, i]));
  const zoneOf = (n: GNode): number => index.get(n.external ? (m.boundaryExternals.has(n.key) ? 'trust' : 'local') : `g:${n.group}`) ?? 1;
  return { zones, zoneOf };
}

/** The class a node's tick wears, from its mark. */
export function tickClass(n: GNode): string {
  const mk = markOf(n);
  return mk.kind === 'open' ? `m-open s-${mk.sev}` : mk.kind === 'resolved' ? 'm-res' : mk.kind === 'empty' ? 'm-empty' : 'm-ext';
}

interface Thread { f: GFlow; s: GNode; t: GNode; zs: number; zt: number; yL: number; yR: number; yPL: number; yPR: number }

export function renderRibbons(m: DiagramModel, nodeIndex: Map<string, number>): RibbonsResult {
  const { zones, zoneOf } = zonesOf(m);
  const used = new Map<string, GNode>();
  for (const f of m.flows) for (const k of [f.source, f.target]) used.set(k, m.nodes.get(k)!);

  // Order: zone, then assets in model order, externals by the mean model position of their asset partners.
  const assetPos = new Map(m.assets.map((a, i) => [a.key, i]));
  const bary = (n: GNode): number => {
    const ps = [...n.flowsOut.map(f => f.target), ...n.flowsIn.map(f => f.source)].filter(k => assetPos.has(k)).map(k => assetPos.get(k)!);
    return ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : 1e6;
  };
  const ordered = [...used.values()].sort((a, b) => zoneOf(a) - zoneOf(b)
    || (a.external ? bary(a) - bary(b) : assetPos.get(a.key)! - assetPos.get(b.key)!)
    || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const rank = new Map(ordered.map((n, i) => [n.key, i]));
  const threads: Thread[] = m.flows.map(f => {
    const s = used.get(f.source)!, t = used.get(f.target)!;
    return { f, s, t, zs: zoneOf(s), zt: zoneOf(t), yL: 0, yR: 0, yPL: 0, yPR: 0 };
  });

  interface Item { header?: Zone; node?: GNode; y: number; h: number; n: number }
  const column = (side: 'L' | 'R'): { items: Item[]; height: number } => {
    const items: Item[] = [];
    let y = 46, lastZ = -1;
    for (const n of ordered) {
      const mine = threads.filter(th => (side === 'L' ? th.s : th.t) === n);
      if (!mine.length) continue;
      const z = zoneOf(n);
      if (z !== lastZ) { if (lastZ >= 0) y += ZONE_GAP; items.push({ header: zones[z], y: y - 9, h: 0, n: 0 }); lastZ = z; }
      mine.sort(side === 'L'
        ? (a, b) => a.zt - b.zt || rank.get(a.t.key)! - rank.get(b.t.key)! || a.f.i - b.f.i
        : (a, b) => a.zs - b.zs || a.yPR - b.yPR || a.f.i - b.f.i);
      const h = Math.max(MIN_SLOT, mine.length * PITCH);
      const y0 = y + (h - mine.length * PITCH) / 2;
      mine.forEach((th, i) => { if (side === 'L') th.yL = y0 + i * PITCH + PITCH / 2; else th.yR = y0 + i * PITCH + PITCH / 2; });
      items.push({ node: n, y, h, n: mine.length });
      y += h + SLOT_GAP;
    }
    return { items, height: y };
  };

  const left = column('L');
  const ribs = new Map<string, { zs: number; zt: number; threads: Thread[]; y0L: number; y0R: number }>();
  for (const th of threads) {
    const k = `${th.zs}>${th.zt}`;
    if (!ribs.has(k)) ribs.set(k, { zs: th.zs, zt: th.zt, threads: [], y0L: 0, y0R: 0 });
    ribs.get(k)!.threads.push(th);
  }
  const ribList = [...ribs.values()];
  for (const r of ribList) r.threads.sort((a, b) => a.yL - b.yL || a.f.i - b.f.i);
  const portH = ribList.reduce((a, r) => a + r.threads.length * PITCH, 0) + PORT_GAP * Math.max(0, ribList.length - 1);
  let H = Math.max(left.height, portH + 40);
  let y = (H - portH) / 2;
  for (const r of ribList.slice().sort((a, b) => a.zs - b.zs || a.zt - b.zt)) {
    r.y0L = y;
    r.threads.forEach((th, i) => { th.yPL = y + i * PITCH + PITCH / 2; });
    y += r.threads.length * PITCH + PORT_GAP;
  }
  y = (H - portH) / 2;
  for (const r of ribList.slice().sort((a, b) => a.zt - b.zt || a.zs - b.zs)) {
    r.y0R = y;
    r.threads.forEach((th, i) => { th.yPR = y + i * PITCH + PITCH / 2; });
    y += r.threads.length * PITCH + PORT_GAP;
  }
  const right = column('R');
  H = Math.ceil(Math.max(H, right.height) + 12);

  const a = XL + F, b = XR - F, m1 = a + (b - a) * 0.38, m2 = a + (b - a) * 0.62;
  const f1 = (n: number): string => r1(n);
  const pathOf = (th: Thread): string =>
    `M${f1(XL)} ${f1(th.yL)}C${f1(XL + F * 0.55)} ${f1(th.yL)} ${f1(a - F * 0.45)} ${f1(th.yPL)} ${f1(a)} ${f1(th.yPL)}`
    + `C${f1(m1)} ${f1(th.yPL)} ${f1(m2)} ${f1(th.yPR)} ${f1(b)} ${f1(th.yPR)}`
    + `C${f1(b + F * 0.45)} ${f1(th.yPR)} ${f1(XR - F * 0.55)} ${f1(th.yR)} ${f1(XR)} ${f1(th.yR)}`;

  const idx = (n: GNode): number => nodeIndex.get(n.key)!;
  const crossingTotal = m.flows.filter(f => f.boundary).length;
  const out: string[] = [];
  out.push(`<svg${attrs({ class: 'dg', 'data-plot': 'ribbons', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'group', tabindex: 0, 'aria-label': `Data flow: ${m.flows.length} flows between ${used.size} nodes in ${ribList.length} ribbons; ${crossingTotal} cross a declared trust line. Arrow keys step through the nodes, Enter pins one.` })}>`);
  out.push(`<defs>${dotPattern('dots-ribbons')}</defs><rect class="ground" width="${W}" height="${H}" fill="url(#dots-ribbons)"/>`);

  // Ribbon bodies.
  out.push('<g class="bodies">');
  for (const r of ribList) {
    const thick = r.threads.length * PITCH;
    const yA = r.y0L + thick / 2, yB = r.y0R + thick / 2;
    const cross = r.threads.some(th => th.f.boundary);
    out.push(`<path${attrs({ class: `rib${cross ? ' cross' : ''}`, d: `M${f1(a)} ${f1(yA)}C${f1(m1)} ${f1(yA)} ${f1(m2)} ${f1(yB)} ${f1(b)} ${f1(yB)}`, 'stroke-width': thick + 3 })}/>`);
  }
  out.push('</g><g class="threads">');
  // Threads: plain first, crossings on top.
  for (const th of threads.slice().sort((p, q) => Number(!!p.f.boundary) - Number(!!q.f.boundary) || p.f.i - q.f.i)) {
    out.push(`<path${attrs({ class: `thr ${th.f.boundary ? 'x-cross' : 'x-flow'}`, d: pathOf(th), 'data-k': `n${idx(th.s)} n${idx(th.t)}`, ...tip(`${th.s.label} → ${th.t.label}`, [['via', th.f.via || '—'], ['why', th.f.description || '—'], ['where', th.f.file ? `${th.f.file}:${th.f.line}` : '—'], ...(th.f.boundary ? [['trust line', th.f.boundary] as [string, string]] : [])]) })}/>`);
  }
  out.push('</g><g class="pills">');

  // Count pills at the first free spot along each thick ribbon's centre line.
  const bez = (p0: number, p1: number, p2: number, p3: number, u: number): number => (1 - u) ** 3 * p0 + 3 * (1 - u) ** 2 * u * p1 + 3 * (1 - u) * u * u * p2 + u ** 3 * p3;
  const pills: { x: number; y: number; w: number }[] = [];
  for (const r of ribList.slice().sort((p, q) => q.threads.length - p.threads.length || p.zs - q.zs || p.zt - q.zt)) {
    const thick = r.threads.length * PITCH;
    if (thick < 8) continue;
    const crossing = r.threads.filter(th => th.f.boundary).length;
    const text = `${r.threads.length}${crossing ? `  ⊢${crossing}` : ''}`;
    const w = 12 + textWidth(text, 10.5, false);
    const yA = r.y0L + thick / 2, yB = r.y0R + thick / 2;
    let spot: { x: number; y: number; w: number } | null = null;
    for (const u of [0.5, 0.38, 0.62, 0.28, 0.72, 0.2, 0.8]) {
      const px = bez(a, m1, m2, b, u), py = bez(yA, yA, yB, yB, u);
      if (!pills.some(q => Math.abs(q.x - px) < (q.w + w) / 2 + 4 && Math.abs(q.y - py) < 19)) { spot = { x: px, y: py, w }; break; }
    }
    if (!spot) continue;
    pills.push(spot);
    out.push(`<g${attrs({ class: 'pill', ...tip(`${zones[r.zs].label} → ${zones[r.zt].label}`, [['flows', r.threads.length], ['cross a trust line', crossing]]) })}><rect x="${f1(spot.x - w / 2)}" y="${f1(spot.y - 8)}" width="${f1(w)}" height="16" rx="8"/><text x="${f1(spot.x)}" y="${f1(spot.y + 3.5)}" text-anchor="middle">${xml(text)}</text></g>`);
  }
  out.push('</g><g class="nodes">');

  let folded = 0;
  const drawColumn = (col: { items: Item[] }, side: 'L' | 'R'): void => {
    const x = side === 'L' ? XL - 5 : XR;
    const cands = col.items.filter(it => it.node).map(it => ({ key: it.node!.key, y: it.y + it.h / 2, priority: (it.node!.open > 0 ? 1e6 : 0) + it.node!.exposures.length * 1000 + it.n }));
    const named = placeNames(cands, NAME_GAP);
    folded += cands.length - named.size;
    for (const it of col.items) {
      if (it.header) {
        out.push(`<text class="hd zone" x="${side === 'L' ? XL - 2 : XR + 2}" y="${f1(it.y)}" text-anchor="${side === 'L' ? 'end' : 'start'}">${xml(it.header.label.toUpperCase())}</text>`);
        continue;
      }
      const n = it.node!;
      const i = idx(n);
      out.push(`<g${attrs({ class: 'nd', 'data-node': `n${i}`, 'data-lights': `n${i}`, 'data-claims': n.exposures.map(e => e.claim).join(' '), 'data-name': n.label, 'data-key': n.key, role: 'button', 'aria-label': `${n.label}: ${markLabel(n)}; ${n.flowsIn.length} in, ${n.flowsOut.length} out`, ...tip(n.label, [['kind', markLabel(n)], ['flows in', n.flowsIn.length], ['flows out', n.flowsOut.length], ...(n.boundaries.length ? [['trust lines', n.boundaries.join(', ')] as [string, string]] : [])]) })}>`);
      out.push(`<rect class="pinbox" x="${f1(x - 2.5)}" y="${f1(it.y - 2.5)}" width="10" height="${f1(it.h + 5)}" rx="2"/>`);
      out.push(`<rect class="tick ${tickClass(n)}" x="${f1(x)}" y="${f1(it.y)}" width="5" height="${f1(it.h)}" rx="1"/>`);
      if (named.has(n.key)) {
        out.push(`<text class="nm${n.open ? ' hot' : ''}" x="${f1(side === 'L' ? XL - 10 : XR + 11)}" y="${f1(it.y + it.h / 2 + 3.5)}" text-anchor="${side === 'L' ? 'end' : 'start'}">${xml(fitLeft(n.label, GUT - 18, 10.5))}</text>`);
      } else {
        out.push(`<rect class="hit" x="${f1(side === 'L' ? x - 26 : x + 5)}" y="${f1(it.y)}" width="26" height="${f1(Math.max(it.h, 4))}"/>`);
      }
      out.push('</g>');
    }
  };
  drawColumn(left, 'L');
  drawColumn(right, 'R');
  out.push(`<text class="hd" x="${XL - 2}" y="14" text-anchor="end">FROM</text><text class="hd" x="${XR + 2}" y="14">TO</text>`);
  out.push('</g></svg>');

  return { svg: out.join(''), flows: m.flows.length, drawn: threads.length, nodes: used.size, ribbons: ribList.length, crossing: crossingTotal, folded };
}

