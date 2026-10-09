/**
 * GuardLink Dashboard — Diagrams › Data flow, neighbourhood: any node, with
 * what flows into it and out of it, two hops each way.
 *
 * Columns by hop distance (−2, −1, focus, +1, +2), as the code graph panel lays
 * out callers, with a budget of 7 nodes per column: a node-link picture stays
 * legible to about a dozen nodes, so past the budget a column says "+ n more —
 * see the table" instead of shrinking.
 *
 * Split in two, deliberately:
 *   - `hoodColumns` runs at generation time for every node and is embedded as
 *     compact JSON — which nodes sit in which column, and which flows join them.
 *     No geometry.
 *   - `renderHoodSvg` and `renderNodeDetail` turn that into markup. They are
 *     SELF-CONTAINED: no imports, no outer references, so the page embeds their
 *     source verbatim (`fn.toString()`) and the browser draws a walk with the
 *     very function the generator used for the first frame and the tests use.
 *     One implementation, and nothing in it measures the DOM, so a hidden or
 *     zero-size panel draws exactly as a visible one.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "renderHoodSvg and renderNodeDetail escape every label, mechanism, path and description with their own esc(); keys in hrefs go through encodeURIComponent"
 */
import type { DiagramModel, GNode } from './graph.js';
import { SEV_RANK, isOpenState } from './graph.js';

export const HOOD_BUDGET = 7;
const SEV_INDEX = ['critical', 'high', 'medium', 'low', 'unset'] as const;
const STATE_INDEX = ['open', 'confirmed', 'mitigated', 'refuted', 'accepted'] as const;

/** One node, as the client renderers read it. */
export interface HoodNode {
  /** Canonical key. */
  k: string;
  /** Label as a reader knows it. */
  l: string;
  /** 1 when outside the model. */
  x: 0 | 1;
  /** Exposures declared on it, and how many are open. */
  n: number;
  o: number;
  /** Worst open severity index (0 critical … 4 unset), or -1. */
  w: number;
  /** Trust lines it sits on. */
  b: string[];
  /** Open exposures, worst first: [threat label, severity index]. At most 3. */
  t: [string, number][];
  /** Every exposure on it: [claim index, severity index, state index, threat label]. */
  e: [number, number, number, string][];
  h: string[];
}

/** One flow: source index, target index, mechanism, boundary label ('' when none), file:line, description. */
export type HoodFlow = [number, number, string, string, string, string];

/** A neighbourhood: node indices per column −2…+2, how many overflowed each, the flows drawn, and the flows among these nodes left undrawn. */
export interface HoodColumns { c: number[][]; m: number[]; e: number[]; u: number }

export interface HoodPayload { nodes: HoodNode[]; flows: HoodFlow[]; hoods: HoodColumns[] }

export function buildHoodPayload(m: DiagramModel): { payload: HoodPayload; index: Map<string, number> } {
  // Every node that a flow touches or an exposure names, assets first in model order.
  const list: GNode[] = [...m.assets, ...m.externals];
  const index = new Map(list.map((n, i) => [n.key, i]));
  const nodes: HoodNode[] = list.map(n => {
    const open = n.exposures.filter(e => isOpenState(e.state)).sort((a, b) => SEV_RANK[a.sev] - SEV_RANK[b.sev]);
    return {
      k: n.key, l: n.label, x: n.external ? 1 : 0, n: n.exposures.length, o: n.open,
      w: n.worst ? SEV_INDEX.indexOf(n.worst) : -1,
      b: n.boundaries,
      t: open.slice(0, 3).map(e => [m.threats.get(e.threat)?.label ?? e.threat, SEV_INDEX.indexOf(e.sev)]),
      e: n.exposures.map(e => [e.claim, SEV_INDEX.indexOf(e.sev), STATE_INDEX.indexOf(e.state), m.threats.get(e.threat)?.label ?? e.threat]),
      h: n.handles,
    };
  });
  const flows: HoodFlow[] = m.flows.map(f => [index.get(f.source)!, index.get(f.target)!, f.via, f.boundary ?? '', f.file ? `${f.file}:${f.line}` : '', f.description]);
  const hoods = list.map((_, i) => hoodColumns(flows, i, HOOD_BUDGET));
  return { payload: { nodes, flows, hoods }, index };
}

/** Columns by hop distance around `focus`, at most `budget` nodes per column. */
export function hoodColumns(flows: HoodFlow[], focus: number, budget: number): HoodColumns {
  const col = new Map<number, number>([[focus, 0]]);
  const cols: number[][] = [[], [], [focus], [], []];
  const over: Set<number>[] = [new Set(), new Set(), new Set(), new Set(), new Set()];
  const add = (n: number, c: number): void => {
    if (col.has(n)) return;
    const slot = c + 2;
    if (cols[slot].length >= budget) { over[slot].add(n); return; }
    col.set(n, c);
    cols[slot].push(n);
  };
  const ins = (n: number): number[] => flows.filter(f => f[1] === n).map(f => f[0]);
  const outs = (n: number): number[] => flows.filter(f => f[0] === n).map(f => f[1]);
  for (const s of ins(focus)) add(s, -1);
  for (const t of outs(focus)) add(t, 1);
  for (const n of cols[1].slice()) for (const s of ins(n)) add(s, -2);
  for (const n of cols[3].slice()) for (const t of outs(n)) add(t, 2);
  const e: number[] = [];
  let among = 0;
  flows.forEach((f, i) => {
    if (!col.has(f[0]) || !col.has(f[1])) return;
    among++;
    if (col.get(f[1]) === col.get(f[0])! + 1) e.push(i);
  });
  // A node that overflowed one column but was placed in another is not missing.
  return { c: cols, m: over.map(s => [...s].filter(n => !col.has(n)).length), e, u: among - e.length };
}

export interface HoodRender { svg: string; drawn: number; nodes: number; undrawn: number }

/**
 * The neighbourhood as SVG. SELF-CONTAINED — embedded in the page by source.
 * Cards: id, open-share gauge, up to three open exposures, the resolved count,
 * ⊢n for trust lines. Edges: orthogonal elbows, r = 8, on spread channels so
 * trunks never stack; a bar across an edge that crosses a trust line.
 */
export function renderHoodSvg(data: HoodPayload, focus: number): HoodRender {
  const esc = (s: unknown): string => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const cut = (s: string, n: number): string => { const a = Array.from(s); return a.length <= n ? s : '…' + a.slice(a.length - n + 1).join(''); };
  const f1 = (n: number): string => String(Math.round(n * 10) / 10);
  const SEV = ['critical', 'high', 'medium', 'low', 'unset'];
  const tipRows = (rows: [string, string | number][]): string => rows.map(r => `${r[0]}\t${String(r[1]).replace(/[\t\n]/g, ' ')}`).join('\n');
  const hood = data.hoods[focus];
  const CW = 168, GAP = 80, TOP = 34, PAD = 20;
  const cardH = (n: HoodNode): number => (n.x ? 40 : 30 + Math.min(3, n.t.length) * 15 + 15);
  const order = [0, 1, 2, 3, 4].filter(c => hood.c[c].length > 0 || hood.m[c] > 0);
  const W = order.length * CW + (order.length - 1) * GAP + PAD * 2;
  const pos = new Map<number, { x: number; y: number; h: number }>();
  let H = 0;
  const colH = order.map(c => hood.c[c].reduce((a, n) => a + cardH(data.nodes[n]) + 14, 0) + (hood.m[c] ? 30 : 0));
  const tallest = Math.max(0, ...colH);
  order.forEach((c, i) => {
    let y = TOP + Math.max(0, (tallest - colH[i]) / 2);
    for (const n of hood.c[c]) { pos.set(n, { x: PAD + i * (CW + GAP), y, h: cardH(data.nodes[n]) }); y += cardH(data.nodes[n]) + 14; }
    H = Math.max(H, y + (hood.m[c] ? 30 : 0));
  });
  H = Math.ceil(H + 16);
  const heads = ['2 HOPS IN', 'FLOWS IN', 'FOCUS', 'FLOWS OUT', '2 HOPS OUT'];
  const F = data.nodes[focus];
  const out: string[] = [];
  out.push(`<svg class="dg hood" data-plot="hood" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="group" tabindex="0" aria-label="${esc(`Neighbourhood of ${F.l}: ${hood.e.length} flows among ${pos.size} nodes. Arrow keys step through the cards, Enter walks to one.`)}">`);
  out.push(`<defs><pattern id="dots-hood" width="16" height="16" patternUnits="userSpaceOnUse"><rect x="7.25" y="7.25" width="1.5" height="1.5" class="dot"/></pattern><marker id="hood-arrow" viewBox="0 0 8 6" refX="7.5" refY="3" markerWidth="8" markerHeight="6" orient="auto"><path d="M0 0L8 3L0 6z" class="arrowhead"/></marker></defs>`);
  out.push(`<rect class="ground" width="${W}" height="${H}" fill="url(#dots-hood)"/>`);
  order.forEach((c, i) => out.push(`<text class="hd" x="${PAD + i * (CW + GAP)}" y="18">${heads[c]}</text>`));

  // Edges below the cards, grouped by the gap they cross so their channels spread.
  const edges = hood.e.map(i => ({ i, f: data.flows[i] }));
  const colOf = (n: number): number => { for (let c = 0; c < 5; c++) if (hood.c[c].includes(n)) return c; return -1; };
  const byGap = new Map<number, typeof edges>();
  for (const e of edges) { const g = colOf(e.f[0]); if (!byGap.has(g)) byGap.set(g, []); byGap.get(g)!.push(e); }
  out.push('<g class="edges">');
  const labels: string[] = [];
  for (const list of byGap.values()) {
    list.sort((a, b) => pos.get(a.f[1])!.y - pos.get(b.f[1])!.y || pos.get(a.f[0])!.y - pos.get(b.f[0])!.y || a.i - b.i);
    list.forEach((e, k) => {
      const A = pos.get(e.f[0])!, B = pos.get(e.f[1])!;
      const outs = edges.filter(x => x.f[0] === e.f[0]), ins = edges.filter(x => x.f[1] === e.f[1]);
      const y1 = A.y + 14 + (outs.indexOf(e) + 1) * Math.min(10, (A.h - 18) / (outs.length + 1));
      const y2 = B.y + 14 + (ins.indexOf(e) + 1) * Math.min(10, (B.h - 18) / (ins.length + 1));
      const x1 = A.x + CW, x2 = B.x;
      const xm = x1 + 16 + ((GAP - 32) * (k + 1)) / (list.length + 1);
      const r = Math.min(8, Math.abs(y2 - y1) / 2);
      const dir = y2 > y1 ? 1 : -1;
      const d = Math.abs(y2 - y1) < 1 ? `M${f1(x1)} ${f1(y1)}H${f1(x2 - 1)}`
        : `M${f1(x1)} ${f1(y1)}H${f1(xm - r)}Q${f1(xm)} ${f1(y1)} ${f1(xm)} ${f1(y1 + dir * r)}V${f1(y2 - dir * r)}Q${f1(xm)} ${f1(y2)} ${f1(xm + r)} ${f1(y2)}H${f1(x2 - 1)}`;
      const cross = !!e.f[3];
      const src = data.nodes[e.f[0]], dst = data.nodes[e.f[1]];
      out.push(`<path class="edge${cross ? ' cross' : ''}" d="${d}" marker-end="url(#hood-arrow)" data-tip="${esc(`${src.l} → ${dst.l}`)}" data-tip-rows="${esc(tipRows([['via', e.f[2] || '—'], ['why', e.f[5] || '—'], ['where', e.f[4] || '—'], ...(cross ? [['trust line', e.f[3]] as [string, string]] : [])]))}"/>`);
      if (cross) labels.push(`<line class="gate" x1="${f1(xm - 6)}" x2="${f1(xm + 6)}" y1="${f1((y1 + y2) / 2)}" y2="${f1((y1 + y2) / 2)}"/>`);
      // A mechanism is named on its line only where it cannot collide: at most two lines leave the card, three enter the target.
      // Cut to what fits in the gap at 9.5 px mono, so a label never runs onto the next card.
      if (e.f[2] && outs.length <= 2 && ins.length <= 3) labels.push(`<text class="mech" x="${f1(x1 + 6)}" y="${f1(y1 - 4)}">${esc(cut(e.f[2], Math.floor((GAP - 14) / (9.5 * 0.62))))}</text>`);
    });
  }
  out.push('</g>', `<g class="labels">${labels.join('')}</g>`, '<g class="cards">');

  for (const [n, p] of pos) {
    const N = data.nodes[n];
    const isFocus = n === focus;
    const kind = N.x ? (N.b.length ? 'outside the model · across a trust line' : 'outside the model') : N.o ? `${N.o} open · worst ${SEV[N.w]}` : N.n ? `all ${N.n} mitigated or accepted` : 'no exposure declared';
    const ins = data.flows.filter(f => f[1] === n).length, outsN = data.flows.filter(f => f[0] === n).length;
    out.push(`<g class="card nd${isFocus ? ' focus' : ''}${N.x ? ' ext' : ''}" data-node="h${n}" data-hood-walk="${n}" data-key="${esc(N.k)}" role="button" aria-label="${esc(`${N.l}: ${kind}`)}" data-tip="${esc(N.l)}" data-tip-rows="${esc(tipRows([['kind', kind], ['flows in', ins], ['flows out', outsN]]))}">`);
    out.push(`<rect class="card-box" x="${f1(p.x)}" y="${f1(p.y)}" width="${CW}" height="${f1(p.h)}" rx="6"/>`);
    if (!N.x) {
      const share = N.n ? Math.max(0.04, N.o / N.n) : 1;
      const g = N.o ? `s-${SEV[N.w]}` : N.n ? 'm-res' : 'm-none';
      out.push(`<rect class="gauge ${g}" x="${f1(p.x)}" y="${f1(p.y + 24)}" width="${f1(CW * share)}" height="2"/>`);
    }
    out.push(`<text class="nm hot strong" x="${f1(p.x + 10)}" y="${f1(p.y + 16)}">${esc(cut(N.l, N.b.length ? 19 : 22))}</text>`);
    if (N.b.length) out.push(`<text class="sub" x="${f1(p.x + CW - 10)}" y="${f1(p.y + 16)}" text-anchor="end">⊢${N.b.length}</text>`);
    if (N.x) {
      out.push(`<text class="sub" x="${f1(p.x + 10)}" y="${f1(p.y + 32)}">${N.b.length ? 'outside · across a trust line' : 'outside the model'}</text>`);
    } else {
      let yy = p.y + 40;
      for (const t of N.t.slice(0, 3)) {
        out.push(`<rect class="sw s-${SEV[t[1]]}" x="${f1(p.x + 10)}" y="${f1(yy - 8)}" width="8" height="8" rx="1.5"/><text class="nm hot" x="${f1(p.x + 24)}" y="${f1(yy)}">${esc(cut(t[0], 20))}</text>`);
        yy += 15;
      }
      if (N.o > 3) out.push(`<text class="sub" x="${f1(p.x + CW - 10)}" y="${f1(yy - 15)}" text-anchor="end">+${N.o - 3}</text>`);
      out.push(N.n
        ? `<text class="sub" x="${f1(p.x + 10)}" y="${f1(yy)}"><tspan class="ok">✓ </tspan>${N.n - N.o} resolved · ${N.o} open</text>`
        : `<text class="sub" x="${f1(p.x + 10)}" y="${f1(yy - 2)}">no exposure declared</text>`);
    }
    out.push('</g>');
  }
  out.push('</g>');
  order.forEach((c, i) => {
    if (!hood.m[c]) return;
    const list = hood.c[c];
    const last = list.length ? pos.get(list[list.length - 1])! : { y: TOP - 14, h: 0 };
    out.push(`<text class="more" x="${PAD + i * (CW + GAP) + 4}" y="${f1(last.y + last.h + 22)}">+ ${hood.m[c]} more — see the table</text>`);
  });
  out.push('</svg>');
  return { svg: out.join(''), drawn: hood.e.length, nodes: pos.size, undrawn: hood.u };
}

/**
 * The detail panel for one node: flows in and out, exposures, and the way into
 * its neighbourhood. SELF-CONTAINED — embedded in the page by source.
 */
export function renderNodeDetail(data: HoodPayload, n: number, view: string): string {
  const esc = (s: unknown): string => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const SEV = ['critical', 'high', 'medium', 'low', 'unset'];
  const STATE = ['open', 'confirmed', 'mitigated', 'refuted', 'accepted'];
  const GLYPH: Record<string, string> = { open: '○', confirmed: '✕', mitigated: '✓', refuted: '✓', accepted: '—' };
  const N = data.nodes[n];
  const routeFor = (k: string, v: string): string => `#diagrams?tab=flow&view=${v}&focus=${encodeURIComponent(k)}`;
  const route = (v: string): string => routeFor(N.k, v);
  const kind = N.x ? (N.b.length ? 'outside the model · across a trust line' : 'outside the model') : N.o ? `${N.o} open · worst ${SEV[N.w]}` : N.n ? `all ${N.n} mitigated or accepted` : 'no exposure declared';
  const flowRow = (i: number, dir: 'in' | 'out'): string => {
    const f = data.flows[i];
    const other = data.nodes[dir === 'in' ? f[0] : f[1]];
    return `<li><a class="mono" href="${routeFor(other.k, view)}">${esc(other.l)}</a>${f[3] ? ` <span class="gate-mark" title="${esc(`crosses ${f[3]}`)}">⊢</span>` : ''}${f[2] ? ` <span class="subtle">via ${esc(f[2])}</span>` : ''}</li>`;
  };
  const ins: number[] = [], outs: number[] = [];
  data.flows.forEach((f, i) => { if (f[1] === n) ins.push(i); if (f[0] === n) outs.push(i); });
  const list = (title: string, items: string[]): string => `<div class="nd-col"><div class="eyebrow">${esc(title)}</div>${items.length ? `<ul>${items.slice(0, 12).join('')}${items.length > 12 ? `<li class="subtle">+ ${items.length - 12} more</li>` : ''}</ul>` : '<p class="subtle">none</p>'}</div>`;
  const ex = N.e.slice().sort((a, b) => (a[2] < 2 ? 0 : 1) - (b[2] < 2 ? 0 : 1) || a[1] - b[1]);
  const exRows = ex.map(e => {
    const st = STATE[e[2]];
    return `<li data-claim="${e[0]}" class="clickable"><span class="chip sev-${SEV[e[1]]}"><span class="sw"></span>${SEV[e[1]]}</span> <span class="mono">${esc(e[3])}</span> <span class="state st-${st}"><span class="g">${GLYPH[st]}</span>${st}</span></li>`;
  });
  return `<div class="node-detail" data-detail="${n}">
    <div class="nd-head"><b class="mono">${esc(N.l)}</b><span class="subtle">${esc(kind)}</span>${N.b.length ? `<span class="subtle">⊢ ${esc(N.b.join(', '))}</span>` : ''}${N.h.map(h => `<span class="tag">${esc(h)}</span>`).join('')}<span class="spacer"></span>${view === 'hood' ? `<a class="btn ghost" href="${route('ribbons')}">Whole model</a>` : `<a class="btn" href="${route('hood')}">Open neighbourhood →</a>`}</div>
    <div class="nd-cols">${list(`Flows in · ${ins.length}`, ins.map(i => flowRow(i, 'in')))}${list(`Flows out · ${outs.length}`, outs.map(i => flowRow(i, 'out')))}${list(`Exposures · ${N.e.length}`, exRows)}</div>
  </div>`;
}
