/**
 * GuardLink Dashboard — Exposures › the asset × threat matrix.
 *
 * Rows are assets in model order — the spine — grouped by `path[0]`; columns
 * are threats, most exposures first. A cell holds every exposure of that pair
 * that passes the filter, and reads in one of three states, never by colour
 * alone: a warm fill in the worst open severity, a mint wash with a stroke once
 * everything in it is mitigated or refuted, a hollow outline when accepted.
 * The margins carry open and resolved totals as length. Compact mode folds the
 * rows and columns the filter leaves empty and says how many.
 *
 * `renderMatrix` is SELF-CONTAINED — no imports, no outer references — so the
 * page embeds its source and the filter chips and compact toggle re-render with
 * the same function the generator used for the first frame. Geometry comes from
 * the counts alone.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "renderMatrix escapes every asset, group and threat label with its own esc()"
 */
import type { DiagramModel } from './graph.js';

const SEV_INDEX = ['critical', 'high', 'medium', 'low', 'unset'] as const;
const STATE_INDEX = ['open', 'confirmed', 'mitigated', 'refuted', 'accepted'] as const;

export interface MatrixData {
  /** Assets in model order: [label, group]. */
  a: [string, string][];
  /** Threat labels, most exposures first. */
  t: string[];
  /** Every exposure: [asset index, threat index, severity index, state index, claim index]. */
  x: [number, number, number, number, number][];
}

export function buildMatrixData(m: DiagramModel): MatrixData {
  const a = m.assets;
  const aIdx = new Map(a.map((n, i) => [n.key, i]));
  const count = new Map<string, number>();
  for (const e of m.exposures) count.set(e.threat, (count.get(e.threat) ?? 0) + 1);
  const label = (k: string): string => m.threats.get(k)?.label ?? k;
  const t = [...count.keys()].sort((p, q) => count.get(q)! - count.get(p)! || (label(p) < label(q) ? -1 : label(p) > label(q) ? 1 : 0));
  const tIdx = new Map(t.map((k, i) => [k, i]));
  return {
    a: a.map(n => [n.label, n.group]),
    t: t.map(label),
    x: m.exposures.map(e => [aIdx.get(e.asset)!, tIdx.get(e.threat)!, SEV_INDEX.indexOf(e.sev), STATE_INDEX.indexOf(e.state), e.claim]),
  };
}

export interface MatrixRender {
  svg: string;
  /** Exposures that pass the filter. */
  exposures: number;
  cells: number;
  foldedRows: number;
  foldedCols: number;
}

/**
 * Which exposures the matrix counts: the state indices and severity indices
 * allowed (empty means any), and the claim indices still in view (null means
 * all) — the same filters the table under it applies. `pin` is the pinned cell
 * as 'asset.threat' indices, or ''.
 */
export interface MatrixFilter { st: number[]; sv: number[]; keep: number[] | null }

export function renderMatrix(d: MatrixData, filter: MatrixFilter, compact: boolean, pin: string): MatrixRender {
  const esc = (s: unknown): string => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const cut = (s: string, n: number): string => { const c = Array.from(s); return c.length <= n ? s : '…' + c.slice(c.length - n + 1).join(''); };
  const f1 = (n: number): string => String(Math.round(n * 10) / 10);
  const SEV = ['critical', 'high', 'medium', 'low', 'unset'];
  const open = (st: number): boolean => st === 0 || st === 1;
  const keep = filter.keep ? new Set(filter.keep) : null;
  const pass = (x: number[]): boolean => (!filter.st.length || filter.st.includes(x[3])) && (!filter.sv.length || filter.sv.includes(x[2])) && (!keep || keep.has(x[4]));
  const xs = d.x.filter(pass);
  const cells = new Map<string, number[][]>();
  for (const x of xs) {
    const k = x[0] + '.' + x[1];
    if (!cells.has(k)) cells.set(k, []);
    cells.get(k)!.push(x);
  }
  let rows = d.a.map((_, i) => i);
  let cols = d.t.map((_, j) => j);
  const rowHas = (i: number): boolean => cols.some(j => cells.has(i + '.' + j));
  const colHas = (j: number): boolean => rows.some(i => cells.has(i + '.' + j));
  let foldedRows = 0, foldedCols = 0;
  if (compact) {
    const r = rows.filter(rowHas), c = cols.filter(colHas);
    foldedRows = rows.length - r.length; foldedCols = cols.length - c.length;
    rows = r; cols = c;
  }
  const cs = cols.length > 40 ? 12 : cols.length > 24 ? 16 : 22;
  const LEFT = 184, TOP = 124, RM = 74, BM = 46, GH = 18;
  const groups = new Set(rows.map(i => d.a[i][1])).size > 1;
  const rowY: number[] = [];
  const heads: { y: number; g: string }[] = [];
  let y = TOP, last: string | null = null;
  for (const i of rows) {
    if (groups && d.a[i][1] !== last) { heads.push({ y, g: d.a[i][1] }); y += GH; last = d.a[i][1]; }
    rowY.push(y);
    y += cs;
  }
  const gridB = y;
  const W = LEFT + cols.length * cs + RM, H = gridB + BM;
  const out: string[] = [];
  out.push(`<svg class="dg matrix" data-plot="matrix" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="group" tabindex="0" aria-label="${esc(`Matrix of ${rows.length} assets by ${cols.length} threats: ${cells.size} cells, ${xs.length} exposures. Arrow keys step through the cells, Enter pins one.`)}">`);
  out.push('<g class="bands">');
  rows.forEach((i, r) => out.push(`<rect class="band" data-row="${i}" x="0" y="${rowY[r]}" width="${LEFT + cols.length * cs}" height="${cs}"/>`));
  cols.forEach((j, c) => out.push(`<rect class="band" data-col="${j}" x="${LEFT + c * cs}" y="${TOP - 4}" width="${cs}" height="${gridB - TOP + 4}"/>`));
  out.push('</g><g class="labels">');
  cols.forEach((j, c) => {
    const x = LEFT + c * cs + cs / 2, yy = TOP - 8;
    out.push(`<text class="nm col" x="${f1(x)}" y="${yy}" transform="rotate(-50 ${f1(x)} ${yy})">${esc(cut(d.t[j], 22))}</text>`);
  });
  for (const h of heads) out.push(`<text class="hd zone" x="8" y="${h.y + 12}">${esc(cut(h.g, 40).toUpperCase())}</text><line class="sep" x1="8" x2="${LEFT + cols.length * cs}" y1="${h.y + 0.5}" y2="${h.y + 0.5}"/>`);
  rows.forEach((i, r) => {
    const any = cols.some(j => (cells.get(i + '.' + j) || []).some(x => open(x[3])));
    out.push(`<text class="nm${any ? ' hot' : ''}" x="${LEFT - 8}" y="${f1(rowY[r] + cs / 2 + 3.5)}" text-anchor="end">${esc(cut(d.a[i][0], 24))}</text>`);
  });
  out.push('</g><g class="grid">');
  rows.forEach((_, r) => cols.forEach((__, c) => out.push(`<rect class="gridcell" x="${LEFT + c * cs + 0.5}" y="${rowY[r] + 0.5}" width="${cs - 1}" height="${cs - 1}"/>`)));
  out.push('</g><g class="cells">');
  const worstOpen = (list: number[][]): number => list.filter(x => open(x[3])).reduce((w, x) => Math.min(w, x[2]), 9);
  rows.forEach((i, r) => cols.forEach((j, c) => {
    const list = cells.get(i + '.' + j);
    if (!list) return;
    const x0 = LEFT + c * cs, y0 = rowY[r];
    const o = list.filter(x => open(x[3])).length;
    const res = list.filter(x => x[3] === 2 || x[3] === 3).length;
    const acc = list.filter(x => x[3] === 4).length;
    const w = worstOpen(list);
    const cls = o ? `c-open s-${SEV[w]}` : res ? 'c-res' : 'c-acc';
    const key = i + '.' + j;
    out.push(`<g class="cell nd ${cls}${pin === key ? ' pin' : ''}" data-node="x${key}" data-cell="${key}" data-row-i="${i}" data-col-j="${j}" data-claims="${list.map(x => x[4]).join(' ')}" role="button" aria-label="${esc(`${d.a[i][0]} × ${d.t[j]}: ${list.length} exposures, ${o} open`)}" data-tip="${esc(`${d.a[i][0]} × ${d.t[j]}`)}" data-tip-rows="${esc([['exposures', list.length], ['open', o ? `${o} · worst ${SEV[w]}` : 0], ['mitigated or refuted', res], ['accepted', acc]].map(p => p[0] + '\t' + p[1]).join('\n'))}">`);
    out.push(`<rect class="mark" x="${x0 + 2.5}" y="${y0 + 2.5}" width="${cs - 5}" height="${cs - 5}" rx="2"/>`);
    if (cs >= 16 && list.length > 1) out.push(`<text class="count" x="${f1(x0 + cs / 2)}" y="${f1(y0 + cs / 2 + 3.5)}" text-anchor="middle">${list.length}</text>`);
    out.push(`<rect class="pinbox" x="${x0 - 0.5}" y="${y0 - 0.5}" width="${cs + 1}" height="${cs + 1}" rx="3"/></g>`);
  }));
  out.push('</g><g class="margins">');
  // Margins as length: open (in the row's worst open severity) then resolved.
  const rowTot = rows.map(i => { const l = xs.filter(x => x[0] === i); return { o: l.filter(x => open(x[3])).length, n: l.length, w: worstOpen(l) }; });
  const rowMax = Math.max(1, ...rowTot.map(t => t.n));
  rows.forEach((_, r) => {
    const t = rowTot[r], x0 = LEFT + cols.length * cs + 8, yy = rowY[r] + cs / 2 - 3, wpx = 54;
    if (t.o) out.push(`<rect class="mg s-${SEV[t.w]}" x="${x0}" y="${f1(yy)}" width="${f1((t.o / rowMax) * wpx)}" height="6" rx="1"/>`);
    if (t.n - t.o) out.push(`<rect class="mg res" x="${f1(x0 + (t.o / rowMax) * wpx + (t.o ? 1.5 : 0))}" y="${f1(yy)}" width="${f1(((t.n - t.o) / rowMax) * wpx)}" height="6" rx="1"/>`);
  });
  const colTot = cols.map(j => { const l = xs.filter(x => x[1] === j); return { o: l.filter(x => open(x[3])).length, n: l.length, w: worstOpen(l) }; });
  const colMax = Math.max(1, ...colTot.map(t => t.n));
  cols.forEach((_, c) => {
    const t = colTot[c], x0 = LEFT + c * cs + cs / 2 - 3, y0 = gridB + 6, hp = 30;
    if (t.o) out.push(`<rect class="mg s-${SEV[t.w]}" x="${f1(x0)}" y="${y0}" width="6" height="${f1((t.o / colMax) * hp)}" rx="1"/>`);
    if (t.n - t.o) out.push(`<rect class="mg res" x="${f1(x0)}" y="${f1(y0 + (t.o / colMax) * hp + (t.o ? 1.5 : 0))}" width="6" height="${f1(((t.n - t.o) / colMax) * hp)}" rx="1"/>`);
  });
  out.push('</g></svg>');
  return { svg: out.join(''), exposures: xs.length, cells: cells.size, foldedRows, foldedCols };
}
