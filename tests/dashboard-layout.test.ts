/**
 * The dashboard's diagrams, as geometry: every relation drawn, nothing
 * colliding, nothing NaN.
 *
 * Each Diagrams tab is laid out from data by a pure module under
 * src/dashboard/layout/. These tests pin what the page promises in its footers
 * — "N of N drawn" — on this repository's own model and on the support-desk
 * reach fixture, and re-implement the collision rules a reader would notice:
 * no two names closer than 11 px in a gutter, no two count pills overlapping,
 * no mechanism label sitting on a card, no card on another card.
 *
 * The neighbourhood and matrix renderers are embedded in the page by source,
 * so they are also run here the way the browser runs them: stringified and
 * evaluated in a context with no globals at all.
 *
 * @validates #output-encoding for #dashboard -- "Labels carrying markup come out escaped in every diagram renderer"
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';
import { parseProject } from '../src/parser/parse-project.js';
import { canonicalizeModelOrder } from '../src/parser/canonical-order.js';
import { buildClaims } from '../src/dashboard/pages/context.js';
import { buildDiagramModel, type DiagramModel } from '../src/dashboard/layout/graph.js';
import { layoutTripartite } from '../src/dashboard/layout/tripartite.js';
import { renderThreatGraph } from '../src/dashboard/layout/threat-graph.js';
import { renderRibbons } from '../src/dashboard/layout/ribbons.js';
import { buildHoodPayload, renderHoodSvg, renderNodeDetail, hoodColumns, HOOD_BUDGET, type HoodPayload } from '../src/dashboard/layout/hood.js';
import { renderShelves } from '../src/dashboard/layout/shelves.js';
import { renderReachDiagram } from '../src/dashboard/layout/reach.js';
import { buildMatrixData, renderMatrix } from '../src/dashboard/layout/matrix.js';
import { summarizeReach } from '../src/reach/index.js';
import type { ThreatModel } from '../src/types/index.js';

const ROOT = process.cwd();
const SUPPORT_DESK = join(ROOT, 'tests', 'fixtures', 'support-desk');

let model: ThreatModel;
let g: DiagramModel;
let hood: HoodPayload;
let index: Map<string, number>;

beforeAll(async () => {
  ({ model } = await parseProject({ root: ROOT, project: 'guardlink' }));
  model = canonicalizeModelOrder(model);
  g = buildDiagramModel(model, buildClaims(model, null, null));
  ({ payload: hood, index } = buildHoodPayload(g));
}, 60_000);

/** Every numeric attribute in the markup. */
const numbers = (svg: string): string[] => [...svg.matchAll(/ (?:x|y|x1|x2|y1|y2|width|height|d|transform|viewBox)="([^"]*)"/g)].map(m => m[1]);

function noNaN(svg: string): void {
  for (const v of numbers(svg)) expect(v, v).not.toMatch(/NaN|Infinity|undefined/);
}

/** Gutter names: `<text class="nm…" x y text-anchor>` grouped by x. */
function namesByColumn(svg: string): Map<string, number[]> {
  const cols = new Map<string, number[]>();
  for (const m of svg.matchAll(/<text class="nm[^"]*" x="([\d.-]+)" y="([\d.-]+)" text-anchor="(?:start|end)"/g)) {
    if (!cols.has(m[1])) cols.set(m[1], []);
    cols.get(m[1])!.push(+m[2]);
  }
  return cols;
}

function namesApart(svg: string, min = 11): void {
  for (const [x, ys] of namesByColumn(svg)) {
    const sorted = ys.slice().sort((a, b) => a - b);
    for (let i = 1; i < sorted.length; i++) expect(sorted[i] - sorted[i - 1], `names at x=${x}`).toBeGreaterThanOrEqual(min - 0.05);
  }
}

interface Box { x: number; y: number; w: number; h: number }
const overlaps = (a: Box, b: Box): boolean => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

describe('the tripartite layout', () => {
  const items = [
    { key: 'a1', col: 0 as const }, { key: 'a2', col: 0 as const },
    { key: 't1', col: 1 as const }, { key: 't2', col: 1 as const },
    { key: 'c1', col: 2 as const, group: 'g1' }, { key: 'c2', col: 2 as const, group: 'g2' },
  ];
  const links = [
    { key: 'l1', from: 'a2', to: 't1' }, { key: 'l2', from: 'a1', to: 't2' }, { key: 'l3', from: 'a1', to: 't2' },
    { key: 'l4', from: 't1', to: 'c2' }, { key: 'l5', from: 't2', to: 'c1' },
  ];
  const opts = { pitch: 3, gap: 4, minH: [8, 20, 8] as [number, number, number], top: 30, groupHead: 10, groupGap: 6 };

  it('keeps column 0 in model order and orders the others by barycentre, to cut crossings', () => {
    const L = layoutTripartite(items, links, opts);
    expect(L.order[0]).toEqual(['a1', 'a2']);
    expect(L.order[1]).toEqual(['t2', 't1']);   // t2's partner is a1 (rank 0)
    expect(L.order[2]).toEqual(['c1', 'c2']);   // c1 hangs off t2 (rank 0)
  });

  it('puts every thread end inside its slot, and is deterministic', () => {
    const L = layoutTripartite(items, links, opts);
    for (const l of links) {
      const e = L.ends.get(l.key)!, a = L.slots.get(l.from)!, b = L.slots.get(l.to)!;
      expect(e.y0).toBeGreaterThanOrEqual(a.y); expect(e.y0).toBeLessThanOrEqual(a.y + a.h);
      expect(e.y1).toBeGreaterThanOrEqual(b.y); expect(e.y1).toBeLessThanOrEqual(b.y + b.h);
    }
    expect(JSON.stringify([...layoutTripartite(items, links, opts).slots])).toBe(JSON.stringify([...L.slots]));
  });
});

describe('Diagrams › Threat graph, on this repository', () => {
  it('draws every exposure and every mitigation', () => {
    const r = renderThreatGraph(g);
    expect(r.exposuresDrawn).toBe(r.exposures);
    expect(r.exposures).toBe(model.exposures.length + model.confirmed.length);
    expect(r.mitigationsDrawn).toBe(model.mitigations.length);
    expect((r.svg.match(/class="thr x-(open|res|acc)[^"]*"/g) ?? []).length).toBe(r.exposures);
    expect((r.svg.match(/class="thr x-ctl"/g) ?? []).length).toBe(model.mitigations.length);
  });

  it('keeps names 11 px apart and has no NaN', () => {
    const r = renderThreatGraph(g);
    noNaN(r.svg);
    namesApart(r.svg);
  });
});

describe('Diagrams › Data flow, on this repository', () => {
  it('draws every @flows as a thread, and counts the ones that cross a trust line', () => {
    const r = renderRibbons(g, index);
    expect(r.drawn).toBe(model.flows.length);
    expect((r.svg.match(/class="thr x-(flow|cross)"/g) ?? []).length).toBe(model.flows.length);
    expect((r.svg.match(/class="thr x-cross"/g) ?? []).length).toBe(r.crossing);
    expect(r.crossing).toBe(g.flows.filter(f => f.boundary).length);
    const endpoints = new Set(g.flows.flatMap(f => [f.source, f.target]));
    expect(r.nodes).toBe(endpoints.size);
  });

  it('keeps names 11 px apart, never overlaps two pills, and has no NaN', () => {
    const r = renderRibbons(g, index);
    noNaN(r.svg);
    namesApart(r.svg);
    const pills = [...r.svg.matchAll(/<g class="pill"[^>]*><rect x="([\d.-]+)" y="([\d.-]+)" width="([\d.-]+)" height="([\d.-]+)"/g)].map(m => ({ x: +m[1], y: +m[2], w: +m[3], h: +m[4] }));
    expect(pills.length).toBeGreaterThan(0);
    for (let i = 0; i < pills.length; i++) for (let j = i + 1; j < pills.length; j++) expect(overlaps(pills[i], pills[j]), `pills ${i} ${j}`).toBe(false);
  });
});

describe('Diagrams › Data flow, the neighbourhood of every node', () => {
  it('holds the budget per column, and lists an overflow rather than shrinking', () => {
    for (let i = 0; i < hood.nodes.length; i++) {
      const h = hood.hoods[i];
      for (const col of h.c) expect(col.length).toBeLessThanOrEqual(HOOD_BUDGET);
      expect(h.c[2]).toEqual([i]);
      // A node sits in one column only.
      const all = h.c.flat();
      expect(new Set(all).size).toBe(all.length);
    }
  });

  it('draws every focus with no NaN, no card on a card, and no mechanism label on a later card', () => {
    for (let i = 0; i < hood.nodes.length; i++) {
      const r = renderHoodSvg(hood, i);
      noNaN(r.svg);
      const cards = [...r.svg.matchAll(/<rect class="card-box" x="([\d.-]+)" y="([\d.-]+)" width="([\d.-]+)" height="([\d.-]+)"/g)].map(m => ({ x: +m[1], y: +m[2], w: +m[3], h: +m[4] }));
      expect(cards.length).toBe(r.nodes);
      for (let a = 0; a < cards.length; a++) for (let b = a + 1; b < cards.length; b++) expect(overlaps(cards[a], cards[b]), `${hood.nodes[i].l}: cards ${a} ${b}`).toBe(false);
      // A label's width is estimated the way the layout estimates it: 9.5 px mono at 0.62 em a character.
      for (const m of r.svg.matchAll(/<text class="mech" x="([\d.-]+)" y="([\d.-]+)">([^<]*)</g)) {
        const label = { x: +m[1], y: +m[2] - 9, w: [...m[3].replace(/&[a-z#0-9]+;/g, '_')].length * 9.5 * 0.62, h: 11 };
        for (const c of cards) expect(overlaps(label, c), `${hood.nodes[i].l}: label "${m[3]}"`).toBe(false);
      }
    }
  });

  it('computes the same columns from the flows alone', () => {
    const i = index.get('mcp')!;
    expect(hoodColumns(hood.flows, i, HOOD_BUDGET)).toEqual(hood.hoods[i]);
  });
});

describe('Diagrams › Attack surface', () => {
  it('puts every asset on a shelf, one tick per exposure', () => {
    const r = renderShelves(g);
    expect(r.cards).toBe(g.assets.length);
    expect((r.html.match(/class="shelf-card nd"/g) ?? []).length).toBe(g.assets.length);
    expect((r.html.match(/<i class="tk /g) ?? []).length).toBe(g.exposures.length);
  });
});

describe('Diagrams › Agent reach, on the support-desk fixture', () => {
  it('draws the golden totals: 7 reaches, 9 effects, 5 unentitled, 5 of 7 mutations ungated, 2 gates', async () => {
    const { model: sd } = await parseProject({ root: SUPPORT_DESK, project: 'support-desk' });
    const s = summarizeReach(sd);
    const golden = JSON.parse(readFileSync(join(SUPPORT_DESK, 'golden', 'reach-summary.json'), 'utf8')) as { totals: Record<string, number> };
    expect(s.totals).toEqual(golden.totals);
    const r = renderReachDiagram(s)!;
    expect({ reaches: r.reaches, effects: r.effects, unentitled: r.unentitled, mutations: r.mutations, ungated: r.ungated, gates: r.gates })
      .toEqual({ reaches: 7, effects: 9, unentitled: 5, mutations: 7, ungated: 5, gates: 2 });
    noNaN(r.svg);
    // Two gate bars: a human stands in front of the refund and the outbound email.
    expect((r.svg.match(/class="gate"/g) ?? []).length).toBe(2);
  });

  it('draws nothing for a model with no reach annotation', () => {
    expect(renderReachDiagram(summarizeReach(model))).toBeNull();
  });
});

describe('Exposures › the matrix', () => {
  it('has one cell per distinct (asset, threat) pair in the filter, and folds what the filter empties', () => {
    const d = buildMatrixData(g);
    const pairs = (keep: (x: number[]) => boolean): number => new Set(d.x.filter(keep).map(x => `${x[0]}.${x[1]}`)).size;
    const all = renderMatrix(d, { st: [], sv: [], keep: null }, true, '');
    expect(all.cells).toBe(pairs(() => true));
    expect(all.exposures).toBe(g.exposures.length);
    expect((all.svg.match(/<g class="cell nd /g) ?? []).length).toBe(all.cells);
    const open = renderMatrix(d, { st: [0, 1], sv: [], keep: null }, true, '');
    expect(open.cells).toBe(pairs(x => x[3] <= 1));
    expect(open.foldedRows).toBeGreaterThan(all.foldedRows);
    const full = renderMatrix(d, { st: [0, 1], sv: [], keep: null }, false, '');
    expect(full.foldedRows + full.foldedCols).toBe(0);
    noNaN(full.svg);
  });

  it('marks the pinned cell, and only it', () => {
    const d = buildMatrixData(g);
    const first = `${d.x[0][0]}.${d.x[0][1]}`;
    const r = renderMatrix(d, { st: [], sv: [], keep: null }, true, first);
    expect(r.svg.match(/class="cell nd [^"]* pin"/g)).toHaveLength(1);
    expect(r.svg).toContain(`data-cell="${first}"`);
  });
});

describe('the renderers the page embeds by source', () => {
  /** What the browser runs: the function's own text, in a context with no globals, behind the same shim the page defines. */
  const run = <T>(fn: (...a: never[]) => T, args: unknown[]): T => {
    const ctx: Record<string, unknown> = { args };
    vm.runInNewContext(`var __name = function (f) { return f; }; var f = ${fn.toString()}; out = f.apply(null, args);`, ctx);
    return ctx.out as T;
  };

  it('are self-contained: stringified and run alone, they draw exactly what the generator drew', () => {
    const i = index.get('mcp')!;
    expect(run(renderHoodSvg as never, [hood, i])).toEqual(renderHoodSvg(hood, i));
    expect(run(renderNodeDetail as never, [hood, i, 'hood'])).toBe(renderNodeDetail(hood, i, 'hood'));
    const d = buildMatrixData(g);
    expect(run(renderMatrix as never, [d, { st: [0], sv: [], keep: null }, true, ''])).toEqual(renderMatrix(d, { st: [0], sv: [], keep: null }, true, ''));
  });

  it('escape every label they draw', () => {
    const evil = '<img src=x onerror=alert(1)>';
    const payload: HoodPayload = {
      nodes: [
        { k: 'a', l: evil, x: 0, n: 1, o: 1, w: 1, b: [evil], t: [[evil, 1]], e: [[0, 1, 0, evil]], h: [evil] },
        { k: 'b"x', l: 'B', x: 1, n: 0, o: 0, w: -1, b: [], t: [], e: [], h: [] },
      ],
      flows: [[1, 0, evil, evil, evil, evil]],
      hoods: [{ c: [[], [1], [0], [], []], m: [0, 0, 0, 0, 0], e: [0], u: 0 }, { c: [[], [], [1], [0], []], m: [0, 0, 0, 0, 0], e: [0], u: 0 }],
    };
    for (const html of [renderHoodSvg(payload, 0).svg, renderNodeDetail(payload, 0, 'hood'), renderNodeDetail(payload, 1, 'ribbons')]) {
      expect(html).not.toContain('<img');
      expect(html).toContain('&lt;img');
    }
    const m = renderMatrix({ a: [[evil, evil]], t: [evil], x: [[0, 0, 1, 0, 0]] }, { st: [], sv: [], keep: null }, false, '');
    expect(m.svg).not.toContain('<img');
  });
});
