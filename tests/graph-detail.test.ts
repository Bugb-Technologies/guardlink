/**
 * guardlink_graph `detail` — strip the payload, not the graph.
 *
 * Measured on this repo at depth 2 from `#cli`: `description` and `location`
 * together are ~44% of the response, and that proportion barely moves with
 * depth. The cost is what hangs off each node, not how many nodes there are —
 * so the answer is not a smaller default depth (depth 1 makes the tool
 * redundant with `asset X`) nor a default direction of `out` (an arbitrary
 * asymmetry that hides everything upstream).
 *
 * The load-bearing test here is TOPOLOGY IDENTITY. A summary mode that quietly
 * dropped a node would be a silent-wrong-answer path in the one tool an agent
 * uses to ask "what does my change affect" — strictly worse than a large
 * payload. It holds structurally, because summarising is a pure post-transform
 * that never sees the traversal options; these tests pin that it stays that way.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { selectSubgraph, traverseGraph, summariseGraphPayload } from '../src/mcp/subgraph.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
let model: ThreatModel;

beforeAll(async () => {
  ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' }));
}, 60_000);

const build = (from: string, depth: number, direction: 'in' | 'out' | 'both' = 'both') => {
  const options = { from, depth, direction };
  const traversal = traverseGraph(model, options);
  const sub = selectSubgraph(model, options);
  return {
    full: { traversal, model: sub },
    summary: summariseGraphPayload({ traversal, model: sub }) as {
      traversal: typeof traversal;
      model: Record<string, unknown>;
    },
  };
};

const CASES: Array<[string, number]> = [
  ['#cli', 1], ['#cli', 2], ['#cli', 3],
  ['#llm-client', 1], ['#llm-client', 2], ['#llm-client', 3],
];

describe('detail — topology is IDENTICAL between summary and full', () => {
  it.each(CASES)('%s depth %i: same nodes, same edges, same counts', (from, depth) => {
    const { full, summary } = build(from, depth);

    expect(summary.traversal.nodes).toEqual(full.traversal.nodes);
    expect(summary.traversal.nodes).toHaveLength(full.traversal.nodes.length);
    expect(summary.traversal.edges).toHaveLength(full.traversal.edges.length);
    expect(summary.traversal.depth_reached).toBe(full.traversal.depth_reached);
    expect(summary.traversal.start).toEqual(full.traversal.start);

    // Same edge endpoints in the same order — only file/line representation moves.
    expect(summary.traversal.edges.map(e => `${e.from}->${e.to}:${e.kind}`))
      .toEqual(full.traversal.edges.map(e => `${e.from}->${e.to}:${e.kind}`));
  });

  it.each(CASES)('%s depth %i: every relation array has the same row count', (from, depth) => {
    const { full, summary } = build(from, depth);
    const fullModel = full.model as unknown as Record<string, unknown>;
    for (const [key, rows] of Object.entries(fullModel)) {
      if (!Array.isArray(rows)) continue;
      expect(summary.model[key], key).toHaveLength(rows.length);
    }
  });

  it('the row identity — not just the count — survives', () => {
    const { full, summary } = build('#cli', 2);
    const ident = (rows: unknown[]) =>
      rows.map(r => {
        const o = r as Record<string, unknown>;
        return `${o.asset ?? o.source ?? o.id ?? o.path}|${o.threat ?? o.target ?? o.name ?? ''}`;
      });
    expect(ident(summary.model.exposures as unknown[])).toEqual(ident(full.model.exposures));
    expect(ident(summary.model.flows as unknown[])).toEqual(ident(full.model.flows));
  });
});

describe('detail — what summary actually drops', () => {
  it('no description survives anywhere in the payload', () => {
    const { summary } = build('#cli', 2);
    expect(JSON.stringify(summary)).not.toMatch(/"description":/);
  });

  it('no location object survives, but file:line does', () => {
    const { summary } = build('#cli', 2);
    const json = JSON.stringify(summary);
    expect(json).not.toMatch(/"location":/);
    expect(json).toMatch(/"at": ?"[^"]+:\d+"/);
  });

  it('`at` points at the same place `location` did', () => {
    const { full, summary } = build('#cli', 2);
    const fullRow = full.model.exposures[0];
    const summaryRow = (summary.model.exposures as Array<Record<string, unknown>>)[0];
    expect(summaryRow.at).toBe(`${fullRow.location.file}:${fullRow.location.line}`);
  });

  it('severity, ids and kinds are kept — they are what blast radius is reasoned from', () => {
    const { full, summary } = build('#cli', 2);
    const rows = summary.model.exposures as Array<Record<string, unknown>>;
    expect(rows[0].asset).toBe(full.model.exposures[0].asset);
    expect(rows[0].threat).toBe(full.model.exposures[0].threat);
    expect(rows[0].severity).toBe(full.model.exposures[0].severity);
    expect((summary.model.threats as Array<Record<string, unknown>>)[0].id).toBeDefined();
  });

  it('full is unchanged — it is still a valid ThreatModel', () => {
    const { full } = build('#cli', 2);
    expect(full.model.exposures[0]).toHaveProperty('description');
    expect(full.model.exposures[0]).toHaveProperty('location');
    expect(full.model.assets.length).toBeGreaterThan(0);
  });

  it('summary labels itself and says how to get the rest', () => {
    const s = summariseGraphPayload(build('#cli', 1).full) as Record<string, unknown>;
    expect(s.detail).toBe('summary');
    expect(String(s.detail_note)).toMatch(/detail:"full"/);
    expect(String(s.detail_note)).toMatch(/identical/i);
  });

  it('summarising does not mutate its input', () => {
    const { full } = build('#cli', 2);
    const before = JSON.stringify(full);
    summariseGraphPayload(full);
    expect(JSON.stringify(full)).toBe(before);
  });
});

describe('detail — the saving is real', () => {
  it.each(CASES)('%s depth %i: summary is smaller than full', (from, depth) => {
    const { full, summary } = build(from, depth);
    const f = JSON.stringify(full, null, 2).length;
    const s = JSON.stringify(summary, null, 2).length;
    expect(s).toBeLessThan(f);
    // Measured 28-40% across these six cases. Pinned loosely: the point is that
    // the saving does not silently evaporate, not that it hits a magic number.
    expect((f - s) / f).toBeGreaterThan(0.25);
  });
});
