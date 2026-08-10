/**
 * `traversal.completeness` — three states, not a boolean.
 *
 * `truncated: boolean` conflated "I stopped because a limit was hit" with "I
 * stopped because there was nothing left to reach" — the
 * didn't-run-versus-found-nothing confusion, applied to traversal. The case that
 * exposed it is pinned first, because it is the one a regression would restore:
 * `#llm-client` depth 1 `out` reported `truncated: true` while depth 2 `out`
 * reported `false`, on an identical 4 nodes / 6 edges.
 *
 * The old flag was testing `frontier.length > 0` — "did the last hop add any
 * nodes" — which is a question about what the result already CONTAINS, not about
 * what is missing from it. Those nodes are in `visited`; they are in the answer.
 *
 * `truncated` is exercised against a constructed chain rather than this repo:
 * the real graph saturates at depth 5, well under MAX_DEPTH, so the ceiling is
 * unreachable here. That is an accident of these annotations, not a property to
 * rely on.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { traverseGraph, MAX_DEPTH } from '../src/mcp/subgraph.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
let model: ThreatModel;

/** A chain longer than MAX_DEPTH: n0 -> n1 -> … -> n15. */
let chainRoot: string;
let chain: ThreatModel;

beforeAll(async () => {
  ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' }));

  chainRoot = await mkdtemp(join(tmpdir(), 'guardlink-chain-'));
  await mkdir(join(chainRoot, 'src'), { recursive: true });
  await writeFile(join(chainRoot, 'package.json'), '{"name":"chain"}\n');
  const lines = ['/**'];
  for (let i = 0; i <= 15; i++) lines.push(` * @asset Chain.N${i} (#n${i}) -- "link ${i}"`);
  for (let i = 0; i < 15; i++) lines.push(` * @flows #n${i} -> #n${i + 1} via step -- "hop ${i}"`);
  lines.push(' */', 'export const chain = 1;');
  await writeFile(join(chainRoot, 'src', 'chain.ts'), lines.join('\n'));
  ({ model: chain } = await parseProject({ root: chainRoot, project: 'chain' }));
}, 60_000);

afterAll(async () => {
  await rm(chainRoot, { recursive: true, force: true });
});

describe('the case that exposed the conflation', () => {
  it('#llm-client d1/out and d2/out return the identical graph', () => {
    const d1 = traverseGraph(model, { from: '#llm-client', depth: 1, direction: 'out' });
    const d2 = traverseGraph(model, { from: '#llm-client', depth: 2, direction: 'out' });

    expect(d1.nodes).toHaveLength(4);
    expect(d1.edges).toHaveLength(6);
    expect(d2.nodes.map(n => n.key)).toEqual(d1.nodes.map(n => n.key));
    expect(d2.edges).toHaveLength(d1.edges.length);
  });

  it('…and therefore must agree on completeness', () => {
    const d1 = traverseGraph(model, { from: '#llm-client', depth: 1, direction: 'out' });
    const d2 = traverseGraph(model, { from: '#llm-client', depth: 2, direction: 'out' });

    // Previously: d1 truncated=true, d2 truncated=false. Same graph, opposite claims.
    expect(d1.completeness).toBe('complete');
    expect(d2.completeness).toBe(d1.completeness);
    expect(d1.frontier_unexplored).toBeUndefined();
  });

  it('the boolean is gone, not renamed', () => {
    const t = traverseGraph(model, { from: '#llm-client', depth: 1, direction: 'out' });
    expect(t).not.toHaveProperty('truncated');
  });
});

describe('complete', () => {
  it('a saturated sink is complete, not truncated', () => {
    // #n15 has no outgoing edges at all. Nothing to find at any depth.
    const t = traverseGraph(chain, { from: '#n15', depth: 3, direction: 'out' });
    expect(t.nodes).toHaveLength(1);
    expect(t.completeness).toBe('complete');
    expect(t.frontier_unexplored).toBeUndefined();
  });

  it('a depth past the graph diameter is complete', () => {
    const t = traverseGraph(model, { from: '#cli', depth: 9, direction: 'both' });
    expect(t.completeness).toBe('complete');
    expect(t.depth_reached).toBeLessThan(9);
  });

  it('depth 0 on an isolated node is complete', () => {
    const t = traverseGraph(chain, { from: '#n15', depth: 0, direction: 'out' });
    expect(t.completeness).toBe('complete');
  });
});

describe('depth_limited', () => {
  it('#cli d1/both has more beyond it, and says what', () => {
    const t = traverseGraph(model, { from: '#cli', depth: 1, direction: 'both' });
    expect(t.completeness).toBe('depth_limited');
    expect(t.frontier_unexplored!.count).toBeGreaterThan(0);
    expect(t.frontier_unexplored!.nodes).toHaveLength(t.frontier_unexplored!.count);
  });

  it('raising depth actually returns those nodes — the promise the state makes', () => {
    const d1 = traverseGraph(model, { from: '#cli', depth: 1, direction: 'both' });
    const d2 = traverseGraph(model, { from: '#cli', depth: 2, direction: 'both' });

    expect(d1.completeness).toBe('depth_limited');
    expect(d2.nodes.length).toBeGreaterThan(d1.nodes.length);
    const d2keys = new Set(d2.nodes.map(n => n.key));
    for (const named of d1.frontier_unexplored!.nodes) {
      expect(d2keys.has(named), `promised ${named} at depth 2`).toBe(true);
    }
  });

  it('depth 0 with neighbours is depth_limited, not complete', () => {
    const t = traverseGraph(chain, { from: '#n0', depth: 0, direction: 'out' });
    expect(t.nodes).toHaveLength(1);
    expect(t.completeness).toBe('depth_limited');
    expect(t.frontier_unexplored!.nodes).toEqual(['n1']);
  });

  it('exactly at MAX_DEPTH with more beyond is depth_limited, not truncated', () => {
    // The caller asked for 10 and got 10. Nothing was taken from them.
    const t = traverseGraph(chain, { from: '#n0', depth: MAX_DEPTH, direction: 'out' });
    expect(t.completeness).toBe('depth_limited');
    expect(t.frontier_unexplored!.nodes).toEqual(['n11']);
  });
});

describe('truncated', () => {
  it('a request beyond MAX_DEPTH with more to reach is truncated', () => {
    const t = traverseGraph(chain, { from: '#n0', depth: MAX_DEPTH + 1, direction: 'out' });
    expect(t.completeness).toBe('truncated');
    expect(t.depth_requested).toBe(MAX_DEPTH + 1);
    expect(t.depth_reached).toBe(MAX_DEPTH);
  });

  it('it reports what was dropped', () => {
    const t = traverseGraph(chain, { from: '#n0', depth: 20, direction: 'out' });
    expect(t.completeness).toBe('truncated');
    expect(t.frontier_unexplored!.count).toBe(1);
    expect(t.frontier_unexplored!.nodes).toEqual(['n11']);
  });

  it('a request beyond MAX_DEPTH on an EXHAUSTED graph is complete, not truncated', () => {
    // The clamp fired, but it cost nothing: there was nothing past depth 5.
    const t = traverseGraph(model, { from: '#cli', depth: 20, direction: 'both' });
    expect(t.depth_requested).toBe(20);
    expect(t.completeness).toBe('complete');
  });
});

describe('all three states are reachable', () => {
  it('and are distinct', () => {
    const states = new Set([
      traverseGraph(chain, { from: '#n15', depth: 3, direction: 'out' }).completeness,
      traverseGraph(chain, { from: '#n0', depth: 2, direction: 'out' }).completeness,
      traverseGraph(chain, { from: '#n0', depth: 20, direction: 'out' }).completeness,
    ]);
    expect([...states].sort()).toEqual(['complete', 'depth_limited', 'truncated']);
  });

  it('frontier_unexplored is present exactly when the answer is partial', () => {
    for (const [from, depth, expected] of [
      ['#n15', 3, 'complete'], ['#n0', 2, 'depth_limited'], ['#n0', 20, 'truncated'],
    ] as const) {
      const t = traverseGraph(chain, { from, depth, direction: 'out' });
      expect(t.completeness).toBe(expected);
      expect(t.frontier_unexplored === undefined).toBe(expected === 'complete');
    }
  });
});
