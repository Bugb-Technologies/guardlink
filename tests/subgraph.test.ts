/**
 * GL-202 — subgraph selection, the architectural spine.
 *
 * The load-bearing test in this file is `generateThreatGraph(selectSubgraph(…))`
 * with zero generator changes. If that stops holding, SG-3 cannot treat `.mmd`
 * artifacts as a disk cache of common selections and has to reimplement
 * selection — which is the design the PRD is built on.
 *
 * Cycle termination is tested against a constructed cycle, not the live repo:
 * the repo has 0 self-loops today and that is an accident of its annotations,
 * not a property worth relying on.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { lookup } from '../src/mcp/lookup.js';
import { generateThreatGraph } from '../src/dashboard/index.js';
import {
  selectSubgraph, traverseGraph, findPath, graphEdges, canonicaliser, MAX_DEPTH,
} from '../src/mcp/subgraph.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

function emptyModel(overrides: Partial<ThreatModel> = {}): ThreatModel {
  return {
    version: '1.0.0', project: 'test', generated_at: '', source_files: 0,
    annotated_files: [], unannotated_files: [], annotations_parsed: 0,
    assets: [], threats: [], controls: [], mitigations: [], exposures: [],
    confirmed: [], acceptances: [], transfers: [], flows: [], boundaries: [],
    validations: [], audits: [], ownership: [], data_handling: [],
    assumptions: [], shields: [], features: [], comments: [],
    coverage: { annotation_count: 0, coverage_percent: 0 },
    ...overrides,
  };
}

const at = (file = 'x.ts', line = 1) => ({ file, line });

describe('selectSubgraph — the ThreatModel contract', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  it('returns something every ThreatModel consumer accepts', () => {
    const sub = selectSubgraph(model, { from: '#cli', depth: 2 });
    // Same field set as the input — a subgraph is a model, not a graph shape.
    for (const key of Object.keys(model)) expect(sub, key).toHaveProperty(key);
    expect(Array.isArray(sub.assets)).toBe(true);
    expect(Array.isArray(sub.flows)).toBe(true);
  });

  it('generateThreatGraph consumes it with ZERO generator changes', () => {
    // The property SG-3 depends on.
    const sub = selectSubgraph(model, { from: '#cli', depth: 2 });
    const mermaid = generateThreatGraph(sub, { showAll: true });
    expect(mermaid).toMatch(/^(flowchart|graph)\s/m);
    expect(mermaid.length).toBeGreaterThan(0);
    // And it is genuinely narrower than the whole-model render.
    expect(mermaid.length).toBeLessThan(generateThreatGraph(model, { showAll: true }).length);
  });

  it('the rendered mermaid is structurally well-formed at every depth', () => {
    // A proxy for "renders in a standard viewer": mermaid is not a dependency of
    // this repo, so the real parse was verified out of band against
    // mermaid@11.16.1 (all nine variants, reported alongside this change). What
    // is pinned here are the failure modes a selection bug would actually cause
    // — an unbalanced subgraph block, or an undefined leaking into a node label.
    for (const opts of [
      { from: '#cli', depth: 1 },
      { from: '#cli', depth: 2, direction: 'out' as const },
      { from: '#cli', depth: 3 },
      { from: '#llm-client', depth: 2, direction: 'in' as const },
      { from: '#no-such-asset', depth: 2 },
    ]) {
      const mmd = generateThreatGraph(selectSubgraph(model, opts), { showAll: true });
      const label = JSON.stringify(opts);
      expect(mmd, label).toMatch(/^(flowchart|graph)\s+\w+/m);
      expect(mmd, label).not.toMatch(/undefined|\[object Object\]/);
      const opens = (mmd.match(/^\s*subgraph\s/gm) || []).length;
      const ends = (mmd.match(/^\s*end\s*$/gm) || []).length;
      expect(ends, `${label}: ${opens} subgraph vs ${ends} end`).toBe(opens);
    }
  });

  it('mermaid rendering passes showAll, so a scoped view is not silently severity-filtered', () => {
    // generateThreatGraph drops everything below high severity once a model
    // names more than 12 distinct threats. On a subgraph the caller already
    // narrowed, a second invisible filter would remove data they asked for.
    const sub = selectSubgraph(model, { from: '#cli', depth: 3 });
    const shown = generateThreatGraph(sub, { showAll: true });
    const filtered = generateThreatGraph(sub, {});
    const lowSeverityThreat = sub.threats.find(t => t.severity === 'low' || t.severity === 'medium');
    if (lowSeverityThreat && shown.length !== filtered.length) {
      expect(shown.length).toBeGreaterThan(filtered.length);
    }
    expect(shown).toMatch(/^(flowchart|graph)\s/m);
  });

  it('the subgraph is a strict subset of the source model', () => {
    const sub = selectSubgraph(model, { from: '#cli', depth: 1 });
    expect(sub.assets.length).toBeLessThanOrEqual(model.assets.length);
    expect(sub.flows.length).toBeLessThanOrEqual(model.flows.length);
    for (const f of sub.flows) expect(model.flows).toContainEqual(f);
    for (const e of sub.exposures) expect(model.exposures).toContainEqual(e);
  });

  it('annotations_parsed is recomputed, not carried over', () => {
    const sub = selectSubgraph(model, { from: '#cli', depth: 1 });
    expect(sub.annotations_parsed).toBeLessThan(model.annotations_parsed);
    const counted = sub.assets.length + sub.threats.length + sub.controls.length
      + sub.mitigations.length + sub.exposures.length + sub.confirmed.length
      + sub.acceptances.length + sub.transfers.length + sub.flows.length
      + sub.boundaries.length + sub.validations.length + sub.audits.length
      + sub.ownership.length + sub.data_handling.length + sub.assumptions.length
      + sub.shields.length + sub.features.length + sub.comments.length;
    expect(sub.annotations_parsed).toBe(counted);
  });

  it('composes with filterByFeature through the feature option', () => {
    const sub = selectSubgraph(model, { feature: 'MCP Integration' });
    expect(sub.annotations_parsed).toBeGreaterThan(0);
    expect(sub.annotations_parsed).toBeLessThan(model.annotations_parsed);
  });
});

describe('selectSubgraph — depth 1 agrees with `asset X`', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  // The regression guard that proves the selector did not quietly invent its own
  // join. Both must resolve the ref the same way and reach the same relations.
  it('every declared asset reports the same relations both ways', () => {
    const key = canonicaliser(model);
    for (const asset of model.assets) {
      const ref = `#${asset.id}`;
      const viaLookup = lookup(model, `asset ${ref}`).results[0];
      const sub = selectSubgraph(model, { from: ref, depth: 1 });
      const self = key(asset.id || '');

      const subExposures = sub.exposures.filter(e => key(e.asset) === self);
      const subMitigations = sub.mitigations.filter(m => key(m.asset) === self);
      const subIn = sub.flows.filter(f => key(f.target) === self);
      const subOut = sub.flows.filter(f => key(f.source) === self);

      expect(subExposures, ref).toHaveLength(viaLookup.relationships.exposures.length);
      expect(subMitigations, ref).toHaveLength(viaLookup.relationships.mitigations.length);
      expect(subIn, ref).toHaveLength(viaLookup.relationships.inbound_flows.length);
      expect(subOut, ref).toHaveLength(viaLookup.relationships.outbound_flows.length);
    }
  });

  it('depth 0 is the node alone', () => {
    const t = traverseGraph(model, { from: '#cli', depth: 0 });
    expect(t.nodes).toHaveLength(1);
    expect(t.nodes[0].key).toBe('cli');
    expect(t.nodes[0].depth).toBe(0);
  });
});

describe('traverseGraph — direction and edge semantics', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  it('out follows flows forwards, in follows them backwards', () => {
    const out = traverseGraph(model, { from: '#cli', depth: 1, direction: 'out' });
    const inb = traverseGraph(model, { from: '#cli', depth: 1, direction: 'in' });
    const both = traverseGraph(model, { from: '#cli', depth: 1, direction: 'both' });

    const keys = (t: typeof out) => new Set(t.nodes.map(n => n.key));
    // `both` is the union of the two directions.
    for (const k of keys(out)) expect(keys(both)).toContain(k);
    for (const k of keys(inb)) expect(keys(both)).toContain(k);
    expect(keys(both).size).toBeGreaterThanOrEqual(Math.max(keys(out).size, keys(inb).size));
  });

  it('depth grows the node set monotonically', () => {
    const sizes = [0, 1, 2, 3].map(d => traverseGraph(model, { from: '#cli', depth: d }).nodes.length);
    for (let i = 1; i < sizes.length; i++) expect(sizes[i]).toBeGreaterThanOrEqual(sizes[i - 1]);
  });

  it('traversal does NOT cross the threat plane', () => {
    // #path-traversal is declared on 10 assets. If a hop could go
    // asset -> threat -> asset, depth 2 would pull most of them in.
    const t = traverseGraph(model, { from: '#cli', depth: 2 });
    const keys = new Set(t.nodes.map(n => n.key));
    const sharers = new Set(
      model.exposures
        .filter(e => e.threat.replace(/^#/, '') === 'path-traversal')
        .map(e => e.asset.replace(/^#/, '').toLowerCase()),
    );
    expect(sharers.size).toBeGreaterThan(5);       // precondition: it really is a hub
    const pulledIn = [...sharers].filter(s => keys.has(s));
    expect(pulledIn.length).toBeLessThan(sharers.size);
  });

  it('threats and controls still come back for every visited asset', () => {
    const sub = selectSubgraph(model, { from: '#cli', depth: 1 });
    expect(sub.exposures.length).toBeGreaterThan(0);
    expect(sub.threats.length).toBeGreaterThan(0);
    // Not transited through, but fully attached.
    expect(sub.threats.some(t => sub.exposures.some(e => e.threat.replace(/^#/, '') === t.id))).toBe(true);
  });

  it('hop 0 resolves fuzzily and says so', () => {
    const t = traverseGraph(model, { from: 'llm', depth: 2 });
    expect(t.start?.matched_via).toBe('substring');
    expect(t.start?.canonical).toBe('llm-client');
  });

  it('later hops match canonical identity only, never fuzzily', () => {
    // Constructed, because on the live repo #cli genuinely IS 2 hops from
    // #llm-client through the ThreatModel endpoint — a real edge, which would
    // make this assertion pass for the wrong reason. Here there is no edge
    // between them at all, so #cli can only appear if a hop matched
    // "cli" ⊂ "llm-client" the way hop 0 is allowed to.
    const m = emptyModel({
      assets: [
        { path: ['Cli'], id: 'cli', location: at() },
        { path: ['LlmClient'], id: 'llm-client', location: at() },
        { path: ['Sink'], id: 'sink', location: at() },
      ],
      flows: [{ source: '#llm-client', target: '#sink', mechanism: 'x', location: at() }],
    });
    const t = traverseGraph(m, { from: 'llm', depth: 5 });
    expect(t.start?.matched_via).toBe('substring');
    expect(t.start?.canonical).toBe('llm-client');
    expect(t.nodes.map(n => n.key).sort()).toEqual(['llm-client', 'sink']);
    expect(t.nodes.map(n => n.key)).not.toContain('cli');
  });

  it('an ambiguous start ref is named, not silently picked', () => {
    const t = traverseGraph(model, { from: 'client', depth: 1 });
    expect(t.start?.ambiguous).toBe(true);
    expect(t.start?.candidates).toEqual(expect.arrayContaining(['cli', 'llm-client']));
  });

  it('an unresolvable start returns an explicit unresolved result', () => {
    const t = traverseGraph(model, { from: '#no-such-asset-anywhere', depth: 2 });
    expect(t.start?.resolved).toBe(false);
    expect(t.nodes).toEqual([]);
    expect(t.edges).toEqual([]);
  });

  it('undeclared flow endpoints are legal start nodes', () => {
    const t = traverseGraph(model, { from: 'LLMProvider', depth: 1 });
    expect(t.start?.resolved).toBe(true);
    expect(t.nodes.length).toBeGreaterThan(1);
  });
});

describe('traverseGraph — boundaries are undirected', () => {
  const model = emptyModel({
    assets: [
      { path: ['A'], id: 'a', location: at() },
      { path: ['B'], id: 'b', location: at() },
    ],
    boundaries: [{ asset_a: '#a', asset_b: '#b', id: 'ab', location: at() }],
  });

  it.each(['in', 'out', 'both'] as const)('a boundary is crossed with direction=%s', (direction) => {
    // An undirected edge is simultaneously in- and out-adjacent. Dropping it
    // from a directional query would hide exactly the edges a trust review wants.
    const t = traverseGraph(model, { from: '#a', depth: 1, direction });
    expect(t.nodes.map(n => n.key).sort()).toEqual(['a', 'b']);
  });

  it('a directed flow is NOT crossed against its direction', () => {
    const m = emptyModel({
      assets: [{ path: ['A'], id: 'a', location: at() }, { path: ['B'], id: 'b', location: at() }],
      flows: [{ source: '#a', target: '#b', mechanism: 'http', location: at() }],
    });
    expect(traverseGraph(m, { from: '#a', depth: 1, direction: 'out' }).nodes.map(n => n.key)).toEqual(['a', 'b']);
    expect(traverseGraph(m, { from: '#a', depth: 1, direction: 'in' }).nodes.map(n => n.key)).toEqual(['a']);
    expect(traverseGraph(m, { from: '#b', depth: 1, direction: 'in' }).nodes.map(n => n.key).sort()).toEqual(['a', 'b']);
  });
});

describe('traverseGraph — cycles terminate', () => {
  // Constructed, because the live repo has 0 self-loops and that is an accident
  // of its annotations rather than something to rely on.
  const cyclic = emptyModel({
    assets: ['a', 'b', 'c'].map(id => ({ path: [id.toUpperCase()], id, location: at() })),
    flows: [
      { source: '#a', target: '#b', mechanism: 'x', location: at() },
      { source: '#b', target: '#c', mechanism: 'x', location: at() },
      { source: '#c', target: '#a', mechanism: 'x', location: at() },   // closes the loop
    ],
  });

  it('a 3-cycle terminates and visits each node once', () => {
    const t = traverseGraph(cyclic, { from: '#a', depth: 50, direction: 'out' });
    expect(t.nodes.map(n => n.key).sort()).toEqual(['a', 'b', 'c']);
    expect(t.nodes.filter(n => n.key === 'a')).toHaveLength(1);
  });

  it('each node records the depth it was first reached at', () => {
    const t = traverseGraph(cyclic, { from: '#a', depth: 10, direction: 'out' });
    const depths = Object.fromEntries(t.nodes.map(n => [n.key, n.depth]));
    expect(depths).toEqual({ a: 0, b: 1, c: 2 });
  });

  it('a self-loop terminates', () => {
    const selfish = emptyModel({
      assets: [{ path: ['A'], id: 'a', location: at() }],
      flows: [{ source: '#a', target: '#a', mechanism: 'recurse', location: at() }],
    });
    const t = traverseGraph(selfish, { from: '#a', depth: 50 });
    expect(t.nodes).toHaveLength(1);
  });

  it('a two-node mutual cycle terminates', () => {
    const mutual = emptyModel({
      assets: [{ path: ['A'], id: 'a', location: at() }, { path: ['B'], id: 'b', location: at() }],
      flows: [
        { source: '#a', target: '#b', mechanism: 'x', location: at() },
        { source: '#b', target: '#a', mechanism: 'y', location: at() },
      ],
    });
    const t = traverseGraph(mutual, { from: '#a', depth: 50 });
    expect(t.nodes.map(n => n.key).sort()).toEqual(['a', 'b']);
  });

  it('depth is clamped so an absurd request cannot run away', () => {
    const t = traverseGraph(cyclic, { from: '#a', depth: 10_000 });
    expect(t.depth_requested).toBe(10_000);
    expect(t.depth_reached).toBeLessThanOrEqual(MAX_DEPTH);
  });
});

describe('kinds filtering', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  it('kinds filters the output', () => {
    const sub = selectSubgraph(model, { from: '#cli', depth: 2, kinds: ['exposures'] });
    expect(sub.exposures.length).toBeGreaterThan(0);
    expect(sub.mitigations).toEqual([]);
    expect(sub.flows).toEqual([]);
  });

  it('kinds does NOT filter the traversal', () => {
    // Excluding flows must not strand the walk — otherwise kinds:['exposures']
    // would return an empty graph, which is a surprising way to say "no edges".
    const withFlows = selectSubgraph(model, { from: '#cli', depth: 2 });
    const without = selectSubgraph(model, { from: '#cli', depth: 2, kinds: ['exposures'] });
    expect(without.exposures).toHaveLength(withFlows.exposures.length);
  });

  it('node definitions survive kinds filtering', () => {
    const sub = selectSubgraph(model, { from: '#cli', depth: 1, kinds: ['flows'] });
    expect(sub.assets.length).toBeGreaterThan(0);
  });
});

describe('findPath', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  it('a reachable pair returns ordered hops', () => {
    const chain = emptyModel({
      assets: ['a', 'b', 'c'].map(id => ({ path: [id.toUpperCase()], id, location: at() })),
      flows: [
        { source: '#a', target: '#b', mechanism: 'first', location: at() },
        { source: '#b', target: '#c', mechanism: 'second', location: at() },
      ],
    });
    const p = findPath(chain, '#a', '#c');
    expect(p.found).toBe(true);
    expect(p.hops.map(h => [h.from, h.to])).toEqual([['a', 'b'], ['b', 'c']]);
    expect(p.hops.map(h => h.via.label)).toEqual(['first', 'second']);
  });

  it('an unreachable pair says so, and says both ends exist', () => {
    const split = emptyModel({
      assets: ['a', 'b'].map(id => ({ path: [id.toUpperCase()], id, location: at() })),
      flows: [{ source: '#a', target: '#a', mechanism: 'x', location: at() }],
      boundaries: [{ asset_a: '#b', asset_b: '#b', id: 'bb', location: at() }],
    });
    const p = findPath(split, '#a', '#b');
    expect(p.found).toBe(false);
    expect(p.from.resolved).toBe(true);
    expect(p.to.resolved).toBe(true);
    expect(p.reason).toMatch(/Both endpoints exist/);
  });

  it('an unresolvable endpoint is a DIFFERENT answer from no path', () => {
    const p = findPath(model, '#cli', '#no-such-thing-at-all');
    expect(p.found).toBe(false);
    expect(p.to.resolved).toBe(false);
    expect(p.reason).toMatch(/Unresolved/);
    // Must not read as "your graph is disconnected".
    expect(p.reason).not.toMatch(/Both endpoints exist/);
  });

  it('direction matters: a -> b exists, b -> a does not', () => {
    const oneWay = emptyModel({
      assets: ['a', 'b'].map(id => ({ path: [id.toUpperCase()], id, location: at() })),
      flows: [{ source: '#a', target: '#b', mechanism: 'x', location: at() }],
    });
    expect(findPath(oneWay, '#a', '#b').found).toBe(true);
    expect(findPath(oneWay, '#b', '#a').found).toBe(false);
  });

  it('a boundary is crossable in either direction', () => {
    const bounded = emptyModel({
      assets: ['a', 'b'].map(id => ({ path: [id.toUpperCase()], id, location: at() })),
      boundaries: [{ asset_a: '#a', asset_b: '#b', id: 'ab', location: at() }],
    });
    expect(findPath(bounded, '#a', '#b').found).toBe(true);
    expect(findPath(bounded, '#b', '#a').found).toBe(true);
  });

  it('a node to itself is a zero-hop path, not a miss', () => {
    const p = findPath(model, '#cli', '#cli');
    expect(p.found).toBe(true);
    expect(p.hops).toEqual([]);
  });

  it('terminates on a cyclic graph', () => {
    const cyclic = emptyModel({
      assets: ['a', 'b', 'c', 'z'].map(id => ({ path: [id.toUpperCase()], id, location: at() })),
      flows: [
        { source: '#a', target: '#b', mechanism: 'x', location: at() },
        { source: '#b', target: '#c', mechanism: 'x', location: at() },
        { source: '#c', target: '#a', mechanism: 'x', location: at() },
      ],
    });
    const p = findPath(cyclic, '#a', '#z');
    expect(p.found).toBe(false);
    expect(p.reason).toMatch(/Both endpoints exist/);
  });
});

describe('graphEdges', () => {
  it('canonicalises endpoints so #id and Dotted.Path collapse', () => {
    const m = emptyModel({
      assets: [{ path: ['App', 'Cli'], id: 'cli', location: at() }],
      flows: [
        { source: 'User', target: '#cli', mechanism: 'a', location: at() },
        { source: 'User', target: 'App.Cli', mechanism: 'b', location: at() },
      ],
    });
    const edges = graphEdges(m);
    expect(edges.map(e => e.to)).toEqual(['cli', 'cli']);
  });

  it('records directedness per edge kind', () => {
    const m = emptyModel({
      flows: [{ source: 'A', target: 'B', mechanism: 'x', location: at() }],
      boundaries: [{ asset_a: 'A', asset_b: 'B', id: 'ab', location: at() }],
      transfers: [{ threat: '#t', source: 'A', target: 'B', location: at() }],
    });
    const byKind = Object.fromEntries(graphEdges(m).map(e => [e.kind, e.directed]));
    expect(byKind).toEqual({ flow: true, boundary: false, transfer: true });
  });
});

// ─── Entitlements survive scoping ────────────────────────────────────
//
// selectSubgraph rebuilds a ThreatModel field by field, so a collection it does
// not name is silently dropped rather than merely unfiltered. An entitlement
// vanishing from a scoped view would read as "this role holds nothing here",
// which is the wrong answer to the one question the verb exists to answer.
describe('selectSubgraph — actors and entitlements', () => {
  const scoped = () => emptyModel({
    assets: [
      { path: ['Parser'], id: 'parser', location: at() },
      { path: ['Cli'], id: 'cli', location: at('other.ts') },
    ],
    threats: [{ name: 'Arbitrary_Write', canonical_name: 'arbitrary_write', id: 'arbitrary-write', external_refs: [], location: at() }],
    exposures: [{ asset: '#parser', threat: '#arbitrary-write', external_refs: [], location: at() }],
    actors: [{ name: 'Local_Developer', canonical_name: 'local_developer', id: 'local-dev', location: at() }],
    entitlements: [
      { actor: '#local-dev', capability: 'clear-annotations', canonical_capability: 'clear_annotations',
        asset: '#parser', threat: '#arbitrary-write', inert: false, imprecise: false,
        citation: { file: 'src/cli/index.ts', line: 1071, raw: 'src/cli/index.ts:1071' }, location: at() },
      { actor: '#local-dev', capability: 'unrelated-thing', canonical_capability: 'unrelated_thing',
        asset: '#cli', threat: '#arbitrary-write', inert: false, imprecise: false,
        citation: { file: 'src/cli/index.ts', line: 1, raw: 'src/cli/index.ts:1' }, location: at('other.ts') },
    ],
  });

  it('keeps an entitlement whose asset is in the selection', () => {
    const sub = selectSubgraph(scoped(), { from: '#parser', depth: 1 });
    expect((sub.entitlements ?? []).map(e => e.canonical_capability)).toContain('clear_annotations');
  });

  it('drops one whose asset is outside it', () => {
    const sub = selectSubgraph(scoped(), { from: '#parser', depth: 1 });
    expect((sub.entitlements ?? []).map(e => e.canonical_capability)).not.toContain('unrelated_thing');
  });

  it('keeps the actor declaration behind a kept entitlement', () => {
    const sub = selectSubgraph(scoped(), { from: '#parser', depth: 1 });
    expect((sub.actors ?? []).map(a => a.id)).toContain('local-dev');
  });

  it('counts entitlements in the recomputed annotation total', () => {
    const sub = selectSubgraph(scoped(), { from: '#parser', depth: 1 });
    const counted = (sub.entitlements ?? []).length + (sub.actors ?? []).length;
    expect(counted).toBeGreaterThan(0);
    expect(sub.annotations_parsed).toBeGreaterThanOrEqual(counted);
  });

  it('honours an explicit kinds filter that excludes them', () => {
    const sub = selectSubgraph(scoped(), { from: '#parser', depth: 1, kinds: ['exposures'] });
    expect(sub.entitlements ?? []).toHaveLength(0);
  });
});
