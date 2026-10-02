/**
 * The model export's `reach_analysis` block (SPEC §5.5): unentitled reaches
 * with their near misses, and the gating of every mutating effect, as
 * `guardlink parse`, `report --format json`, `.guardlink/model.json`, the MCP
 * `guardlink_parse` tool and `guardlink_lookup` give it to a consumer.
 *
 * Read against tests/fixtures/support-desk, the fixture whose pentest SARIF is
 * pinned in tests/fixtures/sarif-pentest/support-desk.sarif.
 *
 * @validates #fail-closed for #parser -- "An uncited or other-asset entitlement never covers a reach, and a capability-scoped gate never covers an effect whose route is unknown: both joins report rather than hide"
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { parseProject } from '../src/parser/parse-project.js';
import {
  buildReachAnalysis, withReachAnalysis, classifyEffects, REACH_ANALYSIS_VERSION,
} from '../src/parser/reach.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { canonicalizeModelOrder } from '../src/parser/canonical-order.js';
import { emitArtifacts } from '../src/artifacts/emit.js';
import { lookup } from '../src/mcp/lookup.js';
import { createServer } from '../src/mcp/server.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const fixture = (name: string) => join(repoRoot, 'tests', 'fixtures', name);
const cli = join(repoRoot, 'dist', 'cli', 'index.js');

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });
const copyOf = (name: string): string => {
  const root = mkdtempSync(join(tmpdir(), `gl-reach-export-${name}-`));
  roots.push(root);
  cpSync(fixture(name), root, { recursive: true });
  return root;
};

let model: ThreatModel;
beforeAll(async () => { ({ model } = await parseProject({ root: fixture('support-desk'), project: 'support-desk' })); });

describe('buildReachAnalysis', () => {
  it('is versioned and counts what it lists', () => {
    const a = buildReachAnalysis(model);
    expect(a.version).toBe(REACH_ANALYSIS_VERSION);
    expect(a.version).toBe(1);
    expect(a.summary).toEqual({
      reaches: 7, agent_reaches: 6, unentitled_reaches: 5,
      effects: 9, mutating_effects: 7, ungated_effects: 5, gates: 2,
    });
    expect(Object.keys(a)).toEqual(['version', 'summary', 'unentitled_reaches', 'mutating_effects']);
  });

  it('lists unentitled reaches with why each near-miss entitlement does not count', () => {
    const rows = buildReachAnalysis(model).unentitled_reaches;
    expect(rows.map(r => [r.capability, r.near_misses.map(n => n.blocker)])).toEqual([
      ['publish-package', []], ['run-sql', []], ['search-kb', ['other-asset']], ['fetch-url', ['uncited']], ['mcp-files', []],
    ]);
    const searchKb = rows[2];
    expect(searchKb.near_misses[0]).toMatchObject({ actor: '#support-agent', capability: 'search-kb', asset: '#kb', cited: true, line: 36 });
    expect(rows[3].near_misses[0]).toMatchObject({ asset: null, cited: false });
    expect(rows[0]).toMatchObject({ verb: 'reaches', actor: '#ci-runner', agent: false, asset: '#registry', identity: null });
    expect(rows[1].colocated_effects.map(e => `${e.effect} ${e.asset}`)).toEqual(['delete #orders-db', 'write #users-db']);
  });

  it('points every row at its claim by index into the exported arrays, and by claim key', () => {
    const a = buildReachAnalysis(model);
    const keys = new Map(relationRecords(model).map(r => [r.location, r.key]));
    for (const r of a.unentitled_reaches) {
      expect(r.claim_key).toBe(keys.get(model.reaches![r.index].location));
      for (const n of r.near_misses) expect(n.claim_key).toBe(keys.get(model.entitlements![n.index].location));
      for (const e of r.colocated_effects) expect(e.claim_key).toBe(keys.get(model.effects![e.index].location));
    }
    for (const e of a.mutating_effects) {
      expect(e.claim_key).toBe(keys.get(model.effects![e.index].location));
      for (const g of [...e.gates, ...e.gate_near_misses]) expect(g.claim_key).toBe(keys.get(model.gates![g.index].location));
      for (const r of e.colocated_reaches) expect(r.claim_key).toBe(keys.get(model.reaches![r.index].location));
    }
  });

  it('gates an effect by an unscoped gate on its asset, or a scoped gate on the capability bound to its code', () => {
    const rows = buildReachAnalysis(model).mutating_effects;
    expect(rows.map(e => [e.effect, e.asset, e.gated, e.gate_near_misses.map(g => g.blocker)])).toEqual([
      ['notify', '#outbox', true, []],
      ['spend', '#payments', false, ['capability-unknown']],
      ['write', '#registry', false, []],
      ['delete', '#orders-db', false, []],
      ['write', '#users-db', false, []],
      ['spend', '#payments', true, []],
      ['write', '#host-fs', false, []],
    ]);
    const refund = rows[5];
    expect(refund.gates).toMatchObject([{ approver: '#support-human', capability: 'issue-refund', canonical_capability: 'issue_refund' }]);
    expect(refund.colocated_reaches.map(r => r.capability)).toEqual(['issue-refund']);
  });

  it('does not let a gate scoped to one capability cover an effect another capability also reaches', () => {
    const refund = model.effects!.find(e => e.effect === 'spend' && e.location.file === 'src/tools.ts')!;
    const loc = { ...refund.location, line: refund.location.line + 100 };
    const other = { ...model.reaches![0], capability: 'cancel-order', canonical_capability: 'cancel_order', location: loc };
    const g = classifyEffects({ ...model, reaches: [...model.reaches!, other] }).find(x => x.effect === refund)!;
    expect(g.gates).toEqual([]);
    expect(g.near_misses.map(n => n.blocker)).toEqual(['other-capability']);
  });
});

describe('withReachAnalysis', () => {
  it('adds nothing to a model that declares no reach, effect or gate', async () => {
    const { model: plain } = await parseProject({ root: fixture('sarif-shop'), project: 'sarif-shop' });
    expect(JSON.stringify(withReachAnalysis(plain))).toBe(JSON.stringify(plain));
  });

  it('appends the block last, rebuilt from the model it is given, never carried stale', () => {
    const exported = withReachAnalysis(model);
    expect(Object.keys(exported).at(-1)).toBe('reach_analysis');
    const narrowed = withReachAnalysis({ ...exported, reaches: [] });
    expect(narrowed.reach_analysis!.summary.reaches).toBe(0);
    expect(narrowed.reach_analysis!.unentitled_reaches).toEqual([]);
    // A stale block on a model that no longer declares any reach is dropped, not carried.
    expect('reach_analysis' in withReachAnalysis({ ...exported, reaches: [], effects: [], gates: [] })).toBe(false);
  });

  it('leaves the annotation hash where it was', () => {
    expect(computeAnnotationHash(withReachAnalysis(model))).toBe(computeAnnotationHash(model));
  });
});

describe('where a consumer reads it', () => {
  it('guardlink parse writes it, and writes nothing new for a model without the verbs', () => {
    const out = JSON.parse(execFileSync('node', [cli, 'parse', fixture('support-desk')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
    // Indexes point into the arrays of the document it is written in.
    const { reach_analysis: written, ...exported } = out;
    expect(written).toEqual(JSON.parse(JSON.stringify(buildReachAnalysis(exported))));
    expect(written.summary).toEqual(buildReachAnalysis(model).summary);
    const plain = JSON.parse(execFileSync('node', [cli, 'parse', fixture('boundary-direction')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
    expect('reach_analysis' in plain).toBe(false);
  });

  it('guardlink report --format json writes it', () => {
    const root = copyOf('support-desk');
    execFileSync('node', [cli, 'report', root, '--format', 'json', '-o', 'tm.json'], { cwd: root, stdio: 'pipe' });
    const report = JSON.parse(readFileSync(join(root, 'tm.json'), 'utf-8'));
    expect(report.reach_analysis.summary.unentitled_reaches).toBe(5);
  });

  it('.guardlink/model.json carries it, indexed into the canonically ordered arrays beside it', () => {
    const root = copyOf('support-desk');
    emitArtifacts({ root, model });
    const written = JSON.parse(readFileSync(join(root, '.guardlink', 'model.json'), 'utf-8'));
    const ordered = canonicalizeModelOrder(model);
    expect(written.reaches.map((r: { capability: string }) => r.capability)).toEqual(ordered.reaches!.map(r => r.capability));
    for (const r of written.reach_analysis.unentitled_reaches) {
      expect(written.reaches[r.index].location.line).toBe(r.line);
      expect(written.reaches[r.index].location.file).toBe(r.file);
    }
    for (const e of written.reach_analysis.mutating_effects) expect(written.effects[e.index].location.line).toBe(e.line);
  });

  it('MCP guardlink_parse returns it', async () => {
    const server = createServer();
    const client = new Client({ name: 'test', version: '0.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const res = await client.callTool({ name: 'guardlink_parse', arguments: { root: fixture('support-desk') } });
      const body = JSON.parse((res.content as { text: string }[])[0].text);
      expect(body.reach_analysis.version).toBe(1);
      expect(body.reach_analysis.summary.ungated_effects).toBe(5);
    } finally {
      await client.close();
    }
  });

  it('guardlink_lookup answers ungated effects, and gives each unentitled reach its claim key', () => {
    const ungated = lookup(model, 'ungated effects');
    expect(ungated).toMatchObject({ type: 'ungated_effects', count: 5 });
    expect(lookup(model, 'ungated effects for #payments').results).toMatchObject([
      { effect: 'spend', gate_near_misses: [{ blocker: 'capability-unknown', approver: '#support-human', capability: 'issue_refund' }] },
    ]);
    expect(lookup(model, 'ungated effects for Shop.Outbox').count).toBe(0);
    const keys = new Set(buildReachAnalysis(model).unentitled_reaches.map(r => r.claim_key));
    const rows = lookup(model, 'unentitled reaches').results as { claim_key: string }[];
    expect(new Set(rows.map(r => r.claim_key))).toEqual(keys);
  });
});
