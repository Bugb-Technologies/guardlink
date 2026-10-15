import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject, withReachAnalysis } from '../src/parser/index.js';
import { buildReachAttestation, parseObservedReach, parseToolPins, storeObservedReach, readObservedState } from '../src/attest/index.js';
import { lookup } from '../src/mcp/lookup.js';
import { diffModels } from '../src/diff/index.js';
const hash = 'sha256:' + 'a'.repeat(64);
const fixture = () => parseObservedReach(JSON.parse(readFileSync('conformance/observed-reach/static.json', 'utf8')));
async function model() {
  const root = mkdtempSync(join(tmpdir(), 'observed-reach-'));
  writeFileSync(join(root, 'app.ts'), '/**\n * @actor Sample (#sample-agent)\n * @agents #sample-agent to mcp.sample.read-record\n * @agents #sample-agent to mcp.sample.write-record\n */\nexport function tool() {}\n');
  const { model } = await parseProject({ root, agentConfig: false });
  rmSync(root, { recursive: true, force: true });
  return model;
}
describe('observed reach', () => {
  it('accepts the four public producer fixtures and rejects extra content', () => {
    for (const src of ['static','introspection','remote','otel']) expect(parseObservedReach(JSON.parse(readFileSync(`conformance/observed-reach/${src}.json`, 'utf8'))).schema).toBe('guardlink.observed-reach/v1');
    expect(() => parseObservedReach({ ...fixture(), prompts: ['secret'] })).toThrow();
    const doc = fixture(); doc.observations[0].tools_available[0].description_sha256 = null;
    expect(() => parseObservedReach(doc)).toThrow(/reason/);
  });
  it('joins only explicit identity and capability, verifies claim hints, and compares exact local pins', async () => {
    const m = await model(), doc = fixture(), o = doc.observations[0];
    o.identity = { actor: '#sample-agent', server: 'sample' };
    o.window = { from: '2026-01-01T00:00:00Z', to: '2026-01-02T00:00:00Z' };
    o.tools_available[0].claim_keys = ['not-a-claim'];
    const pins = parseToolPins({ schema: 'guardlink.tool-pins/v1', pins: [{ identity: o.identity, name: 'read-record', description_sha256: 'sha256:' + 'b'.repeat(64) }] });
    const a = buildReachAttestation(m, doc, pins);
    expect(a.summary.matched_tools).toBe(1);
    expect(a.observed_not_declared.map(r => r.name)).toEqual(['computed-tool']);
    expect(a.declared_not_observed.map(r => r.name)).toEqual(['mcp.sample.write-record']);
    expect(a.declared_not_observed[0].claim_keys[0]).toBeTruthy();
    expect(a.unknown.map(r => r.reason)).toContain('claim_key_mismatch');
    expect(a.pin_changed[0]).toMatchObject({ name: 'read-record', after: hash });
    const exported = withReachAnalysis({ ...m, observed_reach: doc, tool_pins: pins });
    expect(lookup(exported, 'reach drift').count).toBeGreaterThan(0);
    expect(diffModels(m, exported).reachAttestation?.length).toBeGreaterThan(0);
  });
  it('withholds negative availability conclusions for incomplete and truncated data', async () => {
    const m = await model(), doc = fixture(), o = doc.observations[0]; o.identity = { actor: '#sample-agent', server: 'sample' };
    for (const coverage of ['partial','unknown','not_collected'] as const) {
      o.coverage.available = coverage; o.tools_available = [];
      expect(buildReachAttestation(m, doc).declared_not_observed).toEqual([]);
    }
    o.coverage.available = 'complete'; o.coverage.truncated = true;
    expect(buildReachAttestation(m, doc).declared_not_observed).toEqual([]);
    o.coverage.truncated = false; o.coverage.available = 'not_collected'; o.coverage.called = 'complete';
    o.window = { from: '2026-01-01T00:00:00Z', to: '2026-01-02T00:00:00Z' };
    expect(buildReachAttestation(m, doc).declared_not_observed[0]).toMatchObject({ basis: 'called', window: o.window });
  });
  it('stores validated local documents and rejects metadata symlinks', () => {
    const root = mkdtempSync(join(tmpdir(), 'observed-store-'));
    try {
      storeObservedReach(root, 'conformance/observed-reach/otel.json');
      expect(readObservedState(root).observed?.observations[0].source).toBe('otel');
      rmSync(join(root, '.guardlink'), { recursive: true });
      mkdirSync(join(root, 'elsewhere'));
      symlinkSync(join(root, 'elsewhere'), join(root, '.guardlink'));
      storeObservedReach(root, 'conformance/observed-reach/otel.json');
      rmSync(join(root, '.guardlink'));
      symlinkSync(tmpdir(), join(root, '.guardlink'));
      expect(() => readObservedState(root)).toThrow(/leaves repository/);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
