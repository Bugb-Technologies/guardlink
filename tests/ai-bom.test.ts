import { it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { generateAiBom } from '../src/bom/index.js';
import type { ThreatModel } from '../src/types/index.js';
it('exports deterministic CycloneDX inventory and stable references without raw configuration', () => {
  const m = JSON.parse(readFileSync('conformance/agent-config-env.json', 'utf8')) as ThreatModel;
  const bom = generateAiBom(m);
  expect(bom).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1 });
  expect(bom).toEqual(generateAiBom(m));
  expect(bom.components[0].properties.find(p => p.name === 'guardlink:reaches')?.value).toContain('claim_key');
  expect(JSON.stringify(bom)).not.toContain('source.raw');
  const refs = bom.components.map(c => c['bom-ref']);
  expect(new Set(refs).size).toBe(refs.length);
});

it('keeps every bundled and MCP component reference closed in the published synthetic inventory', () => {
  const m = JSON.parse(readFileSync('conformance/agent-config-surfaces.json', 'utf8')) as ThreatModel;
  const bom = generateAiBom(m);
  const refs = new Set(bom.components.map(c => c['bom-ref']));
  expect(bom.components.filter(c => c.properties.some(p => p.name === 'guardlink:kind' && p.value === 'mcp-server'))).toHaveLength(5);
  expect(bom.dependencies.every(d => refs.has(d.ref) && d.dependsOn.every(r => refs.has(r)))).toBe(true);
  expect(bom).toEqual(JSON.parse(readFileSync('conformance/agent-inventory.cdx.json', 'utf8')));
});
