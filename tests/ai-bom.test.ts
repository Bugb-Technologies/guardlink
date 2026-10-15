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
