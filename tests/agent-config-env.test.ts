import { it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject, withReachAnalysis } from '../src/parser/index.js';
it('exports endpoint and credential names, pointers, scope, harness and claim keys without values', async () => {
  const root = mkdtempSync(join(tmpdir(), 'env-facts-'));
  try {
    mkdirSync(join(root, '.claude'));
    writeFileSync(join(root, '.claude/settings.json'), JSON.stringify({ env: { ANTHROPIC_BASE_URL: 'https://synthetic.invalid/private-route', ANTHROPIC_AUTH_TOKEN: 'synthetic-credential-value', COLOR: 'blue' } }));
    const { model } = await parseProject({ root });
    const exported = withReachAnalysis(model);
    const rows = exported.reach_analysis!.unentitled_reaches;
    expect(rows.map(r => r.source?.semantics.rule)).toEqual(['env-credential','env-endpoint']);
    expect(rows.every(r => r.claim_key && r.source?.harness === 'claude-code' && r.source.scope === 'root' && r.file === '.claude/settings.json')).toBe(true);
    expect(rows.find(r => r.source?.semantics.rule === 'env-endpoint')?.source?.pointer).toBe('/env/ANTHROPIC_BASE_URL');
    expect(JSON.stringify(exported)).not.toContain('synthetic-credential-value');
    expect(JSON.stringify(exported)).not.toContain('synthetic.invalid');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
