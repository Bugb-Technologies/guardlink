/**
 * The markdown report's Attribution section: present only when records carry
 * blame, and honest about what could not be attributed.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { generateReport } from '../src/report/index.js';
import type { CommitRef, ExposureBlame, MitigationBlame } from '../src/blame/types.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;
const SOURCE = `import x from 'x';

/**
 * @exposes #api to #sqli [high] cwe:CWE-89 -- "raw"
 * @mitigates #api against #sqli using #prepared-stmts -- "bound"
 */
export function login(email: string) { return email; }
`;

async function project(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-blame-report-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), SOURCE);
  return root;
}

const ref = (author: string, assisted: { tool: string; model: string | null }[] = []): CommitRef => ({
  sha: 'abcdef0123456789abcdef0123456789abcdef01', date: '2026-01-01T00:00:00Z', author, co_authors: [], assisted_by: assisted.map(a => ({ ...a, raw: a.tool })),
});

describe('report attribution section', () => {
  it('is absent when no record carries blame', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'rep' });
    expect(generateReport(model)).not.toContain('## Attribution');
  });

  it('lists people, AI tools and each attributed claim', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'rep' });
    const intro = ref('human:Ann', [{ tool: 'claude-code', model: 'Claude Opus 5 (1M context)' }]);
    const exposure: ExposureBlame = { kind: 'exposure', status: 'ok', granularity: 'symbol', introduced_by: { ...intro, method: 'log-L' }, found_by: intro, contributors: [{ ...intro, lines: 1 }], fixed_by: ref('human:Bob'), time_to_fix_days: 5 };
    const mitigation: MitigationBlame = { kind: 'mitigation', status: 'ok', granularity: 'symbol', declared_by: ref('human:Bob'), contributors: [] };
    model.exposures[0].blame = exposure;
    model.mitigations[0].blame = mitigation;
    const md = generateReport(model);
    expect(md).toContain('## Attribution');
    expect(md).toContain('human:Ann');
    expect(md).toContain('human:Bob');
    expect(md).toContain('claude-code');
    expect(md).toContain('Claude Opus 5 (1M context)');
    expect(md).toContain('abcdef01');
    expect(md).toMatch(/\|\s*5\s*\|/); // the time-to-fix cell
  });

  it('says which claims could not be attributed', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'rep' });
    model.exposures[0].blame = { kind: 'exposure', status: 'no-git', granularity: 'none', introduced_by: null, found_by: null, contributors: [], fixed_by: null, time_to_fix_days: null };
    const md = generateReport(model);
    expect(md).toContain('## Attribution');
    expect(md).toContain('no-git');
  });
});
