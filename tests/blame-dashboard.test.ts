/**
 * The dashboard's Attribution page: present only when records carry blame,
 * every identity HTML-escaped, and the output deterministic.
 *
 * git strips `<` and `>` from author NAMES, so the realistic XSS vector is a
 * trailer, which is free text in the commit message. Both are covered: a
 * hand-built identity and a real commit whose co-author trailer is markup.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { attachBlame } from '../src/blame/attach.js';
import type { CommitRef, ExposureBlame } from '../src/blame/types.js';
import { makeRepo } from './blame-fixture.js';

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

async function plainProject(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-blame-dash-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), SOURCE);
  return root;
}

const ref = (author: string, assisted: { tool: string; model: string | null }[] = []): CommitRef => ({
  sha: 'a'.repeat(40), date: '2026-01-01T00:00:00Z', author, co_authors: [], assisted_by: assisted.map(a => ({ ...a, raw: a.tool })),
});

function handBuilt(author: string): ExposureBlame {
  const r = ref(author, [{ tool: 'claude-code', model: 'Claude Opus 5 (1M context)' }]);
  return { kind: 'exposure', status: 'ok', granularity: 'symbol', introduced_by: { ...r, method: 'log-L' }, found_by: r, contributors: [{ ...r, lines: 2 }], fixed_by: ref('human:Fixer'), time_to_fix_days: 3 };
}

describe('dashboard attribution page', () => {
  it('is absent when no record carries blame', async () => {
    const root = await plainProject();
    const { model } = await parseProject({ root, project: 'dash' });
    const html = generateDashboardHTML(model, root);
    expect(html).not.toContain('sec-attribution');
    expect(html).not.toContain('Attribution');
  });

  it('renders the per-person and per-AI tables with every identity escaped', async () => {
    const root = await plainProject();
    const { model } = await parseProject({ root, project: 'dash' });
    model.exposures[0].blame = handBuilt('human:<script>x</script>');
    const html = generateDashboardHTML(model, root);
    expect(html).toContain('sec-attribution');
    expect(html).toContain('claude-code');
    expect(html).toContain('Claude Opus 5 (1M context)');
    expect(html).toContain('human:Fixer');
    expect(html).toContain('&lt;script&gt;x&lt;/script&gt;');
    expect(html).not.toContain('<script>x</script>');
  });

  it('escapes markup that arrived through a real commit trailer', async () => {
    const repo = await makeRepo('guardlink-blame-dash-xss');
    await repo.write('.guardlink/definitions.ts', DEFINITIONS);
    await repo.write('src/a.ts', SOURCE);
    repo.commit('c1', { trailers: ['Co-Authored-By: <script>alert(1)</script> <a@b.c>'] });
    const { model } = await parseProject({ root: repo.root, project: 'dash' });
    attachBlame(repo.root, model);
    expect(model.exposures[0].blame?.found_by?.co_authors).toEqual(['human:<script>alert(1)</script>']);
    const html = generateDashboardHTML(model, repo.root);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
  });

  it('is deterministic for the same model', async () => {
    const root = await plainProject();
    const { model } = await parseProject({ root, project: 'dash' });
    model.exposures[0].blame = handBuilt('human:Ann');
    expect(generateDashboardHTML(model, root)).toBe(generateDashboardHTML(model, root));
  });
});
