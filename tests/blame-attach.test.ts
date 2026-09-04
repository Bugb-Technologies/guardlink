/**
 * computeBlame / attachBlame against real repositories.
 *
 * The load-bearing assertion: `introduced_by` is the commit that CREATED the
 * span, even after a later (AI-assisted) commit rewrote a line in it. Plain
 * blame would answer with the later commit; `git log -L` answers correctly.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { computeBlame } from '../src/blame/compute.js';
import { attachBlame } from '../src/blame/attach.js';
import type { ExposureBlame, MitigationBlame } from '../src/blame/types.js';
import { makeRepo, makePlainDir, type Repo } from './blame-fixture.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

// A leading comment is a file header to the structure layer (anchor scope `file`),
// so the fixture opens with an import, as real code does — the doc block then
// anchors to `login` (scope `symbol`).
const V1 = `import x from 'x';

/**
 * @exposes #api to #sqli [high] cwe:CWE-89 -- "email concatenated into SQL"
 */
export function login(email: string) {
  return 'SELECT ' + email;
}
`;
const V2 = V1.replace("return 'SELECT ' + email;", "return 'SELECT * FROM u WHERE e=' + email;");
const V3 = V2.replace(
  ' */\nexport function login',
  ' * @mitigates #api against #sqli using #prepared-stmts -- "bound parameters"\n */\nexport function login',
);

const CLAUDE = 'Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>';

/** c1 human creates login (Jan 1); c2 Claude-assisted edit of the body (Jan 2); c3 Codex-assisted @mitigates (Jan 3). */
async function threeCommitRepo(): Promise<Repo & { c1: string; c2: string; c3: string }> {
  const repo = await makeRepo();
  await repo.write('.guardlink/definitions.ts', DEFINITIONS);
  await repo.write('src/a.ts', V1);
  const c1 = repo.commit('create login', { date: '2026-01-01T10:00:00+00:00' });
  await repo.write('src/a.ts', V2);
  const c2 = repo.commit('edit query', { date: '2026-01-02T10:00:00+00:00', trailers: [CLAUDE] });
  await repo.write('src/a.ts', V3);
  const c3 = repo.commit('declare mitigation', { date: '2026-01-03T10:00:00+00:00', trailers: ['Assisted-by: Codex:gpt-5.2'] });
  return { ...repo, c1, c2, c3 };
}

describe('computeBlame on a three-commit history', () => {
  it('introduced_by is the creating commit, found_by the annotation commit, fixed_by the mitigation commit', async () => {
    const repo = await threeCommitRepo();
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const comp = computeBlame(repo.root, model);
    expect(comp.status).toBe('ok');
    expect(comp.head).toBe(repo.c3);

    const b = comp.byRecord.get(model.exposures[0]) as ExposureBlame;
    expect(b.kind).toBe('exposure');
    expect(b.status).toBe('ok');
    expect(b.granularity).toBe('symbol');
    expect(b.introduced_by).toMatchObject({ sha: repo.c1, method: 'log-L', author: 'human:Test Human', assisted_by: [] });
    expect(b.introduced_by?.lower_bound).toBeUndefined();
    expect(b.found_by?.sha).toBe(repo.c1);

    const byC2 = b.contributors.find(c => c.sha === repo.c2);
    expect(byC2).toMatchObject({ lines: 1, assisted_by: [{ tool: 'claude-code', model: 'Claude Opus 5 (1M context)' }] });
    expect(b.contributors[0].sha).toBe(repo.c1); // most lines first

    expect(b.fixed_by).toMatchObject({ sha: repo.c3, assisted_by: [{ tool: 'codex', model: 'gpt-5.2' }] });
    expect(b.time_to_fix_days).toBe(2);
    expect(b.fixed_before_introduced).toBeUndefined();
  });

  it('a mitigation carries declared_by and the span contributors', async () => {
    const repo = await threeCommitRepo();
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const comp = computeBlame(repo.root, model);
    const m = comp.byRecord.get(model.mitigations[0]) as MitigationBlame;
    expect(m).toMatchObject({ kind: 'mitigation', status: 'ok', granularity: 'symbol' });
    expect(m.declared_by?.sha).toBe(repo.c3);
    expect(m.contributors.map(c => c.sha).sort()).toEqual([repo.c1, repo.c2].sort());
  });

  it('computeBlame never mutates the model; attachBlame writes record.blame and leaves the annotation hash alone', async () => {
    const repo = await threeCommitRepo();
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const before = structuredClone(model);
    const hashBefore = computeAnnotationHash(model);
    computeBlame(repo.root, model);
    expect(model).toEqual(before);
    expect(JSON.stringify(model)).not.toContain('"blame"');

    attachBlame(repo.root, model);
    expect(model.exposures[0].blame?.kind).toBe('exposure');
    expect(model.mitigations[0].blame?.kind).toBe('mitigation');
    expect(computeAnnotationHash(model)).toBe(hashBefore);
  });

  it('can be narrowed to one file', async () => {
    const repo = await threeCommitRepo();
    await repo.write('src/other.ts', '/**\n * @exposes #api to #sqli [low] -- "elsewhere"\n */\nexport function q() { return 1; }\n');
    repo.commit('other file');
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const comp = computeBlame(repo.root, model, { file: 'src/other.ts' });
    const blamed = [...comp.byRecord.keys()];
    expect(blamed).toHaveLength(1);
    expect((blamed[0] as { location: { file: string } }).location.file).toBe('src/other.ts');
  });
});

describe('computeBlame degrades honestly', () => {
  it('file-scope anchors report granularity file and the commit that added the file', async () => {
    const repo = await makeRepo();
    await repo.write('.guardlink/definitions.ts', DEFINITIONS);
    await repo.write('src/b.ts', '/**\n * @exposes #api to #sqli [low] -- "file-wide"\n */\nexport {};\n');
    const add = repo.commit('add b', { date: '2026-01-05T10:00:00+00:00' });
    await repo.write('src/b.ts', '/**\n * @exposes #api to #sqli [low] -- "file-wide"\n */\nexport {};\nexport const later = 1;\n');
    repo.commit('extend b', { date: '2026-01-06T10:00:00+00:00' });
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const b = computeBlame(repo.root, model).byRecord.get(model.exposures[0]) as ExposureBlame;
    expect(b.granularity).toBe('file');
    expect(b.introduced_by).toMatchObject({ sha: add, method: 'file-add' });
    expect(b.fixed_by).toBeNull();
    expect(b.time_to_fix_days).toBeNull();
  });

  it('outside a git checkout every record is no-git and nothing throws', async () => {
    const root = await makePlainDir();
    const { writeFile, mkdir } = await import('node:fs/promises');
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'a.ts'), V3);
    const { model } = await parseProject({ root, project: 'test' });
    const comp = computeBlame(root, model);
    expect(comp.status).toBe('no-git');
    expect(comp.head).toBeNull();
    const b = comp.byRecord.get(model.exposures[0]) as ExposureBlame;
    expect(b).toMatchObject({ status: 'no-git', introduced_by: null, found_by: null, fixed_by: null, contributors: [] });
  });

  it('an uncommitted edit inside the span marks the record uncommitted and falls back to blame with a lower bound', async () => {
    const repo = await threeCommitRepo();
    await repo.write('src/a.ts', V3.replace("' + email;", "' + email; // edited"));
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const b = computeBlame(repo.root, model).byRecord.get(model.exposures[0]) as ExposureBlame;
    expect(b.status).toBe('uncommitted');
    expect(b.introduced_by).toMatchObject({ sha: repo.c1, method: 'blame', lower_bound: true });
    expect(b.found_by?.sha).toBe(repo.c1);
  });

  it('a brand-new untracked file is uncommitted with nothing to blame', async () => {
    const repo = await threeCommitRepo();
    await repo.write('src/new.ts', '/**\n * @exposes #api to #sqli [low] -- "new"\n */\nexport function n() { return 1; }\n');
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const rec = model.exposures.find(e => e.location.file === 'src/new.ts')!;
    const b = computeBlame(repo.root, model).byRecord.get(rec) as ExposureBlame;
    expect(b).toMatchObject({ status: 'uncommitted', introduced_by: null, found_by: null, contributors: [] });
  });

  it('a sidecar .gal claim is found_by the sidecar commit while introduced_by follows the source span', async () => {
    const repo = await makeRepo();
    await repo.write('.guardlink/definitions.ts', DEFINITIONS);
    await repo.write('src/api.ts', 'export function login(email: string) {\n  return email;\n}\n');
    const c1 = repo.commit('source', { date: '2026-02-01T10:00:00+00:00' });
    await repo.write('.guardlink/annotations/src/api.ts.gal',
      '@source file:src/api.ts line:1 symbol:login\n@exposes #api to #sqli [high] -- "declared in a sidecar"\n');
    const c2 = repo.commit('sidecar', { date: '2026-02-02T10:00:00+00:00', author: 'Other Person <other@example.com>' });
    const { model } = await parseProject({ root: repo.root, project: 'test' });
    const b = computeBlame(repo.root, model).byRecord.get(model.exposures[0]) as ExposureBlame;
    expect(b.status).toBe('ok');
    expect(b.found_by).toMatchObject({ sha: c2, author: 'human:Other Person' });
    expect(b.introduced_by).toMatchObject({ sha: c1, author: 'human:Test Human' });
  });

  it('a shallow clone still answers, with every introduced_by marked a lower bound', async () => {
    const repo = await threeCommitRepo();
    const dest = await mkdtemp(join(tmpdir(), 'guardlink-blame-shallow-'));
    execFileSync('git', ['clone', '-q', '--depth', '1', `file://${repo.root}`, dest], { stdio: 'pipe' });
    const { model } = await parseProject({ root: dest, project: 'test' });
    const comp = computeBlame(dest, model);
    expect(comp.status).toBe('shallow');
    const b = comp.byRecord.get(model.exposures[0]) as ExposureBlame;
    expect(b.status).toBe('shallow');
    expect(b.introduced_by?.lower_bound).toBe(true);
  });
});
