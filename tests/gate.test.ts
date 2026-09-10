/**
 * The gate: lint rules over the model, what a run added, the re-prompt, the
 * strip, and `guardlink lint` from the CLI.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { parseProject } from '../src/parser/parse-project.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { lintAnnotations, runGate, buildGateFollowUp, stripViolations, formatGateReport } from '../src/gate/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.Web (#web) -- "Web tier"
 * @threat SQL_Injection (#sqli) [high] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 * @threat DoS (#dos) [medium] -- "Resource exhaustion"
 * @control Encoding (#enc) -- "Output encoding"
 * @actor Admin (#admin) -- "Administrator"
 */
export {};
`;

/** A clean file: every exposure names code, is paired, sits within its threat's band. */
const GOOD = `import x from 'x';

/**
 * @exposes #api to #sqli [high] cwe:CWE-89 -- "req.body.email concatenated into findUser() query at db.ts:40"
 * @mitigates #api against #sqli using #enc -- "escapeSql() wraps every literal in query()"
 * @exposes #web to #xss [medium] -- "profile.bio rendered through innerHTML in render()"
 * @audit #web -- "bio is not encoded; needs a control or an acceptance"
 * @flows User -> #api via HTTPS -- "login"
 */
export function login() {}
`;

/** What a careless run adds: vague, unpaired, over-band, an @accepts, an @entitles, an evidence-free @confirmed. */
const BAD = `import y from 'y';

/**
 * @exposes #api to #dos [critical] -- "Input not validated"
 * @exposes #api to #xss -- "SQL injection possible"
 * @confirmed #xss on #web [high] -- "probably exploitable"
 * @accepts #dos on #api -- "we accept this"
 * @entitles #admin to delete-users on #api -- "admins can delete"
 * @mitigates #web against #dos -- "handled"
 * @comment -- "Security stuff"
 */
export function page() {}
`;

async function project(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-gate-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  for (const [name, text] of Object.entries(files)) await writeFile(join(root, 'src', name), text);
  return root;
}

describe('lintAnnotations', () => {
  it('passes a well-formed file and flags every rule on a careless one', async () => {
    const good = await project({ 'a.ts': GOOD });
    const { model: gm } = await parseProject({ root: good, project: 'g' });
    expect(lintAnnotations(gm).filter(v => v.level === 'error')).toEqual([]);

    const bad = await project({ 'a.ts': GOOD, 'b.ts': BAD });
    const { model: bm } = await parseProject({ root: bad, project: 'b' });
    const v = lintAnnotations(bm);
    const rules = (file: string): string[] => v.filter(x => x.file === `src/${file}`).map(x => x.rule).sort();
    expect(rules('a.ts')).toEqual([]);
    const b = rules('b.ts');
    for (const r of ['exposes-no-code-reference', 'exposes-unpaired', 'exposes-severity-above-threat', 'accepts-written', 'entitles-written', 'confirmed-without-evidence', 'mitigates-no-control', 'description-vague']) {
      expect(b, r).toContain(r);
    }
    const dos = v.find(x => x.rule === 'exposes-severity-above-threat')!;
    expect(dos.message).toMatch(/critical.*medium/);
    expect(dos.line).toBe(4);
    for (const x of v) { expect(x.file).toBeTruthy(); expect(x.line).toBeGreaterThan(0); expect(x.message.length).toBeGreaterThan(10); }
  });

  it('accepts a code reference in any of the shapes real descriptions use', async () => {
    const src = `import z from 'z';
/**
 * @exposes #api to #sqli [high] -- "user.email reaches the query"
 * @exposes #api to #xss [high] -- "rendered via innerHTML"
 * @exposes #web to #sqli [high] -- "see handler.go:88"
 * @exposes #web to #xss [high] -- "the BIO_FIELD constant is echoed"
 * @exposes #web to #dos [medium] -- "parseBody() has no size cap"
 * @audit #api -- "review"
 * @audit #web -- "review"
 */
export function a() {}
`;
    const root = await project({ 'c.ts': src });
    const { model } = await parseProject({ root, project: 'c' });
    expect(lintAnnotations(model).filter(v => v.rule === 'exposes-no-code-reference')).toEqual([]);
  });
});

describe('runGate', () => {
  it('lints only what the run added, and the follow-up names each violation with its fix', async () => {
    const root = await project({ 'a.ts': GOOD });
    const { model: before } = await parseProject({ root, project: 'p' });
    await writeFile(join(root, 'src', 'b.ts'), BAD);
    const { model: after } = await parseProject({ root, project: 'p' });
    const report = runGate(before, after);
    expect(report.ok).toBe(false);
    expect(report.added.length).toBe(7);
    expect(report.violations.every(v => v.file === 'src/b.ts')).toBe(true);
    expect(report.violations.some(v => v.rule === 'accepts-written')).toBe(true);
    const followUp = buildGateFollowUp(report);
    expect(followUp).toContain('src/b.ts:4');
    expect(followUp).toMatch(/entry point/i);
    expect(followUp).toMatch(/@accepts/);
    expect(followUp).toMatch(/do not (re-)?write/i);
    const text = formatGateReport(report);
    expect(text).toMatch(/\d+ error/);
    // A run that changed nothing is fine.
    expect(runGate(after, after).ok).toBe(true);
    expect(runGate(after, after).added).toEqual([]);
    // No baseline: everything is "added".
    expect(runGate(null, after).added.length).toBe(relationRecords(after).length);
  });

  it('strips the lines of added claims that still carry an error, and nothing else', async () => {
    const root = await project({ 'a.ts': GOOD });
    const { model: before } = await parseProject({ root, project: 'p' });
    await writeFile(join(root, 'src', 'b.ts'), BAD);
    const { model: after } = await parseProject({ root, project: 'p' });
    const report = runGate(before, after);
    const { removed } = stripViolations(root, report);
    const lines = removed.map(r => r.line).sort((a, b) => a - b);
    expect(lines).toEqual([4, 5, 6, 7, 8]);                       // the five error lines
    const b = await readFile(join(root, 'src', 'b.ts'), 'utf8');
    expect(b).not.toContain('@accepts');
    expect(b).not.toContain('@entitles');
    expect(b).toContain('@mitigates #web against #dos');            // a warning stays
    expect(b).toContain('@comment -- "Security stuff"');
    expect(await readFile(join(root, 'src', 'a.ts'), 'utf8')).toBe(GOOD);
    const { model: again } = await parseProject({ root, project: 'p' });
    expect(runGate(before, again).ok).toBe(true);
  });
});

describe('guardlink lint', () => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
  const run = (cwd: string, ...args: string[]) => new Promise<{ code: number; stdout: string; stderr: string }>((res) =>
    execFile(process.execPath, [tsx, cli, ...args], { cwd, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => res({ code: (err as { code?: number } | null)?.code ?? 0, stdout, stderr })));

  it('exits 1 with the violations, 0 when clean, and --since narrows to claims added after a ref', async () => {
    const root = await project({ 'a.ts': GOOD });
    expect((await run(root, 'lint', '.')).code).toBe(0);
    const git = (...a: string[]) => execFileSync('git', a, { cwd: root, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } });
    git('init', '-q'); git('add', '-A'); git('commit', '-q', '-m', 'clean');
    await writeFile(join(root, 'src', 'b.ts'), BAD);
    const all = await run(root, 'lint', '.');
    expect(all.code).toBe(1);
    expect(all.stdout).toContain('src/b.ts:4');
    expect(all.stdout).toMatch(/exposes-no-code-reference/);
    const since = await run(root, 'lint', '.', '--since', 'HEAD', '--json');
    expect(since.code).toBe(1);
    const j = JSON.parse(since.stdout);
    expect(j.schema).toBe('guardlink.lint/v1');
    expect(j.scope).toMatchObject({ since: 'HEAD', claims: 7 });
    expect(j.violations.every((v: { file: string }) => v.file === 'src/b.ts')).toBe(true);
    expect(j.summary.errors).toBeGreaterThan(0);
  }, 90_000);
});
