/**
 * `guardlink blame` and the `--blame` flags, driven through the real CLI.
 *
 * Spawns are slow under tsx, so each fixture is built once and the commands
 * that share it run in one ordered sequence.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeRepo, makePlainDir } from './blame-fixture.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

interface Run { status: number; stdout: string; stderr: string }
function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;
const V1 = `import x from 'x';

/**
 * @exposes #api to #sqli [high] cwe:CWE-89 -- "raw"
 */
export function login(email: string) {
  return 'SELECT ' + email;
}
`;
const V2 = V1.replace(' */\nexport function login', ' * @mitigates #api against #sqli using #prepared-stmts -- "bound"\n */\nexport function login');

describe('help text', () => {
  it('lists the blame command and the --blame flag on parse, status, report and dashboard', async () => {
    const top = await guardlink(repoRoot, '--help');
    expect(top.stdout).toContain('blame');
    const own = await guardlink(repoRoot, 'blame', '--help');
    for (const flag of ['--file', '--json', '--identity']) expect(own.stdout).toContain(flag);
    for (const cmd of ['parse', 'status', 'report', 'dashboard']) {
      const help = await guardlink(repoRoot, cmd, '--help');
      expect(help.stdout, `${cmd} --help`).toContain('--blame');
    }
  }, 120_000);
});

describe('against a repository', () => {
  let root: string;
  let c1: string;
  let c2: string;

  beforeAll(async () => {
    const repo = await makeRepo('guardlink-blame-cli');
    root = repo.root;
    await repo.write('.guardlink/definitions.ts', DEFINITIONS);
    await repo.write('.guardlink/config.json', '{"project":"cli-fixture","annotation_mode":"inline"}\n');
    await repo.write('src/a.ts', V1);
    c1 = repo.commit('create', { date: '2026-03-01T10:00:00+00:00' });
    await repo.write('src/a.ts', V2);
    c2 = repo.commit('mitigate', { date: '2026-03-04T10:00:00+00:00', trailers: ['Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>'] });
  }, 60_000);

  it('blame --json emits the versioned payload whose keys join to the verification ledger', async () => {
    const verify = await guardlink(root, 'verify', '.', '--all');
    expect(verify.status).toBe(0);
    const run = await guardlink(root, 'blame', '.', '--json');
    expect(run.status).toBe(0);
    const payload = JSON.parse(run.stdout);
    expect(payload.schema).toBe('guardlink.blame/v1');
    expect(payload.status).toBe('ok');
    expect(payload.head).toBe(c2);
    const exposure = payload.entries.find((e: { verb: string }) => e.verb === 'exposes');
    expect(exposure.blame.introduced_by.sha).toBe(c1);
    expect(exposure.blame.fixed_by.sha).toBe(c2);
    expect(exposure.blame.fixed_by.assisted_by[0]).toMatchObject({ tool: 'claude-code', model: 'Claude Opus 5 (1M context)' });
    expect(exposure.blame.time_to_fix_days).toBe(3);

    const ledger = JSON.parse(await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8'));
    const ledgerKeys = new Set(ledger.entries.map((e: { key: string }) => e.key));
    for (const e of payload.entries) expect(ledgerKeys.has(e.key), e.key).toBe(true);
  }, 120_000);

  it('blame prints text grouped by file, and --identity hash hides emails and names', async () => {
    const text = await guardlink(root, 'blame', '.');
    expect(text.status).toBe(0);
    expect(text.stdout).toContain('src/a.ts');
    expect(text.stdout).toContain('By person');
    expect(text.stdout).toContain('human:Test Human');

    const hashed = await guardlink(root, 'blame', '.', '--json', '--identity', 'hash');
    const payload = JSON.parse(hashed.stdout);
    expect(payload.identity_mode).toBe('hash');
    expect(payload.summary.by_human[0].identity).toMatch(/^human:[0-9a-f]{12}$/);

    const bad = await guardlink(root, 'blame', '.', '--identity', 'phone');
    expect(bad.status).toBe(1);
  }, 120_000);

  it('--file narrows to one file', async () => {
    const run = await guardlink(root, 'blame', '.', '--json', '--file', 'src/nope.ts');
    expect(JSON.parse(run.stdout).entries).toEqual([]);
    const hit = await guardlink(root, 'blame', '.', '--json', '--file', './src/a.ts');
    expect(JSON.parse(hit.stdout).entries.length).toBeGreaterThan(0);
  }, 120_000);

  it('parse is byte-identical without --blame and carries blame with it', async () => {
    const plain = await guardlink(root, 'parse', '.');
    expect(plain.stdout).not.toContain('"blame"');
    const withBlame = await guardlink(root, 'parse', '.', '--blame');
    const model = JSON.parse(withBlame.stdout);
    expect(model.exposures[0].blame.kind).toBe('exposure');
    expect(model.mitigations[0].blame.kind).toBe('mitigation');
    // everything except the blame field is unchanged (generated_at is the wall clock of each run)
    const strip = (m: Record<string, unknown>) => JSON.parse(JSON.stringify(m, (k, v) => (k === 'blame' || k === 'generated_at' ? undefined : v)));
    expect(strip(model)).toEqual(strip(JSON.parse(plain.stdout)));
  }, 120_000);

  it('status --blame appends the attribution summary', async () => {
    const run = await guardlink(root, 'status', '.', '--blame');
    expect(run.status).toBe(0);
    expect(run.stdout).toContain('By person');
    expect(run.stdout).toContain('human:Test Human');
  }, 120_000);
});

describe('outside a git checkout', () => {
  it('blame exits 0 and says so', async () => {
    const root = await makePlainDir();
    const { mkdir, writeFile } = await import('node:fs/promises');
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'a.ts'), V2);
    const run = await guardlink(root, 'blame', '.');
    expect(run.status).toBe(0);
    expect(run.stdout).toContain('not a git');
    const json = await guardlink(root, 'blame', '.', '--json');
    expect(JSON.parse(json.stdout).status).toBe('no-git');
  }, 120_000);
});
