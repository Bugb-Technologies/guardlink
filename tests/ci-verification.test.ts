// tests/ci-verification.test.ts
/**
 * The third `ci` check, driven through the real CLI like tests/ci.test.ts,
 * because the thing under test is an exit code and a stream. `verify` is a
 * write, so the fixture moves through its states in one ordered beforeAll.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

interface Run { status: number; stdout: string; stderr: string }
function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8' }, (err, stdout, stderr) => {
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
/** One exposure, mitigated: a repo that has finished, so only staleness can move the verdict. */
const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

async function scaffold(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-ci-verif-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"ci-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return root;
}

describe('guardlink ci — stale claims', () => {
  let root: string;
  const r: Record<string, Run> = {};
  let ledgerBefore = '';
  let ledgerAfter = '';

  beforeAll(async () => {
    root = await scaffold();
    r.noLedger = await guardlink(root, 'ci', '.');
    r.noLedgerStrict = await guardlink(root, 'ci', '.', '--strict');
    r.noLedgerJson = await guardlink(root, 'ci', '.', '--format', 'json');
    await guardlink(root, 'verify', '.', '--by', 'alice');
    r.clean = await guardlink(root, 'ci', '.');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
    ledgerBefore = await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8');
    r.stale = await guardlink(root, 'ci', '.');
    r.staleStrict = await guardlink(root, 'ci', '.', '--strict');
    r.staleJson = await guardlink(root, 'ci', '.', '--format', 'json');
    ledgerAfter = await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8');
    await writeFile(join(root, '.guardlink', 'verified.json'), '{broken');
    r.corrupt = await guardlink(root, 'ci', '.');
    r.corruptJson = await guardlink(root, 'ci', '.', '--format', 'json');
  }, 120_000);

  it('no ledger: advisory, exit 0 even with --strict, prints the bootstrap command', () => {
    expect(r.noLedger.status).toBe(0);
    expect(r.noLedger.stderr).toMatch(/none recorded/);
    expect(r.noLedger.stderr).toMatch(/guardlink verify --all/);
    expect(r.noLedgerStrict.status).toBe(0);
    const json = JSON.parse(r.noLedgerJson.stdout);
    expect(json.summary.ledger).toBe('absent');
    expect(json.stale).toEqual([]);
    expect(json.unverified.length).toBe(2);
    expect(json.summary.demote_stale).toBe(false);
  });

  it('every claim verified: the all-clear line mentions stale claims', () => {
    expect(r.clean.status).toBe(0);
    expect(r.clean.stderr).toMatch(/No stale claims/);
  });

  it('after an edit: stale claims listed, mitigation first, advisory exit 0, strict exit 1', () => {
    expect(r.stale.status).toBe(0);
    expect(r.stale.stderr).toMatch(/2 stale claim\(s\)/);
    // The doc-block is the literal first content of src/api.ts, so the
    // structure layer's first-node rule (spec §6.2 rule 2 — tested in
    // structure-anchor.test.ts) anchors both claims to the whole file, not
    // to the `login` symbol beneath them. Asserting `scope: 'symbol'` here
    // would pin a value the parser has never produced for this fixture.
    expect(r.stale.stderr).toMatch(/src\/api\.ts:3\s+@mitigates #api against #sqli using #prepared-stmts\s+\(whole file, verified \d{4}-\d{2}-\d{2} by human:alice\)/);
    expect(r.stale.stderr).toMatch(/Advisory/);
    expect(r.staleStrict.status).toBe(1);
    const json = JSON.parse(r.staleJson.stdout);
    expect(json.schema).toBe('guardlink.ci/v1');
    expect(json.stale[0].verb).toBe('mitigates');
    expect(json.stale[0]).toMatchObject({ file: 'src/api.ts', line: 3, scope: 'file', symbol: null, verified_by: 'human:alice' });
    expect(json.summary).toMatchObject({ stale: 2, unverified: 0, orphans: 0, demotable_stale: 1, ledger: 'present', stale_by_verb: { mitigates: 1, exposes: 1 } });
  });

  it('ci never writes the ledger', () => {
    expect(ledgerAfter).toBe(ledgerBefore);
  });

  it('corrupt ledger: reported once, treated as absent, still advisory', () => {
    expect(r.corrupt.status).toBe(0);
    expect(r.corrupt.stderr).toMatch(/verified\.json/);
    expect(r.corrupt.stderr).toMatch(/unreadable/);
    expect(JSON.parse(r.corruptJson.stdout).summary.ledger).toBe('corrupt');
  });
});
