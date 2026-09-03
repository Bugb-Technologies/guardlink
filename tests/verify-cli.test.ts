// tests/verify-cli.test.ts
/**
 * `guardlink verify` is a write command, so these cases run in order against
 * one fixture and read the ledger back from disk after each step. Spawns are
 * serial by necessity; the whole sequence runs once in beforeAll under a
 * generous timeout rather than once per `it`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
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
const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

async function scaffold(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-verify-cli-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"verify-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return root;
}

const ledgerOf = async (root: string) => JSON.parse(await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8'));

describe('guardlink verify', () => {
  let root: string;
  const runs: Record<string, Run> = {};
  // Snapshot right after `first` — `it` blocks run only once beforeAll fully
  // completes, and later steps (lineTarget, staleRest) re-lock these same two
  // claims under the default verifier, so a live re-read at test time would
  // reflect the end of the whole sequence, not this step.
  let firstLedger: { entries: { verified_by: string }[] };

  beforeAll(async () => {
    root = await scaffold();
    runs.dry = await guardlink(root, 'verify', '.', '--dry-run');
    runs.dryHadNoLedger = { status: existsSync(join(root, '.guardlink', 'verified.json')) ? 1 : 0, stdout: '', stderr: '' };
    runs.first = await guardlink(root, 'verify', '.', '--by', 'alice', '--format', 'json');
    firstLedger = await ledgerOf(root);
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
    runs.afterEdit = await guardlink(root, 'verify', '.');
    runs.lineTarget = await guardlink(root, 'verify', 'src/api.ts:3');
    runs.staleRest = await guardlink(root, 'verify', '.', '--stale');
    await writeFile(join(root, '.guardlink', 'verified.json'), '{broken');
    runs.corrupt = await guardlink(root, 'verify', '.');
    runs.forced = await guardlink(root, 'verify', '.', '--all', '--force');
  }, 90_000);

  it('--dry-run prints the plan and writes nothing', () => {
    expect(runs.dry.status).toBe(0);
    expect(runs.dry.stderr + runs.dry.stdout).toMatch(/would lock 2/i);
    expect(runs.dryHadNoLedger.status).toBe(0);
  });

  it('first run locks every claim under the named verifier, JSON carries the schema', () => {
    expect(runs.first.status).toBe(0);
    const out = JSON.parse(runs.first.stdout);
    expect(out.schema).toBe('guardlink.verify/v1');
    expect(out.locked.length).toBe(2);
    expect(out.verified_by).toBe('human:alice');
    expect(firstLedger.entries.every((e: { verified_by: string }) => e.verified_by === 'human:alice')).toBe(true);
  });

  it('after an edit, the default run reports stale claims and leaves them', () => {
    expect(runs.afterEdit.status).toBe(0);
    expect(runs.afterEdit.stderr).toMatch(/2 stale claim\(s\) left as they are/);
  });

  it('a file:line target as the first argument re-locks that claim only', () => {
    expect(runs.lineTarget.status).toBe(0);
    expect(runs.lineTarget.stderr).toMatch(/re-locked 1/i);
  });

  it('--stale re-locks what remains', () => {
    expect(runs.staleRest.status).toBe(0);
    expect(runs.staleRest.stderr).toMatch(/re-locked 1/i);
  });

  it('a corrupt ledger is refused without --force and rebuilt with it', async () => {
    expect(runs.corrupt.status).toBe(1);
    expect(runs.corrupt.stderr).toMatch(/ledger-corrupt|not valid JSON/);
    expect(runs.forced.status).toBe(0);
    const ledger = await ledgerOf(root);
    expect(ledger.schema).toBe('guardlink.verified/v1');
    expect(ledger.entries.length).toBe(2);
  });
});

describe('guardlink verify — an unmatched target must not write', () => {
  it('exits 1 and writes nothing when the target names no claim', async () => {
    const root = await scaffold();
    const run = await guardlink(root, 'verify', 'src/nope.ts');
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/no claim at src\/nope\.ts/);
    expect(existsSync(join(root, '.guardlink', 'verified.json'))).toBe(false);
  });
});

describe('guardlink verify — a directory that is not a project root', () => {
  it('refuses src/ rather than parsing it as a project and leaving a ledger there', async () => {
    // The first positional is taken as the root when it is a directory, so
    // `verify src` reads as "verify the claims under src" and would otherwise
    // parse src as its own project and write src/.guardlink/verified.json.
    const root = await scaffold();
    const run = await guardlink(root, 'verify', 'src');
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/not a GuardLink project root/);
    expect(existsSync(join(root, 'src', '.guardlink'))).toBe(false);
    expect(existsSync(join(root, '.guardlink', 'verified.json'))).toBe(false);
  }, 30_000);
});

describe('guardlink verify — a corrupt ledger cannot be partially rebuilt', () => {
  it('--stale --force on a corrupt ledger is refused, not silently rebuilt empty', async () => {
    const root = await scaffold();
    await writeFile(join(root, '.guardlink', 'verified.json'), '{broken');
    const run = await guardlink(root, 'verify', '.', '--stale', '--force');
    expect(run.status).toBe(1);
    const content = await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8');
    expect(content).toBe('{broken');
  });
});
