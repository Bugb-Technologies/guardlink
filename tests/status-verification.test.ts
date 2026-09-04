// tests/status-verification.test.ts
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
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

describe('status and validate know about the ledger', () => {
  let root: string;
  const r: Record<string, Run> = {};

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-status-verif-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"status-fixture","version":"1.0.0"}\n');
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    r.statusNone = await guardlink(root, 'status', '.');
    await guardlink(root, 'verify', '.');
    r.statusAll = await guardlink(root, 'status', '.');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
    r.statusStale = await guardlink(root, 'status', '.');
    r.validateOk = await guardlink(root, 'validate', '.');
    await writeFile(join(root, '.guardlink', 'verified.json'), '{broken');
    r.validateCorrupt = await guardlink(root, 'validate', '.');
  }, 90_000);

  it('status: none recorded, then counts, then stale', () => {
    expect(r.statusNone.stdout).toMatch(/Verified claims:\s+none recorded/);
    expect(r.statusAll.stdout).toMatch(/Verified claims:\s+2 \/ 2 \(stale 0, unverified 0\)/);
    expect(r.statusStale.stdout).toMatch(/Verified claims:\s+0 \/ 2 \(stale 2, unverified 0\)/);
  });

  it('validate: a corrupt ledger is an error that fails the command', () => {
    expect(r.validateOk.status).toBe(0);
    expect(r.validateCorrupt.status).toBe(1);
    expect(r.validateCorrupt.stderr + r.validateCorrupt.stdout).toMatch(/verified\.json/);
  });
});
