import { afterEach, beforeEach, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const tsx = createRequire(import.meta.url).resolve('tsx/cli');
const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');
let root: string;
const run = (...args: string[]) => {
  try {
    return { code: 0, stdout: execFileSync(process.execPath, [tsx, cli, ...args], { cwd: root, encoding: 'utf8', stdio: 'pipe' }), stderr: '' };
  } catch (error) {
    const result = error as { status: number; stdout: string; stderr: string };
    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
  }
};
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'gl-lint-entitlement-'));
  mkdirSync(join(root, '.guardlink')); mkdirSync(join(root, 'src'));
  writeFileSync(join(root, '.guardlink/definitions.ts'), '// @asset Demo.Model (#model)\n// @asset Demo.Other (#other)\n// @actor Connected_Reader (#reader)\n');
  writeFileSync(join(root, 'src/server.ts'), '/**\n * @agents #reader to read-model on #model -- "Read the semantic model"\n */\nexport const readModel = () => ({});\n');
  const git = (...args: string[]) => execFileSync('git', ['-C', root, ...args], { stdio: 'pipe' });
  git('init', '-b', 'main'); git('add', '.'); git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture');
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

it('lint since a base accepts the human decision but rejects unapproved and merely proposed grants', () => {
  const propose = (asset: string, capability = 'read-model') => run('entitle', '.', '--propose', '--actor', '#reader', '--capability', capability, '--asset', asset,
    '--rationale', 'By design: the connected reader may inspect this model. Authz: src/server.ts:4', '--file', 'src/server.ts', '--line', '2');
  expect(propose('#model').code).toBe(0);
  expect(run('entitle', '.', '--accept', 'ent-reader.read_model', '--by', 'Fixture Maintainer', '--note', 'Synthetic fixture approval of read access').code).toBe(0);
  const accepted = run('lint', '.', '--since', 'HEAD', '--json');
  expect(accepted.code).toBe(0);
  expect(JSON.parse(accepted.stdout).violations.some((v: { rule: string }) => v.rule === 'entitles-written')).toBe(false);

  expect(propose('#model', 'write-model').code).toBe(0);
  appendFileSync(join(root, 'src/server.ts'), '\n// @entitles #reader to read-model on #other -- "Authz: src/server.ts:4"\n// @entitles #reader to write-model on #model -- "Authz: src/server.ts:4"\n');
  const unapproved = run('lint', '.', '--since', 'HEAD', '--json');
  expect(unapproved.code).toBe(1);
  const grants = JSON.parse(unapproved.stdout).violations.filter((v: { rule: string }) => v.rule === 'entitles-written');
  expect(grants).toHaveLength(2);
  expect(grants.some((v: { claim: string }) => v.claim.includes('read-model on #other'))).toBe(true);
  expect(grants.some((v: { claim: string }) => v.claim.includes('write-model on #model'))).toBe(true);

  rmSync(join(root, '.guardlink/entitlement-proposals.json'));
  const missing = run('lint', '.', '--since', 'HEAD', '--json');
  expect(missing.code).toBe(1);
  expect(JSON.parse(missing.stdout).violations.filter((v: { rule: string }) => v.rule === 'entitles-written')).toHaveLength(3);

  writeFileSync(join(root, '.guardlink/entitlement-proposals.json'), '{broken');
  const unreadable = run('lint', '.', '--since', 'HEAD', '--json');
  expect(unreadable.code).toBe(1);
  expect(unreadable.stderr).toContain('entitlement');
  // Seven CLI processes through tsx: well over vitest's 5 s default on a shared CI runner.
}, 60_000);
