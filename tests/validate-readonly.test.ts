/**
 * D16 — `validate` and `status` must not write.
 *
 * Both ran `syncAgentFiles` as a side effect, rewriting seven tracked files:
 * CLAUDE.md, AGENTS.md, .clinerules, .cursor/rules/guardlink.mdc,
 * .gemini/GEMINI.md, .github/copilot-instructions.md and .windsurfrules. A
 * command that reads as a check cannot be a CI gate if it dirties the tree it
 * was asked to inspect.
 *
 * These tests drive the real CLI in a real git repo and assert on
 * `git status --porcelain`, because the defect was mtimes and bytes on disk —
 * an in-process assertion that "sync was not called" would not have caught the
 * F1-era version of this, where the writes produced no diff but still happened.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, mkdir, writeFile, readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');

let root: string;

/** Run the CLI under tsx. Exit code is irrelevant here — the tree state is not. */
function guardlink(...args: string[]): string {
  try {
    return execFileSync('npx', ['tsx', cli, ...args], {
      cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return `${e.stdout ?? ''}${e.stderr ?? ''}`;
  }
}

const gitStatus = () =>
  execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf-8' }).trim();

const git = (...args: string[]) =>
  execFileSync('git', args, { cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-d16-'));
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"d16","version":"1.0.0"}\n');
  await writeFile(join(root, 'src', 'auth.ts'),
    '/**\n' +
    ' * @exposes App.API to #sqli [high] -- "raw SQL"\n' +
    ' * @audit App.API -- "needs review"\n' +
    ' */\n' +
    'export function login(e: string) { return e.length > 0; }\n');

  guardlink('init', '.', '--agent', 'claude,cursor,cline,windsurf,copilot,codex');

  git('init', '-q', '.');
  git('config', 'user.email', 'test@example.com');
  git('config', 'user.name', 'test');
  git('add', '-A');
  git('commit', '-q', '-m', 'baseline');
  // Sync once so the agent files hold real model context — the state a repo is
  // actually in when someone runs validate.
  guardlink('sync', '.');
  git('add', '-A');
  git('commit', '-q', '--allow-empty', '-m', 'synced');
}, 120_000);

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('D16 — read commands leave the tree alone', () => {
  it('starts from a clean tree', () => {
    expect(gitStatus()).toBe('');
  });

  it('validate leaves a clean tree clean', () => {
    guardlink('validate', '.');
    expect(gitStatus()).toBe('');
  }, 60_000);

  it('status leaves a clean tree clean', () => {
    guardlink('status', '.');
    expect(gitStatus()).toBe('');
  }, 60_000);

  it('validate leaves the tree clean even when the model has changed', async () => {
    // The F1 fix (annotation_hash alone in the block) means an unchanged model
    // produces no diff whether or not the files are written. A CHANGED model is
    // the case that distinguishes "did not write" from "wrote the same bytes".
    await writeFile(join(root, 'src', 'extra.ts'),
      '/**\n' +
      ' * @exposes App.API to #xss [medium] -- "unescaped render"\n' +
      ' * @audit App.API -- "needs review"\n' +
      ' */\n' +
      'export const render = (s: string) => s;\n');
    git('add', '-A');
    git('commit', '-q', '-m', 'new annotated file');

    const before = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    guardlink('validate', '.');

    expect(gitStatus()).toBe('');
    expect(await readFile(join(root, 'CLAUDE.md'), 'utf-8')).toBe(before);
  }, 60_000);

  it('validate --sync is how you opt back in', async () => {
    const before = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    guardlink('validate', '.', '--sync');

    expect(await readFile(join(root, 'CLAUDE.md'), 'utf-8')).not.toBe(before);
    expect(gitStatus()).not.toBe('');

    git('checkout', '--', '.');
    expect(gitStatus()).toBe('');
  }, 60_000);

  it('sync still writes — the behaviour moved, it did not vanish', async () => {
    guardlink('sync', '.');
    expect(gitStatus()).not.toBe('');
    git('checkout', '--', '.');
  }, 60_000);
});
