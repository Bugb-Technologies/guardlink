/**
 * The git adapter: pure parsers on captured output, then the real commands
 * against a temp repository. Nothing here touches the model.
 */
import { describe, it, expect } from 'vitest';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  ZERO_SHA, gitExec, isGitRepo, isShallow, headSha, trackedFiles, dirtyFiles,
  blameFile, parseBlamePorcelain, spanOldestCommit, fileAddCommit, resolveCommits, parseLogRecords, listCommits,
} from '../src/blame/git.js';
import { makeRepo, makePlainDir } from './blame-fixture.js';

const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);

describe('parseBlamePorcelain', () => {
  it('maps each final line number to its commit, including the zero sha for uncommitted lines', () => {
    const text = [
      `${SHA_A} 1 1 2`, 'author One', 'author-mail <one@x.y>', 'filename src/a.ts', '\tline one',
      `${SHA_A} 2 2`, 'author One', 'author-mail <one@x.y>', 'filename src/a.ts', '\tline two',
      `${ZERO_SHA} 3 3 1`, 'author Not Committed Yet', 'author-mail <not.committed.yet>', 'filename src/a.ts', '\tline three',
      `${SHA_B} 3 4 1`, 'author Two', 'author-mail <two@x.y>', 'filename src/a.ts', '\tline four',
    ].join('\n') + '\n';
    expect(parseBlamePorcelain(text)).toEqual([
      { line: 1, sha: SHA_A }, { line: 2, sha: SHA_A }, { line: 3, sha: ZERO_SHA }, { line: 4, sha: SHA_B },
    ]);
  });
});

describe('parseLogRecords', () => {
  it('splits unit- and record-separated output and keeps multi-line trailer blocks intact', () => {
    const rec = (sha: string, trailers: string) =>
      [sha, 'Ann Author', 'ann@x.y', '2026-08-10T14:29:38+05:30', 'Com Mitter', trailers].join('\x1f') + '\x1e\n';
    const text = rec(SHA_A, 'Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>\nClaude-Session: https://x') + rec(SHA_B, '');
    expect(parseLogRecords(text)).toEqual([
      { sha: SHA_A, authorName: 'Ann Author', authorEmail: 'ann@x.y', date: '2026-08-10T14:29:38+05:30', committerName: 'Com Mitter', trailers: 'Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>\nClaude-Session: https://x' },
      { sha: SHA_B, authorName: 'Ann Author', authorEmail: 'ann@x.y', date: '2026-08-10T14:29:38+05:30', committerName: 'Com Mitter', trailers: '' },
    ]);
  });
});

describe('against a real repository', () => {
  it('isGitRepo is false for a plain directory and gitExec throws on a failing command', async () => {
    const plain = await makePlainDir();
    expect(isGitRepo(plain)).toBe(false);
    expect(headSha(plain)).toBeNull();
    const repo = await makeRepo();
    expect(() => gitExec(repo.root, ['rev-parse', '--verify', 'no-such-ref'])).toThrow();
  });

  it('headSha and isShallow reflect the checkout', async () => {
    const repo = await makeRepo();
    await repo.write('a.txt', 'one\n');
    const sha = repo.commit('c1');
    expect(isGitRepo(repo.root)).toBe(true);
    expect(headSha(repo.root)).toBe(sha);
    expect(isShallow(repo.root)).toBe(false);
  });

  it('spanOldestCommit returns the commit that created the span, not the one that last edited it', async () => {
    const repo = await makeRepo();
    await repo.write('src/a.ts', 'export function f() {\n  return 1;\n}\n');
    const c1 = repo.commit('create f');
    await repo.write('src/a.ts', 'export function f() {\n  return 2;\n}\n');
    const c2 = repo.commit('edit f');
    expect(c2).not.toBe(c1);
    expect(spanOldestCommit(repo.root, 'src/a.ts', 1, 3)).toBe(c1);
  });

  it('fileAddCommit follows a rename back to the commit that added the file', async () => {
    const repo = await makeRepo();
    await repo.write('src/old.ts', 'export const x = 1;\nexport const y = 2;\nexport const z = 3;\n');
    const c1 = repo.commit('add old');
    repo.git('mv', 'src/old.ts', 'src/new.ts');
    repo.commit('rename');
    expect(fileAddCommit(repo.root, 'src/new.ts')).toBe(c1);
    expect(fileAddCommit(repo.root, 'src/missing.ts')).toBeNull();
  });

  it('trackedFiles and dirtyFiles answer for a batch of paths at once', async () => {
    const repo = await makeRepo();
    await repo.write('src/a.ts', 'a\n');
    await repo.write('src/b.ts', 'b\n');
    repo.commit('c1');
    await repo.write('src/b.ts', 'b changed\n');
    await repo.write('src/untracked.ts', 'new\n');
    const files = ['src/a.ts', 'src/b.ts', 'src/untracked.ts'];
    expect([...trackedFiles(repo.root, files)].sort()).toEqual(['src/a.ts', 'src/b.ts']);
    expect([...dirtyFiles(repo.root, files)].sort()).toEqual(['src/b.ts', 'src/untracked.ts']);
  });

  it('blameFile yields the zero sha for a line changed but not committed', async () => {
    const repo = await makeRepo();
    await repo.write('src/a.ts', 'one\ntwo\n');
    const c1 = repo.commit('c1');
    await writeFile(join(repo.root, 'src/a.ts'), 'one\ntwo changed\n');
    expect(blameFile(repo.root, 'src/a.ts', null)).toEqual([{ line: 1, sha: c1 }, { line: 2, sha: ZERO_SHA }]);
  });

  it('blameFile honours an ignore-revs file that exists and ignores one that does not', async () => {
    const repo = await makeRepo();
    await repo.write('src/a.ts', 'one\n');
    const c1 = repo.commit('c1');
    await repo.write('src/a.ts', 'one  \n');
    const c2 = repo.commit('reformat');
    expect(blameFile(repo.root, 'src/a.ts', null)).toEqual([{ line: 1, sha: c2 }]);
    await repo.write('.git-blame-ignore-revs', `${c2}\n`);
    expect(blameFile(repo.root, 'src/a.ts', '.git-blame-ignore-revs')).toEqual([{ line: 1, sha: c1 }]);
    expect(blameFile(repo.root, 'src/a.ts', 'does-not-exist')).toEqual([{ line: 1, sha: c2 }]);
  });

  it('resolveCommits reads author, date and trailers, in chunks of at most 500 shas', async () => {
    const repo = await makeRepo();
    await repo.write('a.txt', 'one\n');
    const c1 = repo.commit('c1', { date: '2026-01-02T03:04:05+00:00', trailers: ['Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>', 'Claude-Session: https://x'] });
    const map = resolveCommits(repo.root, [c1, ZERO_SHA]);
    expect(map.size).toBe(1);
    const rc = map.get(c1)!;
    // git prints a UTC author date as `…Z`; compare the instant, not the spelling.
    expect(Date.parse(rc.date)).toBe(Date.parse('2026-01-02T03:04:05+00:00'));
    expect(rc).toMatchObject({
      sha: c1, authorName: 'Test Human', authorEmail: 'human@example.com',
      committerName: 'Test Human', trailers: 'Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>\nClaude-Session: https://x',
    });

    const calls: string[][] = [];
    const fake = (_root: string, argv: string[]): string => { calls.push(argv); return ''; };
    // i + 1 so no fake sha is the all-zero sha, which resolveCommits rightly skips.
    const many = Array.from({ length: 1001 }, (_, i) => (i + 1).toString(16).padStart(40, '0'));
    resolveCommits(repo.root, many, fake);
    expect(calls).toHaveLength(3);
    expect(calls.map(c => c.filter(a => /^[0-9a-f]{40}$/.test(a)).length)).toEqual([500, 500, 1]);
  });

  it('listCommits walks the history reachable from HEAD once, newest first, with the same fields resolveCommits reads', async () => {
    const repo = await makeRepo();
    await repo.write('a.txt', 'one\n');
    const c1 = repo.commit('c1', { date: '2026-01-01T00:00:00+00:00' });
    await repo.write('a.txt', 'two\n');
    const c2 = repo.commit('c2', { date: '2026-01-02T00:00:00+00:00', trailers: ['Assisted-by: Codex:gpt-5.2'] });
    // A commit on another branch is not reachable from HEAD and must not be counted.
    repo.git('checkout', '-q', '-b', 'side');
    await repo.write('b.txt', 'side\n');
    repo.commit('side');
    repo.git('checkout', '-q', '-');
    await repo.write('a.txt', 'three\n');
    const c3 = repo.commit('c3', { date: '2026-01-03T00:00:00+00:00' });

    const history = listCommits(repo.root);
    expect(history.map(c => c.sha)).toEqual([c3, c2, c1]);
    expect(history[1]).toMatchObject({ authorName: 'Test Human', authorEmail: 'human@example.com', trailers: 'Assisted-by: Codex:gpt-5.2' });
    expect(Date.parse(history[0].date)).toBe(Date.parse('2026-01-03T00:00:00+00:00'));

    const calls: string[][] = [];
    listCommits(repo.root, (_root, argv) => { calls.push(argv); return ''; });
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe('log');
    expect(calls[0]).toContain('HEAD');

    // An empty repository has no HEAD to walk; that is an empty history, not an error.
    const empty = await makeRepo();
    expect(listCommits(empty.root)).toEqual([]);
    expect(listCommits(await makePlainDir())).toEqual([]);
  });
});
