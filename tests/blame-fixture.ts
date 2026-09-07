/**
 * Shared temp-repository fixture for the blame tests.
 *
 * Every git call is `execFileSync('git', argv)` — no shell — mirroring how the
 * code under test spawns git. Author/committer dates are pinned per commit so
 * time-to-fix assertions are exact, not `>= 0`.
 */
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

export interface Repo {
  root: string;
  git: (...args: string[]) => string;
  /** Write a root-relative file, creating parent directories. */
  write: (rel: string, content: string) => Promise<void>;
  /** `git add -A && git commit`; returns the new HEAD sha. */
  commit: (message: string, opts?: { date?: string; trailers?: string[]; author?: string }) => string;
}

export async function makeRepo(prefix = 'guardlink-blame'): Promise<Repo> {
  const root = await mkdtemp(join(tmpdir(), `${prefix}-`));
  const git = (...args: string[]): string =>
    execFileSync('git', args, { cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-q', '.');
  git('config', 'user.name', 'Test Human');
  git('config', 'user.email', 'human@example.com');
  git('config', 'commit.gpgsign', 'false');

  return {
    root,
    git,
    async write(rel, content) {
      await mkdir(dirname(join(root, rel)), { recursive: true });
      await writeFile(join(root, rel), content);
    },
    commit(message, opts = {}) {
      const body = [message, '', ...(opts.trailers ?? [])].join('\n');
      const env = { ...process.env };
      if (opts.date) {
        env.GIT_AUTHOR_DATE = opts.date;
        env.GIT_COMMITTER_DATE = opts.date;
      }
      const args = ['commit', '-q', '--allow-empty', '-m', body];
      if (opts.author) args.push('--author', opts.author);
      execFileSync('git', ['add', '-A'], { cwd: root, stdio: 'pipe' });
      execFileSync('git', args, { cwd: root, stdio: 'pipe', env });
      return git('rev-parse', 'HEAD');
    },
  };
}

/** A plain directory that is not a git checkout. */
export async function makePlainDir(prefix = 'guardlink-blame-plain'): Promise<string> {
  return mkdtemp(join(tmpdir(), `${prefix}-`));
}
