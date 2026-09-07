/**
 * Dashboard repo links — turn a git remote into stable web links.
 *
 * Links point at `HEAD` of the default branch rather than a pinned SHA, so a
 * committed dashboard does not churn on every regeneration. Everything here is
 * pure and subprocess-free: `detectRepoLinks` reads `.git/config` directly.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { linksFromRemote, detectRepoLinks } from '../src/dashboard/links.js';

describe('linksFromRemote — GitHub remote forms', () => {
  const forms = [
    'git@github.com:org/repo.git',
    'https://github.com/org/repo.git',
    'https://github.com/org/repo',
    'ssh://git@github.com/org/repo.git',
  ];

  for (const url of forms) {
    it(`parses ${url}`, () => {
      const links = linksFromRemote(url);
      expect(links).not.toBeNull();
      expect(links!.host).toBe('github');
      expect(links!.web).toBe('https://github.com/org/repo');
      expect(links!.file('src/a.ts', 12)).toBe('https://github.com/org/repo/blob/HEAD/src/a.ts#L12');
      expect(links!.file('src/a.ts')).toBe('https://github.com/org/repo/blob/HEAD/src/a.ts');
      expect(links!.commit('abc123')).toBe('https://github.com/org/repo/commit/abc123');
    });
  }
});

describe('linksFromRemote — credentials, hosts and shapes', () => {
  it('strips embedded credentials and never carries them into a link', () => {
    const links = linksFromRemote('https://user:s3cret-token@github.com/org/repo.git');
    expect(links).not.toBeNull();
    expect(links!.web).toBe('https://github.com/org/repo');
    for (const link of [links!.web, links!.file('a.ts', 1), links!.commit('deadbeef')]) {
      expect(link).not.toContain('user');
      expect(link).not.toContain('s3cret');
      expect(link).not.toContain('@');
    }
  });

  it('classifies gitlab (self-hosted, subgroups) and uses gitlab shapes', () => {
    const links = linksFromRemote('git@gitlab.example.com:group/sub/repo.git');
    expect(links!.host).toBe('gitlab');
    expect(links!.web).toBe('https://gitlab.example.com/group/sub/repo');
    expect(links!.file('lib/x.rb', 7)).toBe('https://gitlab.example.com/group/sub/repo/-/blob/HEAD/lib/x.rb#L7');
    expect(links!.commit('cafe')).toBe('https://gitlab.example.com/group/sub/repo/-/commit/cafe');
  });

  it('classifies bitbucket and uses bitbucket shapes', () => {
    const links = linksFromRemote('https://bitbucket.org/team/repo.git');
    expect(links!.host).toBe('bitbucket');
    expect(links!.web).toBe('https://bitbucket.org/team/repo');
    expect(links!.file('src/m.go', 3)).toBe('https://bitbucket.org/team/repo/src/HEAD/src/m.go#lines-3');
    expect(links!.file('src/m.go')).toBe('https://bitbucket.org/team/repo/src/HEAD/src/m.go');
    expect(links!.commit('f00d')).toBe('https://bitbucket.org/team/repo/commits/f00d');
  });

  it('treats an unknown host as `other` with github-style shapes (best effort)', () => {
    const links = linksFromRemote('ssh://git@git.corp.example:2222/org/repo.git');
    expect(links!.host).toBe('other');
    expect(links!.web).toBe('https://git.corp.example/org/repo');
    expect(links!.file('a.ts', 1)).toBe('https://git.corp.example/org/repo/blob/HEAD/a.ts#L1');
    expect(links!.commit('abc')).toBe('https://git.corp.example/org/repo/commit/abc');
  });

  it('recognises github by hostname substring (GitHub Enterprise)', () => {
    expect(linksFromRemote('https://github.corp.example/org/repo')!.host).toBe('github');
  });

  it('returns null for local paths, file:// and garbage', () => {
    expect(linksFromRemote('/tmp/foo')).toBeNull();
    expect(linksFromRemote('file:///x')).toBeNull();
    expect(linksFromRemote('../bare.git')).toBeNull();
    expect(linksFromRemote('')).toBeNull();
    expect(linksFromRemote('https://github.com/')).toBeNull();
  });
});

describe('linksFromRemote — file path safety', () => {
  const links = () => linksFromRemote('https://github.com/org/repo')!;

  it('URL-encodes each path segment but keeps the separators', () => {
    expect(links().file('src/my file#1.ts', 4)).toBe(
      'https://github.com/org/repo/blob/HEAD/src/my%20file%231.ts#L4',
    );
  });

  it('rejects `..` segments — returns the repo web root, never a link outside the repo', () => {
    expect(links().file('../x')).toBe('https://github.com/org/repo');
    expect(links().file('src/../../x', 9)).toBe('https://github.com/org/repo');
  });

  it('rejects absolute paths — returns the repo web root', () => {
    expect(links().file('/etc/passwd')).toBe('https://github.com/org/repo');
    expect(links().file('/etc/passwd', 1)).toBe('https://github.com/org/repo');
  });

  it('normalises `./` and empty segments instead of rejecting them', () => {
    expect(links().file('./src//a.ts')).toBe('https://github.com/org/repo/blob/HEAD/src/a.ts');
  });

  it('returns the web root for an empty path', () => {
    expect(links().file('')).toBe('https://github.com/org/repo');
  });
});

describe('linksFromRemote — commit()', () => {
  it('encodes the sha so it cannot add path segments', () => {
    expect(linksFromRemote('https://github.com/org/repo')!.commit('a/b')).toBe(
      'https://github.com/org/repo/commit/a%2Fb',
    );
  });
});

describe('detectRepoLinks', () => {
  const dirs: string[] = [];
  const tmp = (): string => {
    const d = mkdtempSync(join(tmpdir(), 'guardlink-links-'));
    dirs.push(d);
    return d;
  };
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const gitConfig = (origin: string, extra = ''): string =>
    `[core]\n\trepositoryformatversion = 0\n\tbare = false\n${extra}[remote "origin"]\n\turl = ${origin}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n`;

  it('reads remote.origin.url from <root>/.git/config', () => {
    const root = tmp();
    mkdirSync(join(root, '.git'));
    writeFileSync(join(root, '.git', 'config'), gitConfig('git@github.com:org/repo.git'));
    const links = detectRepoLinks(root);
    expect(links).not.toBeNull();
    expect(links!.host).toBe('github');
    expect(links!.web).toBe('https://github.com/org/repo');
  });

  it('finds origin even when another remote is listed first', () => {
    const root = tmp();
    mkdirSync(join(root, '.git'));
    writeFileSync(
      join(root, '.git', 'config'),
      gitConfig('https://gitlab.com/g/s/repo.git', '[remote "upstream"]\n\turl = git@github.com:up/stream.git\n'),
    );
    expect(detectRepoLinks(root)!.web).toBe('https://gitlab.com/g/s/repo');
  });

  it('returns null when there is no .git', () => {
    expect(detectRepoLinks(tmp())).toBeNull();
  });

  it('follows a worktree-style `.git` file to <gitdir>/config', () => {
    const gitdir = join(tmp(), 'worktrees', 'wt1');
    mkdirSync(gitdir, { recursive: true });
    writeFileSync(join(gitdir, 'config'), gitConfig('https://bitbucket.org/team/repo.git'));
    const root = tmp();
    writeFileSync(join(root, '.git'), `gitdir: ${gitdir}\n`);
    const links = detectRepoLinks(root);
    expect(links!.host).toBe('bitbucket');
    expect(links!.web).toBe('https://bitbucket.org/team/repo');
  });

  it('resolves a relative gitdir pointer against the root', () => {
    const root = tmp();
    mkdirSync(join(root, 'real.git'));
    writeFileSync(join(root, 'real.git', 'config'), gitConfig('https://github.com/org/rel.git'));
    writeFileSync(join(root, '.git'), 'gitdir: real.git\n');
    expect(detectRepoLinks(root)!.web).toBe('https://github.com/org/rel');
  });

  it('returns null for a local-path or file:// origin', () => {
    for (const origin of ['/tmp/foo', 'file:///x', '../sibling.git']) {
      const root = tmp();
      mkdirSync(join(root, '.git'));
      writeFileSync(join(root, '.git', 'config'), gitConfig(origin));
      expect(detectRepoLinks(root)).toBeNull();
    }
  });

  it('returns null when the config has no origin, and never throws on junk', () => {
    const root = tmp();
    mkdirSync(join(root, '.git'));
    writeFileSync(join(root, '.git', 'config'), '[remote "upstream"]\n\turl = git@github.com:a/b.git\n');
    expect(detectRepoLinks(root)).toBeNull();

    const junk = tmp();
    writeFileSync(join(junk, '.git'), 'not a gitdir pointer');
    expect(detectRepoLinks(junk)).toBeNull();

    const dangling = tmp();
    writeFileSync(join(dangling, '.git'), 'gitdir: /nonexistent/definitely/not/here\n');
    expect(detectRepoLinks(dangling)).toBeNull();
  });
});
