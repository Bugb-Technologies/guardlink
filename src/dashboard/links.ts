/**
 * GuardLink Dashboard — repository web links.
 *
 * Turns a git remote into links a dashboard can embed: the repo's web root, a
 * file (and line) at `HEAD` of the default branch, and a commit. `HEAD` rather
 * than a pinned SHA keeps a committed dashboard from churning on every
 * regeneration. Detection reads `.git/config` directly — no `git` subprocess,
 * no network — mirroring `readGitSha` in `src/workspace/metadata.ts`.
 *
 * @exposes #dashboard to #path-traversal [low] cwe:CWE-22 -- "detectRepoLinks reads <root>/.git/config and, when .git is a worktree file, follows its `gitdir:` pointer to a config elsewhere on disk; a crafted .git file can name any readable path"
 * @mitigates #dashboard against #path-traversal using #path-validation -- "Only the fixed `config` name is read under the pointed-to gitdir, only `remote.origin.url` is extracted from it, and the result is discarded unless it parses as an http(s)/ssh remote to a web host; file links reject `..` segments and absolute paths and fall back to the repo web root"
 * @exposes #dashboard to #data-exposure [low] cwe:CWE-200 -- "Remote URLs may embed credentials (https://user:token@host/...) which would otherwise land in a committed HTML artifact"
 * @mitigates #dashboard against #data-exposure using #output-encoding -- "linksFromRemote rebuilds every link from hostname and path only; userinfo is dropped before anything is emitted, so credentials never reach RepoLinks.web"
 * @flows GitConfig -> #dashboard via readFileSync -- "remote.origin.url read from .git/config (or the worktree's gitdir config)"
 * @flows #dashboard -> DashboardHTML via RepoLinks -- "Web, file and commit links embedded in the generated dashboard"
 * @comment -- "Pure and deterministic: URL parsing is string work, detection is two file reads at most. Hosts are classified by hostname substring (github/gitlab/bitbucket); anything else is `other` and gets GitHub-shaped links as a best effort."
 */

import { readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

export type RepoHost = 'github' | 'gitlab' | 'bitbucket' | 'other';

export interface RepoLinks {
  host: RepoHost;
  /** e.g. https://github.com/org/repo (no trailing slash, no .git) */
  web: string;
  /** Link to a file (and line) at HEAD of the default branch — stable across commits, so a committed dashboard does not churn. */
  file(path: string, line?: number): string;
  /** Link to a commit. */
  commit(sha: string): string;
}

/**
 * Parse a git remote URL into RepoLinks; null when it is not http(s)/ssh to a
 * recognisable host.
 *
 * @comment -- "Accepts scp-style (git@host:org/repo.git), ssh://, http:// and https:// remotes. Strips `.git` and trailing slashes from the path."
 */
export function linksFromRemote(url: string): RepoLinks | null {
  const parsed = parseRemote(url.trim());
  if (!parsed) return null;

  const host = classifyHost(parsed.host);
  const web = `https://${parsed.host}/${parsed.path}`;
  const shape = SHAPES[host];
  return {
    host,
    web,
    file: (path, line) => {
      const safe = safeFilePath(path);
      if (safe === null) return web;
      return `${web}/${shape.blob}/${safe}${line === undefined ? '' : `#${shape.line}${line}`}`;
    },
    commit: (sha) => `${web}/${shape.commit}/${encodeURIComponent(sha)}`,
  };
}

/**
 * Per-host URL fragments. `other` borrows GitHub's shapes as a best effort —
 * most self-hosted forges (Gitea, Gogs, Forgejo) copied them.
 */
const SHAPES: Record<RepoHost, { blob: string; line: string; commit: string }> = {
  github: { blob: 'blob/HEAD', line: 'L', commit: 'commit' },
  gitlab: { blob: '-/blob/HEAD', line: 'L', commit: '-/commit' },
  bitbucket: { blob: 'src/HEAD', line: 'lines-', commit: 'commits' },
  other: { blob: 'blob/HEAD', line: 'L', commit: 'commit' },
};

/** Hostname substring wins so enterprise / self-hosted instances classify too. */
function classifyHost(hostname: string): RepoHost {
  if (hostname.includes('github')) return 'github';
  if (hostname.includes('gitlab')) return 'gitlab';
  if (hostname.includes('bitbucket')) return 'bitbucket';
  return 'other';
}

/**
 * Encode a repo-relative path one segment at a time. Null when the path could
 * escape the repo — absolute, or containing a `..` segment — or when nothing is
 * left after dropping `.` and empty segments. Callers fall back to the web root
 * on null: a link must never point outside the repository.
 *
 * @mitigates #dashboard against #path-traversal using #path-validation -- "Absolute paths and any `..` segment (either separator) are refused; each surviving segment is encodeURIComponent-ed so `#`, `?` and spaces cannot rewrite the URL"
 */
function safeFilePath(path: string): string | null {
  if (path.startsWith('/') || path.startsWith('\\')) return null;
  const segments = path.split(/[\/\\]/).filter((s) => s !== '' && s !== '.');
  if (segments.length === 0 || segments.includes('..')) return null;
  return segments.map(encodeURIComponent).join('/');
}

/**
 * Split a remote into hostname and `org/repo` path. Null for anything that is
 * not an http(s)/ssh URL with a host and a non-empty path.
 */
function parseRemote(url: string): { host: string; path: string } | null {
  const scp = /^[^@\s/:]+@([^:/\s]+):(.+)$/.exec(url);
  const scheme = /^(?:https?|ssh):\/\/(?:[^@/\s]+@)?([^/:\s]+)(?::\d+)?\/(.+)$/.exec(url);
  const match = scheme ?? scp;
  if (!match) return null;

  const host = match[1].toLowerCase();
  const path = match[2].replace(/\/+$/, '').replace(/\.git$/, '').replace(/^\/+/, '');
  if (!path) return null;
  return { host, path };
}

/**
 * Read `remote.origin.url` from `<root>/.git/config` (no subprocess). Null when
 * absent, unreadable, or not a URL we can turn into web links.
 *
 * When `.git` is a file (worktree or submodule checkout) it holds a single
 * `gitdir: <path>` line; the config lives under that directory instead. The
 * pointer is followed as-is — relative paths resolve against `root` — because
 * git itself wrote it, and only the fixed `config` filename is read from it.
 *
 * @comment -- "Best effort and side-effect free: every failure mode (no .git, junk pointer, dangling gitdir, config without origin, local-path origin) collapses to null rather than throwing, so dashboard generation never depends on this succeeding"
 */
export function detectRepoLinks(root: string): RepoLinks | null {
  const origin = readOriginUrl(root);
  return origin === null ? null : linksFromRemote(origin);
}

/** Locate the git config for `root` and pull `url` out of `[remote "origin"]`. */
function readOriginUrl(root: string): string | null {
  try {
    const dotGit = join(root, '.git');
    let config: string;
    try {
      config = readFileSync(join(dotGit, 'config'), 'utf-8');
    } catch {
      // `.git` is not a directory with a config — try it as a gitdir pointer.
      const pointer = /^gitdir:\s*(.+?)\s*$/m.exec(readFileSync(dotGit, 'utf-8'));
      if (!pointer) return null;
      const gitdir = isAbsolute(pointer[1]) ? pointer[1] : join(root, pointer[1]);
      config = readFileSync(join(gitdir, 'config'), 'utf-8');
    }
    return parseOriginUrl(config);
  } catch {
    return null;
  }
}

/**
 * Minimal git-config reader: `[section "sub"]` headers, `key = value` lines,
 * tabs or spaces, `#`/`;` comments. Returns the first `url` under
 * `[remote "origin"]`, or null.
 */
function parseOriginUrl(config: string): string | null {
  let inOrigin = false;
  for (const raw of config.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue;

    const section = /^\[\s*([^\s\]"]+)(?:\s+"([^"]*)")?\s*\]$/.exec(line);
    if (section) {
      inOrigin = section[1].toLowerCase() === 'remote' && section[2] === 'origin';
      continue;
    }
    if (!inOrigin) continue;

    const kv = /^url\s*=\s*(.+)$/i.exec(line);
    if (kv) return kv[1].trim();
  }
  return null;
}
