/**
 * GuardLink — another checkout nested in the scanned tree is not this repository.
 *
 * Claude Code's desktop app keeps one git worktree per session under
 * `<repo>/.claude/worktrees/<name>/`, each a full checkout of the repository
 * with its own `.guardlink/definitions.ts`. Walked as source, that copy made
 * `guardlink validate .` report every definition id as a duplicate of itself
 * and `hypothesis next` list every exposure twice — once at `src/…`, once at
 * `.claude/worktrees/…/src/…` — and coverage, the worklist and the session
 * briefing all counted the copy. Measured on the guardlink checkout itself with
 * one worktree present: a duplicate-id error per definition, every exposure 2×.
 *
 * Two rules, kept here and nowhere else, shared by every walker — the parser's
 * scan, `clear`, the scan fingerprint, `init`'s scope detection, the annotation
 * worklist, agent-config discovery and the analyst's `search_codebase`:
 *
 *   1. `.claude/worktrees/` is skipped by name, wherever it sits.
 *   2. A directory holding a `.git` FILE is another checkout and is skipped.
 *      git writes that file for a linked worktree (under `.worktrees/`,
 *      `worktrees/` or anywhere else) and for a submodule. A repository root
 *      has a `.git` DIRECTORY, which is excluded on its own and marks nothing,
 *      so pointing GuardLink at a folder of repositories still reads them all.
 *      The root being scanned is never tested: the scan may itself be running
 *      inside a worktree.
 *
 * fast-glob cannot express rule 2. Its `ignore` patterns match a `.git` file
 * and a `.git` directory alike (`**\/.git/**` hides both), so the marker is
 * found by a directory walk of its own, bounded by the same excludes as the
 * scan, and handed to fast-glob as one `<dir>/**` ignore per checkout found.
 *
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "`findNestedCheckouts` walks every directory under the root that the scan's excludes do not prune, once per scan"
 * @mitigates #parser against #dos using #resource-limits -- "Directories only, each read once with withFileTypes and no stat per entry; symbolic links are not followed; the names the excludes prune (node_modules, .git, dist, …), the named checkout directories and every checkout found end the walk there"
 * @flows ProjectRoot -> #parser via findNestedCheckouts -- "Directory listing of the scanned tree, read for .git marker files"
 * @comment -- "Deliberately not a nested .git DIRECTORY: a folder of repositories is a thing people point GuardLink at on purpose. What git itself marks with a file — and lists as one opaque `dir/` entry in ls-files, never descending — is what is skipped"
 */

import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import fg from 'fast-glob';

/**
 * Directories that hold other checkouts wherever they sit, as fast-glob
 * ignore patterns — rule 1. Spread into the parser's and `clear`'s
 * DEFAULT_EXCLUDE, so a scan that never calls `scanIgnore` still honours it.
 */
export const NESTED_CHECKOUT_GLOBS: readonly string[] = ['**/.claude/worktrees/**'];

/** The directory each glob above names, matched as a whole path or a path suffix. */
const NAMED_DIRS: readonly string[] = ['.claude/worktrees'];

const posix = (p: string): string => p.replaceAll('\\', '/');

/** Whether root-relative directory `rel` is one of the named checkout directories. */
function namedCheckoutDir(rel: string): boolean {
  return NAMED_DIRS.some(d => rel === d || rel.endsWith(`/${d}`));
}

/** Whether root-relative `path` is a named checkout directory or lies under one. */
function underNamedDir(path: string): boolean {
  return NAMED_DIRS.some(d => path === d || path.startsWith(`${d}/`) || path.includes(`/${d}/`) || path.endsWith(`/${d}`));
}

/**
 * Whether `.git` inside `absDir` is a file — the marker git writes for a
 * linked worktree and for a submodule (rule 2). A repository root's `.git` is
 * a directory and marks nothing; a `.git` symbolic link is followed and judged
 * by what it reaches.
 */
export function hasCheckoutMarker(absDir: string): boolean {
  try { return statSync(join(absDir, '.git')).isFile(); } catch { return false; }
}

/**
 * Whether the directory at `absDir`, whose root-relative path is `relDir`, is
 * another checkout — for a walker already standing at it. Never ask about the
 * root itself.
 */
export function isNestedCheckout(absDir: string, relDir: string): boolean {
  return namedCheckoutDir(posix(relDir)) || hasCheckoutMarker(absDir);
}

export interface NestedCheckouts {
  /** Root-relative POSIX paths of the `.git`-file directories found, sorted. */
  dirs: string[];
  /** One fast-glob ignore pattern per directory in `dirs`. */
  ignore: string[];
  /** Whether root-relative `path` is a nested checkout or lies inside one — by marker or by name. */
  has(path: string): boolean;
}

/** Directory names an exclude glob of the form `**\/name/**` prunes at any depth. */
function prunedNames(exclude: readonly string[]): Set<string> {
  const names = new Set<string>();
  for (const glob of exclude) {
    const m = /^\*\*\/([^*?[\]{}()!/\\]+)\/\*\*$/.exec(glob);
    if (m) names.add(m[1]);
  }
  return names;
}

const byName = (a: { name: string }, b: { name: string }) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

/**
 * Every nested checkout under `root` that a scan with `exclude` would
 * otherwise enter.
 *
 * A directory walk, not a glob — see the module comment for why. Each
 * directory is read once; the only stat is for a `.git` entry the listing
 * shows, to tell a file from a directory. Symbolic links are not followed.
 * The walk does not enter a directory `exclude` prunes by name, a named
 * checkout directory (already ignored by glob, nothing to find inside), or a
 * checkout it has just found.
 */
export function findNestedCheckouts(root: string, exclude: readonly string[]): NestedCheckouts {
  const skip = prunedNames(exclude);
  const dirs: string[] = [];
  const walk = (absDir: string, relDir: string): void => {
    let entries;
    try { entries = readdirSync(absDir, { withFileTypes: true }); } catch { return; }
    if (relDir && entries.some(e => e.name === '.git') && hasCheckoutMarker(absDir)) {
      dirs.push(relDir);
      return;
    }
    for (const e of entries.sort(byName)) {
      if (!e.isDirectory() || skip.has(e.name)) continue;
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (namedCheckoutDir(rel)) continue;
      walk(join(absDir, e.name), rel);
    }
  };
  walk(root, '');
  dirs.sort();
  return {
    dirs,
    ignore: dirs.map(d => `${fg.escapePath(d)}/**`),
    has: (path: string) => {
      const p = posix(path);
      return underNamedDir(p) || dirs.some(d => p === d || p.startsWith(`${d}/`));
    },
  };
}

/**
 * The ignore list for a fast-glob walk of the scan set: `exclude`, plus one
 * pattern per nested checkout found under `root`. Every walk that reads the
 * scan set — the parser, `clear`, the fingerprint, `init`'s scope — goes
 * through here, so the rule has one home and no command carries its own copy.
 */
export function scanIgnore(root: string, exclude: readonly string[]): string[] {
  return [...exclude, ...findNestedCheckouts(root, exclude).ignore];
}
