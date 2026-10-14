/**
 * GuardLink agent config — the files a skill carries beside its `SKILL.md`.
 *
 * A skill is a directory: `SKILL.md` tells the agent when to use it, and the
 * scripts, code and templates beside it are what it runs. Listing them (path,
 * kind, length, content digest) lets a reviewer see a new script arrive and
 * lets `diff` say so, without this module reading what the script does.
 *
 * The directory walked is the skill's own real directory, and nothing outside
 * it is listed:
 *
 *   - A symbolic link inside it, to a file or a directory, is not followed and
 *     not listed. It is reported as unreadable, because what it reaches is not
 *     known to be part of the skill (and a link that leaves the repository
 *     must never be read at all).
 *   - A subdirectory with a `SKILL.md` of its own is another skill, listed under
 *     that skill.
 *   - Dependency and build directories are skipped, as `discover` skips them.
 *   - Files git does not carry (ignored build output, caches) are left out, so
 *     the list is the same on a developer's machine and in CI.
 *
 * @exposes #agent-config to #path-traversal [medium] cwe:CWE-59 -- "collectBundle walks repository-controlled entries with readdirSync and hashes files with readFileSync; symbolic links could redirect that read outside the skill or repository"
 * @mitigates #agent-config against #path-traversal using #path-validation -- "Links are never followed: a link entry is reported unreadable, the skill directory must stay inside the repository root, and every listed file's real path must equal its path under that directory"
 * @exposes #agent-config to #dos [low] cwe:CWE-400 -- "collectBundle processes repository-controlled directory entries through readdirSync and file bytes through readFileSync; unbounded inventory or reads could exhaust memory"
 * @mitigates #agent-config against #dos using #resource-limits -- "At most MAX_BUNDLED files are listed per skill, and a file above MAX_BUNDLED_READ is listed by length without being read"
 * @flows ProjectFiles -> #agent-config via readdirSync -- "Directory listing of a skill's own directory"
 * @comment -- "Never executes, imports or interprets a bundled file: kind comes from the file name, the digest from its bytes"
 */
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { join, relative, sep, dirname, basename } from 'node:path';
import type { AgentConfigBundledFile } from '../types/index.js';
import { SKIP_DIRS, type DiscoveredFile } from './discover.js';

/** A skill with more files than this lists the first ones (in directory-walk order, entries sorted by name) and says the rest were not listed. */
export const MAX_BUNDLED = 500;
/** A bundled file above this is listed by length and not read. */
export const MAX_BUNDLED_READ = 2 * 1024 * 1024;

const SCRIPT_EXT = new Set(['.sh', '.bash', '.zsh', '.fish', '.ksh', '.csh', '.ps1', '.psm1', '.bat', '.cmd']);
const CODE_EXT = new Set([
  '.py', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx', '.rb', '.pl', '.pm', '.php', '.lua', '.go', '.rs',
  '.java', '.kt', '.swift', '.cs', '.c', '.h', '.cc', '.cpp', '.hpp', '.r', '.jl', '.ex', '.exs', '.vbs', '.wasm',
]);

/** The kind of a bundled file, by its name alone. */
export function bundledKind(name: string): AgentConfigBundledFile['kind'] {
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.slice(dot).toLowerCase() : '';
  if (SCRIPT_EXT.has(ext)) return 'script';
  if (CODE_EXT.has(ext)) return 'code';
  return 'asset';
}

export interface BundleResult {
  bundled: AgentConfigBundledFile[];
  unreadable: { file: string; line: number; message: string }[];
}

const byPath = (a: { path: string }, b: { path: string }) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

/**
 * The files in `skill`'s own directory, or null when it has none to look in: a
 * `SKILL.md` at the repository root belongs to a directory that is the
 * repository, not to the skill.
 *
 * `carried` is the set of paths git carries (null: every file counts), checked
 * against both the path as the skill is named and its real path.
 */
export function collectBundle(skill: DiscoveredFile, realRoot: string, carried: Set<string> | null): BundleResult | null {
  if (basename(skill.path) !== 'SKILL.md') return null;
  const realDir = dirname(skill.real);
  if (realDir === realRoot) return null;
  if (!realDir.startsWith(realRoot + sep)) {
    return { bundled: [], unreadable: [{ file: skill.path, line: 1, message: 'skill directory resolves outside repository root; not listed' }] };
  }
  const shownDir = dirname(skill.path);
  const bundled: AgentConfigBundledFile[] = [];
  const unreadable: BundleResult['unreadable'] = [];
  let full = false;

  const walk = (absDir: string, shown: string) => {
    let entries;
    try { entries = readdirSync(absDir, { withFileTypes: true }); } catch (err) {
      unreadable.push({ file: shown, line: 1, message: (err as Error).message });
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (full) return;
      const abs = join(absDir, e.name);
      const rel = `${shown}/${e.name}`;
      if (e.isSymbolicLink()) {
        unreadable.push({ file: rel, line: 1, message: `symbolic link in skill directory ${shownDir}; not followed, so what it reaches is not listed` });
        continue;
      }
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        // Another skill: its files are listed under it.
        try { if (lstatSync(join(abs, 'SKILL.md')).isFile()) continue; } catch { /* no SKILL.md */ }
        walk(abs, rel);
        continue;
      }
      if (!e.isFile()) continue;
      if (rel === skill.path) continue;
      let real: string;
      try { real = realpathSync(abs); } catch { continue; }
      // Nothing is listed that does not sit under the real skill directory where it was found.
      if (real !== abs || !(real.startsWith(realDir + sep))) {
        unreadable.push({ file: rel, line: 1, message: `resolves outside skill directory ${shownDir}; not listed` });
        continue;
      }
      const realRel = relative(realRoot, real).split(sep).join('/');
      if (carried && !carried.has(rel) && !carried.has(realRel)) continue;
      if (bundled.length >= MAX_BUNDLED) {
        full = true;
        unreadable.push({ file: skill.path, line: 1, message: `more than ${MAX_BUNDLED} files beside this skill; the rest were not listed` });
        return;
      }
      let bytes: number;
      let sha256: string | undefined;
      try {
        bytes = lstatSync(real).size;
        if (bytes <= MAX_BUNDLED_READ) sha256 = `sha256-v1:${createHash('sha256').update(readFileSync(real)).digest('hex')}`;
      } catch (err) {
        unreadable.push({ file: rel, line: 1, message: (err as Error).message });
        continue;
      }
      bundled.push({ path: rel, kind: bundledKind(e.name), bytes, ...(sha256 ? { sha256 } : {}) });
    }
  };

  walk(realDir, shownDir);
  bundled.sort(byPath);
  return { bundled, unreadable };
}
