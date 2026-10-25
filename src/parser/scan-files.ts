/**
 * GuardLink — One scanned path per physical file.
 *
 * fast-glob follows symbolic links, so a directory linked into the tree
 * (`proxy/enterprise -> ../../enterprise`) is walked twice: once at its own
 * path and once through the link. Every file under it was then parsed twice,
 * every `#id` it defines was reported as a duplicate of itself, and every
 * file count carried it twice.
 *
 * Links are still followed rather than skipped. A link can be the only path
 * the scan has to a file — a link into a directory the excludes drop, or a
 * link to a single file — and not following it would lose that file's
 * annotations. Instead each group of paths sharing one real path is reduced
 * to a single path: the file's own path when the scan reached it, otherwise
 * the first of the link paths in scan order.
 *
 * @exposes #parser to #path-traversal [medium] cwe:CWE-59 -- "fast-glob follows symlinks and onePathPerFile keeps the path realpathSync resolves, including a link whose target lies outside the project root"
 * @audit #parser -- "A link resolving outside the root is read like any other scanned file; whether to refuse such links is a separate decision from deduplicating them"
 * @flows ProjectFiles -> #parser via realpathSync -- "Each scanned path resolved to its physical file"
 */
import { realpathSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * Keep one path per physical file, in the order given.
 *
 * `paths` are absolute paths under `root`. A path that cannot be resolved (a
 * broken link, a file removed mid-scan) is kept as its own file.
 */
export function onePathPerFile(root: string, paths: string[]): string[] {
  let realRoot = root;
  try { realRoot = realpathSync(root); } catch { /* compare against root as given */ }

  const chosen = new Map<string, string>();
  for (const path of paths) {
    let real: string;
    try { real = realpathSync(path); } catch { real = path; }
    const prev = chosen.get(real);
    if (prev === undefined) {
      chosen.set(real, path);
    } else if (real === join(realRoot, relative(root, path)) && prev !== path) {
      // The file's own path beats any link that reached it first.
      chosen.set(real, path);
    }
  }
  const kept = new Set(chosen.values());
  return [...new Set(paths)].filter(p => kept.has(p));
}
