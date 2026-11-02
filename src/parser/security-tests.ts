/** Shared location of committed security regression tests. */
import { lstatSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep, win32 } from 'node:path';
import { findHiddenUnicode } from '../agentconfig/hidden-unicode.js';

export const DEFAULT_SECURITY_TESTS_DIR = 'security';

/**
 * Read `security_tests_dir` from `.guardlink/config.json`, defaulting to `security`.
 * Returns a normalized repository-relative path without a trailing slash.
 * No directory is created and no tests are executed.
 *
 * @exposes #parser to #path-traversal [medium] cwe:CWE-22 -- "readSecurityTestsDir reads security_tests_dir from config.json for downstream filesystem paths; absolute or parent paths would escape root"
 * @mitigates #parser against #path-traversal using #path-validation -- "Rejects absolute paths, parent segments and the reserved root directories .bravos, .guardlink and .git; real paths of existing ancestors must stay inside the repository"
 * @exposes #parser to #prompt-injection [medium] cwe:CWE-77 -- "readSecurityTestsDir returns security_tests_dir for agentInstructions and buildTranslatePrompt; unfiltered path text could end a code span"
 * @mitigates #parser against #prompt-injection using #input-sanitize -- "Rejects controls, hidden Unicode, backticks and HTML comment delimiters before rendering a single-line code span"
 * @flows ConfigFile -> #parser via readSecurityTestsDir -- "Validated repository-relative security-test directory"
 */
export function readSecurityTestsDir(root: string): string {
  const invalid = (reason: string): never => {
    throw new Error(`.guardlink/config.json security_tests_dir: ${reason}`);
  };
  let config: unknown;
  try {
    config = JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') config = {};
    else return invalid(`cannot read configuration: ${(error as Error).message}`);
  }
  const raw = config !== null && typeof config === 'object' && 'security_tests_dir' in config
    ? config.security_tests_dir : DEFAULT_SECURITY_TESTS_DIR;
  if (typeof raw !== 'string' || !raw.trim()) return invalid('must be a non-empty repository-relative directory');
  // A path written on Windows must have the same meaning on POSIX and vice versa.
  const portable = raw.replaceAll('\\', '/');
  if (isAbsolute(portable) || win32.isAbsolute(raw) || /^[a-z]:/i.test(raw)) return invalid('absolute paths are not allowed; use a repository-relative directory');
  if (portable.split('/').includes('..')) return invalid('parent (..) segments are not allowed; the directory must stay inside the repository');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029\ufeff`]/.test(raw) || raw.includes('<!--') || raw.includes('-->') || findHiddenUnicode(raw).length) {
    return invalid('contains characters unsafe for generated instructions');
  }
  const directory = portable.split('/').filter(part => part && part !== '.').join('/');
  if (!directory) return invalid('must name a directory below the repository root');
  if (['.bravos', '.guardlink', '.git'].includes(directory.split('/')[0])) {
    return invalid('must be outside the repository-root .bravos/, .guardlink/ and .git/ directories');
  }
  const repo = realpathSync(root);
  // Check the nearest existing ancestor too, so a missing child below an
  // outward-pointing symlink cannot be treated as an in-repository location.
  let ancestor = resolve(root, directory);
  while (ancestor !== dirname(ancestor)) {
    try {
      lstatSync(ancestor);
      const rel = relative(repo, realpathSync(ancestor));
      if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
        return invalid('resolves outside the repository through a symlink');
      }
      if (!statSync(ancestor).isDirectory()) return invalid('an existing path component is not a directory');
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOTDIR') return invalid('an existing path component is not a directory');
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      // A dangling symlink must not silently turn into the default location.
      try { lstatSync(ancestor); } catch { ancestor = dirname(ancestor); continue; }
      return invalid('contains a dangling symlink');
    }
  }
  return directory;
}
