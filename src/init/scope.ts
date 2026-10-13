/**
 * GuardLink init — which source files `config.json`'s `include` should cover.
 *
 * `init` used to write the include for ONE language: whichever root manifest
 * `detectLanguage` saw first. A repository with a TypeScript frontend and a Rust
 * backend got `**\/*.{ts,tsx,js,jsx}`, so every `.rs` and `.mjs` file sat
 * outside the scan — an annotation written there reached no model and no
 * diagnostic said so. The include is now built from the files that are actually
 * in the repository: every language the parser reads that is present gets its
 * globs, and the output says which languages were found and why.
 *
 * @exposes #init to #dos [low] cwe:CWE-400 -- "Walks the whole project tree once to count files by extension"
 * @mitigates #init against #dos using #glob-filtering -- "The walk honours DEFAULT_EXCLUDE (node_modules, dist, target, vendor, .git) and skips .guardlink/"
 * @exposes #init to #child-proc-injection [low] cwe:CWE-78 -- "Runs git ls-files in the project root to learn which files are tracked"
 * @mitigates #init against #child-proc-injection using #param-commands -- "execFileSync with a fixed argument array and cwd; no shell, no user-controlled arguments"
 * @flows ProjectRoot -> #init via detectIncludeScope -- "File list read to choose the include globs"
 * @comment -- "Read-only. A git failure falls back to the plain directory walk rather than to a single-language guess"
 */

import { execFileSync } from 'node:child_process';
import fg from 'fast-glob';
import { DEFAULT_EXCLUDE } from '../parser/parse-project.js';
import type { ProjectLanguage } from './detect.js';

/**
 * A language the parser reads, with the include globs it gets when present.
 *
 * `base` is the include `init` has always written for that language, kept so a
 * single-language repository's config is byte-for-byte what it was. Any other
 * extension of the family found in the tree is added on top of it — `.mjs` in
 * a JavaScript project, `.pyi` beside Python.
 */
interface LanguageFamily {
  name: string;
  exts: readonly string[];
  base: readonly string[];
}

const globs = (...exts: string[]) => exts.map(e => `**/*${e}`);

/**
 * Every programming language in the parser's marker table, grouped.
 *
 * Together with {@link NOT_INCLUDED_FORMATS} this partitions
 * `SCANNED_EXTENSIONS` exactly — tests/init-scope.test.ts pins that, so a
 * language added to the parser cannot be left out of `init`'s scope by omission.
 */
export const LANGUAGE_FAMILIES: readonly LanguageFamily[] = [
  { name: 'TypeScript/JavaScript', exts: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'], base: globs('.ts', '.tsx', '.js', '.jsx') },
  { name: 'Python', exts: ['.py', '.pyi'], base: globs('.py') },
  { name: 'Go', exts: ['.go'], base: globs('.go') },
  { name: 'Rust', exts: ['.rs'], base: globs('.rs') },
  { name: 'Java', exts: ['.java'], base: globs('.java') },
  { name: 'C#', exts: ['.cs'], base: globs('.cs') },
  { name: 'Ruby', exts: ['.rb'], base: globs('.rb') },
  { name: 'Swift', exts: ['.swift'], base: globs('.swift') },
  { name: 'Kotlin', exts: ['.kt', '.kts'], base: globs('.kt', '.kts') },
  { name: 'Terraform', exts: ['.tf', '.hcl'], base: globs('.tf', '.hcl') },
  { name: 'C/C++', exts: ['.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh'], base: [] },
  { name: 'Scala', exts: ['.scala'], base: [] },
  { name: 'Dart', exts: ['.dart'], base: [] },
  { name: 'PHP', exts: ['.php'], base: [] },
  { name: 'Objective-C', exts: ['.m', '.mm'], base: [] },
  { name: 'Shell', exts: ['.sh', '.bash'], base: [] },
  { name: 'Perl', exts: ['.pl', '.pm'], base: [] },
  { name: 'R', exts: ['.r'], base: [] },
  { name: 'Elixir', exts: ['.ex', '.exs'], base: [] },
  { name: 'Nim', exts: ['.nim'], base: [] },
  { name: 'Haskell', exts: ['.hs'], base: [] },
  { name: 'Lua', exts: ['.lua'], base: [] },
  { name: 'SQL', exts: ['.sql'], base: [] },
  { name: 'Ada', exts: ['.adb', '.ads'], base: [] },
  { name: 'VHDL', exts: ['.vhd', '.vhdl'], base: [] },
  { name: 'OCaml', exts: ['.ml', '.mli'], base: [] },
  { name: 'Pascal', exts: ['.pas', '.pp'], base: [] },
  { name: 'Erlang', exts: ['.erl', '.hrl'], base: [] },
  { name: 'Lisp', exts: ['.lisp', '.cl'], base: [] },
  { name: 'Clojure', exts: ['.clj', '.cljs', '.cljc'], base: [] },
  { name: 'Assembly', exts: ['.asm', '.s'], base: [] },
  { name: 'Batch', exts: ['.bat', '.cmd'], base: [] },
  { name: 'Visual Basic', exts: ['.vb', '.bas'], base: [] },
];

/**
 * Markup and data formats the marker table can read but `init` does not put in
 * scope: their files are overwhelmingly content and configuration, not the
 * code a threat model describes. A user who annotates templates adds the glob.
 */
export const NOT_INCLUDED_FORMATS: readonly string[] = [
  '.html', '.htm', '.xml', '.svg', '.css', '.yaml', '.yml', '.ini', '.tex',
];

/**
 * Common markup, documentation and data formats outside the marker table. They
 * are reported as data rather than as "no GuardLink parser", which would read
 * as a missing language.
 */
const OTHER_DATA_FORMATS = new Set([
  '.json', '.jsonc', '.json5', '.md', '.mdx', '.markdown', '.rst', '.txt',
  '.toml', '.lock', '.csv', '.tsv', '.scss', '.sass', '.less', '.properties',
  '.env', '.cfg', '.conf', '.proto', '.graphql', '.gql',
]);

/** The include `init` wrote when it could tell nothing about the project. */
const FALLBACK_INCLUDE = globs('.ts', '.js', '.py', '.go', '.rs', '.java');

const FAMILY_FOR_LANGUAGE: Partial<Record<ProjectLanguage, string>> = {
  typescript: 'TypeScript/JavaScript', javascript: 'TypeScript/JavaScript',
  python: 'Python', go: 'Go', rust: 'Rust', java: 'Java', csharp: 'C#',
  ruby: 'Ruby', swift: 'Swift', kotlin: 'Kotlin', terraform: 'Terraform',
};

export interface IncludedLanguage {
  name: string;
  /** Files of this language found, by extension. Empty when only the root manifest named it. */
  files: Record<string, number>;
  /** Why it is in scope, as printed. */
  reason: string;
}

export interface IncludeScope {
  include: string[];
  languages: IncludedLanguage[];
  /** Extensions present but left out of scope, with counts and the reason. */
  excluded: Array<{ ext: string; files: number; reason: string }>;
  /** Where the file list came from. */
  source: 'git' | 'walk';
}

/**
 * Every file the scope considers, relative to `root`: git's tracked and
 * not-ignored files when `root` is in a work tree, the directory walk
 * otherwise. Both pass through DEFAULT_EXCLUDE — the git list is intersected
 * with the walk, which is where the excludes are applied.
 */
function listFiles(root: string): { files: string[]; source: 'git' | 'walk' } {
  const walked = fg.sync('**/*', {
    cwd: root,
    ignore: [...DEFAULT_EXCLUDE, '.guardlink/**'],
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    suppressErrors: true,
  });
  let tracked: Set<string>;
  try {
    const out = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      cwd: root,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 256 * 1024 * 1024,
    });
    tracked = new Set(out.split('\0').filter(Boolean));
  } catch {
    return { files: walked, source: 'walk' };
  }
  return { files: walked.filter(f => tracked.has(f)), source: 'git' };
}

function extOf(path: string): string | null {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot).toLowerCase() : null;
}

const plural = (n: number) => `${n} file${n === 1 ? '' : 's'}`;

/**
 * The include for `root`: every language present that GuardLink parses.
 *
 * `primary` is the language the root manifest names. It is always in scope even
 * with no files yet — a freshly created project keeps the include it had — and
 * when nothing parseable is found and no manifest names a language, the old
 * multi-language fallback stands.
 */
export function detectIncludeScope(root: string, primary: ProjectLanguage): IncludeScope {
  const { files, source } = listFiles(root);

  const counts = new Map<string, number>();
  for (const f of files) {
    const ext = extOf(f);
    if (ext) counts.set(ext, (counts.get(ext) ?? 0) + 1);
  }

  const primaryFamily = FAMILY_FOR_LANGUAGE[primary];
  const include: string[] = [];
  const languages: IncludedLanguage[] = [];
  const claimed = new Set<string>();

  for (const family of LANGUAGE_FAMILIES) {
    for (const e of family.exts) claimed.add(e);
    const present = family.exts.filter(e => counts.has(e));
    if (present.length === 0 && family.name !== primaryFamily) continue;

    const fileCounts = Object.fromEntries(present.map(e => [e, counts.get(e)!]));
    for (const g of [...family.base, ...globs(...present)]) {
      if (!include.includes(g)) include.push(g);
    }
    const found = present.map(e => `${e} ×${counts.get(e)}`).join(', ');
    languages.push({
      name: family.name,
      files: fileCounts,
      reason: present.length > 0 ? `found ${found}` : 'named by the project manifest at the root',
    });
  }

  const excluded: IncludeScope['excluded'] = [];
  // Unparsed languages first: a language left out is the line worth reading.
  const rest = [...counts.entries()]
    .filter(([ext]) => !claimed.has(ext) && !NOT_INCLUDED_FORMATS.includes(ext))
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  for (const [ext, n] of rest) {
    if (!OTHER_DATA_FORMATS.has(ext)) excluded.push({ ext, files: n, reason: 'no GuardLink parser' });
  }
  for (const ext of NOT_INCLUDED_FORMATS) {
    if (counts.has(ext)) excluded.push({ ext, files: counts.get(ext)!, reason: 'markup/data format' });
  }
  for (const [ext, n] of rest) {
    if (OTHER_DATA_FORMATS.has(ext)) excluded.push({ ext, files: n, reason: 'markup/data format' });
  }

  if (include.length === 0) {
    return {
      include: [...FALLBACK_INCLUDE],
      languages: [{ name: 'default', files: {}, reason: 'no parseable source found and no project manifest at the root' }],
      excluded,
      source,
    };
  }
  return { include, languages, excluded, source };
}

/** The lines `init` prints to explain the scope it wrote. */
export function describeScope(scope: IncludeScope, maxExcluded = 6): string[] {
  const lines = scope.languages.map(l => `  + ${l.name}: ${l.reason}`);
  const shown = scope.excluded.slice(0, maxExcluded);
  for (const x of shown) lines.push(`  - ${x.ext} (${plural(x.files)}): ${x.reason}`);
  const rest = scope.excluded.length - shown.length;
  if (rest > 0) lines.push(`  - …and ${rest} more extension${rest === 1 ? '' : 's'} not in scope`);
  lines.push(`  include: ${scope.include.join(', ')}`);
  return lines;
}
