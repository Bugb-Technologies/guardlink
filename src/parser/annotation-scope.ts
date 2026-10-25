/**
 * GuardLink — which files are annotation work, and why the rest are not.
 *
 * Two questions used to share one answer. "Which files does the parser read
 * for annotations?" (model discovery) and "which files still need someone to
 * annotate them?" (the coverage inventory, `unannotated_files`) were both the
 * scan set, so the second inherited everything the first has to read: a
 * gitignored scratch file, a file `.gitattributes` marks generated or
 * vendored, a file `.guardlink/config.json` excludes, a minified bundle, a
 * Next.js export, an SVG logo. Each was reported as unannotated, and an agent
 * working down that list spent its budget on them. Measured on a repository
 * with a committed Next.js export: 457 files of bundles and media and 113
 * asset SVGs in the list, roughly a fifth of the annotation work planned.
 *
 * `config.json`'s `include` and `exclude` were worse than unused: `init`
 * writes them and prints them as the scan scope, and nothing read them.
 *
 * The questions are separate now. Discovery is unchanged — every file the
 * scan set reaches is still parsed, so an annotation already written in a
 * file that is out of scope stays in the model. This module answers only the
 * second question: given a path, is it annotation work, and if not, why not.
 * One reason per path, the first that applies, in this order:
 *
 *   1. `guardlink-data`        `.guardlink/**` and `.gal` sidecars
 *   2. `built-in-exclude`      the parser's own excludes (node_modules, dist, tests, …)
 *   3. `gitignored`            untracked and matched by `.gitignore`
 *   4. `linguist-vendored`     `.gitattributes`
 *   5. `linguist-generated`    `.gitattributes`
 *   6. `config-exclude`        `.guardlink/config.json` `exclude`
 *   7. `asset`                 images, fonts, audio and video
 *   8. `generated-output`      source maps
 *   9. `unsupported-extension` no GuardLink comment syntax for the file type
 *  10. `outside-config-include` `.guardlink/config.json` `include` names it nowhere
 *  11. `generated-output`      minified bundles and Next.js build output
 *  12. `asset`                 an SVG under an asset directory
 *
 * 1–10 are facts or the user's own declarations. 11 and 12 are defaults, and
 * a default has to be overridable: `-linguist-generated` (or
 * `linguist-generated=false`) in `.gitattributes` keeps a file the generated
 * rule would drop, the same switch Linguist itself honours, and
 * `"worklist": { "keep": [...] }` in `config.json` keeps any path 11 or 12
 * would drop. SVG is not excluded as a format — an SVG can be a template, and
 * the parser reads its `<!-- -->` comments — only where it sits among assets.
 *
 * Git answers 3–5 when `root` is in a work tree ("tracked-file view": a file
 * that is tracked stays in scope even when a `.gitignore` pattern matches it).
 * Outside one there is no `.gitignore` to honour and the view is `walk`.
 *
 * @exposes #parser to #child-proc-injection [low] cwe:CWE-78 -- "`git()` hands `execFileSync` the git ls-files and check-attr calls `readIgnored` and `readLinguistAttrs` make in the project root"
 * @mitigates #parser against #child-proc-injection using #param-commands -- "execFileSync with a fixed argument array and cwd, no shell; paths reach git on stdin as NUL-separated data, never as arguments"
 * @exposes #parser to #dos [low] cwe:CWE-1333 -- "`compileScopePattern` turns config.json include, exclude and worklist.keep strings into a `RegExp` via `globSource`"
 * @mitigates #parser against #dos using #glob-filtering -- "globSource quantifies only single character classes, plus one optional any-prefix group per double-star segment, and every pattern is anchored at both ends"
 * @flows ProjectRoot -> #parser via annotationScope -- "git ignore and attribute answers and config.json scope globs, read to classify scanned paths"
 * @comment -- "Classification only: nothing here decides what is parsed, so an out-of-scope file's annotations stay in the model"
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { isScannedPath } from './languages.js';

/** Why a path is not annotation work. */
export type ScopeExclusionReason =
  | 'guardlink-data'
  | 'built-in-exclude'
  | 'gitignored'
  | 'linguist-vendored'
  | 'linguist-generated'
  | 'config-exclude'
  | 'asset'
  | 'generated-output'
  | 'unsupported-extension'
  | 'outside-config-include'
  /** Listed by git, never reached by the scan (the worklist only). */
  | 'not-scanned';

export interface ScopeExclusion {
  reason: ScopeExclusionReason;
  /** The rule that matched, as a reader would look it up. */
  detail: string;
}

/** Where the git answers came from: a work tree, or no git at all. */
export type ScopeView = 'git' | 'walk';

/** `.guardlink/config.json` keys that shape the annotation scope. */
export interface ScopeConfig {
  include?: string[];
  exclude?: string[];
  /** Paths the default generated-output and asset rules would drop, kept. */
  keep?: string[];
}

export interface AnnotationScope {
  view: ScopeView;
  /** Why `path` is not annotation work, or null when it is. */
  classify(path: string): ScopeExclusion | null;
}

export interface AnnotationScopeOptions {
  /** The parser's built-in exclude globs (rule 2). */
  builtInExclude: readonly string[];
  /** Read from `.guardlink/config.json` when omitted. */
  config?: ScopeConfig;
}

// ─── Globs ───────────────────────────────────────────────────────────

/**
 * Regex source for one glob: `**`, `*`, `?`, `[...]` and `{a,b}`.
 *
 * Every emitted quantifier is over a single character class, except `**\/`,
 * which becomes one optional `(?:.*\/)?` group — so the patterns a config file
 * supplies cannot build a backtracking bomb.
 */
function globSource(glob: string): string {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      const segmentStart = i === 0 || glob[i - 1] === '/';
      if (glob[i + 1] === '*' && segmentStart && (glob[i + 2] === '/' || i + 2 === glob.length)) {
        if (glob[i + 2] === '/') { out += '(?:.*/)?'; i += 2; } else { out += '.*'; i += 1; }
        continue;
      }
      while (glob[i + 1] === '*') i++;
      out += '[^/]*';
    } else if (c === '?') {
      out += '[^/]';
    } else if (c === '[') {
      const close = glob.indexOf(']', i + 2);
      if (close < 0) { out += '\\['; continue; }
      let body = glob.slice(i + 1, close).replaceAll('\\', '\\\\').replaceAll(']', '\\]');
      if (body.startsWith('!')) body = `^${body.slice(1)}`;
      out += `[${body}]`;
      i = close;
    } else if (c === '{') {
      const close = matchingBrace(glob, i);
      if (close < 0) { out += '\\{'; continue; }
      out += `(?:${splitTopLevel(glob.slice(i + 1, close)).map(globSource).join('|')})`;
      i = close;
    } else {
      out += /[.+^$()|\\\]}]/.test(c) ? `\\${c}` : c;
    }
  }
  return out;
}

function matchingBrace(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === '{') depth++;
    else if (s[i] === '}' && --depth === 0) return i;
  }
  return -1;
}

function splitTopLevel(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '{') depth++;
    else if (s[i] === '}') depth--;
    else if (s[i] === ',' && depth === 0) { parts.push(s.slice(start, i)); start = i + 1; }
  }
  parts.push(s.slice(start));
  return parts;
}

/**
 * A matcher for one scope pattern, read the way `.gitignore` reads one.
 *
 * A pattern with no `/` (`dist`, `*.min.js`) matches a path segment at any
 * depth — which is how the bare names `init` writes into `exclude` have always
 * read. A pattern with a `/` is relative to the root. Either way, a pattern
 * that matches a directory matches everything beneath it.
 */
export function compileScopePattern(raw: string): ((path: string) => boolean) | null {
  let p = raw.trim().replaceAll('\\', '/');
  if (p.startsWith('./')) p = p.slice(2);
  const anchored = p.startsWith('/');
  if (anchored) p = p.slice(1);
  while (p.endsWith('/')) p = p.slice(0, -1);
  if (p === '') return null;
  const re = new RegExp(`^${globSource(p)}$`);
  if (!anchored && !p.includes('/')) {
    return path => path.split('/').some(seg => re.test(seg));
  }
  return path => {
    if (re.test(path)) return true;
    for (let i = path.indexOf('/'); i > 0; i = path.indexOf('/', i + 1)) {
      if (re.test(path.slice(0, i))) return true;
    }
    return false;
  };
}

interface NamedMatcher { pattern: string; test: (path: string) => boolean }

function matchers(patterns: readonly string[] | undefined): NamedMatcher[] {
  const out: NamedMatcher[] = [];
  for (const pattern of patterns ?? []) {
    const test = compileScopePattern(pattern);
    if (test) out.push({ pattern, test });
  }
  return out;
}

// ─── Config ──────────────────────────────────────────────────────────

const stringList = (v: unknown): string[] | undefined =>
  Array.isArray(v) && v.every(x => typeof x === 'string') ? v : undefined;

/**
 * The scope keys of `.guardlink/config.json`. A key that is absent or not a
 * list of strings is treated as unset, so a malformed config narrows nothing.
 */
export function readScopeConfig(root: string): ScopeConfig {
  try {
    const config = JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf-8'));
    return {
      include: stringList(config?.include),
      exclude: stringList(config?.exclude),
      keep: stringList(config?.worklist?.keep),
    };
  } catch {
    return {};
  }
}

// ─── Git ─────────────────────────────────────────────────────────────

function git(root: string, args: string[], input?: string): string | null {
  try {
    return execFileSync('git', args, {
      cwd: root,
      encoding: 'utf-8',
      input,
      stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'ignore'],
      maxBuffer: 256 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}

/**
 * Untracked paths `.gitignore` matches, with ignored directories collapsed to
 * `dir/` — one entry for an ignored `node_modules`, not a hundred thousand.
 * Null outside a work tree.
 *
 * `check-ignore` is the obvious call and the wrong one: it aborts the whole
 * batch on a path beneath a symbolic link or inside a submodule, both of which
 * the scan reaches.
 */
function readIgnored(root: string): { files: Set<string>; dirs: Set<string> } | null {
  const out = git(root, ['ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--directory']);
  if (out === null) return null;
  const files = new Set<string>();
  const dirs = new Set<string>();
  for (const entry of out.split('\0')) {
    // `./` is the root itself, ignored by a parent repository. Being pointed
    // at it is a choice to read it, so its files stay in scope.
    if (!entry || entry === './') continue;
    if (entry.endsWith('/')) dirs.add(entry.slice(0, -1));
    else files.add(entry);
  }
  return { files, dirs };
}

/** `true` set, `false` unset or false, absent unspecified. */
type Tristate = boolean | undefined;
interface LinguistAttrs { generated: Tristate; vendored: Tristate }

function readLinguistAttrs(root: string, paths: readonly string[]): Map<string, LinguistAttrs> {
  const attrs = new Map<string, LinguistAttrs>();
  if (paths.length === 0) return attrs;
  const out = git(root, ['check-attr', '-z', '--stdin', 'linguist-generated', 'linguist-vendored'], paths.join('\0') + '\0');
  if (out === null) return attrs;
  const fields = out.split('\0');
  for (let i = 0; i + 2 < fields.length; i += 3) {
    const [path, attr, value] = [fields[i], fields[i + 1], fields[i + 2]];
    const v: Tristate = value === 'set' || value === 'true' ? true
      : value === 'unset' || value === 'false' ? false : undefined;
    if (v === undefined) continue;
    const a = attrs.get(path) ?? { generated: undefined, vendored: undefined };
    if (attr === 'linguist-generated') a.generated = v; else a.vendored = v;
    attrs.set(path, a);
  }
  return attrs;
}

// ─── File types ──────────────────────────────────────────────────────

const MEDIA_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.bmp', '.tif', '.tiff', '.heic', '.psd',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac', '.mp4', '.m4v', '.webm', '.mov', '.avi', '.mkv',
]);

/** Directory names whose SVGs are pictures rather than templates. */
const ASSET_DIRS = new Set([
  'assets', 'asset', 'images', 'image', 'img', 'icons', 'icon', 'logos', 'logo', 'media', 'public', 'static', 'fonts',
]);

const MINIFIED = /\.min\.(?:js|mjs|cjs|css)$/i;

function extOf(path: string): string {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot).toLowerCase() : '';
}

const OVERRIDE = 'keep it with `-linguist-generated` in .gitattributes or `worklist.keep` in .guardlink/config.json';

// ─── The scope ───────────────────────────────────────────────────────

/**
 * Build the classifier for `root`.
 *
 * `paths` are the root-relative paths that will be asked about; git's
 * attribute answers for them are read in one call here. A path not in `paths`
 * is still classified, without its `.gitattributes` answer.
 */
export function annotationScope(root: string, paths: readonly string[], options: AnnotationScopeOptions): AnnotationScope {
  const config = options.config ?? readScopeConfig(root);
  const builtIn = matchers(options.builtInExclude);
  const include = config.include ? matchers(config.include) : null;
  const exclude = matchers(config.exclude);
  const keep = matchers(config.keep);

  const ignored = readIgnored(root);
  const view: ScopeView = ignored === null ? 'walk' : 'git';
  const attrs = view === 'git' ? readLinguistAttrs(root, paths) : new Map<string, LinguistAttrs>();

  // A directory holding `_next/` beside its own HTML is a Next.js static
  // export (`output: 'export'`), and everything in it is build output.
  const exportDirs = new Map<string, boolean>();
  const isNextExport = (dir: string): boolean => {
    let hit = exportDirs.get(dir);
    if (hit === undefined) {
      hit = false;
      try {
        hit = statSync(join(root, dir, '_next')).isDirectory()
          && readdirSync(join(root, dir)).some(name => /\.html?$/i.test(name));
      } catch { /* no _next here */ }
      exportDirs.set(dir, hit);
    }
    return hit;
  };

  const isIgnored = (path: string): boolean => {
    if (!ignored) return false;
    if (ignored.files.has(path) || ignored.dirs.has(path)) return true;
    for (let i = path.indexOf('/'); i > 0; i = path.indexOf('/', i + 1)) {
      if (ignored.dirs.has(path.slice(0, i))) return true;
    }
    return false;
  };

  const generatedDefault = (path: string, segments: string[]): string | null => {
    if (MINIFIED.test(path)) return 'minified bundle';
    const next = segments.indexOf('_next');
    if (next >= 0 && next < segments.length - 1) return `Next.js build output (\`${segments.slice(0, next + 1).join('/')}/\`)`;
    for (let i = 1; i < segments.length; i++) {
      const dir = segments.slice(0, i).join('/');
      if (isNextExport(dir)) return `Next.js static export (\`${dir}/\` holds \`_next/\` and its HTML)`;
    }
    return null;
  };

  const classify = (path: string): ScopeExclusion | null => {
    if (path === '.guardlink' || path.startsWith('.guardlink/') || /\.gal$/i.test(path)) {
      return { reason: 'guardlink-data', detail: 'GuardLink\'s own definitions and sidecars: read for the model, never annotation work' };
    }
    const built = builtIn.find(m => m.test(path));
    if (built) return { reason: 'built-in-exclude', detail: `the parser's built-in exclude \`${built.pattern}\`` };
    if (isIgnored(path)) return { reason: 'gitignored', detail: 'untracked and matched by .gitignore' };

    const a = attrs.get(path);
    if (a?.vendored === true) return { reason: 'linguist-vendored', detail: '.gitattributes sets linguist-vendored' };
    if (a?.generated === true) return { reason: 'linguist-generated', detail: '.gitattributes sets linguist-generated' };

    const ex = exclude.find(m => m.test(path));
    if (ex) return { reason: 'config-exclude', detail: `.guardlink/config.json exclude \`${ex.pattern}\`` };

    const ext = extOf(path);
    if (MEDIA_EXTENSIONS.has(ext)) return { reason: 'asset', detail: `${ext} media file` };
    if (ext === '.map') return { reason: 'generated-output', detail: 'source map' };
    if (!isScannedPath(path)) {
      return { reason: 'unsupported-extension', detail: ext ? `GuardLink reads no comments in ${ext} files` : 'no file extension, so no comment syntax to read' };
    }
    if (include && !include.some(m => m.test(path))) {
      return { reason: 'outside-config-include', detail: 'matches no .guardlink/config.json include pattern' };
    }

    if (keep.some(m => m.test(path))) return null;
    const segments = path.split('/');
    if (a?.generated !== false) {
      const generated = generatedDefault(path, segments);
      if (generated) return { reason: 'generated-output', detail: `${generated}; ${OVERRIDE}` };
    }
    if (ext === '.svg') {
      const dir = segments.slice(0, -1).find(s => ASSET_DIRS.has(s.toLowerCase()));
      if (dir) return { reason: 'asset', detail: `SVG under \`${dir}/\`; keep it with \`worklist.keep\` in .guardlink/config.json if it is a template` };
    }
    return null;
  };

  return { view, classify };
}
