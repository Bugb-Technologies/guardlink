/**
 * GuardLink structure layer — the pinned grammar set and the extension map.
 *
 * One table, read by two consumers: `scripts/build-grammars.ts` fetches the
 * WASM for each entry, and `runtime.ts` loads it. A language is symbol-scoped
 * if and only if it appears in GRAMMARS; an extension that maps to null is
 * file-scoped by design (markup, stylesheets, SQL) and an extension that maps
 * to a language with no fetched WASM falls back to file scope at runtime.
 *
 * Every version is exact. The WASM inside a grammar package is built against a
 * tree-sitter ABI the pinned `web-tree-sitter` runtime must accept; a caret
 * here would let a grammar move to an ABI the runtime rejects.
 *
 * @comment -- "Data only: no I/O, no user input. The paths it produces are joined under the package's own grammars/ directory"
 */
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface GrammarSource {
  /** npm package that ships the WASM. */
  package: string;
  /** Exact version. */
  version: string;
  /** File name inside the package tarball. */
  file: string;
}

export const GRAMMARS: Record<string, GrammarSource> = {
  typescript: { package: 'tree-sitter-typescript', version: '0.23.2', file: 'tree-sitter-typescript.wasm' },
  tsx:        { package: 'tree-sitter-typescript', version: '0.23.2', file: 'tree-sitter-tsx.wasm' },
  javascript: { package: 'tree-sitter-javascript', version: '0.25.0', file: 'tree-sitter-javascript.wasm' },
  python:     { package: 'tree-sitter-python',     version: '0.25.0', file: 'tree-sitter-python.wasm' },
  ruby:       { package: 'tree-sitter-ruby',       version: '0.23.1', file: 'tree-sitter-ruby.wasm' },
  go:         { package: 'tree-sitter-go',         version: '0.25.0', file: 'tree-sitter-go.wasm' },
  rust:       { package: 'tree-sitter-rust',       version: '0.24.0', file: 'tree-sitter-rust.wasm' },
  java:       { package: 'tree-sitter-java',       version: '0.23.5', file: 'tree-sitter-java.wasm' },
  scala:      { package: 'tree-sitter-scala',      version: '0.24.0', file: 'tree-sitter-scala.wasm' },
  c:          { package: 'tree-sitter-c',          version: '0.24.1', file: 'tree-sitter-c.wasm' },
  cpp:        { package: 'tree-sitter-cpp',        version: '0.23.4', file: 'tree-sitter-cpp.wasm' },
  c_sharp:    { package: 'tree-sitter-c-sharp',    version: '0.23.5', file: 'tree-sitter-c_sharp.wasm' },
  lua:        { package: '@tree-sitter-grammars/tree-sitter-lua',  version: '0.4.1', file: 'tree-sitter-lua.wasm' },
  haskell:    { package: 'tree-sitter-haskell',    version: '0.23.1', file: 'tree-sitter-haskell.wasm' },
  hcl:        { package: '@tree-sitter-grammars/tree-sitter-hcl',  version: '1.2.0', file: 'tree-sitter-hcl.wasm' },
  yaml:       { package: '@tree-sitter-grammars/tree-sitter-yaml', version: '0.7.1', file: 'tree-sitter-yaml.wasm' },
  bash:       { package: 'tree-sitter-bash',       version: '0.25.1', file: 'tree-sitter-bash.wasm' },
  elixir:     { package: 'tree-sitter-elixir',     version: '0.3.5',  file: 'tree-sitter-elixir.wasm' },
};

/**
 * Languages GuardLink scans with no WASM the pinned runtime can load. Swift
 * and Kotlin ship no tree-sitter WASM package at all. Dart's only published
 * package — `tree-sitter-dart@1.0.0`, the sole version npm has ever carried —
 * ships a WASM built with a pre-"dylink.0" Emscripten toolchain; web-tree-sitter
 * 0.27 only recognizes the newer `dylink.0` custom section and rejects it on
 * load. There is no newer version of the package to pin instead, and no other
 * npm package ships a trustworthy prebuilt Dart WASM as of this writing. All
 * three resolve to file scope with reason `no-grammar` until a working WASM is
 * placed at `grammars/<language>.wasm` by hand (the build script keeps any
 * file it finds).
 */
export const GRAMMARS_UNAVAILABLE = ['swift', 'kotlin', 'dart'] as const;

/**
 * Lower-case extension (with dot) → language id, or null for file scope.
 *
 * Covers every extension in `parser/languages.ts`, which is the list the scan
 * glob is built from. `null` is a real answer, not a gap: the anchor layer
 * resolves that file to file scope with reason `no-grammar`, and an annotation
 * in it still parses and still lands in the model — it just anchors to the file
 * rather than to the enclosing declaration.
 *
 * Most of the languages SPEC §2.9 names have no prebuilt tree-sitter WASM worth
 * pinning, so they are `null` by necessity rather than by design. They are
 * listed anyway, because the alternative — `undefined` — is the difference
 * between "this file anchors to file scope" and "the table forgot this
 * language", and only one of those is a bug.
 */
export const EXTENSION_LANGUAGE: Record<string, string | null> = {
  '.ts': 'typescript', '.tsx': 'tsx', '.js': 'javascript', '.jsx': 'javascript',
  '.mjs': 'javascript', '.cjs': 'javascript', '.mts': 'typescript', '.cts': 'typescript',
  '.py': 'python', '.pyi': 'python', '.rb': 'ruby', '.go': 'go', '.rs': 'rust',
  '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.scala': 'scala',
  '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
  '.hpp': 'cpp', '.hh': 'cpp',
  '.cs': 'c_sharp', '.swift': 'swift', '.dart': 'dart',
  '.lua': 'lua', '.hs': 'haskell',
  '.tf': 'hcl', '.hcl': 'hcl',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.sh': 'bash', '.bash': 'bash',
  '.ex': 'elixir', '.exs': 'elixir',
  // File-scope by design (spec §6.2): no meaningful declaration structure.
  '.sql': null, '.html': null, '.htm': null, '.xml': null, '.svg': null,
  '.css': null, '.ini': null, '.tex': null,
  // File scope for want of a grammar. Annotations parse; anchors are file-wide.
  '.php': null, '.m': null, '.mm': null,
  '.pl': null, '.pm': null, '.r': null, '.nim': null,
  '.adb': null, '.ads': null, '.vhd': null, '.vhdl': null,
  '.ml': null, '.mli': null, '.pas': null, '.pp': null,
  '.erl': null, '.hrl': null,
  '.lisp': null, '.cl': null, '.clj': null, '.cljs': null, '.cljc': null,
  '.asm': null, '.s': null,
  '.bat': null, '.cmd': null, '.vb': null, '.bas': null,
};

/** Language id for a file extension, or null when the file is file-scoped. */
export function languageForExtension(ext: string): string | null {
  return EXTENSION_LANGUAGE[ext.toLowerCase()] ?? null;
}

/**
 * `<package root>/grammars`. From `src/structure/` and from `dist/structure/`
 * the package root is two levels up, so one expression serves both.
 */
export const GRAMMARS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'grammars');

export function grammarPath(language: string): string {
  return join(GRAMMARS_DIR, `${language}.wasm`);
}
