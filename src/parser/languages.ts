/**
 * GuardLink — the languages the parser reads, and the marker each one writes.
 *
 * **One list, so a language cannot be half-added.** There used to be four
 * places that answered "which files does GuardLink read": the parser's scan
 * glob, `clear`'s scan glob, the MCP context layer's extension set, and
 * `commentStyleForExt`'s marker table. They drifted. `stripCommentPrefix`
 * recognised `//`, `#`, `--`, `%`, `;`, `REM`, `'`, `/* *\/`, `(* *)`, `{- -}`
 * and `<!-- -->` — every style SPEC §2.9 tabulates — while the globs listed the
 * extensions of six of the languages that write them.
 *
 * The cost was not a missing feature, it was a **silent** one. An `@exposes`
 * written into a `.php`, `.pyi`, `.kts`, `.erl` or `.vb` file was a correctly
 * formed annotation, in a correctly formed comment, that reached no threat
 * model and produced no diagnostic of any kind: `uncommented-annotation` never
 * fired (the line *is* a comment) and `unrecognised-comment-form` never fired
 * (the marker *does* parse) because the file was never opened to be asked.
 * Measured on a probe repo carrying one annotated file per language §2.9 names:
 * read in **6 of 43** extensions. That is what made `bravos annotate`
 * unusable outside a handful of languages — the agent's analysis was sound, its
 * `@exposes` landed in the file, and the model stayed empty.
 *
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "Widening the scan set grows the file count a single parse walks; every added extension is another glob fast-glob expands and another file read into memory"
 * @mitigates #parser against #dos using #resource-limits -- "The set is bounded by SPEC §2.9's own table rather than open-ended, DEFAULT_EXCLUDE still prunes node_modules/dist/vendor/target, and no extension here matches a lock file, a bundle or a binary"
 * @comment -- "Widening which FILES are opened is safe; widening what counts as a COMMENT would not be. This module adds no marker: every style here was already recognised by stripCommentPrefix, which is why tests/scanned-languages.test.ts pins the negative direction — a bare @exposes in a newly-scanned .php file is still not an annotation"
 * @validates #glob-filtering for #parser -- "tests/scanned-languages.test.ts writes an annotation in every language named here and asserts the model read it, and asserts the scan set and the marker table are the same list"
 */

/**
 * Lower-case extension (with dot) → the single-line comment marker that
 * language writes, per SPEC §2.9.
 *
 * The marker is the one a *writer* should use — `guardlink review` and
 * `guardlink migrate` consult it when they have no neighbouring comment to copy
 * the style from. Reading does not depend on it: `stripCommentPrefix` tries
 * every recognised opener against every line, so a Haskell `{- -}` block or a
 * PHP `#` comment parses regardless of what this table prefers for that file.
 *
 * Block-only styles are spelled by their opener (`/*`, `(*`, `{-`, `<!--`);
 * the write side pairs each with its closer.
 *
 * `.m` is the one genuinely ambiguous extension in circulation — Objective-C
 * (`//`), MATLAB and Mercury (`%`). It is mapped to Objective-C because that is
 * what `.m` overwhelmingly is in a repository GuardLink is pointed at, and the
 * cost of being wrong is bounded: a MATLAB `%` annotation still *parses*, and
 * the write side only reaches this table when there is no comment beside the
 * insertion point to copy.
 */
export const COMMENT_STYLE_BY_EXT: Readonly<Record<string, string>> = {
  // `//` — C, C++, C#, Java, JavaScript, TypeScript, Go, Rust, Swift, Kotlin,
  // Scala, Dart, PHP, Objective-C.
  '.c': '//', '.h': '//',
  '.cpp': '//', '.cc': '//', '.cxx': '//', '.hpp': '//', '.hh': '//',
  '.cs': '//',
  '.java': '//',
  '.js': '//', '.jsx': '//', '.mjs': '//', '.cjs': '//',
  '.ts': '//', '.tsx': '//', '.mts': '//', '.cts': '//',
  '.go': '//', '.rs': '//', '.swift': '//',
  '.kt': '//', '.kts': '//',
  '.scala': '//', '.dart': '//',
  '.php': '//',
  '.m': '//', '.mm': '//',

  // `#` — Python, Ruby, Bash, Perl, YAML, Terraform, R, Elixir, Nim.
  '.py': '#', '.pyi': '#',
  '.rb': '#',
  '.sh': '#', '.bash': '#',
  '.pl': '#', '.pm': '#',
  '.yaml': '#', '.yml': '#',
  '.tf': '#', '.hcl': '#',
  '.r': '#',
  '.ex': '#', '.exs': '#',
  '.nim': '#',

  // `--` — Haskell, Lua, SQL, Ada, VHDL. Haskell also writes `{- -}`, which
  // `stripCommentPrefix` reads; `--` is what a writer should add.
  '.hs': '--',
  '.lua': '--',
  '.sql': '--',
  '.adb': '--', '.ads': '--',
  '.vhd': '--', '.vhdl': '--',

  // `/* */` — CSS block comments.
  '.css': '/*',

  // `(* *)` — OCaml, Pascal.
  '.ml': '(*', '.mli': '(*',
  '.pas': '(*', '.pp': '(*',

  // `%` — LaTeX, Erlang. (MATLAB's `%` shares `.m` with Objective-C; see above.)
  '.tex': '%',
  '.erl': '%', '.hrl': '%',

  // `;` — Lisp, Clojure, Assembly, INI.
  '.lisp': ';', '.cl': ';',
  '.clj': ';', '.cljs': ';', '.cljc': ';',
  '.asm': ';', '.s': ';',
  '.ini': ';',

  // `<!-- -->` — HTML, XML, SVG. Server-rendered templates (Django, Jinja,
  // ERB, Handlebars) carry annotations here perfectly well.
  '.html': '<!--', '.htm': '<!--', '.xml': '<!--', '.svg': '<!--',

  // `REM` — Batch.
  '.bat': 'REM', '.cmd': 'REM',

  // `'` — VBA, VB.NET.
  '.vb': "'", '.bas': "'",
};

/**
 * Every extension the scan opens for annotations in host-language comments,
 * lower-case and with the leading dot.
 *
 * `.gal` is deliberately absent: a standalone GAL file stores raw annotation
 * lines with no host-language marker, so it has no entry in the marker table.
 * It is added to the scan glob separately by {@link sourceGlobs}' caller.
 */
export const SCANNED_EXTENSIONS: readonly string[] = Object.freeze(
  Object.keys(COMMENT_STYLE_BY_EXT),
);

/** Fast lookup for "would the parser open this file?", used by the MCP context layer. */
const SCANNED_EXTENSION_SET = new Set<string>(SCANNED_EXTENSIONS);

/**
 * Whether the parser's default scan set would open `path`.
 *
 * `.gal` counts: it is scanned, just not through the marker table.
 */
export function isScannedPath(path: string): boolean {
  const dot = path.lastIndexOf('.');
  if (dot < 0) return false;
  const ext = path.slice(dot).toLowerCase();
  return ext === '.gal' || SCANNED_EXTENSION_SET.has(ext);
}

/** The `**\/*.<ext>` glob for every language in the marker table. */
export function sourceGlobs(): string[] {
  return SCANNED_EXTENSIONS.map(ext => `**/*${ext}`);
}

/** The case-insensitive glob for standalone GAL sidecars. */
export const GAL_GLOB = '**/*.[gG][aA][lL]';
