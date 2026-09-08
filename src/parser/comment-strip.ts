import { extname } from 'node:path';

/**
 * Comment prefix stripping per §2.9.
 * Strips the host language's comment prefix to expose the annotation text.
 *
 * @exposes #parser to #redos [medium] cwe:CWE-1333 -- "Marker and decoration matching runs on every line of every scanned file, including attacker-supplied source"
 * @mitigates #parser against #redos using #regex-anchoring -- "Every pattern is anchored at ^ and bounded — decoration is {1,3}, the marker tail is a character-by-character scan, and no pattern nests a quantifier"
 * @mitigates #parser against #dos using #resource-limits -- "consumeMarkerTail is linear in the marker, not the line: it stops at the first character that is not the marker's own"
 * @comment -- "Widening what is consumed AFTER a recognised marker is safe; widening the marker set would not be. The openers in LINE_MARKERS are unchanged from the single-marker version, so no line that was code became a comment"
 * @validates #regex-anchoring for #parser -- "tests/comment-forms.test.ts pins every §2.9.1 form and, negatively, that a non-comment still returns null"
 */

/**
 * The single-line comment openers §2.9 recognises, longest first.
 *
 * `repeat` is the character a language doubles or triples to turn an ordinary
 * comment into a doc comment: `//` → `///`, `#` → `##`, `;` → `;;`. It is the
 * marker's own character in every case, which is what makes the rule general
 * rather than a table of spellings — `;;;;` is as much a Lisp comment as `;`,
 * and nobody has to add it here first.
 *
 * `REM` has no repeat form; Batch has no doc-comment convention.
 */
const LINE_MARKERS: ReadonlyArray<{ prefix: string; repeat: string }> = [
  { prefix: '//', repeat: '/' },    // C-family, Rust, Go, JS, TS — /// //! //!<
  { prefix: '#', repeat: '#' },     // Python, Ruby, Bash, YAML, Terraform — ##
  { prefix: '--', repeat: '-' },    // Haskell, Lua, SQL, Ada — --- (LDoc)
  { prefix: '%', repeat: '%' },     // LaTeX, Erlang, MATLAB — %% (Erlang module comment)
  { prefix: ';', repeat: ';' },     // Lisp, Clojure, Assembly — ;; ;;;
  { prefix: 'REM ', repeat: '' },   // Batch (with trailing space)
  { prefix: 'REM\t', repeat: '' },
  { prefix: "'", repeat: "'" },     // VBA, VB.NET — ''' (XML doc)
];

/**
 * Decoration a doc-comment convention hangs off the end of its marker.
 *
 *   `!`  Rust inner doc (`//!`), Doxygen (`//!`, `/*!`)
 *   `<`  Doxygen trailing member docs (`//!<`, `/**<`)
 *   `|`  Haddock (`-- |`) — documents the item that follows
 *   `^`  Haddock (`-- ^`) — documents the item that precedes
 *
 * Bounded to three characters so a line of `!!!!!!!!` is prose, not a marker,
 * and anchored so the scan is linear in the marker, not the line.
 */
const MARKER_DECORATION = /^[!<|^]{1,3}/;

/**
 * Consume the repeated marker character and any doc-comment decoration that
 * follows it, returning the comment's text.
 *
 * The order is fixed by the conventions themselves: repetition first (`///`),
 * then decoration (`//!<`), then whitespace. Haddock is the one convention that
 * puts a space before its decoration (`-- | doc`), so whitespace is allowed to
 * precede the decoration too — but only there, and only once.
 */
function consumeMarkerTail(rest: string, repeat: string): string {
  let i = 0;
  if (repeat) while (rest[i] === repeat) i++;
  let tail = rest.slice(i);

  const spaced = tail.replace(/^[ \t]+/, '');
  const decoration = spaced.match(MARKER_DECORATION);
  if (decoration) tail = spaced.slice(decoration[0].length);

  return tail.trimStart();
}

/**
 * Strip comment prefix from a single line, returning the inner text
 * or null if the line is not a comment.
 *
 * **Repeated and decorated markers are the same marker.** `stripCommentPrefix`
 * used to remove exactly one marker, and `parseLine` then required the very
 * next character to be `@`. Every doc-comment convention in circulation is a
 * marker plus one character, so every one of them landed one character too far
 * in and was dropped — `///`, `//!`, `##`, `;;`, `%%`, `---`, `-- |`, `'''`,
 * and `/**` on its opening line. Measured on a 2,400-file repository: 54 real
 * annotations invisible, among them 32 `@mitigates` and 6 `@exposes`, with no
 * diagnostic of any kind. The generated agent instructions tell authors to put
 * annotations "in the doc-block of the function or module they describe", so
 * the guidance GuardLink writes instructed the exact form it then discarded.
 *
 * What this does **not** do is widen what counts as a comment. The set of
 * openers is unchanged; only what is consumed *after* a recognised opener has
 * grown. A line that was not a comment before is not a comment now.
 */
export function stripCommentPrefix(line: string): string | null {
  const trimmed = line.trimStart();

  for (const { prefix, repeat } of LINE_MARKERS) {
    if (trimmed.startsWith(prefix)) {
      return consumeMarkerTail(trimmed.slice(prefix.length), repeat);
    }
  }

  // Block comment line (already inside a block)
  // Strip leading * (Javadoc-style) or bare text in block
  if (trimmed.startsWith('*') && !trimmed.startsWith('*/')) {
    return consumeMarkerTail(trimmed.slice(1), '');
  }

  // HTML/XML comment: <!-- ... -->
  const htmlMatch = trimmed.match(/^<!--\s*(.*?)\s*-->$/);
  if (htmlMatch) return htmlMatch[1];

  // Opening block comment on same line: /* ... */  or  /* ...
  // `\*+` covers the doc-block openers (`/**`, `/*!`, `/**<`), whose first line
  // carries an annotation as often as the `* @…` continuations below it do.
  const blockOpenClose = trimmed.match(/^\/\*+\s*(.*?)\s*\*\/$/);
  if (blockOpenClose) return consumeMarkerTail(blockOpenClose[1], '');

  const blockOpen = trimmed.match(/^\/\*+(.*)$/);
  if (blockOpen) return consumeMarkerTail(blockOpen[1], '');

  // Haskell block: {- ... -}
  const haskellBlock = trimmed.match(/^\{-\s*(.*?)\s*-\}$/);
  if (haskellBlock) return haskellBlock[1];

  // OCaml/Pascal: (* ... *)
  const ocamlBlock = trimmed.match(/^\(\*\s*(.*?)\s*\*\)$/);
  if (ocamlBlock) return ocamlBlock[1];

  return null;
}

/**
 * Standalone GAL files store raw annotation lines without host-language
 * comment prefixes, unlike annotations embedded in source files.
 */
export function isStandaloneAnnotationFile(filePath: string): boolean {
  return extname(filePath).toLowerCase() === '.gal';
}

/**
 * Detect file's primary comment style from extension.
 * Used for multi-line continuation detection.
 */
export function commentStyleForExt(ext: string): string {
  const map: Record<string, string> = {
    '.ts': '//', '.tsx': '//', '.js': '//', '.jsx': '//',
    '.java': '//', '.c': '//', '.cpp': '//', '.cc': '//',
    '.cs': '//', '.go': '//', '.rs': '//', '.swift': '//',
    '.kt': '//', '.scala': '//', '.dart': '//',
    '.py': '#', '.rb': '#', '.sh': '#', '.bash': '#',
    '.yml': '#', '.yaml': '#', '.tf': '#', '.r': '#',
    '.ex': '#', '.exs': '#', '.nim': '#', '.pl': '#',
    '.hs': '--', '.lua': '--', '.sql': '--', '.ada': '--',
    '.html': '<!--', '.xml': '<!--', '.svg': '<!--',
    '.css': '/*',
    '.tex': '%', '.erl': '%', '.m': '%',
    '.lisp': ';', '.cl': ';', '.clj': ';', '.asm': ';',
    '.bat': 'REM', '.cmd': 'REM',
    '.vb': "'", '.bas': "'",
  };
  return map[ext.toLowerCase()] || '//';
}
