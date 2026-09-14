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
 * Every block form `stripCommentPrefix` above recognises, opener paired with the
 * sequence that ends it. One definition: the stripper's forms and the closers a
 * writer must neutralise are the same set, and a set written twice drifts.
 */
const BLOCK_FORMS: ReadonlyArray<{ open: string; close: string }> = [
  { open: '/*', close: '*/' },
  { open: '<!--', close: '-->' },
  { open: '{-', close: '-}' },
  { open: '(*', close: '*)' },
];

/**
 * Block closers a file could plausibly carry, for a line that does not show its
 * own opener — the LAST resort behind `commentFormAt`, which reads the source.
 *
 * At least as wide as what the stripper accepts for that language, because a
 * table thinner than the stripper leaves the host-grammar defect reachable
 * exactly where it is thin. Markup carries two: an annotation in an inline
 * `<script>` or `<style>` doc-block is stripped the same way and is exposed to
 * the C-family closer as well as its own.
 *
 * Languages whose only comment form is a line comment need no entry — a line
 * comment ends at a newline, and a written description is already one line.
 */
const BLOCK_CLOSERS: Readonly<Record<string, readonly string[]>> = {
  '.ts': ['*/'], '.tsx': ['*/'], '.js': ['*/'], '.jsx': ['*/'], '.mts': ['*/'], '.cts': ['*/'],
  '.java': ['*/'], '.c': ['*/'], '.h': ['*/'], '.cpp': ['*/'], '.cc': ['*/'], '.hpp': ['*/'],
  '.cs': ['*/'], '.go': ['*/'], '.rs': ['*/'], '.swift': ['*/'], '.kt': ['*/'], '.kts': ['*/'],
  '.scala': ['*/'], '.dart': ['*/'], '.php': ['*/'],
  '.css': ['*/'], '.scss': ['*/'], '.less': ['*/'],
  '.sql': ['*/'], '.tf': ['*/'], '.hcl': ['*/'],
  '.hs': ['-}'],
  '.ml': ['*)'], '.mli': ['*)'], '.pas': ['*)'],
  '.html': ['-->', '*/'], '.xml': ['-->'], '.svg': ['-->', '*/'], '.vue': ['-->', '*/'],
};

/** Closers this file could carry, when the line itself cannot settle the form. */
export function blockCommentClosers(filePath: string): readonly string[] {
  return BLOCK_CLOSERS[extname(filePath).toLowerCase()] ?? [];
}

/**
 * Both ends of every block form these closers belong to.
 *
 * Breaking only the closer leaves the other end open, and block comments NEST in
 * Rust, Swift, Kotlin, Scala, Dart, Haskell and OCaml — every one of them in the
 * table above. An injected OPENER there starts a nested comment; the doc-block's
 * own closer on the next line closes only that nested level, and the outer comment
 * runs on past the declaration it documents, so that declaration and everything
 * below it silently leave the compile. Same hole the closer pass exists to close,
 * entered from the other end, and a writer's re-parse is blind to it either way.
 *
 * Uniform, with no table of which grammars nest: an injected opener is inert where
 * they do not nest and fatal where they do, so breaking it always costs nothing and
 * sometimes saves the file — and one more per-language dimension modelled here and
 * relied on elsewhere is the shape that drifts. Both ends come off the same
 * `BLOCK_FORMS` pair, so neither can be widened without the other.
 */
function delimitersFor(closers: readonly string[]): readonly string[] {
  const out: string[] = [];
  for (const close of closers) {
    out.push(close);
    const form = BLOCK_FORMS.find(f => f.close === close);
    if (form) out.push(form.open);
  }
  return out;
}

/** Both delimiters of every form this file could carry, when the line cannot settle it. */
export function blockCommentDelimiters(filePath: string): readonly string[] {
  return delimitersFor(blockCommentClosers(filePath));
}

/**
 * Break every comment delimiter in `text`, so it can neither end nor open the
 * comment it is written into.
 *
 * A space after the delimiter's first character breaks the sequence and still shows
 * the reader what the text said. Each delimiter is applied over the whole string in
 * turn, closer before opener, so a delimiter that breaking another one CREATES is
 * caught: `*` + `/*` collapses to `* /*` on the closer pass and to `* / *` on the
 * opener pass. One function, because a second copy of this transform is how the two
 * passes that need it would come to disagree about what is neutralised.
 */
export function breakCommentDelimiters(text: string, delimiters: readonly string[]): string {
  return delimiters.reduce((s, d) => s.split(d).join(`${d.charAt(0)} ${d.slice(1)}`), text);
}

/** The comment form an annotation line sits in. */
export interface LineCommentForm {
  /** Sequences that would end this comment — empty for a line comment. */
  closers: readonly string[];
  /** Every delimiter a written description must not carry: each closer AND the opener it pairs with. */
  delimiters: readonly string[];
  /** The line opens AND closes its own comment, so a line added after it needs its own terminator. */
  selfClosing: boolean;
}

/**
 * The comment form of `lines[idx]`, derived from the SOURCE rather than guessed
 * from the path.
 *
 * Writing into a comment raises two questions and they have one answer: which
 * sequence would end this comment (so a description carrying it is neutralised),
 * and does this line close itself (so a line inserted after it must reopen and
 * close its own). The file extension answers neither reliably — the stripper
 * accepts `/* … *` + `/` in any file with no language gate, so the extension is
 * a proxy that is thinner than reality in one direction and wrong in the other.
 *
 * Read in order: the line's own opener settles it; a line-comment marker means
 * no closer at all; otherwise the line is a continuation, so look back for the
 * block that opened it; and only when even that is absent fall back to the
 * extension.
 */
export function commentFormAt(lines: readonly string[], idx: number, filePath: string): LineCommentForm {
  const asForm = (closers: readonly string[], selfClosing: boolean): LineCommentForm =>
    ({ closers, delimiters: delimitersFor(closers), selfClosing });
  const own = blockFormOpenedBy(lines[idx] ?? '');
  if (own) return asForm([own.close], closesItself(lines[idx], own));
  const trimmed = (lines[idx] ?? '').trimStart();
  if (LINE_MARKERS.some(m => trimmed.startsWith(m.prefix))) return asForm([], false);
  for (let i = idx - 1; i >= 0; i--) {
    const open = blockFormOpenedBy(lines[i]);
    if (open && !closesItself(lines[i], open)) return asForm([open.close], false);
  }
  return asForm(blockCommentClosers(filePath), false);
}

function blockFormOpenedBy(line: string): { open: string; close: string } | undefined {
  const trimmed = line.trimStart();
  return BLOCK_FORMS.find(f => trimmed.startsWith(f.open));
}

function closesItself(line: string, form: { open: string; close: string }): boolean {
  const body = line.trim();
  return body.length >= form.open.length + form.close.length && body.endsWith(form.close);
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
