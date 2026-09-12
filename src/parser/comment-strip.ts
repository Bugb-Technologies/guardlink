import { extname } from 'node:path';
import { COMMENT_STYLE_BY_EXT } from './languages.js';

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
 * sequence that ends it and with the marker a line INSIDE it must begin with.
 * One definition: the stripper's forms, the closers a writer must neutralise and
 * the prefix a writer must use to stay inside one are the same set, and a set
 * written twice drifts.
 *
 * Only the C-family has a continuation marker — the Javadoc `*`, which the
 * stripper reads a few lines above. The other three have none, and that is not a
 * gap: `stripCommentPrefix` recognises `<!-- … -->`, `{- … -}` and `(* … *)` only
 * as COMPLETE single-line comments, so an annotation on an open-ended opener line
 * of those forms is not a comment to the parser and never reaches the model. The
 * `null` is the honest answer to a question that cannot arise, rather than a hole.
 */
const BLOCK_FORMS: ReadonlyArray<{ open: string; close: string; continuation: string | null }> = [
  { open: '/*', close: '*/', continuation: '* ' },
  { open: '<!--', close: '-->', continuation: null },
  { open: '{-', close: '-}', continuation: null },
  { open: '(*', close: '*)', continuation: null },
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
 * comment ends at a newline, and a written description is already one line. That
 * is why Python, Ruby, Bash, YAML, Erlang, Ada, LaTeX, INI and Batch are absent
 * and must stay absent: they are scanned, and they have no block form to break.
 *
 * **This table has to keep pace with the scan set.** The entry exists so a
 * description written into a claim's comment cannot end that comment; a claim can
 * only exist in a file the parser opens; so every extension in
 * `parser/languages.ts` whose language HAS a block form needs a row here, and a
 * language added to the scan set with a block form and no row is a comment-escape
 * that is reachable the moment someone annotates such a file.
 *
 * `.mjs` `.cjs` `.cxx` `.hh` `.m` `.mm` `.htm` `.pp` `.vhd` `.vhdl` were added
 * for exactly that reason: widening the scan set to every language §2.9 names
 * made claims possible in files this table did not cover. `.scss`, `.less` and
 * `.vue` are the other direction — listed but not scanned, which costs nothing
 * and is left alone, because a safety table wider than the scan set is safe and a
 * thinner one is not. `tests/scanned-languages.test.ts` pins the direction that
 * matters.
 */
const BLOCK_CLOSERS: Readonly<Record<string, readonly string[]>> = {
  '.ts': ['*/'], '.tsx': ['*/'], '.js': ['*/'], '.jsx': ['*/'], '.mts': ['*/'], '.cts': ['*/'],
  '.mjs': ['*/'], '.cjs': ['*/'],
  '.java': ['*/'], '.c': ['*/'], '.h': ['*/'], '.cpp': ['*/'], '.cc': ['*/'], '.hpp': ['*/'],
  '.cxx': ['*/'], '.hh': ['*/'],
  '.cs': ['*/'], '.go': ['*/'], '.rs': ['*/'], '.swift': ['*/'], '.kt': ['*/'], '.kts': ['*/'],
  '.scala': ['*/'], '.dart': ['*/'], '.php': ['*/'],
  '.m': ['*/'], '.mm': ['*/'],
  '.css': ['*/'], '.scss': ['*/'], '.less': ['*/'],
  '.sql': ['*/'], '.tf': ['*/'], '.hcl': ['*/'],
  '.vhd': ['*/'], '.vhdl': ['*/'],
  '.hs': ['-}'],
  '.ml': ['*)'], '.mli': ['*)'], '.pas': ['*)'], '.pp': ['*)'],
  '.html': ['-->', '*/'], '.htm': ['-->', '*/'], '.xml': ['-->'], '.svg': ['-->', '*/'],
  '.vue': ['-->', '*/'],
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
  /**
   * The line OPENS a block comment and does not close it, so its own prefix IS an
   * opener and a line inserted after it must not reuse that prefix.
   *
   * Copying it opens a SECOND comment: where block comments nest (Rust, Swift,
   * Kotlin, Scala, Dart, Haskell, OCaml) the block's own closer then closes only the
   * inner one and the file runs on inside an unterminated comment, silently dropping
   * the declaration it documents and everything below it from the compile. No
   * report-controlled text is needed to reach it — an `@exposes` on a `/**` opening
   * line is enough. Reproducing the closer instead is not the answer: balanced inside
   * a nesting host, it ends the OUTER block early in a non-nesting one.
   */
  opensUnclosedBlock: boolean;
  /** The marker a line inserted inside this form must begin with, or null when the form has none a reader could strip. */
  continuation: string | null;
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
  const asForm = (closers: readonly string[], selfClosing: boolean, opensUnclosedBlock = false): LineCommentForm =>
    ({ closers, delimiters: delimitersFor(closers), selfClosing, opensUnclosedBlock, continuation: continuationFor(closers) });
  const own = blockFormOpenedBy(lines[idx] ?? '');
  if (own) {
    const closes = closesItself(lines[idx], own);
    return asForm([own.close], closes, !closes);
  }
  const trimmed = (lines[idx] ?? '').trimStart();
  if (LINE_MARKERS.some(m => trimmed.startsWith(m.prefix))) return asForm([], false);
  for (let i = idx - 1; i >= 0; i--) {
    const open = blockFormOpenedBy(lines[i]);
    if (open && !closesItself(lines[i], open)) return asForm([open.close], false);
  }
  return asForm(blockCommentClosers(filePath), false);
}

/** The first continuation marker among these closers' forms, or null when none has one. */
function continuationFor(closers: readonly string[]): string | null {
  for (const close of closers) {
    const form = BLOCK_FORMS.find(f => f.close === close);
    if (form?.continuation) return form.continuation;
  }
  return null;
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
 * The comment marker a *writer* should use for this file's language.
 *
 * Used for multi-line continuation detection, and by `guardlink review` and
 * `guardlink migrate` when there is no neighbouring comment whose style they
 * can copy. Reading never depends on it — `stripCommentPrefix` tries every
 * recognised opener against every line.
 *
 * Answers from `COMMENT_STYLE_BY_EXT`, the one list that also decides which
 * files the scan opens. This was a second, drifted copy of that table: it knew
 * `.php` was not in it, `.pyi` was not in it, and `.ada` was in it under an
 * extension Ada does not use (`.adb`/`.ads`).
 *
 * `//` remains the fallback for an unknown extension, which is what the
 * majority of source files in circulation write.
 */
export function commentStyleForExt(ext: string): string {
  return COMMENT_STYLE_BY_EXT[ext.toLowerCase()] ?? '//';
}
