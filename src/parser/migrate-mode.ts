/**
 * GuardLink — annotation mode migration (GL-507).
 *
 * Moving annotations between source comments and `.gal` sidecars. The whole
 * epic assumes a repo can change its mind about where annotations live; without
 * this, choosing external mode is a one-way door you can only walk through by
 * hand.
 *
 * The correctness proof is `annotation_hash`: the same logical model must hash
 * identically before and after, because the hash deliberately excludes line,
 * origin_file and parent_symbol — the only things a migration is allowed to
 * change. If a migration moves the hash, it changed the threat model, which is
 * the one thing it must never do.
 *
 * Annotation text is moved VERBATIM, never re-serialised from parsed objects.
 * Round-tripping through the parser's own formatter would quietly normalise
 * spacing, quoting and severity casing, and a migration that rewrites your
 * annotations while claiming to relocate them is not trustworthy.
 *
 * What counts as an annotation is the parser's answer, never a second guess:
 * the lines removed are exactly the lines that produced a model record, plus
 * the `-- "…"` continuations folded into them. Prose that merely begins with an
 * at-sign word (`@page`, `@media`, a JSDoc tag) is not in the model and is not
 * touched. With the annotations goes the layout that existed only to hold them —
 * the empty separator line, a comment left with nothing in it, one of the two
 * blank lines a removed comment sat between — so the source reads as if it had
 * never been annotated. Restoring writes a canonical layout back, and the
 * guarantee is that the EXTERNAL state round-trips byte for byte.
 *
 * Nothing is dropped quietly. An annotation that cannot be moved — it shares a
 * line with a comment delimiter, it is malformed, its sidecar already exists —
 * leaves its whole file untouched and is reported with file and line.
 *
 * @exposes #parser to #arbitrary-write [high] cwe:CWE-73 -- "Rewrites source files and creates sidecars across the project"
 * @mitigates #parser against #arbitrary-write using #path-validation -- "Only files already in the parsed model are touched; sidecar targets come from resolveGalPath, never from input"
 * @exposes #parser to #data-exposure [low] -- "Reads every annotated source file into memory"
 * @flows ThreatModel -> #parser via migrateAnnotationMode -- "Model drives which files are rewritten"
 * @flows #parser -> FileSystem via writeFileSync -- "Source rewrite and sidecar creation"
 * @audit #parser -- "Migration is destructive by nature — the dry-run path and the hash check are the safety net, and both should be exercised before this is trusted on a repo without clean version control"
 * @comment -- "Restoring a prefix is inferred from context (block comment vs line comment) rather than recorded in the .gal — recording it would put presentation data in the threat model"
 * @comment -- "A line that shares a comment opener or closer with an annotation is refused rather than rewritten: removing it whole takes the delimiter with it and leaves the file uncompilable"
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync, rmdirSync, statSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { stripCommentPrefix, commentStyleForExt } from './comment-strip.js';
import { annotationLineRoles } from './parse-file.js';
import { resolveGalPath, galPathFor, sourceFileForGal, ANNOTATIONS_DIR } from './gal-path.js';
import type { ParseDiagnostic, SourceLocation, ThreatModel } from '../types/index.js';

export type TargetMode = 'inline' | 'external';

export interface MigrateOptions {
  root: string;
  to: TargetMode;
  model: ThreatModel;
  /**
   * The diagnostics from the parse that produced `model`. A malformed
   * annotation is in these and not in the model, so without them a file whose
   * only annotations are malformed is never looked at, and stays behind
   * unreported in a repo that now claims to be external.
   */
  diagnostics?: readonly ParseDiagnostic[];
  dryRun?: boolean;
}

/** One annotation line that stayed where it was, and why. */
export interface Unmigrated {
  file: string;
  line: number;
  reason: string;
}

export interface MigrateResult {
  to: TargetMode;
  /** Source files whose annotations were removed (→external) or restored (→inline). */
  sourceFiles: string[];
  /** Sidecars created (→external) or deleted (→inline). */
  galFiles: string[];
  annotationsMoved: number;
  /** Files already in the target mode, so nothing to do. */
  alreadyThere: string[];
  /** Files with nothing to move, and why. Nothing in them was lost. */
  skipped: { file: string; reason: string }[];
  /**
   * Every annotation line that did not move, with its file, line and reason.
   * Non-empty means the migration is incomplete: the CLI lists each one and
   * exits non-zero rather than reporting success over them.
   */
  unmigrated: Unmigrated[];
}

/** Annotation lines restored directly above one line of the source. */
interface Block {
  /**
   * 1-indexed line of the source AS IT STANDS WITHOUT the block — the line the
   * block is restored above. That is what a sidecar's `@source line:` means
   * everywhere else (SPEC §5.4: the code line, not the annotation), and it is
   * the only coordinate that survives removing the block and its layout.
   */
  line: number;
  annotations: string[];  // verbatim annotation text, comment prefix stripped
}

/**
 * `.guardlink/definitions.*` never migrates.
 *
 * It holds `@asset`/`@threat`/`@control` declarations — the vocabulary the rest
 * of the model refers to by id, not annotations *on* code. There is no source
 * file for a sidecar to sit beside, and moving the definitions out of the file
 * every tool and every agent instruction points at would break the one lookup
 * everything else depends on.
 */
function isDefinitionsFile(file: string): boolean {
  return /(^|\/)\.guardlink\/definitions\.[^/]+$/.test(file.replaceAll('\\', '/'));
}

// ─── Reading comment layout ──────────────────────────────────────────

const BLOCK_PAIRS: ReadonlyArray<readonly [string, string]> = [['/*', '*/'], ['<!--', '-->'], ['{-', '-}'], ['(*', '*)']];
const OPENER_ONLY = /^\/\*+!?$/;   // `/*`, `/**`, `/*!` with nothing after
const CLOSER_ONLY = /^\*+\/$/;     // `*/`, `**/`

/** Past the last line, or on the empty string a trailing newline leaves. */
const isEof = (lines: readonly string[], i: number): boolean =>
  i >= lines.length || (i === lines.length - 1 && lines[i] === '');
const isBlank = (lines: readonly string[], i: number): boolean =>
  i >= 0 && !isEof(lines, i) && lines[i].trim() === '';

/** The marker of a line comment — `//`, `///`, `#`, `--` … — or null for any other line. */
function lineMarker(line: string | undefined): string | null {
  if (line === undefined) return null;
  const t = line.trimStart();
  if (t.startsWith('*') || BLOCK_PAIRS.some(([open]) => t.startsWith(open))) return null;
  const inner = stripCommentPrefix(line);
  return inner === null ? null : t.slice(0, t.length - inner.length).trim();
}

/** The text of a `*` continuation line inside a block comment, or null when the line is not one. */
function starContent(line: string | undefined): string | null {
  if (line === undefined) return null;
  const t = line.trim();
  if (!t.startsWith('*') || t.startsWith('*/') || CLOSER_ONLY.test(t)) return null;
  return t.slice(1).trim();
}

/**
 * How an annotation line is written, which decides what removing it means.
 *
 * - `line` — a line comment (`// @…`, `/// @…`, `# @…`); `marker` is its opener.
 * - `star` — a `* @…` continuation inside a block comment.
 * - `whole` — a comment that opens and closes on its own line (`/** @… *\/`).
 */
type Style = { kind: 'line'; marker: string } | { kind: 'star' } | { kind: 'whole' };

const sameStyle = (a: Style, b: Style): boolean =>
  a.kind === b.kind && (a.kind !== 'line' || a.marker === (b as { marker: string }).marker);

/**
 * The style of a line the parser read an annotation from, or why the line
 * cannot be removed whole.
 *
 * Removing a line takes everything on it. When a comment delimiter shares the
 * line — `/** @audit …` opening a block that continues below, `* @audit … *\/`
 * closing one — the delimiter goes too, and the file no longer compiles. That is
 * refused rather than rewritten: the fix is one keystroke for the author, and a
 * migration that edits around delimiters would be guessing at the host grammar.
 */
function styleOf(line: string): Style | { refused: string } {
  const t = line.trim();
  for (const [open, close] of BLOCK_PAIRS) {
    if (!t.startsWith(open)) continue;
    const at = t.indexOf(close, open.length);
    if (at !== -1 && at === t.length - close.length) return { kind: 'whole' };
    return {
      refused: at === -1
        ? `shares its line with the comment opener \`${open}\`, which removing the line would take with it — move the annotation onto a line of its own and re-run`
        : `shares its line with code after the comment's \`${close}\` — move the annotation onto a line of its own and re-run`,
    };
  }
  if (starContent(line) !== null) {
    return t.includes('*/')
      ? { refused: 'shares its line with the comment closer `*/`, which removing the line would take with it — move `*/` onto a line of its own and re-run' }
      : { kind: 'star' };
  }
  const marker = lineMarker(line);
  return marker !== null ? { kind: 'line', marker } : { refused: 'is not on a comment line migrate can remove' };
}

/**
 * What sits on one side of a removed run, read in the run's own comment style:
 * more of the same comment with text in it, an empty line of it, or the
 * comment's edge — its opener or closer, code, a blank line, another comment,
 * the start or end of the file.
 */
type Side = 'prose' | 'empty' | 'edge';

function sideAt(lines: readonly string[], i: number, style: Style, above: boolean): Side {
  if (i < 0 || isEof(lines, i)) return 'edge';
  if (style.kind === 'line') {
    if (lineMarker(lines[i]) !== style.marker) return 'edge';
    return stripCommentPrefix(lines[i])!.trim() === '' ? 'empty' : 'prose';
  }
  if (style.kind === 'star') {
    const c = starContent(lines[i]);
    if (c !== null) return c === '' ? 'empty' : 'prose';
    // `/** Summary.` opens the block with prose of its own.
    const t = lines[i].trim();
    return above && t.startsWith('/*') && !OPENER_ONLY.test(t) && !t.endsWith('*/') ? 'prose' : 'edge';
  }
  return 'edge';
}

const isCommentLine = (lines: readonly string[], i: number): boolean =>
  i >= 0 && !isEof(lines, i) && lines[i].trim() !== '' && stripCommentPrefix(lines[i]) !== null;

// ─── inline → external ───────────────────────────────────────────────

type Extraction =
  | { kind: 'refused'; refused: Unmigrated[] }
  | { kind: 'empty'; shields: number }
  | { kind: 'ok'; blocks: Block[]; stripped: string; annotationLines: number[] };

/**
 * Work out what leaves a source file: its annotation lines, and the layout that
 * only existed to hold them.
 *
 * **Which lines are annotations is the parser's answer** (`annotationLineRoles`).
 * Migrate used to decide with its own pattern — any comment beginning `@word` —
 * and the two disagreed in both directions. A comment beginning `@page margins…`
 * matched it, so it was deleted from source (one of them inside a string
 * literal, changing what the program prints) and parked in a sidecar where it
 * parses to nothing; `annotation_hash` cannot see a line that was never in the
 * model, so the run reported success. And a `-- "…"` continuation did NOT match,
 * so it was left behind, orphaned from the description it belonged to.
 *
 * `@shield` markers stay, in either direction: they delimit a REGION OF SOURCE
 * TEXT, and `@shield:begin`/`@shield:end` mean nothing outside the file whose
 * lines they bracket. Externalising them strips the protection from the source
 * that needed it. The parser skips everything between them, so the examples
 * they protect are never moved either — moving them would start them parsing as
 * real records.
 *
 * **The layout goes with the annotations.** Removing exactly the annotation
 * lines left their scaffolding behind: the empty `///` or ` *` line that set
 * them off from the prose, a `/**` … ` *\/` with nothing between, and two blank
 * lines where a standalone comment had sat between them. For each removed run:
 *
 * - between prose and prose: one separator survives if there was any;
 * - prose on one side only: every adjacent empty comment line goes;
 * - no prose on either side: the comment is gone, so its empty lines, its
 *   opener and closer go too, and of the blank lines it sat between only one
 *   is kept (none at the start or end of the file).
 *
 * `restoreLines` writes the inverse of each rule, so stripping a restored file
 * reproduces the stripped file exactly.
 */
function planExtraction(file: string, text: string): Extraction {
  const lines = text.split('\n');
  const roles = [...annotationLineRoles(text, file)].sort((a, b) => a[0] - b[0]);

  const refused: Unmigrated[] = [];
  const styles = new Map<number, Style>();
  const annotationLines: number[] = [];
  let shields = 0;
  for (const [lineNum, role] of roles) {
    if (role === 'shield') { shields++; continue; }
    const style = styleOf(lines[lineNum - 1]);
    if ('refused' in style) { refused.push({ file, line: lineNum, reason: style.refused }); continue; }
    if (role === 'malformed') {
      refused.push({ file, line: lineNum, reason: 'is a malformed annotation, so it is not in the model and cannot be moved — `guardlink validate` names the problem; fix it and re-run' });
      continue;
    }
    styles.set(lineNum - 1, style);
    if (role === 'annotation') annotationLines.push(lineNum);
  }
  if (refused.length > 0) return { kind: 'refused', refused };
  if (styles.size === 0) return { kind: 'empty', shields };

  const dead = new Set<number>(styles.keys());
  const prevAlive = (i: number): number => { let j = i - 1; while (j >= 0 && dead.has(j)) j--; return j; };
  const nextAlive = (i: number): number => { let j = i + 1; while (j < lines.length && dead.has(j)) j++; return j; };

  // Runs of moved lines. Two runs of one style with only empty lines of that
  // style between them are one run — the empty lines were separators between
  // annotation groups, and nothing is left for them to separate.
  const runs: { first: number; last: number; style: Style; lines: number[] }[] = [];
  for (const i of [...styles.keys()].sort((a, b) => a - b)) {
    const style = styles.get(i)!;
    const prev = runs.at(-1);
    if (prev && prev.last === i - 1) {
      if (!sameStyle(prev.style, style)) prev.style = { kind: 'whole' };
      prev.last = i; prev.lines.push(i);
      continue;
    }
    if (prev && prev.style.kind !== 'whole' && sameStyle(prev.style, style)) {
      const gap = Array.from({ length: i - prev.last - 1 }, (_, k) => prev.last + 1 + k);
      if (gap.every(g => sideAt(lines, g, style, false) === 'empty')) {
        for (const g of gap) dead.add(g);
        prev.last = i; prev.lines.push(i);
        continue;
      }
    }
    runs.push({ first: i, last: i, style, lines: [i] });
  }

  for (const run of runs) {
    const { style } = run;
    const empties: number[] = [];
    let u = prevAlive(run.first);
    while (sideAt(lines, u, style, true) === 'empty') { empties.push(u); u = prevAlive(u); }
    let d = nextAlive(run.last);
    while (sideAt(lines, d, style, false) === 'empty') { empties.push(d); d = nextAlive(d); }
    const above = sideAt(lines, u, style, true);
    const below = sideAt(lines, d, style, false);

    if (above === 'prose' && below === 'prose') {
      for (const e of empties.sort((a, b) => a - b).slice(1)) dead.add(e);
      continue;
    }
    for (const e of empties) dead.add(e);
    if (above === 'prose' || below === 'prose') continue;

    // Nothing of the comment is left.
    if (style.kind === 'star') {
      if (u < 0 || !OPENER_ONLY.test(lines[u].trim()) || isEof(lines, d) || !CLOSER_ONLY.test(lines[d].trim())) continue;
      dead.add(u); dead.add(d);
      u = prevAlive(u); d = nextAlive(d);
    } else if (style.kind === 'whole' && (isCommentLine(lines, u) || isCommentLine(lines, d))) {
      continue;
    }
    if (isBlank(lines, d) && (u < 0 || isBlank(lines, u))) dead.add(d);
    else if (isEof(lines, d) && isBlank(lines, u)) dead.add(u);
  }

  // Each run's line in the stripped file is the first surviving line after it —
  // or, past the last one, the stripped file's own end, which is not always the
  // original's: removing a final line that had no newline after it makes the
  // newline before it the file's last.
  const kept = lines.filter((_, i) => !dead.has(i));
  const endLine = kept.at(-1) === '' ? kept.length : kept.length + 1;
  const strippedIndex = new Map<number, number>();
  let n = 0;
  for (let i = 0; i <= lines.length; i++) {
    strippedIndex.set(i, n);
    if (i < lines.length && !dead.has(i)) n++;
  }
  const blocks: Block[] = [];
  for (const run of runs) {
    const after = nextAlive(run.last);
    const line = isEof(lines, after) ? endLine : strippedIndex.get(after)! + 1;
    const annotations = run.lines.map(i => stripCommentPrefix(lines[i])!.trim());
    const prev = blocks.at(-1);
    // Runs a removal has left touching are restored as one, so they are one block.
    if (prev && prev.line === line) prev.annotations.push(...annotations);
    else blocks.push({ line, annotations });
  }

  return { kind: 'ok', blocks, stripped: kept.join('\n'), annotationLines };
}

/**
 * Serialise blocks as a `.gal` file.
 *
 * `symbol:` is deliberately absent: an inline annotation carries no symbol, and
 * inventing one from a nearby declaration would fabricate an anchor that
 * `guardlink reanchor` would then treat as authoritative.
 */
function serialiseGal(file: string, blocks: Block[]): string {
  return blocks
    .map(b => [`@source file:${file} line:${b.line}`, ...b.annotations].join('\n'))
    .join('\n\n') + '\n';
}

// ─── external → inline ───────────────────────────────────────────────

interface GalBlock {
  sourceFile: string;
  line: number;
  /** Annotation lines, and the `-- "…"` continuations that extend them. */
  annotations: string[];
  /** The 1-indexed line of the sidecar each entry of `annotations` came from. */
  galLines: number[];
}

/** Parse a `.gal` back into its blocks, keeping annotation text verbatim. */
export function readGalBlocks(text: string): GalBlock[] {
  const blocks: GalBlock[] = [];
  let current: GalBlock | null = null;

  for (const [i, raw] of text.split('\n').entries()) {
    const line = raw.trim();
    if (line.startsWith('@source')) {
      const file = /\bfile:(\S+)/.exec(line)?.[1];
      const at = /\bline:(\d+)/.exec(line)?.[1];
      current = file ? { sourceFile: file, line: at ? Number(at) : 1, annotations: [], galLines: [] } : null;
      if (current) blocks.push(current);
    } else if ((line.startsWith('@') || line.startsWith('--')) && current) {
      // A continuation belongs to the annotation above it; dropping it on the way
      // back would shorten that annotation's description and move the hash.
      current.annotations.push(line);
      current.galLines.push(i + 1);
    }
    // Blank lines separate blocks but do not end one on their own — a @source
    // header is what starts the next.
  }

  return blocks;
}

/**
 * How a block written in `style` would sit at `lines[index]`, read the way
 * `planExtraction` reads it: the layout to write around it, or null when no
 * layout in this style would strip back to these exact lines.
 *
 * Every hole `planExtraction` leaves has one of these four shapes in the style
 * of the run it removed, so restoring in a style that fits is what makes
 * stripping a restored file reproduce the stripped file byte for byte.
 */
function fitAt(lines: readonly string[], index: number, style: Style): 'before' | 'after' | 'none' | null {
  let u = index - 1;
  let empties = 0;
  while (sideAt(lines, u, style, true) === 'empty') { empties++; u--; }
  let d = index;
  while (sideAt(lines, d, style, false) === 'empty') { empties++; d++; }
  const above = sideAt(lines, u, style, true);
  const below = sideAt(lines, d, style, false);
  if (above === 'prose' && below === 'prose') return empties <= 1 ? 'none' : null;
  if (empties > 0) return null;
  if (above === 'prose') return 'before';
  if (below === 'prose') return 'after';
  return null;
}

/**
 * The lines to insert above `lines[index]` to restore one block.
 *
 * The comment form is inferred rather than recorded. The alternative — storing
 * the literal prefix in the `.gal` — puts presentation data in the threat
 * model, and would make two identical annotations differ because one lived in a
 * Javadoc block. The layout is the canonical one `planExtraction` removes: a
 * separator between prose and the annotations that follow or precede it, and
 * only the blank lines that keep removal from collapsing two into one. So
 * inline → external → inline can change layout, once, and external → inline →
 * external reproduces every byte.
 */
function restoreLines(lines: readonly string[], index: number, annotations: string[], ext: string): string[] {
  const shape = (prefix: string, fit: 'before' | 'after' | 'none' | null): string[] => {
    const body = annotations.map(a => `${prefix}${a}`);
    const separator = prefix.trimEnd();
    if (fit === 'before') return [separator, ...body];
    if (fit === 'after') return [...body, separator];
    return body;
  };
  const indentOf = (line: string | undefined): string => /^\s*/.exec(line ?? '')![0];

  // Inside a block comment: scan back for an unterminated opener.
  for (let i = index - 1; i >= 0 && i > index - 200; i--) {
    const t = lines[i].trim();
    if (t.endsWith('*/')) break;
    if (t.startsWith('/*')) {
      // Copy a sibling continuation line's exact indentation where there is one,
      // so restored lines align with the block they rejoin.
      let prefix = `${indentOf(lines[i])} * `;
      for (let j = i + 1; j < lines.length && j < index + 2; j++) {
        const m = /^(\s*\*\s?)/.exec(lines[j]);
        if (m && !lines[j].trim().startsWith('*/')) { prefix = m[1].endsWith(' ') ? m[1] : m[1] + ' '; break; }
      }
      return shape(prefix, fitAt(lines, index, { kind: 'star' }));
    }
  }

  // Next to a line comment: join it, in its marker — the one below first, since
  // annotations lead the comment they describe.
  const atMarker = isEof(lines, index) ? null : lineMarker(lines[index]);
  const aboveMarker = index > 0 ? lineMarker(lines[index - 1]) : null;
  for (const [marker, ref] of [[atMarker, lines[index]], [aboveMarker, lines[index - 1]]] as const) {
    if (marker === null) continue;
    const fit = fitAt(lines, index, { kind: 'line', marker });
    if (fit !== null) return shape(`${indentOf(ref)}${marker} `, fit);
  }

  // A comment of its own, indented like the code it sits above. Its marker must
  // differ from any comment it touches, or stripping would read the two as one.
  let marker = commentStyleForExt(ext);
  while (marker === atMarker || marker === aboveMarker) marker += marker.slice(-1);
  const at = isEof(lines, index) ? '' : lines[index];
  const indent = indentOf(at.trim() === '' || /^[\])}]/.test(at.trim()) ? lines[index - 1] : at);
  const body = annotations.map(a => `${indent}${marker} ${a}`);
  if (isBlank(lines, index) && (index === 0 || isBlank(lines, index - 1))) return [...body, ''];
  if (isEof(lines, index) && isBlank(lines, index - 1)) return ['', ...body];
  return body;
}

// ─── Driver ──────────────────────────────────────────────────────────

/**
 * Move a project's annotations into the requested mode.
 *
 * Existing repos are not migrated implicitly — nothing calls this except the
 * explicit `guardlink migrate` command.
 */
export function migrateAnnotationMode(options: MigrateOptions): MigrateResult {
  const { root, to, model, diagnostics = [], dryRun = false } = options;
  const result: MigrateResult = {
    to, sourceFiles: [], galFiles: [], annotationsMoved: 0, alreadyThere: [], skipped: [], unmigrated: [],
  };

  // Which files hold annotations, and in which mode? origin_file is set only for
  // annotations that came from a sidecar, which is exactly the distinction.
  const inlineLines = new Map<string, Set<number>>();
  const galFiles = new Set<string>();
  for (const loc of allLocations(model)) {
    if (loc.origin_file) galFiles.add(loc.origin_file);
    else if (!isDefinitionsFile(loc.file)) {
      if (!inlineLines.has(loc.file)) inlineLines.set(loc.file, new Set());
      inlineLines.get(loc.file)!.add(loc.line);
    }
  }
  for (const d of diagnostics) {
    if (d.code !== 'malformed-annotation' || !d.file || d.line === undefined) continue;
    if (/\.gal$/i.test(d.file) || isDefinitionsFile(d.file)) continue;
    if (!inlineLines.has(d.file)) inlineLines.set(d.file, new Set());
    inlineLines.get(d.file)!.add(d.line);
  }
  const unmovedAt = (file: string, lineNums: Iterable<number>, reason: string): void => {
    for (const line of [...lineNums].sort((a, b) => a - b)) result.unmigrated.push({ file, line, reason });
  };

  if (to === 'external') {
    for (const file of [...galFiles].sort()) result.alreadyThere.push(file);

    for (const file of [...inlineLines.keys()].sort()) {
      const abs = join(root, file);
      if (!existsSync(abs)) {
        unmovedAt(file, inlineLines.get(file)!, 'file no longer exists');
        continue;
      }
      const plan = planExtraction(file, readFileSync(abs, 'utf-8'));
      if (plan.kind === 'refused') {
        // The whole file stays as it is. Moving the rest would leave a sidecar
        // behind that the re-run, once the author has fixed these lines, refuses
        // to overwrite.
        result.unmigrated.push(...plan.refused);
        continue;
      }
      if (plan.kind === 'empty') {
        if (plan.shields > 0) {
          result.skipped.push({ file, reason: `only @shield markers here, and those stay in source (${plan.shields} left in place)` });
        } else {
          unmovedAt(file, inlineLines.get(file)!, 'the parsed model places an annotation here, but the file no longer holds it — re-run');
        }
        continue;
      }

      const galRel = galPathFor(file);
      const galAbs = resolveGalPath(root, file);
      if (existsSync(galAbs)) {
        unmovedAt(file, plan.annotationLines, `${galRel} already exists — refusing to overwrite. Move or delete it and re-run.`);
        continue;
      }

      if (!dryRun) {
        mkdirSync(dirname(galAbs), { recursive: true });
        writeFileSync(galAbs, serialiseGal(file, plan.blocks));
        writeFileSync(abs, plan.stripped);
      }
      result.sourceFiles.push(file);
      result.galFiles.push(galRel);
      result.annotationsMoved += plan.annotationLines.length;
    }
    return result;
  }

  // ── → inline ──
  for (const file of [...inlineLines.keys()].sort()) result.alreadyThere.push(file);

  for (const gal of [...galFiles].sort()) {
    const galAbs = join(root, gal);
    if (!existsSync(galAbs)) {
      result.skipped.push({ file: gal, reason: 'sidecar no longer exists' });
      continue;
    }
    const blocks = readGalBlocks(readFileSync(galAbs, 'utf-8'));
    if (blocks.length === 0) {
      result.skipped.push({ file: gal, reason: 'no @source blocks found' });
      continue;
    }

    // A sidecar may in principle name several source files; group by target.
    const byFile = new Map<string, GalBlock[]>();
    for (const b of blocks) {
      if (!byFile.has(b.sourceFile)) byFile.set(b.sourceFile, []);
      byFile.get(b.sourceFile)!.push(b);
    }

    // If the sidecar sits at the conventional path, its own name says which file
    // it belongs to; a block naming a different one is a mistake worth reporting.
    const conventional = sourceFileForGal(gal);
    let failed = false;

    for (const [srcFile, srcBlocks] of byFile) {
      const refuse = (reason: string): void => {
        unmovedAt(gal, srcBlocks.flatMap(b => b.galLines), reason);
        failed = true;
      };
      if (conventional && srcFile !== conventional) {
        refuse(`block names ${srcFile} but the sidecar path says ${conventional} — resolve by hand`);
        continue;
      }
      const abs = join(root, srcFile);
      if (!existsSync(abs)) {
        refuse(`${srcFile} no longer exists`);
        continue;
      }

      const ext = extname(srcFile);
      const lines = readFileSync(abs, 'utf-8').split('\n');

      // Blocks naming the same line are one block. Bottom-up, so each insertion
      // leaves the lines above it — the ones every remaining `line:` counts — as
      // they were.
      const merged: GalBlock[] = [];
      for (const b of [...srcBlocks].sort((x, y) => x.line - y.line)) {
        const prev = merged.at(-1);
        if (prev && prev.line === b.line) prev.annotations.push(...b.annotations);
        else merged.push({ ...b, annotations: [...b.annotations] });
      }
      for (const b of merged.reverse()) {
        const index = Math.min(Math.max(b.line - 1, 0), lines.length);
        lines.splice(index, 0, ...restoreLines(lines, index, b.annotations, ext));
        result.annotationsMoved += b.annotations.filter(a => a.startsWith('@')).length;
      }

      if (!dryRun) writeFileSync(abs, lines.join('\n'));
      result.sourceFiles.push(srcFile);
    }

    if (!failed) {
      if (!dryRun) rmSync(galAbs, { force: true });
      result.galFiles.push(gal);
    }
  }

  if (!dryRun && to === 'inline') pruneEmptyDirs(join(root, ANNOTATIONS_DIR));
  return result;
}

/**
 * Annotations a model still holds in the mode a migration was meant to leave —
 * the check that makes a migration that dropped something say so.
 *
 * Asked of the model parsed AFTER the migration, so it reports what is on disk,
 * whatever the reason: `annotation_hash` holds across a migration that moved
 * nothing, because an annotation left where it was still parses. `@shield`
 * markers are excluded; they stay inline in both modes.
 */
export function annotationsLeftBehind(model: ThreatModel, to: TargetMode): { file: string; line: number }[] {
  const seen = new Map<string, { file: string; line: number }>();
  for (const loc of allLocations(model, new Set(['shields']))) {
    const at = to === 'external'
      ? (loc.origin_file || isDefinitionsFile(loc.file) ? null : { file: loc.file, line: loc.line })
      : (loc.origin_file ? { file: loc.origin_file, line: loc.origin_line ?? loc.line } : null);
    if (at) seen.set(`${at.file}:${at.line}`, at);
  }
  return [...seen.values()].sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

/**
 * Every annotation location in the model, from every record list it holds.
 *
 * Read off the model's shape rather than from a list of record kinds. A list
 * here was kept by hand and fell behind twice: once for `@actor`/`@entitles`,
 * and again for `@agents`, `@reaches`, `@effects` and `@gates`, so a file whose
 * only annotations were those was never migrated. Nothing reported it — they
 * stayed inline, still parsed, and `annotation_hash` held.
 */
function allLocations(model: ThreatModel, skip: ReadonlySet<string> = new Set()): SourceLocation[] {
  const out: SourceLocation[] = [];
  for (const [key, value] of Object.entries(model)) {
    if (skip.has(key) || !Array.isArray(value)) continue;
    for (const item of value) {
      const location = (item as { location?: SourceLocation } | null)?.location;
      if (location && typeof location.file === 'string') out.push(location);
    }
  }
  return out;
}

/** Leave no empty scaffolding behind after a migration to inline. */
function pruneEmptyDirs(dir: string): void {
  if (!existsSync(dir)) return;
  const walk = (d: string): boolean => {
    let empty = true;
    for (const entry of readdirSync(d)) {
      const p = join(d, entry);
      if (statSync(p).isDirectory()) {
        if (!walk(p)) empty = false;
      } else {
        empty = false;
      }
    }
    if (empty) rmdirSync(d);
    return empty;
  };
  walk(dir);
}
