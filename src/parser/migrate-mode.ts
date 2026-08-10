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
 * Only annotation lines are removed from source; surrounding comment structure
 * is left exactly as it was. That is what makes the round trip reproduce the
 * original file rather than an equivalent one.
 *
 * @exposes #parser to #arbitrary-write [high] cwe:CWE-73 -- "Rewrites source files and creates sidecars across the project"
 * @mitigates #parser against #arbitrary-write using #path-validation -- "Only files already in the parsed model are touched; sidecar targets come from resolveGalPath, never from input"
 * @exposes #parser to #data-exposure [low] -- "Reads every annotated source file into memory"
 * @flows ThreatModel -> #parser via migrateAnnotationMode -- "Model drives which files are rewritten"
 * @flows #parser -> FileSystem via writeFileSync -- "Source rewrite and sidecar creation"
 * @audit #parser -- "Migration is destructive by nature — the dry-run path and the hash check are the safety net, and both should be exercised before this is trusted on a repo without clean version control"
 * @comment -- "Restoring a prefix is inferred from context (block comment vs line comment) rather than recorded in the .gal — recording it would put presentation data in the threat model"
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync, rmdirSync, statSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { stripCommentPrefix, commentStyleForExt } from './comment-strip.js';
import { resolveGalPath, galPathFor, sourceFileForGal, ANNOTATIONS_DIR } from './gal-path.js';
import type { ThreatModel } from '../types/index.js';

export type TargetMode = 'inline' | 'external';

export interface MigrateOptions {
  root: string;
  to: TargetMode;
  model: ThreatModel;
  dryRun?: boolean;
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
  /** Files that could not be migrated, with the reason. */
  skipped: { file: string; reason: string }[];
}

/** A run of consecutive annotation lines sharing one anchor. */
interface Block {
  line: number;           // 1-indexed physical line of the first annotation
  annotations: string[];  // verbatim annotation text, comment prefix stripped
}

const isAnnotation = (inner: string | null): boolean =>
  inner !== null && /^@[a-z][a-z-]*(\s|:|$)/i.test(inner.trim());

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

// ─── inline → external ───────────────────────────────────────────────

/**
 * `@shield` never migrates, in either direction.
 *
 * It is not a statement about a symbol — it delimits a REGION OF SOURCE TEXT,
 * and `@shield:begin`/`@shield:end` mean nothing outside the file whose lines
 * they bracket. Externalising the pair strips the protection from the source
 * that needed it and leaves the range pinned to line numbers the migration
 * itself just changed. Measured on this repo: migrating them silently unshielded
 * the example annotations in src/init/templates.ts, which is precisely the
 * failure @shield exists to prevent.
 *
 * So shields stay inline in both modes. That is not an exception to external
 * mode; it is what external mode means — annotations move, source markers do not.
 */
const isShield = (inner: string): boolean => /^@shield\b/i.test(inner.trim());

/** Contiguous runs of annotation lines in a source file. */
function inlineBlocks(text: string): { blocks: Block[]; annotatedLines: Set<number>; shields: number } {
  const lines = text.split('\n');
  const blocks: Block[] = [];
  const annotatedLines = new Set<number>();
  let current: Block | null = null;
  let shields = 0;
  let shielded = false;

  for (const [i, line] of lines.entries()) {
    if (isAnnotation(stripCommentPrefix(line))) {
      const inner = stripCommentPrefix(line)!.trim();
      if (isShield(inner)) {
        // Left in place, and it breaks the run: annotations either side of a
        // shield marker are not contiguous once the marker stays behind.
        if (/^@shield:begin\b/i.test(inner)) shielded = true;
        else if (/^@shield:end\b/i.test(inner)) shielded = false;
        shields++;
        current = null;
        continue;
      }
      // Everything between begin and end is excluded from parsing — usually
      // example annotations in documentation strings. Extracting them into a
      // sidecar takes them OUT of the region protecting them, so they start
      // parsing as real records. Measured on this repo: 38 fabricated
      // annotations, every one an example from a prompt template.
      if (shielded) { current = null; continue; }
      annotatedLines.add(i + 1);
      if (current && current.line + current.annotations.length === i + 1) {
        current.annotations.push(inner);
      } else {
        current = { line: i + 1, annotations: [inner] };
        blocks.push(current);
      }
    } else {
      current = null;
    }
  }

  return { blocks, annotatedLines, shields };
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
  annotations: string[];
}

/** Parse a `.gal` back into its blocks, keeping annotation text verbatim. */
export function readGalBlocks(text: string): GalBlock[] {
  const blocks: GalBlock[] = [];
  let current: GalBlock | null = null;

  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('@source')) {
      const file = /\bfile:(\S+)/.exec(line)?.[1];
      const at = /\bline:(\d+)/.exec(line)?.[1];
      current = file ? { sourceFile: file, line: at ? Number(at) : 1, annotations: [] } : null;
      if (current) blocks.push(current);
    } else if (line.startsWith('@') && current) {
      current.annotations.push(line);
    } else if (line === '') {
      // Blank lines separate blocks but do not end one on their own — a @source
      // header is what starts the next.
    }
  }

  return blocks;
}

/**
 * Work out how to comment an annotation line being restored at `index`.
 *
 * Inferred rather than recorded. The alternative — storing the literal prefix
 * in the `.gal` — puts presentation data in the threat model, and would make
 * two identical annotations differ because one lived in a Javadoc block.
 */
function prefixFor(lines: string[], index: number, ext: string): string {
  // Inside a block comment? Scan back for an unterminated opener.
  for (let i = index - 1; i >= 0 && i > index - 200; i--) {
    const t = lines[i].trim();
    if (t.endsWith('*/') || t.endsWith('-}') || t.endsWith('*)')) break;
    if (t.startsWith('/*') || t.startsWith('{-') || t.startsWith('(*')) {
      // Copy a sibling continuation line's exact indentation where there is one,
      // so restored lines align with the block they rejoin.
      for (let j = i + 1; j < lines.length && j < index + 2; j++) {
        const m = /^(\s*\*\s?)/.exec(lines[j]);
        if (m && !lines[j].trim().startsWith('*/')) return m[1].endsWith(' ') ? m[1] : m[1] + ' ';
      }
      const indent = /^\s*/.exec(lines[i])![0];
      return `${indent} * `;
    }
  }
  const indent = /^\s*/.exec(lines[index] ?? '')![0];
  return `${indent}${commentStyleForExt(ext)} `;
}

// ─── Driver ──────────────────────────────────────────────────────────

/**
 * Move a project's annotations into the requested mode.
 *
 * Existing repos are not migrated implicitly — nothing calls this except the
 * explicit `guardlink migrate` command.
 */
export function migrateAnnotationMode(options: MigrateOptions): MigrateResult {
  const { root, to, model, dryRun = false } = options;
  const result: MigrateResult = {
    to, sourceFiles: [], galFiles: [], annotationsMoved: 0, alreadyThere: [], skipped: [],
  };

  // Which files hold annotations, and in which mode? origin_file is set only for
  // annotations that came from a sidecar, which is exactly the distinction.
  const inlineFiles = new Set<string>();
  const galFiles = new Set<string>();
  for (const rel of allLocations(model)) {
    if (rel.origin_file) galFiles.add(rel.origin_file);
    else if (!isDefinitionsFile(rel.file)) inlineFiles.add(rel.file);
  }

  if (to === 'external') {
    for (const file of [...galFiles].sort()) result.alreadyThere.push(file);

    for (const file of [...inlineFiles].sort()) {
      const abs = join(root, file);
      if (!existsSync(abs)) {
        result.skipped.push({ file, reason: 'file no longer exists' });
        continue;
      }
      const text = readFileSync(abs, 'utf-8');
      const { blocks, annotatedLines, shields } = inlineBlocks(text);
      if (blocks.length === 0) {
        result.skipped.push({
          file,
          reason: shields > 0
            ? `only @shield markers here, and those stay in source (${shields} left in place)`
            : 'no annotation lines found in the file itself',
        });
        continue;
      }

      const galRel = galPathFor(file);
      const galAbs = resolveGalPath(root, file);
      if (existsSync(galAbs)) {
        result.skipped.push({
          file,
          reason: `${galRel} already exists — refusing to overwrite. Move or delete it and re-run.`,
        });
        continue;
      }

      const stripped = text.split('\n').filter((_, i) => !annotatedLines.has(i + 1)).join('\n');

      if (!dryRun) {
        mkdirSync(dirname(galAbs), { recursive: true });
        writeFileSync(galAbs, serialiseGal(file, blocks));
        writeFileSync(abs, stripped);
      }
      result.sourceFiles.push(file);
      result.galFiles.push(galRel);
      result.annotationsMoved += blocks.reduce((n, b) => n + b.annotations.length, 0);
    }
    return result;
  }

  // ── → inline ──
  for (const file of [...inlineFiles].sort()) result.alreadyThere.push(file);

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
      if (conventional && srcFile !== conventional) {
        result.skipped.push({
          file: gal,
          reason: `block names ${srcFile} but the sidecar path says ${conventional} — resolve by hand`,
        });
        failed = true;
        continue;
      }
      const abs = join(root, srcFile);
      if (!existsSync(abs)) {
        result.skipped.push({ file: gal, reason: `${srcFile} no longer exists` });
        failed = true;
        continue;
      }

      const ext = extname(srcFile);
      const lines = readFileSync(abs, 'utf-8').split('\n');

      // Ascending, so each insertion shifts only the anchors after it — and the
      // recorded line is where the annotation sat BEFORE it was extracted, so
      // inserting at that index restores the original position exactly.
      for (const b of [...srcBlocks].sort((x, y) => x.line - y.line)) {
        const index = Math.min(Math.max(b.line - 1, 0), lines.length);
        const prefix = prefixFor(lines, index, ext);
        lines.splice(index, 0, ...b.annotations.map(a => `${prefix}${a}`));
        result.annotationsMoved += b.annotations.length;
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

/** Every annotation location in the model, across all relation types. */
function allLocations(model: ThreatModel) {
  return [
    ...model.assets, ...model.threats, ...model.controls,
    ...model.mitigations, ...model.exposures, ...(model.confirmed || []),
    ...model.acceptances, ...model.transfers, ...model.flows,
    ...model.boundaries, ...model.validations, ...model.audits,
    ...model.ownership, ...model.data_handling, ...model.assumptions,
    ...model.shields, ...model.features, ...model.comments,
  ].map(a => a.location);
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
