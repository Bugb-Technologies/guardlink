/**
 * GuardLink — Structured annotation writes (GL-504).
 *
 * `guardlink_annotate` returns a prompt and the agent free-hands the edit. That
 * is non-deterministic, unvalidatable and lands in source files. This writes a
 * well-formed `@source` block into the resolved sidecar instead: validated
 * before it touches disk, idempotent, and confined to `.guardlink/` so a bad
 * write cannot mangle logic.
 *
 * `@accepts` and `@entitles` are refused. Both are governance decisions a human
 * makes and signs. A tool that can write `@accepts` lets an agent close a finding
 * by declaring it acceptable; a tool that can write `@entitles` lets it close one
 * by declaring the caller was allowed all along — and that second route would
 * bypass the propose/accept ledger in src/review/entitlements.ts entirely, which
 * is the gate that makes an entitlement carry a human's name (design §3.6).
 *
 * @exposes #parser to #arbitrary-write [high] cwe:CWE-73 -- "Writes annotation sidecars from tool input"
 * @mitigates #parser against #arbitrary-write using #path-validation -- "Target is always resolveGalPath(root, file); the caller cannot choose the path, and a file escaping root is rejected"
 * @exposes #parser to #insecure-deser [low] cwe:CWE-20 -- "Annotation lines arrive as caller-supplied text"
 * @mitigates #parser against #insecure-deser using #input-sanitize -- "Every line is re-parsed with parseLine before write; anything that does not parse, or parses as @accepts, is rejected"
 * @flows MCPClient -> #parser via applyAnnotations -- "Structured annotation write path"
 * @flows #parser -> FileSystem via writeFileSync -- "Sidecar append"
 * @comment -- "Idempotent by construction: an identical @source block is detected and skipped rather than duplicated"
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { parseLine } from './parse-line.js';
import { galPathFor, resolveGalPath } from './gal-path.js';

/** Verbs a tool may never write. */
const HUMAN_ONLY = new Set(['accepts', 'entitles']);

export interface ApplyAnnotationsOptions {
  root: string;
  /** Source file the annotations describe. */
  file: string;
  /** Line in that file the block anchors to. */
  line: number;
  /** Enclosing symbol, if known. Recorded so GL-505 can detect drift later. */
  symbol?: string;
  /** Raw GAL lines, without comment prefixes. */
  annotations: string[];
  dryRun?: boolean;
}

export interface ApplyAnnotationsResult {
  ok: boolean;
  /** Repo-relative sidecar path the block belongs in. */
  galPath: string;
  /** 'written' | 'unchanged' — unchanged means the identical block was already present. */
  status: 'written' | 'unchanged' | 'rejected';
  /** Unified-style diff of what was added. Empty when unchanged. */
  diff: string;
  /** Why the write was refused. Present only when status is 'rejected'. */
  errors: string[];
  linesWritten: number;
}

const reject = (galPath: string, ...errors: string[]): ApplyAnnotationsResult =>
  ({ ok: false, galPath, status: 'rejected', diff: '', errors, linesWritten: 0 });

/**
 * Append a validated `@source` block to a source file's sidecar.
 *
 * Every line is re-parsed with the real parser before anything is written — a
 * tool that writes annotations the parser cannot read is worse than no tool,
 * because the damage is silent until the next parse.
 */
export function applyAnnotations(options: ApplyAnnotationsOptions): ApplyAnnotationsResult {
  const { root, line, symbol, annotations, dryRun = false } = options;

  // Normalise the source path and refuse anything outside the project.
  const cleaned = options.file.trim().replaceAll('\\', '/').replace(/^\.\//, '');
  const abs = isAbsolute(cleaned) ? cleaned : resolve(root, cleaned);
  const file = relative(resolve(root), abs).replaceAll('\\', '/');
  const galPath = galPathFor(file);

  if (file === '' || file.startsWith('../')) {
    return reject(galPath, `\`${options.file}\` resolves outside the project root; nothing was written.`);
  }
  if (!Number.isInteger(line) || line < 1) {
    return reject(galPath, `line must be a positive integer; received ${JSON.stringify(line)}.`);
  }
  if (!Array.isArray(annotations) || annotations.length === 0) {
    return reject(galPath, 'No annotations supplied.');
  }

  // ── Validate every line against the real parser ──
  const errors: string[] = [];
  const normalised: string[] = [];
  for (const [i, raw] of annotations.entries()) {
    const text = raw.trim();
    if (!text) continue;
    if (text.startsWith('@source')) {
      errors.push(`Line ${i + 1}: do not supply @source yourself — the block header is generated from file, line and symbol.`);
      continue;
    }
    if (!text.startsWith('@')) {
      errors.push(`Line ${i + 1}: \`${text}\` is not an annotation. Supply raw GAL lines with no comment prefix.`);
      continue;
    }
    const parsed = parseLine(text, { file, line });
    if (!parsed.annotation) {
      errors.push(`Line ${i + 1}: \`${text}\` did not parse${parsed.diagnostic ? ` — ${parsed.diagnostic.message}` : '.'}`);
      continue;
    }
    if (HUMAN_ONLY.has(parsed.annotation.verb)) {
      errors.push(
        `Line ${i + 1}: refusing to write \`@${parsed.annotation.verb}\`. `
        + (parsed.annotation.verb === 'entitles'
          ? 'Stating that a privilege is entitled to an effect by design is a human governance '
            + 'decision, and writing it here would bypass the proposal ledger that records who '
            + 'granted it. Propose it with guardlink_entitlement_propose; a human accepts it with '
            + '"guardlink entitle", and that is what writes the annotation.'
          : 'Accepting a risk is a human governance decision. Record the risk with @exposes and '
            + 'flag it with @audit instead.'),
      );
      continue;
    }
    normalised.push(text);
  }

  if (errors.length > 0) return reject(galPath, ...errors);
  if (normalised.length === 0) return reject(galPath, 'No annotations supplied.');

  // ── Build the block ──
  const header = `@source file:${file} line:${line}${symbol ? ` symbol:${symbol}` : ''}`;
  const block = [header, ...normalised].join('\n') + '\n';

  const absGal = resolveGalPath(root, file);
  const existing = existsSync(absGal) ? readFileSync(absGal, 'utf-8') : '';

  // Idempotent: the identical block already present is a no-op, not a duplicate.
  // Compared on normalised text so incidental whitespace does not defeat it.
  const squash = (s: string) => s.split('\n').map(l => l.trim()).filter(Boolean).join('\n');
  if (squash(existing).includes(squash(block))) {
    return { ok: true, galPath, status: 'unchanged', diff: '', errors: [], linesWritten: 0 };
  }

  const separator = existing === '' || existing.endsWith('\n') ? '' : '\n';
  const next = existing + separator + block;
  if (!dryRun) {
    mkdirSync(dirname(absGal), { recursive: true });
    writeFileSync(absGal, next);
  }

  const diff = [
    `--- ${galPath}`,
    `+++ ${galPath}`,
    ...block.trimEnd().split('\n').map(l => `+${l}`),
  ].join('\n');

  return { ok: true, galPath, status: 'written', diff, errors: [], linesWritten: normalised.length + 1 };
}
