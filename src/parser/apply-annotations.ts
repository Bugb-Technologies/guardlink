/**
 * GuardLink — Structured annotation writes (GL-504).
 *
 * `guardlink_annotate` returns a prompt and the agent free-hands the edit. That
 * is non-deterministic, unvalidatable and lands in source files. This writes a
 * well-formed `@source` block into the resolved sidecar instead: validated
 * before it touches disk, idempotent, and confined to `.guardlink/` so a bad
 * write cannot mangle logic.
 *
 * `@accepts` is refused. Risk acceptance is a governance decision a human makes
 * and signs; a tool that can write one lets an agent close a finding by
 * declaring it acceptable, which is the one thing this system must never do on
 * its own.
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
import { dirname, resolve } from 'node:path';
import { parseLine } from './parse-line.js';
import { galPathFor, resolveGalPath, normalizeRepoPath } from './gal-path.js';

/** Verbs a tool may never write. */
const HUMAN_ONLY = new Set(['accepts']);

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
  /**
   * Every `#id` the model declares — assets, threats, controls, boundaries.
   *
   * D39: without this the write path could not tell `#sqli` from a typo, so it
   * wrote both. Supplied by the caller because it already holds a parsed model;
   * re-parsing the project inside a write would make an interactive tool slow
   * for a check the caller can do for free.
   *
   * Omitted means "no model available" and reference checking is skipped — the
   * pre-D39 behaviour, so a caller that genuinely has no model is not broken.
   */
  declaredIds?: Set<string>;
  /**
   * Write despite undeclared references, reporting them as warnings (D39).
   *
   * Default false: an undeclared ref is overwhelmingly a typo, and the workflow
   * this project ships to agents is definition-first. See the module doc-block.
   */
  allowUndeclaredRefs?: boolean;
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
  /** Written, but with something the caller should know (D39 forward refs). */
  warnings?: string[];
  linesWritten: number;
}

const reject = (galPath: string, ...errors: string[]): ApplyAnnotationsResult =>
  ({ ok: false, galPath, status: 'rejected', diff: '', errors, linesWritten: 0 });

/** Every `#id` referenced by an annotation line, in order of appearance. */
function referencedIds(text: string): string[] {
  return [...text.matchAll(/#([A-Za-z0-9][A-Za-z0-9._-]*)/g)]
    .map(m => m[1])
    // `cwe:CWE-89` and friends are external identifiers, not model refs, and
    // `#` never introduces them. Nothing to strip today; guard kept narrow.
    .filter(Boolean);
}

/**
 * Append a validated `@source` block to a source file's sidecar.
 *
 * Every line is re-parsed with the real parser before anything is written — a
 * tool that writes annotations the parser cannot read is worse than no tool,
 * because the damage is silent until the next parse.
 */
export function applyAnnotations(options: ApplyAnnotationsOptions): ApplyAnnotationsResult {
  const { root, line, symbol, annotations, dryRun = false, declaredIds, allowUndeclaredRefs = false } = options;

  // Normalise the source path and refuse anything outside the project. Shared
  // with guardlink_context (D51) — this was a private copy, which is how the
  // write path ended up without the existence check that sat beside the original.
  const rel = normalizeRepoPath(root, options.file);
  const file = rel ?? options.file.trim().replaceAll('\\', '/').replace(/^\.\//, '');
  const galPath = galPathFor(file);

  if (rel === null) {
    return reject(galPath, `\`${options.file}\` resolves outside the project root; nothing was written.`);
  }

  // D51: the sidecar is named after a source file, so a source file that does
  // not exist produces a sidecar describing nothing — and its annotations still
  // enter the model. A single typo injected a phantom critical exposure into
  // `expense-api` and `validate` reported "Validation passed".
  //
  // `guardlink_context` already answered this correctly for the same path
  // (`status: "not_found"`). The check existed and was wired to the tool that
  // could not cause harm.
  if (!existsSync(resolve(root, file))) {
    return reject(
      galPath,
      `\`${file}\` does not exist. A sidecar is named after the source file it annotates, so `
      + 'writing one for a missing file puts annotations into the model that describe nothing. '
      + 'Check the path — it is resolved relative to the project root.',
    );
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
        `Line ${i + 1}: refusing to write \`@${parsed.annotation.verb}\`. Accepting a risk is a human `
        + 'governance decision. Record the risk with @exposes and flag it with @audit instead.',
      );
      continue;
    }
    normalised.push(text);
  }

  // ── D39: references must resolve, or be waved through deliberately ──
  //
  // The tool promised "malformed input is rejected with the reason" and then
  // wrote `@mitigates #api against #xss-by-render using #octet-stream` with
  // `ok: true, errors: []`. Only `validate` noticed, only as a warning, exit 0 —
  // so an invented reference survived the write path, the validate path and CI.
  //
  // Checked against the same rule `findDanglingRefs` uses: `#`-prefixed refs
  // only. A dotted path like `Svc.Db` is not checked here for the same reason it
  // is not checked there, and keeping the two rules identical matters more than
  // catching one more case — two validators that disagree is its own defect.
  const warnings: string[] = [];
  if (declaredIds) {
    const undeclared: string[] = [];
    for (const text of normalised) {
      for (const id of referencedIds(text)) {
        if (!declaredIds.has(id) && !undeclared.includes(id)) undeclared.push(id);
      }
    }
    if (undeclared.length > 0) {
      const list = undeclared.map(i => `#${i}`).join(', ');
      if (!allowUndeclaredRefs) {
        return reject(
          galPath,
          `Undeclared reference(s): ${list}. Definitions live in .guardlink/definitions.* — `
          + 'add them there first, then reference them here. If the reference is deliberate '
          + 'and the definition is coming, re-send with allow_undeclared_refs: true and it '
          + 'will be written with a warning instead.',
        );
      }
      warnings.push(
        `Written with undeclared reference(s): ${list}. Nothing resolves them yet, so `
        + '`guardlink validate` will report them as dangling until they are defined in '
        + '.guardlink/definitions.*.',
      );
    }
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
    return { ok: true, galPath, status: 'unchanged', diff: '', errors: [], ...(warnings.length ? { warnings } : {}), linesWritten: 0 };
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

  return { ok: true, galPath, status: 'written', diff, errors: [], ...(warnings.length ? { warnings } : {}), linesWritten: normalised.length + 1 };
}
