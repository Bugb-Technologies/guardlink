/**
 * GuardLink — Review module.
 *
 * Governance workflow for unmitigated exposures. A reviewer decides:
 *   accept  — write @accepts + @audit (risk acknowledged, intentional)
 *   remediate — write @audit with planned-fix note
 *   skip    — leave open for now
 *
 * ── What an acceptance has to carry, and where that is enforced ─────
 *
 * Measured before this: `guardlink review` accepted a **critical** plaintext-
 * password exposure on a **one-character** justification ("x") and recorded **no
 * author**. The whole test was `while (!justification)` in the interactive
 * prompt — so the MCP tool, and any non-interactive path, had no check at all.
 *
 * The rule therefore lives in `applyReviewAction`, the one function every writer
 * goes through, and it is stated in `parser/acceptance.ts` so the gate that
 * re-checks an acceptance and the writer that creates one cannot disagree about
 * what a good one is. A prompt is a place to be helpful about a rule; it is not
 * a place to keep one.
 *
 * Three things an acceptance now carries that it did not:
 *   `by <who>`    the name of the human who signed, as `guardlink entitle` has
 *                 always recorded for the other human-only verb
 *   `until <date>` a horizon, after which it stops covering anything
 *   a justification long enough to be a reason rather than a category
 *
 * @exposes #cli to #arbitrary-write [medium] cwe:CWE-73 -- "Writes @accepts/@audit annotations into source files"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "Only modifies files already in the parsed project"
 * @exposes #cli to #arbitrary-write [high] cwe:CWE-74 -- "Reviewer-supplied justification and author name are interpolated into annotation text, where a newline would forge a second annotation"
 * @mitigates #cli against #arbitrary-write using #input-sanitize -- "oneLine() collapses newlines/CR/tabs before escapeDesc on every field that reaches a built line"
 * @audit #cli -- "Every acceptance records who decided, why, and until when; the rule is enforced in applyReviewAction so no caller can route around it"
 * @flows ThreatModel -> #cli via getReviewableExposures -- "Exposure list input"
 * @flows #cli -> SourceFiles via writeFile -- "Annotation insertion output"
 * @handles internal on #cli -- "Processes exposure metadata, reviewer identity and justification text"
 * @comment -- "applyReviewAction throws rather than returning a flag: a writer that can be ignored by a caller who forgot to check is the hole this replaced"
 * @comment -- "assertAcceptable never SUPPLIES a missing `by` or `until`, it refuses. Defaulting either is how a signature gets forged (git user.name) or how the longest lease the policy allows becomes the cheapest one to take (the max_horizon_days ceiling) — so the choke point that enforces the rule is also the one place that will not paper over it"
 */

import { readFile, writeFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { commentStyleForExt, stripCommentPrefix } from '../parser/comment-strip.js';
import { parseLine } from '../parser/parse-line.js';
import { findUnmitigatedExposures } from '../parser/validate.js';
import {
  DEFAULT_ACCEPTANCE_POLICY, parseExpiry, todayISO, utcDay,
  type AcceptancePolicy,
} from '../parser/acceptance.js';
import type { ThreatModel, ThreatModelExposure, Severity } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────────────────

export type ReviewDecision = 'accept' | 'remediate' | 'skip';

export interface ReviewableExposure {
  /** 1-based index in the review list */
  index: number;
  exposure: ThreatModelExposure;
  /** Stable ID for MCP */
  id: string;
}

export interface ReviewAction {
  decision: ReviewDecision;
  justification: string;
  /**
   * The human making the decision. Required for `accept` — an acceptance with
   * nobody's name on it is a decision nobody can be asked about, which is what
   * `guardlink entitle` already refuses for the other human-only verb.
   */
  by?: string;
  /**
   * `YYYY-MM-DD` — the last day this acceptance covers anything. Required for
   * `accept` under the default policy. Ignored for `remediate` and `skip`.
   */
  until?: string;
}

/** Thrown when a decision does not meet the policy. Never a silent no-op. */
export class ReviewRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReviewRejected';
  }
}

export interface ReviewResult {
  exposure: ReviewableExposure;
  action: ReviewAction;
  /** Lines inserted into the file (empty for skip) */
  linesInserted: number;
  /** Physical file modified (or logical file for skip) */
  targetFile: string;
}

// ─── Severity ordering ──────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3,
};

// ─── Core logic ─────────────────────────────────────────────────────


/**
 * Get all unmitigated exposures eligible for review, sorted by severity.
 * Excludes test fixtures and files outside the src/ tree.
 *
 * Takes the same `policy` the gate does, and callers pass it, so the loop
 * closes: `guardlink ci --strict` fails on an exposure whose acceptance no
 * longer counts, and `guardlink review --list` shows that exposure so it can be
 * decided again. Before this the two would have disagreed — the gate demanding
 * a decision on something the review UI had already hidden.
 */
export function getReviewableExposures(
  model: ThreatModel,
  opts: { policy?: AcceptancePolicy; now?: Date } = {},
): ReviewableExposure[] {
  const unmitigated = findUnmitigatedExposures(model, opts);

  // Filter out test fixtures and non-source files
  const filtered = unmitigated.filter(e => {
    const f = e.location.file;
    return !f.startsWith('tests/') && !f.startsWith('test/') && !f.includes('__tests__/') && !f.includes('fixtures/');
  });

  // Sort: critical → high → medium → low, then by file
  filtered.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity || 'low'] ?? 3;
    const sb = SEVERITY_ORDER[b.severity || 'low'] ?? 3;
    if (sa !== sb) return sa - sb;
    return a.location.file.localeCompare(b.location.file);
  });

  return filtered.map((exposure, i) => ({
    index: i + 1,
    exposure,
    id: reviewExposureId(exposure),
  }));
}

/**
 * Format a severity tag with color hint for display.
 */
export function severityLabel(s?: Severity): string {
  if (!s) return '[?]';
  return `[${s}]`;
}

// ─── Comment style detection ────────────────────────────────────────

export interface CommentStyle {
  /** The prefix to use for new annotation lines */
  prefix: string;
  /** Optional suffix for single-line wrapper styles like <!-- --> */
  suffix: string;
  /** Indentation (leading whitespace) to match */
  indent: string;
}

/**
 * Detect the comment style and indentation from the @exposes source line.
 * Supports JSDoc ( * @...), single-line (// @...), and hash (# @...) styles.
 */
export function detectCommentStyle(rawLine: string, filePath: string): CommentStyle {
  const indent = rawLine.match(/^(\s*)/)?.[1] || '';
  const trimmed = rawLine.trimStart();

  if (trimmed.startsWith('@')) {
    return { prefix: '', suffix: '', indent };
  }
  if (trimmed.startsWith('* @') || trimmed.startsWith('*  @')) {
    return { prefix: '* ', suffix: '', indent };
  }
  if (trimmed.startsWith('// @')) {
    return { prefix: '// ', suffix: '', indent };
  }
  if (trimmed.startsWith('# @')) {
    return { prefix: '# ', suffix: '', indent };
  }
  if (trimmed.startsWith('-- @')) {
    return { prefix: '-- ', suffix: '', indent };
  }
  if (trimmed.startsWith('<!--')) {
    return { prefix: '<!-- ', suffix: ' -->', indent };
  }
  if (trimmed.startsWith('/*')) {
    return { prefix: '/* ', suffix: ' */', indent };
  }

  return fallbackCommentStyle(filePath, indent);
}

function fallbackCommentStyle(filePath: string, indent: string): CommentStyle {
  switch (commentStyleForExt(extname(filePath))) {
    case '#': return { prefix: '# ', suffix: '', indent };
    case '--': return { prefix: '-- ', suffix: '', indent };
    case '<!--': return { prefix: '<!-- ', suffix: ' -->', indent };
    case '/*': return { prefix: '/* ', suffix: ' */', indent };
    case '%': return { prefix: '% ', suffix: '', indent };
    case ';': return { prefix: '; ', suffix: '', indent };
    case 'REM': return { prefix: 'REM ', suffix: '', indent };
    case "'": return { prefix: "' ", suffix: '', indent };
    case '//':
    default:
      return { prefix: '// ', suffix: '', indent };
  }
}

/**
 * Check if a source line is a GuardLink annotation (used to walk past coupled blocks).
 */
function isAnnotationLine(line: string): boolean {
  const rawTrimmed = line.trimStart();
  if (/^--\s*"/.test(rawTrimmed)) return true;
  const inner = stripCommentPrefix(line) ?? rawTrimmed;
  const parsed = parseLine(inner, { file: '<review>', line: 1 });
  return Boolean(parsed.annotation || parsed.sourceDirective || parsed.isContinuation);
}

/**
 * Find the insertion point after the coupled annotation block that contains
 * the @exposes line at `exposureLine` (1-indexed).
 *
 * Walks forward from the exposure line past consecutive annotation lines
 * to find the end of the block, then returns the 0-indexed line to insert after.
 */
export function findInsertionIndex(lines: string[], exposureLine: number, stopAtSourceBoundary: boolean = false): number {
  // exposureLine is 1-indexed, convert to 0-indexed
  let idx = exposureLine - 1;

  // Walk forward past consecutive annotation lines
  while (idx + 1 < lines.length && isAnnotationLine(lines[idx + 1])) {
    if (stopAtSourceBoundary && lines[idx + 1].trimStart().startsWith('@source')) {
      break;
    }
    idx++;
  }

  // Insert after the last annotation line in the block
  return idx + 1;
}

// ─── Annotation builders ────────────────────────────────────────────

/**
 * Collapse a free-text field to one line.
 *
 * Annotation descriptions are line-oriented, so an embedded newline in a
 * justification would let the text below it be read back as a separate
 * annotation — `escapeDesc` alone does not stop that. Same function and the same
 * reason as `entitlements.ts`; kept here rather than imported to avoid a cycle
 * between the two review writers.
 */
export function oneLine(s: string): string {
  return (s ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim().slice(0, 1000);
}

/**
 * A name safe to place in the `by <who>` position.
 *
 * Always quoted, because a real name has spaces and the grammar's unquoted form
 * is a single token. Quotes and backslashes inside are escaped, and the result
 * is re-parsed by `parseLine` before anything is written (see `buildAcceptLines`).
 */
function quotedAuthor(name: string): string {
  return `"${escapeDesc(oneLine(name))}"`;
}

/** `2027-03-01` — `days` from today, as the horizon a fresh acceptance gets. */
export function horizonFrom(days: number, now: Date = new Date()): string {
  const d = utcDay(now);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

/**
 * Build the annotation lines to insert for an "accept" decision.
 *
 * The `@audit` line now names the person. It used to read "Accepted via
 * guardlink review on <date>" and name nobody, so the one artifact a later
 * reader would find recorded that a decision happened and not who made it.
 *
 * Returns lines WITHOUT trailing newline.
 */
function buildAcceptLines(
  style: CommentStyle, exposure: ThreatModelExposure, action: ReviewAction, now: Date,
): string[] {
  const { prefix, suffix, indent } = style;
  const date = todayISO(now);
  const by = quotedAuthor(action.by!);
  const until = action.until!;
  return [
    `${indent}${prefix}@accepts ${exposure.threat} on ${exposure.asset} by ${by} until ${until}`
      + ` -- "${escapeDesc(oneLine(action.justification))}"${suffix}`,
    `${indent}${prefix}@audit ${exposure.asset} -- "Accepted via guardlink review on ${date}`
      + ` by ${escapeDesc(oneLine(action.by!))}, expires ${until}"${suffix}`,
  ];
}

/**
 * Build the annotation line to insert for a "remediate" decision.
 */
function buildRemediateLines(
  style: CommentStyle, exposure: ThreatModelExposure, action: ReviewAction, now: Date,
): string[] {
  const { prefix, suffix, indent } = style;
  const date = todayISO(now);
  const who = action.by ? ` by ${escapeDesc(oneLine(action.by))}` : '';
  return [
    `${indent}${prefix}@audit ${exposure.asset} -- "Planned remediation: ${escapeDesc(oneLine(action.justification))}`
      + ` — flagged via guardlink review on ${date}${who}"${suffix}`,
  ];
}

/** Escape double quotes in description strings */
export function escapeDesc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Refuse a decision that does not meet the policy, saying which part failed.
 *
 * Called by `applyReviewAction` — NOT by the CLI prompt, which is the whole
 * point. Every writer reaches source through `applyReviewAction`: the
 * interactive prompt, the scripted `--accept`, the `--from` batch, and the MCP
 * tool. One check, at the choke point, so a new caller cannot arrive without it.
 */
export function assertAcceptable(
  action: ReviewAction,
  policy: AcceptancePolicy = DEFAULT_ACCEPTANCE_POLICY,
  now: Date = new Date(),
): void {
  const justification = oneLine(action.justification);
  if (action.decision === 'remediate' && !justification) {
    throw new ReviewRejected('A remediation note must say what the planned fix is.');
  }
  if (action.decision !== 'accept') return;

  if (justification.length < policy.min_justification) {
    throw new ReviewRejected(
      `A justification must be at least ${policy.min_justification} characters — got ${justification.length}. `
      + 'Say what makes this risk acceptable here, not that it is: what compensates for it, '
      + 'who is exposed, and what would change the answer.',
    );
  }
  if (policy.require_author && !oneLine(action.by || '')) {
    throw new ReviewRejected(
      'An acceptance must carry the name of the human making it. Pass --by "<name>". '
      + 'It is not defaulted: this used to fall back to the local git user.name, which '
      + 'signs a risk acceptance in the name of whoever last configured the laptop.',
    );
  }
  if (policy.require_expiry && !action.until) {
    throw new ReviewRejected(
      'An acceptance must carry a horizon: --until <YYYY-MM-DD>. An acceptance with no end '
      + 'date is a permanent deletion, and this repository asked for decisions. '
      + `It is not defaulted either — omitting it used to take the full ${policy.max_horizon_days}-day `
      + `ceiling. ${horizonFrom(policy.default_horizon_days, now)} is ${policy.default_horizon_days} days out.`,
    );
  }
  if (action.until) {
    const until = parseExpiry(action.until);
    if (!until) {
      throw new ReviewRejected(`--until "${action.until}" is not a real calendar date. Use YYYY-MM-DD.`);
    }
    if (until.getTime() < utcDay(now).getTime()) {
      throw new ReviewRejected(`--until ${action.until} is in the past — it would expire the moment it was written.`);
    }
    const days = Math.round((until.getTime() - utcDay(now).getTime()) / 86_400_000);
    if (days > policy.max_horizon_days) {
      throw new ReviewRejected(
        `--until ${action.until} is ${days} days out; this project's ceiling is ${policy.max_horizon_days}. `
        + 'A longer horizon is a permanent deletion wearing a date — shorten it, or raise '
        + 'acceptance.max_horizon_days in .guardlink/config.json and say why in the commit.',
      );
    }
  }
}

// ─── File modification ──────────────────────────────────────────────

/**
 * Insert annotation lines into a source file after the coupled block that
 * contains the annotation at `anchor` (1-indexed line).
 *
 * The comment style is detected from the anchor line and handed to `build`, so
 * a caller composes annotation text without knowing whether the target is a
 * JSDoc block, a `#` comment, or a raw `.gal` file.
 *
 * Returns the number of lines inserted.
 *
 * @comment -- "Shared by exposure review (@accepts/@audit) and entitlement acceptance (@entitles) so both writers place annotations by the same rules"
 * @exposes #cli to #arbitrary-write [high] cwe:CWE-73 -- "Writes annotation lines into a caller-supplied file path"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "Anchor line must exist in the file, and callers resolve the path against the parsed project root"
 * @flows #cli -> SourceFiles via writeFile -- "Annotation insertion output"
 */
export async function insertAnnotationsAt(
  root: string,
  anchor: { file: string; line: number },
  build: (style: CommentStyle) => string[],
): Promise<number> {
  const filePath = resolve(root, anchor.file);
  const content = await readFile(filePath, 'utf-8');
  const lines = content.split('\n');

  const anchorIdx = anchor.line - 1; // 0-indexed
  if (anchorIdx < 0 || anchorIdx >= lines.length) {
    throw new Error(`Line ${anchor.line} out of range in ${anchor.file}`);
  }

  const style = detectCommentStyle(lines[anchorIdx], anchor.file);
  const newLines = build(style);
  const insertIdx = findInsertionIndex(lines, anchor.line, style.prefix === '');

  // Splice in the new lines
  lines.splice(insertIdx, 0, ...newLines);

  await writeFile(filePath, lines.join('\n'));
  return newLines.length;
}

// ─── Public API ─────────────────────────────────────────────────────

/**
 * Apply a review decision to an exposure.
 * For 'accept': inserts @accepts + @audit after the coupled block.
 * For 'remediate': inserts @audit with planned-fix note.
 * For 'skip': does nothing.
 *
 * **This is where the policy is enforced**, not in the prompt that calls it.
 * Throws `ReviewRejected` on a decision that does not meet it, so a caller that
 * forgot to validate gets an error rather than a bad annotation in source.
 *
 * Returns the result including lines inserted.
 */
export async function applyReviewAction(
  root: string,
  reviewable: ReviewableExposure,
  action: ReviewAction,
  opts: { policy?: AcceptancePolicy; now?: Date } = {},
): Promise<ReviewResult> {
  if (action.decision === 'skip') {
    return { exposure: reviewable, action, linesInserted: 0, targetFile: getWriteLocation(reviewable.exposure).file };
  }

  const now = opts.now ?? new Date();
  assertAcceptable(action, opts.policy ?? DEFAULT_ACCEPTANCE_POLICY, now);

  const { exposure } = reviewable;
  const targetLocation = getWriteLocation(exposure);

  const linesInserted = await insertAnnotationsAt(root, targetLocation, style => {
    const lines = action.decision === 'accept'
      ? buildAcceptLines(style, exposure, action, now)
      : buildRemediateLines(style, exposure, action, now);
    // Every line is re-parsed before it is written. A name or a justification
    // that broke out of its quotes would otherwise land in source as a forged
    // annotation, and the next parse would read it as one.
    for (const line of lines) {
      const inner = stripCommentPrefix(line) ?? line.trimStart();
      if (!parseLine(inner, { file: targetLocation.file, line: targetLocation.line }).annotation) {
        throw new ReviewRejected(
          `Refusing to write a line that does not parse back as an annotation: ${line.trim()}`,
        );
      }
    }
    return lines;
  });
  return { exposure: reviewable, action, linesInserted, targetFile: targetLocation.file };
}

function getWriteLocation(exposure: ThreatModelExposure): { file: string; line: number } {
  return {
    file: exposure.location.origin_file || exposure.location.file,
    line: exposure.location.origin_line || exposure.location.line,
  };
}

function reviewExposureId(exposure: ThreatModelExposure): string {
  const writeLocation = getWriteLocation(exposure);
  return [
    writeLocation.file,
    String(writeLocation.line),
    exposure.location.file,
    String(exposure.location.line),
    exposure.asset,
    exposure.threat,
  ].join(':');
}

/**
 * Format an exposure for display in CLI/TUI review UI.
 */
export function formatExposureForReview(r: ReviewableExposure, total: number): string {
  const e = r.exposure;
  const sev = e.severity || 'unknown';
  const desc = e.description || '(no description)';
  return [
    `[${r.index}/${total}] ${e.asset} → ${e.threat} [${sev}]`,
    `  File: ${e.location.file}:${e.location.line}`,
    `  Exposure: "${desc}"`,
  ].join('\n');
}

/**
 * Summarize review session results.
 */
export function summarizeReview(results: ReviewResult[]): string {
  const accepted = results.filter(r => r.action.decision === 'accept').length;
  const remediated = results.filter(r => r.action.decision === 'remediate').length;
  const skipped = results.filter(r => r.action.decision === 'skip').length;
  const totalLines = results.reduce((sum, r) => sum + r.linesInserted, 0);

  const parts: string[] = [];
  if (accepted > 0) parts.push(`${accepted} accepted`);
  if (remediated > 0) parts.push(`${remediated} marked for remediation`);
  if (skipped > 0) parts.push(`${skipped} skipped`);

  return `Review complete: ${parts.join(', ')}. ${totalLines} annotation line(s) written.`;
}

// ─── Scripted review (R9) ───────────────────────────────────────────

/**
 * One decision in a `--from <file>` batch.
 *
 * The shape mirrors the flags exactly, so a reviewer can move between the two
 * without learning a second vocabulary, and a bot that can build one can build
 * the other.
 */
export interface ScriptedDecision {
  id: string;
  decision: ReviewDecision;
  justification?: string;
  by?: string;
  until?: string;
}

/**
 * Read a batch file: `{"decisions": [...]}` or a bare array of the same objects.
 *
 * Validated field by field and refused as a whole on the first bad entry rather
 * than skipping it. A batch that silently drops the one decision it could not
 * read is the same failure as the piped `review` that exited 0 having done
 * nothing — the caller believes work happened.
 */
export function parseReviewBatch(raw: string, source: string): ScriptedDecision[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ReviewRejected(`${source} is not valid JSON: ${(err as Error).message}`);
  }
  const rows = Array.isArray(parsed)
    ? parsed
    : (parsed as { decisions?: unknown })?.decisions;
  if (!Array.isArray(rows)) {
    throw new ReviewRejected(
      `${source} must hold a JSON array of decisions, or an object with a "decisions" array.`,
    );
  }
  return rows.map((row, i) => {
    const at = `${source}[${i}]`;
    if (!row || typeof row !== 'object') throw new ReviewRejected(`${at} is not an object.`);
    const r = row as Record<string, unknown>;
    const id = typeof r.id === 'string' ? r.id.trim() : '';
    if (!id) throw new ReviewRejected(`${at} has no "id". Get ids from: guardlink review . --list --format json`);
    const decision = r.decision ?? 'accept';
    if (decision !== 'accept' && decision !== 'remediate' && decision !== 'skip') {
      throw new ReviewRejected(`${at} has decision "${String(decision)}"; use accept, remediate or skip.`);
    }
    const str = (v: unknown, field: string): string | undefined => {
      if (v === undefined || v === null) return undefined;
      if (typeof v !== 'string') throw new ReviewRejected(`${at}.${field} must be a string.`);
      return v;
    };
    return {
      id,
      decision,
      justification: str(r.justification, 'justification'),
      by: str(r.by, 'by'),
      until: str(r.until, 'until'),
    };
  });
}
