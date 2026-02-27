/**
 * GuardLink — Review module.
 *
 * Interactive governance workflow for unmitigated exposures.
 * Users walk through the GAL (Governance Acceptance List) and decide:
 *   accept  — write @accepts + @audit (risk acknowledged, intentional)
 *   remediate — write @audit with planned-fix note
 *   skip    — leave open for now
 *
 * @exposes #cli to #arbitrary-write [medium] cwe:CWE-73 -- "Writes @accepts/@audit annotations into source files"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "Only modifies files already in the parsed project"
 * @audit #cli -- "Review decisions require human justification; no empty accepts allowed"
 * @flows ThreatModel -> #cli via getReviewableExposures -- "Exposure list input"
 * @flows #cli -> SourceFiles via writeFile -- "Annotation insertion output"
 * @handles internal on #cli -- "Processes exposure metadata and user justification text"
 */

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { stripCommentPrefix } from '../parser/comment-strip.js';
import { findUnmitigatedExposures } from '../parser/validate.js';
import type { ThreatModel, ThreatModelExposure, Severity } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────────────────

export type ReviewDecision = 'accept' | 'remediate' | 'skip';

export interface ReviewableExposure {
  /** 1-based index in the review list */
  index: number;
  exposure: ThreatModelExposure;
  /** Stable ID for MCP: "file:line" */
  id: string;
}

export interface ReviewAction {
  decision: ReviewDecision;
  justification: string;
}

export interface ReviewResult {
  exposure: ReviewableExposure;
  action: ReviewAction;
  /** Lines inserted into the file (empty for skip) */
  linesInserted: number;
}

// ─── Severity ordering ──────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3,
};

// ─── Core logic ─────────────────────────────────────────────────────


/**
 * Get all unmitigated exposures eligible for review, sorted by severity.
 * Excludes test fixtures and files outside the src/ tree.
 */
export function getReviewableExposures(model: ThreatModel): ReviewableExposure[] {
  const unmitigated = findUnmitigatedExposures(model);

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
    id: `${exposure.location.file}:${exposure.location.line}`,
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

interface CommentStyle {
  /** The prefix to use for new annotation lines */
  prefix: string;
  /** Indentation (leading whitespace) to match */
  indent: string;
}

/**
 * Detect the comment style and indentation from the @exposes source line.
 * Supports JSDoc ( * @...), single-line (// @...), and hash (# @...) styles.
 */
function detectCommentStyle(rawLine: string): CommentStyle {
  const indent = rawLine.match(/^(\s*)/)?.[1] || '';
  const trimmed = rawLine.trimStart();

  if (trimmed.startsWith('* @') || trimmed.startsWith('*  @')) {
    return { prefix: '* ', indent };
  }
  if (trimmed.startsWith('// @')) {
    return { prefix: '// ', indent };
  }
  if (trimmed.startsWith('# @')) {
    return { prefix: '# ', indent };
  }
  if (trimmed.startsWith('-- @')) {
    return { prefix: '-- ', indent };
  }
  // Fallback: single-line JS style
  return { prefix: '// ', indent };
}

/**
 * Check if a source line is a GuardLink annotation (used to walk past coupled blocks).
 */
function isAnnotationLine(line: string): boolean {
  const inner = stripCommentPrefix(line);
  if (inner === null) return false;
  const trimmed = inner.trim();
  // Annotation line: starts with @verb
  if (trimmed.startsWith('@')) return true;
  // Continuation line: -- "..."
  if (/^--\s*"/.test(trimmed)) return true;
  return false;
}

/**
 * Find the insertion point after the coupled annotation block that contains
 * the @exposes line at `exposureLine` (1-indexed).
 *
 * Walks forward from the exposure line past consecutive annotation lines
 * to find the end of the block, then returns the 0-indexed line to insert after.
 */
function findInsertionIndex(lines: string[], exposureLine: number): number {
  // exposureLine is 1-indexed, convert to 0-indexed
  let idx = exposureLine - 1;

  // Walk forward past consecutive annotation lines
  while (idx + 1 < lines.length && isAnnotationLine(lines[idx + 1])) {
    idx++;
  }

  // Insert after the last annotation line in the block
  return idx + 1;
}

// ─── Annotation builders ────────────────────────────────────────────

function todayISO(): string {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Build the annotation lines to insert for an "accept" decision.
 * Returns lines WITHOUT trailing newline.
 */
function buildAcceptLines(style: CommentStyle, exposure: ThreatModelExposure, justification: string): string[] {
  const { prefix, indent } = style;
  const date = todayISO();
  return [
    `${indent}${prefix}@accepts ${exposure.threat} on ${exposure.asset} -- "${escapeDesc(justification)}"`,
    `${indent}${prefix}@audit ${exposure.asset} -- "Accepted via guardlink review on ${date}"`,
  ];
}

/**
 * Build the annotation line to insert for a "remediate" decision.
 */
function buildRemediateLines(style: CommentStyle, exposure: ThreatModelExposure, note: string): string[] {
  const { prefix, indent } = style;
  const date = todayISO();
  return [
    `${indent}${prefix}@audit ${exposure.asset} -- "Planned remediation: ${escapeDesc(note)} — flagged via guardlink review on ${date}"`,
  ];
}

/** Escape double quotes in description strings */
function escapeDesc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// ─── File modification ──────────────────────────────────────────────

/**
 * Insert annotation lines into a source file after the coupled block
 * containing the given @exposes annotation.
 *
 * Returns the number of lines inserted.
 */
async function insertAnnotations(
  root: string,
  exposure: ThreatModelExposure,
  newLines: string[],
): Promise<number> {
  const filePath = resolve(root, exposure.location.file);
  const content = await readFile(filePath, 'utf-8');
  const lines = content.split('\n');

  // Validate that the exposure line exists and looks right
  const exposureIdx = exposure.location.line - 1; // 0-indexed
  if (exposureIdx < 0 || exposureIdx >= lines.length) {
    throw new Error(`Line ${exposure.location.line} out of range in ${exposure.location.file}`);
  }

  const insertIdx = findInsertionIndex(lines, exposure.location.line);

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
 * Returns the result including lines inserted.
 */
export async function applyReviewAction(
  root: string,
  reviewable: ReviewableExposure,
  action: ReviewAction,
): Promise<ReviewResult> {
  if (action.decision === 'skip') {
    return { exposure: reviewable, action, linesInserted: 0 };
  }

  const { exposure } = reviewable;
  const filePath = resolve(root, exposure.location.file);
  const content = await readFile(filePath, 'utf-8');
  const lines = content.split('\n');

  // Detect comment style from the @exposes line
  const exposureIdx = exposure.location.line - 1;
  const style = detectCommentStyle(lines[exposureIdx]);

  let newLines: string[];
  if (action.decision === 'accept') {
    newLines = buildAcceptLines(style, exposure, action.justification);
  } else {
    newLines = buildRemediateLines(style, exposure, action.justification);
  }

  const linesInserted = await insertAnnotations(root, exposure, newLines);
  return { exposure: reviewable, action, linesInserted };
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
