/**
 * GuardLink — File-level parser.
 * Reads source files and extracts all GuardLink annotations.
 * Standalone .gal files are treated as raw annotation text.
 *
 * @exposes #parser to #path-traversal [high] cwe:CWE-22 -- "File path from caller read via readFile; no validation here"
 * @exposes #parser to #dos [medium] cwe:CWE-400 -- "Large files loaded entirely into memory"
 * @audit #parser -- "Path validation delegated to callers (CLI/MCP validate root)"
 * @flows FilePath -> #parser via readFile -- "Disk read path"
 * @flows #parser -> Annotations via parseString -- "Parsed annotation output"
 */

import { readFile } from 'node:fs/promises';
import type { Annotation, ParseDiagnostic, ParseResult, SourceLocation } from '../types/index.js';
import { isStandaloneAnnotationFile, stripCommentPrefix } from './comment-strip.js';
import { parseLine } from './parse-line.js';
import { unescapeDescription } from './normalize.js';

/**
 * Parse a single file and return all annotations found.
 */
export async function parseFile(filePath: string): Promise<ParseResult> {
  const content = await readFile(filePath, 'utf-8');
  return parseString(content, filePath);
}

/**
 * Parse a string of source code and return all annotations found.
 * Useful for testing without file I/O.
 */
export function parseString(content: string, filePath: string = '<input>'): ParseResult {
  const lines = content.split('\n');
  const annotations: Annotation[] = [];
  const diagnostics: ParseDiagnostic[] = [];
  let lastAnnotation: Annotation | null = null;
  let inShield = false;
  const allowRawAnnotationLines = isStandaloneAnnotationFile(filePath);
  let currentSource: SourceLocation | null = null;

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;  // 1-indexed
    const rawLine = lines[i];

    // Strip comment prefix unless this is a standalone .gal file, where
    // annotations are stored as raw lines instead of host-language comments.
    const inner = allowRawAnnotationLines ? rawLine : stripCommentPrefix(rawLine);
    if (inner === null) {
      lastAnnotation = null;
      continue;
    }
    const text = inner.trimStart();

    // Check for shield block boundaries — always parse these even inside shields
    const trimmed = text.trim();
    if (trimmed.startsWith('@shield:end')) {
      const location = { file: filePath, line: lineNum };
      const result = parseLine(text, location);
      if (result.annotation) annotations.push(result.annotation);
      inShield = false;
      lastAnnotation = null;
      continue;
    }
    if (trimmed.startsWith('@shield:begin')) {
      const location = { file: filePath, line: lineNum };
      const result = parseLine(text, location);
      if (result.annotation) annotations.push(result.annotation);
      inShield = true;
      lastAnnotation = null;
      continue;
    }

    // Skip all content inside shield blocks — these are excluded from the model
    if (inShield) continue;

    // Check for continuation line: -- "..."
    const contMatch = text.match(/^--\s*"((?:[^"\\]|\\.)*)"/);
    if (contMatch && lastAnnotation) {
      // Append to last annotation's description
      const contDesc = unescapeDescription(contMatch[1]);
      if (lastAnnotation.description) {
        lastAnnotation.description += ' ' + contDesc;
      } else {
        lastAnnotation.description = contDesc;
      }
      continue;
    }

    // Try to parse as annotation
    const location = { file: filePath, line: lineNum };
    const result = parseLine(text, location);

    if (result.sourceDirective) {
      currentSource = {
        file: result.sourceDirective.file,
        line: result.sourceDirective.line,
        parent_symbol: result.sourceDirective.symbol ?? null,
      };
      lastAnnotation = null;
      continue;
    }

    if (result.annotation) {
      if (allowRawAnnotationLines && currentSource) {
        result.annotation.location = {
          file: currentSource.file,
          line: currentSource.line,
          parent_symbol: currentSource.parent_symbol ?? null,
          origin_file: filePath,
          origin_line: lineNum,
        };
      }
      annotations.push(result.annotation);
      if (result.extraAnnotations) annotations.push(...result.extraAnnotations);
      lastAnnotation = annotations[annotations.length - 1];
    } else {
      if (result.diagnostic) {
        diagnostics.push(result.diagnostic);
      }
      if (!result.isContinuation) {
        lastAnnotation = null;
      }
    }
  }

  return { annotations, diagnostics: collapseUnknownVerbs(diagnostics), files_parsed: 1 };
}

/**
 * Collapse repeated `unknown-verb` warnings to one per distinct token per file.
 *
 * **Per file, not per project, and not globally.** Two alternatives were on the
 * table and both lose something this does not:
 *
 * - *One diagnostic for the whole run, with a total count.* Collapses hardest —
 *   1,340 lines to one — but it has to drop `file` and `line` to do it, and
 *   every consumer downstream is anchored on that pair: the CLI prints
 *   `file:line`, editors make it clickable, SARIF requires a
 *   `physicalLocation`. A warning with nowhere to point is a warning you cannot
 *   act on.
 * - *No collapsing.* What shipped first. One genuine `@flow` typo repeated
 *   across a file produced one warning per line, and a house convention
 *   produced 1,340.
 *
 * Per (file, token) keeps the anchor, keeps the fix local — you correct
 * `@flow` in this file by looking at one place — and still tells a developer
 * with the same typo in three files about all three. Output is bounded by
 * distinct tokens × files touched rather than by total lines.
 *
 * The first occurrence keeps the line, because that is where you start reading.
 * The count rides in the message so nothing is silently hidden.
 */
function collapseUnknownVerbs(diagnostics: ParseDiagnostic[]): ParseDiagnostic[] {
  const firstByToken = new Map<string, ParseDiagnostic>();
  const countByToken = new Map<string, number>();

  for (const d of diagnostics) {
    if (d.code !== 'unknown-verb') continue;
    const token = d.message.match(/^Unknown annotation verb (\S+)/)?.[1] ?? d.message;
    countByToken.set(token, (countByToken.get(token) ?? 0) + 1);
    if (!firstByToken.has(token)) firstByToken.set(token, d);
  }
  if (firstByToken.size === 0) return diagnostics;

  const kept = new Set(firstByToken.values());
  const out: ParseDiagnostic[] = [];
  for (const d of diagnostics) {
    if (d.code === 'unknown-verb' && !kept.has(d)) continue;
    if (d.code === 'unknown-verb') {
      const token = d.message.match(/^Unknown annotation verb (\S+)/)?.[1] ?? d.message;
      const n = countByToken.get(token) ?? 1;
      out.push(n > 1
        ? { ...d, message: `${d.message} (${n} occurrences in this file; first at line ${d.line})` }
        : d);
      continue;
    }
    out.push(d);
  }
  return out;
}
