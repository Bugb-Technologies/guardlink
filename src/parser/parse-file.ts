/**
 * GuardLink — File-level parser.
 * Reads source files and extracts all GuardLink annotations.
 *
 * @exposes #parser to #path-traversal [high] cwe:CWE-22 -- "File path from caller read via readFile; no validation here"
 * @exposes #parser to #dos [medium] cwe:CWE-400 -- "Large files loaded entirely into memory"
 * @audit #parser -- "Path validation delegated to callers (CLI/MCP validate root)"
 * @flows FilePath -> #parser via readFile -- "Disk read path"
 * @flows #parser -> Annotations via parseString -- "Parsed annotation output"
 */

import { readFile } from 'node:fs/promises';
import { basename, extname } from 'node:path';
import type { Annotation, ParseDiagnostic, ParseResult } from '../types/index.js';
import { stripCommentPrefix } from './comment-strip.js';
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

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;  // 1-indexed
    const rawLine = lines[i];

    // Strip comment prefix
    const inner = stripCommentPrefix(rawLine);
    if (inner === null) {
      lastAnnotation = null;
      continue;
    }

    // Check for shield block boundaries — always parse these even inside shields
    const trimmed = inner.trim();
    if (trimmed.startsWith('@shield:end')) {
      const location = { file: filePath, line: lineNum };
      const result = parseLine(inner, location);
      if (result.annotation) annotations.push(result.annotation);
      inShield = false;
      lastAnnotation = null;
      continue;
    }
    if (trimmed.startsWith('@shield:begin')) {
      const location = { file: filePath, line: lineNum };
      const result = parseLine(inner, location);
      if (result.annotation) annotations.push(result.annotation);
      inShield = true;
      lastAnnotation = null;
      continue;
    }

    // Skip all content inside shield blocks — these are excluded from the model
    if (inShield) continue;

    // Check for continuation line: -- "..."
    const contMatch = inner.match(/^--\s*"((?:[^"\\]|\\.)*)"/);
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
    const result = parseLine(inner, location);

    if (result.annotation) {
      annotations.push(result.annotation);
      lastAnnotation = result.annotation;
    } else {
      if (result.diagnostic) {
        diagnostics.push(result.diagnostic);
      }
      if (!result.isContinuation) {
        lastAnnotation = null;
      }
    }
  }

  return { annotations, diagnostics, files_parsed: 1 };
}
