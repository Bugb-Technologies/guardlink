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
