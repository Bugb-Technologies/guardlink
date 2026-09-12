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
 * @flows #parser -> ParseDiagnostics via parseString -- "Lines that were meant to be annotations and were not read, named rather than dropped"
 * @comment -- "A line lost before parseLine is a security claim that reached no threat model and produced no warning; the two comment-form diagnostics here exist so the next unread form cannot survive a release unnoticed"
 * @validates #input-sanitize for #parser -- "tests/comment-forms.test.ts pins that doc-tag and decorator traffic produces neither annotations nor diagnostics"
 */

import { readFile } from 'node:fs/promises';
import type { Annotation, ParseDiagnostic, ParseResult, SourceLocation } from '../types/index.js';
import { isStandaloneAnnotationFile, stripCommentPrefix } from './comment-strip.js';
import { parseLine, residualMarkerVerb, uncommentedVerb } from './parse-line.js';
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
      // Not a comment — and that is exactly where a docstring annotation lands.
      // §2.9 lists `""" """`, `=begin`, multi-line `<!-- -->` and `{- -}`; none
      // of them has ever been implemented, and the parser is line-by-line with
      // no block state, so an annotation written inside one arrives here with
      // no marker to strip and used to leave without a word. It cannot be
      // parsed — this file does not know it is inside a block — but it can be
      // named, which is the difference between a narrow parser and a silent one.
      if (!inShield) {
        const bare = uncommentedVerb(rawLine.trim());
        if (bare) {
          diagnostics.push({
            level: 'warning',
            code: 'uncommented-annotation',
            message: `@${bare.verb} on a line with no comment marker (found ${bare.evidence}) — not parsed. `
              + `GuardLink reads annotations from comments only; docstrings and multi-line block `
              + `comments are not read (SPEC §2.9). Move it into a ${'`//`'}-style comment.`,
            file: filePath,
            line: lineNum,
            raw: rawLine.trim(),
          });
        }
      }
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
      } else if (!result.isContinuation && !result.sourceDirective) {
        // This was a comment, and behind punctuation the stripper did not
        // recognise sits a known verb. Every comment form GuardLink reads is
        // handled in comment-strip.ts, so reaching here means the host language
        // has a doc-comment convention nobody has taught it yet — and the cost
        // of not saying so is measured: 54 real annotations on one repository,
        // invisible for months, with `validate` green the whole time.
        const residual = residualMarkerVerb(text);
        if (residual) {
          diagnostics.push({
            level: 'warning',
            code: 'unrecognised-comment-form',
            message: `Unrecognised comment form: '${residual.residue}' sits between the comment marker and `
              + `@${residual.verb}, so this line is not parsed and contributes nothing to the model. `
              + `Report the form so the parser can learn it, or rewrite the annotation in a comment style §2.9 lists.`,
            file: filePath,
            line: lineNum,
            raw: rawLine.trim(),
          });
        }
      }
      if (!result.isContinuation) {
        lastAnnotation = null;
      }
    }
  }

  return { annotations, diagnostics: collapsePerFileToken(diagnostics), files_parsed: 1 };
}

/**
 * Collapse repeated parse warnings to one per distinct token per file.
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
 * The count rides in the message so nothing is silently hidden, and in
 * `occurrences` so a consumer can add it up instead of parsing the English: a
 * count of diagnostics and a count of dropped annotations are different numbers,
 * and only the second says how much of the model is missing.
 *
 * `COLLAPSE_TOKEN` names, per code, the thing a reader would go and fix.
 * `unknown-verb` reads its token back out of its own message, which is where
 * this started and is kept verbatim so its existing tests still describe it.
 * The two comment-form codes collapse per file rather than per token: a
 * doc-comment convention the parser cannot read, or a docstring holding a block
 * of annotations, is **one** mistake with one fix, and listing it once per line
 * would reproduce exactly the flood this function exists to prevent.
 */
const COLLAPSE_TOKEN: Readonly<Record<string, (d: ParseDiagnostic) => string>> = {
  'unknown-verb': d => d.message.match(/^Unknown annotation verb (\S+)/)?.[1] ?? d.message,
  'unrecognised-comment-form': d => d.message.match(/^Unrecognised comment form: ('[^']*')/)?.[1] ?? 'form',
  'uncommented-annotation': () => 'block',
};

function collapsePerFileToken(diagnostics: ParseDiagnostic[]): ParseDiagnostic[] {
  const first = new Map<string, ParseDiagnostic>();
  const count = new Map<string, number>();
  const keyOf = (d: ParseDiagnostic): string | null => {
    const token = d.code ? COLLAPSE_TOKEN[d.code] : undefined;
    return token ? `${d.code}\u0000${token(d)}` : null;
  };

  for (const d of diagnostics) {
    const key = keyOf(d);
    if (key === null) continue;
    count.set(key, (count.get(key) ?? 0) + 1);
    if (!first.has(key)) first.set(key, d);
  }
  if (first.size === 0) return diagnostics;

  const kept = new Set(first.values());
  const out: ParseDiagnostic[] = [];
  for (const d of diagnostics) {
    const key = keyOf(d);
    if (key === null) { out.push(d); continue; }
    if (!kept.has(d)) continue;
    const n = count.get(key) ?? 1;
    out.push(n > 1
      ? { ...d, message: `${d.message} (${n} occurrences in this file; first at line ${d.line})`, occurrences: n }
      : d);
  }
  return out;
}
