/**
 * GuardLink — Annotation clearing utility.
 * Scans project source files and removes all GuardLink annotation lines.
 * Standalone .gal files are treated as raw annotation text.
 *
 * Used by `guardlink clear` and `/clear` to let users start fresh with annotations.
 *
 * @exposes #parser to #arbitrary-write [high] cwe:CWE-73 -- "Writes modified content back to discovered files"
 * @exposes #parser to #path-traversal [high] cwe:CWE-22 -- "Glob patterns determine which files are modified"
 * @mitigates #parser against #path-traversal using #glob-filtering -- "DEFAULT_EXCLUDE blocks sensitive dirs; cwd constrains scope"
 * @audit #parser -- "Destructive operation requires explicit user confirmation via dryRun flag"
 * @flows ProjectRoot -> #parser via fast-glob -- "File discovery path"
 * @flows #parser -> SourceFiles via writeFile -- "Modified file write path"
 * @handles internal on #parser -- "Operates on project source files only"
 */

import fg from 'fast-glob';
import { readFile, writeFile } from 'node:fs/promises';
import { relative } from 'node:path';
import { isStandaloneAnnotationFile, stripCommentPrefix } from './comment-strip.js';

// ─── Known GuardLink verbs ──────────────────────────────────────────

const GUARDLINK_VERBS = new Set([
  'asset', 'threat', 'control',
  'mitigates', 'exposes', 'accepts', 'transfers', 'flows', 'boundary',
  'validates', 'audit', 'owns', 'handles', 'assumes',
  'comment', 'source', 'shield', 'shield:begin', 'shield:end',
  // v1 compat
  'review', 'connects',
]);

const DEFAULT_INCLUDE = [
  '**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx',
  '**/*.py', '**/*.rb', '**/*.go', '**/*.rs',
  '**/*.java', '**/*.kt', '**/*.scala',
  '**/*.c', '**/*.cpp', '**/*.cc', '**/*.h', '**/*.hpp',
  '**/*.cs', '**/*.swift', '**/*.dart',
  '**/*.sql', '**/*.lua', '**/*.hs',
  '**/*.tf', '**/*.hcl',
  '**/*.yaml', '**/*.yml',
  '**/*.sh', '**/*.bash',
  '**/*.html', '**/*.xml', '**/*.svg',
  '**/*.css',
  '**/*.ex', '**/*.exs',
  '**/*.[gG][aA][lL]',
];

const DEFAULT_EXCLUDE = [
  '**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**',
  '**/__pycache__/**', '**/target/**', '**/vendor/**', '**/.next/**',
  '**/tests/**', '**/test/**', '**/__tests__/**',
];

// ─── Types ──────────────────────────────────────────────────────────

export interface ClearAnnotationsOptions {
  root: string;
  include?: string[];
  exclude?: string[];
  /** If true, don't write files — just report what would be removed */
  dryRun?: boolean;
  /** If true, also clear .guardlink/definitions files */
  includeDefinitions?: boolean;
}

export interface ClearAnnotationsResult {
  /** Files that were modified (annotations removed) */
  modifiedFiles: string[];
  /** Total annotation lines removed across all files */
  totalRemoved: number;
  /** Per-file breakdown: relative path → count of lines removed */
  perFile: Map<string, number>;
}

// ─── Core logic ─────────────────────────────────────────────────────

function isGuardLinkAnnotationText(inner: string | null): boolean {
  if (inner === null) return false;

  const trimmed = inner.trim();
  if (!trimmed.startsWith('@')) return false;

  // Extract the verb
  const verbMatch = trimmed.match(/^@(\S+)/);
  if (!verbMatch) return false;

  const verb = verbMatch[1];
  return GUARDLINK_VERBS.has(verb);
}

/**
 * Remove all GuardLink annotation lines from a file's content.
 * Returns the cleaned content and count of lines removed.
 *
 * Also removes:
 * - Continuation lines (-- "...") that follow an annotation
 * - Empty comment lines that are left between annotations (cleanup)
 */
function removeAnnotationsFromContent(content: string, allowRawAnnotationLines: boolean): { cleaned: string; removed: number } {
  const lines = content.split('\n');
  const result: string[] = [];
  let removed = 0;
  let lastWasAnnotation = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const inner = allowRawAnnotationLines ? line : stripCommentPrefix(line);

    if (isGuardLinkAnnotationText(inner)) {
      removed++;
      lastWasAnnotation = true;
      continue;
    }

    // Remove continuation lines that follow an annotation
    if (lastWasAnnotation && inner !== null && /^--\s*"/.test(inner.trim())) {
      removed++;
      continue;
    }

    lastWasAnnotation = false;
    result.push(line);
  }

  // Clean up: remove consecutive empty lines left behind (collapse to max 1)
  const final: string[] = [];
  let prevEmpty = false;
  for (const line of result) {
    const isEmpty = line.trim() === '';
    if (isEmpty && prevEmpty) continue; // skip consecutive empties
    final.push(line);
    prevEmpty = isEmpty;
  }

  return { cleaned: final.join('\n'), removed };
}

/**
 * Scan all project source files and remove GuardLink annotations.
 */
export async function clearAnnotations(options: ClearAnnotationsOptions): Promise<ClearAnnotationsResult> {
  const {
    root,
    include = DEFAULT_INCLUDE,
    exclude = DEFAULT_EXCLUDE,
    dryRun = false,
    includeDefinitions = false,
  } = options;

  const candidateFiles = await fg(include, {
    cwd: root,
    ignore: exclude,
    absolute: true,
    dot: true,
  });
  const files = candidateFiles.filter(filePath =>
    includeDefinitions || !isDefinitionsFile(relative(root, filePath)),
  );

  const modifiedFiles: string[] = [];
  const perFile = new Map<string, number>();
  let totalRemoved = 0;

  for (const filePath of files) {
    const content = await readFile(filePath, 'utf-8');
    const { cleaned, removed } = removeAnnotationsFromContent(content, isStandaloneAnnotationFile(filePath));

    if (removed > 0) {
      const relPath = relative(root, filePath);
      modifiedFiles.push(relPath);
      perFile.set(relPath, removed);
      totalRemoved += removed;

      if (!dryRun) {
        await writeFile(filePath, cleaned);
      }
    }
  }

  return { modifiedFiles, totalRemoved, perFile };
}

function isDefinitionsFile(relPath: string): boolean {
  const normalized = relPath.replaceAll('\\', '/');
  return normalized.startsWith('.guardlink/definitions.');
}
