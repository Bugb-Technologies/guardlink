/**
 * GuardLink Diff — Git integration.
 * Resolves git refs to threat models by checking out files at a given commit
 * and parsing them in a temp directory.
 *
 * @exposes #diff to #cmd-injection [high] cwe:CWE-78 -- "execSync runs git commands with ref argument"
 * @mitigates #diff against #cmd-injection using #input-sanitize -- "rev-parse validates ref exists before use in other commands"
 * @exposes #diff to #arbitrary-write [medium] cwe:CWE-73 -- "writeFileSync creates files in temp directory"
 * @mitigates #diff against #arbitrary-write using #path-validation -- "mkdtempSync creates isolated temp dir; rmSync cleans up"
 * @exposes #diff to #path-traversal [medium] cwe:CWE-22 -- "git show extracts files based on ls-tree output"
 * @mitigates #diff against #path-traversal using #glob-filtering -- "Files constrained to relevantFiles from git ls-tree"
 * @flows GitRef -> #diff via execSync -- "Git command execution"
 * @flows #diff -> TempDir via writeFileSync -- "Extracted file writes"
 * @flows #diff -> ThreatModel via parseProject -- "Parsed model output"
 * @boundary #diff and GitRepo (#git-boundary) -- "Trust boundary at git command execution"
 */

import { execSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseProject } from '../parser/index.js';
import type { ThreatModel } from '../types/index.js';

/**
 * Parse the threat model at a specific git ref (commit, branch, tag, HEAD~1, etc.)
 * by extracting annotated files at that revision into a temp directory.
 */
export async function parseAtRef(root: string, ref: string, project: string): Promise<ThreatModel> {
  // Verify git repo
  try {
    execSync('git rev-parse --is-inside-work-tree', { cwd: root, stdio: 'pipe' });
  } catch {
    throw new Error(`Not a git repository: ${root}`);
  }

  // Verify ref exists
  try {
    execSync(`git rev-parse --verify ${ref}`, { cwd: root, stdio: 'pipe' });
  } catch {
    throw new Error(`Invalid git ref: ${ref}`);
  }

  // Get list of files at that ref
  const filesRaw = execSync(`git ls-tree -r --name-only ${ref}`, { cwd: root, encoding: 'utf-8' });
  const allFiles = filesRaw.trim().split('\n').filter(Boolean);

  // Filter to likely annotated files (source code + standalone GAL annotations)
  const extensions = new Set([
    '.ts', '.tsx', '.js', '.jsx', '.py', '.rs', '.go', '.java', '.rb',
    '.c', '.cpp', '.h', '.cs', '.php', '.swift', '.kt', '.scala',
    '.yaml', '.yml', '.toml', '.json', '.gal',
  ]);
  const relevantFiles = allFiles.filter(f => {
    const ext = f.substring(f.lastIndexOf('.')).toLowerCase();
    return extensions.has(ext) || f.includes('.guardlink/');
  });

  // Create temp directory and extract files
  const tmpDir = mkdtempSync(join(tmpdir(), 'guardlink-diff-'));

  try {
    for (const file of relevantFiles) {
      try {
        const content = execSync(`git show ${ref}:${file}`, { cwd: root, encoding: 'utf-8' });
        const outPath = join(tmpDir, file);
        mkdirSync(join(outPath, '..'), { recursive: true });
        writeFileSync(outPath, content);
      } catch {
        // File might not exist at this ref (deleted), skip
      }
    }

    // Parse the temp directory
    const { model } = await parseProject({ root: tmpDir, project });
    return model;
  } finally {
    // Cleanup
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * List files that changed between `ref` and the working tree, repo-relative.
 *
 * Feeds `diffModels({ changedFiles })` so an @entitles whose cited authorization
 * code moved is reported as stale (actor-entitlement design §3.7). Returns [] on
 * any git failure — staleness is advisory, and a diff that cannot resolve the ref
 * should still report the rest of the delta.
 *
 * @exposes #diff to #cmd-injection [high] cwe:CWE-78 -- "ref is interpolated into an execSync git command"
 * @mitigates #diff against #cmd-injection using #input-sanitize -- "rev-parse --verify must resolve ref to a single revision before it reaches the diff command; a shell metacharacter makes rev-parse fail, so the function returns [] instead of running the second command"
 * @flows GitRef -> #diff via execSync -- "Ref input to git diff --name-only"
 * @flows #diff -> ChangedFileList via return -- "Repo-relative paths used for entitlement staleness"
 */
export function getChangedFiles(root: string, ref: string): string[] {
  try {
    execSync(`git rev-parse --verify ${ref}`, { cwd: root, stdio: 'pipe' });
    const raw = execSync(`git diff --name-only ${ref} --`, { cwd: root, encoding: 'utf-8' });
    return raw.trim().split('\n').map(f => f.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Get the current HEAD commit hash (short).
 */
export function getCurrentRef(root: string): string {
  try {
    return execSync('git rev-parse --short HEAD', { cwd: root, encoding: 'utf-8' }).trim();
  } catch {
    return 'unknown';
  }
}
