/**
 * GuardLink Diff — Git integration.
 * Resolves git refs to threat models by checking out files at a given commit
 * and parsing them in a temp directory.
 *
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

  // Filter to likely annotated files (source code + definitions)
  const extensions = new Set([
    '.ts', '.tsx', '.js', '.jsx', '.py', '.rs', '.go', '.java', '.rb',
    '.c', '.cpp', '.h', '.cs', '.php', '.swift', '.kt', '.scala',
    '.yaml', '.yml', '.toml', '.json',
  ]);
  const relevantFiles = allFiles.filter(f => {
    const ext = f.substring(f.lastIndexOf('.'));
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
 * Get the current HEAD commit hash (short).
 */
export function getCurrentRef(root: string): string {
  try {
    return execSync('git rev-parse --short HEAD', { cwd: root, encoding: 'utf-8' }).trim();
  } catch {
    return 'unknown';
  }
}
