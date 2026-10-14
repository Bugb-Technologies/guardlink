/**
 * GuardLink Diff — Git integration.
 * Resolves git refs to threat models by checking out files at a given commit
 * and parsing them in a temp directory.
 *
 * @exposes #diff to #cmd-injection [high] cwe:CWE-78 -- "The ref is caller-supplied (a CLI or TUI argument, or the ref argument of the guardlink_diff MCP tool) and reaches git"
 * @mitigates #diff against #cmd-injection using #param-commands -- "Every git call is execFileSync with an argument array; no command line is ever handed to a shell"
 * @mitigates #diff against #cmd-injection using #input-sanitize -- "resolveCommit refuses a ref outside REF_SHAPE (a leading '-', whitespace, quoting or shell syntax), passes it after --end-of-options, and resolves it to a commit sha; every later git call takes that sha, never the ref"
 * @exposes #diff to #arbitrary-write [medium] cwe:CWE-73 -- "writeFileSync creates files in temp directory"
 * @mitigates #diff against #arbitrary-write using #path-validation -- "mkdtempSync creates isolated temp dir; rmSync cleans up"
 * @exposes #diff to #path-traversal [medium] cwe:CWE-22 -- "git show extracts files based on ls-tree output"
 * @mitigates #diff against #path-traversal using #glob-filtering -- "Files constrained to relevantFiles from git ls-tree"
 * @exposes #diff to #path-traversal [medium] cwe:CWE-59 -- "Symlinks at the ref are recreated in the temp tree, and a link target is repository content"
 * @mitigates #diff against #path-traversal using #path-validation -- "Only the agent-config reader follows the links, and it drops any whose real path leaves the temp tree; nothing is written through a link"
 * @flows GitRef -> #diff via execFileSync -- "Git command execution"
 * @flows #diff -> TempDir via writeFileSync -- "Extracted file writes"
 * @flows #diff -> ThreatModel via parseProject -- "Parsed model output"
 * @boundary #diff and GitRepo (#git-boundary) -- "Trust boundary at git command execution"
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseProject } from '../parser/index.js';
import { isAgentConfigPath, SKIP_DIRS } from '../agentconfig/discover.js';
import type { ThreatModel } from '../types/index.js';

/**
 * A git ref as a person types one: a sha, branch, tag, `HEAD~3`, `origin/main`,
 * `main@{1}`. It must start with a letter or digit, so it cannot read as an
 * option, and it carries no whitespace, quoting or shell syntax.
 */
export const REF_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]*$/;

function git(root: string, args: string[], maxBuffer?: number): string {
  return execFileSync('git', args, { cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'], ...(maxBuffer ? { maxBuffer } : {}) });
}

/** File content as bytes: a bundled script's digest must match the one taken from the working tree. */
function gitBytes(root: string, args: string[], maxBuffer: number): Buffer {
  return execFileSync('git', args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer });
}

/**
 * Resolve `ref` to the full sha of the commit it names, or throw.
 *
 * The ref is checked against REF_SHAPE and passed after `--end-of-options`, and
 * the sha is what every later git call is given: the ref itself is used once.
 */
export function resolveCommit(root: string, ref: string): string {
  if (!REF_SHAPE.test(ref)) throw new Error(`Invalid git ref: ${ref}`);
  let sha: string;
  try {
    sha = git(root, ['rev-parse', '--verify', '--quiet', '--end-of-options', `${ref}^{commit}`]).trim();
  } catch {
    throw new Error(`Invalid git ref: ${ref}`);
  }
  if (!/^[0-9a-f]{40,64}$/.test(sha)) throw new Error(`Invalid git ref: ${ref}`);
  return sha;
}

/**
 * Parse the threat model at a specific git ref (commit, branch, tag, HEAD~1, etc.)
 * by extracting annotated files at that revision into a temp directory.
 */
export async function parseAtRef(root: string, ref: string, project: string): Promise<ThreatModel> {
  // Verify git repo
  try {
    git(root, ['rev-parse', '--is-inside-work-tree']);
  } catch {
    throw new Error(`Not a git repository: ${root}`);
  }

  const commit = resolveCommit(root, ref);

  // Every entry at that ref with its mode, so a symlink is recreated as one.
  // NUL-separated: a path may hold any byte but NUL.
  const treeRaw = git(root, ['ls-tree', '-r', '-z', commit], 512 * 1024 * 1024);
  const entries = treeRaw.split('\0').filter(Boolean).map(line => {
    const tab = line.indexOf('\t');
    const [mode] = line.slice(0, tab).split(' ');
    return { mode, path: line.slice(tab + 1) };
  });

  // Filter to likely annotated files (source code + standalone GAL annotations),
  // the repository's agent configuration and the scripts its hooks run.
  const extensions = new Set([
    '.ts', '.tsx', '.js', '.jsx', '.py', '.rs', '.go', '.java', '.rb',
    '.c', '.cpp', '.h', '.cs', '.php', '.swift', '.kt', '.scala',
    '.yaml', '.yml', '.toml', '.json', '.gal',
    '.sh', '.bash', '.zsh', '.ps1', '.mjs', '.cjs',
  ]);
  // Everything beside a skill's SKILL.md too: the bundle list is part of what the diff compares.
  const skillDirs = entries.map(e => e.path).filter(f => f.endsWith('/SKILL.md')).map(f => f.slice(0, -'SKILL.md'.length));
  const inSkillDir = (f: string) => skillDirs.some(d => f.startsWith(d) && !f.slice(d.length).split('/').slice(0, -1).some(p => SKIP_DIRS.has(p)));
  const relevant = entries.filter(({ path: f }) => {
    const ext = f.substring(f.lastIndexOf('.')).toLowerCase();
    return extensions.has(ext) || f.includes('.guardlink/') || isAgentConfigPath(f) || inSkillDir(f);
  });
  // A symlinked directory is one entry in git; the files beneath it are reached through it.
  const links = entries.filter(e => e.mode === '120000' && !relevant.includes(e));

  // Create temp directory and extract files
  const tmpDir = mkdtempSync(join(tmpdir(), 'guardlink-diff-'));

  try {
    for (const { mode, path: file } of [...relevant, ...links]) {
      try {
        const content = gitBytes(root, ['show', `${commit}:${file}`], 64 * 1024 * 1024);
        const outPath = join(tmpDir, file);
        mkdirSync(join(outPath, '..'), { recursive: true });
        // The reader follows a link only when it resolves inside the extracted tree.
        if (mode === '120000') symlinkSync(content.toString('utf-8'), outPath);
        else writeFileSync(outPath, content);
      } catch {
        // File might not exist at this ref (deleted), skip
      }
    }

    // Parse the temp directory
    // Historical parse: anchors are never read from this model, so skip the structure pass.
    const { model } = await parseProject({ root: tmpDir, project, anchors: false });
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
 * @exposes #diff to #cmd-injection [high] cwe:CWE-78 -- "getChangedFiles passes the caller's ref (a CLI, TUI or dashboard --since argument) to git diff --name-only"
 * @mitigates #diff against #cmd-injection using #input-sanitize -- "resolveCommit checks the ref's shape and resolves it to a sha first; a ref it refuses returns [] and runs nothing further"
 * @mitigates #diff against #cmd-injection using #param-commands -- "git diff runs through execFileSync with the sha as one argument"
 * @flows GitRef -> #diff via execFileSync -- "Ref input to git diff --name-only"
 * @flows #diff -> ChangedFileList via return -- "Repo-relative paths used for entitlement staleness"
 */
export function getChangedFiles(root: string, ref: string): string[] {
  try {
    const commit = resolveCommit(root, ref);
    const raw = git(root, ['diff', '--name-only', commit, '--']);
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
    return git(root, ['rev-parse', '--short', 'HEAD']).trim();
  } catch {
    return 'unknown';
  }
}
