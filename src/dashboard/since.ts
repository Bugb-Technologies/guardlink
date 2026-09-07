/**
 * GuardLink Dashboard — `--since <ref>`: the model at a git ref, diffed
 * against the model being rendered, plus the ref's place in history. The
 * page turns it into the "what changed" strip and the "new" marks on rows.
 *
 * @exposes #dashboard to #cmd-injection [low] cwe:CWE-78 -- "The ref the user typed reaches git"
 * @mitigates #dashboard against #cmd-injection using #param-commands -- "Checked against a strict ref shape first, then only ever passed as one argv element to execFileSync; parseAtRef rev-parses it before reading anything"
 * @flows GitRepo -> #dashboard via parseAtRef -- "The threat model as it was at the ref"
 * @comment -- "Deterministic per ref: the ref's commit date and the commit count are facts of history, so two runs at the same HEAD produce the same page"
 */
import { execFileSync } from 'node:child_process';
import type { ThreatModel } from '../types/index.js';
import { parseAtRef, getChangedFiles, diffModels } from '../diff/index.js';
import type { SinceInput } from './analytics.js';

export type { SinceInput } from './analytics.js';

/** A git ref as a user types one: tag, branch, sha, HEAD~3, main@{1}. Nothing that could read as an option. */
const REF_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]*$/;

function git(root: string, args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' } }).trim();
  } catch {
    return null;
  }
}

/**
 * Load everything the dashboard needs to say what changed since `ref`.
 * Throws when the directory is not a git checkout or the ref does not exist.
 */
export async function loadSince(root: string, ref: string, project: string, current: ThreatModel): Promise<SinceInput> {
  if (!REF_SHAPE.test(ref)) throw new Error(`Not a git ref: ${ref}`);
  const before = await parseAtRef(root, ref, project);
  const changedFiles = getChangedFiles(root, ref);
  const diff = diffModels(before, current, { changedFiles });
  const refDate = git(root, ['log', '-1', '--format=%cI', ref]);
  const commits = git(root, ['rev-list', '--count', `${ref}..HEAD`]);
  return {
    ref,
    refDate: refDate && refDate.length > 0 ? refDate : null,
    commits: commits !== null && /^\d+$/.test(commits) ? Number(commits) : null,
    diff,
    changedFiles,
  };
}
