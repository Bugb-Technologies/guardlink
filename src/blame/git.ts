/**
 * GuardLink Blame — git adapter.
 *
 * Every command is `execFileSync('git', argv)`: an argv array, no shell, with
 * a literal `--` before every path so a file name can never read as an
 * option. A timeout and an output cap bound each call. `GIT_OPTIONAL_LOCKS=0`
 * keeps even `git status` from refreshing `.git/index`, so a read stays a read.
 *
 * The parsers (`parseBlamePorcelain`, `parseLogRecords`) are pure and exported
 * so they can be pinned on captured output; the commands take an injectable
 * `exec` so batching can be asserted without spawning.
 *
 * @exposes #blame to #cmd-injection [low] cwe:CWE-78 -- "gitExec() builds the argv it spawns from location.file and the start/end line numbers of each parsed record"
 * @mitigates #blame against #cmd-injection using #param-commands -- "execFileSync with an argv array and no shell; paths follow a literal -- and line ranges are integers formatted here, never caller strings"
 * @exposes #blame to #path-traversal [low] cwe:CWE-22 -- "blameFile(), spanOldestCommit() and fileAddCommit() pass location.file to git blame, git log and git ls-files, which read whatever path it names"
 * @mitigates #blame against #path-traversal using #path-validation -- "compute.ts resolves every path against root and drops any that escapes it before this module sees it, and git itself refuses paths outside the work tree"
 * @exposes #blame to #dos [low] cwe:CWE-400 -- "git log -L walks history once per distinct span, blame reads every annotated file, and listCommits reads the whole history reachable from HEAD"
 * @mitigates #blame against #dos using #resource-limits -- "30 s timeout and 64 MiB output cap per call; one blame per file; sha resolution and path queries batched; -L only for symbol/block spans on clean files; the history walk is one call a caller can skip"
 * @flows GitRepo -> #blame via execFileSync -- "blame, log, ls-files, status and rev-parse output"
 * @handles pii on #blame -- "Author names, emails and dates from git log"
 * @comment -- "Read-only by construction: no command here writes to the repository, and optional index refreshes are disabled"
 */
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { RawCommit } from './types.js';

export const ZERO_SHA = '0'.repeat(40);

/** Runs one git command in `root` and returns stdout; throws when git fails. */
export type GitExec = (root: string, argv: string[]) => string;

const TIMEOUT_MS = 30_000;
const MAX_BUFFER = 64 * 1024 * 1024;
/** Shas per `git log --no-walk` call: 500 × 41 bytes stays well under every argv limit. */
const RESOLVE_CHUNK = 500;
/** Paths per `ls-files` / `status` call. */
const PATH_CHUNK = 200;

const SHA_RE = /^[0-9a-f]{40}$/;
const FIELD = '\x1f';
const RECORD = '\x1e';

export const gitExec: GitExec = (root, argv) =>
  execFileSync('git', ['-c', 'core.quotePath=false', ...argv], {
    cwd: root,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
    env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' },
  });

function tryExec(root: string, argv: string[], exec: GitExec): string | null {
  try {
    return exec(root, argv);
  } catch {
    return null;
  }
}

function* chunks<T>(items: T[], size: number): Generator<T[]> {
  for (let i = 0; i < items.length; i += size) yield items.slice(i, i + size);
}

export function isGitRepo(root: string, exec: GitExec = gitExec): boolean {
  return tryExec(root, ['rev-parse', '--is-inside-work-tree'], exec)?.trim() === 'true';
}

export function isShallow(root: string, exec: GitExec = gitExec): boolean {
  return tryExec(root, ['rev-parse', '--is-shallow-repository'], exec)?.trim() === 'true';
}

export function headSha(root: string, exec: GitExec = gitExec): string | null {
  const out = tryExec(root, ['rev-parse', 'HEAD'], exec)?.trim();
  return out && SHA_RE.test(out) ? out : null;
}

/** Which of `files` git tracks. Paths are root-relative with `/` separators. */
export function trackedFiles(root: string, files: string[], exec: GitExec = gitExec): Set<string> {
  const set = new Set<string>();
  for (const chunk of chunks(files, PATH_CHUNK)) {
    const out = tryExec(root, ['ls-files', '-z', '--', ...chunk], exec) ?? '';
    for (const p of out.split('\0')) if (p) set.add(p);
  }
  return set;
}

/** Which of `files` differ from HEAD (modified, staged, or untracked). */
export function dirtyFiles(root: string, files: string[], exec: GitExec = gitExec): Set<string> {
  const set = new Set<string>();
  for (const chunk of chunks(files, PATH_CHUNK)) {
    const out = tryExec(root, ['status', '--porcelain', '-z', '--untracked-files=all', '--', ...chunk], exec) ?? '';
    const parts = out.split('\0');
    for (let i = 0; i < parts.length; i++) {
      const entry = parts[i];
      if (entry.length < 4) continue;
      set.add(entry.slice(3));
      // A rename or copy is followed by the origin path as its own entry.
      if (entry[0] === 'R' || entry[0] === 'C') i++;
    }
  }
  return set;
}

export interface BlameLine {
  /** 1-based line number in the working file. */
  line: number;
  /** Commit that last touched the line; `ZERO_SHA` when not yet committed. */
  sha: string;
}

/** `git blame --line-porcelain`: every group opens with `<sha> <orig> <final> [count]`. */
export function parseBlamePorcelain(text: string): BlameLine[] {
  const out: BlameLine[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^([0-9a-f]{40}) \d+ (\d+)(?: \d+)?$/);
    if (m) out.push({ line: Number(m[2]), sha: m[1] });
  }
  return out;
}

/**
 * Blame the whole working file once; callers slice spans in memory.
 * Throws when git cannot blame the file (untracked, missing, not a repo).
 */
export function blameFile(root: string, file: string, ignoreRevs: string | null, exec: GitExec = gitExec): BlameLine[] {
  const argv = ['blame', '--line-porcelain'];
  if (ignoreRevs && existsSync(join(root, ignoreRevs))) argv.push('--ignore-revs-file', ignoreRevs);
  argv.push('--', file);
  return parseBlamePorcelain(exec(root, argv));
}

function lastSha(out: string | null): string | null {
  if (!out) return null;
  const shas = out.split('\n').map(l => l.trim()).filter(l => SHA_RE.test(l));
  return shas.length > 0 ? shas[shas.length - 1] : null;
}

/**
 * The oldest commit in the span's line history — the one that introduced it.
 * `-L` resolves line numbers against HEAD, so callers only ask for clean files.
 * A path containing `:` cannot be expressed in `-L` and yields null.
 */
export function spanOldestCommit(root: string, file: string, start: number, end: number, exec: GitExec = gitExec): string | null {
  if (file.includes(':')) return null;
  const s = Math.max(1, Math.floor(start));
  const e = Math.max(s, Math.floor(end));
  return lastSha(tryExec(root, ['log', '--format=%H', '--no-patch', `-L${s},${e}:${file}`], exec));
}

/** The commit that added the file, following renames. Null when git has never seen it. */
export function fileAddCommit(root: string, file: string, exec: GitExec = gitExec): string | null {
  return lastSha(tryExec(root, ['log', '--format=%H', '--diff-filter=A', '--follow', '--', file], exec));
}

/** Records are `\x1e`-terminated; fields are `\x1f`-separated; the trailer block may span lines. */
export function parseLogRecords(text: string): RawCommit[] {
  const out: RawCommit[] = [];
  for (const rec of text.split(RECORD)) {
    const body = rec.replace(/^\n+/, '');
    if (body.trim() === '') continue;
    const f = body.split(FIELD);
    if (f.length < 6) continue;
    const sha = f[0].trim();
    if (!SHA_RE.test(sha)) continue;
    out.push({
      sha,
      authorName: f[1],
      authorEmail: f[2],
      date: f[3],
      committerName: f[4],
      trailers: f.slice(5).join(FIELD).replace(/\n+$/, ''),
    });
  }
  return out;
}

/** `%aN`/`%aE`/`%cN` honour `.mailmap`, so one person under two git identities is one identity here. */
const LOG_FORMAT = '--format=%H%x1f%aN%x1f%aE%x1f%aI%x1f%cN%x1f%(trailers:only,unfold)%x1e';

/** Author, date and trailer block for each sha, resolved in batches. The zero sha is never asked for. */
export function resolveCommits(root: string, shas: string[], exec: GitExec = gitExec): Map<string, RawCommit> {
  const unique = [...new Set(shas.filter(s => SHA_RE.test(s) && s !== ZERO_SHA))];
  const map = new Map<string, RawCommit>();
  for (const chunk of chunks(unique, RESOLVE_CHUNK)) {
    const out = tryExec(root, ['log', '--no-walk', LOG_FORMAT, ...chunk], exec);
    if (out === null) continue;
    for (const rc of parseLogRecords(out)) map.set(rc.sha, rc);
  }
  return map;
}

/**
 * Every commit reachable from HEAD, newest first, with the fields
 * `resolveCommits` reads — the denominator of every "per 100 commits" rate
 * and the source of `as_of`. `HEAD --` pins the argument as a revision even
 * when a file is named HEAD. An empty repository (no HEAD yet) or a plain
 * directory is an empty history, not an error.
 *
 * @exposes #blame to #dos [low] cwe:CWE-400 -- "listCommits() runs git log over every commit reachable from HEAD and parseLogRecords() parses each trailer block; history size, not model size, sets the cost"
 * @mitigates #blame against #dos using #resource-limits -- "A single log call under the same 30 s timeout and 64 MiB output cap; nothing is spawned per commit, and compute.ts lets a caller skip the walk with history: false"
 * @handles pii on #blame -- "Author names, emails and co-author trailers of every commit in the history"
 * @flows GitRepo -> #blame via listCommits -- "The reachable history, for commit counts and the HEAD author date"
 * @comment -- "Reachable from HEAD only, never --all: what other branches carry is not this checkout's history"
 */
export function listCommits(root: string, exec: GitExec = gitExec): RawCommit[] {
  const out = tryExec(root, ['log', LOG_FORMAT, 'HEAD', '--'], exec);
  return out === null ? [] : parseLogRecords(out);
}
