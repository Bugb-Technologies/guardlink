/**
 * Another checkout nested in the tree is not this repository.
 *
 * Claude Code's desktop app keeps one git worktree per session under
 * `<repo>/.claude/worktrees/<name>/`, each a full checkout with its own
 * `.guardlink/definitions.ts`. The parser walked into them, so on the guardlink
 * checkout with one worktree present `guardlink validate .` exited 1 with
 * "Duplicate identifier" for every definition id, and `hypothesis next` listed
 * every exposure twice — once at `src/…`, once at `.claude/worktrees/…/src/…`.
 * Coverage, the worklist and the session-start briefing were all inflated by
 * the copy.
 *
 * One rule, in `parser/nested-checkouts.ts`, shared by every walker: a
 * directory under `.claude/worktrees/`, or any directory holding a `.git` FILE
 * (git's worktree and submodule marker — a repository root has a `.git`
 * directory), is another checkout and is skipped. The root itself is never
 * one, even when the scan runs inside a worktree and the root carries that
 * marker.
 *
 * Tested through the module API, through each walker that shares the rule, and
 * through the CLI commands that read the model, because the symptom was in the
 * commands. The CLI fixture is a real `git worktree add`, the shape that broke.
 *
 * @validates #glob-filtering for #parser -- "A nested checkout — .claude/worktrees or a .git-file directory — is skipped by the scan, the worklist, clear, the fingerprint, agent-config discovery and search_codebase, and never reported as a duplicate id or a second exposure"
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { execFile, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject, DEFAULT_EXCLUDE } from '../src/parser/parse-project.js';
import { buildAnnotationWorklist } from '../src/parser/annotation-worklist.js';
import { clearAnnotations } from '../src/parser/clear.js';
import { fingerprintProject } from '../src/parser/fingerprint.js';
import { discover } from '../src/agentconfig/discover.js';
import { createToolExecutor } from '../src/analyze/tools.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

interface Run { status: number; stdout: string; stderr: string }

function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8' }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

async function warm<K extends string>(cwd: string, plan: Record<K, string[]>): Promise<Record<K, Run>> {
  const keys = Object.keys(plan) as K[];
  const runs = await Promise.all(keys.map(k => guardlink(cwd, ...plan[k])));
  return Object.fromEntries(keys.map((k, i) => [k, runs[i]])) as Record<K, Run>;
}

// ─── fixture ─────────────────────────────────────────────────────────

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.DB (#db) -- "Database"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat Path_Traversal (#pt) [medium] cwe:CWE-22 -- "Untrusted path segments"
 */
export {};
`;

/** Two exposures, no controls. */
const EXPOSED_SOURCE = `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @audit #api -- "Needs a human to pick the control"
 */
export function login(email: string) { return email; }

/**
 * @exposes #db to #pt [medium] cwe:CWE-22 -- "path segment from the request"
 * @audit #db -- "Needs a human to pick the control"
 */
export function read(path: string) { return path; }
`;

const PLAIN_SOURCE = 'export const answer = 42;\n';

type Marker = 'file' | 'dir' | 'none';

/**
 * One checkout's worth of files at `dir`: definitions, an annotated source
 * file, an unannotated one and an agent instruction file. `marker` is what
 * `.git` is there: a worktree's file, a repository's directory, or absent.
 */
async function writeCheckout(dir: string, marker: Marker): Promise<void> {
  await mkdir(join(dir, '.guardlink'), { recursive: true });
  await mkdir(join(dir, 'src'), { recursive: true });
  await writeFile(join(dir, 'package.json'), '{"name":"nested-fixture","version":"1.0.0"}\n');
  await writeFile(join(dir, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(dir, 'src', 'api.ts'), EXPOSED_SOURCE);
  await writeFile(join(dir, 'src', 'plain.ts'), PLAIN_SOURCE);
  await writeFile(join(dir, 'CLAUDE.md'), '# Agent rules\n');
  if (marker === 'file') {
    await writeFile(join(dir, '.git'), 'gitdir: /nowhere/.git/worktrees/x\n');
  } else if (marker === 'dir') {
    await mkdir(join(dir, '.git'), { recursive: true });
    await writeFile(join(dir, '.git', 'HEAD'), 'ref: refs/heads/main\n');
  }
}

/** An outer checkout with a full copy of itself at `nested`. */
async function scaffold(prefix: string, nested: string | null, nestedMarker: Marker, rootMarker: Marker = 'none'): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await writeCheckout(root, rootMarker);
  if (nested) await writeCheckout(join(root, nested), nestedMarker);
  return root;
}

const under = (prefix: string) => (path: string) => path === prefix || path.startsWith(`${prefix}/`);

// ─── the rule, through each walker ───────────────────────────────────

describe.each([
  { why: 'under .claude/worktrees, by name alone', nested: '.claude/worktrees/x', marker: 'none' as Marker },
  { why: 'anywhere, marked by a .git file', nested: 'checkouts/feature-a', marker: 'file' as Marker },
])('a nested checkout $why', ({ nested, marker }) => {
  let root: string;
  const inNested = under(nested);

  beforeAll(async () => { root = await scaffold('guardlink-nested-', nested, marker); });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('parses to one model: no duplicate ids, every exposure once, the nested files nowhere', async () => {
    const { model, diagnostics } = await parseProject({ root, project: 'fixture' });
    expect(diagnostics.filter(d => d.code === 'duplicate-id')).toEqual([]);
    expect(model.exposures.map(e => e.location.file)).toEqual(['src/api.ts', 'src/api.ts']);
    // The definitions file carries annotations, so it is an annotated file and
    // counts in `source_files` (GL-502): three outer files, two annotated.
    expect(model.annotated_files).toEqual(['.guardlink/definitions.ts', 'src/api.ts']);
    expect(model.unannotated_files).toEqual(['src/plain.ts']);
    expect(model.source_files).toBe(3);
    expect(JSON.stringify(model)).not.toContain(nested);
  });

  it('is neither listed nor counted by the annotation worklist', async () => {
    const { model } = await parseProject({ root, project: 'fixture' });
    const worklist = buildAnnotationWorklist(root, model);
    expect(worklist.worklist.map(f => f.path)).toEqual(['src/plain.ts']);
    expect(worklist.summary.worklist).toBe(1);
    expect(worklist.summary.annotated).toBe(1);
    expect([...worklist.annotated, ...worklist.excluded.map(x => x.path)].filter(inNested)).toEqual([]);
  });

  it('is left alone by clear', async () => {
    const result = await clearAnnotations({ root, dryRun: true });
    expect(result.modifiedFiles.some(f => f.endsWith('src/api.ts') && !f.includes(nested))).toBe(true);
    expect(result.modifiedFiles.filter(f => f.includes(nested))).toEqual([]);
  });

  it('does not move the scan fingerprint when a file inside it changes', async () => {
    const before = await fingerprintProject(root);
    await writeFile(join(root, nested, 'src', 'extra.ts'), PLAIN_SOURCE);
    expect(await fingerprintProject(root)).toBe(before);
    await writeFile(join(root, 'src', 'extra.ts'), PLAIN_SOURCE);
    expect(await fingerprintProject(root)).not.toBe(before);
    await rm(join(root, 'src', 'extra.ts'));
  });

  it("is not read as this repository's agent configuration", () => {
    const paths = discover(root).files.map(f => f.path);
    expect(paths).toContain('CLAUDE.md');
    expect(paths.filter(inNested)).toEqual([]);
  });

  it('is not searched by search_codebase', async () => {
    const run = createToolExecutor(root, null);
    const result = JSON.parse(await run('search_codebase', { pattern: 'function login' }));
    expect(result.matches.map((m: { file: string }) => m.file)).toEqual(['src/api.ts']);
  });
});

describe('what is not a nested checkout', () => {
  const roots: string[] = [];
  afterAll(async () => { await Promise.all(roots.map(r => rm(r, { recursive: true, force: true }))); });

  it('a nested copy with no marker is still parsed: the rule is the marker, not the depth', async () => {
    const root = await scaffold('guardlink-nested-plain-', 'checkouts/no-marker', 'none');
    roots.push(root);
    const { diagnostics } = await parseProject({ root, project: 'fixture' });
    expect(diagnostics.filter(d => d.code === 'duplicate-id').length).toBeGreaterThan(0);
  });

  it('a nested repository with a .git DIRECTORY is still parsed: a folder of repositories reads them all', async () => {
    const root = await scaffold('guardlink-nested-repo-', 'checkouts/clone', 'dir');
    roots.push(root);
    const { diagnostics } = await parseProject({ root, project: 'fixture' });
    expect(diagnostics.filter(d => d.code === 'duplicate-id').length).toBeGreaterThan(0);
  });

  it('the root itself, even when the scan runs inside a worktree and the root carries the marker', async () => {
    const root = await scaffold('guardlink-nested-root-', null, 'none', 'file');
    roots.push(root);
    const { model, diagnostics } = await parseProject({ root, project: 'fixture' });
    expect(diagnostics.filter(d => d.level === 'error')).toEqual([]);
    expect(model.exposures).toHaveLength(2);
    expect(model.source_files).toBe(3);
  });
});

// ─── the module ──────────────────────────────────────────────────────

describe('parser/nested-checkouts', () => {
  let root: string;
  beforeAll(async () => {
    root = await scaffold('guardlink-nested-api-', 'checkouts/feature-a', 'file');
    // A marker under an excluded directory: the walk must not have gone there.
    await mkdir(join(root, 'node_modules', 'dep'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'dep', '.git'), 'gitdir: /nowhere\n');
    await writeFile(join(root, 'node_modules', 'dep', 'index.ts'), EXPOSED_SOURCE);
  });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('names .claude/worktrees in the parser\'s own excludes', async () => {
    const { NESTED_CHECKOUT_GLOBS } = await import('../src/parser/nested-checkouts.js');
    expect(NESTED_CHECKOUT_GLOBS).toContain('**/.claude/worktrees/**');
    for (const glob of NESTED_CHECKOUT_GLOBS) expect(DEFAULT_EXCLUDE).toContain(glob);
  });

  it('finds every .git-file directory the scan would otherwise enter, and only those', async () => {
    const { findNestedCheckouts } = await import('../src/parser/nested-checkouts.js');
    const found = findNestedCheckouts(root, DEFAULT_EXCLUDE);
    expect(found.dirs).toEqual(['checkouts/feature-a']);
    expect(found.ignore).toEqual(['checkouts/feature-a/**']);
    expect(found.has('checkouts/feature-a/src/api.ts')).toBe(true);
    expect(found.has('checkouts/feature-a')).toBe(true);
    expect(found.has('.claude/worktrees/x/src/api.ts')).toBe(true);
    expect(found.has('checkouts/feature-ab/src/api.ts')).toBe(false);
    expect(found.has('src/api.ts')).toBe(false);
  });

  it('answers for one directory: a .git file, or a .claude/worktrees path', async () => {
    const { isNestedCheckout } = await import('../src/parser/nested-checkouts.js');
    expect(isNestedCheckout(join(root, 'checkouts', 'feature-a'), 'checkouts/feature-a')).toBe(true);
    expect(isNestedCheckout(join(root, 'nope', '.claude', 'worktrees'), 'nope/.claude/worktrees')).toBe(true);
    expect(isNestedCheckout(join(root, '.claude', 'worktrees'), '.claude/worktrees')).toBe(true);
    expect(isNestedCheckout(join(root, 'src'), 'src')).toBe(false);
    expect(isNestedCheckout(join(root, 'checkouts'), 'checkouts')).toBe(false);
  });
});

// ─── the commands, on a real worktree ────────────────────────────────

describe('the CLI on a checkout with a real git worktree under .claude/worktrees', () => {
  let root: string;
  let runs: Record<'validate' | 'parse' | 'ci' | 'next' | 'unannotated' | 'status', Run>;
  const git = (cwd: string, ...args: string[]) =>
    execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], { cwd, stdio: 'ignore' });

  beforeAll(async () => {
    root = await scaffold('guardlink-nested-cli-', null, 'none');
    git(root, 'init', '-q', '-b', 'main', '.');
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'fixture');
    // The shape that broke: the desktop app's per-session worktree, a full
    // checkout of this very repository, marked by a .git file.
    git(root, 'worktree', 'add', '-q', join('.claude', 'worktrees', 'x'), 'HEAD');
    runs = await warm(root, {
      validate: ['validate', '.'],
      parse: ['parse', '.'],
      ci: ['ci', '.', '--format', 'json'],
      next: ['hypothesis', 'next', '.', '--json'],
      unannotated: ['unannotated', '.', '--json'],
      status: ['status', '.'],
    });
  }, 90_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('validate exits 0 with no duplicate identifiers', () => {
    expect(runs.validate.stdout + runs.validate.stderr).not.toContain('Duplicate identifier');
    expect(runs.validate.status).toBe(0);
  });

  it('parse lists the worktree nowhere', () => {
    expect(runs.parse.status).toBe(0);
    const model = JSON.parse(runs.parse.stdout);
    expect(model.exposures).toHaveLength(2);
    expect(runs.parse.stdout).not.toContain('.claude/worktrees');
  });

  it('ci counts coverage over the outer files only', () => {
    expect(runs.ci.status).toBe(0);
    const report = JSON.parse(runs.ci.stdout);
    expect(report.summary.coverage).toMatchObject({ source_files: 3, annotated_files: 2 });
    expect(report.exposures).toHaveLength(2);
    expect(runs.ci.stdout).not.toContain('.claude/worktrees');
  });

  it('hypothesis next lists each exposure once', () => {
    expect(runs.next.status).toBe(0);
    const next = JSON.parse(runs.next.stdout);
    expect(next.total).toBe(2);
    expect(next.queue.map((q: { file: string }) => q.file)).toEqual(['src/api.ts', 'src/api.ts']);
  });

  it('unannotated --json neither lists nor counts the worktree', () => {
    expect(runs.unannotated.status).toBe(0);
    const worklist = JSON.parse(runs.unannotated.stdout);
    expect(worklist.worklist).toEqual([{ path: 'src/plain.ts', reason: 'unannotated' }]);
    expect(worklist.summary.worklist).toBe(1);
    expect(runs.unannotated.stdout).not.toContain('.claude/worktrees');
  });

  it('status counts the outer files only', () => {
    expect(runs.status.status).toBe(0);
    expect(runs.status.stdout).toContain('Files in scope:   3');
    expect(runs.status.stdout).toContain('  Files annotated:    2');
    expect(runs.status.stdout).toContain('Exposures:        2');
  });
});
