/**
 * `guardlink ci` — telling an empty model apart from a finished one.
 *
 * The gate answered "is anything wrong with what this repository says" and
 * never "does this repository say anything". Measured (release-flows-end-to-end,
 * caveat 3, second half): a repository with zero annotations and a repository
 * whose every risk is mitigated produce the SAME line and the SAME exit code —
 *
 *   ✓ No unmitigated exposures, no confirmed exploits, no anchor drift, …
 *   [exit=0]
 *
 * That is `#vacuous-pass` in our own gate, and the gate is the thing people
 * wire into CI: a model that was never written passes it identically to one
 * that was finished, so a pipeline can go green for the wrong reason forever.
 *
 * Two repairs, and they are deliberately different in kind:
 *
 *   The coverage LINE is unconditional. It is a denominator, and a count of
 *   zero findings over zero annotations is a different sentence from zero over
 *   four hundred. Printing it changes no exit code and breaks no pipeline.
 *
 *   The coverage FLOOR is opt-in, via `--min-coverage`. An existing user's
 *   pipeline must not start failing because they upgraded — so the floor exists
 *   only when someone types a number, and asking for it IS the opt-in: it gates
 *   on its own, without `--strict`, because a floor nobody can fail is not one.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

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

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

/** Four source files, every risk answered. The shape of a repository that finished. */
const CLEAN = `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

/** The same four files with nothing written on any of them. */
const BARE = 'export function login(email: string) { return email; }\n';

async function scaffold(prefix: string, source: string, withDefinitions: boolean): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"floor-fixture","version":"1.0.0"}\n');
  if (withDefinitions) await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  else await writeFile(join(root, '.guardlink', 'definitions.ts'), 'export {};\n');
  await writeFile(join(root, 'src', 'api.ts'), source);
  for (const f of ['b', 'c', 'd']) await writeFile(join(root, 'src', `${f}.ts`), BARE);
  return root;
}

describe('an empty model and a finished one are no longer the same answer', () => {
  let empty: string;
  let clean: string;
  let runs: Record<'emptyStrict' | 'cleanStrict' | 'emptyJson' | 'cleanJson', Run>;

  beforeAll(async () => {
    [empty, clean] = await Promise.all([
      scaffold('guardlink-ci-empty-', BARE, false),
      scaffold('guardlink-ci-clean-', CLEAN, true),
    ]);
    const [emptyStrict, cleanStrict, emptyJson, cleanJson] = await Promise.all([
      guardlink(empty, 'ci', '.', '--strict'),
      guardlink(clean, 'ci', '.', '--strict'),
      guardlink(empty, 'ci', '.', '--format', 'json'),
      guardlink(clean, 'ci', '.', '--format', 'json'),
    ]);
    runs = { emptyStrict, cleanStrict, emptyJson, cleanJson };
  }, 90_000);
  afterAll(async () => {
    await Promise.all([rm(empty, { recursive: true, force: true }), rm(clean, { recursive: true, force: true })]);
  });

  it('the empty repository says out loud that it has nothing to say', () => {
    expect(runs.emptyStrict.stderr).toMatch(/Annotation coverage: 0%/);
    expect(runs.emptyStrict.stderr).toMatch(/0 annotation/);
  });

  it('the finished repository reports coverage it actually has', () => {
    expect(runs.cleanStrict.stderr).toMatch(/Annotation coverage: (?!0%)/);
  });

  it('the two ticks no longer read identically', () => {
    const tickOf = (r: Run) => r.stderr.split('\n').filter(l => l.includes('Annotation coverage')).join('\n');
    expect(tickOf(runs.emptyStrict)).not.toBe(tickOf(runs.cleanStrict));
  });

  it('and neither exit code moved, because no floor was asked for', () => {
    expect(runs.emptyStrict.status).toBe(0);
    expect(runs.cleanStrict.status).toBe(0);
  });

  it('the JSON carries the numerator, the denominator and the unit rather than a bare percent', () => {
    const report = JSON.parse(runs.emptyJson.stdout);
    expect(report.summary.coverage).toMatchObject({
      kind: 'file', annotated_files: 0, percent: 0, annotations: 0, floor: null, below_floor: false,
    });
    expect(report.summary.coverage.source_files).toBeGreaterThan(0);
    expect(JSON.parse(runs.cleanJson.stdout).summary.coverage.annotations).toBeGreaterThan(0);
  });
});

describe('--min-coverage is the floor, and it is the user who sets it', () => {
  let empty: string;
  let clean: string;
  let runs: Record<'emptyFloor' | 'cleanFloor' | 'emptyFloorJson' | 'unreachable' | 'zeroFloor', Run>;

  beforeAll(async () => {
    [empty, clean] = await Promise.all([
      scaffold('guardlink-ci-floor-empty-', BARE, false),
      scaffold('guardlink-ci-floor-clean-', CLEAN, true),
    ]);
    const [emptyFloor, cleanFloor, emptyFloorJson, unreachable, zeroFloor] = await Promise.all([
      guardlink(empty, 'ci', '.', '--min-coverage', '20'),
      guardlink(clean, 'ci', '.', '--min-coverage', '20'),
      guardlink(empty, 'ci', '.', '--min-coverage', '20', '--format', 'json'),
      guardlink(clean, 'ci', '.', '--min-coverage', '101'),
      guardlink(empty, 'ci', '.', '--min-coverage', '0'),
    ]);
    runs = { emptyFloor, cleanFloor, emptyFloorJson, unreachable, zeroFloor };
  }, 90_000);
  afterAll(async () => {
    await Promise.all([rm(empty, { recursive: true, force: true }), rm(clean, { recursive: true, force: true })]);
  });

  it('an empty model fails the floor, WITHOUT --strict — asking for a floor is the opt-in', () => {
    expect(runs.emptyFloor.status).toBe(1);
    expect(runs.emptyFloor.stderr).toMatch(/below the 20% floor/);
  });

  it('says why the checks above cannot be trusted, rather than only that a number is small', () => {
    expect(runs.emptyFloor.stderr).toMatch(/nothing to fail/);
  });

  it('a model that clears the floor passes it and says so', () => {
    expect(runs.cleanFloor.status).toBe(0);
    expect(runs.cleanFloor.stderr).toMatch(/floor 20% met/);
  });

  it('the JSON verdict matches the shell, as every other ci verdict does', () => {
    const report = JSON.parse(runs.emptyFloorJson.stdout);
    expect(report.summary.coverage.floor).toBe(20);
    expect(report.summary.coverage.below_floor).toBe(true);
    expect(report.summary.exit_code).toBe(1);
  });

  it('a floor outside 0..100 is refused rather than silently unreachable', () => {
    expect(runs.unreachable.status).toBe(1);
    expect(runs.unreachable.stderr).toMatch(/Invalid --min-coverage/);
    expect(runs.unreachable.stderr).toMatch(/0 and 100/);
  });

  it('--min-coverage 0 is a floor nothing can fail, and it is honoured rather than treated as absent', () => {
    expect(runs.zeroFloor.status).toBe(0);
    expect(runs.zeroFloor.stderr).toMatch(/floor 0% met/);
  });
});

describe('the floor measures what --scope narrowed to, not the whole tree', () => {
  let root: string;
  let runs: Record<'wholeTree' | 'scopedToBare' | 'scopedToAnnotated', Run>;

  beforeAll(async () => {
    // One annotated area and one that nobody has touched. Whole-tree coverage
    // clears a low floor; the pipeline that owns `bare/` must still fail it.
    root = await mkdtemp(join(tmpdir(), 'guardlink-ci-floor-scope-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'covered'), { recursive: true });
    await mkdir(join(root, 'bare'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"floor-scope","version":"1.0.0"}\n');
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'covered', 'api.ts'), CLEAN);
    for (const f of ['a', 'b', 'c']) await writeFile(join(root, 'bare', `${f}.ts`), BARE);

    const [wholeTree, scopedToBare, scopedToAnnotated] = await Promise.all([
      guardlink(root, 'ci', '.', '--min-coverage', '20'),
      guardlink(root, 'ci', '.', '--min-coverage', '20', '--scope', 'bare'),
      guardlink(root, 'ci', '.', '--min-coverage', '20', '--scope', 'covered'),
    ]);
    runs = { wholeTree, scopedToBare, scopedToAnnotated };
  }, 90_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('clears the floor across the whole tree', () => {
    expect(runs.wholeTree.status).toBe(0);
  });

  it('but fails it inside the area that has nothing', () => {
    expect(runs.scopedToBare.status).toBe(1);
    expect(runs.scopedToBare.stderr).toMatch(/below the 20% floor/);
  });

  it('and passes inside the area that does', () => {
    expect(runs.scopedToAnnotated.status).toBe(0);
  });
});
