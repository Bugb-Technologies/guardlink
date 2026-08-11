/**
 * `guardlink ci` — the advisory CI face over coverage (D36) and anchor drift (GL-505).
 *
 * Every case here builds a real repo on disk and drives the real CLI, because
 * the thing under test is an EXIT CODE and a stream, not a return value. An
 * in-process assertion on `runCiChecks` would happily pass while the command
 * exited 1 on a first-run repo — which is the single failure this story exists
 * to prevent, since a gate that fails the day annotations land gets deleted the
 * week after.
 *
 * The drift fixture externalises its annotations into a `.gal` sidecar and then
 * edits the source the way an editor would (imports inserted above the symbol),
 * rather than hand-writing a wrong `line:` — a fabricated anchor would test the
 * reporting and skip the detection.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');

interface Run { status: number; stdout: string; stderr: string }

/**
 * Run the CLI under tsx in `cwd`, capturing both streams and the exit code.
 *
 * Resolves rather than rejecting on a non-zero exit: the exit code is half of
 * what these tests assert, and the human output goes to stderr even on a
 * SUCCESSFUL run, so both streams are wanted whichever way the process ends.
 */
function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile('npx', ['tsx', cli, ...args], { cwd, encoding: 'utf-8' }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

/**
 * Every distinct invocation a describe asserts on, run once and all at once.
 *
 * `npx tsx` costs ~1s per launch locally and GitHub's shared runners spawn
 * roughly 5x slower, so seventeen serial spawns under vitest's 5000ms default
 * timeout left this file one runner hiccup from red — which is how it first
 * failed on CI while passing everywhere else. `ci` reports and never repairs,
 * so these runs are read-only and independent: Promise.all collapses a
 * describe's spawns into roughly one launch of wall time, and the `it` blocks
 * assert against the captured Run instead of launching their own. The global
 * testTimeout stays where it is, so the NEXT slow test still surfaces.
 */
async function warm<K extends string>(cwd: string, plan: Record<K, string[]>): Promise<Record<K, Run>> {
  const keys = Object.keys(plan) as K[];
  const runs = await Promise.all(keys.map(k => guardlink(cwd, ...plan[k])));
  return Object.fromEntries(keys.map((k, i) => [k, runs[i]])) as Record<K, Run>;
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.DB (#db) -- "Database"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat Path_Traversal (#pt) [medium] cwe:CWE-22 -- "Untrusted path segments"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 * @control Path_Validation (#path-validation) -- "Resolved and prefix-checked"
 */
export {};
`;

/** Two exposures, no controls: critical + medium, both uncovered. */
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

/** The same two risks, both mitigated — the shape of a repo that has finished. */
const CLEAN_SOURCE = `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }

/**
 * @exposes #db to #pt [medium] cwe:CWE-22 -- "path segment from the request"
 * @mitigates #db against #pt using #path-validation -- "resolve() then prefix check"
 */
export function read(path: string) { return path; }
`;

async function scaffold(prefix: string, source: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"ci-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), source);
  return root;
}

// ─── unmitigated exposures ───────────────────────────────────────────

describe('exposures are reported and, by default, do not fail the build', () => {
  let root: string;
  let runs: Record<'advisory' | 'strict' | 'json', Run>;

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-exposed-', EXPOSED_SOURCE);
    runs = await warm(root, {
      advisory: ['ci', '.'],
      strict: ['ci', '.', '--strict'],
      json: ['ci', '.', '--format', 'json'],
    });
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('lists every unmitigated exposure and exits 0', () => {
    expect(runs.advisory.status).toBe(0);
    expect(runs.advisory.stderr).toContain('2 unmitigated exposure(s)');
    expect(runs.advisory.stderr).toContain('#api → #sqli [critical]');
    expect(runs.advisory.stderr).toContain('#db → #pt [medium]');
    expect(runs.advisory.stderr).toContain('src/api.ts');
  });

  it('summarises the counts by severity', () => {
    expect(runs.advisory.stderr).toContain('Unmitigated exposures: 2 (critical 1, medium 1)');
  });

  it('says it did not block', () => {
    expect(runs.advisory.stderr).toContain('Advisory');
  });

  it('--strict turns the same finding into exit 1', () => {
    expect(runs.strict.status).toBe(1);
    expect(runs.strict.stderr).toContain('2 unmitigated exposure(s)');
  });

  it('the JSON summary counts match the listed exposures', () => {
    const report = JSON.parse(runs.json.stdout);
    expect(report.summary.exposures).toBe(report.exposures.length);
    expect(report.summary.by_severity).toEqual({
      critical: 1, high: 0, medium: 1, low: 0, unset: 0,
    });
  });
});

// ─── @source anchor drift ────────────────────────────────────────────

describe('drifted @source anchors are reported and, by default, do not fail the build', () => {
  let root: string;
  let runs: Record<'advisory' | 'json' | 'strict' | 'strictJson', Run>;
  /** The sidecar as written, and as it stands after every run above has been made. */
  let sidecarBefore: string;
  let sidecarAfter: string;
  const sidecar = join('.guardlink', 'annotations', 'src', 'api.ts.gal');

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-drift-',
      'export function login(email) { return email; }\n');
    // Externalise: the exposure lives in a sidecar anchored at src/api.ts:1.
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, sidecar),
      '@source file:src/api.ts line:1 symbol:login\n'
      + '@exposes #api to #sqli [critical] -- "email concatenated into SQL"\n'
      + '@mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"\n');
    // Then a real refactor: three imports above push `login` from line 1 to 5.
    await writeFile(join(root, 'src', 'api.ts'),
      "import a from 'a';\nimport b from 'b';\nimport c from 'c';\n\n"
      + 'export function login(email) { return email; }\n');

    sidecarBefore = await readFile(join(root, sidecar), 'utf-8');
    runs = await warm(root, {
      advisory: ['ci', '.'],
      json: ['ci', '.', '--format', 'json'],
      strict: ['ci', '.', '--strict'],
      strictJson: ['ci', '.', '--format', 'json', '--strict'],
    });
    sidecarAfter = await readFile(join(root, sidecar), 'utf-8');
  }, 60_000);

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it("reports kind 'moved' with the suggested line, and exits 0", () => {
    expect(runs.advisory.status).toBe(0);
    expect(runs.advisory.stderr).toContain('1 drifted @source block(s)');
    expect(runs.advisory.stderr).toContain('[moved]');
    expect(runs.advisory.stderr).toContain('is now at line 5');
  });

  it('the drift record is serialized as AnchorDrift, field names unchanged', () => {
    const report = JSON.parse(runs.json.stdout);
    expect(report.drift).toHaveLength(1);
    expect(report.drift[0]).toMatchObject({
      gal_file: '.guardlink/annotations/src/api.ts.gal',
      file: 'src/api.ts',
      recorded_line: 1,
      symbol: 'login',
      kind: 'moved',
      suggested_line: 5,
    });
    expect(report.summary.by_kind).toEqual({
      moved: 1, symbol_gone: 0, file_gone: 0, line_gone: 0,
    });
  });

  it('--strict fails on drift alone, with no unmitigated exposure present', () => {
    expect(runs.strict.status).toBe(1);
    const report = JSON.parse(runs.strictJson.stdout);
    expect(report.summary.exposures).toBe(0);
    expect(report.summary.drift).toBe(1);
    expect(report.summary.exit_code).toBe(1);
  });

  // Brackets the whole batch, `--strict` included, rather than one run: every
  // invocation this file makes has to leave the anchor where the human put it.
  it('leaves the drifted sidecar alone — reports, never repairs', () => {
    expect(sidecarAfter).toBe(sidecarBefore);
    expect(sidecarAfter).toContain('line:1');
  });
});

// ─── the clean repo ──────────────────────────────────────────────────

describe('a repo with nothing to report passes even under --strict', () => {
  let root: string;
  let runs: Record<'advisory' | 'strict' | 'json', Run>;

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-clean-', CLEAN_SOURCE);
    runs = await warm(root, {
      advisory: ['ci', '.'],
      strict: ['ci', '.', '--strict'],
      json: ['ci', '.', '--format', 'json'],
    });
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('reports clean and exits 0', () => {
    expect(runs.advisory.status).toBe(0);
    expect(runs.advisory.stderr).toContain('✓ No unmitigated exposures, no anchor drift.');
  });

  it('exits 0 under --strict too', () => {
    expect(runs.strict.status).toBe(0);
  });

  it('emits empty arrays and a zeroed summary', () => {
    const report = JSON.parse(runs.json.stdout);
    expect(report.exposures).toEqual([]);
    expect(report.drift).toEqual([]);
    expect(report.summary.exposures).toBe(0);
    expect(report.summary.drift).toBe(0);
    expect(report.summary.exit_code).toBe(0);
  });

  it('says zero drift out of zero anchors rather than a bare green check (D48)', () => {
    expect(runs.advisory.stderr)
      .toContain('Anchor drift: 0 (no anchored @source blocks to check)');
  });
});

// ─── the wire format ─────────────────────────────────────────────────

describe('--format json emits guardlink.ci/v1', () => {
  let root: string;
  let runs: Record<'json' | 'badFormat', Run>;

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-schema-', EXPOSED_SOURCE);
    runs = await warm(root, {
      json: ['ci', '.', '--format', 'json'],
      badFormat: ['ci', '.', '--format', 'yaml'],
    });
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('stdout parses and carries the schema id plus both arrays', () => {
    expect(runs.json.status).toBe(0);
    const report = JSON.parse(runs.json.stdout);
    expect(report.schema).toBe('guardlink.ci/v1');
    expect(Array.isArray(report.exposures)).toBe(true);
    expect(Array.isArray(report.drift)).toBe(true);
    expect(report.summary.strict).toBe(false);
  });

  it('serializes exposures with the parser field names, not new ones', () => {
    const report = JSON.parse(runs.json.stdout);
    const sqli = report.exposures.find((e: { threat: string }) => e.threat === '#sqli');
    expect(sqli).toMatchObject({
      asset: '#api',
      threat: '#sqli',
      severity: 'critical',
      external_refs: ['cwe:CWE-89'],
    });
    expect(sqli.location).toMatchObject({ file: 'src/api.ts' });
    expect(typeof sqli.location.line).toBe('number');
  });

  it('rejects an unknown --format instead of guessing', () => {
    expect(runs.badFormat.status).toBe(1);
    expect(runs.badFormat.stderr).toContain("Unknown --format 'yaml'");
  });
});
