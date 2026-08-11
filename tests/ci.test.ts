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
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');

interface Run { status: number; stdout: string; stderr: string }

/**
 * Run the CLI under tsx in `cwd`, capturing both streams and the exit code.
 *
 * `spawnSync` rather than `execFileSync`: the human output goes to stderr on a
 * SUCCESSFUL run, and execFileSync only surfaces stderr by throwing.
 */
function guardlink(cwd: string, ...args: string[]): Run {
  const r = spawnSync('npx', ['tsx', cli, ...args], {
    cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'],
  });
  return { status: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
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

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-exposed-', EXPOSED_SOURCE);
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('lists every unmitigated exposure and exits 0', () => {
    const run = guardlink(root, 'ci', '.');
    expect(run.status).toBe(0);
    expect(run.stderr).toContain('2 unmitigated exposure(s)');
    expect(run.stderr).toContain('#api → #sqli [critical]');
    expect(run.stderr).toContain('#db → #pt [medium]');
    expect(run.stderr).toContain('src/api.ts');
  });

  it('summarises the counts by severity', () => {
    const run = guardlink(root, 'ci', '.');
    expect(run.stderr).toContain('Unmitigated exposures: 2 (critical 1, medium 1)');
  });

  it('says it did not block', () => {
    expect(guardlink(root, 'ci', '.').stderr).toContain('Advisory');
  });

  it('--strict turns the same finding into exit 1', () => {
    const run = guardlink(root, 'ci', '.', '--strict');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('2 unmitigated exposure(s)');
  });

  it('the JSON summary counts match the listed exposures', () => {
    const report = JSON.parse(guardlink(root, 'ci', '.', '--format', 'json').stdout);
    expect(report.summary.exposures).toBe(report.exposures.length);
    expect(report.summary.by_severity).toEqual({
      critical: 1, high: 0, medium: 1, low: 0, unset: 0,
    });
  });
});

// ─── @source anchor drift ────────────────────────────────────────────

describe('drifted @source anchors are reported and, by default, do not fail the build', () => {
  let root: string;

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-drift-',
      'export function login(email) { return email; }\n');
    // Externalise: the exposure lives in a sidecar anchored at src/api.ts:1.
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'api.ts.gal'),
      '@source file:src/api.ts line:1 symbol:login\n'
      + '@exposes #api to #sqli [critical] -- "email concatenated into SQL"\n'
      + '@mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"\n');
    // Then a real refactor: three imports above push `login` from line 1 to 5.
    await writeFile(join(root, 'src', 'api.ts'),
      "import a from 'a';\nimport b from 'b';\nimport c from 'c';\n\n"
      + 'export function login(email) { return email; }\n');
  }, 60_000);

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it("reports kind 'moved' with the suggested line, and exits 0", () => {
    const run = guardlink(root, 'ci', '.');
    expect(run.status).toBe(0);
    expect(run.stderr).toContain('1 drifted @source block(s)');
    expect(run.stderr).toContain('[moved]');
    expect(run.stderr).toContain('is now at line 5');
  });

  it('the drift record is serialized as AnchorDrift, field names unchanged', () => {
    const report = JSON.parse(guardlink(root, 'ci', '.', '--format', 'json').stdout);
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
    const run = guardlink(root, 'ci', '.', '--strict');
    expect(run.status).toBe(1);
    const report = JSON.parse(guardlink(root, 'ci', '.', '--format', 'json', '--strict').stdout);
    expect(report.summary.exposures).toBe(0);
    expect(report.summary.drift).toBe(1);
    expect(report.summary.exit_code).toBe(1);
  });

  it('leaves the drifted sidecar alone — reports, never repairs', () => {
    const before = execFileSync('cat', ['.guardlink/annotations/src/api.ts.gal'],
      { cwd: root, encoding: 'utf-8' });
    guardlink(root, 'ci', '.', '--strict');
    const after = execFileSync('cat', ['.guardlink/annotations/src/api.ts.gal'],
      { cwd: root, encoding: 'utf-8' });
    expect(after).toBe(before);
    expect(after).toContain('line:1');
  });
});

// ─── the clean repo ──────────────────────────────────────────────────

describe('a repo with nothing to report passes even under --strict', () => {
  let root: string;

  beforeAll(async () => { root = await scaffold('guardlink-ci-clean-', CLEAN_SOURCE); }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('reports clean and exits 0', () => {
    const run = guardlink(root, 'ci', '.');
    expect(run.status).toBe(0);
    expect(run.stderr).toContain('✓ No unmitigated exposures, no anchor drift.');
  });

  it('exits 0 under --strict too', () => {
    expect(guardlink(root, 'ci', '.', '--strict').status).toBe(0);
  });

  it('emits empty arrays and a zeroed summary', () => {
    const report = JSON.parse(guardlink(root, 'ci', '.', '--format', 'json').stdout);
    expect(report.exposures).toEqual([]);
    expect(report.drift).toEqual([]);
    expect(report.summary.exposures).toBe(0);
    expect(report.summary.drift).toBe(0);
    expect(report.summary.exit_code).toBe(0);
  });

  it('says zero drift out of zero anchors rather than a bare green check (D48)', () => {
    expect(guardlink(root, 'ci', '.').stderr)
      .toContain('Anchor drift: 0 (no anchored @source blocks to check)');
  });
});

// ─── the wire format ─────────────────────────────────────────────────

describe('--format json emits guardlink.ci/v1', () => {
  let root: string;

  beforeAll(async () => { root = await scaffold('guardlink-ci-schema-', EXPOSED_SOURCE); }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('stdout parses and carries the schema id plus both arrays', () => {
    const run = guardlink(root, 'ci', '.', '--format', 'json');
    expect(run.status).toBe(0);
    const report = JSON.parse(run.stdout);
    expect(report.schema).toBe('guardlink.ci/v1');
    expect(Array.isArray(report.exposures)).toBe(true);
    expect(Array.isArray(report.drift)).toBe(true);
    expect(report.summary.strict).toBe(false);
  });

  it('serializes exposures with the parser field names, not new ones', () => {
    const report = JSON.parse(guardlink(root, 'ci', '.', '--format', 'json').stdout);
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
    const run = guardlink(root, 'ci', '.', '--format', 'yaml');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("Unknown --format 'yaml'");
  });
});
