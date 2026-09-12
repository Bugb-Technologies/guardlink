/**
 * `guardlink merge` — the estate-wide surface, and the three ways it used to
 * report success without having read anything.
 *
 * Measured on a two-repository fixture before this change, with the glob quoted
 * exactly as `link-project`'s own "Next steps" text and the documentation examples
 * write it:
 *
 *   merge '<star>/guardlink-report.json'  →  0/1 repos loaded · 0 unmitigated · exit 0
 *
 * Nothing expanded the glob that `merge --help` advertises, so the pattern reached
 * `readFile` as a literal filename; and the command had no verdict, only a
 * summary, so the empty model it produced left the process as a 0 and a dashboard
 * on disk reading clean. A user following GuardLink's own printed instructions got
 * a clean bill of health for an estate that was never opened.
 *
 * Every case here drives the real CLI, because the thing under test is an EXIT
 * CODE: an in-process assertion on `mergeVerdict` would pass happily while the
 * command still exited 0, which is the entire defect. The two unit blocks at the
 * end cover the shapes that are expensive to reach through a shell (dedupe,
 * ordering, a pattern that only the caller could have meant literally).
 *
 * The fixture is the one from the user-flow measurements: the exposure lives in
 * `orders-api` and the control that covers it lives in `platform-authz`, so a
 * merge that genuinely joins the two reports reads 0 unmitigated and either
 * repository alone reads 1. That makes "the glob loaded both" and "the join is
 * real" the same assertion rather than two.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, access } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveReportPaths, mergeVerdict } from '../src/workspace/index.js';
import type { MergedReport } from '../src/workspace/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
/** This repo's own tsx by absolute path — see the note in ci.test.ts. */
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

const DEFINITIONS = `// @asset Orders.Listing (#listing) -- "Order listing endpoint"
// @threat Broken_Access_Control (#bac) [high] cwe:CWE-639 -- "One tenant reads another's orders"
// @control Tenant_Guard (#tenant-guard) -- "Every query scoped by the session tenant"
`;

/** The risk. On its own: 1 unmitigated. */
const EXPOSED = `/**
 * @exposes #listing to #bac [high] cwe:CWE-639 -- "tenant id read from the request body"
 * @audit #listing -- "Needs a human to pick the control"
 */
export function list(tenant: string) { return tenant; }
`;

/** The control, in a different repository. Together with the above: 0 unmitigated. */
const MITIGATED = `/**
 * @mitigates #listing against #bac using #tenant-guard -- "Scopes every query by the session tenant"
 */
export function scope(q: string) { return q; }
`;

/** A reproduced exploit on the same pair. No acceptance silences one. */
const CONFIRMED = `/**
 * @confirmed #bac on #listing [high] cwe:CWE-639 -- "Reproduced: tenant B read tenant A's order list"
 */
export function probe(q: string) { return q; }
`;

/**
 * A workspace directory holding N repos, each with a real `guardlink-report.json`
 * cut by the real `report` command — not a hand-written JSON. A hand-written one
 * would test the merge against a shape nothing produces, and the first thing it
 * found was that `combineModels` reads fields a minimal fixture omits.
 */
async function scaffoldEstate(
  prefix: string,
  repos: Record<string, string>,
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await Promise.all(Object.entries(repos).map(async ([name, source]) => {
    const dir = join(root, name);
    await mkdir(join(dir, '.guardlink'), { recursive: true });
    await mkdir(join(dir, 'src'), { recursive: true });
    await writeFile(join(dir, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(dir, 'src', 'app.ts'), source);
    const run = await guardlink(dir, 'report', '.', '-p', name, '--format', 'json', '-o', 'guardlink-report.json');
    if (run.status !== 0) throw new Error(`fixture: report failed in ${name}: ${run.stderr}`);
  }));
  return root;
}

const exists = (p: string): Promise<boolean> => access(p).then(() => true, () => false);

// ─── the glob `--help` advertises ────────────────────────────────────

describe('a quoted glob is expanded by merge, not silently read as a filename', () => {
  let root: string;
  let globbed: Run;
  let explicit: Run;

  beforeAll(async () => {
    root = await scaffoldEstate('gl-merge-glob-', { 'orders-api': EXPOSED, 'platform-authz': MITIGATED });
    globbed = await guardlink(root, 'merge', '*/guardlink-report.json', '--summary-only');
    explicit = await guardlink(root, 'merge',
      'orders-api/guardlink-report.json', 'platform-authz/guardlink-report.json', '--summary-only');
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('loads every repository the pattern names', () => {
    expect(globbed.status).toBe(0);
    expect(globbed.stderr).toContain('2/2 repos loaded');
    expect(globbed.stderr).toContain('1 pattern(s) expanded');
  });

  it('joins across repositories: the control in one covers the exposure in the other', () => {
    expect(globbed.stderr).toContain('1 exposures | 0 unmitigated');
  });

  it('answers identically to the same files named explicitly', () => {
    // The point of the glob is to be a shorthand, not a second code path. The
    // merge timestamp is the one line that legitimately differs between two runs.
    const undated = (s: string): string => s.replace(/^\*\*Generated:\*\*.*$/m, '');
    expect(undated(globbed.stdout)).toBe(undated(explicit.stdout));
  });
});

// ─── zero repositories is never a pass ───────────────────────────────

describe('a glob that matches nothing fails, and says which pattern', () => {
  let root: string;
  let run: Run;

  beforeAll(async () => {
    root = await scaffoldEstate('gl-merge-nomatch-', { 'orders-api': EXPOSED });
    run = await guardlink(root, 'merge', 'absent-*/guardlink-report.json', '--summary-only');
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('exits non-zero', () => {
    expect(run.status).toBe(1);
  });

  it('names the pattern verbatim and says the repositories were never read', () => {
    expect(run.stderr).toContain('No report file matched "absent-*/guardlink-report.json"');
    expect(run.stderr).toContain('never read');
  });

  it('does not need --strict to fail: an unread estate is not a finding, it is the absence of one', () => {
    expect(run.stderr).not.toContain('Run with --strict');
  });
});

describe('zero repositories loaded fails even when every path was spelled out', () => {
  let root: string;
  let run: Run;

  beforeAll(async () => {
    root = await scaffoldEstate('gl-merge-zero-', { 'orders-api': EXPOSED });
    run = await guardlink(root, 'merge', 'gone.json');
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('exits non-zero and says the counts are an empty model\'s', () => {
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('0 of 1 repositories loaded');
    expect(run.stderr).toContain("an empty model's");
  });

  it('writes no dashboard — a file on disk outlives the exit code that qualified it', async () => {
    // This is the half of the defect an exit code alone does not fix: whoever
    // opens workspace-dashboard.html tomorrow sees "0 unmitigated" and no trace
    // of the fact that the merge behind it never opened a repository.
    expect(await exists(join(root, 'workspace-dashboard.html'))).toBe(false);
    expect(run.stderr).toContain('Nothing written');
  });
});

// ─── --strict ────────────────────────────────────────────────────────

describe('--strict gates on what the estate says', () => {
  let clean: string;
  let dirty: string;
  let runs: Record<'cleanStrict' | 'dirtyStrict' | 'dirtyAdvisory' | 'confirmedStrict', Run>;

  beforeAll(async () => {
    clean = await scaffoldEstate('gl-merge-strict-clean-', {
      'orders-api': EXPOSED, 'platform-authz': MITIGATED,
    });
    dirty = await scaffoldEstate('gl-merge-strict-dirty-', {
      'orders-api': EXPOSED, 'platform-authz': CONFIRMED,
    });
    const [cleanStrict, dirtyStrict, dirtyAdvisory, confirmedStrict] = await Promise.all([
      guardlink(clean, 'merge', '*/guardlink-report.json', '--summary-only', '--strict'),
      guardlink(dirty, 'merge', 'orders-api/guardlink-report.json', '--summary-only', '--strict'),
      guardlink(dirty, 'merge', 'orders-api/guardlink-report.json', '--summary-only'),
      guardlink(dirty, 'merge', 'platform-authz/guardlink-report.json', '--summary-only', '--strict'),
    ]);
    runs = { cleanStrict, dirtyStrict, dirtyAdvisory, confirmedStrict };
  }, 180_000);
  afterAll(async () => {
    await rm(clean, { recursive: true, force: true });
    await rm(dirty, { recursive: true, force: true });
  });

  it('exits 0 on a clean estate, and says so', () => {
    expect(runs.cleanStrict.status).toBe(0);
    expect(runs.cleanStrict.stderr).toContain('Estate clean');
  });

  it('exits 1 when anything is unmitigated', () => {
    expect(runs.dirtyStrict.status).toBe(1);
    expect(runs.dirtyStrict.stderr).toContain('1 unmitigated exposure(s)');
  });

  it('is opt-in: the same unmitigated estate is advisory without it', () => {
    expect(runs.dirtyAdvisory.status).toBe(0);
    expect(runs.dirtyAdvisory.stderr).toContain('Run with --strict to gate on it');
  });

  it('exits 1 on a reproduced exploit, which 0-unmitigated does not cover', () => {
    // The NodeGoat shape: nothing unmitigated, eight verified exploits, green.
    expect(runs.confirmedStrict.stderr).toContain('0 unmitigated');
    expect(runs.confirmedStrict.status).toBe(1);
    expect(runs.confirmedStrict.stderr).toContain('1 confirmed exploit(s)');
  });
});

describe('--strict fails a partially read estate, and only --strict does', () => {
  let root: string;
  let runs: Record<'strict' | 'advisory', Run>;

  beforeAll(async () => {
    root = await scaffoldEstate('gl-merge-partial-', {
      'orders-api': EXPOSED, 'platform-authz': MITIGATED,
    });
    const args = ['merge', 'orders-api/guardlink-report.json', 'platform-authz/guardlink-report.json',
      'billing-api/guardlink-report.json', '--summary-only'];
    const [strict, advisory] = await Promise.all([
      guardlink(root, ...args, '--strict'),
      guardlink(root, ...args),
    ]);
    runs = { strict, advisory };
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('names the repositories it could not read', () => {
    expect(runs.strict.status).toBe(1);
    expect(runs.strict.stderr).toContain('could not be read (billing-api)');
    expect(runs.strict.stderr).toContain('answered in part');
  });

  it('does not turn the existing advisory run red: a new repo that has not reported yet still exits 0', () => {
    expect(runs.advisory.status).toBe(0);
  });
});

// ─── the units that are awkward to reach through a shell ─────────────

describe('resolveReportPaths', () => {
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'gl-resolve-'));
    await mkdir(join(root, 'b'), { recursive: true });
    await mkdir(join(root, 'a'), { recursive: true });
    await writeFile(join(root, 'a', 'r.json'), '{}');
    await writeFile(join(root, 'b', 'r.json'), '{}');
  });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('expands a pattern to every match, in a stable order', async () => {
    const first = await resolveReportPaths(['*/r.json'], root);
    const second = await resolveReportPaths(['*/r.json'], root);
    expect(first.files).toHaveLength(2);
    expect(first.files).toEqual(second.files);
    expect(first.files.map(f => f.replace(root, ''))).toEqual([join('/a', 'r.json'), join('/b', 'r.json')]);
    expect(first.globbed).toEqual(['*/r.json']);
    expect(first.unmatched).toEqual([]);
  });

  it('passes a plain path through untouched, missing or not — loadAllReports names it per repo', async () => {
    const r = await resolveReportPaths(['a/r.json', 'nowhere/r.json'], root);
    expect(r.files).toHaveLength(2);
    expect(r.unmatched).toEqual([]);
    expect(r.globbed).toEqual([]);
  });

  it('reports a pattern that matched nothing, without inventing a path for it', async () => {
    const r = await resolveReportPaths(['zzz-*/r.json'], root);
    expect(r.files).toEqual([]);
    expect(r.unmatched).toEqual(['zzz-*/r.json']);
  });

  it('does not load a file twice when two patterns name it', async () => {
    const r = await resolveReportPaths(['a/r.json', '*/r.json'], root);
    expect(r.files).toHaveLength(2);
  });
});

describe('mergeVerdict', () => {
  /** Only the fields the verdict reads. */
  const report = (totals: Partial<MergedReport['totals']>, statuses: MergedReport['repo_statuses'] = []): MergedReport =>
    ({
      totals: {
        repos: statuses.length, repos_loaded: statuses.filter(s => s.loaded).length,
        annotations: 0, assets: 0, threats: 0, controls: 0, mitigations: 0,
        exposures: 0, unmitigated_exposures: 0, confirmed: 0, acceptances: 0,
        flows: 0, boundaries: 0, external_refs_resolved: 0, external_refs_unresolved: 0,
        ...totals,
      },
      repo_statuses: statuses,
    } as MergedReport);

  const loaded = [{ name: 'a', loaded: true }];

  it('passes a clean estate with and without --strict', () => {
    expect(mergeVerdict(report({}, loaded)).exit_code).toBe(0);
    expect(mergeVerdict(report({}, loaded), { strict: true }).exit_code).toBe(0);
  });

  it('fails an unread estate regardless of --strict', () => {
    const nothing = report({}, [{ name: 'a', loaded: false, error: 'ENOENT' }]);
    for (const strict of [false, true]) {
      const v = mergeVerdict(nothing, { strict });
      expect(v.exit_code).toBe(1);
      expect(v.failures.map(f => f.code)).toContain('nothing_loaded');
      expect(v.failures.every(f => !f.strict_only)).toBe(true);
    }
  });

  it('says nothing loaded once, naming the unmatched pattern as the cause', () => {
    const v = mergeVerdict(report({}, []), { unmatched: ['*/r.json'] });
    expect(v.exit_code).toBe(1);
    expect(v.failures.map(f => f.code)).toEqual(['unmatched_pattern']);
  });

  it('holds unmitigated and confirmed behind --strict, and reports them separately', () => {
    const dirty = report({ unmitigated_exposures: 3, confirmed: 1 }, loaded);
    expect(mergeVerdict(dirty).exit_code).toBe(0);
    const v = mergeVerdict(dirty, { strict: true });
    expect(v.exit_code).toBe(1);
    expect(v.failures.map(f => f.code)).toEqual(['confirmed', 'unmitigated']);
    expect(v.failures.every(f => f.strict_only)).toBe(true);
  });
});
