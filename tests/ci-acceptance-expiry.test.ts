/**
 * `guardlink ci` and the acceptance that is about to lapse.
 *
 * Measured before this change (release-flows-end-to-end, caveat 14 / flow 6):
 * an `@accepts … until <11 days out>` produced
 *
 *   Acceptances: 1 in the model; 0 do not count as acceptances
 *   ✓ No unmitigated exposures, no confirmed exploits, no anchor drift,
 *     every acceptance accounted for.
 *   [exit=0]
 *
 * — an unqualified green tick eleven days before the signature covering a
 * critical exposure runs out. The horizon was already in the model; the gate
 * simply declined to mention it.
 *
 * The server register does mention it. `bugb_server/notify/lifecycle_transitions.py`
 * fires `ACCEPTANCE_EXPIRING` when `expires_at − warn_window` is crossed, with
 * `warn_window` the tenant's `notify_config.acceptance_warn_days` (default 14,
 * clamped 0..365). Two components disagreeing about whether a waiver is in
 * trouble would be the bug one level up, so the boundary here is the same
 * boundary, the default is the same default, and the verdict is the same
 * verdict: EXPIRING is a warning and the acceptance still counts, EXPIRED is
 * the state change — and `ci` already fails on that one, because an expired
 * acceptance stops covering and its exposures come back.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runCiChecks, formatCiReport } from '../src/ci/index.js';
import {
  DEFAULT_ACCEPTANCE_WARN_DAYS, MAX_ACCEPTANCE_WARN_DAYS,
  findExpiringAcceptances, readAcceptancePolicy, DEFAULT_ACCEPTANCE_POLICY,
} from '../src/parser/acceptance.js';
import { parseProject } from '../src/parser/parse-project.js';
import type { ThreatModel, ThreatModelAcceptance } from '../src/types/index.js';

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

const NOW = new Date('2026-09-14T09:00:00Z');

/** `NOW` plus `days`, as the `until` clause spells it. */
function until(days: number, from: Date = NOW): string {
  return new Date(from.getTime() + days * 86_400_000).toISOString().slice(0, 10);
}

const JUSTIFICATION = 'Internal-only admin tool behind SSO, no PII reaches this query';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.DB (#db) -- "Database"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat Path_Traversal (#pt) [medium] cwe:CWE-22 -- "Untrusted path segments"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

/**
 * One critical exposure, signed for by a real human with a real reason, whose
 * signature runs out in eleven days. The report's fixture, to the day.
 */
function lapsingSource(expires: string): string {
  return `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @accepts #sqli on #api by "Grace Hopper" until ${expires} -- "${JUSTIFICATION}"
 */
export function login(email: string) { return email; }
`;
}

async function scaffold(prefix: string, source: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"expiry-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), source);
  return root;
}

// ─── the predicate, and whose predicate it is ────────────────────────

describe('the warning boundary is the server register\'s, not a second opinion', () => {
  it('defaults to fourteen days, the server\'s DEFAULT_ACCEPTANCE_WARN_DAYS', () => {
    expect(DEFAULT_ACCEPTANCE_WARN_DAYS).toBe(14);
  });

  it('ceilings at a year, the server\'s MAX_ACCEPTANCE_WARN_DAYS and guardlink\'s own max horizon', () => {
    expect(MAX_ACCEPTANCE_WARN_DAYS).toBe(365);
    expect(MAX_ACCEPTANCE_WARN_DAYS).toBe(DEFAULT_ACCEPTANCE_POLICY.max_horizon_days);
  });

  it('the report\'s eleven-day case is inside the default window', () => {
    const model = modelWithAcceptances([acceptance(until(11))]);
    const found = findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, DEFAULT_ACCEPTANCE_WARN_DAYS, NOW);
    expect(found).toHaveLength(1);
    expect(found[0].days_remaining).toBe(11);
  });

  it('a horizon beyond the window is not mentioned', () => {
    const model = modelWithAcceptances([acceptance(until(90))]);
    expect(findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, DEFAULT_ACCEPTANCE_WARN_DAYS, NOW)).toEqual([]);
  });

  it('the boundary day itself is inside the window — `until` is inclusive everywhere else too', () => {
    const model = modelWithAcceptances([acceptance(until(14))]);
    expect(findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, 14, NOW)).toHaveLength(1);
    expect(findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, 13, NOW)).toEqual([]);
  });

  it('today is the last covered day, and it still reads as expiring rather than expired', () => {
    const model = modelWithAcceptances([acceptance(until(0))]);
    const found = findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, 14, NOW);
    expect(found).toHaveLength(1);
    expect(found[0].days_remaining).toBe(0);
  });

  it('a lapsed acceptance is NOT reported as expiring — it is expired, which is a different finding', () => {
    const model = modelWithAcceptances([acceptance(until(-1))]);
    expect(findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, 14, NOW)).toEqual([]);
  });

  it('a warn window of zero is a team asking for no warning at all, exactly as on the server', () => {
    const model = modelWithAcceptances([acceptance(until(1))]);
    expect(findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, 0, NOW)).toEqual([]);
  });

  it('an acceptance that does not count is not warned about — it is already reported as not counting', () => {
    const unqualified = acceptance(until(3));
    unqualified.accepted_by = undefined;
    const model = modelWithAcceptances([unqualified]);
    expect(findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, 14, NOW)).toEqual([]);
  });

  it('several at once come back soonest first', () => {
    const model = modelWithAcceptances([acceptance(until(9)), acceptance(until(2)), acceptance(until(13))]);
    const found = findExpiringAcceptances(model, DEFAULT_ACCEPTANCE_POLICY, 14, NOW);
    expect(found.map(f => f.days_remaining)).toEqual([2, 9, 13]);
  });
});

// ─── config, and what it may move ────────────────────────────────────

describe('the horizon is the project\'s to set, within the same clamp the server uses', () => {
  let root: string;
  beforeAll(async () => { root = await mkdtemp(join(tmpdir(), 'guardlink-warn-config-')); await mkdir(join(root, '.guardlink')); });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  async function policyWith(acceptance: unknown) {
    await writeFile(join(root, '.guardlink', 'config.json'), JSON.stringify({ acceptance }));
    return readAcceptancePolicy(root);
  }

  it('reads acceptance.warn_days', async () => {
    expect((await policyWith({ warn_days: 30 })).warn_days).toBe(30);
  });

  it('clamps above the ceiling rather than refusing — a warning boundary before the grant can never fire', async () => {
    expect((await policyWith({ warn_days: 3650 })).warn_days).toBe(MAX_ACCEPTANCE_WARN_DAYS);
  });

  it('an unreadable value falls back to the default rather than switching warnings off', async () => {
    expect((await policyWith({ warn_days: 'soon' })).warn_days).toBe(DEFAULT_ACCEPTANCE_WARN_DAYS);
  });

  it('zero is a real answer and survives — it is the one way to ask for silence', async () => {
    expect((await policyWith({ warn_days: 0 })).warn_days).toBe(0);
  });
});

// ─── the gate itself ─────────────────────────────────────────────────

describe('a lapsing acceptance qualifies the verdict without moving the exit code', () => {
  let report: ReturnType<typeof runCiChecks>;
  let text: string;
  let root: string;

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-lapsing-', lapsingSource(until(11)));
    const { model, diagnostics } = await parseProject({ root, project: 'expiry-fixture' });
    report = runCiChecks(root, model, { strict: true, diagnostics, now: NOW });
    text = formatCiReport(report);
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the exposure is covered today — the acceptance still counts', () => {
    expect(report.summary.exposures).toBe(0);
    expect(report.summary.unqualified_acceptances).toBe(0);
  });

  it('but the gate now says the signature is running out, and by when', () => {
    expect(report.summary.expiring_acceptances).toBe(1);
    expect(report.expiring_acceptances[0].days_remaining).toBe(11);
    expect(report.expiring_acceptances[0].acceptance.expires).toBe(until(11));
  });

  it('the green tick is no longer unqualified', () => {
    expect(text).toMatch(/lapsing within 14 days/);
    // The exact sentence the report caught: a tick with nothing after it.
    expect(text).not.toMatch(/every acceptance accounted for\.\s*$/);
  });

  it('names the file, the line, the signer and the date a reader has to act before', () => {
    expect(text).toContain('src/api.ts');
    expect(text).toContain('Grace Hopper');
    expect(text).toContain(until(11));
    expect(text).toMatch(/11 day\(s\) left/);
  });

  it('says what happens when it does lapse, so the warning is actionable', () => {
    expect(text).toMatch(/guardlink review \. --accept/);
    expect(text).toMatch(/unmitigated/);
  });

  it('and does NOT fail the build — nobody chose this date, and --strict is still about findings', () => {
    expect(report.summary.exit_code).toBe(0);
  });

  it('the JSON carries the window it judged against, so a green run says what it was green about', () => {
    expect(report.summary.acceptance_warn_days).toBe(14);
  });
});

describe('several acceptances in different states at once each read as themselves', () => {
  let text: string;
  let report: ReturnType<typeof runCiChecks>;
  let root: string;

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-mixed-acceptance-', `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @accepts #sqli on #api by "Grace Hopper" until ${until(3)} -- "${JUSTIFICATION}"
 */
export function login(email: string) { return email; }

/**
 * @exposes #db to #pt [medium] cwe:CWE-22 -- "path segment from the request"
 * @accepts #pt on #db by "Ada Lovelace" until ${until(-30)} -- "${JUSTIFICATION}"
 */
export function read(path: string) { return path; }
`);
    const { model, diagnostics } = await parseProject({ root, project: 'expiry-fixture' });
    report = runCiChecks(root, model, { strict: true, diagnostics, now: NOW });
    text = formatCiReport(report);
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the lapsed one is expired: it stops covering, and the exposure comes back', () => {
    expect(report.summary.exposures).toBe(1);
    expect(report.summary.unqualified_acceptances).toBe(1);
    expect(report.summary.exit_code).toBe(1);
  });

  it('the lapsing one is counted separately and is not double-reported as expired', () => {
    expect(report.summary.expiring_acceptances).toBe(1);
    expect(report.expiring_acceptances[0].days_remaining).toBe(3);
  });

  it('one count line indexes all three states, so a reader knows where to look', () => {
    expect(text).toMatch(/Acceptances: 2 in the model; 1 do(es)? not count[^\n]*1 lapsing within 14 days/);
  });
});

// ─── the green path, unmoved ─────────────────────────────────────────

describe('a clean model with nothing lapsing is exactly as quiet as before', () => {
  let root: string;
  let runs: Record<'strict' | 'json', Run>;

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-quiet-', `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @accepts #sqli on #api by "Grace Hopper" until ${until(200, new Date())} -- "${JUSTIFICATION}"
 */
export function login(email: string) { return email; }
`);
    const [strict, json] = await Promise.all([
      guardlink(root, 'ci', '.', '--strict'),
      guardlink(root, 'ci', '.', '--format', 'json'),
    ]);
    runs = { strict, json };
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('exits 0 and prints the tick with no caveat attached', () => {
    expect(runs.strict.status).toBe(0);
    expect(runs.strict.stderr).toMatch(/✓ No unmitigated exposures/);
    expect(runs.strict.stderr).not.toMatch(/lapsing within/);
  });

  it('the JSON says zero rather than omitting the field', () => {
    const report = JSON.parse(runs.json.stdout);
    expect(report.summary.expiring_acceptances).toBe(0);
    expect(report.expiring_acceptances).toEqual([]);
  });
});

// ─── end to end, on the real clock ───────────────────────────────────

describe('the reproduction from the release report, driven through the real CLI', () => {
  let root: string;
  let runs: Record<'strict' | 'json' | 'silenced', Run>;
  /** Eleven days from *today*, so this measures the shipped clock, not a pinned one. */
  const expires = until(11, new Date());

  beforeAll(async () => {
    root = await scaffold('guardlink-ci-lapsing-cli-', lapsingSource(expires));
    const [strict, json, silenced] = await Promise.all([
      guardlink(root, 'ci', '.', '--strict'),
      guardlink(root, 'ci', '.', '--format', 'json'),
      guardlink(root, 'ci', '.', '--strict', '--expiring-within', '0'),
    ]);
    runs = { strict, json, silenced };
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('no longer prints an unqualified green tick eleven days out', () => {
    expect(runs.strict.stderr).toMatch(/lapsing within 14 days/);
    expect(runs.strict.stderr).toContain(expires);
  });

  it('still exits 0 — a warning, and a CI job that was green yesterday is green today', () => {
    expect(runs.strict.status).toBe(0);
  });

  it('--expiring-within 0 turns the warning off for a team that does not want it', () => {
    expect(runs.silenced.status).toBe(0);
    expect(runs.silenced.stderr).not.toMatch(/lapsing within/);
  });

  it('--expiring-within refuses a value it cannot honour rather than narrowing to silence', async () => {
    const bad = await guardlink(root, 'ci', '.', '--expiring-within', 'soon');
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(/Invalid --expiring-within/);
    expect(bad.stderr).toMatch(/0 and 365/);
  });

  it('the JSON payload carries the finding with everything a dashboard needs', () => {
    const report = JSON.parse(runs.json.stdout);
    expect(report.summary.expiring_acceptances).toBe(1);
    const [finding] = report.expiring_acceptances;
    expect(finding.days_remaining).toBe(11);
    expect(finding.file).toBe('src/api.ts');
    expect(finding.acceptance.accepted_by).toBe('Grace Hopper');
    expect(report.summary.acceptance_register).toBe('code-annotations');
  });
});

// ─── helpers ─────────────────────────────────────────────────────────

function acceptance(expires: string): ThreatModelAcceptance {
  return {
    asset: '#api',
    threat: '#sqli',
    accepted_by: 'Grace Hopper',
    expires,
    description: JUSTIFICATION,
    location: { file: 'src/api.ts', line: 3 },
  } as ThreatModelAcceptance;
}

function modelWithAcceptances(acceptances: ThreatModelAcceptance[]): ThreatModel {
  return {
    version: '1.0.0', project: 'test', generated_at: '', source_files: 1,
    annotated_files: ['src/api.ts'], unannotated_files: [], annotations_parsed: acceptances.length,
    assets: [], threats: [], controls: [], mitigations: [], exposures: [], confirmed: [],
    acceptances, transfers: [], flows: [], boundaries: [], validations: [], audits: [],
    ownership: [], data_handling: [], assumptions: [], shields: [], features: [], comments: [],
    coverage: { annotation_count: acceptances.length, coverage_percent: 100 },
  } as ThreatModel;
}
