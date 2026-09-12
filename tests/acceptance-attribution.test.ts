/**
 * Three ways an accepted risk used to assert more than anyone checked.
 *
 * 1. THE SIGNER WAS INVENTED. `--by` documented itself as "defaults to git
 *    user.name, then the OS user", so an acceptance written without one carried
 *    whatever name a laptop's git config happened to hold — in the annotation,
 *    in the `@audit` line beside it, and in every surface downstream. A
 *    fabricated attribution renders identically to a real one, and nothing that
 *    reads it can tell the difference. Now `--by` is required on every
 *    unattended path, and the git identity only ever appears as a suggestion a
 *    human at a TTY confirms.
 *
 * 2. THE LEASE DEFAULTED TO THE MAXIMUM. `--until` defaulted to
 *    `max_horizon_days` days out, and `max_horizon_days` is also the ceiling
 *    the policy permits — so the path of least effort took the longest lease
 *    available, which is the exact inversion of what a default is for. Now the
 *    scripted paths require it and the interactive prompt suggests
 *    `default_horizon_days` (90).
 *
 * 3. NOBODY SAID WHICH REGISTER A NUMBER CAME FROM. Every acceptance GuardLink
 *    reports is read from `@accepts` in the repository's own code; the server's
 *    decision log, whose author is an authenticated principal, is a different
 *    register with opposite guarantees, and no surface said which one it was
 *    showing.
 *
 * The last block is the one that matters most to a customer: NONE of this is a
 * grammar or parser change, so acceptances already sitting in repositories must
 * keep parsing and keep suppressing exactly what they suppressed. A regression
 * there silently re-opens findings in trees nobody is looking at.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { applyReviewAction, getReviewableExposures, horizonFrom, ReviewRejected } from '../src/review/index.js';
import { explicitDecider, identitySuggestion } from '../src/review/entitlements.js';
import { buildCoverageIndex } from '../src/parser/coverage.js';
import {
  DEFAULT_ACCEPTANCE_POLICY, readAcceptancePolicy, acceptanceDefects,
  ACCEPTANCE_REGISTER_ID,
} from '../src/parser/acceptance.js';
import { runCiChecks, formatCiReport } from '../src/ci/index.js';
import { generateSarif } from '../src/analyzer/sarif.js';

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
 * @asset Data.UserDAO (#user-dao) -- "User data access"
 * @asset App.API (#api) -- "API surface"
 * @threat Plaintext_Password (#plaintext-password) [critical] cwe:CWE-256 -- "Password stored unhashed"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 */
export {};
`;

const DAO = `/**
 * @exposes #user-dao to #plaintext-password [critical] cwe:CWE-256 -- "password written to the users collection as typed"
 */
export function createUser(password: string) { return password; }
`;

/**
 * The name a fabricating default would have reached for. It is written into the
 * fixture's git config and must never turn up in anything the tool wrote.
 */
const LAPTOP_IDENTITY = 'Laptop Git Identity';

async function scaffold(prefix: string, extra: Record<string, string> = {}): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"acceptance-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'dao.ts'), DAO);
  for (const [rel, body] of Object.entries(extra)) {
    await mkdir(dirname(join(root, rel)), { recursive: true });
    await writeFile(join(root, rel), body);
  }
  // A repository whose git identity is exactly what the old default would have
  // signed an acceptance with.
  const git = (...args: string[]): void => {
    execFileSync('git', args, { cwd: root, stdio: ['ignore', 'ignore', 'ignore'] });
  };
  git('init', '-q');
  git('config', 'user.name', LAPTOP_IDENTITY);
  git('config', 'user.email', 'laptop@example.invalid');
  return root;
}

const GOOD = 'Legacy import path, read-only, migrating to argon2 in Q4';
const FUTURE = horizonFrom(30);

// ─── 1. the signer is never invented ─────────────────────────────────

describe('a signer is supplied or the acceptance is refused — never read off the machine', () => {
  let root: string;

  beforeAll(async () => { root = await scaffold('guardlink-attr-signer-'); }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('explicitDecider has no fallback at all, in a repo that has an identity to fall back to', () => {
    // The identity IS there — `identitySuggestion` finds it. The point is that
    // resolving a signer no longer consults it.
    expect(identitySuggestion(root)).toBe(LAPTOP_IDENTITY);
    expect(explicitDecider(undefined)).toBeUndefined();
    expect(explicitDecider('   ')).toBeUndefined();
    expect(explicitDecider('  Ada Lovelace ')).toBe('Ada Lovelace');
  });

  it('--accept without --by refuses, writes nothing, and never names the git identity', async () => {
    const listed = await guardlink(root, 'review', '.', '--list', '--format', 'json');
    const [target] = JSON.parse(listed.stdout);
    const run = await guardlink(root, 'review', '.', '--accept', target.id,
      '--justification', GOOD, '--until', FUTURE);

    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/name of the human/);
    expect(run.stderr).not.toContain(LAPTOP_IDENTITY);
    expect(await readFile(join(root, 'src', 'dao.ts'), 'utf-8')).toBe(DAO);
  }, 60_000);

  it('a --from batch row with no "by" is refused the same way', async () => {
    const listed = await guardlink(root, 'review', '.', '--list', '--format', 'json');
    const [target] = JSON.parse(listed.stdout);
    const batch = join(root, 'decisions.json');
    await writeFile(batch, JSON.stringify({
      decisions: [{ id: target.id, decision: 'accept', justification: GOOD, until: FUTURE }],
    }));
    const run = await guardlink(root, 'review', '.', '--from', batch);

    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/name of the human/);
    expect(await readFile(join(root, 'src', 'dao.ts'), 'utf-8')).toBe(DAO);
  }, 60_000);

  it('the refusal says why there is no default, rather than offering one', async () => {
    await expect(applyReviewAction(root, (await reviewable(root)), {
      decision: 'accept', justification: GOOD, until: FUTURE,
    })).rejects.toThrow(/not defaulted|used to fall back/);
  }, 60_000);

  it('with --by, the annotation carries that name and only that name', async () => {
    const listed = await guardlink(root, 'review', '.', '--list', '--format', 'json');
    const [target] = JSON.parse(listed.stdout);
    const run = await guardlink(root, 'review', '.', '--accept', target.id,
      '--by', 'Ada Lovelace', '--justification', GOOD, '--until', '2027-01-31');

    expect(run.status).toBe(0);
    const after = await readFile(join(root, 'src', 'dao.ts'), 'utf-8');
    expect(after).toContain('by "Ada Lovelace" until 2027-01-31');
    expect(after).not.toContain(LAPTOP_IDENTITY);
  }, 60_000);
});

/** The one reviewable exposure in a scaffolded fixture. */
async function reviewable(root: string): Promise<Awaited<ReturnType<typeof getReviewableExposures>>[number]> {
  const { model } = await parseProject({ root, project: 'tmp' });
  const found = getReviewableExposures(model).find(r => r.exposure.location.file === 'src/dao.ts');
  if (!found) throw new Error('fixture has no reviewable exposure in src/dao.ts');
  return found;
}

// ─── 2. omitting the expiry is not a way to get a year ───────────────

describe('the lease no longer defaults to the maximum', () => {
  let root: string;

  beforeAll(async () => { root = await scaffold('guardlink-attr-lease-'); }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the suggested horizon is strictly shorter than the ceiling', () => {
    expect(DEFAULT_ACCEPTANCE_POLICY.default_horizon_days).toBe(90);
    expect(DEFAULT_ACCEPTANCE_POLICY.default_horizon_days)
      .toBeLessThan(DEFAULT_ACCEPTANCE_POLICY.max_horizon_days);
  });

  it('a project that lowers the ceiling below the suggestion gets the ceiling', async () => {
    await writeFile(join(root, '.guardlink', 'config.json'),
      JSON.stringify({ acceptance: { max_horizon_days: 30 } }));
    expect(readAcceptancePolicy(root).default_horizon_days).toBe(30);
    await rm(join(root, '.guardlink', 'config.json'));
    expect(readAcceptancePolicy(root).default_horizon_days).toBe(90);
  });

  it('--accept with no --until refuses instead of taking the ceiling', async () => {
    const listed = await guardlink(root, 'review', '.', '--list', '--format', 'json');
    const [target] = JSON.parse(listed.stdout);
    const run = await guardlink(root, 'review', '.', '--accept', target.id,
      '--by', 'Ada Lovelace', '--justification', GOOD);

    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/--until <YYYY-MM-DD>/);
    // And the refusal offers the SHORT horizon, not the ceiling.
    expect(run.stderr).toContain(horizonFrom(DEFAULT_ACCEPTANCE_POLICY.default_horizon_days));
    expect(run.stderr).not.toContain(horizonFrom(DEFAULT_ACCEPTANCE_POLICY.max_horizon_days));
    expect(await readFile(join(root, 'src', 'dao.ts'), 'utf-8')).toBe(DAO);
  }, 60_000);

  it('a --from batch row with no "until" is refused too — the writer is the choke point', async () => {
    await expect(applyReviewAction(root, (await reviewable(root)), {
      decision: 'accept', justification: GOOD, by: 'Ada Lovelace',
    })).rejects.toThrow(ReviewRejected);
  }, 60_000);
});

// ─── 3. every surface names its register ─────────────────────────────

describe('an acceptance count says which register it came from', () => {
  let root: string;

  beforeAll(async () => {
    root = await scaffold('guardlink-attr-register-', {
      'src/signed.ts': `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @accepts #sqli on #api by "Grace Hopper" until 2099-01-31 -- "${GOOD}"
 * @audit #api -- "Accepted via guardlink review, expires 2099-01-31"
 */
export function login(email: string) { return email; }
`,
    });
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('guardlink ci names it in the text and in the JSON summary', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    const report = runCiChecks(root, model);
    expect(report.summary.acceptance_register).toBe(ACCEPTANCE_REGISTER_ID);
    expect(formatCiReport(report)).toMatch(/Acceptances: 1.*@accepts annotations in this repository/);
  }, 60_000);

  it('the SARIF envelope names it, without touching a single result', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    const sarif = generateSarif(model, []) as unknown as {
      runs: Array<{ results: unknown[]; properties: Record<string, unknown> }>;
    };
    expect(sarif.runs[0].properties.acceptance_register).toBe(ACCEPTANCE_REGISTER_ID);
    // §3.2: provenance lives in the envelope; no result carries it.
    for (const r of sarif.runs[0].results as Array<Record<string, unknown>>) {
      expect(JSON.stringify(r)).not.toContain('acceptance_register');
    }
  }, 60_000);

  it('the dashboard and the report say it in words', async () => {
    const dash = await guardlink(root, 'dashboard', '.', '-o', 'dash.html');
    expect(dash.status).toBe(0);
    const html = await readFile(join(root, 'dash.html'), 'utf-8');
    expect(html).toContain('not from the server decision log');

    const rep = await guardlink(root, 'report', '.', '-o', 'REPORT.md');
    expect(rep.status).toBe(0);
    expect(await readFile(join(root, 'REPORT.md'), 'utf-8'))
      .toContain('not from the server decision log');
  }, 120_000);

  it('guardlink status says it beside the count', async () => {
    const run = await guardlink(root, 'status', '.');
    expect(run.stdout + run.stderr).toMatch(/Acceptances:\s+1\s+\(source: @accepts annotations in this repository\)/);
  }, 60_000);
});

// ─── accepted is not refuted: two registers, side by side ────────────

/**
 * The hypothesis ledger gave an exposure a third state while this branch was
 * open, and `refuted` lands right next to `accepted`: both "not open", both blue
 * in the dashboard's table, and read from DIFFERENT registers. A refutation was
 * measured — evidence, an author and the code hash beneath the claim, in
 * `.guardlink/hypotheses.json`, lapsing by itself when the code moves. An
 * acceptance was signed — free text nobody verified. Reading the weaker claim as
 * the stronger one is the failure this whole file is about, so the two must not
 * be presentable as the same thing.
 */
describe('a refuted exposure and an accepted one name different registers', () => {
  let root: string;

  beforeAll(async () => {
    root = await scaffold('guardlink-attr-refuted-', {
      'src/signed.ts': `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @accepts #sqli on #api by "Grace Hopper" until 2099-01-31 -- "${GOOD}"
 * @audit #api -- "Accepted via guardlink review, expires 2099-01-31"
 */
export function login(email: string) { return email; }
`,
    });
    // dao.ts carries the exposure with no acceptance — refute that one, so the
    // fixture holds one of each.
    const run = await guardlink(root, 'hypothesis', 'refute', 'src/dao.ts:2',
      '--evidence', 'cxg scan returned 400 on every payload; reproduction confirms the write is parameterized upstream',
      '--by', 'Ada Lovelace');
    expect(run.status).toBe(0);
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('guardlink status labels each line with its own register', async () => {
    const out = await guardlink(root, 'status', '.').then(r => r.stdout + r.stderr);
    expect(out).toMatch(/Hypotheses:.*1 refuted.*\(source: \.guardlink\/hypotheses\.json\)/);
    expect(out).toMatch(/Acceptances:\s+1\s+\(source: @accepts annotations in this repository\)/);
  }, 60_000);

  it('the dashboard distinguishes the two rather than showing both as "not open"', async () => {
    const run = await guardlink(root, 'dashboard', '.', '-o', 'dash.html');
    expect(run.status).toBe(0);
    const html = await readFile(join(root, 'dash.html'), 'utf-8');
    // The refutation names the ledger and carries its evidence; the acceptance
    // names the annotations and says the signer is unverified.
    expect(html).toContain('evidence in the hypothesis ledger');
    expect(html).toContain('not from the server decision log');
    expect(html).toContain('the signer is free text and is not verified');
    // And the old claim the dashboard could not support is gone.
    expect(html).not.toContain('Accepted by a human');
  }, 120_000);
});

// ─── the regression that matters: annotations already in the wild ────

/**
 * Written the way they are found in customer trees — including the forms
 * `guardlink review` never produces. If any of these stops parsing or stops
 * covering, findings re-open in repositories nobody is looking at.
 */
const LEGACY = {
  // The current writer's own output shape.
  'src/legacy-full.ts': `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @accepts #sqli on #api by "Grace Hopper" until 2099-01-31 -- "Internal-only admin tool behind SSO, no PII reaches this query"
 */
export function a(email: string) { return email; }
`,
  // Unquoted single-token signer — the grammar's bare form.
  'src/legacy-bare.ts': `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "second site, same pair"
 * @accepts #sqli on #api by ada until 2099-01-31 -- "Internal-only admin tool behind SSO, no PII reaches this query"
 */
export function b(email: string) { return email; }
`,
  // No `by`, no `until` — the shape that predates the policy entirely. It is
  // UNQUALIFIED, and the gate has always said so; what must not change is that
  // it still parses and still lands in the model.
  'src/legacy-bare-minimum.ts': `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "third site, same pair"
 * @accepts #sqli on #api -- "wontfix"
 */
export function c(email: string) { return email; }
`,
};

describe('acceptances already in customers\' repositories keep parsing and keep suppressing', () => {
  let root: string;

  beforeAll(async () => { root = await scaffold('guardlink-attr-legacy-', LEGACY); }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('all three forms parse, with the fields they were written with', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    const by = (file: string) => model.acceptances.find(a => a.location.file === file);

    expect(model.acceptances).toHaveLength(3);
    expect(by('src/legacy-full.ts')).toMatchObject({
      asset: '#api', threat: '#sqli', accepted_by: 'Grace Hopper', expires: '2099-01-31',
    });
    expect(by('src/legacy-bare.ts')).toMatchObject({ accepted_by: 'ada', expires: '2099-01-31' });
    expect(by('src/legacy-bare-minimum.ts')?.accepted_by).toBeUndefined();
  }, 60_000);

  it('a qualified one still covers its own exposure, and still covers only that file', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    const coverage = buildCoverageIndex(model);
    const at = (file: string) => model.exposures.find(e => e.location.file === file)!;

    expect(coverage.isAccepted(at('src/legacy-full.ts'))).toBe(true);
    expect(coverage.isAccepted(at('src/legacy-bare.ts'))).toBe(true);
    // Per-file scope, unchanged: neither acceptance reaches the third site.
    expect(coverage.isAccepted(at('src/legacy-bare-minimum.ts'))).toBe(true);
  }, 60_000);

  it('the unqualified one is still reported as unqualified, not dropped', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    const minimal = model.acceptances.find(a => a.location.file === 'src/legacy-bare-minimum.ts')!;
    expect([...acceptanceDefects(minimal)].sort())
      .toEqual(['unattributed', 'undated', 'unjustified']);
  }, 60_000);

  it('the gate still suppresses exactly what it suppressed — two of three sites', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    const report = runCiChecks(root, model);
    // The two properly signed sites are covered; the bare-minimum one is not,
    // because its acceptance does not qualify. `src/dao.ts` carries no
    // acceptance at all and is the control case.
    expect(report.summary.acceptances).toBe(3);
    expect(report.summary.unqualified_acceptances).toBe(1);
    expect(report.exposures.map(e => e.location.file).sort())
      .toEqual(['src/dao.ts', 'src/legacy-bare-minimum.ts']);
  }, 60_000);

  it('the SARIF a pentest reads still omits every site an @accepts covers', async () => {
    // Including the unqualified one. That asymmetry with the gate is
    // deliberate and predates this change (see parser/acceptance.ts: scope and
    // expiry are facts and drive the export; attribution and justification are
    // POLICY and drive only the build's colour). It is pinned here because it
    // is exactly the kind of thing a "tighten the acceptance rules" change
    // would move by accident, and moving it re-opens findings in a pentest
    // queue without anybody asking for that.
    const { model } = await parseProject({ root, project: 'tmp' });
    const sarif = JSON.stringify(generateSarif(model, []));
    for (const file of Object.keys(LEGACY)) expect(sarif).not.toContain(file.split('/')[1]);
    // The unaccepted exposure in the same fixture is still exported.
    expect(sarif).toContain('src/dao.ts');
  }, 60_000);

  it('nothing rewrites them — the files are byte-identical after a full parse', async () => {
    for (const [rel, body] of Object.entries(LEGACY)) {
      expect(await readFile(join(root, rel), 'utf-8')).toBe(body);
    }
  }, 60_000);
});
