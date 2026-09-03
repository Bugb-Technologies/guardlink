// tests/verify.test.ts
/**
 * The verify table from spec §10.1, one row per case, each driven through the
 * real parse → classify → plan → apply → write → re-parse → classify cycle. The
 * edit in the "stale" cases is the one a developer makes: change the body.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { readLedger, writeLedger } from '../src/parser/ledger.js';
import { classifyClaims } from '../src/parser/verification.js';
import { planVerification, applyVerification, defaultVerifier, headCommit } from '../src/parser/verify.js';
import type { VerificationReport } from '../src/parser/verification.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }

/**
 * @audit #api -- "Second symbol, own claim"
 */
export function other() { return 1; }
`;

const IDENTITY = { verified_by: 'human:test', verified_at: '2026-09-03T00:00:00.000Z' };

async function scaffold(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-verify-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return root;
}

async function classify(root: string): Promise<VerificationReport> {
  const { model } = await parseProject({ root, project: 'test' });
  return classifyClaims(model, readLedger(root));
}

async function bootstrap(root: string): Promise<void> {
  const report = await classify(root);
  writeLedger(root, applyVerification(null, planVerification(report, { kind: 'all' }), IDENTITY));
}

async function breakLogin(root: string): Promise<void> {
  await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
}

describe('verify', () => {
  it('default: locks unverified, prunes orphans, leaves stale alone', async () => {
    const root = await scaffold();
    const first = planVerification(await classify(root), { kind: 'default' });
    expect(first.lock.map(c => c.verb).sort()).toEqual(['audit', 'exposes', 'mitigates']);
    expect(first.relock).toEqual([]);
    writeLedger(root, applyVerification(null, first, IDENTITY));
    expect((await classify(root)).summary).toMatchObject({ verified: 3, stale: 0, unverified: 0 });

    await breakLogin(root);
    const after = await classify(root);
    expect(after.summary).toMatchObject({ verified: 1, stale: 2 });
    const plan = planVerification(after, { kind: 'default' });
    expect(plan.lock).toEqual([]);
    expect(plan.relock).toEqual([]);
  });

  it('--stale: re-locks every stale claim', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await breakLogin(root);
    const report = await classify(root);
    const plan = planVerification(report, { kind: 'stale' });
    expect(plan.relock.map(c => c.verb).sort()).toEqual(['exposes', 'mitigates']);
    writeLedger(root, applyVerification(readLedger(root).ledger, plan, { ...IDENTITY, verified_by: 'agent:test' }));
    const again = await classify(root);
    expect(again.summary).toMatchObject({ verified: 3, stale: 0 });
    expect(again.claims.find(c => c.verb === 'mitigates')!.entry!.verified_by).toBe('agent:test');
    expect(again.claims.find(c => c.verb === 'audit')!.entry!.verified_by).toBe('human:test');
  });

  it('a file target re-locks stale and locks unverified in that file only', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await breakLogin(root);
    const plan = planVerification(await classify(root), { kind: 'targets', targets: [{ file: 'src/api.ts' }] });
    expect(plan.relock.length).toBe(2);
    expect(plan.unmatched).toEqual([]);
    const none = planVerification(await classify(root), { kind: 'targets', targets: [{ file: 'src/nope.ts' }] });
    expect(none.relock).toEqual([]);
    expect(none.unmatched).toEqual(['src/nope.ts']);
  });

  it('overlapping targets do not double-count the same claim', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await breakLogin(root);
    const plan = planVerification(await classify(root), {
      kind: 'targets',
      targets: [{ file: 'src/api.ts' }, { file: 'src/api.ts' }],
    });
    expect(plan.relock.length).toBe(2);
  });

  it('a file:line target re-locks only the claim on that line', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await breakLogin(root);
    const plan = planVerification(await classify(root), { kind: 'targets', targets: [{ file: 'src/api.ts', line: 3 }] });
    expect(plan.relock.map(c => c.verb)).toEqual(['mitigates']);
    expect(plan.prune).toEqual([]);
  });

  it('orphans are pruned by default and by --all, kept by a line target', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace(' * @audit #api -- "Second symbol, own claim"\n', ''));
    const report = await classify(root);
    expect(report.summary.orphans).toBe(1);
    expect(planVerification(report, { kind: 'default' }).prune.length).toBe(1);
    expect(planVerification(report, { kind: 'all' }).prune.length).toBe(1);
    expect(planVerification(report, { kind: 'targets', targets: [{ file: 'src/api.ts', line: 3 }] }).prune).toEqual([]);
  });

  it('a claim without an anchor is skipped with a reason', async () => {
    const root = await scaffold();
    const report = await classify(root);
    report.claims[0].anchor = null;
    report.claims[0].state = 'unverified';
    const plan = planVerification(report, { kind: 'all' });
    expect(plan.skipped).toEqual([{ key: report.claims[0].key, file: 'src/api.ts', line: report.claims[0].location.line, reason: 'no-anchor' }]);
  });

  it('a ledger at another hash version is rebuilt from the claims re-locked in this run', async () => {
    const root = await scaffold();
    await bootstrap(root);
    const old = readLedger(root).ledger!;
    old.anchor_hash_version = 99;
    writeLedger(root, old);
    const report = await classify(root);
    expect(report.summary.unverified).toBe(3);
    const rebuilt = applyVerification(readLedger(root).ledger, planVerification(report, { kind: 'default' }), IDENTITY);
    expect(rebuilt.anchor_hash_version).not.toBe(99);
    expect(rebuilt.entries.length).toBe(3);
  });

  it('--stale and a targets run refuse a version-mismatched ledger instead of a partial rebuild', async () => {
    const root = await scaffold();
    await bootstrap(root);
    const old = readLedger(root).ledger!;
    old.anchor_hash_version = 99;
    writeLedger(root, old);
    const report = await classify(root);
    expect(report.hash_version_mismatch).toBe(true);

    const stalePlan = planVerification(report, { kind: 'stale' });
    expect(stalePlan).toEqual({ lock: [], relock: [], prune: [], skipped: [], unmatched: [], refused: 'hash-version-mismatch' });

    const targetsPlan = planVerification(report, { kind: 'targets', targets: [{ file: 'src/api.ts' }] });
    expect(targetsPlan).toEqual({ lock: [], relock: [], prune: [], skipped: [], unmatched: [], refused: 'hash-version-mismatch' });
  });

  it('a mismatched ledger counts the entry a whole-repository rebuild drops', async () => {
    const root = await scaffold();
    await bootstrap(root);
    const old = readLedger(root).ledger!;
    old.anchor_hash_version = 99;
    writeLedger(root, old);
    const report = await classify(root);
    const unanchored = report.claims[0];
    unanchored.anchor = null;

    const plan = planVerification(report, { kind: 'default' });
    expect(plan.refused).toBeUndefined();
    expect(plan.prune.map(e => e.key)).toEqual([unanchored.key]);

    const rebuilt = applyVerification(readLedger(root).ledger, plan, IDENTITY);
    expect(rebuilt.entries.map(e => e.key).sort()).toEqual(
      report.claims.filter(c => c.key !== unanchored.key).map(c => c.key).sort(),
    );
  });

  it('identity helpers never throw', async () => {
    const root = await scaffold(); // not a git repo
    expect(defaultVerifier(root)).toMatch(/^human:.+/);
    expect(headCommit(root)).toBeUndefined();
  });
});
