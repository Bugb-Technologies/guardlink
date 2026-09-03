// tests/verification.test.ts
/**
 * Every row of the spec's §7.3 state table, driven through a real parse so the
 * anchors are the ones the product computes, with ledger entries built from
 * those anchors and then bent one field at a time.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { emptyLedger } from '../src/parser/ledger.js';
import type { Ledger, LedgerEntry, LedgerRead } from '../src/parser/ledger.js';
import { classifyClaims, demotionSet } from '../src/parser/verification.js';
import type { ThreatModel } from '../src/types/index.js';

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
`;

async function parsed(): Promise<ThreatModel> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-verif-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return (await parseProject({ root, project: 'test' })).model;
}

/** A ledger that verifies every claim exactly as the model has it now. */
function ledgerFor(model: ThreatModel): Ledger {
  const ledger = emptyLedger();
  for (const r of relationRecords(model)) {
    const a = r.location.anchor!;
    ledger.entries.push({
      key: r.key, file: r.location.file, verb: r.verb, claim: r.claim,
      anchor: { scope: a.scope, symbol: a.symbol }, hash: a.hash,
      verified_by: 'human:test', verified_at: '2026-09-03T00:00:00.000Z',
    });
  }
  return ledger;
}

const present = (ledger: Ledger): LedgerRead => ({ status: 'present', ledger });

describe('classifyClaims', () => {
  it('no ledger: every claim unverified, nothing stale, ledger status carried', async () => {
    const model = await parsed();
    const report = classifyClaims(model, { status: 'absent', ledger: null });
    expect(report.ledger).toBe('absent');
    expect(report.claims.map(c => c.state)).toEqual(['unverified', 'unverified']);
    expect(report.summary).toMatchObject({ verified: 0, stale: 0, unverified: 2, orphans: 0, demotable_stale: 0 });
  });

  it('matching hash: verified', async () => {
    const model = await parsed();
    const report = classifyClaims(model, present(ledgerFor(model)));
    expect(report.claims.every(c => c.state === 'verified')).toBe(true);
    expect(report.claims[0].entry?.verified_by).toBe('human:test');
  });

  it('different hash: stale, counted by verb, demotable for mitigates only', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    for (const e of ledger.entries) e.hash = 'sha256-v1:' + '0'.repeat(64);
    const report = classifyClaims(model, present(ledger));
    expect(report.claims.map(c => c.state)).toEqual(['stale', 'stale']);
    expect(report.summary.stale_by_verb).toEqual({ mitigates: 1, exposes: 1 });
    expect(report.summary.demotable_stale).toBe(1);
    expect([...demotionSet(report)]).toEqual([report.claims.find(c => c.verb === 'mitigates')!.key]);
  });

  it('renamed symbol: stale with the rename hint', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    ledger.entries[0].hash = 'sha256-v1:' + '0'.repeat(64);
    ledger.entries[0].anchor.symbol = 'signIn';
    const report = classifyClaims(model, present(ledger));
    const bent = report.claims.find(c => c.key === ledger.entries[0].key)!;
    expect(bent).toMatchObject({ state: 'stale', hint: 'symbol-renamed' });
  });

  it('hash version mismatch: unverified with the version hint, never stale', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    ledger.anchor_hash_version = 99;
    const report = classifyClaims(model, present(ledger));
    expect(report.claims.every(c => c.state === 'unverified' && c.hint === 'hash-version')).toBe(true);
    expect(report.summary.stale).toBe(0);
  });

  it('entry with no matching claim: orphan', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    const ghost: LedgerEntry = { ...ledger.entries[0], key: 'f'.repeat(64) + ':0', claim: 'gone' };
    ledger.entries.push(ghost);
    const report = classifyClaims(model, present(ledger));
    expect(report.orphans).toEqual([ghost]);
    expect(report.summary.orphans).toBe(1);
  });

  it('a claim with no anchor is unverified and cannot be stale', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    model.mitigations[0].location.anchor = null;
    const report = classifyClaims(model, present(ledger));
    expect(report.claims.find(c => c.verb === 'mitigates')).toMatchObject({ state: 'unverified', anchor: null });
  });

  it('grammar-failed anchor: unverified with the grammar hint, never stale', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    model.mitigations[0].location.anchor = {
      ...model.mitigations[0].location.anchor!,
      hash: 'sha256-v1:' + '0'.repeat(64),
      reason: 'grammar-failed',
    };
    const report = classifyClaims(model, present(ledger));
    expect(report.claims.find(c => c.verb === 'mitigates')).toMatchObject({ state: 'unverified', hint: 'grammar-failed' });
    expect(report.summary.stale).toBe(0);
  });
});
