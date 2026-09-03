import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readLedger, writeLedger, serializeLedger, emptyLedger, LEDGER_FILE, LEDGER_SCHEMA } from '../src/parser/ledger.js';
import type { LedgerEntry } from '../src/parser/ledger.js';

function entry(over: Partial<LedgerEntry>): LedgerEntry {
  return {
    key: 'a'.repeat(64) + ':0', file: 'src/a.ts', verb: 'mitigates', claim: '#api against #sqli',
    anchor: { scope: 'symbol', symbol: 'login' }, hash: 'sha256-v1:' + '1'.repeat(64),
    verified_by: 'human:test', verified_at: '2026-09-03T00:00:00.000Z', ...over,
  };
}

async function scratch(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-ledger-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  return root;
}

describe('verification ledger', () => {
  it('absent when the file does not exist', async () => {
    const root = await scratch();
    expect(readLedger(root)).toEqual({ status: 'absent', ledger: null });
  });

  it('round-trips, sorted by file then key, one entry per line', async () => {
    const root = await scratch();
    const ledger = emptyLedger();
    ledger.entries.push(entry({ file: 'src/b.ts', key: 'b'.repeat(64) + ':0' }));
    ledger.entries.push(entry({ file: 'src/a.ts', key: 'c'.repeat(64) + ':0' }));
    ledger.entries.push(entry({ file: 'src/a.ts', key: 'a'.repeat(64) + ':1' }));
    writeLedger(root, ledger);

    const text = await readFile(join(root, LEDGER_FILE), 'utf-8');
    const lines = text.split('\n');
    expect(lines.filter(l => l.startsWith('    {"key"')).length).toBe(3);
    expect(text.endsWith('\n')).toBe(true);
    expect(JSON.parse(text).schema).toBe(LEDGER_SCHEMA);

    const back = readLedger(root);
    expect(back.status).toBe('present');
    expect(back.ledger!.entries.map(e => [e.file, e.key.slice(0, 1)])).toEqual([['src/a.ts', 'a'], ['src/a.ts', 'c'], ['src/b.ts', 'b']]);
  });

  it('serialises deterministically regardless of input order', () => {
    const a = emptyLedger(); a.entries.push(entry({ key: 'b'.repeat(64) + ':0' }), entry({ key: 'a'.repeat(64) + ':0' }));
    const b = emptyLedger(); b.entries.push(entry({ key: 'a'.repeat(64) + ':0' }), entry({ key: 'b'.repeat(64) + ':0' }));
    expect(serializeLedger(a)).toBe(serializeLedger(b));
  });

  it('reports corrupt with a ledger-corrupt diagnostic on bad JSON, wrong schema, or bad shape', async () => {
    const root = await scratch();
    for (const bad of ['{not json', '{"schema":"other/v9","anchor_hash_version":1,"entries":[]}', '{"schema":"guardlink.verified/v1","anchor_hash_version":1,"entries":[{"key":1}]}']) {
      await writeFile(join(root, LEDGER_FILE), bad);
      const r = readLedger(root);
      expect(r.status).toBe('corrupt');
      expect(r.ledger).toBeNull();
      expect(r.diagnostic).toMatchObject({ level: 'error', code: 'ledger-corrupt', file: LEDGER_FILE });
    }
  });
});
