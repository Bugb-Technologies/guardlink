/**
 * Payload assembly and the per-person / per-AI summaries. Pure over a
 * computation; the only git involved is the no-git path used to prove the
 * keys join to the ledger's claim keys.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { computeBlame } from '../src/blame/compute.js';
import { buildBlamePayload, summarise, median } from '../src/blame/summary.js';
import { formatBlameText } from '../src/blame/format.js';
import { BLAME_SCHEMA, type BlameEntry, type CommitRef, type ExposureBlame } from '../src/blame/types.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const SOURCE = `import x from 'x';

/**
 * @exposes #api to #sqli [high] cwe:CWE-89 -- "raw"
 * @mitigates #api against #sqli using #prepared-stmts -- "bound"
 * @confirmed #sqli on #api [critical] -- "pentest"
 */
export function login(email: string) { return email; }
`;

function ref(sha: string, author: string, date: string, assisted: { tool: string; model: string | null }[] = [], coAuthors: string[] = []): CommitRef {
  return { sha, date, author, co_authors: coAuthors, assisted_by: assisted.map(a => ({ ...a, raw: `${a.tool}` })) };
}

function exposure(over: Partial<ExposureBlame>): ExposureBlame {
  return { kind: 'exposure', status: 'ok', granularity: 'symbol', introduced_by: null, found_by: null, contributors: [], fixed_by: null, time_to_fix_days: null, ...over };
}

function entry(i: number, blame: ExposureBlame, span: string | null = `src/a.ts#${i}`): BlameEntry {
  return { key: `k${i}:0`, verb: 'exposes', asset: '#api', threat: '#sqli', severity: 'high', file: 'src/a.ts', line: i, granularity: blame.granularity, span, blame };
}

const CLAUDE = { tool: 'claude-code', model: 'Claude Opus 5 (1M context)' };
const ANN = 'human:Ann';
const BOB = 'human:Bob';

describe('median', () => {
  it('is null for no values, the middle for odd counts and the mean of the middle pair for even', () => {
    expect(median([])).toBeNull();
    expect(median([5])).toBe(5);
    expect(median([1, 10, 2])).toBe(2);
    expect(median([1, 3])).toBe(2);
  });
});

describe('summarise', () => {
  const entries: BlameEntry[] = [
    // Ann introduced with Claude's help, Bob fixed it in 4 days
    entry(1, exposure({ introduced_by: { ...ref('1'.repeat(40), ANN, '2026-01-01T00:00:00Z', [CLAUDE]), method: 'log-L' }, fixed_by: ref('2'.repeat(40), BOB, '2026-01-05T00:00:00Z'), time_to_fix_days: 4 })),
    // Ann introduced alone, still open
    entry(2, exposure({ introduced_by: { ...ref('3'.repeat(40), ANN, '2026-01-02T00:00:00Z'), method: 'log-L' } })),
    // Bob introduced with Bob's co-author Cy, Ann fixed with Claude in 2 days
    entry(3, exposure({ introduced_by: { ...ref('4'.repeat(40), BOB, '2026-01-03T00:00:00Z', [], ['human:Cy']), method: 'file-add' }, fixed_by: ref('5'.repeat(40), ANN, '2026-01-05T00:00:00Z', [CLAUDE]), time_to_fix_days: 2 })),
    // bot-authored with no human: credited to the agent only
    entry(4, exposure({ introduced_by: { ...ref('6'.repeat(40), 'agent:copilot', '2026-01-04T00:00:00Z', [{ tool: 'copilot', model: null }]), method: 'log-L' } })),
    // nothing attributable
    entry(5, exposure({ status: 'no-git', granularity: 'none' })),
  ];

  it('credits introduced, fixed and open per person, with a median time-to-fix over what they introduced', () => {
    const { by_human } = summarise(entries);
    expect(by_human).toEqual([
      { identity: ANN, introduced: 2, fixed: 1, open: 1, touched: 0, lines: 0, median_time_to_fix_days: 4 },
      { identity: BOB, introduced: 1, fixed: 1, open: 0, touched: 0, lines: 0, median_time_to_fix_days: 2 },
      { identity: 'human:Cy', introduced: 1, fixed: 0, open: 0, touched: 0, lines: 0, median_time_to_fix_days: 2 },
    ]);
  });

  it('credits each AI tool+model the same way, and never lists an agent among the people', () => {
    const { by_agent, by_human } = summarise(entries);
    expect(by_agent).toEqual([
      { tool: 'claude-code', model: 'Claude Opus 5 (1M context)', introduced: 1, fixed: 1, open: 0, touched: 0, lines: 0, median_time_to_fix_days: 4 },
      { tool: 'copilot', model: null, introduced: 1, fixed: 0, open: 1, touched: 0, lines: 0, median_time_to_fix_days: null },
    ]);
    expect(by_human.some(r => r.identity.startsWith('agent:'))).toBe(false);
  });

  it('credits touched claims and owned lines from the span contributors, even to those who introduced nothing', () => {
    // Ann introduced; Ann (with Claude) still owns 3 lines of the span and Bob owns 1.
    const e = entry(9, exposure({
      introduced_by: { ...ref('7'.repeat(40), ANN, '2026-01-01T00:00:00Z'), method: 'log-L' },
      contributors: [
        { ...ref('8'.repeat(40), ANN, '2026-01-06T00:00:00Z', [CLAUDE]), lines: 3 },
        { ...ref('9'.repeat(40), BOB, '2026-01-07T00:00:00Z'), lines: 1 },
      ],
    }));
    const { by_human, by_agent } = summarise([e]);
    expect(by_human).toEqual([
      { identity: ANN, introduced: 1, fixed: 0, open: 1, touched: 1, lines: 3, median_time_to_fix_days: null },
      { identity: BOB, introduced: 0, fixed: 0, open: 0, touched: 1, lines: 1, median_time_to_fix_days: null },
    ]);
    expect(by_agent).toEqual([
      { tool: 'claude-code', model: 'Claude Opus 5 (1M context)', introduced: 0, fixed: 0, open: 0, touched: 1, lines: 3, median_time_to_fix_days: null },
    ]);
  });

  it('counts owned lines once per distinct span, however many claims share it', () => {
    // Ten header claims on one file share one file-wide span: touched is per
    // claim, but the lines are the same lines and count once.
    const own = { ...ref('c'.repeat(40), ANN, '2026-01-06T00:00:00Z', [CLAUDE]), lines: 120 };
    const shared = [1, 2, 3].map(i => entry(i, exposure({ granularity: 'file', contributors: [own] }), 'src/big.ts#file'));
    const { by_human, by_agent } = summarise(shared);
    expect(by_human).toEqual([{ identity: ANN, introduced: 0, fixed: 0, open: 0, touched: 3, lines: 120, median_time_to_fix_days: null }]);
    expect(by_agent[0]).toMatchObject({ tool: 'claude-code', touched: 3, lines: 120 });
  });

  it('orders rows by introduced desc, then identity', () => {
    const rows = summarise([...entries].reverse()).by_human.map(r => r.identity);
    expect(rows).toEqual([ANN, BOB, 'human:Cy']);
  });
});

describe('buildBlamePayload', () => {
  it('keys every entry with the ledger claim key and carries the computation status', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-blame-summary-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'a.ts'), SOURCE);
    const { model } = await parseProject({ root, project: 'test' });
    const comp = computeBlame(root, model);
    const payload = buildBlamePayload(model, comp, root);

    expect(payload.schema).toBe(BLAME_SCHEMA);
    expect(payload.status).toBe('no-git');
    expect(payload.root).toBe(root);
    expect(payload.entries.map(e => e.verb).sort()).toEqual(['confirmed', 'exposes', 'mitigates']);
    const ledgerKeys = new Set(relationRecords(model).map(c => c.key));
    for (const e of payload.entries) expect(ledgerKeys.has(e.key)).toBe(true);
    expect(payload.entries.find(e => e.verb === 'exposes')).toMatchObject({ asset: '#api', threat: '#sqli', severity: 'high', file: 'src/a.ts', line: 4, granularity: 'symbol', span: 'src/a.ts#8-8' });
    expect(payload.summary).toEqual({ by_human: [], by_agent: [] });
  });
});

describe('formatBlameText', () => {
  it('prints a group per file and the two summary tables', () => {
    const e = entry(7, exposure({
      introduced_by: { ...ref('a'.repeat(40), ANN, '2026-01-01T00:00:00Z', [CLAUDE]), method: 'log-L' },
      found_by: ref('a'.repeat(40), ANN, '2026-01-01T00:00:00Z'),
      contributors: [{ ...ref('a'.repeat(40), ANN, '2026-01-01T00:00:00Z', [CLAUDE]), lines: 3 }],
    }));
    const text = formatBlameText({ schema: BLAME_SCHEMA, root: '/r', head: 'b'.repeat(40), identity_mode: 'name', status: 'ok', entries: [e], summary: summarise([e]) });
    expect(text).toContain('src/a.ts');
    expect(text).toContain('#api');
    expect(text).toContain('aaaaaaaa');
    expect(text).toContain('claude-code');
    expect(text).toContain('Claude Opus 5 (1M context)');
    expect(text).toContain('By person');
    expect(text).toContain('By AI tool');
    expect(text).toContain(ANN);
    expect(text).toContain('open');
  });

  it('says so when nothing could be attributed', () => {
    const text = formatBlameText({ schema: BLAME_SCHEMA, root: '/r', head: null, identity_mode: 'name', status: 'no-git', entries: [], summary: { by_human: [], by_agent: [] } });
    expect(text).toContain('not a git');
  });
});
