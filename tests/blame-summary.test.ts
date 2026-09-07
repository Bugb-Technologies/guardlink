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
import {
  BLAME_SCHEMA, type BlameComputation, type BlameEntry, type BlameSummary, type CommitCounts, type CommitRef, type ExposureBlame,
} from '../src/blame/types.js';

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

function entry(i: number, blame: ExposureBlame, span: string | null = `src/a.ts#${i}`, severity: string | null = 'high', file = 'src/a.ts'): BlameEntry {
  return { key: `k${i}:0`, verb: 'exposes', asset: '#api', threat: '#sqli', severity, file, line: i, granularity: blame.granularity, span, blame };
}

const CLAUDE = { tool: 'claude-code', model: 'Claude Opus 5 (1M context)' };
const CODEX = { tool: 'codex', model: 'gpt-5.2' };
const ANN = 'human:Ann';
const BOB = 'human:Bob';

/** The fields every row carries when `summarise` is given no commit counts and no as_of. */
const NO_CTX = { commits: null, per_100_commits: null, oldest_open_days: null };
const EMPTY_SUMMARY: BlameSummary = { as_of: null, by_human: [], by_agent: [], trends: [], comparison: null, hot_files: [] };

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
      { identity: ANN, introduced: 2, fixed: 1, open: 1, touched: 0, lines: 0, median_time_to_fix_days: 4, risk_score: 4, ...NO_CTX },
      { identity: BOB, introduced: 1, fixed: 1, open: 0, touched: 0, lines: 0, median_time_to_fix_days: 2, risk_score: 0, ...NO_CTX },
      { identity: 'human:Cy', introduced: 1, fixed: 0, open: 0, touched: 0, lines: 0, median_time_to_fix_days: 2, risk_score: 0, ...NO_CTX },
    ]);
  });

  it('credits each AI tool+model the same way, and never lists an agent among the people', () => {
    const { by_agent, by_human } = summarise(entries);
    expect(by_agent).toEqual([
      { tool: 'claude-code', model: 'Claude Opus 5 (1M context)', introduced: 1, fixed: 1, open: 0, touched: 0, lines: 0, median_time_to_fix_days: 4, risk_score: 0, ...NO_CTX },
      { tool: 'copilot', model: null, introduced: 1, fixed: 0, open: 1, touched: 0, lines: 0, median_time_to_fix_days: null, risk_score: 4, ...NO_CTX },
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
      { identity: ANN, introduced: 1, fixed: 0, open: 1, touched: 1, lines: 3, median_time_to_fix_days: null, risk_score: 4, ...NO_CTX },
      { identity: BOB, introduced: 0, fixed: 0, open: 0, touched: 1, lines: 1, median_time_to_fix_days: null, risk_score: 0, ...NO_CTX },
    ]);
    expect(by_agent).toEqual([
      { tool: 'claude-code', model: 'Claude Opus 5 (1M context)', introduced: 0, fixed: 0, open: 0, touched: 1, lines: 3, median_time_to_fix_days: null, risk_score: 0, ...NO_CTX },
    ]);
  });

  it('counts owned lines once per distinct span, however many claims share it', () => {
    // Ten header claims on one file share one file-wide span: touched is per
    // claim, but the lines are the same lines and count once.
    const own = { ...ref('c'.repeat(40), ANN, '2026-01-06T00:00:00Z', [CLAUDE]), lines: 120 };
    const shared = [1, 2, 3].map(i => entry(i, exposure({ granularity: 'file', contributors: [own] }), 'src/big.ts#file'));
    const { by_human, by_agent } = summarise(shared);
    expect(by_human).toEqual([{ identity: ANN, introduced: 0, fixed: 0, open: 0, touched: 3, lines: 120, median_time_to_fix_days: null, risk_score: 0, ...NO_CTX }]);
    expect(by_agent[0]).toMatchObject({ tool: 'claude-code', touched: 3, lines: 120 });
  });

  it('orders rows by introduced desc, then identity', () => {
    const rows = summarise([...entries].reverse()).by_human.map(r => r.identity);
    expect(rows).toEqual([ANN, BOB, 'human:Cy']);
  });

  it('without commit counts every row has null commits and per-100, and there is no comparison', () => {
    const s = summarise(entries);
    expect(s.as_of).toBeNull();
    expect(s.comparison).toBeNull();
    for (const r of [...s.by_human, ...s.by_agent]) {
      expect(r.commits).toBeNull();
      expect(r.per_100_commits).toBeNull();
      expect(r.oldest_open_days).toBeNull();
    }
  });
});

describe('summarise analytics', () => {
  const open = (i: number, date: string, severity: string | null, assisted: { tool: string; model: string | null }[] = []): BlameEntry =>
    entry(i, exposure({ introduced_by: { ...ref(String(i).padStart(40, '0'), ANN, date, assisted), method: 'log-L' } }), `src/a.ts#${i}`, severity);

  it('risk_score weighs the open exposures an identity introduced: critical 8, high 4, medium 2, low 1, P0..P3 alike, case-insensitively, anything else 1', () => {
    const entries = [
      open(1, '2026-01-01T00:00:00Z', 'critical'),
      open(2, '2026-01-01T00:00:00Z', 'CRITICAL'),
      open(3, '2026-01-01T00:00:00Z', 'high'),
      open(4, '2026-01-01T00:00:00Z', 'P1'),
      open(5, '2026-01-01T00:00:00Z', 'medium'),
      open(6, '2026-01-01T00:00:00Z', 'p2'),
      open(7, '2026-01-01T00:00:00Z', 'low'),
      open(8, '2026-01-01T00:00:00Z', 'P3'),
      open(9, '2026-01-01T00:00:00Z', null),
      open(10, '2026-01-01T00:00:00Z', 'informational'),
      // fixed: introduced by Ann but no longer open, so it adds nothing
      entry(11, exposure({ introduced_by: { ...ref('b'.repeat(40), ANN, '2026-01-01T00:00:00Z'), method: 'log-L' }, fixed_by: ref('c'.repeat(40), BOB, '2026-01-02T00:00:00Z'), time_to_fix_days: 1 }), 'src/a.ts#11', 'critical'),
    ];
    const { by_human } = summarise(entries);
    expect(by_human[0]).toMatchObject({ identity: ANN, introduced: 11, open: 10, risk_score: 8 + 8 + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 1 });
  });

  it('oldest_open_days counts whole days from the oldest open introduction to as_of, per identity, null when nothing is open', () => {
    const entries = [
      open(1, '2026-01-10T00:00:00Z', 'high'),
      open(2, '2026-01-02T00:00:00Z', 'high', [CLAUDE]),
      // Bob's only introduction is fixed, so he has no oldest open exposure
      entry(3, exposure({ introduced_by: { ...ref('b'.repeat(40), BOB, '2025-06-01T00:00:00Z'), method: 'log-L' }, fixed_by: ref('c'.repeat(40), BOB, '2025-06-03T00:00:00Z'), time_to_fix_days: 2 })),
    ];
    // 2026-01-02 → 2026-03-01 is 58 days; the extra 12 h does not round up.
    const s = summarise(entries, { as_of: '2026-03-01T12:00:00Z' });
    expect(s.as_of).toBe('2026-03-01T12:00:00Z');
    expect(s.by_human.map(r => [r.identity, r.oldest_open_days])).toEqual([[ANN, 58], [BOB, null]]);
    expect(s.by_agent.map(r => [r.tool, r.oldest_open_days])).toEqual([['claude-code', 58]]);
    // An as_of before the introduction (rewritten history) clamps to 0 rather than going negative.
    expect(summarise(entries, { as_of: '2025-12-01T00:00:00Z' }).by_human[0].oldest_open_days).toBe(0);
    expect(summarise(entries).by_human[0].oldest_open_days).toBeNull();
  });

  const counts: CommitCounts = {
    total: 10,
    ai_assisted: 3,
    by_human: { [ANN]: 6, [BOB]: 4 },
    by_agent: {
      'claude-code Claude Opus 5 (1M context)': { ...CLAUDE, commits: 2 },
      'copilot ': { tool: 'copilot', model: null, commits: 1 },
    },
  };
  const cohortEntries: BlameEntry[] = [
    // AI cohort: Ann with Claude, fixed in 4 days
    entry(1, exposure({ introduced_by: { ...ref('1'.repeat(40), ANN, '2026-01-01T00:00:00Z', [CLAUDE]), method: 'log-L' }, fixed_by: ref('2'.repeat(40), BOB, '2026-01-05T00:00:00Z'), time_to_fix_days: 4 })),
    // human cohort: Ann alone, open
    entry(2, exposure({ introduced_by: { ...ref('3'.repeat(40), ANN, '2026-01-02T00:00:00Z'), method: 'log-L' } })),
    // human cohort: Bob with Cy, fixed in 2 days
    entry(3, exposure({ introduced_by: { ...ref('4'.repeat(40), BOB, '2026-01-03T00:00:00Z', [], ['human:Cy']), method: 'file-add' }, fixed_by: ref('5'.repeat(40), ANN, '2026-01-05T00:00:00Z', [CLAUDE]), time_to_fix_days: 2 })),
    // AI cohort: bot-authored, open
    entry(4, exposure({ introduced_by: { ...ref('6'.repeat(40), 'agent:copilot', '2026-01-04T00:00:00Z', [{ tool: 'copilot', model: null }]), method: 'log-L' } })),
    // no introduction: in no cohort
    entry(5, exposure({ status: 'uncommitted' })),
  ];

  it('fills commits and per-100 from the counts, one decimal, null per-100 for an identity with no commits', () => {
    const { by_human, by_agent } = summarise(cohortEntries, { commits: counts });
    expect(by_human.map(r => [r.identity, r.commits, r.per_100_commits])).toEqual([
      [ANN, 6, 33.3],
      [BOB, 4, 25],
      ['human:Cy', 0, null],
    ]);
    expect(by_agent.map(r => [r.tool, r.commits, r.per_100_commits])).toEqual([
      ['claude-code', 2, 50],
      ['copilot', 1, 100],
    ]);
  });

  it('compares the human and AI cohorts by introducing commit', () => {
    const { comparison } = summarise(cohortEntries, { commits: counts });
    expect(comparison).toEqual({
      human: { commits: 7, introduced: 2, fixed: 1, open: 1, per_100_commits: 28.6, median_time_to_fix_days: 2 },
      ai: { commits: 3, introduced: 2, fixed: 1, open: 1, per_100_commits: 66.7, median_time_to_fix_days: 4 },
    });
    const none = summarise(cohortEntries, { commits: { total: 0, ai_assisted: 0, by_human: {}, by_agent: {} } }).comparison!;
    expect(none.human.per_100_commits).toBeNull();
    expect(none.ai.per_100_commits).toBeNull();
  });

  it('trends bucket introductions and fixes by UTC quarter, fill the gaps, and carry open_end cumulatively', () => {
    const entries = [
      // 2025-Q3, human, fixed the same quarter
      entry(1, exposure({ introduced_by: { ...ref('1'.repeat(40), ANN, '2025-08-01T00:00:00Z'), method: 'log-L' }, fixed_by: ref('2'.repeat(40), BOB, '2025-09-01T00:00:00Z'), time_to_fix_days: 31 })),
      // 2025-10-01 01:00 at +02:00 is still 30 September in UTC: 2025-Q3, AI-assisted, fixed in 2026-Q1
      entry(2, exposure({ introduced_by: { ...ref('3'.repeat(40), ANN, '2025-10-01T01:00:00+02:00', [CLAUDE]), method: 'log-L' }, fixed_by: ref('4'.repeat(40), ANN, '2026-02-01T00:00:00Z'), time_to_fix_days: 124 })),
      // 2026-Q1, open
      entry(3, exposure({ introduced_by: { ...ref('5'.repeat(40), BOB, '2026-02-15T00:00:00Z'), method: 'log-L' } })),
      entry(4, exposure({ status: 'no-git', granularity: 'none' })),
    ];
    expect(summarise(entries).trends).toEqual([
      { period: '2025-Q3', introduced: 2, introduced_ai: 1, fixed: 1, open_end: 1 },
      { period: '2025-Q4', introduced: 0, introduced_ai: 0, fixed: 0, open_end: 1 },
      { period: '2026-Q1', introduced: 1, introduced_ai: 0, fixed: 1, open_end: 1 },
    ]);
    expect(summarise([entries[3]]).trends).toEqual([]);
  });

  it('hot_files lists open exposures per file with distinct contributors and AI tools, hottest first, at most ten', () => {
    const c = (sha: string, assisted: { tool: string; model: string | null }[] = []) => ({ ...ref(sha.repeat(40), ANN, '2026-01-01T00:00:00Z', assisted), lines: 1 });
    const at = (file: string, i: number, over: Partial<ExposureBlame>) => entry(i, exposure(over), `${file}#${i}`, 'high', file);
    const entries: BlameEntry[] = [
      // a.ts: three open (one contributor shared across two of them), one fixed that must not count
      at('a.ts', 1, { contributors: [c('1', [CLAUDE]), c('2', [CODEX])] }),
      at('a.ts', 2, { contributors: [c('2', [CODEX])] }),
      at('a.ts', 3, { contributors: [c('3', [CLAUDE])] }),
      at('a.ts', 4, { contributors: [c('4', [{ tool: 'copilot', model: null }])], fixed_by: ref('9'.repeat(40), BOB, '2026-01-05T00:00:00Z') }),
      // b.ts and c.ts: two open each; b has more contributors
      at('b.ts', 5, { contributors: [c('5'), c('6'), c('7')] }),
      at('b.ts', 6, { contributors: [c('5')] }),
      at('c.ts', 7, { contributors: [c('8')] }),
      at('c.ts', 8, { contributors: [] }),
      // nine more files with one open each: only seven fit under the cap, in file order
      ...['d', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'].map((f, n) => at(`${f}.ts`, 20 + n, {})),
      // a mitigation is never an open exposure
      { key: 'm:0', verb: 'mitigates', asset: '#api', threat: '#sqli', severity: null, file: 'z.ts', line: 1, granularity: 'symbol', span: 'z.ts#1', blame: { kind: 'mitigation', status: 'ok', granularity: 'symbol', declared_by: null, contributors: [c('a')] } },
    ];
    const { hot_files } = summarise(entries);
    expect(hot_files).toHaveLength(10);
    expect(hot_files.slice(0, 3)).toEqual([
      { file: 'a.ts', open: 3, contributors: 3, ai_tools: 2 },
      { file: 'b.ts', open: 2, contributors: 3, ai_tools: 0 },
      { file: 'c.ts', open: 2, contributors: 1, ai_tools: 0 },
    ]);
    expect(hot_files.slice(3).map(h => h.file)).toEqual(['d.ts', 'e.ts', 'f.ts', 'g.ts', 'h.ts', 'i.ts', 'j.ts']);
    expect(hot_files[3]).toEqual({ file: 'd.ts', open: 1, contributors: 0, ai_tools: 0 });
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
    // Without git nothing is attributed: no rows, no dated buckets, no cohorts. The two unfixed
    // exposure claims still name their file, with no one to credit.
    expect(payload.summary).toEqual({ ...EMPTY_SUMMARY, hot_files: [{ file: 'src/a.ts', open: 2, contributors: 0, ai_tools: 0 }] });
  });

  it('hands the computation\'s commit counts and as_of to the summary', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-blame-summary-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'a.ts'), SOURCE);
    const { model } = await parseProject({ root, project: 'test' });
    const e = exposure({ introduced_by: { ...ref('1'.repeat(40), ANN, '2026-01-01T00:00:00Z'), method: 'log-L' } });
    const comp: BlameComputation = {
      status: 'ok', head: 'b'.repeat(40), identity_mode: 'name', byRecord: new Map([[model.exposures[0], e]]),
      as_of: '2026-02-01T00:00:00Z',
      commits: { total: 4, ai_assisted: 1, by_human: { [ANN]: 4 }, by_agent: {} },
    };
    const { summary } = buildBlamePayload(model, comp, '/r');
    expect(summary.as_of).toBe('2026-02-01T00:00:00Z');
    expect(summary.comparison).toEqual({
      human: { commits: 3, introduced: 1, fixed: 0, open: 1, per_100_commits: 33.3, median_time_to_fix_days: null },
      ai: { commits: 1, introduced: 0, fixed: 0, open: 0, per_100_commits: 0, median_time_to_fix_days: null },
    });
    expect(summary.by_human[0]).toMatchObject({ identity: ANN, commits: 4, per_100_commits: 25, oldest_open_days: 31 });
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
    const text = formatBlameText({ schema: BLAME_SCHEMA, root: '/r', head: null, identity_mode: 'name', status: 'no-git', entries: [], summary: EMPTY_SUMMARY });
    expect(text).toContain('not a git');
  });

  it('prints commits and per-100 columns, a dash for what is unknown, and a By quarter block', () => {
    const e = entry(7, exposure({ introduced_by: { ...ref('a'.repeat(40), ANN, '2026-02-01T00:00:00Z', [CLAUDE]), method: 'log-L' } }));
    const counts: CommitCounts = { total: 5, ai_assisted: 2, by_human: { [ANN]: 5 }, by_agent: {} };
    const withCounts = formatBlameText({ schema: BLAME_SCHEMA, root: '/r', head: 'b'.repeat(40), identity_mode: 'name', status: 'ok', entries: [e], summary: summarise([e], { commits: counts, as_of: '2026-03-01T00:00:00Z' }) });
    expect(withCounts).toContain('commits');
    expect(withCounts).toContain('per 100');
    expect(withCounts).toMatch(/human:Ann\s+5\s+1\s+20/);
    expect(withCounts).toContain('By quarter');
    expect(withCounts).toContain('2026-Q1  introduced 1 (1 AI)  fixed 0  open 1');

    const without = formatBlameText({ schema: BLAME_SCHEMA, root: '/r', head: 'b'.repeat(40), identity_mode: 'name', status: 'ok', entries: [e], summary: summarise([e]) });
    expect(without).toMatch(/human:Ann\s+—\s+1\s+—/);
    expect(without).toMatch(/claude-code\s+Claude Opus 5 \(1M context\)\s+—\s+1\s+—/);
  });
});
