/**
 * Declared boundaries as claims to test: supported or contradicted outcomes in
 * the hypothesis ledger, keyed by the boundary's claim key, addressed by key,
 * #id or file:line, expiring when the code beneath moves, and imported from a
 * scan report that stamps a boundary key. None of it touches an exposure's state.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { parseProject } from '../src/parser/parse-project.js';
import {
  HYPOTHESES_FILE, readHypotheses, classifyHypotheses, classifyBoundaryClaims, resolveBoundaryTarget,
  recordBoundaryOutcome, recordOutcome, resolveTarget, importScan, formatImport,
} from '../src/hypothesis/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.Db (#db) -- "Database"
 * @threat Broken_Auth (#broken-auth) [high] cwe:CWE-306 -- "Missing authentication"
 */
export {};
`;
const SOURCE = `import x from 'x';

/**
 * @boundary between Client and #api (#http-boundary) -- "Everything past this point has been authenticated"
 * @exposes #api to #broken-auth [high] cwe:CWE-306 -- "GET /export has no login check"
 * @boundary between #api and #db (#data-boundary) -- "application to persistence"
 * @audit #api -- "review"
 */
export function exportAll() { return 1; }
`;
const HTTP = 'src/a.ts:4', EXPOSURE = 'src/a.ts:5', DATA = 'src/a.ts:6';
const NOW = '2026-09-12T10:00:00.000Z';
const GOT_THROUGH = 'GET /export with no session cookie returned HTTP 200 and the full export; reproduced twice';
const REFUSED = 'GET /admin without a session redirected to /login (302); with a user session, 403';

async function project(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-hyp-boundary-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), SOURCE);
  return root;
}
const parse = async (root: string) => (await parseProject({ root, project: 'b' })).model;

describe('boundary claims', () => {
  it('every declared boundary is a claim, unverified until an outcome is recorded', async () => {
    const root = await project();
    const c = classifyBoundaryClaims(await parse(root), readHypotheses(root));
    expect(c.summary).toEqual({ unverified: 2, supported: 0, contradicted: 0, retest: 0 });
    expect(c.records.map(r => [r.id, r.file, r.line, r.state])).toEqual([
      ['http-boundary', 'src/a.ts', 4, 'unverified'],
      ['data-boundary', 'src/a.ts', 6, 'unverified'],
    ]);
    expect(c.records[0].key).toMatch(/^[0-9a-f]{64}:\d+$/);
  });

  it('a target is the claim key, the #id, or the file:line of the @boundary', async () => {
    const root = await project();
    const model = await parse(root);
    const byLine = resolveBoundaryTarget(model, HTTP);
    expect(resolveBoundaryTarget(model, '#http-boundary').key).toBe(byLine.key);
    expect(resolveBoundaryTarget(model, byLine.key).key).toBe(byLine.key);
    expect(() => resolveBoundaryTarget(model, EXPOSURE)).toThrow('no @boundary at src/a.ts:5');
    expect(() => resolveBoundaryTarget(model, '#nope')).toThrow('no @boundary has the id #nope');
    expect(() => resolveBoundaryTarget(model, 'http-boundary')).toThrow('claim key, its #id, or the file:line');
  });

  it('records supported and contradicted against the boundary key, with history, and leaves exposures alone', async () => {
    const root = await project();
    const model = await parse(root);
    recordBoundaryOutcome(root, model, '#http-boundary', 'supported', { evidence: REFUSED, by: 'human:t', at: NOW });
    const { entry } = recordBoundaryOutcome(root, model, HTTP, 'contradicted', { evidence: GOT_THROUGH, by: 'human:t', at: NOW });
    expect(entry).toMatchObject({ outcome: 'contradicted', file: 'src/a.ts', line: 4, history: [{ outcome: 'supported' }] });
    const read = readHypotheses(root);
    expect(read.status).toBe('present');
    const c = classifyBoundaryClaims(model, read);
    expect(c.summary).toEqual({ unverified: 1, supported: 0, contradicted: 1, retest: 0 });
    // The exposure beside it is still untested: a boundary outcome never moves an exposure.
    expect(classifyHypotheses(model, read).summary).toEqual({ untested: 1, confirmed: 0, refuted: 0, retest: 0 });
  });

  it('a contradiction needs evidence in hand; support needs evidence at all', async () => {
    const root = await project();
    const model = await parse(root);
    expect(() => recordBoundaryOutcome(root, model, HTTP, 'contradicted', { evidence: 'I think it is open', by: 'h', at: NOW })).toThrow('A contradiction needs evidence in hand');
    expect(() => recordBoundaryOutcome(root, model, HTTP, 'supported', { evidence: '  ', by: 'h', at: NOW })).toThrow('An outcome needs evidence');
  });

  it('an outcome lapses when the code beneath the boundary changes: supported to unverified, contradicted to retest', async () => {
    const root = await project();
    let model = await parse(root);
    recordBoundaryOutcome(root, model, '#http-boundary', 'contradicted', { evidence: GOT_THROUGH, by: 'h', at: NOW });
    recordBoundaryOutcome(root, model, '#data-boundary', 'supported', { evidence: REFUSED, by: 'h', at: NOW });
    await writeFile(join(root, 'src', 'a.ts'), SOURCE.replace('return 1;', 'return 2;'));
    model = await parse(root);
    const c = classifyBoundaryClaims(model, readHypotheses(root));
    expect(c.records.map(r => [r.id, r.state, r.expired, r.previous?.outcome])).toEqual([
      ['http-boundary', 'retest', true, 'contradicted'],
      ['data-boundary', 'unverified', true, 'supported'],
    ]);
  });

  it('confirm and refute point a boundary target at support and contradict', async () => {
    const root = await project();
    const model = await parse(root);
    expect(() => resolveTarget(model, '#http-boundary')).toThrow('names a @boundary, not an exposure; record its outcome with guardlink hypothesis support|contradict');
    expect(() => recordOutcome(root, model, resolveBoundaryTarget(model, HTTP).key, 'refuted', { evidence: REFUSED, by: 'h', at: NOW })).toThrow('names a @boundary');
  });

  it('the ledger reader refuses an entry whose history mixes exposure and boundary outcomes', async () => {
    const root = await project();
    const model = await parse(root);
    recordBoundaryOutcome(root, model, HTTP, 'supported', { evidence: REFUSED, by: 'h', at: NOW });
    const doc = JSON.parse(await readFile(join(root, HYPOTHESES_FILE), 'utf-8'));
    doc.entries[0].history = [{ ...doc.entries[0], outcome: 'refuted', key: undefined, claim: undefined, file: undefined, line: undefined, history: undefined }];
    await writeFile(join(root, HYPOTHESES_FILE), JSON.stringify(doc));
    expect(readHypotheses(root)).toMatchObject({ status: 'corrupt', error: 'entries do not match the schema' });
  });
});

describe('importing a scan that tested a boundary', () => {
  async function scan(root: string, findings: unknown[]): Promise<string> {
    const path = join(root, 'scan.json');
    await writeFile(path, JSON.stringify({ scan_id: 's1', findings }));
    return path;
  }
  const finding = (extra: Record<string, unknown>) => ({
    id: 'f1', template_id: 'boundary-bypass', severity: 'high', confidence: 90, title: 'export reachable without login',
    evidence: { request: 'GET /export', response: 'HTTP 200 {"rows": 3}' }, ...extra,
  });

  it('a claim key that names a boundary records it contradicted, where it used to read as stale', async () => {
    const root = await project();
    const model = await parse(root);
    const key = resolveBoundaryTarget(model, HTTP).key;
    const r = importScan(root, model, await scan(root, [finding({ claim_key: key })]), { by: 'cxg', at: NOW });
    expect(r.stale).toEqual([]);
    expect(r.confirmed).toEqual([]);
    expect(r.boundaries).toHaveLength(1);
    expect(r.boundaries[0].entry).toMatchObject({ outcome: 'contradicted', by: 'cxg:boundary-bypass', source: { kind: 'scan', joined_by: 'claim-key' } });
    expect(classifyBoundaryClaims(model, readHypotheses(root)).summary.contradicted).toBe(1);
    const text = formatImport(r);
    expect(text).toContain('; 1 boundary outcome recorded');
    expect(text).toContain('Contradicted  boundary #http-boundary (between Client and #api)');
  });

  it('a boundary key beside an exposure key records both claims', async () => {
    const root = await project();
    const model = await parse(root);
    const exposureKey = resolveTarget(model, EXPOSURE).key;
    const boundaryKey = resolveBoundaryTarget(model, HTTP).key;
    const r = importScan(root, model, await scan(root, [finding({ annotation: { file: 'src/a.ts', line: 5, claim_key: exposureKey, boundary_claim_key: boundaryKey } })]), { by: 'cxg', at: NOW });
    expect(r.confirmed.map(c => [c.record.key, c.joinedBy])).toEqual([[exposureKey, 'claim-key']]);
    expect(r.boundaries.map(b => b.record.key)).toEqual([boundaryKey]);
    const read = readHypotheses(root);
    expect(classifyHypotheses(model, read).summary.confirmed).toBe(1);
    expect(classifyBoundaryClaims(model, read).summary.contradicted).toBe(1);
  });

  it('a boundary key alone never falls to the coarse exposure joins', async () => {
    const root = await project();
    const model = await parse(root);
    const boundaryKey = resolveBoundaryTarget(model, HTTP).key;
    // The location names the exposure's line and the asset matches it: without
    // the rule, the location tier would confirm that exposure on boundary evidence.
    const r = importScan(root, model, await scan(root, [finding({ boundaryClaimKey: boundaryKey, asset: '#api', annotation: { file: 'src/a.ts', line: 5 } })]), { by: 'cxg', at: NOW });
    expect(r.confirmed).toEqual([]);
    expect(r.boundaries).toHaveLength(1);
    expect(classifyHypotheses(model, readHypotheses(root)).summary.untested).toBe(1);
  });

  it('records supported when the finding says so, under properties too', async () => {
    const root = await project();
    const model = await parse(root);
    const key = resolveBoundaryTarget(model, DATA).key;
    const r = importScan(root, model, await scan(root, [finding({ boundary_outcome: 'supported', properties: { boundaryClaimKey: key } })]), { by: 'cxg', at: NOW });
    expect(r.boundaries[0].entry.outcome).toBe('supported');
  });

  it('a boundary key that names no boundary is stale, and an unshaped one is malformed', async () => {
    const root = await project();
    const model = await parse(root);
    const gone = `${'a'.repeat(64)}:0`;
    const r = importScan(root, model, await scan(root, [
      finding({ id: 'gone', boundary_claim_key: gone }),
      finding({ id: 'junk', boundary_claim_key: 'not-a-key' }),
    ]), { by: 'cxg', at: NOW });
    expect(r.stale.map(s => [s.finding.id, s.boundary])).toEqual([['gone', true]]);
    expect(r.malformed.map(m => [m.finding.id, m.stamp.field])).toEqual([['junk', 'boundary_claim_key']]);
    expect(r.boundaries).toEqual([]);
    expect(readHypotheses(root).status).toBe('absent');
    expect(formatImport(r)).toContain('was tested against a boundary that is no longer in the model');
  });
});

describe('the CLI', () => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
  const run = (cwd: string, ...args: string[]) => new Promise<{ code: number; stdout: string; stderr: string }>((res) =>
    execFile(process.execPath, [tsx, cli, ...args], { cwd, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => res({ code: (err as { code?: number } | null)?.code ?? 0, stdout, stderr })));

  it('contradict, support and boundaries round-trip through the ledger', async () => {
    const root = await project();
    const c = await run(root, 'hypothesis', 'contradict', '#http-boundary', '.', '--evidence', GOT_THROUGH, '--by', 'human:t');
    expect(c.code).toBe(0);
    expect(c.stdout).toContain('Contradicted  boundary #http-boundary');
    const s = await run(root, 'hypothesis', 'support', DATA, '.', '--evidence', REFUSED, '--by', 'human:t');
    expect(s.code).toBe(0);
    const list = await run(root, 'hypothesis', 'boundaries', '.', '--json');
    const doc = JSON.parse(list.stdout);
    expect(doc.schema).toBe('guardlink.boundary-claims/v1');
    expect(doc.summary).toEqual({ unverified: 0, supported: 1, contradicted: 1, retest: 0 });
    expect(doc.records.map((r: any) => [r.id, r.state, r.outcome.by])).toEqual([['http-boundary', 'contradicted', 'human:t'], ['data-boundary', 'supported', 'human:t']]);
    const missing = await run(root, 'hypothesis', 'support', '#http-boundary', '.');
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain('--evidence is required');
  }, 60_000);
});
