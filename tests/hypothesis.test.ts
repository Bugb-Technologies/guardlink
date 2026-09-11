/**
 * The hypothesis ledger: outcomes with evidence, expiry when the code moves,
 * a ranked queue, scan import, and where the state shows.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { parseProject } from '../src/parser/parse-project.js';
import {
  HYPOTHESES_FILE, readHypotheses, writeHypotheses, emptyHypotheses,
  classifyHypotheses, attachHypotheses, rankUntested, recordOutcome, importScan, confirmedLine, writeConfirmedLine,
} from '../src/hypothesis/index.js';
import { lintAnnotations } from '../src/gate/index.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.Web (#web) -- "Web tier"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 * @threat DoS (#dos) [medium] -- "Resource exhaustion"
 * @control Encoding (#enc) -- "Output encoding"
 */
export {};
`;
const SOURCE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "req.body.email concatenated into findUser() query"
 * @exposes #api to #dos [medium] -- "parseBody() has no size cap"
 * @exposes #web to #xss [high] cwe:CWE-79 -- "profile.bio rendered via innerHTML in render()"
 * @audit #api -- "review the query builder"
 * @audit #web -- "encode bio"
 * @owns platform for #api -- "platform team"
 */
export function login(email: string) { return email; }
`;
const SQLI = 'src/a.ts:4', DOS = 'src/a.ts:5', XSS = 'src/a.ts:6';
const NOW = '2026-09-12T10:00:00.000Z';
const REFUTE = 'guardlink_context with file="x; rm -rf /" returned a Zod validation error; nothing reached execFileSync()';
const CONFIRM = 'POST /login with email=\' OR 1=1-- returned HTTP 200 and three rows; reproduced twice';

async function project(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-hyp-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), SOURCE);
  return root;
}
const parse = async (root: string) => (await parseProject({ root, project: 'h' })).model;

describe('the ledger', () => {
  it('is absent until written, round-trips, and reports corruption instead of throwing', async () => {
    const root = await project();
    expect(readHypotheses(root).status).toBe('absent');
    const model = await parse(root);
    recordOutcome(root, model, SQLI, 'refuted', { evidence: REFUTE, by: 'human:test', at: NOW });
    const read = readHypotheses(root);
    expect(read.status).toBe('present');
    expect(read.ledger!.schema).toBe('guardlink.hypotheses/v1');
    expect(read.ledger!.entries).toHaveLength(1);
    expect(read.ledger!.entries[0]).toMatchObject({ file: 'src/a.ts', line: 4, outcome: 'refuted', evidence: REFUTE, by: 'human:test', at: NOW, source: { kind: 'manual' }, history: [] });
    expect(read.ledger!.entries[0].anchor?.hash).toMatch(/^sha256-v1:/);
    await writeFile(join(root, HYPOTHESES_FILE), '{ not json');
    expect(readHypotheses(root).status).toBe('corrupt');
    writeHypotheses(root, emptyHypotheses());
    expect(readHypotheses(root).ledger!.entries).toEqual([]);
  });
});

describe('classification and expiry', () => {
  it('untested by default; an outcome holds while the code holds; it expires when the code moves', async () => {
    const root = await project();
    let model = await parse(root);
    let c = classifyHypotheses(model, readHypotheses(root));
    expect(c.summary).toEqual({ untested: 3, confirmed: 0, refuted: 0, retest: 0 });
    expect(c.records.map(r => r.state)).toEqual(['untested', 'untested', 'untested']);

    recordOutcome(root, model, SQLI, 'refuted', { evidence: REFUTE, by: 'human:test', at: NOW });
    recordOutcome(root, model, XSS, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    c = classifyHypotheses(model, readHypotheses(root));
    const by = (t: string) => c.records.find(r => `${r.file}:${r.line}` === t)!;
    expect(by(SQLI).state).toBe('refuted');
    expect(by(XSS).state).toBe('confirmed');
    expect(by(DOS).state).toBe('untested');
    expect(c.summary).toEqual({ untested: 1, confirmed: 1, refuted: 1, retest: 0 });

    // The code beneath the claims changes: the refutation lapses, the confirmation asks for a retest.
    await writeFile(join(root, 'src', 'a.ts'), SOURCE.replace('{ return email; }', '{ return email.trim(); }'));
    model = await parse(root);
    c = classifyHypotheses(model, readHypotheses(root));
    const s = c.records.find(r => `${r.file}:${r.line}` === SQLI)!;
    expect(s.state).toBe('untested');
    expect(s.expired).toBe(true);
    expect(s.previous?.outcome).toBe('refuted');
    expect(c.records.find(r => `${r.file}:${r.line}` === XSS)!.state).toBe('retest');
    expect(c.summary).toEqual({ untested: 2, confirmed: 0, refuted: 0, retest: 1 });

    // A second outcome keeps the first in history.
    recordOutcome(root, model, SQLI, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: '2026-10-01T00:00:00.000Z' });
    const e = readHypotheses(root).ledger!.entries.find(x => x.line === 4)!;
    expect(e.outcome).toBe('confirmed');
    expect(e.history).toHaveLength(1);
    expect(e.history[0].outcome).toBe('refuted');
  });

  it('holds both outcomes to the evidence bar', async () => {
    const root = await project();
    const model = await parse(root);
    expect(() => recordOutcome(root, model, SQLI, 'refuted', { evidence: '   ', by: 'human:test', at: NOW })).toThrow(/evidence/i);
    expect(() => recordOutcome(root, model, SQLI, 'confirmed', { evidence: 'probably exploitable', by: 'human:test', at: NOW })).toThrow(/request|response|reproduc/i);
    expect(() => recordOutcome(root, model, 'src/a.ts:99', 'refuted', { evidence: REFUTE, by: 'human:test', at: NOW })).toThrow(/no @exposes/i);
    expect(readHypotheses(root).status).toBe('absent');
  });
});

describe('the queue', () => {
  it('ranks retest first, then severity, then an undefended path, then unowned, and is deterministic', async () => {
    const root = await project();
    let model = await parse(root);
    recordOutcome(root, model, DOS, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    await writeFile(join(root, 'src', 'a.ts'), SOURCE.replace('{ return email; }', '{ return email.trim(); }'));
    model = await parse(root);
    const c = classifyHypotheses(model, readHypotheses(root));
    const a = rankUntested(c.records, model, new Set(['#web']));
    const b = rankUntested(c.records, model, new Set(['#web']));
    expect(a.map(r => `${r.file}:${r.line}`)).toEqual([DOS, SQLI, XSS]);   // retest (medium) beats untested critical; then critical; then high
    expect(a).toEqual(b);
    expect(a[2].onPath).toBe(true);
    expect(a[2].unowned).toBe(true);     // #web has no @owns
    expect(a[1].unowned).toBe(false);    // #api is owned by platform
    // Same severity: the one on a path first, then the unowned one.
    const tie = rankUntested(c.records.filter(r => r.state === 'untested'), model, new Set(['#web']));
    expect(tie.map(r => r.threat)).toEqual(['#sqli', '#xss']);
  });
});

describe('scan import', () => {
  it('joins by annotation location, then asset and threat, then CWE; reports ambiguous and unmatched; redacts evidence', async () => {
    const root = await project();
    const model = await parse(root);
    const scan = {
      scan_id: 'cxg-1',
      findings: [
        { id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94, title: 'SQLi in login', cwe_ids: ['CWE-89'], annotation: { file: 'src/a.ts', line: 4 },
          evidence: { request: "POST /login Authorization: Bearer secrettoken123456 email=' OR 1=1--", response: 'HTTP 200 3 rows', matched_patterns: ['rows'], data: {} } },
        { id: 'f2', template_id: 'xss-bio', severity: 'high', confidence: 0.8, title: 'XSS in bio', cwe_ids: [], asset: '#web', threat: '#xss',
          evidence: { request: 'GET /p?bio=<script>', response: '<script>', matched_patterns: [], data: {} } },
        { id: 'f3', template_id: 'dos-generic', severity: 'medium', confidence: 0.5, title: 'slow', cwe_ids: ['CWE-400'],
          evidence: { request: 'x', response: 'y', matched_patterns: [], data: {} } },
        { id: 'f4', template_id: 'api-generic', severity: 'low', confidence: 0.3, title: 'something on api', cwe_ids: [], asset: '#api',
          evidence: { request: 'x', response: 'y', matched_patterns: [], data: {} } },
      ],
    };
    await writeFile(join(root, 'scan.json'), JSON.stringify(scan));
    const r = importScan(root, model, join(root, 'scan.json'), { by: 'cxg', at: NOW });
    expect(r.confirmed.map(x => `${x.record.file}:${x.record.line}`)).toEqual([SQLI, XSS]);
    expect(r.confirmed[0].joinedBy).toBe('location');
    expect(r.confirmed[1].joinedBy).toBe('asset-threat');
    expect(r.unmatched.map(f => f.id)).toEqual(['f3']);
    expect(r.ambiguous.map(a => a.finding.id)).toEqual(['f4']);
    expect(r.ambiguous[0].candidates.map(c => `${c.file}:${c.line}`)).toEqual([SQLI, DOS]);
    const entries = readHypotheses(root).ledger!.entries;
    expect(entries).toHaveLength(2);
    const sqli = entries.find(e => e.line === 4)!;
    expect(sqli.outcome).toBe('confirmed');
    expect(sqli.by).toBe('cxg:login-sqli');
    expect(sqli.source).toEqual({ kind: 'scan', scan_id: 'cxg-1', template_id: 'login-sqli', confidence: 0.94 });
    expect(sqli.evidence).toContain('HTTP 200');
    expect(sqli.evidence).not.toContain('secrettoken123456');
    // A finding that joins by CWE alone.
    await writeFile(join(root, 'scan2.json'), JSON.stringify({ scan_id: 'cxg-2', findings: [{ id: 'g1', template_id: 'sqli-blind', severity: 'critical', confidence: 0.7, title: 'blind sqli', cwe_ids: ['CWE-89'], evidence: { request: 'q', response: 'delay 5s observed', matched_patterns: [], data: {} } }] }));
    const r2 = importScan(root, model, join(root, 'scan2.json'), { by: 'cxg', at: NOW });
    expect(r2.confirmed[0].joinedBy).toBe('cwe');
    expect(readHypotheses(root).ledger!.entries.find(e => e.line === 4)!.history).toHaveLength(1);
  });
});

describe('writing the @confirmed line', () => {
  it('offers a parseable line and --write puts it under the @exposes with the same prefix, passing the gate', async () => {
    const root = await project();
    const model = await parse(root);
    const { record, entry } = recordOutcome(root, model, SQLI, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    const line = confirmedLine(record, entry);
    expect(line).toBe(`@confirmed #sqli on #api [critical] cwe:CWE-89 -- "${CONFIRM}"`);
    const w = writeConfirmedLine(root, record, line);
    expect(w).toEqual({ file: 'src/a.ts', line: 5 });
    const text = await readFile(join(root, 'src', 'a.ts'), 'utf8');
    expect(text.split('\n')[4]).toBe(` * ${line}`);
    const again = await parse(root);
    expect(again.confirmed).toHaveLength(1);
    expect(lintAnnotations(again).filter(v => v.rule === 'confirmed-without-evidence')).toEqual([]);
    // Writing twice does not duplicate.
    expect(() => writeConfirmedLine(root, record, line)).toThrow(/already/i);
  });
});

describe('where the state shows', () => {
  it('lint treats a refuted exposure as paired; the dashboard drops it from the open count and badges it', async () => {
    const root = await project();
    await writeFile(join(root, 'src', 'a.ts'), SOURCE.replace(' * @audit #web -- "encode bio"\n', ''));   // #web → #xss is now unpaired
    let model = await parse(root);
    expect(lintAnnotations(model).filter(v => v.rule === 'exposes-unpaired')).toHaveLength(1);
    recordOutcome(root, model, XSS, 'refuted', { evidence: REFUTE, by: 'human:test', at: NOW });
    model = await parse(root);
    attachHypotheses(model, classifyHypotheses(model, readHypotheses(root)));
    expect(model.exposures[2].hypothesis).toMatchObject({ state: 'refuted', by: 'human:test', expired: false });
    expect(lintAnnotations(model).filter(v => v.rule === 'exposes-unpaired')).toEqual([]);

    const h = generateDashboardHTML(await parse(root), root);
    expect(h).toContain('<span class="kpi-v">2</span><span class="kpi-l">Open threats</span>');
    expect(h).toContain('data-status="refuted"');
    expect(h).toContain('"hypothesis":{"state":"refuted"');
    expect(h).toContain('function hypothesisBand(');
  });
});

describe('the CLI', () => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
  const run = (cwd: string, ...args: string[]) => new Promise<{ code: number; stdout: string; stderr: string }>((res) =>
    execFile(process.execPath, [tsx, cli, ...args], { cwd, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => res({ code: (err as { code?: number } | null)?.code ?? 0, stdout, stderr })));

  it('refute, list --json, next --intake and status', async () => {
    const root = await project();
    const noEvidence = await run(root, 'hypothesis', 'refute', SQLI, '.');
    expect(noEvidence.code).toBe(1);
    expect(existsSync(join(root, HYPOTHESES_FILE))).toBe(false);

    const ok = await run(root, 'hypothesis', 'refute', SQLI, '.', '--evidence', REFUTE, '--by', 'human:zippon');
    expect(ok.code).toBe(0);
    expect(ok.stdout).toMatch(/Refuted\s+#api → #sqli/);
    expect(ok.stdout).toContain('human:zippon');

    const list = await run(root, 'hypothesis', 'list', '.', '--json');
    expect(list.code).toBe(0);
    const j = JSON.parse(list.stdout);
    expect(j.schema).toBe('guardlink.hypotheses-list/v1');
    expect(j.summary).toEqual({ untested: 2, confirmed: 0, refuted: 1, retest: 0 });
    expect(j.records.find((r: { line: number }) => r.line === 4).state).toBe('refuted');

    const next = await run(root, 'hypothesis', 'next', '.', '--intake');
    expect(next.code).toBe(0);
    expect(next.stdout).toMatch(/bugb intake/);
    expect(next.stdout).toContain('#web → #xss');
    expect(next.stdout).not.toContain('#api → #sqli');   // refuted, not in the queue

    const status = await run(root, 'status', '.');
    expect(status.stdout).toMatch(/Hypotheses:\s+2 untested, 0 confirmed, 1 refuted, 0 retest/);
    expect(status.stdout).toMatch(/Exposures:\s+3 \(1 refuted with evidence\)/);
  }, 120_000);
});
