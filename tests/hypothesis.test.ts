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
  classifyHypotheses, attachHypotheses, rankUntested, recordOutcome, importScan, resolveTarget, confirmedLine, writeConfirmedLine,
} from '../src/hypothesis/index.js';
import { lintAnnotations } from '../src/gate/index.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { generateSarif } from '../src/analyzer/sarif.js';

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

// ─── GAP-58: the stamp and the sibling that landed on its line ────────

/**
 * Two exposures with the same asset, the same threat and the same file. GuardLink
 * derives the threat id from exactly that tuple, so both carry ONE id, and the
 * only thing on a stamped finding that tells them apart is the anchor hash.
 */
const SIBLINGS = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "B: findOrder concatenates id"
 */
export function findOrder(id: string) { return id; }
`;

/** A is gone and B's @exposes now sits on line 4 — the line A was tested at. */
const B_ON_A_LINE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "B: findOrder concatenates id"
 */
export function findOrder(id: string) { return id; }
`;

async function siblings(source: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-gap58-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), source);
  return root;
}

/** What cxg stamps onto a finding: the exported result's location and its fingerprints. */
function stamp(sarif: ReturnType<typeof generateSarif>, line: number) {
  const r = sarif.runs[0].results.find(x => x.locations[0].physicalLocation.region.startLine === line);
  if (!r) throw new Error(`no exported result at line ${line}`);
  return {
    file: r.locations[0].physicalLocation.artifactLocation.uri,
    line: r.locations[0].physicalLocation.region.startLine,
    threat_id: r.partialFingerprints!['guardlink/threatId'],
    anchor_hash: r.partialFingerprints!['guardlink/anchorHash'],
  };
}

const gap58Scan = (annotation: Record<string, unknown>) => ({
  scan_id: 'cxg-gap58',
  findings: [{
    id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94,
    title: 'SQLi in findUser', cwe_ids: ['CWE-89'], annotation,
    evidence: { request: "POST /u email=' OR 1=1--", response: 'HTTP 200 3 rows', matched_patterns: ['rows'], data: {} },
  }],
});

/** A well-formed anchor hash that no claim in these fixtures carries. */
const UNRELATED_HASH = 'sha256-v1:' + '0'.repeat(64);

async function writeScan(root: string, scan: unknown): Promise<string> {
  const path = join(root, 'scan.json');
  await writeFile(path, JSON.stringify(scan));
  return path;
}

describe('scan import — the anchor hash as a discriminator', () => {
  it('still confirms when nothing moved: the stamped claim is the claim that is there', async () => {
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const a = stamp(generateSarif(model), 4);
    expect(a.anchor_hash).toMatch(/^sha256-v1:[0-9a-f]{64}$/);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, anchor_hash: a.anchor_hash }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toHaveLength(1);
    expect(`${r.confirmed[0].record.file}:${r.confirmed[0].record.line}`).toBe('src/a.ts:4');
    expect(r.confirmed[0].record.key).toBe(resolveTarget(model, 'src/a.ts:4').key);
    expect(r.confirmed[0].record.location.anchor?.symbol).toBe('findUser');
    expect(r.stale).toEqual([]);
  }, 60000);

  it('refuses the sibling that landed on the tested line', async () => {
    // A was tested at src/a.ts:4, then deleted; B now sits on line 4. B matches every
    // other stamped value — same file, same line, same asset, same threat, so the same
    // threat id — and differs only in the code it is anchored to.
    const tested = await siblings(SIBLINGS);
    const testedModel = await parse(tested);
    const a = stamp(generateSarif(testedModel), 4);

    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const b = stamp(generateSarif(model), 4);
    expect(b.threat_id).toBe(a.threat_id);
    expect(b.anchor_hash).not.toBe(a.anchor_hash);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, anchor_hash: a.anchor_hash }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(s => s.finding.id)).toEqual(['f1']);
    expect(r.stale[0].candidates.map(c => `${c.file}:${c.line}`)).toEqual(['src/a.ts:4']);
    // Nothing was written: no entry, and B is still untested.
    expect(readHypotheses(root).status).toBe('absent');
  }, 60000);

  it('joins as before when the finding carries no anchor hash', async () => {
    // The same scan without the stamp. Older reports keep the behaviour they had —
    // and this is the join the stamp exists to narrow.
    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const path = await writeScan(root, gap58Scan({ file: 'src/a.ts', line: 4 }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('location');
    expect(r.stale).toEqual([]);
  }, 60000);

  it('narrows an otherwise ambiguous join to the claim the stamp names', async () => {
    // No location on the finding, so the join falls to asset and threat and fits both
    // siblings. The stamp says which code was tested, so there is one candidate left.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const a = stamp(generateSarif(model), 4);

    const path = await writeScan(root, gap58Scan({ asset: '#api', threat: '#sqli', anchor_hash: a.anchor_hash }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.ambiguous).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('asset-threat');
    expect(r.confirmed[0].record.key).toBe(resolveTarget(model, 'src/a.ts:4').key);
  }, 60000);

  it('the CLI refuses it too: nothing recorded, and it says why', async () => {
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
    const tested = await siblings(SIBLINGS);
    const a = stamp(generateSarif(await parse(tested)), 4);

    const root = await siblings(B_ON_A_LINE);
    await writeScan(root, gap58Scan({ file: a.file, line: a.line, anchor_hash: a.anchor_hash }));
    const run = await new Promise<{ code: number; stdout: string }>((res) =>
      execFile(process.execPath, [tsx, cli, 'hypothesis', 'confirm', '.', '--from-scan', 'scan.json'],
        { cwd: root, maxBuffer: 64 * 1024 * 1024 },
        (err, stdout) => res({ code: (err as { code?: number } | null)?.code ?? 0, stdout })));

    expect(run.code).toBe(1);
    expect(run.stdout).toContain('1 stale');
    expect(run.stdout).toMatch(/tested against code that is no longer at src\/a\.ts:4/);
    expect(existsSync(join(root, HYPOTHESES_FILE))).toBe(false);
  }, 120_000);

  it('joins as before when no candidate claim carries an anchor', async () => {
    // Anchors are attached per file and go null all-or-nothing for a file that is
    // outside the root, unreadable, or fails to parse (src/structure/attach.ts).
    // With nothing to compare against, a stamped finding must not be refused.
    const root = await siblings(B_ON_A_LINE);
    const model = (await parseProject({ root, project: 'h', anchors: false })).model;
    expect(model.exposures[0].location.anchor).toBeUndefined();

    const path = await writeScan(root, gap58Scan({ file: 'src/a.ts', line: 4, anchor_hash: UNRELATED_HASH }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.stale).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
  }, 60000);

  it('refusing a mixed candidate set costs no confirmation — that join was ambiguous either way', async () => {
    // Candidates span two files, and one file's anchors are null (the state
    // attach.ts leaves for a file it could not read). The stamp matches neither
    // anchored candidate. Refusing here removes nothing: without the stamp the
    // same three candidates were reported ambiguous, never confirmed.
    const root = await siblings(SIBLINGS);
    await writeFile(join(root, 'src', 'b.ts'), `import y from 'y';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "C: findAccount concatenates id"
 */
export function findAccount(id: string) { return id; }
`);
    const model = await parse(root);
    const inB = model.exposures.find(e => e.location.file === 'src/b.ts')!;
    inB.location.anchor = null;
    // Mixed by construction: two claims anchored, one not.
    expect(model.exposures).toHaveLength(3);
    expect(model.exposures.filter(e => e.location.anchor?.hash)).toHaveLength(2);
    expect(model.exposures.map(e => e.location.anchor?.hash ?? null)).not.toContain(UNRELATED_HASH);

    // Joined by asset and threat, so all three claims are candidates.
    const stamped = await writeScan(root, gap58Scan({ asset: '#api', threat: '#sqli', anchor_hash: UNRELATED_HASH }));
    const withStamp = importScan(root, model, stamped, { by: 'cxg', at: NOW });
    expect(withStamp.confirmed).toEqual([]);
    expect(withStamp.stale.map(x => x.candidates.length)).toEqual([3]);

    const bare = await writeScan(root, gap58Scan({ asset: '#api', threat: '#sqli' }));
    const withoutStamp = importScan(root, model, bare, { by: 'cxg', at: NOW });
    expect(withoutStamp.confirmed).toEqual([]);
    expect(withoutStamp.ambiguous.map(x => x.candidates.length)).toEqual([3]);
  }, 60000);

  it('a file-scope anchor refuses after any edit to that file — the same edit the ledger already expires on', async () => {
    // A module-level doc-block anchors the whole FILE (scope "file", reason
    // "first-node"): 108 of this repository's 115 exposures at 283d41e are that
    // shape. Its hash therefore moves on an unrelated edit elsewhere in the file,
    // and a stamp taken before that edit is refused. That is not a new judgement:
    // the ledger already expires an outcome the moment the hash moves, so the
    // refusal declines to write exactly what would be marked `retest` on sight.
    const MODULE = `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "the query builder concatenates"
 */
import x from 'x';

export function findUser(email: string) { return email; }
`;
    const root = await siblings(MODULE);
    const before = await parse(root);
    expect(before.exposures[0].location.anchor).toMatchObject({ scope: 'file', reason: 'first-node' });
    const a = stamp(generateSarif(before), 2);

    // The ledger's existing rule, on this exact edit: a confirmation recorded now
    // becomes `retest` once the file changes.
    recordOutcome(root, before, 'src/a.ts:2', 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    await writeFile(join(root, 'src', 'a.ts'), `${MODULE}
export function unrelatedHelper(n: number) { return n + 1; }
`);
    const after = await parse(root);
    expect(after.exposures[0].location.anchor!.hash).not.toBe(a.anchor_hash);
    const c = classifyHypotheses(after, readHypotheses(root));
    expect(c.records.find(r => r.verb === 'exposes')!.state).toBe('retest');

    // And the join refuses a stamp from before that edit.
    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, anchor_hash: a.anchor_hash }));
    const r = importScan(root, after, path, { by: 'cxg', at: NOW });
    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(x => x.finding.id)).toEqual(['f1']);
  }, 60000);

  it('does not separate siblings that anchor the same code — the bound on this discriminator', async () => {
    // NOT desired behaviour: the limit of what a hash over the anchor's code tokens
    // can do. Two @exposes in one doc-block anchor the same function, so they carry
    // one anchor hash. Delete the first and the second moves onto its line carrying a
    // hash equal to the stamp, and the stamp cannot tell that this is a different
    // claim. Separating these needs an identity the anchor hash does not hold.
    const shared = (claims: string) => `import x from 'x';

/**
${claims}
 */
export function findUser(email: string) { return email; }
`;
    const A = ' * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"';
    const B = ' * @exposes #api to #sqli [critical] cwe:CWE-89 -- "B: findUser skips the allowlist"';

    const tested = await siblings(shared(`${A}\n${B}`));
    const testedModel = await parse(tested);
    const a = stamp(generateSarif(testedModel), 4);

    const root = await siblings(shared(B));
    const model = await parse(root);
    const b = stamp(generateSarif(model), 4);
    expect(b.anchor_hash).toBe(a.anchor_hash);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, anchor_hash: a.anchor_hash }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    // The confirmation lands on a claim that is not the one the probe tested.
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].record.key).not.toBe(resolveTarget(testedModel, 'src/a.ts:4').key);
  }, 60000);
});
