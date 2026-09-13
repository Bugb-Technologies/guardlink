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
import { relationRecords } from '../src/parser/claim-key.js';
import {
  HYPOTHESES_FILE, readHypotheses, writeHypotheses, emptyHypotheses,
  classifyHypotheses, attachHypotheses, rankUntested, recordOutcome, importScan, resolveTarget, confirmedLine, writeConfirmedLine, formatImport,
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
    // These findings carry no claim key, so the weaker join is recorded as such.
    expect(sqli.source).toEqual({ kind: 'scan', scan_id: 'cxg-1', template_id: 'login-sqli', confidence: 0.94, joined_by: 'location' });
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
 * only thing on a stamped finding that tells them apart is the claim key.
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

/** The exported result at a line, as cxg would find it in the SARIF. */
function exported(sarif: ReturnType<typeof generateSarif>, line: number) {
  const r = sarif.runs[0].results.find(x => x.locations[0].physicalLocation.region.startLine === line);
  if (!r) throw new Error(`no exported result at line ${line}`);
  return r;
}

/** What cxg stamps onto a finding: the exported result's location and its fingerprints. */
function stamp(sarif: ReturnType<typeof generateSarif>, line: number) {
  const r = exported(sarif, line);
  return {
    file: r.locations[0].physicalLocation.artifactLocation.uri,
    line: r.locations[0].physicalLocation.region.startLine,
    threat_id: r.partialFingerprints!['guardlink/threatId'],
    claim_key: r.partialFingerprints!['guardlink/claimKey'],
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

/** A well-formed claim key that no claim in these fixtures carries. */
const UNRELATED_KEY = '0'.repeat(64) + ':0';

async function writeScan(root: string, scan: unknown): Promise<string> {
  const path = join(root, 'scan.json');
  await writeFile(path, JSON.stringify(scan));
  return path;
}

describe('scan import — the claim key as a discriminator', () => {
  it('still confirms when nothing moved: the stamped claim is the claim that is there', async () => {
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const a = stamp(generateSarif(model), 4);
    expect(a.claim_key).toMatch(/^[0-9a-f]{64}:\d+$/);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, claim_key: a.claim_key }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toHaveLength(1);
    expect(`${r.confirmed[0].record.file}:${r.confirmed[0].record.line}`).toBe('src/a.ts:4');
    expect(r.confirmed[0].record.key).toBe(resolveTarget(model, 'src/a.ts:4').key);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
    expect(r.stale).toEqual([]);
    // The provenance is persisted, so the confirmation stays distinguishable later.
    const source = readHypotheses(root).ledger!.entries[0].source;
    expect(source).toMatchObject({ kind: 'scan', joined_by: 'claim-key' });
  }, 60000);

  it('refuses the sibling that landed on the tested line', async () => {
    // A was tested at src/a.ts:4, then deleted; B now sits on line 4. B matches every
    // other stamped value — same file, same line, same asset, same threat, so the same
    // threat id — and differs only in being a different claim.
    const tested = await siblings(SIBLINGS);
    const testedModel = await parse(tested);
    const a = stamp(generateSarif(testedModel), 4);

    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const b = stamp(generateSarif(model), 4);
    expect(b.threat_id).toBe(a.threat_id);
    expect(b.claim_key).not.toBe(a.claim_key);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, claim_key: a.claim_key }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(s => s.finding.id)).toEqual(['f1']);
    // Nothing was written: no entry, and B is still untested.
    expect(readHypotheses(root).status).toBe('absent');
    // B is not offered as a by-hand target: recording A's evidence there is the
    // very confirmation the key just refused.
    expect(formatImport(r)).not.toMatch(/guardlink hypothesis confirm src\/a\.ts:4/);
  }, 60000);

  it('joins as before when the finding carries no claim key', async () => {
    // The same scan without the stamp. Older reports keep the behaviour they had —
    // and this is the join the stamp exists to resolve.
    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const path = await writeScan(root, gap58Scan({ file: 'src/a.ts', line: 4 }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('location');
    expect(r.stale).toEqual([]);

    // But it does not look like a key-verified confirmation, and the report says
    // once that the weaker join was used throughout.
    const out = formatImport(r);
    expect(out).toMatch(/NOT key-verified/);
    expect(out).toMatch(/No finding in this report carried a claim key/);
    expect(readHypotheses(root).ledger!.entries[0].source).toMatchObject({ kind: 'scan', joined_by: 'location' });
  }, 60000);

  it('resolves an otherwise ambiguous join to the claim the stamp names', async () => {
    // Asset and threat alone fit both siblings. The key names one claim, so the
    // coarse tier never runs and nothing is handed back as ambiguous.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const a = stamp(generateSarif(model), 4);

    const path = await writeScan(root, gap58Scan({ asset: '#api', threat: '#sqli', claim_key: a.claim_key }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.ambiguous).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
    expect(r.confirmed[0].record.key).toBe(resolveTarget(model, 'src/a.ts:4').key);
  }, 60000);

  it('resolves a finding that carries nothing but a claim key', async () => {
    // No location, no asset, no threat, no CWE — only the most precise identifier
    // in the system. Every coarse tier would call this unmatched and tell the
    // operator to annotate it first.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const a = stamp(generateSarif(model), 4);

    const path = await writeScan(root, { scan_id: 'cxg-keyonly', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9,
      title: 'SQLi', cwe_ids: [], claim_key: a.claim_key,
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.unmatched).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
    expect(r.confirmed[0].record.key).toBe(resolveTarget(model, 'src/a.ts:4').key);
  }, 60000);

  it('the CLI refuses it too: nothing recorded, and it says why', async () => {
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
    const tested = await siblings(SIBLINGS);
    const a = stamp(generateSarif(await parse(tested)), 4);

    const root = await siblings(B_ON_A_LINE);
    await writeScan(root, gap58Scan({ file: a.file, line: a.line, claim_key: a.claim_key }));
    const run = await new Promise<{ code: number; stdout: string }>((res) =>
      execFile(process.execPath, [tsx, cli, 'hypothesis', 'confirm', '.', '--from-scan', 'scan.json'],
        { cwd: root, maxBuffer: 64 * 1024 * 1024 },
        (err, stdout) => res({ code: (err as { code?: number } | null)?.code ?? 0, stdout })));

    expect(run.code).toBe(1);
    expect(run.stdout).toContain('1 stale');
    expect(run.stdout).toMatch(/tested against a claim that is no longer in the model/);
    expect(run.stdout).toMatch(/Any claim standing there now is a different claim/);
    // B is never offered as a by-hand target — that would be the refused confirmation.
    expect(run.stdout).not.toMatch(/guardlink hypothesis confirm src\/a\.ts:4/);
    expect(existsSync(join(root, HYPOTHESES_FILE))).toBe(false);
  }, 120_000);

  it('a key naming no claim is stale, and that costs no confirmation the coarse join would have made', async () => {
    // Three claims across two files all fit asset-and-threat, so without a stamp
    // this was ambiguous and nothing was recorded. With a stamp that names no
    // claim it is stale — also nothing recorded. Refusing removes no confirmation.
    const root = await siblings(SIBLINGS);
    await writeFile(join(root, 'src', 'b.ts'), `import y from 'y';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "C: findAccount concatenates id"
 */
export function findAccount(id: string) { return id; }
`);
    const model = await parse(root);
    expect(model.exposures).toHaveLength(3);
    const keys = relationRecords(model).filter(r => r.verb === 'exposes').map(r => r.key);
    expect(keys).not.toContain(UNRELATED_KEY);

    const stamped = await writeScan(root, gap58Scan({ asset: '#api', threat: '#sqli', claim_key: UNRELATED_KEY }));
    const withStamp = importScan(root, model, stamped, { by: 'cxg', at: NOW });
    expect(withStamp.confirmed).toEqual([]);
    expect(withStamp.ambiguous).toEqual([]);
    expect(withStamp.stale.map(x => x.finding.id)).toEqual(['f1']);

    const bare = await writeScan(root, gap58Scan({ asset: '#api', threat: '#sqli' }));
    const withoutStamp = importScan(root, model, bare, { by: 'cxg', at: NOW });
    expect(withoutStamp.confirmed).toEqual([]);
    expect(withoutStamp.ambiguous.map(x => x.candidates.length)).toEqual([3]);
  }, 60000);

  it('survives an unrelated edit to the file — the drift that expires a ledger outcome costs no confirmation', async () => {
    // A module-level doc-block anchors the whole FILE (scope "file", reason
    // "first-node"), so its ANCHOR hash moves on an unrelated edit anywhere in the
    // file. The claim key does not: it names the claim, not the code beneath it. The
    // ledger still expires the outcome it recorded against that anchor — that rule is
    // untouched — while the join still recognises the claim the probe tested.
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

    recordOutcome(root, before, 'src/a.ts:2', 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    await writeFile(join(root, 'src', 'a.ts'), `${MODULE}
export function unrelatedHelper(n: number) { return n + 1; }
`);
    const after = await parse(root);

    // The anchor moved, so the ledger asks for a retest — unchanged behaviour.
    expect(after.exposures[0].location.anchor!.hash).not.toBe(before.exposures[0].location.anchor!.hash);
    const c = classifyHypotheses(after, readHypotheses(root));
    expect(c.records.find(r => r.verb === 'exposes')!.state).toBe('retest');

    // The claim key did not, so a stamp from before the edit still joins.
    expect(stamp(generateSarif(after), 2).claim_key).toBe(a.claim_key);
    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, claim_key: a.claim_key }));
    const r = importScan(root, after, path, { by: 'cxg', at: NOW });
    expect(r.stale).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].record.key).toBe(a.claim_key);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
  }, 60000);

  it('resolves a claim whose LINE moved while another claim took the tested line', async () => {
    // The displaced shape, which a key used only to veto the coarse tiers gets
    // backwards. A is stamped at src/a.ts:30. Five lines are removed above it, so
    // A is alive at :25 holding the same key while C now sits on :30. Resolving by
    // key first finds A; letting the location tier win first finds C, fails the
    // veto, and calls a live correctly-stamped finding stale.
    const filler = (n: number) => Array.from({ length: n }, (_, i) => `const filler${i} = ${i};`).join('\n');
    const two = (lead: number) => `${filler(lead)}
/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "C: findAccount concatenates id"
 */
export function findAccount(id: string) { return id; }
`;
    const tested = await siblings(two(28));
    const testedModel = await parse(tested);
    const a = stamp(generateSarif(testedModel), 30);

    const root = await siblings(two(23));
    const model = await parse(root);
    // A moved to :25 and kept its key; C now sits on :30, the tested line.
    expect(resolveTarget(model, 'src/a.ts:25').key).toBe(a.claim_key);
    expect(resolveTarget(model, 'src/a.ts:30').key).not.toBe(a.claim_key);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, claim_key: a.claim_key }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.stale).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
    expect(`${r.confirmed[0].record.file}:${r.confirmed[0].record.line}`).toBe('src/a.ts:25');
  }, 60000);

  it('separates two @exposes that share one doc-block', async () => {
    // They anchor the same function, so they carry one anchor hash; they are
    // different claims, so they carry different keys. Delete the first and the
    // survivor keeps its own key, so the first's stamp joins to nothing.
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
    const both = generateSarif(testedModel);
    const a = stamp(both, 4);
    const bBefore = stamp(both, 5);
    // One anchor, two keys: the anchored code cannot tell these apart and the key can.
    expect(testedModel.exposures[0].location.anchor!.hash).toBe(testedModel.exposures[1].location.anchor!.hash);
    expect(bBefore.claim_key).not.toBe(a.claim_key);

    const root = await siblings(shared(B));
    const model = await parse(root);
    const b = stamp(generateSarif(model), 4);
    // B moved onto A's line and kept its own key.
    expect(b.claim_key).toBe(bBefore.claim_key);
    expect(b.claim_key).not.toBe(a.claim_key);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, claim_key: a.claim_key }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(s => s.finding.id)).toEqual(['f1']);
  }, 60000);

  it('does not separate two BYTE-IDENTICAL claims in one file — the bound on this discriminator', async () => {
    // NOT desired behaviour: the limit of an identity built from the claim's own
    // words. Two @exposes whose verb, asset, threat, refs AND description are all
    // equal share a digest, and only an ordinal in document order separates them.
    // Delete the earlier one and the survivor inherits `<digest>:0` — the deleted
    // claim's exact key — so the stamp cannot tell that this is a different claim.
    const CLAIM = ' * @exposes #api to #sqli [critical] cwe:CWE-89 -- "the query builder concatenates"';
    const tested = await siblings(`import x from 'x';

/**
${CLAIM}
 */
export function findUser(email: string) { return email; }

/**
${CLAIM}
 */
export function findOrder(id: string) { return id; }
`);
    const testedModel = await parse(tested);
    const both = generateSarif(testedModel);
    const first = stamp(both, 4), second = stamp(both, 9);
    // The digests are equal; only the ordinal differs.
    expect(first.claim_key.split(':')[0]).toBe(second.claim_key.split(':')[0]);
    expect([first.claim_key, second.claim_key].map(k => k.split(':')[1])).toEqual(['0', '1']);

    // The first is deleted; the second is all that is left.
    const root = await siblings(`import x from 'x';

/**
${CLAIM}
 */
export function findOrder(id: string) { return id; }
`);
    const model = await parse(root);
    const survivor = stamp(generateSarif(model), 4);
    expect(survivor.claim_key).toBe(first.claim_key);

    const path = await writeScan(root, gap58Scan({ file: first.file, line: first.line, claim_key: first.claim_key }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    // The confirmation lands on a claim that is not the one the probe tested.
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].record.key).not.toBe(resolveTarget(testedModel, 'src/a.ts:9').key);
  }, 60000);

  it('refuses a stamp taken before the claim description was reworded — the second limit', async () => {
    const worded = (desc: string) => `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "${desc}"
 */
export function findUser(email: string) { return email; }
`;
    const tested = await siblings(worded('A: findUser concatenates email'));
    const a = stamp(generateSarif(await parse(tested)), 4);

    const root = await siblings(worded('A: findUser concatenates the email'));
    const model = await parse(root);
    expect(stamp(generateSarif(model), 4).claim_key).not.toBe(a.claim_key);

    const path = await writeScan(root, gap58Scan({ file: a.file, line: a.line, claim_key: a.claim_key }));
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });
    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(s => s.finding.id)).toEqual(['f1']);
  }, 60000);
});

/**
 * The export and the import must agree on what the stamp is CALLED, and the
 * agreement has to be asserted without either side naming the field — a fixture
 * that hardcodes the name on both sides encodes the same assumption twice and
 * cannot catch a mismatch. These tests behave like the consumer that exposed
 * one: they take a real `generateSarif` result and forward its emitted
 * `properties` into the scan finding verbatim, then run the real `importScan`.
 *
 * Both fixtures are shapes where the coarse tiers give the WRONG answer, so a
 * silently-ignored stamp cannot pass by falling through to the location tier.
 */
describe('scan import — the stamp the export emits is the stamp the import reads', () => {
  /** Everything the exporter put on the result, forwarded under its own names. */
  const forward = (sarif: ReturnType<typeof generateSarif>, line: number) => {
    const r = exported(sarif, line);
    return {
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94,
      title: 'SQLi in findUser', cwe_ids: ['CWE-89'],
      annotation: {
        file: r.locations[0].physicalLocation.artifactLocation.uri,
        line: r.locations[0].physicalLocation.region.startLine,
      },
      ...(r.properties as Record<string, unknown>),
      evidence: { request: "POST /u email=' OR 1=1--", response: 'HTTP 200 3 rows', matched_patterns: ['rows'], data: {} },
    };
  };

  it('refuses the sibling that landed on the tested line', async () => {
    const tested = await siblings(SIBLINGS);
    const finding = forward(generateSarif(await parse(tested)), 4);

    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const path = await writeScan(root, { scan_id: 'cxg-fwd', findings: [finding] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    // The location tier alone would have confirmed B here.
    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(s => s.finding.id)).toEqual(['f1']);
  }, 60000);

  it('resolves the claim that moved, not the one now on the tested line', async () => {
    const filler = (n: number) => Array.from({ length: n }, (_, i) => `const filler${i} = ${i};`).join('\n');
    const two = (lead: number) => `${filler(lead)}
/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "C: findAccount concatenates id"
 */
export function findAccount(id: string) { return id; }
`;
    const tested = await siblings(two(28));
    const finding = forward(generateSarif(await parse(tested)), 30);

    const root = await siblings(two(23));
    const model = await parse(root);
    const path = await writeScan(root, { scan_id: 'cxg-fwd', findings: [finding] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    // The location tier alone would have confirmed C at :30.
    expect(r.stale).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
    expect(`${r.confirmed[0].record.file}:${r.confirmed[0].record.line}`).toBe('src/a.ts:25');
  }, 60000);

  it('every exported result that carries a claim key resolves — nothing stamped is unjoinable', async () => {
    // The verb is part of the key digest, so a key stamped from a @confirmed
    // result could never match an exposure record. This asserts the two sides
    // agree about WHICH results are stamped, not just about the field name.
    const root = await siblings(`import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 * @confirmed #sqli on #api [critical] cwe:CWE-89 -- "POST /u returned HTTP 200 and three rows; reproduced twice"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #web to #xss [high] cwe:CWE-79 -- "bio rendered via innerHTML"
 */
export function render(bio: string) { return bio; }
`);
    const model = await parse(root);
    const results = generateSarif(model).runs[0].results;
    const keyed = results.filter(r => (r.properties as Record<string, unknown>).claimKey !== undefined);

    // There is something to check, and the confirmed result is deliberately not in it.
    expect(keyed.length).toBeGreaterThan(0);
    expect(keyed.map(r => r.ruleId)).not.toContain('guardlink/confirmed-exploitable');
    expect(results.some(r => r.ruleId === 'guardlink/confirmed-exploitable')).toBe(true);

    for (const r of keyed) {
      const line = r.locations[0].physicalLocation.region.startLine;
      const path = await writeScan(root, { scan_id: 'cxg-all', findings: [forward(generateSarif(model), line)] });
      const out = importScan(root, model, path, { by: 'cxg', at: NOW });
      expect(out.stale, `result at line ${line} went stale`).toEqual([]);
      expect(out.unmatched, `result at line ${line} went unmatched`).toEqual([]);
      expect(out.confirmed, `result at line ${line} did not resolve`).toHaveLength(1);
      expect(out.confirmed[0].joinedBy).toBe('claim-key');
      expect(out.confirmed[0].record.key).toBe((r.properties as Record<string, unknown>).claimKey);
    }
  }, 60000);
});
