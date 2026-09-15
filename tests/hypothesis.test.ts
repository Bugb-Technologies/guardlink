/**
 * The hypothesis ledger: outcomes with evidence, expiry when the code moves,
 * a ranked queue, scan import, and where the state shows.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, parse as parsePath } from 'node:path';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { parseProject } from '../src/parser/parse-project.js';
import { relationRecords, CLAIM_KEY_SURFACES, CLAIM_KEY_PROPERTY } from '../src/parser/claim-key.js';
import { blockCommentClosers, commentFormAt } from '../src/parser/comment-strip.js';
import {
  HYPOTHESES_FILE, readHypotheses, writeHypotheses, emptyHypotheses,
  classifyHypotheses, attachHypotheses, rankUntested, recordOutcome, importScan, resolveTarget, confirmedLine, writeConfirmedLine, formatImport,
} from '../src/hypothesis/index.js';
import { lintAnnotations } from '../src/gate/index.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { generateSarif } from '../src/analyzer/sarif.js';
import { parseStructure } from '../src/structure/index.js';

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

const tsx = createRequire(import.meta.url).resolve('tsx/cli');
const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
const run = (cwd: string, ...args: string[]) => new Promise<{ code: number; stdout: string; stderr: string }>((res) =>
  execFile(process.execPath, [tsx, cli, ...args], { cwd, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => res({ code: (err as { code?: number } | null)?.code ?? 0, stdout, stderr })));

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
    expect(w).toEqual({ file: 'src/a.ts', line: 5, outcome: 'inserted' });
    const text = await readFile(join(root, 'src', 'a.ts'), 'utf8');
    expect(text.split('\n')[4]).toBe(` * ${line}`);
    const again = await parse(root);
    expect(again.confirmed).toHaveLength(1);
    expect(lintAnnotations(again).filter(v => v.rule === 'confirmed-without-evidence')).toEqual([]);
    // Writing twice does not duplicate, and is not a failure: the claim is in
    // the state that was asked for, reported as where the confirmation already is.
    expect(writeConfirmedLine(root, record, line)).toEqual({ file: 'src/a.ts', line: 5, outcome: 'already-present' });
    expect(await readFile(join(root, 'src', 'a.ts'), 'utf8')).toBe(text);
  });

  it('still throws when the @exposes has moved — already-present did not become a catch-all', async () => {
    // The classification separates one correct outcome from failures; it must not
    // have swallowed the rest. Unreachable from the CLI by design (it parses the
    // model itself and writes descending), so it is pinned on the function.
    const root = await project();
    const model = await parse(root);
    const { record, entry } = recordOutcome(root, model, SQLI, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    const line = confirmedLine(record, entry);
    const moved = { ...record, line: 1 };

    expect(() => writeConfirmedLine(root, moved, line)).toThrow(/does not carry an @exposes any more/);
    expect(await readFile(join(root, 'src', 'a.ts'), 'utf8')).not.toContain('@confirmed');
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

  it('does not call a report unstamped when its stamped finding went stale', async () => {
    // A mixed report: f1 carries A's key and A is gone (stale), f2 carries no key
    // and joins by location. Whether the report was stamped is a fact about the
    // findings, not about the ones that confirmed — reading it off `confirmed`
    // alone announces an unstamped scanner directly above the key it prints.
    const tested = await siblings(SIBLINGS);
    const a = stamp(generateSarif(await parse(tested)), 4);

    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const ev = { request: "POST /u email=' OR 1=1--", response: 'HTTP 200 3 rows', matched_patterns: ['rows'], data: {} };
    const path = await writeScan(root, { scan_id: 'cxg-mixed', findings: [
      { id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94, title: 'SQLi', cwe_ids: ['CWE-89'],
        annotation: { file: a.file, line: a.line }, claim_key: a.claim_key, evidence: ev },
      { id: 'f2', template_id: 'order-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi', cwe_ids: ['CWE-89'],
        annotation: { file: 'src/a.ts', line: 4 }, evidence: ev },
    ] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.stale.map(s => s.finding.id)).toEqual(['f1']);
    expect(r.confirmed.map(c => [c.finding.id, c.joinedBy])).toEqual([['f2', 'location']]);

    const out = formatImport(r);
    // The stale entry prints the key the report carried, so the report was stamped.
    expect(out).toContain(a.claim_key.slice(0, 23));
    expect(out).not.toMatch(/No finding in this report carried a claim key/);
    // The accurate statement is the one scoped to how the confirmations were reached.
    expect(out).toMatch(/1 of 1 findings carried no claim key/);
    expect(out).toMatch(/NOT key-verified: this finding carried no claim key/);
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

  it('a stamp that is not a claim key gets its own state — not unstamped, not stale', async () => {
    // A placeholder, or a same-named field from another tool, landing in a
    // free-form bag we now read. Taking any non-empty string as our stamp sent
    // this finding to `stale` with a definitively wrong cause, destroying a
    // confirmation the location tier would have made. The three situations —
    // no stamp, a key naming no claim, a value that is not a key — have three
    // different right actions and must not collapse into two.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const path = await writeScan(root, { scan_id: 'cxg-bad', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi',
      cwe_ids: ['CWE-89'], annotation: { file: 'src/a.ts', line: 4 },
      properties: { claim_key: 'pending' },
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.malformed.map(m => [m.finding.id, m.stamp.value, m.stamp.field])).toEqual([['f1', 'pending', 'properties.claim_key']]);
    // Its own state: neither of the two it used to be confused with.
    expect(r.stale).toEqual([]);
    expect(r.unmatched).toEqual([]);
    // And never joined: the coarse tiers do not get to confirm on a value we rejected.
    expect(r.confirmed).toEqual([]);
    expect(readHypotheses(root).status).toBe('absent');

    const out = formatImport(r);
    expect(out).toMatch(/1 malformed/);
    expect(out).toMatch(/carried "pending" in properties\.claim_key, which is not a claim key/);
    expect(out).not.toMatch(/no longer in the model/);
  }, 60000);

  it('a junk value under an earlier name does not bury a valid key beside it', async () => {
    // Our own emitted `properties` bag, forwarded wholesale, with another tool's
    // snake_case placeholder added to that free-form bag. `claim_key` sorts ahead
    // of `claimKey`, so validating the first hit refused our own valid key and
    // discarded a confirmation the report had identified precisely.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const emitted = exported(generateSarif(model), 4).properties as Record<string, unknown>;
    const path = await writeScan(root, { scan_id: 'cxg-mix', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi',
      cwe_ids: ['CWE-89'], annotation: { file: 'src/a.ts', line: 4 },
      properties: { ...emitted, claim_key: 'pending' },
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.malformed).toEqual([]);
    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
    expect(r.confirmed[0].record.key).toBe(emitted[CLAIM_KEY_PROPERTY]);

    // The junk is still said out loud — a note, not a refusal.
    const out = formatImport(r);
    expect(out).toMatch(/a valid claim key was used, but 1 other value arrived under a guardlink name/);
    expect(out).toMatch(/f1: "pending" in properties\.claim_key/);
  }, 60000);

  it('resolves to the partialFingerprints key when a report contradicts itself across surfaces', async () => {
    // Surface precedence, pinned rather than asserted in a comment. Before a
    // nested `properties` map was read at all, so a report carrying different
    // keys in the two surfaces resolved to the partialFingerprints one — and
    // widening the reader must not change that.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const a = stamp(generateSarif(model), 4);   // the claim at src/a.ts:4
    const b = stamp(generateSarif(model), 9);   // the claim at src/a.ts:9
    expect(a.claim_key).not.toBe(b.claim_key);

    const path = await writeScan(root, { scan_id: 'cxg-both', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi',
      cwe_ids: ['CWE-89'],
      partialFingerprints: { 'guardlink/claimKey': a.claim_key },
      properties: { claimKey: b.claim_key },
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].record.key).toBe(a.claim_key);
    expect(`${r.confirmed[0].record.file}:${r.confirmed[0].record.line}`).toBe('src/a.ts:4');

    // Deterministic, but not silent: the report named two different claims, so
    // the win came from precedence rather than agreement and says so.
    expect(r.confirmed[0].joinedBy).toBe('claim-key-contested');
    expect(r.confirmed[0].finding.rival_stamps.map(x => [x.value, x.field])).toEqual([[b.claim_key, 'properties.claimKey']]);
    const out = formatImport(r);
    expect(out).toMatch(/Contested/);
    expect(out).toMatch(/CONTESTED — the report carried more than one claim key/);
    expect(out).toContain(b.claim_key!.slice(0, 23));
    // And the ledger keeps it, so a later reader of the entry can tell too.
    expect(readHypotheses(root).ledger!.entries[0].source).toMatchObject({ kind: 'scan', joined_by: 'claim-key-contested' });
  }, 60000);

  it('does not claim an outcome for a contested finding that was never recorded', async () => {
    // The precedence winner names a DELETED claim while the rival names a live
    // one, so the finding goes to `stale` — nothing is recorded, there is no
    // outcome and no write to withhold. The contest is still worth reporting,
    // but not in words that assert a confirmation that never happened.
    const tested = await siblings(SIBLINGS);
    const testedSarif = generateSarif(await parse(tested));
    const dead = stamp(testedSarif, 4).claim_key;   // A — deleted below

    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const live = stamp(generateSarif(model), 4).claim_key;   // B — survived, now on A's line
    expect(dead).not.toBe(live);
    expect(relationRecords(model).map(x => x.key)).not.toContain(dead);

    const path = await writeScan(root, { scan_id: 'cxg-dead', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi', cwe_ids: [],
      partialFingerprints: { 'guardlink/claimKey': dead }, properties: { claimKey: live },
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(x => x.finding.id)).toEqual(['f1']);
    const out = formatImport(r);
    // The contest is reported, and says what actually became of the finding.
    expect(out).toMatch(/Contested\s+a finding that was not recorded/);
    expect(out).toMatch(/Nothing was confirmed for it/);
    // And it must NOT claim an outcome, a CONTESTED label, or a withheld write.
    expect(out).not.toMatch(/The winner above was chosen/);
    expect(out).not.toMatch(/no @confirmed is written to source for it/);
  }, 60000);

  it('names the field a stamp actually arrived in, even when the report uses `location`', async () => {
    // The second level the reader searches is `annotation ?? location`, so a
    // report using `location` was told its bad value sat in `annotation.claim_key`
    // — a field it does not contain. The one message whose purpose is telling a
    // producer what to fix has to name the real path.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const path = await writeScan(root, { scan_id: 'cxg-loc', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi', cwe_ids: ['CWE-89'],
      location: { file: 'src/a.ts', line: 4, claim_key: 'pending' },
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.malformed.map(m => m.stamp.field)).toEqual(['location.claim_key']);
    expect(formatImport(r)).toMatch(/in location\.claim_key/);
    expect(formatImport(r)).not.toMatch(/annotation\.claim_key/);
  }, 60000);

  it('counts one rival key forwarded in two surfaces as one disagreement', async () => {
    // The winner path already treats the same key in two surfaces as agreement;
    // the rivals have to read the same way. Two copies of one rival key were
    // reported as two conflicts, under a header that pluralised as if it were
    // counting findings rather than stamps.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const sarif = generateSarif(model);
    const a = stamp(sarif, 4), b = stamp(sarif, 9);
    const path = await writeScan(root, { scan_id: 'cxg-dupe', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi', cwe_ids: [],
      partialFingerprints: { 'guardlink/claimKey': a.claim_key },
      annotation: {
        file: 'src/a.ts', line: 4,
        partialFingerprints: { 'guardlink/claimKey': b.claim_key },
        properties: { claimKey: b.claim_key },
      },
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].record.key).toBe(a.claim_key);
    // Two raw stamps carry the one rival value; the report must say so once.
    expect(r.confirmed[0].finding.rival_stamps).toHaveLength(2);
    const out = formatImport(r);
    expect(out).toMatch(/Contested {2}a finding carried more than one claim key/);
    expect(out).not.toMatch(/Contested {2}\d+ findings/);
    expect(out.split('\n').filter(l => l.includes('also claimed'))).toHaveLength(1);
    // And that one line names both fields the value arrived in.
    const line = out.split('\n').find(l => l.includes('also claimed'))!;
    expect(line).toContain('annotation.partialFingerprints.guardlink/claimKey');
    expect(line).toContain('annotation.properties.claimKey');
  }, 60000);

  it('treats the same key in both surfaces as agreement, not a conflict', async () => {
    // The ordinary forwarded shape: a consumer copies both emitted surfaces, so
    // the same key arrives twice. Nothing is contested and nothing is withheld.
    const root = await siblings(SIBLINGS);
    const model = await parse(root);
    const a = stamp(generateSarif(model), 4);
    const path = await writeScan(root, { scan_id: 'cxg-agree', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.9, title: 'SQLi', cwe_ids: [],
      partialFingerprints: { 'guardlink/claimKey': a.claim_key }, properties: { claimKey: a.claim_key },
      evidence: { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toHaveLength(1);
    expect(r.confirmed[0].joinedBy).toBe('claim-key');
    expect(r.confirmed[0].finding.rival_stamps).toEqual([]);
    expect(formatImport(r)).not.toMatch(/Contested/);
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
  const EV = { request: "POST /u email=' OR 1=1--", response: 'HTTP 200 3 rows', matched_patterns: ['rows'], data: {} };

  /**
   * Every placement a real consumer can produce, GENERATED from the shared
   * definition rather than listed here: each level the key can sit at (the
   * finding, its `annotation`) × each emitted surface, spread onto that level or
   * left nested under the surface's own name — what copying a SARIF result
   * member wholesale gives you.
   *
   * Listing these by hand is what let the gap survive: the previous matrix
   * wrapped BOTH surfaces under the single literal name `partialFingerprints`,
   * so its (properties, nested) cell exercised a shape no consumer emits and
   * reported coverage it did not have. Deriving the matrix means adding a
   * surface extends it automatically, and a reader missing a container is red.
   */
  const PLACEMENTS: { label: string; place: (r: ReturnType<typeof exported>) => { top: Record<string, unknown>; ann: Record<string, unknown> } }[] = [];
  for (const level of ['finding', 'annotation'] as const) {
    for (const { container } of CLAIM_KEY_SURFACES) {
      const at = (m: Record<string, unknown>) => level === 'finding' ? { top: m, ann: {} } : { top: {}, ann: m };
      const emitted = (r: ReturnType<typeof exported>) => (r as unknown as Record<string, unknown>)[container] as Record<string, unknown>;
      PLACEMENTS.push({ label: `${container} spread onto the ${level}`, place: r => at({ ...emitted(r) }) });
      PLACEMENTS.push({ label: `${container} nested under ${container} on the ${level}`, place: r => at({ [container]: emitted(r) }) });
    }
  }

  /** Forwards what the exporter emitted, naming no field, into one placement. */
  const forward = (sarif: ReturnType<typeof generateSarif>, line: number, place: (typeof PLACEMENTS)[number]['place']) => {
    const r = exported(sarif, line);
    const { top, ann } = place(r);
    return {
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94,
      title: 'SQLi in findUser', cwe_ids: ['CWE-89'],
      annotation: {
        file: r.locations[0].physicalLocation.artifactLocation.uri,
        line: r.locations[0].physicalLocation.region.startLine,
        ...ann,
      },
      ...top,
      evidence: EV,
    };
  };

  const filler = (n: number) => Array.from({ length: n }, (_, i) => `const filler${i} = ${i};`).join('\n');
  /** A at lead+2, C at lead+7 — shift the lead and C lands on A's tested line. */
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

  it('every generated placement refuses the sibling that landed on the tested line', async () => {
    // The location tier alone would confirm B in every one of these.
    const tested = await siblings(SIBLINGS);
    const testedSarif = generateSarif(await parse(tested));

    const got: string[] = [];
    for (const p of PLACEMENTS) {
      const root = await siblings(B_ON_A_LINE);
      const model = await parse(root);
      const path = await writeScan(root, { scan_id: 'cxg-fwd', findings: [forward(testedSarif, 4, p.place)] });
      const r = importScan(root, model, path, { by: 'cxg', at: NOW });
      got.push(`${p.label}: confirmed=${r.confirmed.length} stale=${r.stale.length}`);
    }

    expect(PLACEMENTS.length).toBeGreaterThanOrEqual(8);
    expect(got).toEqual(PLACEMENTS.map(p => `${p.label}: confirmed=0 stale=1`));
  }, 120_000);

  it('every generated placement resolves the claim that moved, not the one now on the tested line', async () => {
    // The location tier alone would confirm C at :30 in every one of these.
    const tested = await siblings(two(28));
    const testedSarif = generateSarif(await parse(tested));

    const got: string[] = [];
    for (const p of PLACEMENTS) {
      const root = await siblings(two(23));
      const model = await parse(root);
      const path = await writeScan(root, { scan_id: 'cxg-fwd', findings: [forward(testedSarif, 30, p.place)] });
      const r = importScan(root, model, path, { by: 'cxg', at: NOW });
      const c = r.confirmed[0];
      got.push(`${p.label}: ${c ? `${c.joinedBy} -> ${c.record.file}:${c.record.line}` : `unresolved (stale=${r.stale.length})`}`);
    }

    expect(got).toEqual(PLACEMENTS.map(p => `${p.label}: claim-key -> src/a.ts:25`));
  }, 120_000);

  it('reads the key under the very name the no-stamp banner tells operators to forward', async () => {
    // Derived from the operator-facing text, not from a list written here: a
    // hand-written list can only contain names someone thought of, and the name
    // the product ADVERTISES is the one that has to work. The banner is an
    // intentional operator-facing text contract; it is produced by running
    // formatImport, and the claim is then settled by running importScan.
    const unstamped = await siblings(SIBLINGS);
    const model0 = await parse(unstamped);
    const bare = await writeScan(unstamped, gap58Scan({ file: 'src/a.ts', line: 4 }));
    const banner = formatImport(importScan(unstamped, model0, bare, { by: 'cxg', at: NOW }));

    const advertised = /forward (\S+) from the SARIF export/.exec(banner)?.[1];
    expect(advertised, `no field name advertised in:\n${banner}`).toBeTruthy();

    // Now carry the key under exactly that name, in the GAP-58 shape where the
    // tiers give the wrong answer, and require the reader to take it.
    const tested = await siblings(SIBLINGS);
    const a = stamp(generateSarif(await parse(tested)), 4);
    const root = await siblings(B_ON_A_LINE);
    const model = await parse(root);
    const path = await writeScan(root, { scan_id: 'cxg-advertised', findings: [{
      id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94, title: 'SQLi', cwe_ids: ['CWE-89'],
      annotation: { file: a.file, line: a.line }, [advertised!]: a.claim_key, evidence: EV,
    }] });
    const r = importScan(root, model, path, { by: 'cxg', at: NOW });

    expect(r.confirmed).toEqual([]);
    expect(r.stale.map(s => s.finding.id)).toEqual(['f1']);
    expect(formatImport(r)).not.toMatch(/No finding in this report carried a claim key/);
  }, 60000);

  it('reads the key under every name and container the --from-scan help advertises', async () => {
    // The generated `--help` text is an operator-facing contract, exactly like the
    // no-stamp banner above, and it is the other place the product advertises what
    // it accepts. The names are taken OUT of it rather than listed here: a list
    // written in a test can only hold names someone thought of, and advertising a
    // spelling the reader refuses is the failure the shared definition exists to
    // make impossible. The claim is settled by running the real reader.
    const help = await new Promise<string>((res) =>
      execFile(process.execPath, [tsx, cli, 'hypothesis', 'confirm', '--help'], { maxBuffer: 64 * 1024 * 1024 },
        (_e, stdout, stderr) => res(stdout + stderr)));
    const flat = help.replace(/\s+/g, ' ');

    const names = /carrying the claim key \(([^—]+)—/.exec(flat)?.[1].split(',').map(s => s.trim()).filter(Boolean) ?? [];
    const containers = /forwarded (\S+) map/.exec(flat)?.[1].split('/') ?? [];
    expect(names.length, `no claim-key names advertised in:\n${help}`).toBeGreaterThan(0);
    expect(containers.length, `no containers advertised in:\n${help}`).toBeGreaterThan(0);

    // Every advertised placement, on the GAP-58 shape where the coarse tiers give
    // the WRONG answer: A was tested, A is gone, and B now sits on A's line. Only
    // a stamp the reader actually takes refuses it.
    const tested = await siblings(SIBLINGS);
    const a = stamp(generateSarif(await parse(tested)), 4);
    const placements: { label: string; stamp: Record<string, unknown> }[] = [];
    for (const name of names) {
      placements.push({ label: `${name} spread onto the finding`, stamp: { [name]: a.claim_key } });
      for (const container of containers) {
        placements.push({ label: `${name} nested under ${container}`, stamp: { [container]: { [name]: a.claim_key } } });
      }
    }

    for (const p of placements) {
      const root = await siblings(B_ON_A_LINE);
      const model = await parse(root);
      const path = await writeScan(root, { scan_id: 'cxg-help', findings: [{
        id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94, title: 'SQLi', cwe_ids: ['CWE-89'],
        annotation: { file: a.file, line: a.line }, ...p.stamp, evidence: EV,
      }] });
      const r = importScan(root, model, path, { by: 'cxg', at: NOW });
      expect(r.stale.map(s => s.finding.id), `${p.label}: the reader did not take the advertised stamp`).toEqual(['f1']);
      expect(r.confirmed, `${p.label}: the reader fell through to a coarse tier`).toEqual([]);
    }
  }, 120_000);

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

    const sarif = generateSarif(model);
    const stampedResults = results.filter(r => (r.properties as Record<string, unknown>)[CLAIM_KEY_PROPERTY] !== undefined);

    // There is something to check, and the confirmed result is deliberately not in it.
    expect(stampedResults.length).toBeGreaterThan(0);
    expect(stampedResults.map(r => r.ruleId)).not.toContain('guardlink/confirmed-exploitable');
    expect(results.some(r => r.ruleId === 'guardlink/confirmed-exploitable')).toBe(true);
    // Every stamped result carries the key on every surface the definition names.
    for (const r of stampedResults) {
      for (const { container, name } of CLAIM_KEY_SURFACES) {
        expect(((r as unknown as Record<string, Record<string, unknown>>)[container])[name]).toBe(
          (r.properties as Record<string, unknown>)[CLAIM_KEY_PROPERTY]);
      }
    }

    for (const r of stampedResults) {
      const line = r.locations[0].physicalLocation.region.startLine;
      for (const p of PLACEMENTS) {
        const path = await writeScan(root, { scan_id: 'cxg-all', findings: [forward(sarif, line, p.place)] });
        const out = importScan(root, model, path, { by: 'cxg', at: NOW });
        const where = `${p.label}, result at line ${line}`;
        expect(out.stale, `${where} went stale`).toEqual([]);
        expect(out.unmatched, `${where} went unmatched`).toEqual([]);
        expect(out.confirmed, `${where} did not resolve`).toHaveLength(1);
        expect(out.confirmed[0].joinedBy, where).toBe('claim-key');
        expect(out.confirmed[0].record.key, where).toBe((r.properties as Record<string, unknown>)[CLAIM_KEY_PROPERTY]);
      }
    }
  }, 120_000);
});

/**
 * An `@confirmed` written into source is not a report line — it is a claim in
 * the repository that this exposure was tested and proven, read by later scans,
 * by reviewers and by `guardlink sarif`, and unlike a ledger entry it never
 * expires. A coarse-joined confirmation may be about a different exposure than
 * the probe tested, so `--write` must not put one there.
 */
describe('hypothesis confirm --from-scan --write', () => {
  const EV = { request: "POST /u email=' OR 1=1--", response: 'HTTP 200 3 rows', matched_patterns: ['rows'], data: {} };
  const ONE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 */
export function findUser(email: string) { return email; }
`;
  const finding = (over: Record<string, unknown>) => ({
    id: 'f1', template_id: 'login-sqli', severity: 'critical', confidence: 0.94,
    title: 'SQLi in findUser', cwe_ids: ['CWE-89'], evidence: EV, ...over,
  });

  const runArgs = async (root: string, ...args: string[]) => {
    return new Promise<{ code: number; out: string }>((res) =>
      execFile(process.execPath, [tsx, cli, ...args], { cwd: root, maxBuffer: 64 * 1024 * 1024 },
        (err, stdout, stderr) => res({ code: (err as { code?: number } | null)?.code ?? 0, out: stdout + stderr })));
  };
  const runCli = (root: string) => runArgs(root, 'hypothesis', 'confirm', '.', '--from-scan', 'scan.json', '--write');

  it('refuses to write a confirmation that was not key-verified, and says how to do it deliberately', async () => {
    const root = await siblings(ONE);
    await writeScan(root, { scan_id: 'cxg-w', findings: [finding({ annotation: { file: 'src/a.ts', line: 4 } })] });
    const run = await runCli(root);

    // It did join — the ledger has it — but nothing was written to the source.
    expect(readHypotheses(root).ledger!.entries[0].source).toMatchObject({ kind: 'scan', joined_by: 'location' });
    expect(await readFile(join(root, 'src', 'a.ts'), 'utf-8')).not.toContain('@confirmed');
    expect(run.out).toMatch(/skipped src\/a\.ts:4 — joined by location, not key-verified/);
    expect(run.out).toMatch(/guardlink hypothesis confirm src\/a\.ts:4 --evidence/);
    expect(run.out).not.toMatch(/wrote src\/a\.ts/);

    // bravos orchestrates this loop and reads the exit code, not stderr. A
    // requested write that put nothing in source must not report success.
    expect(run.code).not.toBe(0);
  }, 120_000);

  it('exits non-zero when a write PARTIALLY landed — one key-verified, one withheld', async () => {
    // The dangerous case is not "nothing was written", it is "half was". If the
    // exit code is 0 here, a run where one confirmation reached source and
    // another did not is indistinguishable from a complete one, and nothing
    // downstream goes looking.
    const MIXED = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #api to #dos [medium] -- "B: parseBody has no size cap"
 */
export function parseBody(body: string) { return body; }
`;
    const root = await siblings(MIXED);
    const a = stamp(generateSarif(await parse(root)), 4);
    await writeScan(root, { scan_id: 'cxg-mixed', findings: [
      finding({ id: 'fA', template_id: 'tA', claim_key: a.claim_key }),
      finding({ id: 'fB', template_id: 'tB', annotation: { file: 'src/a.ts', line: 9 } }),
    ] });
    const run = await runCli(root);

    // The key-verified one landed, and only it. B's @exposes started at line 9
    // and the insertion at line 5 pushed it to 10 — the skip names where it is.
    expect(run.out).toMatch(/wrote src\/a\.ts:5/);
    expect(run.out).toMatch(/skipped src\/a\.ts:10 — joined by location, not key-verified/);
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.confirmed![0]).toMatchObject({ asset: '#api', threat: '#sqli' });

    // Both outcomes are in the ledger — withholding the write never drops one.
    expect(readHypotheses(root).ledger!.entries).toHaveLength(2);

    // And the run still reports that the write it was asked for did not fully happen.
    expect(run.code).not.toBe(0);
  }, 120_000);

  it('writes one @confirmed for two findings carrying the same claim key, and exits 0', async () => {
    // Two cxg templates probing one exposure is the ordinary shape. Both key-join
    // to the same claim and fold into one ledger entry, so writing per finding
    // attempted the same insertion twice and the second was reported as a failure
    // — a run whose source ended up exactly as intended, exiting non-zero.
    const root = await siblings(ONE);
    const a = stamp(generateSarif(await parse(root)), 4);
    await writeScan(root, { scan_id: 'cxg-dup', findings: [
      finding({ id: 'f-union', template_id: 'sqli-union', claim_key: a.claim_key }),
      finding({ id: 'f-boolean', template_id: 'sqli-boolean', claim_key: a.claim_key }),
    ] });
    const run = await runCli(root);

    expect(run.code).toBe(0);
    expect(run.out).not.toMatch(/^ {2}! /m);
    expect(run.out.match(/wrote \S+/g)).toEqual(['wrote src/a.ts:5']);
    // One claim, one write ATTEMPT — not a write plus a redundant report that the
    // claim it just wrote is already confirmed.
    expect(run.out).not.toMatch(/already confirmed/);

    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    expect(src.split('\n').filter(l => l.includes('@confirmed'))).toHaveLength(1);
    expect(await parse(root).then(m => m.confirmed)).toHaveLength(1);

    // One claim, one ledger entry — and the written line carries the evidence the
    // ledger ended up holding, not the superseded first probe's.
    const entries = readHypotheses(root).ledger!.entries;
    expect(entries).toHaveLength(1);
    expect(entries[0].source).toMatchObject({ template_id: 'sqli-boolean' });
    expect(src).toContain('sqli-boolean');
  }, 120_000);

  it('does not report a claim as skipped in the run that wrote it', async () => {
    // The mixed shape during a cxg stamp rollout: one template forwards the claim
    // key, another does not, and both join to the SAME claim. The confirmation is
    // in the source, so that claim was not withheld — and the exit code is the
    // signal bravos reads without ever seeing stderr.
    const root = await siblings(ONE);
    const a = stamp(generateSarif(await parse(root)), 4);
    await writeScan(root, { scan_id: 'cxg-rollout', findings: [
      finding({ id: 'f-stamped', template_id: 'sqli-union', claim_key: a.claim_key }),
      finding({ id: 'f-unstamped', template_id: 'sqli-boolean', annotation: { file: 'src/a.ts', line: 4 } }),
    ] });
    const run = await runCli(root);

    expect(run.out.match(/wrote \S+/g)).toEqual(['wrote src/a.ts:5']);
    expect(run.out).not.toMatch(/skipped/);
    expect(run.code).toBe(0);
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.confirmed![0]).toMatchObject({ asset: '#api', threat: '#sqli' });
  }, 120_000);

  it('offers one by-hand command per withheld CLAIM, not per finding', async () => {
    // Two templates probing one exposure, neither stamped. One claim is withheld,
    // so the operator gets one instruction — and the run still exits non-zero,
    // because that confirmation is not in the source.
    const root = await siblings(ONE);
    await writeScan(root, { scan_id: 'cxg-two-coarse', findings: [
      finding({ id: 'f1', template_id: 't1', annotation: { file: 'src/a.ts', line: 4 } }),
      finding({ id: 'f2', template_id: 't2', annotation: { file: 'src/a.ts', line: 4 } }),
    ] });
    const run = await runCli(root);

    expect(run.out.match(/! skipped \S+/g)).toEqual(['! skipped src/a.ts:4']);
    expect(run.out.match(/guardlink hypothesis confirm \S+/g)).toEqual(['guardlink hypothesis confirm src/a.ts:4']);
    expect(run.code).not.toBe(0);
    expect(await readFile(join(root, 'src', 'a.ts'), 'utf-8')).not.toContain('@confirmed');
  }, 120_000);

  it('re-importing the same report writes nothing more and still exits 0', async () => {
    // The claim key digests the claim's words, so the line the first run inserted
    // does not re-key it: the report joins again and asks for the same write. The
    // confirmation being already there is the state that was asked for.
    const root = await siblings(ONE);
    const a = stamp(generateSarif(await parse(root)), 4);
    await writeScan(root, { scan_id: 'cxg-again', findings: [finding({ claim_key: a.claim_key })] });

    const first = await runCli(root);
    expect(first.code).toBe(0);
    expect(first.out).toMatch(/wrote src\/a\.ts:5/);
    const afterFirst = await readFile(join(root, 'src', 'a.ts'), 'utf-8');

    const second = await runCli(root);
    expect(second.code).toBe(0);
    expect(second.out).toMatch(/already confirmed src\/a\.ts:5/);
    expect(second.out).not.toMatch(/^ {2}! /m);
    expect(second.out).not.toMatch(/wrote src\/a\.ts/);
    expect(await readFile(join(root, 'src', 'a.ts'), 'utf-8')).toBe(afterFirst);
  }, 120_000);

  it('offers AMBIGUOUS candidates at the line they occupy after this run, and each resolves to its own claim', async () => {
    // Same hazard as the withheld block, at its sibling site: the candidate list
    // is a by-hand target, and a key-verified write higher up the same file moves
    // it. With consecutive @exposes the shifted line holds a DIFFERENT claim, and
    // both candidates here are #api → #dos, so only which @exposes the
    // confirmation lands beneath can tell them apart.
    const THREE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 * @exposes #api to #dos [medium] -- "B: parseBody has no size cap"
 * @exposes #api to #dos [medium] -- "C: uploadAvatar has no size cap"
 */
export function login(email: string) { return email; }
`;
    const root = await siblings(THREE);
    const a = stamp(generateSarif(await parse(root)), 4);
    await writeScan(root, { scan_id: 'cxg-ambig', findings: [
      finding({ id: 'fA', template_id: 'tA', claim_key: a.claim_key }),
      // No stamp and no location, so it falls to the asset/threat tier and fits
      // both #dos claims.
      finding({ id: 'fDos', template_id: 'tDos', cwe_ids: [], asset: '#api', threat: '#dos' }),
    ] });
    const run = await runCli(root);

    // A's @confirmed took line 5, so B moved 5→6 and C moved 6→7. Pre-write
    // numbering would have offered 5 and 6 — and 6 is B, not C.
    expect(run.out).toMatch(/wrote src\/a\.ts:5/);
    const offered = [...run.out.matchAll(/guardlink hypothesis confirm (\S+) --evidence/g)].map(m => m[1]);
    expect(offered.sort()).toEqual(['src/a.ts:6', 'src/a.ts:7']);
    // Ambiguity needs a human, so the run says so.
    expect(run.code).not.toBe(0);

    // Run the command we printed for the LAST candidate and require the
    // confirmation to attach to C, the claim that actually stands there.
    const byHand = await runArgs(root, 'hypothesis', 'confirm', 'src/a.ts:7', '.', '--evidence', CONFIRM, '--by', 'human:test', '--write');
    expect(byHand.code).toBe(0);

    const src = (await readFile(join(root, 'src', 'a.ts'), 'utf-8')).split('\n');
    const cAt = src.findIndex(l => l.includes('"C: uploadAvatar has no size cap"'));
    expect(src[cAt + 1]).toMatch(/@confirmed #dos on #api/);
    // B did not get one — the stale line would have hit it.
    const bAt = src.findIndex(l => l.includes('"B: parseBody has no size cap"'));
    expect(src[bAt + 1]).not.toMatch(/@confirmed/);
  }, 120_000);

  it('hands out a by-hand target that survives its own writes, and it resolves to the withheld claim', async () => {
    // The by-hand command is the dangerous output: the operator runs it AFTER
    // the run, and the run moved the line. With consecutive @exposes the
    // pre-write number names a DIFFERENT claim, so following our own
    // instructions records the confirmation against an exposure the probe never
    // tested — GAP-58 delivered through a human's fingers.
    const THREE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 * @exposes #api to #dos [medium] -- "B: parseBody has no size cap"
 * @exposes #web to #xss [high] cwe:CWE-79 -- "C: bio rendered via innerHTML"
 */
export function login(email: string) { return email; }
`;
    const root = await siblings(THREE);
    const a = stamp(generateSarif(await parse(root)), 4);
    await writeScan(root, { scan_id: 'cxg-shift', findings: [
      finding({ id: 'fA', template_id: 'tA', claim_key: a.claim_key }),
      finding({ id: 'fB', template_id: 'tB', annotation: { file: 'src/a.ts', line: 5 } }),
      finding({ id: 'fC', template_id: 'tC', annotation: { file: 'src/a.ts', line: 6 } }),
    ] });
    const run = await runCli(root);

    // A's @confirmed took line 5, so B moved 5→6 and C moved 6→7. Pre-write
    // numbering would have offered 5 and 6 — and 6 is B, not C.
    expect(run.out).toMatch(/wrote src\/a\.ts:5/);
    const offered = [...run.out.matchAll(/guardlink hypothesis confirm (\S+) --evidence/g)].map(m => m[1]);
    expect(offered.sort()).toEqual(['src/a.ts:6', 'src/a.ts:7']);

    // The claim actually standing at each offered line is the withheld claim it
    // was offered for — asserted by running the command we printed for the last
    // one and seeing which @exposes the confirmation attaches to.
    const byHand = await runArgs(root, 'hypothesis', 'confirm', 'src/a.ts:7', '.', '--evidence', CONFIRM, '--by', 'human:test', '--write');
    expect(byHand.code).toBe(0);

    const after = await parse(root);
    const exposureAt = new Map(after.exposures.map(e => [e.location.line, e]));
    for (const c of after.confirmed!) {
      const above = exposureAt.get(c.location.line - 1);
      expect(above, `@confirmed at :${c.location.line} does not sit beneath an @exposes`).toBeDefined();
      expect({ asset: above!.asset, threat: above!.threat }).toEqual({ asset: c.asset, threat: c.threat });
    }
    // C got the confirmation the operator was told to record. B, the claim the
    // stale line would have hit, got none.
    expect(after.confirmed!.map(c => `${c.asset}/${c.threat}`).sort()).toEqual(['#api/#sqli', '#web/#xss']);
  }, 120_000);

  it('writes a key-verified confirmation, and the line says how it was established', async () => {
    const root = await siblings(ONE);
    const a = stamp(generateSarif(await parse(root)), 4);
    await writeScan(root, { scan_id: 'cxg-w', findings: [finding({ annotation: { file: 'src/a.ts', line: 4 }, claim_key: a.claim_key })] });
    const run = await runCli(root);

    expect(run.code).toBe(0);
    expect(run.out).toMatch(/wrote src\/a\.ts:5/);
    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    const line = src.split('\n').find(l => l.includes('@confirmed'))!;
    expect(line).toMatch(/key-verified: the scan stamped this claim's own claim key/);

    // It is a real annotation, not just text: it parses back as a @confirmed on
    // the same pair, and it satisfies the gate's evidence bar.
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.confirmed![0]).toMatchObject({ asset: '#api', threat: '#sqli' });
    expect(lintAnnotations(after).filter(v => v.rule === 'confirmed-without-evidence')).toEqual([]);
  }, 120_000);

  it('leaves the manual path rendering unchanged — human evidence, no join to qualify', async () => {
    const root = await siblings(ONE);
    const model = await parse(root);
    const { record, entry } = recordOutcome(root, model, 'src/a.ts:4', 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    const line = confirmedLine(record, entry);

    expect(line).toContain(CONFIRM);
    expect(line).not.toMatch(/key-verified/);
  }, 60000);

  it('attaches each @confirmed to its own @exposes when several are written to one file', async () => {
    // Three consecutive @exposes, confirming the first and the LAST. Each write
    // splices a line and every record.line came from the pre-write model, so an
    // ascending pass shifts the second target down by one — onto the middle
    // claim's @exposes, where every guard passes and the confirmation lands
    // against a claim the probe never tested.
    const THREE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 * @exposes #api to #dos [medium] -- "B: parseBody has no size cap"
 * @exposes #web to #xss [high] cwe:CWE-79 -- "C: bio rendered via innerHTML"
 */
export function login(email: string) { return email; }
`;
    const root = await siblings(THREE);
    const model = await parse(root);
    const sarif = generateSarif(model);
    await writeScan(root, { scan_id: 'cxg-multi', findings: [
      finding({ id: 'fA', template_id: 'tA', claim_key: stamp(sarif, 4).claim_key }),
      finding({ id: 'fC', template_id: 'tC', claim_key: stamp(sarif, 6).claim_key }),
    ] });
    const run = await runCli(root);
    expect(run.code).toBe(0);
    expect(run.out).not.toMatch(/!/);
    // The reported lines are where the confirmations ended up, in reading order —
    // writing descending means an earlier write gets pushed down by a later one.
    expect(run.out.match(/wrote \S+/g)).toEqual(['wrote src/a.ts:5', 'wrote src/a.ts:8']);

    // The pairing is what matters: re-parse and require every @confirmed to sit
    // directly beneath an @exposes naming the SAME asset and threat.
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(2);
    const exposureAt = new Map(after.exposures.map(e => [e.location.line, e]));
    for (const c of after.confirmed!) {
      const above = exposureAt.get(c.location.line - 1);
      expect(above, `@confirmed at :${c.location.line} does not sit beneath an @exposes`).toBeDefined();
      expect({ asset: above!.asset, threat: above!.threat }).toEqual({ asset: c.asset, threat: c.threat });
    }
    // Both intended claims got one, and the untested middle claim got none.
    expect(after.confirmed!.map(c => `${c.asset}/${c.threat}`).sort()).toEqual(['#api/#sqli', '#web/#xss']);
  }, 120_000);

  it('keeps the key-verified marker when the evidence reaches its cap', async () => {
    // scanEvidence caps each field at 240, so five fields plus the joins exceed
    // 1000 characters of ordinary scan data. Collapsing the marker together with
    // the evidence put it inside that cap and dropped it, leaving a key-verified
    // line that read exactly like an unverified one.
    const root = await siblings(ONE);
    const key = stamp(generateSarif(await parse(root)), 4).claim_key;
    const big = 'x'.repeat(240);
    await writeScan(root, { scan_id: 'scan12chars', findings: [finding({
      id: 'f1', template_id: 'y'.repeat(40), title: 'z'.repeat(200), claim_key: key,
      evidence: { request: big, response: big, matched_patterns: [big], data: {} },
    })] });
    const run = await runCli(root);

    expect(run.code).toBe(0);
    expect(readHypotheses(root).ledger!.entries[0].evidence.length).toBeGreaterThan(1000);
    const written = (await readFile(join(root, 'src', 'a.ts'), 'utf-8')).split('\n').filter(l => l.includes('@confirmed'));
    expect(written).toHaveLength(1);
    expect(written[0]).toMatch(/key-verified: the scan stamped this claim's own claim key/);

    // Still one annotation, and it still parses back as the confirmation.
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.confirmed![0]).toMatchObject({ asset: '#api', threat: '#sqli' });
  }, 120_000);

  it('withholds the write for a contested key while an uncontested one in the same run is written', async () => {
    // Identity in doubt must not be spliced into source as "key-verified": that
    // label would describe a stronger verification than was actually performed,
    // in the highest-consequence place this code writes.
    const TWO = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: email param"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #web to #xss [high] cwe:CWE-79 -- "B: bio via innerHTML"
 */
export function render(bio: string) { return bio; }
`;
    const root = await siblings(TWO);
    const sarif = generateSarif(await parse(root));
    const a = stamp(sarif, 4), b = stamp(sarif, 9);
    await writeScan(root, { scan_id: 'cxg-mix', findings: [
      // Contested: two well-formed keys naming two live claims.
      { ...finding({ id: 'fContested', template_id: 'tC' }),
        partialFingerprints: { 'guardlink/claimKey': a.claim_key }, properties: { claimKey: b.claim_key } },
      // Uncontested, a different claim — must still be written in the same run.
      finding({ id: 'fClean', template_id: 'tK', claim_key: b.claim_key }),
    ] });
    const run = await runCli(root);

    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    const written = src.split('\n').filter(l => l.includes('@confirmed'));
    expect(written).toHaveLength(1);
    // The one that was written is the uncontested claim, and it is the only
    // line carrying the key-verified marker.
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.confirmed![0]).toMatchObject({ asset: '#web', threat: '#xss' });
    expect(written[0]).toMatch(/key-verified/);

    expect(run.out).toMatch(/skipped src\/a\.ts:4 — the report carried more than one claim key naming different claims/);
    expect(run.out).toMatch(/guardlink hypothesis confirm src\/a\.ts:4 --evidence/);
    // Both outcomes are still in the ledger; only the source write was withheld.
    expect(readHypotheses(root).ledger!.entries).toHaveLength(2);
  }, 120_000);

  it('writes both confirmations when two same-asset, same-threat siblings share a doc-block', async () => {
    // The GAP-58 population itself: two @exposes identical but for their
    // description. A written @confirmed carries only (threat, asset), so the
    // duplicate guard could not tell the two apart and refused one of the pair —
    // whichever order the writes went in. Unwritable by any supported path,
    // including the by-hand command the CLI offers.
    const SIB = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: email param"
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "B: name param"
 */
export function login(email: string) { return email; }
`;
    const root = await siblings(SIB);
    const sarif = generateSarif(await parse(root));
    await writeScan(root, { scan_id: 'cxg-sib', findings: [
      finding({ id: 'fA', template_id: 'tplA', claim_key: stamp(sarif, 4).claim_key }),
      finding({ id: 'fB', template_id: 'tplB', claim_key: stamp(sarif, 5).claim_key }),
    ] });
    const run = await runCli(root);

    expect(run.code).toBe(0);
    expect(run.out).not.toMatch(/already carries/);

    // Both written, and each directly beneath ITS OWN @exposes. The pair cannot
    // tell them apart, so the evidence's template id is what identifies each.
    const lines = (await readFile(join(root, 'src', 'a.ts'), 'utf-8')).split('\n');
    const at = (needle: string) => lines.findIndex(l => l.includes(needle));
    expect(lines.filter(l => l.includes('@confirmed'))).toHaveLength(2);
    expect(lines[at('"A: email param"') + 1]).toMatch(/@confirmed .*tplA/);
    expect(lines[at('"B: name param"') + 1]).toMatch(/@confirmed .*tplB/);

    const after = await parse(root);
    expect(after.exposures).toHaveLength(2);
    expect(after.confirmed).toHaveLength(2);
  }, 120_000);

  it('breaks a block-comment closer from the report so the host file still parses', async () => {
    // Sanitisation must cover the HOST grammar too. A probe echoing CSS or JS
    // returns the sequence that ends a TypeScript doc-block; spliced verbatim it
    // terminated the comment and put report-controlled text in code position.
    // The re-parse guard cannot see this — it reads the bare annotation, outside
    // the comment it is about to land in — so assert on the STRUCTURE of the
    // host file, not on our annotation re-reading.
    const root = await siblings(ONE);
    const key = stamp(generateSarif(await parse(root)), 4).claim_key;
    const CLOSER = '*' + '/';
    await writeScan(root, { scan_id: 'cxg-1', findings: [finding({
      title: `t ${CLOSER} in the title`, claim_key: key,
      evidence: { request: 'r', response: `HTTP 200 <style>a{}</style> ${CLOSER} x`, matched_patterns: [`m ${CLOSER} p`], data: {} },
    })] });
    const run = await runCli(root);
    expect(run.code).toBe(0);

    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    const confirmedAt = src.split('\n').findIndex(l => l.includes('@confirmed')) + 1;

    // The blind spot the re-parse guard has: ask the structural parser what the
    // host file means, not whether our line re-reads. A doc-block terminated
    // early no longer documents the declaration below it, so the annotation's
    // anchor loses the symbol — that is the difference this asserts.
    const st = await parseStructure(join(root, 'src', 'a.ts'), src);
    expect(st.language).toBe('typescript');
    expect(st.anchorForLine(confirmedAt)).toMatchObject({ symbol: 'findUser' });
    st.dispose();

    // The closer is gone but the report's text is still legible, and the
    // annotation still reads back as one confirmation.
    const written = src.split('\n').filter(l => l.includes('@confirmed'));
    expect(written).toHaveLength(1);
    expect(written[0]).not.toContain(CLOSER);
    expect(written[0]).toContain('<style>a{}</style>');
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.exposures).toHaveLength(1);
  }, 120_000);

  it('inserts under an opening-line @exposes without repeating its opener', async () => {
    // No scan-controlled text is involved: an ordinary `/** @exposes …` opening
    // line is enough. The prefix used to be copied off that line, so the inserted
    // @confirmed carried `/** ` — and Rust NESTS, so the block's own ` */` closed
    // only the inner comment and everything below ran on inside the outer one.
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rust-open-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'lib.rs'),
      `/** @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into the query"\n * more context\n */\npub fn find_user(email: &str) -> &str { email }\n`);

    const model = await parse(root);
    expect(model.exposures, 'the opening-line annotation should be in the model').toHaveLength(1);
    await writeScan(root, { scan_id: 'cxg-rust-open', findings: [finding({
      claim_key: stamp(generateSarif(model), 1).claim_key,
      evidence: { request: 'r', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} },
    })] });
    const run = await runCli(root);
    expect(run.code).toBe(0);

    const after = (await readFile(join(root, 'src', 'lib.rs'), 'utf-8')).split('\n');
    const written = after.filter(l => l.includes('@confirmed'));
    expect(written).toHaveLength(1);
    // A continuation of the comment, not a second one.
    expect(written[0]).not.toContain('/*');
    expect(written[0].trimStart().startsWith('*')).toBe(true);

    // The block still terminates where it did — one closer line, and the
    // declaration is still below it.
    expect(after.filter(l => l.trim() === '*/')).toHaveLength(1);
    expect(after.findIndex(l => l.startsWith('pub fn find_user')))
      .toBeGreaterThan(after.findIndex(l => l.trim() === '*/'));

    // And the host file still means what it did: an unterminated comment would
    // swallow the declaration and this comes back null.
    const st = await parseStructure(join(root, 'src', 'lib.rs'), after.join('\n'));
    expect(st.language).toBe('rust');
    expect(st.symbolNamed('find_user')).toMatchObject({ scope: 'symbol' });
    st.dispose();

    // The annotation is still readable, so the confirmation is not lost to the model.
    const reparsed = await parse(root);
    expect(reparsed.confirmed).toHaveLength(1);
    expect(reparsed.exposures).toHaveLength(1);
  }, 120_000);

  it('breaks a block-comment OPENER too, so a nesting host is not left inside a comment', async () => {
    // The other end of the same hole. Rust NESTS block comments: an injected `/*`
    // opens a nested comment, the doc-block's own `*/` closes only that nested
    // level, and the outer comment runs on past the declaration it documents —
    // which, with everything below it, silently leaves the compile. Breaking the
    // closer does nothing about this, and our re-parse is blind to it exactly as
    // it was to the closer, so assert on the STRUCTURE of the host file.
    const OPENER = '/' + '*';
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rust-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'lib.rs'),
      `/**\n * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into the query"\n */\npub fn find_user(email: &str) -> &str { email }\n`);

    const model = await parse(root);
    expect(model.exposures, 'the .rs annotation should be in the model').toHaveLength(1);
    await writeScan(root, { scan_id: 'cxg-rust', findings: [finding({
      claim_key: stamp(generateSarif(model), 2).claim_key,
      evidence: { request: 'r', response: `HTTP 200 ${OPENER} echoed source`, matched_patterns: [], data: {} },
    })] });
    const run = await runCli(root);
    expect(run.code).toBe(0);

    const src = await readFile(join(root, 'src', 'lib.rs'), 'utf-8');
    const written = src.split('\n').filter(l => l.includes('@confirmed'));
    expect(written).toHaveLength(1);
    expect(written[0]).not.toContain(OPENER);
    // Broken, not dropped — the reader still sees what the report said.
    expect(written[0]).toContain('echoed source');

    // The doc-block still ends where it ended, so what follows it is still a
    // declaration and not comment text: ask the structural parser for the symbol.
    // An unterminated comment swallows it and this comes back null.
    const st = await parseStructure(join(root, 'src', 'lib.rs'), src);
    expect(st.language).toBe('rust');
    expect(st.symbolNamed('find_user')).toMatchObject({ scope: 'symbol', start_line: 5 });
    st.dispose();

    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.exposures).toHaveLength(1);
  }, 120_000);

  it('breaks the closer from the SOURCE form, for an extension the table does not list', async () => {
    // The derivation pin. `commentFormAt` reads the form off the source: this
    // annotation is a ` * ` continuation, so it looks back, finds the `/*` that
    // opened the block, and returns that form's closer.
    //
    // `.proto` is what makes this test able to fail. The extension table has no
    // entry for it, so `blockCommentClosers('.proto')` is empty and `hostSafe`
    // contributes nothing — the closer can ONLY be broken by the form derived
    // from the line. Bypass `commentFormAt` and the sequence goes in verbatim
    // and ends the comment early. `.sql` cannot pin this: the table answers
    // `*\u002f` for it too, so both routes agree and neither is isolated.
    //
    // Driven through importScan/confirmedLine/writeConfirmedLine rather than the
    // CLI because the CLI parses with DEFAULT_INCLUDE, which does not reach
    // `.proto`; these are the same functions the CLI calls.
    const CLOSER = '*' + '/';
    const root = await mkdtemp(join(tmpdir(), 'guardlink-proto-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'q.proto'), `/*\n * @exposes #api to #sqli [critical] cwe:CWE-89 -- "id concatenated into the predicate"\n ${CLOSER}\nmessage Lookup { int64 id = 1; }\n`);
    const include = ['**/*.ts', '**/*.proto'];
    const model = (await parseProject({ root, project: 'h', include })).model;
    const claim = model.exposures.find(e => e.location.file === 'q.proto');
    expect(claim, 'the .proto annotation should be in the model').toBeDefined();
    expect(blockCommentClosers('q.proto'), 'the table must not answer for .proto, or this pins nothing').toEqual([]);

    const key = stamp(generateSarif(model), claim!.location.line).claim_key;
    await writeScan(root, { scan_id: 'cxg-proto', findings: [finding({
      claim_key: key, evidence: { request: 'r', response: `HTTP 200 <style>a{}</style> ${CLOSER} x`, matched_patterns: [], data: {} },
    })] });
    const r = importScan(root, model, join(root, 'scan.json'), { by: 'cxg', at: NOW });
    expect(r.confirmed).toHaveLength(1);
    writeConfirmedLine(root, r.confirmed[0].record, confirmedLine(r.confirmed[0].record, r.confirmed[0].entry));

    const src = await readFile(join(root, 'q.proto'), 'utf-8');
    const written = src.split('\n').filter(l => l.includes('@confirmed'));
    expect(written).toHaveLength(1);
    expect(written[0]).not.toContain(CLOSER);
    // The block comment still ends where it did, so the message below it is
    // still a message: exactly one closer line, and the schema is outside it.
    expect(src.split('\n').filter(l => l.trim() === CLOSER)).toHaveLength(1);
    expect(src.split('\n').indexOf('message Lookup { int64 id = 1; }')).toBeGreaterThan(
      src.split('\n').findIndex(l => l.trim() === CLOSER));
    // And the annotation still reads back as one confirmation.
    const after = (await parseProject({ root, project: 'h', include })).model;
    expect(after.confirmed).toHaveLength(1);
    expect(after.exposures).toHaveLength(1);
  }, 120_000);

  it('falls back to the extension when the source line settles no form', async () => {
    // The fallback pin, the other route through `commentFormAt`. This annotation
    // is a ` * ` continuation with NO opener above it anywhere, so the line
    // settles nothing and no block opened it — the only thing left to go on is
    // the file's extension, and `.ts` answers with the C-family closer.
    const CLOSER = '*' + '/';
    const root = await siblings(` * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email param"\nexport function findUser(email: string) { return email; }\n`);
    const model = await parse(root);
    expect(model.exposures).toHaveLength(1);
    expect(commentFormAt([' * @exposes x'], 0, 'src/a.ts').closers, 'no opener above, so this must come from the extension').toEqual([CLOSER]);

    await writeScan(root, { scan_id: 'cxg-fallback', findings: [finding({
      claim_key: stamp(generateSarif(model), 1).claim_key,
      evidence: { request: 'r', response: `HTTP 200 <style>a{}</style> ${CLOSER} x`, matched_patterns: [], data: {} },
    })] });
    const run = await runCli(root);
    expect(run.code).toBe(0);

    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    const written = src.split('\n').filter(l => l.includes('@confirmed'));
    expect(written).toHaveLength(1);
    expect(written[0]).not.toContain(CLOSER);
    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
  }, 120_000);

  it('collapses a line separator the report smuggled in, so a line-comment host still parses', async () => {
    // A `//` host has no block closer to break, so `hostSafe` adds nothing and
    // the annotation re-parse — which reads the bare line outside its comment —
    // sees nothing wrong. But ECMAScript ends a `//` comment at U+2028, so a
    // single one between two non-whitespace characters left the rest of the
    // description in CODE position. `\\s{2,}` never caught it: a lone separator
    // matches nothing, and U+0085 is not in `\\s` at all.
    const SEP = String.fromCharCode(0x2028);
    const LINEC = `import x from 'x';

// @exposes #api to #sqli [critical] cwe:CWE-89 -- "email param"
export function findUser(email: string) { return email; }
`;
    const root = await siblings(LINEC);
    const before = await parse(root);
    expect(before.exposures).toHaveLength(1);
    await writeScan(root, { scan_id: 'cxg-sep', findings: [finding({
      claim_key: stamp(generateSarif(before), 3).claim_key,
      evidence: { request: 'r', response: `HTTP200${SEP}const pwned=1;`, matched_patterns: [], data: {} },
    })] });
    const run = await runCli(root);
    expect(run.code).toBe(0);

    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    expect(src).not.toContain(SEP);

    // The host grammar is what this breaks, so ask the structural parser. Left
    // intact, the separator ended the comment and `const pwned=1;` became a real
    // declaration — the anchor resolved to `pwned` instead of `findUser`.
    const confirmedAt = src.split('\n').findIndex(l => l.includes('@confirmed')) + 1;
    const st = await parseStructure(join(root, 'src', 'a.ts'), src);
    expect(st.language).toBe('typescript');
    expect(st.anchorForLine(confirmedAt)).toMatchObject({ symbol: 'findUser' });
    st.dispose();

    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.exposures).toHaveLength(1);
  }, 120_000);

  it('reproduces the terminator when the @exposes closes its own comment', async () => {
    // A self-closing single-line comment — a form stripCommentPrefix accepts.
    // The inserted line inherits the opener from it, so without reproducing the
    // terminator the file is left inside an unterminated comment and everything
    // below silently leaves the compile.
    const CLOSER = '*' + '/';
    const SELF = `import x from 'x';

/** @exposes #api to #sqli [critical] cwe:CWE-89 -- "findUser concatenates email" ${CLOSER}
export function findUser(email: string) { return email; }
`;
    const root = await siblings(SELF);
    const before = await parse(root);
    expect(before.exposures).toHaveLength(1);
    await writeScan(root, { scan_id: 'cxg-self', findings: [finding({ claim_key: stamp(generateSarif(before), 3).claim_key })] });
    const run = await runCli(root);
    expect(run.code).toBe(0);

    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    const confirmedAt = src.split('\n').findIndex(l => l.includes('@confirmed')) + 1;

    // The host file must still be the language it claims to be: ask the
    // structural parser, which is what an unterminated comment actually breaks.
    // The annotation re-parse reads the bare line and is blind to this.
    const st = await parseStructure(join(root, 'src', 'a.ts'), src);
    expect(st.language).toBe('typescript');
    expect(st.anchorForLine(confirmedAt)).toMatchObject({ symbol: 'findUser' });
    st.dispose();

    const after = await parse(root);
    expect(after.confirmed).toHaveLength(1);
    expect(after.exposures).toHaveLength(1);
  }, 120_000);
});

/**
 * External (`.gal`) mode stores annotations as bare lines with no host-language
 * comment prefix, so a guard that reads each line through `stripCommentPrefix`
 * sees null on the first one and stops before comparing anything.
 */
describe('writing an @confirmed into a .gal file', () => {
  const GAL = '.guardlink/annotations/src/a.ts.gal';
  const galProject = async (galBody: string) => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-gal-'));
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, GAL), galBody);
    await writeFile(join(root, 'src', 'a.ts'), 'export function findUser(email: string) { return email; }\n');
    return root;
  };

  it('reports a claim that already carries its @confirmed rather than appending a second', async () => {
    const root = await galProject(`@source file:src/a.ts line:1\n@exposes #api to #sqli [critical] cwe:CWE-89 -- "findUser concatenates email"\n`);
    const model = await parse(root);
    const target = `${GAL}:2`;
    const first = recordOutcome(root, model, target, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    writeConfirmedLine(root, first.record, confirmedLine(first.record, first.entry));

    // The claim now carries its confirmation; asking again must not append a
    // second. Every repeat run used to add another copy.
    const again = recordOutcome(root, await parse(root), target, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    expect(writeConfirmedLine(root, again.record, confirmedLine(again.record, again.entry)))
      .toEqual({ file: GAL, line: 3, outcome: 'already-present' });
    expect((await readFile(join(root, GAL), 'utf-8')).split('\n').filter(l => l.includes('@confirmed'))).toHaveLength(1);
  }, 120_000);

  it('still permits a different claim below it, and stops at the next @source', async () => {
    // The bound is semantic in this mode too: the next @exposes owns what follows,
    // and a @source starts a new anchoring block describing another location.
    const root = await galProject(`@source file:src/a.ts line:1\n@exposes #api to #sqli [critical] cwe:CWE-89 -- "A: email param"\n@exposes #api to #sqli [critical] cwe:CWE-89 -- "B: name param"\n@source file:src/b.ts line:1\n@exposes #api to #sqli [critical] cwe:CWE-89 -- "C: other file"\n`);
    await writeFile(join(root, 'src', 'b.ts'), 'export function findOrder(id: string) { return id; }\n');

    // Descending, as the CLI applies them, so an insertion cannot shift a target.
    for (const line of [5, 3, 2]) {
      const o = recordOutcome(root, await parse(root), `${GAL}:${line}`, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
      writeConfirmedLine(root, o.record, confirmedLine(o.record, o.entry));
    }
    const gal = (await readFile(join(root, GAL), 'utf-8')).split('\n');
    expect(gal.filter(l => l.includes('@confirmed'))).toHaveLength(3);
    // Each confirmation sits directly beneath the claim it belongs to.
    for (const marker of ['"A: email param"', '"B: name param"', '"C: other file"']) {
      expect(gal[gal.findIndex(l => l.includes(marker)) + 1]).toMatch(/@confirmed #sqli on #api/);
    }
  }, 120_000);
});

/**
 * Every value in a scan-derived `@confirmed` description comes from an external
 * report, and the line is spliced into someone's source in the syntax their
 * threat model is parsed from. A newline in any of those values ends our line
 * and puts report-controlled text on the next one.
 */
describe('writing an @confirmed built from a scan report', () => {
  const ONE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 */
export function findUser(email: string) { return email; }
`;

  it('neutralises newlines in every scan-controlled field, and writes one parseable annotation', async () => {
    const root = await siblings(ONE);
    const before = await parse(root);
    const key = stamp(generateSarif(before), 4).claim_key;

    // A newline in each scan-controlled field at once, each trying to open a
    // second annotation line. Covering them together means a field that skips
    // the treatment shows up here rather than being found later.
    const BREAK = '\n * @exposes #api to #sqli [critical] -- "forged"';
    const path = await writeScan(root, { scan_id: `scan${BREAK}`, findings: [{
      id: 'f1', template_id: `login-sqli${BREAK}`, severity: 'critical', confidence: 0.9,
      title: `SQLi${BREAK}`, cwe_ids: ['CWE-89'],
      annotation: { file: 'src/a.ts', line: 4 }, claim_key: key,
      evidence: { request: `POST /u${BREAK}`, response: `HTTP 200${BREAK}`, matched_patterns: [`rows${BREAK}`], data: {} },
    }] });
    const r = importScan(root, before, path, { by: 'cxg', at: NOW });
    expect(r.confirmed).toHaveLength(1);

    const w = writeConfirmedLine(root, r.confirmed[0].record, confirmedLine(r.confirmed[0].record, r.confirmed[0].entry));
    expect(w.line).toBe(5);

    const src = await readFile(join(root, 'src', 'a.ts'), 'utf-8');
    // Exactly one line gained, and it is the @confirmed — no stray line below it.
    expect(src.split('\n')).toHaveLength(ONE.split('\n').length + 1);
    expect(src.split('\n').filter(l => l.includes('@confirmed'))).toHaveLength(1);

    // The file still parses to the one exposure and the one confirmation, and
    // nothing forged an extra @exposes.
    const after = await parse(root);
    expect(after.exposures).toHaveLength(1);
    expect(after.confirmed).toHaveLength(1);
    expect(after.confirmed![0]).toMatchObject({ asset: '#api', threat: '#sqli' });
    expect(after.confirmed![0].description).not.toMatch(/\n/);
  }, 120_000);

  it('refuses to write a line that would not parse back as one @confirmed', async () => {
    // The structural backstop, independent of how the description was built:
    // no caller can hand this function a line that source would read as
    // something other than what it thought it wrote.
    const root = await siblings(ONE);
    const model = await parse(root);
    const record = resolveTarget(model, 'src/a.ts:4');

    expect(() => writeConfirmedLine(root, record, '@confirmed #sqli on #api -- "ends here\n * @exposes #api to #sqli -- "forged"'))
      .toThrow(/does not parse back as one @confirmed/);
    expect(() => writeConfirmedLine(root, record, 'not an annotation at all')).toThrow(/does not parse back as one @confirmed/);
    expect(await readFile(join(root, 'src', 'a.ts'), 'utf-8')).not.toContain('@confirmed');
  }, 60000);
});


// ─── GAP-94 / GAP-95: one queue, bounded the same way, addressable by key ────

/**
 * Five untested claims, two of which share (asset, threat, file) — the tier a
 * consumer would have to join on without a key. They differ only by description
 * and line, so a coarse positional join cannot tell them apart and a claim key
 * can. That is the same shape GAP-58 proved unsafe, here as the corpus the key
 * test runs against rather than as a scan import.
 */
const QUEUE_CORPUS = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: findUser concatenates email"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "B: findOrder concatenates id"
 */
export function findOrder(id: string) { return id; }

/**
 * @exposes #web to #xss [high] cwe:CWE-79 -- "profile.bio rendered via innerHTML in render()"
 */
export function render(bio: string) { return bio; }

/**
 * @exposes #api to #dos [medium] -- "parseBody() has no size cap"
 */
export function parseBody(body: string) { return body; }

/**
 * @exposes #web to #dos [medium] -- "the render loop is unbounded"
 */
export function loop(n: number) { return n; }
`;
const CORPUS_SIZE = 5;

describe('the queue is one queue, whichever renderer prints it', () => {
  /** How many entries each renderer actually printed — counted from its own rows, never from a header. */
  async function counts(root: string, n: number): Promise<{ json: number; table: number; intake: number }> {
    const [json, table, intake] = await Promise.all([
      run(root, 'hypothesis', 'next', '.', '-n', String(n), '--json'),
      run(root, 'hypothesis', 'next', '.', '-n', String(n)),
      run(root, 'hypothesis', 'next', '.', '-n', String(n), '--intake'),
    ]);
    for (const r of [json, table, intake]) expect(r.code).toBe(0);
    const rows = (s: string, re: RegExp) => s.split('\n').filter(l => re.test(l)).length;
    return {
      json: (JSON.parse(json.stdout) as { queue: unknown[] }).queue.length,
      table: rows(table.stdout, /^ {2}\d+ /),
      intake: rows(intake.stdout, /^\d+\. /),
    };
  }

  it('bounds by -n in every renderer, below, at and above the queue length', async () => {
    const root = await siblings(QUEUE_CORPUS);
    // Below, exactly at, and above: a renderer that ignores -n is only visible below the length.
    for (const n of [3, CORPUS_SIZE, 50]) {
      const c = await counts(root, n);
      expect({ n, ...c }).toEqual({ n, json: Math.min(n, CORPUS_SIZE), table: Math.min(n, CORPUS_SIZE), intake: Math.min(n, CORPUS_SIZE) });
    }
  }, 180_000);

  it('names the page and the whole queue in every renderer when -n bounds it', async () => {
    const root = await siblings(QUEUE_CORPUS);
    const SHOWN = 3;
    const [json, table, intake] = await Promise.all([
      run(root, 'hypothesis', 'next', '.', '-n', String(SHOWN), '--json'),
      run(root, 'hypothesis', 'next', '.', '-n', String(SHOWN)),
      run(root, 'hypothesis', 'next', '.', '-n', String(SHOWN), '--intake'),
    ]);
    for (const r of [json, table, intake]) expect(r.code).toBe(0);

    // --json: a consumer holding 3 entries can tell a page from the whole queue.
    const payload = JSON.parse(json.stdout) as { schema: string; total: number; queue: unknown[] };
    expect(payload.schema).toBe('guardlink.hypotheses-next/v1');
    expect(payload.queue).toHaveLength(SHOWN);
    expect(payload.total).toBe(CORPUS_SIZE);

    // The table header: the page size AND the queue size, in that order.
    expect(table.stdout.split('\n')[0]).toMatch(new RegExp(`\\b${SHOWN}\\b.*\\b${CORPUS_SIZE}\\b`));

    // The brief says it before the list and again on the line that hands it over,
    // because either can be the one an operator reads.
    const [head, ...rest] = intake.stdout.split(/^1\. /m);
    const closing = rest.join('1. ').split('\n').filter(Boolean).at(-1)!;
    for (const part of [head, closing]) {
      expect(part).toMatch(new RegExp(`\\b${SHOWN}\\b`));
      expect(part).toMatch(new RegExp(`\\b${CORPUS_SIZE}\\b`));
    }
    expect(closing).toContain('bugb intake');
    expect(head).toContain('-n');   // and how to ask for the rest
  }, 180_000);

  it('claims no truncation when -n hid nothing', async () => {
    const root = await siblings(QUEUE_CORPUS);
    const [json, table, intake] = await Promise.all([
      run(root, 'hypothesis', 'next', '.', '-n', '50', '--json'),
      run(root, 'hypothesis', 'next', '.', '-n', '50'),
      run(root, 'hypothesis', 'next', '.', '-n', '50', '--intake'),
    ]);
    for (const r of [json, table, intake]) expect(r.code).toBe(0);
    expect((JSON.parse(json.stdout) as { total: number; queue: unknown[] }).total).toBe(CORPUS_SIZE);
    expect(table.stdout.split('\n')[0]).toBe(`${CORPUS_SIZE} to test`);
    expect(intake.stdout).not.toMatch(new RegExp(`\\bof ${CORPUS_SIZE}\\b`));
    expect(intake.stdout.split('\n').filter(Boolean).at(-1)).toBe('Hand this to `bugb intake "<brief>"`; an operator approves the plan before anything runs.');
  }, 180_000);

  it('counts the hidden remainder without naming a state, because retests are queued too', async () => {
    const root = await siblings(QUEUE_CORPUS);
    const model = await parse(root);
    // Confirm the two #sqli claims, then move the code beneath both: they become
    // `retest`, and retests sort first — so a page of one leaves a previously
    // CONFIRMED claim in the remainder the notice is summarising.
    for (const target of ['src/a.ts:4', 'src/a.ts:9']) recordOutcome(root, model, target, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    await writeFile(join(root, 'src', 'a.ts'), QUEUE_CORPUS.replace('{ return email; }', '{ return email.trim(); }').replace('{ return id; }', '{ return id.trim(); }'));

    const [list, intake] = await Promise.all([
      run(root, 'hypothesis', 'list', '.', '--json'),
      run(root, 'hypothesis', 'next', '.', '-n', '1', '--intake'),
    ]);
    expect(list.code).toBe(0);
    expect(intake.code).toBe(0);

    const states = (JSON.parse(list.stdout) as { records: { state: string }[] }).records.map(r => r.state);
    expect(states.filter(x => x === 'retest')).toHaveLength(2);

    const shown = intake.stdout.split('\n').filter(l => /^\d+\. /.test(l));
    expect(shown).toHaveLength(1);
    expect(shown[0]).toContain('previously confirmed');   // the page holds one retest; the other is hidden

    // The lines that summarise what is hidden: they count, and claim nothing
    // about the state of what they count.
    const summary = intake.stdout.split('\n').filter(l => !/^\d+\. |^ {3}claim: /.test(l)).join('\n');
    expect(summary).toMatch(new RegExp(`\\b${CORPUS_SIZE - 1}\\b`));   // the remainder, counted
    expect(summary).toMatch(new RegExp(`\\b1\\b.*\\b${CORPUS_SIZE}\\b`));
    expect(summary).toContain('-n <count>');
    expect(summary).not.toMatch(/untested/);
  }, 180_000);

  it('gives every queue entry the claim key that addresses it, and it resolves in `hypothesis list`', async () => {
    const root = await siblings(QUEUE_CORPUS);
    const [next, list] = await Promise.all([
      run(root, 'hypothesis', 'next', '.', '-n', String(CORPUS_SIZE), '--json'),
      run(root, 'hypothesis', 'list', '.', '--json'),
    ]);
    expect(next.code).toBe(0);
    expect(list.code).toBe(0);
    const q = JSON.parse(next.stdout) as { schema: string; queue: { key: string; asset: string; threat: string; file: string; line: number }[] };
    const records = (JSON.parse(list.stdout) as { records: { key: string; asset: string; threat: string; file: string; line: number }[] }).records;
    expect(q.schema).toBe('guardlink.hypotheses-next/v1');   // additive: a consumer tells by the field, not by a version it would have to be rebuilt for
    expect(q.queue).toHaveLength(CORPUS_SIZE);

    // The control: this corpus DOES collide at the tier a keyless consumer would
    // join on, so resolving by key here is not the luck of a distinct tuple.
    const coarse = new Set(records.map(r => `${r.asset}|${r.threat}|${r.file}`));
    expect(coarse.size).toBeLessThan(records.length);

    const byKey = new Map(records.map(r => [r.key, r]));
    expect(byKey.size).toBe(records.length);           // a key names at most one claim
    for (const e of q.queue) {
      expect(e.key, `queue entry ${e.asset} → ${e.threat} at ${e.file}:${e.line} carries no claim key`).toBeTruthy();
      const hit = byKey.get(e.key);
      expect(hit, `key ${e.key} resolves to no record in hypothesis list`).toBeDefined();
      expect(hit).toMatchObject({ asset: e.asset, threat: e.threat, file: e.file, line: e.line });
    }
  }, 180_000);
});


// ─── The bounded notice: grammar, and who states the total ──────────────

describe('a bounded queue says so in a sentence that holds at every count', () => {
  it('agrees in number when exactly one entry is hidden', async () => {
    const root = await siblings(QUEUE_CORPUS);
    // CORPUS_SIZE - 1 shown leaves a remainder of exactly one: the count the
    // sentence was fixed at plural for.
    const one = await run(root, 'hypothesis', 'next', '.', '-n', String(CORPUS_SIZE - 1), '--intake');
    expect(one.code).toBe(0);
    expect(one.stdout).toContain('The other 1 is');
    expect(one.stdout).not.toContain('The other 1 are');

    // And the plural case still reads as it did.
    const many = await run(root, 'hypothesis', 'next', '.', '-n', '2', '--intake');
    expect(many.code).toBe(0);
    expect(many.stdout).toContain(`The other ${CORPUS_SIZE - 2} are`);
  }, 120_000);
});

describe('the total a bounded renderer prints is the caller’s to state', () => {
  const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
  const format = join(process.cwd(), 'src', 'hypothesis', 'format.js');
  const classify = join(process.cwd(), 'src', 'hypothesis', 'classify.js');

  /**
   * Type-check one fixture against the real module and report what tsc said.
   *
   * The fixture is checked under the PROJECT's tsconfig, not a hand-listed flag
   * set: it pulls the whole transitive graph of `format.ts` into the program,
   * and a graph checked under options the repo does not use goes red for
   * reasons that have nothing to do with the arity pinned below. Two overrides
   * are needed to point that config at a file outside `src`: `include` is
   * emptied so the fixture is the only root, and `rootDir` — which governs
   * output layout and nothing else under `--noEmit` — is widened to an ancestor
   * of both the fixture and the repo. The fixture's own `package.json` makes it
   * ESM, matching the modules it imports; without it `nodenext` infers CommonJS
   * for a file outside the package and the import is a `require()` of ESM.
   */
  const check = async (body: string): Promise<{ code: number; out: string }> => {
    const dir = await mkdtemp(join(tmpdir(), 'guardlink-total-'));
    try {
      await writeFile(join(dir, 'fixture.ts'), `import { formatQueue, formatIntake } from '${format}';\nimport type { RankedHypothesis } from '${classify}';\ndeclare const page: RankedHypothesis[];\ndeclare const total: number;\n${body}\n`);
      await writeFile(join(dir, 'package.json'), JSON.stringify({ type: 'module' }));
      const config = join(dir, 'tsconfig.json');
      await writeFile(config, JSON.stringify({
        extends: join(process.cwd(), 'tsconfig.json'),
        compilerOptions: { noEmit: true, rootDir: parsePath(dir).root },
        include: [],
        files: ['fixture.ts'],
      }));
      return await new Promise((res) => execFile(process.execPath, [tsc, '--noEmit', '--project', config], { maxBuffer: 64 * 1024 * 1024 },
        (err, stdout) => res({ code: (err as { code?: number } | null)?.code ?? 0, out: stdout })));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  it('refuses to compile a call that leaves the total unstated', async () => {
    // Omitting it is the defect these renderers exist to prevent, wearing a
    // plausible number: the page length silently becomes the queue length, so a
    // 10-of-142 page reports "10 to test". A required parameter turns that into
    // a build failure instead of a confident wrong answer.
    const omitted = await check('formatQueue(page);\nformatIntake(page, \'p\');');
    expect(omitted.code).not.toBe(0);
    expect(omitted.out).toMatch(/Expected \d+ arguments, but got \d+/);

    // The control: the same fixture with the total stated must compile, so the
    // failure above is the missing argument and not an unrelated type error.
    const stated = await check('formatQueue(page, total);\nformatIntake(page, \'p\', total);');
    expect(stated.out).toBe('');
    expect(stated.code).toBe(0);
  }, 180_000);
});
