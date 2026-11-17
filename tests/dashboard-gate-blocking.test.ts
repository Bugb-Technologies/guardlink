/**
 * The dashboard counts a claim the pre-PR gate blocks on as open work.
 *
 * An exposure was confirmed exploitable and recorded in the hypothesis ledger.
 * The fix then landed: the code beneath the claim changed and a `@mitigates`
 * was declared. The ledger now asks for a retest, and a gate reading it stays
 * blocked until one refutes the exploit. The dashboard read the declared
 * control alone and said "0 of 1 exposure is open", grade A, and "Nothing
 * urgent — every exposure is mitigated". A declared control is not evidence
 * that a confirmed exploit is gone, so:
 *
 * - a claim in `retest` is open, graded by its severity, and listed in "What to
 *   do next" with the command that re-tests it;
 * - a ledger confirmation that still holds is confirmed exploitable, whatever
 *   control is declared beside it, and grades F.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { recordOutcome, readHypotheses, classifyHypotheses, attachHypotheses } from '../src/hypothesis/index.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { computeExposures, computeConfirmed, computeActions } from '../src/dashboard/data.js';

const DEFINITIONS = `/**
 * @asset App.Web (#web) -- "Web tier"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 * @control Encoding (#enc) -- "Output encoding"
 */
export {};
`;
const EXPOSED = `/**
 * @exposes #web to #xss [high] cwe:CWE-79 -- "profile.bio rendered via innerHTML in render()"
 */
export function render(bio: string) { return bio; }
`;
// The fix: the code beneath the claim changes and a control is declared on it.
const FIXED = `/**
 * @exposes #web to #xss [high] cwe:CWE-79 -- "profile.bio rendered via innerHTML in render()"
 * @mitigates #web against #xss using #enc -- "bio is HTML-escaped before rendering"
 */
export function render(bio: string) { return escapeHtml(bio); }
function escapeHtml(s: string) { return s.replace(/</g, '&lt;'); }
`;
const XSS = 'src/a.ts:2';
const NOW = '2026-11-17T03:09:25.000Z';
const CONFIRM = 'GET /profile with bio=<script> rendered the script tag unescaped; reproduced twice';

async function project(source: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-gate-blocking-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), source);
  return root;
}
const parse = async (root: string) => (await parseProject({ root, project: 'gate' })).model;
const headline = (html: string): string => (html.match(/data-stat="headline">([\s\S]*?)<\/h2>/)?.[1] ?? '').replace(/<[^>]+>/g, '');
const grade = (html: string): string | undefined => html.match(/<span class="grade g-([a-f])"/)?.[1];

async function confirmedThenFixed(): Promise<string> {
  const root = await project(EXPOSED);
  recordOutcome(root, await parse(root), XSS, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
  await writeFile(join(root, 'src', 'a.ts'), FIXED);
  return root;
}

describe('a claim in retest is open work on the dashboard', () => {
  it('the ledger reads retest and the exposure reads mitigated by its control', async () => {
    const root = await confirmedThenFixed();
    const model = await parse(root);
    attachHypotheses(model, classifyHypotheses(model, readHypotheses(root)));
    expect(model.exposures[0].hypothesis?.state).toBe('retest');
    const [row] = computeExposures(model);
    expect(row.mitigated).toBe(true);
    expect(row.open).toBe(true);
    expect(row.gate).toBe('retest');
  });

  it('the Overview counts it open and does not grade A', async () => {
    const root = await confirmedThenFixed();
    const html = generateDashboardHTML(await parse(root), root);
    expect(headline(html)).toMatch(/^1 of 1 exposure is open/);
    expect(grade(html)).not.toBe('a');
    expect(grade(html)).toBe('c');
  });

  it('"What to do next" names the retest, not "Nothing urgent"', async () => {
    const root = await confirmedThenFixed();
    const model = await parse(root);
    attachHypotheses(model, classifyHypotheses(model, readHypotheses(root)));
    const actions = computeActions({ model, exposures: computeExposures(model), confirmed: computeConfirmed(model), verification: null, attribution: null, scope: null });
    expect(actions.map(a => a.id)).not.toContain('none');
    const retest = actions.find(a => a.id === 'retest');
    expect(retest).toMatchObject({ level: 'high', count: 1, command: 'guardlink hypothesis next .' });
    expect(retest!.title).toBe('1 confirmed finding needs a retest');
    // The open-severe advice ("add a @mitigates") would be wrong here: a control is already declared.
    expect(actions.find(a => a.id === 'open-severe')).toBeUndefined();

    const html = generateDashboardHTML(model, root);
    expect(html).toContain('1 confirmed finding needs a retest');
    expect(html).not.toContain('Every exposure is mitigated or accepted');
  });

  it('a retest that refutes the exploit closes it again', async () => {
    const root = await confirmedThenFixed();
    recordOutcome(root, await parse(root), XSS, 'refuted', { evidence: 'GET /profile with bio=<script> returned it escaped', by: 'human:test', at: NOW });
    const html = generateDashboardHTML(await parse(root), root);
    expect(headline(html)).toMatch(/^0 of 1 exposure are open/);
    expect(grade(html)).toBe('a');
  });
});

describe('a holding ledger confirmation is confirmed exploitable', () => {
  it('a control declared beside it does not make it mitigated, and it grades F', async () => {
    // The confirmation is recorded against the fixed code, so it still holds.
    const root = await project(FIXED);
    recordOutcome(root, await parse(root), XSS, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    const model = await parse(root);
    attachHypotheses(model, classifyHypotheses(model, readHypotheses(root)));
    expect(model.exposures[0].hypothesis?.state).toBe('confirmed');
    const [row] = computeExposures(model);
    expect(row).toMatchObject({ mitigated: true, open: true, gate: 'confirmed' });
    const actions = computeActions({ model, exposures: [row], confirmed: computeConfirmed(model), verification: null, attribution: null, scope: null });
    expect(actions[0]).toMatchObject({ id: 'confirmed', level: 'critical', count: 1 });

    const html = generateDashboardHTML(await parse(root), root);
    expect(headline(html)).toMatch(/^1 of 1 exposure is open/);
    expect(grade(html)).toBe('f');
  });

  it('a source @confirmed on the same pair is counted once', async () => {
    const root = await project(EXPOSED.replace(' */', ` * @confirmed #xss on #web [high] cwe:CWE-79 -- "${CONFIRM}"\n */`));
    recordOutcome(root, await parse(root), XSS, 'confirmed', { evidence: CONFIRM, by: 'human:test', at: NOW });
    const model = await parse(root);
    attachHypotheses(model, classifyHypotheses(model, readHypotheses(root)));
    const actions = computeActions({ model, exposures: computeExposures(model), confirmed: computeConfirmed(model), verification: null, attribution: null, scope: null });
    expect(actions.find(a => a.id === 'confirmed')?.count).toBe(1);
  });
});

describe('the "what changed" strip reads the ledger too', () => {
  it('a new exposure confirmed then fixed on this branch is newly confirmed and still open, not resolved', async () => {
    const { computeChanges } = await import('../src/dashboard/analytics.js');
    const { buildClaims } = await import('../src/dashboard/pages/context.js');
    const root = await confirmedThenFixed();
    const model = await parse(root);
    attachHypotheses(model, classifyHypotheses(model, readHypotheses(root)));
    const claims = buildClaims(model, null, null);
    const exposure = model.exposures[0];
    const diff = {
      exposures: [{ kind: 'added', item: exposure }], confirmed: [], mitigations: [{ kind: 'added', item: model.mitigations[0] }],
      resolvedExposures: [exposure], summary: { riskDelta: 'decreased' },
    };
    const ch = computeChanges({ ref: 'origin/main', refDate: null, commits: null, diff: diff as never, changedFiles: ['src/a.ts'] }, claims);
    expect(ch.newOpen).toBe(1);
    expect(ch.newConfirmed).toBe(1);
    expect(ch.resolved).toEqual([]);
  });
});
