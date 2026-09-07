/**
 * `computeActions` — the "What to do next" list on the Summary page.
 *
 * Pure over what the dashboard already computes. Order is by urgency, every
 * item points somewhere (a filtered page or a command), and a slice never
 * claims a project-wide measure.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { computeActions, computeExposures, computeConfirmed } from '../src/dashboard/data.js';
import type { VerificationReport } from '../src/parser/verification.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.Web (#web) -- "Web tier"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

async function project(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-actions-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  for (const [rel, content] of Object.entries(files)) {
    await mkdir(join(root, rel, '..'), { recursive: true });
    await writeFile(join(root, rel), content);
  }
  return root;
}

const RISKY = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "raw sql"
 * @exposes #web to #xss [high] cwe:CWE-79 -- "unescaped bio"
 * @exposes #web to #xss [low] -- "minor"
 * @mitigates #web against #xss using #prepared-stmts -- "escaped"
 * @audit #api -- "needs a look"
 */
export function login(email: string) { return email; }
`;

function verification(over: Partial<VerificationReport['summary']>, ledger: VerificationReport['ledger'] = 'ok'): VerificationReport {
  return {
    ledger,
    claims: [],
    orphans: [],
    hash_version_mismatch: false,
    summary: { verified: 0, stale: 0, unverified: 0, orphans: 0, stale_by_verb: {}, demotable_stale: 0, ...over },
  };
}

describe('computeActions', () => {
  it('orders confirmed, then critical/high open, then the ledger, then audits, then coverage', async () => {
    const root = await project({ 'src/a.ts': RISKY, 'src/b.ts': 'export const plain = 1;\n' });
    const { model } = await parseProject({ root, project: 'act' });
    const actions = computeActions({
      model, exposures: computeExposures(model), confirmed: computeConfirmed(model),
      verification: verification({ stale: 2, demotable_stale: 1, verified: 3 }), attribution: null, scope: null,
    });
    expect(actions.map(a => a.id)).toEqual(['open-severe', 'stale-claims', 'audits', 'coverage']);

    const severe = actions[0];
    expect(severe.level).toBe('critical');
    expect(severe.count).toBe(1);               // the critical sqli; the high xss is mitigated
    expect(severe.href).toBe('#threats?sev=critical,high&status=open');

    const stale = actions[1];
    expect(stale.count).toBe(2);
    expect(stale.command).toBe('guardlink verify --stale');
    expect(stale.detail).toMatch(/1 of them (is a|are) mitigation/);

    expect(actions[2]).toMatchObject({ count: 1, href: '#data?q=audit' });
    expect(actions[3].command).toMatch(/^guardlink annotate/);
  });

  it('asks for a first verify when there is no ledger, and counts confirmed findings first', async () => {
    const root = await project({ 'src/a.ts': RISKY.replace(' * @audit #api -- "needs a look"\n', ' * @confirmed #sqli on #api [critical] -- "pentest"\n') });
    const { model } = await parseProject({ root, project: 'act' });
    const actions = computeActions({
      model, exposures: computeExposures(model), confirmed: computeConfirmed(model),
      verification: verification({ unverified: 4 }, 'absent'), attribution: null, scope: null,
    });
    expect(actions[0]).toMatchObject({ id: 'confirmed', level: 'critical', count: 1, href: '#threats?status=confirmed' });
    const first = actions.find(a => a.id === 'start-verifying');
    expect(first).toMatchObject({ command: 'guardlink verify --all', count: 4 });
  });

  it('says nothing is urgent when nothing is', async () => {
    const root = await project({ 'src/a.ts': 'import x from \'x\';\n\n/**\n * @exposes #web to #xss [low] -- "minor"\n * @mitigates #web against #xss using #prepared-stmts -- "escaped"\n */\nexport function f() { return 1; }\n' });
    const { model } = await parseProject({ root, project: 'act' });
    const actions = computeActions({
      model, exposures: computeExposures(model), confirmed: computeConfirmed(model),
      verification: verification({ verified: 2 }), attribution: null, scope: null,
    });
    expect(actions).toEqual([expect.objectContaining({ id: 'none', level: 'info' })]);
  });

  it('withholds project-wide coverage on a feature slice', async () => {
    const root = await project({ 'src/a.ts': RISKY, 'src/b.ts': 'export const plain = 1;\n' });
    const { model } = await parseProject({ root, project: 'act' });
    const actions = computeActions({
      model, exposures: computeExposures(model), confirmed: computeConfirmed(model),
      verification: null, attribution: null, scope: ['Login'],
    });
    expect(actions.some(a => a.id === 'coverage')).toBe(false);
    expect(actions.some(a => a.id === 'start-verifying')).toBe(false);
  });
});
