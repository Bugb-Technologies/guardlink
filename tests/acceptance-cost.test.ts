/**
 * What an acceptance costs — the measured attack, turned into a test.
 *
 * The scout report's §5.2 measured this on OWASP NodeGoat: one generated file of
 * 67 blanket `@accepts` lines plus `guardlink reanchor --apply` took
 * `guardlink ci --strict` from exit 1 to **exit 0** — "✓ No unmitigated
 * exposures, no anchor drift" — while **eight `@confirmed` reproduced exploits**
 * survived untouched in the same model, because the gate's predicate had no
 * `@confirmed` input and no acceptance-quality input.
 *
 * The fixture below is that attack in miniature, built the same way: read the
 * exposures out of `guardlink ci --format json`, write one `@accepts` per
 * distinct `asset::threat` pair into a single new `.gal` file, reanchor, and run
 * the gate. The generation is scripted rather than hand-written for the same
 * reason the report scripted it — a hand-written blanket file is a guess about
 * what an attacker would produce; a generated one is what the tool's own output
 * makes trivial.
 *
 * Every case drives the real CLI, because what is under test is an EXIT CODE.
 * An in-process assertion on `runCiChecks` would pass while the command exited 0.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
/** This repo's own tsx by absolute path — see the note in ci.test.ts. */
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

interface Run { status: number; stdout: string; stderr: string }

function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8' }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.DB (#db) -- "Database"
 * @asset App.Views (#views) -- "Rendered templates"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat Path_Traversal (#pt) [medium] cwe:CWE-22 -- "Untrusted path segments"
 * @threat Cross_Site_Scripting (#xss) [high] cwe:CWE-79 -- "Unescaped output"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

/**
 * Four exposures across three files, one `@confirmed`, no controls.
 *
 * `src/dao.ts` and `src/reset.ts` carry the SAME (asset, threat) pair at two
 * different sites — the shape §5.2 measured, where one acceptance at
 * `app/data/user-dao.js:17` also silenced `artifacts/db-reset.js:12`.
 */
const FILES: Record<string, string> = {
  'src/dao.ts': `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @confirmed #sqli on #api [critical] cwe:CWE-89 -- "Pentest verified: dumped users via the email param"
 * @audit #api -- "Needs a human to pick the control"
 */
export function findUser(email: string) { return email; }
`,
  'src/reset.ts': `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "the same pair at a second site nobody reviewed"
 * @audit #api -- "Needs a human to pick the control"
 */
export function resetUser(email: string) { return email; }
`,
  'src/render.ts': `/**
 * @exposes #views to #xss [high] cwe:CWE-79 -- "user name interpolated into HTML"
 * @exposes #db to #pt [medium] cwe:CWE-22 -- "path segment from the request"
 * @audit #views -- "Needs a human to pick the control"
 */
export function render(name: string) { return name; }
`,
};

async function scaffold(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await mkdir(join(root, '.guardlink', 'annotations'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"acceptance-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  for (const [path, body] of Object.entries(FILES)) await writeFile(join(root, path), body);
  return root;
}

/** The report's own recipe: one `@accepts` per distinct `asset::threat`, in one new file. */
async function writeBlanketAcceptances(root: string): Promise<number> {
  const { stdout } = await guardlink(root, 'ci', '.', '--format', 'json');
  const report = JSON.parse(stdout) as { exposures: Array<{ asset: string; threat: string }> };
  const pairs = new Map<string, { asset: string; threat: string }>();
  for (const e of report.exposures) pairs.set(`${e.asset}::${e.threat}`, e);
  const lines = [...pairs.values()].map(p => `@accepts ${p.threat} on ${p.asset} -- "x"`);
  await writeFile(join(root, '.guardlink', 'annotations', '_blanket.gal'), lines.join('\n') + '\n');
  return lines.length;
}

// ─── §5.2, reproduced ────────────────────────────────────────────────

describe('the blanket-acceptance attack does not buy a green gate', () => {
  let root: string;
  let written: number;
  let before: Run;
  let after: Run;
  let afterJson: Run;
  let sarifAfter: Run;

  beforeAll(async () => {
    root = await scaffold('guardlink-blanket-');
    before = await guardlink(root, 'ci', '.', '--strict');
    written = await writeBlanketAcceptances(root);
    await guardlink(root, 'reanchor', '.', '--apply');
    after = await guardlink(root, 'ci', '.', '--strict');
    afterJson = await guardlink(root, 'ci', '.', '--format', 'json');
    sarifAfter = await guardlink(root, 'sarif', '.');
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the fixture starts red, so the "after" result means something', () => {
    expect(before.status).toBe(1);
  });

  it('writes one acceptance per distinct asset::threat, as the report did', () => {
    // Three distinct pairs across four exposures: #api::#sqli is written twice.
    expect(written).toBe(3);
  });

  it('STAYS RED — this is the measured regression', () => {
    expect(after.status).toBe(1);
    expect(after.stderr).not.toContain('✓ No unmitigated exposures');
  });

  it('every exposure comes back: an acceptance in another file covers nothing', () => {
    const report = JSON.parse(afterJson.stdout);
    expect(report.summary.exposures).toBe(4);
  });

  it('names the acceptances it refused, and why', () => {
    const report = JSON.parse(afterJson.stdout);
    expect(report.summary.acceptances).toBe(3);
    expect(report.summary.unqualified_acceptances).toBe(3);
    expect(after.stderr).toContain('do not count as acceptances');
    expect(after.stderr).toMatch(/no `by <who>`/);
    expect(after.stderr).toMatch(/justification is under 24 characters/);
    expect(after.stderr).toMatch(/no `until <YYYY-MM-DD>`/);
  });

  it('reports the confirmed exploit the old predicate never looked at', () => {
    const report = JSON.parse(afterJson.stdout);
    expect(report.summary.confirmed).toBe(1);
    expect(after.stderr).toContain('CONFIRMED exploit(s)');
  });

  it('the SARIF a pentest reads is not silenced either — the second surface', () => {
    const sarif = JSON.parse(sarifAfter.stdout);
    const rules = (sarif.runs[0].results as Array<{ ruleId: string }>).map(r => r.ruleId);
    expect(rules.filter(r => r.startsWith('guardlink/unmitigated')).length).toBe(4);
    expect(rules.filter(r => r === 'guardlink/confirmed-exploitable').length).toBe(1);
  });
});

// ─── @confirmed is not silenceable ───────────────────────────────────

describe('a reproduced exploit gates through every form of coverage', () => {
  let root: string;
  let run: Run;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-confirmed-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"cfx","version":"1.0.0"}\n');
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    // Mitigated AND accepted, with a good acceptance. Both would remove the
    // exposure; neither may remove the record that somebody reproduced it.
    await writeFile(join(root, 'src', 'a.ts'), `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @confirmed #sqli on #api [critical] cwe:CWE-89 -- "Pentest verified: dumped the users table"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 * @accepts #sqli on #api by "Ada Lovelace" until 2999-01-01 -- "Signed for as well, belt and braces"
 */
export function findUser(email: string) { return email; }
`);
    run = await guardlink(root, 'ci', '.', '--strict');
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('exits 1 with zero unmitigated exposures', () => {
    expect(run.stderr).toContain('Unmitigated exposures: 0');
    expect(run.status).toBe(1);
  });

  it('says the only way out is to remove the claim, not to add one', () => {
    expect(run.stderr).toContain('No acceptance silences these');
  });
});

// ─── --severity and --scope ──────────────────────────────────────────

describe('--severity and --scope narrow the gate without hiding what they dropped', () => {
  let root: string;
  let runs: Record<string, Run>;

  beforeAll(async () => {
    root = await scaffold('guardlink-narrow-');
    const plan: Record<string, string[]> = {
      all: ['ci', '.', '--strict'],
      criticalOnly: ['ci', '.', '--strict', '--severity', 'critical'],
      lowOnly: ['ci', '.', '--strict', '--severity', 'low'],
      criticalJson: ['ci', '.', '--format', 'json', '--severity', 'critical'],
      scopeRender: ['ci', '.', '--strict', '--scope', 'src/render.ts'],
      scopeMissing: ['ci', '.', '--strict', '--scope', 'services/nothing'],
      scopeJson: ['ci', '.', '--format', 'json', '--scope', 'src/render.ts'],
      badSeverity: ['ci', '.', '--strict', '--severity', 'critcal'],
    };
    const keys = Object.keys(plan);
    const out = await Promise.all(keys.map(k => guardlink(root, ...plan[k])));
    runs = Object.fromEntries(keys.map((k, i) => [k, out[i]]));
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the unnarrowed gate sees all four exposures', () => {
    expect(runs.all.status).toBe(1);
    expect(runs.all.stderr).toContain('Unmitigated exposures: 4');
  });

  it('--severity critical keeps the two critical exposures and the confirmed', () => {
    const report = JSON.parse(runs.criticalJson.stdout);
    expect(report.summary.exposures).toBe(2);
    expect(report.summary.confirmed).toBe(1);
    expect(runs.criticalOnly.status).toBe(1);
  });

  it('--severity low goes green on a repo that is red overall', () => {
    expect(runs.lowOnly.status).toBe(0);
  });

  it('says what it was narrowed to, and how much it left out', () => {
    expect(runs.criticalOnly.stderr).toContain('Narrowed to severity critical');
    expect(runs.criticalOnly.stderr).toMatch(/finding\(s\) outside it, not gated on/);
    const report = JSON.parse(runs.criticalJson.stdout);
    expect(report.summary.filters.severity).toEqual(['critical']);
    // Two non-critical exposures dropped; the one confirmed IS critical, so it stays.
    expect(report.summary.filters.excluded_by_severity).toBe(2);
  });

  it('--scope keeps only findings under the path', () => {
    const report = JSON.parse(runs.scopeJson.stdout);
    expect(report.summary.exposures).toBe(2);
    expect(report.exposures.every((e: { location: { file: string } }) => e.location.file === 'src/render.ts')).toBe(true);
    expect(runs.scopeRender.status).toBe(1);
  });

  it('a scope that matches nothing is green, and says so rather than lying', () => {
    expect(runs.scopeMissing.status).toBe(0);
    expect(runs.scopeMissing.stderr).toContain('Narrowed to scope services/nothing');
  });

  it('a misspelled --severity is an error, not a gate that quietly passes', () => {
    // The dangerous failure: `--severity critcal` matching nothing and exiting 0.
    expect(runs.badSeverity.status).toBe(1);
    expect(runs.badSeverity.stderr).toContain("Unknown --severity 'critcal'");
  });
});
