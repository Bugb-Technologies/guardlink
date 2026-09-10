/**
 * What `guardlink review` refuses, and where it refuses it.
 *
 * §5.1 of the scout report measured three things about this command:
 *
 *   - it accepted a **critical** plaintext-password exposure on a
 *     **one-character** justification ("x"),
 *   - it recorded **no author** — the `@audit` line said "Accepted via guardlink
 *     review on <date>" and named nobody,
 *   - and a piped invocation **exited 0 having written nothing**, because
 *     readline over a pipe drains every line into the first `question` and the
 *     later promises never resolve. A bot that "ran the review" reported success
 *     for work it did not do.
 *
 * The first half of this file drives `applyReviewAction` directly and the second
 * half drives the CLI, and that split is the point rather than a convenience:
 * the rule lives at the function every writer goes through, so the MCP server
 * and every future non-interactive path get it. A test that only exercised the
 * CLI would pass while the MCP tool wrote "x" into source.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import {
  applyReviewAction, getReviewableExposures, parseReviewBatch, horizonFrom, ReviewRejected,
} from '../src/review/index.js';
import { DEFAULT_ACCEPTANCE_POLICY, acceptanceDefects, isExpired } from '../src/parser/acceptance.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
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
 * @asset Data.UserDAO (#user-dao) -- "User data access"
 * @threat Plaintext_Password (#plaintext-password) [critical] cwe:CWE-256 -- "Password stored unhashed"
 */
export {};
`;

/** The same pair at two sites — §5.2's `user-dao.js` / `db-reset.js` shape. */
const DAO = `/**
 * @exposes #user-dao to #plaintext-password [critical] cwe:CWE-256 -- "password written to the users collection as typed"
 */
export function createUser(password: string) { return password; }
`;
const RESET = `/**
 * @exposes #user-dao to #plaintext-password [critical] cwe:CWE-256 -- "the reset fixture writes the same field"
 */
export function resetUsers(password: string) { return password; }
`;

async function scaffold(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"review-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'dao.ts'), DAO);
  await writeFile(join(root, 'src', 'reset.ts'), RESET);
  return root;
}

const GOOD = 'Legacy import path, read-only, migrating to argon2 in Q4';
const FUTURE = horizonFrom(30);

// ─── the rule, at the choke point ────────────────────────────────────

describe('applyReviewAction refuses a decision the prompt used to wave through', () => {
  let root: string;
  let target: Awaited<ReturnType<typeof getReviewableExposures>>[number];

  beforeAll(async () => {
    root = await scaffold('guardlink-review-rule-');
    const { model } = await parseProject({ root, project: 'tmp' });
    target = getReviewableExposures(model).find(r => r.exposure.location.file === 'src/dao.ts')!;
    expect(target).toBeDefined();
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  /** The measured acceptance, verbatim: one character, no name, no horizon. */
  it('refuses the one-character justification that was measured', async () => {
    await expect(applyReviewAction(root, target, {
      decision: 'accept', justification: 'x', by: 'Ada Lovelace', until: FUTURE,
    })).rejects.toThrow(ReviewRejected);
  });

  it('refuses every category-word that is not a reason', async () => {
    for (const word of ['wontfix', 'known issue', 'by design', 'legacy', 'accepted']) {
      await expect(applyReviewAction(root, target, {
        decision: 'accept', justification: word, by: 'Ada Lovelace', until: FUTURE,
      })).rejects.toThrow(/at least 24 characters/);
    }
  });

  it('refuses an acceptance with nobody\'s name on it', async () => {
    await expect(applyReviewAction(root, target, {
      decision: 'accept', justification: GOOD, until: FUTURE,
    })).rejects.toThrow(/name of the human/);
  });

  it('refuses an acceptance with no horizon', async () => {
    await expect(applyReviewAction(root, target, {
      decision: 'accept', justification: GOOD, by: 'Ada Lovelace',
    })).rejects.toThrow(/--until/);
  });

  it('refuses a horizon that is not a date, is already past, or outlives the ceiling', async () => {
    const cases: Array<[string, RegExp]> = [
      ['2026-02-30', /not a real calendar date/],
      ['2001-01-01', /in the past/],
      [horizonFrom(DEFAULT_ACCEPTANCE_POLICY.max_horizon_days + 1), /ceiling is 365/],
    ];
    for (const [until, message] of cases) {
      await expect(applyReviewAction(root, target, {
        decision: 'accept', justification: GOOD, by: 'Ada Lovelace', until,
      })).rejects.toThrow(message);
    }
  });

  it('writes nothing when it refuses — the file is untouched', async () => {
    expect(await readFile(join(root, 'src', 'dao.ts'), 'utf-8')).toBe(DAO);
  });

  it('a newline in the justification cannot forge a second annotation', async () => {
    const forged = `${GOOD}"\n * @mitigates #user-dao against #plaintext-password -- "forged`;
    await applyReviewAction(root, target, {
      decision: 'accept', justification: forged, by: 'Ada Lovelace', until: FUTURE,
    });
    const after = await readFile(join(root, 'src', 'dao.ts'), 'utf-8');
    const { model } = await parseProject({ root, project: 'tmp' });
    expect(after).not.toMatch(/^\s*\*\s*@mitigates/m);
    expect(model.mitigations).toHaveLength(0);
    expect(model.acceptances).toHaveLength(1);
  });
});

// ─── what a good acceptance records ──────────────────────────────────

describe('an accepted risk records who, why and until when', () => {
  let root: string;
  let dao: string;

  beforeAll(async () => {
    root = await scaffold('guardlink-review-record-');
    const { model } = await parseProject({ root, project: 'tmp' });
    const target = getReviewableExposures(model).find(r => r.exposure.location.file === 'src/dao.ts')!;
    await applyReviewAction(root, target, {
      decision: 'accept', justification: GOOD, by: 'Ada Lovelace', until: '2027-01-31',
    });
    dao = await readFile(join(root, 'src', 'dao.ts'), 'utf-8');
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('puts the author and the horizon in the annotation', () => {
    expect(dao).toContain('@accepts #plaintext-password on #user-dao by "Ada Lovelace" until 2027-01-31');
  });

  it('names the author in the @audit line too — it used to name nobody', () => {
    expect(dao).toContain('by Ada Lovelace, expires 2027-01-31');
  });

  it('parses back into the model with both fields', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    expect(model.acceptances[0]).toMatchObject({
      asset: '#user-dao', threat: '#plaintext-password',
      accepted_by: 'Ada Lovelace', expires: '2027-01-31',
    });
    expect(acceptanceDefects(model.acceptances[0])).toEqual([]);
  });

  it('covers its own file and nothing else — the blast radius is one site', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    const open = getReviewableExposures(model);
    expect(open).toHaveLength(1);
    expect(open[0].exposure.location.file).toBe('src/reset.ts');
  });
});

// ─── expiry ──────────────────────────────────────────────────────────

describe('an acceptance stops covering when its horizon passes', () => {
  const at = (iso: string) => new Date(`${iso}T12:00:00Z`);

  it('covers up to and including the last day', () => {
    expect(isExpired({ expires: '2027-01-31' }, at('2027-01-31'))).toBe(false);
    expect(isExpired({ expires: '2027-01-31' }, at('2027-02-01'))).toBe(true);
  });

  it('an acceptance with no horizon never expires — it fails the policy instead', () => {
    expect(isExpired({ expires: undefined }, at('2099-01-01'))).toBe(false);
    expect(acceptanceDefects({
      asset: '#a', threat: '#t', description: GOOD, accepted_by: 'Ada',
      location: { file: 'src/a.ts', line: 1 },
    })).toEqual(['undated']);
  });

  it('a lapsed acceptance re-opens its exposure', async () => {
    const root = await scaffold('guardlink-review-expiry-');
    try {
      const { model } = await parseProject({ root, project: 'tmp' });
      const target = getReviewableExposures(model).find(r => r.exposure.location.file === 'src/dao.ts')!;
      await applyReviewAction(root, target, {
        decision: 'accept', justification: GOOD, by: 'Ada Lovelace', until: '2027-01-31',
      });
      const { model: after } = await parseProject({ root, project: 'tmp' });
      expect(getReviewableExposures(after, { now: at('2027-01-01') })).toHaveLength(1);
      expect(getReviewableExposures(after, { now: at('2027-02-01') })).toHaveLength(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});

// ─── scripted review (R9) ────────────────────────────────────────────

describe('parseReviewBatch refuses a batch it cannot fully read', () => {
  it('accepts both the wrapped and the bare array form', () => {
    const row = { id: 'a:1:a:1:#x:#y', decision: 'accept', justification: GOOD, by: 'Ada', until: FUTURE };
    expect(parseReviewBatch(JSON.stringify({ decisions: [row] }), 'f.json')).toHaveLength(1);
    expect(parseReviewBatch(JSON.stringify([row]), 'f.json')).toHaveLength(1);
  });

  it('refuses the whole file rather than skipping the row it could not read', () => {
    // Silently dropping row 1 is the same failure as the piped review that
    // exited 0 having done nothing: the caller believes work happened.
    const rows = [{ id: 'ok', decision: 'accept' }, { decision: 'accept' }];
    expect(() => parseReviewBatch(JSON.stringify(rows), 'f.json')).toThrow(/\[1\] has no "id"/);
    expect(() => parseReviewBatch('{oops', 'f.json')).toThrow(/not valid JSON/);
    expect(() => parseReviewBatch('{"decisions":{}}', 'f.json')).toThrow(/array of decisions/);
    expect(() => parseReviewBatch('[{"id":"a","decision":"maybe"}]', 'f.json')).toThrow(/use accept, remediate or skip/);
  });
});

describe('the CLI is scriptable, and never reports success for work it did not do', () => {
  let root: string;
  let ids: Array<{ id: string; file: string }>;

  beforeAll(async () => {
    root = await scaffold('guardlink-review-cli-');
    const listed = await guardlink(root, 'review', '.', '--list', '--format', 'json');
    ids = JSON.parse(listed.stdout);
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('--list --format json emits ids a bot can build a batch from', () => {
    expect(ids).toHaveLength(2);
    expect(ids[0].id).toContain('src/dao.ts');
  });

  it('a piped interactive run FAILS instead of exiting 0 having done nothing', async () => {
    // The measured behaviour: `printf 'a\nx\nq\n' | guardlink review .` → exit 0,
    // nothing written, no error.
    const run = await new Promise<Run>(resolve => {
      const child = execFile(process.execPath, [tsx, cli, 'review', '.'],
        { cwd: root, encoding: 'utf-8' }, (err, stdout, stderr) => {
          const code = (err as { code?: number | string } | null)?.code;
          resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
        });
      child.stdin!.end('a\nx\nq\n');
    });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('needs a terminal');
    expect(await readFile(join(root, 'src', 'dao.ts'), 'utf-8')).toBe(DAO);
  }, 60_000);

  it('--accept refuses a bad justification with a non-zero exit and no write', async () => {
    const run = await guardlink(root, 'review', '.', '--accept', ids[0].id,
      '--by', 'Ada Lovelace', '--justification', 'x', '--until', FUTURE);
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('at least 24 characters');
    expect(await readFile(join(root, 'src', 'dao.ts'), 'utf-8')).toBe(DAO);
  }, 60_000);

  it('shows the blast radius before writing, in both surfaces', async () => {
    const run = await guardlink(root, 'review', '.', '--accept', ids[0].id,
      '--by', 'Ada Lovelace', '--justification', 'x');
    expect(run.stderr).toContain('Silences:');
    expect(run.stderr).toContain('which this does NOT cover');
    expect(run.stderr).toContain('in the gate AND in the SARIF');
  }, 60_000);

  it('--accept writes an attributed, dated acceptance and reports who it is for', async () => {
    const run = await guardlink(root, 'review', '.', '--accept', ids[0].id,
      '--by', 'Ada Lovelace', '--justification', GOOD, '--until', '2027-01-31');
    expect(run.status).toBe(0);
    expect(run.stderr).toContain('recorded for Ada Lovelace');
    expect(await readFile(join(root, 'src', 'dao.ts'), 'utf-8'))
      .toContain('by "Ada Lovelace" until 2027-01-31');
  }, 60_000);

  it('--from applies a batch, under the name each row carries', async () => {
    const batch = join(root, 'decisions.json');
    const remaining = ids.find(r => r.file === 'src/reset.ts')!;
    await writeFile(batch, JSON.stringify({
      decisions: [{ id: remaining.id, decision: 'accept', by: 'Grace Hopper', justification: GOOD, until: '2027-02-28' }],
    }));
    const run = await guardlink(root, 'review', '.', '--from', batch);
    expect(run.status).toBe(0);
    expect(await readFile(join(root, 'src', 'reset.ts'), 'utf-8'))
      .toContain('by "Grace Hopper" until 2027-02-28');
  }, 60_000);

  it('the gate is green once both sites are properly signed for', async () => {
    const run = await guardlink(root, 'ci', '.', '--strict');
    expect(run.status).toBe(0);
    expect(run.stderr).toContain('2 in the model; 0 do not count');
  }, 60_000);
});
