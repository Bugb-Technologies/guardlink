/**
 * R10 — `annotation_hash` beyond the `.mmd` files.
 *
 * The staleness mechanism existed, worked, and covered the 19 artifacts that
 * matter least. Every `.mmd` carried a `%%` header naming the annotations it was
 * built from and `guardlink validate --artifacts` checked it; `model.json` sat
 * beside them carrying nothing, so the file holding the ACTUAL MODEL was the one
 * file whose staleness the staleness gate could not see. `findings.sarif` — the
 * export a pentest probes from, where a stale copy decides which exposures get
 * tested at all — carried nothing either.
 *
 * These cases assert the two halves separately: that each artifact is STAMPED,
 * and that a stamped artifact is CHECKED. Either alone is useless.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile, appendFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readArtifactHash, OPTIONAL_STAMPED_ARTIFACTS } from '../src/artifacts/emit.js';

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
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 */
export {};
`;

// ─── readArtifactHash reads every carrier ────────────────────────────

describe('readArtifactHash reads all three provenance carriers', () => {
  const hash = 'sha256-v3:abc123';

  it('the mermaid %% header', () => {
    expect(readArtifactHash(`%% artifact: x\n%% annotation_hash: ${hash}\ngraph TD\n`)).toBe(hash);
  });

  it('every JSON shape guardlink emits', () => {
    expect(readArtifactHash(JSON.stringify({ annotation_hash: hash }))).toBe(hash);             // MANIFEST
    expect(readArtifactHash(JSON.stringify({ provenance: { annotation_hash: hash } }))).toBe(hash); // model
    expect(readArtifactHash(JSON.stringify({ metadata: { annotation_hash: hash } }))).toBe(hash);   // report
    expect(readArtifactHash(JSON.stringify({ runs: [{ properties: { annotation_hash: hash } }] }))).toBe(hash); // sarif
  });

  it('the synced agent block\'s freshness line', () => {
    expect(readArtifactHash(`### Block Freshness\n\n- \`annotation_hash\`: \`${hash}\`\n`)).toBe(hash);
  });

  it('returns null rather than throwing on anything it cannot read', () => {
    expect(readArtifactHash('graph TD\n  a --> b\n')).toBeNull();
    expect(readArtifactHash('{not json')).toBeNull();
    expect(readArtifactHash('{}')).toBeNull();
    expect(readArtifactHash('')).toBeNull();
  });
});

// ─── the artifacts are stamped, and the drift check sees them ────────

describe('every published artifact is stamped and checked', () => {
  let root: string;
  let clean: Run;
  let dirty: Run;
  let stamped: Record<string, string | null>;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-stamp-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"stamp-fixture","version":"1.0.0"}\n');
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'a.ts'), `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @audit #api -- "Needs a control"
 */
export function login(email: string) { return email; }
`);

    // Everything a repo can publish.
    await guardlink(root, 'artifacts', '.');
    await guardlink(root, 'parse', '.', '-o', '.guardlink/report.json');
    await guardlink(root, 'sarif', '.', '-o', '.guardlink/findings.sarif');
    await guardlink(root, 'sync', '.');

    const read = async (p: string) => {
      try { return readArtifactHash(await readFile(join(root, p), 'utf-8')); } catch { return null; }
    };
    stamped = Object.fromEntries(await Promise.all(
      ['.guardlink/model.json', '.guardlink/graph/MANIFEST.json', '.guardlink/report.json',
        '.guardlink/findings.sarif', 'CLAUDE.md', 'AGENTS.md']
        .map(async p => [p, await read(p)] as const),
    ));

    clean = await guardlink(root, 'validate', '.', '--artifacts');
    // One new annotation moves the hash and nothing else.
    await appendFile(join(root, 'src', 'a.ts'), '\n// @comment -- "a claim that moves the hash"\n');
    dirty = await guardlink(root, 'validate', '.', '--artifacts');
  }, 180_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('model.json, report.json, findings.sarif and the agent files all carry a hash', () => {
    for (const [path, hash] of Object.entries(stamped)) {
      expect(hash, `${path} carries no annotation_hash`).toMatch(/^sha256-v\d+:[0-9a-f]{64}$/);
    }
  });

  it('all of them agree, because they were cut from one model', () => {
    expect(new Set(Object.values(stamped)).size).toBe(1);
  });

  it('a freshly published repo is clean', () => {
    expect(clean.stderr).toContain('✓ Artifacts are current.');
  });

  it('one changed annotation makes every stamped artifact stale, not just the diagrams', () => {
    expect(dirty.status).toBe(1);
    for (const path of ['.guardlink/model.json', '.guardlink/graph/MANIFEST.json',
      '.guardlink/report.json', '.guardlink/findings.sarif', 'CLAUDE.md', 'AGENTS.md']) {
      expect(dirty.stderr, `${path} was not reported stale`).toContain(`${path} — STALE`);
    }
  });

  it('the diagrams it always covered are still covered', () => {
    expect(dirty.stderr).toContain('.guardlink/graph/threat-graph.mmd — STALE');
  });
});

// ─── absence is not drift ────────────────────────────────────────────

describe('an optional artifact that was never published is not a finding', () => {
  let root: string;
  let run: Run;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-stamp-absent-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"absent-fixture","version":"1.0.0"}\n');
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'a.ts'),
      '/**\n * @exposes #api to #sqli [critical] -- "email concatenated into SQL"\n */\nexport const x = 1;\n');
    await guardlink(root, 'artifacts', '.');
    // No report.json, no findings.sarif, no agent files: nothing published them.
    run = await guardlink(root, 'validate', '.', '--artifacts');
  }, 120_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('reports no drift for artifacts the repo never published', () => {
    expect(run.stderr).toContain('✓ Artifacts are current.');
    for (const path of OPTIONAL_STAMPED_ARTIFACTS) {
      expect(run.stderr).not.toContain(path);
    }
  });

  it('an unstamped optional artifact is not drift either — it makes no claim', async () => {
    // A report.json written by a binary that predates the stamping. Failing the
    // repo for that punishes the wrong thing, and it fixes itself on the next run.
    await writeFile(join(root, '.guardlink', 'report.json'), '{"project":"absent-fixture"}\n');
    const after = await guardlink(root, 'validate', '.', '--artifacts');
    expect(after.stderr).toContain('✓ Artifacts are current.');
  }, 60_000);

  it('but an optional artifact claiming the WRONG hash is', async () => {
    await writeFile(join(root, '.guardlink', 'report.json'),
      JSON.stringify({ metadata: { annotation_hash: 'sha256-v3:' + 'd'.repeat(64) } }) + '\n');
    const after = await guardlink(root, 'validate', '.', '--artifacts');
    expect(after.status).toBe(1);
    expect(after.stderr).toContain('.guardlink/report.json — STALE');
  }, 60_000);
});
