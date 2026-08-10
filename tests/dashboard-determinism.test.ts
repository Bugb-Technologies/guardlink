/**
 * D17 + D25 — the dashboard must not perturb the repo, or churn.
 *
 * D17: `.html` is in DEFAULT_INCLUDE, so `guardlink dashboard` wrote
 * `threat-dashboard.html` into its own scan set. Zero annotations, but it moved
 * `source_files` and `unannotated_files` — the tool measuring the repo was
 * measuring its own output.
 *
 * D25: `docs/examples/threat-dashboard.html` is committed and churned on every
 * regeneration. The PRD attributed that to an embedded wall clock at
 * `generate.ts:40`. Measurement disagreed: that variable was computed and never
 * rendered. The real causes were parse order (D23 — the dashboard path never
 * went through `canonicalizeModelOrder`) and the model's own `generated_at`,
 * embedded verbatim in the page's JSON blob.
 *
 * The determinism test runs generations in SEPARATE PROCESSES. Parse order is
 * stable within a process, so a same-process test would have passed throughout.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject, DEFAULT_EXCLUDE, GENERATED_OUTPUT_FILES } from '../src/parser/parse-project.js';
import { generateDashboardHTML } from '../src/dashboard/generate.js';
import { GITIGNORE_ENTRY } from '../src/init/templates.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');

let root: string;

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-dash-'));
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"dash","version":"1.0.0"}\n');
  // Several annotated files, so parse order has something to vary.
  for (const name of ['auth', 'db', 'api', 'crypto', 'io']) {
    await writeFile(join(root, 'src', `${name}.ts`),
      '/**\n' +
      ` * @exposes App.${name} to #sqli [high] -- "raw input"\n` +
      ` * @audit App.${name} -- "needs review"\n` +
      ` * @flows User -> App.${name} via HTTPS -- "request"\n` +
      ' */\n' +
      `export const ${name} = 1;\n`);
  }
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

const sha = (s: string) => createHash('sha256').update(s).digest('hex');

describe('D25 — two generations in separate processes are byte-identical', () => {
  it('three processes, one hash', async () => {
    // Written OUTSIDE the scanned root. `-o` with a non-default name lands in
    // the scan set of the next run — the default `threat-dashboard.html` is
    // excluded by name, an arbitrary one cannot be. That is D17's residue, and
    // it is the user's `-o` choice rather than something the tool did unasked;
    // it is not what this test is measuring.
    const outDir = await mkdtemp(join(tmpdir(), 'guardlink-dash-out-'));
    try {
      // The Promise.all here used to wrap execFileSync, which is synchronous —
      // so the three generations ran strictly one after another while reading as
      // concurrent. Now they genuinely are. They write to distinct files in a
      // temp dir and read nothing each other writes, so concurrency changes
      // nothing about what is being compared: three separate processes, three
      // hashes, byte-identical.
      const hashes = await Promise.all([1, 2, 3].map(async i => {
        const out = join(outDir, `dash-${i}.html`);
        await run('npx', ['tsx', cli, 'dashboard', root, '-o', out], { cwd: repoRoot });
        return sha(await readFile(out, 'utf-8'));
      }));
      expect(hashes[1]).toBe(hashes[0]);
      expect(hashes[2]).toBe(hashes[0]);
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  }, 180_000);
});

describe('D25 — the volatile fields are gone from the page', () => {
  it('the embedded model carries no generated_at', async () => {
    const { model } = await parseProject({ root, project: 'dash' });
    expect(model.generated_at, 'the model still has one — it is dropped at emission').toBeTruthy();

    const html = generateDashboardHTML(model, root);
    const embedded = html.match(/const threatModel = (\{.*?\});\n/s);
    expect(embedded).not.toBeNull();
    expect(JSON.parse(embedded![1])).not.toHaveProperty('generated_at');
  });

  it('two in-process generations of the same model are identical', async () => {
    const { model } = await parseProject({ root, project: 'dash' });
    expect(sha(generateDashboardHTML(model, root))).toBe(sha(generateDashboardHTML(model, root)));
  });

  it('a model in a different array order still produces the same page', async () => {
    // The canonicalisation, isolated: shuffling the parse-order-dependent arrays
    // must not change a byte. This is what varied across processes.
    const { model } = await parseProject({ root, project: 'dash' });
    const shuffled = {
      ...model,
      exposures: [...model.exposures].reverse(),
      flows: [...model.flows].reverse(),
      audits: [...model.audits].reverse(),
      assets: [...model.assets].reverse(),
    };
    expect(sha(generateDashboardHTML(shuffled, root))).toBe(sha(generateDashboardHTML(model, root)));
  });
});

describe('D17 — generated output is not scan input', () => {
  it('a dashboard written into the project does not enter the scan set', async () => {
    const before = await parseProject({ root, project: 'dash' });

    await writeFile(join(root, 'threat-dashboard.html'), generateDashboardHTML(before.model, root));
    const after = await parseProject({ root, project: 'dash' });

    expect(after.model.source_files).toBe(before.model.source_files);
    expect(after.model.unannotated_files).toEqual(before.model.unannotated_files);
    expect((after.model.unannotated_files ?? []).join()).not.toMatch(/threat-dashboard/);
  });

  it('it is excluded wherever it is written, not only at the root', async () => {
    await mkdir(join(root, 'docs', 'examples'), { recursive: true });
    const before = await parseProject({ root, project: 'dash' });
    await writeFile(join(root, 'docs', 'examples', 'threat-dashboard.html'), '<html></html>');
    const after = await parseProject({ root, project: 'dash' });
    expect(after.model.source_files).toBe(before.model.source_files);
  });

  it('.html is still parsed — templates keep their annotations', async () => {
    // The reason this is a name-based exclusion and not `.html` leaving
    // DEFAULT_INCLUDE: server-rendered templates carry annotations in HTML
    // comments, and dropping the extension would lose them silently.
    await writeFile(join(root, 'src', 'page.html'),
      '<!-- @exposes App.Page to #xss [high] -- "unescaped interpolation" -->\n<div></div>\n');
    const { model } = await parseProject({ root, project: 'dash' });
    expect(model.exposures.some(e => e.asset === 'App.Page')).toBe(true);
  });

  it('every generated output name is excluded', () => {
    for (const name of GENERATED_OUTPUT_FILES) {
      expect(DEFAULT_EXCLUDE, name).toContain(`**/${name}`);
    }
  });

  it('the parser exclusion and .gitignore come from one list', () => {
    // They drifted apart once already; this is the guard.
    for (const name of GENERATED_OUTPUT_FILES) {
      expect(GITIGNORE_ENTRY, name).toContain(name);
    }
  });
});
