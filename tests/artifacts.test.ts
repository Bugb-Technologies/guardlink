/**
 * GL-301/GL-302 — artifact emission and drift detection.
 *
 * The load-bearing case is the drift check. Everything else here is plumbing;
 * the header is what decides whether emitting these files is a net good, because
 * a `.mmd` in a repository looks like source and a reader who does not know it is
 * derived will not think to ask whether it is current.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { canonicalizeModelOrder } from '../src/parser/canonical-order.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import {
  emitArtifacts, checkArtifactDrift, readArtifactHash, stripHeader,
  mermaidHeader, featureSlug,
} from '../src/artifacts/emit.js';
import type { ThreatModel } from '../src/types/index.js';

const SOURCE = `/**
 * @asset App.API (#api) -- "REST surface"
 * @asset App.DB (#db) -- "store"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "untrusted input"
 * @control Prepared_Statements (#ps) -- "parameterized"
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "concatenated"
 * @mitigates #api against #sqli using #ps -- "pg placeholders"
 * @flows User -> #api via HTTPS -- "request"
 * @flows #api -> #db via query -- "lookup"
 * @boundary between #api and #db (#data-boundary) -- "trust change"
 * @feature "Checkout" -- "cart and orders"
 */
export function handler() {}
`;

describe('GL-301 — emission', () => {
  let root: string;
  let model: ThreatModel;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-art-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    ({ model } = await parseProject({ root, project: 'art' }));
  });

  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  it('writes the whole tree', async () => {
    emitArtifacts({ root, model });
    for (const path of [
      '.guardlink/model.json',
      '.guardlink/graph/threat-graph.mmd',
      '.guardlink/graph/dataflow.mmd',
      '.guardlink/graph/attack-surface.mmd',
      '.guardlink/graph/MANIFEST.json',
      '.guardlink/graph/README.md',
      '.guardlink/graph/by-feature/checkout.mmd',
    ]) {
      expect(existsSync(join(root, path)), path).toBe(true);
    }
  });

  it('emits one by-feature diagram per distinct @feature', async () => {
    emitArtifacts({ root, model });
    const files = await readdir(join(root, '.guardlink', 'graph', 'by-feature'));
    expect(files).toEqual(['checkout.mmd']);
  });

  it('removes a by-feature diagram whose @feature is gone', async () => {
    emitArtifacts({ root, model });
    expect(existsSync(join(root, '.guardlink/graph/by-feature/checkout.mmd'))).toBe(true);

    // A stale diagram left behind would claim to describe something the model
    // no longer has — the same lie the drift check exists to prevent.
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace(/ \* @feature.*\n/, ''));
    const { model: after } = await parseProject({ root, project: 'art' });
    emitArtifacts({ root, model: after });
    expect(existsSync(join(root, '.guardlink/graph/by-feature/checkout.mmd'))).toBe(false);
  });

  it('model.json is canonically ordered, so a diff means a real change', async () => {
    emitArtifacts({ root, model });
    const written = JSON.parse(await readFile(join(root, '.guardlink', 'model.json'), 'utf-8'));
    expect(written.exposures).toEqual(canonicalizeModelOrder(model).exposures);
  });

  it('regenerating an unchanged model rewrites BYTE-IDENTICAL files', async () => {
    emitArtifacts({ root, model });
    const first = await readFile(join(root, '.guardlink/graph/threat-graph.mmd'), 'utf-8');
    await new Promise(r => setTimeout(r, 5));
    emitArtifacts({ root, model });
    const second = await readFile(join(root, '.guardlink/graph/threat-graph.mmd'), 'utf-8');
    expect(second).toBe(first);
    expect(stripHeader(second)).toBe(stripHeader(first));
  });

  it('MANIFEST records every artifact with the hash it was built from', async () => {
    const result = emitArtifacts({ root, model });
    const manifest = JSON.parse(await readFile(join(root, '.guardlink/graph/MANIFEST.json'), 'utf-8'));
    expect(manifest.annotation_hash).toBe(computeAnnotationHash(canonicalizeModelOrder(model)));
    expect(manifest.artifacts.length).toBeGreaterThan(3);
    for (const entry of manifest.artifacts) {
      expect(entry.annotation_hash).toBe(result.provenance.annotation_hash);
      expect(entry.bytes).toBeGreaterThan(0);
    }
  });

  it('dry run writes nothing', async () => {
    const result = emitArtifacts({ root, model, dryRun: true });
    expect(result.written.length).toBeGreaterThan(0);
    expect(existsSync(join(root, '.guardlink', 'model.json'))).toBe(false);
  });

  it('emission does not change the dashboard output for the same model', () => {
    // The generators are called, not reimplemented, and nothing about emission
    // perturbs what the dashboard renders.
    const before = generateDashboardHTML(model, root, []);
    emitArtifacts({ root, model });
    const after = generateDashboardHTML(model, root, []);
    expect(after).toBe(before);
  });

  it('emitted artifacts stay out of the parser scan set', async () => {
    emitArtifacts({ root, model });
    const { model: after } = await parseProject({ root, project: 'art' });
    const scanned = [...after.annotated_files, ...after.unannotated_files];
    expect(scanned.filter(f => f.startsWith('.guardlink/graph'))).toEqual([]);
    expect(scanned).not.toContain('.guardlink/model.json');
    // …and therefore the model is unchanged by having emitted it.
    expect(after.annotations_parsed).toBe(model.annotations_parsed);
  });

  it('feature names become safe filenames', () => {
    expect(featureSlug('MCP Integration')).toBe('mcp-integration');
    expect(featureSlug('Auth/Login v2')).toBe('auth-login-v2');
    expect(featureSlug('  ...  ')).toBe('unnamed');
  });
});

describe('GL-302 — provenance headers', () => {
  let root: string;
  let model: ThreatModel;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-prov-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    ({ model } = await parseProject({ root, project: 'art' }));
    emitArtifacts({ root, model });
  });

  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  it('every .mmd carries content-derived provenance and no volatile fields', async () => {
    for (const rel of ['graph/threat-graph.mmd', 'graph/dataflow.mmd',
      'graph/attack-surface.mmd', 'graph/by-feature/checkout.mmd']) {
      const text = await readFile(join(root, '.guardlink', rel), 'utf-8');
      expect(text, rel).toMatch(/^%% annotation_hash: sha256-v\d+:[0-9a-f]{64}$/m);
      expect(text, rel).toMatch(/^%% generator:\s+guardlink@/m);
      // Volatile fields are deliberately absent: these files are committed and a
      // pre-commit hook regenerates them, so a clock would diff every commit.
      expect(text, rel).not.toMatch(/^%% git_sha:/m);
      expect(text, rel).not.toMatch(/^%% generated_at:/m);
      expect(text, rel).toMatch(/GENERATED FILE/);
    }
  });

  it('the header never contains a bare %% line', async () => {
    // A line that is exactly `%%` is read as the start of a `%%{init}%%`
    // directive and breaks the parse. Verified against mermaid@11.16.1 — every
    // artifact failed to parse until this was fixed.
    for (const rel of ['graph/threat-graph.mmd', 'graph/dataflow.mmd', 'graph/attack-surface.mmd']) {
      const text = await readFile(join(root, '.guardlink', rel), 'utf-8');
      expect(text.split('\n').filter(l => l === '%%'), rel).toEqual([]);
    }
  });

  it('the header sits above the diagram and can be stripped back to generator output', async () => {
    const text = await readFile(join(root, '.guardlink/graph/threat-graph.mmd'), 'utf-8');
    expect(stripHeader(text)).toMatch(/^%%\{init:|^graph |^flowchart /);
    expect(stripHeader(text)).not.toMatch(/GENERATED FILE/);
  });

  it('the recorded hash is the model hash', async () => {
    const text = await readFile(join(root, '.guardlink/graph/threat-graph.mmd'), 'utf-8');
    expect(readArtifactHash(text)).toBe(computeAnnotationHash(canonicalizeModelOrder(model)));
  });

  it('mermaidHeader points at git for the facts it does not store', () => {
    const text = mermaidHeader('x.mmd', { annotation_hash: 'h', generator: 'g' });
    expect(text).toMatch(/ask git/);
    expect(text).not.toMatch(/generated_at/);
  });
});

describe('GL-302 — drift detection', () => {
  let root: string;
  let model: ThreatModel;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-drift-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    ({ model } = await parseProject({ root, project: 'art' }));
  });

  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  it('freshly emitted artifacts are clean', () => {
    emitArtifacts({ root, model });
    expect(checkArtifactDrift(root, model)).toEqual([]);
  });

  it('an edited annotation makes every artifact stale', async () => {
    emitArtifacts({ root, model });
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('[critical]', '[low]'));
    const { model: after } = await parseProject({ root, project: 'art' });

    const findings = checkArtifactDrift(root, after);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.kind).toBe('stale');
      expect(f.found).not.toBe(f.expected);
    }
  });

  it('regenerating clears the drift', async () => {
    emitArtifacts({ root, model });
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('[critical]', '[low]'));
    const { model: after } = await parseProject({ root, project: 'art' });
    expect(checkArtifactDrift(root, after).length).toBeGreaterThan(0);
    emitArtifacts({ root, model: after });
    expect(checkArtifactDrift(root, after)).toEqual([]);
  });

  it('a cosmetic source edit does NOT make artifacts stale', async () => {
    // The hash covers annotation content, so reformatting around an annotation
    // must not raise a false alarm — an alarm that cries wolf gets ignored.
    emitArtifacts({ root, model });
    await writeFile(join(root, 'src', 'api.ts'), SOURCE + '\nexport const unrelated = 1;\n');
    const { model: after } = await parseProject({ root, project: 'art' });
    expect(checkArtifactDrift(root, after)).toEqual([]);
  });

  it('a missing graph/ directory is reported as missing, not as clean', () => {
    const findings = checkArtifactDrift(root, model);
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe('missing');
  });

  it('an artifact with no header is reported, not silently trusted', async () => {
    emitArtifacts({ root, model });
    const path = join(root, '.guardlink/graph/threat-graph.mmd');
    await writeFile(path, stripHeader(await readFile(path, 'utf-8')));
    const findings = checkArtifactDrift(root, model);
    expect(findings.some(f => f.kind === 'unheadered')).toBe(true);
  });

  it('hand-editing the diagram body does not hide drift', async () => {
    // Drift compares the recorded hash against the model, not the bytes. Editing
    // the body cannot silence it; editing the header to match would be forging
    // the claim, which is why the README says never to do it.
    emitArtifacts({ root, model });
    const path = join(root, '.guardlink/graph/threat-graph.mmd');
    await writeFile(path, await readFile(path, 'utf-8') + '\n  hand_edited["oops"]\n');
    expect(checkArtifactDrift(root, model)).toEqual([]);   // body edits are not the signal…

    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('[critical]', '[low]'));
    const { model: after } = await parseProject({ root, project: 'art' });
    expect(checkArtifactDrift(root, after).length).toBeGreaterThan(0);   // …annotation drift is
  });
});
