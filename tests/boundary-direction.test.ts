/**
 * The directed `@boundary from <outer> to <inner>` (SPEC §3.2 `@boundary`,
 * Direction): parsed inline and from `.gal` sidecars, recorded in the model,
 * part of the claim's identity and the annotation hash, checked by validation,
 * reported by diff, and taught to agents. The undirected `between` and `|`
 * forms are pinned unchanged alongside it.
 *
 * The SARIF half lives in tests/sarif-pentest.test.ts and the published corpus
 * in tests/conformance-boundaries.test.ts.
 *
 * @validates #input-sanitize for #parser -- "A directed boundary parses only as from <outer> to <inner>; every mixed or partial form is reported as malformed, never read as a boundary"
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { parseLine } from '../src/parser/parse-line.js';
import { parseProject } from '../src/parser/parse-project.js';
import { findUnresolvedBoundarySides } from '../src/parser/validate.js';
import { canonicalAnnotationRecords, computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { diffModels } from '../src/diff/engine.js';
import { formatDiff } from '../src/diff/format.js';
import { lookup } from '../src/mcp/lookup.js';
import { buildAnnotatePrompt } from '../src/agents/prompts.js';
import { getPlaybook } from '../src/playbooks/index.js';
import { agentInstructions, referenceDocContent } from '../src/init/templates.js';
import type { ThreatModel, ThreatModelBoundary } from '../src/types/index.js';

const at = { file: 'app/web.ts', line: 3 };
const line = (text: string) => parseLine(text, at);

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

async function parseFiles(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'gl-boundary-direction-'));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return parseProject({ root, project: 'boundary-direction' });
}

const DEFINITIONS = [
  '// @asset App.Web (#web) -- "Public HTTP API"',
  '// @asset App.Db (#db) -- "Order database"',
  'export {};',
].join('\n');

// ─── Grammar ─────────────────────────────────────────────────────────

describe('parsing the directed form', () => {
  it('reads from <outer> to <inner> as a directed pair, outer first', () => {
    const r = line('@boundary from Client to #web (#edge) -- "Nothing before this point is trusted"');
    expect(r.diagnostic).toBeNull();
    expect(r.annotation).toMatchObject({
      verb: 'boundary', asset_a: 'Client', asset_b: '#web', id: 'edge', directed: true,
      description: 'Nothing before this point is trusted',
    });
  });

  it('takes every endpoint form the undirected one does, with id and description optional', () => {
    expect(line('@boundary from #api to #db').annotation).toMatchObject({ asset_a: '#api', asset_b: '#db', directed: true });
    expect(line('@boundary from External.Internet to App.Api (#perimeter)').annotation)
      .toMatchObject({ asset_a: 'External.Internet', asset_b: 'App.Api', id: 'perimeter', directed: true });
    expect(line('@boundary from "User Browser" to "Backend API"').annotation)
      .toMatchObject({ asset_a: 'User Browser', asset_b: 'Backend API', directed: true });
    expect(line('@boundary from #web to #billing.charge -- "Cross-repo inner side"').annotation)
      .toMatchObject({ asset_a: '#web', asset_b: '#billing.charge', directed: true });
  });

  it('leaves the between and pipe forms undirected, with no directed field at all', () => {
    for (const text of [
      '@boundary between Client and #web (#edge) -- "d"',
      '@boundary Client and #web',
      '@boundary Client | #web (#edge)',
    ]) {
      const a = line(text).annotation as Record<string, unknown>;
      expect(a).toMatchObject({ verb: 'boundary', asset_a: 'Client', asset_b: '#web' });
      expect('directed' in a).toBe(false);
    }
  });

  it('reports every partial or mixed form as a malformed annotation', () => {
    for (const text of [
      '@boundary from #api',
      '@boundary from #api to',
      '@boundary from #api and #db',
      '@boundary between #api to #db',
      '@boundary from #api -> #db',
      '@boundary to #db from #api',
      '@boundary from #api to #db to #cache',
      '@boundary #api to #db',
      '@boundary from Client',
    ]) {
      const r = line(text);
      expect(r.annotation, text).toBeNull();
      expect(r.diagnostic, text).toMatchObject({ level: 'error', code: 'malformed-annotation' });
    }
  });

  it('keeps prose that merely contains from or to a warning, not an error', () => {
    for (const text of [
      '@boundary is used to mark a trust change',
      '@boundary annotations come from the spec',
    ]) {
      expect(line(text).diagnostic, text).toMatchObject({ level: 'warning', code: 'prose-like' });
    }
  });
});

describe('the model', () => {
  it('records directed: true for the directed form, inline and in a .gal sidecar, and nothing for the undirected forms', async () => {
    const { model, diagnostics } = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'app/web.ts': [
        '// @boundary from Client to #web (#edge) -- "inline"',
        '// @boundary between #web and #db (#data) -- "undirected"',
        'export const web = 1;',
      ].join('\n'),
      'app/db.ts': 'export const db = 1;\n',
      '.guardlink/annotations/app/db.ts.gal': [
        '@source file:app/db.ts line:1',
        '@boundary from #web to #db (#store) -- "sidecar"',
      ].join('\n'),
    });
    expect(diagnostics.filter(d => d.level === 'error')).toEqual([]);
    const byId = Object.fromEntries(model.boundaries.map(b => [b.id, b]));
    expect(byId.edge).toMatchObject({ asset_a: 'Client', asset_b: '#web', directed: true });
    expect(byId.store).toMatchObject({ asset_a: '#web', asset_b: '#db', directed: true });
    expect(byId.store.location).toMatchObject({ file: 'app/db.ts', origin_file: '.guardlink/annotations/app/db.ts.gal' });
    expect('directed' in byId.data).toBe(false);
  });
});

// ─── Identity ────────────────────────────────────────────────────────

const boundary = (b: Partial<ThreatModelBoundary>): ThreatModel => ({
  boundaries: [{ asset_a: '#api', asset_b: '#db', id: 'data', description: 'd', location: { file: 'a.ts', line: 1 }, ...b }],
} as unknown as ThreatModel);

describe('identity: annotation hash and claim key', () => {
  it('hashes an undirected boundary exactly as before the directed form existed', () => {
    const SEP = String.fromCharCode(1);
    expect(canonicalAnnotationRecords(boundary({}))).toEqual([['boundary', '#api', '#db', 'data', 'd', 'a.ts'].join(SEP)]);
  });

  it('changes the hash and the claim key when a direction is declared, and when it is reversed', () => {
    const undirected = boundary({});
    const directed = boundary({ directed: true });
    const reversed = boundary({ asset_a: '#db', asset_b: '#api', directed: true });
    const hashes = new Set([undirected, directed, reversed].map(m => computeAnnotationHash(m)));
    expect(hashes.size).toBe(3);
    const keys = new Set([undirected, directed, reversed].map(m => relationRecords(m)[0].key));
    expect(keys.size).toBe(3);
  });

  it('renders the claim in the form it was written', () => {
    expect(relationRecords(boundary({})).map(r => r.claim)).toEqual(['between #api and #db (#data)']);
    expect(relationRecords(boundary({ directed: true })).map(r => r.claim)).toEqual(['from #api to #db (#data)']);
  });
});

// ─── Validation ──────────────────────────────────────────────────────

describe('findUnresolvedBoundarySides', () => {
  it('accepts sides that are declared assets, by id or path, or @flows endpoints', async () => {
    const { model } = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'app/web.ts': [
        '// @flows Client -> #web via HTTPS',
        '// @boundary from Client to #web (#edge)',
        '// @boundary from App.Web to App.Db (#data)',
        '// @boundary from #web to #billing.charge (#remote) -- "resolved by guardlink merge, not here"',
        'export const web = 1;',
      ].join('\n'),
    });
    expect(findUnresolvedBoundarySides(model)).toEqual([]);
  });

  it('errors on a directed side that is no declared asset and no @flows endpoint, naming which side', async () => {
    const { model } = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'app/web.ts': [
        '// @boundary from Clinet to #web (#edge)',
        '// @boundary from #web to #dbb (#data)',
        '// @boundary from Nowhere to Nothing',
        'export const web = 1;',
      ].join('\n'),
    });
    const d = findUnresolvedBoundarySides(model);
    expect(d.map(x => [x.level, x.code, x.line])).toEqual([
      ['error', 'unresolved-boundary-side', 1],
      ['error', 'unresolved-boundary-side', 2],
      ['error', 'unresolved-boundary-side', 3],
    ]);
    expect(d[0].message).toContain('outer side Clinet resolves to no declared @asset');
    expect(d[1].message).toContain('inner side #dbb');
    expect(d[2].message).toContain('outer side Nowhere and inner side Nothing resolve');
  });

  it('never checks an undirected boundary, whose side is the convention to infer', async () => {
    const { model } = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'app/web.ts': '// @boundary between Nowhere and Nothing\nexport const web = 1;\n',
    });
    expect(findUnresolvedBoundarySides(model)).toEqual([]);
  });
});

// ─── Lookup ──────────────────────────────────────────────────────────

describe('guardlink_lookup "boundary for X"', () => {
  it('names the outer and inner side of a directed boundary, and adds nothing to an undirected one', async () => {
    const { model } = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'app/web.ts': [
        '// @boundary from Client to #web (#edge)',
        '// @boundary between #web and #db (#data)',
        'export const web = 1;',
      ].join('\n'),
    });
    const rows = lookup(model, 'boundary for #web').results as Record<string, unknown>[];
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ asset_a: 'Client', asset_b: '#web', directed: true, outer: 'Client', inner: '#web' });
    expect(Object.keys(rows[1])).toEqual(['asset_a', 'asset_b', 'description', 'file', 'line']);
  });
});

// ─── Diff ────────────────────────────────────────────────────────────

describe('diff', () => {
  const model = (b: Partial<ThreatModelBoundary>): ThreatModel => ({
    ...boundary(b),
    assets: [], threats: [], controls: [], mitigations: [], exposures: [], confirmed: [], acceptances: [], flows: [], transfers: [],
  } as unknown as ThreatModel);

  it('reports declaring, reversing and dropping a direction as a modification', () => {
    const undirected = model({});
    const directed = model({ directed: true });
    const reversed = model({ asset_a: '#db', asset_b: '#api', directed: true });
    const one = (a: ThreatModel, b: ThreatModel) => diffModels(a, b).boundaries;
    expect(one(undirected, directed)).toMatchObject([{ kind: 'modified', details: 'direction: undirected → from #api to #db' }]);
    expect(one(directed, reversed)).toMatchObject([{ kind: 'modified', details: 'direction: from #api to #db → from #db to #api' }]);
    expect(one(directed, undirected)).toMatchObject([{ kind: 'modified', details: 'direction: from #api to #db → undirected' }]);
    expect(one(undirected, undirected)).toEqual([]);
    expect(formatDiff(diffModels(undirected, directed))).toContain('~ #api → #db (outer → inner) (direction: undirected → from #api to #db)');
  });
});

// ─── What agents are taught ──────────────────────────────────────────

describe('agent material teaches the directed form', () => {
  it('the annotate prompt, the map playbook and the instruction templates', () => {
    const prompt = buildAnnotatePrompt('annotate the api', '/nonexistent', null, 'inline');
    expect(prompt).toContain('@boundary from <outer> to <inner>');
    expect(getPlaybook('map').body).toContain('@boundary from <outer> to <inner>');
    const project = { name: 'p', language: 'typescript', definitionsPath: '.guardlink/definitions.ts' } as any;
    expect(agentInstructions(project)).toContain('@boundary from #api to #db');
    expect(referenceDocContent(project)).toContain('@boundary from <Outer> to <Inner>');
  });
});
