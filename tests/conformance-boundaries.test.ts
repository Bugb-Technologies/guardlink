/**
 * The published @boundary conformance corpus, run against this parser and exporter.
 *
 * `conformance/boundaries.json` is what other readers of GuardLink annotations and
 * of its SARIF export test against (conformance/README.md); SPEC §3.2 `@boundary`
 * and §6.6/§6.8 are what it pins. Running it here keeps the three in agreement:
 * a change that moves a record, a side or a validation result fails this file
 * before it can ship a corpus that no longer describes the reference.
 *
 * Sides are checked twice — in `run.graphs[0]` and in the pentest profile's
 * boundary claims — because those are the two places a consumer reads them.
 *
 * @validates #input-sanitize for #parser -- "Every conforming @boundary form yields its specified record, and every malformed one yields a diagnostic rather than a dropped line"
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { findUnresolvedBoundarySides } from '../src/parser/validate.js';
import { generateSarif } from '../src/analyzer/sarif.js';
import type { ThreatModelBoundary } from '../src/types/index.js';

interface Site { file: string; line: number }
interface CorpusCase<E> { id: string; rule: string; about?: string; files: Record<string, string>; expect: E }
type Side = { basis: 'declared' | 'undeclared-endpoint'; outer: string; inner: string } | { basis: 'unknown' };
interface Corpus {
  corpus: string;
  version: number;
  parse: CorpusCase<{ boundaries: unknown[]; malformed: Site[] }>[];
  sides: CorpusCase<{ boundary: Site; side: Side }[]>[];
  validation: CorpusCase<{ unresolved: Site[] }>[];
}

const corpus: Corpus = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'boundaries.json'), 'utf-8'));

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

async function parseCase(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'gl-conformance-boundary-'));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return parseProject({ root, project: 'conformance' });
}

/** A boundary record in the corpus's shape: every field present, absence as null or false. */
function record(b: ThreatModelBoundary) {
  return {
    asset_a: b.asset_a,
    asset_b: b.asset_b,
    id: b.id ?? null,
    directed: b.directed === true,
    description: b.description ?? null,
    location: {
      file: b.location.file,
      line: b.location.line,
      origin_file: b.location.origin_file ?? null,
      origin_line: b.location.origin_line ?? null,
    },
  };
}

const bySite = <T extends { location: { file: string; line: number } }>(rows: T[]) =>
  [...rows].sort((a, b) => a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line);

describe(`conformance corpus ${corpus.corpus} v${corpus.version}`, () => {
  it('has a unique id on every case', () => {
    const ids = [...corpus.parse, ...corpus.sides, ...corpus.validation].map(c => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('covers directed, undirected and malformed lines', () => {
    const prefixes = new Set(corpus.parse.map(c => c.id.split('/')[0]));
    for (const p of ['directed', 'undirected', 'malformed']) expect(prefixes).toContain(p);
  });

  describe('parse', () => {
    for (const c of corpus.parse) {
      it(c.id, async () => {
        const { model, diagnostics } = await parseCase(c.files);
        expect(bySite(model.boundaries.map(record))).toEqual(bySite(c.expect.boundaries as ReturnType<typeof record>[]));
        const malformed = diagnostics
          .filter(d => d.code === 'malformed-annotation' && /@boundary/.test(d.message))
          .map(d => ({ file: d.file, line: d.line }))
          .sort((a, b) => a.line - b.line);
        expect(malformed).toEqual(c.expect.malformed);
      });
    }
  });

  describe('sides, as the SARIF export states them', () => {
    for (const c of corpus.sides) {
      it(c.id, async () => {
        const { model } = await parseCase(c.files);
        const run = generateSarif(model, [], [], { profile: 'pentest' }).runs[0];
        const claims = run.results.filter(r => r.ruleId === 'guardlink/boundary-claim');
        for (const want of c.expect) {
          const i = model.boundaries.findIndex(b => b.location.file === want.boundary.file && b.location.line === want.boundary.line);
          expect(i, `${want.boundary.file}:${want.boundary.line}`).toBeGreaterThan(-1);
          const p = claims[i].properties as Record<string, any>;
          // The export names sides by graph node id; the corpus by the side as written.
          const written = (node: string) => (node === p.boundary.a ? p.boundary.asset_a : p.boundary.asset_b);
          const side = (s: Record<string, any>): Side => (s.basis === 'unknown'
            ? { basis: 'unknown' }
            : { basis: s.basis, outer: written(s.outer), inner: written(s.inner) });
          expect(side(p.boundary)).toEqual(want.side);
          const edge = run.graphs![0].edges.find(e => e.id === p['guardlink/edge'])!;
          expect(side(edge.properties['guardlink/side'])).toEqual(want.side);
          expect(edge.properties['guardlink/directed']).toBe(want.side.basis === 'declared');
        }
      });
    }
  });

  describe('validation', () => {
    for (const c of corpus.validation) {
      it(c.id, async () => {
        const { model } = await parseCase(c.files);
        const got = findUnresolvedBoundarySides(model).map(d => ({ file: d.file, line: d.line }));
        expect(got).toEqual(c.expect.unresolved);
      });
    }
  });
});
