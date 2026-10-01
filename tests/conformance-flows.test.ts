/**
 * The published @flows conformance corpus, run against this parser.
 *
 * `conformance/flows.json` is what other readers of GuardLink annotations test
 * against (conformance/README.md), and SPEC §3.2 `@flows` and §3.6 are what it
 * pins. Running it here is what keeps the three in agreement: a parser change
 * that moves a record fails this file before it can ship a corpus that no
 * longer describes the reference implementation.
 *
 * @validates #input-sanitize for #parser -- "Every conforming @flows form yields its specified records, and every malformed one yields a diagnostic rather than a dropped line"
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { buildCoverageIndex } from '../src/parser/coverage.js';
import { canonicaliser } from '../src/parser/canonical-ref.js';
import { buildRouteIndex } from '../src/parser/route.js';
import type { ThreatModel, ThreatModelFlow } from '../src/types/index.js';

interface Site { file: string; line: number }
interface CorpusCase<E> { id: string; rule: string; about?: string; files: Record<string, string>; expect: E }
interface Corpus {
  corpus: string;
  version: number;
  parse: CorpusCase<{ flows: unknown[]; malformed: Site[] }>[];
  route_attribution: CorpusCase<{ exposure: Site; route: unknown }[]>[];
  mitigation_scope: CorpusCase<{ open: Site[]; covered: Site[] }>[];
}

const corpus: Corpus = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'flows.json'), 'utf-8'));

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

async function parseCase(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'gl-conformance-'));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return parseProject({ root, project: 'conformance' });
}

/** A flow record in the corpus's shape: every field present, absence as null. */
function record(f: ThreatModelFlow) {
  return {
    source: f.source,
    target: f.target,
    mechanism: f.mechanism ?? null,
    route: f.route ?? null,
    description: f.description ?? null,
    location: {
      file: f.location.file,
      line: f.location.line,
      origin_file: f.location.origin_file ?? null,
      origin_line: f.location.origin_line ?? null,
    },
  };
}

/** Files are parsed concurrently, so order records by site; hops on one line keep their order. */
const bySite = <T extends { location: { file: string; line: number; origin_line: number | null } }>(rows: T[]) =>
  [...rows].sort((a, b) => a.location.file.localeCompare(b.location.file)
    || a.location.line - b.location.line
    || (a.location.origin_line ?? 0) - (b.location.origin_line ?? 0));

const exposureAt = (model: ThreatModel, site: Site) => {
  const e = model.exposures.find(x => x.location.file === site.file && x.location.line === site.line);
  if (!e) throw new Error(`corpus names an exposure at ${site.file}:${site.line} and the model has none`);
  return e;
};

describe(`conformance corpus ${corpus.corpus} v${corpus.version}`, () => {
  it('has a unique id on every case', () => {
    const ids = [...corpus.parse, ...corpus.route_attribution, ...corpus.mitigation_scope].map(c => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe('parse', () => {
    for (const c of corpus.parse) {
      it(c.id, async () => {
        const { model, diagnostics } = await parseCase(c.files);
        expect(bySite(model.flows.map(record))).toEqual(bySite(c.expect.flows as ReturnType<typeof record>[]));
        const malformed = diagnostics
          .filter(d => d.code === 'malformed-annotation' && /@flows/.test(d.message))
          .map(d => ({ file: d.file, line: d.line }))
          .sort((a, b) => a.line - b.line);
        expect(malformed).toEqual(c.expect.malformed);
      });
    }
  });

  describe('route attribution', () => {
    for (const c of corpus.route_attribution) {
      it(c.id, async () => {
        const { model } = await parseCase(c.files);
        const routes = buildRouteIndex(model.flows, canonicaliser(model));
        for (const want of c.expect) {
          const e = exposureAt(model, want.exposure);
          const got = routes.routeFor(e.asset, e.location);
          const shaped = got === null ? null
            : got.status === 'ambiguous'
              ? { status: 'ambiguous', candidates: got.candidates.map(r => ({ method: r.method, path: r.path, file: r.file, line: r.line })) }
              : { status: 'attributed', scope: got.scope, route: { method: got.route.method, path: got.route.path } };
          expect(shaped, `${want.exposure.file}:${want.exposure.line}`).toEqual(want.route);
        }
      });
    }
  });

  describe('mitigation scope', () => {
    for (const c of corpus.mitigation_scope) {
      it(c.id, async () => {
        const { model } = await parseCase(c.files);
        const coverage = buildCoverageIndex(model);
        for (const site of c.expect.open) expect(coverage.isMitigated(exposureAt(model, site)), `${site.file}:${site.line} open`).toBe(false);
        for (const site of c.expect.covered) expect(coverage.isMitigated(exposureAt(model, site)), `${site.file}:${site.line} covered`).toBe(true);
      });
    }
  });
});
