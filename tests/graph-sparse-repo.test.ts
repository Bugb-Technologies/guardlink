/**
 * D34 — guardlink_graph on a LARGE SPARSE repo.
 *
 * The bug: `selectSubgraph` returns `{...model, <filtered arrays>}`. The spread
 * carried `unannotated_files` through untouched while every relation array
 * around it was filtered, so a neighbourhood query returned the whole repo's
 * file inventory. Measured on specter-v1 (8142 files, 48 annotated): a resolved
 * depth-2 query emitted 709.5 KB of which 654.8 KB was file paths, and a query
 * that resolved NOTHING — 0 nodes, 0 edges — still emitted 687.4 KB.
 *
 * Why no existing test saw it: every one of them parses THIS repo, where 23
 * unannotated files are 0.8% of the payload and the leak is invisible. The
 * corpus was the blind spot, not the coverage. So this file builds its own
 * corpus — a repo whose file count is deliberately decoupled from its
 * annotation count — and asserts the property that actually matters:
 *
 *     the graph payload scales with the GRAPH, never with the repo.
 *
 * It is written as a scaling assertion rather than a fixed byte budget on
 * purpose. A budget would need re-tuning whenever the model grows and would
 * pass again the moment someone raised it; comparing two repos that differ
 * ONLY in unannotated file count cannot be satisfied by any leak at all.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { selectSubgraph, traverseGraph, summariseGraphPayload, withoutFileInventory } from '../src/mcp/subgraph.js';
import type { ThreatModel } from '../src/types/index.js';

const DEFINITIONS = `
// @asset Sparse.Api (#sparse-api) -- "Front door"
// @asset Sparse.Db (#sparse-db) -- "Storage"
// @threat Injection (#sparse-injection) [high] -- "Untrusted input reaches the query"
// @control Prepared_Statements (#sparse-prepared) -- "Parameterised queries"
`.trimStart();

const ANNOTATED_SOURCE = `
/**
 * @exposes #sparse-api to #sparse-injection [high] cwe:CWE-89 -- "Query built by concatenation"
 * @mitigates #sparse-db against #sparse-injection using #sparse-prepared -- "Placeholders only"
 * @flows #sparse-api -> #sparse-db via query -- "Read path"
 */
export const q = 1;
`.trimStart();

/** A repo with exactly one flow edge and `filler` files that carry nothing. */
function buildRepo(filler: number): string {
  const root = mkdtempSync(join(tmpdir(), `gl-sparse-${filler}-`));
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  writeFileSync(join(root, 'annotated.ts'), ANNOTATED_SOURCE);
  mkdirSync(join(root, 'src'), { recursive: true });
  for (let i = 0; i < filler; i++) {
    // Long, realistic-looking paths: the leak's cost is bytes of path, not rows.
    writeFileSync(
      join(root, 'src', `module_with_a_reasonably_long_name_${i}.ts`),
      `export const value${i} = ${i};\n`,
    );
  }
  return root;
}

const emit = (model: ThreatModel, from: string, detail: 'full' | 'summary') => {
  const options = { from, depth: 2, direction: 'both' as const };
  const traversal = traverseGraph(model, options);
  const sub = selectSubgraph(model, options);
  const payload = detail === 'full'
    ? { traversal, model: sub }
    : summariseGraphPayload({ traversal, model: sub });
  const text = JSON.stringify(withoutFileInventory(payload, model.unannotated_files.length), null, 2);
  return { text, bytes: Buffer.byteLength(text), traversal, sub };
};

const SMALL = 50;
const LARGE = 2000;

let small: ThreatModel;
let large: ThreatModel;
const roots: string[] = [];

beforeAll(async () => {
  const a = buildRepo(SMALL); const b = buildRepo(LARGE);
  roots.push(a, b);
  ({ model: small } = await parseProject({ root: a, project: 'sparse-small' }));
  ({ model: large } = await parseProject({ root: b, project: 'sparse-large' }));
}, 120_000);

afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

describe('D34 — the graph payload scales with the graph, not the repo', () => {
  it('builds two repos with the same graph and very different file counts', () => {
    expect(small.unannotated_files.length).toBeGreaterThanOrEqual(SMALL);
    expect(large.unannotated_files.length).toBeGreaterThanOrEqual(LARGE);
    // Same threat model on both sides — only the filler differs.
    expect(large.flows.length).toBe(small.flows.length);
    expect(large.assets.length).toBe(small.assets.length);
  });

  for (const detail of ['full', 'summary'] as const) {
    it(`a RESOLVED query emits the same bytes on both repos (detail=${detail})`, () => {
      const s = emit(small, '#sparse-api', detail);
      const l = emit(large, '#sparse-api', detail);
      expect(s.traversal.start?.resolved).toBe(true);
      expect(l.traversal.start?.resolved).toBe(true);
      expect(l.traversal.nodes.length).toBe(s.traversal.nodes.length);
      // 40x the files. Before the fix this ratio was the file-count ratio.
      expect(l.bytes / s.bytes).toBeLessThan(1.05);
    });

    it(`an UNRESOLVED query emits almost nothing on a large repo (detail=${detail})`, () => {
      const l = emit(large, '#no-such-asset-anywhere', detail);
      expect(l.traversal.start?.resolved).toBe(false);
      expect(l.traversal.nodes).toHaveLength(0);
      expect(l.traversal.edges).toHaveLength(0);
      // A traversal that found nothing must not cost more than a few KB.
      // Before the fix this was 687 KB on specter-v1.
      expect(l.bytes).toBeLessThan(5 * 1024);
    });
  }

  it('no unannotated file path appears anywhere in the payload', () => {
    for (const from of ['#sparse-api', '#no-such-asset-anywhere']) {
      for (const detail of ['full', 'summary'] as const) {
        const { text } = emit(large, from, detail);
        expect(text).not.toContain('module_with_a_reasonably_long_name_');
      }
    }
  });

  it('the model returned by selectSubgraph carries no repo file inventory', () => {
    const { sub } = emit(large, '#sparse-api', 'full');
    // Still a ThreatModel — the type is the contract other consumers rely on.
    expect(Array.isArray(sub.unannotated_files)).toBe(true);
    expect(sub.unannotated_files).toHaveLength(0);
    // annotated_files stays: filtered to the subgraph, and it answers "where do
    // I go to read this".
    expect(sub.annotated_files.length).toBeGreaterThan(0);
    expect(sub.annotated_files.length).toBeLessThan(10);
  });

  it('says the field was omitted rather than leaving it absent or empty', () => {
    const { text } = emit(large, '#sparse-api', 'full');
    const payload = JSON.parse(text) as { model: Record<string, unknown> };
    expect(payload.model).not.toHaveProperty('unannotated_files');
    const marker = payload.model.unannotated_files_omitted as { count: number; reason: string };
    // Absent-because-omitted and absent-because-empty are different facts. The
    // count is the WHOLE REPO's, so a caller cannot read a sparse repo as clean.
    expect(marker.count).toBe(large.unannotated_files.length);
    expect(marker.count).toBeGreaterThanOrEqual(LARGE);
    expect(marker.reason).toContain('guardlink_unannotated');
  });

  it('the mermaid path never carried file paths in the first place', async () => {
    const { generateThreatGraph } = await import('../src/dashboard/index.js');
    const options = { from: '#sparse-api', depth: 2, direction: 'both' as const };
    const mmd = generateThreatGraph(selectSubgraph(large, options), { showAll: true });
    expect(mmd).not.toContain('module_with_a_reasonably_long_name_');
    expect(Buffer.byteLength(mmd)).toBeLessThan(5 * 1024);
  });
});
