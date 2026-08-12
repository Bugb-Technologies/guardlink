/**
 * D42 / D49 — the coverage numbers must mean what their names say.
 *
 * `CoverageStats` used to ship three fields that shared an object and nothing
 * else: `total_symbols` was never computed and was permanently 0,
 * `annotated_symbols` counts ANNOTATIONS, and `coverage_percent` is FILE
 * coverage. `types/index.ts` said all of that correctly, and none of it
 * travelled with the JSON — so both consumers that believed the field names
 * got it wrong:
 *
 *   D42  tui/commands.ts printed `Coverage: 105/0 symbols (100%)`
 *   D49  workspace/merge.ts recomputed percent as annotated/total. total is
 *        always 0, so the `: 0` fallback was the only branch that ever ran, and
 *        two repos at 89% merged to a workspace at 0%
 *
 * The contract now exists as code — `describeCoverage` — instead of only as a
 * doc comment the consumer never sees. Model version 1.2.0 then took the wire
 * change this file originally deferred: the two permanently-constant fields
 * are gone and `annotated_symbols` is `annotation_count`.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { describeCoverage, fileCoveragePercent, annotationCount, normalizeCoverage } from '../src/parser/coverage.js';
import { combineModels } from '../src/workspace/merge.js';
import type { ThreatModel } from '../src/types/index.js';

const roots: string[] = [];
afterEachCleanup();
function afterEachCleanup() {
  process.on('exit', () => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });
}

/** A repo with `annotated` annotated files and `bare` unannotated ones. */
async function repo(annotated: number, bare: number): Promise<ThreatModel> {
  const root = mkdtempSync(join(tmpdir(), 'gl-d42-'));
  roots.push(root);
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  mkdirSync(join(root, 'app'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.py'),
    '# @asset Svc.Api (#api) -- "api"\n# @threat Injection (#inj) [high] -- "inj"\n');
  for (let i = 0; i < annotated; i++) {
    writeFileSync(join(root, 'app', `a${i}.py`),
      `# @exposes #api to #inj [high] -- "site ${i}"\ndef f${i}(): pass\n`);
  }
  for (let i = 0; i < bare; i++) {
    writeFileSync(join(root, 'app', `b${i}.py`), `def g${i}(): pass\n`);
  }
  const { model } = await parseProject({ root, project: 'd42' });
  return model;
}

describe('D42 — coverage describes itself instead of being inferred', () => {
  it('names the numerator, the denominator and the unit', async () => {
    const model = await repo(3, 1);
    const cov = describeCoverage(model);
    expect(cov.kind).toBe('file');
    // 3 annotated sources + `.guardlink/definitions.py`, which carries the
    // @asset and @threat declarations and so counts as annotated itself.
    expect(cov.annotatedFiles).toBe(4);
    expect(cov.sourceFiles).toBe(model.source_files);
    expect(cov.sourceFiles).toBe(5); // the 4 above plus the one bare file
    expect(cov.percent).toBe(fileCoveragePercent(cov.annotatedFiles, cov.sourceFiles));
  });

  it('annotations are reported as a separate quantity, not a numerator', async () => {
    // The D42 misreading in one assertion: annotations and files are different
    // counts, and nothing divides one by the other.
    const model = await repo(3, 0);
    const cov = describeCoverage(model);
    expect(cov.annotations).toBe(model.annotations_parsed);
    expect(cov.annotations).not.toBe(cov.annotatedFiles);
  });

  it('the never-computed total_symbols is gone, not shipped as 0', async () => {
    const model = await repo(2, 2);
    expect(model.coverage).not.toHaveProperty('total_symbols');
    expect(model.coverage).not.toHaveProperty('unannotated_critical');
    expect(model.coverage.annotation_count).toBe(model.annotations_parsed);
    expect(describeCoverage(model).percent).toBeGreaterThan(0);
  });

  it('an empty repo is 0%, not NaN', () => {
    expect(fileCoveragePercent(0, 0)).toBe(0);
  });
});

describe('D49 — a merged workspace reports the coverage its repos report', () => {
  it('two repos at the same percent merge to that percent, not to 0', async () => {
    const a = await repo(3, 1);
    const b = await repo(3, 1);
    const each = describeCoverage(a).percent;
    expect(each).toBeGreaterThan(0);

    const m = combineModels([
      { repo: 'alpha', model: a, source_path: 'a.json' },
      { repo: 'beta', model: b, source_path: 'b.json' },
    ]);
    // The defect: this was 0 for any input, because total_symbols was always 0.
    expect(m.coverage.coverage_percent).not.toBe(0);
    expect(m.coverage.coverage_percent).toBe(
      fileCoveragePercent(m.annotated_files.length, m.source_files),
    );
    expect(m.coverage.coverage_percent).toBe(each);
  });

  it('the emitted field shape is the 1.2.0 shape — two real fields, no constants', async () => {
    const a = await repo(2, 0);
    const merged = combineModels([{ repo: 'alpha', model: a, source_path: 'a.json' }]);
    expect(Object.keys(merged.coverage).sort()).toEqual(
      ['annotation_count', 'coverage_percent'],
    );
    expect(merged.coverage.annotation_count).toBe(a.coverage.annotation_count);
  });
});

describe('a pre-1.2.0 report is still readable — the NaN that shipped for one turn', () => {
  /** A model as GuardLink ≤1.4.5 wrote it: `annotated_symbols`, plus two constants. */
  function legacy(model: ThreatModel): any {
    const m = JSON.parse(JSON.stringify(model));
    m.version = '1.1.0';
    m.coverage = {
      total_symbols: 0,
      annotated_symbols: model.coverage.annotation_count,
      coverage_percent: model.coverage.coverage_percent,
      unannotated_critical: [],
    };
    m.metadata = { ...(m.metadata || {}), schema_version: '1.0.0' };
    return m;
  }

  it('annotationCount reads the old spelling rather than inventing a zero', async () => {
    const m = await repo(3, 1);
    expect(annotationCount(legacy(m))).toBe(m.coverage.annotation_count);
    expect(annotationCount(legacy(m))).toBeGreaterThan(0);
  });

  it('normalizeCoverage rewrites the old block into the current one', async () => {
    const m = await repo(2, 1);
    const n = normalizeCoverage(legacy(m));
    expect(Object.keys(n.coverage).sort()).toEqual(['annotation_count', 'coverage_percent']);
    expect(n.coverage.annotation_count).toBe(m.coverage.annotation_count);
  });

  it('all four merge combinations produce a real count, never NaN', async () => {
    const a = await repo(3, 1);
    const b = await repo(3, 1);
    const each = a.coverage.annotation_count;
    expect(each).toBeGreaterThan(0);

    const combos: [string, any, any][] = [
      ['old+old', legacy(a), legacy(b)],
      ['old+new', legacy(a), b],
      ['new+old', a, legacy(b)],
      ['new+new', a, b],
    ];
    for (const [label, ma, mb] of combos) {
      const merged = combineModels([
        { repo: 'alpha', model: normalizeCoverage(JSON.parse(JSON.stringify(ma))), source_path: 'a.json' },
        { repo: 'beta', model: normalizeCoverage(JSON.parse(JSON.stringify(mb))), source_path: 'b.json' },
      ]);
      // `0 += undefined` is NaN, and JSON.stringify(NaN) is null — which is how
      // this reached a workspace dashboard as `"annotation_count": null`.
      expect(Number.isNaN(merged.coverage.annotation_count), label).toBe(false);
      expect(merged.coverage.annotation_count, label).toBe(each * 2);
      expect(JSON.parse(JSON.stringify(merged)).coverage.annotation_count, label).not.toBeNull();
    }
  });
});
