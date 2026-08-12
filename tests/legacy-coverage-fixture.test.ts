/**
 * A report written by GuardLink ≤1.4.5 must still read correctly.
 *
 * Model 1.2.0 reshaped `coverage`: `annotated_symbols` became `annotation_count`,
 * and the two permanently-constant fields beside it were removed. `guardlink
 * merge` reads report JSON from disk, which is the one path where a current
 * binary meets an older repo's output — and where the reshape first drew blood:
 *
 *   combined.coverage.annotation_count += m.coverage.annotation_count
 *   //                                     ^ undefined on a 1.1.0 report
 *   // 0 += undefined === NaN, and JSON.stringify(NaN) === "null"
 *
 * A workspace dashboard reported `"annotation_count": null`, exit 0, no warning.
 *
 * The obvious repair — coalesce the missing field to 0 — stops the NaN by
 * inventing a number for a repo that had a real one. These tests assert the
 * VALUE, not just that it is finite, because 0 would pass a weaker assertion
 * while still being wrong.
 *
 * The fixture is frozen on purpose; see its README. Nothing here may regenerate it.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { annotationCount, normalizeCoverage } from '../src/parser/coverage.js';
import { combineModels } from '../src/workspace/merge.js';
import type { ThreatModel } from '../src/types/index.js';

const FIXTURE = join(
  dirname(fileURLToPath(import.meta.url)),
  'fixtures', 'legacy-coverage-1.1.0', 'report-1.1.0.json',
);

/** The frozen 1.1.0 report, fresh each time — normalizeCoverage mutates. */
function legacyReport(): ThreatModel {
  return JSON.parse(readFileSync(FIXTURE, 'utf-8'));
}

/** The count the fixture actually carries, so the expectations cannot drift from it. */
const EXPECTED = legacyReport().annotations_parsed;

describe('the frozen 1.1.0 fixture is still in its frozen shape', () => {
  it('carries the pre-1.2.0 coverage block, not the current one', () => {
    const coverage = legacyReport().coverage as Record<string, unknown>;
    expect(Object.keys(coverage).sort()).toEqual(
      ['annotated_symbols', 'coverage_percent', 'total_symbols', 'unannotated_critical'],
    );
    expect(coverage).not.toHaveProperty('annotation_count');
    expect(legacyReport().version).toBe('1.1.0');
    // If this fails, someone regenerated the fixture. Restore it; do not update this.
    expect(EXPECTED).toBeGreaterThan(0);
  });
});

describe('annotationCount reads the 1.1.0 spelling', () => {
  it('returns the real count, not a coalesced zero', () => {
    expect(annotationCount(legacyReport())).toBe(EXPECTED);
  });

  it('0 would be the quiet wrong answer — assert it is not that', () => {
    expect(annotationCount(legacyReport())).not.toBe(0);
  });

  it('falls back to annotations_parsed when coverage carries neither spelling', () => {
    const m = legacyReport();
    (m as unknown as { coverage: unknown }).coverage = { coverage_percent: 50 };
    expect(annotationCount(m)).toBe(EXPECTED);
  });

  it('returns 0 only when nothing in the model knows the count', () => {
    const m = legacyReport();
    (m as unknown as { coverage: unknown }).coverage = {};
    (m as unknown as { annotations_parsed: unknown }).annotations_parsed = undefined;
    expect(annotationCount(m)).toBe(0);
  });
});

describe('normalizeCoverage rewrites 1.1.0 into the current shape', () => {
  it('produces exactly the two current fields', () => {
    const n = normalizeCoverage(legacyReport());
    expect(Object.keys(n.coverage).sort()).toEqual(['annotation_count', 'coverage_percent']);
  });

  it('carries the count across rather than resetting it', () => {
    const n = normalizeCoverage(legacyReport());
    expect(n.coverage.annotation_count).toBe(EXPECTED);
    expect(n.coverage.coverage_percent).toBe(100);
  });

  it('survives JSON round-tripping without becoming null', () => {
    const round = JSON.parse(JSON.stringify(normalizeCoverage(legacyReport())));
    expect(round.coverage.annotation_count).toBe(EXPECTED);
    expect(round.coverage.annotation_count).not.toBeNull();
  });
});

describe('merging the frozen report is the regression this all exists for', () => {
  it('two 1.1.0 reports merge to a real total, never NaN or null', () => {
    const merged = combineModels([
      { repo: 'alpha', model: normalizeCoverage(legacyReport()), source_path: 'a.json' },
      { repo: 'beta', model: normalizeCoverage(legacyReport()), source_path: 'b.json' },
    ]);
    expect(Number.isNaN(merged.coverage.annotation_count)).toBe(false);
    expect(merged.coverage.annotation_count).toBe(EXPECTED * 2);
    expect(JSON.parse(JSON.stringify(merged)).coverage.annotation_count).not.toBeNull();
  });

  it('a 1.1.0 report merged with a current one totals both', () => {
    const current = normalizeCoverage(legacyReport());
    current.version = '1.2.0';
    const merged = combineModels([
      { repo: 'old', model: normalizeCoverage(legacyReport()), source_path: 'old.json' },
      { repo: 'new', model: current, source_path: 'new.json' },
    ]);
    expect(merged.coverage.annotation_count).toBe(EXPECTED * 2);
  });
});
