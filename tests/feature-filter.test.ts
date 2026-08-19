/**
 * Feature filtering — relations are file-scoped, definitions are not.
 *
 * The bug these guard: `@asset`/`@threat`/`@control`/`@actor` live in
 * `.guardlink/definitions.*` by project convention, and that file carries no
 * `@feature`. Filtering every collection by file therefore dropped the entire
 * node vocabulary, and a feature view rendered relationships whose endpoints had
 * no declaration — empty asset heatmap, no threat names or severities, diagrams
 * of bare ids. Measured on this repo before the fix: `--feature "Dashboard"`
 * kept 2 exposures and 0 of 16 assets, 0 of 15 threats, 0 of 12 controls.
 *
 * So the assertions below are mostly about what must SURVIVE the filter, not
 * what it removes.
 */

import { describe, it, expect } from 'vitest';
import { filterByFeature, listFeatures, getFeatureSummaries, countAnnotations } from '../src/parser/feature-filter.js';
import type { ThreatModel } from '../src/types/index.js';

const at = (file: string, line = 1) => ({ file, line });

/** Definitions in the conventional untagged file; relations in two feature files. */
function model(): ThreatModel {
  const DEFS = '.guardlink/definitions.ts';
  return {
    version: '1.0.0', project: 'test', generated_at: '', source_files: 3,
    annotated_files: [DEFS, 'src/pay.ts', 'src/auth.ts'], unannotated_files: [], annotations_parsed: 0,
    assets: [
      { path: ['App', 'Pay'], id: 'pay', description: 'Payments', location: at(DEFS) },
      { path: ['App', 'Auth'], id: 'auth', description: 'Auth', location: at(DEFS) },
      { path: ['App', 'Unrelated'], id: 'unrelated', location: at(DEFS) },
    ],
    threats: [
      { name: 'SQL_Injection', canonical_name: 'sql_injection', id: 'sqli', severity: 'critical', external_refs: ['cwe:CWE-89'], location: at(DEFS) },
      { name: 'Cross_Site_Scripting', canonical_name: 'cross_site_scripting', id: 'xss', severity: 'high', external_refs: [], location: at(DEFS) },
    ],
    controls: [
      { name: 'Prepared_Statements', canonical_name: 'prepared_statements', id: 'prepared-stmts', location: at(DEFS) },
      { name: 'Rate_Limiting', canonical_name: 'rate_limiting', id: 'rate-limit', location: at(DEFS) },
    ],
    actors: [
      { name: 'Payments_Admin', canonical_name: 'payments_admin', id: 'pay-admin', location: at(DEFS) },
      { name: 'Someone_Else', canonical_name: 'someone_else', id: 'other', location: at(DEFS) },
    ],
    entitlements: [
      { actor: '#pay-admin', capability: 'refund', canonical_capability: 'refund', asset: '#pay', threat: '#sqli',
        inert: false, imprecise: false, citation: { file: 'src/authz.ts', line: 9, raw: 'src/authz.ts:9' }, location: at('src/pay.ts') },
    ],
    mitigations: [{ asset: '#pay', threat: '#sqli', control: '#prepared-stmts', location: at('src/pay.ts') }],
    exposures: [
      { asset: '#pay', threat: '#sqli', severity: 'critical', external_refs: [], location: at('src/pay.ts') },
      { asset: '#auth', threat: '#xss', severity: 'high', external_refs: [], location: at('src/auth.ts') },
    ],
    confirmed: [], acceptances: [], transfers: [],
    flows: [{ source: 'User', target: '#pay', location: at('src/pay.ts') }],
    boundaries: [], validations: [], audits: [], ownership: [],
    data_handling: [{ classification: 'financial', asset: '#pay', location: at('src/pay.ts') }],
    assumptions: [], shields: [],
    features: [
      { feature: 'Payments', location: at('src/pay.ts') },
      { feature: 'Login', location: at('src/auth.ts') },
    ],
    comments: [],
    coverage: { total_symbols: 0, annotated_symbols: 0, coverage_percent: 0, unannotated_critical: [] },
  } as unknown as ThreatModel;
}

describe('filterByFeature — definitions survive the filter', () => {
  it('keeps the asset a kept relation references, though it is declared elsewhere', () => {
    const f = filterByFeature(model(), ['Payments']);
    expect(f.assets.map(a => a.id)).toEqual(['pay']);
  });

  it('keeps the threat, with its name and severity intact', () => {
    const f = filterByFeature(model(), ['Payments']);
    expect(f.threats).toHaveLength(1);
    // The bare id was all a diagram had before; the name and severity are what
    // make the node render as anything other than "⚪ sqli".
    expect(f.threats[0].name).toBe('SQL_Injection');
    expect(f.threats[0].severity).toBe('critical');
  });

  it('keeps the control named by a kept @mitigates', () => {
    const f = filterByFeature(model(), ['Payments']);
    expect(f.controls.map(c => c.id)).toEqual(['prepared-stmts']);
  });

  it('keeps the actor behind a kept @entitles', () => {
    const f = filterByFeature(model(), ['Payments']);
    expect((f.actors || []).map(a => a.id)).toEqual(['pay-admin']);
  });

  it('every kept exposure resolves to a definition — the property that was broken', () => {
    for (const name of ['Payments', 'Login']) {
      const f = filterByFeature(model(), [name]);
      for (const e of f.exposures) {
        expect(f.assets.some(a => `#${a.id}` === e.asset), `${name}: asset ${e.asset}`).toBe(true);
        expect(f.threats.some(t => `#${t.id}` === e.threat), `${name}: threat ${e.threat}`).toBe(true);
      }
    }
  });
});

describe('filterByFeature — it is still a filter', () => {
  it('drops definitions no kept relation references', () => {
    const f = filterByFeature(model(), ['Payments']);
    expect(f.assets.map(a => a.id)).not.toContain('unrelated');
    expect(f.threats.map(t => t.id)).not.toContain('xss');
    expect(f.controls.map(c => c.id)).not.toContain('rate-limit');
    expect((f.actors || []).map(a => a.id)).not.toContain('other');
  });

  it('keeps relations file-scoped', () => {
    const f = filterByFeature(model(), ['Payments']);
    expect(f.exposures).toHaveLength(1);
    expect(f.exposures[0].asset).toBe('#pay');
    expect(f.flows).toHaveLength(1);
    expect(f.data_handling).toHaveLength(1);
  });

  it('selects a different slice for a different feature', () => {
    const f = filterByFeature(model(), ['Login']);
    expect(f.exposures.map(e => e.asset)).toEqual(['#auth']);
    expect(f.assets.map(a => a.id)).toEqual(['auth']);
    expect(f.threats.map(t => t.id)).toEqual(['xss']);
    // Nothing in src/auth.ts mitigates, so no control is pulled in.
    expect(f.controls).toHaveLength(0);
  });

  it('matches feature names case-insensitively', () => {
    expect(filterByFeature(model(), ['payments']).exposures).toHaveLength(1);
  });

  it('an unknown feature selects nothing at all', () => {
    const f = filterByFeature(model(), ['Nope']);
    expect(f.exposures).toHaveLength(0);
    expect(f.assets).toHaveLength(0);
    expect(f.threats).toHaveLength(0);
  });
});

/**
 * The second bug: a filtered model kept reporting the PROJECT's metadata, so a
 * consumer rendered feature-scoped contents under project-scoped numbers.
 * Measured on this repo with `--feature "Dashboard"`: `annotations_parsed` 442,
 * `source_files` 87, `unannotated_files` 21 and `coverage.percent` 76 — all
 * unchanged from the full model — above an Executive Summary listing 1 asset.
 */
describe('filterByFeature — metadata describes the feature, not the project', () => {
  /** Sum the annotation arrays by hand, the way a consumer would. */
  const countByHand = (m: ThreatModel) =>
    m.assets.length + m.threats.length + m.controls.length + (m.actors?.length || 0) +
    (m.entitlements?.length || 0) + m.mitigations.length + m.exposures.length +
    m.confirmed.length + m.acceptances.length + m.transfers.length + m.flows.length +
    m.boundaries.length + m.validations.length + m.audits.length + m.ownership.length +
    m.data_handling.length + m.assumptions.length + m.shields.length +
    m.features.length + m.comments.length;

  it('annotations_parsed counts what the model actually holds', () => {
    const f = filterByFeature(model(), ['Payments']);
    // src/pay.ts: @entitles, @mitigates, @exposes, @flows, @handles, @feature = 6
    // resolved from definitions.ts: 1 asset, 1 threat, 1 control, 1 actor = 4
    expect(f.annotations_parsed).toBe(10);
  });

  it('annotations_parsed equals what a caller gets counting the arrays themselves', () => {
    for (const names of [['Payments'], ['Login'], ['Payments', 'Login'], ['Nope']]) {
      const f = filterByFeature(model(), names);
      expect(f.annotations_parsed, names.join('+')).toBe(countByHand(f));
    }
  });

  it('counts a collection added later without being told about it', () => {
    // The guard against the counter rotting: `annotations_parsed` is derived
    // from the model's shape, so a future @verb collection is counted the day
    // it lands rather than the day someone remembers to extend a list.
    const f = filterByFeature(model(), ['Payments']) as ThreatModel & Record<string, unknown>;
    const withNewKind = { ...f, wishes: [{ wish: 'x', location: at('src/pay.ts') }] } as unknown as ThreatModel;
    expect(countAnnotations(withNewKind)).toBe(f.annotations_parsed + 1);
  });

  it('source_files is the feature file count, not the project file count', () => {
    const m = model();
    expect(m.source_files).toBe(3);
    const f = filterByFeature(m, ['Payments']);
    expect(f.source_files).toBe(1);
    expect(f.source_files).toBe(f.annotated_files.length);
    expect(f.annotated_files).toEqual(['src/pay.ts']);
  });

  it('unannotated_files is empty — a feature is made of annotated files', () => {
    const m = model();
    m.unannotated_files = ['src/never-annotated.ts', 'src/other.ts'];
    expect(filterByFeature(m, ['Payments']).unannotated_files).toEqual([]);
  });

  it('coverage does not report the project percentage', () => {
    const m = model();
    m.coverage = { annotation_count: 999, coverage_percent: 76 } as ThreatModel['coverage'];
    const f = filterByFeature(m, ['Payments']);
    // Zeroed rather than recomputed: every file in a feature is annotated by
    // construction, so a recomputation could only ever say 100%.
    expect(f.coverage.coverage_percent).toBe(0);
    // The count, unlike the percentage, has an honest feature-level value.
    expect(f.coverage.annotation_count).toBe(f.annotations_parsed);
  });

  it('marks itself as filtered, and an unfiltered model does not', () => {
    expect(model().filtered_by_features).toBeUndefined();
    expect(filterByFeature(model(), ['Payments']).filtered_by_features).toEqual(['Payments']);
    // Case is preserved as requested, so a view can echo what the user typed.
    expect(filterByFeature(model(), ['payments']).filtered_by_features).toEqual(['payments']);
  });

  it('does not alias the caller\'s array', () => {
    const names = ['Payments'];
    const f = filterByFeature(model(), names);
    names.push('Login');
    expect(f.filtered_by_features).toEqual(['Payments']);
  });

  it('an unfiltered model is untouched — the filter mutates nothing', () => {
    const m = model();
    filterByFeature(m, ['Payments']);
    expect(m.filtered_by_features).toBeUndefined();
    expect(m.source_files).toBe(3);
    expect(m.annotated_files).toHaveLength(3);
    expect(m.assets).toHaveLength(3);
  });

  it('file-scopes external_refs, and leaves the key absent when it was', () => {
    expect('external_refs' in filterByFeature(model(), ['Payments'])).toBe(false);
    const m = model();
    m.external_refs = [
      { tag: '#lib.a', context_verb: 'mitigates', location: at('src/pay.ts') },
      { tag: '#lib.b', context_verb: 'exposes', location: at('src/auth.ts') },
    ] as ThreatModel['external_refs'];
    const f = filterByFeature(m, ['Payments']);
    expect((f.external_refs || []).map(r => r.tag)).toEqual(['#lib.a']);
    // A cross-repo ref is derived from the annotation that names the tag, so it
    // must not inflate the annotation count.
    expect(f.annotations_parsed).toBe(10);
  });

  it('keeps parse provenance and the project prompt', () => {
    const m = model();
    m.metadata = { schema_version: '1.2.0', guardlink_version: '2.0.0', repo: 'test',
      commit_sha: 'abc', branch: 'main', generated_at: '', annotation_hash: 'sha256-v1:ff' } as ThreatModel['metadata'];
    m.prompt = 'This project does X.';
    const f = filterByFeature(m, ['Payments']);
    expect(f.metadata?.annotation_hash).toBe('sha256-v1:ff');
    expect(f.prompt).toBe('This project does X.');
    expect(f.project).toBe('test');
  });
});

describe('filterByFeature — more than one feature at a time', () => {
  it('unions the slices', () => {
    const f = filterByFeature(model(), ['Payments', 'Login']);
    expect(f.exposures.map(e => e.asset).sort()).toEqual(['#auth', '#pay']);
    expect(f.assets.map(a => a.id).sort()).toEqual(['auth', 'pay']);
    expect(f.threats.map(t => t.id).sort()).toEqual(['sqli', 'xss']);
    // Still a filter: the unreferenced definitions stay out.
    expect(f.assets.map(a => a.id)).not.toContain('unrelated');
    expect(f.controls.map(c => c.id)).not.toContain('rate-limit');
  });

  it('metadata describes the union', () => {
    const f = filterByFeature(model(), ['Payments', 'Login']);
    expect(f.annotated_files.sort()).toEqual(['src/auth.ts', 'src/pay.ts']);
    expect(f.source_files).toBe(2);
    expect(f.unannotated_files).toEqual([]);
    expect(f.filtered_by_features).toEqual(['Payments', 'Login']);
    // 6 in src/pay.ts + 2 in src/auth.ts (@exposes, @feature) + 6 definitions
    // referenced (2 assets, 2 threats, 1 control, 1 actor).
    expect(f.annotations_parsed).toBe(14);
  });

  it('an unknown name alongside a known one changes nothing', () => {
    const both = filterByFeature(model(), ['Payments', 'Nope']);
    const one = filterByFeature(model(), ['Payments']);
    expect(both.annotations_parsed).toBe(one.annotations_parsed);
    expect(both.annotated_files).toEqual(one.annotated_files);
  });

  it('an unknown feature reports an empty model, not the project', () => {
    const f = filterByFeature(model(), ['Nope']);
    expect(f.annotations_parsed).toBe(0);
    expect(f.source_files).toBe(0);
    expect(f.annotated_files).toEqual([]);
    expect(f.unannotated_files).toEqual([]);
    expect(f.coverage.coverage_percent).toBe(0);
    expect(f.filtered_by_features).toEqual(['Nope']);
  });
});

describe('getFeatureSummaries — counts stay honest', () => {
  it('counts only annotations located in the feature, not definitions pulled in', () => {
    const [payments] = getFeatureSummaries(model()).filter(s => s.name === 'Payments');
    // src/pay.ts holds: @entitles, @mitigates, @exposes, @flows, @handles, @feature = 6.
    // The 1 asset, 1 threat, 1 control and 1 actor it references live in
    // definitions.ts and must not inflate this.
    expect(payments.annotations).toBe(6);
  });

  it('reports referenced definitions separately, which used to always be zero', () => {
    const [payments] = getFeatureSummaries(model()).filter(s => s.name === 'Payments');
    expect(payments.assets).toBe(1);
    expect(payments.threats).toBe(1);
    expect(payments.exposures).toBe(1);
  });

  it('is not the same question as annotations_parsed', () => {
    // The two counts must stay apart: `annotations_parsed` describes the model
    // returned by the filter (definitions resolved in from definitions.ts
    // included), the summary describes what is written in the feature.
    const [payments] = getFeatureSummaries(model()).filter(s => s.name === 'Payments');
    expect(filterByFeature(model(), ['Payments']).annotations_parsed).toBe(10);
    expect(payments.annotations).toBe(6);
  });

  it('counts a definition that is declared inside the feature\'s own file', () => {
    // It is located in the feature, so it is an annotation of the feature —
    // the "definitions live elsewhere" convention is a convention, not a rule.
    const m = model();
    m.assets = m.assets.map(a => a.id === 'pay' ? { ...a, location: at('src/pay.ts') } : a);
    const [payments] = getFeatureSummaries(m).filter(s => s.name === 'Payments');
    expect(payments.annotations).toBe(7);
    expect(payments.assets).toBe(1);
  });

  it('lists both features', () => {
    expect(listFeatures(model())).toEqual(['Login', 'Payments']);
  });
});
