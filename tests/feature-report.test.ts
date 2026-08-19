/**
 * `guardlink report --feature X` — the document must say it is a slice.
 *
 * The bug: the markdown report rendered a filtered model with no indication that
 * anything had been filtered. Real output from this repo, four lines apart:
 *
 *     > Files scanned: 87 | Annotations: 442      ← the whole project
 *     ...
 *     | Assets | 1 |                              ← the feature
 *
 * and, in one sentence in the Scope section, both scopes at once:
 *
 *     covers **1 assets** and **2 threat categories** derived from
 *     **442 annotations** across **1** of **87** source files.
 *
 * A reader took "87 files, 442 annotations, 0 unmitigated exposures" at face
 * value. Nothing in the document — title, header, headings, footer, diagrams —
 * said the word "feature".
 *
 * So the assertions here are about what the *document* claims, not about what
 * the filter selects (tests/feature-filter.test.ts owns that). The two halves
 * that matter: a filtered report must name its feature everywhere a fact can be
 * read in isolation, and an unfiltered report must be exactly what it was.
 */

import { describe, it, expect } from 'vitest';
import { generateReport } from '../src/report/report.js';
import { generateMermaid } from '../src/report/mermaid.js';
import { generateSequenceDiagram } from '../src/report/sequence.js';
import type { ThreatModel, ThreatModelEntitlement } from '../src/types/index.js';

const at = (file: string, line = 1) => ({ file, line });
const DEFS = '.guardlink/definitions.ts';

/** A model narrowed to one feature is one carrying `filtered_by_features`. */
type Filtered = ThreatModel & { filtered_by_features?: string[] };

/**
 * A whole-project model: two features' worth of annotations, project-level
 * counts, and the prose `.guardlink/prompt.md` supplies.
 */
function projectModel(): ThreatModel {
  return {
    version: '1.0.0',
    project: 'testproj',
    generated_at: '2026-01-01T00:00:00.000Z',
    source_files: 87,
    annotations_parsed: 442,
    annotated_files: [DEFS, 'src/pay.ts', 'src/auth.ts'],
    unannotated_files: ['src/untouched.ts'],
    prompt: '# testproj — Project Description\n\nEverything this repository does.',
    assets: [
      { path: ['App', 'Pay'], id: 'pay', description: 'Payments', location: at(DEFS) },
      { path: ['App', 'Auth'], id: 'auth', description: 'Auth', location: at(DEFS) },
    ],
    threats: [
      { name: 'SQL_Injection', canonical_name: 'sql_injection', id: 'sqli', severity: 'critical', external_refs: [], location: at(DEFS) },
      { name: 'Cross_Site_Scripting', canonical_name: 'cross_site_scripting', id: 'xss', severity: 'high', external_refs: [], location: at(DEFS) },
    ],
    controls: [
      { name: 'Prepared_Statements', canonical_name: 'prepared_statements', id: 'prepared-stmts', location: at(DEFS) },
    ],
    actors: [
      { name: 'Payments_Admin', canonical_name: 'payments_admin', id: 'pay-admin', description: 'Refund desk', location: at(DEFS) },
    ],
    entitlements: [],
    mitigations: [{ asset: '#pay', threat: '#sqli', control: '#prepared-stmts', location: at('src/pay.ts') }],
    exposures: [
      { asset: '#pay', threat: '#sqli', severity: 'critical', external_refs: [], location: at('src/pay.ts') },
      { asset: '#auth', threat: '#xss', severity: 'high', external_refs: [], location: at('src/auth.ts') },
    ],
    confirmed: [], acceptances: [], transfers: [],
    flows: [{ source: 'User', target: '#pay', mechanism: 'HTTPS', location: at('src/pay.ts') }],
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

/**
 * The Payments slice, shaped the way `filterByFeature` returns it: relations
 * file-scoped, definitions resolved from the kept relations, counts and
 * `annotated_files` narrowed, `unannotated_files` emptied — plus the marker.
 */
function paymentsSlice(overrides: Partial<Filtered> = {}): Filtered {
  const m = projectModel();
  return {
    ...m,
    filtered_by_features: ['Payments'],
    source_files: 1,
    annotations_parsed: 5,
    annotated_files: ['src/pay.ts'],
    unannotated_files: [],
    assets: m.assets.filter(a => a.id === 'pay'),
    threats: m.threats.filter(t => t.id === 'sqli'),
    exposures: m.exposures.filter(e => e.asset === '#pay'),
    features: m.features.filter(f => f.feature === 'Payments'),
    ...overrides,
  } as Filtered;
}

const entitlement = (partial: Partial<ThreatModelEntitlement>): ThreatModelEntitlement => ({
  actor: '#pay-admin',
  capability: 'refund',
  canonical_capability: 'refund',
  inert: !partial.citation,
  imprecise: !(partial.asset && partial.threat),
  location: at('src/pay.ts', 9),
  ...partial,
});

// ═══════════════════════════════════════════════════════════════════════
// The report says it is a slice
// ═══════════════════════════════════════════════════════════════════════

describe('a filtered report names its feature', () => {
  it('in the title', () => {
    expect(generateReport(paymentsSlice()).split('\n')[0]).toContain('"Payments"');
  });

  it('in a banner before any number', () => {
    const md = generateReport(paymentsSlice());
    const banner = md.indexOf('FEATURE SLICE');
    expect(banner).toBeGreaterThan(-1);
    // Before the first count a reader could act on. A warning under the
    // Executive Summary is a warning nobody reaches in time.
    expect(banner).toBeLessThan(md.indexOf('| Assets |'));
  });

  it('in the footer', () => {
    expect(generateReport(paymentsSlice())).toMatch(/filtered to feature "Payments"[\s\S]*$/);
  });

  it('on every top-level heading, so a mid-document screenshot still says so', () => {
    const md = generateReport(paymentsSlice());
    const headings = md.split('\n').filter(l => /^## /.test(l) && !l.startsWith('## What'));
    expect(headings.length).toBeGreaterThan(5);
    for (const h of headings) {
      expect(h, `heading does not carry its scope: ${h}`).toMatch(/feature "Payments"|project-wide/);
    }
  });

  it('inside the Executive Summary table itself, which is what gets pasted into a ticket', () => {
    const md = generateReport(paymentsSlice());
    const table = md.slice(md.indexOf('## Executive Summary'), md.indexOf('## Threat Model Diagram'));
    expect(table).toContain('| **Scope** | **feature "Payments"** |');
  });

  it('names every feature when more than one was selected', () => {
    const md = generateReport(paymentsSlice({ filtered_by_features: ['Payments', 'Login'] }));
    expect(md.split('\n')[0]).toContain('"Payments", "Login"');
    expect(md).toContain('features "Payments", "Login"');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Project-wide facts do not masquerade as the feature's
// ═══════════════════════════════════════════════════════════════════════

describe('project-wide numbers never read as the feature\'s', () => {
  it('the header counts are relabelled, not just re-valued', () => {
    const md = generateReport(paymentsSlice());
    // "Files scanned" describes the repository walk. The value is feature-scoped
    // now, so the old label would be a true number under a false name.
    expect(md).not.toContain('Files scanned');
    expect(md).toContain('Files in slice: 1 | Annotations in slice: 5');
  });

  it('the Scope sentence no longer mixes the feature with the repository', () => {
    // Was: "covers **1 assets** … derived from **442 annotations** across **1**
    // of **87** source files" — five numbers, two scopes, one sentence.
    const md = generateReport(paymentsSlice());
    const sentence = md.split('\n').find(l => l.includes('It covers')) || '';
    expect(sentence).toContain('feature slice');
    expect(sentence).not.toContain('87');
    expect(sentence).not.toContain('442');
  });

  it('file coverage is refused rather than recomputed — a feature has no denominator', () => {
    const md = generateReport(paymentsSlice());
    expect(md).toContain('### Coverage — project-wide');
    expect(md).not.toMatch(/files have security annotations/);
    expect(md).not.toMatch(/files have no annotations/);
  });

  it('a stale unannotated_files list cannot leak a project count into the slice', () => {
    // Defence in depth: the contract says filterByFeature empties this, but the
    // report must not depend on it having done so.
    const md = generateReport(paymentsSlice({ unannotated_files: ['src/untouched.ts', 'src/other.ts'] }));
    expect(md).not.toMatch(/files have no annotations/);
  });

  it('the prompt.md narrative is fenced off as project-wide, not left to read as the feature', () => {
    const md = generateReport(paymentsSlice());
    expect(md).toContain('### Project Description — project-wide');
    expect(md).toContain('Everything this repository does.');
    const label = md.indexOf('### Project Description — project-wide');
    expect(label).toBeLessThan(md.indexOf('Everything this repository does.'));
  });

  it('an empty finding list is a statement about the slice, not about the project', () => {
    const md = generateReport(paymentsSlice());
    // "No trust boundaries defined." under a feature heading is a claim the
    // filtered model cannot support — they may all be one directory away.
    expect(md).not.toContain('_No trust boundaries defined.');
    expect(md).toContain('No trust boundaries in the "Payments" feature');
    expect(md).toMatch(/run `guardlink report` without `--feature` before concluding/);
  });

  it('Feature Tags reports the filter, not the project\'s feature inventory', () => {
    const md = generateReport(paymentsSlice());
    expect(md).toContain('This report was filtered to the feature(s) below.');
    expect(md).not.toContain('Annotations are tagged with the following features');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Exposure coverage — the arithmetic the slice exposed
// ═══════════════════════════════════════════════════════════════════════

describe('exposure coverage counts exposures answered, not annotations counted', () => {
  it('cannot exceed 100%', () => {
    // Measured on this repo: `--feature "Dashboard"` printed
    // "150% addressed (3 mitigated, 0 accepted)" against 2 exposures, because
    // the formula divided mitigations by exposures.
    const m = paymentsSlice();
    const md = generateReport({
      ...m,
      mitigations: [
        { asset: '#pay', threat: '#sqli', control: '#prepared-stmts', location: at('src/pay.ts', 1) },
        { asset: '#pay', threat: '#sqli', control: '#prepared-stmts', location: at('src/pay.ts', 2) },
        { asset: '#pay', threat: '#sqli', control: '#prepared-stmts', location: at('src/pay.ts', 3) },
      ],
    } as ThreatModel);
    const row = md.split('\n').find(l => l.startsWith('| Exposure coverage')) || '';
    expect(row).toContain('100% addressed');
    expect(Number(/(\d+)% addressed/.exec(row)?.[1])).toBeLessThanOrEqual(100);
  });

  it('agrees with the unmitigated-exposure count beside it', () => {
    const md = generateReport(paymentsSlice({ mitigations: [] } as Partial<Filtered>));
    expect(md).toContain('| Exposure coverage | 0% addressed (0 of 1 exposures');
    expect(md).toContain('| Unmitigated exposures | 1 (1 critical');
  });

  it('says "no exposures" rather than claiming 100% when the slice has none', () => {
    const md = generateReport(paymentsSlice({ exposures: [], mitigations: [] } as Partial<Filtered>));
    expect(md).toContain('no `@exposes` in the "Payments" feature');
    expect(md).not.toContain('100% addressed');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Principals and entitlements survive into the slice
// ═══════════════════════════════════════════════════════════════════════

describe('declared principals and entitlements render in a filtered report', () => {
  const cited = { file: 'src/authz.ts', line: 9, raw: 'src/authz.ts:9' };

  it('shows the principal and its claim', () => {
    const md = generateReport(paymentsSlice({
      entitlements: [entitlement({ asset: '#pay', threat: '#sqli', citation: cited })],
    }));
    expect(md).toContain('### Declared Principals');
    expect(md).toContain('**Payments_Admin** (`#pay-admin`)');
    expect(md).toContain('entitled to `refund` on #pay against #sqli');
  });

  it('shows both halves of the (actor, asset, threat) join, in the table too', () => {
    const md = generateReport(paymentsSlice({
      entitlements: [entitlement({ asset: '#pay', threat: '#sqli', citation: cited })],
    }));
    expect(md).toContain('| Actor | Capability | On asset | Against threat | Citation | Effect |');
    expect(md).toContain('| #pay-admin | `refund` | #pay | #sqli | `src/authz.ts:9` | can demote |');
  });

  it('a cited claim naming no threat is not shown as operative', () => {
    // The silent-false-negative shape: cited and precise-looking, joins nothing.
    // Rendering it identically to a complete claim is how an over-grant passes
    // review (§9.3).
    const md = generateReport(paymentsSlice({
      entitlements: [entitlement({ asset: '#pay', citation: cited })],
    }));
    expect(md).toContain('cannot demote: no threat');
    expect(md).not.toContain('can demote |');
    // …including under the principal, where the claim used to read as complete.
    const principals = md.slice(md.indexOf('### Declared Principals'), md.indexOf('### Customer'));
    expect(principals).toContain('against <no threat>');
    expect(principals).toContain('cannot demote');
  });

  it('an uncited claim is inert wherever it appears', () => {
    const md = generateReport(paymentsSlice({
      entitlements: [entitlement({ asset: '#pay', threat: '#sqli' })],
    }));
    expect(md).toContain('cannot demote: no citation');
    expect(md).toMatch(/⚠ 1 of 1 entitlement\(s\) cannot demote/);
  });

  it('counts every ineffective claim, not only the uncited ones', () => {
    const md = generateReport(paymentsSlice({
      entitlements: [
        entitlement({ asset: '#pay', threat: '#sqli', citation: cited }),          // effective
        entitlement({ asset: '#pay', citation: cited, capability: 'chargeback' }), // no threat
        entitlement({ asset: '#pay', threat: '#sqli', capability: 'void' }),       // uncited
      ],
    }));
    expect(md).toMatch(/⚠ 2 of 3 entitlement\(s\) cannot demote/);
  });

  it('joins a claim to its principal through the same normalisation the parser uses', () => {
    // `@entitles Payments_Admin` against `canonical_name: payments_admin` — a
    // literal comparison dropped the claim from its principal while the filter,
    // which compares case-insensitively, had kept the actor.
    const md = generateReport(paymentsSlice({
      entitlements: [entitlement({ actor: 'Payments_Admin', asset: '#pay', threat: '#sqli', citation: cited })],
    }));
    const principals = md.slice(md.indexOf('### Declared Principals'), md.indexOf('### Customer'));
    expect(principals).toContain('entitled to `refund`');
    expect(principals).not.toContain('_no entitlements recorded_');
  });

  it('says so when a slice reaches no principals, instead of omitting the section', () => {
    const md = generateReport(paymentsSlice({ actors: [], entitlements: [] } as Partial<Filtered>));
    expect(md).toContain('### Declared Principals');
    expect(md).toContain('No `@actor` or `@entitles` annotations in the "Payments" feature');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Diagrams
// ═══════════════════════════════════════════════════════════════════════

describe('diagrams built from a filtered model', () => {
  it('title themselves as a slice', () => {
    expect(generateMermaid(paymentsSlice())).toContain('title: "Feature slice — Payments');
    expect(generateSequenceDiagram(paymentsSlice())).toContain('title: "Feature slice — Payments');
  });

  it('keep the feature\'s only edge', () => {
    // A two-node diagram is a fine answer; a diagram that drops the one flow the
    // feature has is not.
    const mmd = generateMermaid(paymentsSlice());
    expect(mmd).toContain('User -->|"HTTPS"| _pay');
  });

  it('render something parseable when the slice is empty', () => {
    // `--feature` with a name nothing carries selects zero of everything, and a
    // bare `graph TD` is a Mermaid parse error — an errored block is
    // indistinguishable from a broken tool.
    const empty = paymentsSlice({
      filtered_by_features: ['Nope'],
      assets: [], threats: [], exposures: [], mitigations: [], flows: [],
      data_handling: [], features: [], annotated_files: [], source_files: 0, annotations_parsed: 0,
    } as Partial<Filtered>);
    const mmd = generateMermaid(empty);
    expect(mmd.split('\n').filter(l => l.trim() && !l.startsWith('---') && !l.startsWith('title:') && l !== 'graph TD').length)
      .toBeGreaterThan(0);
    expect(mmd).toContain("No annotated components in feature 'Nope'");
  });

  it('declare the participant they annotate when there are no flows', () => {
    // `Note over System` named a participant that was never declared, so the
    // "nothing to show" case rendered as a parse error.
    const seq = generateSequenceDiagram(paymentsSlice({ flows: [] } as Partial<Filtered>));
    expect(seq).toContain('participant System');
    expect(seq.indexOf('participant System')).toBeLessThan(seq.indexOf('Note over System'));
    expect(seq).toContain('No @flows in feature Payments');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// The normal path is untouched
// ═══════════════════════════════════════════════════════════════════════

describe('an unfiltered report is what it always was', () => {
  const md = () => generateReport(projectModel());

  it('says nothing about features or slices', () => {
    const out = md();
    expect(out.split('\n')[0]).toBe('# Threat Model Report — testproj');
    expect(out).not.toContain('FEATURE SLICE');
    expect(out).not.toContain('feature slice');
    expect(out).not.toContain('project-wide');
    expect(out).not.toContain('| **Scope** |');
    for (const h of out.split('\n').filter(l => l.startsWith('## '))) {
      expect(h).not.toMatch(/— features? "/);
    }
  });

  it('keeps the project header and coverage section', () => {
    const out = md();
    expect(out).toContain('> Files scanned: 87 | Annotations: 442');
    expect(out).toContain('- **3** of **87** files have security annotations (3%)');
    expect(out).toContain('- **1** files have no annotations');
  });

  it('keeps the untouched empty-state wording', () => {
    expect(md()).toContain('_No trust boundaries defined. If multi-tenant, add `@boundary` annotations to document tenant isolation._');
    expect(md()).toContain('_No multi-tenancy annotations found. If this is a multi-tenant application,');
  });

  it('emits no Mermaid frontmatter', () => {
    expect(generateMermaid(projectModel()).split('\n')[0]).toBe('graph TD');
    expect(generateSequenceDiagram(projectModel()).split('\n')[0]).toBe('sequenceDiagram');
  });

  it('a model without the marker takes the unfiltered path, whatever the field holds', () => {
    // The field is optional and arrives from another module; an absent, empty or
    // malformed value must not turn the project report into a slice.
    for (const value of [undefined, [], ['   '], 'Payments' as unknown as string[]]) {
      const out = generateReport({ ...projectModel(), filtered_by_features: value } as ThreatModel);
      expect(out.split('\n')[0], String(value)).toBe('# Threat Model Report — testproj');
      expect(out, String(value)).not.toContain('FEATURE SLICE');
    }
  });
});
