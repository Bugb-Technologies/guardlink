import { describe, it, expect } from 'vitest';
import { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from '../src/dashboard/diagrams.js';
import { computeExposures } from '../src/dashboard/data.js';
import type { ThreatModel } from '../src/types/index.js';

function emptyModel(overrides: Partial<ThreatModel> = {}): ThreatModel {
  return {
    version: '1.0.0', project: 'test', generated_at: '', source_files: 0,
    annotations_parsed: 0, assets: [], threats: [], controls: [],
    mitigations: [], exposures: [], acceptances: [], transfers: [],
    flows: [], boundaries: [], validations: [], audits: [], ownership: [],
    data_handling: [], assumptions: [], shields: [], comments: [],
    coverage: { total_symbols: 0, annotated_symbols: 0, coverage_percent: 0, unannotated_critical: [] },
    ...overrides,
  };
}

const loc = { file: 'test.ts', line: 1 };

// ─── Mermaid label sanitization ──────────────────────────────────────

describe('generateThreatGraph', () => {
  it('sanitizes parentheses and backticks in labels', () => {
    const model = emptyModel({
      threats: [{ name: 'SQL_Injection (OWASP)', canonical_name: 'sql_injection', severity: 'high', external_refs: [], location: loc }],
      exposures: [{ asset: 'App.API', threat: 'SQL_Injection (OWASP)', severity: 'high', external_refs: [], location: loc }],
    });
    const mermaid = generateThreatGraph(model);
    // Parentheses should be stripped to avoid Mermaid syntax breakage
    expect(mermaid).not.toContain('(OWASP)');
    // The name content should still appear (sans parens)
    expect(mermaid).toContain('SQL_Injection OWASP');
  });

  it('resolves severity for #id refs when threat has id', () => {
    const model = emptyModel({
      threats: [{ name: 'XSS', canonical_name: 'xss', id: 'xss', severity: 'critical', external_refs: [], location: loc }],
      exposures: [{ asset: 'App', threat: '#xss', severity: 'critical', external_refs: [], location: loc }],
    });
    const mermaid = generateThreatGraph(model);
    // Critical threats get the red icon
    expect(mermaid).toContain('🔴');
  });

  it('does not create #undefined keys when threat has no id', () => {
    const model = emptyModel({
      threats: [{ name: 'CSRF', canonical_name: 'csrf', severity: 'high', external_refs: [], location: loc }],
      exposures: [{ asset: 'App', threat: 'CSRF', severity: 'high', external_refs: [], location: loc }],
    });
    const mermaid = generateThreatGraph(model);
    expect(mermaid).not.toContain('undefined');
    expect(mermaid).toContain('🟠'); // high severity icon
  });

  it('uses threat definition name when exposure references #id', () => {
    const model = emptyModel({
      threats: [{ name: 'SQL_Injection', canonical_name: 'sql_injection', id: 'sqli', severity: 'high', external_refs: [], location: loc }],
      exposures: [{ asset: 'App.API', threat: '#sqli', severity: 'high', external_refs: [], location: loc }],
    });
    const mermaid = generateThreatGraph(model);
    expect(mermaid).toContain('SQL_Injection');
    expect(mermaid).not.toContain(' sqli');
  });

  it('renders mitigation edge even when mitigation has no control', () => {
    const model = emptyModel({
      threats: [{ name: 'CSRF', canonical_name: 'csrf', severity: 'high', external_refs: [], location: loc }],
      exposures: [{ asset: 'App', threat: 'CSRF', severity: 'high', external_refs: [], location: loc }],
      mitigations: [{ asset: 'App', threat: 'CSRF', location: loc }],
    });
    const mermaid = generateThreatGraph(model);
    expect(mermaid).toContain('-. mitigates .->');
  });

  it('renders transfer edges for threat risk movement', () => {
    const model = emptyModel({
      threats: [{ name: 'Data_Breach', canonical_name: 'data_breach', severity: 'high', external_refs: [], location: loc }],
      exposures: [{ asset: 'Internal.API', threat: 'Data_Breach', severity: 'high', external_refs: [], location: loc }],
      transfers: [{ source: 'Internal.API', target: 'Insurer', threat: 'Data_Breach', location: loc }],
    });
    const mermaid = generateThreatGraph(model);
    expect(mermaid).toContain('transfers risk: Data_Breach');
    expect(mermaid).toContain('Insurer');
  });

  it('renders validation links from controls to assets', () => {
    const model = emptyModel({
      validations: [{ control: '#input_validation', asset: 'App.API', location: loc }],
    });
    const mermaid = generateThreatGraph(model);
    expect(mermaid).toContain('🛡️ input_validation');
    expect(mermaid).toContain('-. validates .->');
  });
});

// ─── Data Flow Diagram: boundary zones ───────────────────────────────

describe('generateDataFlowDiagram', () => {
  it('places boundary sides in separate subgraphs', () => {
    const model = emptyModel({
      boundaries: [{ asset_a: 'External.Internet', asset_b: 'Internal.DMZ', description: 'Firewall', location: loc }],
      flows: [{ source: 'External.Internet', target: 'Internal.DMZ', mechanism: 'HTTPS', location: loc }],
    });
    const mermaid = generateDataFlowDiagram(model);
    // Each side should be in its own subgraph (Z0 and Z1)
    const subgraphCount = (mermaid.match(/subgraph /g) || []).length;
    expect(subgraphCount).toBe(2);
    // Boundary edge should exist between them
    expect(mermaid).toContain('-.-|');
  });

  it('returns empty string when no flows', () => {
    const model = emptyModel();
    expect(generateDataFlowDiagram(model)).toBe('');
  });

  it('keeps long flow mechanism labels untruncated', () => {
    const longMechanism = 'HTTPS + mTLS + JWT verification + request signing + replay protection';
    const model = emptyModel({
      flows: [{ source: 'App.Frontend', target: 'App.API', mechanism: longMechanism, location: loc }],
    });
    const mermaid = generateDataFlowDiagram(model);
    expect(mermaid).toContain(longMechanism);
    expect(mermaid).not.toContain('…');
  });

  it('uses protocol-aware icon for flow mechanisms', () => {
    const model = emptyModel({
      flows: [{ source: 'App.Frontend', target: 'App.API', mechanism: 'HTTPS/443', location: loc }],
    });
    const mermaid = generateDataFlowDiagram(model);
    expect(mermaid).toContain('🔐 HTTPS/443');
  });

  it('renders slash-prefixed mechanism labels using quoted edge text', () => {
    const model = emptyModel({
      flows: [{ source: 'User.Browser', target: '_frontend', mechanism: '/ route', location: loc }],
    });
    const mermaid = generateDataFlowDiagram(model);
    expect(mermaid).toContain('-- "📡 / route" -->');
    expect(mermaid).not.toContain('--|📡 / route|');
  });
});

// ─── Attack Surface: ref normalization ───────────────────────────────

describe('generateAttackSurface', () => {
  it('normalizes refs when matching mitigations to exposures', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
      mitigations: [{ asset: 'app', threat: 'xss', location: loc }],
    });
    const mermaid = generateAttackSurface(model);
    // The exposure should be marked as resolved (strikethrough style)
    expect(mermaid).toContain('✅');
  });

  it('returns empty string when no exposures', () => {
    const model = emptyModel();
    expect(generateAttackSurface(model)).toBe('');
  });
});

// ─── computeExposures: ref normalization ─────────────────────────────

describe('computeExposures', () => {
  it('matches mitigations with normalized refs', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
      mitigations: [{ asset: 'app', threat: 'xss', location: loc }],
    });
    const rows = computeExposures(model);
    expect(rows).toHaveLength(1);
    expect(rows[0].mitigated).toBe(true);
  });

  it('matches acceptances with normalized refs', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
      acceptances: [{ asset: 'app', threat: 'xss', location: loc }],
    });
    const rows = computeExposures(model);
    expect(rows).toHaveLength(1);
    expect(rows[0].accepted).toBe(true);
  });

  it('does not match when refs are genuinely different', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
      mitigations: [{ asset: 'other', threat: 'csrf', location: loc }],
    });
    const rows = computeExposures(model);
    expect(rows[0].mitigated).toBe(false);
  });
});
