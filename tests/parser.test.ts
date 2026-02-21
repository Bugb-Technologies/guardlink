import { describe, it, expect } from 'vitest';
import { parseString } from '../src/parser/parse-file.js';
import { normalizeName, resolveSeverity, unescapeDescription } from '../src/parser/normalize.js';
import { stripCommentPrefix } from '../src/parser/comment-strip.js';
import { findDanglingRefs, findUnmitigatedExposures } from '../src/parser/validate.js';
import type { ThreatModel } from '../src/types/index.js';

// ─── Normalize ───────────────────────────────────────────────────────

describe('normalizeName', () => {
  it('normalizes various forms to canonical', () => {
    expect(normalizeName('SQL_Injection')).toBe('sql_injection');
    expect(normalizeName('sql-injection')).toBe('sql_injection');
    expect(normalizeName('SQL INJECTION')).toBe('sql_injection');
    expect(normalizeName('Sql_Injection')).toBe('sql_injection');
    expect(normalizeName('sql__injection')).toBe('sql_injection');
    expect(normalizeName('SQL-Injection')).toBe('sql_injection');
    expect(normalizeName('_leading_')).toBe('leading');
  });
});

describe('resolveSeverity', () => {
  it('resolves P-levels and words', () => {
    expect(resolveSeverity('P0')).toBe('critical');
    expect(resolveSeverity('p1')).toBe('high');
    expect(resolveSeverity('MEDIUM')).toBe('medium');
    expect(resolveSeverity('low')).toBe('low');
    expect(resolveSeverity('unknown')).toBeUndefined();
  });
});

describe('unescapeDescription', () => {
  it('unescapes quotes and backslashes', () => {
    expect(unescapeDescription('hello \\"world\\"')).toBe('hello "world"');
    expect(unescapeDescription('path\\\\to\\\\file')).toBe('path\\to\\file');
    expect(unescapeDescription('no escapes here')).toBe('no escapes here');
  });
});

// ─── Comment stripping ───────────────────────────────────────────────

describe('stripCommentPrefix', () => {
  it('strips // comments', () => {
    expect(stripCommentPrefix('// @asset Foo')).toBe('@asset Foo');
    expect(stripCommentPrefix('  // @asset Foo')).toBe('@asset Foo');
  });
  it('strips # comments', () => {
    expect(stripCommentPrefix('# @asset Foo')).toBe('@asset Foo');
  });
  it('strips -- comments', () => {
    expect(stripCommentPrefix('-- @asset Foo')).toBe('@asset Foo');
  });
  it('strips /* */ block comments', () => {
    expect(stripCommentPrefix('/* @asset Foo */')).toBe('@asset Foo');
  });
  it('strips * inside block comments', () => {
    expect(stripCommentPrefix(' * @asset Foo')).toBe('@asset Foo');
  });
  it('returns null for non-comments', () => {
    expect(stripCommentPrefix('const x = 1;')).toBeNull();
  });
});

// ─── Line parsing ────────────────────────────────────────────────────

describe('parseString', () => {
  it('parses @asset', () => {
    const { annotations } = parseString('// @asset App.Auth.Login (#login) -- "Login endpoint"');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('asset');
    const a = annotations[0] as any;
    expect(a.path).toBe('App.Auth.Login');
    expect(a.id).toBe('login');
    expect(a.description).toBe('Login endpoint');
  });

  it('parses @threat with severity and external refs', () => {
    const { annotations } = parseString(
      '// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 owasp:A03:2021 -- "Bad input"'
    );
    expect(annotations).toHaveLength(1);
    const t = annotations[0] as any;
    expect(t.verb).toBe('threat');
    expect(t.name).toBe('SQL_Injection');
    expect(t.canonical_name).toBe('sql_injection');
    expect(t.severity).toBe('critical');
    expect(t.external_refs).toEqual(['cwe:CWE-89', 'owasp:A03:2021']);
  });

  it('parses @mitigates with using', () => {
    const { annotations } = parseString(
      '// @mitigates App.Auth against #sqli using #prepared-stmts -- "Parameterized"'
    );
    expect(annotations).toHaveLength(1);
    const m = annotations[0] as any;
    expect(m.verb).toBe('mitigates');
    expect(m.asset).toBe('App.Auth');
    expect(m.threat).toBe('#sqli');
    expect(m.control).toBe('#prepared-stmts');
  });

  it('parses @exposes with severity and cwe', () => {
    const { annotations } = parseString(
      '// @exposes App.API to #idor [P1] cwe:CWE-639 -- "No ownership check"'
    );
    expect(annotations).toHaveLength(1);
    const e = annotations[0] as any;
    expect(e.verb).toBe('exposes');
    expect(e.severity).toBe('high');
    expect(e.external_refs).toEqual(['cwe:CWE-639']);
  });

  it('parses @accepts', () => {
    const { annotations } = parseString(
      '// @accepts #info-disclosure on App.Health -- "Public endpoint"'
    );
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('accepts');
  });

  it('parses @flows with arrow syntax', () => {
    const { annotations } = parseString(
      '// @flows App.Frontend -> App.API via HTTPS/443 -- "TLS 1.3"'
    );
    expect(annotations).toHaveLength(1);
    const f = annotations[0] as any;
    expect(f.verb).toBe('flows');
    expect(f.source).toBe('App.Frontend');
    expect(f.target).toBe('App.API');
    expect(f.mechanism).toBe('HTTPS/443');
  });

  it('parses @boundary', () => {
    const { annotations } = parseString(
      '// @boundary between External.Internet and Internal.DMZ (#perimeter) -- "WAF"'
    );
    expect(annotations).toHaveLength(1);
    const b = annotations[0] as any;
    expect(b.verb).toBe('boundary');
    expect(b.asset_a).toBe('External.Internet');
    expect(b.asset_b).toBe('Internal.DMZ');
    expect(b.id).toBe('perimeter');
  });

  it('parses @handles', () => {
    const { annotations } = parseString('// @handles pii on App.Users -- "Name, email"');
    expect(annotations).toHaveLength(1);
    const h = annotations[0] as any;
    expect(h.classification).toBe('pii');
    expect(h.asset).toBe('App.Users');
  });

  it('parses @comment with description', () => {
    const { annotations } = parseString('// @comment -- "Legacy auth flow, refactor planned"');
    expect(annotations).toHaveLength(1);
    const c = annotations[0] as any;
    expect(c.verb).toBe('comment');
    expect(c.description).toBe('Legacy auth flow, refactor planned');
  });

  it('parses @comment without description', () => {
    const { annotations } = parseString('// @comment');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('comment');
    expect(annotations[0].description).toBeUndefined();
  });

  it('parses @boundary pipe shorthand', () => {
    const { annotations } = parseString(
      '// @boundary External.Internet | Internal.DMZ (#perimeter) -- "Firewall"'
    );
    expect(annotations).toHaveLength(1);
    const b = annotations[0] as any;
    expect(b.verb).toBe('boundary');
    expect(b.asset_a).toBe('External.Internet');
    expect(b.asset_b).toBe('Internal.DMZ');
    expect(b.id).toBe('perimeter');
    expect(b.description).toBe('Firewall');
  });

  it('parses @boundary pipe shorthand without spaces around pipe', () => {
    const { annotations } = parseString('// @boundary Zone.A|Zone.B -- "Tight boundary"');
    expect(annotations).toHaveLength(1);
    const b = annotations[0] as any;
    expect(b.verb).toBe('boundary');
    expect(b.asset_a).toBe('Zone.A');
    expect(b.asset_b).toBe('Zone.B');
  });

  it('parses @shield and @shield:begin/@shield:end', () => {
    const { annotations } = parseString([
      '// @shield -- "Proprietary"',
      '// @shield:begin -- "Crypto block"',
      'function secret() {}',
      '// @shield:end',
    ].join('\n'));
    expect(annotations).toHaveLength(3);
    expect(annotations[0].verb).toBe('shield');
    expect(annotations[1].verb).toBe('shield:begin');
    expect(annotations[2].verb).toBe('shield:end');
  });

  // ── v1 compat ──

  it('parses v1 @mitigates with "with" keyword', () => {
    const { annotations } = parseString(
      '// @mitigates App.Auth against #sqli with #stmts -- "v1 syntax"'
    );
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('mitigates');
  });

  it('parses v1 @accepts with "to" keyword', () => {
    const { annotations } = parseString('// @accepts #risk to App.Health -- "v1"');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('accepts');
  });

  it('parses v1 @review as @audit', () => {
    const { annotations } = parseString('// @review App.Crypto -- "Check algo"');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('audit');
  });

  it('parses v1 @connects as @flows', () => {
    const { annotations } = parseString('// @connects App.A to App.B -- "Data flow"');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('flows');
  });

  // ── Multi-line descriptions ──

  it('handles multi-line continuation', () => {
    const { annotations } = parseString([
      '// @threat Session_Hijacking (#hijack) [P1]',
      '// -- "Attacker steals session token"',
      '// -- "Dangerous on shared networks"',
    ].join('\n'));
    expect(annotations).toHaveLength(1);
    expect(annotations[0].description).toBe(
      'Attacker steals session token Dangerous on shared networks'
    );
  });

  // ── Escaped descriptions ──

  it('unescapes description quotes', () => {
    const { annotations } = parseString(
      '// @threat XSS (#xss) -- "Injects \\"<script>\\" tags"'
    );
    expect(annotations).toHaveLength(1);
    expect(annotations[0].description).toBe('Injects "<script>" tags');
  });

  // ── Python comments ──

  it('parses Python-style comments', () => {
    const { annotations } = parseString('# @asset App.ML (#ml) -- "ML pipeline"');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('asset');
  });

  // ── Error diagnostics ──

  it('reports malformed annotations', () => {
    const { annotations, diagnostics } = parseString('// @mitigates');
    expect(annotations).toHaveLength(0);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0].level).toBe('error');
  });

  it('ignores non-guardlink @ annotations', () => {
    const { annotations, diagnostics } = parseString('// @param name The user name');
    expect(annotations).toHaveLength(0);
    expect(diagnostics).toHaveLength(0);
  });

  // ── Regression: @flows via + description ──

  it('@flows via does not swallow description', () => {
    const { annotations } = parseString(
      '// @flows App.Frontend -> App.API via HTTPS/443 -- "TLS 1.3"'
    );
    expect(annotations).toHaveLength(1);
    const f = annotations[0] as any;
    expect(f.mechanism).toBe('HTTPS/443');
    expect(f.description).toBe('TLS 1.3');
  });

  it('@flows via with multi-word mechanism preserves description', () => {
    const { annotations } = parseString(
      '// @flows App.A -> App.B via gRPC over TLS -- "Mutual TLS auth"'
    );
    expect(annotations).toHaveLength(1);
    const f = annotations[0] as any;
    expect(f.mechanism).toBe('gRPC over TLS');
    expect(f.description).toBe('Mutual TLS auth');
  });

  it('@flows without via still parses description', () => {
    const { annotations } = parseString(
      '// @flows App.A -> App.B -- "Direct connection"'
    );
    expect(annotations).toHaveLength(1);
    const f = annotations[0] as any;
    expect(f.mechanism).toBeUndefined();
    expect(f.description).toBe('Direct connection');
  });

  // ── Regression: @shield regex safety ──

  it('@shield does not match @shield:begin', () => {
    const { annotations } = parseString('// @shield:begin -- "Crypto block"');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('shield:begin');
  });

  it('@shield does not match @shield:end', () => {
    const { annotations } = parseString('// @shield:end');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('shield:end');
  });

  it('@shield alone parses correctly', () => {
    const { annotations } = parseString('// @shield -- "Proprietary"');
    expect(annotations).toHaveLength(1);
    expect(annotations[0].verb).toBe('shield');
  });
});

// ─── Validation: findDanglingRefs ─────────────────────────────────────

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

describe('findDanglingRefs', () => {
  it('detects dangling threat ref in @mitigates', () => {
    const model = emptyModel({
      mitigations: [{ asset: 'App', threat: '#missing', description: '', location: loc }],
    });
    const diags = findDanglingRefs(model);
    expect(diags).toHaveLength(1);
    expect(diags[0].message).toContain('#missing');
  });

  it('detects dangling asset ref in @exposes', () => {
    const model = emptyModel({
      threats: [{ name: 'XSS', canonical_name: 'xss', id: 'xss', severity: 'high', external_refs: [], location: loc }],
      exposures: [{ asset: '#missing-asset', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
    });
    const diags = findDanglingRefs(model);
    expect(diags).toHaveLength(1);
    expect(diags[0].message).toContain('#missing-asset');
  });

  it('detects dangling refs in @flows source/target', () => {
    const model = emptyModel({
      flows: [{ source: '#missing-src', target: '#missing-tgt', location: loc }],
    });
    const diags = findDanglingRefs(model);
    expect(diags).toHaveLength(2);
  });

  it('detects dangling asset ref in @handles', () => {
    const model = emptyModel({
      data_handling: [{ classification: 'pii', asset: '#ghost', location: loc }],
    });
    const diags = findDanglingRefs(model);
    expect(diags).toHaveLength(1);
    expect(diags[0].message).toContain('#ghost');
  });

  it('passes when all refs are defined', () => {
    const model = emptyModel({
      assets: [{ path: ['App'], id: 'app', location: loc }],
      threats: [{ name: 'XSS', canonical_name: 'xss', id: 'xss', severity: 'high', external_refs: [], location: loc }],
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
    });
    const diags = findDanglingRefs(model);
    expect(diags).toHaveLength(0);
  });

  it('ignores dotted-path refs (not #id)', () => {
    const model = emptyModel({
      mitigations: [{ asset: 'App.Auth', threat: 'SQL_Injection', location: loc }],
    });
    const diags = findDanglingRefs(model);
    expect(diags).toHaveLength(0);
  });
});

// ─── Validation: findUnmitigatedExposures ─────────────────────────────

describe('findUnmitigatedExposures', () => {
  it('returns exposures with no mitigation or acceptance', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
    });
    const unmitigated = findUnmitigatedExposures(model);
    expect(unmitigated).toHaveLength(1);
  });

  it('excludes mitigated exposures', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
      mitigations: [{ asset: '#app', threat: '#xss', location: loc }],
    });
    const unmitigated = findUnmitigatedExposures(model);
    expect(unmitigated).toHaveLength(0);
  });

  it('excludes accepted exposures', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
      acceptances: [{ asset: '#app', threat: '#xss', location: loc }],
    });
    const unmitigated = findUnmitigatedExposures(model);
    expect(unmitigated).toHaveLength(0);
  });

  it('normalizes #id refs for consistent matching', () => {
    const model = emptyModel({
      exposures: [{ asset: '#app', threat: '#xss', severity: 'high', external_refs: [], location: loc }],
      mitigations: [{ asset: 'app', threat: 'xss', location: loc }],
    });
    const unmitigated = findUnmitigatedExposures(model);
    expect(unmitigated).toHaveLength(0);
  });
});
