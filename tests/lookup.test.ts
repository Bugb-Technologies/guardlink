import { describe, it, expect } from 'vitest';
import { lookup } from '../src/mcp/lookup.js';
import type { ThreatModel } from '../src/types/index.js';

function emptyModel(overrides: Partial<ThreatModel> = {}): ThreatModel {
  return {
    version: '1.0.0', project: 'test', generated_at: '', source_files: 0,
    annotated_files: [], unannotated_files: [],
    annotations_parsed: 0, assets: [], threats: [], controls: [],
    mitigations: [], exposures: [], acceptances: [], transfers: [],
    flows: [], boundaries: [], validations: [], audits: [], ownership: [],
    data_handling: [], assumptions: [], shields: [], features: [], comments: [],
    confirmed: [],
    coverage: { total_symbols: 0, annotated_symbols: 0, coverage_percent: 0, unannotated_critical: [] },
    ...overrides,
  };
}

const loc = { file: 'routes/login.ts', line: 4 };

// A model that mirrors the Juice Shop test session — undeclared #login asset and
// #login-sqli/#sqli threats referenced through @exposes and @confirmed only.
function juiceShopLikeModel(): ThreatModel {
  return emptyModel({
    exposures: [
      {
        asset: '#login-sqli',
        threat: '#sqli',
        severity: 'critical',
        external_refs: ['cwe:CWE-89'],
        description: 'req.body.email interpolated into raw SQL',
        location: loc,
      },
    ],
    confirmed: [
      {
        asset: '#login',
        threat: '#login-sqli',
        severity: 'critical',
        external_refs: ['cwe:CWE-89'],
        description: "Manual repro 2026-04-24: ' OR 1=1-- via /rest/user/login email field",
        location: { file: 'routes/login.ts', line: 5 },
      },
    ],
    features: [
      { feature: 'Authentication',  description: 'Login, registration, password reset', location: loc },
      { feature: 'Checkout',        description: 'Cart, basket, order placement',       location: { file: 'routes/order.ts', line: 1 } },
      { feature: 'Product Catalog', description: 'Search, browse, view products',       location: { file: 'routes/search.ts', line: 1 } },
    ],
  });
}

// ─── Working queries (regression guards) ─────────────────────────────

describe('lookup — unmitigated', () => {
  it('returns exposures with no matching mitigation or acceptance', () => {
    const result = lookup(juiceShopLikeModel(), 'unmitigated');
    expect(result.type).toBe('unmitigated_exposures');
    expect(result.count).toBe(1);
    expect(result.results[0]).toMatchObject({
      asset: '#login-sqli', threat: '#sqli', severity: 'critical',
    });
  });

  it('excludes exposures that have a matching mitigation', () => {
    const model = juiceShopLikeModel();
    model.mitigations.push({
      asset: '#login-sqli', threat: '#sqli', control: '#prepared-stmts',
      description: 'parameterized query', location: loc,
    });
    const result = lookup(model, 'unmitigated');
    expect(result.count).toBe(0);
  });
});

describe('lookup — confirmed', () => {
  it('returns confirmed entries with evidence string verbatim', () => {
    const result = lookup(juiceShopLikeModel(), 'confirmed');
    expect(result.type).toBe('confirmed_exploitable');
    expect(result.count).toBe(1);
    expect(result.results[0].description).toContain("' OR 1=1--");
    expect(result.results[0].external_refs).toContain('cwe:CWE-89');
  });
});

describe('lookup — features', () => {
  it('returns all features with file lists and descriptions', () => {
    const result = lookup(juiceShopLikeModel(), 'features');
    expect(result.type).toBe('features');
    expect(result.count).toBe(3);
    const names = result.results.map((r: any) => r.feature).sort();
    expect(names).toEqual(['Authentication', 'Checkout', 'Product Catalog']);
    const auth = result.results.find((r: any) => r.feature === 'Authentication');
    expect(auth.files).toContain('routes/login.ts');
    expect(auth.description).toBe('Login, registration, password reset');
  });

  it('deduplicates features tagged in multiple files', () => {
    const model = juiceShopLikeModel();
    model.features.push({
      feature: 'Authentication', description: 'second tag, same feature',
      location: { file: 'routes/2fa.ts', line: 1 },
    });
    const result = lookup(model, 'features');
    expect(result.count).toBe(3); // still 3 unique features
    const auth = result.results.find((r: any) => r.feature === 'Authentication');
    expect(auth.files).toHaveLength(2);
    expect(auth.files).toContain('routes/2fa.ts');
  });
});

describe('lookup — threats for', () => {
  it('finds threats joined through exposures even when asset is undeclared', () => {
    const result = lookup(juiceShopLikeModel(), 'threats for #login-sqli');
    expect(result.type).toBe('threats_for_asset');
    expect(result.count).toBe(1);
    expect(result.results[0]).toMatchObject({
      threat: '#sqli', severity: 'critical', mitigated: false, accepted: false,
    });
  });
});

// ─── Bug 1: asset <id> falls back to undeclared-but-referenced assets ─

describe('lookup — asset (bug 1)', () => {
  it('finds declared assets', () => {
    const model = juiceShopLikeModel();
    model.assets.push({ path: ['App', 'Login'], id: 'login', location: loc });
    const result = lookup(model, 'asset #login');
    expect(result.type).toBe('asset');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('login');
  });

  it('synthesizes a record when an asset is referenced but never declared', () => {
    // #login is referenced by @confirmed, never declared in definitions.ts.
    // Without this fix, `asset #login` returns count: 0 — but `threats for #login`
    // works because it joins through model.confirmed/exposures directly.
    // Both queries should agree the asset exists.
    const result = lookup(juiceShopLikeModel(), 'asset #login');
    expect(result.type).toBe('asset');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('login');
    expect(result.results[0].declared).toBe(false);
    expect(result.results[0].referenced_in).toContain('confirmed');
  });

  it('synthesized record includes relationships from referencing annotations', () => {
    const result = lookup(juiceShopLikeModel(), 'asset #login');
    expect(result.results[0].relationships.confirmed).toEqual([
      { threat: '#login-sqli', severity: 'critical' },
    ]);
  });
});

// ─── Bug 2: bare #id fuzzy-matches across categories AND undeclared refs ─

describe('lookup — bare #id (bug 2)', () => {
  it('resolves bare #id of a declared asset', () => {
    const model = juiceShopLikeModel();
    model.assets.push({ path: ['App', 'Login'], id: 'login', location: loc });
    const result = lookup(model, '#login');
    expect(result.type).toBe('mixed');
    expect(result.count).toBeGreaterThan(0);
    expect(result.results.some((r: any) => r.type === 'asset' && r.id === 'login')).toBe(true);
  });

  it('resolves bare #id when the identifier is only referenced (not declared)', () => {
    // #login-sqli is the asset of an exposure but never declared as @asset.
    // unmitigated returns it; bare #login-sqli should also find it instead of
    // returning no_match.
    const result = lookup(juiceShopLikeModel(), '#login-sqli');
    expect(result.type).not.toBe('no_match');
    expect(result.count).toBeGreaterThan(0);
    expect(result.results.some((r: any) => r.id === 'login-sqli' || r.path === 'login-sqli')).toBe(true);
  });

  it('still returns no_match for genuinely unknown identifiers', () => {
    const result = lookup(juiceShopLikeModel(), '#totally-not-real-anywhere');
    expect(result.type).toBe('no_match');
    expect(result.count).toBe(0);
  });
});

// ─── Bug 3: no_match hint avoids embedded double quotes ───────────────

describe('lookup — no_match hint (bug 3)', () => {
  it('hint text does not contain literal double-quote characters', () => {
    // The hint travels through two JSON.stringify passes (MCP content wrap +
    // JSON-RPC envelope). Embedded double quotes get escaped to \\\" which
    // renders as literal backslashes in clients that print the raw text.
    // Use single quotes or backticks in the hint so it survives both layers.
    const result = lookup(juiceShopLikeModel(), '#totally-not-real-anywhere');
    const hint = (result.results[0] as any).hint as string;
    expect(hint).toBeTypeOf('string');
    expect(hint).not.toContain('"');
  });

  it('hint still names a few example queries', () => {
    const result = lookup(juiceShopLikeModel(), '#totally-not-real-anywhere');
    const hint = (result.results[0] as any).hint as string;
    expect(hint).toMatch(/asset/);
    expect(hint).toMatch(/threats for/);
    expect(hint).toMatch(/unmitigated/);
  });
});
