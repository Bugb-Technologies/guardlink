import { describe, it, expect, beforeAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lookup, SUPPORTED_QUERY_FORMS } from '../src/mcp/lookup.js';
import { parseProject } from '../src/parser/parse-project.js';
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

// ─── D13: exact-match precedence in ref resolution ───────────────────
//
// Both reproductions are asserted against GuardLink's OWN .guardlink/definitions.ts
// rather than a constructed fixture. If the definitions change such that the
// collision disappears, these tests fail loudly instead of passing vacuously —
// they are meant to stay honest, not merely green.

describe('lookup — exact-match precedence (D13)', () => {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
  let model: ThreatModel;

  beforeAll(async () => {
    ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' }));
  });

  it('the substring collisions this guards against still exist in definitions', () => {
    // Preconditions. Without these the two tests below prove nothing.
    const threatIds = model.threats.map(t => t.id);
    expect(threatIds).toContain('dos');
    expect(threatIds).toContain('redos');
    expect('redos'.includes('dos')).toBe(true);

    const assetIds = model.assets.map(a => a.id);
    expect(assetIds).toContain('cli');
    expect(assetIds).toContain('llm-client');
    expect('llm-client'.includes('cli')).toBe(true);

    // #redos is declared before #dos, so a .find() that accepts a substring hit
    // short-circuits on #redos and never reaches the exact match.
    expect(threatIds.indexOf('redos')).toBeLessThan(threatIds.indexOf('dos'));
  });

  it('case 1: "threat dos" resolves #dos, not the earlier-declared #redos', () => {
    const result = lookup(model, 'threat dos');
    expect(result.type).toBe('threat');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('dos');
    expect(result.results[0].canonical_name).toBe('denial_of_service');
  });

  it('case 1: #redos is still reachable by its own exact id', () => {
    const result = lookup(model, 'threat redos');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('redos');
  });

  it('case 1: affected_assets excludes exposures belonging to #redos', () => {
    const result = lookup(model, 'threat dos');
    const affected = result.results[0].affected_assets as { asset: string }[];
    const declaredOnDos = model.exposures.filter(e => e.threat.replace(/^#/, '') === 'dos');
    expect(affected).toHaveLength(declaredOnDos.length);
  });

  it('case 2: "asset cli" returns only exposures declared on #cli', () => {
    const result = lookup(model, 'asset cli');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('cli');

    const declaredOnCli = model.exposures.filter(e => e.asset.replace(/^#/, '') === 'cli');
    const returned = result.results[0].relationships.exposures as { threat: string }[];
    expect(returned).toHaveLength(declaredOnCli.length);
    expect(returned.map(e => e.threat).sort()).toEqual(declaredOnCli.map(e => e.threat).sort());
  });

  it('case 2: flows are not contaminated by #llm-client either', () => {
    const result = lookup(model, 'asset cli');
    const rel = result.results[0].relationships;
    const inbound = model.flows.filter(f => f.target.replace(/^#/, '') === 'cli');
    const outbound = model.flows.filter(f => f.source.replace(/^#/, '') === 'cli');
    expect(rel.inbound_flows).toHaveLength(inbound.length);
    expect(rel.outbound_flows).toHaveLength(outbound.length);
  });

  it('case 2: #llm-client is still reachable by its own id and keeps its exposures', () => {
    const result = lookup(model, 'asset llm-client');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('llm-client');
    const declared = model.exposures.filter(e => e.asset.replace(/^#/, '') === 'llm-client');
    expect(result.results[0].relationships.exposures).toHaveLength(declared.length);
    expect(declared.length).toBeGreaterThan(0);
  });

  it('"exposures for #cli" agrees with "asset cli" about what belongs to #cli', () => {
    const viaAsset = lookup(model, 'asset cli').results[0].relationships.exposures as { threat: string }[];
    const viaExposures = lookup(model, 'exposures for #cli').results as { threat: string }[];
    expect(viaExposures).toHaveLength(viaAsset.length);
  });

  // ─── D12: a query is answered, or refused — never guessed ─────────
  //
  // These three previously returned a byte-identical
  // {type:'mixed', count:1, results:[{type:'asset', id:'cli'}]} — the #cli asset
  // record, containing zero ownership / assumption / comment data — because
  // "owner of #cli".includes("cli") is true under the reverse-substring rule.
  //
  // A2 made them an honest no_match. GL-203 gives them real query forms, so they
  // now return their own relation type. What must hold across BOTH regimes, and
  // is the actual D12 property, is that none of them ever answers with the #cli
  // asset record.

  it.each([
    ['owner of #cli', 'ownership'],
    ['assumptions for #cli', 'assumptions'],
    ['comments for #cli', 'comments'],
  ])('%j is answered as its own relation type, never as the #cli asset record', (q, type) => {
    const result = lookup(model, q);
    expect(result.type).toBe(type);
    expect(result.type).not.toBe('mixed');
    expect(JSON.stringify(result.results)).not.toContain('"type":"asset"');
  });

  it('the three D12 queries return three different things', () => {
    const types = ['owner of #cli', 'assumptions for #cli', 'comments for #cli']
      .map(q => lookup(model, q).type);
    expect(new Set(types).size).toBe(3);
  });

  it('a relation type with no annotations answers zero rather than refusing', () => {
    // This repo declares no @owns anywhere. "Nobody owns this" is a real answer
    // and is not the same as "I did not understand the question".
    expect(model.ownership).toHaveLength(0);
    const result = lookup(model, 'owner of #cli');
    expect(result.type).toBe('ownership');
    expect(result.count).toBe(0);
    expect(result.type).not.toBe('no_match');
  });

  it('a genuinely unrecognised phrase still lists the supported forms', () => {
    const result = lookup(model, 'how bad is the cli really');
    expect(result.type).toBe('no_match');
    const forms = result.results[0].supported_forms as string[];
    expect(forms).toContain('unmitigated');
    expect(forms).toContain('threats for <asset>');
    expect(forms).toContain('asset <id>');
  });

  it('every GL-203 form is registered in SUPPORTED_QUERY_FORMS', () => {
    // A form that works but is not listed makes the rejection message a lie.
    const listed = SUPPORTED_QUERY_FORMS.join('\n');
    for (const stem of ['owner of', 'handles', 'assumptions for', 'audits',
      'validations for', 'acceptances', 'transfers', 'comments', 'shields', 'cross-repo refs', 'cwe:']) {
      expect(listed, stem).toContain(stem);
    }
  });

  it('rejection hint carries no literal double quotes (survives double JSON encoding)', () => {
    const hint = lookup(model, 'how bad is the cli really').results[0].hint as string;
    expect(hint).not.toContain('"');
  });

  it('bare identifiers still fuzzy-match — only phrases are rejected', () => {
    const result = lookup(model, '#parser');
    expect(result.type).not.toBe('no_match');
    expect(result.count).toBeGreaterThan(0);
  });

  it('a trailing question mark does not degrade an exact ref', () => {
    const withMark = lookup(model, 'threats for #cli?');
    const without = lookup(model, 'threats for #cli');
    expect(withMark.count).toBe(without.count);
    expect(withMark.count).toBeGreaterThan(0);
  });

  it('substring matching still resolves a ref that has no exact match', () => {
    // No asset is declared as #llm, so the substring fallback must still find
    // #llm-client. Precedence changed; the fallback did not go away.
    const result = lookup(model, 'asset llm');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('llm-client');
  });

  // ─── GL-105: how the match was made is part of the answer ──────────

  it('an exact hit is labelled exact', () => {
    const result = lookup(model, 'asset cli');
    expect(result.matched_via).toBe('exact');
    expect(result.matched_against).toBe('cli');
  });

  it('a substring hit is labelled, and names what it matched against', () => {
    const result = lookup(model, 'asset llm');
    expect(result.matched_via).toBe('substring');
    expect(result.matched_against).toBe('llm');
    // The caller can see the answer came from a partial match and check it.
    expect(result.results[0].id).toBe('llm-client');
  });

  it('threat and control resolution are labelled too', () => {
    expect(lookup(model, 'threat dos').matched_via).toBe('exact');
    expect(lookup(model, 'control path-validation').matched_via).toBe('exact');
  });

  it('relational forms carry the label as well', () => {
    for (const q of ['threats for #cli', 'controls for #cli', 'exposures for #cli',
      'mitigations for #cli', 'flows into #cli', 'flows from #cli', 'boundary for #cli']) {
      expect(lookup(model, q).matched_via, q).toBe('exact');
    }
  });

  // ─── D18: exact-match PRECEDENCE must not become EXCLUSIVITY ───────
  //
  // The first cut of this work composed the scope tier by re-classifying a
  // match's `matched_against`. For a substring match that field is the query
  // string itself, so classifying it against the query returned 'exact' — the
  // tier self-promoted, the declared record failed the tier guard, and every
  // relation was filtered out. Any threat or control reachable only by substring
  // silently returned count: 0.
  //
  // Phase 0 §7 had already measured `threat denial` -> #dos as working. That
  // baseline was in hand and unpinned. It is pinned now.

  it('threat denial resolves #dos by substring, not nothing', () => {
    const result = lookup(model, 'threat denial');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('dos');
    expect(result.matched_via).toBe('substring');
  });

  it('threat inject resolves an injection threat and names the ambiguity', () => {
    const result = lookup(model, 'threat inject');
    expect(result.count).toBe(1);
    expect(result.matched_via).toBe('substring');
    // Three threats contain "inject"; picking one silently would be the same
    // class of wrong answer D13 removed.
    expect(result.ambiguous).toBe(true);
    expect(result.candidates).toEqual(
      expect.arrayContaining(['cmd-injection', 'prompt-injection', 'child-proc-injection']),
    );
    expect(result.candidates).toContain(result.results[0].id);
  });

  it('control valid resolves a validation control by substring', () => {
    const result = lookup(model, 'control valid');
    expect(result.count).toBe(1);
    expect(result.matched_via).toBe('substring');
    expect(result.results[0].id).toMatch(/validation$/);
    expect(result.ambiguous).toBe(true);
    expect(result.candidates).toEqual(
      expect.arrayContaining(['path-validation', 'config-validation', 'yaml-validation']),
    );
  });

  it('asset llm still resolves #llm-client by substring', () => {
    const result = lookup(model, 'asset llm');
    expect(result.count).toBe(1);
    expect(result.results[0].id).toBe('llm-client');
    expect(result.matched_via).toBe('substring');
  });

  it('a substring-resolved threat still carries its own relations', () => {
    // The D18 symptom was an empty relation set, not just count: 0 — the tier
    // filter excluded everything. Assert the relations survive.
    const viaSubstring = lookup(model, 'threat denial');
    const viaExact = lookup(model, 'threat dos');
    expect(viaSubstring.results[0].affected_assets.length).toBeGreaterThan(0);
    expect(viaSubstring.results[0].affected_assets)
      .toHaveLength(viaExact.results[0].affected_assets.length);
  });

  it('substring resolution never wins over an available exact match (A1 intact)', () => {
    // The regression guard in both directions: `dos` is exact on #dos and
    // substring on #redos, and must still resolve #dos.
    expect(lookup(model, 'threat dos').results[0].id).toBe('dos');
    expect(lookup(model, 'threat dos').matched_via).toBe('exact');
    expect(lookup(model, 'threat dos').ambiguous).toBeUndefined();
    // And #cli must still report only its own 5 exposures, not #llm-client's 14.
    expect(lookup(model, 'asset cli').results[0].relationships.exposures).toHaveLength(5);
  });

  // ─── F3: the three record paths must agree ─────────────────────────

  it('asset, threat and control resolve a ref at the same tier as each other', () => {
    // These three used to be three implementations. D18 was the two that
    // drifted. They now share one resolver; this pins that they agree.
    const cases: { ref: string; expectTier: string }[] = [
      { ref: 'cli', expectTier: 'exact' },          // asset, exact
      { ref: 'dos', expectTier: 'exact' },          // threat, exact
      { ref: 'path-validation', expectTier: 'exact' }, // control, exact
      { ref: 'llm', expectTier: 'substring' },      // asset, substring only
      { ref: 'denial', expectTier: 'substring' },   // threat, substring only
      { ref: 'valid', expectTier: 'substring' },    // control, substring only
    ];
    for (const { ref, expectTier } of cases) {
      const hits = (['asset', 'threat', 'control'] as const)
        .map(kind => ({ kind, r: lookup(model, `${kind} ${ref}`) }))
        .filter(x => x.r.count > 0);
      expect(hits.length, `${ref} resolved nowhere`).toBeGreaterThan(0);
      // Whichever paths resolve it, they resolve it at the same strength.
      for (const { kind, r } of hits) {
        expect(r.matched_via, `${kind} ${ref}`).toBe(expectTier);
      }
    }
  });

  it('no record path silently returns zero for a ref another path resolves', () => {
    // D18 in its general form: asset worked while threat and control collapsed.
    for (const ref of ['denial', 'valid', 'inject', 'llm', 'dos', 'cli']) {
      const counts = (['asset', 'threat', 'control'] as const)
        .map(kind => lookup(model, `${kind} ${ref}`).count);
      expect(counts.some(c => c > 0), `nothing resolved "${ref}"`).toBe(true);
    }
  });
});

describe('lookup — declared vs referenced for threats and controls (D8)', () => {
  it('a declared threat is marked declared', () => {
    const model = juiceShopLikeModel();
    model.threats.push({
      name: 'SQLi', canonical_name: 'sqli', id: 'sqli', severity: 'critical',
      external_refs: [], location: loc,
    });
    const result = lookup(model, 'threat #sqli');
    expect(result.count).toBe(1);
    expect(result.results[0].declared).toBe(true);
  });

  it('a threat referenced only by an exposure is found and marked undeclared', () => {
    // #sqli is the threat of an exposure but never declared. `unmitigated`
    // reports it; `threat #sqli` used to return a bare count: 0 — the two
    // queries disagreeing about the same identifier.
    const result = lookup(juiceShopLikeModel(), 'threat #sqli');
    expect(result.count).toBe(1);
    expect(result.results[0].declared).toBe(false);
    expect(result.results[0].referenced_in).toContain('exposures');
    expect(result.results[0].affected_assets).toHaveLength(1);
  });

  it('a genuinely unknown threat is still count: 0', () => {
    const result = lookup(juiceShopLikeModel(), 'threat #no-such-threat-anywhere');
    expect(result.count).toBe(0);
    expect(result.results).toEqual([]);
  });

  it('a control referenced only by a mitigation is found and marked undeclared', () => {
    const model = juiceShopLikeModel();
    model.mitigations.push({
      asset: '#login-sqli', threat: '#sqli', control: '#prepared-stmts',
      description: 'parameterized query', location: loc,
    });
    const result = lookup(model, 'control #prepared-stmts');
    expect(result.count).toBe(1);
    expect(result.results[0].declared).toBe(false);
    expect(result.results[0].referenced_in).toContain('mitigations');
    expect(result.results[0].protects).toHaveLength(1);
  });

  it('a genuinely unknown control is still count: 0', () => {
    const result = lookup(juiceShopLikeModel(), 'control #no-such-control');
    expect(result.count).toBe(0);
  });
});

// ─── F4: ambiguous substring sets are named, not silently resolved ───

describe('lookup — ambiguous refs (D18 / F4)', () => {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
  let model: ThreatModel;

  beforeAll(async () => {
    ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' }));
  });

  it('asset client ties #cli and #llm-client and says so', () => {
    // Both contain "client"; declaration order alone used to decide, silently.
    const result = lookup(model, 'asset client');
    expect(result.matched_via).toBe('substring');
    expect(result.ambiguous).toBe(true);
    expect(result.candidates?.sort()).toEqual(['cli', 'llm-client']);
    // The returned record is still one of the tied set, deterministically.
    expect(result.candidates).toContain(result.results[0].id);
  });

  it('an unambiguous substring match is not flagged', () => {
    const result = lookup(model, 'asset llm');
    expect(result.matched_via).toBe('substring');
    expect(result.ambiguous).toBeUndefined();
    expect(result.candidates).toBeUndefined();
  });

  it('an exact match is never flagged ambiguous', () => {
    for (const q of ['asset cli', 'threat dos', 'control path-validation']) {
      expect(lookup(model, q).ambiguous, q).toBeUndefined();
    }
  });

  it('relational forms name a tied ref set too', () => {
    // "llm" admits #llm-client and the undeclared LLMProvider endpoint at the
    // same tier. The set is returned either way, but the tie is now stated.
    const result = lookup(model, 'flows into llm');
    expect(result.count).toBeGreaterThan(0);
    expect(result.ambiguous).toBe(true);
    expect(result.candidates).toEqual(expect.arrayContaining(['#llm-client', 'LLMProvider']));
  });

  it('an exact relational query is unambiguous', () => {
    const result = lookup(model, 'flows into #llm-client');
    expect(result.matched_via).toBe('exact');
    expect(result.ambiguous).toBeUndefined();
  });
});
