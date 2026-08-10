/**
 * GL-203 — every relation type the model carries is reachable by a query form.
 *
 * The coverage list is derived from the *assembled model at runtime*, not from a
 * hardcoded count. Add a relation array to `assembleModel` and these tests fail
 * until it has a registered query form — which is the point. A hardcoded "19"
 * would keep passing while the surface silently fell behind the model, which is
 * how nine types ended up unreachable in the first place.
 *
 * The fixture deliberately exercises every verb, including the ones the live
 * repo happens not to use (@confirmed, @accepts, @transfers, @validates, @owns
 * and cross-repo refs are all absent from GuardLink's own annotations), so
 * "reachable" is proven against real rows rather than empty arrays.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { lookup } from '../src/mcp/lookup.js';
import type { ThreatModel } from '../src/types/index.js';

/** Field names that are file inventories, not relations. */
const NOT_RELATIONS = new Set(['annotated_files', 'unannotated_files']);

/**
 * One query form per relation array. Adding a relation to the model without
 * adding an entry here fails `every relation array has a registered query form`.
 */
const QUERY_FOR: Record<string, string> = {
  assets: 'asset #api',
  threats: 'threat #sqli',
  controls: 'control #prepared-stmts',
  mitigations: 'mitigations for #api',
  exposures: 'exposures for #api',
  confirmed: 'confirmed',
  acceptances: 'acceptances for #api',
  transfers: 'transfers for #api',
  flows: 'flows into #api',
  boundaries: 'boundary for #api',
  validations: 'validations for #api',
  audits: 'audits for #api',
  ownership: 'owner of #api',
  data_handling: 'handles pii',
  assumptions: 'assumptions for #api',
  shields: 'shields',
  features: 'features',
  comments: 'comments',
  actors: 'actors',
  entitlements: 'entitlements',
  external_refs: 'external refs',
};

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "Main REST endpoint"
 * @asset App.DB (#db) -- "Primary data store"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat Auth_Bypass (#auth-bypass) [high] -- "Authentication sidestepped"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 * @actor Namespace_Admin (#ns-admin) -- "Administers one namespace's configuration"
 */
export {};
`;

/** Every relationship verb, on one asset, so each array gets at least one row. */
const SOURCE = `/**
 * API surface.
 *
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "Query built by concatenation"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 * @confirmed #sqli on #api [critical] cwe:CWE-89 -- "Pentest verified injection via email param"
 * @accepts #auth-bypass on #api -- "Legacy endpoint, sunset scheduled"
 * @transfers #auth-bypass from #api to #db -- "Delegated to the data layer"
 * @flows User -> #api via HTTPS -- "Request path"
 * @boundary between #api and #db (#data-boundary) -- "App to DB trust change"
 * @validates #prepared-stmts for #api -- "sqlInjectionTest.ts asserts placeholders"
 * @audit #api -- "Connection string handling needs review"
 * @owns security-team for #api -- "Team responsible for reviews"
 * @handles pii on #api -- "Processes email and session token"
 * @assumes #api -- "Runs behind a WAF"
 * @feature "Checkout" -- "Cart and order placement"
 * @comment -- "Rate limit: 100 req/15min"
 * @entitles #ns-admin to configure-archival-destination on #api against #sqli -- "By design: this is namespace configuration. Authz: src/authz.ts:12"
 * @flows "#sibling-lib.tokens" -> #api via header -- "Cross-repo token handoff (quoted: the unquoted form does not parse — see report)"
 */
export function handler(): void {}
`;

const SHIELDED = `/**
 * @shield -- "Proprietary scoring weights"
 */
export const weights = [1, 2, 3];
`;

const WORKSPACE = `workspace: test-workspace
this_repo: main-repo
repos:
  - name: main-repo
  - name: sibling-lib
`;

describe('GL-203 — relation type coverage', () => {
  let root: string;
  let model: ThreatModel;
  let relationArrays: string[];

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-coverage-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, '.guardlink', 'workspace.yaml'), WORKSPACE);
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    await writeFile(join(root, 'src', 'scoring.ts'), SHIELDED);
    ({ model } = await parseProject({ root, project: 'main-repo' }));
    relationArrays = Object.keys(model)
      .filter(k => Array.isArray((model as any)[k]) && !NOT_RELATIONS.has(k));
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the fixture populates every relation array', () => {
    const empty = relationArrays.filter(k => (model as any)[k].length === 0);
    expect(empty, `fixture left these empty: ${empty.join(', ')}`).toEqual([]);
  });

  it('every relation array on the model has a registered query form', () => {
    // Derived from the runtime model, so a relation added to assembleModel
    // fails here until someone gives it a way to be asked about.
    const unmapped = relationArrays.filter(k => !QUERY_FOR[k]);
    expect(unmapped, `no query form registered for: ${unmapped.join(', ')}`).toEqual([]);
  });

  it('every relation array returns content through its query form', () => {
    const unreachable: string[] = [];
    for (const key of relationArrays) {
      const result = lookup(model, QUERY_FOR[key]);
      if (result.count === 0) unreachable.push(`${key} (via "${QUERY_FOR[key]}")`);
    }
    expect(unreachable, `returned nothing: ${unreachable.join('; ')}`).toEqual([]);
  });

  it('no query form falls through to fuzzy matching', () => {
    for (const key of relationArrays) {
      const result = lookup(model, QUERY_FOR[key]);
      expect(result.type, QUERY_FOR[key]).not.toBe('mixed');
      expect(result.type, QUERY_FOR[key]).not.toBe('no_match');
    }
  });

  it('results carry location', () => {
    // Skipping the three definition types, whose records carry location on the
    // declaration itself and are projected by the existing record lookups.
    for (const key of relationArrays.filter(k => !['assets', 'threats', 'controls', 'features'].includes(k))) {
      const result = lookup(model, QUERY_FOR[key]);
      for (const row of result.results) {
        expect(row.file ?? row.location?.file, `${key}: ${JSON.stringify(row)}`).toBeDefined();
      }
    }
  });

  it('@handles is queryable by classification and by asset', () => {
    const byClass = lookup(model, 'handles pii');
    const byAsset = lookup(model, 'handles for #api');
    expect(byClass.count).toBeGreaterThan(0);
    expect(byAsset.count).toBeGreaterThan(0);
    expect(byClass.type).toBe('data_handling');
    expect(byAsset.type).toBe('data_handling');
    // The bare classification word is the same query.
    expect(lookup(model, 'pii').count).toBe(byClass.count);
  });

  it('cross-repo refs are detected and reachable', () => {
    expect(model.external_refs?.length).toBeGreaterThan(0);
    const result = lookup(model, 'external refs');
    expect(result.count).toBeGreaterThan(0);
    expect(result.results[0].tag).toBe('#sibling-lib.tokens');
    expect(result.results[0].inferred_repo).toBe('sibling-lib');
  });

  it('asset-scoped forms all resolve the ref the same way `asset X` does', () => {
    // Same tier, same identity — a form that resolved refs its own way is D18.
    const viaAsset = lookup(model, 'asset #api');
    for (const q of ['owner of #api', 'assumptions for #api', 'audits for #api',
      'handles for #api', 'validations for #api', 'acceptances for #api']) {
      expect(lookup(model, q).matched_via, q).toBe(viaAsset.matched_via);
    }
  });

  it('comments and shields declare that their join is by co-location', () => {
    // Neither verb records an asset, so "for #api" means "in the same files as
    // annotations naming #api" — an inference, and it says so.
    const c = lookup(model, 'comments for #api');
    expect(c.count).toBeGreaterThan(0);
    for (const row of c.results) expect(row.join).toBe('co-located');
    // Scoped by file instead, there is no inference to declare.
    const byFile = lookup(model, 'comments for src/api.ts');
    expect(byFile.count).toBeGreaterThan(0);
    for (const row of byFile.results) expect(row.join).toBeUndefined();
  });

  it('an empty relation answers zero rather than refusing', () => {
    const bare = { ...model, ownership: [] } as ThreatModel;
    const result = lookup(bare, 'owner of #api');
    expect(result.type).toBe('ownership');
    expect(result.count).toBe(0);
  });
});
