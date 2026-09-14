/**
 * W3.1 / mark 8 — one team's tag must not silence another team's finding.
 *
 * Measured in `data/bravos-user-flow-visuals/report.md` §3.3: four repositories,
 * two of them independently declaring `#listing` and `#bac`, one `@mitigates` in
 * a third. `guardlink merge` printed
 *
 *     1 mitigations | 2 exposures | 0 unmitigated          ← wrong
 *     ⚠ Tag "listing" defined in orders-api (owner) and also in: billing-api
 *
 * Two teams exposed, one control, zero reported unmitigated. The warning is
 * right and the count is not: `tag_registry` already records `owner_repo` for
 * every tag, and the join that decides coverage ignored it — a mitigation on
 * orders-api's `#listing` answered for billing-api's unrelated `#listing`,
 * because after `combineModels` both are the string "#listing".
 *
 * A real finding disappearing because two teams picked the same word is the
 * dangerous direction: the estate surface reports clean and nobody is told.
 *
 * ── What the fix may NOT do ─────────────────────────────────────────
 *
 * Scoping is only correct if it leaves the genuine cross-repo case alone. The
 * whole point of `merge` is that platform-authz's control credits orders-api's
 * exposure, so every test below that asserts a re-opened finding is paired with
 * one asserting the cross-repo join still closes. The single-repo and
 * no-collision paths are asserted unchanged for the same reason.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mergeReports } from '../src/workspace/merge.js';
import type {
  ThreatModel, ThreatModelExposure, ThreatModelMitigation,
} from '../src/types/index.js';

// ─── Fixture builders ────────────────────────────────────────────────

interface RepoSpec {
  repo: string;
  /**
   * Tag ids this repo DEFINES in its own .guardlink/definitions.
   *
   * An asset may be given as a bare id — declared identically wherever it
   * appears, i.e. one shared vocabulary — or as `[id, path, description]`, which
   * is how two teams who picked the same word for different things are written.
   * The distinction is load-bearing: it is what separates a collision from a
   * definitions file copied into every repo.
   */
  defines?: {
    assets?: (string | [string, string, string])[];
    threats?: string[];
    controls?: string[];
  };
  exposures?: { asset: string; threat: string; file: string }[];
  mitigations?: { asset: string; threat: string; control?: string; file: string }[];
}

function at(file: string, line = 9) {
  return { file, line };
}

function repoModel(spec: RepoSpec): ThreatModel {
  const d = spec.defines ?? {};
  return {
    version: '1.2.0',
    project: spec.repo,
    generated_at: '2026-09-14T00:00:00.000Z',
    source_files: 1,
    annotations_parsed:
      (spec.exposures?.length ?? 0) + (spec.mitigations?.length ?? 0),
    annotated_files: ['src/app.py'],
    unannotated_files: [],
    assets: (d.assets ?? []).map(a => {
      const [id, path, description] = typeof a === 'string'
        ? [a, a.replace(/^#/, ''), undefined as string | undefined]
        : a;
      return { path: [path], id, description, location: at('.guardlink/definitions.py', 1) };
    }),
    threats: (d.threats ?? []).map(id => ({
      name: id.replace(/^#/, ''), canonical_name: id.replace(/^#/, ''), id,
      external_refs: [], location: at('.guardlink/definitions.py', 2),
    })),
    controls: (d.controls ?? []).map(id => ({
      name: id.replace(/^#/, ''), canonical_name: id.replace(/^#/, ''), id,
      location: at('.guardlink/definitions.py', 3),
    })),
    actors: [],
    entitlements: [],
    mitigations: (spec.mitigations ?? []).map(m => ({
      asset: m.asset, threat: m.threat, control: m.control, location: at(m.file, 7),
    })) as ThreatModelMitigation[],
    exposures: (spec.exposures ?? []).map(e => ({
      asset: e.asset, threat: e.threat, severity: 'high' as const,
      external_refs: [], location: at(e.file, 9),
    })) as ThreatModelExposure[],
    confirmed: [],
    acceptances: [],
    transfers: [],
    flows: [],
    boundaries: [],
    validations: [],
    audits: [],
    ownership: [],
    data_handling: [],
    assumptions: [],
    shields: [],
    features: [],
    comments: [],
    coverage: { annotation_count: 0, coverage_percent: 100 },
    metadata: {
      repo: spec.repo,
      schema_version: '1.2.0',
      generated_at: '2026-09-14T00:00:00.000Z',
    },
  } as unknown as ThreatModel;
}

let dir: string;
beforeAll(async () => { dir = await mkdtemp(join(tmpdir(), 'gl-owner-scope-')); });
afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

let seq = 0;
async function merge(specs: RepoSpec[]) {
  const batch = `b${seq++}`;
  const paths: string[] = [];
  for (const s of specs) {
    const p = join(dir, `${batch}-${s.repo}.json`);
    await writeFile(p, JSON.stringify(repoModel(s)));
    paths.push(p);
  }
  return mergeReports(paths, { workspace: 'acme' });
}

// The two repos that collide. Each declares `#listing`, and they mean DIFFERENT
// endpoints — an order listing and an invoice listing. That disagreement is the
// defect; two repos declaring one tag the same way is a shared vocabulary and is
// covered separately below.
const ordersApi: RepoSpec = {
  repo: 'orders-api',
  defines: { assets: [['#listing', 'Orders.Listing', 'Order listing endpoint']], threats: ['#bac'] },
  exposures: [{ asset: '#listing', threat: '#bac', file: 'src/orders_api/handlers.py' }],
};
const billingApi: RepoSpec = {
  repo: 'billing-api',
  defines: { assets: [['#listing', 'Billing.Listing', 'Invoice listing endpoint']], threats: ['#bac'] },
  exposures: [{ asset: '#listing', threat: '#bac', file: 'src/billing_api/handlers.py' }],
};
// The control lives in a third repo and names orders-api's tags.
const platformAuthz: RepoSpec = {
  repo: 'platform-authz',
  defines: { controls: ['#tenant-guard'] },
  mitigations: [{
    asset: '#listing', threat: '#bac', control: '#tenant-guard',
    file: 'src/platform_authz/tenant_scope.py',
  }],
};

// ─── The defect ──────────────────────────────────────────────────────

describe('mark 8 — a colliding tag must not let one team\'s control cover another team\'s risk', () => {
  it('two teams exposed, one control: one exposure stays open', async () => {
    const merged = await merge([ordersApi, billingApi, platformAuthz]);

    expect(merged.totals.exposures).toBe(2);
    expect(merged.totals.mitigations).toBe(1);
    // Before the fix this was 0: billing-api's finding vanished.
    expect(merged.totals.unmitigated_exposures).toBe(1);
  });

  it('the warning that already named the owner is still emitted', async () => {
    const merged = await merge([ordersApi, billingApi, platformAuthz]);
    const dupes = merged.warnings.filter(w => w.code === 'duplicate_tag');
    expect(dupes.map(w => w.tag).sort()).toContain('#listing');
    expect(dupes.every(w => w.repos?.includes('orders-api'))).toBe(true);
  });

  it('one definitions file shipped to every repo is a shared vocabulary, not a collision', async () => {
    // The shape `tests/merge-verdict.test.ts` scaffolds, and a normal way to run
    // an estate: every repository carries the SAME `definitions.ts`, so every
    // asset is "defined in" N repos while meaning exactly one thing. Scoping on
    // `also_defined_in` alone cut every cross-repo join in a workspace like this
    // — the control in platform-authz stopped covering the exposure in
    // orders-api, and the estate grew a finding nobody had introduced.
    const shared = { assets: ['#listing'], threats: ['#bac'], controls: ['#tenant-guard'] };
    const merged = await merge([
      { repo: 'orders-api', defines: shared,
        exposures: [{ asset: '#listing', threat: '#bac', file: 'src/orders_api/handlers.py' }] },
      { repo: 'platform-authz', defines: shared,
        mitigations: [{ asset: '#listing', threat: '#bac', control: '#tenant-guard', file: 'src/platform_authz/guard.py' }] },
    ]);

    expect(merged.totals.exposures).toBe(1);
    // The duplicate warning is still right — the tag IS defined twice.
    expect(merged.warnings.some(w => w.code === 'duplicate_tag')).toBe(true);
    // And the join still closes, because the two declarations agree.
    expect(merged.totals.unmitigated_exposures).toBe(0);
  });

  it('records whether the definers actually disagree, so a reader can scope from the JSON alone', async () => {
    const collided = await merge([ordersApi, billingApi, platformAuthz]);
    const listing = collided.tag_registry.find(t => t.tag === '#listing' && t.kind === 'asset');
    expect(listing?.also_defined_in).toContain('billing-api');
    expect(listing?.definitions_differ).toBe(true);

    const shared = { assets: ['#listing'], threats: ['#bac'], controls: ['#tenant-guard'] };
    const agreed = await merge([
      { repo: 'orders-api', defines: shared,
        exposures: [{ asset: '#listing', threat: '#bac', file: 'src/orders_api/handlers.py' }] },
      { repo: 'platform-authz', defines: shared,
        mitigations: [{ asset: '#listing', threat: '#bac', control: '#tenant-guard', file: 'src/platform_authz/guard.py' }] },
    ]);
    const same = agreed.tag_registry.find(t => t.tag === '#listing' && t.kind === 'asset');
    expect(same?.also_defined_in).toContain('platform-authz');
    expect(same?.definitions_differ).toBe(false);
  });

  it('scoping is by owner, not by repo: a control in the OWNER repo still covers its own', async () => {
    // orders-api both declares and mitigates; billing-api declares and exposes.
    const merged = await merge([
      { ...ordersApi, mitigations: platformAuthz.mitigations!.map(m => ({ ...m, file: 'src/orders_api/guard.py' })) },
      billingApi,
    ]);
    expect(merged.totals.exposures).toBe(2);
    expect(merged.totals.unmitigated_exposures).toBe(1);
  });
});

// ─── What the fix must leave alone ───────────────────────────────────

describe('mark 8 — the genuine cross-repo join is untouched', () => {
  it('a sibling repo\'s control still closes the owner\'s exposure (report.md §3.3c)', async () => {
    const merged = await merge([ordersApi, platformAuthz]);
    expect(merged.totals.exposures).toBe(1);
    expect(merged.totals.unmitigated_exposures).toBe(0);
  });

  it('and it re-opens when the control is removed — the reverse check', async () => {
    const merged = await merge([ordersApi, { repo: 'platform-authz', defines: { controls: ['#tenant-guard'] } }]);
    expect(merged.totals.unmitigated_exposures).toBe(1);
  });

  it('a repo that never defines the asset still resolves to the single owner', async () => {
    // billing-api DOES NOT declare #listing here, so its reference means
    // orders-api's asset and the shared control answers for both.
    const merged = await merge([
      ordersApi,
      { repo: 'billing-api', exposures: billingApi.exposures },
      platformAuthz,
    ]);
    expect(merged.totals.exposures).toBe(2);
    expect(merged.totals.unmitigated_exposures).toBe(0);
  });

  it('a tag nobody defines joins across repos exactly as before', async () => {
    const merged = await merge([
      { repo: 'a', exposures: [{ asset: '#ghost', threat: '#spook', file: 'src/a.py' }] },
      { repo: 'b', mitigations: [{ asset: '#ghost', threat: '#spook', file: 'src/b.py' }] },
    ]);
    expect(merged.totals.unmitigated_exposures).toBe(0);
  });

  it('a single repo merged alone is unchanged', async () => {
    const merged = await merge([{
      ...ordersApi,
      mitigations: [{ asset: '#listing', threat: '#bac', file: 'src/orders_api/guard.py' }],
    }]);
    expect(merged.totals.unmitigated_exposures).toBe(0);
  });
});
