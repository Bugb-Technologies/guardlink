/**
 * W3.3 / mark 20 — `merge` writes the estate model and nothing read it back.
 *
 * `guardlink merge --json` has always produced a combined threat model, and the
 * only ways to consume one were a browser and a text editor. The question a
 * platform team asks — *what is open across all of our repositories* — had an
 * answer on disk and no command.
 *
 * What is pinned here is what makes the read path trustworthy rather than merely
 * present:
 *
 *   it answers with the SAME coverage the merge computed, owner scope included,
 *     so a number and the list behind it cannot disagree;
 *   it refuses a file that is not a merged report, instead of summarising a
 *     per-repo report into a clean estate;
 *   and it says how much of the estate it actually read, first, because "0 open"
 *     over 0 of 4 repos is the vacuous green one level up.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  estateReport, formatEstateReport, readMergedReport, NotAMergedReport, ESTATE_SCHEMA,
} from '../src/workspace/estate.js';
import { mergeReports } from '../src/workspace/merge.js';
import type { MergedReport } from '../src/workspace/types.js';
import type { ThreatModel } from '../src/types/index.js';

// ─── Fixture ─────────────────────────────────────────────────────────

interface RepoSpec {
  repo: string;
  /**
   * An asset is a bare id (declared identically everywhere — a shared
   * vocabulary) or `[id, path, description]` (two teams who picked one word for
   * different things). Only the second is a collision the coverage join scopes.
   */
  defines?: {
    assets?: (string | [string, string, string])[];
    threats?: string[];
    controls?: string[];
  };
  /** `severity: null` writes an exposure with no severity at all. */
  exposures?: { asset: string; threat: string; file: string; severity?: string | null }[];
  mitigations?: { asset: string; threat: string; control?: string; file: string }[];
  confirmed?: { asset: string; threat: string; file: string }[];
}

function repoModel(spec: RepoSpec): ThreatModel {
  const d = spec.defines ?? {};
  const loc = (file: string, line: number) => ({ file, line });
  return {
    version: '1.2.0',
    project: spec.repo,
    generated_at: '2026-09-14T00:00:00.000Z',
    source_files: 1,
    annotations_parsed: 3,
    annotated_files: ['src/app.py'],
    unannotated_files: [],
    assets: (d.assets ?? []).map(a => {
      const [id, path, description] = typeof a === 'string'
        ? [a, a.replace(/^#/, ''), undefined as string | undefined]
        : a;
      return { path: [path], id, description, location: loc('.guardlink/definitions.py', 1) };
    }),
    threats: (d.threats ?? []).map(id => ({
      name: id.replace(/^#/, ''), canonical_name: id.replace(/^#/, ''), id,
      external_refs: [], location: loc('.guardlink/definitions.py', 2),
    })),
    controls: (d.controls ?? []).map(id => ({
      name: id.replace(/^#/, ''), canonical_name: id.replace(/^#/, ''), id,
      location: loc('.guardlink/definitions.py', 3),
    })),
    actors: [], entitlements: [],
    mitigations: (spec.mitigations ?? []).map(m => ({ ...m, location: loc(m.file, 7) })),
    exposures: (spec.exposures ?? []).map(e => ({
      asset: e.asset, threat: e.threat,
      ...(e.severity === null ? {} : { severity: e.severity ?? 'high' }),
      external_refs: [], location: loc(e.file, 9),
    })),
    confirmed: (spec.confirmed ?? []).map(c => ({
      asset: c.asset, threat: c.threat, severity: 'critical',
      external_refs: [], description: 'pentest reproduced', location: loc(c.file, 11),
    })),
    acceptances: [], transfers: [], flows: [], boundaries: [], validations: [],
    audits: [], ownership: [], data_handling: [], assumptions: [], shields: [],
    features: [], comments: [],
    coverage: { annotation_count: 3, coverage_percent: 100 },
    metadata: { repo: spec.repo, schema_version: '1.2.0', generated_at: '2026-09-14T00:00:00.000Z' },
  } as unknown as ThreatModel;
}

let dir: string;
beforeAll(async () => { dir = await mkdtemp(join(tmpdir(), 'gl-estate-')); });
afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

let seq = 0;
async function mergeOf(specs: RepoSpec[], extraPaths: string[] = []): Promise<MergedReport> {
  const batch = `e${seq++}`;
  const paths: string[] = [];
  for (const s of specs) {
    const p = join(dir, `${batch}-${s.repo}.json`);
    await writeFile(p, JSON.stringify(repoModel(s)));
    paths.push(p);
  }
  return mergeReports([...paths, ...extraPaths], { workspace: 'acme' });
}

// orders-api and billing-api each declare `#listing` and mean a DIFFERENT
// endpoint. That disagreement is what the owner scope narrows on, and it is why
// billing-api's finding survives platform-authz's control below.
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
const platformAuthz: RepoSpec = {
  repo: 'platform-authz',
  defines: { controls: ['#tenant-guard'] },
  mitigations: [{
    asset: '#listing', threat: '#bac', control: '#tenant-guard',
    file: 'src/platform_authz/tenant_scope.py',
  }],
};

// ─── What is open, and where ─────────────────────────────────────────

describe('estate — what is open across the estate', () => {
  it('places each open finding in the repository it was written in', async () => {
    const r = estateReport(await mergeOf([ordersApi, billingApi, platformAuthz]));
    expect(r.schema).toBe(ESTATE_SCHEMA);
    expect(r.open).toHaveLength(1);
    expect(r.open[0]).toMatchObject({
      repo: 'billing-api',
      asset: '#listing',
      threat: '#bac',
      severity: 'high',
      file: 'billing-api/src/billing_api/handlers.py',
    });
    expect(r.by_repo).toEqual({ 'billing-api': 1 });
  });

  it('agrees with the merge it was read from — the count and the list are one answer', async () => {
    const merged = await mergeOf([ordersApi, billingApi, platformAuthz]);
    const r = estateReport(merged);
    expect(r.summary.open).toBe(merged.totals.unmitigated_exposures);
    expect(r.open).toHaveLength(merged.totals.unmitigated_exposures);
    expect(r.summary.owner_scoped).toBe(true);
  });

  it('credits a sibling repo\'s control and reports the estate clean', async () => {
    const r = estateReport(await mergeOf([ordersApi, platformAuthz]));
    expect(r.open).toHaveLength(0);
    expect(r.summary.read_nothing).toBe(false);
    expect(formatEstateReport(r)).toContain('No open exposures across 2 repo(s)');
  });

  it('reports @confirmed separately — no acceptance silences one anywhere', async () => {
    const r = estateReport(await mergeOf([
      { ...ordersApi, confirmed: [{ asset: '#listing', threat: '#bac', file: 'src/orders_api/handlers.py' }] },
      platformAuthz,
    ]));
    expect(r.open).toHaveLength(0);         // the control covers the exposure
    expect(r.confirmed).toHaveLength(1);    // the reproduction stands regardless
    expect(r.confirmed[0].repo).toBe('orders-api');
    expect(formatEstateReport(r)).toContain('reproduced exploit');
  });

  it('a repo with nothing open still appears, so a clean repo is visible as clean', async () => {
    const r = estateReport(await mergeOf([ordersApi, billingApi, platformAuthz]));
    expect(r.repos.map(x => x.name).sort())
      .toEqual(['billing-api', 'orders-api', 'platform-authz']);
    expect(r.repos.find(x => x.name === 'orders-api')).toMatchObject({ loaded: true, open: 0 });
  });
});

// ─── Narrowing ───────────────────────────────────────────────────────

describe('estate — narrowing says what it dropped, and never drops an unrated finding', () => {
  const mixed: RepoSpec = {
    repo: 'mixed',
    defines: { assets: ['#a'], threats: ['#low-t', '#crit-t'] },
    exposures: [
      { asset: '#a', threat: '#low-t', file: 'src/l.py', severity: 'low' },
      { asset: '#a', threat: '#crit-t', file: 'src/c.py', severity: 'critical' },
    ],
  };

  it('--severity keeps only what was asked for', async () => {
    const merged = await mergeOf([mixed]);
    expect(estateReport(merged, { severity: ['critical'] }).open).toHaveLength(1);
    expect(estateReport(merged, { severity: ['critical'] }).open[0].threat).toBe('#crit-t');
  });

  it('an unrated finding survives --severity — it is not a low one', async () => {
    const merged = await mergeOf([{
      repo: 'unrated',
      defines: { assets: ['#a'], threats: ['#t'] },
      exposures: [{ asset: '#a', threat: '#t', file: 'src/u.py', severity: null }],
    }]);
    expect(merged.model.exposures[0].severity).toBeUndefined();
    expect(estateReport(merged, { severity: ['critical'] }).open).toHaveLength(1);
  });

  it('--repo narrows to one team\'s findings', async () => {
    const merged = await mergeOf([ordersApi, billingApi, platformAuthz]);
    expect(estateReport(merged, { repo: ['orders-api'] }).open).toHaveLength(0);
    expect(estateReport(merged, { repo: ['billing-api'] }).open).toHaveLength(1);
  });

  it('worst severity first', async () => {
    const r = estateReport(await mergeOf([mixed]));
    expect(r.open.map(f => f.severity)).toEqual(['critical', 'low']);
  });
});

// ─── Honesty about coverage ──────────────────────────────────────────

describe('estate — an answer over nothing is not a clean estate', () => {
  it('a merge that loaded no repo says so before any count', async () => {
    const merged = await mergeReports([join(dir, 'does-not-exist.json')], { workspace: 'acme' });
    const r = estateReport(merged);
    expect(r.summary.read_nothing).toBe(true);
    expect(r.summary.repos_loaded).toBe(0);
    const text = formatEstateReport(r);
    expect(text).toContain('No repo report was read');
    expect(text).toContain('it is no estate');
    // And the "0 open" line, when it appears, is qualified rather than green.
    expect(text).not.toContain('✓ No open exposures');
  });

  it('a partly-read estate says which repos are missing', async () => {
    const merged = await mergeOf([ordersApi], [join(dir, 'absent-sibling.json')]);
    const r = estateReport(merged);
    expect(r.summary.partial).toBe(true);
    expect(formatEstateReport(r)).toContain('This answer is partial');
  });

  it('--strict fails on an estate that read nothing, even with nothing open', async () => {
    const merged = await mergeReports([join(dir, 'nope.json')], { workspace: 'acme' });
    const r = estateReport(merged, { strict: true });
    expect(r.open).toHaveLength(0);
    expect(r.summary.exit_code).toBe(1);
  });

  it('--strict fails on an open exposure, and passes on a genuinely clean estate', async () => {
    expect(estateReport(await mergeOf([ordersApi, billingApi, platformAuthz]), { strict: true })
      .summary.exit_code).toBe(1);
    expect(estateReport(await mergeOf([ordersApi, platformAuthz]), { strict: true })
      .summary.exit_code).toBe(0);
  });

  it('advisory by default: an open exposure alone never sets a non-zero exit', async () => {
    const r = estateReport(await mergeOf([ordersApi, billingApi, platformAuthz]));
    expect(r.open.length).toBeGreaterThan(0);
    expect(r.summary.exit_code).toBe(0);
  });
});

// ─── Refusing what is not a merged report ────────────────────────────

describe('estate — refuses anything that is not a merged report', () => {
  it('a per-repo report is refused by name, not summarised into a clean estate', async () => {
    const p = join(dir, 'per-repo.json');
    await writeFile(p, JSON.stringify(repoModel(ordersApi)));
    await expect(readMergedReport(p)).rejects.toBeInstanceOf(NotAMergedReport);
    await expect(readMergedReport(p)).rejects.toThrow(/missing .*repo_statuses/);
    await expect(readMergedReport(p)).rejects.toThrow(/guardlink merge/);
  });

  it('a missing file, invalid JSON and a JSON array are each refused', async () => {
    const bad = join(dir, 'bad.json');
    await writeFile(bad, '{ not json');
    const arr = join(dir, 'arr.json');
    await writeFile(arr, '[]');
    await expect(readMergedReport(join(dir, 'gone.json'))).rejects.toBeInstanceOf(NotAMergedReport);
    await expect(readMergedReport(bad)).rejects.toThrow(/invalid JSON/);
    await expect(readMergedReport(arr)).rejects.toThrow(/not an object/);
  });

  it('round-trips a real merged report off disk', async () => {
    const merged = await mergeOf([ordersApi, billingApi, platformAuthz]);
    const p = join(dir, 'merged.json');
    await writeFile(p, JSON.stringify(merged, null, 2));
    const back = await readMergedReport(p);
    expect(estateReport(back).open).toHaveLength(1);
    expect(estateReport(back).summary.open).toBe(merged.totals.unmitigated_exposures);
  });

  it('a report written before tag ownership was recorded answers, and says it could not scope', async () => {
    const merged = await mergeOf([ordersApi, billingApi, platformAuthz]);
    // Strip the field a pre-mark-8 build never wrote.
    const legacy: MergedReport = {
      ...merged,
      tag_registry: merged.tag_registry.map(({ also_defined_in: _drop, ...rest }) => rest),
    };
    const r = estateReport(legacy);
    expect(r.summary.owner_scoped).toBe(false);
    // Unscoped, this is the old answer — stated, not silently produced.
    expect(r.open).toHaveLength(0);
    expect(formatEstateReport(r)).toContain('cannot be scoped here');
  });
});

// ─── Parse state: "unknown" is not "clean", in this surface too ──────

/**
 * #39 (`23d3565`) fixed mark 19 at estate scale: a report JSON said nothing
 * about the parse behind it, so `merge` printed a green tick over member repos
 * that had silently dropped their `@mitigates` lines. It gave `MergeTotals`
 * three states — contributed, errored, unknown — and made `merge --strict` gate
 * on parse errors.
 *
 * `estate` is a SECOND reader of the very same `repo_statuses`. A fix that lives
 * only in `merge`'s verdict is one surface wide, and the surface a platform team
 * actually reads is this one. So the same three states are pinned here: a repo
 * whose parse failed, and a repo whose report cannot say, must each be visible
 * as themselves rather than absorbed into a tick.
 */
describe('estate — a repo whose parse dropped annotations is not reported clean', () => {
  /** Stamp parse state onto a merged report's repo_statuses, as `report --format json` would. */
  function withParse(
    merged: MergedReport,
    states: Record<string, { errors: number; warnings: number; unparsed_annotations: number } | undefined>,
  ): MergedReport {
    return {
      ...merged,
      repo_statuses: merged.repo_statuses.map(s => (
        s.name in states ? { ...s, parse: states[s.name] } : s
      )),
    };
  }

  it('counts errors and unread lines only over the repos that reported, and the rest as unknown', async () => {
    const merged = withParse(await mergeOf([ordersApi, billingApi, platformAuthz]), {
      'orders-api': { errors: 2, warnings: 1, unparsed_annotations: 14 },
      'platform-authz': { errors: 0, warnings: 0, unparsed_annotations: 0 },
      // billing-api reports nothing: its parse is unknown, which is not zero.
    });
    const s = estateReport(merged).summary;
    expect(s.parse_errors).toBe(2);
    expect(s.unparsed_annotations).toBe(14);
    expect(s.repos_parse_unknown).toBe(1);
  });

  it('does not tick a repository whose parse errored, and says how much it could not read', async () => {
    const merged = withParse(await mergeOf([ordersApi, platformAuthz]), {
      'orders-api': { errors: 0, warnings: 0, unparsed_annotations: 0 },
      'platform-authz': { errors: 3, warnings: 0, unparsed_annotations: 9 },
    });
    const text = formatEstateReport(estateReport(merged));
    expect(text).toMatch(/⚠ platform-authz — 0 open, 0 confirmed, 3 parse error\(s\) — 9 annotation line\(s\) unread/);
    expect(text).not.toMatch(/✓ platform-authz/);
  });

  it('a repo that cannot say is marked unknown, not ticked', async () => {
    const merged = await mergeOf([ordersApi, platformAuthz]); // neither carries `parse`
    const text = formatEstateReport(estateReport(merged));
    expect(text).toMatch(/\? orders-api — .*parse state unknown/);
    expect(text).not.toMatch(/✓ orders-api/);
  });

  it('the estate-wide green line refuses the word clean when a parse errored', async () => {
    const merged = withParse(await mergeOf([ordersApi, platformAuthz]), {
      'orders-api': { errors: 1, warnings: 0, unparsed_annotations: 4 },
      'platform-authz': { errors: 0, warnings: 0, unparsed_annotations: 0 },
    });
    const r = estateReport(merged);
    expect(r.open).toHaveLength(0); // nothing open — and still not clean
    const text = formatEstateReport(r);
    expect(text).toMatch(/1 parse error\(s\) left 4 annotation line\(s\) unread — this is not a clean estate/);
    expect(text).not.toMatch(/✓ No open exposures/);
  });

  it('names the repos that did not report, in the same breath as the tick', async () => {
    const merged = withParse(await mergeOf([ordersApi, platformAuthz]), {
      'platform-authz': { errors: 0, warnings: 0, unparsed_annotations: 0 },
    });
    const text = formatEstateReport(estateReport(merged));
    expect(text).toMatch(/✓ No open exposures/);
    expect(text).toMatch(/1 repo\(s\) did not report their parse state — whether their annotations were all read is unknown, not clean/);
  });

  it('parse errors gate under --strict; warnings never do — the split `ci` and `merge` already make', async () => {
    const base = await mergeOf([ordersApi, platformAuthz]);
    const errored = withParse(base, {
      'orders-api': { errors: 1, warnings: 0, unparsed_annotations: 1 },
      'platform-authz': { errors: 0, warnings: 0, unparsed_annotations: 0 },
    });
    const warned = withParse(base, {
      'orders-api': { errors: 0, warnings: 5, unparsed_annotations: 12 },
      'platform-authz': { errors: 0, warnings: 0, unparsed_annotations: 0 },
    });
    expect(estateReport(errored, { strict: true }).summary.exit_code).toBe(1);
    expect(estateReport(warned, { strict: true }).summary.exit_code).toBe(0);
    // An old report still does not fail — it is not a finding, it is named.
    expect(estateReport(base, { strict: true }).summary.exit_code).toBe(0);
    // And advisory stays advisory in every one of those cases.
    expect(estateReport(errored).summary.exit_code).toBe(0);
  });

  it('agrees with `merge --strict` over the same file rather than giving a second opinion', async () => {
    const merged = withParse(await mergeOf([ordersApi, platformAuthz]), {
      'orders-api': { errors: 2, warnings: 0, unparsed_annotations: 5 },
      'platform-authz': { errors: 0, warnings: 0, unparsed_annotations: 0 },
    });
    // `merge`'s own totals, recomputed the way mergeVerdict reads them.
    const loaded = merged.repo_statuses.filter(s => s.loaded);
    const mergeParseErrors = loaded.reduce((n, s) => n + (s.parse?.errors ?? 0), 0);
    expect(estateReport(merged).summary.parse_errors).toBe(mergeParseErrors);
    expect(estateReport(merged, { strict: true }).summary.exit_code).toBe(1);
  });
});
