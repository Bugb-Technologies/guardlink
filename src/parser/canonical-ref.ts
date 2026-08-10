/**
 * GuardLink — one canonical identity for an asset reference.
 *
 * `#db`, `db`, `DB` and `Svc.Db` are four spellings of one asset when the model
 * declares `@asset Svc.Db (#db)`. This resolves all four to `db`.
 *
 * ── Why it lives in the parser and not next to its first caller ─────
 *
 * It was written for `guardlink_graph` and lived in `mcp/subgraph.ts`, which
 * made it unreachable from `parser/coverage.ts` without inverting the layering
 * (`parser` → `mcp` → `parser/feature-filter`). D47 was the cost of that: the
 * graph resolved `Svc.Db` and `#db` to one node while coverage treated them as
 * two assets, so a mitigation written in dotted form did not cover an exposure
 * written in hash form, and `guardlink_graph` and `guardlink validate` disagreed
 * about the same model.
 *
 * Moved here rather than copied. D57 is the standing lesson: the coverage
 * predicate was reimplemented twenty-one times and wrong in twenty of them, and
 * a second resolver would be the same mistake one layer down.
 * `mcp/subgraph.ts` re-exports this so its own callers are unaffected.
 *
 * ── The safety property, which is the whole point ───────────────────
 *
 * Aliasing ADDS coverage, and adding coverage is the direction that hides
 * vulnerabilities. So the map is built from DECLARED assets only:
 *
 *   - an asset with no `id` contributes nothing
 *   - only two keys are registered per asset — its `id` and its dotted path
 *   - an unknown ref falls through to its bare form, which is exactly what
 *     coverage did before aliasing existed
 *
 * A reference therefore resolves to a different string than it did before if
 * and only if the model declares an asset whose dotted path or id it matches.
 * Two references collapse together only when the model itself says they are the
 * same declared asset. Nothing is inferred from spelling similarity.
 *
 * @comment -- "Aliasing can only ever ADD coverage, so the map is built from declared assets only; an undeclared ref resolves to itself, which is the pre-D47 behaviour"
 */
import type { ThreatModel } from '../types/index.js';

/**
 * A function mapping any asset reference to its canonical id.
 *
 * Built once per model; the returned closure is pure.
 */
export function canonicaliser(model: ThreatModel): (ref: string) => string {
  const canon = new Map<string, string>();
  // `?? []` because this moved onto the coverage path, which is called with
  // partially-constructed models — several SARIF fixtures build a model with
  // exposures and flows and no `assets` at all. On the graph path it only ever
  // saw complete models from the parser. A missing collection means "nothing
  // declared", which resolves every ref to its bare form: the pre-D47 behaviour.
  for (const a of model.assets ?? []) {
    if (!a.id) continue;
    const id = a.id.toLowerCase();
    canon.set(id, id);
    canon.set(a.path.join('.').toLowerCase(), id);
  }
  return (ref: string) => {
    const bare = (ref ?? '').trim().replace(/^#/, '').toLowerCase();
    return canon.get(bare) ?? bare;
  };
}
