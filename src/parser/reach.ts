/**
 * GuardLink — what a principal can reach, against what it may.
 *
 * `@agents` and `@reaches` say an actor CAN invoke a capability; `@entitles`
 * says a human decided it MAY. A reach that no entitlement covers is a
 * capability the harness hands out and nobody approved: for an LLM agent that
 * is the Excessive Agency list (OWASP LLM06). This module is the one place
 * that join is written, so `lookup` and `diff` cannot disagree about it.
 *
 * ── The join ─────────────────────────────────────────────────────────
 *
 * An entitlement covers a reach when all of these hold:
 *
 *   - the same actor, after resolving `#id` and declared name to one identity;
 *   - the same capability, compared on the §2.10-normalised token both verbs
 *     write in the same position;
 *   - the entitlement is cited. An uncited (inert) entitlement cannot demote a
 *     finding (§3.4), so it must not close a reach either;
 *   - when the reach names an asset, the entitlement names the same asset. A
 *     grant on one surface says nothing about the same capability on another,
 *     and an entitlement that names no asset is not read as covering all of
 *     them. When the reach names no asset, any asset on the entitlement will do.
 *
 * Every rule errs toward reporting a reach. A reach reported in error costs a
 * reviewer a look; a reach hidden in error is the over-grant this exists to find.
 *
 * Whether an `@entitles` in source has an accepted proposal behind it is not
 * checked here: that needs the proposal ledger on disk, this module is pure,
 * and `validate` already reports such an entitlement as an error.
 *
 * @comment -- "Pure functions over an assembled ThreatModel; no I/O. Uncited entitlements never cover a reach, so the can-minus-may answer errs toward showing a capability rather than hiding one"
 */
import type { ThreatModel, ThreatModelReach, ThreatModelEntitlement } from '../types/index.js';
import { canonicaliser } from './canonical-ref.js';
import { normalizeName } from './normalize.js';
import { normalizeRef } from './coverage.js';

/** Why an entitlement for the same actor and capability does not cover a reach. */
export type ReachCoverBlocker = 'uncited' | 'no-asset' | 'other-asset';

export interface UnentitledReach {
  reach: ThreatModelReach;
  /**
   * Entitlements naming this actor and capability that still do not cover the
   * reach, each with the reason. Empty when no entitlement names the pair at all.
   */
  near_misses: { entitlement: ThreatModelEntitlement; blocker: ReachCoverBlocker }[];
}

/**
 * One identity per actor reference: `#support-agent`, `support-agent` and the
 * declared name `Support_Agent` all resolve to the declared actor's id. An
 * undeclared ref resolves to its bare lowercase form, which `validate` reports.
 */
export function actorResolver(model: ThreatModel): (ref: string) => string {
  const canon = new Map<string, string>();
  for (const ac of model.actors ?? []) {
    const identity = (ac.id ?? ac.canonical_name).toLowerCase();
    if (ac.id) canon.set(ac.id.toLowerCase(), identity);
    canon.set(ac.canonical_name.toLowerCase(), identity);
  }
  return (ref: string) => {
    const bare = normalizeRef(ref);
    return canon.get(bare) ?? canon.get(normalizeName(bare)) ?? bare;
  };
}

/**
 * Why `entitlement` does not cover `reach`, or null when it does. Callers have
 * already matched actor and capability.
 */
function coverBlocker(
  reach: ThreatModelReach,
  entitlement: ThreatModelEntitlement,
  assetKey: (ref: string) => string,
): ReachCoverBlocker | null {
  if (entitlement.inert) return 'uncited';
  if (!reach.asset) return null;
  if (!entitlement.asset) return 'no-asset';
  return assetKey(entitlement.asset) === assetKey(reach.asset) ? null : 'other-asset';
}

/**
 * Every `@agents` / `@reaches` claim no `@entitles` covers, in model order.
 * See the module note for the join.
 */
export function findUnentitledReaches(model: ThreatModel): UnentitledReach[] {
  const actorKey = actorResolver(model);
  const assetKey = canonicaliser(model);
  const byPair = new Map<string, ThreatModelEntitlement[]>();
  for (const en of model.entitlements ?? []) {
    const pair = `${actorKey(en.actor)}::${en.canonical_capability}`;
    byPair.set(pair, [...(byPair.get(pair) ?? []), en]);
  }

  const out: UnentitledReach[] = [];
  for (const reach of model.reaches ?? []) {
    const candidates = byPair.get(`${actorKey(reach.actor)}::${reach.canonical_capability}`) ?? [];
    const near_misses: UnentitledReach['near_misses'] = [];
    let covered = false;
    for (const entitlement of candidates) {
      const blocker = coverBlocker(reach, entitlement, assetKey);
      if (!blocker) { covered = true; break; }
      near_misses.push({ entitlement, blocker });
    }
    if (!covered) out.push({ reach, near_misses });
  }
  return out;
}

/**
 * Identity of a reach for comparing two models: actor, capability and asset.
 * Used by `diff` to tell a newly unentitled reach from one that already was.
 */
export function reachKey(model: ThreatModel): (reach: ThreatModelReach) => string {
  const actorKey = actorResolver(model);
  const assetKey = canonicaliser(model);
  return (r: ThreatModelReach) => `${actorKey(r.actor)}::${r.canonical_capability}::${r.asset ? assetKey(r.asset) : ''}`;
}
