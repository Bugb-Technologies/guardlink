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
 * ── Gated and ungated effects ────────────────────────────────────────
 *
 * `@gates <asset> by <approver>` stands in front of every effect on the asset;
 * with `for <capability>` it stands only in front of that capability's route.
 * An `@effects` names no capability, so the only capability this module can
 * tie to an effect is that of a reach bound to the same code (`boundCode`):
 * the `@agents` and `@effects` written in one doc-block on a tool handler. A
 * capability-scoped gate therefore covers an effect only when every reach
 * bound to the effect's code is that capability. With no reach bound there,
 * the route is unknown and the scoped gate does not count. Whether a gate is
 * really on the route at runtime is a code-graph question this pure join
 * cannot answer, so a covered effect is still a claim to test.
 *
 * ── The export ───────────────────────────────────────────────────────
 *
 * `buildReachAnalysis` is the derived block the model JSON carries as
 * `reach_analysis` (SPEC §5.5): both joins above, with the claim key of each
 * row so a consumer can join it to the SARIF `guardlink/agent-reach` results.
 *
 * @comment -- "Pure functions over an assembled ThreatModel; no I/O. Uncited entitlements never cover a reach, and a gate scoped to a capability never covers an effect whose route is unknown, so both joins err toward showing a capability or an effect rather than hiding one"
 */
import type {
  ThreatModel, ThreatModelReach, ThreatModelEntitlement, ThreatModelEffect, ThreatModelGate,
  EffectClass, SourceLocation,
} from '../types/index.js';
import { canonicaliser } from './canonical-ref.js';
import { normalizeName } from './normalize.js';
import { normalizeRef } from './coverage.js';
import { relationRecords } from './claim-key.js';

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

// ─── Bound code ─────────────────────────────────────────────────────

/**
 * The code a claim is written on: its file and structure-layer anchor (SPEC
 * §5.2). Claims written in one doc-block bind to the same declaration, so they
 * share it. Null when the location has no anchor, or a file-scope one: an
 * anchor on the whole file describes no particular code, and reading every
 * claim in it as bound together would invent links the author never wrote.
 */
export function boundCode(location: SourceLocation): string | null {
  const a = location.anchor;
  if (!a || a.scope === 'file') return null;
  return `${location.file}\u0000${a.start_line}\u0000${a.end_line}`;
}

// ─── Gated and ungated effects ──────────────────────────────────────

/** Every effect that changes something. `read` is the one that does not. */
export const MUTATING_EFFECTS: ReadonlySet<EffectClass> = new Set(['write', 'delete', 'execute', 'spend', 'notify']);

export const isMutatingEffect = (effect: EffectClass): boolean => MUTATING_EFFECTS.has(effect);

/**
 * Why a gate on the effect's asset does not cover it. `capability-unknown`: the
 * gate is scoped to a capability and no reach is bound to the effect's code, so
 * nothing says which route reaches it. `other-capability`: a reach bound there
 * is a capability the gate is not scoped to.
 */
export type GateCoverBlocker = 'capability-unknown' | 'other-capability';

export interface EffectGating {
  effect: ThreatModelEffect;
  /** Reaches bound to the same code as the effect, in model order. */
  colocated_reaches: ThreatModelReach[];
  /** Gates that cover the effect. Empty means the effect is ungated. */
  gates: ThreatModelGate[];
  /** Gates on the same asset that still do not cover it, each with the reason. Empty when it is gated. */
  near_misses: { gate: ThreatModelGate; blocker: GateCoverBlocker }[];
}

/**
 * Every `@effects` claim with the gates in front of it, in model order. See
 * the module note for the join.
 */
export function classifyEffects(model: ThreatModel): EffectGating[] {
  const assetKey = canonicaliser(model);
  const gatesOn = new Map<string, ThreatModelGate[]>();
  for (const g of model.gates ?? []) {
    const k = assetKey(g.asset);
    gatesOn.set(k, [...(gatesOn.get(k) ?? []), g]);
  }
  const reachesAt = new Map<string, ThreatModelReach[]>();
  for (const r of model.reaches ?? []) {
    const k = boundCode(r.location);
    if (k) reachesAt.set(k, [...(reachesAt.get(k) ?? []), r]);
  }

  return (model.effects ?? []).map(effect => {
    const code = boundCode(effect.location);
    const colocated = code ? reachesAt.get(code) ?? [] : [];
    const capabilities = new Set(colocated.map(r => r.canonical_capability));
    const candidates = gatesOn.get(assetKey(effect.asset)) ?? [];

    const unscoped = candidates.filter(g => !g.canonical_capability);
    // Scoped gates cover the effect together, when every capability bound to
    // its code has one; a single scoped gate covers nothing on its own unless
    // it is the only capability there.
    const scoped = candidates.filter(g => g.canonical_capability);
    const scopedCovers = capabilities.size > 0
      && [...capabilities].every(c => scoped.some(g => g.canonical_capability === c));
    const covering = [...unscoped, ...(scopedCovers ? scoped.filter(g => capabilities.has(g.canonical_capability!)) : [])];
    const near_misses: EffectGating['near_misses'] = covering.length > 0 ? [] : scoped.map(gate => ({
      gate,
      blocker: capabilities.size === 0 ? 'capability-unknown' as const : 'other-capability' as const,
    }));
    return {
      effect,
      colocated_reaches: colocated,
      // Model order, whichever rule admitted each gate.
      gates: candidates.filter(g => covering.includes(g)),
      near_misses,
    };
  });
}

/** Every mutating `@effects` claim no gate covers, in model order. */
export function findUngatedEffects(model: ThreatModel): EffectGating[] {
  return classifyEffects(model).filter(g => isMutatingEffect(g.effect.effect) && g.gates.length === 0);
}

// ─── The export: reach_analysis ─────────────────────────────────────

/**
 * Version of the `reach_analysis` block's shape (SPEC §5.5). Bumped when a key
 * is renamed or removed, or a rule above changes what a row means; adding a key
 * does not bump it.
 */
export const REACH_ANALYSIS_VERSION = 1 as const;

/** A pointer to one claim: its index in the model array named by the row, and its claim key. */
interface ClaimRef {
  index: number;
  claim_key: string | null;
  file: string;
  line: number;
}

export interface ReachAnalysisReach extends ClaimRef {
  verb: 'agents' | 'reaches';
  actor: string;
  agent: boolean;
  capability: string;
  canonical_capability: string;
  asset: string | null;
  identity: string | null;
  description: string | null;
}

export interface ReachAnalysisEffect extends ClaimRef {
  effect: EffectClass;
  asset: string;
  identity: string | null;
  description: string | null;
}

export interface ReachAnalysisGate extends ClaimRef {
  asset: string;
  approver: string;
  capability: string | null;
  canonical_capability: string | null;
}

export interface ReachAnalysisEntitlement extends ClaimRef {
  actor: string;
  capability: string;
  asset: string | null;
  cited: boolean;
}

export interface ReachAnalysis {
  version: typeof REACH_ANALYSIS_VERSION;
  summary: {
    reaches: number;
    agent_reaches: number;
    unentitled_reaches: number;
    effects: number;
    mutating_effects: number;
    ungated_effects: number;
    gates: number;
  };
  /** Can minus may: every reach no cited entitlement covers, in model order. */
  unentitled_reaches: (ReachAnalysisReach & {
    near_misses: (ReachAnalysisEntitlement & { blocker: ReachCoverBlocker })[];
    /** Effects bound to the same code as the reach. */
    colocated_effects: ReachAnalysisEffect[];
  })[];
  /** Every effect other than `read`, gated or not, in model order. */
  mutating_effects: (ReachAnalysisEffect & {
    gated: boolean;
    gates: ReachAnalysisGate[];
    gate_near_misses: (ReachAnalysisGate & { blocker: GateCoverBlocker })[];
    /** Reaches bound to the same code as the effect. */
    colocated_reaches: ReachAnalysisReach[];
  })[];
}

/** Whether a model declares anything `reach_analysis` is computed from. */
export function hasReachClaims(model: ThreatModel): boolean {
  return (model.reaches?.length ?? 0) + (model.effects?.length ?? 0) + (model.gates?.length ?? 0) > 0;
}

/**
 * The derived `reach_analysis` block for `model` (SPEC §5.5). Indexes point
 * into the arrays of the same model, so it must be built from the model it is
 * exported with — after any filtering or reordering, never before.
 */
export function buildReachAnalysis(model: ThreatModel): ReachAnalysis {
  const keyOf = new Map<object, string>();
  for (const r of relationRecords(model)) keyOf.set(r.location, r.key);
  const indexer = <T extends object>(items: readonly T[] | undefined) => {
    const at = new Map<T, number>();
    (items ?? []).forEach((x, i) => at.set(x, i));
    return (x: T) => at.get(x) ?? -1;
  };
  const reachIndex = indexer(model.reaches);
  const effectIndex = indexer(model.effects);
  const gateIndex = indexer(model.gates);
  const entitlementIndex = indexer(model.entitlements);
  const ref = (index: number, location: SourceLocation): ClaimRef => ({
    index, claim_key: keyOf.get(location) ?? null, file: location.file, line: location.line,
  });

  const reachRow = (r: ThreatModelReach): ReachAnalysisReach => ({
    ...ref(reachIndex(r), r.location),
    verb: r.agent ? 'agents' : 'reaches',
    actor: r.actor,
    agent: r.agent,
    capability: r.capability,
    canonical_capability: r.canonical_capability,
    asset: r.asset ?? null,
    identity: r.identity ?? null,
    description: r.description ?? null,
  });
  const effectRow = (e: ThreatModelEffect): ReachAnalysisEffect => ({
    ...ref(effectIndex(e), e.location),
    effect: e.effect,
    asset: e.asset,
    identity: e.identity ?? null,
    description: e.description ?? null,
  });
  const gateRow = (g: ThreatModelGate): ReachAnalysisGate => ({
    ...ref(gateIndex(g), g.location),
    asset: g.asset,
    approver: g.approver,
    capability: g.capability ?? null,
    canonical_capability: g.canonical_capability ?? null,
  });

  const gating = classifyEffects(model);
  const effectsAt = new Map<string, ThreatModelEffect[]>();
  for (const e of model.effects ?? []) {
    const k = boundCode(e.location);
    if (k) effectsAt.set(k, [...(effectsAt.get(k) ?? []), e]);
  }

  const unentitled = findUnentitledReaches(model).map(({ reach, near_misses }) => {
    const code = boundCode(reach.location);
    return {
      ...reachRow(reach),
      near_misses: near_misses.map(({ entitlement: en, blocker }) => ({
        ...ref(entitlementIndex(en), en.location),
        actor: en.actor,
        capability: en.capability,
        asset: en.asset ?? null,
        cited: !en.inert,
        blocker,
      })),
      colocated_effects: (code ? effectsAt.get(code) ?? [] : []).map(effectRow),
    };
  });

  const mutating = gating.filter(g => isMutatingEffect(g.effect.effect)).map(g => ({
    ...effectRow(g.effect),
    gated: g.gates.length > 0,
    gates: g.gates.map(gateRow),
    gate_near_misses: g.near_misses.map(n => ({ ...gateRow(n.gate), blocker: n.blocker })),
    colocated_reaches: g.colocated_reaches.map(reachRow),
  }));

  return {
    version: REACH_ANALYSIS_VERSION,
    summary: {
      reaches: model.reaches?.length ?? 0,
      agent_reaches: (model.reaches ?? []).filter(r => r.agent).length,
      unentitled_reaches: unentitled.length,
      effects: model.effects?.length ?? 0,
      mutating_effects: mutating.length,
      ungated_effects: mutating.filter(m => !m.gated).length,
      gates: model.gates?.length ?? 0,
    },
    unentitled_reaches: unentitled,
    mutating_effects: mutating,
  };
}

/**
 * `model` as it is exported: with a freshly built `reach_analysis` when it
 * declares any reach, effect or gate, and without one otherwise. A model with
 * none of those verbs therefore exports exactly the bytes it did before the
 * block existed, and a stale block from an earlier export is never carried.
 */
export function withReachAnalysis<T extends ThreatModel>(model: T): T {
  const { reach_analysis: _stale, ...rest } = model;
  return (hasReachClaims(model) ? { ...rest, reach_analysis: buildReachAnalysis(model) } : rest) as T;
}
