/**
 * GuardLink — Shared validation helpers.
 *
 * Extracted from cli/index.ts and tui/commands.ts to eliminate duplication
 * and ensure consistent validation logic across all entry points.
 *
 * @mitigates #parser against #tag-collision using #prefix-ownership -- "findDanglingRefs ensures #id refs resolve to definitions"
 * @comment -- "@confirmed refs validated same as @exposes for asset and threat"
 * @comment -- "findUnresolvedBoundarySides errors on a directed @boundary whose outer or inner side names no declared asset and no @flows endpoint, so a declared direction cannot point consumers at nothing"
 * @comment -- "findUndeclaredActors / findInertEntitlements implement the two mechanical @entitles checks from docs/prd/actor-entitlement-design.md §3.7 — both typo-class; entitlement intent is not machine-checkable"
 * @comment -- "findUndeclaredActors also covers the actor on @agents/@reaches and the approver on @gates; findAgentReachConflicts errors when one actor is written under both @agents and @reaches, because which verb names an actor is what says whether it is an agent"
 */

import {
  isConventionalGalPath, sourceFileForGal, galPathFor, offConventionMessage,
} from './gal-path.js';
// MERGE: `ThreatModelExposure` left with main's findUnmitigatedExposures /
// findAcceptedExposures — those were the old pair-keyed pair, and D36/D57 moved
// both to parser/coverage.ts, which this file now re-exports from (below).
import type { ThreatModel, ParseDiagnostic, SourceLocation } from '../types/index.js';
import { normalizeName } from './normalize.js';
import { canonicaliser } from './canonical-ref.js';
import { entitlementDemotionBlockers } from './parse-project.js';
import { actorResolver } from './reach.js';

/**
 * Find all dangling #id references in the threat model.
 * A dangling ref is a #id used in a relationship/lifecycle annotation
 * that was never defined via @asset, @threat, @control, or @boundary.
 */
export function findDanglingRefs(model: ThreatModel): ParseDiagnostic[] {
  const diagnostics: ParseDiagnostic[] = [];

  // Collect all defined IDs
  const definedIds = new Set<string>();
  for (const a of model.assets) if (a.id) definedIds.add(a.id);
  for (const t of model.threats) if (t.id) definedIds.add(t.id);
  for (const c of model.controls) if (c.id) definedIds.add(c.id);
  for (const b of model.boundaries) if (b.id) definedIds.add(b.id);
  for (const ac of model.actors || []) if (ac.id) definedIds.add(ac.id);

  const checkRef = (ref: string, loc: { file: string; line: number }) => {
    if (ref.startsWith('#')) {
      const id = ref.slice(1);
      if (!definedIds.has(id)) {
        diagnostics.push({
          level: 'warning',
          code: 'dangling-ref',
          message: `Dangling reference: #${id} is never defined`,
          file: loc.file,
          line: loc.line,
        });
      }
    }
  };

  // Relationship annotations — check both threat/control AND asset refs
  for (const m of model.mitigations) {
    checkRef(m.asset, m.location);
    checkRef(m.threat, m.location);
    if (m.control) checkRef(m.control, m.location);
  }
  for (const e of model.exposures) {
    checkRef(e.asset, e.location);
    checkRef(e.threat, e.location);
  }
  for (const c of model.confirmed || []) {
    checkRef(c.asset, c.location);
    checkRef(c.threat, c.location);
  }
  for (const a of model.acceptances) {
    checkRef(a.asset, a.location);
    checkRef(a.threat, a.location);
  }
  for (const t of model.transfers) {
    checkRef(t.threat, t.location);
    checkRef(t.source, t.location);
    checkRef(t.target, t.location);
  }
  for (const f of model.flows) {
    checkRef(f.source, f.location);
    checkRef(f.target, f.location);
  }
  for (const b of model.boundaries) {
    checkRef(b.asset_a, b.location);
    checkRef(b.asset_b, b.location);
  }

  // Entitlements — the actor ref is checked by findUndeclaredActors (an error,
  // not a warning), so only the two join clauses are checked here. `against
  // <threat>` is checked for the same reason every other threat ref is: a claim
  // naming a threat nobody declared joins no finding, and a typo in that slot is
  // the silent miss §9 exists to prevent. Omitting the clause is fine (§9.3);
  // naming a threat that does not exist is not.
  for (const en of model.entitlements || []) {
    if (en.asset) checkRef(en.asset, en.location);
    if (en.threat) checkRef(en.threat, en.location);
  }

  // Reach, effect and gate. Actors (the reaching actor, the approver) are
  // checked by findUndeclaredActors, as on @entitles; assets and identities here.
  for (const r of model.reaches || []) {
    if (r.asset) checkRef(r.asset, r.location);
    if (r.identity) checkRef(r.identity, r.location);
  }
  for (const ef of model.effects || []) {
    checkRef(ef.asset, ef.location);
    if (ef.identity) checkRef(ef.identity, ef.location);
  }
  for (const g of model.gates || []) checkRef(g.asset, g.location);

  // Lifecycle annotations — check asset refs
  for (const v of model.validations) {
    checkRef(v.control, v.location);
    checkRef(v.asset, v.location);
  }
  for (const a of model.audits) checkRef(a.asset, a.location);
  for (const o of model.ownership) checkRef(o.asset, o.location);
  for (const h of model.data_handling) checkRef(h.asset, h.location);
  for (const a of model.assumptions) checkRef(a.asset, a.location);

  return diagnostics;
}

/**
 * Find directed `@boundary from <outer> to <inner>` annotations naming a side the
 * model cannot place.
 *
 * A direction is only worth declaring if a reader can act on it: a test probes
 * the inner side from the outer one, and the SARIF export states both as graph
 * nodes. A side that names nothing — a typo, a renamed asset — still parses and
 * still exports as `basis: "declared"`, so consumers would trust a direction
 * pointing at no component. That is why this is an error, where a dangling ref
 * on an undirected boundary is a warning: the undirected form claims no side.
 *
 * A side resolves when it is:
 *   - a `#tag` that a declared `@asset` defines as its id;
 *   - any other name that is a declared asset's path, or an endpoint some `@flows`
 *     names (an undeclared endpoint such as `Client` is how the model writes the
 *     outside, SPEC §3.2).
 * A repository-qualified `#repo.tag` belongs to another repository and is
 * resolved by `guardlink merge`, not here. Undirected boundaries are not checked.
 */
export function findUnresolvedBoundarySides(model: ThreatModel): ParseDiagnostic[] {
  const key = canonicaliser(model);
  const assetIds = new Set<string>();
  const names = new Set<string>();
  for (const a of model.assets ?? []) {
    if (a.id) assetIds.add(a.id.toLowerCase());
    names.add(key(a.path.join('.')));
  }
  for (const f of model.flows ?? []) {
    names.add(key(f.source));
    names.add(key(f.target));
  }
  const resolves = (ref: string): boolean => {
    if (ref.startsWith('#')) {
      const id = ref.slice(1);
      return id.includes('.') || assetIds.has(id.toLowerCase());
    }
    return names.has(key(ref));
  };

  const diagnostics: ParseDiagnostic[] = [];
  for (const b of model.boundaries ?? []) {
    if (!b.directed) continue;
    const unresolved = [['outer', b.asset_a], ['inner', b.asset_b]].filter(([, ref]) => !resolves(ref));
    if (unresolved.length === 0) continue;
    diagnostics.push({
      level: 'error',
      code: 'unresolved-boundary-side',
      message: `@boundary from ${b.asset_a} to ${b.asset_b}${b.id ? ` (#${b.id})` : ''} declares a direction, but its `
        + `${unresolved.map(([role, ref]) => `${role} side ${ref}`).join(' and ')} `
        + `${unresolved.length === 1 ? 'resolves' : 'resolve'} to no declared @asset and no @flows endpoint. `
        + 'Declare it with @asset, name it in the @flows that crosses the boundary, or correct the reference.',
      file: b.location.file,
      line: b.location.line,
    });
  }
  return diagnostics;
}

/**
 * Coverage lives in `coverage.ts` — one predicate for the whole product (D36).
 * Re-exported here because every existing caller imports it from this module.
 */
export { findUnmitigatedExposures, findAcceptedExposures, normalizeRef } from './coverage.js';
import { normalizeRef } from './coverage.js';

/**
 * Find annotations naming an actor that was never declared with @actor: the
 * actor on `@entitles`, `@agents` and `@reaches`, and the approver on `@gates`.
 *
 * This is one of the two mechanical checks §3.7 of the actor/entitlement design
 * calls for — both are typo-class. Neither can verify *intent*: whether an actor
 * really is entitled to a capability is a statement about purpose that no check
 * can derive from the code. It is an error rather than a warning because an
 * entitlement pointing at a non-existent principal can never be joined
 * downstream, so it is silently inoperative — the failure mode this design is
 * built to avoid. The same holds for a reach: one naming a misspelt actor joins
 * no entitlement and reads as unentitled for a principal that does not exist,
 * and a gate whose approver is nobody is not a gate.
 */
export function findUndeclaredActors(model: ThreatModel): ParseDiagnostic[] {
  const diagnostics: ParseDiagnostic[] = [];

  const declared = new Set<string>();
  for (const ac of model.actors || []) {
    if (ac.id) declared.add(ac.id);
    declared.add(ac.canonical_name);
  }

  const check = (actor: string, claim: string, location: SourceLocation) => {
    const bare = normalizeRef(actor);
    if (declared.has(bare) || declared.has(normalizeName(bare))) return;
    diagnostics.push({
      level: 'error',
      code: 'undeclared-actor',
      message: `${claim} names actor ${actor} which is never declared with @actor`,
      file: location.file,
      line: location.line,
    });
  };

  for (const en of model.entitlements || []) check(en.actor, '@entitles', en.location);
  for (const r of model.reaches || []) check(r.actor, r.agent ? '@agents' : '@reaches', r.location);
  for (const g of model.gates || []) check(g.approver, '@gates', g.location);

  return diagnostics;
}

/**
 * Find actors named under both `@agents` and `@reaches`.
 *
 * Writing `@agents` about an actor is what marks it as an LLM agent; `@reaches`
 * is the same claim for every other principal. An actor under both verbs is
 * therefore both an agent and not one, and every check that keys on agents
 * (the injection-to-tool routes among them) would answer differently depending
 * on which line it read. It is an error, reported on each `@reaches` line,
 * because the fix is to choose one verb for the actor.
 */
export function findAgentReachConflicts(model: ThreatModel): ParseDiagnostic[] {
  const actorKey = actorResolver(model);
  const agentLines = new Map<string, SourceLocation>();
  for (const r of model.reaches || []) {
    const key = actorKey(r.actor);
    if (r.agent && !agentLines.has(key)) agentLines.set(key, r.location);
  }

  const diagnostics: ParseDiagnostic[] = [];
  for (const r of model.reaches || []) {
    if (r.agent) continue;
    const agentAt = agentLines.get(actorKey(r.actor));
    if (!agentAt) continue;
    diagnostics.push({
      level: 'error',
      code: 'agent-reach-conflict',
      message: `@reaches names ${r.actor}, which @agents marks as an agent at ${agentAt.file}:${agentAt.line}. `
        + 'An actor is an agent or it is not: write @agents for an LLM agent and @reaches for every other principal.',
      file: r.location.file,
      line: r.location.line,
    });
  }
  return diagnostics;
}

/**
 * Find @entitles annotations that cite no authorization code (§3.4).
 *
 * These are inert: parsed, exported, and ignored by downstream triage. Reported
 * as a warning rather than an error — the annotation is well-formed, it simply
 * has no effect until someone points it at the code that grants the privilege.
 */
export function findInertEntitlements(model: ThreatModel): ParseDiagnostic[] {
  const diagnostics: ParseDiagnostic[] = [];

  for (const en of model.entitlements || []) {
    if (!en.inert) continue;
    diagnostics.push({
      level: 'warning',
      code: 'inert-entitlement',
      message: `@entitles ${en.actor} to ${en.capability} cites no authorization code — inert, will not demote any finding. Add a file:line pointer to the authz check in the description.`,
      file: en.location.file,
      line: en.location.line,
    });
  }

  return diagnostics;
}

/**
 * Find @entitles annotations that join nothing, because `on <asset>` or
 * `against <threat>` is missing (§9.3).
 *
 * Reported for the same reason `findInertEntitlements` reports an uncited claim:
 * it parses, it looks like it works, and it does nothing. Triage holds an
 * (asset, threat) pair, so a claim missing either half can never match one —
 * writing it is wasted effort the author has no other way to discover. Kept
 * separate from the inert check so the message can name the missing half rather
 * than saying "ineffective" and leaving the author to guess which.
 */
export function findImpreciseEntitlements(model: ThreatModel): ParseDiagnostic[] {
  const diagnostics: ParseDiagnostic[] = [];

  for (const en of model.entitlements || []) {
    const missing = entitlementDemotionBlockers(en).filter(b => b !== 'uncited');
    if (missing.length === 0) continue;
    const needs = missing
      .map(b => (b === 'no-asset' ? 'on <asset>' : 'against <threat>'))
      .join(' and ');
    diagnostics.push({
      level: 'warning',
      code: 'imprecise-entitlement',
      message:
        `@entitles ${en.actor} to ${en.capability} is missing ${needs}, so it joins no finding `
        + 'and will not demote anything. Triage matches on (actor, asset, threat).',
      file: en.location.file,
      line: en.location.line,
    });
  }

  return diagnostics;
}

/**
 * Find @accepts annotations where the accepted asset has no corresponding @audit.
 * Risk acceptance without an audit trail is a governance concern — the acceptance
 * may be rubber-stamped (e.g., by an AI agent) rather than a deliberate human decision.
 */
export function findAcceptedWithoutAudit(model: ThreatModel): ParseDiagnostic[] {
  const diagnostics: ParseDiagnostic[] = [];

  // Build set of audited assets (normalized)
  const auditedAssets = new Set<string>();
  for (const a of model.audits) {
    auditedAssets.add(normalizeRef(a.asset));
  }

  for (const acc of model.acceptances) {
    const assetNorm = normalizeRef(acc.asset);
    if (!auditedAssets.has(assetNorm)) {
      diagnostics.push({
        level: 'warning',
        code: 'accepted-without-audit',
        message: `@accepts ${acc.threat} on ${acc.asset} without @audit — risk acceptance should be paired with @audit for traceability`,
        file: acc.location.file,
        line: acc.location.line,
      });
    }
  }

  return diagnostics;
}

/**
 * Warn about `.gal` sidecars that are not where the convention says they should be.
 *
 * Enforced by warning, never by refusing to parse. An off-convention file still
 * contributes every annotation it carries — silently dropping a developer's work
 * because it sits in the wrong directory is precisely the failure GL-503 fixed,
 * and reintroducing it as "enforcement" would be worse, not better.
 */
export function findOffConventionGalFiles(model: ThreatModel): ParseDiagnostic[] {
  // Group every annotation by the sidecar it was written in.
  const byOrigin = new Map<string, Set<string>>();
  for (const location of allLocations(model)) {
    const origin = location.origin_file;
    if (!origin) continue;
    if (!byOrigin.has(origin)) byOrigin.set(origin, new Set());
    byOrigin.get(origin)!.add(location.file);
  }

  const diagnostics: ParseDiagnostic[] = [];
  for (const [origin, sources] of [...byOrigin.entries()].sort()) {
    if (isConventionalGalPath(origin)) {
      // On-convention, but does it annotate the file it claims to? A sidecar at
      // annotations/src/a.ts.gal carrying @source blocks for src/b.ts parses
      // fine and is a maintenance trap.
      const expected = sourceFileForGal(origin);
      const strays = [...sources].filter(s => s !== expected);
      if (strays.length > 0) {
        diagnostics.push({
          level: 'warning',
          code: 'stray-gal-source',
          message: `\`${origin}\` is the sidecar for \`${expected}\` but carries @source blocks for `
            + `${strays.join(', ')}. Those belong in their own sidecars: `
            + `${strays.map(s => galPathFor(s)).join(', ')}. `
            + `It is still parsed — this is a convention, not a requirement.`,
          file: origin,
          line: 1,
        });
      }
      continue;
    }
    diagnostics.push({
      level: 'warning',
      code: 'off-convention-gal',
      message: offConventionMessage(origin, [...sources].sort()),
      file: origin,
      line: 1,
    });
  }
  return diagnostics;
}

/** Every annotation location in the model, across all relation types. */
function allLocations(model: ThreatModel): SourceLocation[] {
  return [
    ...model.assets, ...model.threats, ...model.controls,
    ...model.mitigations, ...model.exposures, ...(model.confirmed || []),
    ...model.acceptances, ...model.transfers, ...model.flows,
    ...model.boundaries, ...model.validations, ...model.audits,
    ...model.ownership, ...model.data_handling, ...model.assumptions,
    ...model.shields, ...model.features, ...model.comments,
  ].map(a => a.location);
}
