/**
 * GuardLink — Shared validation helpers.
 *
 * Extracted from cli/index.ts and tui/commands.ts to eliminate duplication
 * and ensure consistent validation logic across all entry points.
 *
 * @mitigates #parser against #tag-collision using #prefix-ownership -- "findDanglingRefs ensures #id refs resolve to definitions"
 * @comment -- "@confirmed refs validated same as @exposes for asset and threat"
 * @comment -- "findUndeclaredActors / findInertEntitlements implement the two mechanical @entitles checks from docs/prd/actor-entitlement-design.md §3.7 — both typo-class; entitlement intent is not machine-checkable"
 */

import {
  isConventionalGalPath, sourceFileForGal, galPathFor, offConventionMessage,
} from './gal-path.js';
import type { ThreatModel, ThreatModelExposure, ParseDiagnostic, SourceLocation } from '../types/index.js';
import { normalizeName } from './normalize.js';

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
 * Normalize a ref for matching: strip leading # so that
 * "#sqli" and "sqli" compare equal.
 */
function normalizeRef(ref: string): string {
  return ref.startsWith('#') ? ref.slice(1) : ref;
}

/**
 * Find exposures that have no matching @mitigates or @accepts.
 * Normalizes refs so that #id and bare-name forms are compared consistently.
 */
export function findUnmitigatedExposures(model: ThreatModel): ThreatModelExposure[] {
  const covered = new Set<string>();
  for (const m of model.mitigations) {
    covered.add(`${normalizeRef(m.asset)}::${normalizeRef(m.threat)}`);
  }
  for (const a of model.acceptances) {
    covered.add(`${normalizeRef(a.asset)}::${normalizeRef(a.threat)}`);
  }
  return model.exposures.filter(e =>
    !covered.has(`${normalizeRef(e.asset)}::${normalizeRef(e.threat)}`)
  );
}

/**
 * Find @entitles annotations naming an actor that was never declared with @actor.
 *
 * This is one of the two mechanical checks §3.7 of the actor/entitlement design
 * calls for — both are typo-class. Neither can verify *intent*: whether an actor
 * really is entitled to a capability is a statement about purpose that no check
 * can derive from the code. It is an error rather than a warning because an
 * entitlement pointing at a non-existent principal can never be joined
 * downstream, so it is silently inoperative — the failure mode this design is
 * built to avoid.
 */
export function findUndeclaredActors(model: ThreatModel): ParseDiagnostic[] {
  const diagnostics: ParseDiagnostic[] = [];

  const declared = new Set<string>();
  for (const ac of model.actors || []) {
    if (ac.id) declared.add(ac.id);
    declared.add(ac.canonical_name);
  }

  for (const en of model.entitlements || []) {
    const bare = normalizeRef(en.actor);
    if (declared.has(bare) || declared.has(normalizeName(bare))) continue;
    diagnostics.push({
      level: 'error',
      message: `@entitles names actor ${en.actor} which is never declared with @actor`,
      file: en.location.file,
      line: en.location.line,
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
      message: `@entitles ${en.actor} to ${en.capability} cites no authorization code — inert, will not demote any finding. Add a file:line pointer to the authz check in the description.`,
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
        message: `@accepts ${acc.threat} on ${acc.asset} without @audit — risk acceptance should be paired with @audit for traceability`,
        file: acc.location.file,
        line: acc.location.line,
      });
    }
  }

  return diagnostics;
}

/**
 * Find exposures that are covered ONLY by @accepts (no real @mitigates).
 * These are "accepted but unmitigated" — the risk exists and no control is in place.
 * Useful for dashboards and reports to distinguish real mitigations from risk acceptance.
 */
export function findAcceptedExposures(model: ThreatModel): ThreatModelExposure[] {
  const mitigated = new Set<string>();
  for (const m of model.mitigations) {
    mitigated.add(`${normalizeRef(m.asset)}::${normalizeRef(m.threat)}`);
  }
  const accepted = new Set<string>();
  for (const a of model.acceptances) {
    accepted.add(`${normalizeRef(a.asset)}::${normalizeRef(a.threat)}`);
  }

  return model.exposures.filter(e => {
    const key = `${normalizeRef(e.asset)}::${normalizeRef(e.threat)}`;
    return accepted.has(key) && !mitigated.has(key);
  });
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
