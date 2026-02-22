/**
 * GuardLink — Shared validation helpers.
 *
 * Extracted from cli/index.ts and tui/commands.ts to eliminate duplication
 * and ensure consistent validation logic across all entry points.
 */

import type { ThreatModel, ThreatModelExposure, ParseDiagnostic } from '../types/index.js';

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
