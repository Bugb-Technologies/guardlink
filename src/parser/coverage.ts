/**
 * GuardLink — is this exposure covered? (D36)
 *
 * One predicate, called by every surface that answers that question. Before this
 * module there were seven independent copies of `${asset}::${threat}` — in
 * `validate.ts` (twice), `diff/engine.ts`, `workspace/merge.ts`, `mcp/context.ts`
 * and `mcp/lookup.ts` (twice) — four of which did not normalise `#` off a ref, so
 * `#db` and `db` were different assets in `diff` and agreed in `validate`. A diff
 * that disagrees with validate about what is covered is its own bug.
 *
 * ── The rule ────────────────────────────────────────────────────────
 *
 * A mitigation (or acceptance) covers an exposure when they name the same asset
 * and the same threat, UNLESS the two records are sited in the same file, both
 * carry a symbol anchor, and those anchors differ.
 *
 * Everything else stays covered. In particular a mitigation in a DIFFERENT FILE
 * always covers, because that is the shape a real control has: the filter lives
 * at the trust boundary and the exposure lives downstream of it.
 *
 * ── Why not simply add the symbol to the key ────────────────────────
 *
 * Because it cries wolf, and an alarm that cries wolf gets ignored. Measured on
 * this repo, simulated as migrated to external mode (61 `@source` blocks):
 * requiring symbol equality moves 16 unmitigated exposures to 22, and ALL SIX of
 * the newly-flagged are cross-file controls that genuinely cover their exposure —
 *
 *   #parser → #path-traversal   parse-file.ts   ← #glob-filtering  parse-project.ts
 *   #tui    → #api-key-exposure tui/index.ts    ← #key-redaction   tui/config.ts
 *   #diff   → #cmd-injection    diff/index.ts   ← #input-sanitize  diff/git.ts
 *
 * — a 6-of-6 false-positive rate on exactly the class the tightening would add.
 * The glob filter in `parse-project.ts` really does run upstream of `parse-file.ts`.
 *
 * ── Why same-file-different-symbol is the honest discriminator ──────
 *
 * It is the only configuration in which the author has demonstrably distinguished
 * two sites and attached the control to one of them. An author annotating one
 * file, who anchors `@exposes` to `find_expenses` and `@mitigates` to
 * `insert_expense`, has said in the model that these are different places. Today
 * the second silently answers for the first. Cross-file carries no such evidence:
 * "the control is over there and reaches here" is the normal reading, and we must
 * not guess otherwise without a call graph, which GuardLink does not have.
 *
 * The narrowing is therefore evidence-driven, not a granularity change. It can
 * only ever REMOVE coverage, never add it, and only where the author's own
 * anchors contradict the claim.
 *
 * ── What this does NOT fix ──────────────────────────────────────────
 *
 * A cross-file mitigation still blanket-covers every exposure on its asset and
 * threat. If expense-api's bound INSERT lived in `queries.py` rather than beside
 * the injectable SELECT, `find_expenses` would still read as mitigated. Closing
 * that needs to know whether a control actually reaches a site, which is a call
 * graph, which is a different and much larger design. This rule fixes the class
 * where the model already contains the evidence, and no more. Said plainly here
 * so nobody reads D36 as fully closed.
 *
 * ── How an author says "this covers the whole asset" ────────────────
 *
 * Omit `symbol:` from the `@source` header — an unanchored mitigation is an
 * asset-level statement and is never narrowed. No new syntax was needed, which is
 * why none was added.
 *
 * @flows ThreatModel -> #parser via isCovered -- "Every unmitigated-exposure answer in the product routes through this predicate"
 * @comment -- "Inline annotations never carry parent_symbol (parse-file.ts populates it only from @source), so this rule is inert in every inline repo — measured: 0 of 74 exposures change state on guardlink, 0 of 61 on specter-v1, 2 of 11 on expense-api"
 * @comment -- "Narrowing is one-directional by construction: coversExposure starts from the (asset, threat) match the old key computed and only ever subtracts. A refactor that made it additive would be a silent-wrong-answer path in the opposite direction"
 */

import type {
  ThreatModel, ThreatModelExposure, ThreatModelMitigation, ThreatModelAcceptance,
  SourceLocation,
} from '../types/index.js';

/** Strip a leading `#` and case so `#sqli`, `sqli` and `SQLi` compare equal. */
export function normalizeRef(ref: string): string {
  return (ref ?? '').replace(/^#/, '').toLowerCase();
}

/** The shape every coverage participant shares: an asset, a threat, a site. */
export interface SitedRelation {
  asset: string;
  threat: string;
  location: SourceLocation;
}

/**
 * True when `cover`'s anchor contradicts `exposure`'s — the one configuration in
 * which a same-(asset, threat) statement does not answer for this site.
 *
 * Requires BOTH anchors. A pair where only one side is anchored carries no
 * evidence that the author distinguished the sites, so it stays covered. That is
 * the conservative reading, and it is what keeps a partially-migrated or
 * hand-written sidecar from producing a flood.
 */
function anchorsContradict(cover: SitedRelation, exposure: SitedRelation): boolean {
  const a = cover.location.parent_symbol;
  const b = exposure.location.parent_symbol;
  return cover.location.file === exposure.location.file
    && !!a && !!b
    && a !== b;
}

/** Does this mitigation or acceptance cover this exposure? */
export function coversExposure(cover: SitedRelation, exposure: SitedRelation): boolean {
  return normalizeRef(cover.asset) === normalizeRef(exposure.asset)
    && normalizeRef(cover.threat) === normalizeRef(exposure.threat)
    && !anchorsContradict(cover, exposure);
}

/**
 * Coverage answers for one model, computed once.
 *
 * Callers used to build a `Set` of pair keys; a Set cannot express a rule that
 * depends on both sides, so this returns predicates instead. The pair index is
 * still used to keep the common case linear — only candidates that already match
 * on (asset, threat) are ever compared site by site.
 */
export interface CoverageIndex {
  isMitigated(exposure: SitedRelation): boolean;
  isAccepted(exposure: SitedRelation): boolean;
  /** Mitigated OR accepted — what "not in the unmitigated list" means. */
  isCovered(exposure: SitedRelation): boolean;
  /** The mitigations that actually cover this exposure, for reporting controls. */
  mitigationsFor(exposure: SitedRelation): ThreatModelMitigation[];
}

function indexByPair<T extends SitedRelation>(rows: T[]): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const r of rows) {
    const key = `${normalizeRef(r.asset)}::${normalizeRef(r.threat)}`;
    const bucket = map.get(key);
    if (bucket) bucket.push(r); else map.set(key, [r]);
  }
  return map;
}

export function buildCoverageIndex(model: ThreatModel): CoverageIndex {
  const mitigations = indexByPair(model.mitigations as unknown as SitedRelation[] as ThreatModelMitigation[]);
  const acceptances = indexByPair(model.acceptances as unknown as SitedRelation[] as ThreatModelAcceptance[]);

  const matching = <T extends SitedRelation>(index: Map<string, T[]>, e: SitedRelation): T[] => {
    const bucket = index.get(`${normalizeRef(e.asset)}::${normalizeRef(e.threat)}`);
    if (!bucket) return [];
    return bucket.filter(c => !anchorsContradict(c, e));
  };

  const isMitigated = (e: SitedRelation) => matching(mitigations, e).length > 0;
  const isAccepted = (e: SitedRelation) => matching(acceptances, e).length > 0;

  return {
    isMitigated,
    isAccepted,
    isCovered: e => isMitigated(e) || isAccepted(e),
    mitigationsFor: e => matching(mitigations, e),
  };
}

/** Exposures with no covering `@mitigates` and no covering `@accepts`. */
export function findUnmitigatedExposures(model: ThreatModel): ThreatModelExposure[] {
  const index = buildCoverageIndex(model);
  return model.exposures.filter(e => !index.isCovered(e));
}

/**
 * Exposures covered ONLY by `@accepts` — the risk is real and no control is in
 * place, a human simply signed for it.
 */
export function findAcceptedExposures(model: ThreatModel): ThreatModelExposure[] {
  const index = buildCoverageIndex(model);
  return model.exposures.filter(e => index.isAccepted(e) && !index.isMitigated(e));
}

// ─── What "coverage" means, said once (D42, D49) ─────────────────────

/**
 * D42/D49 — the coverage numbers, described rather than inferred.
 *
 * `CoverageStats` holds three fields whose names invite a reading the data does
 * not support: `total_symbols` is never computed and is permanently 0,
 * `annotated_symbols` counts ANNOTATIONS not symbols, and `coverage_percent` is
 * FILE coverage and has no arithmetic relationship to either. `types/index.ts`
 * documents all three correctly — and those doc comments do not travel with the
 * JSON, so every consumer that believed the field names got it wrong:
 *
 *   tui/commands.ts   printed `Coverage: 105/0 symbols (100%)`
 *   workspace/merge.ts recomputed percent as annotated/total, and since total is
 *                      always 0 the `: 0` fallback was the only branch that ever
 *                      ran — two repos at 89% merged to a workspace at 0%
 *
 * A contract expressed only where the consumer cannot see it is not a contract.
 * This is that contract as a function: it names the numerator, the denominator
 * and the unit, so nothing downstream has to infer a denominator. Reshaping the
 * wire format is the better fix and is a separate, versioned change — `coverage`
 * ships inside `schema_version: 1.0.0`, which `guardlink merge` cross-checks
 * across repos, so it cannot move without a bump.
 */
export interface CoverageDescription {
  /** The only coverage GuardLink actually computes. */
  kind: 'file';
  annotatedFiles: number;
  sourceFiles: number;
  /** annotatedFiles / sourceFiles, as a whole percent. 0 when there are no files. */
  percent: number;
  /** Annotations parsed. NOT a numerator for `percent` — a separate quantity. */
  annotations: number;
}

/** File coverage as a whole percent. The one place this division happens. */
export function fileCoveragePercent(annotatedFiles: number, sourceFiles: number): number {
  return sourceFiles > 0 ? Math.round((annotatedFiles / sourceFiles) * 100) : 0;
}

/** Coverage as something a caller can render without guessing what it counts. */
export function describeCoverage(model: ThreatModel): CoverageDescription {
  const annotatedFiles = model.annotated_files.length;
  const sourceFiles = model.source_files;
  return {
    kind: 'file',
    annotatedFiles,
    sourceFiles,
    percent: fileCoveragePercent(annotatedFiles, sourceFiles),
    annotations: model.coverage.annotated_symbols,
  };
}
