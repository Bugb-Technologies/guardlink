/**
 * GuardLink Parser — Public API
 */

export { parseFile, parseString } from './parse-file.js';
export { parseProject } from './parse-project.js';
export type { ParseProjectOptions } from './parse-project.js';
// §9.7 — the cited-and-precise test lives in one place so a consumer cannot read
// an imprecise entitlement as an effective one by omission.
export { canEntitlementDemote, entitlementDemotionBlockers } from './parse-project.js';
// MERGE: main's line dropped D19's cross-repo tag exports. Both kept — they are
// additive and `crossRepoTag` is what stops generated docs hand-writing the
// grammar (D19).
export { parseLine, crossRepoTag, CROSS_REPO_TAG_PATTERN } from './parse-line.js';
export { normalizeName, resolveSeverity, unescapeDescription } from './normalize.js';
export { stripCommentPrefix, commentStyleForExt } from './comment-strip.js';
export { findDanglingRefs, findUnmitigatedExposures, findAcceptedWithoutAudit, findAcceptedExposures, findUndeclaredActors, findInertEntitlements, findImpreciseEntitlements, findOffConventionGalFiles } from './validate.js';
// What an acceptance has to be before it counts as one. One implementation,
// shared by the gate that re-checks acceptances and the writer that creates them.
export {
  readAcceptancePolicy, findAcceptanceDefects, acceptanceDefects, isQualified, isExpired,
  daysRemaining, parseExpiry, todayISO, acceptanceCovers, acceptanceBlastRadius,
  formatBlastRadius, DEFAULT_ACCEPTANCE_POLICY,
} from './acceptance.js';
export type { AcceptancePolicy, AcceptanceDefect, AcceptanceFinding, BlastRadius } from './acceptance.js';
export { buildCoverageIndex, normalizeRef, coversExposure } from './coverage.js';
export type { CoverageIndex, CoverageOptions, SitedRelation } from './coverage.js';
export { extractCitation, citationMatchesFile } from './citation.js';
export { resolveGalPath, galPathFor, sourceFileForGal, isConventionalGalPath, ANNOTATIONS_DIR, GAL_CONVENTION } from './gal-path.js';
export { clearAnnotations } from './clear.js';
export type { ClearAnnotationsOptions, ClearAnnotationsResult } from './clear.js';
export { listFeatures, filterByFeature, getFeatureSummaries } from './feature-filter.js';
export type { FeatureSummary } from './feature-filter.js';
export { computeAnnotationHash, canonicalAnnotationRecords, ANNOTATION_HASH_VERSION } from './annotation-hash.js';
export { computeAnchorHash, canonicalAnchorRecords, countAnchors, lostAnchors, ANCHOR_HASH_VERSION } from './annotation-hash.js';
export { applyAnnotations } from './apply-annotations.js';
export type { ApplyAnnotationsOptions, ApplyAnnotationsResult } from './apply-annotations.js';
export { findAnchorDrift, applyReanchor } from './reanchor.js';
export type { AnchorDrift } from './reanchor.js';
export { migrateAnnotationMode, readGalBlocks } from './migrate-mode.js';
export type { MigrateOptions, MigrateResult, TargetMode } from './migrate-mode.js';
// Stale claim detection (docs/superpowers/specs/2026-09-03-stale-claim-detection-design.md).
export { relationRecords, claimText, DEMOTABLE_VERBS } from './claim-key.js';
export type { ClaimSource, ClaimVerb } from './claim-key.js';
export { readLedger, writeLedger, serializeLedger, emptyLedger, LEDGER_FILE, LEDGER_SCHEMA } from './ledger.js';
export type { Ledger, LedgerEntry, LedgerRead, LedgerStatus } from './ledger.js';
export { classifyClaims, demotionSet } from './verification.js';
export type { ClaimRecord, ClaimState, VerificationReport } from './verification.js';
export { planVerification, applyVerification, defaultVerifier, headCommit, nowIso } from './verify.js';
export type { VerifyMode, VerifyPlan, VerifyTarget, VerifierIdentity } from './verify.js';
