/**
 * GuardLink Parser — Public API
 */

export { parseFile, parseString } from './parse-file.js';
export { parseProject } from './parse-project.js';
export type { ParseProjectOptions } from './parse-project.js';
// §9.7 — the cited-and-precise test lives in one place so a consumer cannot read
// an imprecise entitlement as an effective one by omission.
export { canEntitlementDemote, entitlementDemotionBlockers } from './parse-project.js';
export { parseLine } from './parse-line.js';
export { normalizeName, resolveSeverity, unescapeDescription } from './normalize.js';
export { stripCommentPrefix, commentStyleForExt } from './comment-strip.js';
export { findDanglingRefs, findUnmitigatedExposures, findAcceptedWithoutAudit, findAcceptedExposures, findUndeclaredActors, findInertEntitlements, findImpreciseEntitlements, findOffConventionGalFiles } from './validate.js';
export { extractCitation, citationMatchesFile } from './citation.js';
export { resolveGalPath, galPathFor, sourceFileForGal, isConventionalGalPath, ANNOTATIONS_DIR, GAL_CONVENTION } from './gal-path.js';
export { clearAnnotations } from './clear.js';
export type { ClearAnnotationsOptions, ClearAnnotationsResult } from './clear.js';
export { listFeatures, filterByFeature, getFeatureSummaries } from './feature-filter.js';
export type { FeatureSummary } from './feature-filter.js';
export { computeAnnotationHash, canonicalAnnotationRecords, ANNOTATION_HASH_VERSION } from './annotation-hash.js';
export { applyAnnotations } from './apply-annotations.js';
export type { ApplyAnnotationsOptions, ApplyAnnotationsResult } from './apply-annotations.js';
export { findAnchorDrift, applyReanchor } from './reanchor.js';
export type { AnchorDrift } from './reanchor.js';
export { migrateAnnotationMode, readGalBlocks } from './migrate-mode.js';
export type { MigrateOptions, MigrateResult, TargetMode } from './migrate-mode.js';
