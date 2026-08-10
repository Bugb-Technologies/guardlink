/**
 * GuardLink Parser — Public API
 */

export { parseFile, parseString } from './parse-file.js';
export { parseProject } from './parse-project.js';
export type { ParseProjectOptions } from './parse-project.js';
export { parseLine } from './parse-line.js';
export { normalizeName, resolveSeverity, unescapeDescription } from './normalize.js';
export { stripCommentPrefix, commentStyleForExt } from './comment-strip.js';
export { findDanglingRefs, findUnmitigatedExposures, findAcceptedWithoutAudit, findAcceptedExposures, findOffConventionGalFiles } from './validate.js';
export { resolveGalPath, galPathFor, sourceFileForGal, isConventionalGalPath, ANNOTATIONS_DIR, GAL_CONVENTION } from './gal-path.js';
export { clearAnnotations } from './clear.js';
export type { ClearAnnotationsOptions, ClearAnnotationsResult } from './clear.js';
export { listFeatures, filterByFeature, getFeatureSummaries } from './feature-filter.js';
export type { FeatureSummary } from './feature-filter.js';
export { computeAnnotationHash, canonicalAnnotationRecords, ANNOTATION_HASH_VERSION } from './annotation-hash.js';
export { applyAnnotations } from './apply-annotations.js';
export type { ApplyAnnotationsOptions, ApplyAnnotationsResult } from './apply-annotations.js';
