/**
 * GuardLink Parser — Public API
 *
 * @comment -- "Public parser API re-exports: all filesystem functions accept caller-supplied paths; consumers must supply project-owned root paths only — path traversal risks documented in #parser apply when used as a library"
 * @flows LibraryConsumer -> #parser via parseFile -- "Consumer-supplied file path for single-file annotation parsing"
 * @flows LibraryConsumer -> #parser via parseProject -- "Consumer-supplied root for full project scan"
 * @flows LibraryConsumer -> #parser via clearAnnotations -- "Consumer-supplied root for destructive annotation removal across project files"
 */

export { parseFile, parseString } from './parse-file.js';
export { parseProject } from './parse-project.js';
export type { ParseProjectOptions } from './parse-project.js';
export { parseLine } from './parse-line.js';
export { normalizeName, resolveSeverity, unescapeDescription } from './normalize.js';
export { stripCommentPrefix, commentStyleForExt } from './comment-strip.js';
export { findDanglingRefs, findUnmitigatedExposures, findAcceptedWithoutAudit, findAcceptedExposures } from './validate.js';
export { clearAnnotations } from './clear.js';
export type { ClearAnnotationsOptions, ClearAnnotationsResult } from './clear.js';
