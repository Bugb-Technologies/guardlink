/**
 * GuardLink Parser — Public API
 */

export { parseFile, parseString } from './parse-file.js';
export { parseProject } from './parse-project.js';
export type { ParseProjectOptions } from './parse-project.js';
export { parseLine } from './parse-line.js';
export { normalizeName, resolveSeverity, unescapeDescription } from './normalize.js';
export { stripCommentPrefix, commentStyleForExt } from './comment-strip.js';
