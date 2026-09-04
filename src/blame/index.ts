/**
 * GuardLink Blame — git attribution for annotated claims.
 *
 * Who introduced the code beneath an annotation, who declared it, who declared
 * the fix, and which AI tool a commit credited — computed from git at run
 * time, never written into source. See `docs/GUARDLINK_REFERENCE.md`,
 * "Attribution".
 *
 * @comment -- "Public surface of src/blame: computeBlame (non-mutating), attachBlame (CLI --blame), the payload builders, the config reader and listCommits, the one history walk behind the commit counts"
 */
export * from './types.js';
export { listCommits } from './git.js';
export { readBlameConfig, compileRules, DEFAULT_TOOL_RULES, DEFAULT_IGNORE_REVS } from './config.js';
export { attributeCommit, parseTrailerBlock, parseAssistedBy, splitPerson, identityFor, classifyPerson } from './trailers.js';
export type { RawPerson } from './trailers.js';
export { computeBlame, safeRelPath } from './compute.js';
export type { ComputeBlameOptions } from './compute.js';
export { attachBlame } from './attach.js';
export { buildBlamePayload, entriesFromModel, summarise, median } from './summary.js';
export { formatBlameText } from './format.js';
