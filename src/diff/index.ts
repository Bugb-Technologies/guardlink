/**
 * GuardLink Diff — exports.
 *
 * @exposes #diff to #cmd-injection [high] cwe:CWE-78 -- "git.ts runs git with a caller-supplied ref"
 * @mitigates #diff against #cmd-injection using #param-commands -- "git.ts runs every git call through execFileSync with an argument array and resolves the ref to a sha first (resolveCommit)"
 * @flows GitRef -> #diff via parseAtRef -- "Git reference input"
 */

export { diffModels, type ThreatModelDiff, type DiffSummary, type Change, type ChangeKind, type DiffOptions, type StaleEntitlement } from './engine.js';
export { formatDiff, formatDiffMarkdown } from './format.js';
export { parseAtRef, getCurrentRef, getChangedFiles, resolveCommit, REF_SHAPE } from './git.js';
