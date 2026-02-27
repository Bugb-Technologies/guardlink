/**
 * GuardLink Diff — exports.
 *
 * @exposes #diff to #cmd-injection [high] cwe:CWE-78 -- "git.ts uses execSync with ref argument"
 * @audit #diff -- "Git commands use execSync; ref is validated with rev-parse before use"
 * @flows GitRef -> #diff via parseAtRef -- "Git reference input"
 */

export { diffModels, type ThreatModelDiff, type DiffSummary, type Change, type ChangeKind } from './engine.js';
export { formatDiff, formatDiffMarkdown } from './format.js';
export { parseAtRef, getCurrentRef } from './git.js';
