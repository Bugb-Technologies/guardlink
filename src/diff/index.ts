/**
 * GuardLink Diff — exports.
 */

export { diffModels, type ThreatModelDiff, type DiffSummary, type Change, type ChangeKind } from './engine.js';
export { formatDiff, formatDiffMarkdown } from './format.js';
export { parseAtRef, getCurrentRef } from './git.js';
