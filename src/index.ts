/**
 * GuardLink — Reference Implementation
 *
 * Library entry point. Re-exports parser, types, init, and utilities.
 *
 * Usage:
 *   import { parseProject, parseString } from 'guardlink';
 *   import { initProject, detectProject } from 'guardlink';
 *   import type { ThreatModel, Annotation } from 'guardlink';
 */

export * from './types/index.js';
export * from './parser/index.js';
export { initProject, detectProject } from './init/index.js';
export type { InitOptions, InitResult, ProjectInfo, AgentFile } from './init/index.js';
export { generateReport, generateMermaid } from './report/index.js';
export { diffModels, formatDiff, formatDiffMarkdown, parseAtRef } from './diff/index.js';
export type { ThreatModelDiff, DiffSummary, Change, ChangeKind } from './diff/index.js';
export { generateSarif } from './analyzer/index.js';
export type { SarifOptions } from './analyzer/index.js';
export { populateMetadata, loadWorkspaceConfig, REPORT_SCHEMA_VERSION, mergeReports, formatMergeSummary, diffMergedReports, formatDiffSummary } from './workspace/index.js';
export type { WorkspaceConfig, WorkspaceRepo, MergedReport, MergeTotals, MergeDiffSummary, MergeOptions } from './workspace/index.js';
