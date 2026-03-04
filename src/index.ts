/**
 * GuardLink — Reference Implementation
 *
 * Library entry point. Re-exports parser, types, init, and utilities.
 *
 * Usage:
 *   import { parseProject, parseString } from 'guardlink';
 *   import { initProject, detectProject } from 'guardlink';
 *   import type { ThreatModel, Annotation } from 'guardlink';
 *
 * @comment -- "Public npm library entry point: all exported functions accept root paths from library consumers; path traversal, arbitrary-write, and cmd-injection risks documented in #parser, #init, #diff apply equally when called as a library"
 * @assumes #parser -- "Library callers supply trusted project root paths; no additional path sanitization at this entry point — downstream modules apply resolve() + cwd constraints"
 * @flows LibraryConsumer -> #parser via parseProject -- "Consumer-supplied root for annotation scanning"
 * @flows LibraryConsumer -> #parser via clearAnnotations -- "Consumer-supplied root for destructive annotation clearing"
 * @flows LibraryConsumer -> #diff via parseAtRef -- "Consumer-supplied root and git ref for historical diff operations"
 * @flows LibraryConsumer -> #init via initProject -- "Consumer-supplied root for writing agent instruction files to disk"
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
