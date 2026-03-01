/**
 * GuardLink Workspace — Multi-repo linking and merge.
 *
 * @comment -- "Workspace module: config loading, merge engine, link-project setup"
 */

export type {
  WorkspaceConfig, WorkspaceRepo,
  TagOwnership, UnresolvedRef, MergeWarning, MergeWarningCode,
  RepoStatus, MergedReport, MergeTotals, MergeDiffSummary,
} from './types.js';

export {
  REPORT_SCHEMA_VERSION,
  populateMetadata,
  loadWorkspaceConfig,
  parseWorkspaceYaml,
  serializeWorkspaceYaml,
} from './metadata.js';

export {
  mergeReports,
  formatMergeSummary,
  diffMergedReports,
  formatDiffSummary,
} from './merge.js';
export type { MergeOptions } from './merge.js';

export { linkProject, addToWorkspace, removeFromWorkspace, buildWorkspaceContextBlock, detectRepoName } from './link.js';
export type { LinkProjectOptions, AddToWorkspaceOptions, RemoveFromWorkspaceOptions, LinkResult } from './link.js';
