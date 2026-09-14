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
  resolveReportPaths,
  mergeVerdict,
  formatMergeVerdict,
  openExposuresIn,
  formatMergeSummary,
  diffMergedReports,
  formatDiffSummary,
} from './merge.js';
export type {
  MergeOptions, ResolvedReportPaths,
  MergeVerdict, MergeVerdictOptions, MergeFailure, MergeFailureCode,
} from './merge.js';

export {
  estateReport,
  formatEstateReport,
  readMergedReport,
  NotAMergedReport,
  ESTATE_SCHEMA,
} from './estate.js';
export type {
  EstateReport, EstateFinding, EstateRepoLine, EstateSummary, EstateOptions,
  EstateSeverityCounts,
} from './estate.js';

export { buildOwnerScope, repoOfPath, NO_OWNER_SCOPE } from './owner-scope.js';
export type { OwnerScope } from './owner-scope.js';

export { linkProject, addToWorkspace, removeFromWorkspace, buildWorkspaceContextBlock, detectRepoName } from './link.js';
export type { LinkProjectOptions, AddToWorkspaceOptions, RemoveFromWorkspaceOptions, LinkResult } from './link.js';
