/**
 * GuardLink Workspace — Types for multi-repo linking.
 *
 * workspace.yaml lives in each repo's .guardlink/ directory.
 * It declares membership in a workspace and lists sibling repos.
 *
 * @asset Workspace.Config (#workspace-config) -- "Multi-repo workspace definition"
 * @threat Config_Tampering (#config-tamper) [medium] cwe:CWE-15 -- "Malicious workspace.yaml could misdirect agent annotations"
 * @mitigates #workspace-config against #config-tamper using #yaml-validation -- "Schema validation on load"
 */

import type { ThreatModel, Severity, ExternalRef } from '../types/index.js';

// ─── Workspace Configuration (workspace.yaml) ───────────────────────

/** A single repo in the workspace */
export interface WorkspaceRepo {
  /** Short name used as tag prefix (e.g. "payment-service") */
  name: string;
  /** Remote registry URL (e.g. "github.com/unstructured/payment-service") */
  registry?: string;
  /** Local path — only used during link-project setup, not stored in yaml */
  local_path?: string;
}

/** Workspace configuration stored in .guardlink/workspace.yaml */
export interface WorkspaceConfig {
  /** Workspace name (e.g. "unstructured-platform") */
  workspace: string;
  /** This repo's name within the workspace */
  this_repo: string;
  /** All repos in the workspace (including this one) */
  repos: WorkspaceRepo[];
  /** URL to shared definitions file (optional) */
  shared_definitions?: string;
}

// ─── Merge Types ─────────────────────────────────────────────────────

/** Tag ownership record: which repo defines a given tag */
export interface TagOwnership {
  /** The tag (e.g. "#payment-svc.refund") */
  tag: string;
  /** Repo that defines this tag */
  owner_repo: string;
  /** What it defines: asset, threat, or control */
  kind: 'asset' | 'threat' | 'control';
}

/** A cross-repo reference that could not be resolved during merge */
export interface UnresolvedRef extends ExternalRef {
  /** Repo where this reference was found */
  source_repo: string;
}

/** Warning emitted during merge */
export interface MergeWarning {
  level: 'error' | 'warning' | 'info';
  code: MergeWarningCode;
  message: string;
  repos?: string[];
  tag?: string;
}

export type MergeWarningCode =
  | 'duplicate_tag'       // Same tag defined in multiple repos
  | 'unresolved_ref'      // Tag referenced but not defined anywhere
  | 'missing_repo'        // Workspace repo has no report (stale/missing)
  | 'schema_mismatch'     // Report schema_version differs across repos
  | 'tag_prefix_mismatch' // Tag prefix doesn't match any known repo name
  | 'stale_report';       // Report older than threshold

/** Per-repo status in a merged report */
export interface RepoStatus {
  name: string;
  /** Whether we successfully loaded this repo's report */
  loaded: boolean;
  /** ISO timestamp of when the report was generated */
  generated_at?: string;
  /** Commit SHA from the report */
  commit_sha?: string;
  /** Count of annotations in this repo */
  annotation_count?: number;
  /** Why this repo is missing (if loaded=false) */
  error?: string;
}

/** The merged output combining all repo reports */
export interface MergedReport {
  /** Workspace name */
  workspace: string;
  /** ISO timestamp of when merge was run */
  merged_at: string;
  /** Schema version of the merged report */
  schema_version: string;
  /** Status of each repo */
  repo_statuses: RepoStatus[];
  /** Unified tag registry: who owns each tag */
  tag_registry: TagOwnership[];
  /** Unresolved cross-repo references */
  unresolved_refs: UnresolvedRef[];
  /** Warnings from merge process */
  warnings: MergeWarning[];

  /** Aggregated totals */
  totals: MergeTotals;
  /** The combined threat model (all repos merged) */
  model: ThreatModel;
}

export interface MergeTotals {
  repos: number;
  repos_loaded: number;
  annotations: number;
  assets: number;
  threats: number;
  controls: number;
  mitigations: number;
  exposures: number;
  unmitigated_exposures: number;
  acceptances: number;
  flows: number;
  boundaries: number;
  external_refs_resolved: number;
  external_refs_unresolved: number;
}

// ─── Merge Diff (--diff-against) ────────────────────────────────────

/** Delta between two merged reports (weekly summary) */
export interface MergeDiffSummary {
  /** Time range */
  previous_merged_at: string;
  current_merged_at: string;

  /** Per-category deltas */
  assets_added: number;
  assets_removed: number;
  threats_added: number;
  threats_removed: number;
  mitigations_added: number;
  mitigations_removed: number;
  exposures_added: number;
  exposures_removed: number;

  /** Risk-relevant */
  new_unmitigated: number;
  resolved_unmitigated: number;
  risk_delta: 'increased' | 'decreased' | 'unchanged';

  /** Cross-repo changes */
  new_flows: number;
  removed_flows: number;
  new_unresolved_refs: number;
  resolved_refs: number;

  /** Repos changed */
  repos_added: string[];
  repos_removed: string[];
  repos_with_changes: string[];
}
