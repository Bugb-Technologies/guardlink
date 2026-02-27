/**
 * GuardLink Workspace — Report metadata population.
 *
 * Enriches a ThreatModel with provenance metadata (git SHA, branch,
 * workspace info) for the report JSON contract.
 *
 * @asset Workspace.Metadata (#report-metadata) -- "Report provenance data"
 * @flows GitRepo -> #report-metadata via execSync -- "Git info extraction"
 * @flows #report-metadata -> ThreatModel via populateMetadata -- "Metadata injection"
 */

import { execSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ThreatModel, ReportMetadata } from '../types/index.js';
import type { WorkspaceConfig } from './types.js';

/** Current report JSON schema version */
export const REPORT_SCHEMA_VERSION = '1.0.0';

/**
 * Get the guardlink package version at runtime.
 * Falls back to 'unknown' if not determinable.
 */
function getGuardlinkVersion(): string {
  try {
    // Walk up from this file to find package.json
    const pkgPath = new URL('../../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return pkg.version || 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * Get git commit SHA (full) for the given directory.
 * Returns null if not a git repo.
 */
function getCommitSha(root: string): string | null {
  try {
    return execSync('git rev-parse HEAD', { cwd: root, encoding: 'utf-8', stdio: 'pipe' }).trim();
  } catch {
    return null;
  }
}

/**
 * Get current git branch name.
 * Returns null if detached HEAD or not a git repo.
 */
function getBranch(root: string): string | null {
  try {
    const branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: root, encoding: 'utf-8', stdio: 'pipe' }).trim();
    return branch === 'HEAD' ? null : branch; // detached HEAD
  } catch {
    return null;
  }
}

/**
 * Try to load workspace.yaml from the project's .guardlink/ directory.
 * Returns null if not found or invalid.
 */
export function loadWorkspaceConfig(root: string): WorkspaceConfig | null {
  const yamlPath = join(root, '.guardlink', 'workspace.yaml');
  if (!existsSync(yamlPath)) return null;

  try {
    const content = readFileSync(yamlPath, 'utf-8');
    return parseWorkspaceYaml(content);
  } catch {
    return null;
  }
}

/**
 * Parse workspace.yaml content (simple YAML subset — no dependency needed).
 * Supports the flat structure we define; falls back gracefully on malformed input.
 */
export function parseWorkspaceYaml(content: string): WorkspaceConfig {
  const lines = content.split('\n').map(l => l.trimEnd());
  const config: Partial<WorkspaceConfig> = { repos: [] };

  let inRepos = false;
  let currentRepo: Partial<{ name: string; registry: string }> | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Top-level scalar fields
    if (!line.startsWith(' ') && !line.startsWith('\t') && trimmed.includes(':')) {
      // Flush pending repo
      if (currentRepo?.name) {
        config.repos!.push({ name: currentRepo.name, registry: currentRepo.registry });
        currentRepo = null;
      }

      const [key, ...rest] = trimmed.split(':');
      const value = rest.join(':').trim().replace(/^["']|["']$/g, '');

      if (key === 'workspace') config.workspace = value;
      else if (key === 'this_repo') config.this_repo = value;
      else if (key === 'shared_definitions' && value && value !== 'null') config.shared_definitions = value;
      else if (key === 'repos') { inRepos = true; continue; }
      else inRepos = false;
      continue;
    }

    // Inside repos list
    if (inRepos && trimmed.startsWith('- ')) {
      // Flush pending repo
      if (currentRepo?.name) {
        config.repos!.push({ name: currentRepo.name, registry: currentRepo.registry });
      }
      currentRepo = {};
      // Handle "- name: value" shorthand
      const afterDash = trimmed.slice(2).trim();
      if (afterDash.startsWith('name:')) {
        currentRepo.name = afterDash.slice(5).trim().replace(/^["']|["']$/g, '');
      }
      continue;
    }

    // Repo sub-fields (indented under - )
    if (inRepos && currentRepo && (line.startsWith('    ') || line.startsWith('\t\t'))) {
      const [key, ...rest] = trimmed.split(':');
      const value = rest.join(':').trim().replace(/^["']|["']$/g, '');
      if (key === 'name') currentRepo.name = value;
      else if (key === 'registry') currentRepo.registry = value;
    }
  }

  // Flush last repo
  if (currentRepo?.name) {
    config.repos!.push({ name: currentRepo.name, registry: currentRepo.registry });
  }

  if (!config.workspace) throw new Error('workspace.yaml missing "workspace" field');
  if (!config.this_repo) throw new Error('workspace.yaml missing "this_repo" field');

  return config as WorkspaceConfig;
}

/**
 * Generate workspace.yaml content from a WorkspaceConfig.
 */
export function serializeWorkspaceYaml(config: WorkspaceConfig): string {
  const lines: string[] = [];
  lines.push(`workspace: ${config.workspace}`);
  lines.push(`this_repo: ${config.this_repo}`);
  lines.push('repos:');
  for (const repo of config.repos) {
    lines.push(`  - name: ${repo.name}`);
    if (repo.registry) lines.push(`    registry: ${repo.registry}`);
  }
  if (config.shared_definitions) {
    lines.push(`shared_definitions: ${config.shared_definitions}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * Enrich a ThreatModel with provenance metadata.
 * Call this before writing the report JSON.
 */
export function populateMetadata(model: ThreatModel, root: string): ThreatModel {
  const workspace = loadWorkspaceConfig(root);

  const metadata: ReportMetadata = {
    schema_version: REPORT_SCHEMA_VERSION,
    guardlink_version: getGuardlinkVersion(),
    repo: workspace?.this_repo || model.project,
    commit_sha: getCommitSha(root),
    branch: getBranch(root),
    generated_at: model.generated_at,
    ...(workspace?.workspace && { workspace: workspace.workspace }),
  };

  return {
    ...model,
    metadata,
    external_refs: model.external_refs || [],
  };
}
