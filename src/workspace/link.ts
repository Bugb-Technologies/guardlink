/**
 * GuardLink Workspace — link-project command logic.
 *
 * Scaffolds workspace.yaml in each repo and updates agent instruction
 * files with workspace context so agents write cross-repo-aware annotations.
 *
 * @asset Workspace.Link (#workspace-link) -- "Multi-repo workspace linking setup"
 * @flows UserArgs -> #workspace-link via linkProject -- "CLI args to workspace scaffolding"
 * @flows #workspace-link -> AgentFiles via updateAgentWorkspaceContext -- "Inject workspace context"
 */

import { existsSync, readFileSync, mkdirSync, readdirSync, statSync, unlinkSync } from 'node:fs';
import { writeFileSync } from 'node:fs';
import { resolve, basename, dirname, join } from 'node:path';
import type { WorkspaceConfig, WorkspaceRepo } from './types.js';
import { serializeWorkspaceYaml, loadWorkspaceConfig } from './metadata.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface LinkProjectOptions {
  /** Workspace name */
  workspace: string;
  /** Repo directories (absolute or relative paths) */
  repoPaths: string[];
  /** GitHub/GitLab org registry base URL (e.g. "github.com/unstructured") */
  registry?: string;
}

export interface AddToWorkspaceOptions {
  /** Path to the new repo being added */
  newRepoPath: string;
  /** Path to an existing workspace repo (to read workspace.yaml from) */
  existingRepoPath: string;
  /** GitHub/GitLab org registry base URL (optional — inherits from existing workspace) */
  registry?: string;
}

export interface LinkResult {
  /** Repos that were successfully linked */
  linked: string[];
  /** Repos that were skipped (e.g. path not found) */
  skipped: { name: string; reason: string }[];
  /** Agent files updated */
  agentFilesUpdated: string[];
  /** Repos that were auto-initialized */
  initialized: string[];
  /** Repos whose workspace.yaml was updated (for --add mode) */
  updated: string[];
}

// ─── Fresh Link (all repos specified) ────────────────────────────────

/**
 * Link multiple repos into a workspace (fresh setup).
 *
 * For each repo path:
 * 1. Auto-init if not yet guardlink-initialized
 * 2. Detect repo name from git remote, package.json, or directory name
 * 3. Generate .guardlink/workspace.yaml
 * 4. Update agent instruction files with workspace context
 */
export function linkProject(options: LinkProjectOptions): LinkResult {
  const result: LinkResult = {
    linked: [], skipped: [], agentFilesUpdated: [], initialized: [], updated: [],
  };

  // Resolve all repo paths and detect names
  const repos: Array<{ name: string; path: string; registry?: string }> = [];
  for (const rp of options.repoPaths) {
    const absPath = resolve(rp);
    if (!existsSync(absPath)) {
      result.skipped.push({ name: rp, reason: 'Directory not found' });
      continue;
    }

    // Auto-init if needed
    const initResult = ensureInitialized(absPath);
    if (initResult) result.initialized.push(initResult);

    const name = detectRepoName(absPath);
    const registry = options.registry
      ? `${options.registry.replace(/\/$/, '')}/${name}`
      : undefined;
    repos.push({ name, path: absPath, registry });
  }

  if (repos.length === 0) return result;

  // Build the shared repo list
  const workspaceRepos: WorkspaceRepo[] = repos.map(r => ({
    name: r.name,
    ...(r.registry && { registry: r.registry }),
  }));

  // Write workspace.yaml + update agents in each repo
  writeWorkspaceToRepos(repos, workspaceRepos, options.workspace, result);

  return result;
}

// ─── Add to Existing Workspace ───────────────────────────────────────

/**
 * Add a new repo to an existing workspace.
 *
 * 1. Read workspace.yaml from the existing repo
 * 2. Get the full repo list + workspace name
 * 3. Auto-init the new repo if needed
 * 4. Discover existing workspace repos on disk (sibling directory scan)
 * 5. Add the new repo to the list
 * 6. Write updated workspace.yaml + agent files to ALL repos found on disk
 */
export function addToWorkspace(options: AddToWorkspaceOptions): LinkResult {
  const result: LinkResult = {
    linked: [], skipped: [], agentFilesUpdated: [], initialized: [], updated: [],
  };

  const existingPath = resolve(options.existingRepoPath);
  const newPath = resolve(options.newRepoPath);

  // 1. Read existing workspace config
  const existingConfig = loadWorkspaceConfig(existingPath);
  if (!existingConfig) {
    result.skipped.push({
      name: options.existingRepoPath,
      reason: 'No .guardlink/workspace.yaml found — not a workspace repo',
    });
    return result;
  }

  // 2. Auto-init the new repo if needed
  const initResult = ensureInitialized(newPath);
  if (initResult) result.initialized.push(initResult);

  // 3. Detect new repo name and build its WorkspaceRepo entry
  const newRepoName = detectRepoName(newPath);

  // Check if already in workspace
  if (existingConfig.repos.some(r => r.name === newRepoName)) {
    result.skipped.push({
      name: newRepoName,
      reason: `Already in workspace "${existingConfig.workspace}"`,
    });
    return result;
  }

  // Infer registry from existing repos if not provided
  const existingRegistry = existingConfig.repos.find(r => r.registry)?.registry;
  const registryBase = options.registry || extractRegistryBase(existingRegistry);
  const newRepoEntry: WorkspaceRepo = {
    name: newRepoName,
    ...(registryBase && { registry: `${registryBase}/${newRepoName}` }),
  };

  // 4. Build updated repo list
  const updatedRepos: WorkspaceRepo[] = [...existingConfig.repos, newRepoEntry];

  // 5. Discover all workspace repos on disk
  const discoveredPaths = discoverWorkspaceRepos(
    existingPath,
    existingConfig,
    newPath,
    newRepoName,
  );

  // 6. Write to all discovered repos
  const reposWithPaths = discoveredPaths.map(d => ({
    name: d.name,
    path: d.path,
    registry: updatedRepos.find(r => r.name === d.name)?.registry,
  }));

  writeWorkspaceToRepos(reposWithPaths, updatedRepos, existingConfig.workspace, result);

  // Track which existing repos got updated vs the new one that got linked
  for (const d of discoveredPaths) {
    if (d.name !== newRepoName && result.linked.includes(d.name)) {
      // Move from "linked" to "updated" for existing repos
      result.linked = result.linked.filter(n => n !== d.name);
      result.updated.push(d.name);
    }
  }

  return result;
}

// ─── Remove from Existing Workspace ──────────────────────────────────

export interface RemoveFromWorkspaceOptions {
  /** Name of the repo to remove (as listed in workspace.yaml) */
  repoName: string;
  /** Path to any repo currently in the workspace (to read workspace.yaml from) */
  existingRepoPath: string;
}

/**
 * Remove a repo from an existing workspace.
 *
 * 1. Read workspace.yaml from the existing repo
 * 2. Verify the named repo is actually in the workspace
 * 3. Remove it from the repo list
 * 4. Discover all remaining workspace repos on disk
 * 5. Update workspace.yaml + agent files in all remaining repos
 * 6. If the removed repo is found on disk, clean up its workspace.yaml
 *    and strip workspace context from its agent files
 */
export function removeFromWorkspace(options: RemoveFromWorkspaceOptions): LinkResult {
  const result: LinkResult = {
    linked: [], skipped: [], agentFilesUpdated: [], initialized: [], updated: [],
  };

  const existingPath = resolve(options.existingRepoPath);

  // 1. Read existing workspace config
  const existingConfig = loadWorkspaceConfig(existingPath);
  if (!existingConfig) {
    result.skipped.push({
      name: options.existingRepoPath,
      reason: 'No .guardlink/workspace.yaml found — not a workspace repo',
    });
    return result;
  }

  // 2. Verify repo is in workspace
  const targetRepo = existingConfig.repos.find(r => r.name === options.repoName);
  if (!targetRepo) {
    result.skipped.push({
      name: options.repoName,
      reason: `Not found in workspace "${existingConfig.workspace}" (repos: ${existingConfig.repos.map(r => r.name).join(', ')})`,
    });
    return result;
  }

  // 3. Can't remove if it would leave < 2 repos
  if (existingConfig.repos.length <= 2) {
    result.skipped.push({
      name: options.repoName,
      reason: 'Cannot remove — workspace must have at least 2 repos. Use fresh link-project to recreate.',
    });
    return result;
  }

  // 4. Build updated repo list (without the removed repo)
  const updatedRepos = existingConfig.repos.filter(r => r.name !== options.repoName);

  // 5. Discover remaining repos on disk
  //    We pass a dummy new path that won't match anything — we just need discovery
  const discoveredPaths = discoverWorkspaceReposForRemoval(
    existingPath,
    existingConfig,
    options.repoName,
  );

  // 6. Update remaining repos
  const remainingRepos = discoveredPaths
    .filter(d => d.name !== options.repoName)
    .map(d => ({
      name: d.name,
      path: d.path,
      registry: updatedRepos.find(r => r.name === d.name)?.registry,
    }));

  writeWorkspaceToRepos(remainingRepos, updatedRepos, existingConfig.workspace, result);

  // Move all from "linked" to "updated" since these are existing repos being updated
  result.updated = [...result.linked];
  result.linked = [];

  // 7. Clean up the removed repo if found on disk
  const removedOnDisk = discoveredPaths.find(d => d.name === options.repoName);
  if (removedOnDisk) {
    cleanupRemovedRepo(removedOnDisk.path, options.repoName, result);
  }

  return result;
}

/**
 * Clean up a removed repo: delete workspace.yaml, strip workspace context from agent files.
 */
function cleanupRemovedRepo(repoPath: string, repoName: string, result: LinkResult): void {
  // Delete workspace.yaml
  const yamlPath = resolve(repoPath, '.guardlink', 'workspace.yaml');
  if (existsSync(yamlPath)) {
    unlinkSync(yamlPath);
  }

  // Strip workspace context block from agent files
  for (const agent of AGENT_FILES) {
    const filePath = resolve(repoPath, agent.path);
    if (!existsSync(filePath)) continue;

    let content = readFileSync(filePath, 'utf-8');
    const markerIdx = content.indexOf(agent.marker);
    if (markerIdx === -1) continue;

    // Remove from marker to next ## or end of file
    const afterMarker = content.slice(markerIdx);
    const nextSectionMatch = afterMarker.match(/\n## (?!Workspace Context)/);
    const endIdx = nextSectionMatch
      ? markerIdx + (nextSectionMatch.index ?? afterMarker.length)
      : content.length;

    content = content.slice(0, markerIdx).trimEnd() + '\n';
    writeFileSync(filePath, content);
    result.agentFilesUpdated.push(`${repoName}/${agent.path} (cleaned)`);
  }
}

/**
 * Discover workspace repos for removal — scans sibling dirs from the existing repo.
 * Also tries to find the repo being removed so we can clean it up.
 */
function discoverWorkspaceReposForRemoval(
  existingRepoPath: string,
  config: WorkspaceConfig,
  removingRepoName: string,
): DiscoveredRepo[] {
  const discovered: DiscoveredRepo[] = [];
  const found = new Set<string>();

  // Always include the existing repo
  discovered.push({ name: config.this_repo, path: existingRepoPath });
  found.add(config.this_repo);

  // Find all other workspace repos (including the one being removed, for cleanup)
  const remaining = config.repos
    .map(r => r.name)
    .filter(n => !found.has(n));

  const scanDirs = new Set<string>();
  scanDirs.add(dirname(existingRepoPath));
  scanDirs.add(dirname(dirname(existingRepoPath)));

  for (const scanDir of scanDirs) {
    if (!existsSync(scanDir)) continue;
    let entries: string[];
    try { entries = readdirSync(scanDir); } catch { continue; }

    for (const entry of entries) {
      const entryPath = join(scanDir, entry);
      try { if (!statSync(entryPath).isDirectory()) continue; } catch { continue; }

      for (const repoName of remaining) {
        if (found.has(repoName)) continue;
        if (matchesRepoName(entryPath, entry, repoName)) {
          discovered.push({ name: repoName, path: entryPath });
          found.add(repoName);
        }
      }
    }
  }

  return discovered;
}

// ─── Discover Workspace Repos on Disk ─────────────────────────────────

interface DiscoveredRepo {
  name: string;
  path: string;
}

/**
 * Find workspace repos on the local filesystem.
 *
 * Strategy:
 * 1. Start with the known existing repo path and the new repo path
 * 2. For remaining repos in workspace.yaml, scan common parent directories
 * 3. Check: parent of existing repo, parent of new repo, grandparent
 * 4. Match by directory name or git remote name
 */
function discoverWorkspaceRepos(
  existingRepoPath: string,
  config: WorkspaceConfig,
  newRepoPath: string,
  newRepoName: string,
): DiscoveredRepo[] {
  const discovered: DiscoveredRepo[] = [];
  const found = new Set<string>();

  // Always include the existing repo and new repo
  discovered.push({ name: config.this_repo, path: existingRepoPath });
  found.add(config.this_repo);

  discovered.push({ name: newRepoName, path: newRepoPath });
  found.add(newRepoName);

  // Find remaining workspace repos
  const remaining = config.repos
    .map(r => r.name)
    .filter(n => !found.has(n));

  if (remaining.length === 0) return discovered;

  // Directories to scan for sibling repos
  const scanDirs = new Set<string>();
  scanDirs.add(dirname(existingRepoPath));
  scanDirs.add(dirname(newRepoPath));
  // Also try grandparent (for monorepo-style layouts like ~/projects/org/repos/)
  scanDirs.add(dirname(dirname(existingRepoPath)));

  for (const scanDir of scanDirs) {
    if (!existsSync(scanDir)) continue;

    let entries: string[];
    try {
      entries = readdirSync(scanDir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (found.has(entry)) continue; // already discovered by name match

      const entryPath = join(scanDir, entry);
      try {
        if (!statSync(entryPath).isDirectory()) continue;
      } catch {
        continue;
      }

      // Check if this directory matches a remaining repo
      for (const repoName of remaining) {
        if (found.has(repoName)) continue;

        if (matchesRepoName(entryPath, entry, repoName)) {
          discovered.push({ name: repoName, path: entryPath });
          found.add(repoName);
        }
      }
    }
  }

  // Warn about repos we couldn't find (they'll be in the updated workspace.yaml
  // but won't get their files updated — user needs to update them manually)
  // Caller handles this via checking which names are in result.linked vs config.repos

  return discovered;
}

/**
 * Check if a directory matches a workspace repo name.
 * Matches by: exact directory name, or git remote repo name.
 */
function matchesRepoName(dirPath: string, dirName: string, repoName: string): boolean {
  // Direct name match
  if (dirName === repoName) return true;

  // Check git remote
  try {
    const gitConfigPath = join(dirPath, '.git', 'config');
    if (existsSync(gitConfigPath)) {
      const gitConfig = readFileSync(gitConfigPath, 'utf-8');
      const m = gitConfig.match(/url\s*=\s*.*[/:]([^/\s]+?)(?:\.git)?\s*$/m);
      if (m && m[1] === repoName) return true;
    }
  } catch { /* ignore */ }

  return false;
}

/**
 * Extract the org base URL from a full registry URL.
 * "github.com/unstructured/payment-svc" → "github.com/unstructured"
 */
function extractRegistryBase(registry: string | undefined): string | undefined {
  if (!registry) return undefined;
  const lastSlash = registry.lastIndexOf('/');
  return lastSlash > 0 ? registry.slice(0, lastSlash) : undefined;
}

// ─── Shared: Write Workspace Config to Repos ─────────────────────────

function writeWorkspaceToRepos(
  repos: Array<{ name: string; path: string; registry?: string }>,
  workspaceRepos: WorkspaceRepo[],
  workspace: string,
  result: LinkResult,
): void {
  for (const repo of repos) {
    try {
      const config: WorkspaceConfig = {
        workspace,
        this_repo: repo.name,
        repos: workspaceRepos,
      };

      // Ensure .guardlink/ exists
      const guardlinkDir = resolve(repo.path, '.guardlink');
      if (!existsSync(guardlinkDir)) {
        mkdirSync(guardlinkDir, { recursive: true });
      }

      // Write workspace.yaml
      const yamlPath = resolve(guardlinkDir, 'workspace.yaml');
      writeFileSync(yamlPath, serializeWorkspaceYaml(config));

      // Update agent instruction files
      const updated = updateAgentWorkspaceContext(repo.path, config, workspaceRepos);
      result.agentFilesUpdated.push(...updated);

      result.linked.push(repo.name);
    } catch (err) {
      result.skipped.push({
        name: repo.name,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }
}

// ─── Auto-Init ───────────────────────────────────────────────────────

/**
 * Check if a repo has been guardlink-initialized.
 * If not, create minimal structure: .guardlink/ dir and base agent files.
 * Returns the repo name if initialized, null if already set up.
 */
function ensureInitialized(repoPath: string): string | null {
  const guardlinkDir = resolve(repoPath, '.guardlink');
  const hasGuardlink = existsSync(guardlinkDir);

  // Check for at least one agent instruction file
  const hasAnyAgentFile = AGENT_FILES.some(a => existsSync(resolve(repoPath, a.path)));

  if (hasGuardlink && hasAnyAgentFile) return null; // already initialized

  const repoName = detectRepoName(repoPath);

  // Create .guardlink/ if missing
  if (!hasGuardlink) {
    mkdirSync(guardlinkDir, { recursive: true });
  }

  // Create minimal agent instruction files if none exist
  if (!hasAnyAgentFile) {
    createMinimalAgentFiles(repoPath, repoName);
  }

  return repoName;
}

/**
 * Create minimal agent instruction files for a repo that hasn't been
 * guardlink-initialized. We create a subset — just the most common ones
 * (.claude/guardlink.md, AGENTS.md) rather than the full init flow,
 * since the user may not have all agents installed.
 */
function createMinimalAgentFiles(repoPath: string, repoName: string): void {
  const baseContent = [
    `# GuardLink — ${repoName}`,
    '',
    'This project uses [GuardLink](https://guardlink.bugb.io) for security annotations.',
    '',
    '## Annotation Rules',
    '',
    '- Add `@asset`, `@threat`, `@control` annotations to define security elements',
    '- Use `@mitigates`, `@exposes`, `@accepts` to document relationships',
    '- Use `@flows` to document data movement between components',
    '- Never write `@accepts` — risk acceptance is human-only via `guardlink review`',
    '- Run `guardlink validate .` after changes to check for errors',
    '',
  ].join('\n');

  // Create .claude/guardlink.md (most common agent)
  const claudeDir = resolve(repoPath, '.claude');
  if (!existsSync(claudeDir)) mkdirSync(claudeDir, { recursive: true });
  const claudePath = resolve(claudeDir, 'guardlink.md');
  if (!existsSync(claudePath)) writeFileSync(claudePath, baseContent);

  // Create AGENTS.md (universal)
  const agentsPath = resolve(repoPath, 'AGENTS.md');
  if (!existsSync(agentsPath)) writeFileSync(agentsPath, baseContent);
}

// ─── Repo Name Detection ─────────────────────────────────────────────

/**
 * Detect repo name from (in order): git remote origin, package.json name,
 * Cargo.toml name, or directory basename.
 */
export function detectRepoName(repoPath: string): string {
  // 1. Git remote
  try {
    const gitConfigPath = resolve(repoPath, '.git', 'config');
    if (existsSync(gitConfigPath)) {
      const gitConfig = readFileSync(gitConfigPath, 'utf-8');
      const m = gitConfig.match(/url\s*=\s*.*[/:]([^/\s]+?)(?:\.git)?\s*$/m);
      if (m) return m[1];
    }
  } catch { /* ignore */ }

  // 2. package.json
  try {
    const pkgPath = resolve(repoPath, 'package.json');
    if (existsSync(pkgPath)) {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      if (pkg.name && !isGenericName(pkg.name)) return pkg.name;
    }
  } catch { /* ignore */ }

  // 3. Cargo.toml
  try {
    const cargoPath = resolve(repoPath, 'Cargo.toml');
    if (existsSync(cargoPath)) {
      const cargo = readFileSync(cargoPath, 'utf-8');
      const m = cargo.match(/^\s*name\s*=\s*"([^"]+)"/m);
      if (m) return m[1];
    }
  } catch { /* ignore */ }

  // 4. Directory name
  return basename(repoPath);
}

const GENERIC_NAMES = new Set([
  'my-app', 'my-project', 'app', 'project', 'unknown', 'starter',
  'my-v0-project', 'vite-project', 'react-app', 'create-react-app',
]);

function isGenericName(name: string): boolean {
  return GENERIC_NAMES.has(name.toLowerCase());
}

// ─── Agent File Updates ──────────────────────────────────────────────

/** Known agent instruction file paths (relative to repo root) */
const AGENT_FILES = [
  { path: '.claude/guardlink.md', marker: '## Workspace Context' },
  { path: 'CLAUDE.md', marker: '## Workspace Context' },
  { path: '.cursor/rules/guardlink.mdc', marker: '## Workspace Context' },
  { path: '.windsurfrules', marker: '## Workspace Context' },
  { path: '.github/copilot-instructions.md', marker: '## Workspace Context' },
  { path: '.gemini/guardlink.md', marker: '## Workspace Context' },
  { path: 'AGENTS.md', marker: '## Workspace Context' },
];

/**
 * Generate the workspace context block that gets injected into agent files.
 */
export function buildWorkspaceContextBlock(
  config: WorkspaceConfig,
  allRepos: WorkspaceRepo[],
): string {
  const siblings = allRepos.filter(r => r.name !== config.this_repo);
  const siblingNames = siblings.map(r => r.name).join(', ');

  const lines: string[] = [];
  lines.push('## Workspace Context');
  lines.push('');
  lines.push(`This repository (\`${config.this_repo}\`) is part of the **${config.workspace}** workspace`);
  lines.push(`containing ${allRepos.length} linked services: ${allRepos.map(r => r.name).join(', ')}.`);
  lines.push('');
  lines.push('### Cross-Repo Annotation Rules');
  lines.push('');
  lines.push('When writing GuardLink annotations in this repo:');
  lines.push('');
  lines.push(`- **Tag prefix convention:** Use \`#${config.this_repo}.<component>\` for assets defined here.`);
  lines.push(`- **Reference sibling repos:** You may reference assets/threats/controls from: ${siblingNames}.`);
  lines.push(`  Use their tag prefix, e.g. \`#${siblings[0]?.name || 'other-service'}.<component>\`.`);
  lines.push('- **Cross-service data flows:** If this code calls or is called by another service, document it:');
  lines.push(`  \`@flows #request from #${config.this_repo}.handler to #${siblings[0]?.name || 'other-service'}.endpoint\``);
  lines.push('- **Do not redefine** assets that belong to another repo. Reference them by tag.');
  lines.push('- **External refs are OK:** Tags referencing sibling repos will show as "external refs"');
  lines.push('  during local validation but resolve during workspace merge.');
  lines.push('');
  lines.push(`### Sibling Services`);
  lines.push('');
  for (const s of siblings) {
    const reg = s.registry ? ` (${s.registry})` : '';
    lines.push(`- **${s.name}**${reg}`);
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Update agent instruction files in a repo with workspace context.
 * If the file exists and already has a workspace context block, replace it.
 * If the file exists without the block, append it.
 * If the file doesn't exist, skip it.
 *
 * Returns list of files updated.
 */
function updateAgentWorkspaceContext(
  repoPath: string,
  config: WorkspaceConfig,
  allRepos: WorkspaceRepo[],
): string[] {
  const contextBlock = buildWorkspaceContextBlock(config, allRepos);
  const updated: string[] = [];

  for (const agent of AGENT_FILES) {
    const filePath = resolve(repoPath, agent.path);
    if (!existsSync(filePath)) continue;

    let content = readFileSync(filePath, 'utf-8');
    const markerIdx = content.indexOf(agent.marker);

    if (markerIdx !== -1) {
      // Replace existing workspace context block (from marker to next ## or end)
      const afterMarker = content.slice(markerIdx);
      const nextSectionMatch = afterMarker.match(/\n## (?!Workspace Context)/);
      const endIdx = nextSectionMatch
        ? markerIdx + (nextSectionMatch.index ?? afterMarker.length)
        : content.length;
      content = content.slice(0, markerIdx) + contextBlock + content.slice(endIdx);
    } else {
      // Append workspace context block
      content = content.trimEnd() + '\n\n' + contextBlock;
    }

    writeFileSync(filePath, content);
    updated.push(`${config.this_repo}/${agent.path}`);
  }

  return updated;
}
