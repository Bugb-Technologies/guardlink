/**
 * Local workspace membership, using the identity stored in each member's manifest.
 * Names are not inferred from package metadata or from annotation prefixes.
 *
 * @flows ProjectRoot -> #workspace-config via localWorkspaceMembers -- "Read immediate child manifests; never follow directory symlinks or execute member code"
 * @mitigates #workspace-config against #config-tamper using #config-validation -- "Only members named in the selected manifest and declaring the same workspace are selected; conflicting manifests fail explicitly"
 */
import { readdirSync, existsSync, type Dirent } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { loadWorkspaceConfig } from './metadata.js';
import type { WorkspaceConfig } from './types.js';

export interface LocalMember { name: string; path: string; config: WorkspaceConfig }

function childMembers(parent: string): LocalMember[] {
  let entries: Dirent<string>[];
  try { entries = readdirSync(parent, { withFileTypes: true, encoding: 'utf8' }); }
  catch { return []; }
  const excluded = new Set(['node_modules', 'dist', 'build', 'target', 'vendor', '.git', '.bravos', '.bugb']);
  return entries.filter(e => e.isDirectory() && !excluded.has(e.name))
    .sort((a, b) => a.name < b.name ? -1 : 1).flatMap(e => {
      const path = join(parent, e.name);
      const config = loadWorkspaceConfig(path);
      if (!config && existsSync(join(path, '.guardlink/workspace.yaml'))) {
        throw new Error(`Unreadable or invalid linked member manifest: ${path}`);
      }
      return config ? [{ name: config.this_repo, path, config }] : [];
    });
}

/** Locate siblings by their stored identity, preserving old manifests whose directory names differ. */
export function localWorkspaceMembers(root: string, config: WorkspaceConfig): LocalMember[] {
  const members = childMembers(dirname(resolve(root))).filter(m =>
    config.repos.some(r => r.name === m.name) && m.config.workspace === config.workspace,
  );
  if (new Set(members.map(m => m.name)).size !== members.length) throw new Error('Duplicate linked member identity; member names must be unique.');
  return members;
}

/** A container is a workspace only when its immediate members agree on its selected set. */
export function workspaceContainer(root: string): { config: WorkspaceConfig; members: LocalMember[]; missing: string[] } | null {
  if (loadWorkspaceConfig(root)) return null;
  if (existsSync(join(root, '.guardlink/workspace.yaml'))) throw new Error('Unreadable or invalid .guardlink/workspace.yaml');
  const candidates = childMembers(root);
  if (candidates.length === 0) return null;
  const config = candidates[0].config;
  const key = (c: WorkspaceConfig) => JSON.stringify([c.workspace, c.repos.map(r => r.name).sort()]);
  if (candidates.some(m => key(m.config) !== key(config))) {
    throw new Error('Conflicting linked workspace manifests under this folder; make the member lists agree before parsing the application.');
  }
  const names = new Set(config.repos.map(r => r.name));
  const members = candidates.filter(m => names.has(m.name));
  if (new Set(members.map(m => m.name)).size !== members.length) {
    throw new Error('Duplicate linked member identity under this folder; member names must be unique.');
  }
  return { config, members, missing: [...names].filter(n => !members.some(m => m.name === n)) };
}
