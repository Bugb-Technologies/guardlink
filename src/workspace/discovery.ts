/**
 * Local workspace membership, using the identity stored in each member's manifest.
 * Names are not inferred from package metadata or from annotation prefixes.
 *
 * @flows ProjectRoot -> #workspace-config via localWorkspaceMembers -- "Read immediate child manifests; never follow directory symlinks or execute member code"
 * @mitigates #workspace-config against #config-tamper using #config-validation -- "Only members named in the selected manifest and declaring the same workspace are selected; conflicting manifests fail explicitly; duplicate identities report every checkout path and how to select one"
 * @mitigates #parser against #vacuous-pass using #fail-closed -- "A root with its own .guardlink/config.json, definitions or workspace.yaml is a repository and is never replaced by an application inferred from its child folders, so its own exposures stay in validate, lint, diff, sarif and ci; child discovery reads only folders the scan set would read"
 */
import { existsSync, readdirSync, type Dirent } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { loadWorkspaceConfig, WorkspaceConfigError } from './metadata.js';
import type { WorkspaceConfig } from './types.js';
import { DEFAULT_EXCLUDE } from '../parser/parse-project.js';
import { hasCheckoutMarker, prunedNames } from '../parser/nested-checkouts.js';

export interface LocalMember { name: string; path: string; config: WorkspaceConfig }

const byName = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

function membersIn(parent: string, names: string[]): LocalMember[] {
  return names.flatMap(name => {
    const path = join(parent, name);
    const config = loadWorkspaceConfig(path, { strict: true });
    return config ? [{ name: config.this_repo, path, config }] : [];
  });
}

function childMembers(parent: string): LocalMember[] {
  let entries: Dirent<string>[];
  try { entries = readdirSync(parent, { withFileTypes: true, encoding: 'utf8' }); }
  catch { return []; }
  const excluded = new Set(['node_modules', 'dist', 'build', 'target', 'vendor', '.git', '.bravos', '.bugb']);
  return membersIn(parent, entries.filter(e => e.isDirectory() && !excluded.has(e.name)).map(e => e.name).sort(byName));
}

/**
 * Whether `root` is a GuardLink repository rather than a folder of linked checkouts: it carries its own
 * `.guardlink/config.json`, a `.guardlink/definitions.*` file or its own `.guardlink/workspace.yaml`.
 * Such a root's own model is what every command reports. Linked child folders never turn it into an
 * application view by inference; only an explicit selection (`--application-manifest`,
 * `GUARDLINK_APPLICATION_MANIFEST`, `application-view --manifest`) does.
 */
export function isGuardLinkRepository(root: string): boolean {
  if (existsSync(join(root, '.guardlink', 'config.json')) || existsSync(join(root, '.guardlink', 'workspace.yaml'))) return true;
  try { return readdirSync(join(root, '.guardlink')).some(name => /^definitions\.[^.]+$/.test(name)); }
  catch { return false; }
}

/**
 * The direct child folders of `root` whose linked manifest may select an application: the folders a
 * scan of `root` would read. Hidden folders and the names DEFAULT_EXCLUDE prunes (node_modules, vendor,
 * tests, …) are skipped. When `root` is itself a git checkout, a child holding a `.git` FILE — a
 * submodule or a linked worktree — is another checkout and is skipped, exactly as scanIgnore skips it;
 * a plain folder of checkouts is something people point GuardLink at on purpose, so there it is read.
 */
export function manifestCandidates(root: string): string[] {
  let entries: Dirent<string>[];
  try { entries = readdirSync(root, { withFileTypes: true, encoding: 'utf8' }); }
  catch { return []; }
  const pruned = prunedNames(DEFAULT_EXCLUDE);
  const insideGit = existsSync(join(root, '.git'));
  return entries
    .filter(e => e.isDirectory() && !e.name.startsWith('.') && !pruned.has(e.name)
      && !(insideGit && hasCheckoutMarker(join(root, e.name))))
    .map(e => e.name).sort(byName);
}

/**
 * Direct child manifests a repository root ignores but cannot decode, as named errors for a warning:
 * the repository's own model stands, and the broken manifest is still reported rather than silent.
 */
export function unreadableChildManifests(root: string): WorkspaceConfigError[] {
  const errors: WorkspaceConfigError[] = [];
  for (const name of manifestCandidates(root)) {
    try { loadWorkspaceConfig(join(root, name), { strict: true }); }
    catch (error) { if (error instanceof WorkspaceConfigError) errors.push(error); else throw error; }
  }
  return errors;
}

/** Reject ambiguous membership with the manifests and checkout paths needed to fix it. */
function assertUniqueMembers(members: LocalMember[]): void {
  const byIdentity = new Map<string, LocalMember[]>();
  for (const member of members) {
    const key = JSON.stringify([member.config.workspace, member.name]);
    const matches = byIdentity.get(key) ?? [];
    matches.push(member);
    byIdentity.set(key, matches);
  }
  for (const matches of byIdentity.values()) {
    if (matches.length < 2) continue;
    const { name, config, path } = matches[0];
    throw new WorkspaceConfigError(join(path, '.guardlink/workspace.yaml'),
      `Duplicate linked member identity "${name}" in workspace "${config.workspace}": `
      + matches.map(m => `"${m.path}"`).join(', ')
      + ` all declare this_repo: ${name}. Keep one checkout per member in this application folder: `
      + 'move the extra checkout outside it, or relink distinct services with unique --member names.');
  }
}

/** Locate siblings by their stored identity, preserving old manifests whose directory names differ. */
export function localWorkspaceMembers(root: string, config: WorkspaceConfig): LocalMember[] {
  const members = childMembers(dirname(resolve(root))).filter(m =>
    config.repos.some(r => r.name === m.name) && m.config.workspace === config.workspace,
  );
  assertUniqueMembers(members);
  return members;
}

/** A container is a workspace only when its immediate members agree on its selected set. */
export function workspaceContainer(root: string): { config: WorkspaceConfig; members: LocalMember[]; missing: string[] } | null {
  if (isGuardLinkRepository(root)) return null;
  const candidates = membersIn(root, manifestCandidates(root));
  if (candidates.length === 0) return null;
  assertUniqueMembers(candidates);
  const config = candidates[0].config;
  const key = (c: WorkspaceConfig) => JSON.stringify([c.workspace, c.repos.map(r => r.name).sort()]);
  if (candidates.some(m => key(m.config) !== key(config))) {
    throw new Error('Conflicting linked workspace manifests under this folder; make the member lists agree before parsing the application.');
  }
  const names = new Set(config.repos.map(r => r.name));
  const members = candidates.filter(m => names.has(m.name));
  return { config, members, missing: [...names].filter(n => !members.some(m => m.name === n)) };
}
