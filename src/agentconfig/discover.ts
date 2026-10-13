/**
 * GuardLink agent config — which files in a repository are coding-agent
 * configuration, which agents load each one, and in what scope.
 *
 * The file patterns live in the harness tables (`harness/*.json`), so this
 * module only walks the tree and applies them. Three rules carry the design:
 *
 *   - **Symlinks are followed inside the repository and nowhere else.** A
 *     repository that links `.claude/skills` to `.agents/skills` has one skill
 *     loaded by two agents; reading it twice would double every fact, and
 *     reading it once under one path would hide one agent. Each real file is
 *     read once, and every path that reaches it adds its loaders and is kept
 *     in `via`. A link that resolves outside the root is not followed: what it
 *     points at is not part of the repository being described.
 *   - **Scope decides meaning.** `root` and `nested` configuration is what
 *     this repository's agents load. `packaged` configuration ships to others
 *     (a plugin bundle, a template tree, a product's own assets) and creates
 *     no reach here. `fixture` is test data.
 *   - **GuardLink's own directory is not configuration.** `.guardlink/` holds
 *     templates such as the reference `.mcp.json` written by `init
 *     --no-root-files`, which no agent loads from there.
 *
 * @exposes #agent-config to #path-traversal [medium] cwe:CWE-59 -- "Follows symlinks found in the scanned repository"
 * @mitigates #agent-config against #path-traversal using #path-validation -- "Every directory and file is resolved with realpath and dropped unless it stays under the repository root; each real directory is entered once, so a link cycle terminates"
 * @exposes #agent-config to #dos [low] cwe:CWE-400 -- "Walks the whole repository tree"
 * @mitigates #agent-config against #dos using #resource-limits -- "Skips dependency and build directories, enters each real directory once, and stops after MAX_FILES configuration files"
 * @flows ProjectFiles -> #agent-config via readdirSync -- "Directory listing of the scanned repository"
 * @boundary from ProjectFiles to #agent-config (#agent-config-boundary) -- "Repository content is untrusted input to the config reader"
 */
import { readdirSync, realpathSync, statSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { AgentConfigScope, AgentConfigLoadedWhen } from '../types/index.js';
import { loadSemantics, type Semantics, type HarnessFileRule } from './semantics.js';

export const SKIP_DIRS = new Set([
  '.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', 'target', 'coverage',
  '.turbo', '.pnpm-store', 'vendor', '.cache', '.yarn', '.guardlink', '.bravos', '.bugb',
]);
const PACKAGED_SEGMENTS = new Set(['components', 'templates', 'plugins', 'marketplace', 'registry', 'examples']);
const FIXTURE_SEGMENTS = new Set(['fixtures', 'fixture', 'testdata', '__fixtures__', '__tests__', 'test-workspace']);
const AGENT_DIRS = new Set([
  '.claude', '.cursor', '.vscode', '.gemini', '.codex', '.github', '.roo', '.kiro', '.amazonq', '.kilocode',
  '.windsurf', '.zed', '.agents', '.clinerules',
]);
/** A repository with more configuration files than this is reported as truncated rather than read forever. */
export const MAX_FILES = 20_000;

export interface DiscoveredFile {
  /** Repository-relative POSIX path of the first path that reached the file. */
  path: string;
  /** Absolute real path. */
  real: string;
  kind: string;
  /** Every harness that loads it, sorted. */
  harnesses: string[];
  scope: AgentConfigScope;
  loaded_when: AgentConfigLoadedWhen[];
  /** `link -> target` for each symlinked path that also reaches it. */
  via: string[];
}

export interface Discovery {
  files: DiscoveredFile[];
  truncated: boolean;
}

interface Match { kind: string; harnesses: string[]; packaged: boolean; loaded_when: AgentConfigLoadedWhen[] }

/** The harnesses and kind a repository-relative path matches, or null. */
export function matchPath(rel: string, sem: Semantics = loadSemantics()): Match | null {
  let kind: string | null = null;
  let packaged = false;
  const harnesses = new Set<string>();
  const loaded = new Set<AgentConfigLoadedWhen>();
  const apply = (rules: { t: string; r: HarnessFileRule }[]) => {
    for (const { t, r } of rules) {
      if (!new RegExp(r.pattern).test(rel)) continue;
      kind ??= r.kind;
      if (r.kind === kind && r.packaged) packaged = true;
      harnesses.add(r.harness ?? t);
      for (const h of r.also ?? []) harnesses.add(h);
      for (const l of r.loaded_when ?? []) loaded.add(l);
    }
  };
  const all = sem.tables.flatMap(t => t.files.map(r => ({ t: t.harness ?? t.table, r })));
  apply(all.filter(x => !x.r.fallback));
  if (kind === null) apply(all.filter(x => x.r.fallback));
  if (kind === null) return null;
  return { kind, harnesses: [...harnesses].sort(), packaged, loaded_when: [...loaded].sort() as AgentConfigLoadedWhen[] };
}

/**
 * The scope of a configuration file. `isPluginDir` answers whether a
 * repository-relative directory holds a `.claude-plugin/` bundle marker.
 */
export function classifyScope(rel: string, isPluginDir: (dir: string) => boolean): AgentConfigScope {
  const parts = rel.split('/');
  const dirs = parts.slice(0, -1);
  if (dirs.some(p => FIXTURE_SEGMENTS.has(p)) || parts.some(p => p.includes('testWorkspace'))) return 'fixture';
  // Inside a plugin bundle: some ancestor carries .claude-plugin/.
  for (let i = 1; i <= dirs.length; i++) {
    if (isPluginDir(dirs.slice(0, i).join('/')) && !rel.startsWith('.claude/settings')) return 'packaged';
  }
  // Content a product ships (skills or prompts under its source tree) is not this repository's configuration.
  if ((dirs.includes('src') || dirs.some(p => PACKAGED_SEGMENTS.has(p))) && !parts[0].startsWith('.claude')) return 'packaged';
  if (AGENT_DIRS.has(parts[0])) return rel.includes('/plugins/') ? 'packaged' : 'root';
  return parts.length === 1 ? 'root' : 'nested';
}

const CANDIDATE_EXT = /\.(md|mdc|json|toml)$/i;

/**
 * Walk `root` for agent configuration. Deterministic: entries are visited in
 * code-unit order, so the same tree yields the same list.
 */
export function discover(root: string, sem: Semantics = loadSemantics()): Discovery {
  const realRoot = realpathSync(root);
  const inRoot = (real: string) => real === realRoot || real.startsWith(realRoot + sep);
  const byReal = new Map<string, DiscoveredFile>();
  const enteredDirs = new Set<string>();
  const pluginCache = new Map<string, boolean>();
  const isPluginDir = (dir: string) => {
    let v = pluginCache.get(dir);
    if (v === undefined) {
      try { v = statSync(join(root, dir, '.claude-plugin')).isDirectory(); } catch { v = false; }
      pluginCache.set(dir, v);
    }
    return v;
  };
  let truncated = false;

  // A real directory is walked again when another path reaches it through a
  // link (that path may add a loader), but never inside itself: `ancestors` is
  // the chain of real directories above this one, so a link cycle ends.
  const visit = (absDir: string, relDir: string, linkFrom: string | null, ancestors: ReadonlySet<string>) => {
    let real: string;
    try { real = realpathSync(absDir); } catch { return; }
    if (!inRoot(real) || ancestors.has(real)) return;
    if (enteredDirs.has(real) && linkFrom === null) return;
    enteredDirs.add(real);
    const chain = new Set(ancestors).add(real);
    let entries;
    try { entries = readdirSync(absDir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (truncated) return;
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      const abs = join(absDir, e.name);
      let isDir = e.isDirectory();
      let isFile = e.isFile();
      let viaLink = linkFrom;
      if (e.isSymbolicLink()) {
        let target: string;
        try { target = realpathSync(abs); } catch { continue; }
        if (!inRoot(target)) continue;
        try {
          const st = statSync(abs);
          isDir = st.isDirectory();
          isFile = st.isFile();
        } catch { continue; }
        viaLink = `${rel} -> ${relative(realRoot, target).split(sep).join('/')}`;
      }
      if (isDir) {
        if (SKIP_DIRS.has(e.name)) continue;
        visit(abs, rel, viaLink, chain);
        continue;
      }
      if (!isFile) continue;
      if (!CANDIDATE_EXT.test(e.name) && !rel.split('/').some(p => p.startsWith('.'))) continue;
      const m = matchPath(rel, sem);
      if (!m) continue;
      let realFile: string;
      try { realFile = realpathSync(abs); } catch { continue; }
      if (!inRoot(realFile)) continue;
      const seen = byReal.get(realFile);
      if (seen) {
        // The same file reached through a link: every agent that loads either path loads it.
        seen.harnesses = [...new Set([...seen.harnesses, ...m.harnesses])].sort();
        seen.loaded_when = [...new Set([...seen.loaded_when, ...m.loaded_when])].sort() as AgentConfigLoadedWhen[];
        if (viaLink && !seen.via.includes(viaLink)) seen.via.push(viaLink);
        continue;
      }
      let scope = classifyScope(rel, isPluginDir);
      if (m.packaged && scope === 'root') scope = 'packaged';
      byReal.set(realFile, {
        path: rel, real: realFile, kind: m.kind, harnesses: m.harnesses, scope, loaded_when: m.loaded_when,
        via: viaLink ? [viaLink] : [],
      });
      if (byReal.size >= MAX_FILES) truncated = true;
    }
  };

  if (existsSync(root)) visit(root, '', null, new Set());
  const files = [...byReal.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { files, truncated };
}

/** Whether a repository-relative path is agent configuration, by its name alone. Used by `diff` to extract history. */
export function isAgentConfigPath(rel: string, sem: Semantics = loadSemantics()): boolean {
  return matchPath(rel.split(sep).join('/'), sem) !== null;
}

