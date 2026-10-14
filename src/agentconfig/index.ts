/**
 * GuardLink agent config — a repository's coding-agent configuration, read as
 * threat-model facts (SPEC §5.6).
 *
 * Instruction files (AGENTS.md, CLAUDE.md, rules files, copilot-instructions,
 * GEMINI.md), MCP configuration, agent settings and permissions, hooks and
 * skills decide what a coding agent working in the repository may run, read,
 * write or call without asking. This module reads them, offline and
 * deterministically, into the same reach rows a person writes for an embedded
 * agent (`@agents`, `@effects`, `@gates`), each pointing at the file and line
 * that granted it, plus an `agent_config` inventory block. `parseProject`
 * merges both into the model, so the existing reach analysis, report and
 * dashboard read them with no rule of their own.
 *
 * The default path never starts an MCP server, runs a hook or helper, fetches
 * a package, calls a model or contacts the network.
 *
 * @comment -- "Entry point of the config reader: discover() walks the tree, readFiles() reads each file; both are offline and never execute anything they read"
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { relative, sep } from 'node:path';
import type {
  ThreatModelReach, ThreatModelEffect, ThreatModelGate, ThreatModelActor, AgentConfigBlock,
} from '../types/index.js';
import { discover } from './discover.js';
import { readFiles } from './read.js';
import { loadSemantics } from './semantics.js';

export { collectBundle, bundledKind, MAX_BUNDLED } from './bundle.js';
export { discover, matchPath, classifyScope, isAgentConfigPath, type DiscoveredFile } from './discover.js';
export { findHiddenUnicode, describeHiddenUnicode, type HiddenUnicodeHit, type HiddenUnicodeKind } from './hidden-unicode.js';
export { loadSemantics, classifyShell, commandTags, REACH_HARNESSES, HARNESS_DIR, type Semantics } from './semantics.js';
export { parseStamp, GUARDLINK_BEGIN, GUARDLINK_END, STAMP_RE, packageOf, parseRule, WORKSTATION, SESSION, DEVELOPER } from './read.js';
export { parseJsonc } from './jsonc.js';
export { parseToml } from './toml.js';

/** Bump when the set of hashed fields changes; it is part of the emitted string. */
export const AGENT_CONFIG_HASH_VERSION = 1;

export interface AgentConfigResult {
  actors: ThreatModelActor[];
  reaches: ThreatModelReach[];
  effects: ThreatModelEffect[];
  gates: ThreatModelGate[];
  block: AgentConfigBlock;
}

/**
 * What the configuration grants, as a hash that moves only when that does.
 *
 * Covers the file list, every generated row by its words and its key (never its
 * line, so reformatting a file is not a change), MCP servers, hooks, deny rules,
 * the files bundled beside each skill (a new or edited script changes what the
 * skill runs) and the semantics versions that read them. It does NOT cover instruction-file
 * text: the GuardLink block written into those files carries this hash, so a
 * hash over their text could never match the block that states it.
 */
export function computeAgentConfigHash(r: Omit<AgentConfigResult, 'block'> & { block: Omit<AgentConfigBlock, 'agent_config_hash'> }): string {
  const rows = [
    ...r.reaches.map(x => ['agents', x.actor, x.capability, x.asset ?? '', x.identity ?? '']),
    ...r.effects.map(x => ['effects', x.effect, x.asset, x.identity ?? '']),
    ...r.gates.map(x => ['gates', x.asset, x.approver, x.capability ?? '']),
  ].map((fields, i) => {
    const src = [...r.reaches, ...r.effects, ...r.gates][i].source!;
    const loc = [...r.reaches, ...r.effects, ...r.gates][i].location;
    return JSON.stringify([...fields, loc.file, src.pointer, src.raw, src.gated, src.semantics.rule]);
  });
  const bundles = r.block.instruction_files
    .filter(f => f.bundled && f.bundled.length > 0)
    .map(f => [f.path, f.bundled!.map(x => [x.path, x.kind, x.bytes, x.sha256 ?? ''])]);
  const strip = <T extends { line?: number }>(x: T) => { const { line: _l, ...rest } = x; return rest; };
  const canonical = JSON.stringify({
    v: AGENT_CONFIG_HASH_VERSION,
    semantics: r.block.semantics,
    files: r.block.files,
    rows: rows.sort(),
    mcp: r.block.mcp_servers.map(strip),
    hooks: r.block.hooks.map(strip),
    denies: r.block.denies.map(strip),
    // Only when a skill has files beside it, so a repository without any keeps the hash it had.
    ...(bundles.length > 0 ? { bundles } : {}),
  });
  return `sha256-v${AGENT_CONFIG_HASH_VERSION}:${createHash('sha256').update(canonical).digest('hex')}`;
}

/**
 * The repository-relative paths git would carry from `root`: tracked files and
 * untracked ones it does not ignore. Null when `root` is not in a git work tree,
 * in which case every discovered file counts.
 *
 * Configuration a developer keeps for themselves (`.claude/settings.local.json`
 * is gitignored by convention) is not the repository's, and reading it would
 * make the model differ from one machine to the next — and from CI, which
 * checks the committed model against a fresh parse.
 *
 * @exposes #agent-config to #cmd-injection [medium] cwe:CWE-78 -- "Spawns git in the scanned directory"
 * @mitigates #agent-config against #cmd-injection using #param-commands -- "execFileSync with a fixed argument vector and no shell; no repository content reaches the arguments"
 */
export function gitCarriedPaths(root: string): Set<string> | null {
  try {
    const out = execFileSync('git', ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 512 * 1024 * 1024,
    });
    return new Set(out.split('\0').filter(Boolean));
  } catch {
    return null;
  }
}

export interface ReadAgentConfigOptions {
  /** Paths git carries (see gitCarriedPaths); null reads every discovered file. Defaults to asking git. */
  carried?: Set<string> | null;
}

/** Read `root`'s coding-agent configuration. Offline and deterministic. */
export function readAgentConfig(root: string, opts: ReadAgentConfigOptions = {}): AgentConfigResult {
  const sem = loadSemantics();
  const d = discover(root, sem);
  const carried = opts.carried !== undefined ? opts.carried : d.files.length > 0 ? gitCarriedPaths(root) : null;
  if (carried) {
    // A file reached through a symlinked directory is carried under its real path.
    const realRoot = realpathSync(root);
    d.files = d.files.filter(f => carried.has(f.path) || carried.has(relative(realRoot, f.real).split(sep).join('/')));
  }
  const read = readFiles(root, d.files, sem, carried);
  if (d.truncated) {
    read.block.unreadable.push({ file: '.', line: 1, message: 'more agent configuration files than GuardLink reads in one pass; the rest were not read' });
  }
  const agent_config_hash = computeAgentConfigHash(read);
  const { version, ...rest } = read.block;
  return { ...read, block: { version, agent_config_hash, ...rest } };
}
