/**
 * GuardLink init — Project initialization.
 *
 * Detects project language and existing agent files, creates .guardlink/
 * directory with shared definitions, and injects GuardLink instructions
 * into agent instruction files (CLAUDE.md, .cursorrules, etc.).
 *
 * @exposes #init to #arbitrary-write [high] cwe:CWE-73 -- "Creates/modifies files: .guardlink/, CLAUDE.md, .cursorrules, etc."
 * @mitigates #init against #arbitrary-write using #path-validation -- "All paths are relative to root; join() constrains"
 * @exposes #init to #path-traversal [medium] cwe:CWE-22 -- "Reads/writes files based on root argument"
 * @mitigates #init against #path-traversal using #path-validation -- "join() with explicit root constrains file access"
 * @exposes #init to #data-exposure [low] cwe:CWE-200 -- "Writes API key config to .guardlink/config.json"
 * @audit #init -- "Config file may contain API keys; .gitignore entry added automatically"
 * @flows ProjectRoot -> #init via options.root -- "Project root input"
 * @flows #init -> AgentFiles via writeFileSync -- "Agent instruction file writes"
 * @flows #init -> ConfigFile via writeFileSync -- "Config file write"
 * @handles internal on #init -- "Generates definitions and agent instruction content"
 */

import { existsSync, readFileSync, mkdirSync, writeFileSync, appendFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { detectProject, type ProjectInfo } from './detect.js';
import {
  agentInstructions,
  agentInstructionsWithModel,
  cursorRulesContent,
  cursorRulesContentWithModel,
  cursorMdcContent,
  cursorMdcContentWithModel,
  definitionsContent,
  configContent,
  mcpConfig,
  referenceDocContent,
  promptMdContent,
  guardlinkReadmeContent,
  GITIGNORE_ENTRY,
  referenceDocPath,
  REFERENCE_DOC_IN_GUARDLINK,
  REFERENCE_DOC_IN_DOCS,
  GITATTRIBUTES_ENTRY,
  type ModelContextFreshness,
} from './templates.js';
import { computeAnnotationHash } from '../parser/annotation-hash.js';
import { detectAnnotationMode, readConfiguredMode } from '../parser/annotation-mode.js';
// The mode a repo can be OBSERVED in, which includes 'mixed'. `InitOptions.mode`
// stays the narrower 'inline' | 'external' — init chooses one, sync reports what
// is actually there, and the templates have to render both.
import type { AnnotationMode as ObservedAnnotationMode } from '../parser/annotation-mode.js';
import type { ThreatModel } from '../types/index.js';
import type { AnnotationMode } from '../agents/index.js';
import { AGENT_CHOICES } from './picker.js';
import { definitionsArePopulated, configIsCustomised } from './preserve.js';

/**
 * Read a file we are about to consider overwriting.
 *
 * Returns `null` when the read fails, and both D24 guards treat `null` as
 * authored content. A file we cannot read is the last one to destroy on the
 * assumption that it was empty.
 */
function readForGuard(path: string): string | null {
  try {
    return readFileSync(path, 'utf-8');
  } catch {
    return null;
  }
}

export { detectProject, type ProjectInfo, type AgentFile } from './detect.js';
export { promptAgentSelection, resolveAgentFiles, AGENT_CHOICES } from './picker.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface InitOptions {
  /** Project root directory */
  root: string;
  /** Override project name */
  project?: string;
  /** Skip agent file updates (only create .guardlink/) */
  skipAgentFiles?: boolean;
  /**
   * Re-scaffold an already-initialized project: rewrite config, README, prompt,
   * reference doc, `.mcp.json` and the agent instruction blocks.
   *
   * It does NOT overwrite authored content. A definitions file holding
   * declarations the template does not, and a `config.json` carrying settings
   * the template does not, are preserved and reported (D24). Use `reset` for
   * those.
   */
  force?: boolean;
  /**
   * Overwrite authored content too — the definitions file and a customised
   * `config.json`.
   *
   * This DESTROYS the threat model's declarations. Typing the flag is the
   * confirmation; there is no prompt, because the flag exists so the
   * destructive intent has to be stated separately from "re-scaffold".
   * Implies `force`.
   */
  reset?: boolean;
  /** Dry run — show what would be created without writing */
  dryRun?: boolean;
  /** Explicit agent IDs to create files for (when no existing agent files found) */
  agentIds?: string[];
  /**
   * Where annotations LIVE. Nothing else.
   *
   *   external (default) — `.gal` sidecars under `.guardlink/annotations/`
   *   inline             — comments in the source files themselves
   *
   * This used to also decide whether init wrote anything outside `.guardlink/`,
   * which conflated two unrelated questions and made "keep annotations out of my
   * source" cost you MCP auto-discovery and every agent instruction file — the
   * two things that make an agent aware GuardLink exists at all. That footprint
   * question is now `rootFiles` (GL-506).
   */
  mode?: AnnotationMode;
  /**
   * Whether init may write outside `.guardlink/`.
   *
   * Default true: root `.mcp.json`, agent instruction files, `docs/`,
   * `.gitignore` and `.gitattributes`. Set false for a zero-footprint install
   * where `.guardlink/` is the entire diff — what `--mode external` used to
   * imply, now asked for on its own.
   */
  rootFiles?: boolean;
}

export interface InitResult {
  project: ProjectInfo;
  created: string[];
  updated: string[];
  skipped: string[];
  /**
   * Files `--force` declined to overwrite because they hold authored content
   * (D24). Distinct from `skipped`, which is the ordinary "exists, not forcing"
   * case: an entry here means the user asked for an overwrite and did not get
   * one, so callers are expected to say so loudly.
   */
  preserved: string[];
}

// ─── Marker for detecting our content ────────────────────────────────

const GUARDLINK_MARKER = '<!-- guardlink:begin -->';
const GUARDLINK_MARKER_END = '<!-- guardlink:end -->';

// ─── Main init function ──────────────────────────────────────────────

export function initProject(options: InitOptions): InitResult {
  const { root, dryRun = false, skipAgentFiles = false, rootFiles = true, reset = false } = options;
  // --reset implies --force: it is --force plus permission to destroy authored
  // content, not a separate mode.
  const force = options.force === true || reset;
  // Annotation storage. Defaults to external: source files stay clean and the
  // model is reviewable as one directory.
  const mode: 'inline' | 'external' = options.mode === 'inline' ? 'inline' : 'external';

  const project = detectProject(root);
  if (options.project) project.name = options.project;

  const created: string[] = [];
  const updated: string[] = [];
  const skipped: string[] = [];
  const preserved: string[] = [];

  // ── 1. Create .guardlink/ directory ──

  const tsDir = join(root, '.guardlink');
  if (!existsSync(tsDir)) {
    if (!dryRun) mkdirSync(tsDir, { recursive: true });
    created.push('.guardlink/');
  }

  // ── 2. Create config.json ──

  const configPath = join(tsDir, 'config.json');
  const configTemplate = configContent(project, mode);
  if (!existsSync(configPath)) {
    if (!dryRun) writeFileSync(configPath, configTemplate);
    created.push('.guardlink/config.json');
  } else if (force) {
    // D24: --force must not discard settings a human put here.
    const existing = readForGuard(configPath);
    if (!reset && (existing === null || configIsCustomised(existing, configTemplate))) {
      preserved.push('.guardlink/config.json (customised — --reset to overwrite)');
    } else {
      if (!dryRun) writeFileSync(configPath, configTemplate);
      updated.push('.guardlink/config.json');
    }
  } else {
    skipped.push('.guardlink/config.json (exists)');
  }

  // ── 3. Create definitions file ──
  // The one file in a GuardLink repo that is entirely hand-written. D24: --force
  // overwriting it destroyed 38 declarations once already, so it is now guarded
  // by content, not by the flag.

  const defsFile = `definitions${project.definitionsExt}`;
  const defsPath = join(tsDir, defsFile);
  const defsTemplate = definitionsContent(project);
  if (!existsSync(defsPath)) {
    if (!dryRun) writeFileSync(defsPath, defsTemplate);
    created.push(`.guardlink/${defsFile}`);
  } else if (force) {
    const existing = readForGuard(defsPath);
    if (!reset && (existing === null || definitionsArePopulated(existing, defsTemplate, defsFile))) {
      preserved.push(`.guardlink/${defsFile} (has declarations — --reset to overwrite)`);
    } else {
      if (!dryRun) writeFileSync(defsPath, defsTemplate);
      updated.push(`.guardlink/${defsFile}`);
    }
  } else {
    skipped.push(`.guardlink/${defsFile} (exists)`);
  }

  // ── 3b. Create .guardlink/README.md (agent cold-start, GL-402) ──
  // Written unconditionally. With --no-root-files this is the only discovery
  // path an agent has left, so it is never the thing that gets skipped.

  const readmePath = join(tsDir, 'README.md');
  if (!existsSync(readmePath) || force) {
    if (!dryRun) {
      writeFileSync(readmePath, guardlinkReadmeContent(project, {
        mode,
        modeSource: 'config',
        model: null,
        annotationHash: null,
        mcpAtRoot: rootFiles,
        // D45: the same rule init writes by, not a guess from annotation mode.
        referencePath: referenceDocPath(rootFiles),
      }));
    }
    created.push('.guardlink/README.md');
  } else {
    skipped.push('.guardlink/README.md (exists)');
  }

  // ── 4. Create .guardlink/prompt.md (skeleton for report) ──

  const promptPath = join(tsDir, 'prompt.md');
  if (!existsSync(promptPath) || force) {
    if (!dryRun) writeFileSync(promptPath, promptMdContent(project));
    created.push('.guardlink/prompt.md');
  } else {
    skipped.push('.guardlink/prompt.md (exists)');
  }

  // ── 5. Create reference doc ──
  // --no-root-files: inside .guardlink/ (zero footprint outside it)
  // default:         docs/GUARDLINK_REFERENCE.md (visible to humans browsing the project)

  // D45: one rule for where this goes, shared with the README writer that
  // points at it. They used to decide independently, off different inputs.
  const refRelative = referenceDocPath(rootFiles);
  const refDocPath = join(root, refRelative);
  if (!existsSync(refDocPath) || force) {
    if (!dryRun) {
      ensureDir(dirname(refDocPath));
      writeFileSync(refDocPath, referenceDocContent(project));
    }
    created.push(refRelative);
  } else {
    skipped.push(`${refRelative} (exists)`);
  }

  // ── 6. Update .gitignore ──
  // A root file, so gated on rootFiles — and it only ever ignores root-level
  // exports; .guardlink/ is committed as a whole either way.

  // D44: this only ever appended, so a project with no `.gitignore` — every
  // fresh one — got no entry at all. init has already decided which four
  // generated names it expects ignored; it then left `guardlink dashboard`
  // output both untracked and unignored. Create the file when it is absent,
  // exactly as the `.gitattributes` block below already does.
  if (rootFiles) {
    const gitignorePath = join(root, '.gitignore');
    const existing = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf-8') : null;
    const alreadyOurs = existing !== null
      && (existing.includes('GuardLink') || existing.includes('.guardlink'));
    if (!alreadyOurs) {
      if (!dryRun) {
        if (existing === null) writeFileSync(gitignorePath, GITIGNORE_ENTRY.trimStart());
        else appendFileSync(gitignorePath, GITIGNORE_ENTRY);
      }
      (existing === null ? created : updated).push('.gitignore');
    }
  }

  // ── 6b. Mark derived artifacts as generated (GL-302/GL-304) ──

  const gitattributesPath = join(root, '.gitattributes');
  const existingAttrs = rootFiles && existsSync(gitattributesPath) ? readFileSync(gitattributesPath, 'utf-8') : '';
  if (rootFiles && !existingAttrs.includes('.guardlink/graph')) {
    if (!dryRun) {
      if (existingAttrs) appendFileSync(gitattributesPath, GITATTRIBUTES_ENTRY);
      else writeFileSync(gitattributesPath, GITATTRIBUTES_ENTRY.trimStart());
    }
    (existingAttrs ? updated : created).push('.gitattributes');
  }

  // ── 7. Update/create agent instruction files ──
  // Written under external mode too, since GL-506: an agent that never learns
  // GuardLink exists cannot annotate in either mode.

  if (!skipAgentFiles && rootFiles) {
    const agentResults = updateAgentFiles(root, project, force, dryRun, mode, options.agentIds);
    created.push(...agentResults.created);
    updated.push(...agentResults.updated);
    skipped.push(...agentResults.skipped);
  }

  // ── 8. Create .mcp.json for Claude Code MCP integration ──
  // --no-root-files: inside .guardlink/ as a reference template — not auto-discovered
  //   by MCP clients, but it documents the config for devs who want it locally.
  // default: at the project root, where Claude Code and other MCP clients find it.

  if (!rootFiles) {
    const mcpPath = join(tsDir, '.mcp.json');
    if (!existsSync(mcpPath) || force) {
      if (!dryRun) writeFileSync(mcpPath, mcpConfig());
      created.push('.guardlink/.mcp.json');
    } else {
      skipped.push('.guardlink/.mcp.json (exists)');
    }
  } else {
    const mcpPath = join(root, '.mcp.json');
    if (!existsSync(mcpPath) || force) {
      if (!dryRun) writeFileSync(mcpPath, mcpConfig());
      created.push('.mcp.json');
    } else {
      skipped.push('.mcp.json (exists)');
    }
  }

  return { project, created, updated, skipped, preserved };
}

// ─── Agent file update logic ─────────────────────────────────────────

function updateAgentFiles(
  root: string,
  project: ProjectInfo,
  force: boolean,
  dryRun: boolean,
  // D27: the mode init just recorded in config.json. Without it the agent files
  // it writes cannot say where annotations go, which is the whole defect.
  mode: AnnotationMode,
  agentIds?: string[],
): { created: string[]; updated: string[]; skipped: string[] } {
  const created: string[] = [];
  const updated: string[] = [];
  const skipped: string[] = [];

  // Default: write ALL agent files so switching agents is seamless
  const ids = agentIds ?? AGENT_CHOICES.map(c => c.id);

  for (const id of ids) {
    const choice = AGENT_CHOICES.find(c => c.id === id);
    if (!choice) continue;

    const filePath = join(root, choice.file);
    const exists = existsSync(filePath);

    if (exists) {
      // File exists — inject/update GuardLink block
      const af = project.agentFiles.find(f => f.path === choice.file);
      if (af?.hasGuardLink && !force) {
        skipped.push(`${choice.file} (already has GuardLink)`);
        continue;
      }
      const result = injectIntoAgentFile(root, choice.file, project, force, dryRun, mode);
      if (result === 'updated') updated.push(choice.file);
      else if (result === 'skipped') skipped.push(choice.file);
      else skipped.push(result.skippedReason);
    } else {
      // File doesn't exist — create fresh. Route through safeWriteAgentFile so a
      // pre-existing path-type conflict (e.g. a `.cursor/rules` FILE where we need a
      // directory) skips just this agent file with a warning instead of crashing init.
      let content: string;
      if (choice.file.endsWith('.mdc')) {
        content = cursorMdcContent(project, mode);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        content = wrapMarkers(cursorRulesContent(project, mode));
      } else {
        // Markdown-based (CLAUDE.md, AGENTS.md, copilot-instructions.md, .gemini/GEMINI.md)
        content = buildClaudeMdFromScratch(project, mode);
      }
      const res = safeWriteAgentFile(filePath, content, dryRun, project, mode);
      if (!res.ok) skipped.push(res.skipReason);
      else if (res.action === 'merged') updated.push(`${choice.file} → merged into existing .cursor/rules`);
      else created.push(choice.file);
    }
  }

  return { created, updated, skipped };
}

function injectIntoAgentFile(
  root: string,
  relPath: string,
  project: ProjectInfo,
  force: boolean,
  dryRun: boolean,
  mode: AnnotationMode,
): 'updated' | 'skipped' | { skippedReason: string } {
  const fullPath = join(root, relPath);

  // Guard: if the target path exists as a DIRECTORY, every branch below that does
  // readFileSync/writeFileSync would throw EISDIR. Skip this agent file with a reason.
  if (existsSync(fullPath) && statSync(fullPath).isDirectory()) {
    return { skippedReason: `${relPath} (exists as a directory; expected a file — skipped)` };
  }

  // Special handling for Cursor .mdc files
  if (relPath.endsWith('.mdc')) {
    const res = safeWriteAgentFile(fullPath, cursorMdcContent(project, mode), dryRun, project, mode);
    if (!res.ok) return { skippedReason: res.skipReason };
    return 'updated';
  }

  // Special handling for .cursorrules / .windsurfrules / .clinerules (no markdown headers)
  if (relPath === '.cursorrules' || relPath === '.windsurfrules' || relPath === '.clinerules') {
    const existing = readFileSync(fullPath, 'utf-8');
    if (existing.includes('GuardLink') && !force) return 'skipped';

    if (!dryRun) {
      const block = wrapMarkers(cursorRulesContent(project, mode));
      const newContent = replaceOrAppend(existing, block);
      writeFileSync(fullPath, newContent);
    }
    return 'updated';
  }

  // Special handling for Gemini settings.json
  if (relPath.endsWith('settings.json')) {
    return 'skipped';
  }

  // All other markdown-based files
  const existing = readFileSync(fullPath, 'utf-8');
  if (existing.includes('GuardLink') && !force) return 'skipped';

  if (!dryRun) {
    const block = wrapMarkers(agentInstructions(project, mode));
    const newContent = replaceOrAppend(existing, block);
    writeFileSync(fullPath, newContent);
  }
  return 'updated';
}

function buildClaudeMdFromScratch(project: ProjectInfo, mode: AnnotationMode): string {
  return buildMdFromScratch(project, null, undefined, mode);
}

// ─── Helpers ─────────────────────────────────────────────────────────

function wrapMarkers(content: string): string {
  return `${GUARDLINK_MARKER}\n${content}\n${GUARDLINK_MARKER_END}\n`;
}

/**
 * If markers exist, replace the content between them.
 * Otherwise append to end of file.
 */
function replaceOrAppend(existing: string, block: string): string {
  const beginIdx = existing.indexOf(GUARDLINK_MARKER);
  const endIdx = existing.indexOf(GUARDLINK_MARKER_END);

  if (beginIdx !== -1 && endIdx !== -1) {
    // Replace existing block.
    //
    // The preserved tail must have its leading newlines stripped: `wrapMarkers`
    // already ends the block with exactly one, and the tail begins with the one
    // the *previous* sync wrote. Keeping both added a blank line on every run —
    // this repo's own CLAUDE.md had accumulated 55 of them. Stripping makes the
    // replacement idempotent, so syncing an unchanged model is a no-op.
    const tail = existing.slice(endIdx + GUARDLINK_MARKER_END.length).replace(/^\n+/, '');
    return existing.slice(0, beginIdx) + block + tail;
  }

  // Append with separator
  const separator = existing.endsWith('\n') ? '\n' : '\n\n';
  return existing + separator + block;
}

/**
 * Ensure a directory exists, creating it if needed.
 *
 * @exposes #init to #arbitrary-write [high] cwe:CWE-73 -- "Creates directories for agent-file writes"
 * @mitigates #init against #arbitrary-write using #path-validation -- "callers pass join(root, ...) constrained paths"
 *
 * Throws GuardLinkPathConflictError if the path already exists but is a FILE, not a
 * directory. This happens when a project ships an older single-file agent config (e.g.
 * a `.cursor/rules` file) where GuardLink expects the newer directory layout
 * (`.cursor/rules/`). Without this guard, mkdirSync no-ops on the existing file and the
 * subsequent writeFileSync throws a raw ENOTDIR with no actionable message.
 */
function ensureDir(dir: string): void {
  if (existsSync(dir)) {
    if (!statSync(dir).isDirectory()) {
      throw new GuardLinkPathConflictError(dir, 'directory');
    }
    return; // exists and is a directory — good
  }
  mkdirSync(dir, { recursive: true });
}

/**
 * Error raised when a path GuardLink needs to write already exists as the WRONG type
 * (a file where a directory is required, or vice versa). Carries the path and expected
 * type so callers can present a clear, actionable message and skip that one file.
 */
class GuardLinkPathConflictError extends Error {
  constructor(
    public readonly conflictPath: string,
    public readonly expected: 'directory' | 'file',
  ) {
    const other = expected === 'directory' ? 'file' : 'directory';
    super(
      `Path conflict: expected '${conflictPath}' to be a ${expected}, but it already exists as a ${other}. ` +
      `This usually means an existing agent-tool config uses a different layout than GuardLink expects ` +
      `(e.g. an older single-file '.cursor/rules' vs the newer '.cursor/rules/' directory). ` +
      `Rename or remove '${conflictPath}' and re-run, or use 'guardlink init --mode external' to keep all writes inside .guardlink/.`,
    );
    this.name = 'GuardLinkPathConflictError';
  }
}

/**
 * Write an agent file, resolving path-type conflicts intelligently.
 *
 * Returns one of:
 *   { ok: true, action: 'created' | 'merged' }  — write (or legacy-merge) succeeded
 *   { ok: false, skipReason: string }            — unmergeable conflict; skip with reason
 *
 * Two conflict cases are handled:
 *
 *  CASE A (mergeable) — the target is a Cursor `.mdc` whose parent (`.cursor/rules`) already
 *  exists as a FILE. This is a legacy single-file Cursor rules layout. Rather than failing,
 *  we merge GuardLink's block INTO that existing rules file using the same marker-based
 *  inject used for `.cursorrules`/`.clinerules` — preserving the user's content and staying
 *  idempotent. The user keeps a working Cursor setup that now includes GuardLink.
 *
 *  CASE B (unmergeable) — the target path itself already exists as a DIRECTORY (e.g. someone
 *  has a directory named `CLAUDE.md`). There is no safe way to write file content "into" a
 *  directory without destroying it, so we skip with a clear reason.
 */
function safeWriteAgentFile(
  filePath: string,
  content: string,
  dryRun: boolean,
  project: ProjectInfo,
  // Only used by the legacy `.cursor/rules`-is-a-file merge path below, which
  // regenerates the block itself instead of writing `content`.
  mode: ObservedAnnotationMode | null = null,
): { ok: true; action: 'created' | 'merged' } | { ok: false; skipReason: string } {
  // CASE B: target path is itself a directory — cannot write a file there.
  if (existsSync(filePath) && statSync(filePath).isDirectory()) {
    return { ok: false, skipReason: `${filePath} (exists as a directory; expected a file — skipped)` };
  }

  const parent = dirname(filePath);

  // CASE A: parent is an existing FILE (legacy single-file `.cursor/rules`). Merge into it.
  if (existsSync(parent) && !statSync(parent).isDirectory()) {
    // Normalize separators so this works cross-platform.
    const normParent = parent.split('\\').join('/');
    const isCursorLegacy = normParent.endsWith('.cursor/rules');
    if (isCursorLegacy) {
      if (!dryRun) {
        const existing = readFileSync(parent, 'utf-8');
        const block = wrapMarkers(cursorRulesContent(project, mode));
        writeFileSync(parent, replaceOrAppend(existing, block));
      }
      return { ok: true, action: 'merged' };
    }
    // Some other parent-is-a-file collision we don't know how to merge — skip.
    return { ok: false, skipReason: `${parent} (exists as a file; expected a directory — skipped)` };
  }

  // Normal path: parent is a dir (or absent). Ensure it, then write.
  try {
    if (!dryRun) {
      ensureDir(parent);
      writeFileSync(filePath, content);
    }
    return { ok: true, action: 'created' };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (err instanceof GuardLinkPathConflictError || code === 'ENOTDIR' || code === 'EISDIR') {
      return { ok: false, skipReason: `${filePath} (path-type conflict; skipped)` };
    }
    throw err;
  }
}

function toPascalCase(s: string): string {
  return s
    .replace(/[-_./]/g, ' ')
    .split(/\s+/)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join('');
}

function buildMdFromScratch(
  project: ProjectInfo,
  model: ThreatModel | null,
  freshness?: ModelContextFreshness,
  mode: ObservedAnnotationMode | null = null,
): string {
  return `# ${toPascalCase(project.name)} — Project Instructions

${wrapMarkers(agentInstructionsWithModel(project, model, freshness, mode))}`;
}

// ─── Sync: regenerate agent files with live threat model ─────────────

export interface SyncOptions {
  root: string;
  model: ThreatModel | null;
  dryRun?: boolean;
}

export interface SyncResult {
  updated: string[];
  skipped: string[];
}

/**
 * Regenerate ALL agent instruction files with live threat model context.
 * Called after parse/validate/annotate to keep instructions up to date.
 * Uses marker-based replacement so user content outside markers is preserved.
 */
export function syncAgentFiles(options: SyncOptions): SyncResult {
  const { root, model, dryRun = false } = options;
  const project = detectProject(root);
  const updated: string[] = [];
  const skipped: string[] = [];

  // Freshness for the synced block: the content hash alone.
  //
  // synced_at and git_sha were here and are gone. These are TRACKED files
  // regenerated on every sync, so a field moving for reasons unrelated to the
  // block’s content turns every regeneration into a diff — measured at a 9-line
  // diff across 7 files per `guardlink validate`. Both still ship in the MCP
  // envelope, computed per call and written nowhere.
  //
  // This does not fix D16. It restores the property that made D16 tolerable:
  // rewriting unchanged content produces no diff.
  const freshness: ModelContextFreshness | undefined = model && model.annotations_parsed > 0
    ? { annotation_hash: computeAnnotationHash(model) }
    : undefined;

  // Regenerate .guardlink/README.md so it cannot drift from what the tooling
  // actually does. Mode comes from config where recorded, and is otherwise
  // observed from the annotations rather than assumed.
  const configuredMode = readConfiguredMode(root);
  const observed = model ? detectAnnotationMode(model) : null;
  const readmeMode = configuredMode
    ?? (observed && observed.inline + observed.external > 0 ? observed.mode : null);
  const readmeModeSource = configuredMode ? 'config' as const
    : readmeMode ? 'observed' as const : 'default' as const;

  // D27: the same resolved mode the README states now also reaches every agent
  // instruction file. They were allowed to disagree, and did — config.json said
  // external while CLAUDE.md said nothing at all.
  const mode = readmeMode;

  const readmePath = join(root, '.guardlink', 'README.md');
  const readme = guardlinkReadmeContent(project, {
    mode: readmeMode,
    modeSource: readmeModeSource,
    model,
    annotationHash: model && model.annotations_parsed > 0 ? computeAnnotationHash(model) : null,
    mcpAtRoot: existsSync(join(root, '.mcp.json')),
    // D45: sync did not write the reference doc, so it observes where it is
    // rather than assuming — the same shape as mcpAtRoot directly above.
    referencePath: existsSync(join(root, REFERENCE_DOC_IN_GUARDLINK))
      ? REFERENCE_DOC_IN_GUARDLINK
      : REFERENCE_DOC_IN_DOCS,
  });
  if (!dryRun) {
    ensureDir(join(root, '.guardlink'));
    writeFileSync(readmePath, readme);
  }
  updated.push('.guardlink/README.md');

  // Ensure .guardlink/prompt.md exists (fallback if init wasn't run)
  const promptPath = join(root, '.guardlink', 'prompt.md');
  if (!existsSync(promptPath)) {
    if (!dryRun) {
      ensureDir(join(root, '.guardlink'));
      writeFileSync(promptPath, promptMdContent(project));
    }
    updated.push('.guardlink/prompt.md');
  }

  for (const choice of AGENT_CHOICES) {
    const filePath = join(root, choice.file);
    const exists = existsSync(filePath);

    if (!exists) {
      // Create fresh with model context. Route through safeWriteAgentFile so a
      // pre-existing path-type conflict skips just this file instead of crashing sync.
      if (choice.file.endsWith('settings.json')) {
        skipped.push(`${choice.file} (json format — not supported)`);
        continue;
      }
      let content: string;
      if (choice.file.endsWith('.mdc')) {
        content = cursorMdcContentWithModel(project, model, freshness, mode);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        content = wrapMarkers(cursorRulesContentWithModel(project, model, freshness, mode));
      } else {
        // Markdown-based: CLAUDE.md, AGENTS.md, copilot-instructions.md, etc.
        content = buildMdFromScratch(project, model, freshness, mode);
      }
      const res = safeWriteAgentFile(filePath, content, dryRun, project, mode);
      if (!res.ok) skipped.push(res.skipReason);
      else updated.push(res.action === 'merged' ? `${choice.file} → merged into existing .cursor/rules` : choice.file);
    } else {
      // Guard: an existing path that is a DIRECTORY would make readFileSync/writeFileSync
      // below throw EISDIR. Skip it with a reason instead of crashing sync.
      if (statSync(filePath).isDirectory()) {
        skipped.push(`${choice.file} (exists as a directory; expected a file — skipped)`);
        continue;
      }
      // File exists — update the GuardLink block (marker-based replacement)
      if (choice.file.endsWith('.mdc')) {
        if (!dryRun) {
          writeFileSync(filePath, cursorMdcContentWithModel(project, model, freshness, mode));
        }
        updated.push(choice.file);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        const existing = readFileSync(filePath, 'utf-8');
        if (!dryRun) {
          const block = wrapMarkers(cursorRulesContentWithModel(project, model, freshness, mode));
          writeFileSync(filePath, replaceOrAppend(existing, block));
        }
        updated.push(choice.file);
      } else if (choice.file.endsWith('settings.json')) {
        skipped.push(`${choice.file} (json format — not supported)`);
      } else {
        const existing = readFileSync(filePath, 'utf-8');
        if (!dryRun) {
          const block = wrapMarkers(agentInstructionsWithModel(project, model, freshness, mode));
          writeFileSync(filePath, replaceOrAppend(existing, block));
        }
        updated.push(choice.file);
      }
    }
  }

  return { updated, skipped };
}
