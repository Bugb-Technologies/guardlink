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
import { detectProject, type ProjectInfo, type AgentFile } from './detect.js';
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
  GITIGNORE_ENTRY,
} from './templates.js';
import type { ThreatModel } from '../types/index.js';
import type { AnnotationMode } from '../agents/index.js';
import { AGENT_CHOICES } from './picker.js';

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
  /** Force overwrite even if already initialized */
  force?: boolean;
  /** Dry run — show what would be created without writing */
  dryRun?: boolean;
  /** Explicit agent IDs to create files for (when no existing agent files found) */
  agentIds?: string[];
  /**
   * Annotation placement mode.
   * external: restrict all writes to .guardlink/ — no agent files, no .mcp.json at root, no docs/.
   * inline: default behavior, writes all files including agent instruction files.
   */
  mode?: AnnotationMode;
}

export interface InitResult {
  project: ProjectInfo;
  created: string[];
  updated: string[];
  skipped: string[];
}

// ─── Marker for detecting our content ────────────────────────────────

const GUARDLINK_MARKER = '<!-- guardlink:begin -->';
const GUARDLINK_MARKER_END = '<!-- guardlink:end -->';

// ─── Main init function ──────────────────────────────────────────────

export function initProject(options: InitOptions): InitResult {
  const { root, force = false, dryRun = false, skipAgentFiles = false } = options;
  const isExternal = options.mode === 'external';

  const project = detectProject(root);
  if (options.project) project.name = options.project;

  const created: string[] = [];
  const updated: string[] = [];
  const skipped: string[] = [];

  // ── 1. Create .guardlink/ directory ──

  const tsDir = join(root, '.guardlink');
  if (!existsSync(tsDir)) {
    if (!dryRun) mkdirSync(tsDir, { recursive: true });
    created.push('.guardlink/');
  }

  // ── 2. Create config.json ──

  const configPath = join(tsDir, 'config.json');
  if (!existsSync(configPath) || force) {
    if (!dryRun) writeFileSync(configPath, configContent(project));
    created.push('.guardlink/config.json');
  } else {
    skipped.push('.guardlink/config.json (exists)');
  }

  // ── 3. Create definitions file ──

  const defsFile = `definitions${project.definitionsExt}`;
  const defsPath = join(tsDir, defsFile);
  if (!existsSync(defsPath) || force) {
    if (!dryRun) writeFileSync(defsPath, definitionsContent(project));
    created.push(`.guardlink/${defsFile}`);
  } else {
    skipped.push(`.guardlink/${defsFile} (exists)`);
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
  // external mode: inside .guardlink/ (zero footprint outside it)
  // inline mode: docs/GUARDLINK_REFERENCE.md (visible to humans browsing the project)

  if (isExternal) {
    const refDocPath = join(tsDir, 'GUARDLINK_REFERENCE.md');
    if (!existsSync(refDocPath) || force) {
      if (!dryRun) writeFileSync(refDocPath, referenceDocContent(project));
      created.push('.guardlink/GUARDLINK_REFERENCE.md');
    } else {
      skipped.push('.guardlink/GUARDLINK_REFERENCE.md (exists)');
    }
  } else {
    const docsDir = join(root, 'docs');
    const refDocPath = join(docsDir, 'GUARDLINK_REFERENCE.md');
    if (!existsSync(refDocPath) || force) {
      if (!dryRun) {
        ensureDir(docsDir);
        writeFileSync(refDocPath, referenceDocContent(project));
      }
      created.push('docs/GUARDLINK_REFERENCE.md');
    } else {
      skipped.push('docs/GUARDLINK_REFERENCE.md (exists)');
    }
  }

  // ── 6. Update .gitignore ──
  // Skipped in external mode: .guardlink/ is intentionally committed as a whole.

  if (!isExternal) {
    const gitignorePath = join(root, '.gitignore');
    if (existsSync(gitignorePath)) {
      const content = readFileSync(gitignorePath, 'utf-8');
      if (!content.includes('GuardLink') && !content.includes('.guardlink')) {
        if (!dryRun) appendFileSync(gitignorePath, GITIGNORE_ENTRY);
        updated.push('.gitignore');
      }
    }
  }

  // ── 7. Update/create agent instruction files ──
  // Skipped in external mode: all writes are contained in .guardlink/.

  if (!skipAgentFiles && !isExternal) {
    const agentResults = updateAgentFiles(root, project, force, dryRun, options.agentIds);
    created.push(...agentResults.created);
    updated.push(...agentResults.updated);
    skipped.push(...agentResults.skipped);
  }

  // ── 8. Create .mcp.json for Claude Code MCP integration ──
  // external mode: placed inside .guardlink/ as a reference template (won't be auto-discovered
  //   by MCP clients, but documents the config for devs who want to enable it locally).
  // inline mode: .mcp.json at project root for auto-discovery by Claude Code and other MCP clients.

  if (isExternal) {
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

  return { project, created, updated, skipped };
}

// ─── Agent file update logic ─────────────────────────────────────────

function updateAgentFiles(
  root: string,
  project: ProjectInfo,
  force: boolean,
  dryRun: boolean,
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
      const result = injectIntoAgentFile(root, choice.file, project, force, dryRun);
      if (result === 'updated') updated.push(choice.file);
      else if (result === 'skipped') skipped.push(choice.file);
      else skipped.push(result.skippedReason);
    } else {
      // File doesn't exist — create fresh. Route through safeWriteAgentFile so a
      // pre-existing path-type conflict (e.g. a `.cursor/rules` FILE where we need a
      // directory) skips just this agent file with a warning instead of crashing init.
      let content: string;
      if (choice.file.endsWith('.mdc')) {
        content = cursorMdcContent(project);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        content = wrapMarkers(cursorRulesContent(project));
      } else {
        // Markdown-based (CLAUDE.md, AGENTS.md, copilot-instructions.md, .gemini/GEMINI.md)
        content = buildClaudeMdFromScratch(project);
      }
      const skipReason = safeWriteAgentFile(filePath, content, dryRun);
      if (skipReason) skipped.push(skipReason);
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
): 'updated' | 'skipped' | { skippedReason: string } {
  const fullPath = join(root, relPath);

  // Guard: if the target path exists as a DIRECTORY, every branch below that does
  // readFileSync/writeFileSync would throw EISDIR. Skip this agent file with a reason.
  if (existsSync(fullPath) && statSync(fullPath).isDirectory()) {
    return { skippedReason: `${relPath} (exists as a directory; expected a file — skipped)` };
  }

  // Special handling for Cursor .mdc files
  if (relPath.endsWith('.mdc')) {
    const skipReason = safeWriteAgentFile(fullPath, cursorMdcContent(project), dryRun);
    if (skipReason) return { skippedReason: skipReason };
    return 'updated';
  }

  // Special handling for .cursorrules / .windsurfrules / .clinerules (no markdown headers)
  if (relPath === '.cursorrules' || relPath === '.windsurfrules' || relPath === '.clinerules') {
    const existing = readFileSync(fullPath, 'utf-8');
    if (existing.includes('GuardLink') && !force) return 'skipped';

    if (!dryRun) {
      const block = wrapMarkers(cursorRulesContent(project));
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
    const block = wrapMarkers(agentInstructions(project));
    const newContent = replaceOrAppend(existing, block);
    writeFileSync(fullPath, newContent);
  }
  return 'updated';
}

function buildClaudeMdFromScratch(project: ProjectInfo): string {
  return buildMdFromScratch(project, null);
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
    // Replace existing block
    return existing.slice(0, beginIdx) + block + existing.slice(endIdx + GUARDLINK_MARKER_END.length);
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
 * Write a file, but first verify the target path is not already a DIRECTORY (which would
 * make writeFileSync throw EISDIR) and that its parent can hold it. Returns a skip reason
 * string if a path conflict prevents the write, or null on success. Never throws for the
 * conflict case — callers use the reason to skip-and-warn and keep going.
 */
function safeWriteAgentFile(filePath: string, content: string, dryRun: boolean): string | null {
  // Mirror case: the target path itself is a directory where we need to write a file.
  if (existsSync(filePath) && statSync(filePath).isDirectory()) {
    return `${filePath} (exists as a directory; expected a file — skipped)`;
  }
  try {
    if (!dryRun) {
      ensureDir(dirname(filePath));
      writeFileSync(filePath, content);
    }
    return null;
  } catch (err) {
    if (err instanceof GuardLinkPathConflictError) {
      return `${err.conflictPath} (${err.expected === 'directory' ? 'exists as a file' : 'exists as a directory'}; skipped)`;
    }
    // Also catch the raw node errors defensively, in case a parent segment collides.
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOTDIR' || code === 'EISDIR') {
      return `${filePath} (path-type conflict: ${code}; skipped)`;
    }
    throw err; // genuinely unexpected — let it surface
  }
}

function toPascalCase(s: string): string {
  return s
    .replace(/[-_./]/g, ' ')
    .split(/\s+/)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join('');
}

function buildMdFromScratch(project: ProjectInfo, model: ThreatModel | null): string {
  return `# ${toPascalCase(project.name)} — Project Instructions

${wrapMarkers(agentInstructionsWithModel(project, model))}`;
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
        content = cursorMdcContentWithModel(project, model);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        content = wrapMarkers(cursorRulesContentWithModel(project, model));
      } else {
        // Markdown-based: CLAUDE.md, AGENTS.md, copilot-instructions.md, etc.
        content = buildMdFromScratch(project, model);
      }
      const skipReason = safeWriteAgentFile(filePath, content, dryRun);
      if (skipReason) skipped.push(skipReason);
      else updated.push(choice.file);
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
          writeFileSync(filePath, cursorMdcContentWithModel(project, model));
        }
        updated.push(choice.file);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        const existing = readFileSync(filePath, 'utf-8');
        if (!dryRun) {
          const block = wrapMarkers(cursorRulesContentWithModel(project, model));
          writeFileSync(filePath, replaceOrAppend(existing, block));
        }
        updated.push(choice.file);
      } else if (choice.file.endsWith('settings.json')) {
        skipped.push(`${choice.file} (json format — not supported)`);
      } else {
        const existing = readFileSync(filePath, 'utf-8');
        if (!dryRun) {
          const block = wrapMarkers(agentInstructionsWithModel(project, model));
          writeFileSync(filePath, replaceOrAppend(existing, block));
        }
        updated.push(choice.file);
      }
    }
  }

  return { updated, skipped };
}
