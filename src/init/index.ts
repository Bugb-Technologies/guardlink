/**
 * GuardLink init — Project initialization.
 *
 * Detects project language and existing agent files, creates .guardlink/
 * directory with shared definitions, and injects GuardLink instructions
 * into agent instruction files (CLAUDE.md, .cursorrules, etc.).
 *
 */

import { existsSync, readFileSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
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
  GITIGNORE_ENTRY,
} from './templates.js';
import type { ThreatModel } from '../types/index.js';
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

  // ── 4. Create docs/GUARDLINK_REFERENCE.md ──

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

  // ── 5. Update .gitignore ──

  const gitignorePath = join(root, '.gitignore');
  if (existsSync(gitignorePath)) {
    const content = readFileSync(gitignorePath, 'utf-8');
    if (!content.includes('GuardLink') && !content.includes('.guardlink')) {
      if (!dryRun) appendFileSync(gitignorePath, GITIGNORE_ENTRY);
      updated.push('.gitignore');
    }
  }

  // ── 6. Update/create agent instruction files ──

  if (!skipAgentFiles) {
    const agentResults = updateAgentFiles(root, project, force, dryRun, options.agentIds);
    created.push(...agentResults.created);
    updated.push(...agentResults.updated);
    skipped.push(...agentResults.skipped);
  }

  // ── 7. Create .mcp.json for Claude Code MCP integration ──

  const mcpPath = join(root, '.mcp.json');
  if (!existsSync(mcpPath) || force) {
    if (!dryRun) writeFileSync(mcpPath, mcpConfig());
    created.push('.mcp.json');
  } else {
    skipped.push('.mcp.json (exists)');
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
    } else {
      // File doesn't exist — create fresh
      if (choice.file.endsWith('.mdc')) {
        if (!dryRun) {
          ensureDir(dirname(filePath));
          writeFileSync(filePath, cursorMdcContent(project));
        }
        created.push(choice.file);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        if (!dryRun) {
          writeFileSync(filePath, wrapMarkers(cursorRulesContent(project)));
        }
        created.push(choice.file);
      } else {
        // Markdown-based (CLAUDE.md, AGENTS.md, copilot-instructions.md, .gemini/GEMINI.md)
        if (!dryRun) {
          ensureDir(dirname(filePath));
          writeFileSync(filePath, buildClaudeMdFromScratch(project));
        }
        created.push(choice.file);
      }
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
): 'updated' | 'skipped' {
  const fullPath = join(root, relPath);

  // Special handling for Cursor .mdc files
  if (relPath.endsWith('.mdc')) {
    if (!dryRun) {
      ensureDir(dirname(fullPath));
      writeFileSync(fullPath, cursorMdcContent(project));
    }
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

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
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

  for (const choice of AGENT_CHOICES) {
    const filePath = join(root, choice.file);
    const exists = existsSync(filePath);

    if (!exists) {
      // Create fresh with model context
      if (choice.file.endsWith('.mdc')) {
        if (!dryRun) {
          ensureDir(dirname(filePath));
          writeFileSync(filePath, cursorMdcContentWithModel(project, model));
        }
        updated.push(choice.file);
      } else if (choice.file === '.cursorrules' || choice.file === '.windsurfrules' || choice.file === '.clinerules') {
        if (!dryRun) {
          ensureDir(dirname(filePath));
          writeFileSync(filePath, wrapMarkers(cursorRulesContentWithModel(project, model)));
        }
        updated.push(choice.file);
      } else if (choice.file.endsWith('settings.json')) {
        skipped.push(`${choice.file} (json format — not supported)`);
      } else {
        // Markdown-based: CLAUDE.md, AGENTS.md, copilot-instructions.md, etc.
        if (!dryRun) {
          ensureDir(dirname(filePath));
          writeFileSync(filePath, buildMdFromScratch(project, model));
        }
        updated.push(choice.file);
      }
    } else {
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
