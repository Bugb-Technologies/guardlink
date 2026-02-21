/**
 * GuardLink init — Interactive agent picker.
 *
 * Shows a detection-aware prompt:
 *   - Always-created files (reference doc, AGENTS.md, .mcp.json)
 *   - Auto-detected agents (directories found on disk)
 *   - Optional agents the user can additionally select
 */

import { createInterface } from 'node:readline';
import type { AgentFile } from './detect.js';
import { getDetectedPlatforms } from './detect.js';

export interface AgentChoice {
  id: string;
  label: string;
  file: string;
  platform: string;
}

export const AGENT_CHOICES: AgentChoice[] = [
  { id: 'claude',    label: 'Claude Code',    file: 'CLAUDE.md',                         platform: 'claude' },
  { id: 'cursor',    label: 'Cursor',         file: '.cursor/rules/guardlink.mdc',       platform: 'cursor' },
  { id: 'codex',     label: 'Codex',          file: 'AGENTS.md',                          platform: 'codex' },
  { id: 'copilot',   label: 'GitHub Copilot', file: '.github/copilot-instructions.md',    platform: 'copilot' },
  { id: 'windsurf',  label: 'Windsurf',       file: '.windsurfrules',                     platform: 'windsurf' },
  { id: 'cline',     label: 'Cline',          file: '.clinerules',                        platform: 'cline' },
  { id: 'gemini',    label: 'Gemini',         file: '.gemini/GEMINI.md',                  platform: 'gemini' },
];

/** Files that are always created regardless of agent selection. */
export const ALWAYS_FILES = [
  'docs/GUARDLINK_REFERENCE.md',
  '.mcp.json',
];

/**
 * Show detection-aware prompt. Displays:
 *   1. Always-created files
 *   2. Auto-detected agents (from directory presence)
 *   3. Optional agents user can add
 *
 * Returns combined list of agent IDs (detected + user-selected).
 */
export async function promptAgentSelection(agentFiles: AgentFile[]): Promise<string[]> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const ask = (q: string): Promise<string> =>
    new Promise(resolve => rl.question(q, resolve));

  const detected = getDetectedPlatforms(agentFiles);

  // Partition choices into detected vs optional
  const detectedChoices: Array<AgentChoice & { reason: string }> = [];
  const optionalChoices: AgentChoice[] = [];

  for (const choice of AGENT_CHOICES) {
    const reason = detected.get(choice.platform);
    if (reason) {
      detectedChoices.push({ ...choice, reason });
    } else {
      optionalChoices.push(choice);
    }
  }

  // ── Display ──

  console.error('\n  GuardLink will create:\n');

  // Always files
  console.error('  Always:');
  for (const f of ALWAYS_FILES) {
    console.error(`    ✓  ${f}`);
  }

  // Detected agents
  if (detectedChoices.length > 0) {
    console.error('\n  Auto-detected:');
    for (const c of detectedChoices) {
      console.error(`    ✓  ${c.file.padEnd(38)} (${c.reason})`);
    }
  }

  // Optional agents
  if (optionalChoices.length > 0) {
    console.error('\n  Also add instructions for? (comma-separated numbers, Enter to skip)\n');
    for (let i = 0; i < optionalChoices.length; i++) {
      const c = optionalChoices[i];
      console.error(`    ${i + 1}. ${c.label.padEnd(18)} → ${c.file}`);
    }
    console.error('');
  }

  // Collect selection
  const detectedIds = detectedChoices.map(c => c.id);

  if (optionalChoices.length === 0) {
    // Nothing to ask — all agents detected
    console.error('  All known agents detected. No additional selection needed.\n');
    rl.close();
    return detectedIds;
  }

  const answer = await ask('  Selection [Enter to skip]: ');
  rl.close();

  const selectedIds = [...detectedIds];

  if (answer.trim()) {
    const nums = answer.split(/[,\s]+/).map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    for (const n of nums) {
      if (n >= 1 && n <= optionalChoices.length) {
        selectedIds.push(optionalChoices[n - 1].id);
      }
    }
  }

  // Always include claude if nothing was detected or selected
  if (selectedIds.length === 0) {
    selectedIds.push('claude');
  }

  return selectedIds;
}

/**
 * Resolve agent IDs (from picker or flags) to file paths.
 */
export function resolveAgentFiles(agentIds: string[]): AgentChoice[] {
  return agentIds
    .map(id => AGENT_CHOICES.find(c => c.id === id))
    .filter((c): c is AgentChoice => c !== undefined);
}
