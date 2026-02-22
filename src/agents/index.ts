/**
 * GuardLink Agents — Shared agent registry.
 *
 * Used by CLI, TUI, and MCP to identify and resolve coding agents
 * (Claude Code, Codex, Cursor, Windsurf, Gemini, clipboard).
 */

// ─── Agent registry ──────────────────────────────────────────────────

export interface AgentEntry {
  id: string;
  name: string;
  cmd: string | null;     // CLI binary (runs in terminal)
  app: string | null;     // GUI app name (opens with `open -a`)
  flag: string;           // CLI flag (--claude-code, --cursor, etc.)
}

export const AGENTS: readonly AgentEntry[] = [
  { id: 'claude-code', name: 'Claude Code', cmd: 'claude',  app: null,       flag: '--claude-code' },
  { id: 'cursor',      name: 'Cursor',      cmd: null,      app: 'Cursor',   flag: '--cursor' },
  { id: 'windsurf',    name: 'Windsurf',    cmd: null,      app: 'Windsurf', flag: '--windsurf' },
  { id: 'codex',       name: 'Codex CLI',   cmd: 'codex',   app: null,       flag: '--codex' },
  { id: 'gemini',      name: 'Gemini CLI',  cmd: 'gemini',  app: null,       flag: '--gemini' },
  { id: 'clipboard',   name: 'Clipboard',   cmd: null,      app: null,       flag: '--clipboard' },
] as const;

/** Parse --agent flags from a raw args string (TUI slash commands). */
export function parseAgentFlag(args: string): { agent: AgentEntry | null; cleanArgs: string } {
  for (const a of AGENTS) {
    if (args.includes(a.flag)) {
      return { agent: a, cleanArgs: args.replace(a.flag, '').trim() };
    }
  }
  return { agent: null, cleanArgs: args };
}

/** Resolve agent from Commander option booleans (CLI commands). */
export function agentFromOpts(opts: Record<string, any>): AgentEntry | null {
  if (opts.claudeCode) return AGENTS.find(a => a.id === 'claude-code')!;
  if (opts.cursor)     return AGENTS.find(a => a.id === 'cursor')!;
  if (opts.windsurf)   return AGENTS.find(a => a.id === 'windsurf')!;
  if (opts.codex)      return AGENTS.find(a => a.id === 'codex')!;
  if (opts.gemini)     return AGENTS.find(a => a.id === 'gemini')!;
  if (opts.clipboard)  return AGENTS.find(a => a.id === 'clipboard')!;
  return null;
}

export { launchAgentForeground, launchAgentIDE, launchAgent, launchAgentInline, copyToClipboard } from './launcher.js';
export type { InlineResult } from './launcher.js';
export { buildAnnotatePrompt } from './prompts.js';
