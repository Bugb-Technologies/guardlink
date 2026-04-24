/**
 * GuardLink Agents — Shared agent registry.
 *
 * Used by CLI, TUI, and MCP to identify and resolve coding agents
 * (Claude Code, Codex, Cursor, Windsurf, Gemini, clipboard).
 *
 * @comment -- "Agent binaries are hardcoded; no user-controlled binary names"
 * @comment -- "parseAgentFlag extracts flags from args; no injection risk"
 */

// ─── Agent registry ──────────────────────────────────────────────────

export interface AgentEntry {
  id: string;
  name: string;
  cmd: string | null;     // CLI binary (runs in terminal)
  app: string | null;     // GUI app name (opens with `open -a`)
  flag: string;           // CLI flag (--claude-code, --cursor, etc.)
}

export type AnnotationMode = 'inline' | 'external';

export const AGENTS: readonly AgentEntry[] = [
  { id: 'claude-code', name: 'Claude Code', cmd: 'claude',  app: null,       flag: '--claude-code' },
  { id: 'cursor',      name: 'Cursor',      cmd: null,      app: 'Cursor',   flag: '--cursor' },
  { id: 'windsurf',    name: 'Windsurf',    cmd: null,      app: 'Windsurf', flag: '--windsurf' },
  { id: 'codex',       name: 'Codex CLI',   cmd: 'codex',   app: null,       flag: '--codex' },
  { id: 'gemini',      name: 'Gemini CLI',  cmd: 'gemini',  app: null,       flag: '--gemini' },
  { id: 'clipboard',   name: 'Clipboard',   cmd: null,      app: null,       flag: '--clipboard' },
  { id: 'stdout',      name: 'Stdout',      cmd: null,      app: null,       flag: '--stdout' },
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

/** Parse annotation placement mode from raw args (CLI/TUI). */
export function parseAnnotationModeFlag(args: string): { mode: AnnotationMode; cleanArgs: string; error?: string } {
  const eqMatch = args.match(/(?:^|\s)--mode=(inline|external)(?=\s|$)/);
  if (eqMatch) {
    return {
      mode: eqMatch[1] as AnnotationMode,
      cleanArgs: args.replace(eqMatch[0], ' ').replace(/\s+/g, ' ').trim(),
    };
  }

  const spacedMatch = args.match(/(?:^|\s)--mode\s+(inline|external)(?=\s|$)/);
  if (spacedMatch) {
    return {
      mode: spacedMatch[1] as AnnotationMode,
      cleanArgs: args.replace(spacedMatch[0], ' ').replace(/\s+/g, ' ').trim(),
    };
  }

  if (/(?:^|\s)--mode(?:\s|=|$)/.test(args)) {
    return {
      mode: 'inline',
      cleanArgs: args,
      error: 'Invalid --mode value. Use --mode inline or --mode external.',
    };
  }

  return { mode: 'inline', cleanArgs: args };
}

export function resolveAnnotationMode(mode: string | undefined): AnnotationMode {
  if (!mode || mode === 'inline') return 'inline';
  if (mode === 'external') return 'external';
  throw new Error(`Invalid annotation mode "${mode}". Use "inline" or "external".`);
}

/** Resolve agent from Commander option booleans (CLI commands). */
export function agentFromOpts(opts: Record<string, any>): AgentEntry | null {
  if (opts.claudeCode) return AGENTS.find(a => a.id === 'claude-code')!;
  if (opts.cursor)     return AGENTS.find(a => a.id === 'cursor')!;
  if (opts.windsurf)   return AGENTS.find(a => a.id === 'windsurf')!;
  if (opts.codex)      return AGENTS.find(a => a.id === 'codex')!;
  if (opts.gemini)     return AGENTS.find(a => a.id === 'gemini')!;
  if (opts.clipboard)  return AGENTS.find(a => a.id === 'clipboard')!;
  if (opts.stdout)     return AGENTS.find(a => a.id === 'stdout')!;
  return null;
}

export { launchAgentForeground, launchAgentIDE, launchAgent, launchAgentInline, copyToClipboard } from './launcher.js';
export type { InlineResult } from './launcher.js';
export { buildAnnotatePrompt } from './prompts.js';
