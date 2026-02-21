/**
 * GuardLink Agents — Launch helpers.
 *
 * Two launch patterns:
 *   1. Foreground spawn (CLI + TUI): takes over terminal, returns on exit
 *   2. IDE launch: opens GUI app with project directory
 *
 * Clipboard copy is always performed first regardless of agent type.
 *
 * @exposes #agent-launcher to #child-proc-injection [high] cwe:CWE-78 -- "Spawns child processes for AI coding agents"
 * @exposes #agent-launcher to #cmd-injection [critical] cwe:CWE-78 -- "Windows launch uses shell:true in spawnSync"
 * @mitigates #agent-launcher against #child-proc-injection using #process-sandbox -- "Agent commands are fixed binaries (claude, codex), not user-controlled"
 * @mitigates #agent-launcher against #cmd-injection using #param-commands -- "spawnSync with args array on macOS/Linux, only Windows uses shell"
 * @flows #cli -> #agent-launcher via launchAgent -- "CLI invokes agent with prompt and cwd"
 * @flows #agent-launcher -> External_Process via spawnSync -- "Spawns claude, codex, cursor, etc."
 * @boundary between #agent-launcher and External_AI_Agents (#agent-boundary) -- "Process spawn crosses trust boundary to external AI tools"
 * @comment -- "copyToClipboard uses platform-specific clipboard commands (pbcopy, xclip, clip)"
 */

import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';
import type { AgentEntry } from './index.js';

// ─── Clipboard ───────────────────────────────────────────────────────

/** Copy text to system clipboard. Returns true on success. */
export function copyToClipboard(text: string): boolean {
  const cmds = platform() === 'darwin'
    ? ['pbcopy']
    : platform() === 'win32'
      ? ['clip']
      : ['xclip -selection clipboard', 'xsel --clipboard --input'];

  for (const cmd of cmds) {
    const [bin, ...args] = cmd.split(' ');
    try {
      const result = spawnSync(bin, args, {
        input: text,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 5000,
      });
      if (result.status === 0) return true;
    } catch { continue; }
  }
  return false;
}

// ─── Foreground spawn (CLI terminal agents) ──────────────────────────

/**
 * Launch a CLI agent in the foreground — takes over the current terminal.
 * The agent gets full stdin/stdout/stderr (stdio: 'inherit').
 * Returns when the agent exits. Works cross-platform.
 *
 * This is the `git commit` / `$EDITOR` pattern.
 */
export function launchAgentForeground(agent: AgentEntry, cwd: string): {
  exitCode: number | null;
  error?: string;
} {
  if (!agent.cmd) {
    return { exitCode: null, error: `${agent.name} is not a terminal agent` };
  }

  try {
    const result = spawnSync(agent.cmd, [], {
      cwd,
      stdio: 'inherit',
      env: { ...process.env },
      // No timeout — user controls session duration
    });

    if (result.error) {
      // Binary not found or spawn failed
      const msg = (result.error as any).code === 'ENOENT'
        ? `${agent.name} (${agent.cmd}) not found. Install it first.`
        : `Failed to launch ${agent.name}: ${result.error.message}`;
      return { exitCode: null, error: msg };
    }

    return { exitCode: result.status };
  } catch (err: any) {
    return { exitCode: null, error: `Failed to launch ${agent.name}: ${err.message}` };
  }
}

// ─── IDE app launch ──────────────────────────────────────────────────

/**
 * Open an IDE/GUI agent with the project directory.
 * Uses `open -a` (macOS), `xdg-open` (Linux), or `start` (Windows).
 */
export function launchAgentIDE(agent: AgentEntry, cwd: string): {
  success: boolean;
  error?: string;
} {
  if (!agent.app) {
    return { success: false, error: `${agent.name} is not an IDE agent` };
  }

  try {
    const os = platform();
    let result;

    if (os === 'darwin') {
      result = spawnSync('open', ['-a', agent.app, cwd], {
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 10000,
      });
    } else if (os === 'win32') {
      result = spawnSync('start', ['', agent.app], {
        cwd,
        shell: true,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 10000,
      });
    } else {
      // Linux — try xdg-open or direct binary
      result = spawnSync('xdg-open', [cwd], {
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 10000,
      });
    }

    if (result.error || (result.status !== null && result.status !== 0)) {
      return {
        success: false,
        error: `Could not open ${agent.name} automatically. Open it manually and navigate to: ${cwd}`,
      };
    }

    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Unified agent launch ────────────────────────────────────────────

export interface LaunchResult {
  launched: boolean;
  clipboardCopied: boolean;
  error?: string;
}

/**
 * Launch an agent with a prompt. Always copies to clipboard first.
 *
 * For terminal agents (claude, codex, gemini): foreground spawn.
 * For IDE agents (cursor, windsurf): open app.
 * For clipboard: copy only.
 */
export function launchAgent(agent: AgentEntry, prompt: string, cwd: string): LaunchResult {
  // Step 1: Always copy to clipboard
  const clipboardCopied = copyToClipboard(prompt);

  // Step 2: clipboard-only mode
  if (agent.id === 'clipboard') {
    return { launched: true, clipboardCopied };
  }

  // Step 3: Terminal agent — foreground spawn
  if (agent.cmd) {
    const { exitCode, error } = launchAgentForeground(agent, cwd);
    if (error) {
      return { launched: false, clipboardCopied, error };
    }
    return { launched: true, clipboardCopied };
  }

  // Step 4: IDE agent — open app
  if (agent.app) {
    const { success, error } = launchAgentIDE(agent, cwd);
    return { launched: success, clipboardCopied, error };
  }

  return { launched: false, clipboardCopied, error: `Unknown agent type: ${agent.id}` };
}
