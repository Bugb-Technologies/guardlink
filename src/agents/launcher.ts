/**
 * GuardLink Agents — Launch helpers.
 *
 * Two launch patterns:
 *   1. Foreground spawn (CLI + TUI): takes over terminal, returns on exit
 *   2. IDE launch: opens GUI app with project directory
 *
 * Clipboard copy is always performed first regardless of agent type.
 *
 * @exposes #agent-launcher to #child-proc-injection [critical] cwe:CWE-78 -- "[internal] spawn/spawnSync execute external binaries; local dev triggers annotate/threat-report commands"
 * @mitigates #agent-launcher against #child-proc-injection using #param-commands -- "Binary names from hardcoded AGENTS registry; no shell interpolation"
 * @mitigates #agent-launcher against #cmd-injection using #param-commands -- "Arguments passed as array, not shell string"
 * @exposes #agent-launcher to #prompt-injection [medium] cwe:CWE-77 -- "[internal] User prompt passed to agent CLI as argument; local dev types the prompt"
 * @audit #agent-launcher -- "Prompt content is opaque to agent binary; injection risk depends on agent implementation"
 * @exposes #agent-launcher to #dos [low] cwe:CWE-400 -- "[internal] No timeout on foreground spawn; agent controls duration; local dev can Ctrl+C"
 * @comment -- "Timeout intentionally omitted for interactive sessions; inline mode has implicit control"
 * @flows UserPrompt -> #agent-launcher via launchAgent -- "Prompt input path"
 * @flows #agent-launcher -> AgentProcess via spawn -- "Process spawn path"
 * @flows AgentProcess -> #agent-launcher via stdout -- "Agent output capture"
 * @boundary #agent-launcher and AgentProcess (#agent-boundary) -- "Trust boundary at process spawn"
 */

import { spawnSync, spawn } from 'node:child_process';
import { platform } from 'node:os';
import { mkdtempSync, readFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
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

// ─── Inline (non-interactive) agent execution ────────────────────────

export interface InlineResult {
  content: string;
  error?: string;
}

/**
 * CLI agent command + args for non-interactive (print) mode.
 * claude: `claude -p "<prompt>" --dangerously-skip-permissions ...`
 * codex:  `codex exec "<prompt>" --dangerously-bypass-approvals-and-sandbox --color never -o <tmpfile>`
 * gemini: `gemini --prompt "<prompt>" --approval-mode yolo`
 *
 * For codex, we use `-o <tmpfile>` to capture the final agent message to a file,
 * which avoids any TTY/streaming issues. The tmpfile path is passed separately.
 *
 * @exposes #agent-launcher to #prompt-injection [critical] cwe:CWE-77 -- "[mixed] Agents launched with permission bypass flags (--dangerously-skip-permissions, --dangerously-bypass-approvals, --approval-mode yolo); prompt constructed from threat model which includes PR-contributed annotations — injected content could direct agent to write malicious files"
 * @accepts #prompt-injection on #agent-launcher -- "Accepted: permission bypass flags are required for non-interactive inline mode; the prompt is constructed internally by GuardLink (not arbitrary user input), and claude-code is restricted via --allowedTools to read-only operations"
 * @audit #agent-launcher -- "Permission bypass flags eliminate agent safety guardrails; combined with prompt injection, this creates a code-execution path from annotation input — e.g. user prompt controls what an unconstrained codex/gemini agent writes to disk"
 * @comment -- "Partial mitigation for claude-code: --allowedTools restricts to Read and Bash(cat/find/head/tail) — limits write surface; codex and gemini have no tool restrictions in inline mode"
 * @flows InjectedPrompt -> #agent-launcher via buildInlineArgs -- "User-controlled prompt reaches agent binary that has safety guardrails disabled"
 */
function buildInlineArgs(agentId: string, prompt: string, codexOutputFile?: string): string[] | null {
  switch (agentId) {
    case 'claude-code':
      return [
        '-p', prompt,
        '--dangerously-skip-permissions',
        '--allowedTools', 'Read,Bash(cat *),Bash(find *),Bash(head *),Bash(tail *)',
        // stream-json emits one complete JSON object per line per turn, so we can
        // collect text from every assistant turn — not just the final message.
        // --verbose is required by Claude Code when using stream-json with -p.
        '--output-format', 'stream-json',
        '--verbose',
      ];
    case 'codex':
      // `codex exec` runs non-interactively (no TTY needed).
      // --color never: suppress ANSI escape codes in output.
      // -o <file>: write the final agent message to a file for clean extraction.
      // --skip-git-repo-check: allow running outside a git repo.
      return [
        'exec', prompt,
        '--dangerously-bypass-approvals-and-sandbox',
        '--color', 'never',
        '--skip-git-repo-check',
        ...(codexOutputFile ? ['-o', codexOutputFile] : []),
      ];
    case 'gemini':
      return [
        '--prompt', prompt,
        '--approval-mode', 'yolo',
      ];
    default:
      return null;
  }
}

/**
 * Extract text content from a single Claude Code stream-json event line.
 * Claude Code's --output-format stream-json emits one complete JSON object
 * per line per turn. Assistant turns have the shape:
 *   {"type":"assistant","message":{"content":[{"type":"text","text":"..."}],...}}
 * We collect text blocks from every assistant turn so the full multi-turn
 * report is captured, not just the final message.
 *
 * @comment -- "Pure JSON parser; no I/O or security boundary"
 */
function extractClaudeStreamText(line: string): string {
  if (!line.trim()) return '';
  try {
    const event = JSON.parse(line) as Record<string, unknown>;
    const msg = event.message as Record<string, unknown> | undefined;
    if (event.type === 'assistant' && Array.isArray(msg?.content)) {
      return (msg.content as Array<Record<string, unknown>>)
        .filter((b) => b.type === 'text' && typeof b.text === 'string')
        .map((b) => b.text as string)
        .join('');
    }
  } catch { /* not JSON or unrecognised event — skip */ }
  return '';
}

/**
 * Run a CLI agent inline (non-interactive) and stream output.
 *
 * Instead of taking over the terminal, this spawns the agent with
 * a print-mode flag and streams stdout back via onChunk.
 * Returns the full collected output when done.
 */
export async function launchAgentInline(
  agent: AgentEntry,
  prompt: string,
  cwd: string,
  onChunk?: (text: string) => void,
  opts?: { autoYes?: boolean }
): Promise<InlineResult> {
  if (!agent.cmd) {
    return { content: '', error: `${agent.name} is not a terminal agent — cannot run inline` };
  }

  let cmd = agent.cmd;
  let args = buildInlineArgs(agent.id, prompt);
  if (!args) {
    return { content: '', error: `Inline mode not supported for ${agent.name}` };
  }

  return new Promise<InlineResult>((resolve) => {
    try {
      // For Codex: use `codex exec` which is designed for non-interactive/headless use.
      // It does NOT require a TTY for stdin or stdout.
      // We use -o <tmpfile> so the final agent message is written to a file we can read
      // back cleanly, avoiding any streaming/buffering issues with the live output.
      let codexOutputFile: string | undefined;
      if (agent.id === 'codex') {
        const tmpDir = mkdtempSync(join(tmpdir(), 'guardlink-codex-'));
        codexOutputFile = join(tmpDir, 'output.md');
      }

      args = buildInlineArgs(agent.id, prompt, codexOutputFile) as string[];

      // Claude Code and Gemini still need stdin to be a real TTY (they check isatty(stdin)).
      // Codex exec does not — it reads the prompt from the CLI arg, not stdin.
      const stdinMode = agent.id === 'codex' ? 'pipe' : 'inherit';

      const child = spawn(cmd, args, {
        cwd,
        stdio: [stdinMode, 'pipe', 'pipe'],
        env: { ...process.env, NO_COLOR: '1' },
      });

      // For codex, close stdin immediately so it knows there's no interactive input.
      if (agent.id === 'codex') {
        child.stdin?.end();
      }

      let content = '';
      let stderr = '';
      // Buffer for incomplete lines when parsing claude-code stream-json output.
      let jsonLineBuffer = '';

      child.stdout?.on('data', (data: Buffer) => {
        if (agent.id === 'claude-code') {
          // stream-json: parse newline-delimited JSON events and extract assistant text.
          // This captures every turn's text, not just the final message.
          jsonLineBuffer += data.toString();
          const lines = jsonLineBuffer.split('\n');
          jsonLineBuffer = lines.pop() ?? '';
          for (const line of lines) {
            const text = extractClaudeStreamText(line);
            if (text) {
              content += text;
              if (onChunk) onChunk(text);
            }
          }
        } else {
          const text = data.toString();
          content += text;
          if (onChunk) onChunk(text);
        }
      });

      child.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      child.on('error', (err: Error) => {
        const msg = (err as any).code === 'ENOENT'
          ? `${agent.name} (${agent.cmd}) not found. Install it first.`
          : `Failed to launch ${agent.name}: ${err.message}`;
        resolve({ content, error: msg });
      });

      child.on('close', (code: number | null) => {
        // Flush any incomplete JSON line left in the buffer (claude-code stream-json).
        if (agent.id === 'claude-code' && jsonLineBuffer.trim()) {
          const text = extractClaudeStreamText(jsonLineBuffer);
          if (text) content += text;
        }

        // For codex, prefer the -o output file (final agent message) over streamed stdout.
        if (codexOutputFile && existsSync(codexOutputFile)) {
          try {
            const fileContent = readFileSync(codexOutputFile, 'utf-8').trim();
            unlinkSync(codexOutputFile);
            if (fileContent) {
              resolve({ content: fileContent });
              return;
            }
          } catch { /* fall through to stdout content */ }
        }

        if (code !== 0 && code !== null && !content) {
          resolve({ content, error: `${agent.name} exited with code ${code}${stderr ? ': ' + stderr.slice(0, 200) : ''}` });
        } else {
          resolve({ content });
        }
      });
    } catch (err: any) {
      resolve({ content: '', error: `Failed to launch ${agent.name}: ${err.message}` });
    }
  });
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
