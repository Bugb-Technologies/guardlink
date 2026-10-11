import { beforeEach, describe, expect, it, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import type * as ChildProcess from 'node:child_process';
import type * as OS from 'node:os';
import { AGENTS } from '../src/agents/index.js';
import { launchAgent, launchAgentForeground } from '../src/agents/launcher.js';
import { buildAnnotatePrompt } from '../src/agents/prompts.js';

vi.mock('node:child_process', async (importOriginal) => ({
  ...await importOriginal<typeof ChildProcess>(),
  spawnSync: vi.fn(),
}));
vi.mock('node:os', async (importOriginal) => ({
  ...await importOriginal<typeof OS>(),
  platform: () => 'darwin',
}));

const spawnMock = vi.mocked(spawnSync);
const cwd = '/nonexistent-guardlink-root';
const terminalAgents = AGENTS.filter(agent => agent.cmd);
const success = { pid: 1, output: [], stdout: null, stderr: null, status: 0, signal: null };

beforeEach(() => {
  spawnMock.mockReset();
  spawnMock.mockReturnValue(success);
});

/**
 * @validates #param-commands for #agent-launcher -- "Foreground prompts remain one exact argv entry, never interpolated into a shell command"
 */
describe('foreground interactive prompt delivery', () => {
  it.each(terminalAgents)('seeds $name with the exact prompt without print mode', (agent) => {
    const prompt = 'Inspect "auth"; $(touch /tmp/not-executed)\nThen annotate chained threats.';
    launchAgentForeground(agent, cwd, prompt);

    expect(spawnMock).toHaveBeenCalledOnce();
    const [cmd, args, options] = spawnMock.mock.calls[0];
    expect(cmd).toBe(agent.cmd);
    expect(args).toEqual(agent.id === 'gemini' ? ['-i', prompt] : [prompt]);
    expect(args).not.toContain('-p');
    expect(args).not.toContain('exec');
    expect(options).toMatchObject({ cwd, stdio: 'inherit' });
    expect(options).not.toHaveProperty('shell');
    expect(options).not.toHaveProperty('timeout');
  });

  it.each(terminalAgents)('hands the full annotate prompt to $name and keeps a clipboard fallback', (agent) => {
    const intent = 'Identify all critical vulnerabilities and threats as chained as possible and annotate them';
    const prompt = buildAnnotatePrompt(intent, cwd, null, 'inline');
    expect(prompt).toContain(intent);

    const result = launchAgent(agent, prompt, cwd);

    expect(spawnMock).toHaveBeenNthCalledWith(1, 'pbcopy', [], expect.objectContaining({ input: prompt }));
    expect(spawnMock).toHaveBeenNthCalledWith(2, agent.cmd, agent.id === 'gemini' ? ['-i', prompt] : [prompt], expect.objectContaining({ cwd, stdio: 'inherit' }));
    expect(result).toEqual({ launched: true, clipboardCopied: true, exitCode: 0 });
  });

  it('still delivers the prompt when the clipboard is unavailable', () => {
    spawnMock.mockReturnValueOnce({ ...success, status: 1 });
    const claude = terminalAgents.find(agent => agent.id === 'claude-code')!;
    const result = launchAgent(claude, 'Annotate auth', cwd);

    expect(spawnMock).toHaveBeenLastCalledWith('claude', ['Annotate auth'], expect.objectContaining({ stdio: 'inherit' }));
    expect(result).toEqual({ launched: true, clipboardCopied: false, exitCode: 0 });
  });
});

describe('launch results', () => {
  it('surfaces a non-zero terminal exit without treating it as a spawn failure', () => {
    spawnMock.mockReturnValueOnce(success).mockReturnValueOnce({ ...success, status: 1 });
    const result = launchAgent(terminalAgents[0], 'Annotate auth', cwd);
    expect(result).toEqual({ launched: true, clipboardCopied: true, exitCode: 1 });
  });

  it('reports a failed spawn while retaining the clipboard fallback', () => {
    spawnMock.mockReturnValueOnce(success).mockReturnValueOnce({
      ...success,
      status: null,
      error: Object.assign(new Error('missing binary'), { code: 'ENOENT' }),
    });
    const result = launchAgent(terminalAgents[0], 'Annotate auth', cwd);
    expect(result).toEqual({
      launched: false,
      clipboardCopied: true,
      exitCode: null,
      error: 'Claude Code (claude) not found. Install it first.',
    });
  });

  it('reports only start semantics for an IDE agent', () => {
    const cursor = AGENTS.find(agent => agent.id === 'cursor')!;
    const result = launchAgent(cursor, 'Annotate auth', cwd);
    expect(spawnMock).toHaveBeenLastCalledWith('open', ['-a', 'Cursor', cwd], expect.any(Object));
    expect(result).toEqual({ launched: true, clipboardCopied: true, error: undefined });
  });
});
