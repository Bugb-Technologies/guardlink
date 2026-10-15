import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { parseProject, withReachAnalysis } from '../src/parser/index.js';
async function read(files: Record<string,string>) {
  const root = mkdtempSync(join(tmpdir(), 'agent-extended-'));
  try {
    for (const [file,text] of Object.entries(files)) { mkdirSync(dirname(join(root,file)),{recursive:true}); writeFileSync(join(root,file),text); }
    return withReachAnalysis((await parseProject({root})).model);
  } finally { rmSync(root,{recursive:true,force:true}); }
}
describe('documented additional harness formats', () => {
  it('reads project MCP maps and preserves per-tool approval boundaries', async () => {
    const m = await read({
      '.roo/mcp.json': JSON.stringify({mcpServers:{sample:{command:'node',args:['server.js'],alwaysAllow:['read']}}}),
      '.cline/mcp.json': JSON.stringify({mcpServers:{sample:{command:'node',args:['server.js']}}}),
      '.kiro/settings/mcp.json': JSON.stringify({mcpServers:{sample:{command:'node',args:['server.js'],autoApprove:['read']}}}),
      '.zed/settings.json': JSON.stringify({context_servers:{sample:{command:'node',args:['server.js']}},agent:{tool_permissions:{tools:{terminal:{default:'allow',always_deny:[{pattern:'rm'}]}}}}}),
      'opencode.jsonc': '{"mcp":{"sample":{"type":"local","command":["node","server.js"],"enabled":false}},"permission":{"bash":{"*":"ask","git *":"allow"}}}',
    });
    expect(m.agent_config?.mcp_servers.map(s=>s.harness).sort()).toEqual(['kiro','opencode','roo','zed']);
    expect(m.agent_config?.mcp_servers.find(s=>s.harness==='opencode')?.disabled).toBe(true);
    const reaches=m.reaches ?? [];
    expect(reaches.find(r=>r.source?.harness==='kiro' && r.capability==='mcp.sample.read')?.source?.gated).toBe(false);
    expect(reaches.find(r=>r.source?.harness==='kiro' && r.capability==='mcp.sample')?.source?.gated).toBe(true);
    expect(reaches.find(r=>r.source?.harness==='roo' && r.capability==='mcp.sample.read')?.source?.gated).toBe(true);
    expect(reaches.some(r=>r.source?.harness==='opencode' && r.capability==='mcp.sample')).toBe(false);
    expect(m.agent_config?.unreadable.some(d=>d.message.includes('ProjectSettingsContent'))).toBe(true);
    expect(reaches.some(r=>r.source?.harness==='zed' && r.capability.startsWith('terminal'))).toBe(false);
  });
  it('reads current Kiro profiles, marks unsupported legacy profiles, and reads Q explicit approvals', async () => {
    const m=await read({
      '.kiro/agents/current.json': JSON.stringify({permissions:{rules:[{capability:'shell',match:['npm *'],effect:'allow'}]}}),
      '.kiro/agents/legacy.json': JSON.stringify({allowedTools:['shell']}),
      '.amazonq/cli-agents/helper.json': JSON.stringify({allowedTools:['@sample/read'],mcpServers:{sample:{command:'node',args:['server.js']}}}),
      '.windsurf/rules/example.md':'Rule text',
    });
    expect(m.reaches?.some(r=>r.source?.harness==='kiro'&&r.capability==='shell.npm')).toBe(true);
    expect(m.agent_config?.unreadable.some(r=>r.file.endsWith('legacy.json'))).toBe(true);
    expect(m.reaches?.some(r=>r.source?.harness==='amazon-q'&&r.capability==='mcp.sample.read')).toBe(true);
    expect(m.agent_config?.instruction_files.some(f=>f.harnesses.includes('windsurf'))).toBe(true);
  });
  it('exports four static families without workflow prompts, scripts, link payloads or trust-state paths', async () => {
    const m=await read({
      '.github/workflows/agent.yml': 'on: pull_request_target\njobs:\n  review:\n    permissions:\n      contents: write\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: ${{ github.event.pull_request.body }} synthetic-private-prompt\n',
      'package.json': '{"scripts":{"preinstall":"synthetic-private-script"}}',
      '.claude.json': '{"projects":{"/synthetic-private-project":{"hasTrustDialogAccepted":true}}}',
      'README.md': 'cursor://anysphere.cursor-deeplink/mcp/install?config=synthetic-private-payload',
    });
    const surfaces=m.agent_config!.surfaces!;
    expect(surfaces.map(s=>s.family).sort()).toEqual(['ci-agent-workflow','deeplink','pre-trust-toolchain','trust-spoofing']);
    expect(surfaces.find(s=>s.family==='ci-agent-workflow')).toMatchObject({harness:'claude-code',line:7,details:{privileged_trigger:true,untrusted_context:true,write_permissions:['contents']}});
    expect(surfaces.find(s=>s.family==='ci-agent-workflow')?.claim_keys?.[0]).toBeTruthy();
    expect(JSON.stringify(surfaces)).not.toContain('synthetic-private');
    expect(m.reach_analysis?.unentitled_reaches.some(r=>r.source?.semantics.rule==='ci-agent-workflow')).toBe(true);
  });
  it('reports invalid workflow YAML rather than treating it as clean', async () => {
    const m=await read({'.github/workflows/agent.yml':'jobs: [not-valid'});
    expect(m.agent_config?.unreadable[0].message).toContain('Invalid workflow YAML');
  });
});
