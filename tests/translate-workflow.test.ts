import { describe, it, expect, vi } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as childProcess from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';
import { buildTranslatePrompt } from '../src/agents/prompts.js';
import { parseProject } from '../src/parser/parse-project.js';

// Reads may consult git's tracked-file list. No agent, target or template may run.
vi.mock('node:child_process', async importOriginal => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  const forbidden = () => vi.fn(() => { throw new Error('Unexpected process execution'); });
  return { ...actual, spawn: forbidden(), spawnSync: forbidden(), exec: forbidden(), execSync: forbidden(), execFile: forbidden(), execFileSync: vi.fn(actual.execFileSync) };
});

async function snapshot(root: string): Promise<Record<string, string>> {
  const entries = await readdir(root, { withFileTypes: true });
  const result: Record<string, string> = {};
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) Object.assign(result, await snapshot(path));
    else if (entry.isFile()) result[path] = await readFile(path, 'utf8');
  }
  return result;
}

async function connect() {
  const server = createServer();
  const client = new Client({ name: 'translate-test', version: '0' });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
  return client;
}

describe('generation-only translation', () => {
  it('returns an actionable scoped prompt and paths without file writes or execution', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-translate-'));
    const client = await connect();
    try {
      await mkdir(join(root, '.guardlink', 'cxg-templates'), { recursive: true });
      await mkdir(join(root, 'security'));
      await writeFile(join(root, 'package.json'), '{"name":"translate"}');
      await writeFile(join(root, 'app.ts'), '// @exposes App.API to #sqli [high] -- "request email reaches query without parameterisation"\nexport const app = 1;\n');
      await writeFile(join(root, '.guardlink', 'cxg-templates', 'unrelated.py'), 'raise RuntimeError("must not execute")\n');
      await writeFile(join(root, 'security', 'regression.py'), 'raise RuntimeError("must not execute")\n');
      const before = await snapshot(root);
      vi.clearAllMocks();
      const result = await client.callTool({ name: 'guardlink_translate', arguments: { root, prompt: 'Only app.ts SQL input on this branch' } });
      expect(result.isError).not.toBe(true);
      const blocks = result.content as { type: string; text: string }[];
      const response = JSON.parse(blocks[0].text);
      expect(response).toMatchObject({ mode: 'agent', generation_only: true, outputs: { templates: '.guardlink/cxg-templates/', index: '.guardlink/cxg-templates/README.md', findings: '.guardlink/pentest-findings/' } });
      expect(response.prompt).toContain('Only app.ts SQL input on this branch');
      expect(response.prompt).toContain('App.API -> #sqli');
      expect(response.prompt).toContain('Do NOT execute templates');
      expect(response.next_step).toMatch(/execute selected tests separately/);
      expect(JSON.parse(blocks.at(-1)!.text).guardlink.root).toBe(root);
      expect(await snapshot(root)).toEqual(before);
      for (const fn of [childProcess.spawn, childProcess.spawnSync, childProcess.exec, childProcess.execSync, childProcess.execFile]) expect(fn).not.toHaveBeenCalled();
      for (const args of vi.mocked(childProcess.execFileSync).mock.calls) expect(args[0]).toBe('git');
    } finally {
      await client.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('retains the regression obligation when mitigation drops an exposure from candidates', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-translate-fixed-'));
    try {
      await writeFile(join(root, 'app.ts'), '// @exposes App.API to #sqli [high] -- "legacy query"\n// @mitigates App.API against #sqli using Prepared -- "bound parameters"\nexport const app = 1;\n');
      const { model } = await parseProject({ root });
      const prompt = buildTranslatePrompt('Review the SQL fix', root, model);
      expect(prompt).toContain('0 unmitigated exposures');
      expect(prompt).not.toContain('App.API -> #sqli');
      expect(prompt).toMatch(/Keep the regression after a fix/);
      expect(prompt).toMatch(/Preserve unrelated template files and durable regression tests/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
