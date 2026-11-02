import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';

let root: string;
let client: Client;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-translate-contract-'));
  await mkdir(join(root, '.guardlink'));
  await writeFile(join(root, '.guardlink/config.json'), '{"security_tests_dir":"qa/sec-suite"}');
  await writeFile(join(root, 'context.json'), '{"version":1,"threats":[]}');
  const server = createServer();
  client = new Client({ name: 'translate-contract-test', version: '1' });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
});

afterEach(async () => {
  await client?.close();
  await rm(root, { recursive: true, force: true });
});

describe('translation workflow and context interfaces compose', () => {
  it('retains every translation input including graph budget and conversion sources', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === 'guardlink_translate')!;
    expect(Object.keys(tool.inputSchema.properties ?? {})).toEqual(expect.arrayContaining([
      'root', 'prompt', 'context', 'contract', 'from', 'out', 'threat', 'feature',
      'code_graph', 'code_graph_timeout_ms',
    ]));
    expect(tool.inputSchema.properties?.code_graph_timeout_ms).toMatchObject({
      type: 'integer', minimum: 1, maximum: 2147483647,
    });
  });

  it.each([0, -1, 1.5])('refuses invalid graph budget %s at the tool boundary', async value => {
    const result = await client.callTool({ name: 'guardlink_translate', arguments: {
      root, context: 'context.json', code_graph: false, code_graph_timeout_ms: value,
    } });
    expect(result.isError).toBe(true);
  });

  it('retains graph status and resolved output alongside the generation-only handoff', async () => {
    const config = await readFile(join(root, '.guardlink/config.json'), 'utf8');
    const before = await readdir(root);
    const result = await client.callTool({ name: 'guardlink_translate', arguments: {
      root, context: 'context.json', contract: 'scanner', code_graph: false,
      code_graph_timeout_ms: 1234, out: '.guardlink/cxg-templates/change',
    } });
    expect(result.isError).not.toBe(true);
    const blocks = result.content as { type: string; text: string }[];
    const response = JSON.parse(blocks[0].text);
    expect(response).toMatchObject({
      mode: 'agent', generation_only: true,
      context_graph: { status: 'not_requested', reason: 'Explicit context pack supplied' },
      template_dir: resolve(root, '.guardlink/cxg-templates/change'),
      outputs: { templates: '.guardlink/cxg-templates/change/', index: '.guardlink/cxg-templates/change/README.md' },
    });
    expect(resolve(root, response.outputs.templates)).toBe(response.template_dir);
    expect(response.prompt).toContain('Do NOT execute templates');
    expect(response.next_step).toContain('qa/sec-suite/');
    expect(JSON.parse(blocks.at(-1)!.text).guardlink.root).toBe(root);
    expect(await readdir(root)).toEqual(before);
    expect(await readFile(join(root, '.guardlink/config.json'), 'utf8')).toBe(config);
    expect(existsSync(join(root, 'qa'))).toBe(false);
    expect(existsSync(join(root, '.guardlink/cxg-templates'))).toBe(false);
  });
});
