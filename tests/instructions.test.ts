/**
 * GL-401 — MCP server instructions.
 *
 * The SDK stores `instructions` privately at construction, so the text cannot be
 * assembled from tools that have not been registered yet — the tool names in it
 * are prose. This file is what keeps that prose true: every `guardlink_*` named
 * in the instructions is cross-checked against the server's real `tools/list`,
 * so renaming or deleting a tool fails here rather than silently misdirecting
 * every agent that connects.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';
import { buildServerInstructions, readConfiguredMode } from '../src/mcp/instructions.js';
import { SUPPORTED_QUERY_FORMS } from '../src/mcp/lookup.js';

async function connect() {
  const server = createServer();
  const client = new Client({ name: 'test', version: '0.0.0' });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
  return { client, close: () => client.close() };
}

describe('GL-401 — instructions arrive at initialize', () => {
  let session: Awaited<ReturnType<typeof connect>>;
  let instructions: string;
  let toolNames: string[];

  beforeAll(async () => {
    session = await connect();
    instructions = session.client.getInstructions() ?? '';
    toolNames = (await session.client.listTools()).tools.map(t => t.name);
  });

  afterAll(async () => { await session.close(); });

  it('the client receives a non-empty instructions string', () => {
    expect(instructions.length).toBeGreaterThan(500);
  });

  it('stays under 400 words', () => {
    // Orientation delivered before the agent has context to rank detail against.
    // Length costs attention exactly when it is scarcest.
    const words = instructions.trim().split(/\s+/).length;
    expect(words, `${words} words`).toBeLessThan(400);
  });

  it('every tool it names actually exists', () => {
    // The guard that replaces runtime generation. A renamed or removed tool
    // fails here instead of misdirecting agents indefinitely.
    const named = [...new Set(instructions.match(/guardlink_[a-z_]+/g) ?? [])];
    expect(named.length).toBeGreaterThan(3);
    const missing = named.filter(n => !toolNames.includes(n));
    expect(missing, `named but not registered: ${missing.join(', ')}`).toEqual([]);
  });

  it('names the trigger moments, not the tool inventory', () => {
    // It must say WHEN, which tools/list cannot.
    expect(instructions).toMatch(/Opened a file/i);
    expect(instructions).toMatch(/About to change/i);
    expect(instructions).toMatch(/Before you finish/i);
    expect(instructions).toMatch(/After a change/i);
    expect(instructions).toMatch(/scanner reported a CWE/i);
    // And it must NOT be a catalogue: far fewer tools named than registered.
    const named = new Set(instructions.match(/guardlink_[a-z_]+/g) ?? []);
    expect(named.size).toBeLessThan(toolNames.length / 2);
  });

  it('surfaces the tools that were previously undiscoverable', () => {
    for (const tool of ['guardlink_context', 'guardlink_graph', 'guardlink_diff']) {
      expect(instructions, tool).toContain(tool);
    }
  });

  it('teaches the two distinctions that make answers safe to act on', () => {
    // Empty-vs-never-read, and declared-vs-never-heard-of.
    expect(instructions).toMatch(/scanned_without_annotations/);
    expect(instructions).toMatch(/not_scanned/);
    expect(instructions).toMatch(/external_id\.declared/);
    expect(instructions).toMatch(/matched_via/);
  });

  it('reports the real supported-form count, not a hardcoded one', () => {
    expect(instructions).toContain(`${SUPPORTED_QUERY_FORMS.length} named query forms`);
  });

  it('states where annotations are written', () => {
    expect(instructions).toMatch(/@accepts/);
    expect(instructions).toMatch(/definitions/);
  });
});

describe('GL-401 — annotation mode in the instructions', () => {
  it('names inline mode when the project declares it', () => {
    const text = buildServerInstructions({ mode: 'inline', definitionsPath: '.guardlink/definitions.ts' });
    expect(text).toMatch(/annotations INLINE/);
    expect(text).toContain('.guardlink/definitions.ts');
  });

  it('names external mode, its path convention, and the gap that loses data', () => {
    const text = buildServerInstructions({ mode: 'external', definitionsPath: '.guardlink/definitions.ts' });
    expect(text).toMatch(/EXTERNALLY/);
    expect(text).toMatch(/\.guardlink\/annotations/);
    expect(text).toMatch(/@source file:/);
    // D4: documenting a convention that silently drops data without saying so
    // would be worse than not documenting it.
    expect(text).toMatch(/silently dropped/);
    expect(text).toMatch(/test\/|tests\//);
  });

  it('an unrecorded mode is admitted, not guessed', () => {
    const text = buildServerInstructions({ mode: null, definitionsPath: '.guardlink/definitions.ts' });
    expect(text).toMatch(/has not recorded an annotation mode/);
    expect(text).toMatch(/envelope/);
    expect(text).not.toMatch(/annotations INLINE/);
  });
});

describe('readConfiguredMode', () => {
  let root: string;
  beforeAll(async () => { root = await mkdtemp(join(tmpdir(), 'guardlink-mode-')); });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('reads the mode a project recorded', async () => {
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'config.json'), JSON.stringify({ annotation_mode: 'external' }));
    expect(readConfiguredMode(root)).toBe('external');
  });

  it('returns null when the field is absent rather than assuming inline', () => {
    // A repo initialised before the field existed has genuinely not declared a
    // mode. Answering "inline" would be a guess dressed as configuration.
    const bare = { version: '1.1.0', project: 'x' };
    return mkdtemp(join(tmpdir(), 'guardlink-mode2-')).then(async d => {
      await mkdir(join(d, '.guardlink'), { recursive: true });
      await writeFile(join(d, '.guardlink', 'config.json'), JSON.stringify(bare));
      expect(readConfiguredMode(d)).toBeNull();
      await rm(d, { recursive: true, force: true });
    });
  });

  it('returns null when there is no config at all', () => {
    expect(readConfiguredMode('/tmp/definitely-not-a-guardlink-project-xyz')).toBeNull();
  });
});
