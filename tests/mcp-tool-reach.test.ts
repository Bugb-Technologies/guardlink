/**
 * GuardLink's own MCP tools, declared as agent reach.
 *
 * Every tool `src/mcp/server.ts` registers carries `@agents #mcp-agent to
 * <tool name> on <asset>` on its registration, and the tools that write, spawn
 * a process or call a paid API carry `@effects` in the same doc-block. This
 * file keeps that true in both directions:
 *
 *   - the server's real `tools/list` and the `@agents` rows in server.ts name
 *     the same tools, one row each, so a new tool without a reach — or a reach
 *     left behind by a removed tool — fails here;
 *   - `reach_analysis.summary` and the reach and effect rows are pinned as a
 *     golden file beside the other fixtures. Regenerate it with
 *     `npx vitest run tests/mcp-tool-reach.test.ts -u` and read the diff.
 *
 * The summary is of the whole repository, so it also counts the reach
 * generated from `.mcp.json` (origin "agent-config"); the rows below it are
 * the hand-written ones from server.ts only.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';
import { parseProject } from '../src/parser/parse-project.js';
import { withReachAnalysis, boundCode } from '../src/parser/reach.js';
import type { ThreatModel } from '../src/types/index.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SERVER = 'src/mcp/server.ts';
const GOLDEN = './fixtures/mcp-tool-reach/reach.json';

let model: ThreatModel;
let toolNames: string[];
let close: () => Promise<void>;

beforeAll(async () => {
  ({ model } = await parseProject({ root: ROOT, project: 'guardlink' }));
  const server = createServer();
  const client = new Client({ name: 'test', version: '0.0.0' });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
  toolNames = (await client.listTools()).tools.map(t => t.name);
  close = () => client.close();
});

afterAll(async () => { await close(); });

const serverReaches = () => (model.reaches ?? []).filter(r => r.location.file === SERVER);

describe('MCP tools as agent reach', () => {
  it('every registered tool has exactly one @agents row, and every row names a registered tool', () => {
    const declared = serverReaches().map(r => r.capability);
    expect([...declared].sort()).toEqual([...toolNames].sort());
    expect(new Set(declared).size).toBe(declared.length);
    expect(toolNames.length).toBe(28);
  });

  it('each row is an agent reach by #mcp-agent, written by hand', () => {
    for (const r of serverReaches()) {
      expect(r).toMatchObject({ actor: '#mcp-agent', agent: true });
      expect(r.origin).toBeUndefined();
    }
  });

  it('each effect in server.ts is bound to exactly one tool', () => {
    const toolAt = new Map(serverReaches().map(r => [boundCode(r.location), r.capability]));
    for (const e of (model.effects ?? []).filter(x => x.location.file === SERVER)) {
      expect(toolAt.get(boundCode(e.location)), `${e.effect} on ${e.asset} at line ${e.location.line}`).toBeDefined();
    }
  });

  it('matches the golden summary, reaches and effects', async () => {
    const analysis = withReachAnalysis(model).reach_analysis!;
    const toolAt = new Map(serverReaches().map(r => [boundCode(r.location), r.capability]));
    const golden = {
      summary: analysis.summary,
      reaches: serverReaches()
        .map(r => ({ actor: r.actor, capability: r.capability, asset: r.asset }))
        .sort((a, b) => a.capability.localeCompare(b.capability)),
      effects: (model.effects ?? [])
        .filter(e => e.location.file === SERVER)
        .map(e => ({ tool: toolAt.get(boundCode(e.location)), effect: e.effect, asset: e.asset }))
        .sort((a, b) => `${a.tool} ${a.effect} ${a.asset}`.localeCompare(`${b.tool} ${b.effect} ${b.asset}`)),
    };
    await expect(`${JSON.stringify(golden, null, 2)}\n`).toMatchFileSnapshot(GOLDEN);
  });
});
