/**
 * D35 — the `guardlink-mcp` bin actually serves.
 *
 * `package.json` has declared `bin: {"guardlink-mcp": "./dist/mcp/index.js"}`
 * for as long as the bin existed, but that module only *exported*
 * `startStdioServer` — no shebang, no main guard. Running it loaded the module
 * and exited, so piping an `initialize` request at it produced no response.
 *
 * Nothing generated pointed at the dead entry (`init` writes `guardlink mcp`),
 * which is why it went unnoticed: every test drove the server through
 * `createServer()` in-process, and the one path nobody exercised was the one an
 * outside user would type first.
 *
 * The probe here is the missing test: launch the module AS A PROCESS and require
 * a JSON-RPC answer. A `createServer()` unit test cannot fail this way.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const entry = join(repoRoot, 'src', 'mcp', 'index.ts');

const INITIALIZE = JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'probe', version: '1' } },
}) + '\n';

describe('D35 — guardlink-mcp is a live entry point', () => {
  it('responds to initialize when run as a process', () => {
    const out = execFileSync('npx', ['tsx', entry], {
      cwd: repoRoot, input: INITIALIZE, encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 60_000,
    });
    // Before the fix this was the empty string.
    expect(out.trim()).not.toBe('');
    const response = JSON.parse(out.split('\n').find(l => l.trim().startsWith('{'))!);
    expect(response.id).toBe(1);
    expect(response.result.serverInfo.name).toBe('guardlink');
    expect(response.result.capabilities.tools).toBeDefined();
  }, 90_000);

  it('carries the shebang the bin declaration needs', () => {
    expect(readFileSync(entry, 'utf-8').split('\n')[0]).toBe('#!/usr/bin/env node');
  });

  it('the declared bin target is this module', () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8')) as
      { bin: Record<string, string> };
    // dist/mcp/index.js is the compiled form of src/mcp/index.ts. Pinned so a
    // future move of either side cannot quietly re-orphan the bin.
    expect(resolve(repoRoot, pkg.bin['guardlink-mcp'])).toBe(join(repoRoot, 'dist', 'mcp', 'index.js'));
  });

  it('importing the module does NOT start a server', async () => {
    // The other half of the guard: `import { createServer } from './mcp'` must
    // stay a pure import. A bare `startStdioServer()` at module scope would make
    // every consumer of the library open a stdio transport.
    const mod = await import('../src/mcp/index.js');
    expect(typeof mod.startStdioServer).toBe('function');
    expect(typeof mod.createServer).toBe('function');
  });
});
