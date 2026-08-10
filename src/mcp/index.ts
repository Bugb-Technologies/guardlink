#!/usr/bin/env node

/**
 * GuardLink MCP Server — exports and stdio entry point.
 *
 * @exposes #mcp to #cmd-injection [high] cwe:CWE-78 -- "Accepts tool calls from external MCP clients"
 * @audit #mcp -- "All tool calls validated by server.ts before execution"
 * @flows MCPClient -> #mcp via stdio -- "MCP protocol transport"
 * @boundary #mcp and MCPClient (#mcp-boundary) -- "Trust boundary at MCP protocol"
 * @comment -- "D35: the `guardlink-mcp` bin executes this module directly, so it carries a shebang and a main guard. Startup errors go to stderr — stdout is the JSON-RPC channel and a stray line there corrupts the transport."
 */

export { createServer } from './server.js';
export { lookup, type LookupResult } from './lookup.js';
export { suggestAnnotations, type Suggestion, type SuggestOptions } from './suggest.js';

import { createServer } from './server.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * Start the MCP server on stdio transport.
 * Called from CLI: `guardlink mcp`
 */
export async function startStdioServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

/**
 * D35. `package.json` has declared `bin: {"guardlink-mcp": "./dist/mcp/index.js"}`
 * since the bin existed, but this module only ever *exported* the starter — no
 * shebang, no main guard. Running it loaded the module and exited, so piping an
 * `initialize` request at `guardlink-mcp` produced no response at all.
 *
 * Wired up rather than deleted. `guardlink-mcp` is the conventional name an MCP
 * client reaches for (`npx -y guardlink-mcp`) and it is already published in
 * 1.4.5, so removing it would break a hand-written config that a user had every
 * reason to write. There is no second implementation to drift: both entry points
 * call this same function, and `guardlink mcp` stays what `init` generates.
 *
 * `realpathSync` on both sides because npm installs a bin as a symlink in
 * `node_modules/.bin`, and `argv[1]` is then the symlink, not this file.
 */
function isEntryPoint(): boolean {
  const invoked = process.argv[1];
  if (!invoked) return false;
  try {
    return realpathSync(invoked) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  startStdioServer().catch((err: unknown) => {
    // stderr, never stdout: stdout is the JSON-RPC channel and a stray line
    // there corrupts the transport for the client that is reading it.
    console.error(`guardlink-mcp: failed to start — ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
