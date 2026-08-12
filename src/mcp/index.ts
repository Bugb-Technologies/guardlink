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
import { getPackageVersion } from '../version.js';

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

/**
 * `--help` / `--version`, handled before the transport opens.
 *
 * A bin that answers neither is a bin you cannot identify once it is installed:
 * `guardlink-mcp --version` used to hang, because every argument was ignored
 * and the process sat waiting for JSON-RPC on a stdin nobody was writing to.
 *
 * These write to STDOUT and exit without connecting a transport — which is safe
 * precisely because no transport exists yet. Once `startStdioServer()` runs,
 * stdout belongs to the JSON-RPC channel and nothing else may touch it.
 *
 * Returns true if it handled the invocation and the server must not start.
 */
function handleCliArgs(argv: string[]): boolean {
  if (argv.includes('--version') || argv.includes('-V')) {
    console.log(getPackageVersion());
    return true;
  }
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`guardlink-mcp ${getPackageVersion()}

  GuardLink's threat model as an MCP server over stdio. Started by an MCP
  client (Claude Code, Cursor, …), not usually by hand — it speaks JSON-RPC on
  stdin/stdout and produces no output on its own.

Usage
  guardlink-mcp              Serve on stdio
  guardlink-mcp --help       Show this message
  guardlink-mcp --version    Print the version

  Identical to \`guardlink mcp\`; both call the same server.

Client configuration
  {"mcpServers": {"guardlink": {"command": "guardlink-mcp"}}}

  Tools and resources are discovered over the protocol — run \`guardlink gal\`
  or see https://guardlink.bugb.io for the annotation language itself.`);
    return true;
  }
  return false;
}

if (isEntryPoint() && !handleCliArgs(process.argv.slice(2))) {
  startStdioServer().catch((err: unknown) => {
    // stderr, never stdout: stdout is the JSON-RPC channel and a stray line
    // there corrupts the transport for the client that is reading it.
    console.error(`guardlink-mcp: failed to start — ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
