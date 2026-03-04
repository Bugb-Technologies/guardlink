/**
 * GuardLink MCP Server — exports and stdio entry point.
 *
 * @exposes #mcp to #cmd-injection [high] cwe:CWE-78 -- "[potentially-external] Accepts tool calls from MCP clients over stdio; currently local but protocol could be networked"
 * @audit #mcp -- "All tool calls validated by server.ts before execution"
 * @flows MCPClient -> #mcp via stdio -- "MCP protocol transport"
 * @boundary #mcp and MCPClient (#mcp-boundary) -- "Trust boundary at MCP protocol"
 */

export { createServer } from './server.js';
export { lookup, type LookupResult } from './lookup.js';
export { suggestAnnotations, type Suggestion, type SuggestOptions } from './suggest.js';

import { createServer } from './server.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

/**
 * Start the MCP server on stdio transport.
 * Called from CLI: `guardlink mcp`
 */
export async function startStdioServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
