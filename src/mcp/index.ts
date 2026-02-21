/**
 * GuardLink MCP Server — exports and stdio entry point.
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
