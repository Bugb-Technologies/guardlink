/**
 * GuardLink Report — exports.
 *
 * @comment -- "Report generation is pure transformation; no I/O in this module"
 * @comment -- "File writes handled by CLI/MCP callers"
 */

export { generateMermaid } from './mermaid.js';
export { generateReport } from './report.js';
