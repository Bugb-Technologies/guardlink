/**
 * GuardLink Analyzer — exports.
 *
 * @comment -- "SARIF generation is pure transformation; no I/O in this module"
 * @comment -- "File writes handled by CLI/MCP callers"
 */

export { generateSarif, type SarifOptions } from './sarif.js';
