/**
 * GuardLink Analyzer — exports.
 *
 * @comment -- "SARIF generation is pure transformation; no I/O in this module"
 * @comment -- "File writes handled by CLI/MCP callers"
 */

export { generateSarif, type SarifOptions, type SarifVersionControl } from './sarif.js';
export { SARIF_PROFILES, isSarifProfile, MITIGATED_RULE_ID, BOUNDARY_CLAIM_RULE_ID, AGENT_REACH_RULE_ID, type SarifProfile } from './sarif-pentest.js';
