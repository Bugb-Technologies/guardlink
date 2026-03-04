/**
 * GuardLink Dashboard — Self-contained HTML threat model dashboard.
 *
 * @exposes #dashboard to #xss [high] cwe:CWE-79 -- "[mixed] Generates HTML with threat model data from local and PR-contributed annotations"
 * @mitigates #dashboard against #xss using #output-encoding -- "esc() function encodes all interpolated values"
 * @flows ThreatModel -> #dashboard via generateDashboardHTML -- "Model to HTML transformation"
 * @comment -- "Self-contained HTML; no external data injection after generation"
 */

export { generateDashboardHTML } from './generate.js';
export { computeStats, computeSeverity, computeExposures, computeAssetHeatmap } from './data.js';
export { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from './diagrams.js';
