/**
 * GuardLink Dashboard — Self-contained HTML threat model dashboard.
 */

export { generateDashboardHTML } from './generate.js';
export { computeStats, computeSeverity, computeExposures, computeAssetHeatmap } from './data.js';
export { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from './diagrams.js';
