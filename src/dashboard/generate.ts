/**
 * GuardLink Dashboard — HTML generator (Giggs-style layout).
 *
 * Sidebar navigation + drawer detail panel + dark/light toggle.
 * 7 pages: Summary, AI Analysis, Threats, Diagrams, Code, Data, Assets.
 * Mermaid.js via CDN for diagrams. Zero build step.
 *
 * @exposes #dashboard to #xss [high] cwe:CWE-79 -- "Generates HTML with user-controlled threat model data"
 * @mitigates #dashboard against #xss using #output-encoding -- "esc() HTML-encodes all interpolated values"
 * @exposes #dashboard to #path-traversal [medium] cwe:CWE-22 -- "readFileSync reads code files for annotation context"
 * @mitigates #dashboard against #path-traversal using #path-validation -- "resolve() with root constrains file access"
 * @flows ThreatModel -> #dashboard via computeStats -- "Model statistics input"
 * @flows SourceFiles -> #dashboard via readFileSync -- "Code snippet reads"
 * @flows #dashboard -> HTML via return -- "Generated HTML output"
 * @mitigates #dashboard against #xss using #output-encoding -- "Serialized model data escapes closing script tags before embedding in <script>"
 * @handles internal on #dashboard -- "Processes and displays threat model data"
 * @feature "Dashboard" -- "Interactive HTML threat model dashboard"
 */

import type { ThreatModel } from '../types/index.js';
import { listFeatures } from '../parser/feature-filter.js';
import { computeStats, computeSeverity, computeExposures, computeConfirmed, computeAssetHeatmap } from './data.js';
import type { DashboardStats, SeverityBreakdown, ExposureRow, ConfirmedRow, AssetHeatmapEntry } from './data.js';
import { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from './diagrams.js';
import type { ThreatReportWithContent } from '../analyze/index.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';
import { readFileSync } from 'fs';
import { resolve, isAbsolute } from 'path';

/**
 * D25/D23 — the dashboard is an emission boundary, so it canonicalises.
 *
 * `docs/examples/threat-dashboard.html` is committed and churned on every
 * regeneration. The PRD attributed that to an embedded wall clock; measurement
 * says otherwise. The `new Date()` here was dead code — computed, never
 * rendered — and removing it changes nothing. What actually moved was parse
 * order: three runs in three processes produced three different files, differing
 * in the order of flow rows, because `parseProject` inherits fast-glob's
 * completion order and this path never went through `canonicalizeModelOrder`.
 *
 * D23 fixed that at the artifact boundary in a921afa and explicitly left the
 * dashboard out of scope as unreproducible. It reproduces; this closes it the
 * same way, at the boundary rather than in the parser.
 */
export function generateDashboardHTML(rawModel: ThreatModel, root?: string, analyses?: ThreatReportWithContent[]): string {
  const model = canonicalizeModelOrder(rawModel);
  // The model is embedded verbatim into the page, so its own `generated_at`
  // rides along and churns a committed HTML file on every regeneration. Same
  // ruling as D26 for `.guardlink/model.json` and GL-302 for the `.mmd`
  // headers: volatile fields do not belong in tracked files. Dropped here
  // rather than in the parser, because parse output is not a tracked file.
  const { generated_at: _generatedAt, ...durableModel } = model;
  const stats = computeStats(model);
  const severity = computeSeverity(model);
  const exposures = computeExposures(model);
  const confirmedRows = computeConfirmed(model);
  const heatmap = computeAssetHeatmap(model);
  const threatGraph = generateThreatGraph(model);
  const threatGraphFull = generateThreatGraph(model, { showAll: true });
  const dataFlow = generateDataFlowDiagram(model);
  const attackSurface = generateAttackSurface(model);
  const featureNames = listFeatures(model);
  const unmitigated = exposures.filter(e => !e.mitigated && !e.accepted);
  const mitigatedCount = exposures.filter(e => e.mitigated).length;
  const mitigationCoveragePercent = exposures.length > 0
    ? Math.round((mitigatedCount / exposures.length) * 100)
    : 0;
  const riskScore = computeRiskGrade(severity, unmitigated.length, exposures.length, confirmedRows.length);

  // Build file annotations data for code browser + drawer
  const fileAnnotations = buildFileAnnotations(model, root);

  // Build analysis data for drawer
  const analysisData = buildAnalysisData(model, exposures);

  // Check for saved AI analyses
  // (we embed the latest one if model has it, otherwise empty)
  const aiAnalysis = '';  // Will be loaded from .guardlink/analyses/ by CLI

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GuardLink — ${esc(model.project)} Threat Model</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
${CSS_CONTENT}
</style>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body>

<!-- ═══════════ TOP NAV ═══════════ -->
<div class="topnav">
  <div class="topnav-left">
    <div class="logo">TS</div>
    <h1>${esc(model.project)}</h1>
    <span class="badge">Threat Model</span>
  </div>
  <div class="topnav-right">
    <div class="topnav-metrics">
      <div class="tn-stat"><span class="tn-k">Assets</span> <span class="tn-v blue">${stats.assets}</span></div>
      <div class="tn-stat"><span class="tn-k">Open</span> <span class="tn-v red">${unmitigated.length}</span></div>
      <div class="tn-stat"><span class="tn-k">Controls</span> <span class="tn-v green">${stats.controls}</span></div>
      <div class="tn-stat"><span class="tn-k">Coverage</span> <span class="tn-v ${stats.coveragePercent >= 70 ? 'green' : stats.coveragePercent >= 40 ? 'yellow' : 'red'}">${stats.coveragePercent}%</span></div>
    </div>
${featureNames.length > 0 ? `    <div class="feature-filter-wrap">
      <select id="featureFilter" class="feature-filter-select" onchange="applyFeatureFilter(this.value)" title="Filter by feature">
        <option value="">All Features</option>
${featureNames.map(f => `        <option value="${esc(f)}">${esc(f)}</option>`).join('\n')}
      </select>
    </div>` : ''}
    <button id="themeToggle" onclick="toggleTheme()" title="Toggle light/dark mode">
      <span class="icon-sun">☀️</span><span class="icon-moon">🌙</span>
    </button>
  </div>
</div>

<!-- Feature filter banner -->
<div id="feature-banner" class="feature-banner">
  <span>Filtered to feature:</span>
  <strong id="feature-banner-name"></strong>
  <span id="feature-banner-files" class="feature-banner-files"></span>
  <button class="feature-banner-clear" onclick="document.getElementById('featureFilter').value='';applyFeatureFilter('')">Clear Filter</button>
</div>

<div class="layout">

<!-- ═══════════ SIDEBAR ═══════════ -->
<nav class="sidebar" id="sidebar">
  <div class="sidebar-nav">
    <a class="active" onclick="showSection('summary',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 2l6 4v6l-6 4-6-4V6l6-4z"/></svg></span> <span class="nav-text">Executive Summary</span></a>
    <a onclick="showSection('ai-analysis',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1l2 5h5l-4 3 2 5-5-3-5 3 2-5-4-3h5l2-5z"/></svg></span> <span class="nav-text">Threat Reports</span></a>
    <a onclick="showSection('threats',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1L1 15h14L8 1zm0 4l3 8H5l3-8z"/></svg></span> <span class="nav-text">Threats &amp; Exposures</span></a>
    <a onclick="showSection('diagrams',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5" fill="none"/><circle cx="8" cy="8" r="2"/></svg></span> <span class="nav-text">Diagrams</span></a>
    <a onclick="showSection('code',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M5 4L1 8l4 4v-2L3 8l2-2V4zm6 0v2l2 2-2 2v2l4-4-4-4z"/></svg></span> <span class="nav-text">Code &amp; Annotations</span></a>
    <div class="sep"></div>
    <a onclick="showSection('data',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M4 2h8v2H4V2zm0 3h8v2H4V5zm0 3h8v2H4V8zm0 3h8v2H4v-2zm-2-9v12h12V2H2zm1 1h10v10H3V3z"/></svg></span> <span class="nav-text">Data &amp; Boundaries</span></a>
    <a onclick="showSection('assets',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M1 3h14v10H1V3zm1 1v8h12V4H2zm2 2h8v1H4V6zm0 2h6v1H4V8z"/></svg></span> <span class="nav-text">Asset Heatmap</span></a>
  </div>
  <button id="sidebarToggle" onclick="toggleSidebar()" title="Collapse sidebar">
    <svg class="chevron-left" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M10 2L4 8l6 6V2z"/></svg>
    <svg class="chevron-right" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M6 2v12l6-6-6-6z"/></svg>
  </button>
</nav>

<!-- ═══════════ MAIN ═══════════ -->
<div class="main">

${renderSummaryPage(stats, severity, riskScore, unmitigated, exposures, model, mitigatedCount, mitigationCoveragePercent)}
${renderAIAnalysisPage(analyses || [])}
${renderThreatsPage(exposures, confirmedRows, model)}
${renderDiagramsPage(threatGraph, threatGraphFull, dataFlow, attackSurface)}
${renderCodePage(fileAnnotations, model)}
${renderDataPage(model)}
${renderAssetsPage(heatmap)}

</div><!-- /main -->
</div><!-- /layout -->

<!-- ═══════════ DRAWER ═══════════ -->
<div class="drawer-overlay" id="drawer-overlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="drawer-header">
    <h3 id="drawer-title">Details</h3>
    <button class="drawer-close" onclick="closeDrawer()">× Close</button>
  </div>
  <div class="drawer-body" id="drawer-body"></div>
</div>

<script>
/* ===== DATA ===== */
const fileAnnotations = ${JSON.stringify(fileAnnotations).replace(/<\//g, '<\\/')};
const analysisData = ${JSON.stringify(analysisData).replace(/<\//g, '<\\/')};
const exposuresData = ${JSON.stringify(exposures).replace(/<\//g, '<\\/')};
const confirmedData = ${JSON.stringify(confirmedRows).replace(/<\//g, '<\\/')};
const savedAnalyses = ${JSON.stringify(analyses || []).replace(/<\//g, '<\\/')};
const heatmapData = ${JSON.stringify(heatmap).replace(/<\//g, '<\\/')};
const threatModel = ${JSON.stringify(durableModel).replace(/<\//g, '<\\/')};
/* ===== SECTION NAV ===== */
function showSection(id, el) {
  document.querySelectorAll('.section-content').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
  const sec = document.getElementById('sec-' + id);
  if (sec) sec.classList.add('active');
  if (el) el.classList.add('active');
  closeDrawer();
  if (id === 'diagrams') {
    setTimeout(() => { renderActiveDiagram(); }, 100);
  }
  if (id === 'ai-analysis' && !window._aiAnalysisRendered) {
    renderAIAnalysis();
  }
}

/* ===== SIDEBAR TOGGLE ===== */
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('collapsed');
  localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
}

// Restore sidebar state on load
window.addEventListener('DOMContentLoaded', () => {
  const collapsed = localStorage.getItem('sidebarCollapsed') === 'true';
  if (collapsed) document.getElementById('sidebar').classList.add('collapsed');
});

/* ===== FILE TOGGLE ===== */
function toggleFile(header) {
  header.classList.toggle('open');
  header.nextElementSibling.classList.toggle('open');
}

/* ===== DRAWER ===== */
function openDrawer(type, idx) {
  const title = document.getElementById('drawer-title');
  const body = document.getElementById('drawer-body');
  let h = '';

  if (type === 'open_exposure') {
    const e = analysisData.openExposures[idx];
    title.textContent = e.threat + ' (Open)';
    h += sec('Status', '<span style="color:var(--red);font-weight:600">OPEN — No mitigation</span>');
    h += sec('Severity', '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(e.asset) + '</code>');
    h += sec('Threat', '<code>' + esc(e.threat) + '</code>');
    if (e.description) h += sec('Description', esc(e.description));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(e.file) + ':' + e.line + '</span>');
    h += '<div class="d-section" style="margin-top:1rem;padding:.6rem;background:var(--badge-red-bg);border:1px solid var(--sev-crit);border-radius:6px;opacity:.85"><div style="font-size:.78rem;color:var(--sev-crit);font-weight:600">Recommended Action</div><div style="font-size:.78rem;margin-top:.3rem">Add a <code>@mitigates</code> annotation with a control that addresses this threat, or <code>@accepts</code> if the risk is intentionally accepted.</div></div>';
  } else if (type === 'mitigated_exposure') {
    const e = analysisData.mitigatedExposures[idx];
    title.textContent = e.threat + ' (Mitigated)';
    h += sec('Status', '<span style="color:var(--green);font-weight:600">MITIGATED</span>');
    h += sec('Severity', '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(e.asset) + '</code>');
    if (e.description) h += sec('Description', esc(e.description));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(e.file) + ':' + e.line + '</span>');
  } else if (type === 'confirmed') {
    const c = confirmedData[idx];
    title.textContent = c.threat + ' (Confirmed)';
    h += '<div style="background:var(--badge-red-bg);border:1px solid var(--sev-crit);border-radius:6px;padding:.6rem;margin-bottom:1rem"><div style="font-size:.82rem;font-weight:700;color:var(--sev-crit)">🔴 CONFIRMED EXPLOITABLE</div><div style="font-size:.75rem;margin-top:.2rem;color:var(--muted)">Verified through testing — not a false positive</div></div>';
    h += sec('Severity', '<span class="fc-sev ' + sevCls(c.severity) + '">' + esc(c.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(c.asset) + '</code>');
    h += sec('Threat', '<code>' + esc(c.threat) + '</code>');
    if (c.description) h += sec('Evidence', esc(c.description));
    if (c.external_refs && c.external_refs.length) h += sec('References', c.external_refs.map(r => '<code>' + esc(r) + '</code>').join(', '));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(c.file) + ':' + c.line + '</span>');
    h += '<div class="d-section" style="margin-top:1rem;padding:.6rem;background:var(--badge-red-bg);border:1px solid var(--sev-crit);border-radius:6px;opacity:.85"><div style="font-size:.78rem;color:var(--sev-crit);font-weight:600">Immediate Action Required</div><div style="font-size:.78rem;margin-top:.3rem">This threat has been verified exploitable. Apply a <code>@mitigates</code> control urgently, or <code>@accepts</code> with explicit risk sign-off from security.</div></div>';
  } else if (type === 'exposure') {
    const e = exposuresData[idx];
    title.textContent = e.threat;
    const status = e.mitigated ? 'MITIGATED' : e.accepted ? 'ACCEPTED' : 'OPEN';
    const color = e.mitigated ? 'var(--green)' : e.accepted ? 'var(--sev-low)' : 'var(--red)';
    h += sec('Status', '<span style="color:' + color + ';font-weight:600">' + status + '</span>');
    h += sec('Severity', '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(e.asset) + '</code>');
    if (e.description) h += sec('Description', esc(e.description));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(e.file) + ':' + e.line + '</span>');
  } else if (type === 'asset') {
    const a = heatmapData[idx];
    title.textContent = a.name + ' (Asset)';
    
    // Risk level banner
    const riskColors = { critical: 'var(--sev-crit)', high: 'var(--sev-high)', medium: 'var(--sev-med)', low: 'var(--sev-low)', none: 'var(--border)' };
    const rColor = riskColors[a.riskLevel] || 'var(--border)';
    h += sec('Risk Level', '<span style="color:' + rColor + ';font-weight:600;text-transform:uppercase">' + a.riskLevel + '</span>');
    
    // Stats
    h += '<div style="display:flex;gap:1rem;margin-bottom:1rem">';
    h += '<div style="flex:1">' + sec('Exposures', '<span style="font-size:1.1rem;font-weight:600;color:var(--red)">' + a.exposures + '</span>') + '</div>';
    h += '<div style="flex:1">' + sec('Mitigations', '<span style="font-size:1.1rem;font-weight:600;color:var(--green)">' + a.mitigations + '</span>') + '</div>';
    h += '<div style="flex:1">' + sec('Data Flows', '<span style="font-size:1.1rem;font-weight:600;color:var(--blue)">' + a.flows + '</span>') + '</div>';
    h += '</div>';
    
    // Data Handling
    if (a.dataHandling && a.dataHandling.length > 0) {
      h += sec('Data Handled', a.dataHandling.map(d => '<span class="ann-badge ann-data" style="margin-right:4px">' + esc(d) + '</span>').join(''));
    }
    
    // Find related open exposures to show in the drawer
    const openForAsset = analysisData.openExposures.filter(e => e.asset === a.name);
    if (openForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--red);margin-top:1.5rem">Open Threats</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      openForAsset.forEach(e => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--red);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(e.threat) + '</strong>';
        h += '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>';
        h += '</div>';
        if (e.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(e.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(e.file) + ':' + e.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related mitigated exposures
    const mitigatedForAsset = analysisData.mitigatedExposures.filter(e => e.asset === a.name);
    if (mitigatedForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--green);margin-top:1.5rem">Mitigated Threats</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      mitigatedForAsset.forEach(e => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--green);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(e.threat) + '</strong>';
        h += '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>';
        h += '</div>';
        if (e.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(e.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(e.file) + ':' + e.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Data Flows
    const flowsForAsset = threatModel.flows.filter(f => f.source === a.name || f.target === a.name);
    if (flowsForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--blue);margin-top:1.5rem">Data Flows</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      flowsForAsset.forEach(f => {
        const isSource = f.source === a.name;
        const icon = isSource ? '<span style="color:var(--blue)">→</span>' : '<span style="color:var(--orange)">←</span>';
        const partner = isSource ? f.target : f.source;
        const desc = isSource ? 'Sends data to' : 'Receives data from';
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px;font-size:0.8rem">';
        h += '<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.2rem">';
        h += icon + ' <span style="color:var(--muted)">' + desc + '</span> <strong>' + esc(partner) + '</strong>';
        h += '</div>';
        if (f.mechanism) h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted)">via ' + esc(f.mechanism) + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Boundaries
    const boundariesForAsset = threatModel.boundaries.filter(b => b.asset_a === a.name || b.asset_b === a.name);
    if (boundariesForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--purple);margin-top:1.5rem">Trust Boundaries</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      boundariesForAsset.forEach(b => {
        const partner = b.asset_a === a.name ? b.asset_b : b.asset_a;
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px;font-size:0.8rem">';
        h += '<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.2rem">';
        h += '<span style="color:var(--purple)">↔</span> <span style="color:var(--muted)">Boundary with</span> <strong>' + esc(partner) + '</strong>';
        h += '</div>';
        if (b.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(b.description) + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Acceptances
    const acceptedForAsset = threatModel.acceptances.filter(ac => ac.asset === a.name);
    if (acceptedForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--yellow);margin-top:1.5rem">Accepted Risks</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      acceptedForAsset.forEach(ac => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--yellow);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(ac.threat) + '</strong>';
        h += '</div>';
        if (ac.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(ac.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(ac.location.file) + ':' + ac.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Transfers
    const transferredForAsset = threatModel.transfers.filter(t => t.source === a.name || t.target === a.name);
    if (transferredForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--purple);margin-top:1.5rem">Transferred Risks</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      transferredForAsset.forEach(t => {
        const isSource = t.source === a.name;
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--purple);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(t.threat) + '</strong>';
        if (isSource) {
          h += '<span style="font-size:0.75rem;color:var(--muted)">Transferred to <strong>' + esc(t.target) + '</strong></span>';
        } else {
          h += '<span style="font-size:0.75rem;color:var(--muted)">Transferred from <strong>' + esc(t.source) + '</strong></span>';
        }
        h += '</div>';
        if (t.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(t.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(t.location.file) + ':' + t.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    // Additional asset lifecycle details
    const validations = threatModel.validations.filter(v => v.asset === a.name);
    if (validations.length > 0) {
      h += '<div class="sub-h" style="color:var(--green);margin-top:1.5rem">Validations</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      validations.forEach(v => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<strong>' + esc(v.control) + '</strong>';
        if (v.description) h += '<div style="font-size:0.75rem;color:var(--muted);margin-top:0.2rem">' + esc(v.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(v.location.file) + ':' + v.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    const ownership = threatModel.ownership.filter(o => o.asset === a.name);
    if (ownership.length > 0) {
      h += '<div class="sub-h" style="color:var(--blue);margin-top:1.5rem">Ownership</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      ownership.forEach(o => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += 'Owned by <strong>' + esc(o.owner) + '</strong>';
        if (o.description) h += '<div style="font-size:0.75rem;color:var(--muted);margin-top:0.2rem">' + esc(o.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(o.location.file) + ':' + o.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    const assumptions = threatModel.assumptions.filter(asm => asm.asset === a.name);
    if (assumptions.length > 0) {
      h += '<div class="sub-h" style="color:var(--yellow);margin-top:1.5rem">Assumptions</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      assumptions.forEach(asm => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="font-size:0.75rem">' + esc(asm.description || 'Assumed risk or state without description') + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(asm.location.file) + ':' + asm.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    const audits = threatModel.audits.filter(au => au.asset === a.name);
    if (audits.length > 0) {
      h += '<div class="sub-h" style="color:var(--accent);margin-top:1.5rem">Audits</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      audits.forEach(au => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="font-size:0.75rem">' + esc(au.description || 'Audit trail point') + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(au.location.file) + ':' + au.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
  }

  body.innerHTML = h;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
}

function openAnnotationDrawer(fileIdx, annIdx) {
  const title = document.getElementById('drawer-title');
  const body = document.getElementById('drawer-body');
  const fentry = fileAnnotations[fileIdx];
  if (!fentry) return;
  const ann = fentry.annotations[annIdx];
  if (!ann) return;

  title.textContent = ann.kind.toUpperCase() + ': ' + ann.summary;
  let h = '';
  h += sec('Type', '<span class="ann-badge ann-' + ann.kind + '">' + ann.kind + '</span>');
  h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(fentry.file) + ':' + ann.line + '</span>');
  if (ann.description) h += sec('Description', esc(ann.description));
  if (ann.raw) h += sec('Raw Annotation', '<div class="d-code">' + esc(ann.raw) + '</div>');
  body.innerHTML = h;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
}

function closeDrawer() {
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('drawer-overlay').classList.remove('open');
}

function esc(s) { return s == null ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function sec(label, value) { return '<div class="d-section"><div class="d-label">' + label + '</div><div class="d-value">' + value + '</div></div>'; }
function sevCls(s) {
  const l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'crit';
  if (l === 'high' || l === 'p1') return 'high';
  if (l === 'medium' || l === 'p2') return 'med';
  if (l === 'low' || l === 'p3') return 'low';
  return 'unset';
}

/* ===== FEATURE FILTER ===== */
var _activeFeature = '';

function _featureFilesFor(featureName) {
  var files = new Set();
  if (!featureName) return files;
  if (threatModel.features) {
    threatModel.features.forEach(function(f) {
      if (f.feature.toLowerCase() === featureName.toLowerCase()) {
        files.add(f.location.file);
      }
    });
  }
  return files;
}

function applyFeatureFilter(featureName) {
  _activeFeature = featureName;
  var banner = document.getElementById('feature-banner');

  if (!featureName) {
    // ── Clear filter ──────────────────────────────────────────────
    if (banner) banner.style.display = 'none';
    document.querySelectorAll('[data-ff]').forEach(function(el) { el.style.display = ''; });
    document.querySelectorAll('[data-ff-asset]').forEach(function(el) { el.style.display = ''; });
    _restoreFullStats();
    return;
  }

  // ── Compute matching file set ─────────────────────────────────
  var featureFiles = _featureFilesFor(featureName);

  // ── Show banner ───────────────────────────────────────────────
  if (banner) {
    banner.style.display = 'flex';
    document.getElementById('feature-banner-name').textContent = featureName;
    document.getElementById('feature-banner-files').textContent = featureFiles.size + ' file(s)';
  }

  // ── Filter rows/cards by file ─────────────────────────────────
  document.querySelectorAll('[data-ff]').forEach(function(el) {
    var file = el.getAttribute('data-ff');
    // Empty data-ff means the annotation had no location — keep visible
    el.style.display = (!file || featureFiles.has(file)) ? '' : 'none';
  });

  // ── Filter asset heatmap cells by asset name ──────────────────
  // An asset belongs to the feature if any of the feature files contains
  // an annotation that references that asset.
  var featureAssets = new Set();
  exposuresData.forEach(function(e) { if (featureFiles.has(e.file)) { featureAssets.add(e.asset); } });
  threatModel.flows.forEach(function(f) {
    if (f.location && featureFiles.has(f.location.file)) {
      featureAssets.add(f.source); featureAssets.add(f.target);
    }
  });
  threatModel.exposures.forEach(function(e) {
    if (e.location && featureFiles.has(e.location.file)) featureAssets.add(e.asset);
  });
  threatModel.mitigations.forEach(function(m) {
    if (m.location && featureFiles.has(m.location.file)) featureAssets.add(m.asset);
  });

  document.querySelectorAll('[data-ff-asset]').forEach(function(el) {
    var asset = el.getAttribute('data-ff-asset');
    el.style.display = featureAssets.has(asset) ? '' : 'none';
  });

  // ── Recompute & update all live stats ─────────────────────────
  _updateStatsForFilter(featureFiles);
}

function _updateStatsForFilter(featureFiles) {
  // Compute filtered exposure subsets from the raw data arrays
  var visExp = exposuresData.filter(function(e) { return !featureFiles.size || featureFiles.has(e.file); });
  var visOpen = visExp.filter(function(e) { return !e.mitigated && !e.accepted; });
  var visMit  = visExp.filter(function(e) { return e.mitigated; });

  var sev = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  visExp.forEach(function(e) {
    var s = (e.severity || '').toLowerCase();
    if (s === 'critical' || s === 'p0') sev.critical++;
    else if (s === 'high' || s === 'p1') sev.high++;
    else if (s === 'medium' || s === 'p2') sev.medium++;
    else if (s === 'low' || s === 'p3') sev.low++;
    else sev.unset++;
  });

  var totalExp = visExp.length;
  var mitPct = totalExp > 0 ? Math.round(visMit.length / totalExp * 100) : 0;

  // ── Top nav ───────────────────────────────────────────────────
  var tnStats = document.querySelectorAll('.tn-stat');
  tnStats.forEach(function(s) {
    var label = s.querySelector('span:first-child');
    var val   = s.querySelector('.tn-v');
    if (!label || !val) return;
    var lbl = label.textContent.trim();
    if (lbl === 'Open') val.textContent = visOpen.length;
    if (lbl === 'Coverage') {
      val.textContent = mitPct + '%';
      val.className = 'tn-v ' + (mitPct >= 70 ? 'green' : mitPct >= 40 ? 'yellow' : 'red');
    }
  });

  // ── Summary page stats grid ───────────────────────────────────
  _setStat('Open Threats',  visOpen.length);
  _setStat('Mitigated',     visMit.length);

  // ── Coverage bar ──────────────────────────────────────────────
  var covPct = document.querySelector('.coverage-pct');
  if (covPct) {
    covPct.textContent = mitPct + '%';
    covPct.className = 'coverage-pct ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  var covLabel = document.querySelector('.posture-fill')?.parentElement?.nextElementSibling;
  var covFill = document.querySelector('.posture-fill');
  if (covFill) {
    covFill.style.width = Math.min(mitPct, 100) + '%';
    covFill.className = 'posture-fill ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  // Update "X of Y exposures mitigated" label
  document.querySelectorAll('#sec-summary span').forEach(function(sp) {
    if (sp.textContent.includes('exposures mitigated')) {
      sp.textContent = visMit.length + ' of ' + totalExp + ' exposures mitigated';
    }
  });

  // ── Severity bars ─────────────────────────────────────────────
  _updateSevBar('Critical', sev.critical, totalExp);
  _updateSevBar('High',     sev.high,     totalExp);
  _updateSevBar('Medium',   sev.medium,   totalExp);
  _updateSevBar('Low',      sev.low,      totalExp);
  _updateSevBar('Unset',    sev.unset,    totalExp);

  // ── Section headings with counts ─────────────────────────────
  _updateHeading('sec-threats', 'Open Threats',     visOpen.length);
  _updateHeading('sec-threats', 'Mitigated Threats', visMit.length);
  _updateHeading('sec-threats', 'All Exposures',     totalExp);

  // ── Risk banner (recompute grade) ─────────────────────────────
  var visConf = confirmedData.filter(function(c) { return !featureFiles.size || featureFiles.has(c.file); });
  _updateRiskBanner(sev, visOpen.length, totalExp, visConf.length);
}

function _restoreFullStats() {
  // Restore all counts from the original full data sets
  var allOpen = exposuresData.filter(function(e) { return !e.mitigated && !e.accepted; });
  var allMit  = exposuresData.filter(function(e) { return e.mitigated; });
  var totalExp = exposuresData.length;
  var mitPct = totalExp > 0 ? Math.round(allMit.length / totalExp * 100) : 0;

  var sev = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  exposuresData.forEach(function(e) {
    var s = (e.severity || '').toLowerCase();
    if (s === 'critical' || s === 'p0') sev.critical++;
    else if (s === 'high' || s === 'p1') sev.high++;
    else if (s === 'medium' || s === 'p2') sev.medium++;
    else if (s === 'low' || s === 'p3') sev.low++;
    else sev.unset++;
  });

  // Top nav
  var tnStats = document.querySelectorAll('.tn-stat');
  tnStats.forEach(function(s) {
    var label = s.querySelector('span:first-child');
    var val   = s.querySelector('.tn-v');
    if (!label || !val) return;
    var lbl = label.textContent.trim();
    if (lbl === 'Open') val.textContent = allOpen.length;
    if (lbl === 'Coverage') {
      val.textContent = mitPct + '%';
      val.className = 'tn-v ' + (mitPct >= 70 ? 'green' : mitPct >= 40 ? 'yellow' : 'red');
    }
  });

  _setStat('Open Threats', allOpen.length);
  _setStat('Mitigated',    allMit.length);

  var covPct = document.querySelector('.coverage-pct');
  if (covPct) {
    covPct.textContent = mitPct + '%';
    covPct.className = 'coverage-pct ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  var covFill = document.querySelector('.posture-fill');
  if (covFill) {
    covFill.style.width = Math.min(mitPct, 100) + '%';
    covFill.className = 'posture-fill ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  document.querySelectorAll('#sec-summary span').forEach(function(sp) {
    if (sp.textContent.includes('exposures mitigated')) {
      sp.textContent = allMit.length + ' of ' + totalExp + ' exposures mitigated';
    }
  });

  _updateSevBar('Critical', sev.critical, totalExp);
  _updateSevBar('High',     sev.high,     totalExp);
  _updateSevBar('Medium',   sev.medium,   totalExp);
  _updateSevBar('Low',      sev.low,      totalExp);
  _updateSevBar('Unset',    sev.unset,    totalExp);

  _updateHeading('sec-threats', 'Open Threats',      allOpen.length);
  _updateHeading('sec-threats', 'Mitigated Threats', allMit.length);
  _updateHeading('sec-threats', 'All Exposures',     totalExp);

  _updateRiskBanner(sev, allOpen.length, totalExp, confirmedData.length);
}

/* ── Helpers ──────────────────────────────────────────────────────── */

function _setStat(label, value) {
  document.querySelectorAll('.stat-card').forEach(function(card) {
    var lbl = card.querySelector('.label');
    var val = card.querySelector('.value');
    if (lbl && val && lbl.textContent.trim() === label) {
      val.textContent = value;
    }
  });
}

function _updateSevBar(label, count, total) {
  var pct = total > 0 ? Math.round(count / total * 100) : 0;
  document.querySelectorAll('.sev-row').forEach(function(row) {
    var lbl = row.querySelector('.sev-label');
    if (!lbl || lbl.textContent.trim() !== label) return;
    var fill = row.querySelector('.sev-fill');
    var cnt  = row.querySelector('.sev-count');
    if (fill) fill.style.width = pct + '%';
    if (cnt)  cnt.textContent = count;
  });
}

function _updateHeading(sectionId, prefix, count) {
  var sec = document.getElementById(sectionId);
  if (!sec) return;
  sec.querySelectorAll('.sub-h').forEach(function(h) {
    if (h.textContent.trim().startsWith(prefix)) {
      // Replace trailing (N) count
      h.textContent = h.textContent.replace(/\(\d+\)$/, '(' + count + ')').replace(/\s+\d+$/, ' ' + count);
    }
  });
}

function _updateRiskBanner(sev, openCount, totalExp, confirmedCount) {
  var grade, label, summary;
  if (confirmedCount > 0) {
    grade = 'F'; label = 'Critical Risk';
    summary = confirmedCount + ' confirmed exploitable finding(s) — immediate remediation required';
  } else if (sev.critical > 0) {
    grade = 'F'; label = 'Critical Risk';
    summary = sev.critical + ' critical exposure(s) require immediate attention';
  } else if (sev.high >= 3 || openCount >= 5) {
    grade = 'D'; label = 'High Risk';
    summary = openCount + ' unmitigated exposure(s), ' + sev.high + ' high severity';
  } else if (sev.high >= 1 || openCount >= 3) {
    grade = 'C'; label = 'Moderate Risk';
    summary = openCount + ' unmitigated exposure(s) need remediation';
  } else if (openCount >= 1) {
    grade = 'B'; label = 'Low Risk';
    summary = openCount + ' minor unmitigated exposure(s)';
  } else if (totalExp === 0) {
    grade = 'A'; label = 'Excellent';
    summary = 'No exposures detected — consider adding more annotations';
  } else {
    grade = 'A'; label = 'Excellent';
    summary = 'All exposures mitigated or accepted';
  }

  var banner = document.querySelector('.risk-banner');
  if (!banner) return;
  // Update grade class
  banner.className = banner.className.replace(/risk-[a-z]/g, 'risk-' + grade.toLowerCase());
  var gradeEl = banner.querySelector('.risk-grade');
  if (gradeEl) gradeEl.textContent = grade;
  var detail = banner.querySelector('.risk-detail');
  if (detail) {
    var strong = detail.querySelector('strong');
    var span   = detail.querySelector('span');
    if (strong) strong.textContent = label;
    if (span)   span.textContent   = summary;
  }
}

/* ===== THEME ===== */
function toggleTheme() {
  const html = document.documentElement;
  const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  // Re-render mermaid with new theme
  window._mermaidRendered = false;
  if (document.getElementById('sec-diagrams').classList.contains('active')) {
    renderActiveDiagram();
  }
}

/* ===== DIAGRAM TABS ===== */
function switchDiagramTab(id, btn) {
  document.querySelectorAll('.diagram-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.diagram-tab').forEach(t => t.classList.remove('active'));
  const panel = document.getElementById('dtab-' + id);
  if (panel) panel.classList.add('active');
  if (btn) btn.classList.add('active');
  setTimeout(() => { renderActiveDiagram(); }, 50);
}

function toggleThreatGraphAll(btn) {
  const panel = document.getElementById('dtab-threat-graph');
  if (!panel) return;
  const filtered = panel.querySelector('.mermaid[data-variant="filtered"]');
  const full = panel.querySelector('.mermaid[data-variant="full"]');
  if (!filtered || !full) return;
  const showFull = full.style.display === 'none';
  filtered.style.display = showFull ? 'none' : '';
  full.style.display = showFull ? '' : 'none';
  if (btn) {
    btn.classList.toggle('active', showFull);
    btn.textContent = showFull ? 'High/Critical only' : 'All severities';
  }
  // Force mermaid to re-render the now-visible variant
  panel._diagramZoom = null;
  setTimeout(() => { renderActiveDiagram(); }, 50);
}

function diagramZoom(action) {
  const panel = document.querySelector('.diagram-panel.active');
  if (!panel || !panel._diagramZoom) return;
  const state = panel._diagramZoom;
  const svg = state.svg;
  const zoom = state.zoom;
  if (!svg || !zoom) return;

  if (action === 'fit') {
    svg.transition().duration(420).call(zoom.transform, d3.zoomIdentity);
    return;
  }
  const factor = action === 'in' ? 1.2 : 1 / 1.2;
  svg.transition().duration(220).call(zoom.scaleBy, factor);
}

/* ===== MERMAID ===== */
async function getMermaidInstance() {
  if (!window._mermaidMod) {
    const mod = await import('https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs');
    window._mermaidMod = mod.default;
  }
  const mermaid = window._mermaidMod;
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  mermaid.initialize({
    startOnLoad: false,
    theme: isDark ? 'dark' : 'default',
    themeVariables: isDark ? {
      primaryColor: '#17272e', primaryTextColor: '#f0f0f0', primaryBorderColor: '#55899e',
      lineColor: '#6b93a6', secondaryColor: '#1f3943', tertiaryColor: '#0f1b20',
      background: '#0f1b20', mainBkg: '#17272e', nodeBorder: '#55899e', secondBkg: '#1f3943',
      clusterBkg: 'rgba(23,39,46,.55)', clusterBorder: '#3b6779',
      titleColor: '#f0f0f0', edgeLabelBackground: '#0f1b20', labelBackground: '#0f1b20',
      nodeTextColor: '#f0f0f0',
      fontSize: '12px', fontFamily: 'Inter, system-ui, sans-serif',
    } : {
      primaryColor: '#ffffff', primaryTextColor: '#1f3943', primaryBorderColor: '#55899e',
      lineColor: '#3b6779', secondaryColor: '#f4f7f8', tertiaryColor: '#ffffff',
      background: '#ffffff', mainBkg: '#ffffff', nodeBorder: '#55899e', secondBkg: '#e8eef0',
      clusterBkg: '#f7fafb', clusterBorder: '#d9e4e8',
      titleColor: '#1f3943', edgeLabelBackground: '#ffffff', labelBackground: '#ffffff',
      nodeTextColor: '#1f3943',
      fontSize: '12px', fontFamily: 'Inter, system-ui, sans-serif',
    },
    flowchart: { curve: 'monotoneX', padding: 20, nodeSpacing: 48, rankSpacing: 62, htmlLabels: false, useMaxWidth: false, defaultRenderer: 'dagre-d3' },
    securityLevel: 'loose',
  });
  return mermaid;
}

async function renderMermaidPanel(panel) {
  if (!panel) return;
  const mermaid = await getMermaidInstance();
  // Render only the currently visible mermaid block(s). Hidden variants (e.g. the
  // full threat graph behind the "All severities" toggle) would otherwise fail
  // getBBox during layout sizing.
  const allEls = Array.from(panel.querySelectorAll('.mermaid'));
  const els = allEls.filter(el => el.offsetParent !== null || el.style.display !== 'none');
  const targets = els.length > 0 ? els : allEls;

  // Re-run mermaid
  targets.forEach(el => {
    el.removeAttribute('data-processed');
    el.innerHTML = el.getAttribute('data-original') || el.textContent;
  });
  await mermaid.run({ nodes: targets });
  
  // Add interactive zoom/pan to the rendered SVG
  if (typeof d3 !== 'undefined') {
    targets.forEach(el => {
      const svg = d3.select(el).select('svg');
      if (!svg.empty()) {
        const inner = svg.select('.root'); // Mermaid puts everything in a .root group
        if (!inner.empty()) {
          const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (e) => {
              inner.attr('transform', e.transform);
            });
          svg.call(zoom);
          panel._diagramZoom = { svg, zoom };
          
          // Preserve natural SVG size so long labels are not clipped.
          // Container scrolling handles overflow for large graphs.
          const rootNode = inner.node();
          if (rootNode && typeof rootNode.getBBox === 'function') {
            const bbox = rootNode.getBBox();
            const pad = 80;
            const viewX = Math.floor(bbox.x - pad / 2);
            const viewY = Math.floor(bbox.y - pad / 2);
            const viewW = Math.max(900, Math.ceil(bbox.width + pad));
            const viewH = Math.max(520, Math.ceil(bbox.height + pad));
            svg
              .attr('viewBox', viewX + ' ' + viewY + ' ' + viewW + ' ' + viewH)
              .attr('width', viewW)
              .attr('height', viewH)
              .style('max-width', 'none')
              .style('overflow', 'visible');
          }
          
          // Double click to reset
          svg.on('dblclick.zoom', null); // disable default dblclick zoom
          svg.on('dblclick', () => {
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
          });
        }
      }
    });
  }
}

async function renderMermaid() {
  // Render only the currently active diagram panel
  const active = document.querySelector('.diagram-panel.active');
  if (active) await renderMermaidPanel(active);
  window._mermaidRendered = true;
}

function renderActiveDiagram() {
  const active = document.querySelector('.diagram-panel.active');
  if (!active) return;
  renderMermaidPanel(active).then(() => { window._mermaidRendered = true; });
}

// Save original diagram source
document.querySelectorAll('.mermaid').forEach(el => {
  el.setAttribute('data-original', el.textContent.trim());
});

/* Keyboard: Escape closes drawer */
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

/* ===== AI ANALYSIS EXPLORER ===== */
let _selectedAnalysisIdx = 0;

function renderAIAnalysisContent(container, content) {
  if (!container) return;
  if (content && content.trim()) {
    if (typeof marked !== 'undefined') {
      try { container.innerHTML = marked.parse(content); }
      catch { container.innerHTML = '<pre style="white-space:pre-wrap">' + esc(content) + '</pre>'; }
    } else {
      container.innerHTML = '<pre style="white-space:pre-wrap">' + esc(content) + '</pre>';
    }
  } else {
    container.innerHTML = '<div class="empty-state" style="text-align:center;padding:3rem 1rem">' +
      '<div style="font-size:3rem;margin-bottom:1rem;opacity:0.5">✨</div>' +
      '<div style="font-size:1.1rem;font-weight:600;margin-bottom:0.5rem">No Threat Reports Yet</div>' +
      '<div style="color:var(--muted);margin-bottom:1.5rem">Generate an AI threat report using the threat-report command</div>' +
      '<div style="display:flex;flex-direction:column;gap:0.5rem;max-width:500px;margin:0 auto;text-align:left">' +
      '<div style="font-size:0.88rem;color:var(--muted)"><strong>Available modes:</strong></div>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report stride</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report dread</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report pasta</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report attacker</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report rapid</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report general</code>' +
      '<div style="margin-top:0.5rem;font-size:0.82rem;color:var(--muted)">Or a custom prompt: <code>guardlink threat-report general --custom "focus on auth"</code></div>' +
      '</div></div>';
  }
}

function formatAnalysisDate(ts) {
  try {
    // Handle both ISO and filename-style timestamps
    const normalized = ts.replace(/T(\\d{2})-(\\d{2})-(\\d{2})/, 'T$1:$2:$3');
    const d = new Date(normalized);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
           ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  } catch { return ts; }
}

function renderAIAnalysis() {
  window._aiAnalysisRendered = true;
  const selector = document.getElementById('report-selector');
  const container = document.getElementById('ai-content');
  if (!container) return;

  const list = savedAnalyses;
  const hasList = Array.isArray(list) && list.length > 0;

  if (hasList && selector) {
    // Populate dropdown with reports
    selector.innerHTML = list.map((a, i) => {
      const label = esc(a.label || a.framework || 'Analysis');
      const date = esc(formatAnalysisDate(a.timestamp || ''));
      const model = a.model ? ' — ' + esc(a.model) : '';
      return '<option value="' + i + '">' + label + ' (' + date + ')' + model + '</option>';
    }).join('');

    // Set initial selection
    selector.value = String(_selectedAnalysisIdx);

    // Handle dropdown change
    selector.addEventListener('change', function() {
      var idx = parseInt(this.value, 10);
      if (isNaN(idx) || idx === _selectedAnalysisIdx) return;
      _selectedAnalysisIdx = idx;
      renderAIAnalysisContent(container, (list[idx] && list[idx].content) ? list[idx].content : '');
    });

    // Render initial content
    renderAIAnalysisContent(container, (list[_selectedAnalysisIdx] && list[_selectedAnalysisIdx].content) ? list[_selectedAnalysisIdx].content : '');
  } else {
    if (selector) selector.style.display = 'none';
    renderAIAnalysisContent(container, '');
  }
}
</script>

</body>
</html>`;
}

// ─── Page renderers ──────────────────────────────────────────────────

function renderSummaryPage(
  stats: DashboardStats, severity: SeverityBreakdown,
  risk: { grade: string; label: string; summary: string },
  unmitigated: ExposureRow[], exposures: ExposureRow[], model: ThreatModel,
  mitigatedCount: number, mitigationCoveragePercent: number
): string {
  return `
<div id="sec-summary" class="section-content active">
  <div class="sec-h"><span class="sec-icon">◆</span> Executive Summary</div>

  <!-- Risk Grade -->
  <div class="risk-banner risk-${risk.grade.toLowerCase()}">
    <div class="risk-grade">${risk.grade}</div>
    <div class="risk-detail">
      <strong>${risk.label}</strong>
      <span>${risk.summary}</span>
    </div>
  </div>

  <!-- Stats Grid -->
  <div class="stats-grid">
    ${statCard(stats.assets, 'Assets')}
    ${statCard(unmitigated.length, 'Open Threats', 'danger')}
    ${stats.confirmed > 0 ? statCard(stats.confirmed, 'Confirmed', 'danger') : ''}
    ${statCard(mitigatedCount, 'Mitigated', 'success')}
    ${statCard(stats.controls, 'Controls', 'success')}
    ${statCard(stats.flows, 'Data Flows')}
    ${statCard(stats.boundaries, 'Boundaries')}
    ${statCard(stats.transfers, 'Transfers')}
    ${statCard(stats.validations, 'Validations', 'success')}
    ${statCard(stats.audits, 'Audits')}
    ${statCard(stats.assumptions, 'Assumptions')}
    ${statCard(stats.ownership, 'Ownership')}
    ${statCard(stats.comments, 'Comments', 'muted')}
    ${stats.shields > 0 ? statCard(stats.shields, 'Shields', 'muted') : ''}
  </div>

  <div class="summary-panels">
  <!-- Coverage Bar -->
  <div class="panel">
  <div class="sub-h">Threat Mitigation Coverage</div>
  <div class="panel-row">
    <span class="coverage-pct ${mitigationCoveragePercent >= 70 ? 'good' : mitigationCoveragePercent >= 40 ? 'warn' : 'bad'}">${mitigationCoveragePercent}%</span>
    <span class="panel-muted">${mitigatedCount} of ${exposures.length} exposures mitigated</span>
  </div>
  <div class="posture-bar"><div class="posture-fill ${mitigationCoveragePercent >= 70 ? 'good' : mitigationCoveragePercent >= 40 ? 'warn' : 'bad'}" style="width:${Math.min(mitigationCoveragePercent, 100)}%"></div></div>
  </div>

  <!-- Severity Breakdown -->
  <div class="panel">
  <div class="sub-h">Severity Breakdown</div>
  <div class="severity-chart">
    ${severityBar('Critical', severity.critical, stats.exposures, 'crit')}
    ${severityBar('High', severity.high, stats.exposures, 'high')}
    ${severityBar('Medium', severity.medium, stats.exposures, 'med')}
    ${severityBar('Low', severity.low, stats.exposures, 'low')}
    ${severity.unset > 0 ? severityBar('Unset', severity.unset, stats.exposures, 'unset') : ''}
  </div>
  </div>
  </div>

  ${unmitigated.length > 0 ? `
  <!-- Open Threats -->
  <div class="panel">
  <div class="sub-h sub-h-alert">⚠ Open Threats (No Mitigation)</div>
  ${unmitigated.map((e, i) => `
  <div class="finding-card" data-ff="${esc(e.file)}" onclick="openDrawer('open_exposure', ${i})">
    <div class="fc-top">
      <span class="fc-risk">${esc(e.threat)}</span>
      <span class="fc-sev ${sevClass(e.severity)}">${esc(e.severity)}</span>
    </div>
    ${e.description ? `<div class="fc-desc">${esc(e.description)}</div>` : ''}
    <div class="fc-assets">Asset: ${esc(e.asset)}</div>
  </div>`).join('')}
  </div>` : ''}

  ${model.flows.length > 0 ? `
  <!-- Data Flows -->
  <div class="panel">
  <div class="sub-h">Data Flows</div>
  <table>
    <thead><tr><th>Source</th><th></th><th>Target</th><th>Mechanism</th><th>Location</th></tr></thead>
    <tbody>
    ${model.flows.map(f => `
    <tr data-ff="${f.location ? esc(f.location.file) : ''}">
      <td><code>${esc(f.source)}</code></td>
      <td class="flow-arrow">→</td>
      <td><code>${esc(f.target)}</code></td>
      <td>${esc(f.mechanism || '—')}</td>
      <td class="loc">${f.location ? `${esc(f.location.file)}:${f.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>
  </div>` : ''}
</div>`;
}

function renderAIAnalysisPage(analyses: ThreatReportWithContent[]): string {
  return `
<div id="sec-ai-analysis" class="section-content">
  <div class="sec-h"><span class="sec-icon">✨</span> Threat Reports</div>
  <div class="panel ai-analysis-panel">
  <div class="ai-analysis-controls">
    <label for="report-selector" class="report-selector-label">Select Report:</label>
    <select id="report-selector" class="report-selector" aria-label="Select threat report"></select>
  </div>
  <div id="ai-content" class="md-content ai-analysis-main"></div>
  </div>
</div>`;
}

function renderThreatsPage(exposures: ExposureRow[], confirmed: ConfirmedRow[], model: ThreatModel): string {
  const open = exposures.filter(e => !e.mitigated && !e.accepted);
  const mitigated = exposures.filter(e => e.mitigated);
  const accepted = exposures.filter(e => e.accepted);

  return `
<div id="sec-threats" class="section-content">
  <div class="sec-h"><span class="sec-icon">⚠</span> Threats &amp; Exposures</div>

  ${confirmed.length > 0 ? `
  <div class="sub-h sub-h-critical">🔴 Confirmed Exploitable (${confirmed.length})</div>
  <p class="section-note">Verified through pentest, scanning, or manual reproduction — <strong>not false positives</strong>.</p>
  <table>
    <thead><tr><th>Asset</th><th>Threat</th><th>Severity</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${confirmed.map((c, i) => `
    <tr class="clickable row-open" data-ff="${esc(c.file)}" onclick="openDrawer('confirmed', ${i})" style="border-left:3px solid var(--sev-crit, #e74c3c)">
      <td><code>${esc(c.asset)}</code></td>
      <td><code>${esc(c.threat)}</code></td>
      <td><span class="fc-sev ${sevClass(c.severity)}">${esc(c.severity)}</span></td>
      <td>${esc(c.description || '—')}</td>
      <td class="loc">${esc(c.file)}:${c.line}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  <div class="sub-h sub-h-alert">Open Threats (${open.length})</div>
  <p class="section-note">Exposed in code but <strong>not mitigated</strong> by any control.</p>
  ${open.length > 0 ? `
  <table>
    <thead><tr><th>Asset</th><th>Threat</th><th>Severity</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${open.map((e, i) => `
    <tr class="clickable" data-ff="${esc(e.file)}" onclick="openDrawer('open_exposure', ${i})">
      <td><code>${esc(e.asset)}</code></td>
      <td><code>${esc(e.threat)}</code></td>
      <td><span class="fc-sev ${sevClass(e.severity)}">${esc(e.severity)}</span></td>
      <td>${esc(e.description || '—')}</td>
      <td class="loc">${esc(e.file)}:${e.line}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : '<p class="empty-state">All exposed threats are mitigated or accepted.</p>'}

  <div class="sub-h sub-h-ok">Mitigated Threats (${mitigated.length})</div>
  ${mitigated.length > 0 ? `
  <table>
    <thead><tr><th>Asset</th><th>Threat</th><th>Severity</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${mitigated.map((e, i) => `
    <tr class="clickable" data-ff="${esc(e.file)}" onclick="openDrawer('mitigated_exposure', ${i})">
      <td><code>${esc(e.asset)}</code></td>
      <td><code>${esc(e.threat)}</code></td>
      <td><span class="fc-sev ${sevClass(e.severity)}">${esc(e.severity)}</span></td>
      <td>${esc(e.description || '—')}</td>
      <td class="loc">${esc(e.file)}:${e.line}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : '<p class="empty-state">No mitigations found.</p>'}

  ${accepted.length > 0 ? `
  <div class="sub-h sub-h-neutral">Accepted Risks (${accepted.length})</div>
  <table>
    <thead><tr><th>Asset</th><th>Threat</th><th>Severity</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${accepted.map(e => `
    <tr data-ff="${esc(e.file)}">
      <td><code>${esc(e.asset)}</code></td>
      <td><code>${esc(e.threat)}</code></td>
      <td><span class="fc-sev ${sevClass(e.severity)}">${esc(e.severity)}</span></td>
      <td>${esc(e.description || '—')}</td>
      <td class="loc">${esc(e.file)}:${e.line}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.transfers.length > 0 ? `
  <div class="sub-h sub-h-info">Transferred Risks (${model.transfers.length})</div>
  <table>
    <thead><tr><th>Source</th><th>Threat</th><th>Target</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${model.transfers.map(t => `
    <tr data-ff="${t.location ? esc(t.location.file) : ''}">
      <td><code>${esc(t.source)}</code></td>
      <td><code>${esc(t.threat)}</code></td>
      <td><code>${esc(t.target)}</code></td>
      <td>${esc(t.description || '—')}</td>
      <td class="loc">${t.location ? `${esc(t.location.file)}:${t.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${exposures.length > 0 ? `
  <div class="sub-h">All Exposures (${exposures.length})</div>
  <table>
    <thead><tr><th>Status</th><th>Asset</th><th>Threat</th><th>Severity</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${exposures.map((e, i) => `
    <tr class="clickable ${!e.mitigated && !e.accepted ? 'row-open' : ''}" data-ff="${esc(e.file)}" onclick="openDrawer('exposure', ${i})">
      <td>${e.mitigated ? '<span class="badge badge-green">Mitigated</span>' : e.accepted ? '<span class="badge badge-blue">Accepted</span>' : '<span class="badge badge-red">Open</span>'}</td>
      <td><code>${esc(e.asset)}</code></td>
      <td><code>${esc(e.threat)}</code></td>
      <td><span class="fc-sev ${sevClass(e.severity)}">${esc(e.severity)}</span></td>
      <td>${esc(e.description || '—')}</td>
      <td class="loc">${esc(e.file)}:${e.line}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}
</div>`;
}

function renderDiagramsPage(threatGraph: string, threatGraphFull: string, dataFlow: string, attackSurface: string): string {
  const tabs = [];
  const panels = [];
  const diagramActions = `
          <div class="diagram-actions">
            <button class="diagram-btn" onclick="diagramZoom('out')" title="Zoom out">−</button>
            <button class="diagram-btn" onclick="diagramZoom('in')" title="Zoom in">+</button>
            <button class="diagram-btn" onclick="diagramZoom('fit')" title="Reset view">Reset</button>
          </div>`;

  if (threatGraph) {
    tabs.push({ id: 'threat-graph', label: 'Threat Graph', icon: '🔷' });
    const hasFullVariant = threatGraphFull && threatGraphFull !== threatGraph;
    const showAllBtn = hasFullVariant
      ? `<button id="threatGraphToggle" class="diagram-btn" onclick="toggleThreatGraphAll(this)" title="Show all threat severities (not just high/critical)">All severities</button>`
      : '';
    panels.push(`<div id="dtab-threat-graph" class="diagram-panel${panels.length === 0 ? ' active' : ''}">
      <div class="diagram-shell">
        <div class="diagram-toolbar">
          <span class="diagram-title">Threat Graph</span>
          <div class="diagram-actions">
            ${showAllBtn}
            <button class="diagram-btn" onclick="diagramZoom('out')" title="Zoom out">−</button>
            <button class="diagram-btn" onclick="diagramZoom('in')" title="Zoom in">+</button>
            <button class="diagram-btn" onclick="diagramZoom('fit')" title="Reset view">Reset</button>
          </div>
        </div>
        <div class="mermaid-wrap">
          <pre class="mermaid" data-variant="filtered">\n${esc(threatGraph)}\n</pre>
          ${hasFullVariant ? `<pre class="mermaid" data-variant="full" style="display:none">\n${esc(threatGraphFull)}\n</pre>` : ''}
        </div>
        <div class="diagram-meta">Assets, threats, controls, and mitigations. ${hasFullVariant ? 'Filtered to high/critical by default — click <em>All severities</em> to expand.' : ''}</div>
      </div>
    </div>`);
  }
  if (dataFlow) {
    tabs.push({ id: 'data-flow', label: 'Data Flow', icon: '↔' });
    panels.push(`<div id="dtab-data-flow" class="diagram-panel">
      <div class="diagram-shell">
        <div class="diagram-toolbar">
          <span class="diagram-title">Data Flow</span>
${diagramActions}
        </div>
        <div class="mermaid-wrap"><pre class="mermaid">\n${esc(dataFlow)}\n</pre></div>
        <div class="diagram-meta">Trust zones (🧱) and data movement across system boundaries. Each boundary shows both sides of the trust line.</div>
      </div>
    </div>`);
  }
  if (attackSurface) {
    tabs.push({ id: 'attack-surface', label: 'Attack Surface', icon: '⚠' });
    panels.push(`<div id="dtab-attack-surface" class="diagram-panel">
      <div class="diagram-shell">
        <div class="diagram-toolbar">
          <span class="diagram-title">Attack Surface</span>
${diagramActions}
        </div>
        <div class="mermaid-wrap"><pre class="mermaid">\n${esc(attackSurface)}\n</pre></div>
        <div class="diagram-meta">Exposures per asset, severity-coloured. <strong>💥 confirmed</strong>, <strong>⚠️ open</strong>, <strong>✅ mitigated</strong>, <strong>🟦 accepted</strong>.</div>
      </div>
    </div>`);
  }

  if (tabs.length === 0) {
    return `<div id="sec-diagrams" class="section-content">
      <div class="sec-h"><span class="sec-icon">◉</span> Diagrams</div>
      <p class="empty-state">No diagram data — add @exposes, @flows, or @mitigates annotations.</p>
    </div>`;
  }

  return `
<div id="sec-diagrams" class="section-content">
  <div class="sec-h"><span class="sec-icon">◉</span> Diagrams</div>
  <p class="diagram-hint">Interactive diagrams generated from annotations. Scroll to zoom, drag to pan, double-click to reset the view.</p>
  <div class="diagram-tabs">
    ${tabs.map((t, i) => `<button class="diagram-tab${i === 0 ? ' active' : ''}" onclick="switchDiagramTab('${t.id}', this)">${t.icon} ${t.label}</button>`).join('')}
  </div>
  ${panels.join('\n')}
</div>`;
}

function renderCodePage(fileAnnotations: FileAnnotationGroup[], model: ThreatModel): string {
  const unannotated = model.unannotated_files || [];
  const annotatedCount = model.annotated_files?.length || fileAnnotations.length;
  const totalFiles = annotatedCount + unannotated.length;
  return `
<div id="sec-code" class="section-content">
  <div class="sec-h"><span class="sec-icon">&lt;/&gt;</span> Code &amp; Annotations</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.8rem">
    Every file with GuardLink annotations. Click any annotation to see details.
  </p>
  ${fileAnnotations.length > 0 ? fileAnnotations.map((f, fi) => `
  <div class="file-card" data-ff="${esc(f.file)}">
    <div class="file-card-header" onclick="toggleFile(this)">
      <span class="file-path">${esc(f.file)}</span>
      <span style="display:flex;align-items:center;gap:.4rem">
        <span class="file-count">${f.annotations.length}</span>
        <span class="chevron">▶</span>
      </span>
    </div>
    <div class="file-card-body">
      ${f.annotations.map((ann, ai) => `
      <div class="ann-entry" onclick="openAnnotationDrawer(${fi}, ${ai})">
        <div class="ann-header">
          <span class="ann-line">L${ann.line}</span>
          <span class="ann-badge ann-${ann.kind}">${ann.kind}</span>
          <span class="ann-summary">${esc(ann.summary)}</span>
        </div>
        ${ann.description ? `<div class="ann-desc">${esc(ann.description)}</div>` : ''}
        ${ann.codeContext.length > 0 ? `<div class="code-block">${ann.codeContext.map((cl, ci) =>
          `<span class="${ci === ann.annLineIdx ? 'code-line-ann' : 'code-line-code'}">${esc(cl)}</span>`
        ).join('')}</div>` : ''}
      </div>`).join('')}
    </div>
  </div>`).join('') : '<p class="empty-state">No annotations found.</p>'}

  <!-- File Coverage Summary -->
  <div class="sub-h" style="margin-top:1.5rem">File Coverage</div>
  <div style="display:flex;align-items:center;gap:.8rem;margin-bottom:.3rem">
    <span style="font-size:.88rem;font-weight:600;color:${totalFiles > 0 && annotatedCount / totalFiles >= 0.7 ? 'var(--green)' : annotatedCount / totalFiles >= 0.4 ? 'var(--yellow)' : 'var(--red)'}">${annotatedCount} of ${totalFiles} files</span>
    <span style="color:var(--muted);font-size:.82rem">have GuardLink annotations</span>
  </div>
  ${totalFiles > 0 ? `<div class="posture-bar"><div class="posture-fill ${annotatedCount / totalFiles >= 0.7 ? 'good' : annotatedCount / totalFiles >= 0.4 ? 'warn' : 'bad'}" style="width:${Math.round(annotatedCount / totalFiles * 100)}%"></div></div>` : ''}

  ${unannotated.length > 0 ? `
  <div class="sub-h" style="color:var(--yellow);margin-top:1rem">⚠ Unannotated Files (${unannotated.length})</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">
    Source files with no GuardLink annotations. Not all files need annotations — only those touching security boundaries.
  </p>
  <div style="display:flex;flex-direction:column;gap:2px;margin-bottom:1rem">
    ${unannotated.map(f => `<div style="font-family:var(--font-mono);font-size:.78rem;padding:.3rem .6rem;background:var(--surface2);border-left:3px solid var(--yellow);border-radius:2px">${esc(f)}</div>`).join('')}
  </div>` : `<p style="color:var(--green);font-size:.82rem;margin-top:.5rem">✓ All source files have annotations.</p>`}
</div>`;
}

function renderDataPage(model: ThreatModel): string {
  return `
<div id="sec-data" class="section-content">
  <div class="sec-h"><span class="sec-icon">🔒</span> Data &amp; Boundaries</div>

  ${model.boundaries.length > 0 ? `
  <div class="sub-h">Trust Boundaries</div>
  <table>
    <thead><tr><th>Side A</th><th></th><th>Side B</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${model.boundaries.map(b => `
    <tr data-ff="${b.location ? esc(b.location.file) : ''}">
      <td><code>${esc(b.asset_a)}</code></td>
      <td style="color:var(--purple)">↔</td>
      <td><code>${esc(b.asset_b)}</code></td>
      <td>${esc(b.description || '—')}</td>
      <td class="loc">${b.location ? `${esc(b.location.file)}:${b.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.data_handling.length > 0 ? `
  <div class="sub-h">Data Classifications</div>
  <table>
    <thead><tr><th>Classification</th><th>Asset</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${model.data_handling.map(d => `
    <tr data-ff="${d.location ? esc(d.location.file) : ''}">
      <td><span class="ann-badge ann-data">${esc(d.classification)}</span></td>
      <td><code>${esc(d.asset || '—')}</code></td>
      <td>${esc(d.description || '—')}</td>
      <td class="loc">${d.location ? `${esc(d.location.file)}:${d.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.validations.length > 0 ? `
  <div class="sub-h">Validations (${model.validations.length})</div>
  <table>
    <thead><tr><th>Control</th><th>Asset</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${model.validations.map(v => `
    <tr data-ff="${v.location ? esc(v.location.file) : ''}">
      <td><code>${esc(v.control)}</code></td>
      <td><code>${esc(v.asset)}</code></td>
      <td>${esc(v.description || '—')}</td>
      <td class="loc">${v.location ? `${esc(v.location.file)}:${v.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.ownership.length > 0 ? `
  <div class="sub-h">Ownership (${model.ownership.length})</div>
  <table>
    <thead><tr><th>Asset</th><th>Owner</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${model.ownership.map(o => `
    <tr data-ff="${o.location ? esc(o.location.file) : ''}">
      <td><code>${esc(o.asset)}</code></td>
      <td><strong>${esc(o.owner)}</strong></td>
      <td>${esc(o.description || '—')}</td>
      <td class="loc">${o.location ? `${esc(o.location.file)}:${o.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.audits.length > 0 ? `
  <div class="sub-h">Audit Items (${model.audits.length})</div>
  <table>
    <thead><tr><th>Asset</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>
    ${model.audits.map(a => `
    <tr data-ff="${a.location ? esc(a.location.file) : ''}">
      <td><code>${esc(a.asset)}</code></td>
      <td>${esc(a.description || 'Needs review')}</td>
      <td class="loc">${a.location ? `${esc(a.location.file)}:${a.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.assumptions.length > 0 ? `
  <div class="sub-h">Assumptions (${model.assumptions.length})</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">Unverified assumptions that should be periodically reviewed.</p>
  <table>
    <thead><tr><th>Asset</th><th>Assumption</th><th>Location</th></tr></thead>
    <tbody>
    ${model.assumptions.map(a => `
    <tr data-ff="${a.location ? esc(a.location.file) : ''}">
      <td><code>${esc(a.asset)}</code></td>
      <td>${esc(a.description || 'Unverified assumption')}</td>
      <td class="loc">${a.location ? `${esc(a.location.file)}:${a.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.shields.length > 0 ? `
  <div class="sub-h">Shielded Regions (${model.shields.length})</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">Code regions where annotations are intentionally suppressed via <code>@shield</code>.</p>
  <table>
    <thead><tr><th>Reason</th><th>Location</th></tr></thead>
    <tbody>
    ${model.shields.map(s => `
    <tr data-ff="${s.location ? esc(s.location.file) : ''}">
      <td>${esc(s.reason || 'No reason provided')}</td>
      <td class="loc">${s.location ? `${esc(s.location.file)}:${s.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.comments.length > 0 ? `
  <div class="sub-h">Developer Comments (${model.comments.length})</div>
  <table>
    <thead><tr><th>Comment</th><th>Location</th></tr></thead>
    <tbody>
    ${model.comments.map(c => `
    <tr data-ff="${c.location ? esc(c.location.file) : ''}">
      <td>${esc(c.description || '(no description)')}</td>
      <td class="loc">${c.location ? `${esc(c.location.file)}:${c.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  ${model.boundaries.length === 0 && model.data_handling.length === 0 && model.comments.length === 0
    && model.validations.length === 0 && model.ownership.length === 0 && model.audits.length === 0
    && model.assumptions.length === 0 && model.shields.length === 0
    ? '<p class="empty-state">No data classifications, trust boundaries, or lifecycle annotations found.</p>' : ''}
</div>`;
}

function renderAssetsPage(heatmap: AssetHeatmapEntry[]): string {
  return `
<div id="sec-assets" class="section-content">
  <div class="sec-h"><span class="sec-icon">🗺</span> Asset Risk Heatmap</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.8rem">Assets sorted by risk level. Unmitigated exposures increase risk. Click an asset for details.</p>
  ${heatmap.length > 0 ? `
  <div class="heatmap">
    ${heatmap.map((a, i) => `
    <div class="heatmap-cell risk-cell-${a.riskLevel} clickable" data-ff-asset="${esc(a.name)}" onclick="openDrawer('asset', ${i})">
      <div class="heatmap-name">${esc(a.name)}</div>
      <div class="heatmap-stats">
        <span title="Exposures">⚠ ${a.exposures}</span>
        <span title="Mitigations">🛡 ${a.mitigations}</span>
        <span title="Data flows">↔ ${a.flows}</span>
      </div>
      ${a.dataHandling.length > 0 ? `<div class="heatmap-data">${a.dataHandling.map(d => `<span class="data-badge">${esc(d)}</span>`).join('')}</div>` : ''}
    </div>`).join('')}
  </div>` : '<p class="empty-state">No assets found.</p>'}
</div>`;
}

// ─── Data builders ───────────────────────────────────────────────────

interface FileAnnotation {
  kind: string;
  line: number;
  summary: string;
  description: string;
  raw: string;
  codeContext: string[];  // surrounding source lines with line numbers
  annLineIdx: number;     // which index in codeContext is the annotation line
}

interface FileAnnotationGroup {
  file: string;
  annotations: FileAnnotation[];
}

/** Read source file lines and extract context around a given line */
function readCodeContext(filePath: string, line: number, root?: string, contextLines = 5): { lines: string[]; annIdx: number } {
  try {
    const abs = root && !isAbsolute(filePath) ? resolve(root, filePath) : filePath;
    const content = readFileSync(abs, 'utf-8');
    const allLines = content.split('\n');
    const start = Math.max(0, line - 1 - contextLines);
    const end = Math.min(allLines.length, line + contextLines);
    const slice = allLines.slice(start, end).map((l, i) => {
      const lineNum = start + i + 1;
      return `${String(lineNum).padStart(4)} │ ${l}`;
    });
    return { lines: slice, annIdx: line - 1 - start };
  } catch {
    return { lines: [], annIdx: 0 };
  }
}

function buildFileAnnotations(model: ThreatModel, root?: string): FileAnnotationGroup[] {
  const byFile = new Map<string, FileAnnotation[]>();

  const addEntry = (kind: string, item: { location?: { file: string; line: number; raw_text?: string }; description?: string }, summary: string) => {
    if (!item.location) return;
    const file = item.location.file;
    if (!byFile.has(file)) byFile.set(file, []);
    const { lines: codeContext, annIdx } = readCodeContext(file, item.location.line, root);
    byFile.get(file)!.push({
      kind,
      line: item.location.line,
      summary,
      description: item.description || '',
      raw: (item.location as any).raw_text || '',
      codeContext,
      annLineIdx: annIdx,
    });
  };

  for (const a of model.assets) addEntry('asset', a as any, a.path.join('.'));
  for (const t of model.threats) addEntry('threat', t as any, t.name);
  for (const c of model.controls) addEntry('control', c as any, c.name);
  for (const e of model.exposures) addEntry('exposes', e as any, `${e.asset} → ${e.threat}`);
  for (const cf of (model.confirmed || [])) addEntry('confirmed', cf as any, `${cf.asset} confirmed ${cf.threat}`);
  for (const m of model.mitigations) addEntry('mitigates', m as any, `${m.control} mitigates ${m.threat}`);
  for (const a of model.acceptances) addEntry('accepts', a as any, `${a.asset} accepts ${a.threat}`);
  for (const t of model.transfers) addEntry('transfers', t as any, `${t.source} → ${t.target}`);
  for (const f of model.flows) addEntry('flow', f as any, `${f.source} → ${f.target}`);
  for (const b of model.boundaries) addEntry('boundary', b as any, `${b.asset_a} ↔ ${b.asset_b}`);
  for (const h of model.data_handling) addEntry('handles', h as any, `${h.asset}: ${h.classification}`);
  for (const v of model.validations) addEntry('validates', v as any, `${v.control} validates ${v.asset}`);
  for (const o of model.ownership) addEntry('owns', o as any, `${o.owner} owns ${o.asset}`);
  for (const a of model.audits) addEntry('audit', a as any, `Audit: ${a.asset}`);
  for (const a of model.assumptions) addEntry('assumes', a as any, `Assumes: ${a.asset}`);
  for (const s of model.shields) addEntry('shield', s as any, s.reason || 'Shielded region');
  for (const c of model.comments) addEntry('comment', c as any, c.description || 'Developer note');

  const result: FileAnnotationGroup[] = [];
  for (const [file, anns] of [...byFile.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    result.push({ file, annotations: anns.sort((a, b) => a.line - b.line) });
  }
  return result;
}

function buildAnalysisData(model: ThreatModel, exposures: ExposureRow[]) {
  return {
    openExposures: exposures.filter(e => !e.mitigated && !e.accepted),
    mitigatedExposures: exposures.filter(e => e.mitigated),
    acceptedExposures: exposures.filter(e => e.accepted),
  };
}

// ─── Template helpers ────────────────────────────────────────────────

function esc(s: string): string {
  return (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function statCard(value: number, label: string, variant = ''): string {
  return `<div class="stat-card${variant ? ` stat-${variant}` : ''}"><div class="value">${value}</div><div class="label">${label}</div></div>`;
}

function severityBar(label: string, count: number, total: number, cls: string): string {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return `<div class="sev-row">
    <span class="sev-label">${label}</span>
    <div class="sev-track"><div class="sev-fill sev-fill-${cls}" style="width:${pct}%"></div></div>
    <span class="sev-count">${count}</span>
  </div>`;
}

function sevClass(s: string): string {
  const l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'crit';
  if (l === 'high' || l === 'p1') return 'high';
  if (l === 'medium' || l === 'p2') return 'med';
  if (l === 'low' || l === 'p3') return 'low';
  return 'unset';
}

function computeRiskGrade(sev: SeverityBreakdown, unmitigatedCount: number, totalExposures: number, confirmedCount: number = 0) {
  if (confirmedCount > 0) return { grade: 'F', label: 'Critical Risk', summary: `${confirmedCount} confirmed exploitable finding(s) — immediate remediation required` };
  if (sev.critical > 0) return { grade: 'F', label: 'Critical Risk', summary: `${sev.critical} critical exposure(s) require immediate attention` };
  if (sev.high >= 3 || unmitigatedCount >= 5) return { grade: 'D', label: 'High Risk', summary: `${unmitigatedCount} unmitigated exposure(s), ${sev.high} high severity` };
  if (sev.high >= 1 || unmitigatedCount >= 3) return { grade: 'C', label: 'Moderate Risk', summary: `${unmitigatedCount} unmitigated exposure(s) need remediation` };
  if (unmitigatedCount >= 1) return { grade: 'B', label: 'Low Risk', summary: `${unmitigatedCount} minor unmitigated exposure(s)` };
  if (totalExposures === 0) return { grade: 'A', label: 'Excellent', summary: 'No exposures detected — consider adding more annotations' };
  return { grade: 'A', label: 'Excellent', summary: 'All exposures mitigated or accepted' };
}

// ─── CSS ─────────────────────────────────────────────────────────────

const CSS_CONTENT = `
/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
*::selection { background: color-mix(in oklab, var(--accent) 35%, transparent); color: var(--text); }
:root {
  --font-ui: 'Inter', system-ui, -apple-system, sans-serif;
  --font-mono: 'JetBrains Mono', 'SF Mono', Menlo, Consolas, monospace;
  --ease: cubic-bezier(.2,.8,.2,1);
  --radius-sm: 6px; --radius-md: 8px; --radius-lg: 12px;
  --drawer-w: 440px; --sidebar-w: 220px;
}

/* ══ DARK THEME — Modern deep-slate ══ */
[data-theme="dark"] {
  --bg: #000000;
  --bg-gradient: radial-gradient(ellipse 1000px 500px at 15% 0%, rgba(51,212,157,.09), transparent 58%),
                 radial-gradient(ellipse 800px 400px at 95% 10%, rgba(3,96,162,.10), transparent 60%);
  --surface: #0f1b20;
  --surface2: #172930;
  --surface3: #1f3943;
  --border: #1f3943;
  --border-subtle: #1a3139;
  --border-strong: #55899e;

  --text: #f0f0f0;
  --muted: #55899e;
  --text-dim: #3b6779;

  --accent: #33d49d;
  --accent-soft: rgba(51,212,157,.12);
  --accent-dim: rgba(51,212,157,.22);
  --accent-hover: #ffffff;

  --blue: #0360a2;
  --green: #33d49d;
  --red: #ea1d1d;
  --orange: #ea1d1d;
  --yellow: #55899e;
  --purple: #0360a2;

  --sev-crit: #ea1d1d;
  --sev-high: #ea1d1d;
  --sev-med:  #55899e;
  --sev-low:  #0360a2;
  --sev-unset:#3b6779;

  --sev-crit-bg: rgba(234,29,29,.14);
  --sev-high-bg: rgba(234,29,29,.10);
  --sev-med-bg:  rgba(85,137,158,.16);
  --sev-low-bg:  rgba(3,96,162,.16);

  --badge-red-bg:   rgba(234,29,29,.16);
  --badge-green-bg: rgba(51,212,157,.16);
  --badge-blue-bg:  rgba(3,96,162,.16);
  --badge-red-fg:   #f0f0f0;
  --badge-green-fg: #33d49d;
  --badge-blue-fg:  #f0f0f0;

  --risk-f: linear-gradient(135deg, rgba(234,29,29,.20), rgba(234,29,29,.05));
  --risk-d: linear-gradient(135deg, rgba(234,29,29,.14), rgba(234,29,29,.04));
  --risk-c: linear-gradient(135deg, rgba(85,137,158,.18), rgba(85,137,158,.05));
  --risk-b: linear-gradient(135deg, rgba(3,96,162,.18), rgba(3,96,162,.05));
  --risk-a: linear-gradient(135deg, rgba(51,212,157,.20), rgba(51,212,157,.05));
  --risk-border-f: rgba(234,29,29,.40);
  --risk-border-d: rgba(234,29,29,.28);
  --risk-border-c: rgba(85,137,158,.35);
  --risk-border-b: rgba(3,96,162,.35);
  --risk-border-a: rgba(51,212,157,.35);

  --heatmap-crit: linear-gradient(135deg, rgba(234,29,29,.20), rgba(234,29,29,.05));
  --heatmap-high: linear-gradient(135deg, rgba(234,29,29,.14), rgba(234,29,29,.04));
  --heatmap-med:  linear-gradient(135deg, rgba(85,137,158,.16), rgba(85,137,158,.04));
  --heatmap-low:  linear-gradient(135deg, rgba(3,96,162,.16), rgba(3,96,162,.04));
  --heatmap-none: #172930;

  --table-alt: #13232a;
  --table-hover: #1c323a;
  --shadow-sm: 0 1px 2px rgba(0,0,0,.3);
  --shadow-md: 0 4px 12px rgba(0,0,0,.35), 0 1px 2px rgba(0,0,0,.4);
  --shadow-lg: 0 12px 32px rgba(0,0,0,.45), 0 2px 6px rgba(0,0,0,.4);
  --glow-accent: 0 0 0 1px rgba(45,212,191,.25), 0 8px 24px rgba(45,212,191,.12);

  --logo-bg: linear-gradient(135deg, #33d49d, #0360a2);
  --logo-text: #000000;
}

/* ══ LIGHT THEME — Refined off-white ══ */
[data-theme="light"] {
  --bg: #f0f0f0;
  --bg-gradient: radial-gradient(ellipse 1000px 500px at 15% 0%, rgba(51,212,157,.10), transparent 58%),
                 radial-gradient(ellipse 800px 400px at 95% 10%, rgba(3,96,162,.08), transparent 60%);
  --surface: #ffffff;
  --surface2: #f0f0f0;
  --surface3: #e8eef0;
  --border: #55899e;
  --border-subtle: #d9e4e8;
  --border-strong: #1f3943;

  --text: #1f3943;
  --muted: #55899e;
  --text-dim: #3b6779;

  --accent: #33d49d;
  --accent-soft: rgba(51,212,157,.12);
  --accent-dim: rgba(51,212,157,.20);
  --accent-hover: #0360a2;

  --blue: #0360a2;
  --green: #33d49d;
  --red: #ea1d1d;
  --orange: #ea1d1d;
  --yellow: #55899e;
  --purple: #0360a2;

  --sev-crit: #ea1d1d;
  --sev-high: #ea1d1d;
  --sev-med:  #3b6779;
  --sev-low:  #0360a2;
  --sev-unset:#55899e;

  --sev-crit-bg: rgba(234,29,29,.10);
  --sev-high-bg: rgba(234,29,29,.08);
  --sev-med-bg:  rgba(59,103,121,.10);
  --sev-low-bg:  rgba(3,96,162,.10);

  --badge-red-bg:   rgba(234,29,29,.12);
  --badge-green-bg: rgba(51,212,157,.14);
  --badge-blue-bg:  rgba(3,96,162,.14);
  --badge-red-fg:   #ea1d1d;
  --badge-green-fg: #1f3943;
  --badge-blue-fg:  #0360a2;

  --risk-f: linear-gradient(135deg, rgba(234,29,29,.12), rgba(234,29,29,.02));
  --risk-d: linear-gradient(135deg, rgba(234,29,29,.09), rgba(234,29,29,.02));
  --risk-c: linear-gradient(135deg, rgba(59,103,121,.12), rgba(59,103,121,.02));
  --risk-b: linear-gradient(135deg, rgba(3,96,162,.12), rgba(3,96,162,.02));
  --risk-a: linear-gradient(135deg, rgba(51,212,157,.14), rgba(51,212,157,.02));
  --risk-border-f: rgba(234,29,29,.28);
  --risk-border-d: rgba(234,29,29,.2);
  --risk-border-c: rgba(59,103,121,.26);
  --risk-border-b: rgba(3,96,162,.24);
  --risk-border-a: rgba(51,212,157,.28);

  --heatmap-crit: linear-gradient(135deg, rgba(234,29,29,.14), rgba(234,29,29,.02));
  --heatmap-high: linear-gradient(135deg, rgba(234,29,29,.10), rgba(234,29,29,.02));
  --heatmap-med:  linear-gradient(135deg, rgba(59,103,121,.10), rgba(59,103,121,.02));
  --heatmap-low:  linear-gradient(135deg, rgba(3,96,162,.10), rgba(3,96,162,.02));
  --heatmap-none: #f0f0f0;

  --table-alt: #f7f9fa;
  --table-hover: #edf3f5;
  --shadow-sm: 0 1px 2px rgba(15,23,42,.04);
  --shadow-md: 0 4px 12px rgba(15,23,42,.06), 0 1px 2px rgba(15,23,42,.04);
  --shadow-lg: 0 12px 32px rgba(15,23,42,.08), 0 2px 6px rgba(15,23,42,.04);
  --glow-accent: 0 0 0 1px rgba(13,148,136,.20), 0 8px 24px rgba(13,148,136,.10);

  --logo-bg: linear-gradient(135deg, #33d49d, #0360a2);
  --logo-text: #ffffff;
}

html, body { height: 100%; }
body {
  font-family: var(--font-ui);
  background: var(--bg-gradient), var(--bg);
  color: var(--text);
  line-height: 1.5;
  font-size: 13.5px;
  overflow: hidden;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  letter-spacing: -0.005em;
}
a { color: var(--accent); text-decoration: none; transition: color .15s var(--ease); }
a:hover { color: var(--accent-hover); }
code {
  background: var(--surface2);
  border: 1px solid var(--border-subtle);
  padding: 1px 5px;
  border-radius: 4px;
  font-size: .76rem;
  font-family: var(--font-mono);
  color: var(--text);
}
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; border: 2px solid var(--bg); }
::-webkit-scrollbar-thumb:hover { background: var(--border-strong); }

/* ── Top Nav ── */
.topnav {
  height: 52px;
  background: color-mix(in oklab, var(--surface) 92%, transparent);
  backdrop-filter: saturate(160%) blur(12px);
  -webkit-backdrop-filter: saturate(160%) blur(12px);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center;
  padding: 0 1.4rem; gap: 1rem;
  z-index: 100;
  position: relative;
}
.topnav::after {
  content: ''; position: absolute; left: 0; right: 0; bottom: -1px; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent-dim) 40%, var(--accent-dim) 60%, transparent);
  opacity: .55; pointer-events: none;
}
.topnav-left { display: flex; align-items: center; gap: .7rem; }
.topnav-right { margin-left: auto; display: flex; align-items: center; gap: .75rem; }
.topnav-metrics { display: flex; align-items: center; gap: .5rem; }
.topnav h1 { font-size: 1.02rem; font-weight: 650; white-space: nowrap; letter-spacing: -0.01em; }
.badge {
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--accent-dim);
  padding: 2px 9px; border-radius: 999px;
  font-size: .64rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: .6px;
}
.tn-stat {
  font-size: .72rem; color: var(--muted); display: flex; align-items: center; gap: 6px;
  background: color-mix(in oklab, var(--surface2) 88%, transparent);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 4px 10px;
  backdrop-filter: blur(4px);
}
.tn-stat .tn-k { letter-spacing: .2px; }
.tn-stat .tn-v { font-weight: 700; font-size: .85rem; color: var(--text); font-variant-numeric: tabular-nums; }
.tn-v.red { color: var(--sev-crit); } .tn-v.green { color: var(--green); }
.tn-v.blue { color: var(--accent); } .tn-v.yellow { color: var(--yellow); }
.feature-filter-wrap { display: flex; align-items: center; }
.feature-filter-select {
  max-width: 170px;
  background: var(--surface2);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 5px 10px;
  font-size: .74rem;
  font-family: var(--font-ui);
  cursor: pointer;
  transition: all .15s var(--ease);
}
.feature-filter-select:hover { border-color: var(--border-strong); background: var(--surface3); }
.feature-filter-select:focus { outline: none; border-color: var(--accent); box-shadow: var(--glow-accent); }
.logo {
  width: 34px; height: 34px;
  background: var(--logo-bg); color: var(--logo-text);
  border-radius: 9px;
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: 12px; letter-spacing: .3px;
  box-shadow: var(--shadow-sm);
}
#themeToggle {
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: 8px; padding: 5px 9px; cursor: pointer;
  font-size: 14px; line-height: 1; color: var(--text);
  transition: all .15s var(--ease);
}
#themeToggle:hover { background: var(--surface3); border-color: var(--border-strong); }
[data-theme="dark"] .icon-sun { display: none; }
[data-theme="light"] .icon-moon { display: none; }
.feature-banner {
  display: none;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: color-mix(in oklab, var(--accent) 88%, var(--surface));
  color: #fff;
  font-size: .8rem;
  font-weight: 600;
  border-bottom: 1px solid color-mix(in oklab, var(--accent) 45%, var(--border));
}
.feature-banner-files { opacity: .75; font-weight: 500; }
.feature-banner-clear {
  margin-left: auto;
  background: rgba(255,255,255,.18);
  border: 1px solid rgba(255,255,255,.28);
  color: #fff;
  padding: 4px 10px;
  border-radius: 999px;
  cursor: pointer;
  font-size: .72rem;
  font-weight: 600;
}
.feature-banner-clear:hover { background: rgba(255,255,255,.28); }

/* ── Layout ── */
.layout { display: flex; height: calc(100vh - 54px); position: relative; }
.sidebar {
  width: var(--sidebar-w); min-width: var(--sidebar-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  transition: width .25s var(--ease), min-width .25s var(--ease);
}
.sidebar-nav { flex: 1; overflow-y: auto; padding: .75rem .55rem; }
.sidebar.collapsed { width: 52px; min-width: 52px; }
.sidebar.collapsed .nav-text { display: none; }
.sidebar.collapsed .sep { margin: .5rem .5rem; }
.sidebar.collapsed .chevron-left { display: none; }
.sidebar.collapsed .chevron-right { display: block; }
#sidebarToggle {
  background: transparent; border: none; border-top: 1px solid var(--border);
  padding: .7rem; cursor: pointer; color: var(--muted);
  transition: all .15s var(--ease);
  display: flex; align-items: center; justify-content: center; width: 100%;
}
#sidebarToggle:hover { background: var(--surface2); color: var(--accent); }
#sidebarToggle svg { display: block; }
#sidebarToggle .chevron-right { display: none; }
.sidebar a {
  display: flex; align-items: center; gap: .65rem;
  padding: .52rem .75rem; margin: 1px .1rem;
  font-size: .8rem; color: var(--muted); cursor: pointer;
  border-radius: 7px;
  transition: background .12s var(--ease), color .12s var(--ease);
  user-select: none;
  position: relative;
}
.sidebar a:hover { background: var(--surface2); color: var(--text); }
.sidebar a.active {
  color: var(--accent);
  background: var(--accent-soft);
  font-weight: 550;
}
.sidebar a.active::before {
  content: ''; position: absolute; left: -.1rem; top: 20%; bottom: 20%; width: 2px;
  background: var(--accent); border-radius: 2px;
}
.sidebar .nav-icon { width: 18px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; opacity: .85; }
.sidebar a.active .nav-icon { opacity: 1; }
.sidebar .nav-icon svg { display: block; }
.sidebar .sep { height: 1px; background: var(--border); margin: .6rem .8rem; }
.main { flex: 1; overflow-y: auto; padding: 0; }
.section-content { display: none; padding: 1.6rem 2rem 3rem; max-width: 1400px; }
.section-content.active { display: block; animation: fadeIn .2s var(--ease); }
@keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: none; } }
.panel {
  background: color-mix(in oklab, var(--surface) 94%, transparent);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 1rem 1.1rem;
  box-shadow: var(--shadow-sm);
  margin-bottom: 1rem;
}
.panel-row { display: flex; align-items: center; gap: .8rem; margin-bottom: .35rem; }
.panel-muted { color: var(--muted); font-size: .82rem; }
.summary-panels {
  display: grid;
  grid-template-columns: minmax(250px, 1fr) minmax(320px, 1.3fr);
  gap: .9rem;
}
.ai-analysis-panel { padding-top: .9rem; }

/* ── Drawer ── */
.drawer-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,.48);
  backdrop-filter: blur(2px);
  -webkit-backdrop-filter: blur(2px);
  z-index: 200; display: none;
}
.drawer-overlay.open { display: block; animation: fadeIn .15s var(--ease); }
.drawer {
  position: fixed; top: 0; right: 0;
  width: var(--drawer-w); height: 100vh;
  background: var(--surface);
  border-left: 1px solid var(--border);
  z-index: 201;
  transform: translateX(100%);
  transition: transform .28s var(--ease);
  overflow-y: auto;
  box-shadow: var(--shadow-lg);
}
.drawer.open { transform: translateX(0); }
.drawer-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1rem 1.2rem;
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
  background: color-mix(in oklab, var(--surface) 94%, transparent);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  z-index: 1;
}
.drawer-header h3 { font-size: .95rem; color: var(--text); font-weight: 650; letter-spacing: -.01em; }
.drawer-close {
  background: var(--surface2); border: 1px solid var(--border);
  color: var(--muted); cursor: pointer;
  padding: 5px 11px; border-radius: 6px; font-size: .78rem;
  transition: all .15s var(--ease);
}
.drawer-close:hover { color: var(--text); border-color: var(--border-strong); background: var(--surface3); }
.drawer-body { padding: 1.2rem; }
.d-section { margin-bottom: 1.2rem; }
.d-label { font-size: .68rem; text-transform: uppercase; color: var(--muted); letter-spacing: .8px; margin-bottom: .35rem; font-weight: 600; }
.d-value { font-size: .85rem; }
.d-code {
  background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-md);
  padding: .65rem .8rem; font-family: var(--font-mono); font-size: .72rem;
  line-height: 1.65; color: var(--muted); white-space: pre; overflow-x: auto;
}

/* ── Section headings ── */
.sec-h {
  font-size: 1.25rem; font-weight: 700;
  margin-bottom: 1rem;
  display: flex; align-items: center; gap: .6rem;
  letter-spacing: -.02em;
}
.sec-icon {
  font-size: 1rem;
  width: 30px; height: 30px;
  display: inline-flex; align-items: center; justify-content: center;
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--accent-dim);
  border-radius: 8px;
}
.sub-h {
  font-size: .78rem; font-weight: 600; color: var(--muted);
  margin: 1.2rem 0 .55rem 0;
  text-transform: uppercase; letter-spacing: .7px;
  display: flex; align-items: center; gap: .5rem;
}
.sub-h::after {
  content: ''; flex: 1; height: 1px;
  background: linear-gradient(90deg, var(--border), transparent);
}
.sub-h-alert { color: var(--red); }
.sub-h-critical { color: var(--sev-crit); }
.sub-h-ok { color: var(--green); }
.sub-h-neutral { color: var(--yellow); }
.sub-h-info { color: var(--blue); }
.section-note { color: var(--muted); font-size: .78rem; margin-bottom: .55rem; }
.flow-arrow { color: var(--muted); font-weight: 700; font-size: .88rem; text-align: center; }

/* ── Stats Grid ── */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(118px, 1fr)); gap: .6rem; margin-bottom: 1.2rem; }
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: .75rem .7rem;
  text-align: center;
  transition: transform .15s var(--ease), border-color .15s var(--ease), box-shadow .15s var(--ease);
  position: relative; overflow: hidden;
}
.stat-card::before {
  content: ''; position: absolute; inset: 0 0 auto 0; height: 2px;
  background: var(--accent); opacity: 0; transition: opacity .15s var(--ease);
}
.stat-card:hover { transform: translateY(-1px); border-color: var(--border-strong); box-shadow: var(--shadow-sm); }
.stat-card:hover::before { opacity: .8; }
.stat-card .value { font-size: 1.5rem; font-weight: 700; color: var(--accent); font-variant-numeric: tabular-nums; letter-spacing: -.02em; line-height: 1.1; }
.stat-card .label { font-size: .68rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .4px; font-weight: 500; }
.stat-danger .value { color: var(--sev-crit); } .stat-danger::before { background: var(--sev-crit); }
.stat-success .value { color: var(--green); } .stat-success::before { background: var(--green); }
.stat-muted .value { color: var(--muted); } .stat-muted::before { background: var(--muted); }
.stat-muted .label { color: var(--text-dim); }

/* ── Risk Banner ── */
.risk-banner {
  display: flex; align-items: center; gap: 22px;
  padding: 18px 22px;
  border-radius: var(--radius-lg);
  border: 1px solid var(--border);
  margin-bottom: 1.2rem;
  box-shadow: var(--shadow-sm);
}
.risk-grade {
  font-size: 34px; font-weight: 800;
  width: 58px; height: 58px;
  display: flex; align-items: center; justify-content: center;
  border-radius: var(--radius-md);
  letter-spacing: -.03em;
  box-shadow: 0 6px 16px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.15);
}
.risk-detail { display: flex; flex-direction: column; gap: 3px; }
.risk-detail strong { font-size: 15px; font-weight: 650; letter-spacing: -.01em; }
.risk-detail span { font-size: 13px; color: var(--muted); }
.risk-f { background: var(--risk-f); border-color: var(--risk-border-f); } .risk-f .risk-grade { background: var(--sev-crit); color: #fff; }
.risk-d { background: var(--risk-d); border-color: var(--risk-border-d); } .risk-d .risk-grade { background: var(--sev-high); color: #fff; }
.risk-c { background: var(--risk-c); border-color: var(--risk-border-c); } .risk-c .risk-grade { background: var(--sev-med); color: #fff; }
.risk-b { background: var(--risk-b); border-color: var(--risk-border-b); } .risk-b .risk-grade { background: var(--sev-low); color: #fff; }
.risk-a { background: var(--risk-a); border-color: var(--risk-border-a); } .risk-a .risk-grade { background: var(--green); color: #fff; }

/* ── Coverage Bar ── */
.coverage-pct { font-size: 2rem; font-weight: 700; font-variant-numeric: tabular-nums; letter-spacing: -.03em; }
.coverage-pct.good { color: var(--green); } .coverage-pct.warn { color: var(--yellow); } .coverage-pct.bad { color: var(--sev-crit); }
.posture-bar { height: 10px; border-radius: 999px; background: var(--surface2); margin: .7rem 0; overflow: hidden; border: 1px solid var(--border-subtle); }
.posture-fill { height: 100%; border-radius: 999px; transition: width .6s var(--ease); }
.posture-fill.good { background: linear-gradient(90deg, var(--green), var(--accent)); }
.posture-fill.warn { background: linear-gradient(90deg, var(--yellow), var(--muted)); }
.posture-fill.bad  { background: linear-gradient(90deg, var(--sev-crit), var(--red)); }

/* ── Severity Chart ── */
.severity-chart { display: flex; flex-direction: column; gap: 9px; margin-bottom: 1rem; }
.sev-row { display: flex; align-items: center; gap: 12px; }
.sev-label { width: 62px; font-size: 12.5px; font-weight: 550; text-align: right; color: var(--muted); }
.sev-track { flex: 1; height: 22px; background: var(--surface2); border-radius: 6px; overflow: hidden; border: 1px solid var(--border-subtle); }
.sev-fill { height: 100%; border-radius: 6px; min-width: 2px; transition: width .6s var(--ease); }
.sev-fill-crit { background: linear-gradient(90deg, var(--sev-crit), var(--red)); }
.sev-fill-high { background: linear-gradient(90deg, var(--sev-high), var(--red)); }
.sev-fill-med  { background: linear-gradient(90deg, var(--sev-med), var(--text-dim)); }
.sev-fill-low  { background: linear-gradient(90deg, var(--sev-low), var(--blue)); }
.sev-fill-unset { background: var(--sev-unset); }
.sev-count { width: 32px; font-size: 14px; font-weight: 700; font-family: var(--font-mono); color: var(--text); font-variant-numeric: tabular-nums; }

/* ── Finding Cards ── */
.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: .8rem 1rem;
  margin-bottom: .55rem;
  cursor: pointer;
  transition: all .15s var(--ease);
  position: relative;
}
.finding-card::before {
  content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--sev-crit); border-radius: 3px 0 0 3px;
  opacity: .7;
}
.finding-card:hover {
  border-color: var(--border-strong);
  transform: translateX(2px);
  box-shadow: var(--shadow-sm);
}
.fc-top { display: flex; align-items: center; gap: .55rem; margin-bottom: .25rem; }
.fc-risk { font-weight: 600; font-size: .88rem; letter-spacing: -.005em; }
.fc-desc { font-size: .8rem; color: var(--muted); line-height: 1.5; }
.fc-assets { font-size: .72rem; color: var(--muted); margin-top: .3rem; font-family: var(--font-mono); }
.fc-sev {
  font-size: .66rem;
  padding: 2px 8px;
  border-radius: 999px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .4px;
  border: 1px solid transparent;
}
.fc-sev.crit  { background: var(--sev-crit-bg); color: var(--sev-crit); border-color: color-mix(in oklab, var(--sev-crit) 35%, transparent); }
.fc-sev.high  { background: var(--sev-high-bg); color: var(--sev-high); border-color: color-mix(in oklab, var(--sev-high) 35%, transparent); }
.fc-sev.med   { background: var(--sev-med-bg);  color: var(--sev-med);  border-color: color-mix(in oklab, var(--sev-med) 35%, transparent); }
.fc-sev.low   { background: var(--sev-low-bg);  color: var(--sev-low);  border-color: color-mix(in oklab, var(--sev-low) 35%, transparent); }
.fc-sev.unset { background: var(--surface2);    color: var(--muted);    border-color: var(--border); }

/* ── Tables ── */
table {
  width: 100%; border-collapse: separate; border-spacing: 0;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
  margin-bottom: 1rem;
  box-shadow: var(--shadow-sm);
}
th, td { padding: .6rem .85rem; text-align: left; border-bottom: 1px solid var(--border-subtle); font-size: .8rem; }
tr:last-child td { border-bottom: none; }
th {
  background: var(--surface2);
  color: var(--muted); font-weight: 650;
  text-transform: uppercase; font-size: .66rem; letter-spacing: .7px;
  position: sticky; top: 0;
}
tbody tr { transition: background .12s var(--ease); }
tbody tr:nth-child(even) { background: var(--table-alt); }
tr.clickable { cursor: pointer; }
tr.clickable:hover { background: var(--table-hover); }
.row-open { box-shadow: inset 3px 0 0 var(--sev-crit); }
.loc { color: var(--muted); font-family: var(--font-mono); font-size: .72rem; white-space: nowrap; }
.empty-state {
  color: var(--muted); font-style: italic;
  padding: 1.2rem;
  font-size: .82rem; text-align: center;
  background: var(--surface); border: 1px dashed var(--border);
  border-radius: var(--radius-md);
}

/* ── Badges ── */
.badge-red, .badge-green, .badge-blue {
  display: inline-block; padding: 2px 9px;
  border-radius: 999px;
  font-size: .66rem; font-weight: 650;
  text-transform: uppercase; letter-spacing: .4px;
  border: 1px solid transparent;
}
.badge-red   { background: var(--badge-red-bg);   color: var(--badge-red-fg);   border-color: color-mix(in oklab, var(--sev-crit) 25%, transparent); }
.badge-green { background: var(--badge-green-bg); color: var(--badge-green-fg); border-color: color-mix(in oklab, var(--green) 25%, transparent); }
.badge-blue  { background: var(--badge-blue-bg);  color: var(--badge-blue-fg);  border-color: color-mix(in oklab, var(--sev-low) 25%, transparent); }

/* ── Annotation badges (theme-aware) ── */
.ann-badge {
  display: inline-block; padding: 2px 8px;
  border-radius: 5px;
  font-size: .66rem; font-weight: 650;
  text-transform: uppercase; letter-spacing: .35px;
  border: 1px solid transparent;
}
.ann-asset    { background: rgba(3,96,162,.14);    color: #f0f0f0; border-color: rgba(3,96,162,.3); }
.ann-threat   { background: rgba(234,29,29,.14);   color: #f0f0f0; border-color: rgba(234,29,29,.3); }
.ann-control  { background: rgba(51,212,157,.14);  color: #33d49d; border-color: rgba(51,212,157,.3); }
.ann-exposes  { background: rgba(234,29,29,.14);   color: #f0f0f0; border-color: rgba(234,29,29,.3); }
.ann-mitigates{ background: rgba(51,212,157,.14);  color: #33d49d; border-color: rgba(51,212,157,.3); }
.ann-accepts  { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-transfers{ background: rgba(59,103,121,.18);  color: #f0f0f0; border-color: rgba(59,103,121,.3); }
.ann-flow     { background: var(--surface2);       color: var(--muted); border-color: var(--border); }
.ann-boundary { background: rgba(59,103,121,.18);  color: #f0f0f0; border-color: rgba(59,103,121,.3); }
.ann-data     { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-handles  { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-validates{ background: rgba(51,212,157,.14);  color: #33d49d; border-color: rgba(51,212,157,.3); }
.ann-owns     { background: rgba(3,96,162,.14);    color: #f0f0f0; border-color: rgba(3,96,162,.3); }
.ann-audit    { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-assumes  { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-shield   { background: var(--surface2);       color: var(--muted); border-color: var(--border); }
.ann-comment  { background: var(--surface2);       color: var(--muted); border: 1px solid var(--border); }
[data-theme="light"] .ann-asset    { color: #0360a2; background: rgba(3,96,162,.10); border-color: rgba(3,96,162,.25); }
[data-theme="light"] .ann-threat,
[data-theme="light"] .ann-exposes  { color: #ea1d1d; background: rgba(234,29,29,.10); border-color: rgba(234,29,29,.25); }
[data-theme="light"] .ann-control,
[data-theme="light"] .ann-mitigates,
[data-theme="light"] .ann-validates{ color: #1f3943; background: rgba(51,212,157,.16); border-color: rgba(51,212,157,.25); }
[data-theme="light"] .ann-accepts,
[data-theme="light"] .ann-audit,
[data-theme="light"] .ann-assumes  { color: #3b6779; background: rgba(85,137,158,.14); border-color: rgba(85,137,158,.25); }
[data-theme="light"] .ann-transfers,
[data-theme="light"] .ann-boundary { color: #1f3943; background: rgba(59,103,121,.12); border-color: rgba(59,103,121,.25); }
[data-theme="light"] .ann-data,
[data-theme="light"] .ann-handles  { color: #3b6779; background: rgba(85,137,158,.14); border-color: rgba(85,137,158,.25); }
[data-theme="light"] .ann-owns     { color: #0360a2; background: rgba(3,96,162,.10); border-color: rgba(3,96,162,.25); }

/* ── File Cards (Code Browser) ── */
.file-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: .7rem;
  overflow: hidden;
  transition: border-color .15s var(--ease);
}
.file-card:hover { border-color: var(--border-strong); }
.file-card-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: .65rem .9rem;
  background: var(--surface2);
  cursor: pointer; user-select: none;
  transition: background .12s var(--ease);
}
.file-card-header:hover { background: var(--surface3); }
.file-path { font-family: var(--font-mono); font-size: .78rem; color: var(--accent); font-weight: 600; }
.file-count {
  font-size: .68rem; color: var(--muted);
  background: var(--surface); border: 1px solid var(--border);
  padding: 2px 9px; border-radius: 999px; font-weight: 600;
}
.chevron { color: var(--muted); transition: transform .2s var(--ease); font-size: .75rem; }
.file-card-header.open .chevron { transform: rotate(90deg); }
.file-card-body { display: none; border-top: 1px solid var(--border); }
.file-card-body.open { display: block; animation: fadeIn .2s var(--ease); }
.ann-entry {
  padding: .7rem .9rem;
  border-bottom: 1px solid var(--border-subtle);
  cursor: pointer;
  transition: background .1s var(--ease);
}
.ann-entry:hover { background: var(--accent-soft); }
.ann-entry:last-child { border-bottom: none; }
.ann-header { display: flex; align-items: center; gap: .5rem; margin-bottom: .25rem; }
.ann-line { font-family: var(--font-mono); font-size: .68rem; color: var(--muted); min-width: 38px; }
.ann-summary { font-size: .8rem; font-weight: 550; }
.ann-desc {
  font-size: .76rem; color: var(--muted);
  margin: .2rem 0 .3rem 0;
  padding-left: .6rem; border-left: 2px solid var(--border);
}

/* ── Diagrams ── */
.diagram-hint { font-size: .78rem; color: var(--muted); margin-bottom: .7rem; }
.diagram-shell {
  background: color-mix(in oklab, var(--surface) 92%, transparent);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
  margin-bottom: 1rem;
}
.diagram-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: .8rem;
  padding: .65rem .8rem;
  border-bottom: 1px solid var(--border);
  background: color-mix(in oklab, var(--surface2) 92%, transparent);
}
.diagram-title {
  font-size: .8rem;
  font-weight: 650;
  letter-spacing: .3px;
  color: var(--text);
  text-transform: uppercase;
}
.diagram-actions { display: flex; align-items: center; gap: .35rem; }
.diagram-btn {
  min-width: 28px;
  height: 28px;
  border-radius: 7px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  font-size: .78rem;
  font-weight: 650;
  cursor: pointer;
  transition: all .15s var(--ease);
}
.diagram-btn:hover { border-color: var(--border-strong); background: var(--surface3); }
.diagram-meta {
  padding: .55rem .8rem;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: .74rem;
}
.mermaid-wrap {
  background: var(--surface);
  border: none;
  border-radius: 0;
  padding: 16px 18px;
  overflow: auto;
  margin-bottom: 0;
  box-shadow: none;
}
.mermaid { text-align: left; width: max-content; min-width: 100%; }
.mermaid svg { max-width: none; height: auto; display: block; }
.mermaid svg .cluster rect,
.mermaid svg .cluster polygon {
  rx: 10;
  ry: 10;
  stroke-dasharray: 4 3;
  stroke-opacity: .72;
}
.mermaid svg .cluster-label .nodeLabel,
.mermaid svg .cluster .cluster-label text {
  font-weight: 700 !important;
  letter-spacing: .3px;
}
.mermaid svg .edgeLabel { font-size: 11px !important; }
.mermaid svg .edgeLabel rect { opacity: .92; }
.mermaid svg .node rect,
.mermaid svg .node polygon,
.mermaid svg .node circle {
  filter: drop-shadow(0 2px 4px rgba(0,0,0,.18));
}
.mermaid svg path.flowchart-link {
  stroke-linecap: round;
}

/* ── Heatmap ── */
.heatmap { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }
.heatmap-cell {
  border-radius: var(--radius-md);
  padding: 14px;
  border: 1px solid var(--border);
  transition: all .15s var(--ease);
  box-shadow: var(--shadow-sm);
}
.heatmap-cell.clickable { cursor: pointer; }
.heatmap-cell.clickable:hover {
  border-color: var(--border-strong);
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}
.heatmap-name { font-weight: 650; font-size: 13px; margin-bottom: 6px; font-family: var(--font-mono); word-break: break-all; color: var(--text); }
.heatmap-stats { display: flex; gap: 12px; font-size: 12px; color: var(--muted); }
.heatmap-data { margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; }
.data-badge {
  font-size: 10px; padding: 2px 7px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--accent-dim);
  font-weight: 650; text-transform: uppercase; letter-spacing: .3px;
}
.risk-cell-critical { background: var(--heatmap-crit); border-color: var(--risk-border-f); }
.risk-cell-high     { background: var(--heatmap-high); border-color: var(--risk-border-d); }
.risk-cell-medium   { background: var(--heatmap-med);  border-color: var(--risk-border-c); }
.risk-cell-low      { background: var(--heatmap-low);  border-color: var(--risk-border-b); }
.risk-cell-none     { background: var(--heatmap-none); }

/* ── Code Blocks ── */
.code-block {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: .4rem .7rem;
  overflow-x: auto;
  margin-top: .3rem;
  font-family: var(--font-mono);
  font-size: .72rem; line-height: 1.5;
  tab-size: 2;
}
.code-line-code { display: block; color: var(--muted); white-space: pre; }
.code-line-ann {
  display: block; color: var(--accent);
  background: var(--accent-soft);
  margin: 0 -.7rem; padding: 0 .7rem;
  border-left: 2px solid var(--accent);
  white-space: pre;
}

/* ── Diagram Tabs ── */
.diagram-tabs { display: flex; gap: .25rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; padding: 0 .2rem; }
.diagram-tab {
  background: none; border: none; border-bottom: 2px solid transparent;
  padding: .55rem 1rem; color: var(--muted);
  font-size: .82rem; font-weight: 550;
  cursor: pointer; font-family: var(--font-ui);
  transition: all .15s var(--ease);
  border-radius: 6px 6px 0 0;
}
.diagram-tab:hover { color: var(--text); background: var(--surface2); }
.diagram-tab.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
  background: var(--accent-soft);
}
.diagram-panel { display: none; } .diagram-panel.active { display: block; }

/* ── AI Analysis Controls ── */
.ai-analysis-controls { display: flex; align-items: center; gap: .85rem; margin: .75rem 0 1.5rem; }
.report-selector-label { font-weight: 600; font-size: .85rem; color: var(--text); }
.report-selector {
  flex: 1; max-width: 600px;
  padding: .55rem .85rem;
  font-size: .88rem; font-family: var(--font-ui);
  background: var(--surface);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  transition: all .15s var(--ease);
  box-shadow: var(--shadow-sm);
}
.report-selector:hover { background: var(--surface2); border-color: var(--border-strong); }
.report-selector:focus {
  outline: none; border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.report-selector option { background: var(--surface); color: var(--text); padding: .5rem; }
.ai-analysis-main { margin-top: .5rem; }

/* ── Markdown content ── */
.md-content h1 { font-size: 1.5rem; font-weight: 700; margin: 1.3rem 0 .7rem; color: var(--text); letter-spacing: -.02em; }
.md-content h2 {
  font-size: 1.2rem; font-weight: 650; margin: 1.2rem 0 .6rem;
  color: var(--text); border-bottom: 1px solid var(--border);
  padding-bottom: .4rem; letter-spacing: -.01em;
}
.md-content h3 { font-size: 1.02rem; font-weight: 650; margin: 1rem 0 .45rem; color: var(--text); letter-spacing: -.01em; }
.md-content p { margin: .5rem 0; line-height: 1.65; color: var(--text); }
.md-content ul, .md-content ol { margin: .5rem 0 .5rem 1.6rem; }
.md-content li { margin: .25rem 0; line-height: 1.6; }
.md-content code { font-family: var(--font-mono); font-size: .82rem; background: var(--surface2); border: 1px solid var(--border-subtle); padding: 1px 6px; border-radius: 4px; }
.md-content pre { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-md); padding: .9rem 1rem; overflow-x: auto; margin: .8rem 0; box-shadow: var(--shadow-sm); }
.md-content pre code { background: none; padding: 0; border: none; font-size: .8rem; }
.md-content blockquote { border-left: 3px solid var(--accent); padding: .1rem 0 .1rem .9rem; margin: .7rem 0; color: var(--muted); background: var(--accent-soft); border-radius: 0 6px 6px 0; }
.md-content table { width: 100%; border-collapse: separate; border-spacing: 0; margin: .7rem 0; font-size: .82rem; border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }
.md-content th, .md-content td { padding: .5rem .75rem; border-bottom: 1px solid var(--border-subtle); text-align: left; }
.md-content tr:last-child td { border-bottom: none; }
.md-content th { background: var(--surface2); font-weight: 650; color: var(--muted); text-transform: uppercase; font-size: .68rem; letter-spacing: .5px; }
.md-content strong { color: var(--text); font-weight: 650; }

/* ── Responsive ── */
@media (max-width: 900px) {
  .section-content { padding: 1.2rem 1rem 2rem; }
  .summary-panels { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
  .sidebar { width: 52px; min-width: 52px; } .sidebar .nav-text { display: none; }
  .topnav .topnav-metrics { display: none; }
  .feature-filter-select { max-width: 130px; }
  .risk-banner { flex-direction: column; align-items: flex-start; gap: 12px; }
  :root { --drawer-w: 100vw; }
}
@media print {
  .topnav, .sidebar, #sidebarToggle, #themeToggle { display: none; }
  .main { margin: 0; } .layout { display: block; }
  body { overflow: auto; height: auto; background: #fff; color: #000; }
}
`;
