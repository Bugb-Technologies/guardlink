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
 * @handles internal on #dashboard -- "Processes and displays threat model data"
 * @feature "Dashboard" -- "Interactive HTML threat model dashboard"
 */

import type { ThreatModel } from '../types/index.js';
import { listFeatures } from '../parser/feature-filter.js';
import { computeStats, computeSeverity, computeExposures, computeConfirmed, computeAssetHeatmap } from './data.js';
import type { DashboardStats, SeverityBreakdown, ExposureRow, ConfirmedRow, AssetHeatmapEntry } from './data.js';
import { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from './diagrams.js';
import type { ThreatReportWithContent, PentestData } from '../analyze/index.js';
import { readFileSync } from 'fs';
import { resolve, isAbsolute } from 'path';

export function generateDashboardHTML(model: ThreatModel, root?: string, analyses?: ThreatReportWithContent[], pentestData?: PentestData): string {
  const stats = computeStats(model);
  const severity = computeSeverity(model);
  const exposures = computeExposures(model);
  const confirmedRows = computeConfirmed(model);
  const heatmap = computeAssetHeatmap(model);
  const threatGraph = generateThreatGraph(model);
  const dataFlow = generateDataFlowDiagram(model);
  const attackSurface = generateAttackSurface(model);
  const featureNames = listFeatures(model);
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
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

  // Pentest data (may be null/empty)
  const pentest = pentestData || { scans: [], templates: [], totalFindings: 0, findingsBySeverity: {} };

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
    <div class="tn-stat"><span>Assets</span> <span class="tn-v blue">${stats.assets}</span></div>
    <div class="tn-stat"><span>Open</span> <span class="tn-v red">${unmitigated.length}</span></div>
    <div class="tn-stat"><span>Controls</span> <span class="tn-v green">${stats.controls}</span></div>
    <div class="tn-stat"><span>Coverage</span> <span class="tn-v ${stats.coveragePercent >= 70 ? 'green' : stats.coveragePercent >= 40 ? 'yellow' : 'red'}">${stats.coveragePercent}%</span></div>
${featureNames.length > 0 ? `    <div class="tn-stat feature-filter-wrap">
      <select id="featureFilter" onchange="applyFeatureFilter(this.value)" title="Filter by feature" style="background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;padding:2px 6px;font-size:.75rem;font-family:var(--font-ui);cursor:pointer;max-width:160px">
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
<div id="feature-banner" style="display:none;align-items:center;gap:8px;padding:6px 16px;background:var(--accent);color:#fff;font-size:.82rem;font-weight:500">
  <span>Filtered to feature:</span>
  <strong id="feature-banner-name"></strong>
  <span id="feature-banner-files" style="opacity:.7"></span>
  <button onclick="document.getElementById('featureFilter').value='';applyFeatureFilter('')" style="margin-left:auto;background:rgba(255,255,255,.2);border:none;color:#fff;padding:2px 8px;border-radius:3px;cursor:pointer;font-size:.75rem">Clear Filter</button>
</div>

<div class="layout">

<!-- ═══════════ SIDEBAR ═══════════ -->
<nav class="sidebar" id="sidebar">
  <div class="sidebar-nav">
    <a class="active" onclick="showSection('summary',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 2l6 4v6l-6 4-6-4V6l6-4z"/></svg></span> <span class="nav-text">Executive Summary</span></a>
    <a onclick="showSection('ai-analysis',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1l2 5h5l-4 3 2 5-5-3-5 3 2-5-4-3h5l2-5z"/></svg></span> <span class="nav-text">Threat Reports</span></a>
    <a onclick="showSection('pentest',this)"><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 2a1.5 1.5 0 110 3 1.5 1.5 0 010-3zM6 7h4v1.5H8.5V13h-1V8.5H6V7z"/></svg></span> <span class="nav-text">Pentest Findings</span></a>
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
${renderPentestPage(pentest)}
${renderThreatsPage(exposures, confirmedRows, model)}
${renderDiagramsPage(threatGraph, dataFlow, attackSurface)}
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
const pentestData = ${JSON.stringify(pentest).replace(/<\//g, '<\\/')};
const heatmapData = ${JSON.stringify(heatmap).replace(/<\//g, '<\\/')};
const threatModel = ${JSON.stringify(model).replace(/<\//g, '<\\/')};
/* ===== SECTION NAV ===== */
function showSection(id, el) {
  document.querySelectorAll('.section-content').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
  const sec = document.getElementById('sec-' + id);
  if (sec) sec.classList.add('active');
  if (el) el.classList.add('active');
  closeDrawer();
  if (id === 'diagrams' && !window._mermaidRendered) {
    setTimeout(() => { renderMermaid(); }, 100);
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

function openPentestDrawer(scanIdx, findingIdx) {
  var title = document.getElementById('drawer-title');
  var body = document.getElementById('drawer-body');
  var scan = pentestData.scans[scanIdx];
  if (!scan) return;
  var f = scan.findings[findingIdx];
  if (!f) return;
  title.textContent = f.title;
  var h = '';
  var sevColor = f.severity === 'critical' ? 'var(--sev-crit)' : f.severity === 'high' ? 'var(--sev-high)' : f.severity === 'medium' ? 'var(--sev-med)' : 'var(--sev-low)';
  h += sec('Severity', '<span style="color:' + sevColor + ';font-weight:600;text-transform:uppercase">' + esc(f.severity) + '</span>');
  h += sec('Confidence', '<span style="font-weight:600">' + f.confidence + '%</span>');
  h += sec('Template', '<code>' + esc(f.template_id) + '</code>');
  if (f.cwe_ids && f.cwe_ids.length) h += sec('CWE', f.cwe_ids.map(function(c){return '<code>' + esc(c) + '</code>'}).join(', '));
  h += sec('Description', '<div style="line-height:1.5">' + esc(f.description) + '</div>');

  // Evidence section
  if (f.evidence) {
    h += '<div class="sub-h" style="margin-top:1rem">Evidence</div>';
    if (f.evidence.request) {
      h += sec('Request / Payload', '<div class="code-block" style="max-height:200px;overflow:auto;white-space:pre-wrap">' + esc(String(f.evidence.request).slice(0, 2000)) + '</div>');
    }
    if (f.evidence.response) {
      h += sec('Response / Output', '<div class="code-block" style="max-height:200px;overflow:auto;white-space:pre-wrap">' + esc(String(f.evidence.response).slice(0, 2000)) + '</div>');
    }
    if (f.evidence.matched_patterns && f.evidence.matched_patterns.length) {
      h += sec('Matched Patterns', f.evidence.matched_patterns.map(function(p){return '<span class="ann-badge ann-threat" style="margin-right:4px;margin-bottom:2px">' + esc(String(p)) + '</span>'}).join(''));
    }
    if (f.evidence.data && Object.keys(f.evidence.data).length > 0) {
      var dataHtml = '<table style="font-size:.75rem"><tbody>';
      Object.keys(f.evidence.data).forEach(function(k) {
        var val = f.evidence.data[k];
        var vs = typeof val === 'string' ? val : JSON.stringify(val);
        if (vs && vs.length > 500) vs = vs.slice(0, 500) + '...';
        dataHtml += '<tr><td style="font-weight:600;white-space:nowrap;vertical-align:top;padding-right:.5rem">' + esc(k) + '</td><td style="word-break:break-all">' + esc(vs) + '</td></tr>';
      });
      dataHtml += '</tbody></table>';
      h += sec('Evidence Data', dataHtml);
    }
  }

  if (f.remediation) h += sec('Remediation', '<div style="line-height:1.5;white-space:pre-line">' + esc(f.remediation) + '</div>');
  h += sec('Scan ID', '<code style="font-size:.72rem">' + esc(scan.scan_id) + '</code>');
  h += sec('Timestamp', esc(f.timestamp || scan.completed_at || ''));

  body.innerHTML = h;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
}

function openTemplateDrawer(idx) {
  var title = document.getElementById('drawer-title');
  var body = document.getElementById('drawer-body');
  var t = pentestData.templates[idx];
  if (!t) return;
  title.textContent = t.id;
  var h = '';
  h += sec('File', '<code>' + esc(t.filename) + '</code>');
  h += sec('Language', '<span class="ann-badge ann-control">' + esc(t.language) + '</span>');
  h += sec('Severity', '<span class="fc-sev ' + (t.severity === 'critical' ? 'crit' : t.severity === 'high' ? 'high' : t.severity === 'medium' ? 'med' : 'low') + '">' + esc(t.severity) + '</span>');
  if (t.tags && t.tags.length) h += sec('Tags', t.tags.map(function(tag){return '<span class="ann-badge ann-asset" style="margin-right:4px">' + esc(tag) + '</span>'}).join(''));

  // Find related findings
  var relatedFindings = [];
  pentestData.scans.forEach(function(scan) {
    scan.findings.forEach(function(f) {
      if (f.template_id === t.id) relatedFindings.push(f);
    });
  });
  if (relatedFindings.length > 0) {
    h += '<div class="sub-h" style="margin-top:1rem;color:var(--red)">Findings from this Template (' + relatedFindings.length + ')</div>';
    relatedFindings.forEach(function(f) {
      var sc = f.severity === 'critical' ? 'var(--sev-crit)' : f.severity === 'high' ? 'var(--sev-high)' : f.severity === 'medium' ? 'var(--sev-med)' : 'var(--sev-low)';
      h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid ' + sc + ';padding:0.5rem 0.8rem;border-radius:4px;margin-bottom:0.5rem">';
      h += '<strong>' + esc(f.title) + '</strong>';
      h += '<div style="font-size:.75rem;color:var(--muted);margin-top:.2rem">' + esc(f.description.slice(0, 200)) + '</div>';
      h += '</div>';
    });
  } else {
    h += sec('Findings', '<span class="empty-state">No findings from this template yet — run CXG scan to test</span>');
  }

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
    renderMermaid();
  }
}

/* ===== DIAGRAM TABS ===== */
function switchDiagramTab(id, btn) {
  document.querySelectorAll('.diagram-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.diagram-tab').forEach(t => t.classList.remove('active'));
  const panel = document.getElementById('dtab-' + id);
  if (panel) panel.classList.add('active');
  if (btn) btn.classList.add('active');
  // Always re-render mermaid for newly visible panel
  setTimeout(() => { renderMermaidPanel(panel); }, 50);
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
      primaryColor: '#1a2228', primaryTextColor: '#f0f0f0', primaryBorderColor: '#3b6779',
      lineColor: '#55899e', secondaryColor: '#1e2830', tertiaryColor: '#0d1117',
      background: '#0a0d10', mainBkg: '#1a2228', nodeBorder: '#3b6779',
      clusterBkg: '#0d1117', clusterBorder: '#1f3943', fontSize: '12px', fontFamily: 'var(--font-ui)'
    } : {
      primaryColor: '#e8f4f8', primaryTextColor: '#1a1a2e', primaryBorderColor: '#94a3b8',
      lineColor: '#64748b', secondaryColor: '#f1f5f9', tertiaryColor: '#ffffff',
      background: '#ffffff', mainBkg: '#e8f4f8', nodeBorder: '#94a3b8',
      clusterBkg: '#f8fafc', clusterBorder: '#cbd5e1', fontSize: '12px', fontFamily: 'var(--font-ui)'
    },
    flowchart: { curve: 'basis', padding: 15, nodeSpacing: 40, rankSpacing: 50, htmlLabels: false, useMaxWidth: false },
    securityLevel: 'loose',
  });
  return mermaid;
}

async function renderMermaidPanel(panel) {
  if (!panel) return;
  const mermaid = await getMermaidInstance();
  const els = panel.querySelectorAll('.mermaid');
  
  // Re-run mermaid
  els.forEach(el => {
    el.removeAttribute('data-processed');
    el.innerHTML = el.getAttribute('data-original') || el.textContent;
  });
  await mermaid.run({ nodes: Array.from(els) });
  
  // Add interactive zoom/pan to the rendered SVG
  if (typeof d3 !== 'undefined') {
    els.forEach(el => {
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

  <!-- Coverage Bar -->
  <div class="sub-h">Threat Mitigation Coverage</div>
  <div style="display:flex;align-items:center;gap:.8rem;margin-bottom:.3rem">
    <span class="coverage-pct ${mitigationCoveragePercent >= 70 ? 'good' : mitigationCoveragePercent >= 40 ? 'warn' : 'bad'}">${mitigationCoveragePercent}%</span>
    <span style="color:var(--muted);font-size:.82rem">${mitigatedCount} of ${exposures.length} exposures mitigated</span>
  </div>
  <div class="posture-bar"><div class="posture-fill ${mitigationCoveragePercent >= 70 ? 'good' : mitigationCoveragePercent >= 40 ? 'warn' : 'bad'}" style="width:${Math.min(mitigationCoveragePercent, 100)}%"></div></div>

  <!-- Severity Breakdown -->
  <div class="sub-h">Severity Breakdown</div>
  <div class="severity-chart">
    ${severityBar('Critical', severity.critical, stats.exposures, 'crit')}
    ${severityBar('High', severity.high, stats.exposures, 'high')}
    ${severityBar('Medium', severity.medium, stats.exposures, 'med')}
    ${severityBar('Low', severity.low, stats.exposures, 'low')}
    ${severity.unset > 0 ? severityBar('Unset', severity.unset, stats.exposures, 'unset') : ''}
  </div>

  ${unmitigated.length > 0 ? `
  <!-- Open Threats -->
  <div class="sub-h" style="color:var(--red)">⚠ Open Threats (No Mitigation)</div>
  ${unmitigated.map((e, i) => `
  <div class="finding-card" data-ff="${esc(e.file)}" onclick="openDrawer('open_exposure', ${i})">
    <div class="fc-top">
      <span class="fc-risk">${esc(e.threat)}</span>
      <span class="fc-sev ${sevClass(e.severity)}">${esc(e.severity)}</span>
    </div>
    ${e.description ? `<div class="fc-desc">${esc(e.description)}</div>` : ''}
    <div class="fc-assets">Asset: ${esc(e.asset)}</div>
  </div>`).join('')}` : ''}

  ${model.flows.length > 0 ? `
  <!-- Data Flows -->
  <div class="sub-h">Data Flows</div>
  <table>
    <thead><tr><th>Source</th><th></th><th>Target</th><th>Mechanism</th><th>Location</th></tr></thead>
    <tbody>
    ${model.flows.map(f => `
    <tr data-ff="${f.location ? esc(f.location.file) : ''}">
      <td><code>${esc(f.source)}</code></td>
      <td style="color:var(--muted)">→</td>
      <td><code>${esc(f.target)}</code></td>
      <td>${esc(f.mechanism || '—')}</td>
      <td class="loc">${f.location ? `${esc(f.location.file)}:${f.location.line}` : ''}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}
</div>`;
}

function renderAIAnalysisPage(analyses: ThreatReportWithContent[]): string {
  return `
<div id="sec-ai-analysis" class="section-content">
  <div class="sec-h"><span class="sec-icon">✨</span> Threat Reports</div>
  <div class="ai-analysis-controls">
    <label for="report-selector" class="report-selector-label">Select Report:</label>
    <select id="report-selector" class="report-selector" aria-label="Select threat report"></select>
  </div>
  <div id="ai-content" class="md-content ai-analysis-main"></div>
</div>`;
}

function renderPentestPage(pentest: PentestData): string {
  const hasScanData = pentest.scans.length > 0;
  const hasTemplates = pentest.templates.length > 0;
  const latestScan = pentest.scans[0];

  let findingsHtml = '';
  if (hasScanData) {
    pentest.scans.forEach((scan, si) => {
      const scanDate = scan.completed_at ? scan.completed_at.slice(0, 19).replace('T', ' ') : 'unknown';
      const duration = scan.statistics?.duration
        ? `${scan.statistics.duration.secs}s`
        : '?';
      findingsHtml += `
      <div style="margin-bottom:1.5rem">
        <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.5rem">
          <span style="font-weight:600;font-size:.9rem">Scan ${esc(scan.scan_id.slice(0, 8))}</span>
          <span style="font-size:.72rem;color:var(--muted)">${esc(scanDate)} &middot; ${esc(duration)} &middot; ${scan.findings.length} finding(s)</span>
          <span style="font-size:.68rem;color:var(--muted);background:var(--surface2);padding:1px 6px;border-radius:4px">${esc(scan.source_file)}</span>
        </div>`;

      if (scan.findings.length > 0) {
        findingsHtml += `
        <table>
          <thead><tr><th>Severity</th><th>Title</th><th>Template</th><th>CWE</th><th>Confidence</th></tr></thead>
          <tbody>
          ${scan.findings.map((f, fi) => `
          <tr class="clickable" onclick="openPentestDrawer(${si}, ${fi})">
            <td><span class="fc-sev ${f.severity === 'critical' ? 'crit' : f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'med' : 'low'}">${esc(f.severity)}</span></td>
            <td>${esc(f.title)}</td>
            <td><code style="font-size:.72rem">${esc(f.template_id)}</code></td>
            <td>${f.cwe_ids?.length ? f.cwe_ids.map(c => `<code style="font-size:.7rem">${esc(c)}</code>`).join(' ') : '—'}</td>
            <td>${f.confidence}%</td>
          </tr>`).join('')}
          </tbody>
        </table>`;
      } else {
        findingsHtml += '<p class="empty-state">No findings in this scan — all checks passed.</p>';
      }
      findingsHtml += '</div>';
    });
  }

  let templatesHtml = '';
  if (hasTemplates) {
    templatesHtml = `
    <div class="sub-h">Templates (${pentest.templates.length})</div>
    <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">CXG templates in <code>.guardlink/cxg-templates/</code> — click for details.</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px">
      ${pentest.templates.map((t, i) => `
      <div class="finding-card" onclick="openTemplateDrawer(${i})">
        <div class="fc-top">
          <span class="fc-risk">${esc(t.id)}</span>
          <span class="fc-sev ${t.severity === 'critical' ? 'crit' : t.severity === 'high' ? 'high' : t.severity === 'medium' ? 'med' : 'low'}">${esc(t.severity)}</span>
        </div>
        <div class="fc-assets">${esc(t.filename)} &middot; ${esc(t.language)}</div>
        ${t.tags.length > 0 ? `<div style="margin-top:.3rem">${t.tags.slice(0, 4).map(tag => `<span class="data-badge">${esc(tag)}</span>`).join(' ')}</div>` : ''}
      </div>`).join('')}
    </div>`;
  }

  const sevBreakdown = pentest.findingsBySeverity;
  const maxSevCount = Math.max(1, ...Object.values(sevBreakdown));

  return `
<div id="sec-pentest" class="section-content">
  <div class="sec-h"><span class="sec-icon">🔬</span> Pentest Findings</div>

  ${hasScanData || hasTemplates ? `
  <!-- Stats bar -->
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:1.2rem">
    <div class="stat-card stat-red"><span class="value">${pentest.totalFindings}</span><span class="label">Total Findings</span></div>
    <div class="stat-card"><span class="value">${sevBreakdown['critical'] || 0}</span><span class="label" style="color:var(--sev-crit)">Critical</span></div>
    <div class="stat-card"><span class="value">${sevBreakdown['high'] || 0}</span><span class="label" style="color:var(--sev-high)">High</span></div>
    <div class="stat-card"><span class="value">${sevBreakdown['medium'] || 0}</span><span class="label" style="color:var(--sev-med)">Medium</span></div>
    <div class="stat-card"><span class="value">${sevBreakdown['low'] || 0}</span><span class="label" style="color:var(--sev-low)">Low</span></div>
    <div class="stat-card stat-muted"><span class="value">${pentest.templates.length}</span><span class="label">Templates</span></div>
    <div class="stat-card stat-muted"><span class="value">${pentest.scans.length}</span><span class="label">Scans</span></div>
  </div>

  ${hasScanData ? `
  <div class="sub-h" style="color:var(--red)">Findings (${pentest.totalFindings})</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">Results from CXG security scans — click a finding for full evidence details.</p>
  ${findingsHtml}
  ` : ''}

  ${templatesHtml}
  ` : `
  <div class="empty-state" style="text-align:center;padding:3rem 1rem">
    <div style="font-size:3rem;margin-bottom:1rem;opacity:0.5">🔬</div>
    <div style="font-size:1.1rem;font-weight:600;margin-bottom:0.5rem">No Pentest Data Yet</div>
    <div style="color:var(--muted);margin-bottom:1.5rem">Generate CXG templates and run scans to see findings here</div>
    <div style="display:flex;flex-direction:column;gap:0.5rem;max-width:550px;margin:0 auto;text-align:left">
      <div style="font-size:0.88rem;color:var(--muted)"><strong>Step 1 — Generate templates:</strong></div>
      <code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink translate "Create templates for critical threats" --claude-code</code>
      <div style="font-size:0.88rem;color:var(--muted);margin-top:0.5rem"><strong>Step 2 — Run CXG scan:</strong></div>
      <code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">cxg scan --scope local://. --template-dir .guardlink/cxg-templates/ --output .guardlink/pentest-findings/guardlink-pentest --output-format json,sarif</code>
      <div style="font-size:0.88rem;color:var(--muted);margin-top:0.5rem"><strong>Step 3 — View results:</strong></div>
      <code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink dashboard</code>
    </div>
  </div>`}
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
  <div class="sub-h" style="color:var(--sev-crit, #e74c3c)">🔴 Confirmed Exploitable (${confirmed.length})</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">Verified through pentest, scanning, or manual reproduction — <strong>not false positives</strong>.</p>
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

  <div class="sub-h" style="color:var(--red)">Open Threats (${open.length})</div>
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">Exposed in code but <strong>not mitigated</strong> by any control.</p>
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

  <div class="sub-h" style="color:var(--green)">Mitigated Threats (${mitigated.length})</div>
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
  <div class="sub-h" style="color:var(--yellow)">Accepted Risks (${accepted.length})</div>
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
  <div class="sub-h" style="color:var(--purple)">Transferred Risks (${model.transfers.length})</div>
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

function renderDiagramsPage(threatGraph: string, dataFlow: string, attackSurface: string): string {
  const tabs = [];
  const panels = [];

  if (threatGraph) {
    tabs.push({ id: 'threat-graph', label: 'Threat Graph', icon: '🔷' });
    panels.push(`<div id="dtab-threat-graph" class="diagram-panel active"><div class="mermaid-wrap"><pre class="mermaid">\n${threatGraph}\n</pre></div></div>`);
  }
  if (dataFlow) {
    tabs.push({ id: 'data-flow', label: 'Data Flow', icon: '↔' });
    panels.push(`<div id="dtab-data-flow" class="diagram-panel"><div class="mermaid-wrap"><pre class="mermaid">\n${dataFlow}\n</pre></div></div>`);
  }
  if (attackSurface) {
    tabs.push({ id: 'attack-surface', label: 'Attack Surface', icon: '⚠' });
    panels.push(`<div id="dtab-attack-surface" class="diagram-panel"><div class="mermaid-wrap"><pre class="mermaid">\n${attackSurface}\n</pre></div></div>`);
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
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.8rem">Interactive diagrams from annotations. Scroll to zoom, drag to pan, double-click to reset.</p>
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
:root { --font-ui: 'Inter', system-ui, -apple-system, sans-serif; --font-mono: 'JetBrains Mono', 'SF Mono', Menlo, Consolas, monospace; }

/* ══ DARK THEME (Bravos) ══ */
[data-theme="dark"] {
  --bg: #0a0d10; --surface: #0d1117; --surface2: #1a1f25; --border: #1f3943; --border-subtle: #162028;
  --text: #f0f0f0; --muted: #55899e; --text-dim: #3b6779;
  --accent: #2dd4a7; --blue: #0360a2; --green: #10b981; --red: #ea1d1d;
  --orange: #f97316; --yellow: #f59e0b; --purple: #a78bfa;
  --sev-crit: #ef4444; --sev-high: #f97316; --sev-med: #f59e0b; --sev-low: #3b82f6; --sev-unset: #6b7280;
  --badge-red-bg: #7f1d1d; --badge-green-bg: #065f46; --badge-blue-bg: #1e3a5f;
  --risk-f: #7f1d1d; --risk-d: #7c2d12; --risk-c: #78350f; --risk-b: #1e3a5f; --risk-a: #065f46;
  --heatmap-crit: #7f1d1d; --heatmap-high: #7c2d12; --heatmap-med: #78350f;
  --heatmap-low: #1e3a5f; --heatmap-none: #1a1f25;
  --table-alt: #141a20; --table-hover: #1e2830; --shadow: 0 1px 3px rgba(0,0,0,.4);
  --logo-bg: #2dd4a7; --logo-text: #0a0d10;
  --drawer-w: 420px; --sidebar-w: 210px;
}

/* ══ LIGHT THEME ══ */
[data-theme="light"] {
  --bg: #f8fafc; --surface: #ffffff; --surface2: #f1f5f9; --border: #d1d5db; --border-subtle: #e5e7eb;
  --text: #1a1a2e; --muted: #4a5568; --text-dim: #9ca3af;
  --accent: #0d9373; --blue: #2563eb; --green: #059669; --red: #dc2626;
  --orange: #ea580c; --yellow: #d97706; --purple: #7c3aed;
  --sev-crit: #dc2626; --sev-high: #ea580c; --sev-med: #d97706; --sev-low: #2563eb; --sev-unset: #6b7280;
  --badge-red-bg: #fef2f2; --badge-green-bg: #ecfdf5; --badge-blue-bg: #eff6ff;
  --risk-f: #fef2f2; --risk-d: #fff7ed; --risk-c: #fffbeb; --risk-b: #eff6ff; --risk-a: #ecfdf5;
  --heatmap-crit: #fef2f2; --heatmap-high: #fff7ed; --heatmap-med: #fffbeb;
  --heatmap-low: #eff6ff; --heatmap-none: #f9fafb;
  --table-alt: #f9fafb; --table-hover: #f1f5f9; --shadow: 0 1px 3px rgba(0,0,0,.08);
  --logo-bg: #0d9373; --logo-text: #ffffff;
  --drawer-w: 420px; --sidebar-w: 210px;
}

body { font-family: var(--font-ui); background: var(--bg); color: var(--text); line-height: 1.5; overflow: hidden; height: 100vh; }
a { color: var(--accent); text-decoration: none; }
code { background: var(--border); padding: 1px 4px; border-radius: 3px; font-size: .75rem; font-family: var(--font-mono); }

/* ── Top Nav ── */
.topnav { height: 48px; background: var(--surface); border-bottom: 1px solid var(--border); display: flex; align-items: center; padding: 0 1.2rem; gap: 1rem; z-index: 100; }
.topnav-left { display: flex; align-items: center; gap: .6rem; }
.topnav-right { margin-left: auto; display: flex; align-items: center; gap: 1rem; }
.topnav h1 { font-size: 1.1rem; font-weight: 700; white-space: nowrap; }
.badge { background: var(--accent); color: var(--logo-text); padding: 2px 8px; border-radius: 10px; font-size: .65rem; font-weight: 600; }
.tn-stat { font-size: .72rem; color: var(--muted); display: flex; align-items: center; gap: 4px; }
.tn-stat .tn-v { font-weight: 700; font-size: .82rem; }
.tn-v.red { color: var(--red); } .tn-v.green { color: var(--green); } .tn-v.blue { color: var(--accent); } .tn-v.yellow { color: var(--yellow); }
.logo { width: 32px; height: 32px; background: var(--logo-bg); color: var(--logo-text); border-radius: 6px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; }
#themeToggle { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 4px 8px; cursor: pointer; font-size: 14px; line-height: 1; }
#themeToggle:hover { background: var(--border); }
[data-theme="dark"] .icon-sun { display: none; }
[data-theme="light"] .icon-moon { display: none; }

/* ── Layout ── */
.layout { display: flex; height: calc(100vh - 48px); position: relative; }
.sidebar { width: var(--sidebar-w); min-width: var(--sidebar-w); background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; transition: all .25s ease; }
.sidebar-nav { flex: 1; overflow-y: auto; padding: .6rem 0; }
.sidebar.collapsed { width: 50px; min-width: 50px; }
.sidebar.collapsed .nav-text { display: none; }
.sidebar.collapsed .sep { margin: .5rem .5rem; }
.sidebar.collapsed .chevron-left { display: none; }
.sidebar.collapsed .chevron-right { display: block; }
#sidebarToggle { background: var(--surface2); border: none; border-top: 1px solid var(--border); padding: .8rem; cursor: pointer; color: var(--muted); transition: all .2s; display: flex; align-items: center; justify-content: center; width: 100%; }
#sidebarToggle:hover { background: var(--border); color: var(--accent); }
#sidebarToggle svg { display: block; }
#sidebarToggle .chevron-right { display: none; }
.sidebar a { display: flex; align-items: center; gap: .6rem; padding: .55rem 1rem; font-size: .8rem; color: var(--muted); cursor: pointer; border-left: 3px solid transparent; transition: all .12s; user-select: none; }
.sidebar a:hover { background: var(--surface2); color: var(--text); }
.sidebar a.active { color: var(--accent); border-left-color: var(--accent); background: rgba(45,212,167,.08); }
.sidebar .nav-icon { width: 20px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.sidebar .nav-icon svg { display: block; }
.sidebar .sep { height: 1px; background: var(--border); margin: .5rem 1rem; }
.main { flex: 1; overflow-y: auto; padding: 0; }
.section-content { display: none; padding: 1.2rem 1.5rem; } .section-content.active { display: block; }

/* ── Drawer ── */
.drawer-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,.4); z-index: 200; display: none; }
.drawer-overlay.open { display: block; }
.drawer { position: fixed; top: 0; right: 0; width: var(--drawer-w); height: 100vh; background: var(--surface); border-left: 1px solid var(--border); z-index: 201; transform: translateX(100%); transition: transform .25s ease; overflow-y: auto; }
.drawer.open { transform: translateX(0); }
.drawer-header { display: flex; align-items: center; justify-content: space-between; padding: .8rem 1rem; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--surface); z-index: 1; }
.drawer-header h3 { font-size: .95rem; color: var(--accent); }
.drawer-close { background: none; border: 1px solid var(--border); color: var(--muted); cursor: pointer; padding: 4px 10px; border-radius: 4px; font-size: .8rem; }
.drawer-close:hover { color: var(--text); border-color: var(--muted); }
.drawer-body { padding: 1rem; }
.d-section { margin-bottom: 1rem; } .d-label { font-size: .7rem; text-transform: uppercase; color: var(--muted); letter-spacing: .5px; margin-bottom: .3rem; } .d-value { font-size: .82rem; }
.d-code { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: .5rem .7rem; font-family: var(--font-mono); font-size: .72rem; line-height: 1.6; color: var(--muted); white-space: pre; overflow-x: auto; }

/* ── Section headings ── */
.sec-h { font-size: 1.1rem; font-weight: 700; margin-bottom: .8rem; display: flex; align-items: center; gap: .5rem; }
.sec-icon { font-size: 1.2rem; }
.sub-h { font-size: .9rem; font-weight: 600; color: var(--accent); margin: 1rem 0 .5rem 0; }

/* ── Stats Grid ── */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: .5rem; margin-bottom: 1.2rem; }
.stat-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: .5rem; text-align: center; }
.stat-card .value { font-size: 1.3rem; font-weight: 700; color: var(--accent); }
.stat-card .label { font-size: .65rem; color: var(--muted); margin-top: 2px; }
.stat-danger .value { color: var(--red); } .stat-success .value { color: var(--green); }
.stat-muted .value { color: var(--muted); } .stat-muted .label { color: var(--text-dim); }

/* ── Risk Banner ── */
.risk-banner { display: flex; align-items: center; gap: 20px; padding: 16px 20px; border-radius: 10px; border: 1px solid var(--border); margin-bottom: 1rem; }
.risk-grade { font-size: 40px; font-weight: 700; width: 60px; height: 60px; display: flex; align-items: center; justify-content: center; border-radius: 10px; }
.risk-detail { display: flex; flex-direction: column; gap: 2px; }
.risk-detail strong { font-size: 15px; } .risk-detail span { font-size: 13px; color: var(--muted); }
.risk-f { background: var(--risk-f); } .risk-f .risk-grade { background: var(--sev-crit); color: #fff; }
.risk-d { background: var(--risk-d); } .risk-d .risk-grade { background: var(--sev-high); color: #fff; }
.risk-c { background: var(--risk-c); } .risk-c .risk-grade { background: var(--sev-med); color: #fff; }
.risk-b { background: var(--risk-b); } .risk-b .risk-grade { background: var(--sev-low); color: #fff; }
.risk-a { background: var(--risk-a); } .risk-a .risk-grade { background: var(--green); color: #fff; }

/* ── Coverage Bar ── */
.coverage-pct { font-size: 1.8rem; font-weight: 700; }
.coverage-pct.good { color: var(--green); } .coverage-pct.warn { color: var(--yellow); } .coverage-pct.bad { color: var(--red); }
.posture-bar { height: 8px; border-radius: 4px; background: var(--border); margin: .6rem 0; overflow: hidden; }
.posture-fill { height: 100%; border-radius: 4px; transition: width .4s; }
.posture-fill.good { background: var(--green); } .posture-fill.warn { background: var(--yellow); } .posture-fill.bad { background: var(--red); }

/* ── Severity Chart ── */
.severity-chart { display: flex; flex-direction: column; gap: 8px; margin-bottom: 1rem; }
.sev-row { display: flex; align-items: center; gap: 10px; }
.sev-label { width: 55px; font-size: 13px; font-weight: 500; text-align: right; }
.sev-track { flex: 1; height: 22px; background: var(--surface2); border-radius: 5px; overflow: hidden; }
.sev-fill { height: 100%; border-radius: 5px; min-width: 2px; transition: width .6s; }
.sev-fill-crit { background: var(--sev-crit); } .sev-fill-high { background: var(--sev-high); }
.sev-fill-med { background: var(--sev-med); } .sev-fill-low { background: var(--sev-low); }
.sev-fill-unset { background: var(--sev-unset); }
.sev-count { width: 28px; font-size: 14px; font-weight: 600; font-family: var(--font-mono); }

/* ── Finding Cards ── */
.finding-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: .7rem 1rem; margin-bottom: .5rem; cursor: pointer; transition: border-color .15s; }
.finding-card:hover { border-color: var(--accent); }
.fc-top { display: flex; align-items: center; gap: .5rem; margin-bottom: .2rem; }
.fc-risk { font-weight: 600; font-size: .85rem; } .fc-desc { font-size: .78rem; color: var(--muted); }
.fc-assets { font-size: .72rem; color: var(--muted); margin-top: .2rem; font-family: var(--font-mono); }
.fc-sev { font-size: .7rem; padding: 1px 6px; border-radius: 3px; font-weight: 600; }
.fc-sev.crit { background: var(--sev-crit); color: #fff; } .fc-sev.high { background: var(--sev-high); color: #fff; }
.fc-sev.med { background: var(--sev-med); color: #000; } .fc-sev.low { background: var(--border); color: var(--muted); }
.fc-sev.unset { background: var(--border); color: var(--muted); }

/* ── Tables ── */
table { width: 100%; border-collapse: collapse; background: var(--surface2); border-radius: 6px; overflow: hidden; margin-bottom: .8rem; }
th, td { padding: .45rem .7rem; text-align: left; border-bottom: 1px solid var(--border); font-size: .78rem; }
th { background: var(--border); color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: .68rem; }
tr.clickable { cursor: pointer; } tr.clickable:hover { background: var(--table-hover); }
.row-open { border-left: 3px solid var(--red); }
.loc { color: var(--muted); font-family: var(--font-mono); font-size: .72rem; white-space: nowrap; }
.empty-state { color: var(--muted); font-style: italic; padding: .8rem; font-size: .82rem; }

/* ── Badges ── */
.badge-red { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: .68rem; font-weight: 600; background: var(--badge-red-bg); color: var(--sev-crit); }
.badge-green { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: .68rem; font-weight: 600; background: var(--badge-green-bg); color: var(--green); }
.badge-blue { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: .68rem; font-weight: 600; background: var(--badge-blue-bg); color: var(--sev-low); }

/* ── Annotation badges ── */
.ann-badge { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: .68rem; font-weight: 600; text-transform: uppercase; letter-spacing: .3px; }
.ann-asset { background: #1c3a5e; color: #58a6ff; } .ann-threat { background: #4a1a1a; color: #f85149; }
.ann-control { background: #1a3a1a; color: #3fb950; } .ann-exposes { background: #4a1a1a; color: #f85149; }
.ann-mitigates { background: #1a3a1a; color: #3fb950; } .ann-accepts { background: #3a3a1a; color: #d29922; }
.ann-transfers { background: #2a1a3a; color: #bc8cff; } .ann-flow { background: #2a2a2a; color: #8b949e; }
.ann-boundary { background: #2a1a3a; color: #bc8cff; } .ann-data { background: #3a2a1a; color: #db6d28; }
.ann-handles { background: #3a2a1a; color: #db6d28; } .ann-validates { background: #1a3a1a; color: #3fb950; }
.ann-owns { background: #1c3a5e; color: #58a6ff; } .ann-audit { background: #3a3a1a; color: #d29922; }
.ann-assumes { background: #3a3a1a; color: #d29922; } .ann-shield { background: #2a2a2a; color: #8b949e; }
.ann-comment { background: var(--surface2); color: var(--muted); border: 1px solid var(--border); }

/* ── File Cards (Code Browser) ── */
.file-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; margin-bottom: .7rem; overflow: hidden; }
.file-card-header { display: flex; align-items: center; justify-content: space-between; padding: .5rem .8rem; background: var(--surface); cursor: pointer; user-select: none; }
.file-card-header:hover { background: var(--border); }
.file-path { font-family: var(--font-mono); font-size: .78rem; color: var(--accent); font-weight: 600; }
.file-count { font-size: .68rem; color: var(--muted); background: var(--border); padding: 1px 7px; border-radius: 10px; }
.chevron { color: var(--muted); transition: transform .2s; font-size: .75rem; }
.file-card-header.open .chevron { transform: rotate(90deg); }
.file-card-body { display: none; border-top: 1px solid var(--border); } .file-card-body.open { display: block; }
.ann-entry { padding: .6rem .8rem; border-bottom: 1px solid var(--border); cursor: pointer; }
.ann-entry:hover { background: rgba(45,212,167,.04); } .ann-entry:last-child { border-bottom: none; }
.ann-header { display: flex; align-items: center; gap: .4rem; margin-bottom: .2rem; }
.ann-line { font-family: var(--font-mono); font-size: .68rem; color: var(--muted); min-width: 35px; }
.ann-summary { font-size: .78rem; font-weight: 500; }
.ann-desc { font-size: .75rem; color: var(--muted); margin: .15rem 0 .25rem 0; padding-left: .5rem; border-left: 2px solid var(--border); }

/* ── Diagrams ── */
.diagram-hint { font-size: .75rem; color: var(--muted); margin-bottom: .6rem; }
.mermaid-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px; overflow: auto; margin-bottom: 1rem; }
.mermaid { text-align: left; width: max-content; min-width: 100%; }
.mermaid svg { max-width: none; height: auto; display: block; }

/* ── Heatmap ── */
.heatmap { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }
.heatmap-cell { border-radius: 8px; padding: 12px; border: 1px solid var(--border); transition: border-color 0.15s; }
.heatmap-cell.clickable { cursor: pointer; }
.heatmap-cell.clickable:hover { border-color: var(--accent); }
.heatmap-name { font-weight: 600; font-size: 13px; margin-bottom: 4px; font-family: var(--font-mono); word-break: break-all; }
.heatmap-stats { display: flex; gap: 10px; font-size: 12px; color: var(--muted); }
.heatmap-data { margin-top: 4px; display: flex; gap: 4px; flex-wrap: wrap; }
.data-badge { font-size: 10px; padding: 1px 6px; border-radius: 4px; background: rgba(45,212,167,.15); color: var(--accent); font-weight: 600; text-transform: uppercase; }
.risk-cell-critical { background: var(--heatmap-crit); } .risk-cell-high { background: var(--heatmap-high); }
.risk-cell-medium { background: var(--heatmap-med); } .risk-cell-low { background: var(--heatmap-low); }
.risk-cell-none { background: var(--heatmap-none); }

/* ── Code Blocks ── */
.code-block { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: .3rem .6rem; overflow-x: auto; margin-top: .25rem; font-family: var(--font-mono); font-size: .72rem; line-height: 1.45; tab-size: 2; }
.code-line-code { display: block; color: var(--muted); white-space: pre; }
.code-line-ann { display: block; color: var(--accent); background: rgba(45,212,167,.08); margin: 0 -.6rem; padding: 0 .6rem; border-left: 2px solid var(--accent); white-space: pre; }

/* ── Diagram Tabs ── */
.diagram-tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
.diagram-tab { background: none; border: none; border-bottom: 2px solid transparent; padding: .5rem 1rem; color: var(--muted); font-size: .82rem; cursor: pointer; font-family: var(--font-ui); transition: all .15s; }
.diagram-tab:hover { color: var(--text); background: var(--surface2); }
.diagram-tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.diagram-panel { display: none; } .diagram-panel.active { display: block; }

/* ── AI Analysis Controls ── */
.ai-analysis-controls { display: flex; align-items: center; gap: 0.75rem; margin: 0.75rem 0 1.25rem; }
.report-selector-label { font-weight: 600; font-size: 0.88rem; color: var(--text); }
.report-selector { flex: 1; max-width: 600px; padding: 0.5rem 0.75rem; font-size: 0.88rem; font-family: var(--font-base); background: var(--surface2); color: var(--text); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; transition: border-color 0.15s, background 0.15s; }
.report-selector:hover { background: var(--surface3); border-color: var(--accent); }
.report-selector:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(45,212,167,0.1); }
.report-selector option { background: var(--surface); color: var(--text); padding: 0.5rem; }
.ai-analysis-main { margin-top: 0.5rem; }
.md-content h1 { font-size: 1.4rem; font-weight: 700; margin: 1.2rem 0 .6rem; color: var(--text); }
.md-content h2 { font-size: 1.15rem; font-weight: 600; margin: 1rem 0 .5rem; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: .3rem; }
.md-content h3 { font-size: 1rem; font-weight: 600; margin: .8rem 0 .4rem; color: var(--text); }
.md-content p { margin: .4rem 0; line-height: 1.6; }
.md-content ul, .md-content ol { margin: .4rem 0 .4rem 1.5rem; }
.md-content li { margin: .2rem 0; line-height: 1.5; }
.md-content code { font-family: var(--font-mono); font-size: .82rem; background: var(--surface2); padding: 1px 5px; border-radius: 3px; }
.md-content pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: .8rem; overflow-x: auto; margin: .6rem 0; }
.md-content pre code { background: none; padding: 0; }
.md-content blockquote { border-left: 3px solid var(--accent); padding-left: .8rem; margin: .6rem 0; color: var(--muted); }
.md-content table { width: 100%; border-collapse: collapse; margin: .6rem 0; font-size: .82rem; }
.md-content th, .md-content td { padding: .4rem .6rem; border: 1px solid var(--border); text-align: left; }
.md-content th { background: var(--surface2); font-weight: 600; }
.md-content strong { color: var(--text); }

/* ── Responsive ── */
@media (max-width: 768px) {
  .sidebar { width: 50px; min-width: 50px; } .sidebar .nav-text { display: none; }
  .topnav .tn-stat { display: none; }
}
@media print { .topnav, .sidebar, #sidebarToggle { display: none; } .main { margin: 0; } .layout { display: block; } #themeToggle { display: none; } }
`;
