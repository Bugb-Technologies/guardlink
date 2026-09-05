/**
 * GuardLink Dashboard — HTML generator. Composition root.
 *
 * One self-contained page: sidebar navigation driven by the URL hash, a
 * search box, a drawer, and one section per page rendered by `pages/*`.
 * Mermaid, marked and d3 come from CDNs; no build step. The model is
 * embedded verbatim for the client-side feature filter and the drawers.
 *
 * D25/D23 — the dashboard is an emission boundary, so it canonicalises the
 * model's array order and drops `generated_at`: `docs/examples/threat-dashboard.html`
 * is committed, and a volatile field would churn it on every regeneration.
 * Everything else the page reads is content-derived or, for attribution,
 * fixed per HEAD (the as-of date is the HEAD commit's).
 *
 * Pages: Summary, Analytics (heatmaps and distributions over the same claim
 * rows the tables show), Threats, Diagrams, Code, Reports, Data, Assets and,
 * with --blame, Attribution.
 *
 * @exposes #dashboard to #xss [high] cwe:CWE-79 -- "Generates HTML with user-controlled threat model data, git identities and commit trailers"
 * @mitigates #dashboard against #xss using #output-encoding -- "esc() HTML-encodes every interpolated value in every page module; serialized data escapes closing script tags before embedding in <script>"
 * @exposes #dashboard to #path-traversal [medium] cwe:CWE-22 -- "readFileSync reads code files for annotation context"
 * @mitigates #dashboard against #path-traversal using #path-validation -- "resolve() with root constrains file access (annotations.ts)"
 * @flows ThreatModel -> #dashboard via computeStats -- "Model statistics input"
 * @flows SourceFiles -> #dashboard via readFileSync -- "Code snippet reads"
 * @flows LedgerFile -> #dashboard via computeLedgerStates -- "Claim states for badges and the stale-claims action"
 * @flows GitConfig -> #dashboard via detectRepoLinks -- "The remote's web host, for file and commit links"
 * @flows #dashboard -> HTML via return -- "Generated HTML output"
 * @handles internal on #dashboard -- "Processes and displays threat model data"
 * @handles pii on #dashboard -- "Author identities from attribution, in the configured identity mode"
 * @feature "Dashboard" -- "Interactive HTML threat model dashboard"
 * @mitigates #dashboard against #xss using #output-encoding -- "Feature scope names come from @feature annotations and the --feature flag; every one is rendered through esc()"
 * @comment -- "A model narrowed with --feature carries filtered_by_features. The page then declares itself a slice in the title, the top bar and a banner, and suppresses the project-wide measures (file coverage, unannotated files) that a slice cannot answer"
 */
import type { ThreatModel } from '../types/index.js';
import { listFeatures } from '../parser/feature-filter.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';
import type { ThreatReportWithContent } from '../analyze/index.js';
import { computeStats, computeSeverity, computeSeverityOf, computeExposures, computeConfirmed, computeAssetHeatmap, computeAttribution, computeActions, computeLedgerStates, computeAssetDetails } from './data.js';
import type { SeverityBreakdown } from './data.js';
import { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from './diagrams.js';
import { detectRepoLinks } from './links.js';
import { buildFileAnnotations, buildAnalysisData } from './annotations.js';
import { esc, featureScope, scopeLabel, hostLabel } from './html.js';
import { BASE_CSS, UPGRADE_CSS } from './styles.js';
import { CLIENT_JS } from './client.js';
import { FEATURE_FILTER_JS, DIAGRAMS_AND_REPORTS_JS, LEGACY_DRAWER_JS } from './client-legacy.js';
import { buildClaims, type PageContext } from './pages/context.js';
import { renderSummaryPage } from './pages/summary.js';
import { renderReportsPage } from './pages/reports.js';
import { renderThreatsPage } from './pages/threats.js';
import { renderDiagramsPage } from './pages/diagrams.js';
import { renderCodePage } from './pages/code.js';
import { renderDataPage } from './pages/data-boundaries.js';
import { renderAssetsPage } from './pages/assets.js';
import { renderAttributionPage } from './pages/attribution.js';
import { renderAnalyticsPage } from './pages/analytics.js';

export function computeRiskGrade(sev: SeverityBreakdown, unmitigatedCount: number, totalExposures: number, confirmedCount = 0): { grade: string; label: string; summary: string } {
  if (confirmedCount > 0) return { grade: 'F', label: 'Critical Risk', summary: `${confirmedCount} confirmed exploitable finding(s) — immediate remediation required` };
  if (sev.critical > 0) return { grade: 'F', label: 'Critical Risk', summary: `${sev.critical} critical exposure(s) require immediate attention` };
  if (sev.high >= 3 || unmitigatedCount >= 5) return { grade: 'D', label: 'High Risk', summary: `${unmitigatedCount} unmitigated exposure(s), ${sev.high} high severity` };
  if (sev.high >= 1 || unmitigatedCount >= 3) return { grade: 'C', label: 'Moderate Risk', summary: `${unmitigatedCount} unmitigated exposure(s) need remediation` };
  if (unmitigatedCount >= 1) return { grade: 'B', label: 'Low Risk', summary: `${unmitigatedCount} minor unmitigated exposure(s)` };
  if (totalExposures === 0) return { grade: 'A', label: 'Excellent', summary: 'No exposures detected — consider adding more annotations' };
  return { grade: 'A', label: 'Excellent', summary: 'All exposures mitigated or accepted' };
}

/**
 * Diagrams start fitted to their panel instead of at natural size: the svg's
 * box shrinks to the panel width while its viewBox keeps the whole drawing,
 * so the browser scales it and "Fit" (the identity transform) means fitted.
 * A no-op when the legacy block changes shape.
 */
const DIAGRAMS_JS = DIAGRAMS_AND_REPORTS_JS.replace(
  ".style('overflow', 'visible');",
  ".style('overflow', 'visible');\n            var wrap = el.closest('.mermaid-wrap');\n            if (wrap && wrap.clientWidth) { var avail = Math.max(320, wrap.clientWidth - 36); if (viewW > avail) { svg.attr('width', avail).attr('height', Math.max(320, Math.ceil(viewH * (avail / viewW)))); } }",
);

const embed = (value: unknown): string => JSON.stringify(value).replace(/<\//g, '<\\/');

const NAV_ICONS: Record<string, string> = {
  summary: '<path d="M8 2l6 4v6l-6 4-6-4V6l6-4z"/>',
  analytics: '<path d="M1 1h6v6H1V1zm8 0h6v6H9V1zM1 9h6v6H1V9zm8 0h6v6H9V9z"/>',
  'ai-analysis': '<path d="M8 1l2 5h5l-4 3 2 5-5-3-5 3 2-5-4-3h5l2-5z"/>',
  threats: '<path d="M8 1L1 15h14L8 1zm0 4l3 8H5l3-8z"/>',
  diagrams: '<circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5" fill="none"/><circle cx="8" cy="8" r="2"/>',
  code: '<path d="M5 4L1 8l4 4v-2L3 8l2-2V4zm6 0v2l2 2-2 2v2l4-4-4-4z"/>',
  data: '<path d="M4 2h8v2H4V2zm0 3h8v2H4V5zm0 3h8v2H4V8zm0 3h8v2H4v-2zm-2-9v12h12V2H2zm1 1h10v10H3V3z"/>',
  assets: '<path d="M1 3h14v10H1V3zm1 1v8h12V4H2zm2 2h8v1H4V6zm0 2h6v1H4V8z"/>',
  attribution: '<path d="M8 2a3 3 0 110 6 3 3 0 010-6zm-5 11c0-2.5 2.2-4 5-4s5 1.5 5 4v1H3v-1z"/>',
};

function navLink(page: string, label: string, active = false, badge?: string): string {
  return `<a href="#${page}" data-page="${page}"${active ? ' class="active"' : ''}><span class="nav-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">${NAV_ICONS[page]}</svg></span> <span class="nav-text">${label}</span>${badge ? `<span class="nav-badge">${badge}</span>` : ''}</a>`;
}

export function generateDashboardHTML(rawModel: ThreatModel, root?: string, analyses?: ThreatReportWithContent[]): string {
  const model = canonicalizeModelOrder(rawModel);
  // Read from rawModel: canonicalisation reorders, it does not add fields.
  const scope = featureScope(rawModel);
  const { generated_at: _generatedAt, blame_context: _blameContext, ...durableModel } = model as ThreatModel & { blame_context?: unknown };

  const stats = computeStats(model);
  const severity = computeSeverity(model);
  const attribution = computeAttribution(model);
  const exposures = computeExposures(model);
  const confirmed = computeConfirmed(model);
  const heatmap = computeAssetHeatmap(model);
  const links = root ? detectRepoLinks(root) : null;
  const ledgerRead = root ? computeLedgerStates(model, root) : null;
  const ledger = ledgerRead && ledgerRead.report.ledger !== 'absent' ? ledgerRead : null;
  const featureNames = listFeatures(model);
  const unmitigated = exposures.filter(e => !e.mitigated && !e.accepted);
  const mitigatedCount = exposures.filter(e => e.mitigated).length;
  const mitigationCoveragePercent = exposures.length > 0 ? Math.round((mitigatedCount / exposures.length) * 100) : 0;
  // The grade counts what is still open: a mitigated critical is not a critical risk.
  const risk = computeRiskGrade(computeSeverityOf(unmitigated), unmitigated.length, exposures.length, confirmed.length);
  // Files actually carrying one of the scoped @feature tags. `annotated_files`
  // is not the same thing: definitions the feature references live in
  // `.guardlink/definitions.*`, which carries no tag.
  const scopeFiles = scope ? new Set(model.features.map(f => f.location.file)).size : 0;
  const fileAnnotations = buildFileAnnotations(model, root);
  const analysisData = buildAnalysisData(exposures);
  const claims = buildClaims(model, links, ledger);
  const actions = computeActions({ model, exposures, confirmed, verification: ledgerRead?.report ?? null, attribution, scope });
  // One record per heatmap tile, in tile order: the asset drawer indexes it by the tile's position.
  const assetsData = computeAssetDetails(model, claims, heatmap, attribution?.as_of ?? null);

  const ctx: PageContext = {
    model, scope, scopeFiles, links, hostLabel: hostLabel(links),
    stats, severity, exposures, confirmed, unmitigated, mitigatedCount, mitigationCoveragePercent, risk,
    claims, ledger, attribution, actions, heatmap, fileAnnotations,
    diagrams: {
      threatGraph: generateThreatGraph(model),
      threatGraphFull: generateThreatGraph(model, { showAll: true }),
      dataFlow: generateDataFlowDiagram(model),
      attackSurface: generateAttackSurface(model),
    },
    analyses: analyses || [],
  };

  const claimsData = claims.map(c => ({
    idx: c.idx, verb: c.verb, status: c.status, statusLabel: c.statusLabel, asset: c.asset, threat: c.threat, severity: c.severity,
    description: c.description, control: c.control, refs: c.refs, file: c.file, line: c.line, url: c.url, state: c.state, blame: c.blame,
  }));

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GuardLink — ${esc(model.project)} Threat Model${scope ? ` — PARTIAL: ${scope.length > 1 ? 'features' : 'feature'} ${esc(scopeLabel(scope))}` : ''}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
${BASE_CSS}
${UPGRADE_CSS}
</style>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body${scope ? ' class="scoped"' : ''}>

<!-- ═══════════ TOP NAV ═══════════ -->
<div class="topnav">
  <div class="topnav-left">
    <div class="logo">TS</div>
    <h1>${esc(model.project)}</h1>
    <span class="badge">Threat Model</span>
${scope ? `    <span class="badge badge-scope" title="This page was generated with --feature and covers only part of the threat model">◑ Feature slice — ${esc(scope.join(', '))}</span>` : ''}
  </div>
  <div class="topnav-right">
    <div class="topnav-metrics">
      <div class="tn-stat"><span class="tn-k">Assets</span> <span class="tn-v blue">${stats.assets}</span></div>
      <div class="tn-stat"><span class="tn-k">Open</span> <span class="tn-v red">${unmitigated.length}</span></div>
      <div class="tn-stat"><span class="tn-k">Controls</span> <span class="tn-v green">${stats.controls}</span></div>
${scope
    // Repository file coverage means nothing on a slice (see the code page);
    // a slice reports the one coverage it can defend.
    ? `      <div class="tn-stat" title="Exposures mitigated within this feature. Project file coverage is not shown on a slice."><span class="tn-k">Mitigated</span> <span class="tn-v ${mitigationCoveragePercent >= 70 ? 'green' : mitigationCoveragePercent >= 40 ? 'yellow' : 'red'}">${mitigationCoveragePercent}%</span></div>`
    : `      <div class="tn-stat"><span class="tn-k">Coverage</span> <span class="tn-v ${stats.coveragePercent >= 70 ? 'green' : stats.coveragePercent >= 40 ? 'yellow' : 'red'}">${stats.coveragePercent}%</span></div>`}
    </div>
    <div class="search-wrap"><span class="search-icon">⌕</span><input id="search" type="search" placeholder="Search this page…" autocomplete="off" oninput="onSearchInput(this)" aria-label="Search this page"><kbd>/</kbd></div>
${featureNames.length > 0 ? `    <div class="feature-filter-wrap">
      <select id="featureFilter" class="feature-filter-select" onchange="applyFeatureFilter(this.value)" title="${scope ? 'Narrow further within this slice — the page already excludes everything outside it' : 'Filter by feature'}">
        <option value="">${scope ? 'All in this slice' : 'All Features'}</option>
${featureNames.map(f => `        <option value="${esc(f)}">${esc(f)}</option>`).join('\n')}
      </select>
    </div>` : ''}
    <button id="themeToggle" onclick="toggleTheme()" title="Toggle light/dark mode">
      <span class="icon-sun">☀️</span><span class="icon-moon">🌙</span>
    </button>
  </div>
</div>

<!-- Generation-time scope banner. Static, always visible, never dismissible:
     a screenshot of this page must not be mistakable for the whole model. -->
${scope ? `<div id="scope-banner" class="scope-banner" role="note">
  <span class="scope-banner-tag">Partial threat model</span>
  <span class="scope-banner-text">Narrowed to ${scope.length > 1 ? 'features' : 'feature'} ${esc(scopeLabel(scope))} — the ${scopeFiles} file(s) tagged <code>@feature</code>, plus the definitions they reference. <strong>Every count, chart, table and diagram below describes ${scope.length > 1 ? 'these features' : 'this feature'} only, not the whole project.</strong> Project-wide file coverage and unannotated files are omitted, because a slice cannot answer them. Regenerate without <code>--feature</code> for the full model.</span>
</div>` : ''}

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
    ${navLink('summary', 'Executive Summary', true)}
    ${navLink('analytics', 'Analytics')}
    ${navLink('threats', 'Threats &amp; Exposures', false, unmitigated.length > 0 ? String(unmitigated.length) : undefined)}
    ${navLink('diagrams', 'Diagrams')}
    ${navLink('code', 'Code &amp; Annotations')}
    ${navLink('ai-analysis', 'Threat Reports', false, ctx.analyses.length > 0 ? String(ctx.analyses.length) : undefined)}
    <div class="sep"></div>
    ${navLink('data', 'Data &amp; Boundaries')}
    ${navLink('assets', 'Asset Heatmap')}
    ${attribution ? navLink('attribution', 'Attribution') : ''}
  </div>
  <button id="sidebarToggle" onclick="toggleSidebar()" title="Collapse sidebar">
    <svg class="chevron-left" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M10 2L4 8l6 6V2z"/></svg>
    <svg class="chevron-right" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M6 2v12l6-6-6-6z"/></svg>
  </button>
</nav>

<!-- ═══════════ MAIN ═══════════ -->
<div class="main">

${renderSummaryPage(ctx)}
${renderAnalyticsPage(ctx)}
${renderReportsPage(ctx)}
${renderThreatsPage(ctx)}
${renderDiagramsPage(ctx)}
${renderCodePage(ctx)}
${renderDataPage(ctx)}
${renderAssetsPage(ctx)}
${attribution ? renderAttributionPage(attribution, ctx) : ''}

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
<div class="toast" id="toast" role="status" aria-live="polite"></div>

<script>
/* ===== DATA ===== */
const fileAnnotations = ${embed(fileAnnotations)};
const analysisData = ${embed(analysisData)};
const exposuresData = ${embed(exposures)};
const confirmedData = ${embed(confirmed)};
const savedAnalyses = ${embed(analyses || [])};
const heatmapData = ${embed(heatmap)};
const threatModel = ${embed(durableModel)};
const claimsData = ${embed(claimsData)};
const assetsData = ${embed(assetsData)};
const openOnHost = ${JSON.stringify(`Open on ${hostLabel(links)}`)};
${CLIENT_JS}
${LEGACY_DRAWER_JS}
${FEATURE_FILTER_JS}
${DIAGRAMS_JS}
</script>

</body>
</html>`;
}
