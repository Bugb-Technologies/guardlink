/**
 * GuardLink Dashboard — HTML generator. Composition root.
 *
 * One self-contained page: a rail of seven pages (Overview, Exposures,
 * Diagrams, Assets, Code, Agents & reach, Reports — plus Attribution with
 * --blame) driven by the URL hash, a search box, a feature filter, a drawer,
 * and one section per page rendered by `pages/*`.
 *
 * SELF-CONTAINED: the page makes no network request when it renders. There is
 * no CDN script, no stylesheet or font host, no remote `import()`. Every
 * diagram is our own SVG, laid out here from data (`layout/*`); reports are
 * rendered to HTML here (`markdown.ts`); the type is the system stack. The one
 * script is inline, and the generated markup carries no inline `on*` handler —
 * every interaction is a `data-*` hook with a delegated listener (`client.ts`).
 *
 * The page follows the OS light/dark preference, with a toggle; `theme` pins
 * one. Inside a VS Code webview a host can set `data-host="vscode"` on the root
 * and every colour role is then read from the editor's own theme variables.
 *
 * D25/D23 — the dashboard is an emission boundary, so it canonicalises the
 * model's array order and drops `generated_at`: `docs/examples/threat-dashboard.html`
 * is committed, and a volatile field would churn it on every regeneration.
 * Everything else the page reads is content-derived or, for attribution,
 * fixed per HEAD (the as-of date is the HEAD commit's).
 *
 * @flows GitRepo -> #dashboard via loadSince -- "The model at --since <ref>, diffed against the one rendered"
 *
 * @exposes #dashboard to #xss [high] cwe:CWE-79 -- "generateDashboardHTML() interpolates model descriptions, asset names, git identities, commit trailers and report prose into the page markup, the SVG diagrams and the embedded JSON constants"
 * @mitigates #dashboard against #xss using #output-encoding -- "esc() HTML-encodes every interpolated value in every page module, the layout modules escape every SVG label, report prose is escaped before markup is added back, and serialized data escapes closing script tags before embedding in <script>"
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
 * @comment -- "No remote reference of any kind is emitted: the page renders offline and under a host policy that blocks every network origin"
 */
import type { ThreatModel } from '../types/index.js';
import { listFeatures, filterByFeature } from '../parser/feature-filter.js';
import { canonicaliser } from '../mcp/subgraph.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';
import type { ThreatReportWithContent } from '../analyze/index.js';
import { computeStats, computeSeverity, computeSeverityOf, computeExposures, computeConfirmed, computeAssetHeatmap, computeAttribution, computeActions, computeLedgerStates, computeAssetDetails, computeOwnership, computeFileRisk, fileRiskRank, computeChanges, newClaimKeys } from './data.js';
import type { SinceInput } from './analytics.js';
import { computeRiskGrade } from './grade.js';
import { detectRepoLinks } from './links.js';
import { readHypotheses, classifyHypotheses, attachHypotheses } from '../hypothesis/index.js';
import { buildFileAnnotations } from './annotations.js';
import { esc, featureScope, scopeLabel, hostLabel, icon } from './html.js';
import { STYLES } from './styles.js';
import { CLIENT_JS } from './client.js';
import { buildClaims, type PageContext } from './pages/context.js';
import { renderOverviewPage, type OverviewVariant } from './pages/overview.js';
import { renderExposuresPage, type BreakdownVariant } from './pages/exposures.js';
import { renderDiagramsPage } from './pages/diagrams.js';
import { renderAssetsPage } from './pages/assets.js';
import { renderCodePage } from './pages/code.js';
import { renderAgentsPage } from './pages/agents.js';
import { renderReportsPage } from './pages/reports.js';
import { renderAttributionPage } from './pages/attribution.js';
import { summarizeReach } from '../reach/index.js';
import { findUnmitigatedPaths, classifyEndpoints } from '../paths/index.js';
import { buildDiagramModel } from './layout/graph.js';
import { buildHoodPayload, renderHoodSvg, renderNodeDetail } from './layout/hood.js';
import { buildMatrixData, renderMatrix } from './layout/matrix.js';

export { computeRiskGrade };

const embed = (value: unknown): string => JSON.stringify(value).replace(/<\//g, '<\\/');

const RAIL: { page: string; label: string; icon: string }[] = [
  { page: 'overview', label: 'Overview', icon: 'layout' },
  { page: 'exposures', label: 'Exposures', icon: 'alert' },
  { page: 'diagrams', label: 'Diagrams', icon: 'diagram' },
  { page: 'assets', label: 'Assets', icon: 'map' },
  { page: 'code', label: 'Code', icon: 'code' },
  { page: 'agents', label: 'Agents &amp; reach', icon: 'zap' },
  { page: 'reports', label: 'Reports', icon: 'file' },
];

function railLink(page: string, label: string, ico: string, active = false, badge?: string): string {
  return `<a href="#${page}" data-page="${page}"${active ? ' class="active" aria-current="page"' : ''}><span class="nav-icon">${icon(ico)}</span><span class="nav-text">${label}</span>${badge ? `<span class="nav-badge num">${badge}</span>` : ''}</a>`;
}

export interface DashboardOptions {
  /** What changed since a git ref, from `loadSince`; adds the Overview strip and marks new rows. */
  since?: SinceInput;
  /** Pin a theme instead of following the OS preference (the CLI's --light). */
  theme?: 'dark' | 'light';
}

export function generateDashboardHTML(rawModel: ThreatModel, root?: string, analyses?: ThreatReportWithContent[], opts: DashboardOptions = {}): string {
  const model = canonicalizeModelOrder(rawModel);
  // The tested state of every exposure, when a ledger exists: a refuted claim is not open.
  // @flows LedgerFile -> #dashboard via readHypotheses -- "Outcomes for the badges, the drawer and the open count"
  const hypotheses = root ? classifyHypotheses(model, readHypotheses(root)) : null;
  if (hypotheses) attachHypotheses(model, hypotheses);
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
  const unmitigated = exposures.filter(e => !e.mitigated && !e.accepted && !e.refuted);
  const mitigatedCount = exposures.filter(e => e.mitigated).length;
  const mitigationCoveragePercent = exposures.length > 0 ? Math.round((mitigatedCount / exposures.length) * 100) : 0;
  // The grade counts what is still open: a mitigated critical is not a critical risk.
  const risk = computeRiskGrade(computeSeverityOf(unmitigated), unmitigated.length, exposures.length, confirmed.length);
  // Files actually carrying one of the scoped @feature tags. `annotated_files`
  // is not the same thing: definitions the feature references live in
  // `.guardlink/definitions.*`, which carries no tag.
  const scopeFiles = scope ? new Set(model.features.map(f => f.location.file)).size : 0;
  const newKeys = opts.since ? newClaimKeys(opts.since) : undefined;
  const claims = buildClaims(model, links, ledger, { newKeys });
  const changes = opts.since ? computeChanges(opts.since, claims) : null;
  const ownership = computeOwnership(model, claims);
  const fileRisk = computeFileRisk(claims);
  // Annotations join to the claim rows and asset tiles the drawers render.
  const fileAnnotations = buildFileAnnotations(model, root, { claims, assets: heatmap, links });
  // Riskiest file first: confirmed, then the worst open severity, then how many are open; the drawer indexes this order.
  fileAnnotations.sort((a, b) => fileRiskRank(fileRisk.get(a.file)) - fileRiskRank(fileRisk.get(b.file))
    || (fileRisk.get(b.file)?.open ?? 0) - (fileRisk.get(a.file)?.open ?? 0)
    || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  // What agents and other principals can reach: the Agents page, the asset drawer, the actor table and the actions read it.
  const reach = summarizeReach(model);
  const actions = computeActions({ model, exposures, confirmed, verification: ledgerRead?.report ?? null, attribution, scope, unownedExposed: ownership.unowned.map(u => u.asset), reach });
  // One record per asset, in heatmap order: the asset drawer indexes it.
  const assetsData = computeAssetDetails(model, claims, heatmap, attribution?.as_of ?? null, reach);

  // The diagrams' one model, and the compact payloads the client's renderers read.
  const graph = buildDiagramModel(model, claims);
  const { payload: hood, index: nodeIndex } = buildHoodPayload(graph);
  const degree = (i: number): number => hood.flows.filter(f => f[0] === i || f[1] === i).length;
  const withFlows = hood.nodes.map((n, i) => ({ n, i })).filter(x => degree(x.i) > 0);
  const defaultFocus = withFlows.sort((a, b) => b.n.o - a.n.o || degree(b.i) - degree(a.i) || a.i - b.i)[0]?.i ?? 0;
  const matrixData = buildMatrixData(graph);

  const ctx: PageContext = {
    model, scope, scopeFiles, links, hostLabel: hostLabel(links),
    stats, severity, exposures, confirmed, unmitigated, mitigatedCount, mitigationCoveragePercent, risk,
    claims, ledger, attribution, actions, heatmap, fileAnnotations, reach,
    analyses: analyses || [],
    changes,
    fileRisk,
  };

  // The Overview numbers and the Exposures breakdowns recomputed per feature, so the top-bar dropdown can swap them in.
  const variants = featureNames.map(f => {
    const fm = filterByFeature(model, [f]);
    const fClaims = buildClaims(fm, links, ledger, { newKeys });
    const files = new Set(fm.features.map(x => x.location.file)).size;
    return {
      overview: { feature: f, input: { scope: [f], claims: fClaims, model: fm, stats: computeStats(fm), scopeFiles: files } } as OverviewVariant,
      breakdown: { feature: f, input: { scope: [f], model: fm, claims: fClaims, attribution: computeAttribution(fm), heatmap: computeAssetHeatmap(fm) } } as BreakdownVariant,
    };
  });

  // `akey` is the canonical asset key: one component spelled `#mcp` in one
  // file and `GuardLink.MCP` in another is one asset to every view.
  const assetKey = canonicaliser(model);
  const claimsData = claims.map(c => ({
    idx: c.idx, verb: c.verb, status: c.status, statusLabel: c.statusLabel, asset: c.asset, akey: assetKey(c.asset), threat: c.threat, severity: c.severity,
    description: c.description, control: c.control, refs: c.refs, file: c.file, line: c.line, url: c.url, state: c.state, verifiedBy: c.verifiedBy, verifiedAt: c.verifiedAt,
    owners: c.owners, handles: c.handles, change: c.change, hypothesis: c.hypothesis, blame: c.blame,
  }));

  const filesAnnotated = model.annotated_files?.length || 0;
  const filesTotal = filesAnnotated + (model.unannotated_files || []).length;
  const openCount = claims.filter(c => c.status === 'open' || c.status === 'confirmed').length;
  const theme = opts.theme ? ` data-theme="${opts.theme}" data-theme-pinned` : '';

  return `<!DOCTYPE html>
<html lang="en"${theme}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<link rel="icon" href="data:,">
<title>GuardLink — ${esc(model.project)} Threat Model${scope ? ` — PARTIAL: ${scope.length > 1 ? 'features' : 'feature'} ${esc(scopeLabel(scope))}` : ''}</title>
<style>
${STYLES}
</style>
</head>
<body${scope ? ' class="scoped"' : ''}>

<header class="topbar">
  <button class="icon-btn rail-btn" data-action="rail" title="Collapse or expand the page rail" aria-label="Toggle the page rail">${icon('layout')}</button>
  <div class="brand"><b class="project">${esc(model.project)}</b><span class="eyebrow">threat model</span>
${scope ? `    <span class="badge badge-scope" title="This page was generated with --feature and covers only part of the threat model">◑ Feature slice — ${esc(scope.join(', '))}</span>` : ''}
  </div>
  <div class="topbar-metrics">
    <div class="tn-stat"><span class="tn-k">Assets</span> <span class="tn-v">${stats.assets}</span></div>
    <div class="tn-stat"><span class="tn-k">Open</span> <span class="tn-v">${unmitigated.length}</span></div>
    <div class="tn-stat"><span class="tn-k">Controls</span> <span class="tn-v">${stats.controls}</span></div>
${scope
    // Repository file coverage means nothing on a slice (see the code page);
    // a slice reports the one coverage it can defend.
    ? `    <div class="tn-stat" title="Exposures mitigated within this feature. Project file coverage is not shown on a slice."><span class="tn-k">Mitigated</span> <span class="tn-v">${mitigationCoveragePercent}%</span></div>`
    : `    <div class="tn-stat"><span class="tn-k">Coverage</span> <span class="tn-v">${stats.coveragePercent}%</span></div>`}
  </div>
  <div class="search-wrap"><span class="search-icon">${icon('search')}</span><input id="search" type="search" placeholder="Search this page…" autocomplete="off" aria-label="Search this page"><kbd>/</kbd></div>
${featureNames.length > 0 ? `  <select id="featureFilter" class="feature-filter-select" aria-label="Filter by feature" title="${scope ? 'Narrow further within this slice — the page already excludes everything outside it' : 'Filter by feature'}">
    <option value="">${scope ? 'All in this slice' : 'All features'}</option>
${featureNames.map(f => `    <option value="${esc(f)}">${esc(f)}</option>`).join('\n')}
  </select>` : ''}
  <button class="icon-btn" id="themeToggle" data-action="theme" title="Switch between light and dark" aria-label="Switch between light and dark">
    <span class="icon-sun">${icon('sun')}</span><span class="icon-moon">${icon('moon')}</span>
  </button>
</header>

<!-- Generation-time scope banner. Static, always visible, never dismissible:
     a screenshot of this page must not be mistakable for the whole model. -->
${scope ? `<div id="scope-banner" class="scope-banner" role="note">
  <span class="scope-banner-tag">Partial threat model</span>
  <span class="scope-banner-text">Narrowed to ${scope.length > 1 ? 'features' : 'feature'} ${esc(scopeLabel(scope))} — the ${scopeFiles} file(s) tagged <code>@feature</code>, plus the definitions they reference. <strong>Every count, chart, table and diagram below describes ${scope.length > 1 ? 'these features' : 'this feature'} only, not the whole project.</strong> Project-wide file coverage and unannotated files are omitted, because a slice cannot answer them. Regenerate without <code>--feature</code> for the full model.</span>
</div>` : ''}

<div id="feature-banner" class="feature-banner" role="status" hidden>
  <span>Filtered to feature</span>
  <strong id="feature-banner-name"></strong>
  <span id="feature-banner-files" class="subtle"></span>
  <button class="btn ghost" data-action="feature-clear">Clear filter</button>
</div>

<div class="layout">

<nav class="rail" id="sidebar" aria-label="Dashboard pages">
  <div class="rail-nav">
    ${RAIL.map((r, i) => railLink(r.page, r.label, r.icon, i === 0,
      r.page === 'exposures' && openCount > 0 ? String(openCount)
      : r.page === 'agents' && reach.totals.unentitled + reach.totals.ungated > 0 ? String(reach.totals.unentitled + reach.totals.ungated)
      : r.page === 'reports' && ctx.analyses.length > 0 ? String(ctx.analyses.length) : undefined)).join('\n    ')}
    ${attribution ? `<div class="sep"></div>${railLink('attribution', 'Attribution', 'users')}` : ''}
  </div>
  <div class="rail-foot">
    ${scope
      ? `<div>${scopeFiles} tagged file(s)</div><div class="subtle">Scope: ${esc(scopeLabel(scope))}</div>`
      : `<div>${filesAnnotated} of ${filesTotal} files annotated</div><div class="gauge"><i class="g-structure" style="width:${filesTotal ? Math.max(1, Math.round((filesAnnotated / filesTotal) * 100)) : 0}%"></i></div><div class="subtle">Scope: all features</div>`}
  </div>
</nav>

<main class="main" id="main">

${renderOverviewPage(ctx, variants.map(v => v.overview))}
${renderExposuresPage(ctx, matrixData, variants.map(v => v.breakdown))}
${renderDiagramsPage(ctx, { graph, hood, nodeIndex, defaultFocus, paths: findUnmitigatedPaths(model), pathsTotal: findUnmitigatedPaths(model, { includeMitigated: true }).length, endpoints: classifyEndpoints(model) })}
${renderAssetsPage(ctx, graph)}
${renderCodePage(ctx)}
${renderAgentsPage(ctx, reach)}
${renderReportsPage(ctx)}
${attribution ? renderAttributionPage(attribution, ctx) : ''}

</main>
</div>

<div class="drawer-overlay" id="drawer-overlay"></div>
<aside class="drawer" id="drawer" aria-labelledby="drawer-title">
  <div class="drawer-header">
    <h3 id="drawer-title">Details</h3>
    <button class="btn ghost drawer-close" data-action="drawer-close">${icon('x')} Close</button>
  </div>
  <div class="drawer-body" id="drawer-body"></div>
</aside>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<div class="tip" id="tip" role="tooltip" hidden></div>

<script>
/* ===== DATA ===== */
const fileAnnotations = ${embed(fileAnnotations)};
const exposuresData = ${embed(exposures)};
const savedAnalyses = ${embed((analyses || []).map(a => ({ label: a.label, framework: a.framework, timestamp: a.timestamp, model: a.model, content: a.content })))};
const threatModel = ${embed(durableModel)};
const claimsData = ${embed(claimsData)};
const assetsData = ${embed(assetsData)};
const matrixData = ${embed(matrixData)};
const hoodData = ${embed({ ...hood, initial: defaultFocus })};
const openOnHost = ${JSON.stringify(`Open on ${hostLabel(links)}`)};
const ICONS = ${JSON.stringify({ copy: icon('copy'), external: icon('external'), x: icon('x') })};
/* ===== RENDERERS: the generator's own, embedded by source (src/dashboard/layout) ===== */
var __name = function (f) { return f; };
${renderHoodSvg.toString()}
${renderNodeDetail.toString()}
${renderMatrix.toString()}
${CLIENT_JS}
</script>

</body>
</html>`;
}
