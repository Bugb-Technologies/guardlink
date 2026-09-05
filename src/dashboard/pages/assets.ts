/**
 * GuardLink Dashboard — Asset Risk Heatmap.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Asset names and classifications are escaped"
 * @comment -- "Cells keep data-ff-asset (every alias of the tile, |-separated) and the asset drawer; the legend and search text are new"
 */
import { esc, scopeLabel, sectionHead } from '../html.js';
import type { PageContext } from './context.js';

export function renderAssetsPage(ctx: PageContext): string {
  const { heatmap, scope } = ctx;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  for (const a of heatmap) counts[a.riskLevel]++;
  return `
<div id="sec-assets" class="section-content">
  ${sectionHead('🗺', 'Asset Risk Heatmap', scope, `<span class="muted"><span data-count-for="assets">${heatmap.length}</span> assets</span>`)}
  <p class="lead">Assets sorted by risk. Risk rises with unmitigated exposures: <strong>critical</strong> 3 or more open, <strong>high</strong> 2, <strong>medium</strong> 1, <strong>low</strong> exposed but covered. Click an asset for its threats, controls, flows, owners, files and who introduced its open exposures.${scope ? ` Only assets ${esc(scopeLabel(scope))} touches appear, and each tile counts only that feature's exposures, mitigations and flows — an asset shown here as low-risk may carry open threats elsewhere in the project.` : ''}</p>
  <div class="chips">
    <span class="chips-label">Legend</span>
    <span class="chip chip-crit active" style="cursor:default">Critical<span class="chip-n">${counts.critical}</span></span>
    <span class="chip chip-high active" style="cursor:default">High<span class="chip-n">${counts.high}</span></span>
    <span class="chip chip-med active" style="cursor:default">Medium<span class="chip-n">${counts.medium}</span></span>
    <span class="chip chip-low active" style="cursor:default">Low<span class="chip-n">${counts.low}</span></span>
    <span class="chip" style="cursor:default">No exposure<span class="chip-n">${counts.none}</span></span>
  </div>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn btn-ghost" data-clear-filters>Clear</button></div>
  ${heatmap.length > 0 ? `
  <div class="heatmap" data-list="assets">
    ${heatmap.map((a, i) => `
    <div class="heatmap-cell risk-cell-${a.riskLevel} clickable" data-ff-asset="${esc(a.aliases.join('|'))}" data-search="${esc(`${a.aliases.join(' ')} ${a.riskLevel} ${a.dataHandling.join(' ')}`.toLowerCase())}" onclick="openDrawer('asset', ${i})">
      <div class="heatmap-name">${esc(a.name)}</div>
      <div class="heatmap-stats">
        <span title="Exposures">⚠ ${a.exposures}</span>
        <span title="Mitigations">🛡 ${a.mitigations}</span>
        <span title="Data flows">↔ ${a.flows}</span>
      </div>
      ${a.dataHandling.length > 0 ? `<div class="heatmap-data">${a.dataHandling.map(d => `<span class="data-badge">${esc(d)}</span>`).join('')}</div>` : ''}
    </div>`).join('')}
  </div>
  <div class="no-match" data-count-for="assets" hidden>No asset matches the current filters.</div>` : `<p class="empty-state">${scope ? `No assets are referenced by the files tagged ${esc(scopeLabel(scope))}.` : 'No assets found.'}</p>`}
</div>`;
}
