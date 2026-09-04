/**
 * GuardLink Dashboard — Threat Reports: the saved AI analyses, rendered
 * client-side from the embedded markdown by the legacy report explorer.
 *
 * @comment -- "Whole-project documents: --feature does not narrow them, and the page says so on a slice"
 */
import { esc, scopeLabel, sectionHead } from '../html.js';
import type { PageContext } from './context.js';

export function renderReportsPage(ctx: PageContext): string {
  const { scope, analyses } = ctx;
  return `
<div id="sec-ai-analysis" class="section-content">
  ${sectionHead('✨', 'Threat Reports', null, `<span class="muted">${analyses.length} saved</span>`)}
${scope ? `  <p class="scope-note">⚠ These reports are <strong>whole-project</strong> documents. Unlike the rest of this page they are not narrowed to ${esc(scopeLabel(scope))}, and they may discuss assets outside it.</p>` : ''}
  <p class="lead">Reports written by <code>guardlink threat-report</code> (STRIDE, DREAD, PASTA, attacker, rapid, general or a custom prompt). Pick one to read it here.</p>
  <div class="panel ai-analysis-panel">
  <div class="ai-analysis-controls">
    <label for="report-selector" class="report-selector-label">Select Report:</label>
    <select id="report-selector" class="report-selector" aria-label="Select threat report"></select>
  </div>
  <div id="ai-content" class="md-content ai-analysis-main"></div>
  </div>
</div>`;
}
