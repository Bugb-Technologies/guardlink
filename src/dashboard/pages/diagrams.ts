/**
 * GuardLink Dashboard — Diagrams: threat graph, data flow, attack surface.
 * Mermaid sources are embedded escaped and rendered client-side.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Mermaid source is escaped into the <pre>; the client reads it back as text"
 * @comment -- "Ported from the first generate.ts with the same panel ids and data-variant hooks the diagram script expects"
 */
import { esc, scopeLabel, sectionHead } from '../html.js';
import type { PageContext } from './context.js';

export function renderDiagramsPage(ctx: PageContext): string {
  const { scope } = ctx;
  const { threatGraph, threatGraphFull, dataFlow, attackSurface } = ctx.diagrams;
  const tabs: { id: string; label: string; icon: string }[] = [];
  const panels: string[] = [];
  const zoomButtons = `
            <button class="diagram-btn" onclick="diagramZoom('out')" title="Zoom out">−</button>
            <button class="diagram-btn" onclick="diagramZoom('in')" title="Zoom in">+</button>
            <button class="diagram-btn" onclick="diagramZoom('fit')" title="Reset view">Reset</button>`;

  if (threatGraph) {
    tabs.push({ id: 'threat-graph', label: 'Threat Graph', icon: '🔷' });
    const hasFullVariant = !!threatGraphFull && threatGraphFull !== threatGraph;
    panels.push(`<div id="dtab-threat-graph" class="diagram-panel${panels.length === 0 ? ' active' : ''}">
      <div class="diagram-shell">
        <div class="diagram-toolbar">
          <span class="diagram-title">Threat Graph</span>
          <div class="diagram-actions">
            ${hasFullVariant ? `<button id="threatGraphToggle" class="diagram-btn" onclick="toggleThreatGraphAll(this)" title="Show all threat severities (not just high/critical)">All severities</button>` : ''}${zoomButtons}
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
        <div class="diagram-toolbar"><span class="diagram-title">Data Flow</span><div class="diagram-actions">${zoomButtons}</div></div>
        <div class="mermaid-wrap"><pre class="mermaid">\n${esc(dataFlow)}\n</pre></div>
        <div class="diagram-meta">Trust zones (🧱) and data movement across system boundaries. Each boundary shows both sides of the trust line.</div>
      </div>
    </div>`);
  }
  if (attackSurface) {
    tabs.push({ id: 'attack-surface', label: 'Attack Surface', icon: '⚠' });
    panels.push(`<div id="dtab-attack-surface" class="diagram-panel">
      <div class="diagram-shell">
        <div class="diagram-toolbar"><span class="diagram-title">Attack Surface</span><div class="diagram-actions">${zoomButtons}</div></div>
        <div class="mermaid-wrap"><pre class="mermaid">\n${esc(attackSurface)}\n</pre></div>
        <div class="diagram-meta">Exposures per asset, severity-coloured. <strong>💥 confirmed</strong>, <strong>⚠️ open</strong>, <strong>✅ mitigated</strong>, <strong>🟦 accepted</strong>.</div>
      </div>
    </div>`);
  }

  if (tabs.length === 0) {
    return `
<div id="sec-diagrams" class="section-content">
  ${sectionHead('◉', 'Diagrams', scope)}
  <p class="empty-state">${scope
    ? `Nothing to draw for ${esc(scopeLabel(scope))} — the files tagged with ${scope.length > 1 ? 'these features' : 'this feature'} carry no <code>@exposes</code>, <code>@flows</code> or <code>@mitigates</code>. The project's own diagrams are not shown on a slice; regenerate without <code>--feature</code> to see them.`
    : 'No diagram data — add @exposes, @flows, or @mitigates annotations.'}</p>
</div>`;
  }

  return `
<div id="sec-diagrams" class="section-content">
  ${sectionHead('◉', 'Diagrams', scope)}
  <p class="diagram-hint">Interactive diagrams generated from annotations. The view starts fitted to the panel; scroll to zoom, drag to pan, double-click to reset.</p>
${scope ? `  <p class="scope-note">These are <strong>narrowed</strong> diagrams: the edges are this feature's relations, and the nodes are the assets, threats and controls those relations reference. A node the feature never touches is absent — an absent node does not mean the project lacks it. The same narrowed graph is written to <code>.guardlink/graph/by-feature/</code>.</p>` : ''}
  <div class="diagram-tabs">
    ${tabs.map((t, i) => `<button class="diagram-tab${i === 0 ? ' active' : ''}" onclick="switchDiagramTab('${t.id}', this)">${t.icon} ${t.label}</button>`).join('')}
  </div>
  ${panels.join('\n')}
</div>`;
}
