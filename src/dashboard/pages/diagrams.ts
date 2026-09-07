/**
 * GuardLink Dashboard — Diagrams: threat graph, data flow, attack surface.
 * Mermaid sources are embedded escaped and rendered client-side.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Mermaid source is escaped into the <pre>; the client reads it back as text"
 * @comment -- "Ported from the first generate.ts with the same panel ids and data-variant hooks the diagram script expects; the toolbar is a segmented zoom group plus copy-source"
 */
import { esc, scopeLabel, sectionHead, icon, wholeModelNote } from '../html.js';
import type { PageContext } from './context.js';

const TOOLS = `
            <input class="diagram-find" type="search" placeholder="Find node" aria-label="Find a node in the diagram" oninput="diagramFind(this.value)">
            <div class="diagram-seg" role="group" aria-label="Zoom">
              <button class="diagram-btn" onclick="diagramZoom('out')" title="Zoom out">−</button>
              <button class="diagram-btn" onclick="diagramZoom('fit')" title="Fit to panel (or double-click the diagram)">Fit</button>
              <button class="diagram-btn" onclick="diagramZoom('in')" title="Zoom in">+</button>
            </div>
            <button class="diagram-btn" data-copy-diagram title="Copy the Mermaid source — paste it into mermaid.live or a markdown file">${icon('copy')} Source</button>`;

const SW = (c: string): string => `<i class="sw" style="background:${c}"></i>`;
const LEGEND_THREAT = `<span class="diagram-legend"><span>${icon('square')} asset</span><span>${icon('hexagon')} threat</span><span>${icon('pill')} control</span><span>${SW('#ea1d1d')} critical / high</span><span>${SW('#55899e')} medium</span><span>${SW('#0360a2')} low</span><span>dashed box: trust zone</span></span>`;
const LEGEND_FLOW = `<span class="diagram-legend"><span>${icon('pill')} client or user</span><span>${icon('flag')} external party</span><span>${icon('cylinder')} data store</span><span>${icon('square')} service</span><span>dashed box: trust zone</span></span>`;
const LEGEND_SURFACE = `<span class="diagram-legend"><span>${icon('hexagon')} confirmed</span><span>${icon('square')} open</span><span>${icon('pill')} mitigated</span><span>${icon('slant')} accepted</span><span>colour is severity</span></span>`;

function shell(id: string, title: string, body: string, meta: string, extra = '', active = false): string {
  return `<div id="dtab-${id}" class="diagram-panel${active ? ' active' : ''}">
      <div class="diagram-shell">
        <div class="diagram-toolbar">
          <span class="diagram-title">${title}</span>
          <div class="diagram-actions">${extra}${TOOLS}
          </div>
        </div>
        <div class="mermaid-wrap">${body}</div>
        <div class="diagram-meta">${meta}</div>
      </div>
    </div>`;
}

export function renderDiagramsPage(ctx: PageContext): string {
  const { scope } = ctx;
  const { threatGraph, threatGraphFull, dataFlow, attackSurface, focus } = ctx.diagrams;
  const tabs: { id: string; label: string; icon: string }[] = [];
  const panels: string[] = [];

  if (threatGraph) {
    tabs.push({ id: 'threat-graph', label: 'Threat Graph', icon: icon('diagram') });
    const hasFullVariant = !!threatGraphFull && threatGraphFull !== threatGraph;
    panels.push(shell('threat-graph', 'Threat Graph',
      `
          <pre class="mermaid" data-variant="filtered">\n${esc(threatGraph)}\n</pre>
          ${hasFullVariant ? `<pre class="mermaid" data-variant="full" style="display:none">\n${esc(threatGraphFull)}\n</pre>` : ''}
          ${focus.map(f => `<pre class="mermaid" data-focus="${esc(f.name)}" style="display:none">\n${esc(f.src)}\n</pre>`).join('\n          ')}
        `,
      `Assets, threats, controls, and mitigations. ${hasFullVariant ? 'Filtered to high/critical by default — click <em>All severities</em> to expand. ' : ''}${LEGEND_THREAT}`,
      (focus.length > 0 ? `
            <select class="diagram-focus" onchange="diagramFocus(this.value)" title="Show one asset with its threats, controls and neighbours"><option value="">Whole graph</option>${focus.map(f => `<option value="${esc(f.name)}">${esc(f.name)}</option>`).join('')}</select>` : '') + (hasFullVariant ? `
            <button id="threatGraphToggle" class="diagram-btn" onclick="toggleThreatGraphAll(this)" title="Show all threat severities (not just high/critical)">All severities</button>` : ''),
      true));
  }
  if (dataFlow) {
    tabs.push({ id: 'data-flow', label: 'Data Flow', icon: icon('arrows') });
    panels.push(shell('data-flow', 'Data Flow', `<pre class="mermaid">\n${esc(dataFlow)}\n</pre>`,
      `Data movement across trust boundaries; each boundary shows both sides of the trust line. ${LEGEND_FLOW}`, '', panels.length === 0));
  }
  if (attackSurface) {
    tabs.push({ id: 'attack-surface', label: 'Attack Surface', icon: icon('alert') });
    panels.push(shell('attack-surface', 'Attack Surface', `<pre class="mermaid">\n${esc(attackSurface)}\n</pre>`,
      `Exposures per asset. ${LEGEND_SURFACE}`, '', panels.length === 0));
  }

  if (tabs.length === 0) {
    return `
<div id="sec-diagrams" class="section-content">
  ${sectionHead(icon('diagram'), 'Diagrams', scope)}
  <p class="empty-state">${scope
    ? `Nothing to draw for ${esc(scopeLabel(scope))} — the files tagged with ${scope.length > 1 ? 'these features' : 'this feature'} carry no <code>@exposes</code>, <code>@flows</code> or <code>@mitigates</code>. The project's own diagrams are not shown on a slice; regenerate without <code>--feature</code> to see them.`
    : 'No diagram data — add @exposes, @flows, or @mitigates annotations.'}</p>
</div>`;
  }

  return `
<div id="sec-diagrams" class="section-content">
  ${sectionHead(icon('diagram'), 'Diagrams', scope)}
  ${wholeModelNote()}
  <p class="diagram-hint">Interactive diagrams generated from annotations. The view starts fitted to the panel (never below 60%, so labels stay legible; scroll sideways for the rest); scroll to zoom, drag to pan, double-click or press <em>Fit</em> to reset. <em>Find</em> dims everything that does not match; on the threat graph, pick an asset to see only it and its neighbours. <em>Source</em> copies the Mermaid text.</p>
${scope ? `  <p class="scope-note">These are <strong>narrowed</strong> diagrams: the edges are this feature's relations, and the nodes are the assets, threats and controls those relations reference. A node the feature never touches is absent — an absent node does not mean the project lacks it. The same narrowed graph is written to <code>.guardlink/graph/by-feature/</code>.</p>` : ''}
  <div class="diagram-tabs">
    ${tabs.map((t, i) => `<button class="diagram-tab${i === 0 ? ' active' : ''}" onclick="switchDiagramTab('${t.id}', this)">${t.icon} ${t.label}</button>`).join('')}
  </div>
  ${panels.join('\n')}
</div>`;
}
