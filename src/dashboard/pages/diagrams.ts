/**
 * GuardLink Dashboard — Diagrams: four tabs, each drawn as our own SVG.
 *
 *   Threat graph    assets → threats → controls, one thread per exposure and per mitigation
 *   Data flow       the whole model as flow ribbons; any node opens its neighbourhood
 *   Attack surface  every asset on a shelf, one tick per exposure
 *   Agent reach     who acts → capability → the effect it lands
 *   System model    the data-flow diagram, with trust boundaries drawn as zones
 *
 * Every whole-model picture is laid out here, at generation time, from data
 * alone, and emitted as SVG. Nothing is handed to a third-party layout engine
 * in the browser, so nothing can be laid out into a hidden or zero-size panel
 * and come back NaN, and nothing has to be re-drawn when a tab is shown. The
 * client adds hover and pin by toggling classes; the neighbourhood is redrawn
 * on a walk by the same self-contained renderer that drew its first frame.
 *
 * This page also holds what were the Explore and Data & Boundaries pages:
 * Explore's questions are the entry points that pick a neighbourhood's focus,
 * its undefended routes sit under the data flow, and the flow, boundary and
 * classification tables are the data flow's table twin.
 *
 * Mermaid text is still generated for the `.mmd` artifacts and the report;
 * none of it is on this page.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Labels reach the SVG through the layout modules' xml()/attrs(); everything interpolated here goes through esc()"
 */
import { esc, sectionHead, wholeModelNote, scopeLabel, locInline, stateChip } from '../html.js';
import { plural } from '../layout/text.js';
import type { PageContext } from './context.js';
import type { DiagramModel } from '../layout/graph.js';
import { renderThreatGraph } from '../layout/threat-graph.js';
import { renderRibbons } from '../layout/ribbons.js';
import { renderHoodSvg, renderNodeDetail, type HoodPayload } from '../layout/hood.js';
import { renderShelves } from '../layout/shelves.js';
import { renderReachDiagram } from '../layout/reach.js';
import { renderSystemModel, type BoundaryState } from '../layout/system.js';
import { flowTables } from './tables.js';
import type { PathFinding } from '../../paths/index.js';
import { unevaluatedReason } from '../../paths/format.js';

export interface DiagramsInput {
  graph: DiagramModel;
  /** Tested state per declared boundary, keyed `file:line`. */
  boundaryStates: Map<string, BoundaryState>;
  hood: HoodPayload;
  nodeIndex: Map<string, number>;
  /** The node the neighbourhood opens on when no focus is in the route. */
  defaultFocus: number;
  paths: PathFinding[];
  pathsTotal: number;
  endpoints: { entries: string[]; exits: string[] };
}

const TABS: [string, string][] = [['threat', 'Threat graph'], ['flow', 'Data flow'], ['surface', 'Attack surface'], ['reach', 'Agent reach'], ['system', 'System model']];

const legendSw = (cls: string, text: string): string => `<span><i class="lg ${cls}"></i>${text}</span>`;

function pinBar(plot: string): string {
  return `<div class="pin-bar" data-pin-bar="${plot}" hidden><span class="eyebrow">Pinned</span> <b class="mono" data-pin-label></b><span class="subtle" data-pin-count></span><button class="btn ghost" data-unpin="${plot}">Clear pin</button></div>
  <div class="twin" data-twin="${plot}" hidden></div>`;
}

function threatTab(g: DiagramModel): string {
  if (g.exposures.length === 0 && g.mitigations.length === 0) return '<p class="empty-state">This model declares no <code>@exposes</code> or <code>@mitigates</code>, so there is no threat graph to draw.</p>';
  const r = renderThreatGraph(g);
  return `
  <p class="guide">Assets → threats → controls. One line per exposure: <b>warm</b> open, <b>mint</b> mitigated, <b>dashed</b> accepted. Hover to trace it; click to list its exposures.</p>
  <div class="panel plot-panel"><div class="plot-scroll">${r.svg}</div></div>
  <div class="fidelity"><span><b class="num">${r.exposuresDrawn}</b> of ${r.exposures} exposures and <b class="num">${r.mitigationsDrawn}</b> of ${r.mitigations} mitigations drawn</span><span>${plural(r.assets, 'asset')} · ${plural(r.threats, 'threat')} · ${plural(r.controls, 'control')}</span>${r.uncontrolled ? `<span>${plural(r.uncontrolled, 'mitigation')} name no control (the dashed tick)</span>` : ''}${r.folded ? `<span>${plural(r.folded, 'name')} folded so names stay 11 px apart — hover a tick for it</span>` : ''}</div>
  <div class="legend">${legendSw('thr-open', 'open, by severity')}${legendSw('thr-res', 'mitigated or refuted')}${legendSw('thr-acc', 'accepted')}${legendSw('thr-ctl', 'mitigation → control')}</div>
  ${pinBar('threat')}`;
}

function flowTab(ctx: PageContext, d: DiagramsInput): string {
  const g = d.graph;
  if (g.flows.length === 0) {
    return `<p class="empty-state">This model declares no <code>@flows</code>, so there is no data flow to draw. The threat graph and attack surface still draw every exposure.</p>${flowTables(ctx)}`;
  }
  const r = renderRibbons(g, d.nodeIndex);
  const hood = renderHoodSvg(d.hood, d.defaultFocus);
  const nodes = d.hood.nodes;
  // Explore's questions, as entry points that pick the neighbourhood's focus.
  const byOpen = nodes.map((n, i) => ({ n, i })).filter(x => !x.n.x && x.n.o > 0).sort((a, b) => b.n.o - a.n.o || a.i - b.i)[0];
  const degree = (i: number): number => d.hood.flows.filter(f => f[0] === i || f[1] === i).length;
  const byFlows = nodes.map((n, i) => ({ n, i })).sort((a, b) => degree(b.i) - degree(a.i) || a.i - b.i)[0];
  const byTrust = nodes.map((n, i) => ({ n, i })).filter(x => x.n.b.length > 0).sort((a, b) => b.n.b.length - a.n.b.length || degree(b.i) - degree(a.i) || a.i - b.i)[0];
  const entry = (label: string, x: { n: { k: string; l: string }; i: number } | undefined): string =>
    x ? `<a class="chip" href="#diagrams?tab=flow&amp;view=hood&amp;focus=${encodeURIComponent(x.n.k)}"><span class="subtle">${esc(label)}</span> <span class="mono">${esc(x.n.l)}</span></a>` : '';
  const usedNodes = nodes.map((n, i) => ({ n, i })).filter(x => degree(x.i) > 0);
  const paths = d.paths;
  return `
  <div class="view-bar">
    <div class="seg" role="group" aria-label="View">
      <a class="seg-btn" href="#diagrams?tab=flow&amp;view=ribbons" data-view-btn="ribbons">Whole model · flow ribbons</a>
      <a class="seg-btn" href="#diagrams?tab=flow&amp;view=hood" data-view-btn="hood">Neighbourhood</a>
    </div>
    <div class="entry-chips"><span class="eyebrow">Start from</span>${entry('most open', byOpen)}${entry('most flows', byFlows)}${entry('on a trust boundary', byTrust)}
      <select data-focus-select aria-label="Open the neighbourhood of a node">${usedNodes.map(x => `<option value="${esc(x.n.k)}"${x.i === d.defaultFocus ? ' selected' : ''}>${esc(x.n.l)}${x.n.o ? ` — ${x.n.o} open` : ''}</option>`).join('')}</select>
    </div>
  </div>

  <div data-view-panel="ribbons">
    <p class="guide">Every flow, from where data starts (left) to where it lands (right). Flows between the same groups bundle into a ribbon. <b>Bold</b> flows cross a trust boundary — ⊢ counts them. Click a node for its detail.</p>
    <div class="panel plot-panel"><div class="plot-scroll">${r.svg}</div></div>
    <div class="fidelity"><span><b class="num">${r.drawn}</b> of ${r.flows} flows drawn · ${plural(r.nodes, 'node')} · ${plural(r.ribbons, 'ribbon')}</span><span>${r.crossing} cross a declared trust boundary (stronger ink, ⊢ in the pill)</span>${r.folded ? `<span>${plural(r.folded, 'tick name')} folded to avoid collisions — hover a tick for it</span>` : ''}</div>
    <div class="legend">${legendSw('m-open s-high', 'asset with an open exposure (worst severity)')}${legendSw('m-res', 'asset, all mitigated')}${legendSw('m-empty', 'asset, nothing declared')}${legendSw('m-ext', 'outside the model')}${legendSw('thr-cross', 'crosses a trust boundary')}</div>
  </div>

  <div data-view-panel="hood" hidden>
    <div class="trail" data-hood-trail><span class="eyebrow">Focus</span> <b class="mono" data-hood-focus>${esc(nodes[d.defaultFocus].l)}</b></div>
    <div class="panel plot-panel"><div class="plot-scroll" data-hood-host>${hood.svg}</div></div>
    <div class="fidelity" data-hood-footer><span><b class="num">${hood.drawn}</b> flows drawn among ${plural(hood.nodes, 'node')} (budget: 7 per column)</span>${hood.undrawn ? `<span>${hood.undrawn} flows among these nodes run backwards or within a column and are listed in the table, not drawn</span>` : ''}<span>Click a card to step to it; the trail takes you back. A bar ⊢ marks a trust boundary. Hover a line to see how the data moves.</span></div>
  </div>

  <div class="panel" data-node-detail>${renderNodeDetail(d.hood, d.defaultFocus, 'ribbons')}</div>

  <h3 class="block-h">Undefended routes</h3>
  <p class="guide">Routes from an entry point to a sink with no mitigation anywhere on the way. Between ${plural(d.endpoints.entries.length, 'entry point')} and ${plural(d.endpoints.exits.length, 'sink')}: ${paths.length} of ${plural(d.pathsTotal, 'route')}.</p>
  ${paths.length > 0 ? `<div class="paths">${paths.map(p => `
    <div class="path-finding">
      <div class="path-chain">${p.chain.map((n, i) => `${i > 0 ? '<span class="path-arrow">→</span>' : ''}<code class="path-node${p.assetsOnPath.includes(n) ? ' path-asset' : ''}">${esc(n)}</code>`).join('')}</div>
      <div class="path-meta">${p.crossesBoundary ? stateChip('open', `crosses ${p.boundariesCrossed.join(', ')}`) : stateChip('accepted', 'no declared boundary on this route')}<span class="path-hops">${p.hops.map(h => locInline(h.via.file, h.via.line, ctx.links)).join(' · ')}</span></div>
    </div>`).join('')}</div>` : unevaluatedReason(d.endpoints) ? `<p class="empty-state">${esc(unevaluatedReason(d.endpoints)!)} Entries and sinks are <code>@flows</code> endpoints that are not declared <code>@asset</code>s, so this is not a clean result: no route was examined.</p>` : `<p class="empty-state">No undefended route found. Every one of the ${plural(d.pathsTotal, 'entry-to-sink route')} in this model passes through at least one component carrying a <code>@mitigates</code>.</p>`}

  <h3 class="block-h">The same flows, as rows</h3>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn ghost" data-clear-filters>Clear</button></div>
  ${flowTables(ctx)}`;
}

function surfaceTab(g: DiagramModel): string {
  if (g.assets.length === 0) return '<p class="empty-state">No assets to put on a shelf.</p>';
  const r = renderShelves(g);
  return `
  <p class="guide">One card per asset, one tick per exposure: <b>warm</b> open, <b>mint</b> mitigated, <b>hollow</b> accepted. Wider card, more exposures. Click a card to see them.</p>
  ${r.html}
  <div class="fidelity"><span><b class="num">${r.cards}</b> asset cards on ${plural(r.shelves, 'shelf', 'shelves')} · ${plural(r.exposures, 'exposure')} drawn as ticks</span></div>
  <div class="legend">${legendSw('tk-open', 'tick: open, by severity')}${legendSw('tk-res', 'mitigated or refuted')}${legendSw('tk-acc', 'accepted')}<span>rule: open share · dashed: nothing declared</span><span>⊢ trust boundaries · tags: data it handles</span></div>
  ${pinBar('surface')}`;
}

function reachTab(ctx: PageContext): string {
  const r = renderReachDiagram(ctx.reach);
  if (!r) {
    return `<p class="empty-state">${ctx.scope
      ? `No <code>@agents</code>, <code>@reaches</code> or <code>@effects</code> in the files tagged ${esc(scopeLabel(ctx.scope))}.`
      : 'This model declares no <code>@agents</code>, <code>@reaches</code> or <code>@effects</code>, so nothing says what an embedded agent or another principal can reach.'} <a href="#agents">Agents &amp; reach</a> shows how to declare it.</p>`;
  }
  const t = ctx.reach.totals;
  return `
  <p class="guide">Who acts → what they may do → what it changes. ✓ approved, ✕ not. <b>Warm</b>: changes something with no sign-off. A bar: a person approves first.</p>
  <div class="panel plot-panel"><div class="plot-scroll">${r.svg}</div></div>
  <div class="fidelity"><span><b class="num">${r.reaches}</b> of ${t.reaches} reaches · <b class="num">${r.effects}</b> of ${t.effects} effects drawn</span><span>${t.unentitled} unentitled · ${t.ungated} of ${t.mutations} mutations ungated · ${t.gates} gates</span><span>the same facts as rows: <a href="#agents">Agents &amp; reach</a></span></div>
  <div class="legend">${legendSw('cap-ok', '✓ entitled capability')}${legendSw('cap-bad', '✕ unentitled')}${legendSw('eff-ungated', 'mutation, no gate')}${legendSw('eff-gated', 'gated: a named approver decides first')}${legendSw('eff-read', 'reads only')}</div>`;
}

function systemTab(d: DiagramsInput): string {
  const r = renderSystemModel(d.graph, { states: d.boundaryStates });
  if (!r) return '<p class="empty-state">This model declares no <code>@flows</code>, so there is no system to draw. The threat graph and attack surface still draw every exposure.</p>';
  return `
  <p class="guide">Your system as a data-flow diagram. Dashed boxes are trust zones; a bar ⊢ marks where a flow crosses one. A <b>dashed</b> flow leaves a zone with no boundary declared — worth a look. Click anything for its flows.</p>
  ${r.implied ? `<div class="plot-head"><label class="toggle"><input type="checkbox" data-system-implied checked> Show flows that leave a zone with no boundary declared (${r.implied})</label></div>` : ''}
  <div class="panel plot-panel"><div class="plot-scroll">${r.svg}</div></div>
  <div class="fidelity"><span><b class="num">${r.flows}</b> of ${r.flows} flows drawn, as ${plural(r.lines, 'line')} (repeat flows between one pair share a line — hover for each)</span><span><b class="num">${r.elements}</b> of ${r.elements} elements: ${plural(r.processes, 'process', 'processes')} · ${plural(r.stores, 'data store')} · ${plural(r.entities, 'external entity', 'external entities')} — kinds inferred from names and mechanisms</span><span>${plural(r.boundaries, 'boundary', 'boundaries')} · ${plural(r.outerZones + (r.innerZones > 1 ? r.innerZones : 0), 'trust zone')} · ${r.crossing} flows cross one as declared${r.implied ? ` · ${r.implied} leave a zone with none declared` : ''}</span>${r.silent.length ? `<span>no flow crosses ${esc(r.silent.join(', '))} as declared</span>` : ''}${r.unsplit.length ? `<span>${esc(r.unsplit.join(', '))}: a route around it, so drawn as a gate, not a zone</span>` : ''}</div>
  <div class="legend">${legendSw('k-proc', 'process: a declared asset')}${legendSw('k-store', 'data store')}${legendSw('k-ent', 'external entity')}${legendSw('k-zone', 'trust zone')}${legendSw('thr-cross', 'crosses a trust boundary ⊢')}${legendSw('thr-implied', 'leaves a zone, no boundary declared')}${legendSw('thr-flow', 'flow inside the system')}<span>○ boundary untested · ✓ held · ✕ broken</span></div>`;
}

export function renderDiagramsPage(ctx: PageContext, d: DiagramsInput): string {
  const { scope } = ctx;
  return `
<section id="sec-diagrams" class="section-content" aria-label="Diagrams">
  ${sectionHead('', 'Diagrams', scope)}
  ${wholeModelNote()}
  <p class="lead">Five views of one model. Nothing is left out — each footer says what is drawn.</p>
${scope ? `  <p class="scope-note">These are <strong>narrowed</strong> diagrams: the edges are this feature's relations, and the nodes are the assets, threats and controls those relations reference. A node the feature never touches is absent — an absent node does not mean the project lacks it. The same narrowed graph is written to <code>.guardlink/graph/by-feature/</code>.</p>` : ''}
  <nav class="tabs" role="tablist" aria-label="Diagram">${TABS.map(([k, l]) => `<a class="tab" role="tab" href="#diagrams?tab=${k}" data-tab="${k}">${l}</a>`).join('')}</nav>
  <div class="tab-panel" data-tab-panel="threat">${threatTab(d.graph)}</div>
  <div class="tab-panel" data-tab-panel="flow" hidden>${flowTab(ctx, d)}</div>
  <div class="tab-panel" data-tab-panel="surface" hidden>${surfaceTab(d.graph)}</div>
  <div class="tab-panel" data-tab-panel="reach" hidden>${reachTab(ctx)}</div>
  <div class="tab-panel" data-tab-panel="system" hidden>${systemTab(d)}</div>
</section>`;
}
