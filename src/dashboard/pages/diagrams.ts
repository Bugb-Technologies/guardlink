/**
 * GuardLink Dashboard — Diagrams: threat graph, data flow, attack surface.
 * Mermaid sources are embedded escaped and rendered client-side.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Mermaid source is escaped into the <pre>; the client reads it back as text"
 * @comment -- "Ported from the first generate.ts with the same panel ids and data-variant hooks the diagram script expects; the toolbar is a segmented zoom group plus copy-source"
 */
import { esc, scopeLabel, sectionHead, icon, wholeModelNote } from '../html.js';
import {
  checkRenderBudget, oversizedStub, describeViolation,
  DASHBOARD_FALLBACK, MERMAID_LIMITS_SOURCE,
} from '../render-budget.js';
import { checkLegibility, describeLegibility, LEGIBILITY_BUDGET } from '../../graph/legibility.js';
import type { PageContext } from './context.js';

/**
 * A diagram is embedded only if something will draw it.
 *
 * The dashboard's failure at scale was not that the picture got crowded — it was
 * that Mermaid's text-size limit fails SILENTLY. `mermaid.render` resolves, the
 * console stays empty, and the page draws one pink box reading "Maximum text
 * size in diagram exceeded" while keeping the zoom controls, the Find box, the
 * focus dropdown and a legend describing a diagram that is not there.
 *
 * So the check happens here, where the source is placed into the page, and an
 * over-budget diagram is swapped for a stub that says what exceeded and by how
 * much. The stub goes inside the same `<pre class="mermaid">` on purpose: the
 * variant toggle, the focus dropdown and `diagramFind` all address these
 * elements by class and `data-` attribute, and a different element here would
 * make the toggle silently do nothing — one more control that looks live and is
 * not. The banner above the panel carries the same facts as real HTML, for the
 * reader who should not have to read a diagram to learn that the diagram is
 * missing.
 */
interface BudgetedDiagram {
  /** The Mermaid source to embed — the stub when the original is over budget. */
  src: string;
  /** One line per violation, empty when the diagram is fine. */
  reasons: string[];
  /**
   * How far past READABLE this diagram is, when it is. Empty when it fits.
   *
   * A second question about the same drawing, and the one that fails first. The
   * render budget above asks whether anything will draw it; this asks whether
   * anyone can read what gets drawn, and between the two limits sits every
   * whole-model diagram GuardLink has ever produced — 43 nodes on this
   * repository against a measured ceiling of 12, drawn perfectly and telling
   * the reader nothing. Saying so is the difference between a picture that is
   * honest about its size and one presented as though it were fine.
   */
  tooBig: string;
}

function budgeted(name: string, src: string): BudgetedDiagram {
  if (!src) return { src, reasons: [], tooBig: '' };
  const legibility = checkLegibility(src);
  const tooBig = legibility.legible ? '' : `${name} — ${describeLegibility(legibility)}`;
  const verdict = checkRenderBudget(src);
  if (verdict.renderable) return { src, reasons: [], tooBig };
  return {
    src: oversizedStub(name, verdict, DASHBOARD_FALLBACK),
    reasons: verdict.violations.map(v => `${name} — ${describeViolation(v)}. ${v.symptom}`),
    // A diagram that was not drawn at all has no drawn size to be honest about;
    // the render-budget banner above it already says what happened.
    tooBig: '',
  };
}

/**
 * The notice above a whole-model diagram that draws but cannot be read.
 *
 * Deliberately not styled as an error and deliberately not a refusal: the
 * drawing stays, because on a small repository it is the right picture and
 * because panning around a big one is sometimes what a reader wants. What
 * changes is that the page stops implying it is legible, and names the surface
 * that answers the same question at a size that is.
 */
function legibilityNotice(tooBig: string[]): string {
  if (tooBig.length === 0) return '';
  return `<div class="diagram-toobig" role="note">
          <strong>${tooBig.length > 1 ? 'These are whole-model diagrams' : 'This is a whole-model diagram'}, past the size anyone can read.</strong>
          <ul>${tooBig.map(t => `<li>${esc(t)}</li>`).join('')}</ul>
          <p>The budget is ${LEGIBILITY_BUDGET.nodes} nodes and ${LEGIBILITY_BUDGET.edges} edges, measured against this panel at its label size — past it the drawing grows taller than the panel and "Fit" shrinks the labels below reading size rather than fitting. It still draws, and zoom and pan still work, so it is kept: on a small model it is the right picture. For a model this size, <a href="#explore">Explore</a> answers one question at a time and every answer is sized to be read.</p>
        </div>`;
}

/**
 * What the panel footer says when nothing in it was drawn.
 *
 * The legend is a key to shapes and colours that are not on the page. Leaving it
 * under a stub is a smaller version of the same defect — a control describing
 * content that is not there — so a fully-stubbed panel drops it.
 */
function budgetMeta(allStubbed: boolean, meta: string): string {
  return allStubbed
    ? 'No diagram is drawn at this size — see the notice above. The legend is omitted because there is nothing to key.'
    : meta;
}

/** The plain-HTML notice that sits above a panel holding at least one stub. */
function budgetBanner(reasons: string[]): string {
  if (reasons.length === 0) return '';
  return `<div class="diagram-budget" role="status">
          <strong>${reasons.length > 1 ? 'These diagrams were' : 'This diagram was'} not drawn.</strong>
          <ul>${reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
          <p>The limits are Mermaid's own (${esc(MERMAID_LIMITS_SOURCE)}), so this model does not draw in GitHub or mermaid.live either — it is the picture that does not fit, not the model. ${esc(DASHBOARD_FALLBACK)} Tagging code with <code>@feature</code> also gives one smaller graph per feature, in <code>.guardlink/graph/by-feature/</code>.</p>
        </div>`;
}

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
    const bFiltered = budgeted('Threat Graph (high/critical)', threatGraph);
    const bFull = budgeted('Threat Graph (all severities)', hasFullVariant ? threatGraphFull : '');
    const bFocus = focus.map(f => ({ name: f.name, ...budgeted(`Threat Graph — ${f.name}`, f.src) }));
    panels.push(shell('threat-graph', 'Threat Graph',
      `${budgetBanner([...bFiltered.reasons, ...bFull.reasons, ...bFocus.flatMap(f => f.reasons)])}
          ${legibilityNotice([bFiltered.tooBig, bFull.tooBig].filter(Boolean))}
          <pre class="mermaid" data-variant="filtered">\n${esc(bFiltered.src)}\n</pre>
          ${hasFullVariant ? `<pre class="mermaid" data-variant="full" style="display:none">\n${esc(bFull.src)}\n</pre>` : ''}
          ${bFocus.map(f => `<pre class="mermaid" data-focus="${esc(f.name)}" style="display:none">\n${esc(f.src)}\n</pre>`).join('\n          ')}
        `,
      budgetMeta(
        bFiltered.reasons.length > 0
          && (!hasFullVariant || bFull.reasons.length > 0)
          && bFocus.every(f => f.reasons.length > 0),
        `Assets, threats, controls, and mitigations. ${hasFullVariant ? 'Filtered to high/critical by default — click <em>All severities</em> to expand. ' : ''}${LEGEND_THREAT}`),
      (focus.length > 0 ? `
            <select class="diagram-focus" onchange="diagramFocus(this.value)" title="Show one asset with its threats, controls and neighbours"><option value="">Whole graph</option>${focus.map(f => `<option value="${esc(f.name)}">${esc(f.name)}</option>`).join('')}</select>` : '') + (hasFullVariant ? `
            <button id="threatGraphToggle" class="diagram-btn" onclick="toggleThreatGraphAll(this)" title="Show all threat severities (not just high/critical)">All severities</button>` : ''),
      true));
  }
  if (dataFlow) {
    tabs.push({ id: 'data-flow', label: 'Data Flow', icon: icon('arrows') });
    const b = budgeted('Data Flow', dataFlow);
    panels.push(shell('data-flow', 'Data Flow', `${budgetBanner(b.reasons)}${legibilityNotice([b.tooBig].filter(Boolean))}<pre class="mermaid">\n${esc(b.src)}\n</pre>`,
      budgetMeta(b.reasons.length > 0,
        `Data movement across trust boundaries; each boundary shows both sides of the trust line. ${LEGEND_FLOW}`), '', panels.length === 0));
  }
  if (attackSurface) {
    tabs.push({ id: 'attack-surface', label: 'Attack Surface', icon: icon('alert') });
    const b = budgeted('Attack Surface', attackSurface);
    panels.push(shell('attack-surface', 'Attack Surface', `${budgetBanner(b.reasons)}${legibilityNotice([b.tooBig].filter(Boolean))}<pre class="mermaid">\n${esc(b.src)}\n</pre>`,
      budgetMeta(b.reasons.length > 0, `Exposures per asset. ${LEGEND_SURFACE}`), '', panels.length === 0));
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
  <p class="diagram-hint"><strong>These are the whole model in one picture.</strong> That is the right thing on a small repository and stops being readable at about a dozen components — each panel below says its own size, and <a href="#explore">Explore</a> is where a question gets an answer scaled to be read. Scroll to zoom, drag to pan, double-click or press <em>Fit</em> to reset. <em>Find</em> dims everything that does not match; on the threat graph, pick an asset to see only it and its neighbours. <em>Source</em> copies the Mermaid text.</p>
${scope ? `  <p class="scope-note">These are <strong>narrowed</strong> diagrams: the edges are this feature's relations, and the nodes are the assets, threats and controls those relations reference. A node the feature never touches is absent — an absent node does not mean the project lacks it. The same narrowed graph is written to <code>.guardlink/graph/by-feature/</code>.</p>` : ''}
  <div class="diagram-tabs">
    ${tabs.map((t, i) => `<button class="diagram-tab${i === 0 ? ' active' : ''}" onclick="switchDiagramTab('${t.id}', this)">${t.icon} ${t.label}</button>`).join('')}
  </div>
  ${panels.join('\n')}
</div>`;
}
