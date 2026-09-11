/**
 * GuardLink Dashboard — Explore: ask a question, see the part of the graph that
 * answers it.
 *
 * The Diagrams page draws the whole model. On this repository that is 43 nodes
 * against a measured legibility ceiling of 12, and on a 257-file repository it
 * is a pink box reading "Maximum text size in diagram exceeded". This page is
 * the other half of the answer: every panel here is scoped to one question and
 * budgeted to something a person can read, and the panel says which question it
 * is answering before it shows anything.
 *
 * ── What this page does that the old focus dropdown did not ──────────
 *
 * The dropdown on the Diagrams page already pre-rendered a per-asset slice, and
 * it was a real improvement — 68% of the drawing visible against 5% for the
 * whole Data Flow. It was still a hairball, for three reasons this page fixes:
 *
 *   it was sized by HOPS (`depth: 1`) rather than by the drawing, so the slice
 *   for one asset dragged in a neighbour's entire threat plane and came out at
 *   20 nodes — 1.7x over budget;
 *
 *   it fused the two planes onto one canvas, so "what is this exposed to" and
 *   "what does it talk to" competed for the same layout;
 *
 *   it never said what it left out, so a partial picture read as a whole one.
 *
 * Every panel here states its size against the budget, and every narrowed panel
 * names what fell outside the frame.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every interpolated value — asset ids, threat names, file paths, descriptions, boundary labels and the Mermaid source itself — goes through esc(); the Mermaid text is escaped into the <pre> and read back by the client as textContent"
 * @comment -- "Panes carry .diagram-panel so the existing zoom, find and copy-source controls work unchanged; .explore-pane is what the router shows and hides"
 * @comment -- "Nothing is selected in the browser: buildExploreData has already run every query at generation time, so the page holds answers rather than a query engine"
 */
import {
  esc, icon, sectionHead, subHead, badge,
  locInline, heatTable, routeWithQuery, plural, wholeModelNote,
} from '../html.js';
import { GRAPH_VIEWS, type GraphView } from '../../graph/views.js';
import { LEGIBILITY_BUDGET } from '../../graph/legibility.js';
import { computeAssetThreatMatrix } from '../analytics.js';
import { canonicaliser } from '../../mcp/subgraph.js';
import type { ExploreData, ExploreDiagram } from '../explore.js';
import type { PageContext } from './context.js';

/** Assets and threats the matrix will show before it starts eliding. */
const MATRIX_ROWS = 24;
const MATRIX_COLS = 14;
/** Rows in the "what to fix next" worklist before it points at the full table. */
const WORKLIST = 25;

/**
 * Where the rows for a pane come from.
 *
 * A slot, not a table. Every view wants the same rows — status, severity, the
 * claim, and the `file:line` it was written on — and every claim belongs to one
 * component, one weakness class and one file, so rendering the rows into each
 * pane here would put every claim on the page three times over. Measured: doing
 * exactly that added **1.19 MB to a 4.21 MB dashboard, +28%**, almost all of it
 * the same descriptions repeated.
 *
 * `claimsData` is already embedded for the Threats table and the drawer, so the
 * client fills these in from data the page was carrying anyway. The rows it
 * builds carry `data-claim`, which the existing delegated click handler turns
 * into the claim drawer with no extra wiring.
 *
 * The counts a heading wants are filled in the same pass, through
 * `data-rows-count`, rather than being computed twice on two sides of the wire.
 */
function rowSlot(kind: string, value: string, opts: { limit?: number; noAsset?: boolean; empty?: string } = {}): string {
  return `<div class="explore-rows-slot" data-rows-kind="${esc(kind)}" data-rows-value="${esc(value)}"`
    + `${opts.limit ? ` data-rows-limit="${opts.limit}"` : ''}${opts.noAsset ? ' data-rows-noasset="1"' : ''}`
    + `${opts.empty ? ` data-rows-empty="${esc(opts.empty)}"` : ''}></div>`;
}

/** A count the client fills from the same pass that renders the rows. */
function rowCount(kind: string, value: string, suffix = ''): string {
  return `<span data-rows-count="${esc(kind)}:${esc(value)}">—</span>${esc(suffix)}`;
}

/**
 * A diagram, or an honest statement of why there is not one.
 *
 * Three outcomes, and the panel must be able to tell them apart, because
 * conflating them is the defect this whole page exists to remove:
 *
 *   drawn            the picture, plus its size against the budget
 *   drawn, narrowed  the picture, plus what the narrowing hid
 *   not drawn        no canvas at all, and a sentence saying why
 *
 * The third never renders an empty frame. An empty diagram panel with a
 * toolbar, a legend and zoom controls above it is precisely how the whole-model
 * view failed at scale, and repeating it here at a smaller size would be the
 * same lie in a nicer font.
 */
function diagramBlock(title: string, purpose: string, d: ExploreDiagram): string {
  const body = d.source
    ? `<div class="mermaid-wrap"><pre class="mermaid">\n${esc(d.source)}\n</pre></div>`
    : `<p class="explore-nodraw">${esc(d.emptyReason ?? 'Nothing to draw.')}</p>`;

  const notes: string[] = [];
  if (d.source) notes.push(esc(d.budgetNote));
  if (d.narrowing === 'high-severity-only') {
    notes.push(`narrowed to high and critical — ${d.hidden ?? 0} lower-severity ${plural(d.hidden ?? 0, 'claim')} hidden, all of them in the rows below`);
  }
  if (d.source && d.omitted.length > 0) {
    notes.push(`${d.omitted.length} ${plural(d.omitted.length, 'neighbour')} just outside the frame: ${d.omitted.slice(0, 8).map(esc).join(', ')}${d.omitted.length > 8 ? `, and ${d.omitted.length - 8} more` : ''}`);
  }
  if (!d.source && !d.legible) {
    notes.push(`the full picture would be ${esc(d.budgetNote)}`);
  }

  return `<div class="explore-diagram">
    <div class="explore-diagram-head"><span class="explore-diagram-title">${esc(title)}</span><span class="explore-diagram-purpose">${esc(purpose)}</span></div>
    ${body}
    ${notes.length > 0 ? `<p class="explore-budget">${notes.join(' · ')}</p>` : ''}
  </div>`;
}

/** One answer pane. Hidden until the router selects it. */
function pane(view: string, subject: string, body: string, active = false): string {
  return `<div class="explore-pane diagram-panel${active ? ' active' : ''}" data-view="${esc(view)}" data-subject="${esc(subject)}">${body}</div>`;
}

/** What this view is for, rendered above every answer it can give. */
function purposeBlock(v: GraphView): string {
  return `<div class="explore-purpose" data-view="${esc(v.id)}" hidden>
    <p class="explore-question">${esc(v.question)}</p>
    ${v.shapeReason ? `<p class="explore-shape"><strong>${esc(SHAPE_LABEL[v.shape])}.</strong> ${esc(v.shapeReason)}</p>` : ''}
  </div>`;
}

const SHAPE_LABEL: Record<GraphView['shape'], string> = {
  diagram: 'Answered as a diagram',
  matrix: 'Answered as a matrix, not a diagram',
  list: 'Answered as a list, not a diagram',
  chains: 'Answered as chains, not a diagram',
};

const TOOLS = `
      <input class="diagram-find" type="search" placeholder="Find node" aria-label="Find a node in the diagram" oninput="diagramFind(this.value)">
      <div class="diagram-seg" role="group" aria-label="Zoom">
        <button class="diagram-btn" onclick="diagramZoom('out')" title="Zoom out">−</button>
        <button class="diagram-btn" onclick="diagramZoom('fit')" title="Fit to panel (or double-click the diagram)">Fit</button>
        <button class="diagram-btn" onclick="diagramZoom('in')" title="Zoom in">+</button>
      </div>`;

export function renderExplorePage(ctx: PageContext, data: ExploreData): string {
  const { scope, claims, model } = ctx;
  const key = canonicaliser(model);
  const matrix = computeAssetThreatMatrix(claims);
  const shownAssets = matrix.assets.slice(0, MATRIX_ROWS);
  const shownThreats = matrix.threats.slice(0, MATRIX_COLS);
  const matrixCapped = shownAssets.length < matrix.assets.length || shownThreats.length < matrix.threats.length;
  const maxCell = Math.max(1, ...matrix.cells.map(c => c.total));
  const cellOf = new Map(matrix.cells.map(c => [`${c.asset} ${c.threat}`, c]));

  // Only offer a drill-down to an asset that actually has a pane.
  const paneForAsset = new Map(data.assets.map(a => [a.key, a]));
  const assetRoute = (asset: string): string => {
    const k = key(asset);
    return paneForAsset.has(k) ? `#explore?view=asset&subject=${encodeURIComponent(k)}` : routeWithQuery('threats', asset);
  };
  const threatRoute = (threat: string): string => `#explore?view=threat&subject=${encodeURIComponent(threat)}`;

  const views = GRAPH_VIEWS.filter(v => v.id !== 'diff' || data.diff !== null);
  const panes: string[] = [];

  // ── Where the risk is ─────────────────────────────────────────────
  panes.push(pane('overview', '', `
    ${matrix.cells.length > 0 ? heatTable({
    id: 'explore-matrix',
    rowHead: 'component \\ weakness',
    rows: shownAssets,
    cols: shownThreats,
    rowHref: a => assetRoute(a),
    colHref: t => threatRoute(t),
    cell: (a, t) => {
      const c = cellOf.get(`${a} ${t}`);
      if (!c) return null;
      return {
        value: c.total,
        h: c.total / maxCell,
        tone: c.worst === 'open' || c.worst === 'confirmed' ? 'red' : c.worst === 'mitigated' ? 'green' : 'blue',
        href: assetRoute(a),
        title: `${a} → ${t}: ${c.total} ${plural(c.total, 'exposure')} · ${c.open + c.confirmed} open · ${c.mitigated} mitigated · ${c.accepted} accepted · worst severity ${c.maxSev}. Opens the diagram for ${a}.`,
      };
    },
  }) : '<p class="empty-state">No exposures to chart — add <code>@exposes</code> annotations.</p>'}
    <p class="explore-budget">${matrix.assets.length} ${plural(matrix.assets.length, 'component')} against ${matrix.threats.length} ${plural(matrix.threats.length, 'weakness class')} — ${matrix.cells.length} ${plural(matrix.cells.length, 'pair')} in all. A matrix has no legibility budget to exceed: one cell per pair, however many pairs there are.${matrixCapped ? ` Showing the ${shownAssets.length} components with the most open exposures and the ${shownThreats.length} most frequent weaknesses; the rest are in <a href="#threats">Threats &amp; Exposures</a>.` : ''}</p>
    <p class="guide">Red means at least one claim in that cell is open or confirmed, green that all are mitigated, blue accepted; darker is more. <strong>Click a cell or a row to open that component's diagrams</strong>, a column for everywhere that weakness was declared.</p>
  `, true));

  // ── One component ─────────────────────────────────────────────────
  for (const a of data.assets) {
    panes.push(pane('asset', a.key, `
      <div class="explore-planes">
        ${diagramBlock('Exposed to', 'threats declared on this component, and the controls that answer them', a.threatPlane)}
        ${diagramBlock('Talks to', 'data flows and trust boundaries in its neighbourhood', a.flowPlane)}
      </div>
      ${subHead(`Every claim on ${a.label}`, '', `${rowCount('asset', a.key, ' rows')} · ${a.open} open`)}
      ${rowSlot('asset', a.key, { noAsset: true, empty: 'No claims recorded against this component.' })}`));
  }

  // ── One weakness class ────────────────────────────────────────────
  for (const threat of matrix.threats) {
    const rows = claims.filter(c => c.threat === threat);
    const open = rows.filter(c => c.status === 'open' || c.status === 'confirmed').length;
    const assetsHit = new Set(rows.map(c => c.asset));
    panes.push(pane('threat', threat, `
      ${subHead(threat, '', `${assetsHit.size} ${plural(assetsHit.size, 'component')} · ${open} still open`)}
      <p class="explore-budget">Drawn as a node-link graph this would be one node with ${assetsHit.size} ${plural(assetsHit.size, 'spoke')}, every spoke labelled the same word — past the ${LEGIBILITY_BUDGET.nodes}-node budget at ${LEGIBILITY_BUDGET.nodes + 1} components, and carrying nothing the rows do not. Open a component to see this weakness in its context.</p>
      ${rowSlot('threat', threat)}`));
  }

  // ── One trust line ────────────────────────────────────────────────
  for (const b of data.boundaries) {
    panes.push(pane('boundary', b.id, `
      ${subHead(b.label, '', b.sides.join('  ↔  '))}
      ${diagramBlock('Across the line', 'both sides, and what flows between them', b.diagram)}
      <p class="explore-budget">Declared at ${locInline(b.file, b.line, ctx.links)}.</p>`));
  }

  // ── Undefended routes ─────────────────────────────────────────────
  panes.push(pane('paths', '', pathsPane(ctx, data)));

  // ── Blast radius from a file ──────────────────────────────────────
  for (const f of data.files) {
    panes.push(pane('blast', f.file, `
      ${subHead(f.file, '', `${f.assets.length} ${plural(f.assets.length, 'component')} named here`)}
      ${diagramBlock('Reaches', 'the components this file names, and where their data goes', f.diagram)}
      ${subHead('Claims written in this file', '', rowCount('file', f.file, ' rows'))}
      ${rowSlot('file', f.file, { empty: 'This file names components in its flows but records no exposure, mitigation or confirmation of its own.' })}`));
  }

  // ── What to fix next ──────────────────────────────────────────────
  const openCount = claims.filter(c => c.status === 'open' || c.status === 'confirmed').length;
  panes.push(pane('open', '', `
    ${subHead('Open, worst first', '', `${openCount} ${plural(openCount, 'claim')}`)}
    ${rowSlot('open', '', { limit: WORKLIST, empty: 'Nothing open. Every declared exposure is mitigated or accepted.' })}
    <p class="explore-budget">${openCount > WORKLIST
      ? `The ${WORKLIST} worst of ${openCount}. <a href="${routeWithQuery('threats', '', { status: 'open' })}">Every open claim is in Threats &amp; Exposures</a>, sortable and filterable.`
      : 'Every open claim is here.'} A ranking is a list — there is no graph question in "what should I fix next".</p>`));

  // ── What this branch touched ──────────────────────────────────────
  if (data.diff && ctx.changes) {
    const changed = ctx.changes;
    panes.push(pane('diff', '', `
      ${subHead(`Since ${changed.ref}`, '', `${changed.newExposures.length} added · ${changed.removed} removed · ${changed.newMitigations} new ${plural(changed.newMitigations, 'mitigation')}`)}
      ${diagramBlock('What the additions reach', 'the flow neighbourhood of the components this branch added claims to', data.diff.diagram)}
      ${rowSlot('new', '', { empty: 'This branch added no exposures or confirmed findings.' })}`));
  }

  const subjectPickers = `
    <select class="explore-subject" data-view="asset" onchange="exploreSubject(this.value)" aria-label="Pick a component" hidden>
      ${data.assets.map(a => `<option value="${esc(a.key)}">${esc(a.label)}${a.open > 0 ? ` — ${a.open} open` : ''}</option>`).join('')}
    </select>
    <select class="explore-subject" data-view="threat" onchange="exploreSubject(this.value)" aria-label="Pick a weakness class" hidden>
      ${matrix.threats.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join('')}
    </select>
    <select class="explore-subject" data-view="boundary" onchange="exploreSubject(this.value)" aria-label="Pick a trust boundary" hidden>
      ${data.boundaries.map(b => `<option value="${esc(b.id)}">${esc(b.label)} — ${esc(b.sides.join(' ↔ '))}</option>`).join('')}
    </select>
    <select class="explore-subject" data-view="blast" onchange="exploreSubject(this.value)" aria-label="Pick a file" hidden>
      ${data.files.map(f => `<option value="${esc(f.file)}">${esc(f.file)}</option>`).join('')}
    </select>`;

  return `
<div id="sec-explore" class="section-content">
  ${sectionHead(icon('search'), 'Explore', scope)}
  ${wholeModelNote()}
  <p class="diagram-hint">One question at a time, and an answer sized to be read. Each panel states what it is for, how big the drawing is against the <strong>${LEGIBILITY_BUDGET.nodes}-node / ${LEGIBILITY_BUDGET.edges}-edge legibility budget</strong> measured for this panel, and what fell just outside the frame. Diagrams here are drawn at full size and never shrunk to fit — where long labels make one wider than the panel, drag to pan or press <em>Fit</em>. The whole-model pictures are still on <a href="#diagrams">Diagrams</a>, where they say their own size.</p>

  <div class="explore-bar">
    <div class="explore-questions" role="tablist" aria-label="Question">
      ${views.map((v, i) => `<button class="explore-q${i === 0 ? ' active' : ''}" data-view="${esc(v.id)}" onclick="exploreView('${esc(v.id)}')" title="${esc(v.question)}">${esc(v.label)}</button>`).join('')}
    </div>
    <div class="explore-controls">${subjectPickers}${TOOLS}</div>
  </div>

  ${views.map(purposeBlock).join('\n  ')}

  ${panes.join('\n  ')}
</div>`;
}

/**
 * Undefended source-to-sink routes.
 *
 * Drawn as chains rather than as a graph because a path is the one shape that
 * stays legible at any length — and because these are DERIVED from `@flows` and
 * `@mitigates` rather than declared by anyone, so each hop can cite the line its
 * flow was written on.
 *
 * The empty case is the one that has to be got right. "No undefended routes" and
 * "no routes at all" look identical on a page and are opposite facts about a
 * codebase, so the total is always stated: on this repository it is 1 of 254.
 */
function pathsPane(ctx: PageContext, data: ExploreData): string {
  const { paths, pathsTotal, endpoints } = data;
  const defended = pathsTotal - paths.length;
  const searched = `${endpoints.entries.length} ${plural(endpoints.entries.length, 'entry point')} and ${endpoints.exits.length} ${plural(endpoints.exits.length, 'sink')}`;

  const chains = paths.map(p => `
    <div class="path-finding">
      <div class="path-chain">${p.chain.map((n, i) => `${i > 0 ? '<span class="path-arrow">→</span>' : ''}<code class="path-node${p.assetsOnPath.includes(n) ? ' path-asset' : ''}">${esc(n)}</code>`).join('')}</div>
      <div class="path-meta">
        ${p.crossesBoundary ? badge(`crosses ${p.boundariesCrossed.join(', ')}`, 'red') : badge('no declared boundary on this route', 'neutral')}
        <span class="path-hops">${p.hops.map(h => locInline(h.via.file, h.via.line, ctx.links)).join(' · ')}</span>
      </div>
    </div>`).join('');

  return `
    ${subHead('Entry to sink with nothing in the way', '', `${paths.length} of ${pathsTotal} ${plural(pathsTotal, 'route')}`)}
    ${paths.length > 0
    ? chains
    : `<p class="empty-state">No undefended route found. Every one of the ${pathsTotal} entry-to-sink ${plural(pathsTotal, 'route')} in this model passes through at least one component carrying a <code>@mitigates</code>.</p>`}
    <p class="explore-budget">Searched between ${searched} — endpoints that appear in the flow graph without an <code>@asset</code> declaration, classified by degree: no inbound flow means data originates there, no outbound flow means it terminates there.${defended > 0 ? ` ${defended} further ${plural(defended, 'route')} ${defended === 1 ? 'runs' : 'run'} entry to sink and ${defended === 1 ? 'is' : 'are'} defended; those are not findings.` : ''} Derived from the annotations with no model in the loop, so none of this can cite a line that does not exist.</p>`;
}
