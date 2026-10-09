/**
 * GuardLink Dashboard — Exposures: the asset × threat matrix over the table
 * of every claim, then the breakdowns of the same rows.
 *
 * The matrix and the table read the same filters (the chips, the search box,
 * the feature dropdown), so a cell count is always the number of rows under it.
 * Clicking a cell pins it, and the table narrows to that pair. Below them sit
 * the cuts that used to be the Analytics page — who owns the open risk,
 * sensitive data under open exposure, severity × status, threats by frequency,
 * control coverage, the files carrying the most open exposures and, with
 * --blame, people × time and AI tool × severity — rendered once for the whole
 * model and once per @feature.
 *
 * Rows carry the attributes the client filters act on (`data-sev`,
 * `data-status`, `data-state`, `data-who`, `data-search`) and open the claim
 * drawer through `data-claim`. Tables are fixed-layout so a long description
 * or path clamps instead of stretching the row; the full text stays in the
 * cell title and the drawer.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every cell, attribute and identity is escaped; the search text is escaped as an attribute value; the matrix SVG escapes its own labels"
 * @handles pii on #dashboard -- "Introducer identities in the people × time grid"
 * @comment -- "Scope wording lives in a note, not in headings: the client feature filter rewrites headings by textContent"
 */
import { esc, chip, sortableHead, rowAttrs, sevBadge, sevRank, locCellShort, claimStateBadge, whoLink, badge, scopeLabel, subHead, normSev, descCell, colgroup, pager, pageHead, stateChip, heatTable, barList, plural, routeWithQuery, numCell, shortPath } from '../html.js';
import type { PageContext, ClaimView } from './context.js';
import { computeControlCoverage, computeSeverityStatus, computeIntroductionHeat, computeToolSeverity, computeOwnership, computeSensitiveData, computeAssetThreatMatrix, SEV_ORDER } from '../analytics.js';
import type { SevKey } from '../analytics.js';
import { renderMatrix, type MatrixData } from '../layout/matrix.js';
import { ACCEPTANCE_REGISTER_NOTE } from '../../parser/acceptance.js';

const STATUS_LABEL: Record<string, string> = { open: 'Open', mitigated: 'Mitigated', accepted: 'Accepted', confirmed: 'Confirmed', control: 'Control', refuted: 'Refuted' };

// Accepted and Refuted are not the same kind of claim: a refutation was
// measured and its evidence, author and code hash are in the hypothesis
// ledger, while an acceptance was signed in a comment by a name nobody
// verified. Each chip carries the register it came from, so hovering
// distinguishes them.
function statusBadge(c: ClaimView): string {
  const title = c.status === 'refuted' && c.hypothesis
    ? `Tested and not exploitable: ${c.hypothesis.evidence ?? ''} (${c.hypothesis.by ?? ''}, ${(c.hypothesis.at ?? '').slice(0, 10)})`
    : c.status === 'accepted' ? ACCEPTANCE_REGISTER_NOTE : undefined;
  return stateChip(c.status, STATUS_LABEL[c.status] ?? c.status, title) + (c.hypothesis?.state === 'retest' ? stateChip('review', 'retest', 'Confirmed before; the code beneath it changed') : '');
}

function introducedCell(c: ClaimView): string {
  const r = c.blame?.introduced ?? c.blame?.declared;
  if (!r) return '<td data-v="">—</td>';
  return `<td data-v="${esc(r.author)}">${whoLink(r.author)}${r.ai.length > 0 ? `<div class="attr-ai">${r.ai.map(a => badge(a, 'blue')).join('')}</div>` : ''}</td>`;
}

function claimRow(c: ClaimView, ctx: PageContext, showState: boolean, showWho: boolean): string {
  return `
    <tr class="clickable${c.status === 'open' || c.status === 'confirmed' ? ' row-open' : ''}" data-claim="${c.idx}" ${rowAttrs({ file: c.file, sev: c.severity, status: c.status, who: c.who, state: c.state, owners: c.owners, handles: c.handles, change: c.change, search: [c.search] })}>
      <td data-v="${esc(c.status)}"><div class="status-cell">${statusBadge(c)}${showState ? claimStateBadge(c.state ?? undefined) : ''}${c.change === 'new' ? badge('new', 'blue', 'Added since the --since ref') : ''}</div></td>
      ${numCell(sevRank(c.severity), sevBadge(c.severity))}
      <td data-v="${esc(`${c.asset} ${c.threat}`)}"><div class="claim-cell" title="${esc(`${c.asset} → ${c.threat}`)}"><code class="cc-asset">${esc(c.asset)}</code><code class="cc-threat">${esc(c.threat)}</code></div></td>
      ${descCell(c.description)}
      ${locCellShort(c.file, c.line, ctx.links)}
      ${showWho ? introducedCell(c) : ''}
    </tr>`;
}

/** What the breakdowns need; a feature variant supplies the same shape for a narrowed model. */
export type BreakdownInput = Pick<PageContext, 'scope' | 'claims' | 'model' | 'attribution' | 'heatmap'>;
export interface BreakdownVariant { feature: string; input: BreakdownInput }

const sevRankCell = (sev: SevKey, show: boolean): string => numCell(SEV_ORDER.length - SEV_ORDER.indexOf(sev), show ? sevBadge(sev) : '—');

function ownersPanel(input: BreakdownInput): string {
  const o = computeOwnership(input.model, input.claims);
  const hasAge = input.attribution !== null;
  const hasLedger = input.claims.some(c => c.state !== null);
  const cols = [
    { key: 'owner', label: 'Owner' }, { key: 'assets', label: 'Assets', numeric: true }, { key: 'open', label: 'Open', numeric: true },
    { key: 'confirmed', label: 'Confirmed', numeric: true }, { key: 'worst', label: 'Worst', numeric: true },
    ...(hasLedger ? [{ key: 'stale', label: 'Stale', numeric: true }] : []),
    ...(hasAge ? [{ key: 'oldest', label: 'Oldest open', numeric: true }] : []),
  ];
  return `${subHead('Who owns the open risk', '', `${o.owners.length} ${plural(o.owners.length, 'team')} · ${o.unowned.length} unowned`)}
      <p class="guide">Open exposures rolled up to the team named by <code>@owns</code> on the asset. An exposed asset with no owner has nobody accountable for closing it.</p>
      ${o.owners.length > 0 ? `<div class="table-wrap"><table id="owners" class="sortable">${sortableHead(cols)}<tbody>${o.owners.map(r => `
        <tr><td><a class="who" href="${esc(`#exposures?owner=${encodeURIComponent(r.owner)}&status=open`)}" title="Show this team's open rows"><code>${esc(r.owner)}</code></a></td>
        ${numCell(r.assets.length, `<span title="${esc(r.assets.join(', '))}">${r.assets.length}</span>`)}${numCell(r.open, r.open > 0 ? `<b>${r.open}</b>` : '0')}${numCell(r.confirmed)}${sevRankCell(r.worstSev, r.open > 0)}${hasLedger ? numCell(r.stale) : ''}${hasAge ? numCell(r.oldestOpenDays, r.oldestOpenDays === null ? '—' : `${r.oldestOpenDays} d`) : ''}</tr>`).join('')}</tbody></table></div>` : '<p class="empty-state">No <code>@owns</code> in the model, so no team is accountable for anything here.</p>'}
      ${o.unowned.length > 0 ? `<div class="pill-row">${stateChip('open', `${o.unowned.length} exposed, unowned`)} ${o.unowned.slice(0, 12).map(u => `<a class="pill" href="${esc(`#exposures?q=${encodeURIComponent(u.asset)}&status=open`)}"><code>${esc(u.asset)}</code><span class="muted">${u.open} open</span></a>`).join(' ')}${o.unowned.length > 12 ? `<span class="muted">and ${o.unowned.length - 12} more</span>` : ''}</div>` : ''}`;
}

function sensitivePanel(input: BreakdownInput): string {
  const rows = computeSensitiveData(input.model, input.claims);
  const cols = [
    { key: 'class', label: 'Classification' }, { key: 'assets', label: 'Assets', numeric: true }, { key: 'exposed', label: 'With open exposure', numeric: true },
    { key: 'open', label: 'Open', numeric: true }, { key: 'confirmed', label: 'Confirmed', numeric: true }, { key: 'worst', label: 'Worst', numeric: true },
  ];
  return `${subHead('Sensitive data under open exposure', '', `${rows.length} ${plural(rows.length, 'classification')}`)}
      <p class="guide">Assets recorded with <code>@handles</code>, and how many of them carry an open exposure. Click a class for its rows; each pill is one exposed asset.</p>
      ${rows.length > 0 ? `<div class="table-wrap"><table id="sensitive" class="sortable">${sortableHead(cols)}<tbody>${rows.map(r => `
        <tr><td><a class="who" href="${esc(`#exposures?handles=${encodeURIComponent(r.classification)}&status=open`)}" title="Show open rows on assets handling this"><code>${esc(r.classification)}</code></a>${r.exposedAssets > 0 ? `<div class="attr-ai">${r.assetList.filter(a => a.open > 0).slice(0, 6).map(a => `<a class="pill" href="${esc(`#exposures?q=${encodeURIComponent(a.asset)}&status=open`)}"><code>${esc(a.asset)}</code><span class="muted">${a.open}</span></a>`).join('')}</div>` : ''}</td>
        ${numCell(r.assets)}${numCell(r.exposedAssets, r.exposedAssets > 0 ? `<b>${r.exposedAssets}</b>` : '0')}${numCell(r.open)}${numCell(r.confirmed)}${sevRankCell(r.worstSev, r.open > 0)}</tr>`).join('')}</tbody></table></div>` : '<p class="empty-state">No <code>@handles</code> in the model, so nothing here is classified.</p>'}`;
}

function breakdownBody(input: BreakdownInput): string {
  const { claims, model } = input;
  const exposures = claims.filter(c => c.verb !== 'mitigates');
  const matrix = computeAssetThreatMatrix(claims);
  const sevStatus = computeSeverityStatus(claims);
  const coverage = computeControlCoverage(model);
  const threatFreq = matrix.threats.map(t => {
    const cells = matrix.cells.filter(c => c.threat === t);
    const open = cells.reduce((n, c) => n + c.open + c.confirmed, 0);
    const total = cells.reduce((n, c) => n + c.total, 0);
    return { label: t, value: total, hint: open > 0 ? `${open} open` : 'all covered', href: routeWithQuery('exposures', t), tone: open > 0 ? 'open' as const : 'res' as const };
  }).slice(0, 12);
  const fileOpen = new Map<string, number>();
  for (const c of exposures) if (c.status === 'open' || c.status === 'confirmed') fileOpen.set(c.file, (fileOpen.get(c.file) ?? 0) + 1);
  const hotFiles = [...fileOpen].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 10)
    .map(([file, n]) => ({ label: shortPath(file), value: n, href: `#exposures?file=${encodeURIComponent(file)}&status=open`, tone: 'open' as const }));
  const unused = coverage.filter(c => c.unused);
  const used = coverage.filter(c => !c.unused);
  const peopleHeat = input.attribution ? computeIntroductionHeat(claims) : null;
  const toolSev = input.attribution ? computeToolSeverity(claims) : null;
  const maxPeople = peopleHeat ? Math.max(1, ...peopleHeat.cells.flat()) : 1;
  const maxTool = toolSev ? Math.max(1, ...toolSev.cells.flat()) : 1;
  type StatusKey = (typeof sevStatus.cols)[number];
  const maxSevStatus = Math.max(1, ...SEV_ORDER.map(x => Math.max(...sevStatus.cols.map(y => sevStatus.counts[x][y]))));

  return `
  <div class="grid2">
    <div class="panel"><div class="panel-b">${ownersPanel(input)}</div></div>
    <div class="panel"><div class="panel-b">${sensitivePanel(input)}</div></div>
  </div>
  <div class="grid2">
    <div class="panel"><div class="panel-b">
      ${subHead('Severity × status', '', `${exposures.length} exposures`)}
      <p class="guide">Open critical and high cells are the ones to close first; a large mitigated column with a small open one is a model in good shape. Stronger ink is more.</p>
      ${heatTable({
        rowHead: 'severity \\ status',
        rows: SEV_ORDER.filter(s => sevStatus.bySeverity[s] > 0),
        cols: sevStatus.cols.filter(s => sevStatus.totals[s] > 0),
        colLabel: s => STATUS_LABEL[s] ?? s,
        rowHref: s => `#exposures?sev=${s}`,
        colHref: s => `#exposures?status=${s}`,
        cell: (s, st) => {
          const v = sevStatus.counts[s as SevKey][st as StatusKey];
          return v === 0 ? null : { value: v, h: v / maxSevStatus, tone: st === 'open' || st === 'confirmed' ? 'red' : st === 'mitigated' || st === 'refuted' ? 'green' : 'neutral', href: `#exposures?sev=${s}&status=${st}`, title: `${v} ${s} ${st}` };
        },
      })}
    </div></div>
    <div class="panel"><div class="panel-b">
      ${subHead('Threats by frequency', '', 'exposures per threat class')}
      <p class="guide">How often each threat class appears across the model; the hint says how many of those are still open.</p>
      ${threatFreq.length > 0 ? barList(threatFreq) : '<p class="empty-state">No exposures.</p>'}
    </div></div>
  </div>
  <div class="grid2">
    <div class="panel"><div class="panel-b">
      ${subHead('Control coverage', '', `${used.length} used · ${unused.length} unused`)}
      <p class="guide">What each declared control actually mitigates. A control declared in the definitions that no <code>@mitigates</code> names is doing nothing for the model — either it is missing annotations or it is not real.</p>
      ${used.length > 0 ? barList(used.slice(0, 12).map(c => ({ label: c.control, value: c.mitigations, hint: `${c.threats.length} ${plural(c.threats.length, 'threat')} · ${c.assets.length} ${plural(c.assets.length, 'asset')}`, href: routeWithQuery('exposures', c.control), tone: 'ctl' }))) : '<p class="empty-state">No <code>@mitigates</code> names a control.</p>'}
      ${unused.length > 0 ? `<div class="pill-row">${stateChip('review', `${unused.length} unused`)} ${unused.map(c => `<code>${esc(c.control)}</code>`).join(' ')}</div>` : ''}
    </div></div>
    <div class="panel"><div class="panel-b">
      ${subHead('Files with the most open exposures', '', `top ${hotFiles.length}`)}
      <p class="guide">Where the open exposure concentrates in the tree. Click to see that file's open rows.</p>
      ${hotFiles.length > 0 ? barList(hotFiles) : '<p class="empty-state">No open exposures.</p>'}
    </div></div>
  </div>
  ${peopleHeat && toolSev ? `
  <div class="grid2">
    <div class="panel"><div class="panel-b">
      ${subHead('People × time', '', `top ${peopleHeat.rows.length} introducers · by ${peopleHeat.unit}`)}
      <p class="guide">Exposures each person's commits introduced, per ${peopleHeat.unit}. A row that stays strong is someone who keeps introducing exposed code; a row that fades is improvement. Click a name for their claims.</p>
      ${peopleHeat.rows.length > 0 ? heatTable({
        rowHead: `person \\ ${peopleHeat.unit}`,
        rows: peopleHeat.rows,
        cols: peopleHeat.cols,
        rowHref: r => `#attribution?who=${encodeURIComponent(r)}`,
        cell: (r, c) => {
          const v = peopleHeat.cells[peopleHeat.rows.indexOf(r)][peopleHeat.cols.indexOf(c)];
          return v === 0 ? null : { value: v, h: v / maxPeople, tone: 'red', title: `${r}: ${v} introduced in ${c}` };
        },
      }) : '<p class="empty-state">No attributed introductions.</p>'}
    </div></div>
    <div class="panel"><div class="panel-b">
      ${subHead('AI tool × severity', '', `${toolSev.rows.length} ${plural(toolSev.rows.length, 'tool')}`)}
      <p class="guide">Exposures whose introducing commit credited each AI tool, by severity. Credit is declared by the commit's trailers, never detected.</p>
      ${toolSev.rows.length > 0 ? heatTable({
        rowHead: 'tool \\ severity',
        rows: toolSev.rows,
        cols: toolSev.cols.filter(s => toolSev.cells.some(row => row[toolSev.cols.indexOf(s)] > 0)),
        rowHref: r => `#attribution?who=${encodeURIComponent(r.replace(/ \(.*\)$/, ''))}`,
        cell: (r, s) => {
          const v = toolSev.cells[toolSev.rows.indexOf(r)][toolSev.cols.indexOf(s as SevKey)];
          return v === 0 ? null : { value: v, h: v / maxTool, tone: s === 'critical' || s === 'high' ? 'red' : 'neutral', title: `${r}: ${v} ${s}` };
        },
      }) : '<p class="empty-state">No AI tool is credited on an introducing commit.</p>'}
    </div></div>
  </div>` : '<p class="guide">Generate with <code>guardlink dashboard --blame</code> to add the people × time and AI tool × severity grids.</p>'}`;
}

export function renderExposuresPage(ctx: PageContext, matrixData: MatrixData, variants: BreakdownVariant[] = []): string {
  const { scope, claims, ledger, attribution, model, changes } = ctx;
  const exposures = claims.filter(c => c.verb === 'exposes');
  const confirmed = claims.filter(c => c.verb === 'confirmed');
  const open = exposures.filter(c => c.status === 'open');
  const mitigated = exposures.filter(c => c.status === 'mitigated');
  const accepted = exposures.filter(c => c.status === 'accepted');
  const refuted = exposures.filter(c => c.status === 'refuted');
  const bySev = (k: string): number => exposures.filter(c => normSev(c.severity) === k).length;
  const showState = ledger !== null;
  const showWho = attribution !== null;
  const within = scope ? ` in ${scope.length > 1 ? 'features' : 'feature'} ${esc(scopeLabel(scope))}` : '';
  const m = renderMatrix(matrixData, { st: [], sv: [], keep: null }, true, '');

  const cols = [
    { key: 'status', label: 'Status' },
    { key: 'severity', label: 'Severity', numeric: true },
    { key: 'claim', label: 'Asset → threat' },
    { key: 'description', label: 'Description', plain: true },
    { key: 'location', label: 'Location', cls: 'loc' },
    ...(showWho ? [{ key: 'who', label: 'Introduced by' }] : []),
  ];
  const widths = ['12%', '9%', showWho ? '17%' : '19%', '', showWho ? '15%' : '17%', ...(showWho ? ['13%'] : [])];
  const head = colgroup(widths) + sortableHead(cols);

  return `
<section id="sec-exposures" class="section-content" aria-label="Exposures">
  ${pageHead('Exposures', scope, `Every <code>@exposes</code> in the model, as a matrix of asset against threat and as rows. A cell is warm while something in it is open (in its worst open severity), a mint wash once everything in it is mitigated or refuted, hollow when accepted. Rows run in model order; columns by how many exposures each threat has. Click a cell to pin it — the table narrows to that pair. Click a row for detail; type <kbd>/</kbd> to search.`, `<span class="muted"><span data-count-for="exposure-rows">${exposures.length}</span> exposures</span>`)}
${scope ? `  <p class="scope-note">Only exposures annotated in the files tagged ${esc(scopeLabel(scope))}. Exposures elsewhere in the project are not listed here and are not counted below.</p>` : ''}

  <div class="chips" id="threat-chips">
    <span class="chips-label">Status</span>
    ${chip('status', '', 'All', { count: exposures.length + confirmed.length })}
    ${chip('status', 'open', 'Open', { count: open.length })}
    ${chip('status', 'mitigated', 'Mitigated', { count: mitigated.length })}
    ${chip('status', 'accepted', 'Accepted', { count: accepted.length })}
    ${refuted.length > 0 ? chip('status', 'refuted', 'Refuted', { count: refuted.length }) : ''}
    ${confirmed.length > 0 ? chip('status', 'confirmed', 'Confirmed', { count: confirmed.length }) : ''}
    <span class="sep"></span>
    <span class="chips-label">Severity</span>
    ${chip('sev', 'critical', 'Critical', { count: bySev('critical'), cls: 'chip-sev s-critical' })}
    ${chip('sev', 'high', 'High', { count: bySev('high'), cls: 'chip-sev s-high' })}
    ${chip('sev', 'medium', 'Medium', { count: bySev('medium'), cls: 'chip-sev s-medium' })}
    ${chip('sev', 'low', 'Low', { count: bySev('low'), cls: 'chip-sev s-low' })}
    ${showState ? `<span class="sep"></span><span class="chips-label">Claim</span>${chip('state', 'verified', 'Verified')}${chip('state', 'stale', 'Stale')}${chip('state', 'unverified', 'Unverified')}` : ''}
    ${changes ? `<span class="sep"></span>${chip('change', 'new', `New since ${changes.ref}`, { count: claims.filter(c => c.change === 'new').length })}` : ''}
  </div>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn ghost" data-clear-filters>Clear</button></div>
  <div class="who-filter" hidden><span>Showing claims credited to</span> <strong class="who-filter-name"></strong><button class="btn ghost" data-clear-filters>Clear</button></div>

  ${exposures.length + confirmed.length > 0 ? `
  <div class="plot-head"><span class="eyebrow">Asset × threat</span><label class="toggle"><input type="checkbox" data-matrix-compact checked> fold empty rows and columns</label></div>
  <div class="panel plot-panel"><div class="plot-scroll" id="matrix-host">${m.svg}</div></div>
  <div class="fidelity" id="matrix-footer"><span><b class="num">${m.exposures}</b> exposures in <b class="num">${m.cells}</b> cells</span><span>${m.foldedRows} assets and ${m.foldedCols} threats with nothing in this filter are folded — untick to see the complete grid</span><span>margins: open (warm) and resolved (mint) per row and column</span></div>
  <div class="pin-bar" id="matrix-pin" hidden><span class="eyebrow">Pinned</span> <b class="mono" data-pin-label></b><button class="btn ghost" data-unpin="matrix">Clear pin</button></div>` : ''}

  ${confirmed.length > 0 ? `
  ${subHead(`Confirmed exploitable (${confirmed.length})`)}
  <p class="section-note">Verified through pentest, scanning, or manual reproduction — <strong>not false positives</strong>.</p>
  <div class="table-wrap"><table id="confirmed" class="sortable fixed" data-paginate="25">
    ${head}
    <tbody>${confirmed.map(c => claimRow(c, ctx, showState, showWho)).join('')}</tbody>
  </table></div>
  ${pager('confirmed')}
  <div class="no-match" data-count-for="confirmed" hidden>No confirmed finding matches the current filters.</div>` : ''}

  ${subHead('Exposures', '', `<span class="muted">${open.length} open · ${mitigated.length} mitigated · ${accepted.length} accepted${refuted.length > 0 ? ` · ${refuted.length} refuted` : ''}</span>`)}
  <p class="section-note">One table, every exposure${within}, open first. <strong>Open</strong> rows have no covering control.</p>
  ${accepted.length > 0 ? `<p class="section-note">${esc(ACCEPTANCE_REGISTER_NOTE)}</p>` : ''}
  ${exposures.length > 0 ? `
  <div class="table-wrap"><table id="exposure-rows" class="sortable fixed" data-paginate="25">
    ${head}
    <tbody>${[...exposures].sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1) || sevRank(a.severity) - sevRank(b.severity)).map(c => claimRow(c, ctx, showState, showWho)).join('')}</tbody>
  </table></div>
  ${pager('exposure-rows')}
  <div class="no-match" data-count-for="exposure-rows" hidden>No exposure matches the current filters.</div>`
  : `<p class="empty-state">No <code>@exposes</code> annotations${within}.${scope ? ' Exposures declared elsewhere in the project are not shown.' : ''}</p>`}

  ${model.transfers.length > 0 ? `
  ${subHead(`Transferred risks (${model.transfers.length})`)}
  <div class="table-wrap"><table id="transfers" class="sortable fixed" data-paginate="25">
    ${colgroup(['16%', '14%', '16%', '', '17%'])}
    ${sortableHead([{ key: 'source', label: 'Source' }, { key: 'threat', label: 'Threat' }, { key: 'target', label: 'Target' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.transfers.map(t => `
    <tr ${rowAttrs({ file: t.location?.file, search: ['transfer', t.source, t.threat, t.target, t.description ?? '', t.location?.file ?? ''] })}>
      <td><code>${esc(t.source)}</code></td>
      <td><code>${esc(t.threat)}</code></td>
      <td><code>${esc(t.target)}</code></td>
      ${descCell(t.description)}
      ${locCellShort(t.location?.file, t.location?.line, ctx.links)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('transfers')}` : ''}

  <h3 class="block-h">Breakdowns</h3>
  <p class="guide">The same rows, cut by owner, data class, severity and status, threat class, control and file.${variants.length > 0 ? ' Pick a feature in the top bar and every breakdown recomputes for it.' : ''}</p>
  <div class="analytics-body" data-feature="">${breakdownBody(ctx)}</div>
  ${variants.map(v => `<div class="analytics-body" data-feature="${esc(v.feature)}" hidden><p class="variant-note">Counting only the files tagged <code>@feature "${esc(v.feature)}"</code> and the definitions they reference.</p>${breakdownBody(v.input)}</div>`).join('')}
</section>`;
}
