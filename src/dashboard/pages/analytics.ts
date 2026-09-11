/**
 * GuardLink Dashboard — Analytics: the heatmaps and distributions the model
 * can answer without prose. Asset × threat, severity × status, threat
 * frequency, control coverage (including controls nothing uses), the files
 * with the most open exposures, and — with attribution — people × time and
 * AI tool × severity.
 *
 * Every cell links into the filtered Threats page, so a number is never a
 * dead end.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Asset, threat, control, file and identity names are escaped by heatTable/barList; routes are attribute-escaped"
 * @handles pii on #dashboard -- "Introducer identities in the people × time heatmap"
 * @comment -- "Pure rendering over the analytics builders; the same claim rows feed every grid so the numbers agree with the tables"
 */
import { esc, heatTable, barList, sectionHead, subHead, routeWithQuery, badge, kpi, plural, shortPath, icon, sortableHead, numCell, sevBadge } from '../html.js';
import { computeAssetThreatMatrix, computeControlCoverage, computeSeverityStatus, computeIntroductionHeat, computeToolSeverity, computeOwnership, computeSensitiveData, SEV_ORDER } from '../analytics.js';
import type { SevKey } from '../analytics.js';
import type { PageContext } from './context.js';

const STATUS_LABEL: Record<string, string> = { open: 'Open', mitigated: 'Mitigated', accepted: 'Accepted', confirmed: 'Confirmed', refuted: 'Refuted' };

/** What the grids need; a feature variant supplies the same shape for a narrowed model. */
export type AnalyticsInput = Pick<PageContext, 'scope' | 'claims' | 'model' | 'attribution' | 'heatmap'>;
export interface AnalyticsVariant { feature: string; input: AnalyticsInput }

const sevRankCell = (sev: SevKey, show: boolean): string => numCell(SEV_ORDER.length - SEV_ORDER.indexOf(sev), show ? sevBadge(sev) : '—');

/** Open risk per owning team, and the exposed assets no team owns. */
function ownersPanel(input: AnalyticsInput): string {
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
        <tr><td><a class="who" href="${esc(`#threats?owner=${encodeURIComponent(r.owner)}&status=open`)}" title="Show this team's open rows"><code>${esc(r.owner)}</code></a></td>
        ${numCell(r.assets.length, `<span title="${esc(r.assets.join(', '))}">${r.assets.length}</span>`)}${numCell(r.open, r.open > 0 ? `<b class="red">${r.open}</b>` : '0')}${numCell(r.confirmed)}${sevRankCell(r.worstSev, r.open > 0)}${hasLedger ? numCell(r.stale) : ''}${hasAge ? numCell(r.oldestOpenDays, r.oldestOpenDays === null ? '—' : `${r.oldestOpenDays} d`) : ''}</tr>`).join('')}</tbody></table></div>` : '<p class="empty-state">No <code>@owns</code> in the model, so no team is accountable for anything here.</p>'}
      ${o.unowned.length > 0 ? `<div class="unused-controls">${badge(`${o.unowned.length} exposed, unowned`, 'red')} ${o.unowned.slice(0, 12).map(u => `<a class="pill" href="${esc(`#threats?q=${encodeURIComponent(u.asset)}&status=open`)}"><code>${esc(u.asset)}</code><span class="muted">${u.open} open</span></a>`).join(' ')}${o.unowned.length > 12 ? `<span class="muted">and ${o.unowned.length - 12} more</span>` : ''}</div>` : ''}`;
}

/** Open exposure per data classification. */
function sensitivePanel(input: AnalyticsInput): string {
  const rows = computeSensitiveData(input.model, input.claims);
  const cols = [
    { key: 'class', label: 'Classification' }, { key: 'assets', label: 'Assets', numeric: true }, { key: 'exposed', label: 'With open exposure', numeric: true },
    { key: 'open', label: 'Open', numeric: true }, { key: 'confirmed', label: 'Confirmed', numeric: true }, { key: 'worst', label: 'Worst', numeric: true },
  ];
  return `${subHead('Sensitive data under open exposure', '', `${rows.length} ${plural(rows.length, 'classification')}`)}
      <p class="guide">Assets recorded with <code>@handles</code>, and how many of them carry an open exposure. Click a class for its rows; each pill is one exposed asset.</p>
      ${rows.length > 0 ? `<div class="table-wrap"><table id="sensitive" class="sortable">${sortableHead(cols)}<tbody>${rows.map(r => `
        <tr><td><a class="who" href="${esc(`#threats?handles=${encodeURIComponent(r.classification)}&status=open`)}" title="Show open rows on assets handling this"><code>${esc(r.classification)}</code></a>${r.exposedAssets > 0 ? `<div class="attr-ai">${r.assetList.filter(a => a.open > 0).slice(0, 6).map(a => `<a class="pill" href="${esc(`#threats?q=${encodeURIComponent(a.asset)}&status=open`)}"><code>${esc(a.asset)}</code><span class="muted">${a.open}</span></a>`).join('')}</div>` : ''}</td>
        ${numCell(r.assets)}${numCell(r.exposedAssets, r.exposedAssets > 0 ? `<b class="red">${r.exposedAssets}</b>` : '0')}${numCell(r.open)}${numCell(r.confirmed)}${sevRankCell(r.worstSev, r.open > 0)}</tr>`).join('')}</tbody></table></div>` : '<p class="empty-state">No <code>@handles</code> in the model, so nothing here is classified.</p>'}`;
}

/** The whole page: the grids for the whole model, then one hidden body per feature that the top-bar dropdown swaps in. */
export function renderAnalyticsPage(ctx: PageContext, variants: AnalyticsVariant[] = []): string {
  const { scope } = ctx;
  return `
<div id="sec-analytics" class="section-content">
  ${sectionHead(icon('grid'), 'Analytics', scope)}
${scope ? `  <p class="scope-note">Every grid below counts only the annotations in the files tagged ${esc(String(scope.map(s => `"${s}"`).join(', ')))}.</p>` : ''}
  <p class="lead">Where the exposure is concentrated, who owns it, what covers it, and what nothing covers. Every cell is a link into the filtered Threats page.${variants.length > 0 ? ' Pick a feature in the top bar and every grid recomputes for it.' : ''}</p>
  <div class="analytics-body" data-feature="">${renderAnalyticsBody(ctx)}</div>
  ${variants.map(v => `<div class="analytics-body" data-feature="${esc(v.feature)}" hidden><p class="variant-note">Counting only the files tagged <code>@feature "${esc(v.feature)}"</code> and the definitions they reference.</p>${renderAnalyticsBody(v.input)}</div>`).join('')}
</div>`;
}

function renderAnalyticsBody(input: AnalyticsInput): string {
  const { scope, claims, model } = input;
  const exposures = claims.filter(c => c.verb !== 'mitigates');
  const matrix = computeAssetThreatMatrix(claims);
  const MAX_ROWS = 24, MAX_COLS = 14;
  const shownAssets = matrix.assets.slice(0, MAX_ROWS);
  const shownThreats = matrix.threats.slice(0, MAX_COLS);
  const capped = shownAssets.length < matrix.assets.length || shownThreats.length < matrix.threats.length;
  const sevStatus = computeSeverityStatus(claims);
  const coverage = computeControlCoverage(model);
  const maxCell = Math.max(1, ...matrix.cells.map(c => c.total));
  const cellOf = new Map(matrix.cells.map(c => [`${c.asset} ${c.threat}`, c]));

  const threatFreq = matrix.threats.map(t => {
    const cells = matrix.cells.filter(c => c.threat === t);
    const open = cells.reduce((n, c) => n + c.open + c.confirmed, 0);
    const total = cells.reduce((n, c) => n + c.total, 0);
    return { label: t, value: total, hint: open > 0 ? `${open} open` : 'all covered', href: routeWithQuery('threats', t), tone: open > 0 ? 'sev-fill-high' : 'sev-fill-low' };
  }).slice(0, 12);

  const fileOpen = new Map<string, number>();
  for (const c of exposures) if (c.status === 'open' || c.status === 'confirmed') fileOpen.set(c.file, (fileOpen.get(c.file) ?? 0) + 1);
  const hotFiles = [...fileOpen].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 10)
    .map(([file, n]) => ({ label: shortPath(file), value: n, href: `#threats?file=${encodeURIComponent(file)}&status=open`, tone: 'sev-fill-crit' }));

  const unused = coverage.filter(c => c.unused);
  const used = coverage.filter(c => !c.unused);

  const peopleHeat = input.attribution ? computeIntroductionHeat(claims) : null;
  const toolSev = input.attribution ? computeToolSeverity(claims) : null;
  const maxPeople = peopleHeat ? Math.max(1, ...peopleHeat.cells.flat()) : 1;
  const maxTool = toolSev ? Math.max(1, ...toolSev.cells.flat()) : 1;

  const openTotal = sevStatus.totals.open + sevStatus.totals.confirmed;
  type StatusKey = (typeof sevStatus.cols)[number];
  const maxSevStatus = Math.max(1, ...SEV_ORDER.map(x => Math.max(...sevStatus.cols.map(y => sevStatus.counts[x][y]))));

  void scope;
  return `
  <div class="kpis">
    ${kpi({ value: matrix.assets.length, label: 'Assets with exposures', href: '#assets', hint: `of ${model.assets.length} declared` })}
    ${kpi({ value: matrix.threats.length, label: 'Threat classes seen', href: '#threats', hint: `of ${model.threats.length} declared` })}
    ${kpi({ value: openTotal, label: 'Open pairs to close', href: '#threats?status=open', tone: openTotal > 0 ? 'danger' : 'success', hint: `${matrix.cells.filter(c => c.open + c.confirmed > 0).length} asset·threat pairs` })}
    ${kpi({ value: used.length, label: 'Controls in use', href: '#analytics', tone: 'success', hint: `${unused.length} declared but unused` })}
    ${kpi({ value: hotFiles.length > 0 ? hotFiles[0].value : 0, label: 'Most open in one file', href: hotFiles.length > 0 ? hotFiles[0].href : '#code', tone: hotFiles.length > 0 ? 'warn' : 'muted', hint: hotFiles.length > 0 ? hotFiles[0].label : 'no open exposure' })}
  </div>

  <div class="panel">${ownersPanel(input)}</div>
  <div class="panel">${sensitivePanel(input)}</div>

  <div class="panel">
    ${subHead('Asset × threat', '', `${matrix.assets.length} assets · ${matrix.threats.length} threats`)}
    <p class="guide">Each cell is how many exposures that asset carries for that threat. Red means at least one is open (or confirmed), green means all are mitigated, blue all accepted; darker is more. Click a cell for those rows, a row for the asset, a column for the threat.</p>
    ${matrix.cells.length > 0 ? heatTable({
      id: 'matrix',
      rowHead: 'asset \\ threat',
      rows: shownAssets,
      cols: shownThreats,
      rowHref: a => routeWithQuery('threats', a),
      colHref: t => routeWithQuery('threats', t),
      cell: (a, t) => {
        const c = cellOf.get(`${a} ${t}`);
        if (!c) return null;
        return {
          value: c.total,
          h: c.total / maxCell,
          tone: c.worst === 'open' || c.worst === 'confirmed' ? 'red' : c.worst === 'mitigated' ? 'green' : 'blue',
          href: routeWithQuery('threats', `${a} ${t}`),
          title: `${a} → ${t}: ${c.total} ${plural(c.total, 'exposure')} · ${c.open + c.confirmed} open · ${c.mitigated} mitigated · ${c.accepted} accepted · worst severity ${c.maxSev}`,
        };
      },
    }) : '<p class="empty-state">No exposures to chart.</p>'}
    ${capped ? `<p class="guide">Showing the ${shownAssets.length} assets with the most open exposures and the ${shownThreats.length} most frequent threats (of ${matrix.assets.length} and ${matrix.threats.length}). The Threats page lists everything.</p>` : ''}
  </div>

  <div class="summary-grid">
    <div class="panel">
      ${subHead('Severity × status', '', `${exposures.length} exposures`)}
      <p class="guide">Open critical and high cells are the ones to close first; a large mitigated column with a small open one is a model in good shape.</p>
      ${heatTable({
        rowHead: 'severity \\ status',
        rows: SEV_ORDER.filter(s => sevStatus.bySeverity[s] > 0),
        cols: sevStatus.cols.filter(s => sevStatus.totals[s] > 0),
        colLabel: s => STATUS_LABEL[s] ?? s,
        rowHref: s => `#threats?sev=${s}`,
        colHref: s => `#threats?status=${s}`,
        cell: (s, st) => {
          const v = sevStatus.counts[s as SevKey][st as StatusKey];
          return v === 0 ? null : { value: v, h: v / maxSevStatus, tone: st === 'open' || st === 'confirmed' ? 'red' : st === 'mitigated' ? 'green' : 'blue', href: `#threats?sev=${s}&status=${st}`, title: `${v} ${s} ${st}` };
        },
      })}
    </div>
    <div class="panel">
      ${subHead('Threats by frequency', '', 'exposures per threat class')}
      <p class="guide">How often each threat class appears across the model; the hint says how many of those are still open.</p>
      ${threatFreq.length > 0 ? barList(threatFreq) : '<p class="empty-state">No exposures.</p>'}
    </div>
  </div>

  <div class="summary-grid">
    <div class="panel">
      ${subHead('Control coverage', '', `${used.length} used · ${unused.length} unused`)}
      <p class="guide">What each declared control actually mitigates. A control declared in the definitions that no <code>@mitigates</code> names is doing nothing for the model — either it is missing annotations or it is not real.</p>
      ${used.length > 0 ? barList(used.slice(0, 12).map(c => ({ label: c.control, value: c.mitigations, hint: `${c.threats.length} ${plural(c.threats.length, 'threat')} · ${c.assets.length} ${plural(c.assets.length, 'asset')}`, href: routeWithQuery('threats', c.control), tone: 'sev-fill-low' }))) : '<p class="empty-state">No <code>@mitigates</code> names a control.</p>'}
      ${unused.length > 0 ? `<div class="unused-controls">${badge(`${unused.length} unused`, 'red')} ${unused.map(c => `<code>${esc(c.control)}</code>`).join(' ')}</div>` : ''}
    </div>
    <div class="panel">
      ${subHead('Files with the most open exposures', '', `top ${hotFiles.length}`)}
      <p class="guide">Where the open exposure concentrates in the tree. Click to see that file's open rows.</p>
      ${hotFiles.length > 0 ? barList(hotFiles) : '<p class="empty-state">No open exposures.</p>'}
    </div>
  </div>

  ${peopleHeat && toolSev ? `
    <div class="panel">
      ${subHead('People × time', '', `top ${peopleHeat.rows.length} introducers · by ${peopleHeat.unit}`)}
      <p class="guide">Exposures each person's commits introduced, per ${peopleHeat.unit}. A row that stays dark is someone who keeps introducing exposed code; a row that fades is improvement. Click a name for their claims.</p>
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
    </div>
    <div class="panel">
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
    </div>` : `<p class="guide">Generate with <code>guardlink dashboard --blame</code> to add the people × time and AI tool × severity grids.</p>`}`;
}
