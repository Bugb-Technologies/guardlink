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
import { esc, heatTable, barList, sectionHead, subHead, routeWithQuery, badge, kpi, plural, shortPath } from '../html.js';
import { computeAssetThreatMatrix, computeControlCoverage, computeSeverityStatus, computeIntroductionHeat, computeToolSeverity, SEV_ORDER } from '../analytics.js';
import type { SevKey } from '../analytics.js';
import type { PageContext } from './context.js';

const STATUS_LABEL: Record<string, string> = { open: 'Open', mitigated: 'Mitigated', accepted: 'Accepted', confirmed: 'Confirmed' };

export function renderAnalyticsPage(ctx: PageContext): string {
  const { scope, claims, model } = ctx;
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

  const peopleHeat = ctx.attribution ? computeIntroductionHeat(claims) : null;
  const toolSev = ctx.attribution ? computeToolSeverity(claims) : null;
  const maxPeople = peopleHeat ? Math.max(1, ...peopleHeat.cells.flat()) : 1;
  const maxTool = toolSev ? Math.max(1, ...toolSev.cells.flat()) : 1;

  const openTotal = sevStatus.totals.open + sevStatus.totals.confirmed;
  type StatusKey = (typeof sevStatus.cols)[number];
  const maxSevStatus = Math.max(1, ...SEV_ORDER.map(x => Math.max(...sevStatus.cols.map(y => sevStatus.counts[x][y]))));

  return `
<div id="sec-analytics" class="section-content">
  ${sectionHead('▦', 'Analytics', scope)}
${scope ? `  <p class="scope-note">Every grid below counts only the annotations in the files tagged ${esc(String(scope.map(s => `"${s}"`).join(', ')))}.</p>` : ''}
  <p class="lead">Where the exposure is concentrated, what covers it, and what nothing covers. Every cell is a link into the filtered Threats page.</p>

  <div class="kpis">
    ${kpi({ value: matrix.assets.length, label: 'Assets with exposures', href: '#assets', hint: `of ${model.assets.length} declared` })}
    ${kpi({ value: matrix.threats.length, label: 'Threat classes seen', href: '#threats', hint: `of ${model.threats.length} declared` })}
    ${kpi({ value: openTotal, label: 'Open pairs to close', href: '#threats?status=open', tone: openTotal > 0 ? 'danger' : 'success', hint: `${matrix.cells.filter(c => c.open + c.confirmed > 0).length} asset·threat pairs` })}
    ${kpi({ value: used.length, label: 'Controls in use', href: '#analytics', tone: 'success', hint: `${unused.length} declared but unused` })}
    ${kpi({ value: hotFiles.length > 0 ? hotFiles[0].value : 0, label: 'Most open in one file', href: hotFiles.length > 0 ? hotFiles[0].href : '#code', tone: hotFiles.length > 0 ? 'warn' : 'muted', hint: hotFiles.length > 0 ? hotFiles[0].label : 'no open exposure' })}
  </div>

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
    </div>` : `<p class="guide">Generate with <code>guardlink dashboard --blame</code> to add the people × time and AI tool × severity grids.</p>`}
</div>`;
}
