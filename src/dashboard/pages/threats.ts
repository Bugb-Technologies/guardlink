/**
 * GuardLink Dashboard — Threats & Exposures: one sortable, filterable,
 * paginated table of every claim, confirmed findings on top, transfers below.
 *
 * Rows carry the attributes the client filters act on (`data-sev`,
 * `data-status`, `data-state`, `data-who`, `data-search`) and open the claim
 * drawer through `data-claim`. Tables are fixed-layout so a long description
 * or path clamps instead of stretching the row; the full text stays in the
 * cell title and the drawer.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every cell, attribute and identity is escaped; the search text is escaped as an attribute value"
 * @comment -- "Scope wording lives in a note, not in headings: the client feature filter rewrites headings by textContent"
 */
import { esc, chip, sortableHead, rowAttrs, sevBadge, sevRank, numCell, locCellShort, claimStateBadge, whoLink, badge, scopeLabel, sectionHead, subHead, normSev, descCell, colgroup, pager } from '../html.js';
import type { PageContext, ClaimView } from './context.js';

const STATUS_LABEL: Record<string, string> = { open: 'Open', mitigated: 'Mitigated', accepted: 'Accepted', confirmed: 'Confirmed', control: 'Control' };

function statusBadge(c: ClaimView): string {
  const tone = c.status === 'open' || c.status === 'confirmed' ? 'red' : c.status === 'mitigated' ? 'green' : c.status === 'accepted' ? 'blue' : 'neutral';
  return badge(STATUS_LABEL[c.status] ?? c.status, tone);
}

function introducedCell(c: ClaimView): string {
  const r = c.blame?.introduced ?? c.blame?.declared;
  if (!r) return '<td data-v="">—</td>';
  return `<td data-v="${esc(r.author)}">${whoLink(r.author)}${r.ai.length > 0 ? `<div class="attr-ai">${r.ai.map(a => badge(a, 'blue')).join('')}</div>` : ''}</td>`;
}

function claimRow(c: ClaimView, ctx: PageContext, showState: boolean, showWho: boolean): string {
  return `
    <tr class="clickable${c.status === 'open' || c.status === 'confirmed' ? ' row-open' : ''}" data-claim="${c.idx}" ${rowAttrs({ file: c.file, sev: c.severity, status: c.status, who: c.who, state: c.state, search: [c.search] })}>
      <td data-v="${esc(c.status)}"><div class="status-cell">${statusBadge(c)}${showState ? claimStateBadge(c.state ?? undefined) : ''}</div></td>
      ${numCell(sevRank(c.severity), sevBadge(c.severity))}
      <td data-v="${esc(`${c.asset} ${c.threat}`)}"><div class="claim-cell" title="${esc(`${c.asset} → ${c.threat}`)}"><code class="cc-asset">${esc(c.asset)}</code><code class="cc-threat">${esc(c.threat)}</code></div></td>
      ${descCell(c.description)}
      ${locCellShort(c.file, c.line, ctx.links)}
      ${showWho ? introducedCell(c) : ''}
    </tr>`;
}

export function renderThreatsPage(ctx: PageContext): string {
  const { scope, claims, ledger, attribution, model } = ctx;
  const exposures = claims.filter(c => c.verb === 'exposes');
  const confirmed = claims.filter(c => c.verb === 'confirmed');
  const open = exposures.filter(c => c.status === 'open');
  const mitigated = exposures.filter(c => c.status === 'mitigated');
  const accepted = exposures.filter(c => c.status === 'accepted');
  const bySev = (k: string): number => exposures.filter(c => normSev(c.severity) === k).length;
  const showState = ledger !== null;
  const showWho = attribution !== null;
  const within = scope ? ` in ${scope.length > 1 ? 'features' : 'feature'} ${esc(scopeLabel(scope))}` : '';

  const cols = [
    { key: 'status', label: 'Status' },
    { key: 'severity', label: 'Severity', numeric: true },
    { key: 'claim', label: 'Asset → threat' },
    { key: 'description', label: 'Description', plain: true },
    { key: 'location', label: 'Location', cls: 'loc' },
    ...(showWho ? [{ key: 'who', label: 'Introduced by' }] : []),
  ];
  const widths = ['10%', '9%', showWho ? '17%' : '19%', '', showWho ? '15%' : '17%', ...(showWho ? ['14%'] : [])];
  const head = colgroup(widths) + sortableHead(cols);

  return `
<div id="sec-threats" class="section-content">
  ${sectionHead('⚠', 'Threats &amp; Exposures', scope, `<span class="muted"><span data-count-for="exposures">${exposures.length}</span> exposures</span>`)}
${scope ? `  <p class="scope-note">Only exposures annotated in the files tagged ${esc(scopeLabel(scope))}. Exposures elsewhere in the project are not listed here and are not counted below.</p>` : ''}
  <p class="lead">Every <code>@exposes</code> in the model, with whether a control covers it${showState ? ', whether the claim is still verified against the code beneath it' : ''}${showWho ? ', and who introduced that code' : ''}. Click a row for detail and actions; click a column to sort; type <kbd>/</kbd> to search (every word must match, so <code>#api sqli</code> narrows to one pair).</p>

  <div class="chips" id="threat-chips">
    <span class="chips-label">Status</span>
    ${chip('status', '', 'All', { count: exposures.length + confirmed.length })}
    ${chip('status', 'open', 'Open', { count: open.length, cls: 'chip-crit' })}
    ${chip('status', 'mitigated', 'Mitigated', { count: mitigated.length })}
    ${chip('status', 'accepted', 'Accepted', { count: accepted.length })}
    ${confirmed.length > 0 ? chip('status', 'confirmed', 'Confirmed', { count: confirmed.length, cls: 'chip-crit' }) : ''}
    <span class="sep"></span>
    <span class="chips-label">Severity</span>
    ${chip('sev', 'critical', 'Critical', { count: bySev('critical'), cls: 'chip-crit' })}
    ${chip('sev', 'high', 'High', { count: bySev('high'), cls: 'chip-high' })}
    ${chip('sev', 'medium', 'Medium', { count: bySev('medium'), cls: 'chip-med' })}
    ${chip('sev', 'low', 'Low', { count: bySev('low'), cls: 'chip-low' })}
    ${showState ? `<span class="sep"></span><span class="chips-label">Claim</span>${chip('state', 'verified', 'Verified')}${chip('state', 'stale', 'Stale')}${chip('state', 'unverified', 'Unverified')}` : ''}
  </div>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn btn-ghost" data-clear-filters>Clear</button></div>
  <div class="who-filter" hidden><span>Showing claims credited to</span> <strong class="who-filter-name"></strong><button class="btn btn-ghost" data-clear-filters style="margin-left:auto">Clear</button></div>

  ${confirmed.length > 0 ? `
  ${subHead(`🔴 Confirmed Exploitable (${confirmed.length})`, 'sub-h-critical')}
  <p class="section-note">Verified through pentest, scanning, or manual reproduction — <strong>not false positives</strong>.</p>
  <div class="table-wrap"><table id="confirmed" class="sortable fixed" data-paginate="25">
    ${head}
    <tbody>${confirmed.map(c => claimRow(c, ctx, showState, showWho)).join('')}</tbody>
  </table></div>
  ${pager('confirmed')}
  <div class="no-match" data-count-for="confirmed" hidden>No confirmed finding matches the current filters.</div>` : ''}

  ${subHead('Exposures', open.length > 0 ? 'sub-h-alert' : 'sub-h-ok', `<span class="muted">${open.length} open · ${mitigated.length} mitigated · ${accepted.length} accepted</span>`)}
  <p class="section-note">One table, every exposure${within}, open first. <strong>Open</strong> rows have no covering control; use the chips above to narrow, or click a column header to sort.</p>
  ${exposures.length > 0 ? `
  <div class="table-wrap"><table id="exposures" class="sortable fixed" data-paginate="25">
    ${head}
    <tbody>${[...exposures].sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1) || sevRank(a.severity) - sevRank(b.severity)).map(c => claimRow(c, ctx, showState, showWho)).join('')}</tbody>
  </table></div>
  ${pager('exposures')}
  <div class="no-match" data-count-for="exposures" hidden>No exposure matches the current filters.</div>`
  : `<p class="empty-state">No <code>@exposes</code> annotations${within}.${scope ? ' Exposures declared elsewhere in the project are not shown.' : ''}</p>`}

  ${model.transfers.length > 0 ? `
  ${subHead(`Transferred Risks (${model.transfers.length})`, 'sub-h-info')}
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
</div>`;
}
