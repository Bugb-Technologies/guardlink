/**
 * GuardLink Dashboard — Tickets: the open tickets an external tracker holds
 * for the threat model's risks, as recorded with `@ticket`.
 *
 * GuardLink never talks to the tracker. Each row is one annotation, joined to
 * where its threat-on-asset pair stands now — still open, mitigated, accepted,
 * or not declared at all — so a ticket whose risk has since been closed in
 * code reads as one to ask about. The page is only rendered when the model
 * holds at least one `@ticket`.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Ticket refs, SLA labels, assignees and descriptions are model text and go through esc(); a ref is an href only when externalHref() reads it as absolute http(s), so a javascript: ref renders as text"
 * @flows ThreatModel -> #dashboard via computeTickets -- "Ticket rows with their pair state"
 * @comment -- "Overdue is not decided here: the page must be byte-identical across runs, so each row carries data-due and the client compares it with the viewer's own date"
 */
import { esc, externalHref, scopeLabel, pageHead, sortableHead, rowAttrs, locCellShort, descCell, pager, plural, statTile, stateChip, chip, copyButton, colgroup, icon } from '../html.js';
import type { TicketRow } from '../data.js';
import type { PageContext } from './context.js';

const STATE_LABEL: Record<TicketRow['state'], string> = {
  open: 'open risk', mitigated: 'mitigated', accepted: 'accepted', unexposed: 'not declared',
};

const STATE_TITLE: Record<TicketRow['state'], string> = {
  open: 'At least one @exposes or @confirmed site of this pair has no control or acceptance',
  mitigated: 'Every site of this pair is now covered, at least one by a control: the ticket may be ready to close',
  accepted: 'Every site of this pair is covered by an acceptance only',
  unexposed: 'No @exposes or @confirmed declares this pair: check the threat and asset on the @ticket line',
};

/** The ref as a link when it is an http(s) URL, else plain text; either way copyable. */
function refCell(t: TicketRow): string {
  const href = externalHref(t.ref);
  const inner = href
    ? `<a class="ticket-ref" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="Open in the tracker">${esc(shortRef(t.ref))}</a>`
    : `<code class="ticket-ref">${esc(t.ref)}</code>`;
  return `<td data-v="${esc(t.ref.toLowerCase())}"><div class="ticket-cell">${inner}${copyButton(t.ref, 'Copy ticket')}</div></td>`;
}

/** A tracker URL shown by its last path segment — `…/browse/SEC-42` reads as `SEC-42`; the full URL stays in the href and the copy. */
function shortRef(ref: string): string {
  const m = /^https?:\/\/[^/]+\/(?:.*\/)?([^/?#]+)\/?(?:[?#].*)?$/i.exec(ref);
  return m && m[1] ? m[1] : ref;
}

export function renderTicketsPage(ctx: PageContext): string {
  const { scope, links, tickets } = ctx;
  // The asset drawer indexes the heatmap; an asset is found by any of its aliases.
  const tileOf = new Map<string, number>();
  ctx.heatmap.forEach((a, i) => { for (const alias of [a.name, ...a.aliases]) tileOf.set(alias.trim().toLowerCase(), i); });
  // Each row opens the annotation drawer of its own @ticket line.
  const annotationOf = new Map<string, string>();
  ctx.fileAnnotations.forEach((f, fi) => f.annotations.forEach((a, ai) => {
    if (a.kind === 'ticket') annotationOf.set(`${f.file}:${a.line}:${a.fields.ref ?? ''}`, `${fi}:${ai}`);
  }));

  const count = (s: TicketRow['state']) => tickets.filter(t => t.state === s).length;
  const closed = count('mitigated') + count('accepted');
  const undated = tickets.filter(t => !t.due).length;
  const assignees = new Set(tickets.map(t => t.assignee).filter(Boolean)).size;

  const rows = tickets.map(t => {
    const ann = annotationOf.get(`${t.file}:${t.line}:${t.ref}`);
    const tile = tileOf.get(t.asset.trim().toLowerCase());
    const search = [t.ref, t.threat, t.asset, t.sla, t.assignee, t.due, t.description, t.file, STATE_LABEL[t.state], t.confirmed ? 'confirmed' : ''];
    return `
    <tr ${ann ? `class="clickable" data-annotation="${esc(ann)}" role="button" tabindex="0" ` : ''}${rowAttrs({ file: t.file, status: t.state, search })}${t.due ? ` data-due="${esc(t.due)}"` : ''}>
      ${refCell(t)}
      <td data-v="${esc(t.threat.toLowerCase())}"><a class="pill" href="#exposures?q=${encodeURIComponent(t.threat)}" title="Exposures naming this threat"><code>${esc(t.threat)}</code></a></td>
      <td data-v="${esc(t.asset.toLowerCase())}"><div class="ticket-cell"><a class="pill" href="#exposures?q=${encodeURIComponent(t.asset)}" title="Exposures on this asset"><code>${esc(t.asset)}</code></a>${tile !== undefined ? `<button class="btn ghost btn-xs" data-asset-drawer="${tile}" title="Everything about this asset" aria-label="Everything about ${esc(t.asset)}">${icon('info')}</button>` : ''}</div></td>
      <td data-v="${esc(t.sla.toLowerCase())}">${t.sla ? `<span class="tag">${esc(t.sla)}</span>` : '<span class="subtle">—</span>'}</td>
      <td data-v="${esc(t.assignee.toLowerCase())}">${t.assignee ? `<a class="who" href="#tickets?q=${encodeURIComponent(t.assignee)}" title="This assignee's tickets">${esc(t.assignee)}</a>` : '<span class="subtle">unassigned</span>'}</td>
      <td class="ticket-due" data-v="${esc(t.due || '9999-99-99')}">${t.due ? `<span class="num">${esc(t.due)}</span>` : '<span class="subtle">—</span>'}</td>
      <td data-v="${esc(t.state)}">${stateChip(t.state === 'unexposed' ? 'review' : t.state, STATE_LABEL[t.state], STATE_TITLE[t.state])}${t.confirmed ? ` ${stateChip('confirmed', 'confirmed', 'The pair carries a @confirmed: someone reproduced it')}` : ''}</td>
      ${descCell(t.description)}
      ${locCellShort(t.file, t.line, links)}
    </tr>`;
  }).join('');

  return `
<section id="sec-tickets" class="section-content" aria-label="Tickets">
  ${pageHead('Tickets', scope, '', `<span class="muted">${tickets.length} ${plural(tickets.length, 'ticket')} · ${assignees} ${plural(assignees, 'assignee')}</span>`)}
  <p class="lead">Open tickets in your tracker for risks in this model, as recorded with <code>@ticket</code>. GuardLink does not read the tracker: the annotation is the whole record, and removing it is how a ticket leaves this page. <b>State</b> is where the risk behind each ticket stands now in the code.${scope ? ` Only tickets in the files tagged ${esc(scopeLabel(scope))} are shown.` : ''}</p>
  <div class="panel tiles">
    ${statTile('Tickets', tickets.length, `${assignees} ${plural(assignees, 'assignee')}`, { href: '#tickets', big: true })}
    ${statTile('On open risk', count('open'), 'the work is still needed', { href: '#tickets?status=open' })}
    ${statTile('Risk now covered', closed, 'mitigated or accepted: close the ticket?', { href: '#tickets?status=mitigated,accepted' })}
    <a class="stat" href="#tickets?q=overdue"><span class="k">Overdue</span><span class="v" data-ticket-overdue>—</span><span class="s">past the until date, today</span></a>
    ${statTile('No due date', undated, 'no until clause')}
  </div>
  <div class="chips" id="ticket-chips">
    <span class="chips-label">State</span>
    ${chip('status', '', 'All', { count: tickets.length })}
    ${chip('status', 'open', 'Open risk', { count: count('open'), cls: 'chip-crit' })}
    ${chip('status', 'mitigated', 'Mitigated', { count: count('mitigated') })}
    ${chip('status', 'accepted', 'Accepted', { count: count('accepted') })}
    ${count('unexposed') > 0 ? chip('status', 'unexposed', 'Not declared', { count: count('unexposed') }) : ''}
  </div>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn ghost" data-clear-filters>Clear</button></div>
  <p class="guide">Search matches every column — ticket, threat, asset, SLA, assignee, due date, description and file. Type <code>overdue</code> for the tickets past their date. Click a row for the annotation and the code around it.</p>
  <div class="table-wrap"><table id="tickets-table" class="sortable fixed" data-paginate="25">
    ${colgroup(['12%', '9%', '11%', '8%', '11%', '9%', '10%', '', '10%'])}
    ${sortableHead([{ key: 'ref', label: 'Ticket' }, { key: 'threat', label: 'Threat' }, { key: 'asset', label: 'Asset' }, { key: 'sla', label: 'SLA' }, { key: 'assignee', label: 'Assignee' }, { key: 'due', label: 'Due' }, { key: 'state', label: 'State' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>${rows}
    </tbody>
  </table></div>
  <p class="empty-state no-match" data-count-for="tickets-table" hidden>No ticket matches this filter.</p>
  ${pager('tickets-table')}
</section>`;
}
