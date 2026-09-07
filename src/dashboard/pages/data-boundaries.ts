/**
 * GuardLink Dashboard — Data & Boundaries: flows, trust boundaries,
 * classifications and every lifecycle annotation, each table sortable and
 * searchable, with jump links at the top.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every cell is escaped, including owner names, rationale and entitlement citations"
 * @comment -- "The empty-state sentence and its condition are unchanged (flows are not part of it) because the feature-slice test pins the sentence"
 */
import { esc, scopeLabel, sectionHead, subHead, sortableHead, rowAttrs, locCellShort, descCell, pager, icon } from '../html.js';
import type { PageContext } from './context.js';

export function renderDataPage(ctx: PageContext): string {
  const { model, scope, links } = ctx;
  const loc = (l: { file: string; line: number } | undefined | null): string => locCellShort(l?.file, l?.line, links);
  const sections: { id: string; label: string; count: number }[] = [];
  const add = (id: string, label: string, count: number): void => { if (count > 0) sections.push({ id, label, count }); };
  add('flows', 'Data Flows', model.flows.length);
  add('boundaries', 'Trust Boundaries', model.boundaries.length);
  add('classifications', 'Data Classifications', model.data_handling.length);
  add('validations', 'Validations', model.validations.length);
  add('ownership', 'Ownership', model.ownership.length);
  add('audits', 'Audit Items', model.audits.length);
  add('entitlements', 'Entitlements', (model.entitlements || []).length);
  add('assumptions', 'Assumptions', model.assumptions.length);
  add('shields', 'Shielded Regions', model.shields.length);
  add('comments', 'Developer Comments', model.comments.length);

  const nothingLifecycle = model.boundaries.length === 0 && model.data_handling.length === 0 && model.comments.length === 0
    && model.validations.length === 0 && model.ownership.length === 0 && model.audits.length === 0
    && model.assumptions.length === 0 && model.shields.length === 0 && (model.entitlements || []).length === 0;

  return `
<div id="sec-data" class="section-content">
  ${sectionHead(icon('lock'), 'Data &amp; Boundaries', scope)}
  <p class="lead">Where data moves, where trust changes hands, what is classified, and the lifecycle claims (validations, ownership, audits, entitlements, assumptions). Type <kbd>/</kbd> to search across all of them.</p>
  ${sections.length > 0 ? `<div class="jump">${sections.map(s => `<a href="#data-${s.id}" onclick="event.preventDefault();document.getElementById('data-${s.id}').scrollIntoView({behavior:'smooth',block:'start'})">${s.label}<b>${s.count}</b></a>`).join('')}</div>` : ''}
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn btn-ghost" data-clear-filters>Clear</button></div>

  ${model.flows.length > 0 ? `
  ${subHead('Data Flows', '', `<span data-count-for="flows">${model.flows.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-flows">')}
  <div class="table-wrap"><table id="flows" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'source', label: 'Source' }, { key: 'arrow', label: '', plain: true }, { key: 'target', label: 'Target' }, { key: 'mechanism', label: 'Mechanism' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.flows.map(f => `
    <tr ${rowAttrs({ file: f.location?.file, search: ['flow', f.source, f.target, f.mechanism ?? '', f.description ?? '', f.location?.file ?? ''] })}>
      <td><code>${esc(f.source)}</code></td>
      <td class="flow-arrow">→</td>
      <td><code>${esc(f.target)}</code></td>
      <td>${esc(f.mechanism || '—')}</td>
      ${descCell(f.description, '—')}
      ${loc(f.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('flows')}
  <div class="no-match" data-count-for="flows" hidden>No flow matches the current filters.</div>` : ''}

  ${model.boundaries.length > 0 ? `
  ${subHead('Trust Boundaries', '', `<span data-count-for="boundaries">${model.boundaries.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-boundaries">')}
  <div class="table-wrap"><table id="boundaries" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'a', label: 'Side A' }, { key: 'arrow', label: '', plain: true }, { key: 'b', label: 'Side B' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.boundaries.map(b => `
    <tr ${rowAttrs({ file: b.location?.file, search: ['boundary', b.asset_a, b.asset_b, b.description ?? '', b.location?.file ?? ''] })}>
      <td><code>${esc(b.asset_a)}</code></td>
      <td style="color:var(--purple)">↔</td>
      <td><code>${esc(b.asset_b)}</code></td>
      ${descCell(b.description, '—')}
      ${loc(b.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('boundaries')}` : ''}

  ${model.data_handling.length > 0 ? `
  ${subHead('Data Classifications', '', `<span data-count-for="classifications">${model.data_handling.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-classifications">')}
  <div class="table-wrap"><table id="classifications" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'class', label: 'Classification' }, { key: 'asset', label: 'Asset' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.data_handling.map(d => `
    <tr ${rowAttrs({ file: d.location?.file, search: ['handles', d.classification, d.asset ?? '', d.description ?? '', d.location?.file ?? ''] })}>
      <td><span class="ann-badge ann-data">${esc(d.classification)}</span></td>
      <td><code>${esc(d.asset || '—')}</code></td>
      ${descCell(d.description, '—')}
      ${loc(d.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('classifications')}` : ''}

  ${model.validations.length > 0 ? `
  ${subHead('Validations', '', `<span data-count-for="validations">${model.validations.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-validations">')}
  <div class="table-wrap"><table id="validations" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'control', label: 'Control' }, { key: 'asset', label: 'Asset' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.validations.map(v => `
    <tr ${rowAttrs({ file: v.location?.file, search: ['validates', v.control, v.asset, v.description ?? '', v.location?.file ?? ''] })}>
      <td><code>${esc(v.control)}</code></td>
      <td><code>${esc(v.asset)}</code></td>
      ${descCell(v.description, '—')}
      ${loc(v.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('validations')}` : ''}

  ${model.ownership.length > 0 ? `
  ${subHead('Ownership', '', `<span data-count-for="ownership">${model.ownership.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-ownership">')}
  <div class="table-wrap"><table id="ownership" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'asset', label: 'Asset' }, { key: 'owner', label: 'Owner' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.ownership.map(o => `
    <tr ${rowAttrs({ file: o.location?.file, search: ['owns', o.asset, o.owner, o.description ?? '', o.location?.file ?? ''] })}>
      <td><code>${esc(o.asset)}</code></td>
      <td><strong>${esc(o.owner)}</strong></td>
      ${descCell(o.description, '—')}
      ${loc(o.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('ownership')}` : ''}

  ${model.audits.length > 0 ? `
  ${subHead('Audit Items', '', `<span data-count-for="audits">${model.audits.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-audits">')}
  <p class="guide">Each <code>@audit</code> marks a risk that has no control yet and needs a human decision.</p>
  <div class="table-wrap"><table id="audits" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'asset', label: 'Asset' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.audits.map(a => `
    <tr ${rowAttrs({ file: a.location?.file, search: ['audit', a.asset, a.description ?? '', a.location?.file ?? ''] })}>
      <td><code>${esc(a.asset)}</code></td>
      ${descCell(a.description, 'Needs review')}
      ${loc(a.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('audits')}` : ''}

  ${(model.entitlements || []).length > 0 ? `
  ${subHead('Entitlements', '', `<span data-count-for="entitlements">${model.entitlements!.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-entitlements">')}
  <p class="guide">Capabilities a principal is claimed to hold <strong>by design</strong>. The join is (actor, asset, threat) — a row with either <em>missing</em> joins no finding and cannot demote one. An entitlement never suppresses a finding and never gates testing; it only changes what downstream triage recommends. A claim that cites no authorization code is <strong>inert</strong> and has no effect.</p>
  <div class="table-wrap"><table id="entitlements" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'actor', label: 'Actor' }, { key: 'capability', label: 'Capability' }, { key: 'asset', label: 'Asset' }, { key: 'threat', label: 'Threat' }, { key: 'citation', label: 'Citation' }, { key: 'rationale', label: 'Rationale', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.entitlements!.map(en => `
    <tr ${rowAttrs({ file: en.location?.file, search: ['entitles', en.inert ? 'inert' : 'cited', en.actor, en.capability, en.asset ?? '', en.threat ?? '', en.description ?? '', en.location?.file ?? ''] })}>
      <td><code>${esc(en.actor)}</code></td>
      <td><code>${esc(en.capability)}</code></td>
      <td>${en.asset ? `<code>${esc(en.asset)}</code>` : '<strong style="color:var(--sev-high)">missing</strong>'}</td>
      <td>${en.threat ? `<code>${esc(en.threat)}</code>` : '<strong style="color:var(--sev-high)">missing</strong>'}</td>
      <td>${en.citation ? `<code>${esc(en.citation.raw)}</code>` : '<strong style="color:var(--sev-high)">inert &mdash; uncited</strong>'}</td>
      ${descCell(en.description, '(no rationale given)')}
      ${loc(en.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('entitlements')}` : ''}

  ${model.assumptions.length > 0 ? `
  ${subHead('Assumptions', '', `<span data-count-for="assumptions">${model.assumptions.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-assumptions">')}
  <p class="guide">Unverified assumptions that should be periodically reviewed.</p>
  <div class="table-wrap"><table id="assumptions" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'asset', label: 'Asset' }, { key: 'assumption', label: 'Assumption', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.assumptions.map(a => `
    <tr ${rowAttrs({ file: a.location?.file, search: ['assumes', a.asset, a.description ?? '', a.location?.file ?? ''] })}>
      <td><code>${esc(a.asset)}</code></td>
      ${descCell(a.description, 'Unverified assumption')}
      ${loc(a.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('assumptions')}` : ''}

  ${model.shields.length > 0 ? `
  ${subHead('Shielded Regions', '', `<span data-count-for="shields">${model.shields.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-shields">')}
  <p class="guide">Code regions where annotations are intentionally suppressed via <code>@shield</code>.</p>
  <div class="table-wrap"><table id="shields" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'reason', label: 'Reason', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.shields.map(s => `
    <tr ${rowAttrs({ file: s.location?.file, search: ['shield', s.reason ?? '', s.location?.file ?? ''] })}>
      <td>${esc(s.reason || 'No reason provided')}</td>
      ${loc(s.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('shields')}` : ''}

  ${model.comments.length > 0 ? `
  ${subHead('Developer Comments', '', `<span data-count-for="comments">${model.comments.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="data-comments">')}
  <div class="table-wrap"><table id="comments" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'comment', label: 'Comment', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.comments.map(c => `
    <tr ${rowAttrs({ file: c.location?.file, search: ['comment', c.description ?? '', c.location?.file ?? ''] })}>
      ${descCell(c.description, '(no description)')}
      ${loc(c.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('comments')}` : ''}

  ${nothingLifecycle
    ? `<p class="empty-state">${scope
        ? `No trust boundaries, data classifications or lifecycle annotations in the files tagged ${esc(scopeLabel(scope))}. The project may declare them elsewhere — this slice does not show them.`
        : 'No data classifications, trust boundaries, or lifecycle annotations found.'}</p>` : ''}
</div>`;
}
