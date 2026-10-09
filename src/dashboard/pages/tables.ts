/**
 * GuardLink Dashboard — the record tables that used to make up "Data &
 * Boundaries", each now on the page it belongs to:
 *   - flows, trust boundaries and data classifications are the table twin of
 *     Diagrams › Data flow;
 *   - validations, ownership, audits and assumptions sit under the Assets ledger;
 *   - actors and entitlements under Agents & reach;
 *   - developer comments and shielded regions under Code.
 *
 * Every table is sortable and searchable; rows carry the attributes the client
 * filters act on.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every cell is escaped, including owner names, rationale and entitlement citations"
 * @comment -- "The empty-state sentence and its condition are kept word for word (flows are not part of it): the feature-slice test pins the sentence"
 */
import { esc, scopeLabel, subHead, sortableHead, rowAttrs, locCellShort, descCell, pager } from '../html.js';
import type { PageContext } from './context.js';

type Ctx = Pick<PageContext, 'model' | 'scope' | 'links' | 'reach'>;
const head = (id: string, title: string, n: number): string => subHead(title, '', `<span data-count-for="${id}">${n}</span>`).replace('<div class="sub-h">', `<div class="sub-h" id="t-${id}">`);
const locOf = (ctx: Ctx) => (l: { file: string; line: number } | undefined | null): string => locCellShort(l?.file, l?.line, ctx.links);

/** Diagrams › Data flow, the table twin: flows, trust boundaries, data classifications. */
export function flowTables(ctx: Ctx): string {
  const { model } = ctx;
  const loc = locOf(ctx);
  const empty = model.boundaries.length === 0 && model.data_handling.length === 0 && model.comments.length === 0
    && model.validations.length === 0 && model.ownership.length === 0 && model.audits.length === 0
    && model.assumptions.length === 0 && model.shields.length === 0 && (model.entitlements || []).length === 0;
  return `
  ${model.flows.length > 0 ? `
  ${head('flows', 'Data flows', model.flows.length)}
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
  ${head('boundaries', 'Trust boundaries', model.boundaries.length)}
  <div class="table-wrap"><table id="boundaries" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'a', label: 'Side A' }, { key: 'arrow', label: '', plain: true }, { key: 'b', label: 'Side B' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.boundaries.map(b => `
    <tr ${rowAttrs({ file: b.location?.file, search: ['boundary', b.asset_a, b.asset_b, b.description ?? '', b.location?.file ?? ''] })}>
      <td><code>${esc(b.asset_a)}</code></td>
      <td class="flow-arrow" title="${b.directed ? 'from the less-trusted side to the more-trusted side' : 'a trust line between the two'}">${b.directed ? '⊢→' : '⊢'}</td>
      <td><code>${esc(b.asset_b)}</code></td>
      ${descCell(b.description, '—')}
      ${loc(b.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('boundaries')}` : ''}

  ${model.data_handling.length > 0 ? `
  ${head('classifications', 'Data classifications', model.data_handling.length)}
  <div class="table-wrap"><table id="classifications" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'class', label: 'Classification' }, { key: 'asset', label: 'Asset' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.data_handling.map(d => `
    <tr ${rowAttrs({ file: d.location?.file, search: ['handles', d.classification, d.asset ?? '', d.description ?? '', d.location?.file ?? ''] })}>
      <td><span class="tag">${esc(d.classification)}</span></td>
      <td><code>${esc(d.asset || '—')}</code></td>
      ${descCell(d.description, '—')}
      ${loc(d.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('classifications')}` : ''}

  ${empty
    ? `<p class="empty-state">${ctx.scope
        ? `No trust boundaries, data classifications or lifecycle annotations in the files tagged ${esc(scopeLabel(ctx.scope))}. The project may declare them elsewhere — this slice does not show them.`
        : 'No data classifications, trust boundaries, or lifecycle annotations found.'}</p>` : ''}`;
}

/** Under the Assets ledger: validations, ownership, audits, assumptions. */
export function lifecycleTables(ctx: Ctx): string {
  const { model } = ctx;
  const loc = locOf(ctx);
  return `
  ${model.validations.length > 0 ? `
  ${head('validations', 'Validations', model.validations.length)}
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
  ${head('ownership', 'Ownership', model.ownership.length)}
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
  ${head('audits', 'Audit items', model.audits.length)}
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

  ${model.assumptions.length > 0 ? `
  ${head('assumptions', 'Assumptions', model.assumptions.length)}
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
  ${pager('assumptions')}` : ''}`;
}

/** Under Agents & reach: every declared actor, and the entitlements claimed for them. */
export function actorTables(ctx: Ctx): string {
  const { model, reach } = ctx;
  const loc = locOf(ctx);
  return `
  ${reach.actors.length > 0 ? `
  ${head('actors', 'Actors', reach.actors.length)}
  <p class="guide">Principals in the authorization model. An actor is an <strong>AI agent</strong> when some <code>@agents</code> names it.</p>
  <div class="table-wrap"><table id="actors" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'actor', label: 'Actor' }, { key: 'kind', label: 'Kind' }, { key: 'reaches', label: 'Reaches' }, { key: 'unentitled', label: 'Unentitled' }, { key: 'approves', label: 'Approves' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${reach.actors.map(a => `
    <tr ${rowAttrs({ file: a.loc?.file, search: ['actor', a.agent ? 'agent' : a.reaches > 0 ? 'principal' : '', a.approves > 0 ? 'approver' : '', a.declared ? '' : 'undeclared', a.ref, a.name, a.description ?? ''] })}>
      <td><code>${esc(a.ref)}</code></td>
      <td>${a.agent ? '<span class="reach-kind agent">AI agent</span>' : a.reaches > 0 ? '<span class="reach-kind">principal</span>' : a.approves > 0 ? '<span class="reach-kind">approver</span>' : '<span class="muted">—</span>'}${a.declared ? '' : ' <span class="state st-review"><span class="g">◐</span>undeclared</span>'}</td>
      <td class="num">${a.reaches}</td>
      <td class="num">${a.unentitled > 0 ? `<strong>${a.unentitled}</strong>` : '0'}</td>
      <td class="num">${a.approves}</td>
      ${descCell(a.description, '—')}
      ${loc(a.loc)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('actors')}` : ''}

  ${(model.entitlements || []).length > 0 ? `
  ${head('entitlements', 'Entitlements', model.entitlements!.length)}
  <p class="guide">Capabilities a principal is claimed to hold <strong>by design</strong>. The join is (actor, asset, threat) — a row with either <em>missing</em> joins no finding and cannot demote one. An entitlement never suppresses a finding and never gates testing; it only changes what downstream triage recommends. A claim that cites no authorization code is <strong>inert</strong> and has no effect.</p>
  <div class="table-wrap"><table id="entitlements" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'actor', label: 'Actor' }, { key: 'capability', label: 'Capability' }, { key: 'asset', label: 'Asset' }, { key: 'threat', label: 'Threat' }, { key: 'citation', label: 'Citation' }, { key: 'rationale', label: 'Rationale', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${model.entitlements!.map(en => `
    <tr ${rowAttrs({ file: en.location?.file, search: ['entitles', en.inert ? 'inert' : 'cited', en.actor, en.capability, en.asset ?? '', en.threat ?? '', en.description ?? '', en.location?.file ?? ''] })}>
      <td><code>${esc(en.actor)}</code></td>
      <td><code>${esc(en.capability)}</code></td>
      <td>${en.asset ? `<code>${esc(en.asset)}</code>` : '<span class="state st-review"><span class="g">◐</span>missing</span>'}</td>
      <td>${en.threat ? `<code>${esc(en.threat)}</code>` : '<span class="state st-review"><span class="g">◐</span>missing</span>'}</td>
      <td>${en.citation ? `<code>${esc(en.citation.raw)}</code>` : '<span class="state st-review"><span class="g">◐</span>inert &mdash; uncited</span>'}</td>
      ${descCell(en.description, '(no rationale given)')}
      ${loc(en.location)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('entitlements')}` : ''}`;
}

/** Under Code: developer comments and shielded regions. */
export function codeTables(ctx: Ctx): string {
  const { model } = ctx;
  const loc = locOf(ctx);
  return `
  ${model.shields.length > 0 ? `
  ${head('shields', 'Shielded regions', model.shields.length)}
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
  ${head('comments', 'Developer comments', model.comments.length)}
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
  ${pager('comments')}` : ''}`;
}
