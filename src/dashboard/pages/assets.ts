/**
 * GuardLink Dashboard — Assets: every asset as a ranked ledger, riskiest first.
 *
 * The rows are the table twin of Diagrams › Attack surface. Columns: the asset
 * and its path; what is open (a severity chip with the count); one tick per
 * exposure; controls; flows in and out; trust lines; data classes. Headers
 * sort — by risk, by exposures, by name. A row expands to its exposures, with
 * the way onto the threat graph and into its data flow. The lifecycle records
 * (validations, ownership, audits, assumptions) follow as tables.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Asset names, paths, threat labels and classifications are escaped"
 * @comment -- "Rows keep data-ff-asset (every alias of the asset, |-separated) so the feature filter can hide what a feature never touches"
 */
import { esc, pageHead, sevBadge, stateChip, sortableHead, plural } from '../html.js';
import type { PageContext } from './context.js';
import type { DiagramModel, GNode } from '../layout/graph.js';
import { SEV_RANK, isOpenState } from '../layout/graph.js';
import { lifecycleTables } from './tables.js';

const ORDER: Record<string, number> = { open: 0, confirmed: 0, accepted: 1, mitigated: 2, refuted: 2 };

/** Risk rank for sorting: open count first, then the worst open severity, then how much it carries. */
const riskScore = (a: GNode): number => a.open * 1e6 + (a.worst ? (5 - SEV_RANK[a.worst]) * 1e4 : 0) + a.exposures.length;

export function renderAssetsPage(ctx: PageContext, g: DiagramModel): string {
  const { scope, heatmap } = ctx;
  // The asset drawer indexes the heatmap; join by canonical key.
  const drawerIdx = new Map(heatmap.map((h, i) => [g.assetKey(h.name), i]));
  const aliasesOf = new Map(heatmap.map(h => [g.assetKey(h.name), h.aliases]));
  const controls = (a: GNode): number => new Set(g.mitigations.filter(m => m.asset === a.key && m.control).map(m => m.control)).size;
  const rows = g.assets.slice().sort((x, y) => riskScore(y) - riskScore(x) || x.order - y.order);
  const agentRefs = new Set(ctx.reach.actors.filter(a => a.agent).flatMap(a => [a.ref.toLowerCase(), a.name.toLowerCase()]));

  const body = rows.map(a => {
    const ex = a.exposures.slice().sort((x, y) => ORDER[x.state] - ORDER[y.state] || SEV_RANK[x.sev] - SEV_RANK[y.sev] || x.claim - y.claim);
    const ticks = ex.map(e => `<i class="${isOpenState(e.state) ? `tk s-${e.sev}` : e.state === 'accepted' ? 'tk acc' : 'tk res'}" data-tip="${esc(`${a.label} → ${g.threats.get(e.threat)?.label ?? e.threat}`)}" data-tip-rows="${esc(`severity\t${e.sev}\nstate\t${e.state}`)}"></i>`).join('');
    const idx = drawerIdx.get(a.key);
    const aliases = aliasesOf.get(a.key) ?? [a.label];
    const search = [a.label, a.group, ...a.handles, ...ex.map(e => g.threats.get(e.threat)?.label ?? e.threat), a.description].join(' ').toLowerCase();
    const detail = ex.length ? `<ul class="asset-ex">${ex.map(e => `<li class="clickable" data-claim="${e.claim}">${sevBadge(e.sev)} <code>${esc(g.threats.get(e.threat)?.label ?? e.threat)}</code> ${stateChip(e.state)} <span class="subtle">${esc(e.description)}</span></li>`).join('')}</ul>` : '<p class="subtle">No exposure declared on this asset.</p>';
    return `
    <tbody class="row-group" data-ff-asset="${esc(aliases.join('|'))}">
    <tr class="clickable" data-expand data-search="${esc(search)}">
      <td data-v="${esc(a.label.toLowerCase())}"><b class="mono">${esc(a.label)}</b>${agentRefs.has(a.label.toLowerCase()) ? ' <span class="reach-kind agent">AI agent</span>' : ''}<div class="subtle small">${esc(a.group === 'Model' ? '' : a.group)}${a.description ? `${a.group === 'Model' ? '' : ' · '}${esc(a.description)}` : ''}</div></td>
      <td data-v="${riskScore(a)}">${a.open ? sevBadge(a.worst, `${a.open} · ${a.worst}`) : a.exposures.length ? stateChip('mitigated', 'none open') : '<span class="subtle">—</span>'}</td>
      <td data-v="${a.exposures.length}"><span class="ticks">${ticks || '<span class="subtle">nothing declared</span>'}</span></td>
      <td class="num" data-v="${controls(a)}">${controls(a)}</td>
      <td class="num" data-v="${a.flowsIn.length + a.flowsOut.length}">${a.flowsIn.length} in · ${a.flowsOut.length} out</td>
      <td class="num" data-v="${a.boundaries.length}"${a.boundaries.length ? ` title="${esc(a.boundaries.join(', '))}"` : ''}>${a.boundaries.length ? `⊢ ${a.boundaries.length}` : '—'}</td>
      <td>${a.handles.map(h => `<span class="tag">${esc(h)}</span>`).join(' ')}</td>
    </tr>
    <tr class="row-detail" hidden><td colspan="7">
      ${detail}
      <div class="row-actions">
        <a class="btn" href="#diagrams?tab=threat&amp;pin=${encodeURIComponent(a.key)}">On the threat graph →</a>
        <a class="btn ghost" href="#diagrams?tab=flow&amp;view=hood&amp;focus=${encodeURIComponent(a.key)}">Its data flow →</a>
        ${idx !== undefined ? `<button class="btn ghost" data-asset-drawer="${idx}">Everything about it</button>` : ''}
      </div>
    </td></tr>
    </tbody>`;
  }).join('');

  return `
<section id="sec-assets" class="section-content" aria-label="Assets">
  ${pageHead('Assets', scope, `Every asset, riskiest first: what is open on it, one tick per exposure, what controls and flows it has, the trust lines it sits on and the data it handles. Click a header to sort by risk, exposures or name; click a row for its exposures and the way onto the diagrams. The picture of the same assets is <a href="#diagrams?tab=surface">Diagrams › Attack surface</a>.${scope ? ' Only assets this feature touches appear, and each row counts only its exposures.' : ''}`, `<span class="muted"><span data-count-for="assets-ledger">${rows.length}</span> ${plural(rows.length, 'asset')}</span>`)}
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn ghost" data-clear-filters>Clear</button></div>
  ${rows.length > 0 ? `
  <div class="table-wrap"><table id="assets-ledger" class="sortable ledger" data-sort-groups>
    ${sortableHead([{ key: 'asset', label: 'Asset' }, { key: 'risk', label: 'Open', numeric: true }, { key: 'exposures', label: 'Exposures, one tick each', numeric: true }, { key: 'controls', label: 'Controls', numeric: true }, { key: 'flows', label: 'Flows', numeric: true }, { key: 'trust', label: 'Trust lines', numeric: true }, { key: 'handles', label: 'Handles', plain: true }])}
    ${body}
  </table></div>
  <div class="no-match" data-count-for="assets-ledger" hidden>No asset matches the current filters.</div>` : `<p class="empty-state">${scope ? 'No assets are referenced by the files tagged with this feature.' : 'No assets found.'}</p>`}
  ${lifecycleTables(ctx)}
</section>`;
}
