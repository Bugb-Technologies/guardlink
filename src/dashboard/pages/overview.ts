/**
 * GuardLink Dashboard — Overview: how much is open, where every exposure
 * stands, what the model can see, and what to do next.
 *
 * The page leads with a sentence carrying the two numbers that matter — how
 * many exposures are open, and how many of those are critical or high. The
 * A–F grade survives as a small tag beside it: a judgement, not a number to act
 * on. Three panels follow: open by severity (a mix bar), every exposure
 * accounted for (one bar, every exposure in exactly one segment), and what the
 * model covers. Then the computed "What to do next" list, the worst open
 * exposures, attribution when the model carries blame, and the inventory.
 *
 * The headline and the three panels are rendered once for the whole model and
 * once per @feature, so the feature dropdown swaps in numbers computed by the
 * same code rather than patching text in the browser.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every model value, action text and identity is rendered through esc(); hrefs are attribute-escaped"
 * @comment -- "The inventory keeps statCard markup and labels: the feature filter rewrites the Open Threats and Mitigated tiles by label, and a test greps the tile"
 */
import { esc, statCard, sevBadge, sevRank, scopeLabel, subHead, copyButton, locInline, whoLink, plural, normSev, routeWithQuery, mixBar, statTile, stateChip, scopeTag, type Segment } from '../html.js';
import type { PageContext } from './context.js';
import type { ChangeSummary, ChangedClaim } from '../analytics.js';
import { computeRiskGrade } from '../grade.js';
import { computeSeverityOf } from '../data.js';
import { ACCEPTANCE_REGISTER_NOTE } from '../../parser/acceptance.js';

const SEVS = ['critical', 'high', 'medium', 'low', 'unset'] as const;

const pair = (c: ChangedClaim): string => `<a class="pill" href="${esc(routeWithQuery('exposures', `${c.asset} ${c.threat}`))}" title="${esc(`${c.file}:${c.line}`)}"><code>${esc(c.asset)}</code> → <code>${esc(c.threat)}</code></a>`;
const pillList = (list: ChangedClaim[], max = 6): string => list.slice(0, max).map(pair).join(' ') + (list.length > max ? ` <span class="muted">and ${list.length - max} more</span>` : '');

/** What changed since --since <ref>: the numbers that move open risk, each a way into the rows behind it. */
function sinceStrip(ch: ChangeSummary): string {
  const when = ch.refDate ? ch.refDate.slice(0, 10) : null;
  const meta = [when, ch.commits !== null ? `${ch.commits} ${plural(ch.commits, 'commit')}` : null].filter(Boolean).join(', ');
  const delta = ch.riskDelta === 'increased' ? 'worse' : ch.riskDelta === 'decreased' ? 'better' : 'unchanged';
  const cell = (n: number, label: string, small: string, href: string, mark: 'warm' | 'res' | 'review' | 'none'): string =>
    `<a class="since-cell" href="${href}"><span class="since-mark m-${mark}" aria-hidden="true">${mark === 'warm' ? '+' : mark === 'res' ? '−' : mark === 'review' ? '◐' : '·'}</span><b class="num">${n}</b><span>${label}</span><small>${small}</small></a>`;
  return `
  <div class="since-strip panel since-${esc(ch.riskDelta)}" id="since-strip">
    <div class="since-head">
      <span class="since-title">What changed since <code>${esc(ch.ref)}</code>${meta ? ` <span class="muted">(${esc(meta)})</span>` : ''}</span>
      <span class="since-delta">open risk ${delta}</span>
    </div>
    <div class="since-cells">
      ${cell(ch.newExposures.length, `new ${plural(ch.newExposures.length, 'exposure')}`, `${ch.newOpen} still open`, '#exposures?change=new', ch.newOpen > 0 ? 'warm' : 'none')}
      ${cell(ch.resolved.length, 'resolved', 'mitigated, accepted or removed', '#exposures?status=mitigated', ch.resolved.length > 0 ? 'res' : 'none')}
      ${cell(ch.newConfirmed, 'newly confirmed', 'proven exploitable', '#exposures?status=confirmed', ch.newConfirmed > 0 ? 'warm' : 'none')}
      ${cell(ch.newMitigations, `new ${plural(ch.newMitigations, 'mitigation')}`, 'controls declared', '#exposures?status=mitigated', ch.newMitigations > 0 ? 'res' : 'none')}
      ${cell(ch.wentStale.length, 'went stale', 'verified claims in files that changed', '#exposures?state=stale', ch.wentStale.length > 0 ? 'review' : 'none')}
    </div>
    ${ch.newExposures.length > 0 ? `<div class="since-list"><span class="since-list-label">+ New</span> ${pillList(ch.newExposures)}</div>` : ''}
    ${ch.resolved.length > 0 ? `<div class="since-list"><span class="since-list-label">− Resolved</span> ${pillList(ch.resolved)}</div>` : ''}
    ${ch.wentStale.length > 0 ? `<div class="since-list"><span class="since-list-label">◐ Stale</span> ${pillList(ch.wentStale)}</div>` : ''}
  </div>`;
}

/** What the headline and the three panels need; a feature variant supplies the same shape for a narrowed model. */
export type OverviewInput = Pick<PageContext, 'scope' | 'claims' | 'model' | 'stats' | 'scopeFiles'>;
export interface OverviewVariant { feature: string; input: OverviewInput }

/** The headline sentence, the grade tag and the three panels, for one model. */
export function overviewBody(input: OverviewInput, featureFiles?: number): string {
  // A feature variant says what it counts in its own note; only the page's scope tags the headline.
  const variant = featureFiles !== undefined;
  const { claims, model, stats, scope, scopeFiles } = input;
  const ex = claims.filter(c => c.verb !== 'mitigates');
  const open = ex.filter(c => c.status === 'open' || c.status === 'confirmed');
  const bySev = (list: typeof ex, k: string): number => list.filter(c => normSev(c.severity) === k).length;
  const critHigh = bySev(open, 'critical') + bySev(open, 'high');
  const mitigated = ex.filter(c => c.status === 'mitigated').length;
  const refuted = ex.filter(c => c.status === 'refuted').length;
  const accepted = ex.filter(c => c.status === 'accepted').length;
  const confirmed = ex.filter(c => c.status === 'confirmed').length;
  const exposuresOnly = ex.filter(c => c.verb === 'exposes');
  const openExposures = exposuresOnly.filter(c => c.status === 'open');
  const risk = computeRiskGrade(computeSeverityOf(openExposures), openExposures.length, exposuresOnly.length, confirmed);
  const pct = ex.length ? Math.round((mitigated / ex.length) * 100) : 0;

  const openSegs: Segment[] = SEVS.filter(k => k !== 'unset' || bySev(open, 'unset') > 0)
    .map(k => ({ label: k, n: bySev(open, k), cls: `s-${k}`, href: `#exposures?sev=${k}&status=open` }));
  const acct: Segment[] = [
    ...(confirmed ? [{ label: 'proven exploitable', n: confirmed, cls: 's-critical proven', href: '#exposures?status=confirmed' }] : []),
    ...SEVS.filter(k => bySev(openExposures, k) > 0).map(k => ({ label: `open · ${k}`, n: bySev(openExposures, k), cls: `s-${k}`, href: `#exposures?sev=${k}&status=open` })),
    { label: 'accepted', n: accepted, cls: 'acc', href: '#exposures?status=accepted' },
    ...(refuted ? [{ label: 'refuted', n: refuted, cls: 'res', href: '#exposures?status=refuted' }] : []),
    { label: 'mitigated', n: mitigated, cls: 'res', href: '#exposures?status=mitigated' },
  ];
  // The ledger, when one exists: how many claims are locked to the code beneath them. A ledger
  // with nothing stale or unverified usually means one `guardlink verify` locked every claim,
  // so say who and when — 100% then reads as a lock, not a review.
  const states = claims.filter(c => c.state !== null);
  const verified = states.filter(c => c.state === 'verified').length;
  const verifiedPct = states.length ? Math.round((verified / states.length) * 100) : 0;
  const lockedHint = ((): string | null => {
    if (!states.length || verified !== states.length) return null;
    const whos = [...new Set(states.map(c => c.verifiedBy).filter(Boolean))];
    const dates = states.map(c => (c.verifiedAt ?? '').slice(0, 10)).filter(Boolean).sort();
    if (!whos.length || !dates.length) return null;
    const when = dates[0] === dates[dates.length - 1] ? dates[0] : `${dates[0]} to ${dates[dates.length - 1]}`;
    return `all locked ${when} by ${whos.length === 1 ? whos[0] : `${whos.length} people`}`;
  })();
  const files = model.annotated_files?.length || 0;
  const filesTotal = files + (model.unannotated_files || []).length;
  const crossing = (() => {
    const pairs = new Set(model.boundaries.flatMap(b => [`${b.asset_a}\u0000${b.asset_b}`, `${b.asset_b}\u0000${b.asset_a}`].map(s => s.toLowerCase())));
    return model.flows.filter(f => pairs.has(`${f.source}\u0000${f.target}`.toLowerCase())).length;
  })();

  return `
  <div class="page-head">
    <div class="ph-text">
      <h2 class="ph-title headline" data-stat="headline"><span class="num">${open.length}</span> of <span class="num">${ex.length}</span> ${plural(ex.length, 'exposure')} ${open.length === 1 ? 'is' : 'are'} open${variant ? '' : scopeTag(scope)}</h2>
      <p class="lead">${critHigh} critical or high. Mitigated means a <code>@mitigates</code> covers the same asset and threat; accepted means an <code>@accepts</code> in code signs the risk off. ${esc(ACCEPTANCE_REGISTER_NOTE)}</p>
    </div>
    <div class="ph-right"><span class="grade g-${esc(risk.grade.toLowerCase())}" title="${esc(`${risk.label}: ${risk.summary}. Graded from confirmed findings first, then open exposures by severity; mitigated exposures do not count.`)}"><b>${esc(risk.grade)}</b> risk grade</span></div>
  </div>

  <div class="grid3">
    <div class="panel">
      <div class="panel-h"><span class="eyebrow">Open, by severity</span></div>
      <div class="panel-b"><a class="big" href="#exposures?status=open" data-stat="open">${open.length}</a>${mixBar(openSegs, 'open exposures by severity')}</div>
    </div>
    <div class="panel">
      <div class="panel-h"><span class="eyebrow">Every exposure, accounted for</span></div>
      <div class="panel-b"><div><a class="big" href="#exposures?status=mitigated" data-stat="mitigated-pct">${pct}%</a> <span class="muted">mitigated · ${mitigated} of ${ex.length}</span></div>${mixBar(acct, 'exposure accounting')}${states.length ? `<div class="ledger-line">${statTile('Verified claims', `${verifiedPct}%`, lockedHint ?? `${states.filter(c => c.state === 'stale').length} stale · ${states.filter(c => c.state === 'unverified').length} unverified`, { href: '#exposures?state=verified' })}</div>` : ''}</div>
    </div>
    <div class="panel">
      <div class="panel-h"><span class="eyebrow">What the model covers</span></div>
      <div class="panel-b tiles2">
        ${scope
          ? statTile('Files in this slice', featureFiles ?? scopeFiles, `tagged @feature ${scopeLabel(scope)}`, { href: '#code' })
          : statTile('Files annotated', files, filesTotal ? `of ${filesTotal} · ${Math.round((files / filesTotal) * 100)}%` : 'no source files', { href: '#code' })}
        ${statTile('Controls', stats.controls, `${model.mitigations.length} ${plural(model.mitigations.length, 'mitigation')}`, { href: '#diagrams?tab=threat' })}
        ${statTile('Trust lines', stats.boundaries, 'declared @boundary', { href: '#diagrams?tab=flow' })}
        ${statTile('Flows', stats.flows, `${crossing} cross a trust line`, { href: '#diagrams?tab=flow' })}
      </div>
    </div>
  </div>`;
}

export function renderOverviewPage(ctx: PageContext, variants: OverviewVariant[] = []): string {
  const { unmitigated, stats, scope, actions, attribution, links, changes, mitigatedCount } = ctx;
  const worst = [...unmitigated].sort((a, b) => sevRank(a.severity) - sevRank(b.severity)).slice(0, 8);
  const claimIdx = new Map(ctx.claims.filter(c => c.verb === 'exposes').map(c => [`${c.file}:${c.line}:${c.asset}:${c.threat}`, c.idx]));
  const live = actions.filter(a => a.id !== 'none');
  // The marker is warm only when the action is about an open threat claim.
  const warm = new Set(['confirmed', 'open-severe']);

  return `
<section id="sec-overview" class="section-content active" aria-label="Overview">
${scope ? `  <p class="scope-note">Every number on this page counts annotations from the ${ctx.scopeFiles} file(s) tagged <code>@feature ${esc(scopeLabel(scope))}</code>. The risk grade grades ${scope.length > 1 ? 'these features' : 'this feature'} — it is <strong>not</strong> the project's grade.</p>` : ''}
  <div class="feature-body" data-feature="">${overviewBody(ctx)}</div>
  ${variants.map(v => `<div class="feature-body" data-feature="${esc(v.feature)}" hidden><p class="variant-note">Counting only the files tagged <code>@feature "${esc(v.feature)}"</code> and the definitions they reference.</p>${overviewBody(v.input, v.input.scopeFiles)}</div>`).join('')}
${changes ? sinceStrip(changes) : ''}

  <div class="grid2">
    <div class="panel" id="actions">
      <div class="panel-h"><span class="eyebrow">What to do next</span><span class="subtle">${live.length} ${plural(live.length, 'item')}</span></div>
      <div class="panel-b actions">
        ${actions.map(a => `
        <div class="action" data-action="${esc(a.id)}">
          <span class="action-mark${warm.has(a.id) ? ` s-${a.level === 'critical' ? 'critical' : 'high'}` : ''}" aria-hidden="true"></span>
          <div class="action-main">
            <div class="action-title">${a.href ? `<a href="${esc(a.href)}">${esc(a.title)}</a>` : esc(a.title)}</div>
            <div class="action-detail">${esc(a.detail)}</div>
            ${a.command ? `<div class="well cmd"><code>${esc(a.command)}</code>${copyButton(a.command, 'Copy command')}</div>` : ''}
          </div>
          <div class="action-ctas">
            ${a.href ? `<a class="btn ghost" href="${esc(a.href)}">Show</a>` : ''}
            ${a.command ? `<button class="btn ghost" data-copy="${esc(a.command)}">Copy command</button>` : ''}
          </div>
        </div>`).join('')}
      </div>
    </div>

    <div class="panel">
      <div class="panel-h"><span class="eyebrow">Worst open exposures</span><span class="subtle">${worst.length} of ${unmitigated.length}</span></div>
      <div class="panel-b">
      ${unmitigated.length > 0 ? `
      <div class="table-wrap"><table class="tbl compact"><thead><tr><th>Severity</th><th>Asset → threat</th><th>State</th></tr></thead><tbody>
      ${worst.map(e => {
        const idx = claimIdx.get(`${e.file}:${e.line}:${e.asset}:${e.threat}`);
        return `
        <tr class="clickable" data-ff="${esc(e.file)}"${idx !== undefined ? ` data-claim="${idx}"` : ''}>
          <td>${sevBadge(e.severity)}</td>
          <td><div class="mono"><code>${esc(e.asset)}</code> → <code>${esc(e.threat)}</code></div>${e.description ? `<div class="desc">${esc(e.description)}</div>` : ''}<div class="loc-line">${locInline(e.file, e.line, links)}</div></td>
          <td>${stateChip('open')}</td>
        </tr>`;
      }).join('')}
      </tbody></table></div>
      <a class="see-all" href="#exposures?status=open">See all ${unmitigated.length} open ${plural(unmitigated.length, 'exposure')} →</a>` : `<p class="empty-state">Every exposure${scope ? ` in ${scope.length > 1 ? 'these features' : 'this feature'}` : ''} is mitigated or accepted.</p>`}
      </div>
    </div>
  </div>

  ${attribution ? `
  <div class="panel">
    <div class="panel-h"><span class="eyebrow">Who introduces exposed code</span><a class="see-all" href="#attribution">Attribution →</a></div>
    <div class="panel-b">
    <p class="guide">From git history: the author, co-authors and any AI tool credited on the commit that introduced each exposure's code. ${attribution.comparison ? `${attribution.comparison.ai.introduced} of ${attribution.comparison.ai.introduced + attribution.comparison.human.introduced} exposures were introduced with AI help.` : ''}</p>
    <div class="cohorts">
      <div class="cohort"><h4>People</h4>${attribution.humans.slice(0, 4).map(r => `<div class="cohort-row"><span>${whoLink(r.identity)}</span><b>${r.introduced} introduced · ${r.open} open</b></div>`).join('') || '<div class="cohort-row"><span class="muted">no one attributed</span></div>'}</div>
      <div class="cohort"><h4>AI tools</h4>${attribution.agents.slice(0, 4).map(r => `<div class="cohort-row"><span>${whoLink(`${r.tool} ${r.model ?? ''}`.trim())}</span><b>${r.introduced} introduced · ${r.open} open</b></div>`).join('') || '<div class="cohort-row"><span class="muted">no AI tool credited on any attributed commit</span></div>'}</div>
    </div>
    </div>
  </div>` : ''}

  ${subHead('Model inventory', '', 'each tile opens its page')}
  <div class="stats-grid inventory">
    ${statCard(stats.assets, 'Assets', '', '#assets')}
    ${statCard(unmitigated.length, 'Open Threats', 'danger', '#exposures?status=open')}
    ${stats.confirmed > 0 ? statCard(stats.confirmed, 'Confirmed', 'danger', '#exposures?status=confirmed') : ''}
    ${statCard(mitigatedCount, 'Mitigated', 'success', '#exposures?status=mitigated')}
    ${statCard(stats.controls, 'Controls', 'success', '#diagrams?tab=threat')}
    ${statCard(stats.flows, 'Data Flows', '', '#diagrams?tab=flow')}
    ${statCard(stats.boundaries, 'Boundaries', '', '#diagrams?tab=flow&q=boundary')}
    ${statCard(stats.transfers, 'Transfers', '', '#exposures?q=transfer')}
    ${statCard(stats.validations, 'Validations', 'success', '#assets?q=validates')}
    ${statCard(stats.audits, 'Audits', '', '#assets?q=audit')}
    ${statCard(stats.assumptions, 'Assumptions', '', '#assets?q=assumes')}
    ${stats.actors > 0 ? statCard(stats.actors, 'Actors', '', '#agents?q=actor') : ''}
    ${stats.entitlements > 0 ? statCard(stats.entitlements, 'Entitlements', '', '#agents?q=entitle') : ''}
    ${statCard(stats.ownership, 'Ownership', '', '#assets?q=owns')}
    ${statCard(stats.comments, 'Comments', 'muted', '#code?q=comment')}
    ${stats.shields > 0 ? statCard(stats.shields, 'Shields', 'muted', '#code?q=shield') : ''}
  </div>
</section>`;
}
