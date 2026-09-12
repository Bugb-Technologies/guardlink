/**
 * GuardLink Dashboard — Executive Summary: how bad, and what now.
 *
 * Grade, five numbers that each open the view behind them, the computed
 * "What to do next" list, coverage and severity, a digest of the worst open
 * exposures, an attribution teaser when the model carries blame, and the
 * inventory of everything else as small linked tiles.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every model value, action text and identity is rendered through esc(); hrefs are attribute-escaped"
 * @comment -- "The Open Threats tile keeps its exact markup and label, and the coverage panel keeps .coverage-pct / .posture-fill / the 'exposures mitigated' sentence: the client feature filter rewrites those by label, and a test greps the tile"
 */
import { esc, kpi, statCard, sevBadge, sevRank, scopeLabel, sectionHead, subHead, copyButton, locInline, whoLink, plural, normSev, icon, routeWithQuery } from '../html.js';
import type { PageContext } from './context.js';
import type { ChangeSummary, ChangedClaim } from '../analytics.js';
import { ACCEPTANCE_REGISTER_NOTE } from '../../parser/acceptance.js';

function severityBar(label: string, count: number, total: number, cls: string): string {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return `<div class="sev-row">
    <span class="sev-label">${label}</span>
    <div class="sev-track"><div class="sev-fill sev-fill-${cls}" style="width:${pct}%"></div></div>
    <span class="sev-count">${count}</span>
  </div>`;
}

const pair = (c: ChangedClaim): string => `<a class="pill" href="${esc(routeWithQuery('threats', `${c.asset} ${c.threat}`))}" title="${esc(`${c.file}:${c.line}`)}"><code>${esc(c.asset)}</code> → <code>${esc(c.threat)}</code></a>`;
const pillList = (list: ChangedClaim[], max = 6): string => list.slice(0, max).map(pair).join(' ') + (list.length > max ? ` <span class="muted">and ${list.length - max} more</span>` : '');

/** What changed since --since <ref>: the numbers that move open risk, each a way into the rows behind it. */
function sinceStrip(ch: ChangeSummary): string {
  const when = ch.refDate ? ch.refDate.slice(0, 10) : null;
  const meta = [when, ch.commits !== null ? `${ch.commits} ${plural(ch.commits, 'commit')}` : null].filter(Boolean).join(', ');
  const delta = ch.riskDelta === 'increased' ? 'worse' : ch.riskDelta === 'decreased' ? 'better' : 'unchanged';
  return `
  <div class="since-strip since-${esc(ch.riskDelta)}" id="since-strip">
    <div class="since-head">
      <span class="since-title">What changed since <code>${esc(ch.ref)}</code>${meta ? ` <span class="muted">(${esc(meta)})</span>` : ''}</span>
      <span class="since-delta">open risk ${delta}</span>
    </div>
    <div class="since-cells">
      <a class="since-cell ${ch.newOpen > 0 ? 'bad' : 'neutral'}" href="#threats?change=new"><b>${ch.newExposures.length}</b><span>new ${plural(ch.newExposures.length, 'exposure')}</span><small>${ch.newOpen} still open</small></a>
      <a class="since-cell ${ch.resolved.length > 0 ? 'good' : 'neutral'}" href="#threats?status=mitigated"><b>${ch.resolved.length}</b><span>resolved</span><small>mitigated, accepted or removed</small></a>
      <a class="since-cell ${ch.newConfirmed > 0 ? 'bad' : 'neutral'}" href="#threats?status=confirmed"><b>${ch.newConfirmed}</b><span>newly confirmed</span><small>proven exploitable</small></a>
      <a class="since-cell ${ch.newMitigations > 0 ? 'good' : 'neutral'}" href="#threats?status=mitigated"><b>${ch.newMitigations}</b><span>new ${plural(ch.newMitigations, 'mitigation')}</span><small>controls declared</small></a>
      <a class="since-cell ${ch.wentStale.length > 0 ? 'warn' : 'neutral'}" href="#threats?state=stale"><b>${ch.wentStale.length}</b><span>went stale</span><small>verified claims in files that changed</small></a>
    </div>
    ${ch.newExposures.length > 0 ? `<div class="since-list"><span class="since-list-label">New</span> ${pillList(ch.newExposures)}</div>` : ''}
    ${ch.resolved.length > 0 ? `<div class="since-list"><span class="since-list-label">Resolved</span> ${pillList(ch.resolved)}</div>` : ''}
    ${ch.wentStale.length > 0 ? `<div class="since-list"><span class="since-list-label">Stale</span> ${pillList(ch.wentStale)}</div>` : ''}
  </div>`;
}

export function renderSummaryPage(ctx: PageContext): string {
  const { stats, severity, risk, unmitigated, exposures, model, mitigatedCount, mitigationCoveragePercent, scope, scopeFiles, actions, ledger, attribution, links, changes } = ctx;
  const severeOpen = unmitigated.filter(e => ['critical', 'high'].includes(normSev(e.severity))).length;
  const accepted = exposures.filter(e => e.accepted).length;
  const verified = ledger ? ledger.report.summary : null;
  const claimsTotal = verified ? verified.verified + verified.stale + verified.unverified : 0;
  const verifiedPct = verified && claimsTotal > 0 ? Math.round((verified.verified / claimsTotal) * 100) : 0;
  // A ledger where nothing is stale or unverified usually means one `guardlink verify`
  // locked every claim; say so, with who and when, so 100% reads as a lock, not a review.
  const lockedHint = ((): string | null => {
    if (!ledger || !verified || verified.stale > 0 || verified.unverified > 0) return null;
    const entries = ledger.report.claims.map(c => c.entry).filter((e): e is NonNullable<typeof e> => !!e);
    if (entries.length === 0) return null;
    const whos = [...new Set(entries.map(e => e.verified_by))];
    const dates = entries.map(e => e.verified_at.slice(0, 10)).sort();
    const when = dates[0] === dates[dates.length - 1] ? dates[0] : `${dates[0]} to ${dates[dates.length - 1]}`;
    return `all locked ${when} by ${whos.length === 1 ? whos[0] : `${whos.length} people`}`;
  })();
  const filesTotal = (model.annotated_files?.length || 0) + (model.unannotated_files || []).length;

  const kpis = [
    kpi({ value: unmitigated.length, label: 'Open threats', href: '#threats?status=open', tone: unmitigated.length > 0 ? 'danger' : 'success', hint: `${severeOpen} critical or high` }),
    kpi({ value: severeOpen, label: 'Critical / high open', href: '#threats?sev=critical,high&status=open', tone: severeOpen > 0 ? 'danger' : 'success', hint: `${severity.critical} critical · ${severity.high} high in total` }),
    stats.confirmed > 0
      ? kpi({ value: stats.confirmed, label: 'Confirmed exploitable', href: '#threats?status=confirmed', tone: 'danger', hint: 'verified by test or scan' })
      // "signed off by a human" was a claim nothing here can support: the
      // signer on an @accepts is free text in a comment, and this dashboard has
      // never read the server decision log where an author is an authenticated
      // principal. Name the register instead of asserting the guarantee.
      : kpi({ value: accepted, label: 'Accepted risks', href: '#threats?status=accepted', tone: 'muted', hint: 'from @accepts in code' }),
    kpi({ value: `${mitigationCoveragePercent}%`, label: 'Mitigation coverage', href: '#threats?status=mitigated', tone: mitigationCoveragePercent >= 70 ? 'success' : mitigationCoveragePercent >= 40 ? 'warn' : 'danger', hint: `${mitigatedCount} of ${exposures.length} exposures` }),
    verified
      ? kpi({ value: `${verifiedPct}%`, label: 'Verified claims', href: '#threats?state=verified', tone: verified.stale > 0 ? 'warn' : verifiedPct >= 70 ? 'success' : 'muted', hint: lockedHint ?? `${verified.stale} stale · ${verified.unverified} unverified` })
      : scope
        ? kpi({ value: scopeFiles, label: 'Files in this slice', href: '#code', tone: 'muted', hint: `tagged @feature ${scopeLabel(scope)}` })
        : kpi({ value: `${stats.coveragePercent}%`, label: 'Files annotated', href: '#code', tone: stats.coveragePercent >= 70 ? 'success' : stats.coveragePercent >= 40 ? 'warn' : 'danger', hint: `${model.annotated_files?.length || 0} of ${filesTotal} source files` }),
  ];

  const worst = [...unmitigated].sort((a, b) => sevRank(a.severity) - sevRank(b.severity)).slice(0, 6);
  const claimIdx = new Map(ctx.claims.filter(c => c.verb === 'exposes').map(c => [`${c.file}:${c.line}:${c.asset}:${c.threat}`, c.idx]));

  return `
<div id="sec-summary" class="section-content active">
  ${sectionHead(icon('layout'), 'Executive Summary', scope)}
${scope ? `  <p class="scope-note">Every number on this page counts annotations from the ${scopeFiles} file(s) tagged <code>@feature ${esc(scopeLabel(scope))}</code>. The risk grade below grades ${scope.length > 1 ? 'these features' : 'this feature'} — it is <strong>not</strong> the project's grade.</p>` : ''}

  <div class="risk-banner risk-${risk.grade.toLowerCase()}">
    <div class="risk-grade">${esc(risk.grade)}</div>
    <div class="risk-detail">
      <strong>${esc(risk.label)}</strong>
      <span>${esc(risk.summary)}</span>
    </div>
    <span class="risk-tagline">Graded from confirmed findings first, then open exposures by severity. Mitigated exposures do not count.</span>
  </div>

  <div class="kpis">${kpis.join('')}</div>
${changes ? sinceStrip(changes) : ''}

  <div class="summary-grid">
    <div class="panel" id="actions">
      ${subHead('What to do next', '', `${actions.filter(a => a.id !== 'none').length} ${plural(actions.filter(a => a.id !== 'none').length, 'item')}`)}
      <div class="actions">
        ${actions.map(a => `
        <div class="action action-${esc(a.level)}" data-action="${esc(a.id)}">
          <span class="action-dot"></span>
          <div>
            <div class="action-title">${a.href ? `<a href="${esc(a.href)}">${esc(a.title)}</a>` : esc(a.title)}</div>
            <div class="action-detail">${esc(a.detail)}</div>
            ${a.command ? `<div class="action-cmd"><code>${esc(a.command)}</code>${copyButton(a.command, 'Copy command')}</div>` : ''}
          </div>
          <div class="action-ctas">
            ${a.href ? `<a class="btn btn-primary" href="${esc(a.href)}">Show</a>` : ''}
            ${a.command ? `<button class="btn" data-copy="${esc(a.command)}">Copy command</button>` : ''}
          </div>
        </div>`).join('')}
      </div>
    </div>

    <div>
      <div class="panel" style="margin-bottom:.9rem">
        ${subHead(`Threat mitigation coverage${scope ? ' <span class="scope-tag">this feature</span>' : ''}`)}
        <div class="panel-row">
          <span class="coverage-pct ${mitigationCoveragePercent >= 70 ? 'good' : mitigationCoveragePercent >= 40 ? 'warn' : 'bad'}">${mitigationCoveragePercent}%</span>
          <span class="panel-muted">${mitigatedCount} of ${exposures.length} exposures mitigated</span>
        </div>
        <div class="posture-bar"><div class="posture-fill ${mitigationCoveragePercent >= 70 ? 'good' : mitigationCoveragePercent >= 40 ? 'warn' : 'bad'}" style="width:${Math.min(mitigationCoveragePercent, 100)}%"></div></div>
        <p class="guide" style="margin-top:.6rem">An exposure counts as mitigated when a <code>@mitigates</code> on the same asset and threat covers it. Accepted risks are not mitigations. ${esc(ACCEPTANCE_REGISTER_NOTE)}</p>
      </div>
      <div class="panel">
        ${subHead(`Severity breakdown${scope ? ' <span class="scope-tag">this feature</span>' : ''}`, '', 'all exposures')}
        <div class="severity-chart">
          ${severityBar('Critical', severity.critical, stats.exposures, 'crit')}
          ${severityBar('High', severity.high, stats.exposures, 'high')}
          ${severityBar('Medium', severity.medium, stats.exposures, 'med')}
          ${severityBar('Low', severity.low, stats.exposures, 'low')}
          ${severity.unset > 0 ? severityBar('Unset', severity.unset, stats.exposures, 'unset') : ''}
        </div>
      </div>
    </div>
  </div>

  ${unmitigated.length > 0 ? `
  <div class="panel">
    ${subHead('Worst open exposures', 'sub-h-alert', `${worst.length} of ${unmitigated.length}`)}
    <div class="digest">
      ${worst.map(e => {
        const idx = claimIdx.get(`${e.file}:${e.line}:${e.asset}:${e.threat}`);
        return `
      <div class="digest-row" data-ff="${esc(e.file)}"${idx !== undefined ? ` data-claim="${idx}"` : ''}>
        ${sevBadge(e.severity)}
        <div class="digest-main"><code>${esc(e.asset)}</code> → <code>${esc(e.threat)}</code>${e.description ? `<div class="desc">${esc(e.description)}</div>` : ''}</div>
        ${locInline(e.file, e.line, links)}
      </div>`;
      }).join('')}
    </div>
    <a class="see-all" href="#threats?status=open">See all ${unmitigated.length} open ${plural(unmitigated.length, 'exposure')} →</a>
  </div>` : `
  <div class="panel"><p class="empty-state">Every exposure${scope ? ` in ${scope.length > 1 ? 'these features' : 'this feature'}` : ''} is mitigated or accepted.</p></div>`}

  ${attribution ? `
  <div class="panel">
    ${subHead('Who introduces exposed code', '', `<a class="see-all" style="margin:0" href="#attribution">Attribution →</a>`)}
    <p class="guide">From git history: the author, co-authors and any AI tool credited on the commit that introduced each exposure's code. ${attribution.comparison ? `${attribution.comparison.ai.introduced} of ${attribution.comparison.ai.introduced + attribution.comparison.human.introduced} exposures were introduced with AI help.` : ''}</p>
    <div class="cohorts">
      <div class="cohort"><h4>People</h4>${attribution.humans.slice(0, 4).map(r => `<div class="cohort-row"><span>${whoLink(r.identity)}</span><b>${r.introduced} introduced · ${r.open} open</b></div>`).join('') || '<div class="cohort-row"><span class="muted">no one attributed</span></div>'}</div>
      <div class="cohort"><h4>AI tools</h4>${attribution.agents.slice(0, 4).map(r => `<div class="cohort-row"><span>${whoLink(`${r.tool} ${r.model ?? ''}`.trim())}</span><b>${r.introduced} introduced · ${r.open} open</b></div>`).join('') || '<div class="cohort-row"><span class="muted">no AI tool credited on any attributed commit</span></div>'}</div>
    </div>
  </div>` : ''}

  ${subHead('Model inventory', '', 'click a tile to open its page')}
  <div class="stats-grid inventory">
    ${statCard(stats.assets, 'Assets', '', '#assets')}
    ${statCard(unmitigated.length, 'Open Threats', 'danger', '#threats?status=open')}
    ${stats.confirmed > 0 ? statCard(stats.confirmed, 'Confirmed', 'danger', '#threats?status=confirmed') : ''}
    ${statCard(mitigatedCount, 'Mitigated', 'success', '#threats?status=mitigated')}
    ${statCard(stats.controls, 'Controls', 'success', '#diagrams')}
    ${statCard(stats.flows, 'Data Flows', '', '#data?q=flow')}
    ${statCard(stats.boundaries, 'Boundaries', '', '#data?q=boundary')}
    ${statCard(stats.transfers, 'Transfers', '', '#threats?q=transfer')}
    ${statCard(stats.validations, 'Validations', 'success', '#data?q=validates')}
    ${statCard(stats.audits, 'Audits', '', '#data?q=audit')}
    ${statCard(stats.assumptions, 'Assumptions', '', '#data?q=assumes')}
    ${stats.actors > 0 ? statCard(stats.actors, 'Actors', '', '#data?q=actor') : ''}
    ${stats.entitlements > 0 ? statCard(stats.entitlements, 'Entitlements', '', '#data?q=entitle') : ''}
    ${statCard(stats.ownership, 'Ownership', '', '#data?q=owns')}
    ${statCard(stats.comments, 'Comments', 'muted', '#data?q=comment')}
    ${stats.shields > 0 ? statCard(stats.shields, 'Shields', 'muted', '#data?q=shield') : ''}
  </div>
</div>`;
}
