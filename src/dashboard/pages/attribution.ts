/**
 * GuardLink Dashboard — Attribution: who introduces, declares and fixes
 * exposed code, which AI tools are involved, and whether it is getting better.
 *
 * Rendered only when the model went through `attachBlame`. Every number here
 * is explained once in a reading guide next to it, and every identity is a
 * link that narrows the claims table to that person or tool.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Identities, model names, shas, paths and statuses all pass through esc(); a co-author trailer is free text in a commit message and is the realistic vector"
 * @handles pii on #dashboard -- "Author identities rendered into a page that is often committed; blame.identity=hash in config.json is the setting for a shared dashboard"
 * @comment -- "No wall clock: ages are measured to the HEAD commit's date, so two generations at the same HEAD are byte-identical"
 */
import { esc, kpi, chip, sortableHead, rowAttrs, numCell, sevBadge, sevRank, locCellShort, whoLink, badge, sectionHead, subHead, plural, num, pager, colgroup } from '../html.js';
import type { AttributionData } from '../data.js';
import type { PageContext, ClaimView, DrawerRef } from './context.js';
import type { Cohort, TrendBucket } from '../../blame/types.js';

function refCell(r: DrawerRef | null, links: PageContext['links']): string {
  if (!r) return '<td data-v="">—</td>';
  return `<td data-v="${esc(r.date)}">${links ? `<a class="sha" href="${esc(r.url ?? '')}" target="_blank" rel="noopener" title="${esc(r.sha)}"><code>${esc(r.sha.slice(0, 8))}</code></a>` : `<code class="sha" title="${esc(r.sha)}">${esc(r.sha.slice(0, 8))}</code>`} <span class="muted">${esc(r.date)}</span><br>${whoLink(r.author)}${r.co.length > 0 ? ` <span class="muted">+ ${r.co.map(whoLink).join(', ')}</span>` : ''}${r.ai.length > 0 ? `<div class="attr-ai">${r.ai.map(a => badge(a, 'blue')).join('')}</div>` : ''}</td>`;
}

/** Past 16 quarters the columns become unreadable; roll them up to years (open_end = the year's last quarter). */
function rollUp(trends: TrendBucket[]): { buckets: TrendBucket[]; unit: 'quarter' | 'year' } {
  if (trends.length <= 16) return { buckets: trends, unit: 'quarter' };
  const byYear = new Map<string, TrendBucket>();
  for (const t of trends) {
    const y = t.period.slice(0, 4);
    const b = byYear.get(y) ?? { period: y, introduced: 0, introduced_ai: 0, fixed: 0, open_end: 0 };
    b.introduced += t.introduced; b.introduced_ai += t.introduced_ai; b.fixed += t.fixed; b.open_end = t.open_end;
    byYear.set(y, b);
  }
  return { buckets: [...byYear.values()], unit: 'year' };
}

function trendChart(raw: TrendBucket[]): string {
  if (raw.length === 0) return '<p class="empty-state">No dated introductions to chart.</p>';
  const { buckets: trends, unit } = rollUp(raw);
  const max = Math.max(1, ...trends.map(t => Math.max(t.introduced, t.fixed)));
  const maxOpen = Math.max(1, ...trends.map(t => t.open_end));
  const h = (n: number): number => Math.round((n / max) * 100);
  const last = trends[trends.length - 1];
  return `
  <div class="trend-legend"><span class="l-human">Introduced (human)</span><span class="l-ai">Introduced (AI-assisted)</span><span class="l-fixed">Fixed</span></div>
  <div class="trend">
    ${trends.map(t => `
    <div class="trend-col" title="${esc(t.period)}: ${t.introduced} introduced (${t.introduced_ai} AI-assisted), ${t.fixed} fixed, ${t.open_end} open at the end">
      <div class="trend-bars">
        <div class="trend-bar-stack" style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%">
          <div class="trend-bar ai" style="height:${h(t.introduced_ai)}%;border-radius:${t.introduced - t.introduced_ai > 0 ? '0' : '3px 3px 0 0'}"></div>
          <div class="trend-bar human" style="height:${h(t.introduced - t.introduced_ai)}%"></div>
        </div>
        <div class="trend-bar fixed" style="height:${h(t.fixed)}%"></div>
      </div>
      <div class="trend-label">${esc(t.period)}</div>
    </div>`).join('')}
  </div>
  ${unit === 'year' ? '<div class="guide" style="margin-top:.4rem">Rolled up to years: the history spans more quarters than a column each can show.</div>' : ''}
  <div class="trend-legend" style="margin-top:.8rem"><span class="l-open">Open at period end</span><span class="muted">latest: <b>${last.open_end}</b> at ${esc(last.period)}</span></div>
  <div class="trend trend-open">
    ${trends.map(t => `<div class="trend-col" title="${esc(t.period)}: ${t.open_end} open at the end"><div class="trend-bars"><div class="trend-bar open" style="height:${Math.round((t.open_end / maxOpen) * 100)}%"></div></div><div class="trend-label">${esc(t.period)}</div></div>`).join('')}
  </div>`;
}

function cohortCard(title: string, c: Cohort, note: string): string {
  return `
  <div class="cohort">
    <h4>${esc(title)}</h4>
    <div class="cohort-row"><span>Commits in history</span><b>${c.commits}</b></div>
    <div class="cohort-row"><span>Exposures introduced</span><b>${c.introduced}</b></div>
    <div class="cohort-row"><span>Per 100 commits</span><b>${num(c.per_100_commits)}</b></div>
    <div class="cohort-row"><span>Fixed</span><b>${c.fixed}</b></div>
    <div class="cohort-row"><span>Still open</span><b>${c.open}</b></div>
    <div class="cohort-row"><span>Median days to fix</span><b>${num(c.median_time_to_fix_days)}</b></div>
    <p class="guide" style="margin:.5rem 0 0">${esc(note)}</p>
  </div>`;
}

function rateCols(hasCommits: boolean): { key: string; label: string; numeric?: boolean; plain?: boolean; cls?: string }[] {
  return [
    { key: 'introduced', label: 'Introduced', numeric: true },
    { key: 'bar', label: '', plain: true, cls: 'attr-bar' },
    { key: 'fixed', label: 'Fixed', numeric: true },
    { key: 'open', label: 'Open', numeric: true },
    { key: 'risk', label: 'Risk score', numeric: true },
    ...(hasCommits ? [{ key: 'commits', label: 'Commits', numeric: true }, { key: 'per100', label: 'Per 100 commits', numeric: true }] : []),
    { key: 'touched', label: 'Touched', numeric: true },
    { key: 'lines', label: 'Lines', numeric: true },
    { key: 'oldest', label: 'Oldest open (days)', numeric: true },
    { key: 'median', label: 'Median days to fix', numeric: true },
  ];
}

function rateCells(r: { introduced: number; fixed: number; open: number; risk_score: number; commits: number | null; per_100_commits: number | null; touched: number; lines: number; oldest_open_days: number | null; median_time_to_fix_days: number | null }, max: number, hasCommits: boolean): string {
  const bar = `<div class="sev-track attr-track"><div class="sev-fill attr-fill" style="width:${max > 0 ? Math.round((r.introduced / max) * 100) : 0}%"></div></div>`;
  return `${numCell(r.introduced)}<td class="attr-bar">${bar}</td>${numCell(r.fixed)}${numCell(r.open)}${numCell(r.risk_score, String(r.risk_score), 'score')}${hasCommits ? `${numCell(r.commits)}${numCell(r.per_100_commits)}` : ''}${numCell(r.touched)}${numCell(r.lines)}${numCell(r.oldest_open_days)}${numCell(r.median_time_to_fix_days)}`;
}

function claimRow(c: ClaimView, ctx: PageContext): string {
  const b = c.blame!;
  return `
    <tr class="clickable${c.status === 'open' || c.status === 'confirmed' ? ' row-open' : ''}" data-claim="${c.idx}" ${rowAttrs({ file: c.file, sev: c.severity, status: c.status, who: c.who, state: c.state, search: [c.search, b.status] })}>
      <td data-v="${esc(c.status)}">${badge(c.status === 'control' ? 'control' : c.status, c.status === 'open' || c.status === 'confirmed' ? 'red' : c.status === 'mitigated' ? 'green' : c.status === 'accepted' ? 'blue' : 'neutral')}</td>
      ${numCell(sevRank(c.severity), c.verb === 'mitigates' ? '—' : sevBadge(c.severity))}
      <td data-v="${esc(`${c.asset} ${c.threat}`)}"><div class="claim-cell" title="${esc(`${c.asset} → ${c.threat}`)}"><code class="cc-asset">${esc(c.asset)}</code><code class="cc-threat">${esc(c.threat)}</code></div></td>
      ${locCellShort(c.file, c.line, ctx.links)}
      ${c.verb === 'mitigates' ? '<td data-v="">—</td>' : refCell(b.introduced, ctx.links)}
      ${refCell(b.declared, ctx.links)}
      ${c.verb === 'mitigates' ? '<td data-v="">—</td>' : b.fixed ? refCell(b.fixed, ctx.links) : '<td data-v="">' + badge('open', 'red') + '</td>'}
      ${numCell(b.days)}
      <td data-v="${esc(b.status)}">${b.status === 'ok' ? badge('ok', 'green') : badge(b.status, 'neutral')}${b.lowerBound ? ' ' + badge('lower bound', 'neutral', 'History is truncated or the file has uncommitted edits: the true introduction may be older') : ''}</td>
    </tr>`;
}

export function renderAttributionPage(a: AttributionData, ctx: PageContext): string {
  const { scope, links, claims } = ctx;
  const attributed = claims.filter(c => c.blame !== null);
  const exposuresWithBlame = attributed.filter(c => c.verb !== 'mitigates');
  const fixed = exposuresWithBlame.filter(c => c.blame!.fixed !== null).length;
  const aiOpen = exposuresWithBlame.filter(c => c.status === 'open' && c.blame!.introduced && c.blame!.introduced.ai.length > 0).length;
  const days = exposuresWithBlame.map(c => c.blame!.days).filter((d): d is number => d !== null).sort((x, y) => x - y);
  const medianDays = days.length === 0 ? null : days.length % 2 ? days[(days.length - 1) / 2] : (days[days.length / 2 - 1] + days[days.length / 2]) / 2;
  const hasCommits = a.commits !== null;
  const cols = rateCols(hasCommits);
  const maxIntro = a.maxIntroduced;
  const cmp = a.comparison;
  const pct = (part: number, whole: number): string => { if (whole <= 0) return '—'; const p = (part / whole) * 100; return p > 0 && p < 10 ? p.toFixed(1) : String(Math.round(p)); };
  const aiShareCommits = cmp ? pct(cmp.ai.commits, cmp.human.commits + cmp.ai.commits) : null;
  const aiShareIntro = cmp ? pct(cmp.ai.introduced, cmp.human.introduced + cmp.ai.introduced) : null;

  return `
<div id="sec-attribution" class="section-content">
  ${sectionHead('👥', 'Attribution', scope, a.as_of ? `<span class="muted">as of ${esc(a.as_of.slice(0, 10))}</span>` : '')}
  <p class="lead">Who introduced the code beneath each claim, who declared it, who declared its fix, and which AI tool co-authored those commits — read from git history. AI credit is <strong>declared</strong> by commit trailers (<code>Co-Authored-By</code>, <code>Assisted-by</code>), never detected from code; a commit with no trailer stays human. Click any person or tool to see exactly their claims.</p>

  <div class="kpis">
    ${kpi({ value: attributed.length, label: 'Claims read from git', href: '#attribution', hint: `${exposuresWithBlame.length} exposures, ${attributed.length - exposuresWithBlame.length} controls` })}
    ${kpi({ value: a.humans.length, label: 'People credited', href: '#attribution', hint: 'authors and human co-authors' })}
    ${kpi({ value: a.agents.length, label: 'AI tools credited', href: '#attribution?who=ai', tone: a.agents.length > 0 ? 'warn' : 'muted', hint: 'tool + model pairs' })}
    ${kpi({ value: aiOpen, label: 'Open, AI-assisted', href: '#attribution?who=ai&status=open', tone: aiOpen > 0 ? 'danger' : 'success', hint: 'introduced with AI help, still open' })}
    ${kpi({ value: fixed, label: 'Fixed', href: '#attribution?status=mitigated', tone: 'success', hint: `of ${exposuresWithBlame.length} exposures` })}
    ${kpi({ value: medianDays === null ? '—' : medianDays, label: 'Median days to fix', href: '#attribution?status=mitigated', tone: 'muted', hint: 'introduction to declared fix' })}
  </div>

  <div class="summary-grid">
    <div class="panel">
      ${subHead('Exposures over time', '', 'by quarter of the introducing commit')}
      <p class="guide">Each column is a quarter. The left bar is exposures whose code was introduced that quarter, split into human-only and AI-assisted commits; the right bar is exposures whose fix was declared that quarter. A rising "open at period end" means introductions outpace fixes.</p>
      ${trendChart(a.trends)}
    </div>
    <div class="panel">
      ${subHead('Human vs AI-assisted', '', hasCommits ? `${a.commits!.total} commits in history` : 'needs history')}
      ${cmp ? `
      <p class="guide">AI-assisted commits are <strong>${aiShareCommits}%</strong> of history and introduced <strong>${aiShareIntro}%</strong> of the attributed exposures. "Per 100 commits" is the fair comparison: it divides each cohort's exposures by its own commit count.</p>
      <div class="cohorts">
        ${cohortCard('Human-only commits', cmp.human, 'Commits whose author and trailers credit no AI tool.')}
        ${cohortCard('AI-assisted commits', cmp.ai, 'Commits whose author or a trailer credits an AI tool.')}
      </div>` : '<p class="empty-state">Commit counts were not read for this run, so cohorts cannot be compared. Run without <code>history: false</code>.</p>'}
    </div>
  </div>

  ${subHead('By person', '', `<span data-count-for="people">${a.humans.length}</span> credited`)}
  <p class="guide"><strong>Introduced</strong> credits the author, every human co-author and every AI tool on the commit that introduced the exposure's code. <strong>Risk score</strong> weights that person's still-open introductions by severity (critical 8, high 4, medium 2, low 1). <strong>Touched</strong> counts exposures whose span they currently own lines of, whoever introduced them. <strong>Per 100 commits</strong> divides introductions by the person's commits in history.</p>
  ${a.humans.length > 0 ? `
  <div class="table-wrap"><table id="people" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'identity', label: 'Identity' }, ...cols])}
    <tbody>
    ${a.humans.map(r => `
    <tr ${rowAttrs({ file: '', search: ['person', r.identity] })}>
      <td>${whoLink(r.identity)}</td>
      ${rateCells(r, maxIntro, hasCommits)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('people')}
  <div class="no-match" data-count-for="people" hidden>No person matches the current search.</div>` : '<p class="empty-state">No one could be attributed.</p>'}

  ${subHead('By AI tool', '', `<span data-count-for="agents">${a.agents.length}</span> credited`)}
  <p class="guide">Same measures per tool and model. A tool is credited only when a commit declared it; the granularity is the commit, so a co-authored commit means the tool was involved, not that it wrote every line.</p>
  ${a.agents.length > 0 ? `
  <div class="table-wrap"><table id="agents" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'tool', label: 'Tool' }, { key: 'model', label: 'Model' }, ...cols])}
    <tbody>
    ${a.agents.map(r => `
    <tr ${rowAttrs({ file: '', search: ['agent', r.tool, r.model ?? ''] })}>
      <td><code>${esc(r.tool)}</code></td>
      <td>${whoLink(`${r.tool} ${r.model ?? ''}`.trim()).replace(`>${esc(`${r.tool} ${r.model ?? ''}`.trim())}<`, `>${esc(r.model ?? '—')}<`)}</td>
      ${rateCells(r, maxIntro, hasCommits)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('agents')}` : '<p class="empty-state">No AI tool is credited on any attributed commit.</p>'}

  ${a.hot_files.length > 0 ? `
  ${subHead('Files most rewritten under open exposures', '', `top ${a.hot_files.length}`)}
  <p class="guide">Files whose open exposures have the most distinct commits still owning lines — where many hands, and possibly many tools, keep touching exposed code.</p>
  <div class="table-wrap"><table id="hotfiles" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'file', label: 'File', cls: 'loc' }, { key: 'open', label: 'Open exposures', numeric: true }, { key: 'contributors', label: 'Commits owning lines', numeric: true }, { key: 'ai', label: 'AI tools', numeric: true }])}
    <tbody>
    ${a.hot_files.map(f => `
    <tr ${rowAttrs({ file: f.file, search: ['hot', f.file] })}>
      ${locCellShort(f.file, null, links)}
      ${numCell(f.open)}${numCell(f.contributors)}${numCell(f.ai_tools)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('hotfiles')}` : ''}

  ${subHead('Claims', '', `<span data-count-for="claims">${attributed.length}</span>`)}
  <div class="chips">
    <span class="chips-label">Show</span>
    ${chip('who', '', 'Everyone')}
    ${chip('who', 'ai', 'AI-assisted only', { count: attributed.filter(c => c.who.includes('ai')).length })}
    <span class="sep"></span>
    <span class="chips-label">Status</span>
    ${chip('status', '', 'All')}
    ${chip('status', 'open', 'Open', { count: attributed.filter(c => c.status === 'open').length, cls: 'chip-crit' })}
    ${chip('status', 'mitigated', 'Mitigated', { count: attributed.filter(c => c.status === 'mitigated').length })}
    ${chip('status', 'control', 'Controls', { count: attributed.filter(c => c.status === 'control').length })}
  </div>
  <div class="who-filter" hidden><span>Showing claims credited to</span> <strong class="who-filter-name"></strong><button class="btn btn-ghost" data-clear-filters style="margin-left:auto">Clear</button></div>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn btn-ghost" data-clear-filters>Clear</button></div>
  <div class="table-wrap"><table id="claims" class="sortable fixed" data-paginate="25">
    ${colgroup(['9%', '10%', '13%', '16%', '12%', '12%', '11%', '6%', ''])}
    ${sortableHead([{ key: 'status', label: 'Status' }, { key: 'severity', label: 'Severity', numeric: true }, { key: 'claim', label: 'Claim' }, { key: 'location', label: 'Location', cls: 'loc' }, { key: 'introduced', label: 'Introduced by' }, { key: 'declared', label: 'Declared by' }, { key: 'fixed', label: 'Fixed by' }, { key: 'days', label: 'Days', numeric: true }, { key: 'bstatus', label: 'Attribution' }])}
    <tbody>${attributed.map(c => claimRow(c, ctx)).join('')}</tbody>
  </table></div>
  ${pager('claims')}
  <div class="no-match" data-count-for="claims" hidden>No claim matches the current filters.</div>
  ${a.degraded.length > 0 ? `<p class="guide">Not fully attributed: ${a.degraded.map(d => `<code>${esc(d.status)}</code> ×${d.count}`).join(', ')}. <code>no-git</code>: not a git checkout · <code>uncommitted</code>: the line or its span has changes git has not seen · <code>shallow</code>: history is truncated, so every introduction is a lower bound · <code>no-anchor</code>: the claim has no code span, only its own line.</p>` : ''}
  <p class="guide">${plural(attributed.length, 'claim')} read from git at ${a.as_of ? esc(a.as_of.slice(0, 10)) : 'HEAD'}. Identities are shown as configured by <code>blame.identity</code> (name, email or hash).</p>
</div>`;
}
