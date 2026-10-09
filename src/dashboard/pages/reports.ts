/**
 * GuardLink Dashboard — Reports: the saved threat reports, each rendered here
 * at generation time, with a toolbar to switch, copy or download the one on
 * screen and the commands that write the next one.
 *
 * Each report is rendered once by the built-in Markdown renderer
 * (`../markdown.ts`), which escapes the whole text before adding markup back,
 * and is shown or hidden by the selector. The page loads no Markdown library.
 * The findings block a report declares is drawn as a table above its prose,
 * each id a way into the Exposures table.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Report prose goes through renderMarkdown (escape first, allow-listed link schemes); every finding field goes through esc()"
 * @comment -- "Whole-project documents: --feature does not narrow them, and the page says so on a slice. With no saved report the page renders its own empty state so the copy buttons exist without the client"
 */
import { esc, scopeLabel, pageHead, copyButton, icon, sevBadge, stateChip } from '../html.js';
import type { PageContext } from './context.js';
import type { Finding } from '../../analyze/findings.js';
import { renderMarkdown } from '../markdown.js';

const FRAMEWORKS = ['stride', 'dread', 'pasta', 'attacker', 'rapid', 'general'];
const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function commandChips(): string {
  return `<div class="report-cmds">${FRAMEWORKS.map(f => `<span class="report-cmd mono">guardlink threat-report ${f}${copyButton(`guardlink threat-report ${f}`, `Copy the ${f} command`)}</span>`).join('')}
    <span class="report-cmd mono">guardlink threat-report general --custom "focus on auth"${copyButton('guardlink threat-report general --custom "focus on auth"', 'Copy the custom-prompt command')}</span>
  </div>`;
}

/** One row per finding the report declared, each id a link into the Exposures table. */
export function findingsTable(findings: Finding[]): string {
  if (!findings.length) return '';
  const rows = findings.slice().sort((a, b) => (RANK[a.severity] ?? 4) - (RANK[b.severity] ?? 4) || String(a.id).localeCompare(String(b.id)));
  return `<div class="findings"><div class="sub-h"><span>Findings</span><span class="sub-h-right">${rows.length} declared by the report</span></div>
  <div class="table-wrap"><table class="sortable fixed findings-table"><colgroup><col style="width:7%"><col style="width:10%"><col style="width:11%"><col style="width:14%"><col style="width:14%"><col><col style="width:16%"></colgroup>
  <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Asset</th><th>Threat</th><th>Finding</th><th class="loc">Location</th></tr></thead><tbody>
  ${rows.map(f => {
    const loc = f.location && f.location.file ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}` : '';
    const q = encodeURIComponent(`${f.asset || ''} ${f.threat || ''}`.trim());
    return `<tr title="${esc(f.evidence || '')}"><td><code>${esc(f.id)}</code></td>
      <td>${sevBadge(f.severity)}</td>
      <td>${stateChip(f.status === 'confirmed' ? 'confirmed' : f.status === 'mitigated' ? 'mitigated' : f.status === 'accepted' ? 'accepted' : 'open', f.status)}</td>
      <td>${f.asset ? `<a class="pill" href="#exposures?q=${encodeURIComponent(f.asset)}"><code>${esc(f.asset)}</code></a>` : ''}</td>
      <td>${f.threat ? `<a class="pill" href="#exposures?q=${encodeURIComponent(f.threat)}"><code>${esc(f.threat)}</code></a>` : ''}</td>
      <td><a href="#exposures?q=${q}">${esc(f.title || '')}</a>${f.remediation ? `<div class="subtle small">${esc(f.remediation)}</div>` : ''}</td>
      <td class="loc">${loc ? `<span class="loc-text">${esc(loc)}</span>${copyButton(loc, 'Copy path')}` : ''}</td></tr>`;
  }).join('')}
  </tbody></table></div></div>`;
}

function reportLabel(r: PageContext['analyses'][number]): string {
  return `${r.label || r.framework || 'Analysis'} (${r.timestamp || ''})${r.model ? ` — ${r.model}` : ''}`;
}

export function renderReportsPage(ctx: PageContext): string {
  const { scope, analyses } = ctx;
  const has = analyses.length > 0;
  return `
<section id="sec-reports" class="section-content" aria-label="Reports">
  ${pageHead('Reports', null, `Reports written by <code>guardlink threat-report</code> (STRIDE, DREAD, PASTA, attacker, rapid, general or a custom prompt). ${has ? 'Pick one to read it here; copy or download it to share.' : 'None saved yet — copy a command below to write the first.'}`, `<span class="muted">${analyses.length} saved</span>`)}
${scope ? `  <p class="scope-note">These reports are <strong>whole-project</strong> documents. Unlike the rest of this page they are not narrowed to ${esc(scopeLabel(scope))}, and they may discuss assets outside it.</p>` : ''}
  ${has ? `
  <div class="panel">
    <div class="report-toolbar">
      <select id="report-selector" class="report-selector" data-report-select aria-label="Select threat report">${analyses.map((r, i) => `<option value="${i}">${esc(reportLabel(r))}</option>`).join('')}</select>
      <button class="btn" data-copy-report title="Copy the whole report as markdown">${icon('copy')} Copy report</button>
      <button class="btn ghost" data-download-report title="Save the report as a .md file">${icon('download')} Download .md</button>
    </div>
    ${analyses.map((r, i) => `<article class="md-content" data-report="${i}"${i === 0 ? '' : ' hidden'}>${findingsTable(r.findings || [])}${r.content && r.content.trim() ? renderMarkdown(r.content) : '<p class="empty-state">This report has no prose.</p>'}</article>`).join('')}
  </div>
  <p class="guide">Write another:</p>
  ${commandChips()}` : `
  <div class="panel report-empty">
    <h3>No threat reports yet</h3>
    <p>Generate one with the threat-report command, then regenerate this dashboard. Each framework asks a different question of the same model.</p>
    ${commandChips()}
  </div>`}
</section>`;
}
