/**
 * GuardLink Dashboard — Threat Reports: the saved AI analyses, rendered
 * client-side from the embedded markdown by the legacy report explorer, with
 * a toolbar to copy or download the one on screen and to copy the command
 * that writes the next one.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Framework names in the command chips are fixed strings; nothing from a report is interpolated server-side"
 * @comment -- "Whole-project documents: --feature does not narrow them, and the page says so on a slice. With no saved report the page renders its own empty state so the copy buttons exist without the client"
 */
import { esc, scopeLabel, sectionHead, copyButton } from '../html.js';
import type { PageContext } from './context.js';

const FRAMEWORKS = ['stride', 'dread', 'pasta', 'attacker', 'rapid', 'general'];

function commandChips(): string {
  return `<div class="report-cmds">${FRAMEWORKS.map(f => `<span class="report-cmd">guardlink threat-report ${f}${copyButton(`guardlink threat-report ${f}`, `Copy the ${f} command`)}</span>`).join('')}
    <span class="report-cmd">guardlink threat-report general --custom "focus on auth"${copyButton('guardlink threat-report general --custom "focus on auth"', 'Copy the custom-prompt command')}</span>
  </div>`;
}

export function renderReportsPage(ctx: PageContext): string {
  const { scope, analyses } = ctx;
  const has = analyses.length > 0;
  return `
<div id="sec-ai-analysis" class="section-content">
  ${sectionHead('✨', 'Threat Reports', null, `<span class="muted">${analyses.length} saved</span>`)}
${scope ? `  <p class="scope-note">⚠ These reports are <strong>whole-project</strong> documents. Unlike the rest of this page they are not narrowed to ${esc(scopeLabel(scope))}, and they may discuss assets outside it.</p>` : ''}
  <p class="lead">Reports written by <code>guardlink threat-report</code> (STRIDE, DREAD, PASTA, attacker, rapid, general or a custom prompt). ${has ? 'Pick one to read it here; copy or download it to share.' : 'None saved yet — copy a command below to write the first.'}</p>
  ${has ? `
  <div class="panel ai-analysis-panel">
    <div class="report-toolbar">
      <select id="report-selector" class="report-selector" aria-label="Select threat report"></select>
      <button class="btn btn-primary" data-copy-report title="Copy the whole report as markdown">⧉ Copy report</button>
      <button class="btn" data-download-report title="Save the report as a .md file">↓ Download .md</button>
    </div>
    <div id="ai-content" class="md-content ai-analysis-main"></div>
  </div>
  <p class="guide">Write another:</p>
  ${commandChips()}` : `
  <div class="panel report-empty">
    <div class="big">✨</div>
    <h3>No threat reports yet</h3>
    <p>Generate one with the threat-report command, then regenerate this dashboard. Each framework asks a different question of the same model.</p>
    ${commandChips()}
  </div>`}
</div>`;
}
