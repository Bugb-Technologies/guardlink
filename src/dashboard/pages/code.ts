/**
 * GuardLink Dashboard — Code & Annotations: every annotated file with its
 * annotations and a few lines of context, plus the two project-wide measures
 * a feature slice must not show.
 *
 * File coverage is a property of the REPOSITORY — annotated files over source
 * files. On a slice the number is either the project's (wrong) or the feature's
 * own files over themselves (100% by construction). Both are withheld and named
 * as withheld, with the command that does answer them.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "File paths, summaries, descriptions and code lines are escaped"
 * @comment -- "The withheld-on-a-slice sentence and the coverage strings are pinned by tests; file cards gain search text and a host link"
 * @comment -- "No inline handlers: a file header carries data-toggle-file and an annotation data-annotation, and the page's one delegated listener acts on them"
 */
import { esc, scopeLabel, pageHead, subHead, copyButton, plural, icon, sevBadge, stateChip, claimStateBadge } from '../html.js';
import type { PageContext } from './context.js';
import { codeTables } from './tables.js';
import type { FileRisk } from '../analytics.js';

function fileRiskBadges(r: FileRisk | undefined): string {
  if (!r || (r.open === 0 && r.confirmed === 0 && r.stale === 0)) return '<span class="file-risk"></span>';
  return `<span class="file-risk">${r.confirmed > 0 ? stateChip('confirmed', `${r.confirmed} confirmed`) : ''}${r.open > 0 ? stateChip('open', `${r.open} open`) + sevBadge(r.worst) : ''}${r.stale > 0 ? claimStateBadge('stale').replace('>stale<', `>${r.stale} stale<`) : ''}</span>`;
}

export function renderCodePage(ctx: PageContext): string {
  const { fileAnnotations, model, scope, scopeFiles, links, fileRisk } = ctx;
  const unannotated = model.unannotated_files || [];
  const annotatedCount = model.annotated_files?.length || fileAnnotations.length;
  const totalFiles = annotatedCount + unannotated.length;
  const pct = totalFiles > 0 ? annotatedCount / totalFiles : 0;

  return `
<section id="sec-code" class="section-content" aria-label="Code">
  ${pageHead('Code', scope, scope
      ? `Files tagged ${esc(scopeLabel(scope))}, plus the definition file(s) holding the assets, threats and controls they reference. Click any annotation to see details.`
      : 'Every file with GuardLink annotations, riskiest first. Click a file to expand it and any annotation to see details; type <kbd>/</kbd> to search by path, kind or asset.', `<span class="muted"><span data-count-for="files">${fileAnnotations.length}</span> ${plural(fileAnnotations.length, 'file')}</span>`)}
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn btn-ghost" data-clear-filters>Clear</button></div>
  <div data-list="files">
  ${fileAnnotations.length > 0 ? fileAnnotations.map((f, fi) => {
    const kinds = new Map<string, number>();
    for (const a of f.annotations) kinds.set(a.kind, (kinds.get(a.kind) ?? 0) + 1);
    const search = [f.file, ...kinds.keys(), ...f.annotations.map(a => `${a.summary} ${a.description}`)].join(' ');
    return `
  <div class="file-card" data-ff="${esc(f.file)}" data-search="${esc(search.toLowerCase())}">
    <div class="file-card-header" data-toggle-file role="button" tabindex="0" aria-expanded="false">
      <span class="file-path mono"><bdi>${esc(f.file)}</bdi>${copyButton(f.file, 'Copy path')}</span>
      ${fileRiskBadges(fileRisk.get(f.file))}
      <span class="file-kinds">${[...kinds].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, n]) => `<span>${esc(k)} ${n}</span>`).join('')}</span>
      <span class="file-end">
        ${links ? `<a class="loc-link" href="${esc(links.file(f.file))}" target="_blank" rel="noopener" title="Open on host">${icon('external')} open</a>` : ''}
        <span class="file-count">${f.annotations.length}</span>
        <span class="chevron">${icon('chevron')}</span>
      </span>
    </div>
    <div class="file-card-body">
      ${f.annotations.map((ann, ai) => `
      <div class="ann-entry" data-annotation="${fi}:${ai}" role="button" tabindex="0">
        <div class="ann-header">
          <span class="ann-line">${links ? `<a class="loc-link" href="${esc(links.file(f.file, ann.line))}" target="_blank" rel="noopener">L${ann.line}</a>` : `L${ann.line}`}</span>
          <span class="ann-badge ann-${esc(ann.kind)}">${esc(ann.kind)}</span>
          <span class="ann-summary">${esc(ann.summary)}</span>
        </div>
        ${ann.description ? `<div class="ann-desc">${esc(ann.description)}</div>` : ''}
        ${ann.codeContext.length > 0 ? `<div class="code-block">${ann.codeContext.map((cl, ci) =>
          `<span class="${ci === ann.annLineIdx ? 'code-line-ann' : 'code-line-code'}">${esc(cl)}</span>`,
        ).join('')}</div>` : ''}
      </div>`).join('')}
    </div>
  </div>`;
  }).join('') : `<p class="empty-state">${scope ? `No annotations in the files tagged ${esc(scopeLabel(scope))}.` : 'No annotations found.'}</p>`}
  </div>
  <div class="no-match" data-count-for="files" hidden>No annotated file matches the current filters.</div>

  ${scope ? `
  <!-- File coverage and the unannotated list measure the repository; a slice
       cannot answer either. -->
  ${subHead('Files in this slice')}
  <div class="cov-line">
    <b>${scopeFiles} tagged file(s)</b>
    <span class="muted">carry ${esc(scopeLabel(scope))}${fileAnnotations.length > scopeFiles ? ` — ${fileAnnotations.length - scopeFiles} further file(s) appear above because this feature references definitions declared in them` : ''}</span>
  </div>
  <p class="guide">
    <strong>Project file coverage and the unannotated-file list are not shown on a feature slice.</strong>
    Both measure the repository — how much of it is annotated at all — and a slice has no view of the files outside it.
    Run <code>guardlink dashboard .</code> without <code>--feature</code>, or <code>guardlink status .</code>, for those numbers.
  </p>
  ` : `
  ${subHead('File Coverage')}
  <div class="cov-line">
    <b>${annotatedCount} of ${totalFiles} files</b>
    <span class="muted">have GuardLink annotations</span>
  </div>
  ${totalFiles > 0 ? `<div class="gauge wide"><i class="g-structure" style="width:${Math.round(pct * 100)}%"></i></div>` : ''}

  ${unannotated.length > 0 ? `
  ${subHead(`${icon('alert')} Unannotated Files (${unannotated.length})`, '', `<span class="action-cmd"><code>guardlink unannotated .</code>${copyButton('guardlink unannotated .', 'Copy command')}</span>`)}
  <p class="guide">
    Source files with no GuardLink annotations. Not all files need annotations — only those touching security boundaries.
  </p>
  <div class="unannotated" data-list="unannotated">
    ${unannotated.map(f => `<div class="unann-row mono" data-search="unannotated ${esc(f.toLowerCase())}">${links ? `<a class="loc-link" href="${esc(links.file(f))}" target="_blank" rel="noopener">${esc(f)}</a>` : esc(f)}${copyButton(f, 'Copy path')}</div>`).join('')}
  </div>` : `<p class="guide">${stateChip('mitigated', 'All source files have annotations.')}</p>`}
  `}
  ${codeTables(ctx)}
</section>`;
}
