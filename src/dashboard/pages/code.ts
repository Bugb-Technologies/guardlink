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
 */
import { esc, scopeLabel, sectionHead, subHead, copyButton, plural, icon } from '../html.js';
import type { PageContext } from './context.js';

export function renderCodePage(ctx: PageContext): string {
  const { fileAnnotations, model, scope, scopeFiles, links } = ctx;
  const unannotated = model.unannotated_files || [];
  const annotatedCount = model.annotated_files?.length || fileAnnotations.length;
  const totalFiles = annotatedCount + unannotated.length;
  const pct = totalFiles > 0 ? annotatedCount / totalFiles : 0;
  const tone = pct >= 0.7 ? 'var(--green)' : pct >= 0.4 ? 'var(--yellow)' : 'var(--red)';

  return `
<div id="sec-code" class="section-content">
  ${sectionHead(icon('code'), 'Code &amp; Annotations', scope, `<span class="muted"><span data-count-for="files">${fileAnnotations.length}</span> ${plural(fileAnnotations.length, 'file')}</span>`)}
  <p class="lead">
    ${scope
      ? `Files tagged ${esc(scopeLabel(scope))}, plus the definition file(s) holding the assets, threats and controls they reference. Click any annotation to see details.`
      : 'Every file with GuardLink annotations. Click a file to expand it and any annotation to see details; type <kbd>/</kbd> to search by path, kind or asset.'}
  </p>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn btn-ghost" data-clear-filters>Clear</button></div>
  <div data-list="files">
  ${fileAnnotations.length > 0 ? fileAnnotations.map((f, fi) => {
    const kinds = new Map<string, number>();
    for (const a of f.annotations) kinds.set(a.kind, (kinds.get(a.kind) ?? 0) + 1);
    const search = [f.file, ...kinds.keys(), ...f.annotations.map(a => `${a.summary} ${a.description}`)].join(' ');
    return `
  <div class="file-card" data-ff="${esc(f.file)}" data-search="${esc(search.toLowerCase())}">
    <div class="file-card-header" onclick="toggleFile(this)">
      <span class="file-path">${esc(f.file)}${copyButton(f.file, 'Copy path')}</span>
      <span class="file-kinds">${[...kinds].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, n]) => `<span>${esc(k)} ${n}</span>`).join('')}</span>
      <span style="display:flex;align-items:center;gap:.4rem;margin-left:auto">
        ${links ? `<a class="loc-link" href="${esc(links.file(f.file))}" target="_blank" rel="noopener" title="Open on host" onclick="event.stopPropagation()">${icon('external')} open</a>` : ''}
        <span class="file-count">${f.annotations.length}</span>
        <span class="chevron">${icon('chevron')}</span>
      </span>
    </div>
    <div class="file-card-body">
      ${f.annotations.map((ann, ai) => `
      <div class="ann-entry" onclick="openAnnotationDrawer(${fi}, ${ai})">
        <div class="ann-header">
          <span class="ann-line">${links ? `<a class="loc-link" href="${esc(links.file(f.file, ann.line))}" target="_blank" rel="noopener" onclick="event.stopPropagation()">L${ann.line}</a>` : `L${ann.line}`}</span>
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
  <div style="display:flex;align-items:center;gap:.8rem;margin-bottom:.3rem">
    <span style="font-size:.88rem;font-weight:600">${scopeFiles} tagged file(s)</span>
    <span style="color:var(--muted);font-size:.82rem">carry ${esc(scopeLabel(scope))}${fileAnnotations.length > scopeFiles ? ` — ${fileAnnotations.length - scopeFiles} further file(s) appear above because this feature references definitions declared in them` : ''}</span>
  </div>
  <p style="color:var(--muted);font-size:.78rem;margin-top:.5rem">
    <strong>Project file coverage and the unannotated-file list are not shown on a feature slice.</strong>
    Both measure the repository — how much of it is annotated at all — and a slice has no view of the files outside it.
    Run <code>guardlink dashboard .</code> without <code>--feature</code>, or <code>guardlink status .</code>, for those numbers.
  </p>
  ` : `
  ${subHead('File Coverage')}
  <div style="display:flex;align-items:center;gap:.8rem;margin-bottom:.3rem">
    <span style="font-size:.88rem;font-weight:600;color:${tone}">${annotatedCount} of ${totalFiles} files</span>
    <span style="color:var(--muted);font-size:.82rem">have GuardLink annotations</span>
  </div>
  ${totalFiles > 0 ? `<div class="posture-bar"><div class="posture-fill ${pct >= 0.7 ? 'good' : pct >= 0.4 ? 'warn' : 'bad'}" style="width:${Math.round(pct * 100)}%"></div></div>` : ''}

  ${unannotated.length > 0 ? `
  ${subHead(`${icon('alert')} Unannotated Files (${unannotated.length})`, '', `<span class="action-cmd"><code>guardlink unannotated .</code>${copyButton('guardlink unannotated .', 'Copy command')}</span>`)}
  <p style="color:var(--muted);font-size:.78rem;margin-bottom:.5rem">
    Source files with no GuardLink annotations. Not all files need annotations — only those touching security boundaries.
  </p>
  <div style="display:flex;flex-direction:column;gap:2px;margin-bottom:1rem" data-list="unannotated">
    ${unannotated.map(f => `<div data-search="unannotated ${esc(f.toLowerCase())}" style="display:flex;align-items:center;font-family:var(--font-mono);font-size:.78rem;padding:.3rem .6rem;background:var(--surface2);border-left:3px solid var(--yellow);border-radius:2px">${links ? `<a class="loc-link" href="${esc(links.file(f))}" target="_blank" rel="noopener">${esc(f)}</a>` : esc(f)}${copyButton(f, 'Copy path')}</div>`).join('')}
  </div>` : `<p style="color:var(--green-text);font-size:.82rem;margin-top:.5rem">${icon('check')} All source files have annotations.</p>`}
  `}
</div>`;
}
