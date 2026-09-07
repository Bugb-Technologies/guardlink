/**
 * GuardLink Dashboard — shared markup helpers. Pure string builders.
 *
 * Every value that came from the model, from git, or from a file name passes
 * through `esc()` here or in the page that calls these. The one exception is
 * markup these helpers build themselves.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "esc() HTML-encodes every interpolated value; hrefs built here are encoded too, so a hash route carrying a search term cannot break out of the attribute"
 * @comment -- "statCard keeps its exact markup: the feature-slice test greps the Open Threats tile by that string"
 */
import type { RepoLinks } from './links.js';
import type { ThreatModel } from '../types/index.js';
import type { ClaimState } from '../parser/verification.js';

export function esc(s: unknown): string {
  return (s === null || s === undefined ? '' : String(s))
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export type SevKey = 'critical' | 'high' | 'medium' | 'low' | 'unset';

/** `P0..P3` and the words, case-insensitively, onto five buckets. */
export function normSev(s: string | undefined | null): SevKey {
  const l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'critical';
  if (l === 'high' || l === 'p1') return 'high';
  if (l === 'medium' || l === 'p2') return 'medium';
  if (l === 'low' || l === 'p3') return 'low';
  return 'unset';
}

/** CSS class suffix used by `.fc-sev`, `.sev-fill-*`. */
export function sevClass(s: string | undefined | null): 'crit' | 'high' | 'med' | 'low' | 'unset' {
  const k = normSev(s);
  return k === 'critical' ? 'crit' : k === 'medium' ? 'med' : k;
}

/** Sort rank: critical first. */
export function sevRank(s: string | undefined | null): number {
  return { critical: 0, high: 1, medium: 2, low: 3, unset: 4 }[normSev(s)];
}

export function sevBadge(s: string | undefined | null): string {
  return `<span class="fc-sev ${sevClass(s)}">${esc(normSev(s) === 'unset' ? (s || 'unset') : normSev(s))}</span>`;
}

export function badge(text: string, tone: 'red' | 'green' | 'blue' | 'neutral' = 'neutral', title?: string): string {
  const cls = tone === 'neutral' ? 'badge' : `badge badge-${tone}`;
  return `<span class="${cls}"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</span>`;
}

/** The inventory tile. Markup is pinned by tests/feature-dashboard.test.ts — do not restyle the string. */
export function statCard(value: number, label: string, variant = '', href?: string): string {
  const card = `<div class="stat-card${variant ? ` stat-${variant}` : ''}"><div class="value">${value}</div><div class="label">${label}</div></div>`;
  return href ? `<a class="stat-link" href="${esc(href)}">${card}</a>` : card;
}

export interface KpiSpec {
  value: string | number;
  label: string;
  href: string;
  tone?: 'danger' | 'success' | 'warn' | 'muted' | '';
  /** One line under the number: what it means or what changed. */
  hint?: string;
}

/** A headline number that is also the way into the view behind it. */
export function kpi(k: KpiSpec): string {
  return `<a class="kpi${k.tone ? ` kpi-${k.tone}` : ''}" href="${esc(k.href)}"><span class="kpi-v">${esc(k.value)}</span><span class="kpi-l">${esc(k.label)}</span>${k.hint ? `<span class="kpi-h">${esc(k.hint)}</span>` : ''}</a>`;
}

/** A filter chip. `data-chip` groups it; `data-value` is what it sets. */
export function chip(group: string, value: string, label: string, opts: { count?: number; active?: boolean; cls?: string } = {}): string {
  return `<button class="chip${opts.active ? ' active' : ''}${opts.cls ? ` ${opts.cls}` : ''}" data-chip="${esc(group)}" data-value="${esc(value)}">${esc(label)}${opts.count !== undefined ? `<span class="chip-n">${opts.count}</span>` : ''}</button>`;
}

const ICON_PATHS: Record<string, string> = {
  layout: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  diagram: '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.6 13.5 6.8 4"/><path d="m15.4 6.5-6.8 4"/>',
  code: '<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/>',
  file: '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5z"/><path d="M14 2v6h6"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  map: '<path d="m12 2 8.5 4.5v9L12 20l-8.5-4.5v-9z"/><path d="M12 11.5 20.5 7"/><path d="M12 11.5v8.5"/><path d="M12 11.5 3.5 7"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9"/><path d="M16 3.1a4 4 0 0 1 0 7.8"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
  external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  chevron: '<path d="m9 18 6-6-6-6"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.9 4.9 1.4 1.4"/><path d="m17.7 17.7 1.4 1.4"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.3 17.7-1.4 1.4"/><path d="m19.1 4.9-1.4 1.4"/>',
  moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  shield: '<path d="M20 13c0 5-3.5 7.5-7.7 8.8a2 2 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.6a1 1 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z"/>',
  arrows: '<path d="m16 3 4 4-4 4"/><path d="M20 7H4"/><path d="m8 21-4-4 4-4"/><path d="M4 17h16"/>',
  zap: '<path d="M4 14a1 1 0 0 1-.8-1.6l9-12a.5.5 0 0 1 .9.4L11.5 9h8.3a1 1 0 0 1 .8 1.6l-9 12a.5.5 0 0 1-.9-.4L13 15z"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
  hexagon: '<path d="M21 16V8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l7-4a2 2 0 0 0 1-1.7z"/>',
  pill: '<rect x="2" y="7" width="20" height="10" rx="5"/>',
  square: '<rect x="3" y="3" width="18" height="18" rx="2"/>',
  slant: '<path d="M7 4h14l-4 16H3z"/>',
  cylinder: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/>',
  flag: '<path d="M4 22V4h12l-3 5 3 5H4"/>',
};

/**
 * An inline SVG icon (currentColor stroke), so the page needs no icon font
 * and shows no emoji. Unknown names render nothing rather than a glyph.
 */
export function icon(name: string, cls = ''): string {
  const d = ICON_PATHS[name];
  if (!d) return '';
  return `<svg class="ico${cls ? ` ${cls}` : ''}" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
}

/** A small copy-to-clipboard button. The script reads `data-copy`. */
export function copyButton(text: string, title = 'Copy'): string {
  return `<button class="copy" data-copy="${esc(text)}" title="${esc(title)}" aria-label="${esc(title)}">${icon('copy')}</button>`;
}

export function hostLabel(links: RepoLinks | null): string {
  if (!links) return 'repository';
  return links.host === 'github' ? 'GitHub' : links.host === 'gitlab' ? 'GitLab' : links.host === 'bitbucket' ? 'Bitbucket' : 'repository';
}

/**
 * `file:line` as a link to the file at HEAD on the repo host when one is
 * known, else plain text; always with a copy button so the path can travel.
 */
export function locCell(file: string | undefined | null, line: number | undefined | null, links: RepoLinks | null): string {
  if (!file) return '<td class="loc"></td>';
  const text = line ? `${file}:${line}` : file;
  const inner = links
    ? `<a class="loc-link" href="${esc(links.file(file, line ?? undefined))}" target="_blank" rel="noopener" title="Open on ${hostLabel(links)}">${esc(text)}</a>`
    : `<span>${esc(text)}</span>`;
  return `<td class="loc">${inner}${copyButton(text, 'Copy path')}</td>`;
}

/** Inline `file:line` (not a cell) for cards and drawers. */
export function locInline(file: string, line: number | undefined | null, links: RepoLinks | null): string {
  const text = line ? `${file}:${line}` : file;
  return links
    ? `<a class="loc-link" href="${esc(links.file(file, line ?? undefined))}" target="_blank" rel="noopener" title="Open on ${hostLabel(links)}">${esc(text)}</a>`
    : `<span class="loc-text">${esc(text)}</span>`;
}

/** A short sha, linked to the commit when the host is known. */
export function shaLink(sha: string, links: RepoLinks | null): string {
  const short = sha.slice(0, 8);
  return links
    ? `<a class="sha" href="${esc(links.commit(sha))}" target="_blank" rel="noopener" title="${esc(sha)}"><code>${esc(short)}</code></a>`
    : `<code class="sha" title="${esc(sha)}">${esc(short)}</code>`;
}

/**
 * An identity, as a link that narrows the Attribution page to it. The
 * `human:` / `agent:` prefix is its own span so a table cell can hide it
 * (the column already says what the identity is); the full identity stays in
 * the title and the route.
 */
export function whoLink(identity: string): string {
  const m = /^(human|agent):(.+)$/.exec(identity);
  const shown = m ? `<span class="who-kind">${esc(m[1])}:</span>${esc(m[2])}` : esc(identity);
  return `<a class="who" href="#attribution?who=${encodeURIComponent(identity)}" title="${esc(identity)}">${shown}</a>`;
}

export function claimStateBadge(state: ClaimState | undefined): string {
  if (!state) return '';
  const title = state === 'verified' ? 'The code beneath this claim matches the verified hash'
    : state === 'stale' ? 'The code beneath this claim changed since it was verified'
    : 'Never verified — run guardlink verify';
  return `<span class="claim-state ${state}" title="${title}">${state}</span>`;
}

export interface Column {
  key: string;
  label: string;
  /** Sort numerically on `data-v` rather than by text. */
  numeric?: boolean;
  /** Not sortable (an icon column, an actions column). */
  plain?: boolean;
  cls?: string;
}

/** `<thead>` for a sortable table. The script sorts on click of `th[data-sort]`. */
export function sortableHead(cols: Column[]): string {
  return `<thead><tr>${cols.map(c => (c.plain
    ? `<th${c.cls ? ` class="${c.cls}"` : ''}>${c.label}</th>`
    : `<th data-sort="${esc(c.key)}"${c.numeric ? ' data-type="num"' : ''}${c.cls ? ` class="${c.cls}"` : ''}><button class="th-sort">${c.label}<span class="th-arrow" aria-hidden="true"></span></button></th>`)).join('')}</tr></thead>`;
}

export interface RowAttrs {
  file?: string | null;
  sev?: string | null;
  status?: string | null;
  who?: string[] | null;
  state?: ClaimState | null;
  owners?: string[] | null;
  handles?: string[] | null;
  change?: string | null;
  search?: string[];
}

/** The attributes the client filters act on. Order is stable; tests grep it. */
export function rowAttrs(a: RowAttrs): string {
  const parts: string[] = [];
  parts.push(`data-ff="${esc(a.file ?? '')}"`);
  if (a.sev !== undefined) parts.push(`data-sev="${esc(normSev(a.sev))}"`);
  if (a.status) parts.push(`data-status="${esc(a.status)}"`);
  if (a.who && a.who.length > 0) parts.push(`data-who="${esc(a.who.join('|'))}"`);
  if (a.state) parts.push(`data-state="${esc(a.state)}"`);
  if (a.owners && a.owners.length > 0) parts.push(`data-owner="${esc(a.owners.join('|'))}"`);
  if (a.handles && a.handles.length > 0) parts.push(`data-handles="${esc(a.handles.join('|'))}"`);
  if (a.change) parts.push(`data-change="${esc(a.change)}"`);
  parts.push(`data-search="${esc((a.search ?? []).join(' ').toLowerCase())}"`);
  return parts.join(' ');
}

/** `data-v` for numeric sorting of a cell. */
export function numCell(value: number | null, shown?: string, cls = ''): string {
  return `<td${cls ? ` class="${cls}"` : ''} data-v="${value ?? -1}">${shown ?? (value === null ? '—' : String(value))}</td>`;
}

export const num = (n: number | null | undefined): string => (n === null || n === undefined ? '—' : String(n));

/** A description cell clamped to a few lines; the full text stays in the drawer and in the title. */
export function descCell(text: string | undefined | null, fallback = '—'): string {
  const t = text || fallback;
  return t.length > 160
    ? `<td><div class="desc-clamp" title="${esc(t)}">${esc(t)}</div></td>`
    : `<td>${esc(t)}</td>`;
}

/** `"Dashboard", "Login"` — quoted so an odd name is visible. Caller escapes. */
export function scopeLabel(scope: string[]): string {
  return scope.map(f => `"${f}"`).join(', ');
}

/**
 * The feature names this model was narrowed to, or null for a whole project.
 * Read structurally and validated: anything that is not a non-empty array of
 * non-empty strings means "not a slice".
 */
export function featureScope(model: ThreatModel): string[] | null {
  const raw = (model as ThreatModel & { filtered_by_features?: unknown }).filtered_by_features;
  if (!Array.isArray(raw)) return null;
  const names = raw.filter((n): n is string => typeof n === 'string' && n.trim().length > 0);
  return names.length > 0 ? names : null;
}

export function scopeTag(scope: string[] | null): string {
  return scope ? ` <span class="scope-tag">feature ${esc(scopeLabel(scope))}</span>` : '';
}

/** Section heading with an optional right-hand toolbar. */
export function sectionHead(icon: string, title: string, scope: string[] | null, toolbar = ''): string {
  return `<div class="sec-h"><span class="sec-icon">${icon}</span> ${title}${scopeTag(scope)}${toolbar ? `<span class="sec-tools">${toolbar}</span>` : ''}</div>`;
}

export function subHead(title: string, cls = '', right = ''): string {
  return `<div class="sub-h${cls ? ` ${cls}` : ''}"><span>${title}</span>${right ? `<span class="sub-h-right">${right}</span>` : ''}</div>`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return n === 1 ? one : many;
}

/**
 * Shown when the feature dropdown is active on a page whose numbers are the
 * whole model's (diagrams, attribution). The client fills the feature name
 * and the regenerate command.
 */
export function wholeModelNote(): string {
  return `<div class="whole-model-note filter-status" hidden><span class="filter-status-text">Feature <strong class="wm-feature"></strong> is selected, but this page shows the whole model. For a feature-only view, regenerate with the command.</span><button class="btn" data-copy="guardlink dashboard . --feature">Copy command</button></div>`;
}

/** `…/dir/file.ts` for deep paths; the full path travels in `title` and the copy button. */
export function shortPath(file: string): string {
  const parts = file.split('/');
  return parts.length > 3 ? `…/${parts.slice(-2).join('/')}` : file;
}

/**
 * A compact location cell for fixed-layout tables: the file name and line on
 * one line, its directory in small type beneath, the full path in the title,
 * the sort key and the copy button. The file name is what a reader scans for,
 * so it is the part that never gets cut.
 */
export function locCellShort(file: string | undefined | null, line: number | undefined | null, links: RepoLinks | null): string {
  if (!file) return '<td class="loc" data-v=""></td>';
  const full = line ? `${file}:${line}` : file;
  const slash = file.lastIndexOf('/');
  const base = slash >= 0 ? file.slice(slash + 1) : file;
  const dir = slash >= 0 ? file.slice(0, slash) : '';
  const body = `<span class="loc-file">${esc(line ? `${base}:${line}` : base)}</span>${dir ? `<span class="loc-dir">${esc(dir)}</span>` : ''}`;
  const inner = links
    ? `<a class="loc-link" href="${esc(links.file(file, line ?? undefined))}" target="_blank" rel="noopener" title="${esc(full)} — open on ${hostLabel(links)}">${body}</a>`
    : `<span class="loc-text" title="${esc(full)}">${body}</span>`;
  return `<td class="loc" data-v="${esc(full)}"><div class="loc-cell">${inner}${copyButton(full, 'Copy path')}</div></td>`;
}

/** Column widths for a fixed-layout table. */
export function colgroup(widths: string[]): string {
  return `<colgroup>${widths.map(w => `<col style="width:${w}">`).join('')}</colgroup>`;
}

/** The pager container the client fills for a paginated table. */
export function pager(tableId: string): string {
  return `<div class="pager" data-pager-for="${esc(tableId)}"></div>`;
}

/** `#page?q=a b` with the search encoded the way the client's URLSearchParams reads it. */
export function routeWithQuery(page: string, q: string, extra: Record<string, string> = {}): string {
  const p = new URLSearchParams({ q, ...extra });
  return `#${page}?${p.toString()}`;
}

export interface HeatCell {
  value: number;
  /** 0..1 intensity. */
  h: number;
  tone?: 'red' | 'green' | 'blue' | 'neutral';
  href?: string;
  title?: string;
  label?: string;
}

export interface HeatSpec {
  id?: string;
  rowHead: string;
  rows: string[];
  cols: string[];
  cell: (row: string, col: string) => HeatCell | null;
  rowHref?: (row: string) => string | null;
  colHref?: (col: string) => string | null;
  rowLabel?: (row: string) => string;
  colLabel?: (col: string) => string;
}

/** A heatmap as a table: colour intensity is `--h`, tone is a class, every cell can link into a filtered page. */
export function heatTable(spec: HeatSpec): string {
  const rl = spec.rowLabel ?? ((r: string) => r);
  const cl = spec.colLabel ?? ((c: string) => c);
  const head = `<thead><tr><th class="heat-corner">${esc(spec.rowHead)}</th>${spec.cols.map(c => {
    const href = spec.colHref?.(c);
    return `<th class="heat-col" title="${esc(cl(c))}"><span>${href ? `<a href="${esc(href)}">${esc(cl(c))}</a>` : esc(cl(c))}</span></th>`;
  }).join('')}</tr></thead>`;
  const body = `<tbody>${spec.rows.map(r => {
    const href = spec.rowHref?.(r);
    return `<tr><th class="heat-row" title="${esc(rl(r))}"><span>${href ? `<a href="${esc(href)}">${esc(rl(r))}</a>` : esc(rl(r))}</span></th>${spec.cols.map(c => {
      const cell = spec.cell(r, c);
      if (!cell || cell.value === 0) return '<td class="heat-cell empty"></td>';
      const shown = cell.label ?? String(cell.value);
      return `<td class="heat-cell tone-${cell.tone ?? 'neutral'}" style="--h:${Math.max(0.12, Math.min(1, cell.h)).toFixed(2)}"${cell.title ? ` title="${esc(cell.title)}"` : ''}>${cell.href ? `<a href="${esc(cell.href)}">${esc(shown)}</a>` : esc(shown)}</td>`;
    }).join('')}</tr>`;
  }).join('')}</tbody>`;
  return `<div class="table-wrap heat-wrap"><table class="heat"${spec.id ? ` id="${esc(spec.id)}"` : ''}>${head}${body}</table></div>`;
}

/** A horizontal bar list: label, value, bar scaled to the max. */
export function barList(items: { label: string; value: number; href?: string; tone?: string; hint?: string }[], max?: number): string {
  const top = max ?? Math.max(1, ...items.map(i => i.value));
  return `<div class="bars">${items.map(i => `
  <div class="bar-row">
    <span class="bar-label">${i.href ? `<a href="${esc(i.href)}">${esc(i.label)}</a>` : esc(i.label)}</span>
    <div class="sev-track"><div class="sev-fill ${i.tone ?? 'attr-fill'}" style="width:${Math.round((i.value / top) * 100)}%"></div></div>
    <span class="bar-value">${i.value}${i.hint ? ` <span class="muted">${esc(i.hint)}</span>` : ''}</span>
  </div>`).join('')}</div>`;
}
