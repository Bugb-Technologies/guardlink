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

/** A small copy-to-clipboard button. The script reads `data-copy`. */
export function copyButton(text: string, title = 'Copy'): string {
  return `<button class="copy" data-copy="${esc(text)}" title="${esc(title)}" aria-label="${esc(title)}">⧉</button>`;
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

/** An identity, as a link that narrows the Attribution page to it. */
export function whoLink(identity: string): string {
  return `<a class="who" href="#attribution?who=${encodeURIComponent(identity)}">${esc(identity)}</a>`;
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
