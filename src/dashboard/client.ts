/**
 * GuardLink Dashboard — the page's one client script, as a string.
 *
 * Routing (the URL hash is the page and its filters; the old page names
 * redirect), search, sortable and paginated tables, filter chips, copy, the
 * claim / asset / annotation drawers, the feature filter, the shared tooltip,
 * hover-and-pin on every diagram, the neighbourhood walk, the matrix's filters
 * and compact mode, reports, theme and rail.
 *
 * Every interaction is wired through `data-*` attributes and listeners
 * delegated from `document`; the generated markup carries no inline `on*`
 * handler, so a host's content security policy can admit the page without
 * 'unsafe-inline' for scripts. Navigation is hash links, which a webview host
 * can route.
 *
 * Nothing measures the DOM to lay anything out. The neighbourhood and the
 * matrix are re-drawn by the generator's own self-contained renderers
 * (`layout/hood.ts`, `layout/matrix.ts`, embedded by source before this
 * script); the only geometry read here is the pointer position, and a focused
 * mark's rectangle to anchor the tooltip for keyboard users.
 *
 * Nothing from the model is interpolated into this string at generation time;
 * the page's data arrives through the JSON constants emitted before it, and
 * everything rendered from them goes through the client `esc()` or textContent.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every value the drawers, twins and tooltip render from the embedded data passes through esc() or textContent; URLs are pre-built server-side and attribute-escaped here"
 * @comment -- "No network: the clipboard API with a textarea fallback, history.replaceState for filters, localStorage only for theme and rail state"
 */
import { ACCEPTANCE_REGISTER_NOTE } from '../parser/acceptance.js';
import { HYPOTHESES_FILE } from '../hypothesis/ledger.js';

export const CLIENT_JS = `
/* ===== HELPERS ===== */
function esc(s) { return s == null ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function $(sel, root) { return (root || document).querySelector(sel); }
function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
function sec(label, value) { return '<div class="d-section"><div class="d-label">' + label + '</div><div class="d-value">' + value + '</div></div>'; }
function normSev(s) {
  var l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'critical';
  if (l === 'high' || l === 'p1') return 'high';
  if (l === 'medium' || l === 'p2') return 'medium';
  if (l === 'low' || l === 'p3') return 'low';
  return 'unset';
}
var GLYPH = { open: '○', confirmed: '✕', mitigated: '✓', refuted: '✓', accepted: '—', control: '⊢', verified: '✓', stale: '◐', unverified: '○', review: '◐' };
function sevChip(s) { var k = normSev(s); return '<span class="chip sev-' + k + '"><i class="sw"></i>' + esc(k === 'unset' ? (s || 'unset') : k) + '</span>'; }
function stateChip(st, label) { return '<span class="state st-' + esc(st) + '"><span class="g">' + (GLYPH[st] || '·') + '</span>' + esc(label || st) + '</span>'; }
function _plural(n, one) { return n + ' ' + one + (n === 1 ? '' : 's'); }
/* Severity buckets of a list of exposure rows — the grade counts OPEN ones only. */
function _sevOf(list) {
  var sev = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  list.forEach(function (e) { sev[normSev(e.severity)]++; });
  return sev;
}

/* ===== ROUTER: #page?q=&sev=&status=&state=&who=&file=&tab=&view=&focus=&pin=&cell= ===== */
var PAGES = ['overview', 'exposures', 'diagrams', 'assets', 'code', 'agents', 'reports', 'attribution'];
/* The page names before the seven-page rail. Links in reports and older pages keep working. */
var OLD = { summary: 'overview', analytics: 'exposures', threats: 'exposures', explore: 'diagrams', data: 'diagrams', 'ai-analysis': 'reports' };
var _route = { page: 'overview', params: new URLSearchParams() };
var _lastHash = null;

function redirectOld(page, params) {
  var p = new URLSearchParams(params.toString());
  if (page === 'explore') {
    var view = p.get('view') || '', subject = p.get('subject') || '';
    p.delete('view'); p.delete('subject');
    if (view === 'threat' && subject) return { page: 'exposures', params: new URLSearchParams({ q: subject }) };
    if (view === 'open') return { page: 'exposures', params: new URLSearchParams({ status: 'open' }) };
    if (view === 'diff') return { page: 'exposures', params: new URLSearchParams({ change: 'new' }) };
    p.set('tab', 'flow');
    if ((view === 'asset' || view === 'blast' || view === 'boundary') && subject && view === 'asset') { p.set('view', 'hood'); p.set('focus', subject); }
    return { page: 'diagrams', params: p };
  }
  if (page === 'data') { p.set('tab', 'flow'); return { page: 'diagrams', params: p }; }
  return { page: OLD[page], params: p };
}

function parseHash() {
  var h = location.hash.replace(/^#/, '');
  var i = h.indexOf('?');
  var page = (i >= 0 ? h.slice(0, i) : h) || 'overview';
  var params = new URLSearchParams(i >= 0 ? h.slice(i + 1) : '');
  if (OLD[page]) {
    var r = redirectOld(page, params);
    var qs = r.params.toString();
    try { history.replaceState(null, '', '#' + r.page + (qs ? '?' + qs : '')); } catch (e) { /* sandboxed host */ }
    _lastHash = location.hash;
    page = r.page; params = r.params;
  }
  if (!document.getElementById('sec-' + page)) page = 'overview';
  return { page: page, params: params };
}

function showSection(id) {
  $$('.section-content').forEach(function (s) { s.classList.toggle('active', s.id === 'sec-' + id); });
  $$('.rail a[data-page]').forEach(function (a) {
    var on = a.getAttribute('data-page') === id;
    a.classList.toggle('active', on);
    if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  closeDrawer();
}

function applyRoute() {
  if (location.hash === _lastHash) return;
  _lastHash = location.hash;
  var prev = _route.page;
  var r = parseHash();
  _route = r;
  showSection(r.page);
  syncControls(r.page, r.params);
  filterPage(r.page);
  if (r.page === 'diagrams') applyDiagrams(r.params);
  if (r.page === 'reports') showReport();
  if (prev !== r.page) { var m = $('.main'); if (m) m.scrollTop = 0; window.scrollTo(0, 0); }
}
window.addEventListener('hashchange', applyRoute);
window.addEventListener('popstate', applyRoute);

/* Filter groups that hold one value (the rest are lists). */
var SINGLE = ['who', 'file', 'owner', 'handles', 'change'];

function currentFilters() {
  var p = _route.params;
  var list = function (k) { var v = p.get(k); return v ? v.split(',').filter(Boolean) : []; };
  return { q: (p.get('q') || '').toLowerCase().trim(), sev: list('sev'), status: list('status'), state: list('state'), who: p.get('who') || '', file: p.get('file') || '', owner: p.get('owner') || '', handles: p.get('handles') || '', change: p.get('change') || '', cell: p.get('cell') || '' };
}

function setParam(k, v) {
  var p = new URLSearchParams(_route.params.toString());
  if (v) p.set(k, v); else p.delete(k);
  var qs = p.toString();
  var target = '#' + _route.page + (qs ? '?' + qs : '');
  _route.params = p;
  _lastHash = target;
  try { history.replaceState(null, '', target); } catch (e) { /* sandboxed host */ }
  syncControls(_route.page, p);
  filterPage(_route.page);
  if (_route.page === 'diagrams') applyDiagrams(p);
}

function toggleInList(k, value) {
  var list = currentFilters()[k] || [];
  var i = list.indexOf(value);
  if (i >= 0) list.splice(i, 1); else list.push(value);
  setParam(k, list.join(','));
}

function syncControls(page, params) {
  var f = currentFilters();
  var search = document.getElementById('search');
  if (search && document.activeElement !== search) search.value = params.get('q') || '';
  var sec = document.getElementById('sec-' + page);
  $$('.chip[data-chip]').forEach(function (c) {
    var group = c.getAttribute('data-chip'), value = c.getAttribute('data-value');
    var active;
    if (SINGLE.indexOf(group) >= 0) active = value ? f[group] === value : !f[group];
    else active = value ? (f[group] || []).indexOf(value) >= 0 : !(f[group] || []).length;
    c.classList.toggle('active', !!active);
    c.setAttribute('aria-pressed', active ? 'true' : 'false');
  });
  var who = sec ? $('.who-filter', sec) : null;
  if (who) { who.hidden = !f.who; var name = $('.who-filter-name', who); if (name) name.textContent = f.who === 'ai' ? 'AI-assisted only' : f.who; }
}

/* The claims a pinned matrix cell holds, from the embedded matrix data. */
function cellClaims(cell) {
  var out = {};
  if (!cell || typeof matrixData === 'undefined') return out;
  var ij = cell.split('.');
  matrixData.x.forEach(function (x) { if (String(x[0]) === ij[0] && String(x[1]) === ij[1]) out[x[4]] = 1; });
  return out;
}

function filterPage(page) {
  var f = currentFilters();
  var sec = document.getElementById('sec-' + page);
  if (!sec) return;
  var groups = {};
  var terms = f.q ? f.q.split(' ').filter(Boolean) : [];
  var inCell = f.cell ? cellClaims(f.cell) : null;
  var keep = [];
  $$('[data-search]', sec).forEach(function (el) {
    var ok = true;
    if (terms.length) { var hay = el.getAttribute('data-search'); for (var i = 0; i < terms.length; i++) { if (hay.indexOf(terms[i]) < 0) { ok = false; break; } } }
    if (ok && f.sev.length && el.hasAttribute('data-sev') && f.sev.indexOf(el.getAttribute('data-sev')) < 0) ok = false;
    if (ok && f.status.length && el.hasAttribute('data-status') && f.status.indexOf(el.getAttribute('data-status')) < 0) ok = false;
    if (ok && f.state.length && el.hasAttribute('data-state') && f.state.indexOf(el.getAttribute('data-state')) < 0) ok = false;
    if (ok && f.who && el.hasAttribute('data-who')) {
      ok = el.getAttribute('data-who').split('|').indexOf(f.who) >= 0;
    } else if (ok && f.who && el.hasAttribute('data-sev')) {
      ok = false; // a claim row with no attribution never matches an identity filter
    }
    if (ok && f.file && el.hasAttribute('data-ff') && el.getAttribute('data-ff') !== f.file) ok = false;
    if (ok && f.owner && el.hasAttribute('data-sev')) ok = el.hasAttribute('data-owner') && el.getAttribute('data-owner').split('|').indexOf(f.owner) >= 0;
    if (ok && f.handles && el.hasAttribute('data-sev')) ok = el.hasAttribute('data-handles') && el.getAttribute('data-handles').split('|').indexOf(f.handles) >= 0;
    if (ok && f.change && el.hasAttribute('data-sev')) ok = el.getAttribute('data-change') === f.change;
    if (ok && el.classList.contains('ff-out')) ok = false;
    /* The matrix counts what the table shows before a cell pin narrows it. */
    if (ok && el.hasAttribute('data-claim')) keep.push(parseInt(el.getAttribute('data-claim'), 10));
    if (ok && inCell && el.hasAttribute('data-claim')) ok = !!inCell[el.getAttribute('data-claim')];
    el.classList.toggle('filtered-out', !ok);
    var g = el.getAttribute('data-group') || (el.closest('table') && el.closest('table').id) || (el.closest('[data-list]') && el.closest('[data-list]').getAttribute('data-list'));
    if (g) { groups[g] = groups[g] || { shown: 0, total: 0 }; groups[g].total++; if (ok) groups[g].shown++; }
  });
  $$('[data-count-for]:not(.no-match)', sec).forEach(function (c) {
    var s = groups[c.getAttribute('data-count-for')];
    if (!s) return;
    c.textContent = s.shown === s.total ? String(s.total) : s.shown + ' of ' + s.total;
  });
  $$('.no-match', sec).forEach(function (n) {
    var s = groups[n.getAttribute('data-count-for')];
    n.hidden = !s || s.shown > 0 || s.total === 0;
  });
  $$('table[data-paginate]', sec).forEach(function (t) { t.setAttribute('data-page', '1'); paginate(t); });
  var active = !!(f.q || f.sev.length || f.status.length || f.state.length || f.who || f.file || f.owner || f.handles || f.change || f.cell);
  var bar = $('.filter-status:not(.whole-model-note)', sec);
  if (bar) {
    bar.hidden = !active;
    var parts = [];
    if (f.q) parts.push('search "' + f.q + '"');
    if (f.sev.length) parts.push('severity ' + f.sev.join(', '));
    if (f.status.length) parts.push('status ' + f.status.join(', '));
    if (f.state.length) parts.push('claims ' + f.state.join(', '));
    if (f.who) parts.push(f.who === 'ai' ? 'AI-assisted only' : f.who);
    if (f.file) parts.push(f.file);
    if (f.owner) parts.push('owned by ' + f.owner);
    if (f.handles) parts.push('handles ' + f.handles);
    if (f.change === 'new') parts.push('new since the compared ref');
    if (f.cell) parts.push('pinned cell');
    var txt = $('.filter-status-text', bar); if (txt) txt.textContent = 'Filtered: ' + parts.join(' · ');
  }
  if (page === 'exposures') drawMatrix(keep, f.cell);
}

function clearFilters() {
  var keepKeys = ['tab', 'view', 'focus'];
  var p = new URLSearchParams();
  keepKeys.forEach(function (k) { var v = _route.params.get(k); if (v) p.set(k, v); });
  var qs = p.toString();
  var target = '#' + _route.page + (qs ? '?' + qs : '');
  _route.params = p;
  _lastHash = target;
  try { history.replaceState(null, '', target); } catch (e) { /* sandboxed host */ }
  syncControls(_route.page, _route.params);
  filterPage(_route.page);
}

/* ===== SEARCH ===== */
var _searchTimer = null;
function onSearchInput(el) {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(function () { setParam('q', el.value.trim()); }, 120);
}

/* ===== SORT ===== */
function sortTable(th) {
  var table = th.closest('table'); if (!table) return;
  var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
  var numeric = th.getAttribute('data-type') === 'num';
  var dir = th.classList.contains('sorted-asc') ? 'desc' : 'asc';
  $$('th', table).forEach(function (h) { h.classList.remove('sorted-asc', 'sorted-desc'); h.removeAttribute('aria-sort'); });
  th.classList.add('sorted-' + dir);
  th.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
  var grouped = table.hasAttribute('data-sort-groups');
  /* A grouped table sorts whole tbody groups (a row and its detail row) by the group's first row. */
  var items = grouped ? $$('tbody', table) : $$('tbody > tr', table);
  var rowOf = function (it) { return grouped ? it.rows[0] : it; };
  var key = function (it) {
    var c = rowOf(it).children[idx]; if (!c) return numeric ? -Infinity : '';
    if (numeric) { var v = c.getAttribute('data-v'); var n = v !== null ? parseFloat(v) : parseFloat(c.textContent); return isNaN(n) ? -Infinity : n; }
    var tv = c.getAttribute('data-v');
    return (tv !== null ? tv : c.textContent).trim().toLowerCase();
  };
  items.sort(function (a, b) { var ka = key(a), kb = key(b); var c = ka < kb ? -1 : ka > kb ? 1 : 0; return dir === 'asc' ? c : -c; });
  var parent = grouped ? table : table.tBodies[0];
  items.forEach(function (it) { parent.appendChild(it); });
  if (table.hasAttribute('data-paginate')) { table.setAttribute('data-page', '1'); paginate(table); }
}

/* ===== COPY ===== */
function copyText(text, btn) {
  var done = function () {
    if (btn) { btn.classList.add('copied'); setTimeout(function () { btn.classList.remove('copied'); }, 1200); }
    toast('Copied');
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
  } else { fallbackCopy(text); done(); }
}
function fallbackCopy(text) {
  var ta = document.createElement('textarea');
  ta.value = text; ta.setAttribute('readonly', ''); ta.className = 'offscreen';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); } catch (e) { /* nothing to do */ }
  document.body.removeChild(ta);
}
function toast(msg) {
  var t = document.getElementById('toast'); if (!t) return;
  t.textContent = msg; t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(function () { t.classList.remove('show'); }, 1400);
}

/* ===== CLAIM DRAWER ===== */
var _drawerCtx = null;

function openDrawer(type, idx, rowEl) {
  if (type === 'asset') return renderAssetDrawer(idx);
  var c = claimsData[idx]; if (!c) return;
  var list = [idx];
  if (rowEl) {
    var container = rowEl.closest('table, ul, .twin');
    if (container) list = $$('[data-claim]', container)
      .filter(function (r) { return !r.classList.contains('filtered-out') && !r.classList.contains('ff-out'); })
      .map(function (r) { return parseInt(r.getAttribute('data-claim'), 10); });
  }
  _drawerCtx = { list: list, pos: Math.max(0, list.indexOf(idx)) };
  renderClaimDrawer(c);
}

function drawerNav(step) {
  if (!_drawerCtx) return;
  var pos = _drawerCtx.pos + step;
  if (pos < 0 || pos >= _drawerCtx.list.length) return;
  _drawerCtx.pos = pos;
  renderClaimDrawer(claimsData[_drawerCtx.list[pos]]);
}

function whoHtml(id) { return '<a class="who" href="#attribution?who=' + encodeURIComponent(id) + '">' + esc(id) + '</a>'; }
function aiHtml(list) { return (list || []).map(function (a) { return '<span class="badge badge-blue">' + esc(a) + '</span>'; }).join(' '); }
function refHtml(r) {
  if (!r) return '<span class="muted">—</span>';
  var sha = r.url ? '<a class="sha" href="' + esc(r.url) + '" target="_blank" rel="noopener" title="' + esc(r.sha) + '"><code>' + esc(r.sha.slice(0, 8)) + '</code></a>' : '<code class="sha" title="' + esc(r.sha) + '">' + esc(r.sha.slice(0, 8)) + '</code>';
  return sha + ' <span class="muted">' + esc(r.date) + '</span> ' + whoHtml(r.author) + (r.co.length ? ' <span class="muted">+ ' + r.co.map(whoHtml).join(', ') + '</span>' : '') + (r.ai.length ? ' ' + aiHtml(r.ai) : '');
}

function advice(c) {
  if (c.status === 'confirmed') return '<strong>Immediate action required.</strong> This threat has been verified exploitable. Apply a <code>@mitigates</code> control urgently, or <code>@accepts</code> with explicit risk sign-off from security.';
  if (c.status === 'open') return '<strong>Recommended:</strong> add a <code>@mitigates</code> annotation naming the control that addresses this threat, or <code>@accepts</code> if the risk is intentionally accepted. Then <code>guardlink verify</code> the claim.';
  if (c.status === 'mitigated') return c.state === 'stale' ? '<strong>Stale:</strong> the code beneath this mitigation changed after it was verified. Re-check that the control still holds, then re-lock with <code>guardlink verify --stale</code>.' : 'Mitigated. Keep the control and its claim verified as the code moves.';
  if (c.status === 'accepted') return 'Accepted. ' + ${JSON.stringify(ACCEPTANCE_REGISTER_NOTE)} + ' Revisit the acceptance when the asset or the threat changes.';
  if (c.status === 'refuted') return 'Tested and not exploitable, with the evidence above, recorded in <code>${HYPOTHESES_FILE}</code>. Unlike an acceptance this outcome was measured rather than signed: the claim stays in the source so the risk class is documented, and the outcome expires by itself when the code beneath it changes.';
  return 'A declared control. Verify it so a later edit beneath it is flagged as stale.';
}

/* Status band: coverage status, ledger state, and who locked the claim when. */
function statusBand(c) {
  var by = c.verifiedBy ? '<span class="d-state-by">' + (c.state === 'stale' ? 'locked' : 'by') + ' ' + esc(c.verifiedBy) + (c.verifiedAt ? ' on ' + esc(String(c.verifiedAt).slice(0, 10)) : '') + (c.state === 'stale' ? ', code changed since' : '') + '</span>' : '';
  return '<div class="d-status d-status-' + esc(c.status) + '">' + stateChip(c.status, c.statusLabel)
     + (c.state ? '<span class="claim-state ' + esc(c.state) + '"><span class="g">' + GLYPH[c.state] + '</span>' + esc(c.state) + '</span>' + by : '')
     + (c.change === 'new' ? '<span class="badge badge-blue" title="Added since the compared ref">new</span>' : '') + '</div>';
}
/* The tested state: what happened when this exposure was tried, by whom, and whether the code moved since. */
function hypothesisBand(c) {
  var h = c.hypothesis; if (!h || h.state === 'untested' && !h.previous_outcome) return '';
  var label = h.state === 'refuted' ? 'Tested: not exploitable' : h.state === 'confirmed' ? 'Tested: exploitable' : h.state === 'retest' ? 'Confirmed before — code changed, retest' : 'Untested again — code changed since it was ' + esc(h.previous_outcome);
  var tone = h.state === 'refuted' ? 'refuted' : h.state === 'confirmed' ? 'confirmed' : 'review';
  return '<div class="d-status d-hyp">' + stateChip(tone, label)
    + (h.by ? '<span class="d-state-by">by ' + esc(h.by) + (h.at ? ' on ' + esc(String(h.at).slice(0, 10)) : '') + '</span>' : '') + '</div>'
    + (h.evidence ? sec('Evidence', '<div class="well">' + esc(h.evidence) + '</div>') : '');
}
function blameBlock(c) {
  if (!c.blame) return '';
  return '<div class="d-blame"><div class="d-label">Attribution</div>'
       + '<div class="d-blame-row"><span>Introduced</span><span class="d-ref">' + refHtml(c.blame.introduced) + (c.blame.lowerBound ? ' <span class="badge" title="History is truncated or the file has uncommitted edits: the true introduction may be older">lower bound</span>' : '') + '</span></div>'
       + '<div class="d-blame-row"><span>Declared</span><span class="d-ref">' + refHtml(c.blame.declared) + '</span></div>'
       + (c.verb !== 'mitigates' ? '<div class="d-blame-row"><span>Fixed</span><span class="d-ref">' + (c.blame.fixed ? refHtml(c.blame.fixed) + (c.blame.days !== null ? ' <span class="muted">after ' + c.blame.days + ' days</span>' : '') : stateChip('open')) + '</span></div>' : '')
       + (c.blame.status !== 'ok' ? '<div class="d-blame-row"><span>Status</span><span class="badge">' + esc(c.blame.status) + '</span></div>' : '')
       + '</div>';
}

function openDrawerShell() {
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
  var close = $('#drawer [data-action="drawer-close"]'); if (close) close.focus();
}

function renderClaimDrawer(c) {
  var title = document.getElementById('drawer-title'), body = document.getElementById('drawer-body');
  title.textContent = c.threat + ' · ' + c.asset;
  var h = '';
  h += statusBand(c);
  h += hypothesisBand(c);
  h += '<div class="d-grid">'
     + sec('Severity', sevChip(c.severity))
     + sec('Kind', '<code>' + esc(c.verb) + '</code>')
     + sec('Asset', '<code>' + esc(c.asset) + '</code>')
     + sec('Threat', '<code>' + esc(c.threat) + '</code>')
     + '</div>';
  if (c.description) h += sec('Description', esc(c.description));
  if (c.control) h += sec('Control', '<code>' + esc(c.control) + '</code>');
  if (c.refs && c.refs.length) h += sec('References', c.refs.map(function (r) { return '<code>' + esc(r) + '</code>'; }).join(' '));
  h += sec('Location', (c.url ? '<a class="loc-link" href="' + esc(c.url) + '" target="_blank" rel="noopener">' : '<span class="loc-text">')
     + esc(c.file + ':' + c.line) + (c.url ? '</a>' : '</span>')
     + ' <button class="copy" data-copy="' + esc(c.file + ':' + c.line) + '" title="Copy path" aria-label="Copy path">' + ICONS.copy + '</button>');
  h += blameBlock(c);
  h += '<div class="d-actions">'
     + (c.url ? '<a class="btn primary" href="' + esc(c.url) + '" target="_blank" rel="noopener">' + esc(openOnHost) + '</a>' : '')
     + '<button class="btn" data-copy="guardlink verify ' + esc(c.file + ':' + c.line) + '">Copy verify command</button>'
     + '<button class="btn" data-copy="guardlink blame . --file ' + esc(c.file) + '">Copy blame command</button>'
     + '<a class="btn ghost" href="#diagrams?tab=threat&amp;pin=' + encodeURIComponent(c.akey) + '">On the threat graph</a>'
     + '</div>';
  h += '<div class="d-advice d-advice-' + esc(c.status) + '">' + advice(c) + '</div>';
  h += '<div class="d-nav">'
     + '<button class="btn ghost" data-drawer-nav="prev"' + (_drawerCtx.pos <= 0 ? ' disabled' : '') + '>← Previous</button>'
     + '<span class="d-pos">' + (_drawerCtx.pos + 1) + ' / ' + _drawerCtx.list.length + '</span>'
     + '<button class="btn ghost" data-drawer-nav="next"' + (_drawerCtx.pos >= _drawerCtx.list.length - 1 ? ' disabled' : '') + '>Next →</button>'
     + '</div>';
  body.innerHTML = h;
  openDrawerShell();
}

function closeDrawer() {
  var d = document.getElementById('drawer'); if (!d) return;
  d.classList.remove('open');
  document.getElementById('drawer-overlay').classList.remove('open');
}

/* ===== PAGINATION ===== */
function _pageRows(table) {
  return $$('tbody > tr', table).filter(function (r) { return !r.classList.contains('filtered-out') && !r.classList.contains('ff-out'); });
}
/* Rows outside the current page get .paged-out; the pager under the table is rebuilt. Hidden entirely when everything fits. */
function paginate(table) {
  if (typeof table === 'string') table = document.getElementById(table);
  if (!table) return;
  var base = parseInt(table.getAttribute('data-paginate'), 10) || 25;
  var sel = table.getAttribute('data-page-size');
  var size = sel === 'all' ? Infinity : (parseInt(sel, 10) || base);
  var rows = _pageRows(table);
  var pages = Math.max(1, Math.ceil(rows.length / size));
  var page = Math.min(pages, Math.max(1, parseInt(table.getAttribute('data-page'), 10) || 1));
  table.setAttribute('data-page', String(page));
  var start = (page - 1) * size, end = start + size;
  $$('tbody > tr', table).forEach(function (r) { r.classList.remove('paged-out'); });
  rows.forEach(function (r, i) { if (i < start || i >= end) r.classList.add('paged-out'); });
  renderPager(table, rows.length, page, pages, start, Math.min(end, rows.length), base);
}
function renderPager(table, total, page, pages, start, end, base) {
  var el = $('[data-pager-for="' + table.id + '"]'); if (!el) return;
  if (total <= base) { el.innerHTML = ''; el.hidden = true; return; }
  el.hidden = false;
  var cur = table.getAttribute('data-page-size') || String(base);
  var sizes = [base, base * 2, base * 4, 'all'];
  var h = '<span class="pager-info">' + (total ? (start + 1) + '–' + end : '0') + ' of ' + total + '</span>';
  h += '<span class="pager-ctl">';
  h += '<button class="pager-btn" data-page-go="prev"' + (page <= 1 ? ' disabled' : '') + ' title="Previous page">‹</button>';
  var last = 0;
  for (var p = 1; p <= pages; p++) {
    if (!(p === 1 || p === pages || Math.abs(p - page) <= 2)) continue;
    if (p - last > 1) h += '<span class="pager-gap">…</span>';
    h += '<button class="pager-btn' + (p === page ? ' active' : '') + '" data-page-go="' + p + '"' + (p === page ? ' aria-current="page"' : '') + '>' + p + '</button>';
    last = p;
  }
  h += '<button class="pager-btn" data-page-go="next"' + (page >= pages ? ' disabled' : '') + ' title="Next page">›</button>';
  h += '</span>';
  h += '<label class="pager-size">Rows <select data-page-size>' + sizes.map(function (v) { var s = String(v); return '<option value="' + s + '"' + (s === cur ? ' selected' : '') + '>' + (v === 'all' ? 'All' : v) + '</option>'; }).join('') + '</select></label>';
  el.innerHTML = h;
}
function _pagerTable(el) {
  var pager = el.closest('[data-pager-for]'); if (!pager) return null;
  return document.getElementById(pager.getAttribute('data-pager-for'));
}
function pagerGo(el, action) {
  var table = _pagerTable(el); if (!table) return;
  var page = parseInt(table.getAttribute('data-page'), 10) || 1;
  if (action === 'prev') page--; else if (action === 'next') page++; else page = parseInt(action, 10) || 1;
  table.setAttribute('data-page', String(page));
  paginate(table);
}
function pagerSize(sel) {
  var table = _pagerTable(sel); if (!table) return;
  table.setAttribute('data-page-size', sel.value);
  table.setAttribute('data-page', '1');
  paginate(table);
}

/* ===== ASSET DRAWER ===== */
function _bar(n, max, cls) { return '<div class="bar-track"><i class="bar-fill ' + cls + '" style="width:' + (max > 0 ? Math.round((n / max) * 100) : 0) + '%"></i></div>'; }
/* Everything the model knows about one asset, from the precomputed assetsData; every number links into the filtered Exposures page. */
function renderAssetDrawer(idx) {
  var a = typeof assetsData !== 'undefined' ? assetsData[idx] : null;
  if (!a) return;
  var title = document.getElementById('drawer-title'), body = document.getElementById('drawer-body');
  title.textContent = a.name;
  var q = encodeURIComponent(a.name);
  var open = a.exposures.open + a.exposures.confirmed;
  var h = '';
  h += '<div class="d-status">' + (open > 0 ? stateChip('open', open + ' open of ' + _plural(a.exposures.total, 'exposure')) : a.exposures.total > 0 ? stateChip('mitigated', 'all ' + _plural(a.exposures.total, 'exposure') + ' covered') : stateChip('accepted', 'no exposures declared')) + '</div>';
  h += '<div class="d-grid d-grid-4">'
     + sec('Open', '<a href="#exposures?q=' + q + '&amp;status=open">' + open + '</a>')
     + sec('Mitigated', '<a href="#exposures?q=' + q + '&amp;status=mitigated">' + a.exposures.mitigated + '</a>')
     + sec('Accepted', '<a href="#exposures?q=' + q + '&amp;status=accepted">' + a.exposures.accepted + '</a>')
     + sec('Confirmed', '<a href="#exposures?q=' + q + '&amp;status=confirmed">' + a.exposures.confirmed + '</a>')
     + '</div>';
  var sevs = ['critical', 'high', 'medium', 'low'].filter(function (s) { return a.bySeverity[s] > 0; });
  if (sevs.length) {
    h += sec('Open by severity', sevs.map(function (s) { return '<a href="#exposures?q=' + q + '&amp;sev=' + s + '&amp;status=open">' + sevChip(s).replace('</i>' + s, '</i>' + a.bySeverity[s] + ' ' + s) + '</a>'; }).join(' '));
  }
  if (a.threats.length) {
    var maxT = Math.max.apply(null, a.threats.map(function (t) { return t.total; }));
    h += '<div class="d-section"><div class="d-label">' + _plural(a.threats.length, 'threat') + '</div><div class="d-bars">' + a.threats.map(function (t) {
      return '<a class="d-bar-row" href="#exposures?q=' + encodeURIComponent(a.name + ' ' + t.threat) + '" title="Show these rows"><span class="d-bar-label"><code>' + esc(t.threat) + '</code></span>' + _bar(t.total, maxT, t.open > 0 ? 'b-open' : 'b-res') + '<span class="d-bar-value">' + (t.open > 0 ? '<b>' + t.open + ' open</b> / ' : '') + t.total + '</span></a>';
    }).join('') + '</div></div>';
  }
  if (a.controls.length) {
    h += sec(_plural(a.controls.length, 'control'), a.controls.map(function (c) { return '<a class="pill" href="#exposures?q=' + encodeURIComponent(a.name + ' ' + c.control) + '"><code>' + esc(c.control) + '</code><span class="muted">×' + c.count + '</span></a>'; }).join(' '));
  } else if (a.exposures.total > 0) {
    h += sec('Controls', '<span class="muted">None declared — nothing here is covered by a <code>@mitigates</code>.</span>');
  }
  if (a.flowsIn.length || a.flowsOut.length) {
    h += '<div class="d-section"><div class="d-label">' + _plural(a.flowsIn.length + a.flowsOut.length, 'data flow') + '</div><div class="d-value d-flows">'
       + a.flowsIn.map(function (f) { return '<div><code>' + esc(f.from) + '</code> <span class="muted">→</span> <b>' + esc(a.name) + '</b>' + (f.via ? ' <span class="muted">via ' + esc(f.via) + '</span>' : '') + '</div>'; }).join('')
       + a.flowsOut.map(function (f) { return '<div><b>' + esc(a.name) + '</b> <span class="muted">→</span> <code>' + esc(f.to) + '</code>' + (f.via ? ' <span class="muted">via ' + esc(f.via) + '</span>' : '') + '</div>'; }).join('')
       + '</div></div>';
  }
  if (a.reach) {
    var rp = [];
    a.reach.capabilities.forEach(function (c) { rp.push('<div><code>' + esc(c.actor) + '</code>' + (c.agent ? ' <span class="reach-kind agent">AI agent</span>' : '') + ' <span class="muted">can</span> <span class="reach-chip reach-cap ' + (c.entitled ? 'ok' : 'bad') + '" title="' + (c.entitled ? 'Entitled' : 'No cited @entitles covers it') + '"><span class="g">' + (c.entitled ? '✓' : '✕') + '</span>' + esc(c.capability) + '</span></div>'); });
    a.reach.effects.forEach(function (e) {
      var st = e.gated === null ? 'read' : e.gated ? 'gated' : 'ungated';
      rp.push('<div>' + (e.actor ? '<code>' + esc(e.actor) + '</code>' : '<span class="muted">code not tied to a reach</span>') + ' <span class="muted">does</span> <span class="reach-chip reach-eff ' + st + '">' + (st === 'ungated' ? '<i class="sw"></i>' : st === 'gated' ? '⊢ ' : '') + esc(e.effect) + (e.gated === false ? ' · no gate' : e.gated ? ' · gated by ' + esc(e.approvers.join(', ')) : '') + '</span>' + (e.via.length ? ' <span class="muted">via ' + esc(e.via.join(', ')) + '</span>' : '') + '</div>');
    });
    a.reach.gates.forEach(function (g) { rp.push('<div><code>' + esc(g.approver) + '</code> <span class="muted">approves first' + (g.capability ? ' for</span> <code>' + esc(g.capability) + '</code>' : '</span>') + '</div>'); });
    h += '<div class="d-section"><div class="d-label">Reach</div><div class="d-value d-reach">' + rp.join('') + '</div><div class="d-value"><a href="#agents">Open Agents &amp; reach</a></div></div>';
  }
  var facts = [];
  if (a.dataHandling.length) facts.push(sec('Handles', a.dataHandling.map(function (d) { return '<span class="tag">' + esc(d) + '</span>'; }).join(' ')));
  if (a.boundaries.length) facts.push(sec('Trust boundaries with', a.boundaries.map(function (b) { return '<code>' + esc(b) + '</code>'; }).join(' ')));
  if (a.owners.length) facts.push(sec('Owner', a.owners.map(function (o) { return '<code>' + esc(o) + '</code>'; }).join(' ')));
  var life = [];
  if (a.audits) life.push(_plural(a.audits, 'audit'));
  if (a.assumptions) life.push(_plural(a.assumptions, 'assumption'));
  if (a.validations) life.push(_plural(a.validations, 'validation'));
  if (life.length) facts.push(sec('Lifecycle', life.join(' · ')));
  if (a.states) facts.push(sec('Claims', ['verified', 'stale', 'unverified'].map(function (k) { return '<span class="claim-state ' + k + '"><span class="g">' + GLYPH[k] + '</span>' + a.states[k] + ' ' + k + '</span>'; }).join(' ')));
  if (facts.length) h += '<div class="d-grid">' + facts.join('') + '</div>';
  if (a.attribution) {
    var at = a.attribution;
    h += '<div class="d-blame"><div class="d-label">Attribution</div>'
       + '<div class="d-blame-row"><span>Introduced by</span><span>' + (at.introducers.length ? at.introducers.map(function (p) { return whoHtml(p.identity) + ' <span class="muted">×' + p.count + '</span>'; }).join(', ') : '<span class="muted">—</span>') + '</span></div>'
       + '<div class="d-blame-row"><span>AI-assisted</span><span>' + at.ai + ' of ' + a.exposures.total + (at.aiTools.length ? ' ' + aiHtml(at.aiTools) : '') + '</span></div>'
       + (at.oldestOpenDays !== null ? '<div class="d-blame-row"><span>Oldest open</span><span>' + at.oldestOpenDays + ' days</span></div>' : '')
       + '</div>';
  }
  if (a.files.length) {
    h += '<div class="d-section"><div class="d-label">' + _plural(a.files.length, 'file') + '</div><div class="d-value d-files">' + a.files.slice(0, 8).map(function (f) {
      return '<div><a class="loc-text" href="#exposures?file=' + encodeURIComponent(f.file) + '" title="Show the rows in this file">' + esc(f.file) + '</a> <span class="muted">' + f.claims + '</span><button class="copy" data-copy="' + esc(f.file) + '" title="Copy path" aria-label="Copy path">' + ICONS.copy + '</button></div>';
    }).join('') + (a.files.length > 8 ? '<div class="muted">+ ' + (a.files.length - 8) + ' more</div>' : '') + '</div></div>';
  }
  h += '<div class="d-actions">'
     + '<a class="btn primary" href="#exposures?q=' + q + (open > 0 ? '&amp;status=open' : '') + '">' + (open > 0 ? 'Show ' + open + ' open' : 'Show exposures') + '</a>'
     + '<a class="btn" href="#diagrams?tab=threat&amp;pin=' + q + '">On the threat graph</a>'
     + '<button class="btn ghost" data-copy="guardlink_lookup(&quot;asset ' + esc(a.name) + '&quot;)">Copy lookup</button>'
     + '</div>';
  body.innerHTML = h;
  _drawerCtx = null;
  openDrawerShell();
}

/* ===== ANNOTATION DRAWER ===== */
var FIELD_ORDER = ['asset', 'threat', 'control', 'severity', 'source', 'target', 'mechanism', 'classification', 'owner', 'actor', 'capability', 'asset_a', 'asset_b', 'reason', 'justification', 'path', 'id', 'name'];
var FIELD_LABEL = { asset_a: 'Side A', asset_b: 'Side B', id: 'Id', path: 'Path' };
/* Everything one annotation carries: its fields, the claim it makes (status, ledger state, attribution), the asset it is about, its raw text and the code around it. */
function openAnnotationDrawer(fileIdx, annIdx) {
  var f = typeof fileAnnotations !== 'undefined' ? fileAnnotations[fileIdx] : null; if (!f) return;
  var a = f.annotations[annIdx]; if (!a) return;
  var title = document.getElementById('drawer-title'), body = document.getElementById('drawer-body');
  var c = a.claimIdx !== null && a.claimIdx !== undefined && typeof claimsData !== 'undefined' ? claimsData[a.claimIdx] : null;
  var tile = a.assetIdx !== null && a.assetIdx !== undefined && typeof assetsData !== 'undefined' ? assetsData[a.assetIdx] : null;
  title.textContent = '@' + a.kind + ' · ' + a.summary;
  var h = '';
  h += '<div class="d-kind"><span class="ann-badge ann-' + esc(a.kind) + '">' + esc(a.kind) + '</span><span class="d-kind-summary">' + esc(a.summary) + '</span></div>';
  if (c) h += statusBand(c);
  var fields = a.fields || {};
  var keys = FIELD_ORDER.filter(function (k) { return fields[k]; });
  if (keys.length || (a.refs && a.refs.length)) {
    h += '<div class="d-fields">' + keys.map(function (k) {
      var label = FIELD_LABEL[k] || (k.charAt(0).toUpperCase() + k.slice(1));
      var v = k === 'severity' ? sevChip(fields[k])
        : k === 'asset' || k === 'threat' || k === 'control' || k === 'source' || k === 'target' || k === 'asset_a' || k === 'asset_b' || k === 'id' || k === 'path'
          ? '<a class="pill" href="#exposures?q=' + encodeURIComponent(fields[k]) + '" title="Show rows naming this"><code>' + esc(fields[k]) + '</code></a>'
          : esc(fields[k]);
      return sec(label, v);
    }).join('') + (a.refs && a.refs.length ? sec('References', a.refs.map(function (r) { return '<code>' + esc(r) + '</code>'; }).join(' ')) : '') + '</div>';
  }
  if (a.description) h += sec('Description', esc(a.description));
  if (c) h += blameBlock(c);
  if (tile) {
    var open = tile.exposures.open + tile.exposures.confirmed;
    h += sec('Asset', (open > 0 ? stateChip('open', open + ' open') : stateChip('mitigated', 'none open')) + ' <span class="muted">' + open + ' open of ' + tile.exposures.total + ' exposures · ' + tile.controls.length + ' controls · ' + (tile.flowsIn.length + tile.flowsOut.length) + ' flows</span>');
  }
  var loc = f.file + ':' + a.line;
  h += sec('Location', (a.url ? '<a class="loc-link" href="' + esc(a.url) + '" target="_blank" rel="noopener">' : '<span class="loc-text">') + esc(loc) + (a.url ? '</a>' : '</span>') + ' <button class="copy" data-copy="' + esc(loc) + '" title="Copy path" aria-label="Copy path">' + ICONS.copy + '</button>');
  if (a.raw) h += '<div class="d-section d-raw"><div class="d-label">Annotation</div><div class="d-code">' + esc(a.raw) + '</div><button class="copy" data-copy="' + esc(a.raw) + '" title="Copy annotation" aria-label="Copy annotation">' + ICONS.copy + '</button></div>';
  if (a.codeContext && a.codeContext.length) {
    h += '<div class="d-section"><div class="d-label">Code</div><div class="d-code-ctx">' + a.codeContext.map(function (line, i) { return '<span' + (i === a.annLineIdx ? ' class="hl"' : '') + '>' + esc(line) + '</span>'; }).join('') + '</div></div>';
  }
  var q = fields.asset && fields.threat ? fields.asset + ' ' + fields.threat : fields.asset || fields.control || fields.source || fields.path || '';
  h += '<div class="d-actions">'
     + (c ? '<a class="btn primary" href="#exposures?q=' + encodeURIComponent(q) + '">Open in Exposures</a>' : q ? '<a class="btn primary" href="#exposures?q=' + encodeURIComponent(q) + '">Related exposures</a>' : '')
     + (tile ? '<button class="btn" data-asset-drawer="' + a.assetIdx + '">Asset details</button>' : '')
     + (a.url ? '<a class="btn" href="' + esc(a.url) + '" target="_blank" rel="noopener">' + esc(openOnHost) + '</a>' : '')
     + (c ? '<button class="btn ghost" data-copy="guardlink verify ' + esc(loc) + '">Copy verify command</button>' : '')
     + '</div>';
  body.innerHTML = h;
  _drawerCtx = null;
  openDrawerShell();
}

/* ===== FEATURE FILTER =====
   The dropdown narrows to the files tagged with one @feature: rows and cards
   outside them are hidden, the per-feature Overview numbers and Exposures
   breakdowns (computed at generation time) are swapped in, and the pages whose
   pictures are the whole model say so. */
var _activeFeature = '';
function _featureFiles(name) {
  var files = {};
  if (name && threatModel.features) threatModel.features.forEach(function (f) { if (f.feature.toLowerCase() === name.toLowerCase()) files[f.location.file] = 1; });
  return files;
}
function applyFeatureFilter(name) {
  _activeFeature = name || '';
  var files = _featureFiles(_activeFeature);
  var on = !!_activeFeature;
  var banner = document.getElementById('feature-banner');
  if (banner) {
    banner.hidden = !on;
    var bn = document.getElementById('feature-banner-name'); if (bn) bn.textContent = _activeFeature;
    var bf = document.getElementById('feature-banner-files'); if (bf) bf.textContent = Object.keys(files).length + ' file(s)';
  }
  $$('[data-ff]').forEach(function (el) { var f = el.getAttribute('data-ff'); el.classList.toggle('ff-out', on && !!f && !files[f]); });
  var assets = {};
  if (on) {
    exposuresData.forEach(function (e) { if (files[e.file]) assets[e.asset] = 1; });
    (threatModel.flows || []).forEach(function (f) { if (f.location && files[f.location.file]) { assets[f.source] = 1; assets[f.target] = 1; } });
    (threatModel.mitigations || []).forEach(function (m) { if (m.location && files[m.location.file]) assets[m.asset] = 1; });
  }
  $$('[data-ff-asset]').forEach(function (el) { el.classList.toggle('ff-out', on && !el.getAttribute('data-ff-asset').split('|').some(function (n) { return assets[n]; })); });
  $$('[data-feature]').forEach(function (b) { if (b.tagName !== 'OPTION') b.hidden = b.getAttribute('data-feature') !== _activeFeature; });
  $$('.whole-model-note').forEach(function (n) {
    n.hidden = !on;
    var f = $('.wm-feature', n); if (f) f.textContent = _activeFeature;
    var c = $('[data-copy]', n); if (c) c.setAttribute('data-copy', 'guardlink dashboard . --feature "' + _activeFeature + '"');
  });
  var vis = exposuresData.filter(function (e) { return !on || files[e.file]; });
  var open = vis.filter(function (e) { return !e.mitigated && !e.accepted && !e.refuted; }).length;
  var mit = vis.filter(function (e) { return e.mitigated; }).length;
  var pct = vis.length ? Math.round((mit / vis.length) * 100) : 0;
  $$('.tn-stat').forEach(function (s) {
    var k = $('.tn-k', s), v = $('.tn-v', s); if (!k || !v) return;
    var lbl = k.textContent.trim();
    if (lbl === 'Open') v.textContent = open;
    if (lbl === 'Coverage' || lbl === 'Mitigated') v.textContent = pct + '%';
  });
  $$('.stat-card').forEach(function (card) {
    var l = $('.label', card), v = $('.value', card); if (!l || !v) return;
    if (l.textContent.trim() === 'Open Threats') v.textContent = open;
    if (l.textContent.trim() === 'Mitigated') v.textContent = mit;
  });
  $$('table[data-paginate]').forEach(function (tb) { tb.setAttribute('data-page', '1'); paginate(tb); });
  filterPage(_route.page);
}

/* ===== TOOLTIP: one shared readout for every mark ===== */
var _tipEl = null;
function tipShow(el, x, y) {
  var t = _tipEl || (_tipEl = document.getElementById('tip')); if (!t) return;
  t.replaceChildren();
  var h = document.createElement('div'); h.className = 'tt'; h.textContent = el.getAttribute('data-tip'); t.appendChild(h);
  var rows = el.getAttribute('data-tip-rows');
  if (rows) rows.split('\\n').forEach(function (line) {
    var i = line.indexOf('\\t');
    var r = document.createElement('div'); r.className = 'tr';
    var k = document.createElement('span'); k.textContent = i >= 0 ? line.slice(0, i) : '';
    var v = document.createElement('b'); v.textContent = i >= 0 ? line.slice(i + 1) : line;
    r.appendChild(k); r.appendChild(v); t.appendChild(r);
  });
  t.hidden = false;
  tipMove(x, y);
}
/* The tooltip flips by quadrant with a transform, so it never has to measure itself. */
function tipMove(x, y) {
  var t = _tipEl; if (!t || t.hidden) return;
  var left = x > window.innerWidth / 2, up = y > window.innerHeight / 2;
  t.style.left = (left ? x - 14 : x + 14) + 'px';
  t.style.top = (up ? y - 14 : y + 14) + 'px';
  t.style.transform = 'translate(' + (left ? '-100%' : '0') + ',' + (up ? '-100%' : '0') + ')';
}
function tipHide() { if (_tipEl) _tipEl.hidden = true; }
/* Keyboard focus has no pointer: anchor the readout to the mark's on-screen box. Positioning only — nothing is laid out from it. */
function tipAt(el) { var r = el.getBoundingClientRect(); tipShow(el, r.right, r.top); }

/* ===== PLOTS: hover lights, click pins, CSS dims =====
   A node lists the keys it lights (data-lights); a thread lists the keys it
   belongs to (data-k). Lighting toggles .lit and the plot's .hl class; the
   stylesheet dims everything unlit. */
var _pins = {};
function plotOf(el) { return el.closest('[data-plot]'); }
function light(plot, keys) {
  if (!plot) return;
  var set = {};
  (keys || []).forEach(function (k) { set[k] = 1; });
  plot.classList.toggle('hl', !!keys);
  $$('[data-k]', plot).forEach(function (t) {
    var lit = !!keys && t.getAttribute('data-k').split(' ').some(function (k) { return set[k]; });
    t.classList.toggle('lit', lit);
  });
}
function restore(plot) {
  if (!plot) return;
  var pin = plot.querySelector('.nd.pin');
  light(plot, pin && pin.getAttribute('data-lights') ? pin.getAttribute('data-lights').split(' ') : null);
}
function nodeEl(plot, id) {
  if (!plot || !id) return null;
  return plot.querySelector('[data-node="' + CSS.escape(id) + '"]') || plot.querySelector('.nd[data-key="' + CSS.escape(id) + '"]');
}
function setPin(name, plot, node) {
  if (plot) $$('.nd.pin', plot).forEach(function (n) { n.classList.remove('pin'); });
  var nodes = node && plot ? $$('[data-node="' + CSS.escape(node.getAttribute('data-node')) + '"]', plot) : [];
  nodes.forEach(function (n) { n.classList.add('pin'); });
  _pins[name] = node ? node.getAttribute('data-node') : null;
  if (plot) restore(plot);
  var bar = $('[data-pin-bar="' + name + '"]'), twin = $('[data-twin="' + name + '"]');
  if (bar) {
    bar.hidden = !node;
    if (node) { $('[data-pin-label]', bar).textContent = node.getAttribute('data-name') || node.getAttribute('data-tip') || ''; }
  }
  if (twin) {
    var claims = node && node.getAttribute('data-claims') ? node.getAttribute('data-claims').split(' ').filter(Boolean).map(Number) : [];
    twin.hidden = !node;
    if (node) {
      var cnt = bar ? $('[data-pin-count]', bar) : null; if (cnt) cnt.textContent = _plural(claims.length, 'exposure');
      twin.innerHTML = claims.length ? twinTable(claims) : '<p class="empty-state">Nothing declared here.</p>';
    }
  }
}
var STATE_RANK = { confirmed: 0, open: 1, accepted: 2, refuted: 3, mitigated: 4, control: 5 };
var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, unset: 4 };
/* The table twin of a pinned mark: its claims as rows, worst first. Rows open the claim drawer. */
function twinTable(idxs) {
  var rows = idxs.map(function (i) { return claimsData[i]; }).filter(Boolean).sort(function (a, b) {
    return (STATE_RANK[a.status] - STATE_RANK[b.status]) || (SEV_RANK[normSev(a.severity)] - SEV_RANK[normSev(b.severity)]) || (a.idx - b.idx);
  });
  return '<div class="table-wrap"><table class="tbl twin-table"><thead><tr><th>Severity</th><th>Asset → threat</th><th>Why</th><th>Where</th><th>State</th></tr></thead><tbody>'
    + rows.map(function (c) {
      return '<tr class="clickable" data-claim="' + c.idx + '"><td>' + sevChip(c.severity) + '</td><td class="mono"><code>' + esc(c.asset) + '</code> → <code>' + esc(c.threat) + '</code></td><td class="desc">' + esc(c.description || '—') + '</td><td class="loc mono"><bdi>' + esc(c.file + ':' + c.line) + '</bdi></td><td>' + stateChip(c.status) + '</td></tr>';
    }).join('') + '</tbody></table></div>';
}

/* ===== DIAGRAMS: tabs, the data-flow views, the neighbourhood walk ===== */
var _hoodFocus = null, _detailFocus = null, _trail = [], _walking = false;
function nodeIndex(key) {
  if (typeof hoodData === 'undefined' || !key) return -1;
  for (var i = 0; i < hoodData.nodes.length; i++) if (hoodData.nodes[i].k === key) return i;
  return -1;
}
function applyDiagrams(p) {
  var sec = document.getElementById('sec-diagrams'); if (!sec) return;
  var tab = p.get('tab') || 'threat';
  if (!$('[data-tab-panel="' + CSS.escape(tab) + '"]', sec)) tab = 'threat';
  $$('[data-tab-panel]', sec).forEach(function (el) { el.hidden = el.getAttribute('data-tab-panel') !== tab; });
  $$('.tabs [data-tab]', sec).forEach(function (a) {
    var on = a.getAttribute('data-tab') === tab;
    a.classList.toggle('active', on); a.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  if (tab === 'threat') {
    var plot = $('[data-plot="threat"]', sec);
    var pin = p.get('pin');
    setPin('threat', plot, pin ? nodeEl(plot, pin) : null);
  }
  if (tab === 'flow' && typeof hoodData !== 'undefined') {
    var view = p.get('view') === 'hood' ? 'hood' : 'ribbons';
    $$('[data-view-panel]', sec).forEach(function (el) { el.hidden = el.getAttribute('data-view-panel') !== view; });
    $$('[data-view-btn]', sec).forEach(function (b) {
      var on = b.getAttribute('data-view-btn') === view;
      b.classList.toggle('active', on); b.setAttribute('aria-pressed', on ? 'true' : 'false');
      var q = new URLSearchParams(p.toString()); q.set('view', b.getAttribute('data-view-btn')); q.delete('q');
      b.setAttribute('href', '#diagrams?' + q.toString());
    });
    var focus = nodeIndex(p.get('focus'));
    if (focus < 0) focus = hoodData.initial;
    if (view === 'hood' && focus !== _hoodFocus) {
      /* A walk (a card click) extends the trail; a crumb goes back along it; any other way of picking a focus starts afresh. */
      var at = _trail.indexOf(focus);
      if (at >= 0) _trail = _trail.slice(0, at);
      else if (_walking && _hoodFocus !== null) { _trail.push(_hoodFocus); if (_trail.length > 6) _trail.shift(); }
      else _trail = [];
      _walking = false;
      _hoodFocus = focus;
      var r = renderHoodSvg(hoodData, focus);
      var host = $('[data-hood-host]', sec); if (host) host.innerHTML = r.svg;
      var foot = $('[data-hood-footer]', sec);
      if (foot) foot.firstElementChild.textContent = r.drawn + ' flows drawn among ' + _plural(r.nodes, 'node') + ' (budget: 7 per column)';
      var trail = $('[data-hood-trail]', sec);
      if (trail) {
        trail.innerHTML = '<span class="eyebrow">Focus</span> ' + _trail.map(function (i) {
          return '<a class="crumb mono" href="#diagrams?tab=flow&amp;view=hood&amp;focus=' + encodeURIComponent(hoodData.nodes[i].k) + '">' + esc(hoodData.nodes[i].l) + '</a><span class="subtle">›</span>';
        }).join('') + ' <b class="mono">' + esc(hoodData.nodes[focus].l) + '</b>';
      }
    }
    if (focus !== _detailFocus || view !== _detailView) {
      _detailFocus = focus; _detailView = view;
      var d = $('[data-node-detail]', sec); if (d) d.innerHTML = renderNodeDetail(hoodData, focus, view);
    }
    var sel = $('[data-focus-select]', sec); if (sel && sel.value !== hoodData.nodes[focus].k) sel.value = hoodData.nodes[focus].k;
    var rib = $('[data-plot="ribbons"]', sec);
    if (rib) setPin('ribbons', rib, p.get('focus') ? nodeEl(rib, 'n' + focus) : null);
  }
}
var _detailView = 'ribbons';

/* ===== EXPOSURES: the matrix follows the table's filters ===== */
var _compact = true, _matrixKey = '';
function drawMatrix(keep, cell) {
  if (typeof matrixData === 'undefined') return;
  var host = document.getElementById('matrix-host'); if (!host) return;
  keep = keep.slice().sort(function (a, b) { return a - b; });
  var key = (_compact ? 'c' : 'f') + '|' + (cell || '') + '|' + keep.join(',');
  if (key === _matrixKey) return;
  _matrixKey = key;
  var r = renderMatrix(matrixData, { st: [], sv: [], keep: keep }, _compact, cell || '');
  host.innerHTML = r.svg;
  var foot = document.getElementById('matrix-footer');
  if (foot) {
    foot.children[0].innerHTML = '<b class="num">' + r.exposures + '</b> exposures in <b class="num">' + r.cells + '</b> cells';
    foot.children[1].textContent = _compact ? r.foldedRows + ' assets and ' + r.foldedCols + ' threats with nothing in this filter are folded — untick to see the complete grid' : 'complete grid: every asset against every threat';
  }
  var pinBar = document.getElementById('matrix-pin');
  if (pinBar) {
    var n = cell ? host.querySelector('[data-cell="' + CSS.escape(cell) + '"]') : null;
    pinBar.hidden = !cell;
    var lbl = $('[data-pin-label]', pinBar); if (lbl) lbl.textContent = n ? n.getAttribute('data-tip') : (cell ? 'a cell outside this filter' : '');
  }
}

/* ===== REPORTS ===== */
function _reportIdx() { var s = document.getElementById('report-selector'); var i = s ? parseInt(s.value, 10) : 0; return isNaN(i) ? 0 : i; }
function _currentReport() { var list = typeof savedAnalyses !== 'undefined' && Array.isArray(savedAnalyses) ? savedAnalyses : []; return list[_reportIdx()] || null; }
function showReport() {
  var i = _reportIdx();
  $$('[data-report]').forEach(function (a) {
    var on = a.getAttribute('data-report') === String(i);
    a.hidden = !on;
    if (on && !a.hasAttribute('data-linked')) { linkifyIds(a); a.setAttribute('data-linked', '1'); }
  });
}
function copyReport(btn) { var r = _currentReport(); if (!r || !r.content) { toast('No report to copy'); return; } copyText(r.content, btn); }
function downloadReport() {
  var r = _currentReport();
  if (!r || !r.content) { toast('No report to download'); return; }
  var name = ((r.framework || r.label || 'threat-report') + '-' + (r.timestamp || '')).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/-+$/, '') + '.md';
  var url = URL.createObjectURL(new Blob([r.content], { type: 'text/markdown' }));
  var a = document.createElement('a'); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  toast('Downloading ' + name);
}
/* The model's ids in a report, as links into the Exposures table. */
function linkifyIds(container) {
  if (!container || typeof threatModel === 'undefined') return;
  var ids = {};
  (threatModel.assets || []).forEach(function (a) { if (a.id) ids['#' + String(a.id).toLowerCase()] = 1; });
  (threatModel.threats || []).forEach(function (t) { if (t.id) ids['#' + String(t.id).toLowerCase()] = 1; });
  (threatModel.controls || []).forEach(function (c) { if (c.id) ids['#' + String(c.id).toLowerCase()] = 1; });
  var walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null);
  var nodes = [], n;
  while ((n = walker.nextNode())) { if (n.nodeValue.indexOf('#') >= 0 && !(n.parentNode && n.parentNode.closest && n.parentNode.closest('a, pre'))) nodes.push(n); }
  nodes.forEach(function (tn) {
    var txt = tn.nodeValue, re = /#[A-Za-z0-9][A-Za-z0-9_-]*/g, last = 0, m, any = false;
    var frag = document.createDocumentFragment();
    while ((m = re.exec(txt))) {
      if (!ids[m[0].toLowerCase()]) continue;
      any = true;
      frag.appendChild(document.createTextNode(txt.slice(last, m.index)));
      var a = document.createElement('a'); a.href = '#exposures?q=' + encodeURIComponent(m[0]); a.className = 'id-link'; a.title = 'Show rows naming ' + m[0]; a.textContent = m[0];
      frag.appendChild(a);
      last = m.index + m[0].length;
    }
    if (!any) return;
    frag.appendChild(document.createTextNode(txt.slice(last)));
    tn.parentNode.replaceChild(frag, tn);
  });
}

/* ===== THEME & RAIL ===== */
function currentTheme() {
  var t = document.documentElement.getAttribute('data-theme');
  if (t === 'light' || t === 'dark') return t;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}
function toggleTheme() {
  var next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('guardlink-theme', next); } catch (e) { /* private mode */ }
}
function toggleRail() {
  var rail = document.getElementById('sidebar');
  rail.classList.toggle('collapsed');
  try { localStorage.setItem('guardlink-rail', rail.classList.contains('collapsed') ? '1' : ''); } catch (e) { /* private mode */ }
}

/* ===== EVENTS: every listener delegated from document ===== */
function activate(e, el) {
  /* A click inside a link or button belongs to that control, not to the row or card around it. */
  var inner = e.target.closest('a, button, select, input, label');
  return !inner || inner === el;
}
document.addEventListener('click', function (e) {
  var t = e.target;
  var act = t.closest('[data-action]');
  if (act && act.tagName === 'BUTTON') {
    var a = act.getAttribute('data-action');
    if (a === 'theme') { toggleTheme(); return; }
    if (a === 'rail') { toggleRail(); return; }
    if (a === 'drawer-close') { closeDrawer(); return; }
    if (a === 'feature-clear') { var ff = document.getElementById('featureFilter'); if (ff) ff.value = ''; applyFeatureFilter(''); return; }
  }
  if (t.closest('#drawer-overlay')) { closeDrawer(); return; }
  var th = t.closest('th[data-sort]');
  if (th) { sortTable(th); return; }
  var chip = t.closest('.chip[data-chip]');
  if (chip) {
    var group = chip.getAttribute('data-chip'), value = chip.getAttribute('data-value');
    if (!value) setParam(group, '');
    else if (SINGLE.indexOf(group) >= 0) setParam(group, currentFilters()[group] === value ? '' : value);
    else toggleInList(group, value);
    return;
  }
  if (t.closest('[data-clear-filters]')) { clearFilters(); return; }
  var cp = t.closest('[data-copy]');
  if (cp) { e.preventDefault(); e.stopPropagation(); copyText(cp.getAttribute('data-copy'), cp); return; }
  var pg = t.closest('[data-page-go]');
  if (pg) { if (!pg.disabled) pagerGo(pg, pg.getAttribute('data-page-go')); return; }
  if (t.closest('[data-copy-report]')) { copyReport(t.closest('[data-copy-report]')); return; }
  if (t.closest('[data-download-report]')) { downloadReport(); return; }
  var ad = t.closest('[data-asset-drawer]');
  if (ad) { renderAssetDrawer(parseInt(ad.getAttribute('data-asset-drawer'), 10)); return; }
  var nav = t.closest('[data-drawer-nav]');
  if (nav) { drawerNav(nav.getAttribute('data-drawer-nav') === 'next' ? 1 : -1); return; }
  var unpin = t.closest('[data-unpin]');
  if (unpin) {
    var which = unpin.getAttribute('data-unpin');
    if (which === 'matrix') setParam('cell', '');
    else if (which === 'threat') setParam('pin', '');
    else setPin(which, $('[data-plot="' + which + '"]') || $('#sec-diagrams'), null);
    return;
  }
  var jump = t.closest('[data-jump]');
  if (jump) { e.preventDefault(); var target = document.getElementById(jump.getAttribute('data-jump')); if (target) target.scrollIntoView({ block: 'start' }); return; }
  var tf = t.closest('[data-toggle-file]');
  if (tf && activate(e, tf)) { var open = tf.classList.toggle('open'); tf.setAttribute('aria-expanded', open ? 'true' : 'false'); if (tf.nextElementSibling) tf.nextElementSibling.classList.toggle('open', open); return; }
  var ann = t.closest('[data-annotation]');
  if (ann && activate(e, ann)) { var p = ann.getAttribute('data-annotation').split(':'); openAnnotationDrawer(parseInt(p[0], 10), parseInt(p[1], 10)); return; }
  var ex = t.closest('[data-expand]');
  if (ex && activate(e, ex)) { var det = ex.nextElementSibling; if (det) { det.hidden = !det.hidden; ex.classList.toggle('expanded', !det.hidden); } return; }
  /* Diagrams: walk the neighbourhood, pin a node, pin a matrix cell, pin a shelf card. */
  var walk = t.closest('[data-hood-walk]');
  if (walk) { var k = walk.getAttribute('data-key'); _walking = true; location.hash = '#diagrams?tab=flow&view=hood&focus=' + encodeURIComponent(k); return; }
  var cell = t.closest('[data-cell]');
  if (cell) { var c = cell.getAttribute('data-cell'); setParam('cell', currentFilters().cell === c ? '' : c); return; }
  var node = t.closest('.nd[data-node]');
  if (node && activate(e, node)) { pinNode(node); return; }
  var row = t.closest('[data-claim]');
  if (row && activate(e, row)) { openDrawer('claim', parseInt(row.getAttribute('data-claim'), 10), row); }
});

function pinNode(node) {
  var plot = plotOf(node);
  var kind = plot ? plot.getAttribute('data-plot') : (node.classList.contains('shelf-card') ? 'surface' : '');
  if (kind === 'threat') { setParam('pin', _pins.threat === node.getAttribute('data-node') ? '' : node.getAttribute('data-node')); return; }
  if (kind === 'ribbons') {
    var k = node.getAttribute('data-key');
    setParam('focus', _route.params.get('focus') === k ? '' : k);
    return;
  }
  if (kind === 'surface') {
    var host = $('#sec-diagrams [data-tab-panel="surface"]');
    var again = node.classList.contains('pin');
    $$('.shelf-card.pin').forEach(function (n) { n.classList.remove('pin'); n.setAttribute('aria-pressed', 'false'); });
    if (!again) { node.setAttribute('aria-pressed', 'true'); }
    setPin('surface', host, again ? null : node);
    return;
  }
  if (plot) setPin(kind, plot, _pins[kind] === node.getAttribute('data-node') ? null : node);
}

document.addEventListener('mouseover', function (e) {
  var tipEl = e.target.closest('[data-tip]');
  if (tipEl) tipShow(tipEl, e.clientX, e.clientY); else tipHide();
  var node = e.target.closest('.dg .nd[data-lights]');
  if (node) light(plotOf(node), node.getAttribute('data-lights').split(' '));
  var cell = e.target.closest('.dg [data-cell]');
  if (cell) {
    var plot = plotOf(cell);
    $$('.band.hot', plot).forEach(function (b) { b.classList.remove('hot'); });
    $$('[data-row="' + cell.getAttribute('data-row-i') + '"], [data-col="' + cell.getAttribute('data-col-j') + '"]', plot).forEach(function (b) { b.classList.add('hot'); });
  }
});
document.addEventListener('mouseout', function (e) {
  var node = e.target.closest('.dg .nd[data-lights]');
  if (node && !(e.relatedTarget && node.contains(e.relatedTarget))) restore(plotOf(node));
  var cell = e.target.closest('.dg [data-cell]');
  if (cell && !(e.relatedTarget && cell.contains(e.relatedTarget))) $$('.band.hot', plotOf(cell)).forEach(function (b) { b.classList.remove('hot'); });
});
document.addEventListener('mousemove', function (e) { tipMove(e.clientX, e.clientY); });

document.addEventListener('input', function (e) {
  if (e.target && e.target.id === 'search') onSearchInput(e.target);
});
document.addEventListener('change', function (e) {
  var t = e.target; if (!t) return;
  if (t.hasAttribute('data-page-size')) { pagerSize(t); return; }
  if (t.id === 'featureFilter') { applyFeatureFilter(t.value); return; }
  if (t.hasAttribute('data-report-select')) { showReport(); return; }
  if (t.hasAttribute('data-matrix-compact')) { _compact = t.checked; _matrixKey = ''; filterPage('exposures'); return; }
  if (t.hasAttribute('data-focus-select')) { location.hash = '#diagrams?tab=flow&view=hood&focus=' + encodeURIComponent(t.value); }
});

/* Keyboard: a plot is one tab stop; arrows step through its marks, Enter or Space pins, Esc clears. */
var _kf = null;
function plotStep(plot, dir) {
  var marks = $$('.nd[data-node]', plot);
  if (!marks.length) return;
  var i = _kf && _kf.plot === plot ? marks.indexOf(_kf.el) : -1;
  i = i < 0 ? 0 : Math.max(0, Math.min(marks.length - 1, i + dir));
  if (_kf && _kf.el) _kf.el.classList.remove('kfocus');
  _kf = { plot: plot, el: marks[i] };
  marks[i].classList.add('kfocus');
  if (marks[i].getAttribute('data-lights')) light(plot, marks[i].getAttribute('data-lights').split(' '));
  if (marks[i].hasAttribute('data-tip')) tipAt(marks[i]);
  plot.setAttribute('aria-activedescendant', '');
  plot.setAttribute('aria-label', plot.getAttribute('aria-label').split(' — focused: ')[0] + ' — focused: ' + (marks[i].getAttribute('aria-label') || marks[i].getAttribute('data-tip') || ''));
}
document.addEventListener('keydown', function (e) {
  var t = e.target;
  var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((t && t.tagName) || '');
  if (e.key === 'Escape') {
    if (typing && t.id === 'search' && t.value) { t.value = ''; setParam('q', ''); return; }
    if (document.getElementById('drawer').classList.contains('open')) { closeDrawer(); return; }
    tipHide();
    if (_route.page === 'diagrams' && _route.params.get('pin')) { setParam('pin', ''); return; }
    if (_route.page === 'exposures' && _route.params.get('cell')) { setParam('cell', ''); return; }
    Object.keys(_pins).forEach(function (k) { if (_pins[k]) setPin(k, $('[data-plot="' + k + '"]') || $('#sec-diagrams'), null); });
    return;
  }
  if (typing) return;
  var plot = t && t.closest ? t.closest('[data-plot]') : null;
  if (plot && t === plot) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') { e.preventDefault(); plotStep(plot, 1); return; }
    if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') { e.preventDefault(); plotStep(plot, -1); return; }
    if ((e.key === 'Enter' || e.key === ' ') && _kf && _kf.plot === plot) { e.preventDefault(); _kf.el.dispatchEvent(new MouseEvent('click', { bubbles: true })); return; }
  }
  if ((e.key === 'Enter' || e.key === ' ') && t && t.matches && t.matches('[data-toggle-file], [data-annotation], .shelf-card, [data-expand]')) { e.preventDefault(); t.click(); return; }
  if (e.key === '/') { var s = document.getElementById('search'); if (s) { e.preventDefault(); s.focus(); s.select(); } return; }
  if (document.getElementById('drawer').classList.contains('open')) {
    if (e.key === 'ArrowRight' || e.key === 'j') drawerNav(1);
    if (e.key === 'ArrowLeft' || e.key === 'k') drawerNav(-1);
  }
});
document.addEventListener('focusout', function (e) {
  var plot = e.target && e.target.closest ? e.target.closest('[data-plot]') : null;
  if (plot && _kf && _kf.plot === plot) { _kf.el.classList.remove('kfocus'); _kf = null; tipHide(); restore(plot); }
});

function boot() {
  try {
    if (localStorage.getItem('guardlink-rail') === '1') document.getElementById('sidebar').classList.add('collapsed');
    var theme = localStorage.getItem('guardlink-theme');
    if ((theme === 'light' || theme === 'dark') && !document.documentElement.hasAttribute('data-theme-pinned')) document.documentElement.setAttribute('data-theme', theme);
  } catch (e) { /* private mode */ }
  applyRoute();
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
`;
