/**
 * GuardLink Dashboard — the upgrade's client script, as a string.
 *
 * Routing (the URL hash is the page and its filters), search (every term
 * must match), sortable and paginated tables, filter chips, copy-to-clipboard,
 * the claim drawer with its actions and previous/next, the asset drawer over
 * the precomputed asset details, report copy/download, theme, sidebar. The legacy blocks it relies on
 * (feature filter, diagrams, threat reports, asset/annotation drawers) are
 * appended after it from client-legacy.ts.
 *
 * Nothing from the model is interpolated into this string at generation
 * time; the page's data arrives through the JSON constants emitted before it,
 * and everything rendered from them goes through the client `esc()`.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Every value the drawer renders from the embedded data passes through the client esc(); URLs are pre-built server-side and attribute-escaped here"
 * @comment -- "No network: the clipboard API with a textarea fallback, history.replaceState for filters, localStorage only for theme and sidebar state"
 */
export const CLIENT_JS = `
/* ===== HELPERS ===== */
function esc(s) { return s == null ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function sec(label, value) { return '<div class="d-section"><div class="d-label">' + label + '</div><div class="d-value">' + value + '</div></div>'; }
function sevCls(s) {
  var l = (s || '').toLowerCase();
  if (l === 'critical' || l === 'p0') return 'crit';
  if (l === 'high' || l === 'p1') return 'high';
  if (l === 'medium' || l === 'p2') return 'med';
  if (l === 'low' || l === 'p3') return 'low';
  return 'unset';
}
function $(sel, root) { return (root || document).querySelector(sel); }
/* Severity buckets of a list of exposure rows — the grade counts OPEN ones only. */
function _sevOf(list) {
  var sev = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  list.forEach(function (e) {
    var s = (e.severity || '').toLowerCase();
    if (s === 'critical' || s === 'p0') sev.critical++;
    else if (s === 'high' || s === 'p1') sev.high++;
    else if (s === 'medium' || s === 'p2') sev.medium++;
    else if (s === 'low' || s === 'p3') sev.low++;
    else sev.unset++;
  });
  return sev;
}
function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

/* ===== ROUTER: #page?q=&sev=&status=&state=&who=&file= ===== */
var _route = { page: 'summary', params: new URLSearchParams() };
var _lastHash = null;

function parseHash() {
  var h = location.hash.replace(/^#/, '');
  var i = h.indexOf('?');
  var page = (i >= 0 ? h.slice(0, i) : h) || 'summary';
  var params = new URLSearchParams(i >= 0 ? h.slice(i + 1) : '');
  if (!document.getElementById('sec-' + page)) page = 'summary';
  return { page: page, params: params };
}

function showSection(id, el, opts) {
  opts = opts || {};
  $$('.section-content').forEach(function (s) { s.classList.remove('active'); });
  $$('.sidebar a').forEach(function (a) { a.classList.remove('active'); });
  var sec = document.getElementById('sec-' + id) || document.getElementById('sec-summary');
  if (sec) sec.classList.add('active');
  var nav = el || $('.sidebar a[data-page="' + id + '"]');
  if (nav) nav.classList.add('active');
  closeDrawer();
  if (id === 'diagrams') setTimeout(function () { renderActiveDiagram(); }, 100);
  if (id === 'ai-analysis' && !window._aiAnalysisRendered) renderAIAnalysis();
  if (!opts.silent) {
    var target = '#' + id + (opts.query ? '?' + opts.query : '');
    if (location.hash !== target) location.hash = target;
  }
  var main = $('.main'); if (main) main.scrollTop = 0;
  window.scrollTo(0, 0);
}

function applyRoute() {
  if (location.hash === _lastHash) return;
  _lastHash = location.hash;
  var r = parseHash();
  _route = r;
  showSection(r.page, null, { silent: true });
  syncControls(r.page, r.params);
  filterPage(r.page);
}
window.addEventListener('hashchange', applyRoute);
window.addEventListener('popstate', applyRoute);

/* Filter groups that hold one value (the rest are lists). */
var SINGLE = ['who', 'file', 'owner', 'handles', 'change'];

function currentFilters() {
  var p = _route.params;
  var list = function (k) { var v = p.get(k); return v ? v.split(',').filter(Boolean) : []; };
  return { q: (p.get('q') || '').toLowerCase().trim(), sev: list('sev'), status: list('status'), state: list('state'), who: p.get('who') || '', file: p.get('file') || '', owner: p.get('owner') || '', handles: p.get('handles') || '', change: p.get('change') || '' };
}

function setParam(k, v) {
  var p = new URLSearchParams(_route.params.toString());
  if (v) p.set(k, v); else p.delete(k);
  var qs = p.toString();
  var target = '#' + _route.page + (qs ? '?' + qs : '');
  _route.params = p;
  _lastHash = target;
  history.replaceState(null, '', target);
  syncControls(_route.page, p);
  filterPage(_route.page);
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
  });
  var who = sec ? $('.who-filter', sec) : null;
  if (who) { who.hidden = !f.who; var name = $('.who-filter-name', who); if (name) name.textContent = f.who === 'ai' ? 'AI-assisted only' : f.who; }
}

function filterPage(page) {
  var f = currentFilters();
  var sec = document.getElementById('sec-' + page);
  if (!sec) return;
  var groups = {};
  var terms = f.q ? f.q.split(/\\s+/).filter(Boolean) : [];
  $$('[data-search]', sec).forEach(function (el) {
    var ok = true;
    if (terms.length) { var hay = el.getAttribute('data-search'); for (var i = 0; i < terms.length; i++) { if (hay.indexOf(terms[i]) < 0) { ok = false; break; } } }
    if (ok && f.sev.length && el.hasAttribute('data-sev') && f.sev.indexOf(el.getAttribute('data-sev')) < 0) ok = false;
    if (ok && f.status.length && el.hasAttribute('data-status') && f.status.indexOf(el.getAttribute('data-status')) < 0) ok = false;
    if (ok && f.state.length && el.hasAttribute('data-state') && f.state.indexOf(el.getAttribute('data-state')) < 0) ok = false;
    if (ok && f.who && el.hasAttribute('data-who')) {
      var who = el.getAttribute('data-who').split('|');
      ok = who.indexOf(f.who) >= 0;
    } else if (ok && f.who && el.hasAttribute('data-sev')) {
      ok = false; // a claim row with no attribution never matches an identity filter
    }
    if (ok && f.file && el.hasAttribute('data-ff') && el.getAttribute('data-ff') !== f.file) ok = false;
    if (ok && f.owner && el.hasAttribute('data-sev')) ok = el.hasAttribute('data-owner') && el.getAttribute('data-owner').split('|').indexOf(f.owner) >= 0;
    if (ok && f.handles && el.hasAttribute('data-sev')) ok = el.hasAttribute('data-handles') && el.getAttribute('data-handles').split('|').indexOf(f.handles) >= 0;
    if (ok && f.change && el.hasAttribute('data-sev')) ok = el.getAttribute('data-change') === f.change;
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
  var active = !!(f.q || f.sev.length || f.status.length || f.state.length || f.who || f.file || f.owner || f.handles || f.change);
  var bar = $('.filter-status', sec);
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
    var txt = $('.filter-status-text', bar); if (txt) txt.textContent = 'Filtered: ' + parts.join(' · ');
  }
}

function clearFilters() {
  var target = '#' + _route.page;
  _route.params = new URLSearchParams();
  _lastHash = target;
  history.replaceState(null, '', target);
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
  var table = th.closest('table'); if (!table || !table.tBodies[0]) return;
  var tbody = table.tBodies[0];
  var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
  var numeric = th.getAttribute('data-type') === 'num';
  var dir = th.classList.contains('sorted-asc') ? 'desc' : 'asc';
  $$('th', table).forEach(function (h) { h.classList.remove('sorted-asc', 'sorted-desc'); });
  th.classList.add('sorted-' + dir);
  var rows = $$('tbody > tr', table);
  var key = function (r) {
    var c = r.children[idx]; if (!c) return numeric ? -Infinity : '';
    if (numeric) { var v = c.getAttribute('data-v'); var n = v !== null ? parseFloat(v) : parseFloat(c.textContent); return isNaN(n) ? -Infinity : n; }
    var tv = c.getAttribute('data-v');
    return (tv !== null ? tv : c.textContent).trim().toLowerCase();
  };
  rows.sort(function (a, b) { var ka = key(a), kb = key(b); var c = ka < kb ? -1 : ka > kb ? 1 : 0; return dir === 'asc' ? c : -c; });
  rows.forEach(function (r) { tbody.appendChild(r); });
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
  ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
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
  if (type !== 'claim') return openLegacyDrawer(type, idx);
  var c = claimsData[idx]; if (!c) return;
  var list = [idx];
  if (rowEl) {
    var table = rowEl.closest('table');
    if (table) list = $$('tr[data-claim]', table)
      .filter(function (r) { return !r.classList.contains('filtered-out') && r.style.display !== 'none'; })
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
  if (c.status === 'accepted') return 'Accepted by a human. Revisit the acceptance when the asset or the threat changes.';
  if (c.status === 'refuted') return 'Tested and not exploitable, with the evidence above. The claim stays in the source so the risk class is documented; the outcome expires by itself when the code beneath it changes.';
  return 'A declared control. Verify it so a later edit beneath it is flagged as stale.';
}

/* Status band: coverage status, ledger state, and who locked the claim when. */
function statusBand(c) {
  var by = c.verifiedBy ? '<span class="d-state-by">' + (c.state === 'stale' ? 'locked' : 'by') + ' ' + esc(c.verifiedBy) + (c.verifiedAt ? ' on ' + esc(String(c.verifiedAt).slice(0, 10)) : '') + (c.state === 'stale' ? ', code changed since' : '') + '</span>' : '';
  return '<div class="d-status d-status-' + esc(c.status) + '"><span class="d-status-label">' + esc(c.statusLabel) + '</span>'
     + (c.state ? '<span class="claim-state ' + esc(c.state) + '">' + esc(c.state) + '</span>' + by : '')
     + (c.change === 'new' ? '<span class="badge badge-blue" title="Added since the compared ref">new</span>' : '') + '</div>';
}
/* The tested state: what happened when this exposure was tried, by whom, and whether the code moved since. */
function hypothesisBand(c) {
  var h = c.hypothesis; if (!h || h.state === 'untested' && !h.previous_outcome) return '';
  var label = h.state === 'refuted' ? 'Tested: not exploitable' : h.state === 'confirmed' ? 'Tested: exploitable' : h.state === 'retest' ? 'Confirmed before — code changed, retest' : 'Untested again — code changed since it was ' + esc(h.previous_outcome);
  var tone = h.state === 'refuted' ? 'mitigated' : h.state === 'confirmed' ? 'confirmed' : 'open';
  return '<div class="d-status d-status-' + tone + ' d-hyp"><span class="d-status-label">' + label + '</span>'
    + (h.by ? '<span class="d-state-by">by ' + esc(h.by) + (h.at ? ' on ' + esc(String(h.at).slice(0, 10)) : '') + '</span>' : '') + '</div>'
    + (h.evidence ? sec('Evidence', esc(h.evidence)) : '');
}
function blameBlock(c) {
  if (!c.blame) return '';
  return '<div class="d-blame"><div class="d-label">Attribution</div>'
       + '<div class="d-blame-row"><span>Introduced</span><span class="d-ref">' + refHtml(c.blame.introduced) + (c.blame.lowerBound ? ' <span class="badge" title="History is truncated or the file has uncommitted edits: the true introduction may be older">lower bound</span>' : '') + '</span></div>'
       + '<div class="d-blame-row"><span>Declared</span><span class="d-ref">' + refHtml(c.blame.declared) + '</span></div>'
       + (c.verb !== 'mitigates' ? '<div class="d-blame-row"><span>Fixed</span><span class="d-ref">' + (c.blame.fixed ? refHtml(c.blame.fixed) + (c.blame.days !== null ? ' <span class="muted">after ' + c.blame.days + ' days</span>' : '') : '<span class="badge badge-red">open</span>') + '</span></div>' : '')
       + (c.blame.status !== 'ok' ? '<div class="d-blame-row"><span>Status</span><span class="badge">' + esc(c.blame.status) + '</span></div>' : '')
       + '</div>';
}

function renderClaimDrawer(c) {
  var title = document.getElementById('drawer-title'), body = document.getElementById('drawer-body');
  title.textContent = c.threat + ' · ' + c.asset;
  var h = '';
  h += statusBand(c);
  h += hypothesisBand(c);
  h += '<div class="d-grid">'
     + sec('Severity', '<span class="fc-sev ' + sevCls(c.severity) + '">' + esc(c.severity) + '</span>')
     + sec('Kind', '<code>' + esc(c.verb) + '</code>')
     + sec('Asset', '<code>' + esc(c.asset) + '</code>')
     + sec('Threat', '<code>' + esc(c.threat) + '</code>')
     + '</div>';
  if (c.description) h += sec('Description', esc(c.description));
  if (c.control) h += sec('Control', '<code>' + esc(c.control) + '</code>');
  if (c.refs && c.refs.length) h += sec('References', c.refs.map(function (r) { return '<code>' + esc(r) + '</code>'; }).join(' '));
  h += sec('Location', (c.url ? '<a class="loc-link" href="' + esc(c.url) + '" target="_blank" rel="noopener">' : '<span class="loc-text">')
     + esc(c.file + ':' + c.line) + (c.url ? '</a>' : '</span>')
     + ' <button class="copy" data-copy="' + esc(c.file + ':' + c.line) + '" title="Copy path">' + ICONS.copy + '</button>');
  h += blameBlock(c);
  h += '<div class="d-actions">'
     + (c.url ? '<a class="btn btn-primary" href="' + esc(c.url) + '" target="_blank" rel="noopener">' + esc(openOnHost) + '</a>' : '')
     + '<button class="btn" data-copy="guardlink verify ' + esc(c.file + ':' + c.line) + '">Copy verify command</button>'
     + '<button class="btn" data-copy="guardlink blame . --file ' + esc(c.file) + '">Copy blame command</button>'
     + '</div>';
  h += '<div class="d-advice d-advice-' + esc(c.status) + '">' + advice(c) + '</div>';
  h += '<div class="d-nav">'
     + '<button class="btn btn-ghost" data-drawer-nav="prev"' + (_drawerCtx.pos <= 0 ? ' disabled' : '') + '>← Previous</button>'
     + '<span class="d-pos">' + (_drawerCtx.pos + 1) + ' / ' + _drawerCtx.list.length + '</span>'
     + '<button class="btn btn-ghost" data-drawer-nav="next"' + (_drawerCtx.pos >= _drawerCtx.list.length - 1 ? ' disabled' : '') + '>Next →</button>'
     + '</div>';
  body.innerHTML = h;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
}

function closeDrawer() {
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('drawer-overlay').classList.remove('open');
}

/* ===== PAGINATION ===== */
function _pageRows(table) {
  return $$('tbody > tr', table).filter(function (r) { return !r.classList.contains('filtered-out') && r.style.display !== 'none'; });
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
  var wrap = table.closest('.table-wrap');
  if (wrap && wrap.getBoundingClientRect().top < 0) wrap.scrollIntoView({ block: 'start', behavior: 'smooth' });
}
function pagerSize(sel) {
  var table = _pagerTable(sel); if (!table) return;
  table.setAttribute('data-page-size', sel.value);
  table.setAttribute('data-page', '1');
  paginate(table);
}

/* ===== ASSET DRAWER ===== */
function _bar(n, max, cls) { return '<div class="sev-track"><div class="sev-fill ' + cls + '" style="width:' + (max > 0 ? Math.round((n / max) * 100) : 0) + '%"></div></div>'; }
function _plural(n, one) { return n + ' ' + one + (n === 1 ? '' : 's'); }
/* Everything the model knows about one asset, from the precomputed assetsData; every number links into the filtered Threats page. */
function renderAssetDrawer(idx) {
  var a = typeof assetsData !== 'undefined' ? assetsData[idx] : null;
  if (!a) return openLegacyDrawer('asset', idx);
  var title = document.getElementById('drawer-title'), body = document.getElementById('drawer-body');
  title.textContent = a.name;
  var q = encodeURIComponent(a.name);
  var open = a.exposures.open + a.exposures.confirmed;
  var h = '';
  h += '<div class="d-status d-status-' + (open > 0 ? 'open' : a.exposures.total > 0 ? 'mitigated' : 'control') + '"><span class="d-status-label">' + (a.riskLevel === 'none' ? 'no exposure' : esc(a.riskLevel) + ' risk') + '</span><span class="muted">'
     + (open > 0 ? open + ' open of ' + _plural(a.exposures.total, 'exposure') : a.exposures.total > 0 ? 'all ' + _plural(a.exposures.total, 'exposure') + ' covered' : 'no exposures declared') + '</span></div>';
  h += '<div class="d-grid d-grid-4">'
     + sec('Open', '<a href="#threats?q=' + q + '&status=open" class="' + (open > 0 ? 'red' : 'muted') + '">' + open + '</a>')
     + sec('Mitigated', '<a href="#threats?q=' + q + '&status=mitigated">' + a.exposures.mitigated + '</a>')
     + sec('Accepted', '<a href="#threats?q=' + q + '&status=accepted">' + a.exposures.accepted + '</a>')
     + sec('Confirmed', '<a href="#threats?q=' + q + '&status=confirmed" class="' + (a.exposures.confirmed > 0 ? 'red' : 'muted') + '">' + a.exposures.confirmed + '</a>')
     + '</div>';
  var sevs = ['critical', 'high', 'medium', 'low'].filter(function (s) { return a.bySeverity[s] > 0; });
  if (sevs.length) {
    h += sec('Open by severity', sevs.map(function (s) { return '<a href="#threats?q=' + q + '&sev=' + s + '&status=open" class="fc-sev ' + sevCls(s) + '">' + a.bySeverity[s] + ' ' + s + '</a>'; }).join(' '));
  }
  if (a.threats.length) {
    var maxT = Math.max.apply(null, a.threats.map(function (t) { return t.total; }));
    h += '<div class="d-section"><div class="d-label">' + _plural(a.threats.length, 'threat') + '</div><div class="d-bars">' + a.threats.map(function (t) {
      return '<a class="d-bar-row" href="#threats?q=' + encodeURIComponent(a.name + ' ' + t.threat) + '" title="Show these rows"><span class="d-bar-label"><code>' + esc(t.threat) + '</code></span>' + _bar(t.total, maxT, t.open > 0 ? 'sev-fill-crit' : 'sev-fill-low') + '<span class="d-bar-value">' + (t.open > 0 ? '<b class="red">' + t.open + ' open</b> / ' : '') + t.total + '</span></a>';
    }).join('') + '</div></div>';
  }
  if (a.controls.length) {
    h += sec(_plural(a.controls.length, 'control'), a.controls.map(function (c) { return '<a class="pill" href="#threats?q=' + encodeURIComponent(a.name + ' ' + c.control) + '"><code>' + esc(c.control) + '</code><span class="muted">×' + c.count + '</span></a>'; }).join(' '));
  } else if (a.exposures.total > 0) {
    h += sec('Controls', '<span class="muted">None declared — nothing here is covered by a <code>@mitigates</code>.</span>');
  }
  if (a.flowsIn.length || a.flowsOut.length) {
    h += '<div class="d-section"><div class="d-label">' + _plural(a.flowsIn.length + a.flowsOut.length, 'data flow') + '</div><div class="d-value d-flows">'
       + a.flowsIn.map(function (f) { return '<div><code>' + esc(f.from) + '</code> <span class="muted">→</span> <b>' + esc(a.name) + '</b>' + (f.via ? ' <span class="muted">via ' + esc(f.via) + '</span>' : '') + '</div>'; }).join('')
       + a.flowsOut.map(function (f) { return '<div><b>' + esc(a.name) + '</b> <span class="muted">→</span> <code>' + esc(f.to) + '</code>' + (f.via ? ' <span class="muted">via ' + esc(f.via) + '</span>' : '') + '</div>'; }).join('')
       + '</div></div>';
  }
  var facts = [];
  if (a.dataHandling.length) facts.push(sec('Handles', a.dataHandling.map(function (d) { return '<span class="badge badge-blue">' + esc(d) + '</span>'; }).join(' ')));
  if (a.boundaries.length) facts.push(sec('Trust boundaries with', a.boundaries.map(function (b) { return '<code>' + esc(b) + '</code>'; }).join(' ')));
  if (a.owners.length) facts.push(sec('Owner', a.owners.map(function (o) { return '<code>' + esc(o) + '</code>'; }).join(' ')));
  var life = [];
  if (a.audits) life.push(_plural(a.audits, 'audit'));
  if (a.assumptions) life.push(_plural(a.assumptions, 'assumption'));
  if (a.validations) life.push(_plural(a.validations, 'validation'));
  if (life.length) facts.push(sec('Lifecycle', life.join(' · ')));
  if (a.states) facts.push(sec('Claims', ['verified', 'stale', 'unverified'].map(function (k) { return '<span class="claim-state ' + k + '">' + a.states[k] + ' ' + k + '</span>'; }).join(' ')));
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
      return '<div><a class="loc-text" href="#threats?file=' + encodeURIComponent(f.file) + '" title="Show the rows in this file">' + esc(f.file) + '</a> <span class="muted">' + f.claims + '</span><button class="copy" data-copy="' + esc(f.file) + '" title="Copy path">' + ICONS.copy + '</button></div>';
    }).join('') + (a.files.length > 8 ? '<div class="muted">+ ' + (a.files.length - 8) + ' more</div>' : '') + '</div></div>';
  }
  h += '<div class="d-actions">'
     + '<a class="btn btn-primary" href="#threats?q=' + q + (open > 0 ? '&status=open' : '') + '">' + (open > 0 ? 'Show ' + open + ' open' : 'Show exposures') + '</a>'
     + '<a class="btn" href="#analytics">Compare in Analytics</a>'
     + '<button class="btn" data-copy="guardlink_lookup(&quot;asset ' + esc(a.name) + '&quot;)">Copy lookup</button>'
     + '</div>';
  body.innerHTML = h;
  _drawerCtx = null;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
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
      var v = k === 'severity' ? '<span class="fc-sev ' + sevCls(fields[k]) + '">' + esc(fields[k]) + '</span>'
        : k === 'asset' || k === 'threat' || k === 'control' || k === 'source' || k === 'target' || k === 'asset_a' || k === 'asset_b' || k === 'id' || k === 'path'
          ? '<a class="pill" href="#threats?q=' + encodeURIComponent(fields[k]) + '" title="Show rows naming this"><code>' + esc(fields[k]) + '</code></a>'
          : esc(fields[k]);
      return sec(label, v);
    }).join('') + (a.refs && a.refs.length ? sec('References', a.refs.map(function (r) { return '<code>' + esc(r) + '</code>'; }).join(' ')) : '') + '</div>';
  }
  if (a.description) h += sec('Description', esc(a.description));
  if (c) h += blameBlock(c);
  if (tile) {
    var open = tile.exposures.open + tile.exposures.confirmed;
    h += sec('Asset', '<span class="badge badge-' + (open > 0 ? 'red' : 'green') + '">' + (tile.riskLevel === 'none' ? 'no exposure' : esc(tile.riskLevel) + ' risk') + '</span> <span class="muted">' + open + ' open of ' + tile.exposures.total + ' exposures · ' + tile.controls.length + ' controls · ' + (tile.flowsIn.length + tile.flowsOut.length) + ' flows</span>');
  }
  var loc = f.file + ':' + a.line;
  h += sec('Location', (a.url ? '<a class="loc-link" href="' + esc(a.url) + '" target="_blank" rel="noopener">' : '<span class="loc-text">') + esc(loc) + (a.url ? '</a>' : '</span>') + ' <button class="copy" data-copy="' + esc(loc) + '" title="Copy path">' + ICONS.copy + '</button>');
  if (a.raw) h += '<div class="d-section d-raw"><div class="d-label">Annotation</div><div class="d-code">' + esc(a.raw) + '</div><button class="copy" data-copy="' + esc(a.raw) + '" title="Copy annotation">' + ICONS.copy + '</button></div>';
  if (a.codeContext && a.codeContext.length) {
    h += '<div class="d-section"><div class="d-label">Code</div><div class="d-code-ctx">' + a.codeContext.map(function (line, i) { return '<span' + (i === a.annLineIdx ? ' class="hl"' : '') + '>' + esc(line) + '</span>'; }).join('') + '</div></div>';
  }
  var q = fields.asset && fields.threat ? fields.asset + ' ' + fields.threat : fields.asset || fields.control || fields.source || fields.path || '';
  h += '<div class="d-actions">'
     + (c ? '<a class="btn btn-primary" href="#threats?q=' + encodeURIComponent(q) + '">Open in Threats</a>' : q ? '<a class="btn btn-primary" href="#threats?q=' + encodeURIComponent(q) + '">Related exposures</a>' : '')
     + (tile ? '<button class="btn" data-asset-drawer="' + a.assetIdx + '">Asset details</button>' : '')
     + (a.url ? '<a class="btn" href="' + esc(a.url) + '" target="_blank" rel="noopener">' + esc(openOnHost) + '</a>' : '')
     + (c ? '<button class="btn" data-copy="guardlink verify ' + esc(loc) + '">Copy verify command</button>' : '')
     + '</div>';
  body.innerHTML = h;
  _drawerCtx = null;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
}

/* ===== FEATURE FILTER HOOK ===== */
/* The legacy dropdown hides rows by file; the Analytics grids are recomputed per feature server-side and swapped here, and whole-model pages say so. */
function onFeatureFilter(name) {
  name = name || '';
  $$('.analytics-body[data-feature]').forEach(function (b) { b.hidden = b.getAttribute('data-feature') !== name; });
  $$('.whole-model-note').forEach(function (n) {
    n.hidden = !name;
    var f = $('.wm-feature', n); if (f) f.textContent = name;
    var c = $('[data-copy]', n); if (c) c.setAttribute('data-copy', 'guardlink dashboard . --feature "' + name + '"');
  });
  filterPage(_route.page);
}

/* ===== DIAGRAMS: focus, find, theme ===== */
function diagramFocus(name) {
  var panel = document.getElementById('dtab-threat-graph'); if (!panel) return;
  var toggle = document.getElementById('threatGraphToggle');
  var full = !!(toggle && toggle.classList.contains('active'));
  $$('.mermaid', panel).forEach(function (el) {
    var f = el.getAttribute('data-focus'), v = el.getAttribute('data-variant');
    var show = name ? f === name : (v === 'full' ? full : v === 'filtered' ? !full : false);
    el.style.display = show ? '' : 'none';
  });
  if (toggle) toggle.disabled = !!name;
  var find = $('.diagram-find', panel); if (find) { find.value = ''; }
  renderActiveDiagram();
}
function diagramFind(term) {
  var panel = document.querySelector('.diagram-panel.active'); if (!panel) return;
  var t = (term || '').toLowerCase().trim();
  $$('svg .node, svg .cluster', panel).forEach(function (n) { n.classList.toggle('dim', !!t && n.textContent.toLowerCase().indexOf(t) < 0); });
  $$('svg .edgePath, svg .edgeLabel, svg .edgePaths > path, svg .flowchart-link', panel).forEach(function (e) { e.classList.toggle('dim-edge', !!t); });
}
/* Mermaid sources carry dark fills for GitHub; on the light theme swap them for light tints before rendering. */
function themeMermaid(src) {
  if (document.documentElement.getAttribute('data-theme') === 'dark') return src;
  var map = { 'fill:#3a1010': 'fill:#fbe3e3', 'fill:#402019': 'fill:#fdebe0', 'fill:#1f3943': 'fill:#e3eef3', 'fill:#10263b': 'fill:#e1ecf5', 'fill:#223942': 'fill:#e8eef0', 'fill:#102a24': 'fill:#e0f7ee', 'color:#f0f0f0': 'color:#1f3943' };
  return src.replace(/fill:#3a1010|fill:#402019|fill:#1f3943|fill:#10263b|fill:#223942|fill:#102a24|color:#f0f0f0/g, function (m) { return map[m] || m; });
}

/* ===== REPORTS: the findings block as rows ===== */
/* One row per finding the report declared, each id a link into the Threats table. Prose stays below. */
function renderFindingsTable(findings) {
  if (!findings || !findings.length) return '';
  var rank = { critical: 0, high: 1, medium: 2, low: 3, unset: 4 };
  var rows = findings.slice().sort(function (a, b) { return (rank[a.severity] || 4) - (rank[b.severity] || 4) || String(a.id).localeCompare(String(b.id)); });
  var h = '<div class="findings"><div class="sub-h"><span>Findings</span><span class="sub-h-right">' + rows.length + ' declared by the report</span></div>';
  h += '<div class="table-wrap"><table class="sortable fixed findings-table"><colgroup><col style="width:7%"><col style="width:9%"><col style="width:9%"><col style="width:14%"><col style="width:14%"><col><col style="width:16%"></colgroup>';
  h += '<thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Asset</th><th>Threat</th><th>Finding</th><th class="loc">Location</th></tr></thead><tbody>';
  rows.forEach(function (f) {
    var q = encodeURIComponent((f.asset || '') + ' ' + (f.threat || ''));
    var loc = f.location && f.location.file ? f.location.file + (f.location.line ? ':' + f.location.line : '') : '';
    var st = f.status === 'open' || f.status === 'confirmed' ? 'red' : f.status === 'mitigated' ? 'green' : f.status === 'accepted' ? 'blue' : 'neutral';
    h += '<tr title="' + esc(f.evidence || '') + '"><td><code>' + esc(f.id) + '</code></td>'
       + '<td><span class="fc-sev ' + sevCls(f.severity) + '">' + esc(f.severity) + '</span></td>'
       + '<td><span class="badge' + (st === 'neutral' ? '' : ' badge-' + st) + '">' + esc(f.status) + '</span></td>'
       + '<td>' + (f.asset ? '<a class="pill" href="#threats?q=' + encodeURIComponent(f.asset) + '"><code>' + esc(f.asset) + '</code></a>' : '') + '</td>'
       + '<td>' + (f.threat ? '<a class="pill" href="#threats?q=' + encodeURIComponent(f.threat) + '"><code>' + esc(f.threat) + '</code></a>' : '') + '</td>'
       + '<td><a class="who" href="#threats?q=' + q + '">' + esc(f.title || '') + '</a>' + (f.remediation ? '<div class="muted small">' + esc(f.remediation) + '</div>' : '') + '</td>'
       + '<td class="loc">' + (loc ? '<span class="loc-text">' + esc(loc) + '</span><button class="copy" data-copy="' + esc(loc) + '" title="Copy path">' + ICONS.copy + '</button>' : '') + '</td></tr>';
  });
  h += '</tbody></table></div></div>';
  return h;
}

/* ===== REPORTS: link the model's ids ===== */
function linkifyIds(container) {
  if (!container || typeof threatModel === 'undefined') return;
  var ids = {};
  (threatModel.assets || []).forEach(function (a) { if (a.id) ids['#' + String(a.id).toLowerCase()] = 1; });
  (threatModel.threats || []).forEach(function (t) { if (t.id) ids['#' + String(t.id).toLowerCase()] = 1; });
  (threatModel.controls || []).forEach(function (c) { if (c.id) ids['#' + String(c.id).toLowerCase()] = 1; });
  var walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null);
  var nodes = [], n;
  while ((n = walker.nextNode())) { if (n.nodeValue.indexOf('#') >= 0 && !(n.parentNode && n.parentNode.closest && n.parentNode.closest('a'))) nodes.push(n); }
  nodes.forEach(function (tn) {
    var txt = tn.nodeValue, re = /#[A-Za-z0-9][A-Za-z0-9_-]*/g, last = 0, m, any = false;
    var frag = document.createDocumentFragment();
    while ((m = re.exec(txt))) {
      if (!ids[m[0].toLowerCase()]) continue;
      any = true;
      frag.appendChild(document.createTextNode(txt.slice(last, m.index)));
      var a = document.createElement('a'); a.href = '#threats?q=' + encodeURIComponent(m[0]); a.className = 'id-link'; a.title = 'Show rows naming ' + m[0]; a.textContent = m[0];
      frag.appendChild(a);
      last = m.index + m[0].length;
    }
    if (!any) return;
    frag.appendChild(document.createTextNode(txt.slice(last)));
    tn.parentNode.replaceChild(frag, tn);
  });
}

/* ===== REPORTS & DIAGRAMS ===== */
function _currentReport() {
  var list = typeof savedAnalyses !== 'undefined' && Array.isArray(savedAnalyses) ? savedAnalyses : [];
  var sel = document.getElementById('report-selector');
  var i = sel && sel.value !== '' ? parseInt(sel.value, 10) : 0;
  return list[isNaN(i) ? 0 : i] || null;
}
function copyReport(btn) {
  var r = _currentReport();
  if (!r || !r.content) { toast('No report to copy'); return; }
  copyText(r.content, btn);
}
function downloadReport() {
  var r = _currentReport();
  if (!r || !r.content) { toast('No report to download'); return; }
  var name = ((r.framework || r.label || 'threat-report') + '-' + (r.timestamp || '')).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/-+$/, '') + '.md';
  var blob = new Blob([r.content], { type: 'text/markdown' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a'); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  toast('Downloading ' + name);
}
function diagramCopySource(btn) {
  var panel = btn.closest('.diagram-panel'); if (!panel) return;
  var el = $$('.mermaid', panel).filter(function (m) { return m.style.display !== 'none'; })[0] || $('.mermaid', panel);
  if (!el) return;
  copyText(el.getAttribute('data-original') || el.textContent.trim(), btn);
}

/* ===== EVENTS ===== */
document.addEventListener('click', function (e) {
  var th = e.target.closest('th[data-sort]');
  if (th) { sortTable(th); return; }
  var chip = e.target.closest('.chip[data-chip]');
  if (chip) {
    var group = chip.getAttribute('data-chip'), value = chip.getAttribute('data-value');
    if (!value) setParam(group, '');
    else if (SINGLE.indexOf(group) >= 0) setParam(group, currentFilters()[group] === value ? '' : value);
    else toggleInList(group, value);
    return;
  }
  var clear = e.target.closest('[data-clear-filters]');
  if (clear) { clearFilters(); return; }
  var cp = e.target.closest('[data-copy]');
  if (cp) { e.preventDefault(); e.stopPropagation(); copyText(cp.getAttribute('data-copy'), cp); return; }
  var pg = e.target.closest('[data-page-go]');
  if (pg) { if (!pg.disabled) pagerGo(pg, pg.getAttribute('data-page-go')); return; }
  var cr = e.target.closest('[data-copy-report]');
  if (cr) { copyReport(cr); return; }
  var dr = e.target.closest('[data-download-report]');
  if (dr) { downloadReport(); return; }
  var ds = e.target.closest('[data-copy-diagram]');
  if (ds) { diagramCopySource(ds); return; }
  var ad = e.target.closest('[data-asset-drawer]');
  if (ad) { renderAssetDrawer(parseInt(ad.getAttribute('data-asset-drawer'), 10)); return; }
  var nav = e.target.closest('[data-drawer-nav]');
  if (nav) { drawerNav(nav.getAttribute('data-drawer-nav') === 'next' ? 1 : -1); return; }
  var row = e.target.closest('[data-claim]');
  if (row && !e.target.closest('a, button')) { openDrawer('claim', parseInt(row.getAttribute('data-claim'), 10), row); }
});

document.addEventListener('change', function (e) {
  var t = e.target;
  if (t && t.hasAttribute && t.hasAttribute('data-page-size')) { pagerSize(t); return; }
  if (t && t.id === 'featureFilter') setTimeout(function () { $$('table[data-paginate]').forEach(function (tb) { tb.setAttribute('data-page', '1'); paginate(tb); }); }, 0);
});

document.addEventListener('keydown', function (e) {
  var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || '');
  if (e.key === 'Escape') {
    if (typing && e.target.id === 'search' && e.target.value) { e.target.value = ''; setParam('q', ''); return; }
    closeDrawer(); return;
  }
  if (typing) return;
  if (e.key === '/') { var s = document.getElementById('search'); if (s) { e.preventDefault(); s.focus(); s.select(); } return; }
  if (document.getElementById('drawer').classList.contains('open')) {
    if (e.key === 'ArrowRight' || e.key === 'j') drawerNav(1);
    if (e.key === 'ArrowLeft' || e.key === 'k') drawerNav(-1);
  }
});

/* ===== THEME & SIDEBAR ===== */
function toggleTheme() {
  var html = document.documentElement;
  var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  try { localStorage.setItem('theme', next); } catch (e) { /* private mode */ }
  window._mermaidRendered = false;
  if (document.getElementById('sec-diagrams').classList.contains('active')) renderActiveDiagram();
}
function toggleSidebar() {
  var sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('collapsed');
  try { localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed')); } catch (e) { /* private mode */ }
}
function toggleFile(header) {
  header.classList.toggle('open');
  header.nextElementSibling.classList.toggle('open');
}

window.addEventListener('DOMContentLoaded', function () {
  try {
    if (localStorage.getItem('sidebarCollapsed') === 'true') document.getElementById('sidebar').classList.add('collapsed');
    var theme = localStorage.getItem('theme');
    if (theme === 'light' || theme === 'dark') document.documentElement.setAttribute('data-theme', theme);
  } catch (e) { /* private mode */ }
  applyRoute();
});
`;
