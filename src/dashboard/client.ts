/**
 * GuardLink Dashboard — the upgrade's client script, as a string.
 *
 * Routing (the URL hash is the page and its filters), search, sortable
 * tables, filter chips, copy-to-clipboard, the claim drawer with its actions
 * and previous/next, theme, sidebar. The legacy blocks it relies on
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

function currentFilters() {
  var p = _route.params;
  var list = function (k) { var v = p.get(k); return v ? v.split(',').filter(Boolean) : []; };
  return { q: (p.get('q') || '').toLowerCase().trim(), sev: list('sev'), status: list('status'), state: list('state'), who: p.get('who') || '', file: p.get('file') || '' };
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
    if (group === 'who' || group === 'file') active = value ? f[group] === value : !f[group];
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
  $$('[data-search]', sec).forEach(function (el) {
    var ok = true;
    if (f.q && el.getAttribute('data-search').indexOf(f.q) < 0) ok = false;
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
  var active = !!(f.q || f.sev.length || f.status.length || f.state.length || f.who || f.file);
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
    return c.textContent.trim().toLowerCase();
  };
  rows.sort(function (a, b) { var ka = key(a), kb = key(b); var c = ka < kb ? -1 : ka > kb ? 1 : 0; return dir === 'asc' ? c : -c; });
  rows.forEach(function (r) { tbody.appendChild(r); });
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
  return 'A declared control. Verify it so a later edit beneath it is flagged as stale.';
}

function renderClaimDrawer(c) {
  var title = document.getElementById('drawer-title'), body = document.getElementById('drawer-body');
  title.textContent = c.threat + ' · ' + c.asset;
  var h = '';
  h += '<div class="d-status d-status-' + esc(c.status) + '"><span class="d-status-label">' + esc(c.statusLabel) + '</span>'
     + (c.state ? '<span class="claim-state ' + esc(c.state) + '">' + esc(c.state) + '</span>' : '') + '</div>';
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
     + ' <button class="copy" data-copy="' + esc(c.file + ':' + c.line) + '" title="Copy path">⧉</button>');
  if (c.blame) {
    h += '<div class="d-blame"><div class="d-label">Attribution</div>'
       + '<div class="d-blame-row"><span>Introduced</span>' + refHtml(c.blame.introduced) + (c.blame.lowerBound ? ' <span class="badge" title="History is truncated or the file has uncommitted edits: the true introduction may be older">lower bound</span>' : '') + '</div>'
       + '<div class="d-blame-row"><span>Declared</span>' + refHtml(c.blame.declared) + '</div>'
       + (c.verb !== 'mitigates' ? '<div class="d-blame-row"><span>Fixed</span>' + (c.blame.fixed ? refHtml(c.blame.fixed) + (c.blame.days !== null ? ' <span class="muted">after ' + c.blame.days + ' days</span>' : '') : '<span class="badge badge-red">open</span>') + '</div>' : '')
       + (c.blame.status !== 'ok' ? '<div class="d-blame-row"><span>Status</span><span class="badge">' + esc(c.blame.status) + '</span></div>' : '')
       + '</div>';
  }
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

/* ===== EVENTS ===== */
document.addEventListener('click', function (e) {
  var th = e.target.closest('th[data-sort]');
  if (th) { sortTable(th); return; }
  var chip = e.target.closest('.chip[data-chip]');
  if (chip) {
    var group = chip.getAttribute('data-chip'), value = chip.getAttribute('data-value');
    if (!value) setParam(group, '');
    else if (group === 'who' || group === 'file') setParam(group, currentFilters()[group] === value ? '' : value);
    else toggleInList(group, value);
    return;
  }
  var clear = e.target.closest('[data-clear-filters]');
  if (clear) { clearFilters(); return; }
  var cp = e.target.closest('[data-copy]');
  if (cp) { e.preventDefault(); e.stopPropagation(); copyText(cp.getAttribute('data-copy'), cp); return; }
  var nav = e.target.closest('[data-drawer-nav]');
  if (nav) { drawerNav(nav.getAttribute('data-drawer-nav') === 'next' ? 1 : -1); return; }
  var row = e.target.closest('[data-claim]');
  if (row && !e.target.closest('a, button')) { openDrawer('claim', parseInt(row.getAttribute('data-claim'), 10), row); }
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
