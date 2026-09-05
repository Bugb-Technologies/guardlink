/**
 * GuardLink Dashboard — client code carried over from the first dashboard.
 *
 * Two blocks the upgrade keeps verbatim: the feature filter (it rewrites the
 * stat tiles, headings and risk banner by label text, so those elements keep
 * their labels) and the diagram + threat-report machinery (mermaid, d3 zoom,
 * marked). Both are plain strings inlined into the page's script.
 *
 * @comment -- "Verbatim from the previous generate.ts; behaviour unchanged. Model data never reaches these strings at generation time — they read the embedded arrays at run time"
 */
export const FEATURE_FILTER_JS = `/* ===== FEATURE FILTER ===== */
var _activeFeature = '';

function _featureFilesFor(featureName) {
  var files = new Set();
  if (!featureName) return files;
  if (threatModel.features) {
    threatModel.features.forEach(function(f) {
      if (f.feature.toLowerCase() === featureName.toLowerCase()) {
        files.add(f.location.file);
      }
    });
  }
  return files;
}

function applyFeatureFilter(featureName) {
  _activeFeature = featureName;
  var banner = document.getElementById('feature-banner');

  if (!featureName) {
    // ── Clear filter ──────────────────────────────────────────────
    if (banner) banner.style.display = 'none';
    document.querySelectorAll('[data-ff]').forEach(function(el) { el.style.display = ''; });
    document.querySelectorAll('[data-ff-asset]').forEach(function(el) { el.style.display = ''; });
    _restoreFullStats();
    return;
  }

  // ── Compute matching file set ─────────────────────────────────
  var featureFiles = _featureFilesFor(featureName);

  // ── Show banner ───────────────────────────────────────────────
  if (banner) {
    banner.style.display = 'flex';
    document.getElementById('feature-banner-name').textContent = featureName;
    document.getElementById('feature-banner-files').textContent = featureFiles.size + ' file(s)';
  }

  // ── Filter rows/cards by file ─────────────────────────────────
  document.querySelectorAll('[data-ff]').forEach(function(el) {
    var file = el.getAttribute('data-ff');
    // Empty data-ff means the annotation had no location — keep visible
    el.style.display = (!file || featureFiles.has(file)) ? '' : 'none';
  });

  // ── Filter asset heatmap cells by asset name ──────────────────
  // An asset belongs to the feature if any of the feature files contains
  // an annotation that references that asset.
  var featureAssets = new Set();
  exposuresData.forEach(function(e) { if (featureFiles.has(e.file)) { featureAssets.add(e.asset); } });
  threatModel.flows.forEach(function(f) {
    if (f.location && featureFiles.has(f.location.file)) {
      featureAssets.add(f.source); featureAssets.add(f.target);
    }
  });
  threatModel.exposures.forEach(function(e) {
    if (e.location && featureFiles.has(e.location.file)) featureAssets.add(e.asset);
  });
  threatModel.mitigations.forEach(function(m) {
    if (m.location && featureFiles.has(m.location.file)) featureAssets.add(m.asset);
  });

  document.querySelectorAll('[data-ff-asset]').forEach(function(el) {
    var names = el.getAttribute('data-ff-asset').split('|');
    el.style.display = names.some(function(n) { return featureAssets.has(n); }) ? '' : 'none';
  });

  // ── Recompute & update all live stats ─────────────────────────
  _updateStatsForFilter(featureFiles);
}

function _updateStatsForFilter(featureFiles) {
  // Compute filtered exposure subsets from the raw data arrays
  var visExp = exposuresData.filter(function(e) { return !featureFiles.size || featureFiles.has(e.file); });
  var visOpen = visExp.filter(function(e) { return !e.mitigated && !e.accepted; });
  var visMit  = visExp.filter(function(e) { return e.mitigated; });

  var sev = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  visExp.forEach(function(e) {
    var s = (e.severity || '').toLowerCase();
    if (s === 'critical' || s === 'p0') sev.critical++;
    else if (s === 'high' || s === 'p1') sev.high++;
    else if (s === 'medium' || s === 'p2') sev.medium++;
    else if (s === 'low' || s === 'p3') sev.low++;
    else sev.unset++;
  });

  var totalExp = visExp.length;
  var mitPct = totalExp > 0 ? Math.round(visMit.length / totalExp * 100) : 0;

  // ── Top nav ───────────────────────────────────────────────────
  var tnStats = document.querySelectorAll('.tn-stat');
  tnStats.forEach(function(s) {
    var label = s.querySelector('span:first-child');
    var val   = s.querySelector('.tn-v');
    if (!label || !val) return;
    var lbl = label.textContent.trim();
    if (lbl === 'Open') val.textContent = visOpen.length;
    // 'Mitigated' is the label a feature-scoped page uses for this tile; the
    // value written here is the mitigation percentage either way.
    if (lbl === 'Coverage' || lbl === 'Mitigated') {
      val.textContent = mitPct + '%';
      val.className = 'tn-v ' + (mitPct >= 70 ? 'green' : mitPct >= 40 ? 'yellow' : 'red');
    }
  });

  // ── Summary page stats grid ───────────────────────────────────
  _setStat('Open Threats',  visOpen.length);
  _setStat('Mitigated',     visMit.length);

  // ── Coverage bar ──────────────────────────────────────────────
  var covPct = document.querySelector('.coverage-pct');
  if (covPct) {
    covPct.textContent = mitPct + '%';
    covPct.className = 'coverage-pct ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  var covLabel = document.querySelector('.posture-fill')?.parentElement?.nextElementSibling;
  var covFill = document.querySelector('.posture-fill');
  if (covFill) {
    covFill.style.width = Math.min(mitPct, 100) + '%';
    covFill.className = 'posture-fill ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  // Update "X of Y exposures mitigated" label
  document.querySelectorAll('#sec-summary span').forEach(function(sp) {
    if (sp.textContent.includes('exposures mitigated')) {
      sp.textContent = visMit.length + ' of ' + totalExp + ' exposures mitigated';
    }
  });

  // ── Severity bars ─────────────────────────────────────────────
  _updateSevBar('Critical', sev.critical, totalExp);
  _updateSevBar('High',     sev.high,     totalExp);
  _updateSevBar('Medium',   sev.medium,   totalExp);
  _updateSevBar('Low',      sev.low,      totalExp);
  _updateSevBar('Unset',    sev.unset,    totalExp);

  // ── Section headings with counts ─────────────────────────────
  _updateHeading('sec-threats', 'Open Threats',     visOpen.length);
  _updateHeading('sec-threats', 'Mitigated Threats', visMit.length);
  _updateHeading('sec-threats', 'All Exposures',     totalExp);

  // ── Risk banner (recompute grade) ─────────────────────────────
  var visConf = confirmedData.filter(function(c) { return !featureFiles.size || featureFiles.has(c.file); });
  _updateRiskBanner(_sevOf(visOpen), visOpen.length, totalExp, visConf.length);
}

function _restoreFullStats() {
  // Restore all counts from the original full data sets
  var allOpen = exposuresData.filter(function(e) { return !e.mitigated && !e.accepted; });
  var allMit  = exposuresData.filter(function(e) { return e.mitigated; });
  var totalExp = exposuresData.length;
  var mitPct = totalExp > 0 ? Math.round(allMit.length / totalExp * 100) : 0;

  var sev = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  exposuresData.forEach(function(e) {
    var s = (e.severity || '').toLowerCase();
    if (s === 'critical' || s === 'p0') sev.critical++;
    else if (s === 'high' || s === 'p1') sev.high++;
    else if (s === 'medium' || s === 'p2') sev.medium++;
    else if (s === 'low' || s === 'p3') sev.low++;
    else sev.unset++;
  });

  // Top nav
  var tnStats = document.querySelectorAll('.tn-stat');
  tnStats.forEach(function(s) {
    var label = s.querySelector('span:first-child');
    var val   = s.querySelector('.tn-v');
    if (!label || !val) return;
    var lbl = label.textContent.trim();
    if (lbl === 'Open') val.textContent = allOpen.length;
    // 'Mitigated' is the label a feature-scoped page uses for this tile; the
    // value written here is the mitigation percentage either way.
    if (lbl === 'Coverage' || lbl === 'Mitigated') {
      val.textContent = mitPct + '%';
      val.className = 'tn-v ' + (mitPct >= 70 ? 'green' : mitPct >= 40 ? 'yellow' : 'red');
    }
  });

  _setStat('Open Threats', allOpen.length);
  _setStat('Mitigated',    allMit.length);

  var covPct = document.querySelector('.coverage-pct');
  if (covPct) {
    covPct.textContent = mitPct + '%';
    covPct.className = 'coverage-pct ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  var covFill = document.querySelector('.posture-fill');
  if (covFill) {
    covFill.style.width = Math.min(mitPct, 100) + '%';
    covFill.className = 'posture-fill ' + (mitPct >= 70 ? 'good' : mitPct >= 40 ? 'warn' : 'bad');
  }
  document.querySelectorAll('#sec-summary span').forEach(function(sp) {
    if (sp.textContent.includes('exposures mitigated')) {
      sp.textContent = allMit.length + ' of ' + totalExp + ' exposures mitigated';
    }
  });

  _updateSevBar('Critical', sev.critical, totalExp);
  _updateSevBar('High',     sev.high,     totalExp);
  _updateSevBar('Medium',   sev.medium,   totalExp);
  _updateSevBar('Low',      sev.low,      totalExp);
  _updateSevBar('Unset',    sev.unset,    totalExp);

  _updateHeading('sec-threats', 'Open Threats',      allOpen.length);
  _updateHeading('sec-threats', 'Mitigated Threats', allMit.length);
  _updateHeading('sec-threats', 'All Exposures',     totalExp);

  _updateRiskBanner(_sevOf(allOpen), allOpen.length, totalExp, confirmedData.length);
}

/* ── Helpers ──────────────────────────────────────────────────────── */

function _setStat(label, value) {
  document.querySelectorAll('.stat-card').forEach(function(card) {
    var lbl = card.querySelector('.label');
    var val = card.querySelector('.value');
    if (lbl && val && lbl.textContent.trim() === label) {
      val.textContent = value;
    }
  });
}

function _updateSevBar(label, count, total) {
  var pct = total > 0 ? Math.round(count / total * 100) : 0;
  document.querySelectorAll('.sev-row').forEach(function(row) {
    var lbl = row.querySelector('.sev-label');
    if (!lbl || lbl.textContent.trim() !== label) return;
    var fill = row.querySelector('.sev-fill');
    var cnt  = row.querySelector('.sev-count');
    if (fill) fill.style.width = pct + '%';
    if (cnt)  cnt.textContent = count;
  });
}

function _updateHeading(sectionId, prefix, count) {
  var sec = document.getElementById(sectionId);
  if (!sec) return;
  sec.querySelectorAll('.sub-h').forEach(function(h) {
    if (h.textContent.trim().startsWith(prefix)) {
      // Replace trailing (N) count
      h.textContent = h.textContent.replace(/\\(\\d+\\)$/, '(' + count + ')').replace(/\\s+\\d+$/, ' ' + count);
    }
  });
}

function _updateRiskBanner(sev, openCount, totalExp, confirmedCount) {
  var grade, label, summary;
  if (confirmedCount > 0) {
    grade = 'F'; label = 'Critical Risk';
    summary = confirmedCount + ' confirmed exploitable finding(s) — immediate remediation required';
  } else if (sev.critical > 0) {
    grade = 'F'; label = 'Critical Risk';
    summary = sev.critical + ' critical exposure(s) require immediate attention';
  } else if (sev.high >= 3 || openCount >= 5) {
    grade = 'D'; label = 'High Risk';
    summary = openCount + ' unmitigated exposure(s), ' + sev.high + ' high severity';
  } else if (sev.high >= 1 || openCount >= 3) {
    grade = 'C'; label = 'Moderate Risk';
    summary = openCount + ' unmitigated exposure(s) need remediation';
  } else if (openCount >= 1) {
    grade = 'B'; label = 'Low Risk';
    summary = openCount + ' minor unmitigated exposure(s)';
  } else if (totalExp === 0) {
    grade = 'A'; label = 'Excellent';
    summary = 'No exposures detected — consider adding more annotations';
  } else {
    grade = 'A'; label = 'Excellent';
    summary = 'All exposures mitigated or accepted';
  }

  var banner = document.querySelector('.risk-banner');
  if (!banner) return;
  // Update grade class
  banner.className = banner.className.replace(/risk-[a-z]/g, 'risk-' + grade.toLowerCase());
  var gradeEl = banner.querySelector('.risk-grade');
  if (gradeEl) gradeEl.textContent = grade;
  var detail = banner.querySelector('.risk-detail');
  if (detail) {
    var strong = detail.querySelector('strong');
    var span   = detail.querySelector('span');
    if (strong) strong.textContent = label;
    if (span)   span.textContent   = summary;
  }
}

/* ===== THEME ===== */
`;

export const DIAGRAMS_AND_REPORTS_JS = `/* ===== DIAGRAM TABS ===== */
function switchDiagramTab(id, btn) {
  document.querySelectorAll('.diagram-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.diagram-tab').forEach(t => t.classList.remove('active'));
  const panel = document.getElementById('dtab-' + id);
  if (panel) panel.classList.add('active');
  if (btn) btn.classList.add('active');
  setTimeout(() => { renderActiveDiagram(); }, 50);
}

function toggleThreatGraphAll(btn) {
  const panel = document.getElementById('dtab-threat-graph');
  if (!panel) return;
  const filtered = panel.querySelector('.mermaid[data-variant="filtered"]');
  const full = panel.querySelector('.mermaid[data-variant="full"]');
  if (!filtered || !full) return;
  const showFull = full.style.display === 'none';
  filtered.style.display = showFull ? 'none' : '';
  full.style.display = showFull ? '' : 'none';
  if (btn) {
    btn.classList.toggle('active', showFull);
    btn.textContent = showFull ? 'High/Critical only' : 'All severities';
  }
  // Force mermaid to re-render the now-visible variant
  panel._diagramZoom = null;
  setTimeout(() => { renderActiveDiagram(); }, 50);
}

function diagramZoom(action) {
  const panel = document.querySelector('.diagram-panel.active');
  if (!panel || !panel._diagramZoom) return;
  const state = panel._diagramZoom;
  const svg = state.svg;
  const zoom = state.zoom;
  if (!svg || !zoom) return;

  if (action === 'fit') {
    svg.transition().duration(420).call(zoom.transform, d3.zoomIdentity);
    return;
  }
  const factor = action === 'in' ? 1.2 : 1 / 1.2;
  svg.transition().duration(220).call(zoom.scaleBy, factor);
}

/* ===== MERMAID ===== */
async function getMermaidInstance() {
  if (!window._mermaidMod) {
    const mod = await import('https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs');
    window._mermaidMod = mod.default;
  }
  const mermaid = window._mermaidMod;
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  mermaid.initialize({
    startOnLoad: false,
    theme: isDark ? 'dark' : 'default',
    themeVariables: isDark ? {
      primaryColor: '#17272e', primaryTextColor: '#f0f0f0', primaryBorderColor: '#55899e',
      lineColor: '#6b93a6', secondaryColor: '#1f3943', tertiaryColor: '#0f1b20',
      background: '#0f1b20', mainBkg: '#17272e', nodeBorder: '#55899e', secondBkg: '#1f3943',
      clusterBkg: 'rgba(23,39,46,.55)', clusterBorder: '#3b6779',
      titleColor: '#f0f0f0', edgeLabelBackground: '#0f1b20', labelBackground: '#0f1b20',
      nodeTextColor: '#f0f0f0',
      fontSize: '12px', fontFamily: 'Inter, system-ui, sans-serif',
    } : {
      primaryColor: '#ffffff', primaryTextColor: '#1f3943', primaryBorderColor: '#55899e',
      lineColor: '#3b6779', secondaryColor: '#f4f7f8', tertiaryColor: '#ffffff',
      background: '#ffffff', mainBkg: '#ffffff', nodeBorder: '#55899e', secondBkg: '#e8eef0',
      clusterBkg: '#f7fafb', clusterBorder: '#d9e4e8',
      titleColor: '#1f3943', edgeLabelBackground: '#ffffff', labelBackground: '#ffffff',
      nodeTextColor: '#1f3943',
      fontSize: '12px', fontFamily: 'Inter, system-ui, sans-serif',
    },
    flowchart: { curve: 'monotoneX', padding: 20, nodeSpacing: 48, rankSpacing: 62, htmlLabels: false, useMaxWidth: false, defaultRenderer: 'dagre-d3' },
    securityLevel: 'loose',
  });
  return mermaid;
}

async function renderMermaidPanel(panel) {
  if (!panel) return;
  const mermaid = await getMermaidInstance();
  // Render only the currently visible mermaid block(s). Hidden variants (e.g. the
  // full threat graph behind the "All severities" toggle) would otherwise fail
  // getBBox during layout sizing.
  const allEls = Array.from(panel.querySelectorAll('.mermaid'));
  const els = allEls.filter(el => el.offsetParent !== null || el.style.display !== 'none');
  const targets = els.length > 0 ? els : allEls;

  // Re-run mermaid
  targets.forEach(el => {
    el.removeAttribute('data-processed');
    el.innerHTML = el.getAttribute('data-original') || el.textContent;
  });
  await mermaid.run({ nodes: targets });
  
  // Add interactive zoom/pan to the rendered SVG
  if (typeof d3 !== 'undefined') {
    targets.forEach(el => {
      const svg = d3.select(el).select('svg');
      if (!svg.empty()) {
        const inner = svg.select('.root'); // Mermaid puts everything in a .root group
        if (!inner.empty()) {
          const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (e) => {
              inner.attr('transform', e.transform);
            });
          svg.call(zoom);
          panel._diagramZoom = { svg, zoom };
          
          // Preserve natural SVG size so long labels are not clipped.
          // Container scrolling handles overflow for large graphs.
          const rootNode = inner.node();
          if (rootNode && typeof rootNode.getBBox === 'function') {
            const bbox = rootNode.getBBox();
            const pad = 80;
            const viewX = Math.floor(bbox.x - pad / 2);
            const viewY = Math.floor(bbox.y - pad / 2);
            const viewW = Math.max(900, Math.ceil(bbox.width + pad));
            const viewH = Math.max(520, Math.ceil(bbox.height + pad));
            svg
              .attr('viewBox', viewX + ' ' + viewY + ' ' + viewW + ' ' + viewH)
              .attr('width', viewW)
              .attr('height', viewH)
              .style('max-width', 'none')
              .style('overflow', 'visible');
          }
          
          // Double click to reset
          svg.on('dblclick.zoom', null); // disable default dblclick zoom
          svg.on('dblclick', () => {
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
          });
        }
      }
    });
  }
}

async function renderMermaid() {
  // Render only the currently active diagram panel
  const active = document.querySelector('.diagram-panel.active');
  if (active) await renderMermaidPanel(active);
  window._mermaidRendered = true;
}

function renderActiveDiagram() {
  const active = document.querySelector('.diagram-panel.active');
  if (!active) return;
  renderMermaidPanel(active).then(() => { window._mermaidRendered = true; });
}

// Save original diagram source
document.querySelectorAll('.mermaid').forEach(el => {
  el.setAttribute('data-original', el.textContent.trim());
});

/* Keyboard: Escape closes drawer */
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

/* ===== AI ANALYSIS EXPLORER ===== */
let _selectedAnalysisIdx = 0;

function renderAIAnalysisContent(container, content) {
  if (!container) return;
  if (content && content.trim()) {
    if (typeof marked !== 'undefined') {
      try { container.innerHTML = marked.parse(content); }
      catch { container.innerHTML = '<pre style="white-space:pre-wrap">' + esc(content) + '</pre>'; }
    } else {
      container.innerHTML = '<pre style="white-space:pre-wrap">' + esc(content) + '</pre>';
    }
  } else {
    container.innerHTML = '<div class="empty-state" style="text-align:center;padding:3rem 1rem">' +
      '<div style="font-size:1.1rem;font-weight:600;margin-bottom:0.5rem">No Threat Reports Yet</div>' +
      '<div style="color:var(--muted);margin-bottom:1.5rem">Generate an AI threat report using the threat-report command</div>' +
      '<div style="display:flex;flex-direction:column;gap:0.5rem;max-width:500px;margin:0 auto;text-align:left">' +
      '<div style="font-size:0.88rem;color:var(--muted)"><strong>Available modes:</strong></div>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report stride</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report dread</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report pasta</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report attacker</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report rapid</code>' +
      '<code style="display:block;padding:0.5rem;background:var(--surface2);border-radius:4px;font-size:0.82rem">guardlink threat-report general</code>' +
      '<div style="margin-top:0.5rem;font-size:0.82rem;color:var(--muted)">Or a custom prompt: <code>guardlink threat-report general --custom "focus on auth"</code></div>' +
      '</div></div>';
  }
}

function formatAnalysisDate(ts) {
  try {
    // Handle both ISO and filename-style timestamps
    const normalized = ts.replace(/T(\\\\d{2})-(\\\\d{2})-(\\\\d{2})/, 'T$1:$2:$3');
    const d = new Date(normalized);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
           ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  } catch { return ts; }
}

function renderAIAnalysis() {
  window._aiAnalysisRendered = true;
  const selector = document.getElementById('report-selector');
  const container = document.getElementById('ai-content');
  if (!container) return;

  const list = savedAnalyses;
  const hasList = Array.isArray(list) && list.length > 0;

  if (hasList && selector) {
    // Populate dropdown with reports
    selector.innerHTML = list.map((a, i) => {
      const label = esc(a.label || a.framework || 'Analysis');
      const date = esc(formatAnalysisDate(a.timestamp || ''));
      const model = a.model ? ' — ' + esc(a.model) : '';
      return '<option value="' + i + '">' + label + ' (' + date + ')' + model + '</option>';
    }).join('');

    // Set initial selection
    selector.value = String(_selectedAnalysisIdx);

    // Handle dropdown change
    selector.addEventListener('change', function() {
      var idx = parseInt(this.value, 10);
      if (isNaN(idx) || idx === _selectedAnalysisIdx) return;
      _selectedAnalysisIdx = idx;
      renderAIAnalysisContent(container, (list[idx] && list[idx].content) ? list[idx].content : '');
    });

    // Render initial content
    renderAIAnalysisContent(container, (list[_selectedAnalysisIdx] && list[_selectedAnalysisIdx].content) ? list[_selectedAnalysisIdx].content : '');
  } else {
    if (selector) selector.style.display = 'none';
    renderAIAnalysisContent(container, '');
  }
}
`;

/**
 * The first dashboard's drawer builders for assets and annotations, kept as
 * `openLegacyDrawer`. Claim, asset and annotation drawers are the upgrade's
 * own (client.ts); these builders remain for the legacy exposure types.
 */
export const LEGACY_DRAWER_JS = `function openLegacyDrawer(type, idx) {
  const title = document.getElementById('drawer-title');
  const body = document.getElementById('drawer-body');
  let h = '';

  if (type === 'open_exposure') {
    const e = analysisData.openExposures[idx];
    title.textContent = e.threat + ' (Open)';
    h += sec('Status', '<span style="color:var(--red);font-weight:600">OPEN — No mitigation</span>');
    h += sec('Severity', '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(e.asset) + '</code>');
    h += sec('Threat', '<code>' + esc(e.threat) + '</code>');
    if (e.description) h += sec('Description', esc(e.description));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(e.file) + ':' + e.line + '</span>');
    h += '<div class="d-section" style="margin-top:1rem;padding:.6rem;background:var(--badge-red-bg);border:1px solid var(--sev-crit);border-radius:6px;opacity:.85"><div style="font-size:.78rem;color:var(--sev-crit);font-weight:600">Recommended Action</div><div style="font-size:.78rem;margin-top:.3rem">Add a <code>@mitigates</code> annotation with a control that addresses this threat, or <code>@accepts</code> if the risk is intentionally accepted.</div></div>';
  } else if (type === 'mitigated_exposure') {
    const e = analysisData.mitigatedExposures[idx];
    title.textContent = e.threat + ' (Mitigated)';
    h += sec('Status', '<span style="color:var(--green);font-weight:600">MITIGATED</span>');
    h += sec('Severity', '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(e.asset) + '</code>');
    if (e.description) h += sec('Description', esc(e.description));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(e.file) + ':' + e.line + '</span>');
  } else if (type === 'confirmed') {
    const c = confirmedData[idx];
    title.textContent = c.threat + ' (Confirmed)';
    h += '<div style="background:var(--badge-red-bg);border:1px solid var(--sev-crit);border-radius:6px;padding:.6rem;margin-bottom:1rem"><div style="font-size:.82rem;font-weight:700;color:var(--sev-crit)">CONFIRMED EXPLOITABLE</div><div style="font-size:.75rem;margin-top:.2rem;color:var(--muted)">Verified through testing — not a false positive</div></div>';
    h += sec('Severity', '<span class="fc-sev ' + sevCls(c.severity) + '">' + esc(c.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(c.asset) + '</code>');
    h += sec('Threat', '<code>' + esc(c.threat) + '</code>');
    if (c.description) h += sec('Evidence', esc(c.description));
    if (c.external_refs && c.external_refs.length) h += sec('References', c.external_refs.map(r => '<code>' + esc(r) + '</code>').join(', '));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(c.file) + ':' + c.line + '</span>');
    h += '<div class="d-section" style="margin-top:1rem;padding:.6rem;background:var(--badge-red-bg);border:1px solid var(--sev-crit);border-radius:6px;opacity:.85"><div style="font-size:.78rem;color:var(--sev-crit);font-weight:600">Immediate Action Required</div><div style="font-size:.78rem;margin-top:.3rem">This threat has been verified exploitable. Apply a <code>@mitigates</code> control urgently, or <code>@accepts</code> with explicit risk sign-off from security.</div></div>';
  } else if (type === 'exposure') {
    const e = exposuresData[idx];
    title.textContent = e.threat;
    const status = e.mitigated ? 'MITIGATED' : e.accepted ? 'ACCEPTED' : 'OPEN';
    const color = e.mitigated ? 'var(--green)' : e.accepted ? 'var(--sev-low)' : 'var(--red)';
    h += sec('Status', '<span style="color:' + color + ';font-weight:600">' + status + '</span>');
    h += sec('Severity', '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>');
    h += sec('Asset', '<code>' + esc(e.asset) + '</code>');
    if (e.description) h += sec('Description', esc(e.description));
    h += sec('Location', '<span style="font-family:var(--font-mono);font-size:.78rem;color:var(--muted)">' + esc(e.file) + ':' + e.line + '</span>');
  } else if (type === 'asset') {
    const a = heatmapData[idx];
    title.textContent = a.name + ' (Asset)';
    
    // Risk level banner
    const riskColors = { critical: 'var(--sev-crit)', high: 'var(--sev-high)', medium: 'var(--sev-med)', low: 'var(--sev-low)', none: 'var(--border)' };
    const rColor = riskColors[a.riskLevel] || 'var(--border)';
    h += sec('Risk Level', '<span style="color:' + rColor + ';font-weight:600;text-transform:uppercase">' + a.riskLevel + '</span>');
    
    // Stats
    h += '<div style="display:flex;gap:1rem;margin-bottom:1rem">';
    h += '<div style="flex:1">' + sec('Exposures', '<span style="font-size:1.1rem;font-weight:600;color:var(--red)">' + a.exposures + '</span>') + '</div>';
    h += '<div style="flex:1">' + sec('Mitigations', '<span style="font-size:1.1rem;font-weight:600;color:var(--green)">' + a.mitigations + '</span>') + '</div>';
    h += '<div style="flex:1">' + sec('Data Flows', '<span style="font-size:1.1rem;font-weight:600;color:var(--blue)">' + a.flows + '</span>') + '</div>';
    h += '</div>';
    
    // Data Handling
    if (a.dataHandling && a.dataHandling.length > 0) {
      h += sec('Data Handled', a.dataHandling.map(d => '<span class="ann-badge ann-data" style="margin-right:4px">' + esc(d) + '</span>').join(''));
    }
    
    // Find related open exposures to show in the drawer
    const openForAsset = analysisData.openExposures.filter(e => e.asset === a.name);
    if (openForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--red);margin-top:1.5rem">Open Threats</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      openForAsset.forEach(e => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--red);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(e.threat) + '</strong>';
        h += '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>';
        h += '</div>';
        if (e.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(e.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(e.file) + ':' + e.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related mitigated exposures
    const mitigatedForAsset = analysisData.mitigatedExposures.filter(e => e.asset === a.name);
    if (mitigatedForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--green);margin-top:1.5rem">Mitigated Threats</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      mitigatedForAsset.forEach(e => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--green);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(e.threat) + '</strong>';
        h += '<span class="fc-sev ' + sevCls(e.severity) + '">' + esc(e.severity) + '</span>';
        h += '</div>';
        if (e.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(e.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(e.file) + ':' + e.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Data Flows
    const flowsForAsset = threatModel.flows.filter(f => f.source === a.name || f.target === a.name);
    if (flowsForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--blue);margin-top:1.5rem">Data Flows</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      flowsForAsset.forEach(f => {
        const isSource = f.source === a.name;
        const icon = isSource ? '<span style="color:var(--blue)">→</span>' : '<span style="color:var(--orange)">←</span>';
        const partner = isSource ? f.target : f.source;
        const desc = isSource ? 'Sends data to' : 'Receives data from';
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px;font-size:0.8rem">';
        h += '<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.2rem">';
        h += icon + ' <span style="color:var(--muted)">' + desc + '</span> <strong>' + esc(partner) + '</strong>';
        h += '</div>';
        if (f.mechanism) h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted)">via ' + esc(f.mechanism) + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Boundaries
    const boundariesForAsset = threatModel.boundaries.filter(b => b.asset_a === a.name || b.asset_b === a.name);
    if (boundariesForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--purple);margin-top:1.5rem">Trust Boundaries</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      boundariesForAsset.forEach(b => {
        const partner = b.asset_a === a.name ? b.asset_b : b.asset_a;
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px;font-size:0.8rem">';
        h += '<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.2rem">';
        h += '<span style="color:var(--purple)">↔</span> <span style="color:var(--muted)">Boundary with</span> <strong>' + esc(partner) + '</strong>';
        h += '</div>';
        if (b.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(b.description) + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Acceptances
    const acceptedForAsset = threatModel.acceptances.filter(ac => ac.asset === a.name);
    if (acceptedForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--yellow);margin-top:1.5rem">Accepted Risks</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      acceptedForAsset.forEach(ac => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--yellow);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(ac.threat) + '</strong>';
        h += '</div>';
        if (ac.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(ac.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(ac.location.file) + ':' + ac.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
    
    // Find related Transfers
    const transferredForAsset = threatModel.transfers.filter(t => t.source === a.name || t.target === a.name);
    if (transferredForAsset.length > 0) {
      h += '<div class="sub-h" style="color:var(--purple);margin-top:1.5rem">Transferred Risks</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      transferredForAsset.forEach(t => {
        const isSource = t.source === a.name;
        h += '<div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--purple);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem">';
        h += '<strong>' + esc(t.threat) + '</strong>';
        if (isSource) {
          h += '<span style="font-size:0.75rem;color:var(--muted)">Transferred to <strong>' + esc(t.target) + '</strong></span>';
        } else {
          h += '<span style="font-size:0.75rem;color:var(--muted)">Transferred from <strong>' + esc(t.source) + '</strong></span>';
        }
        h += '</div>';
        if (t.description) h += '<div style="font-size:0.75rem;color:var(--muted)">' + esc(t.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(t.location.file) + ':' + t.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    // Additional asset lifecycle details
    const validations = threatModel.validations.filter(v => v.asset === a.name);
    if (validations.length > 0) {
      h += '<div class="sub-h" style="color:var(--green);margin-top:1.5rem">Validations</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      validations.forEach(v => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<strong>' + esc(v.control) + '</strong>';
        if (v.description) h += '<div style="font-size:0.75rem;color:var(--muted);margin-top:0.2rem">' + esc(v.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(v.location.file) + ':' + v.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    const ownership = threatModel.ownership.filter(o => o.asset === a.name);
    if (ownership.length > 0) {
      h += '<div class="sub-h" style="color:var(--blue);margin-top:1.5rem">Ownership</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      ownership.forEach(o => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += 'Owned by <strong>' + esc(o.owner) + '</strong>';
        if (o.description) h += '<div style="font-size:0.75rem;color:var(--muted);margin-top:0.2rem">' + esc(o.description) + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(o.location.file) + ':' + o.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    const assumptions = threatModel.assumptions.filter(asm => asm.asset === a.name);
    if (assumptions.length > 0) {
      h += '<div class="sub-h" style="color:var(--yellow);margin-top:1.5rem">Assumptions</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      assumptions.forEach(asm => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="font-size:0.75rem">' + esc(asm.description || 'Assumed risk or state without description') + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(asm.location.file) + ':' + asm.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    const audits = threatModel.audits.filter(au => au.asset === a.name);
    if (audits.length > 0) {
      h += '<div class="sub-h" style="color:var(--accent);margin-top:1.5rem">Audits</div>';
      h += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
      audits.forEach(au => {
        h += '<div style="background:var(--surface2);border:1px solid var(--border);padding:0.5rem 0.8rem;border-radius:4px">';
        h += '<div style="font-size:0.75rem">' + esc(au.description || 'Audit trail point') + '</div>';
        h += '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--muted);margin-top:0.3rem">' + esc(au.location.file) + ':' + au.location.line + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }
  }

  body.innerHTML = h;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
}


`;
