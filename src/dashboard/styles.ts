/**
 * GuardLink Dashboard — stylesheet.
 *
 * BASE_CSS is the sheet the dashboard shipped with (tokens, layout, drawer,
 * diagrams, code cards, heatmap, markdown). UPGRADE_CSS layers the new
 * components on top and tightens type and spacing; it is appended after, so
 * its rules win where they overlap.
 *
 * @comment -- "Static CSS only; nothing here interpolates model data"
 */
export const BASE_CSS = `
/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
*::selection { background: color-mix(in oklab, var(--accent) 35%, transparent); color: var(--text); }
:root {
  --font-ui: 'Helvetica Neue', Helvetica, Arial, system-ui, sans-serif;
  --font-mono: 'Monoska', 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  --ease: cubic-bezier(.2,.8,.2,1);
  --radius-sm: 6px; --radius-md: 8px; --radius-lg: 12px;
  --drawer-w: 440px; --sidebar-w: 220px;
}

/* ══ DARK THEME — Modern deep-slate ══ */
[data-theme="dark"] {
  --bg: #000000;
  --bg-gradient: radial-gradient(ellipse 1000px 500px at 15% 0%, rgba(51,212,157,.08), transparent 58%),
                 radial-gradient(ellipse 800px 400px at 95% 10%, rgba(26,152,208,.08), transparent 60%);
  --surface: #0c171c;
  --surface2: #142329;
  --surface3: #1f3943;
  --border: #1f3943;
  --border-subtle: #182a31;
  --border-strong: #3b6779;

  --text: #f0f0f0;
  --muted: color-mix(in oklab, #55899e 55%, #f0f0f0);
  --text-dim: color-mix(in oklab, #55899e 85%, #f0f0f0);

  --accent: #33d49d;
  --accent-soft: rgba(51,212,157,.12);
  --accent-dim: rgba(51,212,157,.30);
  --accent-hover: #ffffff;

  --blue: #1a98d0;
  --green: #33d49d;
  --green-text: #33d49d;
  --red: #ea1d1d;
  --orange: #ea1d1d;
  --yellow: #1a98d0;
  --purple: #1a98d0;

  --sev-crit: #ea1d1d;
  --sev-high: #ea1d1d;
  --sev-med:  #1a98d0;
  --sev-low:  color-mix(in oklab, #55899e 70%, #f0f0f0);
  --sev-unset: #3b6779;

  --sev-crit-bg: rgba(234,29,29,.16);
  --sev-high-bg: rgba(234,29,29,.10);
  --sev-med-bg:  rgba(26,152,208,.16);
  --sev-low-bg:  rgba(85,137,158,.18);

  --badge-red-bg:   rgba(234,29,29,.18);
  --badge-green-bg: rgba(51,212,157,.16);
  --badge-blue-bg:  rgba(26,152,208,.18);
  --badge-red-fg:   #f0f0f0;
  --badge-green-fg: #33d49d;
  --badge-blue-fg:  #f0f0f0;

  --risk-f: linear-gradient(135deg, rgba(234,29,29,.22), rgba(234,29,29,.05));
  --risk-d: linear-gradient(135deg, rgba(234,29,29,.14), rgba(234,29,29,.04));
  --risk-c: linear-gradient(135deg, rgba(26,152,208,.18), rgba(26,152,208,.05));
  --risk-b: linear-gradient(135deg, rgba(3,96,162,.18), rgba(3,96,162,.05));
  --risk-a: linear-gradient(135deg, rgba(51,212,157,.20), rgba(51,212,157,.05));
  --risk-border-f: rgba(234,29,29,.45);
  --risk-border-d: rgba(234,29,29,.30);
  --risk-border-c: rgba(26,152,208,.35);
  --risk-border-b: rgba(3,96,162,.35);
  --risk-border-a: rgba(51,212,157,.35);

  --heatmap-crit: linear-gradient(135deg, rgba(234,29,29,.22), rgba(234,29,29,.06));
  --heatmap-high: linear-gradient(135deg, rgba(234,29,29,.14), rgba(234,29,29,.04));
  --heatmap-med:  linear-gradient(135deg, rgba(26,152,208,.16), rgba(26,152,208,.04));
  --heatmap-low:  linear-gradient(135deg, rgba(85,137,158,.16), rgba(85,137,158,.04));
  --heatmap-none: #142329;

  --table-alt: #10202a;
  --table-hover: #1a2f37;
  --shadow-sm: 0 1px 2px rgba(0,0,0,.3);
  --shadow-md: 0 4px 12px rgba(0,0,0,.35), 0 1px 2px rgba(0,0,0,.4);
  --shadow-lg: 0 12px 32px rgba(0,0,0,.45), 0 2px 6px rgba(0,0,0,.4);
  --glow-accent: 0 0 0 1px rgba(51,212,157,.25), 0 8px 24px rgba(51,212,157,.12);

  --logo-bg: linear-gradient(135deg, #33d49d, #0360a2);
  --logo-text: #000000;
}

/* ══ LIGHT THEME — Refined off-white ══ */
[data-theme="light"] {
  --bg: #f0f0f0;
  --bg-gradient: radial-gradient(ellipse 1000px 500px at 15% 0%, rgba(51,212,157,.12), transparent 58%),
                 radial-gradient(ellipse 800px 400px at 95% 10%, rgba(26,152,208,.10), transparent 60%);
  --surface: #ffffff;
  --surface2: #f5f7f8;
  --surface3: #e5edf0;
  --border: color-mix(in oklab, #55899e 32%, #ffffff);
  --border-subtle: color-mix(in oklab, #55899e 18%, #ffffff);
  --border-strong: #55899e;

  --text: #1f3943;
  --muted: #3b6779;
  --text-dim: #55899e;

  --accent: #0360a2;
  --accent-soft: rgba(3,96,162,.08);
  --accent-dim: rgba(3,96,162,.24);
  --accent-hover: #1a98d0;

  --blue: #0360a2;
  --green: #33d49d;
  --green-text: color-mix(in oklab, #33d49d 62%, #000000);
  --red: #ea1d1d;
  --orange: #ea1d1d;
  --yellow: #0360a2;
  --purple: #0360a2;

  --sev-crit: #ea1d1d;
  --sev-high: #ea1d1d;
  --sev-med:  #0360a2;
  --sev-low:  #3b6779;
  --sev-unset: #55899e;

  --sev-crit-bg: rgba(234,29,29,.10);
  --sev-high-bg: rgba(234,29,29,.07);
  --sev-med-bg:  rgba(3,96,162,.09);
  --sev-low-bg:  rgba(59,103,121,.10);

  --badge-red-bg:   rgba(234,29,29,.10);
  --badge-green-bg: rgba(51,212,157,.18);
  --badge-blue-bg:  rgba(3,96,162,.10);
  --badge-red-fg:   #ea1d1d;
  --badge-green-fg: #1f3943;
  --badge-blue-fg:  #0360a2;

  --risk-f: linear-gradient(135deg, rgba(234,29,29,.12), rgba(234,29,29,.03));
  --risk-d: linear-gradient(135deg, rgba(234,29,29,.09), rgba(234,29,29,.02));
  --risk-c: linear-gradient(135deg, rgba(3,96,162,.10), rgba(3,96,162,.03));
  --risk-b: linear-gradient(135deg, rgba(26,152,208,.12), rgba(26,152,208,.03));
  --risk-a: linear-gradient(135deg, rgba(51,212,157,.16), rgba(51,212,157,.04));
  --risk-border-f: rgba(234,29,29,.35);
  --risk-border-d: rgba(234,29,29,.25);
  --risk-border-c: rgba(3,96,162,.30);
  --risk-border-b: rgba(26,152,208,.30);
  --risk-border-a: rgba(51,212,157,.40);

  --heatmap-crit: linear-gradient(135deg, rgba(234,29,29,.12), rgba(234,29,29,.03));
  --heatmap-high: linear-gradient(135deg, rgba(234,29,29,.08), rgba(234,29,29,.02));
  --heatmap-med:  linear-gradient(135deg, rgba(3,96,162,.10), rgba(3,96,162,.03));
  --heatmap-low:  linear-gradient(135deg, rgba(85,137,158,.12), rgba(85,137,158,.03));
  --heatmap-none: #f5f7f8;

  --table-alt: #f7f9fa;
  --table-hover: #eaf1f4;
  --shadow-sm: 0 1px 2px rgba(31,57,67,.06);
  --shadow-md: 0 4px 12px rgba(31,57,67,.08), 0 1px 2px rgba(31,57,67,.06);
  --shadow-lg: 0 12px 32px rgba(31,57,67,.12), 0 2px 6px rgba(31,57,67,.08);
  --glow-accent: 0 0 0 1px rgba(3,96,162,.20), 0 8px 24px rgba(3,96,162,.10);

  --logo-bg: linear-gradient(135deg, #33d49d, #0360a2);
  --logo-text: #ffffff;
}

html, body { height: 100%; }
body {
  font-family: var(--font-ui);
  background: var(--bg-gradient), var(--bg);
  color: var(--text);
  line-height: 1.5;
  font-size: 13.5px;
  overflow: hidden;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  letter-spacing: -0.005em;
}
a { color: var(--accent); text-decoration: none; transition: color .15s var(--ease); }
a:hover { color: var(--accent-hover); }
code {
  background: var(--surface2);
  border: 1px solid var(--border-subtle);
  padding: 1px 5px;
  border-radius: 4px;
  font-size: .76rem;
  font-family: var(--font-mono);
  color: var(--text);
}
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; border: 2px solid var(--bg); }
::-webkit-scrollbar-thumb:hover { background: var(--border-strong); }

/* ── Top Nav ── */
.topnav {
  height: 52px;
  background: color-mix(in oklab, var(--surface) 92%, transparent);
  backdrop-filter: saturate(160%) blur(12px);
  -webkit-backdrop-filter: saturate(160%) blur(12px);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center;
  padding: 0 1.4rem; gap: 1rem;
  z-index: 100;
  position: relative;
}
.topnav::after {
  content: ''; position: absolute; left: 0; right: 0; bottom: -1px; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent-dim) 40%, var(--accent-dim) 60%, transparent);
  opacity: .55; pointer-events: none;
}
.topnav-left { display: flex; align-items: center; gap: .7rem; }
.topnav-right { margin-left: auto; display: flex; align-items: center; gap: .75rem; }
.topnav-metrics { display: flex; align-items: center; gap: .5rem; }
.topnav h1 { font-size: 1.02rem; font-weight: 650; white-space: nowrap; letter-spacing: -0.01em; }
.badge {
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--accent-dim);
  padding: 2px 9px; border-radius: 999px;
  font-size: .64rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: .6px;
}
.tn-stat {
  font-size: .72rem; color: var(--muted); display: flex; align-items: center; gap: 6px;
  background: color-mix(in oklab, var(--surface2) 88%, transparent);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 4px 10px;
  backdrop-filter: blur(4px);
}
.tn-stat .tn-k { letter-spacing: .2px; }
.tn-stat .tn-v { font-weight: 700; font-size: .85rem; color: var(--text); font-variant-numeric: tabular-nums; }
.tn-v.red { color: var(--sev-crit); } .tn-v.green { color: var(--green-text); }
.tn-v.blue { color: var(--accent); } .tn-v.yellow { color: var(--yellow); }
.feature-filter-wrap { display: flex; align-items: center; }
.feature-filter-select {
  max-width: 170px;
  background: var(--surface2);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 5px 10px;
  font-size: .74rem;
  font-family: var(--font-ui);
  cursor: pointer;
  transition: all .15s var(--ease);
}
.feature-filter-select:hover { border-color: var(--border-strong); background: var(--surface3); }
.feature-filter-select:focus { outline: none; border-color: var(--accent); box-shadow: var(--glow-accent); }
.logo {
  width: 34px; height: 34px;
  background: var(--logo-bg); color: var(--logo-text);
  border-radius: 9px;
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: 12px; letter-spacing: .3px;
  box-shadow: var(--shadow-sm);
}
#themeToggle {
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: 8px; padding: 5px 9px; cursor: pointer;
  font-size: 14px; line-height: 1; color: var(--text);
  transition: all .15s var(--ease);
}
#themeToggle:hover { background: var(--surface3); border-color: var(--border-strong); }
[data-theme="dark"] .icon-sun { display: none; }
[data-theme="light"] .icon-moon { display: none; }
.feature-banner {
  display: none;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: color-mix(in oklab, var(--accent) 88%, var(--surface));
  color: #fff;
  font-size: .8rem;
  font-weight: 600;
  border-bottom: 1px solid color-mix(in oklab, var(--accent) 45%, var(--border));
}
.feature-banner-files { opacity: .75; font-weight: 500; }
.feature-banner-clear {
  margin-left: auto;
  background: rgba(255,255,255,.18);
  border: 1px solid rgba(255,255,255,.28);
  color: #fff;
  padding: 4px 10px;
  border-radius: 999px;
  cursor: pointer;
  font-size: .72rem;
  font-weight: 600;
}
.feature-banner-clear:hover { background: rgba(255,255,255,.28); }

/* ── Generation-time scope (--feature) ── */
.badge-scope {
  background: var(--sev-med-bg);
  color: var(--text);
  border-color: color-mix(in oklab, var(--sev-med) 55%, transparent);
  text-transform: none; letter-spacing: .2px; font-size: .68rem;
}
.scope-banner {
  display: flex; align-items: baseline; gap: 10px;
  padding: 9px 16px;
  background: color-mix(in oklab, var(--sev-med) 22%, var(--surface));
  border-bottom: 2px solid var(--sev-med);
  font-size: .78rem; line-height: 1.45;
  color: var(--text);
}
.scope-banner-tag {
  flex: none;
  background: var(--sev-med); color: #fff;
  border-radius: 999px; padding: 2px 10px;
  font-size: .64rem; font-weight: 700;
  text-transform: uppercase; letter-spacing: .6px;
  white-space: nowrap;
}
.scope-banner code, .scope-note code { font-family: var(--font-mono); font-size: .92em; }
.scope-note {
  border-left: 3px solid var(--sev-med);
  background: color-mix(in oklab, var(--sev-med) 10%, transparent);
  padding: .5rem .7rem; margin-bottom: .8rem;
  font-size: .78rem; line-height: 1.5; color: var(--muted);
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
}
.scope-tag {
  display: inline-block; vertical-align: middle;
  background: var(--sev-med-bg); color: var(--muted);
  border: 1px solid color-mix(in oklab, var(--sev-med) 40%, transparent);
  border-radius: 999px; padding: 1px 8px; margin-left: .4rem;
  font-size: .62rem; font-weight: 600; letter-spacing: .3px;
  text-transform: none;
}

/* ── Layout ── */
.layout { display: flex; height: calc(100vh - 54px); position: relative; }
/* The scope banner sits above .layout, so the viewport-height calculation has
   to account for it or the page grows a second scrollbar. */
body.scoped .layout { height: calc(100vh - 54px - 46px); }
.sidebar {
  width: var(--sidebar-w); min-width: var(--sidebar-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  transition: width .25s var(--ease), min-width .25s var(--ease);
}
.sidebar-nav { flex: 1; overflow-y: auto; padding: .75rem .55rem; }
.sidebar.collapsed { width: 52px; min-width: 52px; }
.sidebar.collapsed .nav-text { display: none; }
.sidebar.collapsed .sep { margin: .5rem .5rem; }
.sidebar.collapsed .chevron-left { display: none; }
.sidebar.collapsed .chevron-right { display: block; }
#sidebarToggle {
  background: transparent; border: none; border-top: 1px solid var(--border);
  padding: .7rem; cursor: pointer; color: var(--muted);
  transition: all .15s var(--ease);
  display: flex; align-items: center; justify-content: center; width: 100%;
}
#sidebarToggle:hover { background: var(--surface2); color: var(--accent); }
#sidebarToggle svg { display: block; }
#sidebarToggle .chevron-right { display: none; }
.sidebar a {
  display: flex; align-items: center; gap: .65rem;
  padding: .52rem .75rem; margin: 1px .1rem;
  font-size: .8rem; color: var(--muted); cursor: pointer;
  border-radius: 7px;
  transition: background .12s var(--ease), color .12s var(--ease);
  user-select: none;
  position: relative;
}
.sidebar a:hover { background: var(--surface2); color: var(--text); }
.sidebar a.active {
  color: var(--accent);
  background: var(--accent-soft);
  font-weight: 550;
}
.sidebar a.active::before {
  content: ''; position: absolute; left: -.1rem; top: 20%; bottom: 20%; width: 2px;
  background: var(--accent); border-radius: 2px;
}
.sidebar .nav-icon { width: 18px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; opacity: .85; }
.sidebar a.active .nav-icon { opacity: 1; }
.sidebar .nav-icon svg { display: block; }
.sidebar .sep { height: 1px; background: var(--border); margin: .6rem .8rem; }
.main { flex: 1; overflow-y: auto; padding: 0; }
.section-content { display: none; padding: 1.6rem 2rem 3rem; max-width: 1400px; }
.section-content.active { display: block; animation: fadeIn .2s var(--ease); }
@keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: none; } }
.panel {
  background: color-mix(in oklab, var(--surface) 94%, transparent);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 1rem 1.1rem;
  box-shadow: var(--shadow-sm);
  margin-bottom: 1rem;
}
.panel-row { display: flex; align-items: center; gap: .8rem; margin-bottom: .35rem; }
.panel-muted { color: var(--muted); font-size: .82rem; }
.summary-panels {
  display: grid;
  grid-template-columns: minmax(250px, 1fr) minmax(320px, 1.3fr);
  gap: .9rem;
}
.ai-analysis-panel { padding-top: .9rem; }

/* ── Drawer ── */
.drawer-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,.48);
  backdrop-filter: blur(2px);
  -webkit-backdrop-filter: blur(2px);
  z-index: 200; display: none;
}
.drawer-overlay.open { display: block; animation: fadeIn .15s var(--ease); }
.drawer {
  position: fixed; top: 0; right: 0;
  width: var(--drawer-w); height: 100vh;
  background: var(--surface);
  border-left: 1px solid var(--border);
  z-index: 201;
  transform: translateX(100%);
  transition: transform .28s var(--ease);
  overflow-y: auto;
  box-shadow: var(--shadow-lg);
}
.drawer.open { transform: translateX(0); }
.drawer-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1rem 1.2rem;
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
  background: color-mix(in oklab, var(--surface) 94%, transparent);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  z-index: 1;
}
.drawer-header h3 { font-size: .95rem; color: var(--text); font-weight: 650; letter-spacing: -.01em; }
.drawer-close {
  background: var(--surface2); border: 1px solid var(--border);
  color: var(--muted); cursor: pointer;
  padding: 5px 11px; border-radius: 6px; font-size: .78rem;
  transition: all .15s var(--ease);
}
.drawer-close:hover { color: var(--text); border-color: var(--border-strong); background: var(--surface3); }
.drawer-body { padding: 1.2rem; }
.d-section { margin-bottom: 1.2rem; }
.d-label { font-size: .68rem; text-transform: uppercase; color: var(--muted); letter-spacing: .8px; margin-bottom: .35rem; font-weight: 600; }
.d-value { font-size: .85rem; }
.d-code {
  background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-md);
  padding: .65rem .8rem; font-family: var(--font-mono); font-size: .72rem;
  line-height: 1.65; color: var(--muted); white-space: pre; overflow-x: auto;
}

/* ── Section headings ── */
.sec-h {
  font-size: 1.25rem; font-weight: 700;
  margin-bottom: 1rem;
  display: flex; align-items: center; gap: .6rem;
  letter-spacing: -.02em;
}
.sec-icon {
  font-size: 1rem;
  width: 30px; height: 30px;
  display: inline-flex; align-items: center; justify-content: center;
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--accent-dim);
  border-radius: 8px;
}
.sub-h {
  font-size: .78rem; font-weight: 600; color: var(--muted);
  margin: 1.2rem 0 .55rem 0;
  text-transform: uppercase; letter-spacing: .7px;
  display: flex; align-items: center; gap: .5rem;
}
.sub-h::after {
  content: ''; flex: 1; height: 1px;
  background: linear-gradient(90deg, var(--border), transparent);
}
.sub-h-alert { color: var(--red); }
.sub-h-critical { color: var(--sev-crit); }
.sub-h-ok { color: var(--green-text); }
.sub-h-neutral { color: var(--yellow); }
.sub-h-info { color: var(--blue); }
.section-note { color: var(--muted); font-size: .78rem; margin-bottom: .55rem; }
.flow-arrow { color: var(--muted); font-weight: 700; font-size: .88rem; text-align: center; }

/* ── Stats Grid ── */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(118px, 1fr)); gap: .6rem; margin-bottom: 1.2rem; }
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: .75rem .7rem;
  text-align: center;
  transition: transform .15s var(--ease), border-color .15s var(--ease), box-shadow .15s var(--ease);
  position: relative; overflow: hidden;
}
.stat-card::before {
  content: ''; position: absolute; inset: 0 0 auto 0; height: 2px;
  background: var(--accent); opacity: 0; transition: opacity .15s var(--ease);
}
.stat-card:hover { transform: translateY(-1px); border-color: var(--border-strong); box-shadow: var(--shadow-sm); }
.stat-card:hover::before { opacity: .8; }
.stat-card .value { font-size: 1.5rem; font-weight: 700; color: var(--accent); font-variant-numeric: tabular-nums; letter-spacing: -.02em; line-height: 1.1; }
.stat-card .label { font-size: .68rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .4px; font-weight: 500; }
.stat-danger .value { color: var(--sev-crit); } .stat-danger::before { background: var(--sev-crit); }
.stat-success .value { color: var(--green-text); } .stat-success::before { background: var(--green); }
.stat-muted .value { color: var(--muted); } .stat-muted::before { background: var(--muted); }
.stat-muted .label { color: var(--text-dim); }

/* ── Risk Banner ── */
.risk-banner {
  display: flex; align-items: center; gap: 22px;
  padding: 18px 22px;
  border-radius: var(--radius-lg);
  border: 1px solid var(--border);
  margin-bottom: 1.2rem;
  box-shadow: var(--shadow-sm);
}
.risk-grade {
  font-size: 34px; font-weight: 800;
  width: 58px; height: 58px;
  display: flex; align-items: center; justify-content: center;
  border-radius: var(--radius-md);
  letter-spacing: -.03em;
  box-shadow: 0 6px 16px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.15);
}
.risk-detail { display: flex; flex-direction: column; gap: 3px; }
.risk-detail strong { font-size: 15px; font-weight: 650; letter-spacing: -.01em; }
.risk-detail span { font-size: 13px; color: var(--muted); }
.risk-f { background: var(--risk-f); border-color: var(--risk-border-f); } .risk-f .risk-grade { background: var(--sev-crit); color: #fff; }
.risk-d { background: var(--risk-d); border-color: var(--risk-border-d); } .risk-d .risk-grade { background: var(--sev-high); color: #fff; }
.risk-c { background: var(--risk-c); border-color: var(--risk-border-c); } .risk-c .risk-grade { background: var(--sev-med); color: #fff; }
.risk-b { background: var(--risk-b); border-color: var(--risk-border-b); } .risk-b .risk-grade { background: var(--sev-low); color: #fff; }
.risk-a { background: var(--risk-a); border-color: var(--risk-border-a); } .risk-a .risk-grade { background: var(--green); color: #fff; }

/* ── Coverage Bar ── */
.coverage-pct { font-size: 2rem; font-weight: 700; font-variant-numeric: tabular-nums; letter-spacing: -.03em; }
.coverage-pct.good { color: var(--green-text); } .coverage-pct.warn { color: var(--yellow); } .coverage-pct.bad { color: var(--sev-crit); }
.posture-bar { height: 10px; border-radius: 999px; background: var(--surface2); margin: .7rem 0; overflow: hidden; border: 1px solid var(--border-subtle); }
.posture-fill { height: 100%; border-radius: 999px; transition: width .6s var(--ease); }
.posture-fill.good { background: linear-gradient(90deg, var(--green), var(--accent)); }
.posture-fill.warn { background: linear-gradient(90deg, var(--yellow), var(--muted)); }
.posture-fill.bad  { background: linear-gradient(90deg, var(--sev-crit), var(--red)); }

/* ── Severity Chart ── */
.severity-chart { display: flex; flex-direction: column; gap: 9px; margin-bottom: 1rem; }
.sev-row { display: flex; align-items: center; gap: 12px; }
.sev-label { width: 62px; font-size: 12.5px; font-weight: 550; text-align: right; color: var(--muted); }
.sev-track { flex: 1; height: 22px; background: var(--surface2); border-radius: 6px; overflow: hidden; border: 1px solid var(--border-subtle); }
.sev-fill { height: 100%; border-radius: 6px; min-width: 2px; transition: width .6s var(--ease); }
.sev-fill-crit { background: linear-gradient(90deg, var(--sev-crit), var(--red)); }
.sev-fill-high { background: linear-gradient(90deg, var(--sev-high), var(--red)); }
.sev-fill-med  { background: linear-gradient(90deg, var(--sev-med), var(--text-dim)); }
.sev-fill-low  { background: linear-gradient(90deg, var(--sev-low), var(--blue)); }
.sev-fill-unset { background: var(--sev-unset); }
.attr-track { height: 10px; }
.attr-fill { background: linear-gradient(90deg, var(--accent), var(--blue)); }
th.attr-bar, td.attr-bar { width: 22%; min-width: 120px; }
.attr-ai { margin-top: 3px; display: flex; flex-wrap: wrap; gap: 3px; }
.sev-count { width: 32px; font-size: 14px; font-weight: 700; font-family: var(--font-mono); color: var(--text); font-variant-numeric: tabular-nums; }

/* ── Finding Cards ── */
.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: .8rem 1rem;
  margin-bottom: .55rem;
  cursor: pointer;
  transition: all .15s var(--ease);
  position: relative;
}
.finding-card::before {
  content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--sev-crit); border-radius: 3px 0 0 3px;
  opacity: .7;
}
.finding-card:hover {
  border-color: var(--border-strong);
  transform: translateX(2px);
  box-shadow: var(--shadow-sm);
}
.fc-top { display: flex; align-items: center; gap: .55rem; margin-bottom: .25rem; }
.fc-risk { font-weight: 600; font-size: .88rem; letter-spacing: -.005em; }
.fc-desc { font-size: .8rem; color: var(--muted); line-height: 1.5; }
.fc-assets { font-size: .72rem; color: var(--muted); margin-top: .3rem; font-family: var(--font-mono); }
.fc-sev {
  font-size: .66rem;
  padding: 2px 8px;
  border-radius: 999px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .4px;
  border: 1px solid transparent;
}
.fc-sev.crit  { background: var(--sev-crit-bg); color: var(--sev-crit); border-color: color-mix(in oklab, var(--sev-crit) 35%, transparent); }
.fc-sev.high  { background: var(--sev-high-bg); color: var(--sev-high); border-color: color-mix(in oklab, var(--sev-high) 35%, transparent); }
.fc-sev.med   { background: var(--sev-med-bg);  color: var(--sev-med);  border-color: color-mix(in oklab, var(--sev-med) 35%, transparent); }
.fc-sev.low   { background: var(--sev-low-bg);  color: var(--sev-low);  border-color: color-mix(in oklab, var(--sev-low) 35%, transparent); }
.fc-sev.unset { background: var(--surface2);    color: var(--muted);    border-color: var(--border); }

/* ── Tables ── */
table {
  width: 100%; border-collapse: separate; border-spacing: 0;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
  margin-bottom: 1rem;
  box-shadow: var(--shadow-sm);
}
th, td { padding: .6rem .85rem; text-align: left; border-bottom: 1px solid var(--border-subtle); font-size: .8rem; }
tr:last-child td { border-bottom: none; }
th {
  background: var(--surface2);
  color: var(--muted); font-weight: 650;
  text-transform: uppercase; font-size: .66rem; letter-spacing: .7px;
  position: sticky; top: 0;
}
tbody tr { transition: background .12s var(--ease); }
tbody tr:nth-child(even) { background: var(--table-alt); }
tr.clickable { cursor: pointer; }
tr.clickable:hover { background: var(--table-hover); }
.row-open { box-shadow: inset 3px 0 0 var(--sev-crit); }
.loc { color: var(--muted); font-family: var(--font-mono); font-size: .72rem; white-space: nowrap; }
.empty-state {
  color: var(--muted); font-style: italic;
  padding: 1.2rem;
  font-size: .82rem; text-align: center;
  background: var(--surface); border: 1px dashed var(--border);
  border-radius: var(--radius-md);
}

/* ── Badges ── */
.badge-red, .badge-green, .badge-blue {
  display: inline-block; padding: 2px 9px;
  border-radius: 999px;
  font-size: .66rem; font-weight: 650;
  text-transform: uppercase; letter-spacing: .4px;
  border: 1px solid transparent;
}
.badge-red   { background: var(--badge-red-bg);   color: var(--badge-red-fg);   border-color: color-mix(in oklab, var(--sev-crit) 25%, transparent); }
.badge-green { background: var(--badge-green-bg); color: var(--badge-green-fg); border-color: color-mix(in oklab, var(--green) 25%, transparent); }
.badge-blue  { background: var(--badge-blue-bg);  color: var(--badge-blue-fg);  border-color: color-mix(in oklab, var(--sev-low) 25%, transparent); }

/* ── Annotation badges (theme-aware) ── */
.ann-badge {
  display: inline-block; padding: 2px 8px;
  border-radius: 5px;
  font-size: .66rem; font-weight: 650;
  text-transform: uppercase; letter-spacing: .35px;
  border: 1px solid transparent;
}
.ann-asset    { background: rgba(3,96,162,.14);    color: #f0f0f0; border-color: rgba(3,96,162,.3); }
.ann-threat   { background: rgba(234,29,29,.14);   color: #f0f0f0; border-color: rgba(234,29,29,.3); }
.ann-control  { background: rgba(51,212,157,.14);  color: #33d49d; border-color: rgba(51,212,157,.3); }
.ann-exposes  { background: rgba(234,29,29,.14);   color: #f0f0f0; border-color: rgba(234,29,29,.3); }
.ann-mitigates{ background: rgba(51,212,157,.14);  color: #33d49d; border-color: rgba(51,212,157,.3); }
.ann-accepts  { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-transfers{ background: rgba(59,103,121,.18);  color: #f0f0f0; border-color: rgba(59,103,121,.3); }
.ann-flow     { background: var(--surface2);       color: var(--muted); border-color: var(--border); }
.ann-boundary { background: rgba(59,103,121,.18);  color: #f0f0f0; border-color: rgba(59,103,121,.3); }
.ann-data     { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-handles  { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-validates{ background: rgba(51,212,157,.14);  color: #33d49d; border-color: rgba(51,212,157,.3); }
.ann-owns     { background: rgba(3,96,162,.14);    color: #f0f0f0; border-color: rgba(3,96,162,.3); }
.ann-audit    { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-assumes  { background: rgba(85,137,158,.16);  color: #f0f0f0; border-color: rgba(85,137,158,.3); }
.ann-shield   { background: var(--surface2);       color: var(--muted); border-color: var(--border); }
.ann-comment  { background: var(--surface2);       color: var(--muted); border: 1px solid var(--border); }
[data-theme="light"] .ann-asset    { color: #0360a2; background: rgba(3,96,162,.10); border-color: rgba(3,96,162,.25); }
[data-theme="light"] .ann-threat,
[data-theme="light"] .ann-exposes  { color: #ea1d1d; background: rgba(234,29,29,.10); border-color: rgba(234,29,29,.25); }
[data-theme="light"] .ann-control,
[data-theme="light"] .ann-mitigates,
[data-theme="light"] .ann-validates{ color: #1f3943; background: rgba(51,212,157,.16); border-color: rgba(51,212,157,.25); }
[data-theme="light"] .ann-accepts,
[data-theme="light"] .ann-audit,
[data-theme="light"] .ann-assumes  { color: #3b6779; background: rgba(85,137,158,.14); border-color: rgba(85,137,158,.25); }
[data-theme="light"] .ann-transfers,
[data-theme="light"] .ann-boundary { color: #1f3943; background: rgba(59,103,121,.12); border-color: rgba(59,103,121,.25); }
[data-theme="light"] .ann-data,
[data-theme="light"] .ann-handles  { color: #3b6779; background: rgba(85,137,158,.14); border-color: rgba(85,137,158,.25); }
[data-theme="light"] .ann-owns     { color: #0360a2; background: rgba(3,96,162,.10); border-color: rgba(3,96,162,.25); }

/* ── File Cards (Code Browser) ── */
.file-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: .7rem;
  overflow: hidden;
  transition: border-color .15s var(--ease);
}
.file-card:hover { border-color: var(--border-strong); }
.file-card-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: .65rem .9rem;
  background: var(--surface2);
  cursor: pointer; user-select: none;
  transition: background .12s var(--ease);
}
.file-card-header:hover { background: var(--surface3); }
.file-path { font-family: var(--font-mono); font-size: .78rem; color: var(--accent); font-weight: 600; }
.file-count {
  font-size: .68rem; color: var(--muted);
  background: var(--surface); border: 1px solid var(--border);
  padding: 2px 9px; border-radius: 999px; font-weight: 600;
}
.chevron { color: var(--muted); transition: transform .2s var(--ease); font-size: .75rem; }
.file-card-header.open .chevron { transform: rotate(90deg); }
.file-card-body { display: none; border-top: 1px solid var(--border); }
.file-card-body.open { display: block; animation: fadeIn .2s var(--ease); }
.ann-entry {
  padding: .7rem .9rem;
  border-bottom: 1px solid var(--border-subtle);
  cursor: pointer;
  transition: background .1s var(--ease);
}
.ann-entry:hover { background: var(--accent-soft); }
.ann-entry:last-child { border-bottom: none; }
.ann-header { display: flex; align-items: center; gap: .5rem; margin-bottom: .25rem; }
.ann-line { font-family: var(--font-mono); font-size: .68rem; color: var(--muted); min-width: 38px; }
.ann-summary { font-size: .8rem; font-weight: 550; }
.ann-desc {
  font-size: .76rem; color: var(--muted);
  margin: .2rem 0 .3rem 0;
  padding-left: .6rem; border-left: 2px solid var(--border);
}

/* ── Diagrams ── */
.diagram-hint { font-size: .78rem; color: var(--muted); margin-bottom: .7rem; }
.diagram-shell {
  background: color-mix(in oklab, var(--surface) 92%, transparent);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
  margin-bottom: 1rem;
}
.diagram-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: .8rem;
  padding: .65rem .8rem;
  border-bottom: 1px solid var(--border);
  background: color-mix(in oklab, var(--surface2) 92%, transparent);
}
.diagram-title {
  font-size: .8rem;
  font-weight: 650;
  letter-spacing: .3px;
  color: var(--text);
  text-transform: uppercase;
}
.diagram-actions { display: flex; align-items: center; gap: .35rem; }
.diagram-btn {
  min-width: 28px;
  height: 28px;
  border-radius: 7px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  font-size: .78rem;
  font-weight: 650;
  cursor: pointer;
  transition: all .15s var(--ease);
}
.diagram-btn:hover { border-color: var(--border-strong); background: var(--surface3); }
.diagram-meta {
  padding: .55rem .8rem;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: .74rem;
}
.mermaid-wrap {
  background: var(--surface);
  border: none;
  border-radius: 0;
  padding: 16px 18px;
  overflow: auto;
  margin-bottom: 0;
  box-shadow: none;
}
/* The render budget said this diagram would not draw. Styled to read as a
   notice and not as a diagram: the failure it replaces was one pink box that
   looked exactly like a rendered graph. */
.diagram-budget {
  border: 1px solid var(--danger, #ea1d1d);
  border-left-width: 3px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--danger, #ea1d1d) 8%, var(--surface));
  padding: .7rem .9rem;
  margin: 0 0 14px;
  font-size: .78rem;
  color: var(--text);
  max-width: 82ch;
}
.diagram-budget strong { display: block; margin-bottom: .35rem; }
.diagram-budget ul { margin: 0 0 .5rem; padding-left: 1.1rem; }
.diagram-budget li { margin-bottom: .2rem; }
.diagram-budget p { margin: 0; color: var(--muted); }
/* The client-side backstop, when mermaid.run throws despite the budget. */
.diagram-render-failed {
  display: block;
  white-space: normal;
  color: var(--danger, #ea1d1d);
  font-size: .8rem;
  max-width: 82ch;
}
.mermaid { text-align: left; width: max-content; min-width: 100%; }
.mermaid svg { max-width: none; height: auto; display: block; }
.mermaid svg .cluster rect,
.mermaid svg .cluster polygon {
  rx: 10;
  ry: 10;
  stroke-dasharray: 4 3;
  stroke-opacity: .72;
}
.mermaid svg .cluster-label .nodeLabel,
.mermaid svg .cluster .cluster-label text {
  font-weight: 700 !important;
  letter-spacing: .3px;
}
.mermaid svg .edgeLabel { font-size: 11px !important; }
.mermaid svg .edgeLabel rect { opacity: .92; }
.mermaid svg .node rect,
.mermaid svg .node polygon,
.mermaid svg .node circle {
  filter: drop-shadow(0 2px 4px rgba(0,0,0,.18));
}
.mermaid svg path.flowchart-link {
  stroke-linecap: round;
}

/* ── Heatmap ── */
.heatmap { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }
.heatmap-cell {
  border-radius: var(--radius-md);
  padding: 14px;
  border: 1px solid var(--border);
  transition: all .15s var(--ease);
  box-shadow: var(--shadow-sm);
}
.heatmap-cell.clickable { cursor: pointer; }
.heatmap-cell.clickable:hover {
  border-color: var(--border-strong);
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}
.heatmap-name { font-weight: 650; font-size: 13px; margin-bottom: 6px; font-family: var(--font-mono); word-break: break-all; color: var(--text); }
.heatmap-stats { display: flex; gap: 12px; font-size: 12px; color: var(--muted); }
.heatmap-data { margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; }
.data-badge {
  font-size: 10px; padding: 2px 7px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--accent-dim);
  font-weight: 650; text-transform: uppercase; letter-spacing: .3px;
}
.risk-cell-critical { background: var(--heatmap-crit); border-color: var(--risk-border-f); }
.risk-cell-high     { background: var(--heatmap-high); border-color: var(--risk-border-d); }
.risk-cell-medium   { background: var(--heatmap-med);  border-color: var(--risk-border-c); }
.risk-cell-low      { background: var(--heatmap-low);  border-color: var(--risk-border-b); }
.risk-cell-none     { background: var(--heatmap-none); }

/* ── Code Blocks ── */
.code-block {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: .4rem .7rem;
  overflow-x: auto;
  margin-top: .3rem;
  font-family: var(--font-mono);
  font-size: .72rem; line-height: 1.5;
  tab-size: 2;
}
.code-line-code { display: block; color: var(--muted); white-space: pre; }
.code-line-ann {
  display: block; color: var(--accent);
  background: var(--accent-soft);
  margin: 0 -.7rem; padding: 0 .7rem;
  border-left: 2px solid var(--accent);
  white-space: pre;
}

/* ── Diagram Tabs ── */
.diagram-tabs { display: flex; gap: .25rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; padding: 0 .2rem; }
.diagram-tab {
  background: none; border: none; border-bottom: 2px solid transparent;
  padding: .55rem 1rem; color: var(--muted);
  font-size: .82rem; font-weight: 550;
  cursor: pointer; font-family: var(--font-ui);
  transition: all .15s var(--ease);
  border-radius: 6px 6px 0 0;
}
.diagram-tab:hover { color: var(--text); background: var(--surface2); }
.diagram-tab.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
  background: var(--accent-soft);
}
.diagram-panel { display: none; } .diagram-panel.active { display: block; }

/* ── AI Analysis Controls ── */
.ai-analysis-controls { display: flex; align-items: center; gap: .85rem; margin: .75rem 0 1.5rem; }
.report-selector-label { font-weight: 600; font-size: .85rem; color: var(--text); }
.report-selector {
  flex: 1; max-width: 600px;
  padding: .55rem .85rem;
  font-size: .88rem; font-family: var(--font-ui);
  background: var(--surface);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  transition: all .15s var(--ease);
  box-shadow: var(--shadow-sm);
}
.report-selector:hover { background: var(--surface2); border-color: var(--border-strong); }
.report-selector:focus {
  outline: none; border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.report-selector option { background: var(--surface); color: var(--text); padding: .5rem; }
.ai-analysis-main { margin-top: .5rem; }

/* ── Markdown content ── */
.md-content h1 { font-size: 1.5rem; font-weight: 700; margin: 1.3rem 0 .7rem; color: var(--text); letter-spacing: -.02em; }
.md-content h2 {
  font-size: 1.2rem; font-weight: 650; margin: 1.2rem 0 .6rem;
  color: var(--text); border-bottom: 1px solid var(--border);
  padding-bottom: .4rem; letter-spacing: -.01em;
}
.md-content h3 { font-size: 1.02rem; font-weight: 650; margin: 1rem 0 .45rem; color: var(--text); letter-spacing: -.01em; }
.md-content p { margin: .5rem 0; line-height: 1.65; color: var(--text); }
.md-content ul, .md-content ol { margin: .5rem 0 .5rem 1.6rem; }
.md-content li { margin: .25rem 0; line-height: 1.6; }
.md-content code { font-family: var(--font-mono); font-size: .82rem; background: var(--surface2); border: 1px solid var(--border-subtle); padding: 1px 6px; border-radius: 4px; }
.md-content pre { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-md); padding: .9rem 1rem; overflow-x: auto; margin: .8rem 0; box-shadow: var(--shadow-sm); }
.md-content pre code { background: none; padding: 0; border: none; font-size: .8rem; }
.md-content blockquote { border-left: 3px solid var(--accent); padding: .1rem 0 .1rem .9rem; margin: .7rem 0; color: var(--muted); background: var(--accent-soft); border-radius: 0 6px 6px 0; }
.md-content table { width: 100%; border-collapse: separate; border-spacing: 0; margin: .7rem 0; font-size: .82rem; border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }
.md-content th, .md-content td { padding: .5rem .75rem; border-bottom: 1px solid var(--border-subtle); text-align: left; }
.md-content tr:last-child td { border-bottom: none; }
.md-content th { background: var(--surface2); font-weight: 650; color: var(--muted); text-transform: uppercase; font-size: .68rem; letter-spacing: .5px; }
.md-content strong { color: var(--text); font-weight: 650; }

/* ── Responsive ── */
@media (max-width: 900px) {
  .section-content { padding: 1.2rem 1rem 2rem; }
  .summary-panels { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
  .sidebar { width: 52px; min-width: 52px; } .sidebar .nav-text { display: none; }
  .topnav .topnav-metrics { display: none; }
  .feature-filter-select { max-width: 130px; }
  .risk-banner { flex-direction: column; align-items: flex-start; gap: 12px; }
  :root { --drawer-w: 100vw; }
}
@media print {
  .topnav, .sidebar, #sidebarToggle, #themeToggle { display: none; }
  .main { margin: 0; } .layout { display: block; }
  body { overflow: auto; height: auto; background: #fff; color: #000; }
}
`;

/** The upgrade's components and the tightened type and spacing, layered after BASE_CSS. */
export const UPGRADE_CSS = `
/* ── rhythm ─────────────────────────────────────────────────────── */
.main { padding: 1.4rem 1.8rem 3rem; }
.sec-h { font-size: 1.15rem; font-weight: 700; letter-spacing: -.01em; margin: 0 0 .9rem; display: flex; align-items: center; gap: .6rem; }
.sec-h .sec-tools { margin-left: auto; display: flex; gap: .4rem; align-items: center; font-size: .78rem; font-weight: 500; }
.sub-h { display: flex; align-items: baseline; gap: .6rem; font-size: .72rem; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); margin: 1.4rem 0 .6rem; }
.sub-h .sub-h-right { margin-left: auto; letter-spacing: 0; text-transform: none; font-size: .76rem; color: var(--text-dim); }
.lead { color: var(--muted); font-size: .82rem; line-height: 1.5; margin: -.3rem 0 1rem; max-width: 72ch; }
.muted { color: var(--muted); }
th, td { padding: .5rem .7rem; font-size: .79rem; vertical-align: top; }
thead th { position: sticky; top: 0; background: var(--surface2); z-index: 1; }
table { margin-bottom: 1rem; }
tr.filtered-out { display: none !important; }
code { font-size: .74rem; }

/* ── KPIs ───────────────────────────────────────────────────────── */
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .6rem; margin: 0 0 1.2rem; }
.kpi { display: flex; flex-direction: column; gap: 2px; padding: .8rem .9rem; background: var(--surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); text-decoration: none; color: inherit; transition: border-color .15s var(--ease), transform .15s var(--ease); }
.kpi:hover { border-color: var(--border-strong); transform: translateY(-1px); }
.kpi-v { font-size: 1.55rem; font-weight: 700; letter-spacing: -.02em; line-height: 1.1; font-variant-numeric: tabular-nums; color: var(--text); }
.kpi-l { font-size: .68rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); font-weight: 600; }
.kpi-h { font-size: .72rem; color: var(--text-dim); margin-top: 2px; }
.kpi-danger .kpi-v { color: var(--red); }
.kpi-success .kpi-v { color: var(--green-text); }
.kpi-warn .kpi-v { color: var(--yellow); }
.kpi-muted .kpi-v { color: var(--muted); }
.stat-link { text-decoration: none; color: inherit; display: block; }
.stats-grid.inventory { grid-template-columns: repeat(auto-fill, minmax(112px, 1fr)); gap: .45rem; margin-bottom: 1rem; }
.inventory .stat-card { padding: .55rem .7rem; }
.inventory .stat-card .value { font-size: 1.1rem; }
.inventory .stat-card .label { font-size: .62rem; margin-top: 2px; }
.summary-grid { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: .9rem; margin-bottom: 1rem; }
@media (max-width: 1100px) { .summary-grid { grid-template-columns: minmax(0, 1fr); } }
.summary-panels { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: .9rem; margin-bottom: 1rem; }
.panel { padding: .9rem 1rem; }
.panel .sub-h { margin-top: 0; }
.risk-banner { margin-bottom: 1rem; padding: .9rem 1.1rem; }
.risk-banner .risk-grade { width: 52px; height: 52px; font-size: 1.7rem; }
.risk-tagline { margin-left: auto; font-size: .76rem; color: var(--muted); max-width: 34ch; text-align: right; }

/* ── actions ────────────────────────────────────────────────────── */
.actions { display: flex; flex-direction: column; gap: .5rem; }
.action { display: grid; grid-template-columns: 10px minmax(0, 1fr) auto; gap: .7rem; align-items: start; padding: .7rem .8rem; background: var(--surface2); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); }
.action-dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 5px; background: var(--muted); }
.action-critical .action-dot { background: var(--sev-crit); box-shadow: 0 0 0 3px var(--sev-crit-bg); }
.action-high .action-dot { background: var(--sev-high); box-shadow: 0 0 0 3px var(--sev-high-bg); }
.action-medium .action-dot { background: var(--sev-med); box-shadow: 0 0 0 3px var(--sev-med-bg); }
.action-info .action-dot { background: var(--blue); box-shadow: 0 0 0 3px var(--sev-low-bg); }
.action-title { font-weight: 600; font-size: .86rem; }
.action-title a { color: inherit; text-decoration: none; border-bottom: 1px dotted var(--border-strong); }
.action-title a:hover { color: var(--accent); }
.action-detail { color: var(--muted); font-size: .76rem; line-height: 1.45; margin-top: 2px; }
.action-cmd { display: inline-flex; align-items: center; gap: .3rem; margin-top: .4rem; font-family: var(--font-mono); font-size: .7rem; color: var(--text-dim); }
.action-cmd code { padding: .15rem .4rem; background: var(--surface); border: 1px solid var(--border-subtle); border-radius: 4px; }
.action-ctas { display: flex; flex-direction: column; gap: .35rem; align-items: flex-end; }

/* ── buttons, chips, copy ───────────────────────────────────────── */
.btn { display: inline-flex; align-items: center; gap: .35rem; padding: .38rem .7rem; font: inherit; font-size: .74rem; font-weight: 600; color: var(--text); background: var(--surface2); border: 1px solid var(--border); border-radius: var(--radius-sm); cursor: pointer; text-decoration: none; white-space: nowrap; transition: border-color .15s var(--ease), background .15s var(--ease); }
.btn:hover { border-color: var(--border-strong); background: var(--surface3); }
.btn-primary { background: var(--accent-soft); border-color: var(--accent-dim); color: var(--text); }
.btn-primary:hover { background: var(--accent-dim); }
.btn-ghost { background: transparent; }
.btn[disabled] { opacity: .4; cursor: default; }
.chips { display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; margin: .2rem 0 .8rem; }
.chips .chips-label { font-size: .68rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-right: .2rem; }
.chips .sep { width: 1px; height: 18px; background: var(--border-subtle); margin: 0 .25rem; }
.chip { display: inline-flex; align-items: center; gap: .35rem; padding: .28rem .6rem; font: inherit; font-size: .72rem; font-weight: 500; color: var(--muted); background: var(--surface); border: 1px solid var(--border-subtle); border-radius: 999px; cursor: pointer; transition: all .15s var(--ease); }
.chip:hover { border-color: var(--border-strong); color: var(--text); }
.chip.active { color: var(--text); background: var(--accent-soft); border-color: var(--accent-dim); }
.chip.chip-crit.active { background: var(--sev-crit-bg); border-color: var(--sev-crit); }
.chip.chip-high.active { background: var(--sev-high-bg); border-color: var(--sev-high); }
.chip.chip-med.active { background: var(--sev-med-bg); border-color: var(--sev-med); }
.chip.chip-low.active { background: var(--sev-low-bg); border-color: var(--sev-low); }
.chip-n { font-variant-numeric: tabular-nums; color: var(--text-dim); font-size: .68rem; }
.copy { font: inherit; font-size: .72rem; line-height: 1; padding: .1rem .3rem; margin-left: .3rem; color: var(--text-dim); background: transparent; border: 1px solid transparent; border-radius: 4px; cursor: pointer; opacity: 0; transition: opacity .12s, color .12s; vertical-align: middle; }
tr:hover .copy, .d-value .copy, .action .copy, .loc:hover .copy, .file-card-header:hover .copy { opacity: 1; }
.copy:hover { color: var(--text); border-color: var(--border-subtle); background: var(--surface3); }
.copy.copied { color: var(--accent); opacity: 1; }
.loc-link, .sha { color: var(--muted); text-decoration: none; border-bottom: 1px dotted var(--border); }
.loc-link:hover, .sha:hover { color: var(--accent); border-bottom-color: var(--accent); }
.who { color: var(--text); text-decoration: none; border-bottom: 1px dotted var(--border); }
.who:hover { color: var(--accent); }
.claim-state { display: inline-block; padding: .1rem .45rem; border-radius: 999px; font-size: .64rem; font-weight: 600; letter-spacing: .03em; text-transform: uppercase; border: 1px solid transparent; }
.claim-state.verified { color: var(--badge-green-fg); background: var(--badge-green-bg); border-color: var(--accent-dim); }
.claim-state.stale { color: var(--sev-high); background: var(--sev-high-bg); border-color: var(--sev-high); }
.claim-state.unverified { color: var(--muted); background: var(--surface2); border-color: var(--border-subtle); }
.filter-status { display: flex; align-items: center; gap: .6rem; padding: .45rem .7rem; margin: 0 0 .8rem; font-size: .76rem; color: var(--text); background: var(--accent-soft); border: 1px solid var(--accent-dim); border-radius: var(--radius-sm); }
.filter-status .btn { margin-left: auto; }
.no-match { padding: .8rem; color: var(--muted); font-size: .8rem; text-align: center; border: 1px dashed var(--border-subtle); border-radius: var(--radius-sm); margin-bottom: 1rem; }
.who-filter { display: flex; align-items: center; gap: .5rem; padding: .45rem .7rem; margin: 0 0 .8rem; font-size: .78rem; background: var(--accent-soft); border: 1px solid var(--accent-dim); border-radius: var(--radius-sm); }
th[data-sort] { cursor: pointer; user-select: none; }
th[data-sort] .th-sort { all: unset; cursor: pointer; display: inline-flex; align-items: center; gap: .25rem; }
th .th-arrow::after { content: '↕'; opacity: .35; font-size: .7em; }
th.sorted-asc .th-arrow::after { content: '↑'; opacity: 1; }
th.sorted-desc .th-arrow::after { content: '↓'; opacity: 1; }

/* ── top bar search ─────────────────────────────────────────────── */
.search-wrap { position: relative; display: flex; align-items: center; }
.search-wrap input { width: 220px; padding: .38rem .7rem .38rem 1.8rem; font: inherit; font-size: .78rem; color: var(--text); background: var(--surface2); border: 1px solid var(--border-subtle); border-radius: 999px; outline: none; transition: border-color .15s, width .2s var(--ease); }
.search-wrap input:focus { border-color: var(--accent-dim); width: 280px; }
.search-wrap .search-icon { position: absolute; left: .6rem; color: var(--muted); font-size: .8rem; pointer-events: none; }
.search-wrap kbd { position: absolute; right: .55rem; font-family: var(--font-mono); font-size: .62rem; color: var(--text-dim); border: 1px solid var(--border-subtle); border-radius: 3px; padding: 0 .3rem; pointer-events: none; }
.search-wrap input:focus + kbd, .search-wrap input:not(:placeholder-shown) + kbd { display: none; }

/* ── drawer ─────────────────────────────────────────────────────── */
.d-status { display: flex; align-items: center; gap: .6rem; padding: .55rem .8rem; margin-bottom: 1rem; border-left: 3px solid var(--muted); background: var(--surface2); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
.d-status-label { font-weight: 700; font-size: .8rem; letter-spacing: .04em; text-transform: uppercase; }
.d-status-open, .d-status-confirmed { border-left-color: var(--red); } .d-status-open .d-status-label, .d-status-confirmed .d-status-label { color: var(--red); }
.d-status-mitigated { border-left-color: var(--green-text); } .d-status-mitigated .d-status-label { color: var(--green-text); }
.d-status-accepted { border-left-color: var(--blue); } .d-status-accepted .d-status-label { color: var(--blue); }
.d-status-control { border-left-color: var(--accent); } .d-status-control .d-status-label { color: var(--accent); }
.d-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 1rem; }
.d-blame { margin: .6rem 0 1rem; padding: .7rem .8rem; background: var(--surface2); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); }
.d-blame .d-label { margin-bottom: .4rem; }
.d-blame-row { display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: .5rem; font-size: .76rem; padding: .25rem 0; align-items: baseline; }
.d-blame-row > span:first-child { color: var(--muted); font-size: .68rem; text-transform: uppercase; letter-spacing: .04em; }
.d-actions { display: flex; flex-wrap: wrap; gap: .4rem; margin: .8rem 0; }
.d-advice { font-size: .78rem; line-height: 1.5; padding: .7rem .8rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); background: var(--surface2); }
.d-advice-open, .d-advice-confirmed { border-color: var(--sev-crit); background: var(--badge-red-bg); }
.d-nav { display: flex; align-items: center; justify-content: space-between; margin-top: 1rem; padding-top: .8rem; border-top: 1px solid var(--border-subtle); }
.d-pos { font-size: .72rem; color: var(--muted); font-variant-numeric: tabular-nums; }

/* ── toast ──────────────────────────────────────────────────────── */
.toast { position: fixed; left: 50%; bottom: 1.4rem; transform: translate(-50%, 12px); padding: .45rem .9rem; font-size: .78rem; color: var(--text); background: var(--surface3); border: 1px solid var(--border-strong); border-radius: 999px; opacity: 0; pointer-events: none; transition: opacity .18s var(--ease), transform .18s var(--ease); z-index: 60; }
.toast.show { opacity: 1; transform: translate(-50%, 0); }

/* ── open-threat digest on the summary ──────────────────────────── */
.digest { display: flex; flex-direction: column; gap: .35rem; }
.digest-row { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; gap: .6rem; align-items: center; padding: .45rem .6rem; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); background: var(--surface2); cursor: pointer; }
.digest-row:hover { border-color: var(--border-strong); }
.digest-row .digest-main { min-width: 0; font-size: .8rem; }
.digest-row .digest-main .desc { color: var(--muted); font-size: .74rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.digest-row .loc-text, .digest-row .loc-link { font-family: var(--font-mono); font-size: .7rem; }
.see-all { display: inline-block; margin-top: .5rem; font-size: .76rem; color: var(--accent); text-decoration: none; }

/* ── attribution ────────────────────────────────────────────────── */
.guide { font-size: .74rem; color: var(--muted); margin: -.3rem 0 .7rem; line-height: 1.45; }
.trend { display: grid; grid-auto-flow: column; grid-auto-columns: minmax(0, 1fr); gap: .3rem; align-items: end; height: 150px; padding: .4rem .2rem 0; border-bottom: 1px solid var(--border-subtle); }
.trend-col { display: flex; flex-direction: column; justify-content: flex-end; align-items: stretch; min-width: 0; height: 100%; gap: 2px; }
.trend-bars { display: flex; gap: 2px; align-items: flex-end; flex: 1; }
.trend-bar { flex: 1; border-radius: 3px 3px 0 0; min-height: 2px; }
.trend-bar.human { background: var(--sev-med); }
.trend-bar.ai { background: var(--accent); }
.trend-bar.fixed { background: var(--blue); opacity: .8; }
.trend-label { font-size: .58rem; color: var(--text-dim); text-align: center; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding-top: 3px; font-family: var(--font-mono); }
.trend-legend { display: flex; gap: 1rem; font-size: .7rem; color: var(--muted); margin: .4rem 0 .2rem; }
.trend-legend span::before { content: ''; display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: .35rem; vertical-align: -1px; }
.trend-legend .l-human::before { background: var(--sev-med); }
.trend-legend .l-ai::before { background: var(--accent); }
.trend-legend .l-fixed::before { background: var(--blue); }
.cohorts { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: .8rem; }
.cohort { padding: .8rem .9rem; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); background: var(--surface2); }
.cohort h4 { margin: 0 0 .5rem; font-size: .8rem; }
.cohort-row { display: flex; justify-content: space-between; font-size: .76rem; padding: .2rem 0; border-bottom: 1px dashed var(--border-subtle); }
.cohort-row:last-child { border-bottom: 0; }
.cohort-row b { font-variant-numeric: tabular-nums; }
.attr-track { height: 8px; }
.attr-fill { background: linear-gradient(90deg, var(--accent), var(--blue)); }
th.attr-bar, td.attr-bar { width: 18%; min-width: 100px; }
.attr-ai { margin-top: 3px; display: flex; flex-wrap: wrap; gap: 3px; }
.score { font-variant-numeric: tabular-nums; }

/* ── code page ──────────────────────────────────────────────────── */
.file-card-header .file-kinds { display: flex; gap: .3rem; margin-left: .6rem; }
.file-card-header .file-kinds span { font-size: .62rem; padding: .05rem .4rem; border-radius: 999px; background: var(--surface3); color: var(--muted); }
.file-card-header .loc-link { border-bottom: 0; }

/* ── data page jump links ───────────────────────────────────────── */
.jump { display: flex; flex-wrap: wrap; gap: .35rem; margin-bottom: 1rem; }
.jump a { font-size: .72rem; color: var(--muted); text-decoration: none; padding: .25rem .55rem; border: 1px solid var(--border-subtle); border-radius: 999px; }
.jump a:hover { color: var(--text); border-color: var(--border-strong); }
.jump a b { color: var(--text); font-variant-numeric: tabular-nums; margin-left: .25rem; }

/* ── print ──────────────────────────────────────────────────────── */
@media print {
  .sidebar, .topnav-right, .drawer, .drawer-overlay, .copy, .btn, .chips, .search-wrap, #sidebarToggle { display: none !important; }
  .layout { display: block; }
  .main { padding: 0; }
  .section-content { display: block !important; page-break-before: always; }
  thead th { position: static; }
}

/* ── fixes ───────────────────────────────────────────────────────── */
[hidden] { display: none !important; }
.table-wrap { overflow-x: auto; margin-bottom: 1rem; border-radius: var(--radius-md); }
.table-wrap table { margin-bottom: 0; min-width: 100%; }
.table-wrap td { max-width: 34ch; }
.kpis { grid-template-columns: repeat(auto-fit, minmax(128px, 1fr)); }
.nav-badge { margin-left: auto; font-size: .64rem; font-weight: 600; padding: .05rem .45rem; border-radius: 999px; background: var(--badge-red-bg); color: var(--red); }
.sidebar.collapsed .nav-badge { display: none; }
.sidebar a { display: flex; align-items: center; }

/* ── compact badges inside tables ────────────────────────────────── */
.attr-ai .badge, td .badge.badge-blue { text-transform: none; letter-spacing: 0; font-weight: 500; font-size: .64rem; white-space: nowrap; padding: .1rem .45rem; }
.table-wrap td code { white-space: nowrap; }
.table-wrap td.loc { white-space: nowrap; }
#claims td, #people td, #agents td { vertical-align: top; }

/* ── clamped descriptions, open-at-end chart ─────────────────────── */
.desc-clamp { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; max-width: 52ch; }
.trend-open { height: 56px; }
.trend-bar.open { background: var(--sev-med); opacity: .55; }
.trend-legend .l-open::before { background: var(--sev-med); opacity: .55; }
.trend-label { min-width: 0; }
.trend-col:nth-child(n+17) .trend-label { visibility: hidden; }
.trend-col:nth-child(n+17):nth-child(4n+1) .trend-label { visibility: visible; }

/* stacked bars keep their own heights; flex:1 on .trend-bar is for the row, not the stack */
.trend-bar-stack .trend-bar { flex: 0 0 auto; }

/* ── tables: compact rows, fixed layout, sort arrows on demand ───── */
.table-wrap th, .table-wrap td { padding: .42rem .6rem; font-size: .77rem; line-height: 1.35; vertical-align: middle; }
.table-wrap thead th { font-size: .66rem; letter-spacing: .3px; text-transform: uppercase; color: var(--muted); white-space: nowrap; }
th .th-arrow::after { opacity: 0; }
th[data-sort]:hover .th-arrow::after { opacity: .45; }
th.sorted-asc .th-arrow::after, th.sorted-desc .th-arrow::after { opacity: 1; }
table.fixed { table-layout: fixed; width: 100%; }
.table-wrap table.fixed td { max-width: none; overflow: hidden; text-overflow: ellipsis; }
td.loc .loc-cell { display: flex; align-items: center; gap: .3rem; min-width: 0; }
td.loc .loc-cell .loc-link, td.loc .loc-cell .loc-text { display: flex; flex-direction: column; min-width: 0; flex: 1 1 auto; border-bottom: 0; line-height: 1.25; }
td.loc .loc-file { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: var(--font-mono); font-size: .72rem; }
td.loc .loc-dir { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: var(--font-mono); font-size: .62rem; color: var(--muted); }
td.loc .loc-cell .copy { flex: 0 0 auto; }
td .who { display: inline-block; max-width: 100%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
td .who .who-kind { display: none; }
.table-wrap td .badge, .table-wrap td .fc-sev { font-size: .58rem; padding: .12rem .38rem; letter-spacing: 0; }
td.loc .loc-cell { position: relative; }
td.loc .loc-cell .copy { position: absolute; right: 0; top: 50%; transform: translateY(-50%); background: var(--surface2); border-radius: 4px; }
.d-flows { max-height: 240px; overflow: auto; padding-right: .2rem; }
.d-flows > div > code, .d-flows > div > b { white-space: nowrap; flex: 0 0 auto; }
.d-flows > div > .muted { min-width: 0; flex: 1 1 auto; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.d-bars { max-height: 300px; overflow: auto; }
table.fixed .desc-clamp { max-width: none; }
.claim-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.claim-cell code { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.claim-cell .cc-threat { color: var(--muted); font-size: .7rem; }
.status-cell { display: flex; flex-direction: column; align-items: flex-start; gap: 3px; }
.paged-out { display: none !important; }
.pager { display: flex; align-items: center; gap: .8rem; flex-wrap: wrap; margin: -.5rem 0 1.2rem; font-size: .74rem; color: var(--muted); }
.pager-ctl { display: inline-flex; align-items: center; gap: 2px; }
.pager-btn { min-width: 26px; height: 26px; padding: 0 .45rem; border: 1px solid var(--border-subtle); background: var(--surface2); color: var(--text); border-radius: 6px; font: inherit; font-size: .72rem; cursor: pointer; font-variant-numeric: tabular-nums; }
.pager-btn:hover:not(:disabled) { border-color: var(--border-strong); background: var(--surface3); }
.pager-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
.pager-btn:disabled { opacity: .4; cursor: default; }
.pager-gap { padding: 0 .2rem; }
.pager-size { margin-left: auto; display: inline-flex; align-items: center; gap: .35rem; }
.pager-size select { font: inherit; font-size: .72rem; padding: .2rem .4rem; border: 1px solid var(--border-subtle); border-radius: 6px; background: var(--surface2); color: var(--text); }

/* ── heatmaps ────────────────────────────────────────────────────── */
.heat-wrap { margin-bottom: .6rem; }
table.heat { border-collapse: separate; border-spacing: 3px; width: auto; min-width: 0; margin: 0; }
.table-wrap table.heat th, .table-wrap table.heat td { padding: 0; border: 0; background: transparent; font-size: .72rem; max-width: none; }
table.heat th { text-transform: none; letter-spacing: 0; }
table.heat thead th { position: static; }
table.heat .heat-corner { color: var(--text-dim); font-size: .62rem; font-weight: 500; text-align: left; padding: 0 .4rem; white-space: nowrap; }
table.heat .heat-col { vertical-align: bottom; text-align: center; }
table.heat .heat-col span { display: inline-block; writing-mode: vertical-rl; transform: rotate(180deg); max-height: 128px; padding: .15rem 0 .1rem; font-family: var(--font-mono); font-size: .64rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; line-height: 1.2; }
table.heat .heat-row { text-align: right; padding: 0 .5rem 0 .2rem; font-family: var(--font-mono); font-size: .68rem; font-weight: 500; color: var(--text); white-space: nowrap; }
table.heat .heat-row span { display: block; max-width: 150px; overflow: hidden; text-overflow: ellipsis; }
table.heat th a { color: inherit; text-decoration: none; border-bottom: 1px dotted transparent; }
table.heat th a:hover { color: var(--accent); border-bottom-color: var(--accent); }
.heat-cell { width: 42px; min-width: 42px; height: 30px; text-align: center; border-radius: 5px; font-variant-numeric: tabular-nums; font-weight: 600; font-size: .72rem; color: var(--text); background: var(--surface2); transition: transform .1s var(--ease), box-shadow .1s var(--ease); }
.heat-cell.empty { background: color-mix(in oklab, var(--surface2) 55%, transparent); }
.heat-cell.tone-red { background: color-mix(in oklab, var(--red) calc(var(--h) * 78%), var(--surface2)); }
.heat-cell.tone-green { background: color-mix(in oklab, var(--green) calc(var(--h) * 70%), var(--surface2)); }
.heat-cell.tone-blue { background: color-mix(in oklab, var(--blue) calc(var(--h) * 70%), var(--surface2)); }
.heat-cell.tone-neutral { background: color-mix(in oklab, var(--accent) calc(var(--h) * 70%), var(--surface2)); }
.heat-cell a { display: block; width: 100%; height: 100%; line-height: 30px; color: inherit; text-decoration: none; }
.heat-cell:not(.empty):hover { transform: scale(1.08); box-shadow: 0 0 0 2px var(--accent); position: relative; z-index: 1; }

/* ── bar lists ───────────────────────────────────────────────────── */
.bars { display: flex; flex-direction: column; gap: .3rem; }
.bar-row { display: grid; grid-template-columns: minmax(0, 170px) minmax(0, 1fr) auto; align-items: center; gap: .6rem; font-size: .74rem; }
.bar-label { min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: var(--font-mono); font-size: .7rem; }
.bar-label a { color: var(--text); text-decoration: none; }
.bar-label a:hover { color: var(--accent); }
.bar-row .sev-track { height: 8px; }
.bar-value { font-variant-numeric: tabular-nums; font-weight: 600; white-space: nowrap; }
.bar-value .muted { font-weight: 400; font-size: .68rem; }
.unused-controls { margin-top: .7rem; padding-top: .6rem; border-top: 1px dashed var(--border-subtle); font-size: .74rem; display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; }

/* ── asset drawer ────────────────────────────────────────────────── */
.red { color: var(--red); }
.d-grid-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.d-grid-4 .d-value a { font-size: 1.15rem; font-weight: 700; color: var(--text); text-decoration: none; font-variant-numeric: tabular-nums; }
.d-grid-4 .d-value a.red { color: var(--red); }
.d-grid-4 .d-value a.muted { color: var(--muted); }
.d-grid-4 .d-value a:hover { text-decoration: underline; }
.d-bars { display: flex; flex-direction: column; gap: .25rem; }
.d-bar-row { display: grid; grid-template-columns: minmax(0, 150px) minmax(0, 1fr) auto; gap: .5rem; align-items: center; color: var(--text); text-decoration: none; font-size: .74rem; padding: .15rem .3rem; margin: 0 -.3rem; border-radius: 4px; }
.d-bar-row:hover { background: var(--surface2); }
.d-bar-label { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.d-bar-row .sev-track { height: 7px; }
.d-bar-value { font-variant-numeric: tabular-nums; white-space: nowrap; font-size: .72rem; }
.pill { display: inline-flex; align-items: center; gap: .3rem; padding: .15rem .5rem; margin: 0 .2rem .25rem 0; border: 1px solid var(--border-subtle); border-radius: 999px; text-decoration: none; color: var(--text); font-size: .74rem; }
.pill:hover { border-color: var(--accent); }
.d-flows > div, .d-files > div { font-size: .74rem; padding: .18rem 0; border-bottom: 1px dashed var(--border-subtle); display: flex; align-items: center; gap: .4rem; min-width: 0; }
.d-flows > div:last-child, .d-files > div:last-child { border-bottom: 0; }
.d-files a { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text); text-decoration: none; font-family: var(--font-mono); font-size: .7rem; }
.d-files a:hover { color: var(--accent); }
.d-files .copy { opacity: 1; margin-left: auto; }
.d-status .muted { margin-left: auto; font-size: .74rem; font-weight: 400; }
.d-value .fc-sev { text-decoration: none; margin-right: .3rem; }

/* ── diagram toolbar ─────────────────────────────────────────────── */
.diagram-toolbar { padding: .5rem .7rem; }
.diagram-actions { gap: .5rem; }
.diagram-seg { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: var(--surface); }
.diagram-seg .diagram-btn { border: 0; border-radius: 0; height: 28px; min-width: 32px; padding: 0 .55rem; background: transparent; }
.diagram-seg .diagram-btn + .diagram-btn { border-left: 1px solid var(--border); }
.diagram-seg .diagram-btn:hover { background: var(--surface3); }
.diagram-btn { padding: 0 .6rem; font-weight: 550; font-family: var(--font-ui); display: inline-flex; align-items: center; gap: .3rem; }
.diagram-btn.active { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
.diagram-btn.copied { color: var(--green-text); }
.mermaid-wrap { max-height: 72vh; }

/* ── reports toolbar ─────────────────────────────────────────────── */
.report-toolbar { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; margin: .2rem 0 1rem; }
.report-toolbar .report-selector { flex: 1 1 260px; max-width: 520px; padding: .45rem .7rem; font-size: .8rem; }
.report-toolbar .btn { white-space: nowrap; }
.report-cmds { display: flex; flex-wrap: wrap; gap: .4rem; margin: .4rem 0 1rem; }
.report-cmd { display: inline-flex; align-items: center; gap: .3rem; padding: .25rem .3rem .25rem .6rem; border: 1px solid var(--border-subtle); border-radius: 8px; background: var(--surface2); font-family: var(--font-mono); font-size: .7rem; color: var(--text); }
.report-cmd .copy { opacity: 1; }
.report-empty { text-align: center; padding: 2.2rem 1rem 1.6rem; }
.report-empty .big { font-size: 2.4rem; opacity: .5; margin-bottom: .5rem; }
.report-empty h3 { margin: 0 0 .3rem; font-size: 1rem; }
.report-empty p { color: var(--muted); font-size: .8rem; margin: 0 0 1rem; }

/* ── round four: fonts, palette contrast, icons, matrices, drawers ── */
.ico { width: 1em; height: 1em; vertical-align: -.15em; flex: 0 0 auto; }
.sec-icon .ico { width: 16px; height: 16px; }
.nav-icon .ico { width: 16px; height: 16px; display: block; }
.btn .ico, .diagram-btn .ico { width: 14px; height: 14px; }
.copy .ico { width: 13px; height: 13px; display: block; }
.copy { display: inline-flex; align-items: center; justify-content: center; }
.chip .ico, .sub-h .ico, .heatmap-stats .ico { width: 13px; height: 13px; margin-right: .2rem; }
.sub-h .ico { vertical-align: -2px; }
.search-icon { display: inline-flex; align-items: center; }
#themeToggle { display: inline-flex; align-items: center; justify-content: center; width: 30px; height: 30px; padding: 0; }
#themeToggle .ico { width: 15px; height: 15px; }
.icon-sun, .icon-moon { display: inline-flex; }
[data-theme="dark"] .icon-sun { display: none; }
[data-theme="light"] .icon-moon { display: none; }
.chevron { display: inline-flex; }
.chevron .ico { width: 14px; height: 14px; }
.drawer-close { display: inline-flex; align-items: center; gap: .3rem; }
.report-empty .big .ico { width: 40px; height: 40px; stroke-width: 1.4; }
.diagram-legend { display: inline-flex; flex-wrap: wrap; gap: .6rem; align-items: center; }
.diagram-legend span { display: inline-flex; align-items: center; gap: .3rem; white-space: nowrap; }
.diagram-legend .ico { width: 13px; height: 13px; }
.diagram-legend .sw { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.sec-icon { color: var(--accent); }

/* severity: filled critical, outlined high, blue medium, steel low */
.fc-sev.crit { background: var(--sev-crit); color: #ffffff; border-color: var(--sev-crit); }
.fc-sev.high { background: var(--sev-high-bg); color: var(--sev-high); border-color: var(--sev-high); }
.fc-sev.med  { background: var(--sev-med-bg);  color: var(--sev-med);  border-color: color-mix(in oklab, var(--sev-med) 55%, transparent); }
.fc-sev.low  { background: var(--sev-low-bg);  color: var(--sev-low);  border-color: color-mix(in oklab, var(--sev-low) 55%, transparent); }
.fc-sev.unset { background: var(--surface2); color: var(--muted); border-color: var(--border); }

/* matrices fill their panel instead of huddling in a bordered box */
.heat-wrap { border: 0; background: transparent; box-shadow: none; border-radius: 0; }
table.heat { width: 100%; border: 0; }
.heat-cell { height: 36px; font-size: .8rem; min-width: 44px; }
.heat-cell a { line-height: 36px; }
table.heat .heat-row { font-size: .74rem; }
table.heat .heat-row span { max-width: 190px; }
table.heat .heat-col span { font-size: .68rem; }

/* wider drawer, richer annotation drawer */
:root { --drawer-w: min(680px, 92vw); }
.d-kind { display: flex; align-items: center; gap: .6rem; margin-bottom: 1rem; }
.d-kind-summary { font-weight: 600; font-size: .92rem; min-width: 0; overflow-wrap: anywhere; }
.d-fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .2rem 1rem; margin-bottom: 1.2rem; }
.d-fields .d-section { margin-bottom: .6rem; }
.d-raw { position: relative; }
.d-raw .copy { position: absolute; top: .35rem; right: .35rem; opacity: 1; }
.d-code-ctx { font-family: var(--font-mono); font-size: .72rem; line-height: 1.5; background: var(--surface2); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: .5rem .6rem; overflow-x: auto; white-space: pre; }
.d-code-ctx .hl { background: var(--accent-soft); color: var(--text); display: block; margin: 0 -.6rem; padding: 0 .6rem; border-left: 2px solid var(--accent); }
.d-code-ctx span { display: block; color: var(--muted); }
.d-state-by { font-size: .72rem; color: var(--muted); }
.d-status .d-state-by { margin-left: 0; }
.d-ref { min-width: 0; overflow-wrap: anywhere; line-height: 1.6; }

/* ── what changed since <ref> ─────────────────────────────────────── */
.since-strip { margin: .2rem 0 1.1rem; padding: .8rem .95rem; border: 1px solid var(--border); border-radius: var(--radius-lg); background: color-mix(in oklab, var(--surface) 92%, transparent); }
.since-strip.since-increased { border-color: color-mix(in oklab, var(--red) 45%, var(--border)); }
.since-strip.since-decreased { border-color: color-mix(in oklab, var(--green) 55%, var(--border)); }
.since-head { display: flex; align-items: baseline; gap: .8rem; margin-bottom: .6rem; font-size: .8rem; }
.since-title { font-weight: 650; }
.since-delta { margin-left: auto; font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
.since-increased .since-delta { color: var(--red); }
.since-decreased .since-delta { color: var(--green-text); }
.since-cells { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .5rem; }
.since-cell { display: flex; flex-direction: column; gap: .1rem; padding: .55rem .7rem; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); background: var(--surface2); color: var(--text); text-decoration: none; transition: border-color .15s var(--ease); }
.since-cell:hover { border-color: var(--border-strong); }
.since-cell b { font-size: 1.3rem; line-height: 1.1; font-variant-numeric: tabular-nums; }
.since-cell span { font-size: .74rem; font-weight: 600; }
.since-cell small { font-size: .66rem; color: var(--muted); }
.since-cell.bad b { color: var(--red); }
.since-cell.good b { color: var(--green-text); }
.since-cell.warn b { color: var(--blue); }
.since-cell.neutral b { color: var(--muted); }
.since-list { margin-top: .6rem; font-size: .74rem; display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; }
.since-list-label { color: var(--muted); text-transform: uppercase; font-size: .64rem; letter-spacing: .05em; margin-right: .2rem; }
.chip-new.active, .chip-new:hover { border-color: var(--blue); color: var(--blue); }

/* ── file cards: risk first ───────────────────────────────────────── */
.file-risk { display: inline-flex; gap: .3rem; align-items: center; margin-left: .5rem; }
.file-risk .badge, .file-risk .fc-sev { font-size: .58rem; padding: .1rem .38rem; letter-spacing: 0; }

/* ── diagrams: focus, find, dimming ───────────────────────────────── */
.diagram-focus, .diagram-find { height: 28px; font: inherit; font-size: .74rem; color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 0 .55rem; }
.diagram-focus { max-width: 200px; }
.diagram-find { width: 140px; }
.diagram-find:focus, .diagram-focus:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
.mermaid svg .node, .mermaid svg .cluster, .mermaid svg .edgePath, .mermaid svg .edgeLabel, .mermaid svg .flowchart-link { transition: opacity .15s var(--ease); }
.mermaid svg .node.dim, .mermaid svg .cluster.dim { opacity: .12; }
.mermaid svg .dim-edge { opacity: .22; }

/* ── linked ids in reports, whole-model note ──────────────────────── */
.md-content a.id-link { color: var(--accent); text-decoration: none; border-bottom: 1px dotted var(--accent-dim); }
.md-content a.id-link:hover { border-bottom-style: solid; }
.whole-model-note { margin-bottom: .9rem; }
.whole-model-note .btn { margin-left: auto; }
#owners td .who, #sensitive td .who { border-bottom: 0; }
.variant-note { font-size: .78rem; color: var(--muted); margin: 0 0 .9rem; padding: .5rem .7rem; border-left: 3px solid var(--accent); background: var(--accent-soft); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }

/* ── report findings ─────────────────────────────────────────────── */
.findings { margin: .2rem 0 1.2rem; }
.findings .sub-h { margin-top: .2rem; }
.findings-table td .who { border-bottom: 0; font-weight: 600; }
.findings-table td .small { font-size: .7rem; margin-top: 2px; }
.findings-table td .pill { margin: 0; }

/* ── Explore: one question at a time ─────────────────────────────── */
/* The question bar is the page's primary control, so it reads as a control
   strip rather than as a row of tabs inside a panel: it stays put while the
   answer beneath it changes shape completely. */
.explore-bar {
  display: flex; flex-wrap: wrap; gap: .6rem .9rem; align-items: center;
  justify-content: space-between;
  padding: .55rem .7rem; margin-bottom: .8rem;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  position: sticky; top: 0; z-index: 5;
}
.explore-questions { display: flex; flex-wrap: wrap; gap: .3rem; }
.explore-q {
  font: inherit; font-size: .78rem; font-weight: 600;
  padding: .34rem .7rem; border-radius: 999px; cursor: pointer;
  background: transparent; color: var(--muted);
  border: 1px solid var(--border); transition: all .15s var(--ease);
}
.explore-q:hover { color: var(--text); border-color: var(--accent-dim); }
.explore-q.active { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
.explore-controls { display: flex; flex-wrap: wrap; gap: .4rem; align-items: center; }
.explore-subject {
  font: inherit; font-size: .76rem; max-width: 22rem;
  padding: .3rem .5rem; border-radius: var(--radius-sm);
  background: var(--surface2); color: var(--text); border: 1px solid var(--border);
}
.explore-subject:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }

/* What the view is for. Always above the answer, never collapsible: a reader
   has to be able to tell a view somebody wanted from one the data allowed. */
.explore-purpose {
  margin: 0 0 .9rem; padding: .6rem .85rem;
  border-left: 3px solid var(--accent); background: var(--accent-soft);
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0; max-width: 90ch;
}
.explore-question { margin: 0; font-size: .86rem; font-weight: 600; color: var(--text); }
.explore-shape { margin: .35rem 0 0; font-size: .76rem; color: var(--muted); }

.explore-pane { display: none; }
.explore-pane.active { display: block; }

/* One plane per row, never two abreast.
   They are separate questions and must never share one canvas — but they must
   not share a ROW either. The 12-node budget is a measurement against a
   1096 x 648 panel; put two of those side by side on the same page and each
   gets ~530px, the layout no longer fits, and a diagram that passed the budget
   is cropped or scaled to illegible labels. Measured in a browser: the #mcp
   threat plane at 7 nodes / 8 edges — comfortably inside budget — ran off the
   right edge of a half-width panel. Stacking costs a scroll; the alternative
   costs the guarantee. */
.explore-planes { display: grid; grid-template-columns: 1fr; gap: .8rem; margin-bottom: 1rem; }
.explore-diagram { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
.explore-diagram-head {
  display: flex; flex-wrap: wrap; gap: .2rem .6rem; align-items: baseline;
  padding: .5rem .8rem; border-bottom: 1px solid var(--border); background: var(--surface2);
}
.explore-diagram-title { font-size: .8rem; font-weight: 700; letter-spacing: .2px; }
.explore-diagram-purpose { font-size: .73rem; color: var(--muted); }
.explore-diagram .mermaid-wrap { max-height: 46vh; }

/* The size readout. Deliberately unalarming — it is the normal state of a
   working view, not a warning — and always present, so its absence never has
   to be interpreted. */
.explore-budget {
  margin: 0; padding: .45rem .8rem;
  font-size: .72rem; color: var(--muted); line-height: 1.5;
  border-top: 1px solid var(--border); background: var(--surface2);
}
.explore-pane > .explore-budget { border: 1px solid var(--border); border-radius: var(--radius-sm); margin: .6rem 0; max-width: 90ch; }

/* "There is no picture, and here is why." Not styled as an error: declining to
   draw an illegible graph is the view working correctly. */
.explore-nodraw {
  margin: 0; padding: 1.1rem .9rem; text-align: center;
  font-size: .78rem; color: var(--muted); background: var(--surface2);
}

.explore-rows { font-size: .78rem; }
.explore-rows td, .explore-rows th { padding: .35rem .55rem; }

/* ── undefended routes: a path drawn as the line it is ───────────── */
.path-finding {
  padding: .6rem .8rem; margin-bottom: .55rem;
  background: var(--surface); border: 1px solid var(--border);
  border-left: 3px solid var(--danger, #ea1d1d); border-radius: var(--radius-sm);
}
.path-chain { display: flex; flex-wrap: wrap; gap: .3rem; align-items: center; }
.path-node { font-size: .78rem; padding: .15rem .45rem; border-radius: var(--radius-sm); background: var(--surface2); border: 1px solid var(--border); }
.path-node.path-asset { border-color: var(--accent); color: var(--accent); font-weight: 600; }
.path-arrow { color: var(--muted); font-size: .8rem; }
.path-meta { display: flex; flex-wrap: wrap; gap: .3rem .6rem; align-items: center; margin-top: .4rem; font-size: .72rem; color: var(--muted); }
.path-hops { display: flex; flex-wrap: wrap; gap: .3rem; }

@media (max-width: 900px) {
  .explore-bar { position: static; }
}

/* A whole-model diagram that draws but cannot be read. Not an error colour:
   the picture is still there and still correct, it is only being honest about
   its size — which is a different thing from the render-budget banner above it,
   where nothing was drawn at all. */
.diagram-toobig {
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 8px;
  background: var(--accent-soft);
  padding: .7rem .9rem;
  margin: 0 0 14px;
  font-size: .78rem;
  color: var(--text);
  max-width: 86ch;
}
.diagram-toobig strong { display: block; margin-bottom: .35rem; }
.diagram-toobig ul { margin: 0 0 .5rem; padding-left: 1.1rem; }
.diagram-toobig li { margin-bottom: .2rem; }
.diagram-toobig p { margin: 0; color: var(--muted); }
`;
