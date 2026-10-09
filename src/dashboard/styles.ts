/**
 * GuardLink Dashboard — stylesheet.
 *
 * Every colour on the page is a ROLE, declared once in the token blocks at the
 * top and resolved per theme and per host; nothing below them names a colour.
 *
 *   ground    canvas · sunken · panel · raised · hover · hairlines · dot
 *   ink       fg · fg-muted · fg-subtle
 *   accent    steel — links, focus, the pinned mark, the current tab; nothing else
 *   sev-*     one warm hue, lightness by step — a threat claim and nothing else
 *   resolved  mint — mitigated, refuted, cleared; never the accent
 *   review    amber — a claim awaiting a human; an outline and ◐, never a fill
 *   poles     structure (flows) · change (time) · people (owners, controls)
 *   stipple   could not see — a texture, not a hue
 *
 * Standalone, the page follows `prefers-color-scheme`, and `data-theme` on the
 * root pins one. Inside a VS Code webview a host sets `data-host="vscode"` and
 * every role is read from the editor's theme variables instead, falling back
 * to the standalone values. The ramp passes the ordinal palette checks (one hue,
 * monotone lightness, adjacent ΔL ≥ 0.06, light end ≥ 2:1) on every ground it
 * sits on; text never wears a severity colour.
 *
 * Type is the system stack, or Inter and JetBrains Mono when installed. The
 * page requests no web font.
 *
 * @comment -- "Static CSS only; nothing here interpolates model data, and nothing here references a remote resource"
 */

/** The token blocks: the only place a colour literal may appear. */
export const TOKENS_CSS = `
:root {
  color-scheme: dark;
  --canvas: #0d1114; --sunken: #0a0d10; --panel: #14191f; --raised: #1a212a; --hover: #212a34;
  --border: #222a33; --border-muted: #1a212a; --border-strong: #3d4c5c;
  --fg: #e8eef4; --fg-muted: #b9c4cf; --fg-subtle: #97a2ae;
  --accent: #8fc4ee; --on-accent: #08131b;
  --sev-low: #7c5c3f; --sev-medium: #af6533; --sev-high: #db693a; --sev-critical: #ff7064;
  --resolved: #3fae86; --review: #e0a24e;
  --structure: #83b0d7; --change: #4ccae5; --people: #b798ee;
  --shadow: 0 8px 24px rgba(0, 0, 0, .35);
  --scrim: rgba(0, 0, 0, .5);
  --mix-sev: 20%; --mix-res: 18%; --mix-review: 14%; --mix-accent: 16%; --mix-dot: 26%;
}
:root[data-theme="light"] {
  color-scheme: light;
  --canvas: #ffffff; --sunken: #f4f6f8; --panel: #ffffff; --raised: #f4f6f8; --hover: #eaedf1;
  --border: #d9dde3; --border-muted: #e6e9ee; --border-strong: #b4bcc6;
  --fg: #14181d; --fg-muted: #59636e; --fg-subtle: #656f7b;
  --accent: #2f6f9e; --on-accent: #ffffff;
  --sev-low: #c69b78; --sev-medium: #c36c36; --sev-high: #b4410d; --sev-critical: #9e1618;
  --resolved: #1b7a59; --review: #93650a;
  --structure: #326893; --change: #00769c; --people: #714ca6;
  --shadow: 0 8px 24px rgba(20, 24, 29, .14);
  --scrim: rgba(20, 24, 29, .32);
  --mix-sev: 14%; --mix-res: 12%; --mix-review: 10%; --mix-accent: 10%; --mix-dot: 30%;
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]):not([data-host="vscode"]) {
    color-scheme: light;
    --canvas: #ffffff; --sunken: #f4f6f8; --panel: #ffffff; --raised: #f4f6f8; --hover: #eaedf1;
    --border: #d9dde3; --border-muted: #e6e9ee; --border-strong: #b4bcc6;
    --fg: #14181d; --fg-muted: #59636e; --fg-subtle: #656f7b;
    --accent: #2f6f9e; --on-accent: #ffffff;
    --sev-low: #c69b78; --sev-medium: #c36c36; --sev-high: #b4410d; --sev-critical: #9e1618;
    --resolved: #1b7a59; --review: #93650a;
    --structure: #326893; --change: #00769c; --people: #714ca6;
    --shadow: 0 8px 24px rgba(20, 24, 29, .14);
    --scrim: rgba(20, 24, 29, .32);
    --mix-sev: 14%; --mix-res: 12%; --mix-review: 10%; --mix-accent: 10%; --mix-dot: 30%;
  }
}
/* Inside a VS Code webview every role is the editor's own; the standalone value is the fallback. */
:root[data-host="vscode"] {
  --canvas: var(--vscode-editor-background, #1f1f1f);
  --sunken: var(--vscode-sideBar-background, #181818);
  --panel: var(--vscode-editorWidget-background, var(--vscode-sideBar-background, #202020));
  --raised: var(--vscode-input-background, #282828);
  --hover: var(--vscode-list-hoverBackground, #2a2d2e);
  --border: var(--vscode-panel-border, var(--vscode-editorGroup-border, #2b2b2b));
  --border-muted: var(--vscode-editorGroup-border, #262626);
  --border-strong: var(--vscode-input-border, var(--vscode-contrastBorder, #3c3c3c));
  --fg: var(--vscode-foreground, #cccccc);
  --fg-muted: var(--vscode-descriptionForeground, #9d9d9d);
  --fg-subtle: var(--vscode-disabledForeground, #8b8b8b);
  --accent: var(--vscode-focusBorder, var(--vscode-textLink-foreground, #0078d4));
  --on-accent: var(--vscode-button-foreground, #ffffff);
}
:root[data-host="vscode"] body.vscode-light, :root[data-host="vscode"] body.vscode-high-contrast-light {
  --sev-low: #c69b78; --sev-medium: #c36c36; --sev-high: #b4410d; --sev-critical: #9e1618;
  --resolved: #1b7a59; --review: #93650a;
  --structure: #326893; --change: #00769c; --people: #714ca6;
  --mix-sev: 14%; --mix-res: 12%; --mix-review: 10%; --mix-accent: 10%; --mix-dot: 30%;
}
`;

/** Derived roles: OKLab mixes of the roles above, never new literals. Declared on body so a host override on body reaches them. */
const DERIVED_CSS = `
body {
  --sev-low-subtle: color-mix(in oklab, var(--panel), var(--sev-low) var(--mix-sev));
  --sev-medium-subtle: color-mix(in oklab, var(--panel), var(--sev-medium) var(--mix-sev));
  --sev-high-subtle: color-mix(in oklab, var(--panel), var(--sev-high) var(--mix-sev));
  --sev-critical-subtle: color-mix(in oklab, var(--panel), var(--sev-critical) var(--mix-sev));
  --resolved-subtle: color-mix(in oklab, var(--panel), var(--resolved) var(--mix-res));
  --resolved-wash: color-mix(in oklab, var(--panel), var(--resolved) 55%);
  --review-subtle: color-mix(in oklab, var(--panel), var(--review) var(--mix-review));
  --accent-subtle: color-mix(in oklab, var(--panel), var(--accent) var(--mix-accent));
  --dot: color-mix(in oklab, var(--canvas), var(--fg) var(--mix-dot));
  --stipple: color-mix(in oklab, var(--panel), var(--fg-subtle) 55%);
  --thread: color-mix(in oklab, var(--border-strong), var(--structure) 60%);
  --thread-strong: color-mix(in oklab, var(--structure), var(--fg) 55%);
  --ribbon: color-mix(in oklab, var(--canvas), var(--structure) 12%);
  --ribbon-cross: color-mix(in oklab, var(--canvas), var(--fg) 9%);
  --control-ink: color-mix(in oklab, var(--border-strong), var(--people) 60%);
  --font-ui: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
:root[data-host="vscode"] body {
  --font-ui: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe WPC", "Segoe UI", system-ui, sans-serif);
  --font-mono: var(--vscode-editor-font-family, Menlo, Monaco, "Courier New", monospace);
}
`;

const BASE_CSS = `
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
*::selection { background: var(--accent-subtle); color: var(--fg); }
html, body { height: 100%; }
body { font: 13.5px/1.5 var(--font-ui); background: var(--canvas); color: var(--fg); overflow: hidden; -webkit-font-smoothing: antialiased; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
button, select, input { font: inherit; color: inherit; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
code, kbd, .mono { font-family: var(--font-mono); }
code { font-size: .92em; background: var(--sunken); border: 1px solid var(--border-muted); border-radius: 4px; padding: 0 4px; color: var(--fg); }
kbd { font-size: 10.5px; border: 1px solid var(--border-strong); border-bottom-width: 2px; border-radius: 4px; padding: 0 4px; color: var(--fg-muted); background: var(--sunken); }
.num { font-variant-numeric: tabular-nums; }
.muted { color: var(--fg-muted); }
.subtle { color: var(--fg-subtle); }
.small { font-size: 11.5px; }
.spacer { flex: 1; }
.eyebrow { font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-subtle); }
.offscreen { position: fixed; left: -9999px; top: 0; opacity: 0; }
[hidden] { display: none !important; }
.ico { display: block; flex: none; }
.ico + * { min-width: 0; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 10px; border: 2px solid var(--canvas); }
::-webkit-scrollbar-track { background: transparent; }

/* ── top bar ── */
.topbar { height: 52px; display: flex; align-items: center; gap: 12px; padding: 0 16px; background: var(--sunken); border-bottom: 1px solid var(--border); position: relative; z-index: 20; }
.brand { display: flex; align-items: baseline; gap: 10px; min-width: 0; }
.brand .project { font-size: 14px; font-weight: 650; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 260px; }
.topbar-metrics { display: flex; gap: 6px; margin-left: auto; }
.tn-stat { display: flex; align-items: baseline; gap: 6px; font-size: 11.5px; color: var(--fg-subtle); padding: 3px 9px; border: 1px solid var(--border); border-radius: 999px; background: var(--panel); white-space: nowrap; }
.tn-stat .tn-v { color: var(--fg); font-weight: 650; font-variant-numeric: tabular-nums; }
.search-wrap { position: relative; display: flex; align-items: center; }
.search-icon { position: absolute; left: 9px; color: var(--fg-subtle); pointer-events: none; }
.search-wrap kbd { position: absolute; right: 8px; pointer-events: none; }
#search { width: 220px; height: 28px; padding: 0 28px 0 30px; border-radius: 6px; border: 1px solid var(--border-strong); background: var(--panel); }
#search::placeholder { color: var(--fg-subtle); }
.feature-filter-select { height: 28px; max-width: 180px; border-radius: 6px; border: 1px solid var(--border-strong); background: var(--panel); padding: 0 8px; }
.icon-btn { width: 30px; height: 28px; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px; border: 1px solid var(--border-strong); background: var(--raised); color: var(--fg-muted); cursor: pointer; flex: none; }
.icon-btn:hover { background: var(--hover); color: var(--fg); }
#themeToggle .icon-sun { display: none; }
:root[data-theme="light"] #themeToggle .icon-sun { display: block; }
:root[data-theme="light"] #themeToggle .icon-moon { display: none; }
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) #themeToggle .icon-sun { display: block; }
  :root:not([data-theme="dark"]) #themeToggle .icon-moon { display: none; }
}
.badge { display: inline-flex; align-items: center; gap: 4px; height: 18px; padding: 0 7px; border-radius: 999px; font-size: 10.5px; font-weight: 600; color: var(--fg-muted); border: 1px solid var(--border-strong); white-space: nowrap; }
.badge-red { color: var(--fg); border-color: var(--sev-high); }
.badge-green { color: var(--fg); border-color: var(--resolved); }
.badge-blue { color: var(--fg-muted); border-color: var(--border-strong); }
.badge-scope { border-style: dashed; border-color: var(--review); color: var(--fg); }

/* ── banners ── */
.scope-banner { display: flex; gap: 10px; align-items: baseline; padding: 8px 16px; background: var(--review-subtle); border-bottom: 2px dashed var(--review); font-size: 12.5px; }
.scope-banner-tag { flex: none; font-size: 10.5px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; border: 1px dashed var(--review); border-radius: 999px; padding: 1px 8px; }
.feature-banner { display: flex; gap: 8px; align-items: center; padding: 6px 16px; background: var(--accent-subtle); border-bottom: 1px solid var(--border); font-size: 12.5px; }
.feature-banner .btn { margin-left: auto; }
.scope-note, .variant-note { border-left: 3px dashed var(--review); background: var(--review-subtle); padding: 8px 12px; margin: 0 0 12px; font-size: 12.5px; color: var(--fg-muted); border-radius: 0 6px 6px 0; }
.scope-tag { display: inline-flex; vertical-align: middle; margin-left: 8px; font-size: 10.5px; font-weight: 600; color: var(--fg-muted); border: 1px dashed var(--review); border-radius: 999px; padding: 0 8px; letter-spacing: 0; text-transform: none; }

/* ── layout: rail + main ── */
.layout { display: flex; height: calc(100vh - 52px); }
body.scoped .layout { height: calc(100vh - 52px - 40px); }
.rail { width: 196px; flex: none; display: flex; flex-direction: column; background: var(--sunken); border-right: 1px solid var(--border); }
.rail-nav { flex: 1; overflow-y: auto; padding: 10px 8px; display: flex; flex-direction: column; gap: 2px; }
.rail a[data-page] { display: flex; align-items: center; gap: 9px; padding: 6px 8px; border-radius: 6px; color: var(--fg-muted); font-size: 12.5px; text-decoration: none; position: relative; }
.rail a[data-page]:hover { background: var(--hover); color: var(--fg); }
.rail a[data-page].active { background: var(--raised); color: var(--fg); box-shadow: inset 2px 0 0 var(--accent); }
.rail .nav-icon { width: 16px; color: var(--fg-subtle); display: flex; }
.rail a.active .nav-icon { color: var(--accent); }
.rail .nav-text { flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rail .nav-badge { font-size: 11px; color: var(--fg); }
.rail .sep { height: 1px; background: var(--border); margin: 6px 8px; }
.rail-foot { padding: 10px 14px 12px; border-top: 1px solid var(--border); font-size: 11px; color: var(--fg-subtle); display: flex; flex-direction: column; gap: 5px; }
.rail.collapsed { width: 52px; }
.rail.collapsed .nav-text, .rail.collapsed .nav-badge, .rail.collapsed .rail-foot { display: none; }
.main { flex: 1; min-width: 0; overflow-y: auto; }
.section-content { display: none; padding: 20px 24px 64px; max-width: 1360px; }
.section-content.active { display: block; }

/* ── page heads and type ── */
.page-head, .sec-h { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 8px 16px; margin-bottom: 14px; }
.ph-text { flex: 1 1 420px; min-width: 0; }
.ph-title { font-size: 18px; font-weight: 650; letter-spacing: -.01em; line-height: 1.3; }
.ph-title.headline { font-size: 26px; letter-spacing: -.015em; }
.ph-right, .sec-tools { display: flex; gap: 8px; align-items: center; margin-left: auto; font-size: 12px; }
.lead { color: var(--fg-muted); max-width: 900px; margin-top: 4px; font-size: 13px; }
.guide, .section-note { color: var(--fg-muted); font-size: 12.5px; margin: 0 0 10px; max-width: 900px; }
.sub-h { display: flex; align-items: baseline; gap: 10px; margin: 22px 0 8px; font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-subtle); }
.sub-h-right { margin-left: auto; text-transform: none; letter-spacing: 0; font-weight: 400; font-size: 12px; }
.block-h { font-size: 14px; font-weight: 600; margin: 28px 0 6px; }
.empty-state { color: var(--fg-muted); padding: 14px 16px; border: 1px dashed var(--border-strong); border-radius: 10px; margin: 8px 0 12px; font-size: 12.5px; }
.grade { display: inline-flex; align-items: center; gap: 8px; font-size: 12px; color: var(--fg-muted); border: 1px solid var(--border-strong); border-radius: 999px; padding: 2px 10px 2px 4px; }
.grade b { width: 22px; height: 22px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 12px; color: var(--fg); border: 1px solid var(--border-strong); }

/* ── panels, grids, stat tiles ── */
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; min-width: 0; margin-bottom: 12px; }
.panel-h { display: flex; align-items: baseline; gap: 10px; padding: 10px 14px 0; flex-wrap: wrap; }
.panel-h .see-all { margin-left: auto; }
.panel-b { padding: 10px 14px 14px; }
.grid2, .grid3 { display: grid; gap: 12px; margin-bottom: 12px; }
.grid2 { grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr)); }
.grid3 { grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr)); }
.grid2 > .panel, .grid3 > .panel { margin-bottom: 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; padding: 12px 14px; }
.tiles2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.stat { display: flex; flex-direction: column; gap: 2px; min-width: 0; color: var(--fg); text-decoration: none; }
a.stat:hover { text-decoration: none; }
a.stat:hover .k { color: var(--accent); }
.stat .k { font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-subtle); }
.stat .v { font-size: 20px; font-weight: 650; font-variant-numeric: tabular-nums; }
.stat .s { font-size: 11.5px; color: var(--fg-subtle); }
.big { display: inline-block; font-size: 28px; font-weight: 650; letter-spacing: -.02em; line-height: 1.15; font-variant-numeric: tabular-nums; color: var(--fg); }
a.big:hover { text-decoration: none; color: var(--accent); }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px; margin-bottom: 16px; }
.stat-link { text-decoration: none; color: inherit; }
.stat-link:hover { text-decoration: none; }
.stat-card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; }
.stat-link:hover .stat-card { border-color: var(--border-strong); background: var(--hover); }
.stat-card .value { font-size: 18px; font-weight: 650; font-variant-numeric: tabular-nums; }
.stat-card .label { font-size: 10.5px; color: var(--fg-subtle); letter-spacing: .06em; text-transform: uppercase; font-weight: 600; }
.stat-danger .value::before { content: ''; display: inline-block; width: 8px; height: 8px; border-radius: 2px; background: var(--sev-high); margin-right: 6px; vertical-align: 2px; }
.stat-success .value::before { content: '✓ '; color: var(--resolved); font-size: 13px; }
.stat-muted .value { color: var(--fg-muted); }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 14px; }
.kpi { display: flex; flex-direction: column; gap: 2px; padding: 10px 12px; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; color: var(--fg); text-decoration: none; }
.kpi:hover { border-color: var(--border-strong); text-decoration: none; }
.kpi-v { font-size: 20px; font-weight: 650; font-variant-numeric: tabular-nums; }
.kpi-l { font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-subtle); }
.kpi-h { font-size: 11.5px; color: var(--fg-subtle); }
.kpi-danger .kpi-v::before { content: ''; display: inline-block; width: 8px; height: 8px; border-radius: 2px; background: var(--sev-high); margin-right: 6px; vertical-align: 3px; }
.ledger-line { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border-muted); }
.well { background: var(--sunken); border: 1px solid var(--border); border-radius: 6px; padding: 6px 9px; font-family: var(--font-mono); font-size: 11.5px; color: var(--fg-muted); white-space: pre-wrap; word-break: break-word; }
.well code { background: none; border: 0; padding: 0; }
.well.cmd { display: inline-flex; align-items: center; gap: 6px; margin-top: 6px; white-space: normal; }
.tag { display: inline-flex; align-items: center; height: 18px; padding: 0 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 10.5px; color: var(--fg-muted); background: var(--sunken); border: 1px solid var(--border); white-space: nowrap; }
.pill { display: inline-flex; align-items: center; gap: 5px; padding: 1px 6px; border: 1px solid var(--border); border-radius: 999px; font-size: 11.5px; color: var(--fg); background: var(--sunken); margin: 2px 2px 2px 0; }
.pill:hover { border-color: var(--accent); text-decoration: none; }
.pill code { background: none; border: 0; padding: 0; }
.pill-row { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; margin-top: 8px; }
.see-all { display: inline-block; margin-top: 8px; font-size: 12px; }
.desc { color: var(--fg-muted); font-size: 12px; }
.loc-line { font-family: var(--font-mono); font-size: 11px; color: var(--fg-subtle); }

/* ── buttons ── */
.btn { display: inline-flex; align-items: center; gap: 6px; height: 26px; padding: 0 10px; border-radius: 6px; border: 1px solid var(--border-strong); background: var(--raised); color: var(--fg); cursor: pointer; font-size: 12px; white-space: nowrap; text-decoration: none; }
.btn:hover { background: var(--hover); text-decoration: none; }
.btn:disabled { opacity: .45; cursor: default; }
.btn.primary, .btn-primary { background: var(--fg); color: var(--canvas); border-color: var(--fg); }
.btn.primary:hover, .btn-primary:hover { background: var(--fg-muted); }
.btn.ghost, .btn-ghost { background: transparent; }
.copy { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 20px; border: 0; background: transparent; color: var(--fg-subtle); cursor: pointer; border-radius: 4px; flex: none; vertical-align: middle; }
.copy:hover { color: var(--fg); background: var(--hover); }
.copy .ico { width: 13px; height: 13px; }
.copy.copied { color: var(--resolved); }

/* ── chips: severity is filled, state is outlined with a glyph ── */
.chip { display: inline-flex; align-items: center; gap: 5px; height: 20px; padding: 0 7px; border-radius: 5px; font-size: 11px; font-weight: 600; white-space: nowrap; color: var(--fg); background: var(--raised); border: 1px solid transparent; }
.chip .sw { display: block; width: 8px; height: 8px; border-radius: 2px; flex: none; background: var(--fg-subtle); }
.chip.sev-critical { background: var(--sev-critical-subtle); } .chip.sev-critical .sw { background: var(--sev-critical); }
.chip.sev-high { background: var(--sev-high-subtle); } .chip.sev-high .sw { background: var(--sev-high); }
.chip.sev-medium { background: var(--sev-medium-subtle); } .chip.sev-medium .sw { background: var(--sev-medium); }
.chip.sev-low { background: var(--sev-low-subtle); } .chip.sev-low .sw { background: var(--sev-low); }
.chips { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 0 0 12px; }
.chips-label { font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-subtle); }
.chips .sep { width: 1px; height: 18px; background: var(--border); margin: 0 4px; }
button.chip[data-chip], a.chip { cursor: pointer; background: var(--panel); border-color: var(--border-strong); color: var(--fg-muted); font-weight: 500; height: 24px; text-decoration: none; }
button.chip[data-chip]:hover, a.chip:hover { color: var(--fg); background: var(--hover); text-decoration: none; }
button.chip[data-chip].active { color: var(--fg); background: var(--accent-subtle); border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
.chip-sev::before { content: ''; width: 8px; height: 8px; border-radius: 2px; background: var(--fg-subtle); }
.chip-sev.s-critical::before { background: var(--sev-critical); } .chip-sev.s-high::before { background: var(--sev-high); }
.chip-sev.s-medium::before { background: var(--sev-medium); } .chip-sev.s-low::before { background: var(--sev-low); }
.chip-n { font-variant-numeric: tabular-nums; color: var(--fg-subtle); margin-left: 2px; }
.state, .claim-state { display: inline-flex; align-items: center; gap: 5px; height: 20px; padding: 0 8px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; border: 1px solid var(--border-strong); color: var(--fg-muted); background: transparent; }
.state .g, .claim-state .g { font-family: var(--font-mono); font-size: 11px; line-height: 1; }
.st-open { color: var(--fg); }
.st-confirmed { border-color: var(--fg); color: var(--fg); }
.st-mitigated, .st-refuted, .claim-state.verified { border-color: var(--resolved); color: var(--fg); }
.st-mitigated .g, .st-refuted .g, .claim-state.verified .g { color: var(--resolved); }
.st-review, .claim-state.stale { border-color: var(--review); border-style: dashed; color: var(--fg); }
.st-review .g, .claim-state.stale .g { color: var(--review); }
.st-accepted, .st-control, .claim-state.unverified { color: var(--fg-muted); }
.st-untested { background-image: repeating-linear-gradient(135deg, var(--stipple) 0 1px, transparent 1px 4px); }

/* ── mix bar and accounting bar: length, fixed order, 2 px gaps ── */
.mix-bar { display: flex; gap: 2px; height: 14px; margin: 10px 0 6px; }
.mix-bar.empty { border: 1px dashed var(--border-strong); border-radius: 3px; }
.mix-bar .seg { display: flex; align-items: center; justify-content: center; min-width: 3px; border-radius: 2px; overflow: hidden; }
.mix-bar .seg b { font-size: 10px; font-weight: 600; color: var(--fg); font-variant-numeric: tabular-nums; padding: 0 3px; }
.mix-legend { display: flex; flex-wrap: wrap; gap: 4px 12px; font-size: 11.5px; color: var(--fg-muted); }
.mix-legend a, .mix-legend span { color: var(--fg-muted); display: inline-flex; align-items: center; gap: 5px; text-decoration: none; }
.mix-legend a:hover { color: var(--fg); }
.mix-legend b { color: var(--fg); font-weight: 600; }
.key { display: inline-block; width: 9px; height: 9px; border-radius: 2px; flex: none; }
.seg.s-critical, .key.s-critical { background: var(--sev-critical); }
.seg.s-high, .key.s-high { background: var(--sev-high); }
.seg.s-medium, .key.s-medium { background: var(--sev-medium); }
.seg.s-low, .key.s-low { background: var(--sev-low); }
.seg.s-unset, .key.s-unset { background: var(--fg-subtle); }
.seg.res, .key.res { background: var(--resolved-wash); }
.seg.acc, .key.acc { box-shadow: inset 0 0 0 1.5px var(--fg-subtle); background: transparent; }
.seg.review, .key.review { box-shadow: inset 0 0 0 1.5px var(--review); }
.seg.stipple, .key.stipple { background-image: repeating-linear-gradient(135deg, var(--stipple) 0 1px, transparent 1px 4px); box-shadow: inset 0 0 0 1px var(--border-strong); }
.seg.proven, .key.proven { box-shadow: inset 0 0 0 1.5px var(--fg); }
.seg.res b, .seg.acc b { color: var(--fg); }
.seg.s-critical b, .seg.s-high b { color: var(--canvas); }

/* ── gauge: a 2 px rule whose length is the share it names ── */
.gauge { position: relative; height: 2px; background: var(--border); border-radius: 1px; margin-top: 6px; }
.gauge.wide { height: 4px; margin: 6px 0 12px; max-width: 520px; }
.gauge i { position: absolute; left: 0; top: 0; bottom: 0; border-radius: 1px; }
.gauge.silent { background: repeating-linear-gradient(90deg, var(--border-strong) 0 4px, transparent 4px 7px); }
.gauge .s-critical { background: var(--sev-critical); } .gauge .s-high { background: var(--sev-high); }
.gauge .s-medium { background: var(--sev-medium); } .gauge .s-low { background: var(--sev-low); } .gauge .s-unset { background: var(--fg-subtle); }
.gauge .m-res { background: var(--resolved); }
.gauge .g-structure { background: var(--structure); }

/* ── overview: actions, since strip, cohorts ── */
.actions { display: flex; flex-direction: column; }
.action { display: grid; grid-template-columns: 14px minmax(0, 1fr) auto; gap: 10px; align-items: start; padding: 10px 0; border-bottom: 1px solid var(--border-muted); }
.action:last-child { border-bottom: 0; }
.action-mark { width: 10px; height: 10px; margin-top: 4px; border-radius: 2px; box-shadow: inset 0 0 0 1.5px var(--fg-subtle); }
.action-mark.s-critical { background: var(--sev-critical); box-shadow: none; }
.action-mark.s-high { background: var(--sev-high); box-shadow: none; }
.action-title { font-weight: 600; }
.action-title a { color: var(--fg); }
.action-detail { color: var(--fg-muted); font-size: 12px; }
.action-ctas { display: flex; flex-direction: column; gap: 4px; }
.since-strip { padding: 12px 14px; }
.since-head { display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline; margin-bottom: 10px; }
.since-title { font-weight: 600; }
.since-delta { margin-left: auto; font-size: 12px; color: var(--fg-muted); border: 1px solid var(--border-strong); border-radius: 999px; padding: 0 8px; }
.since-increased .since-delta { border-color: var(--sev-high); color: var(--fg); }
.since-decreased .since-delta { border-color: var(--resolved); color: var(--fg); }
.since-cells { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
.since-cell { display: grid; grid-template-columns: auto 1fr; column-gap: 8px; padding: 8px 10px; border: 1px solid var(--border); border-radius: 6px; color: var(--fg); text-decoration: none; background: var(--sunken); }
.since-cell:hover { border-color: var(--border-strong); text-decoration: none; }
.since-cell b { font-size: 18px; grid-column: 2; }
.since-cell span:not(.since-mark), .since-cell small { grid-column: 2; font-size: 11.5px; color: var(--fg-muted); }
.since-mark { grid-row: 1 / span 3; font-family: var(--font-mono); font-weight: 700; width: 16px; text-align: center; color: var(--fg-subtle); }
.since-mark.m-warm { color: var(--sev-high); } .since-mark.m-res { color: var(--resolved); } .since-mark.m-review { color: var(--review); }
.since-list { margin-top: 8px; font-size: 12px; display: flex; flex-wrap: wrap; align-items: center; gap: 4px; }
.since-list-label { font-weight: 600; margin-right: 4px; font-family: var(--font-mono); }
.cohorts { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr)); gap: 12px; }
.cohort { background: var(--sunken); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; }
.cohort h4 { font-size: 12.5px; margin-bottom: 6px; }
.cohort-row { display: flex; justify-content: space-between; gap: 10px; font-size: 12px; padding: 2px 0; border-bottom: 1px solid var(--border-muted); }
.cohort-row b { font-weight: 600; font-variant-numeric: tabular-nums; }

/* ── tables ── */
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; background: var(--panel); margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
table.fixed { table-layout: fixed; }
th { text-align: left; font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-subtle); padding: 7px 9px; border-bottom: 1px solid var(--border); background: var(--panel); position: sticky; top: 0; z-index: 1; white-space: nowrap; }
td { padding: 7px 9px; border-bottom: 1px solid var(--border-muted); vertical-align: top; overflow-wrap: anywhere; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover > td { background: var(--hover); }
tr.clickable { cursor: pointer; }
.th-sort { all: unset; cursor: pointer; display: inline-flex; gap: 4px; align-items: center; letter-spacing: inherit; text-transform: inherit; }
.th-sort:focus-visible { outline: 2px solid var(--accent); }
.th-arrow::after { content: '↕'; opacity: .45; }
th.sorted-asc .th-arrow::after { content: '↑'; opacity: 1; color: var(--accent); }
th.sorted-desc .th-arrow::after { content: '↓'; opacity: 1; color: var(--accent); }
.filtered-out, .paged-out, .ff-out { display: none !important; }
.desc-clamp { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
td.loc, th.loc { width: 17%; }
.loc-cell { display: flex; align-items: flex-start; gap: 2px; min-width: 0; }
.loc-link, .loc-text { display: flex; flex-direction: column; min-width: 0; font-family: var(--font-mono); font-size: 11.5px; }
.loc-text { color: var(--fg-muted); }
.loc-file { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; direction: rtl; text-align: left; }
.loc-dir { font-size: 10.5px; color: var(--fg-subtle); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; direction: rtl; text-align: left; }
.status-cell { display: flex; flex-wrap: wrap; gap: 4px; }
.claim-cell { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.claim-cell code { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; display: block; }
.cc-threat { color: var(--fg-muted); }
.tbl { width: 100%; }
.tbl.compact td { padding: 6px 8px; }
.no-match { color: var(--fg-muted); font-size: 12.5px; padding: 8px 2px; }
.filter-status, .who-filter { display: flex; gap: 8px; align-items: center; padding: 6px 10px; margin-bottom: 10px; border: 1px solid var(--accent); border-radius: 6px; background: var(--accent-subtle); font-size: 12.5px; }
.filter-status .btn, .who-filter .btn { margin-left: auto; }
.pager { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; font-size: 12px; color: var(--fg-muted); margin: -4px 0 12px; }
.pager-ctl { display: flex; gap: 2px; align-items: center; }
.pager-btn { min-width: 26px; height: 24px; border-radius: 5px; border: 1px solid var(--border); background: var(--panel); cursor: pointer; font-size: 12px; }
.pager-btn.active { border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); color: var(--fg); }
.pager-btn:disabled { opacity: .4; cursor: default; }
.pager-size select { height: 24px; border-radius: 5px; border: 1px solid var(--border-strong); background: var(--panel); }
.attr-ai { display: flex; flex-wrap: wrap; gap: 3px; margin-top: 3px; }
.who { color: var(--accent); }
.who-kind { color: var(--fg-subtle); }
.sha code { color: var(--accent); }
.flow-arrow { color: var(--fg-subtle); text-align: center; width: 36px; }

/* count grids (people × time, tool × severity, severity × status) */
.heat-wrap { max-height: 520px; }
table.heat { width: auto; min-width: 100%; }
.heat th.heat-col { writing-mode: vertical-rl; transform: rotate(180deg); height: 120px; text-transform: none; letter-spacing: 0; font-family: var(--font-mono); font-weight: 500; vertical-align: bottom; }
.heat th.heat-row { text-transform: none; letter-spacing: 0; font-family: var(--font-mono); font-weight: 500; color: var(--fg-muted); position: static; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
.heat th.heat-col span, .heat th.heat-row span { display: inline-block; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
.heat td { text-align: center; padding: 4px; min-width: 30px; }
.heat-cell { font-variant-numeric: tabular-nums; font-weight: 600; }
.heat-cell a { color: var(--fg); display: block; }
.heat-cell.tone-red { background: color-mix(in oklab, var(--panel), var(--sev-high) calc(var(--h) * 70%)); }
.heat-cell.tone-green { background: color-mix(in oklab, var(--panel), var(--resolved) calc(var(--h) * 55%)); }
.heat-cell.tone-blue, .heat-cell.tone-neutral { background: color-mix(in oklab, var(--panel), var(--structure) calc(var(--h) * 45%)); }
.reach-cell { text-align: left !important; }
.reach-cell .reach-chip { margin: 2px 2px 2px 0; }

/* bar lists */
.bars { display: flex; flex-direction: column; gap: 6px; }
.bar-row { display: grid; grid-template-columns: minmax(0, 200px) minmax(60px, 1fr) auto; gap: 10px; align-items: center; font-size: 12px; }
.bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-track { height: 8px; background: var(--sunken); border-radius: 2px; overflow: hidden; }
.bar-fill { display: block; height: 100%; border-radius: 2px; }
.b-open { background: var(--sev-high); } .b-res { background: var(--resolved-wash); } .b-ctl { background: var(--people); } .b-neutral { background: var(--structure); }
.bar-value { white-space: nowrap; }

/* ── plots ── */
.plot-head { display: flex; align-items: baseline; gap: 12px; margin: 4px 0 6px; flex-wrap: wrap; }
.toggle { display: inline-flex; gap: 6px; align-items: center; font-size: 12px; color: var(--fg-muted); cursor: pointer; }
.plot-panel { padding: 6px; }
.plot-scroll { overflow: auto; max-width: 100%; }
.plot-scroll > svg { display: block; }
.fidelity { display: flex; flex-wrap: wrap; gap: 4px 16px; font-size: 11.5px; color: var(--fg-subtle); margin: -4px 2px 8px; }
.fidelity b { color: var(--fg); }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 11.5px; color: var(--fg-muted); margin: 0 2px 12px; align-items: center; }
.legend span { display: inline-flex; align-items: center; gap: 6px; }
.lg { display: inline-block; width: 14px; height: 10px; flex: none; }
.lg.thr-open { border-top: 2px solid var(--sev-high); margin-top: 6px; height: 2px; }
.lg.thr-res { border-top: 1.5px solid var(--resolved-wash); height: 2px; margin-top: 6px; }
.lg.thr-acc { border-top: 1.5px dashed var(--fg-subtle); height: 2px; margin-top: 6px; }
.lg.thr-ctl { border-top: 1.5px solid var(--control-ink); height: 2px; margin-top: 6px; }
.lg.thr-cross { border-top: 2px solid var(--thread-strong); height: 2px; margin-top: 6px; }
.lg.m-open { width: 6px; background: var(--sev-high); } .lg.m-res { width: 6px; background: var(--resolved); }
.lg.m-empty { width: 6px; background: var(--hover); box-shadow: inset 0 0 0 1px var(--fg-subtle); }
.lg.m-ext { width: 6px; box-shadow: inset 0 0 0 1px var(--fg-subtle); border: 1px dashed var(--fg-subtle); }
.lg.tk-open { width: 6px; height: 14px; background: var(--sev-high); border-radius: 1.5px; }
.lg.tk-res { width: 6px; height: 14px; background: var(--resolved-wash); border-radius: 1.5px; }
.lg.tk-acc { width: 6px; height: 14px; box-shadow: inset 0 0 0 1.2px var(--fg-subtle); border-radius: 1.5px; }
.lg.cap-ok { border: 1px solid var(--resolved); border-radius: 6px; }
.lg.cap-bad { border: 1.4px solid var(--sev-high); border-radius: 6px; }
.lg.eff-ungated { width: 9px; height: 9px; background: var(--sev-high); border-radius: 2px; }
.lg.eff-gated { width: 9px; height: 9px; background: var(--resolved); border-radius: 2px; }
.lg.eff-read { width: 9px; height: 9px; box-shadow: inset 0 0 0 1px var(--fg-subtle); border-radius: 2px; }
.pin-bar { display: flex; align-items: center; gap: 10px; padding: 6px 10px; margin: 0 0 8px; border: 1px solid var(--accent); border-radius: 6px; background: var(--accent-subtle); font-size: 12.5px; flex-wrap: wrap; }
.pin-bar .btn { margin-left: auto; }
.twin { margin-bottom: 12px; }
.twin-table td.loc { font-size: 11px; color: var(--fg-muted); max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; direction: rtl; text-align: left; }
.analytics-body > .grid2 { margin-top: 0; }

/* tabs and segmented controls */
.tabs { display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin: 6px 0 14px; overflow-x: auto; }
.tab { padding: 7px 12px; color: var(--fg-muted); font-size: 13px; border-bottom: 2px solid transparent; margin-bottom: -1px; white-space: nowrap; text-decoration: none; }
.tab:hover { color: var(--fg); text-decoration: none; }
.tab.active { color: var(--fg); border-bottom-color: var(--accent); }
.view-bar { display: flex; flex-wrap: wrap; gap: 10px 16px; align-items: center; margin-bottom: 10px; }
.seg { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; padding: 2px; background: var(--panel); gap: 2px; }
.seg-btn { padding: 3px 10px; border-radius: 6px; color: var(--fg-muted); font-size: 12.5px; text-decoration: none; white-space: nowrap; }
.seg-btn:hover { color: var(--fg); background: var(--hover); text-decoration: none; }
.seg-btn.active { color: var(--fg); background: var(--raised); box-shadow: inset 0 -2px 0 var(--accent); }
.entry-chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.entry-chips select { height: 24px; max-width: 220px; border-radius: 5px; border: 1px solid var(--border-strong); background: var(--panel); font-family: var(--font-mono); font-size: 11.5px; }
.trail { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 8px; font-size: 12px; }
.crumb { color: var(--accent); }
.node-detail { padding: 12px 14px; }
.nd-head { display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: baseline; }
.nd-cols { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); margin-top: 8px; }
.nd-col ul, .asset-ex { list-style: none; display: flex; flex-direction: column; gap: 3px; margin-top: 4px; font-size: 12px; }
.nd-col li { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
.gate-mark { color: var(--fg); font-weight: 700; }
.paths { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
.path-finding { padding: 8px 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--panel); }
.path-chain { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
.path-asset { border-color: var(--border-strong); }
.path-arrow { color: var(--fg-subtle); }
.path-meta { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 6px; font-size: 11.5px; }
.path-hops { display: inline-flex; flex-wrap: wrap; gap: 4px; }
.path-hops .loc-link, .path-hops .loc-text { display: inline; }

/* SVG diagrams: the shared ink */
.dg { font-family: var(--font-mono); font-size: 10.5px; user-select: none; }
.dg:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.dg .dot { fill: var(--dot); }
.dg .hd { font-family: var(--font-ui); font-size: 10px; font-weight: 600; letter-spacing: .08em; fill: var(--fg-subtle); }
.dg .nm { fill: var(--fg-muted); }
.dg .nm.hot { fill: var(--fg); }
.dg .nm.strong { font-weight: 600; }
.dg .sub { font-family: var(--font-ui); font-size: 10px; fill: var(--fg-subtle); }
.dg .nd { cursor: pointer; }
.dg .hit { fill: transparent; }
.dg .pinbox { fill: none; stroke: none; }
.dg .pin .pinbox, .dg .kfocus .pinbox { stroke: var(--accent); stroke-width: 1.6; }
.dg .kfocus .card-box, .dg .kfocus .mark { stroke: var(--accent); stroke-width: 1.6; }
.dg .thr { fill: none; transition: opacity .12s; }
.dg .thr.x-open { stroke-width: 1.8; }
.dg .s-critical.x-open, .dg .tick.s-critical, .dg .slab-edge.s-critical, .dg .sw.s-critical, .dg .gauge.s-critical, .dg .c-open.s-critical .mark, .dg .mg.s-critical { stroke: var(--sev-critical); fill: var(--sev-critical); }
.dg .s-high.x-open, .dg .tick.s-high, .dg .slab-edge.s-high, .dg .sw.s-high, .dg .gauge.s-high, .dg .c-open.s-high .mark, .dg .mg.s-high { stroke: var(--sev-high); fill: var(--sev-high); }
.dg .s-medium.x-open, .dg .tick.s-medium, .dg .slab-edge.s-medium, .dg .sw.s-medium, .dg .gauge.s-medium, .dg .c-open.s-medium .mark, .dg .mg.s-medium { stroke: var(--sev-medium); fill: var(--sev-medium); }
.dg .s-low.x-open, .dg .tick.s-low, .dg .slab-edge.s-low, .dg .sw.s-low, .dg .gauge.s-low, .dg .c-open.s-low .mark, .dg .mg.s-low { stroke: var(--sev-low); fill: var(--sev-low); }
.dg .s-unset.x-open, .dg .tick.s-unset, .dg .slab-edge.s-unset, .dg .sw.s-unset, .dg .gauge.s-unset, .dg .c-open.s-unset .mark, .dg .mg.s-unset { stroke: var(--fg-subtle); fill: var(--fg-subtle); }
.dg .thr.x-open { fill: none; }
.dg .thr.x-res { stroke: var(--resolved-wash); stroke-width: 1.1; }
.dg .thr.x-acc { stroke: var(--fg-subtle); stroke-width: 1.1; stroke-dasharray: 3 2; }
.dg .thr.x-ctl { stroke: var(--control-ink); stroke-width: 1.1; }
.dg .thr.x-flow { stroke: var(--thread); stroke-width: 1.1; }
.dg .thr.x-cross { stroke: var(--thread-strong); stroke-width: 1.5; }
.dg .thr.x-ok { stroke: var(--resolved-wash); stroke-width: 1.3; }
.dg .thr.x-bad, .dg .thr.x-ungated { stroke: var(--sev-high); stroke-width: 1.8; }
.dg .thr.x-gated { stroke: var(--resolved); stroke-width: 1.2; }
.dg .thr.x-read { stroke: var(--fg-subtle); stroke-width: 1.2; }
.dg .thr.x-loose { stroke-dasharray: 4 3; }
.dg .thr:hover { stroke-width: 2.6; }
.dg.hl .thr:not(.lit) { opacity: .1; }
.dg.hl .bodies { opacity: .35; }
.dg .tick.m-res { fill: var(--resolved); stroke: none; }
.dg .tick.m-empty { fill: var(--hover); stroke: var(--fg-subtle); stroke-width: 1; }
.dg .tick.m-ext { fill: none; stroke: var(--fg-subtle); stroke-width: 1; stroke-dasharray: 2 2; }
.dg .tick.m-ctl { fill: var(--people); stroke: none; }
.dg .tick[class*=" s-"] { stroke: none; }
.dg .slab { fill: var(--panel); stroke: var(--border-strong); }
.dg .slab-edge { stroke: none; }
.dg .rib { fill: none; stroke: var(--ribbon); stroke-linecap: butt; }
.dg .rib.cross { stroke: var(--ribbon-cross); }
.dg .pill rect { fill: var(--canvas); stroke: var(--border-strong); }
.dg .pill text { font-family: var(--font-ui); font-variant-numeric: tabular-nums; fill: var(--fg); }
.dg .edge { fill: none; stroke: var(--structure); stroke-opacity: .75; stroke-width: 1.2; }
.dg .edge.cross { stroke: var(--thread-strong); stroke-opacity: 1; stroke-width: 1.6; }
.dg .edge:hover { stroke-width: 2.4; }
.dg .arrowhead { fill: var(--fg-subtle); }
.dg .gate { stroke: var(--fg); stroke-width: 2; }
.dg .mech { font-size: 9.5px; fill: var(--fg-subtle); paint-order: stroke; stroke: var(--canvas); stroke-width: 3; }
.dg .card-box { fill: var(--panel); stroke: var(--border-strong); }
.dg .card.ext .card-box { fill: var(--canvas); stroke: var(--fg-subtle); stroke-dasharray: 4 3; }
.dg .card.focus .card-box { stroke: var(--accent); stroke-width: 1.8; }
.dg .card:hover .card-box { stroke: var(--fg-muted); }
.dg .gauge { stroke: none; }
.dg .gauge.m-res { fill: var(--resolved); } .dg .gauge.m-none { fill: var(--border); }
.dg .sw { stroke: none; }
.dg tspan.ok, .dg .ok { fill: var(--resolved); }
.dg tspan.bad { fill: var(--sev-high); }
.dg .more { font-family: var(--font-ui); font-size: 11px; fill: var(--fg-muted); }
.dg .actor { fill: var(--panel); stroke: var(--border-strong); }
.dg .actor.loose { fill: none; stroke: var(--fg-subtle); stroke-dasharray: 4 3; }
.dg .cap { fill: var(--panel); }
.dg .cap.ok { stroke: var(--resolved); } .dg .cap.bad { stroke: var(--sev-high); stroke-width: 1.4; }
.dg .eff-sw.read { fill: none; stroke: var(--fg-subtle); } .dg .eff-sw.gated { fill: var(--resolved); } .dg .eff-sw.ungated { fill: var(--sev-high); }
/* the matrix */
.dg .band { fill: transparent; }
.dg .band.hot { fill: var(--hover); }
.dg .gridcell { fill: none; stroke: var(--border-muted); }
.dg .sep { stroke: var(--border-strong); }
.dg .cell { cursor: pointer; }
.dg .c-open .mark { stroke: none; }
.dg .c-res .mark { fill: var(--resolved-subtle); stroke: var(--resolved); }
.dg .c-acc .mark { fill: none; stroke: var(--fg-subtle); stroke-width: 1.5; }
.dg .count { font-family: var(--font-ui); font-size: 10px; font-weight: 600; fill: var(--fg); pointer-events: none; }
.dg .c-open.s-critical .count, .dg .c-open.s-high .count { fill: var(--canvas); }
.dg .mg.res { fill: var(--resolved-wash); stroke: none; }
.dg .mg { stroke: none; }

/* shelves */
.shelf { overflow: hidden; }
.shelf-h { display: flex; gap: 10px; align-items: baseline; padding: 8px 12px; border-bottom: 1px solid var(--border); }
.zone-h { font-size: 13.5px; font-weight: 600; letter-spacing: .06em; font-variant: all-small-caps; }
.dotground { background-color: var(--canvas); background-image: radial-gradient(circle, var(--dot) .8px, transparent 1px); background-size: 16px 16px; }
.shelf-field { display: flex; flex-wrap: wrap; gap: 10px; padding: 12px; }
/* Absorbs the last row's slack, so a lone card on it keeps its own width instead of stretching. */
.shelf-field::after { content: ''; flex: 1000 1 0; }
.shelf-card { min-width: 140px; max-width: 100%; background: var(--panel); border: 1px solid var(--border-strong); border-radius: 6px; cursor: pointer; overflow: hidden; }
.shelf-card:hover { border-color: var(--fg-muted); }
.shelf-card.pin { border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
.sc-head { display: flex; gap: 8px; align-items: baseline; padding: 7px 9px 0; }
.sc-head b { font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.shelf-card > .gauge { margin: 6px 9px 0; }
.sc-ticks, .ticks { display: flex; flex-wrap: wrap; gap: 2px; padding: 8px 9px 4px; min-height: 26px; }
.ticks { padding: 0; min-height: 0; max-width: 260px; }
.tk { display: block; width: 6px; height: 14px; border-radius: 1.5px; background: var(--fg-subtle); }
.ticks .tk { width: 5px; height: 12px; }
.tk.s-critical { background: var(--sev-critical); } .tk.s-high { background: var(--sev-high); } .tk.s-medium { background: var(--sev-medium); } .tk.s-low { background: var(--sev-low); }
.tk.res { background: var(--resolved-wash); }
.tk.acc { background: transparent; box-shadow: inset 0 0 0 1.2px var(--fg-subtle); }
.sc-foot { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; padding: 2px 9px 8px; font-size: 11px; color: var(--fg-muted); }

/* the assets ledger */
.ledger tbody.row-group:hover > tr:first-child > td { background: var(--hover); }
.ledger tr.expanded > td { background: var(--accent-subtle); }
.row-detail td { background: var(--sunken); }
.row-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.asset-ex li { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; cursor: pointer; }

/* code page */
.file-card { border: 1px solid var(--border); border-radius: 10px; background: var(--panel); margin-bottom: 8px; overflow: hidden; }
.file-card-header { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 8px 12px; cursor: pointer; }
.file-card-header:hover { background: var(--hover); }
.file-path { font-size: 12px; display: inline-flex; align-items: center; gap: 2px; min-width: 0; max-width: 100%; overflow: hidden; }
.file-path bdi { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-risk, .file-kinds { display: inline-flex; flex-wrap: wrap; gap: 4px; }
.file-kinds span { font-size: 11px; color: var(--fg-subtle); font-family: var(--font-mono); }
.file-end { display: inline-flex; align-items: center; gap: 8px; margin-left: auto; }
.file-count { font-size: 11px; color: var(--fg-muted); font-variant-numeric: tabular-nums; }
.chevron { display: inline-flex; color: var(--fg-subtle); transition: transform .15s; }
.file-card-header.open .chevron { transform: rotate(90deg); }
.file-card-body { display: none; border-top: 1px solid var(--border); padding: 6px 12px 10px; }
.file-card-body.open { display: block; }
.ann-entry { padding: 8px 6px; border-bottom: 1px solid var(--border-muted); cursor: pointer; border-radius: 4px; }
.ann-entry:hover { background: var(--hover); }
.ann-header { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.ann-line { font-family: var(--font-mono); font-size: 11px; color: var(--fg-subtle); min-width: 36px; }
.ann-badge { font-family: var(--font-mono); font-size: 10.5px; padding: 0 6px; border-radius: 4px; border: 1px solid var(--border-strong); color: var(--fg-muted); background: var(--sunken); }
.ann-exposes, .ann-confirmed, .ann-threat { border-color: var(--sev-high); color: var(--fg); }
.ann-mitigates, .ann-validates, .ann-control { border-color: var(--resolved); color: var(--fg); }
.ann-audit, .ann-assumes { border-color: var(--review); border-style: dashed; color: var(--fg); }
.ann-flows, .ann-boundary { border-color: var(--structure); color: var(--fg); }
.ann-owns { border-color: var(--people); color: var(--fg); }
.ann-summary { font-family: var(--font-mono); font-size: 11.5px; overflow-wrap: anywhere; }
.ann-desc { font-size: 12px; color: var(--fg-muted); margin: 4px 0 0 44px; }
.code-block, .d-code-ctx { margin-top: 6px; background: var(--sunken); border: 1px solid var(--border); border-radius: 6px; padding: 6px 0; font-family: var(--font-mono); font-size: 11px; overflow-x: auto; }
.code-block span, .d-code-ctx span { display: block; white-space: pre; padding: 0 10px; color: var(--fg-muted); }
.code-line-ann, .d-code-ctx .hl { background: var(--accent-subtle); color: var(--fg); }
.cov-line { display: flex; flex-wrap: wrap; gap: 10px; align-items: baseline; margin-bottom: 4px; }
.unannotated { display: flex; flex-direction: column; gap: 2px; margin-bottom: 14px; }
.unann-row { display: flex; align-items: center; gap: 4px; font-size: 11.5px; padding: 3px 8px; background: var(--sunken); border-left: 3px dashed var(--review); border-radius: 2px; }

/* agents & reach */
.reach-kind { display: inline-flex; align-items: center; height: 18px; padding: 0 7px; font-size: 10.5px; font-weight: 600; border-radius: 999px; border: 1px solid var(--border-strong); color: var(--fg-muted); white-space: nowrap; }
.reach-kind.agent { border-radius: 9px; color: var(--fg); }
.reach-kind.loose { border-style: dashed; }
.reach-chip { display: inline-flex; align-items: center; gap: 5px; height: 20px; padding: 0 8px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; border: 1px solid var(--border-strong); color: var(--fg); background: transparent; }
.reach-chip .g { font-family: var(--font-mono); }
.reach-cap.ok { border-color: var(--resolved); } .reach-cap.ok .g { color: var(--resolved); }
.reach-cap.bad { border-color: var(--sev-high); } .reach-cap.bad .g { color: var(--sev-high); }
.reach-eff.ungated { border-radius: 5px; border-color: transparent; background: var(--sev-high-subtle); }
.reach-eff.ungated .sw { display: block; width: 8px; height: 8px; border-radius: 2px; background: var(--sev-high); }
.reach-eff.gated { border-color: var(--resolved); }
.reach-eff.read { border-radius: 4px; font-family: var(--font-mono); font-weight: 400; color: var(--fg-muted); background: var(--sunken); border-color: var(--border); }
.reach-actor { white-space: nowrap; }
.reach-actor span { display: block; }
.reach-legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 11.5px; color: var(--fg-muted); margin-bottom: 14px; }
.reach-miss { font-size: 12px; margin: 2px 0; }
.reach-example { margin-bottom: 14px; }
.reach-owasp { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); }
.reach-owasp-item { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; background: var(--panel); }
.reach-owasp-item.has { border-color: var(--border-strong); }
.reach-owasp-h { font-weight: 600; display: flex; gap: 8px; align-items: baseline; }
.reach-owasp-id { font-family: var(--font-mono); font-size: 11px; color: var(--fg-subtle); }
.reach-owasp-n { margin-left: auto; font-variant-numeric: tabular-nums; }
.reach-owasp-item ul { margin: 6px 0 0 16px; font-size: 12px; }
.reach-facet { font-size: 10.5px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; color: var(--fg-subtle); }

/* attribution */
.trend { display: flex; gap: 6px; align-items: flex-end; height: 140px; padding: 6px 0; overflow-x: auto; }
.trend.trend-open { height: 80px; }
.trend-col { display: flex; flex-direction: column; align-items: center; gap: 4px; min-width: 34px; height: 100%; }
.trend-bars { flex: 1; display: flex; gap: 2px; align-items: flex-end; width: 100%; }
.trend-bar { flex: 1; min-height: 1px; border-radius: 2px 2px 0 0; }
.trend-bar.human { background: var(--sev-medium); }
.trend-bar.ai { background: var(--sev-high); }
.trend-bar.fixed { background: var(--resolved-wash); }
.trend-bar.open { background: var(--sev-low); }
.trend-label { font-size: 10px; color: var(--fg-subtle); white-space: nowrap; }
.trend-legend { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 11.5px; color: var(--fg-muted); }
.trend-legend span::before { content: ''; display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; background: var(--fg-subtle); }
.trend-legend .l-human::before { background: var(--sev-medium); } .trend-legend .l-ai::before { background: var(--sev-high); }
.trend-legend .l-fixed::before { background: var(--resolved-wash); } .trend-legend .l-open::before { background: var(--sev-low); }
.trend-legend .muted::before { display: none; }

/* reports */
.report-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--border); }
.report-selector { height: 26px; max-width: 100%; border-radius: 6px; border: 1px solid var(--border-strong); background: var(--panel); padding: 0 8px; }
.report-cmds { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0 14px; }
.report-cmd { display: inline-flex; align-items: center; gap: 2px; font-size: 11.5px; padding: 2px 4px 2px 8px; background: var(--sunken); border: 1px solid var(--border); border-radius: 6px; }
.report-empty { padding: 18px; }
.report-empty h3 { font-size: 15px; margin-bottom: 4px; }
.report-empty p { color: var(--fg-muted); margin-bottom: 8px; }
.md-content { padding: 14px 18px 18px; max-width: 980px; font-size: 13.5px; line-height: 1.6; }
.md-content h1, .md-content h2, .md-content h3, .md-content h4 { margin: 18px 0 6px; line-height: 1.3; }
.md-content h1 { font-size: 20px; } .md-content h2 { font-size: 16px; } .md-content h3 { font-size: 14px; } .md-content h4 { font-size: 13px; }
.md-content p, .md-content ul, .md-content ol, .md-content pre, .md-content blockquote, .md-content .table-wrap { margin: 0 0 10px; }
.md-content ul, .md-content ol { padding-left: 22px; }
.md-content pre { background: var(--sunken); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; overflow-x: auto; font-size: 12px; }
.md-content pre code { background: none; border: 0; padding: 0; }
.md-content blockquote { border-left: 3px solid var(--border-strong); padding-left: 10px; color: var(--fg-muted); }
.md-content hr { border: 0; border-top: 1px solid var(--border); margin: 14px 0; }
.findings { margin-bottom: 14px; }
.id-link { font-family: var(--font-mono); }

/* drawer, toast, tooltip */
.drawer-overlay { position: fixed; inset: 0; background: var(--scrim); z-index: 60; display: none; }
.drawer-overlay.open { display: block; }
.drawer { position: fixed; top: 0; right: 0; width: min(460px, 100vw); height: 100vh; background: var(--panel); border-left: 1px solid var(--border-strong); z-index: 61; transform: translateX(100%); transition: transform .2s; overflow-y: auto; }
.drawer.open { transform: none; }
.drawer-header { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--panel); z-index: 1; }
.drawer-header h3 { font-size: 14px; font-weight: 600; overflow-wrap: anywhere; }
.drawer-close .ico { width: 14px; height: 14px; }
.drawer-body { padding: 14px 16px 24px; }
.d-section { margin-bottom: 14px; }
.d-label { font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-subtle); margin-bottom: 4px; }
.d-value { font-size: 13px; overflow-wrap: anywhere; }
.d-code { background: var(--sunken); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font-family: var(--font-mono); font-size: 11.5px; white-space: pre-wrap; overflow-wrap: anywhere; color: var(--fg-muted); }
.d-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px; }
.d-grid-4 { grid-template-columns: repeat(4, 1fr); }
.d-status { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 12px; }
.d-state-by { font-size: 11.5px; color: var(--fg-subtle); }
.d-blame { border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; margin-bottom: 14px; background: var(--sunken); }
.d-blame-row { display: flex; gap: 10px; font-size: 12px; padding: 2px 0; }
.d-blame-row > span:first-child { width: 90px; flex: none; color: var(--fg-subtle); }
.d-ref { min-width: 0; overflow-wrap: anywhere; }
.d-actions { display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }
.d-advice { font-size: 12.5px; color: var(--fg-muted); padding: 8px 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--sunken); }
.d-advice-open, .d-advice-confirmed { border-left: 3px solid var(--sev-high); }
.d-advice-mitigated, .d-advice-refuted { border-left: 3px solid var(--resolved); }
.d-nav { display: flex; justify-content: space-between; align-items: center; margin-top: 14px; }
.d-pos { font-size: 12px; color: var(--fg-subtle); font-variant-numeric: tabular-nums; }
.d-kind { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
.d-kind-summary { font-family: var(--font-mono); font-size: 12px; overflow-wrap: anywhere; }
.d-fields { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px; }
.d-raw { position: relative; }
.d-raw .copy { position: absolute; top: 20px; right: 4px; }
.d-bars { display: flex; flex-direction: column; gap: 4px; }
.d-bar-row { display: grid; grid-template-columns: minmax(0, 1fr) 90px auto; gap: 8px; align-items: center; font-size: 12px; color: var(--fg); text-decoration: none; }
.d-bar-row:hover { text-decoration: none; background: var(--hover); }
.d-bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.d-bar-value { white-space: nowrap; font-variant-numeric: tabular-nums; }
.d-flows, .d-reach, .d-files { display: flex; flex-direction: column; gap: 3px; font-size: 12px; }
.toast { position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%); background: var(--raised); color: var(--fg); border: 1px solid var(--border-strong); border-radius: 6px; padding: 6px 12px; font-size: 12.5px; opacity: 0; pointer-events: none; transition: opacity .15s; z-index: 90; }
.toast.show { opacity: 1; }
.tip { position: fixed; z-index: 80; pointer-events: none; background: var(--raised); color: var(--fg); border: 1px solid var(--border-strong); border-radius: 8px; padding: 8px 10px; font-size: 12px; max-width: 360px; box-shadow: var(--shadow); left: 0; top: 0; }
.tip .tt { font-weight: 600; margin-bottom: 3px; overflow-wrap: anywhere; font-family: var(--font-mono); font-size: 11.5px; }
.tip .tr { display: flex; justify-content: space-between; gap: 14px; color: var(--fg-muted); }
.tip .tr b { color: var(--fg); font-weight: 500; font-variant-numeric: tabular-nums; text-align: right; overflow-wrap: anywhere; }
.tip .tr span:empty { display: none; }

/* narrow screens: the rail becomes a strip, the page keeps a 16 px gutter */
@media (max-width: 760px) {
  body { overflow: auto; }
  .topbar { height: auto; flex-wrap: wrap; padding: 8px 12px; }
  .topbar-metrics { display: none; }
  #search { width: 160px; }
  .layout { flex-direction: column; height: auto; }
  .rail { width: auto; border-right: 0; border-bottom: 1px solid var(--border); }
  .rail-nav { flex-direction: row; flex-wrap: wrap; padding: 6px; }
  .rail .nav-icon { display: none; }
  .rail-foot { display: none; }
  .main { overflow: visible; }
  .section-content { padding: 16px 16px 48px; }
  .tiles2 { grid-template-columns: 1fr; }
  .d-grid-4 { grid-template-columns: 1fr 1fr; }
}
@media print {
  body { overflow: visible; }
  .topbar, .rail, .drawer, .drawer-overlay { display: none; }
  .layout, .main { height: auto; overflow: visible; }
  .section-content { display: block !important; }
}
`;

export const STYLES = TOKENS_CSS + DERIVED_CSS + BASE_CSS;
