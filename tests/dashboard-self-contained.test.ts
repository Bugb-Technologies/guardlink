/**
 * The generated dashboard is one self-contained file that a strict host can
 * admit as it is.
 *
 *   - No network at render time: no script, stylesheet, font or module is
 *     fetched from anywhere. Links to the repository host stay — a link is not
 *     a request until a reader follows it.
 *   - No inline event handlers: every interaction is a data-* hook with a
 *     delegated listener, so a content security policy needs no
 *     'unsafe-inline' for scripts.
 *   - No layout measurement in the diagram code, so a hidden or zero-size
 *     panel cannot lay anything out as NaN — and no re-render shims to paper
 *     over it.
 *   - One palette, declared once: no colour literal outside the token blocks,
 *     a single-hue severity ramp that passes the ordinal checks on every ground
 *     it sits on, and ink that clears WCAG AA on a panel in both themes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { generateDashboardHTML } from '../src/dashboard/generate.js';
import { STYLES, TOKENS_CSS } from '../src/dashboard/styles.js';
import { CLIENT_JS } from '../src/dashboard/client.js';
import { renderHoodSvg, renderNodeDetail } from '../src/dashboard/layout/hood.js';
import { renderMatrix } from '../src/dashboard/layout/matrix.js';

const ROOT = process.cwd();
let html: string;
let markup: string;

beforeAll(async () => {
  const { model } = await parseProject({ root: ROOT, project: 'guardlink' });
  html = generateDashboardHTML(model, ROOT);
  // The markup, with the one script block's text taken out: model text embedded
  // as JSON is data, not markup, and is checked through the renderers instead.
  markup = html.replace(/<script>[\s\S]*?<\/script>/g, '<script></script>');
}, 60_000);

describe('no network at render time', () => {
  it('loads no script, stylesheet, font or module from anywhere', () => {
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/@import/i);
    expect(html).not.toMatch(/url\(\s*['"]?(https?:)?\/\//i);
    expect(html).not.toMatch(/\bimport\(\s*['"`]/);
    expect(html).not.toMatch(/fonts\.googleapis|cdn\.jsdelivr|d3js\.org|unpkg\.com/);
    // The one <link> is an inline, empty icon — it stops the browser's own favicon request.
    expect([...markup.matchAll(/<link\b[^>]*>/gi)].map(m => m[0])).toEqual(['<link rel="icon" href="data:,">']);
  });

  it('references nothing remote from an element that loads it', () => {
    for (const m of markup.matchAll(/<(img|iframe|embed|object|source|audio|video|use|image)\b[^>]*>/gi)) {
      expect(m[0]).not.toMatch(/(src|href|data)="(https?:)?\/\//i);
    }
    expect(markup).not.toMatch(/\ssrcset=/i);
  });

  it('draws no Mermaid and carries no d3 or marked', () => {
    expect(markup).not.toMatch(/class="mermaid"/);
    expect(CLIENT_JS).not.toMatch(/mermaid|d3\.|marked\./);
  });
});

describe('no inline event handlers', () => {
  it('in the generated markup', () => {
    expect(markup).not.toMatch(/<[^>]+\son[a-z]+\s*=/i);
  });

  it('in the markup the page script builds at run time', () => {
    for (const src of [CLIENT_JS, renderHoodSvg.toString(), renderNodeDetail.toString(), renderMatrix.toString()]) {
      expect(src).not.toMatch(/\son(click|change|input|load|error|mouse\w*|key\w*|submit|focus|blur)\s*=/i);
    }
  });

  it('wires every control through a data hook the delegated listeners read', () => {
    for (const hook of ['data-action="theme"', 'data-action="rail"', 'data-action="drawer-close"', 'data-chip=', 'data-copy=', 'data-sort=']) expect(markup).toContain(hook);
    for (const hook of ['data-toggle-file', 'data-annotation=', 'data-expand', 'data-matrix-compact', 'data-focus-select', 'data-unpin=']) expect(markup).toContain(hook);
    expect(CLIENT_JS).toContain("document.addEventListener('click'");
    expect(CLIENT_JS).toContain("document.addEventListener('change'");
    expect(CLIENT_JS).toContain("document.addEventListener('keydown'");
  });

  it('navigates with hash links: the rail, the diagram tabs and the views are all <a href="#…">', () => {
    for (const page of ['overview', 'exposures', 'diagrams', 'assets', 'code', 'agents', 'reports']) expect(markup).toContain(`<a href="#${page}" data-page="${page}"`);
    for (const tab of ['threat', 'flow', 'surface', 'reach']) expect(markup).toContain(`href="#diagrams?tab=${tab}" data-tab="${tab}"`);
  });
});

describe('no layout measurement', () => {
  const layoutDir = join(ROOT, 'src', 'dashboard', 'layout');
  const MEASURE = /getBBox|getBoundingClientRect|offsetWidth|offsetHeight|clientWidth|clientHeight|getComputedTextLength/;

  it('in any diagram module', () => {
    for (const f of readdirSync(layoutDir)) {
      const src = readFileSync(join(layoutDir, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
      expect(src, f).not.toMatch(MEASURE);
    }
  });

  it('in the page script, beyond anchoring the tooltip for a keyboard user', () => {
    const uses = CLIENT_JS.match(new RegExp(MEASURE.source, 'g')) ?? [];
    expect(uses).toEqual(['getBoundingClientRect']);
    expect(CLIENT_JS).toMatch(/function tipAt\(el\) \{ var r = el\.getBoundingClientRect\(\);/);
  });

  it('with no re-render shim left anywhere', () => {
    expect(html).not.toMatch(/renderActiveDiagram|renderMermaid|setTimeout\(\(\) => \{ render/);
  });
});

// ─── Colour ──────────────────────────────────────────────────────────

function block(css: string, selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {`);
  const body = css.slice(start + selector.length + 2, css.indexOf('}', start));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
}

const hex = (h: string): [number, number, number] => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16)) as [number, number, number];
const lin = (c: number): number => { c /= 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
const luminance = (h: string): number => { const [r, g, b] = hex(h).map(lin); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
const contrast = (a: string, b: string): number => { const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
function oklch(h: string): { L: number; C: number; H: number } {
  const [r, g, b] = hex(h).map(lin);
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  const L = 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s;
  const A = 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s;
  const B = 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s;
  return { L, C: Math.hypot(A, B), H: ((Math.atan2(B, A) * 180) / Math.PI + 360) % 360 };
}

/** The dataviz ordinal checks: one hue, monotone lightness, adjacent ΔL ≥ 0.06, the quiet end ≥ 2:1 on the ground. */
function ordinal(ramp: string[], surface: string, mode: 'dark' | 'light'): void {
  const ls = ramp.map(c => oklch(c).L);
  for (let i = 1; i < ls.length; i++) {
    if (mode === 'dark') expect(ls[i], `${ramp[i]} lighter than ${ramp[i - 1]}`).toBeGreaterThan(ls[i - 1]);
    else expect(ls[i], `${ramp[i]} darker than ${ramp[i - 1]}`).toBeLessThan(ls[i - 1]);
    expect(Math.abs(ls[i] - ls[i - 1]), `ΔL ${ramp[i - 1]}→${ramp[i]}`).toBeGreaterThanOrEqual(0.06);
  }
  expect(contrast(ramp[0], surface), `${ramp[0]} on ${surface}`).toBeGreaterThanOrEqual(2);
  const hues = ramp.map(c => oklch(c).H);
  expect(Math.max(...hues) - Math.min(...hues), 'hue spread').toBeLessThanOrEqual(40);
}

describe('one palette, declared once', () => {
  const dark = block(TOKENS_CSS, ':root');
  const light = block(TOKENS_CSS, ':root[data-theme="light"]');
  const ramp = (t: Record<string, string>): string[] => ['low', 'medium', 'high', 'critical'].map(k => t[`sev-${k}`]);

  it('names no colour outside the token blocks', () => {
    const rest = STYLES.slice(TOKENS_CSS.length);
    expect(rest).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/i);
    // And the page markup paints with roles and classes, not literals.
    expect(markup.replace(/<style>[\s\S]*?<\/style>/, '')).not.toMatch(/(fill|stroke|color|background)\s*[:=]\s*"?#[0-9a-f]{3,8}\b/i);
  });

  it('follows the OS with the same light values the toggle pins', () => {
    const media = TOKENS_CSS.slice(TOKENS_CSS.indexOf('@media (prefers-color-scheme: light)'));
    expect(block(media, ':root:not([data-theme="dark"]):not([data-host="vscode"])')).toEqual(light);
  });

  it('passes the ordinal checks: the dark ramp on every dark ground, the light ramp on every light one', () => {
    expect(ramp(dark)).toEqual(['#7c5c3f', '#af6533', '#db693a', '#ff7064']);
    expect(ramp(light)).toEqual(['#c69b78', '#c36c36', '#b4410d', '#9e1618']);
    for (const ground of [dark.canvas, dark.panel, '#1f1f1f']) ordinal(ramp(dark), ground, 'dark');
    for (const ground of [light.canvas, light.sunken]) ordinal(ramp(light), ground, 'light');
    // Inside VS Code's light themes the light ramp is the one in force.
    expect(ramp(block(TOKENS_CSS, ':root[data-host="vscode"] body.vscode-light, :root[data-host="vscode"] body.vscode-high-contrast-light'))).toEqual(ramp(light));
  });

  it('clears WCAG AA for every ink, the accent, resolved and review, on a panel, in both themes', () => {
    for (const [name, t] of [['dark', dark], ['light', light]] as const) {
      for (const role of ['fg', 'fg-muted', 'fg-subtle', 'accent', 'resolved', 'review']) {
        expect(contrast(t[role], t.panel), `${name} ${role}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it('keeps the accent off every data mark: steel is for selection, mint for resolved, warm for a threat claim', () => {
    expect(dark.accent).toBe('#8fc4ee');
    expect(light.accent).toBe('#2f6f9e');
    expect(dark.accent).not.toBe(dark.resolved);
    const diagramInk = STYLES.slice(STYLES.indexOf('/* SVG diagrams: the shared ink */'), STYLES.indexOf('/* shelves */'));
    // In the diagrams the accent marks only the pin, keyboard focus and the focused card.
    for (const line of diagramInk.split('\n').filter(l => l.includes('var(--accent)'))) expect(line, line).toMatch(/\.pin|\.kfocus|\.focus|:focus-visible/);
  });
});
