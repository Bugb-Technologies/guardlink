/**
 * Diagrams › System model: the data-flow diagram with trust boundaries as
 * zones, and the two page fixes that ride with it.
 *
 * The layout is checked on the repository's own fixtures, each of which
 * exercises one zone rule: directed boundaries between assets split the
 * system into ordered zones (boundary-direction); a boundary with an
 * undeclared route around it stays a gate, not a zone (expense-api); a model
 * with no boundaries is one zone; a model with no flows draws nothing.
 *
 * The page fixes:
 *  - Embedded data carries no `<`, so a host that adds a nonce to every
 *    `<script` in the page cannot rewrite one inside a string literal and
 *    stop the page script. Model text saying `<script>` used to do exactly
 *    that in an editor webview, which left every click on the page dead.
 *  - A click on a diagram mark answers in the drawer, which needs the mark to
 *    resolve to a drawer record: an asset to `assetsData`, an endpoint to
 *    `hoodData`.
 *
 * @validates #output-encoding for #dashboard -- "Model text containing <script> embeds with no tag-like sequence, and the page script still parses"
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseProject } from '../src/parser/parse-project.js';
import { canonicalizeModelOrder } from '../src/parser/canonical-order.js';
import { buildClaims } from '../src/dashboard/pages/context.js';
import { buildDiagramModel, type DiagramModel } from '../src/dashboard/layout/graph.js';
import { renderSystemModel, inferKind } from '../src/dashboard/layout/system.js';
import { generateDashboardHTML } from '../src/dashboard/generate.js';
import type { ThreatModel } from '../src/types/index.js';

const ROOT = process.cwd();
const fixture = (name: string): string => join(ROOT, 'tests', 'fixtures', name);

async function graphOf(root: string, project: string): Promise<{ model: ThreatModel; g: DiagramModel }> {
  let { model } = await parseProject({ root, project });
  model = canonicalizeModelOrder(model);
  return { model, g: buildDiagramModel(model, buildClaims(model, null, null)) };
}

/** The top of each element's first shape, by name. */
function rowY(svg: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const m of svg.matchAll(/<g class="el nd[^"]*"[^>]*data-name="([^"]+)"[^>]*>(?:<rect class="hit"[^>]*>)?<(?:rect|path) class="shape" (?:x="[^"]*" y="([\d.]+)"|d="M[\d.]+ ([\d.]+))/g)) {
    out.set(m[1].replace(/&#39;/g, "'"), Number(m[2] ?? m[3]));
  }
  return out;
}

function noNaN(svg: string): void {
  expect(svg).not.toMatch(/NaN|Infinity|undefined/);
}

describe('system model layout', () => {
  it('splits a layered system into zones ordered outer → inner by directed boundaries', async () => {
    const { g } = await graphOf(fixture('boundary-direction'), 'boundary-direction');
    const r = renderSystemModel(g)!;
    expect(r.innerZones).toBe(3);
    expect(r.outerZones).toBe(2);
    expect(r.unsplit).toEqual([]);
    const y = rowY(r.svg);
    expect(y.get('#web')!).toBeLessThan(y.get('#orders')!);
    expect(y.get('#orders')!).toBeLessThan(y.get('#store')!);
    expect(r.svg).toContain('ZONE 3');
    // Every asset ↔ asset boundary that separates two zones is a gate on its arc.
    expect((r.svg.match(/class="gate"/g) ?? []).length).toBe(r.crossing);
    noNaN(r.svg);
  });

  it('keeps a boundary with a way around it as a gate, and flags flows that leave a zone undeclared', async () => {
    const { g } = await graphOf(fixture('expense-api'), 'expense-api');
    const r = renderSystemModel(g)!;
    // #config and #auth connect #api and #db with no boundary, so #data-boundary cannot enclose a region.
    expect(r.innerZones).toBe(1);
    expect(r.unsplit).toEqual(['#data-boundary']);
    // Client is fenced off from #api, and also sends to #auth with no boundary declared there.
    const ends = (f: { source: string; target: string }): string => [g.nodes.get(f.source)!.label, g.nodes.get(f.target)!.label].sort().join(' ');
    const implied = g.flows.filter(f => ends(f) === '#auth Client');
    expect(implied.length).toBeGreaterThan(0);
    expect(r.implied).toBe(implied.length);
    // One line per direction.
    expect((r.svg.match(/class="thr x-implied"/g) ?? []).length).toBe(new Set(implied.map(f => `${f.source}>${f.target}`)).size);
    noNaN(r.svg);
  });

  it('draws one zone and no trust column when nothing is fenced off', async () => {
    const { model } = await graphOf(fixture('boundary-direction'), 'boundary-direction');
    const bare = { ...model, boundaries: [] };
    const g = buildDiagramModel(bare, buildClaims(bare, null, null));
    const r = renderSystemModel(g)!;
    expect(r.outerZones).toBe(0);
    expect(r.innerZones).toBe(1);
    expect(r.crossing).toBe(0);
    expect(r.svg).not.toContain('TRUST ZONE');
    expect(r.svg).toContain('one trust zone — no @boundary separates two of its assets');
    expect(r.elements).toBe(g.nodes.size);
  });

  it('draws nothing for a model with no flows', async () => {
    const { g } = await graphOf(fixture('support-desk'), 'support-desk');
    expect(g.flows.length).toBe(0);
    expect(renderSystemModel(g)).toBeNull();
  });

  it('draws every element and every flow of this repository\'s own model', async () => {
    const { g } = await graphOf(ROOT, 'guardlink');
    const r = renderSystemModel(g)!;
    expect(r.elements).toBe(g.nodes.size);
    expect(r.flows).toBe(g.flows.length);
    expect(r.processes + r.stores + r.entities).toBe(r.elements);
    expect(r.crossing).toBe(g.flows.filter(f => f.boundaries.length).length);
    expect((r.svg.match(/<g class="el nd/g) ?? []).length).toBe(r.elements);
    expect(r.boundaries).toBe(g.boundaryList.length);
    noNaN(r.svg);
  });
});

describe('element kinds are inferred', () => {
  const node = (label: string, external: boolean, via = '', actor = false) => ({
    key: label.toLowerCase(), label, external, actor, group: '', order: 0, description: '', exposures: [], open: 0, worst: null,
    flowsIn: via ? [{ i: 0, source: 'x', target: label.toLowerCase(), via, description: '', file: '', line: 0, boundary: null, boundaries: [] }] : [],
    flowsOut: [], boundaries: [], handles: [],
  });
  it('reads a declared asset as a process unless its name says it holds data', () => {
    expect(inferKind(node('#api', false))).toBe('process');
    expect(inferKind(node('#orders-db', false))).toBe('store');
  });
  it('reads an endpoint as a data store from its name or mechanism, otherwise an external entity', () => {
    expect(inferKind(node('ConfigFile', true))).toBe('store');
    expect(inferKind(node('Uploads', true, 'writeFileSync'))).toBe('store');
    expect(inferKind(node('Client', true))).toBe('entity');
    expect(inferKind(node('External.Stripe', true))).toBe('entity');
    expect(inferKind(node('ReportStore', true, '', true))).toBe('entity');
  });
});

describe('the page around it', () => {
  let root: string;
  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-sysmodel-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"sysmodel","version":"1.0.0"}\n');
    await writeFile(join(root, 'src', 'defs.ts'), [
      '// @asset App.Api (#api) -- "HTTP handlers"',
      '// @threat Cross_Site_Scripting (#xss) [high] -- "Markup from input"',
      '// @control Output_Encoding (#enc) -- "Escape on output"',
      '',
    ].join('\n'));
    await writeFile(join(root, 'src', 'api.ts'), [
      '/**',
      ' * @exposes #api to #xss [high] -- "Echoes a <script> tag the caller sent, then </script>"',
      ' * @boundary between Client and #api (#http) -- "Requests from the internet"',
      ' * @boundary between Client and #api (#tls) -- "TLS terminates here"',
      ' * @flows Client -> #api via POST./echo -- "Body to the handler"',
      ' * @flows #api -> Uploads via writeFileSync -- "Stored to disk"',
      ' */',
      'export const api = 1;',
      '',
    ].join('\n'));
  });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('keeps every boundary that names a pair, not just the last one', async () => {
    const { g } = await graphOf(root, 'sysmodel');
    const inbound = g.flows.find(f => g.nodes.get(f.source)!.label === 'Client')!;
    expect(inbound.boundaries).toEqual(['#http', '#tls']);
    expect(inbound.boundary).toBe('#http, #tls');
    const r = renderSystemModel(g)!;
    expect(r.svg).toContain('#http');
    expect(r.svg).toContain('#tls');
    expect(r.silent).toEqual([]);
  });

  it('embeds model text that says <script> without leaving a tag in the page', async () => {
    const { model } = await graphOf(root, 'sysmodel');
    const html = generateDashboardHTML(model, root);
    // One real script element, and nothing tag-like anywhere inside it.
    expect(html.match(/<script/gi)?.length).toBe(1);
    expect(html.match(/<\/script/gi)?.length).toBe(1);
    const body = html.slice(html.indexOf('<script>') + 8, html.lastIndexOf('</script>'));
    expect(() => new Function(body)).not.toThrow();
    // A host that adds a nonce to each `<script` leaves the page script intact.
    const rewritten = html.replace(/<script/g, '<script nonce="n0nce"');
    const after = rewritten.slice(rewritten.indexOf('>', rewritten.indexOf('<script')) + 1, rewritten.lastIndexOf('</script>'));
    expect(after).toBe(body);
    // The text itself survives: the escape is for the parser, not a loss.
    const claims = JSON.parse(/const claimsData = (\[.*?\]);\n/s.exec(html)![1]) as { description: string }[];
    expect(claims.some(c => c.description.includes('<script> tag'))).toBe(true);
  });

  it('gives every clickable diagram mark a drawer record to open', async () => {
    const { model } = await graphOf(root, 'sysmodel');
    const html = generateDashboardHTML(model, root);
    const assets = (JSON.parse(/const assetsData = (\[.*?\]);\n/s.exec(html)![1]) as { name: string }[]).map(a => a.name);
    const hood = JSON.parse(/const hoodData = (\{.*?\});\n/s.exec(html)![1]) as { nodes: { k: string; x: number }[] };
    const cards = [...html.matchAll(/class="shelf-card nd"[^>]*data-name="([^"]+)"/g)].map(m => m[1]);
    expect(cards.length).toBeGreaterThan(0);
    for (const c of cards) expect(assets).toContain(c);
    const marks = [...html.matchAll(/<g class="el nd k-\w+( ext)?"[^>]*data-key="([^"]+)"[^>]*data-name="([^"]+)"/g)];
    expect(marks.length).toBeGreaterThan(0);
    for (const [, ext, key, name] of marks) {
      if (ext) expect(hood.nodes.some(n => n.k === key && n.x)).toBe(true);
      else expect(assets).toContain(name);
    }
    expect(html).toContain('data-tab-panel="system"');
  });
});
