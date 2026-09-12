/**
 * Query-driven graph views, and the legibility budget that sizes them.
 *
 * The defect this covers is not a crash. It is a picture that draws perfectly,
 * passes every check the repository had, and cannot be read: GuardLink's own
 * threat graph is 43 nodes against a measured ceiling of 12, and its data flow
 * diagram is 67. Nothing in the product could say so, because the only question
 * anything asked about a diagram was whether Mermaid would draw it — and Mermaid
 * draws 43 nodes without complaint.
 *
 * So the claims pinned here are the ones that make "narrowed to fit" a thing a
 * reader can rely on:
 *
 *   every diagram a view emits is within the budget, or is not emitted;
 *   a view that could not be narrowed says so instead of drawing anyway;
 *   what fell outside the frame is named, and is what is ADJACENT to the frame
 *     rather than everything reachable;
 *   the committed slices hold the same guarantee, on the surfaces we do not
 *     configure;
 *   and #34's guarantees are exactly where #34 left them.
 *
 * The last one matters as much as the rest: `validate --artifacts` runs in other
 * people's pipelines, and a repository that was green before this change has to
 * still be green, byte for byte.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { canonicalizeModelOrder } from '../src/parser/canonical-order.js';
import { generateThreatGraph, generateDataFlowDiagram } from '../src/dashboard/diagrams.js';
import { generateDashboardHTML } from '../src/dashboard/generate.js';
import { buildExploreData } from '../src/dashboard/explore.js';
import { selectSubgraph } from '../src/mcp/subgraph.js';
import { checkRenderBudget } from '../src/dashboard/render-budget.js';
import {
  LEGIBILITY_BUDGET, checkLegibility, measureLegibility, countMermaidNodes,
  countMermaidClusters, describeLegibility, legibilityImpliesDrawable,
} from '../src/graph/legibility.js';
import {
  GRAPH_VIEWS, growWithinBudget, assetThreatPlane, keepHighSeverity,
  assetsDeclaredIn, boundarySides, FLOW_KINDS,
} from '../src/graph/views.js';
import {
  emitArtifacts, sliceArtifacts, expectedArtifactPaths, legibilityPreamble,
  checkArtifactDrift, checkArtifactRenderability, mermaidHeader,
} from '../src/artifacts/emit.js';
import type { ThreatModel } from '../src/types/index.js';

// ─── Fixtures ────────────────────────────────────────────────────────

/** Small enough that every whole-model diagram is legible. #34's shape. */
const TINY = `/**
 * @asset App.API (#api) -- "REST surface"
 * @asset App.DB (#db) -- "store"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "untrusted input"
 * @control Prepared_Statements (#ps) -- "parameterized"
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "concatenated"
 * @mitigates #api against #sqli using #ps -- "pg placeholders"
 * @flows User -> #api via HTTPS -- "request"
 * @flows #api -> #db via query -- "lookup"
 * @boundary between #api and #db -- "app to store"
 */
export function handler() {}
`;

/**
 * A hub: one component carrying many threats and many flow neighbours.
 *
 * Both narrowing ladders have to fire somewhere, and neither fires on a model
 * small enough to draw whole — which is exactly why the defect survived so
 * long. `#hub` carries 14 threats across four severities (so the severity rung
 * is reachable AND still over budget for the threat plane) and is wired to 20
 * satellites (so the flow plane must stop growing).
 */
async function writeHubRepo(root: string): Promise<void> {
  await mkdir(join(root, '.guardlink'), { recursive: true });
  // Four serious threats and ten quiet ones: enough that the whole plane is
  // over budget (1 + 14 + 6 = 21 nodes) and the high/critical narrowing lands
  // under it. An even spread across severities leaves eight serious threats,
  // which is still over — and then this fixture would only ever exercise the
  // bottom rung of the ladder.
  const sev = (i: number) => (i < 4 ? ['critical', 'high'][i % 2] : ['medium', 'low'][i % 2]);
  const defs = ['/**', ' * @asset App.Hub (#hub) -- "the busy one"', ' * @asset App.Quiet (#quiet) -- "no claims at all"'];
  for (let i = 0; i < 14; i++) defs.push(` * @threat Threat_${i} (#t${i}) [${sev(i)}] -- "synthetic ${i}"`);
  for (let i = 0; i < 6; i++) defs.push(` * @control Control_${i} (#c${i}) -- "synthetic control ${i}"`);
  for (let i = 0; i < 20; i++) defs.push(` * @asset App.Sat${i} (#sat${i}) -- "satellite ${i}"`);
  defs.push(' */');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), defs.join('\n') + '\nexport {};\n');

  await mkdir(join(root, 'src'), { recursive: true });
  const hub: string[] = ['/**'];
  for (let i = 0; i < 14; i++) hub.push(` * @exposes #hub to #t${i} [${sev(i)}] -- "hub weakness ${i}"`);
  for (let i = 0; i < 6; i++) hub.push(` * @mitigates #hub against #t${i} using #c${i} -- "hub control ${i}"`);
  hub.push(' */');
  await writeFile(join(root, 'src', 'hub.ts'), hub.join('\n') + '\nexport function hub() {}\n');

  const wires: string[] = ['/**'];
  for (let i = 0; i < 20; i++) wires.push(` * @flows #hub -> #sat${i} via call${i} -- "hub to satellite ${i}"`);
  wires.push(' * @boundary between #hub and #sat0 -- "hub to first satellite"');
  wires.push(' */');
  await writeFile(join(root, 'src', 'wires.ts'), wires.join('\n') + '\nexport function wires() {}\n');
}

const THREAT_PLANE = (m: ThreatModel): string => generateThreatGraph(m, { showAll: true, icons: 'none' });
const FLOW_PLANE = (m: ThreatModel): string => generateDataFlowDiagram(m, { icons: 'none' });

// ─── The budget itself ───────────────────────────────────────────────

describe('the legibility budget', () => {
  it('is the measured ceiling, not a round number someone liked', () => {
    // `#blame` at 11 nodes / 15 edges was the last slice that fitted with legible
    // labels; `#cli` at 14 / 21 was the first that did not.
    expect(LEGIBILITY_BUDGET.nodes).toBe(12);
    expect(LEGIBILITY_BUDGET.edges).toBe(16);
  });

  it('is strictly tighter than drawability, so a legible diagram can never hit Mermaid\'s silent failure', () => {
    expect(legibilityImpliesDrawable()).toBe(true);
  });

  it('counts what the real generators emit, exactly', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-leg-'));
    try {
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(join(root, 'src', 'api.ts'), TINY);
      const { model } = await parseProject({ root, project: 'leg' });
      const src = THREAT_PLANE(canonicalizeModelOrder(model));
      // #api, #sqli, #ps. #db carries no claim, so the threat graph never
      // registers it — the trust zone it shares with #api is still drawn.
      expect(countMermaidNodes(src)).toBe(3);
      expect(countMermaidClusters(src)).toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reads endpoints off a link, not just declarations — an inline arrow label is not a node', () => {
    const src = [
      'graph LR',
      '  a["asset"]',
      '  b{{"threat"}}:::sev_high',
      '  a -. exposes .-> b',
      '  a -- mitigates --> b',
      '  a -- "transfers risk: something" --> b',
      '  a -.-|trust boundary| b',
      '  classDef sev_high fill:#402019',
    ].join('\n');
    // `exposes`, `mitigates`, `sev_high` and the quoted caption are not nodes.
    expect(countMermaidNodes(src)).toBe(2);
  });

  it('does not count a subgraph container as a node — Mermaid draws it as a cluster', () => {
    const src = ['graph LR', '  subgraph TZ0["zone"]', '    a["one"]', '  end', '  b["two"]', '  a --> b'].join('\n');
    expect(countMermaidNodes(src)).toBe(2);
    expect(countMermaidClusters(src)).toBe(1);
  });

  it('treats an empty diagram as legible — "nothing to draw" is not "too big to read"', () => {
    expect(checkLegibility('').legible).toBe(true);
    expect(measureLegibility('').nodes).toBe(0);
  });

  it('says the size and the budget in one line, both ways round', () => {
    expect(describeLegibility(checkLegibility('graph LR\n  a["x"]\n  b["y"]\n  a --> b')))
      .toBe('2 nodes / 1 edge, within the 12 / 16 legibility budget');
    const big = ['graph LR', ...Array.from({ length: 20 }, (_, i) => `  n${i}["node ${i}"]`),
      ...Array.from({ length: 19 }, (_, i) => `  n${i} --> n${i + 1}`)].join('\n');
    expect(describeLegibility(checkLegibility(big)))
      .toBe('20 nodes / 19 edges, past the 12 / 16 legibility budget (20 nodes against 12, 19 edges against 16)');
  });
});

/**
 * The numbers above were independently measured in a real browser against real
 * rendered SVG geometry. This is the check that the counter agrees with what
 * Mermaid actually draws.
 *
 * **The measured input is frozen, not re-parsed.** This used to point at a live
 * `parseProject('.')` — guardlink's own model — because that is the one diagram
 * both the browser and the counter could be aimed at. But then the assertion
 * says two things at once: "the counter agrees with the browser" and "this
 * repository's model is still exactly the size it was the day someone opened
 * Chrome". Only the first is a claim about the code. The second decays on the
 * next annotation anyone adds, which `CLAUDE.md` *requires* them to add on any
 * security-relevant change — so the suite went red for doing what the project
 * asks, and the cheap repair (bump the literal) silently falsifies the comment
 * beside it, which cites a real measurement.
 *
 * So the diagram Chrome measured is checked in as a fixture, and the live model
 * is asserted only where the answer cannot decay: it is at least as large as
 * the frozen one, and it is past the budget. The exact live size is not a fact
 * about this code.
 */
describe('the node counter against browser-measured geometry', () => {
  const FROZEN = join(
    dirname(fileURLToPath(import.meta.url)),
    'fixtures', 'threat-graph-browser-measured.mmd',
  );

  it('agrees with the rendered SVG on the diagram the browser measured', () => {
    // Measured in Chrome at 1440x900 against the default (high/critical-
    // filtered) threat graph of this repository's model at 5c720d3: 29 `.node`
    // elements and 70 `path.flowchart-link`s.
    const m = measureLegibility(readFileSync(FROZEN, 'utf-8'));
    expect(m.nodes).toBe(29);
    expect(m.edges).toBe(70);
  });

  it('still reports this repository past the budget, at whatever size it now is', async () => {
    const { model } = await parseProject({ root: '.', project: 'guardlink' });
    const ordered = canonicalizeModelOrder(model);
    const frozen = measureLegibility(readFileSync(FROZEN, 'utf-8'));

    // A model only grows here: annotations are added far more often than
    // removed, and a removal that shrank the graph past the frozen size is
    // worth a failing test and a look.
    const live = measureLegibility(generateThreatGraph(ordered, { icons: 'none' }));
    expect(live.nodes).toBeGreaterThanOrEqual(frozen.nodes);
    expect(live.edges).toBeGreaterThanOrEqual(frozen.edges);

    // And the claim the whole of this work exists for: the whole-model diagram
    // is far past a legibility budget of ~12 nodes. That is the durable fact —
    // not the particular number it overshoots by this week.
    const all = measureLegibility(generateThreatGraph(ordered, { showAll: true, icons: 'none' }));
    expect(all.nodes).toBeGreaterThan(frozen.nodes);
    expect(checkLegibility(generateThreatGraph(ordered, { showAll: true, icons: 'none' })).legible).toBe(false);
  });
});

// ─── Selection ───────────────────────────────────────────────────────

describe('growing a neighbourhood to fit', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-hub-'));
    await writeHubRepo(root);
    ({ model } = await parseProject({ root, project: 'hub' }));
    model = canonicalizeModelOrder(model);
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the fixture is genuinely past the budget whole — otherwise this suite proves nothing', () => {
    expect(checkLegibility(FLOW_PLANE(model)).legible).toBe(false);
    expect(checkLegibility(THREAT_PLANE(model)).legible).toBe(false);
  });

  it('stops at the budget instead of at a hop count', () => {
    const grown = growWithinBudget(model, { seeds: ['#hub'], render: FLOW_PLANE, kinds: FLOW_KINDS });
    expect(grown.verdict.legible).toBe(true);
    expect(grown.verdict.measurement.nodes).toBeLessThanOrEqual(LEGIBILITY_BUDGET.nodes);
    expect(grown.verdict.measurement.edges).toBeLessThanOrEqual(LEGIBILITY_BUDGET.edges);
    // It grew: a hub wired to 20 satellites gives back more than the seed alone.
    expect(grown.included.length).toBeGreaterThan(1);
  });

  it('always keeps the seeds — they are what the reader asked about', () => {
    const grown = growWithinBudget(model, { seeds: ['#hub'], render: FLOW_PLANE, kinds: FLOW_KINDS });
    expect(grown.included[0]).toBe('hub');
  });

  it('names what is one hop outside the frame, not everything reachable', () => {
    const grown = growWithinBudget(model, { seeds: ['#hub'], render: FLOW_PLANE, kinds: FLOW_KINDS });
    const drawn = new Set(grown.included);
    expect(grown.omitted.length).toBeGreaterThan(0);
    // Every omitted node is adjacent to something drawn, and none is drawn.
    for (const k of grown.omitted) expect(drawn.has(k)).toBe(false);
    expect(grown.included.length + grown.omitted.length).toBe(21); // hub + 20 satellites
  });

  it('is deterministic — the same model always yields the same view', () => {
    const a = growWithinBudget(model, { seeds: ['#hub'], render: FLOW_PLANE, kinds: FLOW_KINDS });
    const b = growWithinBudget(model, { seeds: ['#hub'], render: FLOW_PLANE, kinds: FLOW_KINDS });
    expect(a.included).toEqual(b.included);
    expect(a.source).toBe(b.source);
  });

  it('reports an empty answer as empty rather than as an unreadable one', () => {
    // `#quiet` has no flows at all. A generator returns a header and classDefs
    // for that; a panel must be able to tell it from a drawing.
    const grown = growWithinBudget(model, { seeds: ['#quiet'], render: FLOW_PLANE, kinds: FLOW_KINDS });
    expect(grown.source).toBe('');
  });
});

describe('one component\'s classification plane', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-plane-'));
    await writeHubRepo(root);
    ({ model } = await parseProject({ root, project: 'hub' }));
    model = canonicalizeModelOrder(model);
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('narrows by severity rather than drawing 14 threats around one node', () => {
    const plane = assetThreatPlane(model, '#hub', THREAT_PLANE);
    expect(plane.narrowing).toBe('high-severity-only');
    expect(plane.hidden).toBeGreaterThan(0);
    expect(checkLegibility(plane.source).legible).toBe(true);
  });

  it('never returns a source that exceeds the budget — it returns none', () => {
    for (const asset of model.assets) {
      const plane = assetThreatPlane(model, asset.id ?? '', THREAT_PLANE);
      if (plane.source) expect(checkLegibility(plane.source).legible, asset.id).toBe(true);
      else expect(['not-drawn', 'none']).toContain(plane.narrowing);
    }
  });

  it('declines to draw rather than drawing something illegible, when narrowing is not enough', () => {
    // Thirty critical threats on one component cannot be narrowed by severity:
    // every one of them survives the filter.
    const threat0 = model.threats[0];
    const exposure0 = model.exposures[0];
    const crowded: ThreatModel = {
      ...model,
      threats: Array.from({ length: 30 }, (_, i) => ({ ...threat0, id: `x${i}`, canonical_name: `X_${i}`, severity: 'critical' })),
      exposures: Array.from({ length: 30 }, (_, i) => ({ ...exposure0, asset: '#hub', threat: `#x${i}`, severity: 'critical' })),
      mitigations: [], confirmed: [], acceptances: [], validations: [],
    };
    const plane = assetThreatPlane(crowded, '#hub', THREAT_PLANE);
    expect(plane.narrowing).toBe('not-drawn');
    expect(plane.source).toBe('');
  });

  it('an empty plane is empty, not narrowed and not refused', () => {
    const plane = assetThreatPlane(model, '#quiet', THREAT_PLANE);
    expect(plane.narrowing).toBe('none');
    expect(plane.source).toBe('');
  });

  it('keepHighSeverity drops a threat definition left behind by its last claim', () => {
    const { model: kept, hidden } = keepHighSeverity(
      selectSubgraph(model, { nodes: ['hub'], kinds: ['exposures', 'mitigations'] }));
    expect(hidden).toBeGreaterThan(0);
    for (const t of kept.threats) expect(['critical', 'high']).toContain((t.severity || '').toLowerCase());
  });
});

describe('selectSubgraph\'s explicit node set', () => {
  let model: ThreatModel;

  beforeAll(async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-nodes-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), TINY);
    ({ model } = await parseProject({ root, project: 'nodes' }));
    model = canonicalizeModelOrder(model);
    await rm(root, { recursive: true, force: true });
  });

  it('canonicalises, so one component spelled three ways is one node', () => {
    const a = selectSubgraph(model, { nodes: ['#api'] });
    const b = selectSubgraph(model, { nodes: ['api'] });
    const c = selectSubgraph(model, { nodes: ['App.API'] });
    expect(a.exposures.length).toBe(1);
    expect(b.exposures.length).toBe(1);
    expect(c.exposures.length).toBe(1);
  });

  it('takes precedence over a traversal — the caller already decided', () => {
    // depth 2 from #api reaches #db; an explicit node set of just #api does not.
    const traversed = selectSubgraph(model, { from: '#api', depth: 2 });
    expect(traversed.flows.length).toBeGreaterThan(0);
    const explicit = selectSubgraph(model, { from: '#api', depth: 2, nodes: ['#api'] });
    expect(explicit.flows.length).toBe(0);
  });

  it('still composes with kinds', () => {
    const flows = selectSubgraph(model, { nodes: ['#api', '#db'], kinds: ['flows'] });
    expect(flows.flows.length).toBe(1);
    expect(flows.exposures).toEqual([]);
  });
});

// ─── The Explore page ────────────────────────────────────────────────

describe('the Explore page', () => {
  let root: string;
  let model: ThreatModel;
  let html: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-explore-'));
    await writeHubRepo(root);
    ({ model } = await parseProject({ root, project: 'hub' }));
    model = canonicalizeModelOrder(model);
    html = generateDashboardHTML(model, root);
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('every diagram it embeds is within the budget — the whole claim, on a model that is not', () => {
    const data = buildExploreData({ model, openByAsset: new Map(), totalByAsset: new Map(), changes: null });
    const every = [
      ...data.assets.flatMap(a => [a.threatPlane, a.flowPlane]),
      ...data.boundaries.map(b => b.diagram),
      ...data.files.map(f => f.diagram),
    ];
    expect(every.length).toBeGreaterThan(0);
    for (const d of every) {
      if (!d.source) continue;
      const v = checkLegibility(d.source);
      expect(v.legible, `${d.budgetNote}`).toBe(true);
      // And therefore drawable, without needing a second check.
      expect(checkRenderBudget(d.source).renderable).toBe(true);
    }
  });

  it('says what every view is for, in the reader\'s words', () => {
    for (const v of GRAPH_VIEWS) {
      if (v.id === 'diff') continue; // only present under --since
      expect(html, v.id).toContain(v.question);
    }
  });

  it('tells the reader the feature dropdown does not narrow these answers', () => {
    // The top-bar feature filter hides rows by file; an Explore pane carries no
    // file, so selecting a feature cannot narrow it. wholeModelNote() is the
    // sentence that says so — and it only works if filterPage stops clobbering
    // it, because it carries `filter-status` as well as `whole-model-note` and
    // the lookup returns the first match. Measured in a browser before the fix:
    // onFeatureFilter un-hid the note and filterPage re-hid it in the same tick,
    // so a feature could be selected on Explore with no effect and no
    // explanation.
    expect(html).toContain('whole-model-note');
    expect(html).toContain('but this page shows the whole model');
    expect(html).toContain(".filter-status:not(.whole-model-note)");
  });

  it('says why a view that is not a diagram is not a diagram', () => {
    const list = GRAPH_VIEWS.find(v => v.id === 'threat')!;
    expect(list.shape).toBe('list');
    expect(html).toContain('Answered as a list, not a diagram');
    expect(html).toContain('Answered as a matrix, not a diagram');
  });

  it('offers no subject that has no pane behind it', () => {
    const panes = new Set<string>();
    for (const m of html.matchAll(/data-view="([^"]*)" data-subject="([^"]*)"/g)) panes.add(`${m[1]} ${m[2]}`);
    for (const sel of html.matchAll(/<select class="explore-subject" data-view="([^"]+)"[\s\S]*?<\/select>/g)) {
      const view = sel[1];
      for (const opt of sel[0].matchAll(/<option value="([^"]*)"/g)) {
        expect(panes.has(`${view} ${opt[1]}`), `${view}:${opt[1]}`).toBe(true);
      }
    }
  });

  it('states the size of every diagram it does draw, and what fell outside', () => {
    const data = buildExploreData({ model, openByAsset: new Map(), totalByAsset: new Map(), changes: null });
    const hub = data.assets.find(a => a.key === 'hub')!;
    expect(hub.flowPlane.budgetNote).toContain('legibility budget');
    expect(hub.flowPlane.omitted.length).toBeGreaterThan(0);
    expect(hub.threatPlane.narrowing).toBe('high-severity-only');
  });

  it('says why there is nothing to draw, rather than showing an empty canvas', () => {
    const data = buildExploreData({ model, openByAsset: new Map(), totalByAsset: new Map(), changes: null });
    const quiet = data.assets.find(a => a.key === 'quiet')!;
    expect(quiet.flowPlane.source).toBe('');
    expect(quiet.flowPlane.emptyReason).toBeTruthy();
  });

  it('says how many routes it searched, so "no findings" cannot be read as "no routes"', () => {
    const data = buildExploreData({ model, openByAsset: new Map(), totalByAsset: new Map(), changes: null });
    expect(data.pathsTotal).toBeGreaterThanOrEqual(data.paths.length);
  });
});

describe('the whole-model Diagrams page', () => {
  it('names its own size when it is past readable, instead of presenting it as fine', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-whole-'));
    try {
      await writeHubRepo(root);
      const { model } = await parseProject({ root, project: 'hub' });
      const html = generateDashboardHTML(canonicalizeModelOrder(model), root);
      // The class name alone would match the stylesheet, which every page
      // carries. The notice is what has to be there.
      expect(html).toContain('past the size anyone can read');
      expect(html).toContain('<div class="diagram-toobig" role="note">');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('says nothing of the kind on a model small enough to read whole', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-whole-ok-'));
    try {
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(join(root, 'src', 'api.ts'), TINY);
      const { model } = await parseProject({ root, project: 'ok' });
      const html = generateDashboardHTML(canonicalizeModelOrder(model), root);
      expect(html).not.toContain('<div class="diagram-toobig" role="note">');
      expect(html).not.toContain('past the size anyone can read');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ─── The committed slices ────────────────────────────────────────────

describe('the committed slices', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-slices-'));
    await writeHubRepo(root);
    ({ model } = await parseProject({ root, project: 'hub' }));
    model = canonicalizeModelOrder(model);
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('every emitted .mmd under by-asset/ and by-boundary/ is legible', async () => {
    emitArtifacts({ root, model });
    for (const dir of ['by-asset', 'by-boundary']) {
      const at = join(root, '.guardlink', 'graph', dir);
      const files = await readdir(at);
      expect(files.length, dir).toBeGreaterThan(0);
      for (const f of files) {
        const text = await readFile(join(at, f), 'utf-8');
        const v = checkLegibility(text);
        expect(v.legible, `${dir}/${f}: ${describeLegibility(v)}`).toBe(true);
      }
    }
  });

  it('writes nothing for a slice it could not make legible, and no stub either', () => {
    const slices = sliceArtifacts(model);
    for (const s of slices) expect(checkLegibility(s.body).legible, s.path).toBe(true);
    // `#quiet` declares no claims and no flows, so it contributes no file at all.
    expect(slices.some(s => s.file.startsWith('quiet.'))).toBe(false);
  });

  it('each slice says what it leaves out, in its own header', async () => {
    emitArtifacts({ root, model });
    const text = await readFile(join(root, '.guardlink', 'graph', 'by-asset', 'hub.flows.mmd'), 'utf-8');
    expect(text).toContain('%% scope:           PARTIAL —');
    expect(text).toContain('neighbour(s) one hop out are not shown');
    // And still carries the hash the drift check reads.
    expect(text).toMatch(/^%% annotation_hash: sha256-/m);
  });

  it('the emitter and the drift check agree on which files should exist', () => {
    const { written } = emitArtifacts({ root, model });
    for (const expected of expectedArtifactPaths(model)) {
      expect(written, expected).toContain(expected);
    }
    expect(checkArtifactDrift(root, model)).toEqual([]);
    expect(checkArtifactRenderability(root)).toEqual([]);
  });

  it('sweeps a slice whose component no longer exists', async () => {
    emitArtifacts({ root, model });
    const at = join(root, '.guardlink', 'graph', 'by-asset', 'ghost.threats.mmd');
    await writeFile(at, mermaidHeader('by-asset/ghost.threats.mmd', { annotation_hash: 'stale', generator: 'x' }) + 'graph LR\n  a["x"]\n');
    emitArtifacts({ root, model });
    await expect(readFile(at, 'utf-8')).rejects.toThrow();
  });

  it('index.md lists every slice that was written', async () => {
    const { written } = emitArtifacts({ root, model });
    const index = await readFile(join(root, '.guardlink', 'graph', 'index.md'), 'utf-8');
    for (const path of written) {
      if (!path.includes('/by-asset/') && !path.includes('/by-boundary/')) continue;
      expect(index, path).toContain(path.replace('.guardlink/graph/', ''));
    }
    expect(index).toContain('what to open, and for which question');
  });

  it('a whole-model diagram that draws but cannot be read says so, in the file itself', async () => {
    emitArtifacts({ root, model });
    const text = await readFile(join(root, '.guardlink', 'graph', 'threat-graph.mmd'), 'utf-8');
    expect(text).toContain('%% DRAWS, BUT IS TOO BIG TO READ.');
    expect(text).toContain('by-asset/');
    // And saying it costs nothing against the limit it is not about: `%%` lines
    // are stripped before Mermaid measures.
    expect(checkRenderBudget(text).renderable).toBe(true);
  });

  it('addresses a boundary by its declared id, so an edited description does not rename the file', () => {
    const slices = sliceArtifacts(model);
    expect(slices.some(s => s.path.includes('/by-boundary/'))).toBe(true);
    expect(boundarySides(model, 0).length).toBe(2);
  });

  it('finds the components a file names, for the blast-radius view', () => {
    expect(assetsDeclaredIn(model, 'src/wires.ts')).toContain('hub');
    expect(assetsDeclaredIn(model, 'src/nowhere.ts')).toEqual([]);
  });
});

/**
 * #34 drew a line: a repository within budget emits byte-identical `.mmd` files
 * and `validate --artifacts` still exits 0. This change adds files beside them
 * and must not move that line, because the check runs in other people's
 * pipelines.
 */
describe('a repository that was already fine is still fine', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-unchanged-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), TINY);
    ({ model } = await parseProject({ root, project: 'unchanged' }));
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('the three whole-model diagrams are still exactly the header plus the generator output', async () => {
    const { provenance } = emitArtifacts({ root, model });
    const ordered = canonicalizeModelOrder(model);
    const text = await readFile(join(root, '.guardlink', 'graph', 'threat-graph.mmd'), 'utf-8');
    expect(text).toBe(mermaidHeader('threat-graph.mmd', provenance) + generateThreatGraph(ordered, { showAll: true }));
    // Which means: not one character of legibility text on a model that fits.
    expect(text).not.toContain('TOO BIG TO READ');
  });

  it('reports nothing undrawable and nothing stale', () => {
    const result = emitArtifacts({ root, model });
    expect(result.undrawable).toEqual([]);
    expect(checkArtifactRenderability(root)).toEqual([]);
    expect(checkArtifactDrift(root, model)).toEqual([]);
  });

  it('regenerating twice produces identical bytes across every new directory too', async () => {
    emitArtifacts({ root, model });
    const read = async () => {
      const out: Record<string, string> = {};
      for (const dir of ['', 'by-asset', 'by-boundary', 'by-feature']) {
        const at = join(root, '.guardlink', 'graph', dir);
        for (const f of await readdir(at, { withFileTypes: true })) {
          if (f.isFile()) out[`${dir}/${f.name}`] = await readFile(join(at, f.name), 'utf-8');
        }
      }
      return out;
    };
    const first = await read();
    emitArtifacts({ root, model });
    expect(await read()).toEqual(first);
  });

  it('legibilityPreamble is silent on anything that fits', () => {
    expect(legibilityPreamble('x.mmd', 'graph LR\n  a["one"]\n  b["two"]\n  a --> b')).toBe('');
  });
});
