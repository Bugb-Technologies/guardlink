/**
 * The Mermaid render budget — the check that answers "will anything draw this?"
 *
 * The defect this covers is a silent one. Past `maxTextSize` Mermaid resolves
 * the render successfully, writes nothing to the console and draws a single pink
 * box reading "Maximum text size in diagram exceeded"; past `maxEdges` it throws
 * and the page shows a syntax error. Measured on a 257-annotated-file repository,
 * `guardlink artifacts` wrote a threat graph no renderer would draw and
 * `guardlink validate . --artifacts` reported "Artifacts are current".
 *
 * Two things are therefore pinned here and nowhere else: that a model at that
 * measured size produces a diagnostic instead of an undrawable file, and that a
 * model BELOW it is byte-for-byte what it always was. The second matters as much
 * as the first — this check runs in other people's pipelines.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import {
  generateDashboardHTML, generateThreatGraph, generateDataFlowDiagram, generateAttackSurface,
} from '../src/dashboard/index.js';
import { canonicalizeModelOrder } from '../src/parser/canonical-order.js';
import {
  MERMAID_LIMITS, mermaidRenderText, countMermaidEdges, measureDiagram,
  checkRenderBudget, describeViolation, oversizedStub,
} from '../src/dashboard/render-budget.js';
import { emitArtifacts, checkArtifactDrift, checkArtifactRenderability, mermaidHeader } from '../src/artifacts/emit.js';
import type { ThreatModel } from '../src/types/index.js';

// ─── Fixtures ────────────────────────────────────────────────────────

const SMALL = `/**
 * @asset App.API (#api) -- "REST surface"
 * @asset App.DB (#db) -- "store"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "untrusted input"
 * @control Prepared_Statements (#ps) -- "parameterized"
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "concatenated"
 * @mitigates #api against #sqli using #ps -- "pg placeholders"
 * @flows User -> #api via HTTPS -- "request"
 * @flows #api -> #db via query -- "lookup"
 */
export function handler() {}
`;

/**
 * The shape the scout report measured: 64 modules × 4 annotated files = 257
 * annotated files, whose threat graph crosses Mermaid's edge cap.
 *
 * Written out rather than hand-built as a ThreatModel so the parser is in the
 * loop — the claim under test is about what `guardlink artifacts` does to a
 * repository, not about what one function does to an object.
 */
async function writeScaleRepo(root: string, modules: number): Promise<void> {
  const threats = [
    ['SQL_Injection', 'sqli', 'critical', 'CWE-89'],
    ['Cross_Site_Scripting', 'xss', 'high', 'CWE-79'],
    ['Path_Traversal', 'ptrav', 'high', 'CWE-22'],
    ['Broken_Access_Control', 'bac', 'medium', 'CWE-285'],
    ['Sensitive_Data_Exposure', 'sde', 'low', 'CWE-200'],
  ];
  const controls = [['Prepared_Statements', 'ps'], ['Output_Encoding', 'oe'], ['Path_Validation', 'pv'], ['AuthZ_Check', 'az'], ['Redaction', 'rd']];

  await mkdir(join(root, '.guardlink'), { recursive: true });
  const defs = [
    '/**',
    ...threats.map(([n, i, s, c]) => ` * @threat ${n} (#${i}) [${s}] cwe:${c} -- "synthetic ${n}"`),
    ...controls.map(([n, i]) => ` * @control ${n} (#${i}) -- "synthetic ${n}"`),
  ];
  for (let m = 0; m < modules; m++) {
    defs.push(` * @asset Mod${m}.API (#m${m}-api) -- "module ${m} api surface"`);
    defs.push(` * @asset Mod${m}.DB (#m${m}-db) -- "module ${m} store"`);
  }
  defs.push(' */');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), defs.join('\n') + '\nexport {};\n');

  for (let m = 0; m < modules; m++) {
    const dir = join(root, 'src', `mod${m}`);
    await mkdir(dir, { recursive: true });
    const t = threats[m % threats.length];
    const t2 = threats[(m + 2) % threats.length];
    const c = controls[m % controls.length];
    await writeFile(join(dir, 'api.ts'), `/**
 * @exposes #m${m}-api to #${t[1]} [${t[2]}] cwe:${t[3]} -- "module ${m} untrusted input reaches the handler"
 * @exposes #m${m}-api to #${t2[1]} [${t2[2]}] -- "module ${m} second weakness on the same surface"
 * @mitigates #m${m}-api against #${t[1]} using #${c[1]} -- "module ${m} control on the request path"
 * @flows User -> #m${m}-api via HTTPS -- "module ${m} request"
 * @flows #m${m}-api -> #m${m}-db via query -- "module ${m} lookup"
 * @boundary between #m${m}-api and #m${m}-db -- "module ${m} trust change"
 * @handles pii on #m${m}-api -- "module ${m} handles email"
 */
export function handler${m}() {}
`);
    await writeFile(join(dir, 'db.ts'), `/**
 * @exposes #m${m}-db to #sde [low] -- "module ${m} store holds records"
 * @audit #m${m}-db -- "module ${m} retention needs human review"
 * @flows #m${m}-db -> #m${(m + 1) % modules}-api via replication -- "module ${m} fan-out"
 */
export function store${m}() {}
`);
    await writeFile(join(dir, 'worker.ts'), `/**
 * @assumes #m${m}-api -- "module ${m} caller already authenticated"
 * @flows #m${m}-api -> External.Queue via publish -- "module ${m} job"
 */
export function worker${m}() {}
`);
    await writeFile(join(dir, 'test.ts'), `/**
 * @validates #${c[1]} for #m${m}-api -- "module ${m} test pins the control"
 */
export function test${m}() {}
`);
  }
}

// ─── The limits themselves ───────────────────────────────────────────

describe('the limits are Mermaid\'s, not ours', () => {
  it('are the defaults mermaid@11 ships', () => {
    // Read out of mermaid@11.17.2's bundle, not out of the docs:
    //   chunk-QJSWEUOL.mjs   …layout:"dagre",maxTextSize:5e4,maxEdges:500,…
    //   mermaid.esm.min.mjs  e.length>(o?.maxTextSize??yo)&&(e=xo); var yo=5e4
    //   chunk-CLS4B6BI.mjs   if(this.edges.length<(this.config.maxEdges??500))…else throw
    expect(MERMAID_LIMITS.maxTextSize).toBe(50_000);
    expect(MERMAID_LIMITS.maxEdges).toBe(500);
  });

  it('the dashboard states them rather than inheriting them', async () => {
    // The page loads `mermaid@11` from a CDN, so an implicit default could move
    // underneath the budget on any patch release and the two would disagree.
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rb-init-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SMALL);
    const { model } = await parseProject({ root, project: 'rb' });
    const html = generateDashboardHTML(model, root);
    expect(html).toContain(`maxTextSize: ${MERMAID_LIMITS.maxTextSize}`);
    expect(html).toContain(`maxEdges: ${MERMAID_LIMITS.maxEdges}`);
    await rm(root, { recursive: true, force: true });
  });
});

// ─── Measurement ─────────────────────────────────────────────────────

describe('measuring a diagram the way Mermaid measures it', () => {
  it('does not charge the provenance header against the budget', () => {
    // Mermaid's cleanupComments strips `%%` lines before the length check, so a
    // file measured by its byte length would be measured wrong.
    const withHeader = '%% GENERATED FILE — do not edit.\n%% annotation_hash: sha256-v3:abc\n\nflowchart TB\n  A --> B';
    expect(mermaidRenderText(withHeader)).toBe('flowchart TB\n  A --> B');
  });

  it('keeps %%{init}%% directives, which are not comments', () => {
    const directive = '%%{init: {"theme":"dark"}}%%\nflowchart TB\n  A --> B';
    expect(mermaidRenderText(directive)).toContain('%%{init');
  });

  it.each([
    ['A --> B', 1],
    ['A --- B', 1],
    ['A -- mitigates --> B', 1],
    ['A -. exposes .-> B', 1],
    ['A -.-|trust boundary| B', 1],
    ['A -.-> B', 1],
    ['A ==> B', 1],
    ['A --x B', 1],
    ['A <--> B', 1],
    ['A -->|label| B', 1],
    ['A --> B --> C', 2],
    ['A & B --> C', 2],
    ['A & B --> C & D', 4],
    ['A["a label containing --> an arrow"]', 0],
    ['classDef threat fill:#3a1010,stroke:#ea1d1d', 0],
    ['subgraph zone["a --> b"]', 0],
  ])('counts %j as %i edge(s)', (line, expected) => {
    expect(countMermaidEdges(`flowchart TB\n  ${line}`)).toBe(expected);
  });

  it('counts the real generators exactly — one link per line', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rb-count-'));
    await writeScaleRepo(root, 8);
    const { model } = await parseProject({ root, project: 'rb' });
    const result = emitArtifacts({ root, model });
    const text = await readFile(join(root, '.guardlink', 'graph', 'threat-graph.mmd'), 'utf-8');
    // Every edge the generators emit sits on its own line, so the count has to
    // equal the number of lines carrying a link token.
    const linkLines = mermaidRenderText(text).split('\n')
      .filter(l => /(-{2,}[>ox]|-\.-|\.-+>|={2,}>|-{3,})/.test(l)).length;
    expect(countMermaidEdges(text)).toBe(linkLines);
    expect(result.undrawable).toEqual([]);
    await rm(root, { recursive: true, force: true });
  });
});

describe('the verdict', () => {
  const line = (n: number) => `  n${n} --> m${n}\n`;

  it('is renderable exactly AT each limit and not one past it', () => {
    // Mermaid fails on `text.length > maxTextSize` and refuses the edge that
    // would make `edges.length` exceed maxEdges, so the boundary is inclusive.
    const atEdges = 'flowchart TB\n' + Array.from({ length: MERMAID_LIMITS.maxEdges }, (_, i) => line(i)).join('');
    expect(checkRenderBudget(atEdges).renderable).toBe(true);
    const overEdges = atEdges + line(MERMAID_LIMITS.maxEdges);
    expect(checkRenderBudget(overEdges).renderable).toBe(false);

    const pad = 'flowchart TB\n  a["' + 'x'.repeat(MERMAID_LIMITS.maxTextSize - 20) + '"]';
    expect(measureDiagram(pad).textSize).toBeLessThanOrEqual(MERMAID_LIMITS.maxTextSize);
    expect(checkRenderBudget(pad).renderable).toBe(true);
    expect(checkRenderBudget(pad + 'y'.repeat(21)).renderable).toBe(false);
  });

  it('names the limit that failed, by how much, and what a renderer does', () => {
    const over = 'flowchart TB\n' + Array.from({ length: MERMAID_LIMITS.maxEdges + 17 }, (_, i) => line(i)).join('');
    const [violation] = checkRenderBudget(over).violations;
    expect(violation.limit).toBe('maxEdges');
    expect(violation.measured).toBe(517);
    expect(violation.over).toBe(17);
    expect(describeViolation(violation)).toBe("517 edges, over Mermaid's maxEdges of 500 by 17 (+3%)");
    expect(violation.symptom).toContain('Edge limit exceeded');
  });

  it('calls the silent failure silent, because nothing else will', () => {
    const huge = 'flowchart TB\n  a["' + 'x'.repeat(MERMAID_LIMITS.maxTextSize) + '"]';
    const [violation] = checkRenderBudget(huge).violations;
    expect(violation.limit).toBe('maxTextSize');
    expect(violation.symptom).toContain('resolves the render successfully');
    expect(violation.symptom).toContain('no console output');
  });

  it('treats an empty diagram as renderable — "nothing to draw" is not "cannot be drawn"', () => {
    expect(checkRenderBudget('').renderable).toBe(true);
  });

  it('the stub it writes is itself drawable, and says where to read the model', () => {
    const over = 'graph TB\n' + Array.from({ length: 600 }, (_, i) => line(i)).join('');
    const stub = oversizedStub('threat-graph.mmd', checkRenderBudget(over), 'Open Analytics.');
    expect(checkRenderBudget(stub).renderable).toBe(true);
    expect(stub).toContain('threat-graph.mmd was not drawn');
    expect(stub).toContain('600 edges');
    expect(stub).toContain('Open Analytics.');
  });

  it('opens with the same keyword the generators do, so it draws where they draw', async () => {
    // Measured in a browser, not assumed: the dashboard initialises Mermaid with
    // `defaultRenderer: 'dagre-d3'`, and under that setting `flowchart TB` fails
    // to parse at all ("No diagram type detected"). A stub that cannot be drawn
    // would be the same defect wearing a smaller file.
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rb-kw-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SMALL);
    const { model } = await parseProject({ root, project: 'rb' });
    // The first line that is not a `%%{init}%%` directive — that is the line
    // Mermaid dispatches the diagram type on.
    const keyword = (src: string) =>
      mermaidRenderText(src).split('\n').find(l => !l.startsWith('%%'))!.trim().split(/\s/)[0];

    const stub = oversizedStub('x.mmd', checkRenderBudget('graph TB\n' + line(0).repeat(1)), 'Read the model.');
    for (const generated of [
      generateThreatGraph(canonicalizeModelOrder(model), { showAll: true }),
      generateDataFlowDiagram(canonicalizeModelOrder(model)),
      generateAttackSurface(canonicalizeModelOrder(model)),
    ]) {
      expect(keyword(stub)).toBe(keyword(generated));
    }
    await rm(root, { recursive: true, force: true });
  });
});

// ─── Emission, at the size the report measured ───────────────────────

describe('emission at 257 annotated files — the measured size', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-rb-scale-'));
    await writeScaleRepo(root, 64);
    ({ model } = await parseProject({ root, project: 'rb' }));
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('is the size the scout report measured', () => {
    expect(model.annotated_files.length).toBe(257);
  });

  it('the threat graph at this size is over Mermaid\'s edge cap', () => {
    // The premise of everything below. If this stops being true the fixture has
    // drifted and the rest of this block is testing nothing.
    const written = emitArtifacts({ root, model, dryRun: true });
    const entry = written.manifest.find(e => e.path.endsWith('threat-graph.mmd'));
    expect(entry?.render?.edges).toBeGreaterThan(MERMAID_LIMITS.maxEdges);
  });

  it('writes a diagnostic, not a diagram nothing can draw', async () => {
    const result = emitArtifacts({ root, model });
    expect(result.undrawable.map(u => u.path)).toEqual(['.guardlink/graph/threat-graph.mmd']);

    const text = await readFile(join(root, '.guardlink', 'graph', 'threat-graph.mmd'), 'utf-8');
    expect(checkRenderBudget(text).renderable).toBe(true);
    expect(text).toContain('NOT A DIAGRAM');
    expect(text).toContain("over Mermaid's maxEdges of 500");
    expect(text).toContain('.guardlink/model.json');
    // And it is still an artifact: the provenance header a stale-check reads is
    // untouched, and the path is the one that was always expected.
    expect(text).toContain(`%% annotation_hash: ${result.provenance.annotation_hash}`);
  });

  it('records renderable:false in MANIFEST.json, beside the hash and not instead of it', async () => {
    emitArtifacts({ root, model });
    const manifest = JSON.parse(await readFile(join(root, '.guardlink', 'graph', 'MANIFEST.json'), 'utf-8'));
    const entry = manifest.artifacts.find((a: { path: string }) => a.path.endsWith('threat-graph.mmd'));
    expect(entry.renderable).toBe(false);
    expect(entry.render.edges).toBeGreaterThan(MERMAID_LIMITS.maxEdges);
    expect(entry.annotation_hash).toBe(manifest.annotation_hash);
    // The diagrams that DO draw are recorded as drawing, not left silent.
    const flow = manifest.artifacts.find((a: { path: string }) => a.path.endsWith('dataflow.mmd'));
    expect(flow.renderable).toBe(true);
  });

  it('the model itself is untouched — it is the picture that did not fit', async () => {
    emitArtifacts({ root, model });
    const written = JSON.parse(await readFile(join(root, '.guardlink', 'model.json'), 'utf-8'));
    expect(written.assets.length).toBe(128);
    expect(written.exposures.length).toBe(model.exposures.length);
  });

  it('validate --artifacts can no longer certify it as current-and-fine', async () => {
    emitArtifacts({ root, model });
    // Freshness passes — it always did, and that is the whole problem.
    expect(checkArtifactDrift(root, model)).toEqual([]);
    // Drawability is the second, separate answer. After regeneration the stub is
    // drawable, so the gate is self-clearing: it stops a pipeline once, with the
    // fix in the message.
    expect(checkArtifactRenderability(root)).toEqual([]);

    // The state a repository is actually in before it regenerates: the diagram a
    // pre-budget GuardLink wrote, still on disk, still hash-current.
    const undrawable = await readFile(join(root, '.guardlink', 'graph', 'dataflow.mmd'), 'utf-8');
    const oversized = undrawable.replace(
      /^graph LR$/m,
      'graph LR\n' + Array.from({ length: 600 }, (_, i) => `  q${i} --> r${i}`).join('\n'),
    );
    await writeFile(join(root, '.guardlink', 'graph', 'dataflow.mmd'), oversized);

    expect(checkArtifactDrift(root, model)).toEqual([]);           // still "current"
    const findings = checkArtifactRenderability(root);             // and now caught
    expect(findings.map(f => f.path)).toEqual(['.guardlink/graph/dataflow.mmd']);
    expect(findings[0].violations[0].limit).toBe('maxEdges');
  }, 30_000);
});

// ─── The dashboard at the same size ──────────────────────────────────

describe('the dashboard at the measured size', () => {
  it('never serves a diagram that would draw the pink box', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rb-dash-'));
    await writeScaleRepo(root, 64);
    const { model } = await parseProject({ root, project: 'rb' });
    const html = generateDashboardHTML(model, root);

    // Every `<pre class="mermaid">` on the page is within budget.
    const blocks = [...html.matchAll(/<pre class="mermaid"[^>]*>\n([\s\S]*?)\n<\/pre>/g)]
      .map(m => m[1].replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'));
    expect(blocks.length).toBeGreaterThan(0);
    for (const block of blocks) expect(checkRenderBudget(block).renderable).toBe(true);

    // And the page says out loud which one is missing, in HTML a reader can see
    // without rendering a diagram to find out the diagram is gone.
    expect(html).toContain('<div class="diagram-budget"');
    expect(html).toContain('was not drawn');
    // The whole-graph variants are stubbed, but the per-asset focus slices still
    // draw, so the panel's legend still keys something and stays. Suppression is
    // for a panel where NOTHING was drawn, not for a panel with one stub in it.
    expect(html).toContain('Assets, threats, controls, and mitigations.');
    await rm(root, { recursive: true, force: true });
  }, 30_000);

  it('drops the legend on a panel where nothing at all was drawn', async () => {
    // Data Flow is a single-variant panel, so past the cap the whole panel is a
    // stub — and a legend keying shapes and colours that are not on the page is
    // a smaller copy of the defect this change exists to remove.
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rb-legend-'));
    await writeScaleRepo(root, 160);
    const { model } = await parseProject({ root, project: 'rb' });
    const html = generateDashboardHTML(model, root);

    expect(html).toContain('The legend is omitted because there is nothing to key');
    expect(html).not.toContain('Data movement across trust boundaries');
    await rm(root, { recursive: true, force: true });
  }, 60_000);
});

// ─── Nothing changes for a repository that was always fine ───────────

describe('a normal repository is untouched', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-rb-small-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SMALL);
    ({ model } = await parseProject({ root, project: 'rb' }));
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('emits no stub and reports nothing undrawable', () => {
    const result = emitArtifacts({ root, model });
    expect(result.undrawable).toEqual([]);
    expect(checkArtifactRenderability(root)).toEqual([]);
  });

  it('every .mmd is exactly the header plus the generator output — no budget text at all', async () => {
    const { provenance } = emitArtifacts({ root, model });
    const ordered = canonicalizeModelOrder(model);
    const bodies: [string, string][] = [
      ['threat-graph.mmd', generateThreatGraph(ordered, { showAll: true })],
      ['dataflow.mmd', generateDataFlowDiagram(ordered)],
      ['attack-surface.mmd', generateAttackSurface(ordered)],
    ];
    for (const [name, body] of bodies) {
      const text = await readFile(join(root, '.guardlink', 'graph', name), 'utf-8');
      // Byte-for-byte what the emitter has always written: the same header, the
      // same generator output, and not one character of budget text.
      expect(text, name).toBe(mermaidHeader(name, provenance) + body);
    }
  });

  it('MANIFEST records it as drawable rather than staying silent', async () => {
    emitArtifacts({ root, model });
    const manifest = JSON.parse(await readFile(join(root, '.guardlink', 'graph', 'MANIFEST.json'), 'utf-8'));
    for (const entry of manifest.artifacts) {
      if (entry.path.endsWith('.mmd')) expect(entry.renderable, entry.path).toBe(true);
      else expect(entry.renderable, entry.path).toBeUndefined();
    }
  });

  it('the dashboard embeds the diagrams with no notice attached', async () => {
    const html = generateDashboardHTML(model, root);
    expect(html).not.toContain('<div class="diagram-budget"');
    expect(html).not.toContain('was not drawn');
    expect(html).toContain('<pre class="mermaid"');
    // The legend is untouched where the diagram is drawn.
    expect(html).toContain('Assets, threats, controls, and mitigations.');
    expect(html).not.toContain('The legend is omitted');
  });
});

// ─── The gate itself ─────────────────────────────────────────────────

/**
 * `validate --artifacts` is what runs in other people's pipelines, so the claim
 * has to be about its EXIT CODE and not about a function it happens to call.
 *
 * Turning a previously-green check red is a real consequence, and it is the
 * intended one: the flag is opt-in, its whole job is to say whether the
 * committed artifacts can be trusted, and a diagram nothing will draw cannot be.
 * It is also self-clearing — one `guardlink artifacts .` and the same repository
 * is green again — which is why it is an exit code and not a warning: the fix is
 * in the message, and the pipeline stops exactly once.
 */
describe('guardlink validate --artifacts', () => {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
  const cli = join(repoRoot, 'src', 'cli', 'index.ts');

  // spawnSync, not execFileSync: validate reports on stderr, and the assertions
  // below are about what a human running it in a pipeline sees, which is both.
  function guardlink(...args: string[]): { out: string; code: number } {
    const r = spawnSync('npx', ['tsx', cli, ...args], {
      cwd: repoRoot, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { out: `${r.stdout ?? ''}${r.stderr ?? ''}`, code: r.status ?? 1 };
  }

  // One tsx spawn plus a 257-file parse; ~5s locally, slower in CI.
  it('exits 1 on a committed artifact no renderer will draw, and says what exceeded', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rb-gate-'));
    await writeScaleRepo(root, 64);
    const { model } = await parseProject({ root, project: 'rb' });

    // The state a repository reaches with a GuardLink that predates the budget:
    // the real diagram on disk, hash-current, and undrawable.
    emitArtifacts({ root, model });
    // dataflow.mmd is within budget at this size, so it is the one still holding
    // a real diagram — grow it past the edge cap the way a bigger repository
    // would, leaving the provenance header (and therefore the freshness check)
    // exactly as the emitter wrote it.
    const target = join(root, '.guardlink', 'graph', 'dataflow.mmd');
    const drawable = await readFile(target, 'utf-8');
    const opener = drawable.split('\n').find(l => l.startsWith('graph '))!;
    await writeFile(target, drawable.replace(
      opener,
      opener + '\n' + Array.from({ length: 600 }, (_, i) => `  q${i} --> r${i}`).join('\n'),
    ));

    const bad = guardlink('validate', root, '--artifacts');
    expect(bad.code).toBe(1);
    expect(bad.out).toContain('✓ Artifacts are current.');     // freshness still passes
    expect(bad.out).toContain('no renderer will draw');        // drawability does not
    expect(bad.out).toContain("over Mermaid's maxEdges of 500");
    expect(bad.out).toContain('Regenerate with: guardlink artifacts .');

    // And regenerating clears it, in one command, with no flag to learn.
    expect(guardlink('artifacts', root).code).toBe(0);
    const good = guardlink('validate', root, '--artifacts');
    expect(good.code).toBe(0);
    expect(good.out).toContain('✓ Artifacts are drawable.');

    await rm(root, { recursive: true, force: true });
  }, 120_000);

  it('exits 0 on a repository that was always fine, and still says both things', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-rb-gate-ok-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SMALL);
    const { model } = await parseProject({ root, project: 'rb' });
    emitArtifacts({ root, model });

    const ok = guardlink('validate', root, '--artifacts');
    expect(ok.code).toBe(0);
    expect(ok.out).toContain('✓ Artifacts are current.');
    expect(ok.out).toContain('✓ Artifacts are drawable.');
    expect(ok.out).not.toContain('no renderer will draw');

    await rm(root, { recursive: true, force: true });
  }, 120_000);
});
