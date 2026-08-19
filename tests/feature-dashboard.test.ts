/**
 * A dashboard generated with `--feature` is a SLICE, and the page has to say so.
 *
 * Two failure modes are being pinned here, and they pull in opposite directions:
 *
 *   - A slice that does not announce itself. Someone sent a screenshot of
 *     `guardlink dashboard . --feature "Dashboard"` reads a grade, an open-threat
 *     count and a coverage bar as the project's. They are one feature's.
 *   - A slice that announces itself by dropping its vocabulary. Definitions live
 *     in `.guardlink/definitions.*`, which carries no `@feature`, so scoping them
 *     by file rendered every node as a bare id of unknown severity. The narrowed
 *     model keeps them; these tests fail if that regresses.
 *
 * Plus the invariant that pays for both: an UNFILTERED page must be untouched by
 * any of it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateDashboardHTML } from '../src/dashboard/generate.js';
import { generateThreatGraph } from '../src/dashboard/diagrams.js';
import { filterByFeature } from '../src/parser/feature-filter.js';
import { parseProject } from '../src/parser/parse-project.js';
import { emitArtifacts, readArtifactHash } from '../src/artifacts/emit.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { canonicalizeModelOrder } from '../src/parser/canonical-order.js';
import type { ThreatModel } from '../src/types/index.js';

// Paths that do not exist on disk: the dashboard reads source around every
// annotation for its code browser, and a fixture pointing at real files would
// smuggle this repository's own text into the assertions.
const loc = { file: 'src/alpha/render.ts', line: 10 };
const mcpLoc = { file: 'src/beta/server.ts', line: 4 };
const defs = { file: 'defs/definitions.ts', line: 3 };

function emptyModel(overrides: Partial<ThreatModel> = {}): ThreatModel {
  return {
    version: '1.0.0', project: 'test', generated_at: '', source_files: 0,
    annotated_files: [], unannotated_files: [],
    annotations_parsed: 0, assets: [], threats: [], controls: [],
    mitigations: [], exposures: [], confirmed: [], acceptances: [], transfers: [],
    flows: [], boundaries: [], validations: [], audits: [], ownership: [],
    data_handling: [], assumptions: [], shields: [], features: [], comments: [],
    coverage: { annotation_count: 0, coverage_percent: 0 },
    ...overrides,
  };
}

/**
 * A whole-project model: two features' worth of annotations, definitions in the
 * conventional definitions file, and a project-wide file coverage of 25%.
 */
function projectModel(): ThreatModel {
  return emptyModel({
    project: 'guardlink',
    source_files: 4,
    annotations_parsed: 42,
    annotated_files: ['src/alpha/render.ts', 'src/beta/server.ts', 'defs/definitions.ts'],
    unannotated_files: ['src/util/color.ts', 'src/util/pad.ts', 'scripts/postbuild.mjs'],
    coverage: { annotation_count: 42, coverage_percent: 25 },
    assets: [
      { path: ['GuardLink', 'Dashboard'], id: 'dashboard', location: defs },
      { path: ['GuardLink', 'MCP'], id: 'mcp', location: defs },
    ],
    threats: [
      { name: 'Cross_Site_Scripting', canonical_name: 'cross_site_scripting', id: 'xss', severity: 'high', external_refs: ['cwe:CWE-79'], location: defs },
      { name: 'Command_Injection', canonical_name: 'command_injection', id: 'cmd-injection', severity: 'critical', external_refs: ['cwe:CWE-77'], location: defs },
    ],
    controls: [
      { name: 'Output_Encoding', canonical_name: 'output_encoding', id: 'output-encoding', location: defs },
    ],
    exposures: [
      { asset: '#dashboard', threat: '#xss', severity: 'high', external_refs: [], location: loc },
      { asset: '#mcp', threat: '#cmd-injection', severity: 'critical', external_refs: [], location: mcpLoc },
    ],
    mitigations: [
      { asset: '#dashboard', threat: '#xss', control: '#output-encoding', location: loc },
    ],
    flows: [
      { source: 'ThreatModel', target: '#dashboard', mechanism: 'computeStats', location: loc },
    ],
    features: [
      { feature: 'Dashboard', description: 'HTML dashboard', location: loc },
      { feature: 'MCP Integration', description: 'MCP server', location: mcpLoc },
    ],
  });
}

/** What `filterByFeature` hands the dashboard once it has narrowed the model. */
function narrowed(model: ThreatModel, features: string[]): ThreatModel {
  const filtered = filterByFeature(model, features) as ThreatModel & { filtered_by_features?: string[] };
  // The marker is the dashboard's whole input contract. Set it explicitly so
  // these tests pin the dashboard's behaviour rather than the filter's.
  filtered.filtered_by_features = features;
  return filtered;
}

// ─── 1. The page says it is a slice ──────────────────────────────────

describe('a feature-scoped dashboard declares its scope', () => {
  const html = () => generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));

  it('names the feature in the title, so even a browser tab says it is partial', () => {
    expect(html()).toContain('<title>GuardLink — guardlink Threat Model — PARTIAL: feature &quot;Dashboard&quot;</title>');
  });

  it('carries a scope banner naming the feature above the fold', () => {
    const h = html();
    expect(h).toContain('id="scope-banner"');
    expect(h).toContain('Partial threat model');
    expect(h).toMatch(/Narrowed to feature &quot;Dashboard&quot;/);
    // The claim that matters for a screenshot.
    expect(h).toContain('not the whole project');
  });

  it('badges the top bar, which travels with every screenshot of the header', () => {
    expect(html()).toMatch(/class="badge badge-scope"[^>]*>[^<]*Feature slice — Dashboard/);
  });

  it('names both features when narrowed to more than one', () => {
    const h = generateDashboardHTML(narrowed(projectModel(), ['Dashboard', 'MCP Integration']));
    expect(h).toContain('&quot;Dashboard&quot;, &quot;MCP Integration&quot;');
    expect(h).toContain('these features');
    expect(h).toContain('PARTIAL: features');
    expect(h).toContain('Narrowed to features');
  });

  it('marks each page, not only the summary', () => {
    const h = html();
    for (const section of ['sec-summary', 'sec-threats', 'sec-diagrams', 'sec-code', 'sec-data', 'sec-assets']) {
      const start = h.indexOf(`id="${section}"`);
      expect(start, section).toBeGreaterThan(-1);
      const page = h.slice(start, h.indexOf('id="sec-', start + 10));
      expect(page, section).toMatch(/scope-tag|scope-note/);
    }
  });
});

// ─── 2. Project-wide numbers are not passed off as the feature's ─────

describe('project-wide measures are not shown as the feature\'s', () => {
  it('drops the project file-coverage tile from the top bar', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));
    // 25% is the repository's annotated-files ratio. It must not appear as a
    // headline number on a page about one feature.
    expect(scoped).not.toContain('<span class="tn-k">Coverage</span>');
    expect(scoped).not.toContain('>25%<');
    // What replaces it is the one coverage a slice can defend.
    expect(scoped).toContain('<span class="tn-k">Mitigated</span>');
  });

  it('does not render the project file-coverage bar on the code page', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));
    expect(scoped).not.toMatch(/\d+ of \d+ files/);
    expect(scoped).toContain('Project file coverage and the unannotated-file list are not shown on a feature slice.');
  });

  it('never lists the project\'s unannotated files, nor claims there are none', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));
    expect(scoped).not.toContain('src/util/color.ts');
    expect(scoped).not.toContain('Unannotated Files');
    // The other half of the trap: once the filter empties unannotated_files, the
    // "all clear" branch would fire and assert something no slice can know.
    expect(scoped).not.toContain('All source files have annotations');
  });

  it('counts only the feature\'s exposures in the stat tiles', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));
    const open = scoped.match(/<div class="stat-card stat-danger"><div class="value">(\d+)<\/div><div class="label">Open Threats/);
    // The project has one open (critical, in MCP) and one mitigated (in
    // Dashboard). The Dashboard slice therefore has zero open.
    expect(open?.[1]).toBe('0');
    expect(scoped).not.toContain('Command_Injection');
  });

  it('says why an empty section is empty instead of showing a bare heading', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));
    // No @boundary/@handles/@owns in the feature's file.
    expect(scoped).toMatch(/No trust boundaries, data classifications or lifecycle annotations in the files tagged &quot;Dashboard&quot;/);
  });

  it('flags threat reports as whole-project, since --feature does not narrow them', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']), undefined, []);
    expect(scoped).toContain('whole-project</strong> documents');
  });
});

// ─── 3. Definitions survive the narrowing ────────────────────────────

describe('a narrowed model keeps the definitions its relations reference', () => {
  it('renders resolved names and severities, not bare ids', () => {
    const mermaid = generateThreatGraph(filterByFeature(projectModel(), ['Dashboard']), { showAll: true });
    // The regression this replaced:  xss["⚪ xss"]:::threat
    expect(mermaid).toContain('Cross_Site_Scripting');
    expect(mermaid).toContain('cwe:CWE-79');
    expect(mermaid).toContain('🟠');
    expect(mermaid).not.toContain('⚪');
    expect(mermaid).not.toMatch(/\["[^"]*\bxss"\]/);
    expect(mermaid).toContain('GuardLink.Dashboard');
    expect(mermaid).toContain('Output_Encoding');
  });

  it('shows the same resolved nodes in the dashboard\'s diagram panel', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));
    expect(scoped).toContain('🟠 Cross_Site_Scripting (cwe:CWE-79)');
    expect(scoped).not.toContain('⚪ xss');
  });

  it('tells the reader an absent node is out of scope, not out of the model', () => {
    const scoped = generateDashboardHTML(narrowed(projectModel(), ['Dashboard']));
    expect(scoped).toContain('A node the feature never touches is absent');
  });
});

// ─── 4. An unfiltered dashboard is untouched ─────────────────────────

describe('an unfiltered dashboard is unchanged', () => {
  it('has no scope banner, badge, note or partial title', () => {
    const full = generateDashboardHTML(projectModel());
    expect(full).toContain('<title>GuardLink — guardlink Threat Model</title>');
    // The stylesheet is one constant and always carries the rules; what must be
    // absent is any element wearing them.
    expect(full).not.toContain('id="scope-banner"');
    expect(full).not.toContain('class="badge badge-scope"');
    expect(full).not.toContain('class="scope-note"');
    expect(full).not.toContain('class="scope-tag"');
    expect(full).not.toContain('<body class="scoped">');
    expect(full).toContain('<body>');
  });

  it('still reports project file coverage and unannotated files', () => {
    const full = generateDashboardHTML(projectModel());
    expect(full).toContain('<span class="tn-k">Coverage</span>');
    expect(full).toContain('25%');
    expect(full).toContain('3 of 6 files');
    expect(full).toContain('Unannotated Files (3)');
    expect(full).toContain('src/util/color.ts');
  });

  it('treats a missing marker as the whole project, byte for byte', () => {
    const model = { ...projectModel(), filtered_by_features: undefined } as unknown as ThreatModel;
    expect(generateDashboardHTML(model)).toBe(generateDashboardHTML(projectModel()));
  });

  it('treats an empty or malformed marker as the whole project', () => {
    // The field is optional and comes from a model this generator does not
    // produce. Anything that is not a non-empty list of names means "not a
    // slice" — the page must not half-declare a scope it cannot name.
    for (const marker of [[], 'Dashboard', ['   '], [7], null, {}]) {
      const model = { ...projectModel(), filtered_by_features: marker } as unknown as ThreatModel;
      const h = generateDashboardHTML(model);
      expect(h, JSON.stringify(marker)).toContain('<title>GuardLink — guardlink Threat Model</title>');
      expect(h, JSON.stringify(marker)).not.toContain('id="scope-banner"');
      expect(h, JSON.stringify(marker)).toContain('<span class="tn-k">Coverage</span>');
    }
  });
});

// ─── 5. Scope names are model data, and get escaped like any other ───

describe('feature names are HTML-escaped everywhere they are rendered', () => {
  it('cannot inject markup through a feature name', () => {
    const model = projectModel();
    const evil = '<img src=x onerror="alert(1)">';
    model.features = [{ feature: evil, description: 'x', location: loc }];
    const scoped = generateDashboardHTML(narrowed(model, [evil]));
    // The markup region: everything the scope work renders. (The model is also
    // embedded verbatim into a <script> below it as JSON — a separate context,
    // guarded by the existing `</` escape, and not what this test is about.)
    const markup = scoped.slice(scoped.indexOf('<body'), scoped.indexOf('/* ===== DATA'));
    expect(markup).not.toContain('<img src=x');
    expect(markup).toContain('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
    // The title is markup too, and is where a name lands first.
    expect(scoped).toContain('PARTIAL: feature &quot;&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&quot;');
  });
});

// ─── 6. The emitted by-feature artifact says the same thing ──────────

const SOURCE = `/**
 * @asset App.API (#api) -- "REST surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "untrusted input"
 * @control Prepared_Statements (#ps) -- "parameterized"
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "concatenated"
 * @mitigates #api against #sqli using #ps -- "pg placeholders"
 * @feature "Checkout" -- "cart and orders"
 */
export function handler() {}
`;

describe('by-feature/*.mmd declares itself partial', () => {
  let root: string;
  let model: ThreatModel;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-featart-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    ({ model } = await parseProject({ root, project: 'art' }));
    emitArtifacts({ root, model });
  });

  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  const read = () => readFile(join(root, '.guardlink/graph/by-feature/checkout.mmd'), 'utf-8');

  it('names the feature and says the view is partial', async () => {
    const text = await read();
    expect(text).toContain('%% scope:           PARTIAL — @feature "Checkout" only, not the whole model');
    expect(text).toContain('NARROWED VIEW');
    expect(text).toContain('it is NOT missing from the threat model');
  });

  it('carries the project annotation_hash, and says that is what it is', async () => {
    const text = await read();
    // The value is the whole project's — the state this view was cut from — and
    // it stays machine-readable so `validate --artifacts` keeps working.
    expect(readArtifactHash(text)).toBe(computeAnnotationHash(canonicalizeModelOrder(model)));
    expect(text).toContain("the hash of the WHOLE project's annotations");
  });

  it('renders resolved definitions, not the bare ids of a stripped model', async () => {
    const text = await read();
    expect(text).toContain('SQL_Injection');
    expect(text).toContain('Prepared_Statements');
    expect(text).toContain('App.API');
    expect(text).not.toContain('⚪');
  });

  it('adds no bare %% line, which mermaid reads as a broken init directive', async () => {
    const text = await read();
    expect(text.split('\n').filter(l => l === '%%')).toEqual([]);
  });

  it('leaves the whole-project diagrams unscoped', async () => {
    const text = await readFile(join(root, '.guardlink/graph/threat-graph.mmd'), 'utf-8');
    expect(text).not.toContain('%% scope:');
    expect(text).not.toContain('NARROWED VIEW');
  });
});
