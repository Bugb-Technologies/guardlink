/**
 * Analytics builders (pure) and the markup contracts of the second pass:
 * the Analytics page with its heatmaps, pagination hooks, the reports
 * toolbar, and the asset drawer data.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { computeAssetThreatMatrix, computeControlCoverage, computeSeverityStatus, computeAssetDetails, computeAssetHeatmap } from '../src/dashboard/data.js';
import { buildClaims } from '../src/dashboard/pages/context.js';
import type { ExposureBlame } from '../src/blame/types.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.Web (#web) -- "Web tier"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 * @control Output_Encoding (#output-encoding) -- "HTML encoding"
 * @control Unused_Control (#unused) -- "Declared, never used"
 */
export {};
`;
const SOURCE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "raw sql"
 * @exposes #api to #xss [medium] -- "reflected"
 * @exposes #web to #xss [high] -- "bio"
 * @mitigates #web against #xss using #output-encoding -- "escaped"
 * @flows User -> #api via HTTPS -- "login"
 * @handles pii on #api -- "emails"
 * @owns platform for #api -- "platform team"
 */
export function login(email: string) { return email; }
`;

async function project(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-analytics-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), SOURCE);
  return root;
}

describe('analytics builders', () => {
  it('asset × threat matrix counts exposures per pair with the worst status and severity', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const claims = buildClaims(model, null, null);
    const m = computeAssetThreatMatrix(claims);
    expect(m.assets).toEqual(['#api', '#web']);           // most open first
    expect(m.threats).toEqual(['#xss', '#sqli']);         // most exposures first
    const api_sqli = m.cells.find(c => c.asset === '#api' && c.threat === '#sqli')!;
    expect(api_sqli).toMatchObject({ total: 1, open: 1, mitigated: 0, worst: 'open', maxSev: 'critical' });
    const web_xss = m.cells.find(c => c.asset === '#web' && c.threat === '#xss')!;
    expect(web_xss).toMatchObject({ total: 1, open: 0, mitigated: 1, worst: 'mitigated', maxSev: 'high' });
    expect(m.cells.find(c => c.asset === '#web' && c.threat === '#sqli')).toBeUndefined();
  });

  it('control coverage lists what each control mitigates and flags unused controls', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const cov = computeControlCoverage(model);
    expect(cov.find(c => c.control === '#output-encoding')).toMatchObject({ mitigations: 1, threats: ['#xss'], assets: ['#web'], unused: false });
    expect(cov.find(c => c.control === '#unused')).toMatchObject({ mitigations: 0, unused: true });
    expect(cov[0].control).toBe('#output-encoding');       // used controls first
  });

  it('severity × status matrix', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const claims = buildClaims(model, null, null);
    const s = computeSeverityStatus(claims);
    expect(s.counts.critical.open).toBe(1);
    expect(s.counts.high.mitigated).toBe(1);
    expect(s.counts.medium.open).toBe(1);
    expect(s.totals.open).toBe(2);
  });

  it('asset details carry threats, controls, files, owners, classes and attribution', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const intro = { sha: 'a'.repeat(40), date: '2026-01-01T00:00:00Z', author: 'human:Ann', co_authors: [], assisted_by: [{ tool: 'claude-code', model: 'Claude Opus 5', raw: 'x' }] };
    const b: ExposureBlame = { kind: 'exposure', status: 'ok', granularity: 'symbol', introduced_by: { ...intro, method: 'log-L' }, found_by: intro, contributors: [], fixed_by: null, time_to_fix_days: null };
    model.exposures[0].blame = b;
    (model as unknown as { blame_context: unknown }).blame_context = { commits: null, as_of: '2026-01-11T00:00:00Z' };
    const claims = buildClaims(model, null, null);
    const heatmap = computeAssetHeatmap(model);
    const details = computeAssetDetails(model, claims, heatmap, '2026-01-11T00:00:00Z');
    const api = details.find(d => d.name === '#api')!;
    expect(api.exposures).toMatchObject({ total: 2, open: 2, mitigated: 0 });
    expect(api.threats.map(t => t.threat)).toEqual(['#sqli', '#xss']);
    expect(api.dataHandling).toEqual(['pii']);
    expect(api.owners).toEqual(['platform']);
    expect(api.files[0]).toMatchObject({ file: 'src/a.ts' });
    expect(api.attribution).toMatchObject({ introducers: [{ identity: 'human:Ann', count: 1 }], ai: 1, oldestOpenDays: 10 });
    const web = details.find(d => d.name === '#web')!;
    expect(web.controls).toEqual([{ control: '#output-encoding', count: 1 }]);
    expect(web.attribution).toBeNull();
  });
});

describe('markup', () => {
  it('renders the Analytics page with clickable heatmap cells, and paginates long tables', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const h = generateDashboardHTML(model, root);
    expect(h).toContain('id="sec-analytics"');
    expect(h).toContain('href="#analytics"');
    expect(h).toMatch(/<td class="heat-cell[^"]*"[^>]*style="--h:/);
    expect(h).toContain('href="#threats?q=%23api+%23sqli"');
    expect(h).toMatch(/<table id="exposures" class="sortable fixed" data-paginate="25"/);
    expect(h).toContain('data-pager-for="exposures"');
    expect(h).toContain('function paginate(');
  });

  it('gives the reports page a toolbar with copy actions, even with no saved report', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const h = generateDashboardHTML(model, root);
    expect(h).toContain('data-copy-report');
    expect(h).toContain('data-copy="guardlink threat-report stride"');
    expect(h).toContain('function copyReport(');
  });

  it('emits a page script that parses: a stray quote in a JS string would silently disable every control', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const h = generateDashboardHTML(model, root);
    const inline = [...h.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
    expect(inline.length).toBeGreaterThan(0);
    for (const body of inline) expect(() => new Function(body)).not.toThrow();
  });

  it('embeds the asset details the drawer renders', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'an' });
    const h = generateDashboardHTML(model, root);
    const embedded = h.match(/const assetsData = (\[.*?\]);\n/s);
    expect(embedded).not.toBeNull();
    const data = JSON.parse(embedded![1]);
    const api = data.find((d: { name: string }) => d.name === '#api');
    expect(api.threats.length).toBe(2);
    expect(api.owners).toEqual(['platform']);
    expect(h).toContain('function renderAssetDrawer(');
  });
});
