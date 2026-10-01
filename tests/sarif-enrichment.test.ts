/**
 * The declared context the SARIF export carries around each finding
 * (src/analyzer/sarif-context.ts), and the guarantee that makes it safe to ship:
 * it is purely additive.
 *
 * Consumers of this export key on the result index, on `message.text`, on rule
 * ids and on `partialFingerprints`. So the central test here strips every member
 * the enrichment adds and compares what is left, byte for byte, with exports cut
 * BEFORE the enrichment existed (tests/fixtures/sarif-baseline/*.sarif, written
 * by `guardlink sarif` at the commit this change was based on). If a result is
 * added, dropped, reordered or reworded, or a rule changes, that comparison
 * fails.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { readFileSync, mkdtempSync, rmSync, cpSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv-draft-04';
import addFormats from 'ajv-formats';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { generateSarif, SARIF_AUTOMATION_ID, SARIF_PROFILE_VERSION } from '../src/analyzer/sarif.js';
import { parseProject } from '../src/parser/parse-project.js';
import { findDanglingRefs } from '../src/parser/validate.js';
import { readVersionControl } from '../src/workspace/metadata.js';
import { createServer } from '../src/mcp/server.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const fixture = (name: string) => join(repoRoot, 'tests', 'fixtures', name);
const baselineDir = fixture('sarif-baseline');

type Sarif = ReturnType<typeof generateSarif>;
type Run = Sarif['runs'][number];
type Result = Run['results'][number];

/** What `guardlink sarif <dir>` computes, minus the git provenance. */
async function exportOf(root: string, minSeverity?: 'critical' | 'high' | 'medium' | 'low'): Promise<Sarif> {
  const { model, diagnostics } = await parseProject({ root, project: 'unused' });
  return generateSarif(model, diagnostics, findDanglingRefs(model), {
    includeDiagnostics: true, includeDanglingRefs: true, minSeverity,
  });
}

/**
 * Delete exactly the members the enrichment adds. Deliberately a list, not a
 * pattern: a member added later and not named here makes the byte comparison
 * fail, which is the point — every addition has to be argued additive.
 */
function strip(run: Run): Pick<Run, 'results' | 'tool'> {
  const { results, tool } = structuredClone({ results: run.results, tool: run.tool });
  for (const r of results) {
    delete r.taxa;
    delete r.relatedLocations;
    delete r.codeFlows;
    for (const l of r.locations) delete l.logicalLocations;
    if (r.properties) {
      delete r.properties['guardlink/anchor'];
      delete r.properties['guardlink/flowAttribution'];
    }
  }
  for (const rule of tool.driver.rules) {
    delete rule.help;
    delete rule.properties;
  }
  return { results, tool };
}

/** The driver version moves with package.json; nothing else in `tool` may. */
const withoutVersion = (tool: Run['tool']) => ({ ...tool, driver: { ...tool.driver, version: '<version>' } });

const baseline = (name: string): Run =>
  JSON.parse(readFileSync(join(baselineDir, `${name}.sarif`), 'utf-8')).runs[0];

const validator = (() => {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile(JSON.parse(readFileSync(join(baselineDir, 'sarif-schema-2.1.0.json'), 'utf-8')));
})();

function expectSchemaValid(sarif: unknown): void {
  const ok = validator(JSON.parse(JSON.stringify(sarif)));
  expect(validator.errors ?? []).toEqual([]);
  expect(ok).toBe(true);
}

const byMessage = (run: Run, start: string): Result => {
  const found = run.results.find(r => r.message.text.startsWith(start));
  if (!found) throw new Error(`no result starting "${start}"`);
  return found;
};
const props = (r: Result) => r.properties as Record<string, unknown>;

// ─── Additive ────────────────────────────────────────────────────────

describe('SARIF enrichment is additive', () => {
  for (const name of ['expense-api', 'sarif-shop']) {
    it(`${name}: stripping the new members gives back the earlier export's results and tool, byte for byte`, async () => {
      const run = (await exportOf(fixture(name))).runs[0];
      const before = baseline(name);
      const after = strip(run);
      expect(JSON.stringify(after.results)).toBe(JSON.stringify(before.results));
      expect(JSON.stringify(withoutVersion(after.tool))).toBe(JSON.stringify(withoutVersion(before.tool)));
    });

    it(`${name}: the comparison is not vacuous — the enrichment did add members`, async () => {
      const run = (await exportOf(fixture(name))).runs[0];
      expect(run.results.length).toBeGreaterThan(0);
      expect(run.results.some(r => r.codeFlows?.length)).toBe(true);
      expect(run.results.some(r => r.relatedLocations?.length)).toBe(true);
      expect(run.results.some(r => r.taxa?.length)).toBe(true);
      expect(run.results.some(r => r.locations[0].logicalLocations?.length)).toBe(true);
      expect(run.graphs?.[0].edges.length).toBeGreaterThan(0);
      expect(run.tool.driver.rules.every(r => r.help && r.properties)).toBe(true);
    });
  }

  it('keeps the run envelope: provenance properties unchanged, new ones appended', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const before = baseline('sarif-shop');
    const { sarif_profile_version, ...rest } = run.properties;
    expect(sarif_profile_version).toBe(SARIF_PROFILE_VERSION);
    expect(Object.keys(rest)).toEqual(Object.keys(before.properties));
    expect(rest.annotation_hash).toBe(before.properties.annotation_hash);
    // Existing run members first, in their old order.
    expect(Object.keys(run).slice(0, 3)).toEqual(['tool', 'results', 'properties']);
  });
});

// ─── Schema ──────────────────────────────────────────────────────────

describe('SARIF enrichment validates against the SARIF 2.1.0 schema', () => {
  it('expense-api', async () => expectSchemaValid(await exportOf(fixture('expense-api'))));
  it('sarif-shop', async () => expectSchemaValid(await exportOf(fixture('sarif-shop'))));
  it('this repository', async () => expectSchemaValid(await exportOf(repoRoot)), 60_000);

  it('with version control provenance', async () => {
    const { model } = await parseProject({ root: fixture('sarif-shop'), project: 'unused' });
    expectSchemaValid(generateSarif(model, [], [], {
      versionControl: { repositoryUri: 'https://example.com/org/shop', revisionId: 'a'.repeat(40), branch: 'main' },
    }));
  });

  it('a partial model with no assets, flows or boundaries', () => {
    expectSchemaValid(generateSarif({
      exposures: [{ asset: '#a', threat: '#t', severity: 'low', external_refs: ['cwe:CWE-79'], location: { file: 'a.ts', line: 1 } }],
      mitigations: [], acceptances: [], confirmed: [], flows: [],
    } as unknown as ThreatModel));
  });
});

// ─── Code flows ──────────────────────────────────────────────────────

describe('codeFlows: the declared @flows chain into a claim', () => {
  it('follows the chain whose hops are declared on the claim\'s own handler, ending at the claim', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const sqli = byMessage(run, '#store is exposed to sqli');
    expect(props(sqli)['guardlink/flowAttribution']).toBe('handler');
    const [first] = sqli.codeFlows!;
    const steps = first.threadFlows[0].locations;
    expect(steps.map(s => s.location.message?.text)).toEqual([
      'Client -> #web via POST./orders/search [crosses #edge]',
      '#web -> #orders via searchOrders',
      '#orders -> #store via query [crosses #data]',
      '@exposes #store to #sqli',
    ]);
    expect(steps.map(s => s.kinds)).toEqual([
      ['flow', 'boundary-crossing'], ['flow'], ['flow', 'boundary-crossing'], ['claim'],
    ]);
    expect(steps[0].webRequest).toEqual({ method: 'POST', target: '/orders/search' });
    expect(steps.slice(0, 3).map(s => s.properties?.['guardlink/hopAttribution'])).toEqual(['handler', 'handler', 'handler']);
    expect(steps[3].importance).toBe('essential');
    // Every hop is sited at its own @flows line.
    expect(steps.every(s => s.location.physicalLocation.artifactLocation.uri === 'src/web.ts')).toBe(true);
  });

  it('marks an upstream hop joined only by graph adjacency as such', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const ssrf = byMessage(run, '#mailer is exposed to ssrf');
    expect(props(ssrf)['guardlink/flowAttribution']).toBe('file');
    for (const flow of ssrf.codeFlows!) {
      const steps = flow.threadFlows[0].locations;
      const last = steps[steps.length - 2];
      expect(last.location.message?.text).toBe('#orders -> #mailer via notify');
      expect(last.properties?.['guardlink/hopAttribution']).toBe('file');
      // The hops before it are in another file: nothing ties them to this claim.
      for (const s of steps.slice(0, -2)) expect(s.properties?.['guardlink/hopAttribution']).toBe('graph');
    }
  });

  it('emits no chain when no hop into the asset is declared on the claim\'s handler or file', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    // src/export.ts declares no flow; the only flows into #store are in src/web.ts.
    const dos = byMessage(run, '#store is exposed to dos');
    expect(dos.codeFlows).toBeUndefined();
    expect(props(dos)).not.toHaveProperty('guardlink/flowAttribution');
    // deleteOrder's file has flows into #orders, but only on SIBLING handlers.
    const csrf = byMessage(run, '#orders is exposed to csrf');
    expect(csrf.codeFlows).toBeUndefined();
  });

  it('gives a @confirmed result its chain too, ending at the confirmed claim', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const confirmed = run.results.find(r => r.ruleId === 'guardlink/confirmed-exploitable')!;
    const steps = confirmed.codeFlows![0].threadFlows[0].locations;
    expect(steps[steps.length - 1].location.message?.text).toBe('@confirmed #idor on #orders');
    expect(steps.map(s => s.location.message?.text)).toContain('Client -> #web via GET./orders/:id [crosses #edge]');
  });

  it('emits at most three chains per result', async () => {
    const run = (await exportOf(fixture('expense-api'))).runs[0];
    expect(Math.max(...run.results.map(r => r.codeFlows?.length ?? 0))).toBe(3);
  });

  it('terminates on a cycle and on a dense graph', () => {
    // A ring of 12 assets with every pair joined both ways: chain enumeration
    // without bounds would explode. The export must still return promptly.
    const assets = Array.from({ length: 12 }, (_, i) => `#n${i}`);
    const flows = assets.flatMap((a, i) => assets.filter((_, j) => j !== i).map(b => ({
      source: a, target: b, mechanism: 'call', location: { file: 'g.ts', line: i + 1 },
    })));
    flows.push({ source: 'Client', target: '#n0', mechanism: 'HTTPS', location: { file: 'g.ts', line: 99 } });
    const model = {
      assets: assets.map((a, i) => ({ path: [`N${i}`], id: a.slice(1), location: { file: 'd.ts', line: i + 1 } })),
      exposures: [{ asset: '#n5', threat: '#t', severity: 'high', external_refs: [], location: { file: 'g.ts', line: 6 } }],
      mitigations: [], acceptances: [], confirmed: [], boundaries: [], flows,
    } as unknown as ThreatModel;
    const started = Date.now();
    const sarif = generateSarif(model);
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(sarif.runs[0].results).toHaveLength(1);
    const chains = sarif.runs[0].results[0].codeFlows!;
    expect(chains.length).toBeLessThanOrEqual(3);
    // The budget is spent shortest-first, so the two-hop chain from the one
    // entry is found rather than lost inside the cluster.
    expect(chains[0].threadFlows[0].locations.map(l => l.location.message?.text)).toEqual([
      'Client -> #n0 via HTTPS', '#n0 -> #n5 via call', '@exposes #n5 to #t',
    ]);
  });
});

// ─── Related locations, taxa, logical locations ──────────────────────

describe('relatedLocations: declared context on the claim\'s asset', () => {
  it('lists boundaries, assumptions, data classes, transfers and audits, each sited and keyed', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const ssrf = byMessage(run, '#mailer is exposed to ssrf');
    expect(ssrf.relatedLocations!.map(l => [l.id, l.properties?.['guardlink/verb'], l.message?.text])).toEqual([
      [1, 'assumes', '@assumes #mailer: Callers pass only registered webhook URLs'],
      [2, 'transfers', '@transfers #ssrf from #mailer to #web: URL validation is the API layer\'s job'],
      [3, 'audit', '@audit #mailer: Confirm the API layer really rejects private address ranges'],
    ]);
    for (const l of ssrf.relatedLocations!) {
      expect(l.properties?.['guardlink/claimKey']).toMatch(/^[0-9a-f]{64}:\d+$/);
      expect(l.physicalLocation.artifactLocation.uri).toBe('src/notify.ts');
    }
    // A transfer names one threat: it is context for #ssrf, not for #log-flood.
    const flood = byMessage(run, '#mailer is exposed to log-flood');
    expect(flood.relatedLocations!.map(l => l.properties?.['guardlink/verb'])).toEqual(['assumes', 'audit']);
  });

  it('points a boundary at its graph edge', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const sqli = byMessage(run, '#store is exposed to sqli');
    const boundary = sqli.relatedLocations!.find(l => l.properties?.['guardlink/verb'] === 'boundary')!;
    expect(boundary.message?.text).toBe('@boundary between #orders and #store (#data): Service to database');
    const edge = run.graphs![0].edges.find(e => e.id === boundary.properties?.['guardlink/edge'])!;
    expect(edge.properties['guardlink/boundaryId']).toBe('data');
    expect(sqli.relatedLocations!.map(l => l.properties?.['guardlink/verb'])).toEqual(['boundary', 'handles']);
  });
});

describe('taxa: CWE and OWASP refs as SARIF taxonomies', () => {
  it('maps the claim\'s own refs, keeping properties.externalRefs', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const sqli = byMessage(run, '#store is exposed to sqli');
    expect(props(sqli).externalRefs).toEqual(['cwe:CWE-89', 'owasp:A03:2021']);
    expect(sqli.taxa!.map(t => [t.toolComponent.name, t.id])).toEqual([['CWE', '89'], ['OWASP', 'A03:2021']]);
  });

  it('resolves every reference through run.taxonomies by index', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    expect(run.taxonomies!.map(t => t.name)).toEqual(['CWE', 'OWASP']);
    for (const r of run.results) {
      for (const t of r.taxa ?? []) {
        const tax = run.taxonomies![t.toolComponent.index];
        expect(tax.name).toBe(t.toolComponent.name);
        expect(tax.taxa[t.index].id).toBe(t.id);
      }
    }
  });

  it('ignores schemes it has no taxonomy for, and omits run.taxonomies when nothing is referenced', () => {
    const sarif = generateSarif({
      exposures: [{ asset: '#a', threat: '#t', severity: 'low', external_refs: ['capec:CAPEC-66'], location: { file: 'a.ts', line: 1 } }],
      mitigations: [], acceptances: [], confirmed: [], flows: [],
    } as unknown as ThreatModel);
    expect(sarif.runs[0].results[0].taxa).toBeUndefined();
    expect(sarif.runs[0].taxonomies).toBeUndefined();
  });
});

describe('logicalLocations and the anchor', () => {
  it('names the handler a claim is attached to, and leaves the region on the annotation line', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const before = byMessage(baseline('sarif-shop') as Run, '#store is exposed to sqli');
    const sqli = byMessage(run, '#store is exposed to sqli');
    expect(sqli.locations[0].logicalLocations).toEqual([{ name: 'searchOrders' }]);
    expect(sqli.locations[0].physicalLocation).toEqual(before.locations[0].physicalLocation);
    expect(props(sqli)['guardlink/anchor']).toMatchObject({ scope: 'symbol', symbol: 'searchOrders' });
  });

  it('gives a module-level claim no logical location', async () => {
    const run = (await exportOf(fixture('sarif-shop'))).runs[0];
    const ssrf = byMessage(run, '#mailer is exposed to ssrf');
    expect(ssrf.locations[0].logicalLocations).toBeUndefined();
    expect(props(ssrf)['guardlink/anchor']).toMatchObject({ scope: 'file' });
  });
});

// ─── Graph ───────────────────────────────────────────────────────────

describe('run.graphs: the declared flow and boundary graph', () => {
  it('carries every @flows and @boundary as an edge between existing nodes', async () => {
    const { model } = await parseProject({ root: fixture('sarif-shop'), project: 'unused' });
    const graph = generateSarif(model).runs[0].graphs![0];
    const nodeIds = new Set(graph.nodes.map(n => n.id));
    expect(graph.edges.filter(e => e.properties['guardlink/kind'] === 'flow')).toHaveLength(model.flows.length);
    expect(graph.edges.filter(e => e.properties['guardlink/kind'] === 'boundary')).toHaveLength(model.boundaries.length);
    for (const e of graph.edges) {
      expect(nodeIds.has(e.sourceNodeId) && nodeIds.has(e.targetNodeId)).toBe(true);
      expect(e.properties['guardlink/claimKey']).toMatch(/^[0-9a-f]{64}:\d+$/);
    }
    expect(new Set(graph.edges.map(e => e.id)).size).toBe(graph.edges.length);
    // Declared assets are nodes with their definition site; undeclared endpoints are marked.
    expect(graph.nodes.find(n => n.id === 'store')).toMatchObject({ label: { text: '#store' }, properties: { 'guardlink/declared': true } });
    expect(graph.nodes.find(n => n.id === 'client')).toMatchObject({ label: { text: 'Client' }, properties: { 'guardlink/declared': false } });
  });

  it('infers a boundary\'s outer side only from an undeclared endpoint', async () => {
    const graph = (await exportOf(fixture('sarif-shop'))).runs[0].graphs![0];
    const edge = graph.edges.find(e => e.properties['guardlink/boundaryId'] === 'edge')!;
    expect(edge.properties['guardlink/side']).toEqual({ basis: 'undeclared-endpoint', outer: 'client', inner: 'web' });
    const data = graph.edges.find(e => e.properties['guardlink/boundaryId'] === 'data')!;
    expect(data.properties['guardlink/side']).toEqual({ basis: 'unknown' });
  });

  it('links each boundary to the flows that cross it, and each crossing flow back', async () => {
    const graph = (await exportOf(fixture('sarif-shop'))).runs[0].graphs![0];
    const edge = graph.edges.find(e => e.properties['guardlink/boundaryId'] === 'edge')!;
    const crossings = edge.properties['guardlink/crossings'] as string[];
    expect(crossings.length).toBe(4); // HTTPS, GET, POST, DELETE
    for (const id of crossings) {
      const flow = graph.edges.find(e => e.id === id)!;
      expect(flow.properties['guardlink/crosses']).toEqual([edge.id]);
    }
    const post = graph.edges.find(e => e.label?.text === 'POST./orders/search')!;
    expect(post.properties['guardlink/route']).toEqual({ http_method: 'POST', http_path: '/orders/search' });
  });
});

// ─── Rules and run envelope ─────────────────────────────────────────

describe('rules and the run envelope', () => {
  const run = generateSarif({ exposures: [], mitigations: [], acceptances: [], confirmed: [], flows: [] } as unknown as ThreatModel).runs[0];
  const rule = (id: string) => run.tool.driver.rules.find(r => r.id === id)!;

  it('bands security-severity for GitHub, and keeps diagnostics out of the security category', () => {
    expect(rule('guardlink/confirmed-exploitable').properties).toEqual({ tags: ['security', 'threat-model'], 'security-severity': '9.0' });
    expect(rule('guardlink/unmitigated-critical').properties).toEqual({ tags: ['security', 'threat-model'], 'security-severity': '8.9' });
    expect(rule('guardlink/unmitigated-exposure').properties).toEqual({ tags: ['security', 'threat-model'], 'security-severity': '5.0' });
    for (const id of ['guardlink/parse-error', 'guardlink/dangling-ref']) {
      expect(rule(id).properties).toEqual({ tags: ['threat-model'] });
    }
    for (const r of run.tool.driver.rules) expect(r.help?.text && r.help?.markdown).toBeTruthy();
  });

  it('files results under their own code scanning category', () => {
    expect(run.automationDetails).toEqual({ id: SARIF_AUTOMATION_ID });
    expect(SARIF_AUTOMATION_ID).toBe('guardlink/threat-model/');
  });

  it('writes versionControlProvenance only when given a repository URI, dropping empty fields', () => {
    expect(run.versionControlProvenance).toBeUndefined();
    const m = { exposures: [], mitigations: [], acceptances: [], confirmed: [], flows: [] } as unknown as ThreatModel;
    expect(generateSarif(m, [], [], { versionControl: { repositoryUri: 'https://example.com/o/r', revisionId: 'abc', branch: null } })
      .runs[0].versionControlProvenance).toEqual([{ repositoryUri: 'https://example.com/o/r', revisionId: 'abc' }]);
    expect(generateSarif(m, [], [], { versionControl: null }).runs[0].versionControlProvenance).toBeUndefined();
  });
});

describe('readVersionControl', () => {
  const roots: string[] = [];
  afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });
  const repo = (remote?: string) => {
    const root = mkdtempSync(join(tmpdir(), 'gl-sarif-vcs-'));
    roots.push(root);
    const git = (args: string) => execSync(`git ${args}`, { cwd: root, stdio: 'pipe' });
    git('init -q -b trunk');
    git('-c user.email=t@example.com -c user.name=t commit -q --allow-empty -m init');
    if (remote) git(`remote add origin ${remote}`);
    return root;
  };

  it('reads the web URL, HEAD and branch, and never the credentials in the remote', () => {
    const root = repo('https://someone:s3cret-token@github.com/acme/shop.git');
    const vcs = readVersionControl(root)!;
    expect(vcs.repositoryUri).toBe('https://github.com/acme/shop');
    expect(vcs.revisionId).toMatch(/^[0-9a-f]{40}$/);
    expect(vcs.branch).toBe('trunk');
    expect(JSON.stringify(vcs)).not.toContain('s3cret');
  });

  it('is null with no origin, or an origin that is a local path', () => {
    expect(readVersionControl(repo())).toBeNull();
    expect(readVersionControl(repo('/srv/git/shop.git'))).toBeNull();
  });
});

// ─── The two front-end defects ───────────────────────────────────────

describe('--min-severity', () => {
  it('filters unmitigated exposures and always keeps @confirmed results', async () => {
    const all = (await exportOf(fixture('sarif-shop'))).runs[0];
    const critical = (await exportOf(fixture('sarif-shop'), 'critical')).runs[0];
    const exposures = (run: Run) => run.results.filter(r => r.ruleId.startsWith('guardlink/unmitigated'));
    expect(exposures(all).length).toBeGreaterThan(1);
    expect(exposures(critical).map(r => props(r).severity)).toEqual(['critical']);
    // The confirmed finding is [high], below the floor, and is still exported.
    const confirmed = critical.results.filter(r => r.ruleId === 'guardlink/confirmed-exploitable');
    expect(confirmed.map(r => props(r).severity)).toEqual(['high']);
  });
});

describe('MCP guardlink_sarif', () => {
  const roots: string[] = [];
  afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

  it('reports dangling refs exactly as `guardlink sarif` does', async () => {
    const root = mkdtempSync(join(tmpdir(), 'gl-sarif-mcp-'));
    roots.push(root);
    cpSync(fixture('sarif-shop'), root, { recursive: true });

    const server = createServer();
    const client = new Client({ name: 'test', version: '0.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      await client.callTool({ name: 'guardlink_sarif', arguments: { root, output: 'out.sarif' } });
    } finally {
      await client.close();
    }

    const viaMcp = JSON.parse(readFileSync(join(root, 'out.sarif'), 'utf-8')).runs[0] as Run;
    const viaCli = (await exportOf(root)).runs[0];
    expect(viaMcp.results.filter(r => r.ruleId === 'guardlink/dangling-ref')).toHaveLength(1);
    expect(JSON.stringify(viaMcp.results)).toBe(JSON.stringify(viaCli.results));
  });
});
