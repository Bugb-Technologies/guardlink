/**
 * Reach on the surfaces people read: the dashboard's Agents & Reach page, the
 * report's "Agents and LLM Reach" section, the agent-only report
 * (`report --agents`), and the threat-report serialisation.
 *
 * Driven by `tests/fixtures/support-desk` — the same fixture the reach export
 * and the pentest SARIF are pinned on — plus a small inline app for what that
 * fixture does not declare (untrusted input, egress, a broader identity). The derived
 * view (`summarizeReach`), the report section, the agent report and the reach
 * diagram are pinned as golden files beside the fixture; regenerate them with
 * `npx vitest run tests/agent-reach-surfaces.test.ts -u` and read the diff.
 *
 * @validates #output-encoding for #dashboard -- "Actor, capability and description text from reach annotations is HTML-escaped on the Agents page and the actor table"
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { summarizeReach, hasReach } from '../src/reach/index.js';
import { buildReachAnalysis } from '../src/parser/reach.js';
import { generateReport, generateAgentReachReport, emitAgentReach } from '../src/report/index.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { generateReachDiagram } from '../src/dashboard/diagrams.js';
import { serializeAgentReach, serializeModel } from '../src/analyze/index.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE = join(repoRoot, 'tests', 'fixtures', 'support-desk');
const GOLDEN = './fixtures/support-desk/golden';

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

function writeProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-reach-surfaces-'));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return root;
}

const parse = async (root: string) => (await parseProject({ root, project: 'support-desk' })).model;

/** The section between one `<div id="sec-…">` and the next. */
function page(html: string, id: string): string {
  const start = html.indexOf(`<div id="sec-${id}"`);
  const next = html.indexOf('<div id="sec-', start + 1);
  return html.slice(start, next < 0 ? undefined : next);
}

let model: ThreatModel;
beforeAll(async () => { model = await parse(FIXTURE); });

// ─── The derived view ────────────────────────────────────────────────

describe('summarizeReach over the support-desk fixture', () => {
  it('matches the golden view the dashboard and the report both draw', async () => {
    await expect(`${JSON.stringify(summarizeReach(model), null, 2)}\n`).toMatchFileSnapshot(`${GOLDEN}/reach-summary.json`);
  });

  it('agrees with reach_analysis on what is unentitled and ungated', () => {
    const s = summarizeReach(model);
    const ra = buildReachAnalysis(model);
    expect(s.totals.unentitled).toBe(ra.summary.unentitled_reaches);
    expect(s.totals.mutations).toBe(ra.summary.mutating_effects);
    expect(s.totals.ungated).toBe(ra.summary.ungated_effects);
    const where = (r: { file: string; line: number }) => `${r.file}:${r.line}`;
    expect(s.ungated.map(u => where(u.loc)).sort())
      .toEqual(ra.mutating_effects.filter(m => !m.gated).map(where).sort());
  });

  it('puts each tool\'s effects in the agent\'s row through the code they are bound to', () => {
    const s = summarizeReach(model);
    const agentRow = s.cells.filter(c => c.actor === 'support-agent');
    expect(agentRow.find(c => c.asset === 'orders-db')!.effects.map(e => [e.effect, e.gated, e.via])).toEqual([
      ['read', null, ['lookup-order']],
      ['delete', false, ['run-sql']],
    ]);
    expect(agentRow.find(c => c.asset === 'payments')!.effects).toMatchObject([
      { effect: 'spend', gated: true, approvers: ['#support-human'], via: ['issue-refund'] },
    ]);
    // The nightly sweep and the reviewed email have no reach on their code.
    expect(s.loose.map(l => [l.asset, l.effects.map(e => [e.effect, e.gated])])).toEqual([
      ['outbox', [['notify', true]]],
      ['payments', [['spend', false]]],
    ]);
  });

  it('gives each unentitled reach, and each ungated mutation, the reason a near miss does not count', () => {
    const s = summarizeReach(model);
    expect(Object.fromEntries(s.unentitled.map(u => [u.capability, u.near_misses.map(n => n.blocker)]))).toEqual({
      'run-sql': [], 'search-kb': ['other-asset'], 'fetch-url': ['uncited'], 'mcp-files': [], 'publish-package': [],
    });
    expect(s.ungated.find(u => u.effect === 'spend')).toMatchObject({
      asset: '#payments', via: [], gate_near_misses: [{ approver: '#support-human', capability: 'issue-refund', blocker: 'capability-unknown' }],
    });
  });

  it('maps only the agent\'s reach to OWASP rows', () => {
    const s = summarizeReach(model);
    const owasp = Object.fromEntries(s.owasp.map(o => [o.id, o.items.map(i => i.facet)]));
    expect(owasp.LLM06).toEqual(['functionality', 'functionality', 'functionality', 'functionality', 'autonomy', 'autonomy', 'autonomy']);
    expect(owasp.LLM01).toEqual([]);
    expect(owasp.LLM05).toHaveLength(3);
    // The CI runner is not an agent: its ungated write is listed, but on no OWASP LLM row.
    expect(s.ungated.find(u => u.asset === '#registry')).toMatchObject({ agent: false });
    expect(s.owasp.flatMap(o => o.items).some(i => i.agent === '#ci-runner')).toBe(false);
  });
});

// ─── Injection, egress and identity ──────────────────────────────────

describe('an agent with untrusted input, egress and a broader identity', () => {
  const DEFS = `/**
 * @asset Tools (#tools) -- "t"
 * @asset Db (#db) -- "d"
 * @asset Session (#session) -- "customer token"
 * @asset DbAdmin (#db-admin) -- "admin role"
 * @actor Bot (#bot) -- "agent"
 */
export {};
`;
  const APP = `const x = 1;

/**
 * @flows Customer -> #bot via chat -- "the prompt"
 */
export function chat(): void {}

/**
 * @agents #bot to run-sql on #tools as #session
 * @effects write on #db as #db-admin -- "model-written SQL"
 */
export function runSql(): void {}

/**
 * @agents #bot to fetch-url on #tools
 * @flows #tools -> External.Internet via fetch
 * @boundary between #tools and External.Internet (#egress) -- "leaves the app"
 */
export function fetchUrl(): void {}
`;
  let s: ReturnType<typeof summarizeReach>;
  beforeAll(async () => { s = summarizeReach(await parse(writeProject({ '.guardlink/definitions.ts': DEFS, 'src/app.ts': APP }))); });

  it('finds the injection-to-tool route from outside input to the ungated write', () => {
    expect(s.injection).toMatchObject([{ entry: 'Customer', chain: ['Customer', '#bot'], agent: '#bot', effects: [{ effect: 'write', asset: '#db' }] }]);
    expect(s.owasp.find(o => o.id === 'LLM01')!.items).toHaveLength(1);
  });

  it('reports egress across the boundary, and the broader execution identity', () => {
    expect(s.egress).toMatchObject([{ actors: ['#bot'], source: '#tools', target: 'External.Internet', external: true, boundaries: ['#egress'] }]);
    const llm06 = s.owasp.find(o => o.id === 'LLM06')!.items;
    expect(llm06.filter(i => i.facet === 'permissions').map(i => i.text))
      .toEqual(['run-sql presents #session, and the write on #db runs as #db-admin with no gate between']);
  });
});

// ─── The report ──────────────────────────────────────────────────────

describe('the report', () => {
  const stamp = (md: string) => md.replace(/^> Generated: .*$/m, '> Generated: <generated_at>');

  it('matches the golden "Agents and LLM Reach" section', async () => {
    const lines: string[] = [];
    emitAgentReach(model, lines);
    await expect(`${lines.join('\n')}\n`).toMatchFileSnapshot(`${GOLDEN}/agent-reach-section.md`);
  });

  it('matches the golden agent-only threat model', async () => {
    await expect(`${stamp(generateAgentReachReport(model))}\n`).toMatchFileSnapshot(`${GOLDEN}/threat-model-agents.md`);
  });

  it('places the same section in the main threat model, and counts it in the summary', () => {
    const md = generateReport(model);
    expect(md).toContain('## Agents and LLM Reach');
    const section = md.slice(md.indexOf('## Agents and LLM Reach'), md.indexOf('## Executive Summary'));
    const lines: string[] = [];
    emitAgentReach(model, lines);
    expect(section).toContain(lines.join('\n'));
    expect(md).toContain('| **Unentitled reaches** | **5** |');
    expect(md).toContain('| **Ungated mutations** | **5** |');
  });

  it('leaves a model with no reach annotation exactly as it reported before', async () => {
    const m = await parse(writeProject({
      '.guardlink/definitions.ts': '/**\n * @asset App (#app) -- "a"\n * @threat Sqli (#sqli) [high] -- "s"\n */\nexport {};\n',
      'src/a.ts': 'const x = 1;\n\n/**\n * @exposes #app to #sqli [high] -- "raw sql"\n */\nexport function q(): void {}\n',
    }));
    expect(hasReach(m)).toBe(false);
    const md = generateReport(m);
    expect(md).not.toContain('Agents and LLM Reach');
    expect(md).not.toContain('Unentitled reaches');
    expect(generateAgentReachReport(m)).toContain('_No `@agents`, `@reaches`, `@effects` or `@gates` annotations.');
  });

  it('carries a feature slice into every heading of the agent report', () => {
    const sliced = { ...model, filtered_by_features: ['Support'] } as ThreatModel;
    const md = generateAgentReachReport(sliced);
    expect(md).toContain('# Agent and LLM Threat Model — support-desk — feature "Support"');
    for (const h of md.split('\n').filter(l => l.startsWith('## ') || l.startsWith('### '))) {
      expect(h, h).toContain('feature "Support"');
    }
  });
});

// ─── The threat-report path ──────────────────────────────────────────

describe('the threat-report serialisation', () => {
  it('hands the LLM the reach claims and the derived lists', () => {
    const reach = serializeAgentReach(model)!;
    expect(reach.unentitled_reaches).toHaveLength(5);
    expect(reach.ungated_mutations).toHaveLength(5);
    // Only the rows with evidence: this fixture declares no untrusted input, so no LLM01.
    expect((reach.owasp_llm as { id: string }[]).map(o => o.id)).toEqual(['LLM06', 'LLM05']);
    expect(JSON.parse(serializeModel(model)).agent_reach).toEqual(reach);
  });

  it('adds nothing for a model with no reach annotation', async () => {
    const m = await parse(writeProject({ '.guardlink/definitions.ts': '// @asset App (#app) -- "a"\nexport {};\n' }));
    expect(serializeAgentReach(m)).toBeUndefined();
    expect(JSON.parse(serializeModel(m))).not.toHaveProperty('agent_reach');
  });
});

// ─── The dashboard ───────────────────────────────────────────────────

describe('the dashboard', () => {
  let html: string;
  beforeAll(() => { html = generateDashboardHTML(model, FIXTURE); });

  it('adds an Agents & Reach page with the reach map, its lists and the OWASP rows', () => {
    expect(html).toContain('<a href="#agents" data-page="agents">');
    const agents = page(html, 'agents');
    expect(agents).toContain('id="reach-map"');
    expect(agents).toContain('id="agent-unentitled"');
    expect(agents).toContain('id="agent-ungated"');
    expect(agents).toContain('id="agent-gates"');
    expect(agents).toContain('id="agents-owasp"');
    // One row per actor that reaches something, the agent marked, and one for effects no reach is bound to.
    expect(agents.match(/<th class="heat-row reach-actor"/g)).toHaveLength(3);
    expect(agents).toContain('<span>not tied to a reach</span>');
    expect(agents).toContain('<span class="reach-kind agent">AI agent</span>');
    expect(agents.match(/reach-chip reach-cap bad/g)!.length).toBeGreaterThanOrEqual(5);
  });

  it('draws the reach map as a diagram tab, matching the golden Mermaid source', async () => {
    expect(page(html, 'diagrams')).toContain('Agent Reach');
    await expect(`${generateReachDiagram(summarizeReach(model))}\n`).toMatchFileSnapshot(`${GOLDEN}/agent-reach.mmd`);
  });

  it('marks agents in the actor table, and gives reached assets a reach section in their drawer', () => {
    const data = page(html, 'data');
    expect(data).toContain('id="actors"');
    expect(data).toMatch(/<code>#support-agent<\/code><\/td>\s*<td><span class="reach-kind agent">AI agent<\/span>/);
    expect(data).toMatch(/<code>#support-human<\/code><\/td>\s*<td><span class="reach-kind">approver<\/span>/);
    const assets = JSON.parse(html.match(/const assetsData = (.*);\n/)![1]) as { name: string; reach: unknown }[];
    expect(assets.find(a => a.name === '#payments')!.reach).toEqual({
      capabilities: [],
      effects: [
        { actor: '#support-agent', effect: 'spend', gated: true, approvers: ['#support-human'], via: ['issue-refund'] },
        // The nightly sweep: no reach on its code, so the issue-refund gate does not cover it.
        { actor: null, effect: 'spend', gated: false, approvers: [], via: [] },
      ],
      gates: [{ approver: '#support-human', capability: 'issue-refund' }],
    });
    expect(assets.find(a => a.name === '#agent-session')!.reach).toBeNull();
  });

  it('puts unentitled reaches and ungated mutations on the summary\'s to-do list', () => {
    const summary = page(html, 'summary');
    expect(summary).toContain('5 capabilities handed out that nobody approved');
    expect(summary).toContain('5 mutations with no one deciding first');
  });

  it('shows an empty state, not an empty grid, when nothing declares reach', async () => {
    const m = await parse(writeProject({
      '.guardlink/definitions.ts': '/**\n * @asset App (#app) -- "a"\n * @threat Sqli (#sqli) [high] -- "s"\n */\nexport {};\n',
      'src/a.ts': 'const x = 1;\n\n/**\n * @exposes #app to #sqli [high] -- "raw sql"\n */\nexport function q(): void {}\n',
    }));
    const out = generateDashboardHTML(m);
    const agents = page(out, 'agents');
    expect(agents).toContain('class="empty-state"');
    expect(agents).not.toContain('id="reach-map"');
    expect(page(out, 'diagrams')).not.toContain('Agent Reach');
    expect(page(out, 'summary')).not.toContain('nobody approved');
  });

  it('escapes reach text from the model', async () => {
    const m = await parse(writeProject({
      '.guardlink/definitions.ts': '/**\n * @asset Tools (#tools) -- "t"\n * @actor Bot (#bot) -- "<img src=x onerror=alert(1)>"\n */\nexport {};\n',
      'src/a.ts': 'const x = 1;\n\n/**\n * @agents #bot to run-sql on #tools -- "<script>alert(1)</script>"\n */\nexport function q(): void {}\n',
    }));
    const out = generateDashboardHTML(m);
    for (const id of ['agents', 'data']) {
      expect(page(out, id)).not.toContain('<img src=x');
      expect(page(out, id)).not.toContain('<script>alert');
    }
    expect(page(out, 'agents')).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });
});

// ─── The CLI ─────────────────────────────────────────────────────────

describe('guardlink report --agents', () => {
  const cli = join(repoRoot, 'src', 'cli', 'index.ts');
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const run = (cwd: string, ...args: string[]) => new Promise<{ status: number; stderr: string }>(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8' }, (err, _stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stderr });
    });
  });

  it('writes the agent threat model alone, and the full report still carries the section', async () => {
    const root = mkdtempSync(join(tmpdir(), 'gl-reach-cli-'));
    roots.push(root);
    cpSync(FIXTURE, root, { recursive: true, filter: src => !src.includes(`${'/'}golden`) });

    const agents = await run(root, 'report', '.', '--agents');
    expect(agents.status, agents.stderr).toBe(0);
    const md = readFileSync(join(root, 'threat-model-agents.md'), 'utf-8');
    expect(md.startsWith('# Agent and LLM Threat Model — support-desk')).toBe(true);
    expect(md).toContain('### Unentitled Reaches');
    expect(existsSync(join(root, 'threat-model.json'))).toBe(false);

    const full = await run(root, 'report', '.');
    expect(full.status, full.stderr).toBe(0);
    expect(readFileSync(join(root, 'threat-model.md'), 'utf-8')).toContain('## Agents and LLM Reach');
  }, 60_000);
});
