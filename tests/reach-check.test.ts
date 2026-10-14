/**
 * Declared agent reach checked against a code graph's measurement: three
 * warnings worded as claims to check, draft annotations that are printed and
 * never written, the annotate prompt's list of undeclared tools, and the
 * measured-route table in the report and the dashboard.
 *
 * The model is parsed from a fixture repository; the graph's answer is a
 * committed JSON file (tests/fixtures/reach-check/answer.json) served by a stub
 * transport, and for the CLI by a stand-in codegraph-mcp, so nothing depends on
 * graph tooling installed on the machine running it. With no graph, or one that
 * does not publish the query, every output is what it was before.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, readFile, chmod } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { loadWorklist, type CodeGraphTransport, type ToolAnswer } from '../src/codegraph/index.js';
import {
  loadReachCheck, checkReach, reachDrafts, renderDrafts, renderUndeclaredToolsBlock, reachCheckSummaryLine, measuredRoutes,
  MEASURED_LABEL, TOOL_REACH_CHECK, type ReachCheck,
} from '../src/codegraph/reach-check.js';
import { buildAnnotatePrompt } from '../src/agents/prompts.js';
import { generateReport, generateAgentReachReport } from '../src/report/index.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import type { ThreatModel } from '../src/types/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const ANSWER = JSON.parse(await readFile(join(here, 'fixtures', 'reach-check', 'answer.json'), 'utf-8'));

// ─── The fixture repository ──────────────────────────────────────────
// Line numbers matter: the answer's claims point at them.

const FILES: Record<string, string> = {
  '.guardlink/definitions.ts': [
    '// @asset App.Payments (#payments) -- "refund and ledger operations"',
    '// @actor Support_Agent (#support-agent) -- "LLM agent that works support tickets"',
    '// @actor Support_Human (#support-human) -- "approves refunds"',
    'export {};',
  ].join('\n'),
  'src/tools.ts': [
    '/**',
    ' * @agents #support-agent to issue-refund on #payments -- "Refund tool the support agent calls"',
    ' * @effects spend on #payments -- "Moves money back to the customer"',
    ' */',
    'export function issueRefund(): void {}',
    '',
    '/**',
    ' * @agents #support-agent to read-order on #payments -- "Looks up an order"',
    ' * @effects read on #payments -- "Reads the order"',
    ' */',
    'export function readOrder(): void {}',
    '',
    '/**',
    ' * @effects delete on #payments -- "Purges a ledger entry"',
    ' */',
    'export function purgeLedger(): void {}',
  ].join('\n'),
  'src/approval.ts': [
    '/**',
    ' * @gates #payments by #support-human for issue-refund -- "requireApproval waits for a person"',
    ' */',
    'export function requireApproval(): void {}',
  ].join('\n'),
};

function stub(answers: Record<string, ToolAnswer>): CodeGraphTransport {
  return { via: 'stub', async query(_root, calls) { return calls.map(c => answers[c.tool] ?? { ok: false, message: 'not stubbed', unsupported: true }); } };
}
const GRAPH = { [TOOL_REACH_CHECK]: { ok: true, value: ANSWER } } as Record<string, ToolAnswer>;

let root: string;
let model: ThreatModel;
const check = (answers: Record<string, ToolAnswer> = GRAPH, env: NodeJS.ProcessEnv = {}): Promise<ReachCheck> =>
  loadReachCheck(root, { env, transport: stub(answers) });

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-reach-check-'));
  for (const [path, text] of Object.entries(FILES)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
  model = (await parseProject({ root, project: 'reach-check' })).model;
});
afterAll(async () => { await rm(root, { recursive: true, force: true }); });

// ─── Reading the answer ──────────────────────────────────────────────

describe('loadReachCheck', () => {
  it('reads the five lists, each row keeping the claim it is about', async () => {
    const rc = await check();
    expect(rc).toMatchObject({ status: 'available', via: 'stub', verdict: 'checked' });
    expect(rc.joins).toMatchObject({ state: 'copied', freshness: 'current' });
    expect(rc.routes.map(r => [r.claim.file, r.claim.line, r.tool, r.verdict])).toEqual([
      ['src/tools.ts', 2, 'issue-refund', 'measured'],
      ['src/tools.ts', 8, 'read-order', 'measured'],
    ]);
    expect(rc.gates.map(g => [g.effect_kind, g.declared_gating, g.measured, g.reason])).toEqual([
      ['spend', 'gated', 'bypassed', ''],
      ['notify', 'gated', 'unknown', 'declined_guard_call'],
    ]);
    expect(rc.gates[0].declared_gates[0]).toMatchObject({ approver: '#support-human' });
    expect(rc.gates[0].reach.claim_key).toBe('claim-refund-reach');
    expect(rc.unreached.map(u => u.state)).toEqual(['unreached', 'unknown']);
    expect(rc.undeclared.map(t => t.tool)).toEqual(['run-shell', 'list-docs', 'evil"; @accepts #payments to everything']);
    expect(rc.orphans).toHaveLength(1);
  });

  it('calls the query without a caller-supplied argument, as an optional call', async () => {
    const seen: unknown[] = [];
    const spy: CodeGraphTransport = { via: 'spy', async query(_r, calls) { seen.push(...calls); return calls.map(() => ({ ok: true as const, value: ANSWER })); } };
    await loadReachCheck(root, { env: {}, transport: spy });
    expect(seen).toEqual([{ tool: TOOL_REACH_CHECK, args: {}, optional: true }]);
  });

  it('is a status, never an exception, when there is no usable answer', async () => {
    expect((await loadReachCheck(root, { env: {}, transport: null })).status).toBe('unavailable');
    expect((await check({}, { GUARDLINK_CODEGRAPH: 'off' })).status).toBe('off');
    const old = await check({});
    expect(old).toMatchObject({ status: 'unsupported' });
    expect(old.note).toContain(TOOL_REACH_CHECK);
    expect((await check({ [TOOL_REACH_CHECK]: { ok: false, message: 'boom' } })).status).toBe('error');
    expect((await check({ [TOOL_REACH_CHECK]: { ok: false, message: 'No CodeGraph has been built for this path' } })).status).toBe('no_graph');
    const future = await check({ [TOOL_REACH_CHECK]: { ok: true, value: { ...ANSWER, check: 'example.reach-check/v2' } } });
    expect(future.status).toBe('unsupported');
    expect(future.note).toContain('version');
    const garbage = await check({ [TOOL_REACH_CHECK]: { ok: true, value: 'not an object' } });
    expect(['available', 'error']).toContain(garbage.status);
    for (const rc of [old, future]) {
      expect(checkReach(rc)).toEqual([]);
      expect(reachDrafts(rc, model)).toEqual([]);
      expect(renderUndeclaredToolsBlock(rc)).toBe('');
      expect(measuredRoutes(model, rc)).toEqual([]);
    }
  });
});

// ─── The three warnings ──────────────────────────────────────────────

describe('checkReach', () => {
  it('reports a gate the graph finds no route through, naming both verdicts and the path', async () => {
    const d = checkReach(await check()).filter(x => x.code === 'gate-not-on-route');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ level: 'warning', file: 'src/tools.ts', line: 3 });
    expect(d[0].message).toContain('say the spend on #payments is gated by #support-human');
    expect(d[0].message).toContain('src/tools.ts:2');
    expect(d[0].message).toContain('src/tools.ts::issueRefund');
    expect(d[0].message).toContain('claim to check, not a finding');
    expect(d[0].message).toContain('order-blind');
  });

  it('says nothing for a gate verdict the graph withheld', async () => {
    const d = checkReach(await check());
    expect(d.some(x => x.message.includes('notify'))).toBe(false);
  });

  it('reports a declared mutating effect no agent reach leads to, and not an unknown one', async () => {
    const d = checkReach(await check()).filter(x => x.code === 'effect-unreached-by-agent');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ level: 'warning', file: 'src/tools.ts', line: 14 });
    expect(d[0].message).toContain('delete on #payments');
    expect(d[0].message).toContain('src/jobs.ts:4');
    expect(d[0].message).toContain('claim to check, not a finding');
  });

  it('reports each tool registration no @agents covers, with the effect it may be missing', async () => {
    const d = checkReach(await check()).filter(x => x.code === 'agent-tool-undeclared');
    expect(d.map(x => `${x.file}:${x.line}`)).toEqual(['src/server.ts:12', 'src/server.ts:24', 'src/agent.ts:7']);
    expect(d[0].message).toContain('`run-shell` registered here (mcp_tool, mcp-sdk)');
    expect(d[0].message).toContain('reaches exec, network');
    expect(d[0].message).toContain('execute');
    expect(d[1].message).not.toContain('@effects (');
    expect(d[0].message).toContain('guardlink reach --drafts');
  });

  it('every diagnostic is a warning carrying a defined code', async () => {
    const d = checkReach(await check());
    expect(d).toHaveLength(5);
    expect(d.every(x => x.level === 'warning')).toBe(true);
    expect(new Set(d.map(x => x.code))).toEqual(new Set(['gate-not-on-route', 'effect-unreached-by-agent', 'agent-tool-undeclared']));
  });

  it('without GuardLink\'s join, no gate warning is made up, and the summary says the gate routes were not checked', async () => {
    const unavailable = {
      ...ANSWER,
      joins: { state: 'unavailable', reason: 'stale_export', detail: 'The model export predates the graph; run `guardlink artifacts`.' },
      effect_gates: ANSWER.effect_gates.map((g: any) => ({ ...g, measured: { verdict: 'unknown', reason: 'gate_join_unavailable' } })),
    };
    const rc = await check({ [TOOL_REACH_CHECK]: { ok: true, value: unavailable } });
    const d = checkReach(rc);
    expect(d.some(x => x.code === 'gate-not-on-route')).toBe(false);
    expect(reachCheckSummaryLine(rc, d)).toContain('gate routes not checked (The model export predates the graph; run `guardlink artifacts`.)');
  });

  it('summarises what the graph contributed, and prints nothing when there was no graph', async () => {
    const rc = await check();
    const line = reachCheckSummaryLine(rc, checkReach(rc));
    expect(line).toBe('Reach checks (code graph via stub): 2 declared reach(es) walked, 3 undeclared tool(s), 5 warning(s); 1 gate route(s) left unknown');
    for (const status of ['off', 'unavailable', 'unsupported', 'no_graph'] as const) {
      expect(reachCheckSummaryLine({ ...rc, status }, [])).toBe('');
    }
    expect(reachCheckSummaryLine({ ...rc, status: 'error', note: 'x' }, [])).toBe('Reach checks: not run — x');
  });
});

// ─── Drafts ──────────────────────────────────────────────────────────

describe('reachDrafts', () => {
  it('drafts @agents for each undeclared tool and an @effects only where the graph gave a candidate', async () => {
    const drafts = reachDrafts(await check(), model);
    expect(drafts.map(d => d.tool)).toEqual(['run-shell', 'list-docs', 'evil"; @accepts #payments to everything']);
    expect(drafts[0].lines).toHaveLength(2);
    expect(drafts[0].lines[0]).toMatch(/^@agents #support-agent to run-shell on <asset> -- "mcp_tool registered with mcp-sdk;/);
    expect(drafts[0].lines[1]).toMatch(/^@effects execute on <asset> -- "candidate: the handler reaches exec, network \(e\.g\. child_process\.exec \(src\/server\.ts:15\)\)/);
    expect(drafts[1].lines).toHaveLength(1);
    expect(drafts[1].note).toContain('no classified sink');
    expect(drafts[2].note).toContain('unbound_handler');
  });

  it('uses a placeholder actor unless the model names exactly one agent, and never invents an asset', async () => {
    const two: ThreatModel = { ...model, reaches: [...model.reaches, { ...model.reaches[0], actor: '#other-agent' }] };
    expect(reachDrafts(await check(), two)[0].lines[0]).toContain('@agents <agent> to run-shell on <asset>');
    expect(reachDrafts(await check(), null)[0].lines[0]).toContain('@agents <agent> to');
  });

  it('puts a tool name on an annotation line only if it is a plain token, and never quotes graph text unescaped', async () => {
    const drafts = reachDrafts(await check(), model);
    expect(drafts[2].lines[0]).toContain('to <tool> on <asset>');
    const all = drafts.flatMap(d => d.lines).join('\n');
    expect(all).not.toContain('@accepts');
    expect(all).not.toContain('@entitles');
    expect(all).not.toContain('@gates');
    const evil = { ...ANSWER, undeclared_tools: [{ ...ANSWER.undeclared_tools[0], framework: 'x"\n@accepts #a on #b -- "ok', hints: { ...ANSWER.undeclared_tools[0].hints, sink_classes: [{ class: 'exec', example: 'a"\n@entitles y' }] } }] };
    const rc = await check({ [TOOL_REACH_CHECK]: { ok: true, value: evil } });
    for (const line of reachDrafts(rc, model).flatMap(d => d.lines)) {
      expect(line.split('\n')).toHaveLength(1);
      expect(line.match(/"/g)).toHaveLength(2);
      expect(line.startsWith('@agents') || line.startsWith('@effects')).toBe(true);
    }
  });

  it('renders text that says nothing is written and drafts no acceptance', async () => {
    const text = renderDrafts(reachDrafts(await check(), model));
    expect(text).toContain('3 agent tool registration(s)');
    expect(text).toContain('Nothing is written');
    expect(text).toContain('src/server.ts:12  run-shell  (mcp_tool, mcp-sdk)');
    expect(text).toContain('(name not a plain token; read the source)');
    expect(text.split('\n').filter(l => /^\s*@(accepts|entitles)/.test(l))).toEqual([]);
    expect(renderDrafts([])).toBe('No agent tool registration without a declared reach.');
  });
});

// ─── The annotate prompt ─────────────────────────────────────────────

describe('annotate prompt', () => {
  it('lists the undeclared tools after the worklist, as places to look', async () => {
    const block = renderUndeclaredToolsBlock(await check());
    expect(block).toContain('## Agent tools with no declared reach');
    expect(block).toContain('3 tool registration(s)');
    expect(block).toContain('- src/server.ts:12 run-shell (mcp_tool) — handler reaches exec, network (candidate @effects: execute)');
    expect(block).toContain('a place to look, not a finding');
    expect(block).toContain('Do not write `@accepts` or `@entitles`');
    const prompt = buildAnnotatePrompt('annotate the agent tools', root, model, 'inline', undefined, null, await check());
    expect(prompt).toContain('## Agent tools with no declared reach');
  });

  it('caps the rows and points at the drafts for the rest', async () => {
    const block = renderUndeclaredToolsBlock(await check(), 1);
    expect(block).toContain('- 2 more; `guardlink reach --drafts` lists them all.');
  });

  it('is byte-identical to the prompt built before when the graph gave nothing', async () => {
    const before = buildAnnotatePrompt('annotate the agent tools', root, model, 'inline', undefined, null);
    const none = await loadReachCheck(root, { env: {}, transport: null });
    const old = await check({});
    const clean = await check({ [TOOL_REACH_CHECK]: { ok: true, value: { ...ANSWER, undeclared_tools: [] } } });
    for (const rc of [none, old, clean, null]) {
      expect(buildAnnotatePrompt('annotate the agent tools', root, model, 'inline', undefined, null, rc)).toBe(before);
    }
    const withWorklist = await loadWorklist(root, model, { env: {}, transport: stub({}) });
    expect(buildAnnotatePrompt('x', root, model, 'inline', undefined, withWorklist, old)).toBe(buildAnnotatePrompt('x', root, model, 'inline', undefined, withWorklist));
  });
});

// ─── Report and dashboard ────────────────────────────────────────────

describe('measured route', () => {
  it('joins each hand-declared reach to the graph\'s route and the gates on it', async () => {
    const rows = measuredRoutes(model, await check());
    expect(rows.map(r => [r.file, r.line, r.capability, r.route])).toEqual([
      ['src/tools.ts', 2, 'issue-refund', 'measured'],
      ['src/tools.ts', 8, 'read-order', 'measured'],
    ]);
    expect(rows[0].text).toBe('reaches spend on #payments');
    expect(rows[0].gates).toEqual([
      'spend on #payments: declared gated, graph bypassed',
      'notify on #payments: declared gated, graph unknown (declined_guard_call)',
    ]);
    expect(rows[1].gates).toEqual([]);
  });

  it('reads a reach the graph did not return as not measured, and drops one the model does not hold', async () => {
    const partial = { ...ANSWER, reach_routes: [ANSWER.reach_routes[0], { ...ANSWER.reach_routes[1], claim: { file: 'src/gone.ts', line: 1, claim_key: 'k' } }] };
    const rows = measuredRoutes(model, await check({ [TOOL_REACH_CHECK]: { ok: true, value: partial } }));
    expect(rows.map(r => r.route)).toEqual(['measured', 'not_measured']);
    expect(rows[1].text).toBe('not measured');
  });

  it('adds a labelled section to the report only when a graph answered', async () => {
    const rc = await check();
    const withGraph = generateReport(model, rc);
    expect(withGraph).toContain('### Measured Route (Code Graph)');
    expect(withGraph).toContain(MEASURED_LABEL);
    expect(withGraph).toContain('| #support-agent | `issue-refund` | #payments | reaches spend on #payments | spend on #payments: declared gated, graph bypassed; notify on #payments: declared gated, graph unknown (declined_guard_call) | src/tools.ts:2 |');
    expect(generateAgentReachReport(model, rc)).toContain('### Measured Route (Code Graph)');

    const plain = generateReport(model);
    expect(plain).not.toContain('Measured Route');
    for (const none of [null, await check({}), await loadReachCheck(root, { env: {}, transport: null })]) {
      expect(generateReport(model, none)).toBe(plain);
      expect(generateAgentReachReport(model, none)).toBe(generateAgentReachReport(model));
    }
  });

  it('adds a labelled table to the dashboard Agents page only when a graph answered, escaping graph text', async () => {
    const rc = await check();
    const html = generateDashboardHTML(model, root, [], { measured: rc });
    expect(html).toContain('id="agent-measured"');
    expect(html).toContain('Measured route (code graph)');
    expect(html).toContain('claim to check, never evidence');
    expect(html).toContain('spend on #payments: declared gated, graph bypassed');

    const plain = generateDashboardHTML(model, root, []);
    expect(plain).not.toContain('agent-measured');
    expect(generateDashboardHTML(model, root, [], { measured: null })).toBe(plain);
    expect(generateDashboardHTML(model, root, [], { measured: await check({}) })).toBe(plain);

    const hostile = { ...ANSWER, reach_routes: [{ ...ANSWER.reach_routes[0], actor: '<script>x</script>', effects: [{ ...ANSWER.reach_routes[0].effects[0], effect: '<img src=x onerror=y>' }] }, ANSWER.reach_routes[1]] };
    const escaped = generateDashboardHTML(model, root, [], { measured: await check({ [TOOL_REACH_CHECK]: { ok: true, value: hostile } }) });
    expect(escaped).not.toContain('<img src=x onerror=y>');
    expect(escaped).toContain('&lt;img src=x onerror=y&gt;');
  });
});

// ─── Through the CLI ─────────────────────────────────────────────────

const repoRoot = join(here, '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

function guardlink(cwd: string, env: NodeJS.ProcessEnv, ...args: string[]): Promise<{ status: number; stdout: string; stderr: string }> {
  return new Promise(resolvePromise => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, env, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolvePromise({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

/** A stand-in codegraph-mcp: MCP over stdio, canned answers, and only the tools it is given. */
function fakeMcp(answers: Record<string, unknown>): string {
  return `#!/usr/bin/env node
const answers = ${JSON.stringify(answers)};
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    const m = JSON.parse(line);
    if (m.id === undefined) continue;
    let out = {};
    if (m.method === 'tools/list') out = { tools: Object.keys(answers).map((name) => ({ name })) };
    else if (m.method === 'tools/call') out = { content: [{ type: 'text', text: JSON.stringify(answers[m.params.name]) }] };
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: out }) + '\\n');
  }
});
process.stdin.on('end', () => process.exit(0));
`;
}

const WORKLIST = { codegraph_attack_surface: { verdict: 'no_entry_points' }, codegraph_routes: { routes: [] } };

describe('through the CLI, against a stand-in code graph', () => {
  let withReach: NodeJS.ProcessEnv;
  let withoutReach: NodeJS.ProcessEnv;

  beforeAll(async () => {
    const a = join(root, 'fake-graph-with-reach');
    const b = join(root, 'fake-graph-without-reach');
    await writeFile(a, fakeMcp({ ...WORKLIST, [TOOL_REACH_CHECK]: ANSWER }));
    await writeFile(b, fakeMcp(WORKLIST));
    await chmod(a, 0o755);
    await chmod(b, 0o755);
    const base = { ...process.env };
    delete base.GUARDLINK_CODEGRAPH;
    withReach = { ...base, GUARDLINK_CODEGRAPH_MCP: a };
    withoutReach = { ...base, GUARDLINK_CODEGRAPH_MCP: b };
  });

  it('validate --code-graph adds the reach warnings and a summary line; warnings never fail it', async () => {
    const plain = await guardlink(root, withReach, 'validate', '.');
    expect(plain.stderr).not.toMatch(/Reach checks|gate-not-on-route|claim to check/);

    const checked = await guardlink(root, withReach, 'validate', '.', '--code-graph');
    expect(checked.stderr).toContain('Reach checks (code graph via codegraph-mcp): 2 declared reach(es) walked, 3 undeclared tool(s), 5 warning(s)');
    expect(checked.stderr).toContain('src/tools.ts:3: The annotations say the spend on #payments is gated by #support-human');
    expect(checked.stderr).toContain('src/tools.ts:14: The delete on #payments is declared');
    expect(checked.stderr).toContain('src/server.ts:12: The code graph finds `run-shell` registered here');
    expect(checked.status).toBe(plain.status);
  }, 60_000);

  it('with a graph that does not publish the query, or none, validate prints what it printed before', async () => {
    const older = await guardlink(root, withoutReach, 'validate', '.', '--code-graph');
    expect(older.stderr).not.toMatch(/Reach checks|gate-not-on-route|effect-unreached|agent-tool-undeclared/);
    const off = await guardlink(root, { ...process.env, GUARDLINK_CODEGRAPH: 'off' }, 'validate', '.', '--code-graph');
    expect(off.stderr).toContain('Boundary checks: code graph switched off');
    expect(off.stderr).not.toMatch(/Reach checks|gate-not-on-route/);
  }, 60_000);

  it('reach --drafts prints drafts and writes nothing', async () => {
    const before = await Promise.all(Object.keys(FILES).map(f => readFile(join(root, f), 'utf-8')));
    const r = await guardlink(root, withReach, 'reach', '.', '--drafts');
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('3 agent tool registration(s)');
    expect(r.stdout).toContain('@agents #support-agent to run-shell on <asset>');
    expect(r.stdout).toContain('@effects execute on <asset>');
    expect(r.stdout.split('\n').filter(l => /^\s*@(accepts|entitles)/.test(l))).toEqual([]);
    const after = await Promise.all(Object.keys(FILES).map(f => readFile(join(root, f), 'utf-8')));
    expect(after).toEqual(before);

    const json = await guardlink(root, withReach, 'reach', '.', '--drafts', '--json');
    expect(JSON.parse(json.stdout).drafts).toHaveLength(3);
  }, 60_000);

  it('reach prints the warnings, and fails naming the reason when the graph could not be read', async () => {
    const r = await guardlink(root, withReach, 'reach', '.');
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('claim to check, not a finding');
    expect(r.stderr).toContain('Reach checks (code graph via codegraph-mcp)');

    const none = await guardlink(root, withoutReach, 'reach', '.', '--drafts');
    expect(none.status).toBe(1);
    expect(none.stderr).toContain('No code-graph answer:');
    expect(none.stderr).toContain(TOOL_REACH_CHECK);
    expect(none.stdout).toBe('');
  }, 60_000);

  it('report and dashboard add the measured route only with --code-graph', async () => {
    const out = join(root, 'out');
    await mkdir(out, { recursive: true });
    const plain = await guardlink(root, withReach, 'report', '.', '-o', 'out/plain.md');
    expect(plain.status).toBe(0);
    expect(await readFile(join(root, 'out/plain.md'), 'utf-8')).not.toContain('Measured Route');

    const measured = await guardlink(root, withReach, 'report', '.', '--code-graph', '-o', 'out/measured.md');
    expect(measured.status).toBe(0);
    expect(measured.stderr).toContain('Measured route (code graph via codegraph-mcp): 2 declared reach(es) measured');
    expect(await readFile(join(root, 'out/measured.md'), 'utf-8')).toContain('### Measured Route (Code Graph)');

    const noReach = await guardlink(root, withoutReach, 'report', '.', '--code-graph', '-o', 'out/none.md');
    expect(noReach.stderr).toContain('Measured route: not added');
    expect(await readFile(join(root, 'out/none.md'), 'utf-8')).not.toContain('Measured Route');

    const dash = await guardlink(root, withReach, 'dashboard', '.', '--code-graph', '-o', 'out/dash.html');
    expect(dash.status).toBe(0);
    expect(await readFile(join(root, 'out/dash.html'), 'utf-8')).toContain('id="agent-measured"');
    const dashPlain = await guardlink(root, withReach, 'dashboard', '.', '-o', 'out/dash-plain.html');
    expect(dashPlain.status).toBe(0);
    expect(await readFile(join(root, 'out/dash-plain.html'), 'utf-8')).not.toContain('agent-measured');
  }, 120_000);
});
