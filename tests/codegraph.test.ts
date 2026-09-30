/**
 * The optional code graph: detection, the ranked worklist, per-function reach,
 * the honesty gate, and — the contract everything else rests on — that with no
 * graph the annotate prompt is byte-identical to the one built without this
 * feature.
 *
 * Every case pins its transport (a stub object, or a stand-in executable on a
 * private PATH), so nothing here depends on graph tooling installed on the
 * machine running it. vitest.config.ts turns discovery off for the rest of the
 * suite for the same reason.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  loadWorklist, reachFor, renderWorklistBlock, worklistUsable, worklistSummaryLine,
  discoverTransport, mcpTransport, bravosTransport, graphSwitchedOff,
  GraphUnsupported, GraphToolingMissing, PROMPT_WORKLIST_ROWS,
  type CodeGraphTransport, type ToolAnswer, type ToolCall, type Worklist,
} from '../src/codegraph/index.js';
import { buildAnnotatePrompt } from '../src/agents/prompts.js';
import { getPlaybook } from '../src/playbooks/index.js';
import type { ThreatModel } from '../src/types/index.js';

// ─── Canned graph answers, in the shape codegraph-mcp publishes ──────

function sinkClass(cls: string, sinks: number, weighted: number, callee: string, file: string, line: number) {
  return {
    class: cls, sinks, weighted, min_depth: 1, label: cls, weight: 1,
    example: {
      path: [{ symbol: `${file}::handler` }, { symbol: `${file}::${callee}` }],
      sink: { callee, class: cls, file, line },
    },
  };
}

function row(rank: number, file: string, name: string, line: number, routes: string[], score: number, classes: any[] = []) {
  return { rank, score, routes, classes, entry: { id: `${file}::${name}`, file, name, line, kind: 'function' } };
}

const SURFACE = {
  verdict: 'sinks_reached',
  message: '3 of 4 entry points reach a classified sink',
  entry_points: { default_rule: 'route handlers from the routes table' },
  confidence: { shortfalls: [], sufficient: true },
  graph_currency: { state: 'current' },
  rows: [
    row(1, 'api/users.py', 'delete_user', 40, ['DELETE /users/{name}'], 9,
      [sinkClass('data_layer', 4, 4, 'User.query.delete', 'models/user.py', 12), sinkClass('network', 1, 5, 'requests.get', 'api/users.py', 50)]),
    row(2, 'api/books.py', 'add_book', 10, ['POST /books'], 4, [sinkClass('data_layer', 4, 4, 'db.session.add', 'api/books.py', 20)]),
    row(3, 'api/admin.py', 'run_job', 5, ['POST /admin/run'], 2, [sinkClass('exec', 1, 2, 'subprocess.run', 'api/admin.py', 9)]),
    row(4, 'api/main.py', 'index', 3, ['GET /'], 0),
  ],
};

const ROUTES = {
  routes_total: 5,
  handlers_unbound: 1,
  dynamic_paths: 0,
  graph_currency: { state: 'current' },
  routes: [
    { methods: ['GET'], path: '/', resolution: 'bound', registered_at: 'spec.yml:1' },
    { methods: ['POST'], path: '/legacy', resolution: 'no_node', registered_at: 'app.py:77' },
  ],
};

/** A transport that answers from a table and records what it was asked. */
function stub(answers: Record<string, ToolAnswer>, via = 'stub'): CodeGraphTransport & { asked: ToolCall[][] } {
  const asked: ToolCall[][] = [];
  return {
    via, asked,
    async query(_root, calls) {
      asked.push(calls);
      return calls.map(c => answers[c.tool] ?? { ok: false, message: `${c.tool} not stubbed` });
    },
  };
}

const HAPPY = { codegraph_attack_surface: { ok: true, value: SURFACE }, codegraph_routes: { ok: true, value: ROUTES } } as const;

/** A model carrying only what the worklist reads: located, anchored annotation rows. */
function modelWith(rows: Array<{ file: string; scope: 'symbol' | 'file'; start: number; end: number; symbol?: string }>): ThreatModel {
  return {
    exposures: rows.map(r => ({
      location: { file: r.file, line: r.start - 1, anchor: { scope: r.scope, symbol: r.symbol ?? null, start_line: r.start, end_line: r.end, hash: 'x' } },
    })),
  } as unknown as ThreatModel;
}

const ON = { env: {} as NodeJS.ProcessEnv };

// ─── The worklist ────────────────────────────────────────────────────

describe('loadWorklist — ranking', () => {
  it('ranks unannotated handlers first, heaviest reach first within each state', async () => {
    // add_book's handler is annotated; delete_user's file is annotated elsewhere; run_job's file is not.
    const model = modelWith([
      { file: 'api/books.py', scope: 'symbol', start: 10, end: 30, symbol: 'add_book' },
      { file: 'api/users.py', scope: 'symbol', start: 100, end: 120, symbol: 'other' },
    ]);
    const w = await loadWorklist('/repo', model, { ...ON, transport: stub(HAPPY) });
    expect(w.status).toBe('available');
    expect(worklistUsable(w)).toBe(true);
    expect(w.entries.map(e => [e.name, e.annotated, e.position])).toEqual([
      ['run_job', 'none', 1],
      ['index', 'none', 2],
      ['delete_user', 'file', 3],
      ['add_book', 'handler', 4],
    ]);
    // Heaviest sink class first, with an example a reader can open.
    expect(w.entries[2].reaches[0]).toMatchObject({ class: 'network', example: 'requests.get at api/users.py:50' });
    expect(w.routes_unbound).toBe(1);
    expect(w.unbound_examples[0]).toContain('POST /legacy registered at app.py:77');
  });

  it('with no model every handler reads as unannotated, in graph order', async () => {
    const w = await loadWorklist('/repo', null, { ...ON, transport: stub(HAPPY) });
    expect(w.entries.map(e => e.name)).toEqual(['delete_user', 'add_book', 'run_job', 'index']);
    expect(w.entries.every(e => e.annotated === 'none')).toBe(true);
  });

  it('asks for the attack surface and the routes in one query, at the graph caps', async () => {
    const t = stub(HAPPY);
    await loadWorklist('/repo', null, { ...ON, transport: t });
    expect(t.asked).toHaveLength(1);
    expect(t.asked[0].map(c => c.tool)).toEqual(['codegraph_attack_surface', 'codegraph_routes']);
  });

  it('carries a currency caveat when the graph was indexed from another tree', async () => {
    const stale = { ...SURFACE, graph_currency: { state: 'diverged', caveat: 'working tree moved in 1 file(s)' } };
    const w = await loadWorklist('/repo', null, { ...ON, transport: stub({ ...HAPPY, codegraph_attack_surface: { ok: true, value: stale } }) });
    expect(w.currency_caveat).toContain('diverged');
    expect(renderWorklistBlock(w)).toContain('Caveat: the graph is diverged');
  });
});

describe('loadWorklist — every no-graph outcome is a status, never a throw', () => {
  const cases: Array<[string, Partial<Parameters<typeof loadWorklist>[2]>, string]> = [
    ['off by the caller', { enabled: false, transport: stub(HAPPY) }, 'off'],
    ['off by the environment', { env: { GUARDLINK_CODEGRAPH: 'off' }, transport: stub(HAPPY) }, 'off'],
    ['no tooling', { transport: null }, 'unavailable'],
    ['tooling too old', { transport: { via: 'x', query: async () => { throw new GraphUnsupported('codegraph_attack_surface'); } } }, 'unsupported'],
    ['binary will not start', { transport: { via: 'x', query: async () => { throw new GraphToolingMissing('x: not found'); } } }, 'unavailable'],
    ['query failed', { transport: { via: 'x', query: async () => { throw new Error('boom'); } } }, 'error'],
    ['no graph built', { transport: stub({ codegraph_attack_surface: { ok: false, message: 'No CodeGraph for project abc. Index the repository first.' }, codegraph_routes: { ok: false, message: 'No CodeGraph for project abc.' } }) }, 'no_graph'],
    ['unreadable answer', { transport: stub({ codegraph_attack_surface: { ok: true, value: { verdict: 'sinks_reached', rows: 'not-a-list' } }, codegraph_routes: { ok: true, value: {} } }) }, 'error'],
  ];

  for (const [label, opts, status] of cases) {
    it(`${label} → ${status}, no entries, nothing rendered`, async () => {
      const w = await loadWorklist('/repo', null, { env: {}, ...opts });
      expect(w.status).toBe(status);
      expect(w.entries).toEqual([]);
      expect(renderWorklistBlock(w)).toBe('');
      if (status !== 'off') expect(w.note).not.toBe('');
    });
  }

  it('the off switch never reaches the transport', async () => {
    const t = stub(HAPPY);
    await loadWorklist('/repo', null, { enabled: false, transport: t, env: {} });
    await loadWorklist('/repo', null, { transport: t, env: { GUARDLINK_CODEGRAPH: 'false' } });
    expect(t.asked).toEqual([]);
  });

  it('reads the environment switch spellings', () => {
    for (const v of ['off', 'OFF', '0', 'false', 'no', 'disabled']) expect(graphSwitchedOff({ GUARDLINK_CODEGRAPH: v })).toBe(true);
    for (const v of ['', 'on', '1', 'auto']) expect(graphSwitchedOff({ GUARDLINK_CODEGRAPH: v })).toBe(false);
  });
});

describe('the honesty gate — a thin graph withholds the worklist and says why', () => {
  const thin = {
    verdict: 'insufficient_resolution', rows: [],
    message: 'The graph could not resolve enough of this project\'s calls to rank reachable sinks',
    confidence: { shortfalls: ['16 resolved call edges over 268 functions is 0.06 per function, below the 0.5 this ranking needs'], sufficient: false },
  };

  it('insufficient_resolution: no entries, the graph\'s own reason carried', async () => {
    const w = await loadWorklist('/repo', null, { ...ON, transport: stub({ ...HAPPY, codegraph_attack_surface: { ok: true, value: thin } }) });
    expect(w.status).toBe('available');
    expect(worklistUsable(w)).toBe(false);
    expect(w.entries).toEqual([]);
    expect(w.withheld_reason).toContain('insufficient call resolution');
    expect(w.withheld_reason).toContain('0.06 per function');
    const block = renderWorklistBlock(w);
    expect(block).toContain('ranking is withheld');
    expect(block).toContain('0.06 per function');
    expect(block).toContain('do not read the absence of a list as a small attack surface');
    expect(block).not.toMatch(/^\s*\d+\. \[/m);
    expect(worklistSummaryLine(w)).toContain('worklist withheld');
  });

  it('even rows the graph sent anyway are not used under a withheld verdict', async () => {
    const w = await loadWorklist('/repo', null, { ...ON, transport: stub({ ...HAPPY, codegraph_attack_surface: { ok: true, value: { ...thin, rows: SURFACE.rows } } }) });
    expect(w.entries).toEqual([]);
  });

  for (const verdict of ['no_entry_points', 'no_sinks_reached']) {
    it(`${verdict} withholds too`, async () => {
      const w = await loadWorklist('/repo', null, { ...ON, transport: stub({ ...HAPPY, codegraph_attack_surface: { ok: true, value: { verdict, rows: SURFACE.rows } } }) });
      expect(worklistUsable(w)).toBe(false);
      expect(w.withheld_reason).not.toBe('');
      expect(renderWorklistBlock(w)).toContain('withheld');
    });
  }
});

// ─── The annotate prompt ─────────────────────────────────────────────

describe('buildAnnotatePrompt — unchanged without a graph', () => {
  const root = '/nonexistent-guardlink-root';

  it('is byte-identical for every no-graph status, in every playbook', async () => {
    const statuses: Worklist[] = await Promise.all([
      loadWorklist(root, null, { enabled: false }),
      loadWorklist(root, null, { env: {}, transport: null }),
      loadWorklist(root, null, { env: {}, transport: { via: 'x', query: async () => { throw new GraphUnsupported('t'); } } }),
      loadWorklist(root, null, { env: {}, transport: { via: 'x', query: async () => { throw new Error('boom'); } } }),
      loadWorklist(root, null, { env: {}, transport: stub({ codegraph_attack_surface: { ok: false, message: 'No CodeGraph' }, codegraph_routes: { ok: false, message: 'No CodeGraph' } }) }),
    ]);
    for (const playbook of ['map', 'exploitable', 'chains', 'diff', 'coverage', 'verify']) {
      const without = buildAnnotatePrompt('annotate the api', root, null, 'inline', playbook);
      expect(buildAnnotatePrompt('annotate the api', root, null, 'inline', playbook, null)).toBe(without);
      for (const w of statuses) {
        expect(buildAnnotatePrompt('annotate the api', root, null, 'inline', playbook, w), `${playbook}/${w.status}`).toBe(without);
      }
    }
  });
});

describe('buildAnnotatePrompt — with a graph', () => {
  const root = '/nonexistent-guardlink-root';

  it('places the worklist between the scope and the method', async () => {
    const w = await loadWorklist(root, null, { ...ON, transport: stub(HAPPY, 'codegraph-mcp') });
    const p = buildAnnotatePrompt('bring the api into the model', root, null, 'inline', 'coverage', w);
    const scope = p.indexOf('## Scope and intent');
    const block = p.indexOf('## Code-graph worklist');
    const method = p.indexOf('## Method — Coverage');
    expect(scope).toBeGreaterThan(-1);
    expect(block).toBeGreaterThan(scope);
    expect(method).toBeGreaterThan(block);
    expect(p).toContain('(via codegraph-mcp)');
    expect(p).toContain(' 1. [none] DELETE /users/{name} → api/users.py:40 delete_user — reach 9: network 1 (e.g. requests.get at api/users.py:50); data_layer 4');
    expect(p).toContain('1 route registration(s) could not be bound');
    expect(p).toContain('guardlink_reach(symbol)');
  });

  it('the coverage playbook takes the worklist as its "entry points first" order', async () => {
    const w = await loadWorklist(root, null, { ...ON, transport: stub(HAPPY) });
    const coverage = buildAnnotatePrompt('x', root, null, 'inline', 'coverage', w);
    expect(getPlaybook('coverage').worklistUse).toBeTruthy();
    expect(coverage).toContain(getPlaybook('coverage').worklistUse!);
    expect(coverage).toContain('"entry points first" order');
    // Other playbooks get the neutral instruction, which widens nothing.
    const exploitable = buildAnnotatePrompt('x', root, null, 'inline', 'exploitable', w);
    expect(exploitable).not.toContain('"entry points first" order');
    expect(exploitable).toContain('it adds no file to the scope and lowers no bar');
  });

  it('is bounded: the prompt carries the first rows and says how many more exist', async () => {
    const many = { ...SURFACE, rows: Array.from({ length: 40 }, (_, i) => row(i + 1, `api/h${i}.py`, `h${i}`, 1, [`GET /h${i}`], 40 - i, [sinkClass('data_layer', 1, 1, 'q', `api/h${i}.py`, 2)])) };
    const w = await loadWorklist(root, null, { ...ON, transport: stub({ ...HAPPY, codegraph_attack_surface: { ok: true, value: many } }) });
    expect(w.entries).toHaveLength(40);
    const block = renderWorklistBlock(w);
    expect(block.match(/^\s*\d+\. \[/gm)).toHaveLength(PROMPT_WORKLIST_ROWS);
    expect(block).toContain(`${40 - PROMPT_WORKLIST_ROWS} more ranked entry point(s) not shown`);
  });
});

// ─── One function's reach ────────────────────────────────────────────

describe('reachFor', () => {
  const SINKS = {
    verdict: 'sinks_reached', message: 'delete_user reaches 4 data_layer',
    reach: { classes: [sinkClass('data_layer', 4, 4, 'User.query.delete', 'models/user.py', 12)] },
  };
  const ENTRY = {
    reach: {
      liveness: 'live_via_route',
      entries: [{ node_id: 'api/users.py::delete_user', kind: 'route', depth: 0, path: ['api/users.py::delete_user'], routes: [{ methods: ['DELETE'], path: '/users/{name}' }] }],
    },
    entry_points: { coverage_note: 'CLI dispatch is not recognised' },
  };

  it('returns sink classes with their paths and the entry points that reach the symbol', async () => {
    const t = stub({ codegraph_reachable_sinks: { ok: true, value: SINKS }, codegraph_entry_reach: { ok: true, value: ENTRY } });
    const r = await reachFor('/repo', 'api/users.py::delete_user', { ...ON, transport: t });
    expect(t.asked[0]).toEqual([
      { tool: 'codegraph_reachable_sinks', args: { symbol: 'api/users.py::delete_user' } },
      { tool: 'codegraph_entry_reach', args: { symbol: 'api/users.py::delete_user' } },
    ]);
    expect(r.status).toBe('available');
    expect(r.reaches[0]).toMatchObject({ class: 'data_layer', sinks: 4, example: 'User.query.delete at models/user.py:12' });
    expect(r.reaches[0].path.length).toBeGreaterThan(0);
    expect(r.liveness).toBe('live_via_route');
    expect(r.entries[0]).toMatchObject({ entry: 'api/users.py::delete_user', routes: ['DELETE /users/{name}'] });
  });

  it('carries the graph\'s refusal and candidates for an ambiguous name', async () => {
    const refusal: ToolAnswer = { ok: false, message: 'Symbol is ambiguous: handler', data: { candidates: [{ id: 'a.py::handler' }, { id: 'b.py::handler' }] } };
    const r = await reachFor('/repo', 'handler', { ...ON, transport: stub({ codegraph_reachable_sinks: refusal, codegraph_entry_reach: refusal }) });
    expect(r.status).toBe('available');
    expect(r.refused).toContain('ambiguous');
    expect(r.candidates).toEqual(['a.py::handler', 'b.py::handler']);
    expect(r.reaches).toEqual([]);
  });

  it('withholds sinks under insufficient resolution and never calls unknown liveness dead', async () => {
    const t = stub({
      codegraph_reachable_sinks: { ok: true, value: { verdict: 'insufficient_resolution', confidence: { shortfalls: ['0.06 per function'] }, reach: { classes: [sinkClass('exec', 1, 5, 'eval', 'a.js', 1)] } } },
      codegraph_entry_reach: { ok: true, value: { reach: { liveness: 'unknown', unknown_reason: 'insufficient_resolution', entries: [] } } },
    });
    const r = await reachFor('/repo', 'a.js::f', { ...ON, transport: t });
    expect(r.reaches).toEqual([]);
    expect(r.sinks_withheld_reason).toContain('not a clean answer');
    expect(r.liveness).toBe('unknown');
    expect(r.liveness_note).toBe('insufficient_resolution');
  });

  it('no tooling is a status', async () => {
    const r = await reachFor('/repo', 'x', { env: {}, transport: null });
    expect(r.status).toBe('unavailable');
  });
});

// ─── Transports, against stand-in executables ────────────────────────

/** A stand-in codegraph-mcp: MCP over stdio, canned answers, optional tool set. */
function fakeMcpScript(tools: string[], answers: Record<string, unknown>, opts: { silent?: boolean } = {}) {
  return `#!/usr/bin/env node
const tools = ${JSON.stringify(tools)};
const answers = ${JSON.stringify(answers)};
const silent = ${JSON.stringify(!!opts.silent)};
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim() || silent) continue;
    const m = JSON.parse(line);
    if (m.id === undefined) continue;
    let out;
    if (m.method === 'initialize') out = { protocolVersion: '2024-11-05', capabilities: { tools: {} } };
    else if (m.method === 'tools/list') out = { tools: tools.map((name) => ({ name })) };
    else if (m.method === 'tools/call') {
      const a = answers[m.params.name];
      if (a && a.error) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: a.error }) + '\\n'); continue; }
      out = { content: [{ type: 'text', text: JSON.stringify(a) }] };
    }
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: out }) + '\\n');
  }
});
process.stdin.on('end', () => process.exit(0));
`;
}

/** A stand-in bravos: \`bravos graph --repo R <verb> --json [--k v]\`, canned answers. */
function fakeBravosScript(answers: Record<string, unknown>, known: string[]) {
  return `#!/usr/bin/env node
const answers = ${JSON.stringify(answers)};
const known = ${JSON.stringify(known)};
const argv = process.argv.slice(2);
const verb = argv[3];
if (!known.includes(verb)) {
  process.stderr.write("bravos: the code graph has no question called '" + verb + "'\\n");
  process.exit(4);
}
process.stdout.write(JSON.stringify({ tool: verb, arguments: {}, result: answers[verb], argv }) + '\\n');
`;
}

describe('transports and discovery', () => {
  let dir: string;
  const write = async (path: string, text: string) => { await writeFile(path, text); await chmod(path, 0o755); };

  beforeAll(async () => { dir = await mkdtemp(join(tmpdir(), 'guardlink-codegraph-')); });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  it('speaks MCP stdio to codegraph-mcp and reads both answers from one process', async () => {
    const bin = join(dir, 'mcp-ok');
    await write(bin, fakeMcpScript(['codegraph_attack_surface', 'codegraph_routes'], { codegraph_attack_surface: SURFACE, codegraph_routes: ROUTES }));
    const w = await loadWorklist(dir, null, { env: {}, transport: mcpTransport(bin, 10_000) });
    expect(w.status).toBe('available');
    expect(w.via).toBe('codegraph-mcp');
    expect(w.entries).toHaveLength(4);
  });

  it('a server that does not publish the queries is unsupported', async () => {
    const bin = join(dir, 'mcp-old');
    await write(bin, fakeMcpScript(['codegraph_callers'], {}));
    const w = await loadWorklist(dir, null, { env: {}, transport: mcpTransport(bin, 10_000) });
    expect(w.status).toBe('unsupported');
    expect(w.note).toContain('codegraph_attack_surface');
  });

  it('a repository with no graph built is no_graph', async () => {
    const bin = join(dir, 'mcp-nograph');
    const err = { error: { code: -32600, message: 'No CodeGraph for project abc. Index the repository in Bravos first.' } };
    await write(bin, fakeMcpScript(['codegraph_attack_surface', 'codegraph_routes'], { codegraph_attack_surface: err, codegraph_routes: err }));
    const w = await loadWorklist(dir, null, { env: {}, transport: mcpTransport(bin, 10_000) });
    expect(w.status).toBe('no_graph');
  });

  it('a wedged server costs the timeout, not the run', async () => {
    const bin = join(dir, 'mcp-wedged');
    await write(bin, fakeMcpScript([], {}, { silent: true }));
    const started = Date.now();
    const w = await loadWorklist(dir, null, { env: {}, transport: mcpTransport(bin, 800) });
    expect(w.status).toBe('error');
    expect(w.note).toContain('no answer within');
    expect(Date.now() - started).toBeLessThan(8000);
  });

  it('a binary that is not there is unavailable', async () => {
    const w = await loadWorklist(dir, null, { env: {}, transport: mcpTransport(join(dir, 'does-not-exist'), 5000) });
    expect(w.status).toBe('unavailable');
  });

  it('speaks `bravos graph <verb> --json`, one process per query', async () => {
    const bin = join(dir, 'bravos-ok');
    await write(bin, fakeBravosScript({ 'attack-surface': SURFACE, routes: ROUTES, 'reachable-sinks': { verdict: 'sinks_reached', reach: { classes: [] } }, 'entry-reach': { reach: { liveness: 'not_reached', entries: [] } } }, ['attack-surface', 'routes', 'reachable-sinks', 'entry-reach']));
    const w = await loadWorklist(dir, null, { env: {}, transport: bravosTransport(bin, 10_000) });
    expect(w.status).toBe('available');
    expect(w.via).toBe('bravos graph');
    expect(w.entries).toHaveLength(4);
    const r = await reachFor(dir, 'a.py::f', { env: {}, transport: bravosTransport(bin, 10_000) });
    expect(r.liveness).toBe('not_reached');
  });

  it('a bravos whose graph predates the queries is unsupported', async () => {
    const bin = join(dir, 'bravos-old');
    await write(bin, fakeBravosScript({}, ['callers']));
    const w = await loadWorklist(dir, null, { env: {}, transport: bravosTransport(bin, 10_000) });
    expect(w.status).toBe('unsupported');
  });

  it('discovery: explicit override, then codegraph-mcp on PATH, then bravos on PATH, else none', async () => {
    const onlyBravos = join(dir, 'path-bravos');
    const both = join(dir, 'path-both');
    await mkdir(onlyBravos, { recursive: true });
    await mkdir(both, { recursive: true });
    await write(join(onlyBravos, 'bravos'), '#!/bin/sh\n');
    await write(join(both, 'bravos'), '#!/bin/sh\n');
    await write(join(both, 'codegraph-mcp'), '#!/bin/sh\n');

    expect(discoverTransport({ PATH: join(dir, 'empty-nowhere') })).toBeNull();
    expect(discoverTransport({ PATH: onlyBravos })?.via).toBe('bravos graph');
    expect(discoverTransport({ PATH: [onlyBravos, both].join(delimiter) })?.via).toBe('codegraph-mcp');
    expect(discoverTransport({ PATH: onlyBravos, GUARDLINK_CODEGRAPH_MCP: '/opt/cg/codegraph-mcp' })?.via).toBe('codegraph-mcp');
  });
});

// ─── A real graph, when one is installed ─────────────────────────────

/**
 * Indexes a tiny Flask service with the real codegraph-build and reads it back
 * through the real codegraph-mcp. Skipped unless both are on PATH — which
 * includes CI, where nothing graph-related is installed.
 */
function which(name: string): string | null {
  for (const d of (process.env.PATH || '').split(delimiter)) {
    if (d && existsSync(join(d, name))) return join(d, name);
  }
  return null;
}
const LIVE_MCP = which('codegraph-mcp');
const LIVE_BUILD = which('codegraph-build');

describe.skipIf(!LIVE_MCP || !LIVE_BUILD)('live: a real code graph', () => {
  let repo: string;
  beforeAll(async () => {
    repo = await mkdtemp(join(tmpdir(), 'guardlink-live-graph-'));
    await writeFile(join(repo, 'app.py'), [
      'import subprocess',
      'from flask import Flask, request',
      'app = Flask(__name__)',
      '',
      'def run(cmd):',
      '    return subprocess.run(cmd, shell=True)',
      '',
      '@app.route("/run", methods=["POST"])',
      'def run_job():',
      '    return run(request.form["cmd"])',
      '',
      '@app.route("/", methods=["GET"])',
      'def index():',
      '    return "ok"',
      '',
    ].join('\n'));
    execFileSync('git', ['init', '-q'], { cwd: repo });
    execFileSync(LIVE_BUILD!, ['--project-path', repo, '--json'], { stdio: 'ignore' });
  });
  afterAll(async () => { await rm(repo, { recursive: true, force: true }); });

  it('ranks the handler that reaches exec, or withholds with a reason', async () => {
    const w = await loadWorklist(repo, null, { env: {}, transport: mcpTransport(LIVE_MCP!) });
    expect(w.status).toBe('available');
    if (worklistUsable(w)) {
      expect(w.entries[0].name).toBe('run_job');
      expect(w.entries[0].reaches.map(r => r.class)).toContain('exec');
    } else {
      expect(w.withheld_reason).not.toBe('');
    }
    const r = await reachFor(repo, 'app.py::run', { env: {}, transport: mcpTransport(LIVE_MCP!) });
    expect(r.status).toBe('available');
    expect(r.refused).toBe('');
  });
});

// ─── Over MCP, the way an agent in its own editor asks ───────────────

describe('MCP: guardlink_worklist, guardlink_reach, guardlink_annotate', () => {
  let dir: string;
  let session: { client: any; close: () => Promise<void> };
  const saved = { switch: process.env.GUARDLINK_CODEGRAPH, bin: process.env.GUARDLINK_CODEGRAPH_MCP };

  beforeAll(async () => {
    const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
    const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');
    const { createServer } = await import('../src/mcp/server.js');
    dir = await mkdtemp(join(tmpdir(), 'guardlink-codegraph-mcp-'));
    await mkdir(join(dir, 'api'), { recursive: true });
    await writeFile(join(dir, 'api', 'books.py'), '# @comment -- "books handlers"\ndef add_book():\n    pass\n');
    const bin = join(dir, 'fake-codegraph-mcp');
    await writeFile(bin, fakeMcpScript(
      ['codegraph_attack_surface', 'codegraph_routes', 'codegraph_reachable_sinks', 'codegraph_entry_reach'],
      {
        codegraph_attack_surface: SURFACE, codegraph_routes: ROUTES,
        codegraph_reachable_sinks: { verdict: 'sinks_reached', reach: { classes: [sinkClass('exec', 1, 5, 'subprocess.run', 'api/admin.py', 9)] } },
        codegraph_entry_reach: { reach: { liveness: 'live_via_route', entries: [] } },
      }));
    await chmod(bin, 0o755);
    process.env.GUARDLINK_CODEGRAPH_MCP = bin;
    const server = createServer();
    const client = new Client({ name: 'test', version: '0.0.0' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(b), client.connect(a)]);
    session = { client, close: () => client.close() };
  });
  afterAll(async () => {
    await session.close();
    if (saved.switch === undefined) delete process.env.GUARDLINK_CODEGRAPH; else process.env.GUARDLINK_CODEGRAPH = saved.switch;
    if (saved.bin === undefined) delete process.env.GUARDLINK_CODEGRAPH_MCP; else process.env.GUARDLINK_CODEGRAPH_MCP = saved.bin;
    await rm(dir, { recursive: true, force: true });
  });

  const call = async (name: string, args: Record<string, unknown>) =>
    JSON.parse((await session.client.callTool({ name, arguments: { root: dir, ...args } })).content[0].text);

  it('switched off: a status, no entries, and the annotate prompt carries no worklist', async () => {
    process.env.GUARDLINK_CODEGRAPH = 'off';
    const w = await call('guardlink_worklist', {});
    expect(w.code_graph.status).toBe('off');
    expect(w.entries).toEqual([]);
    expect((await call('guardlink_reach', { symbol: 'x' })).status).toBe('off');
    const a = await call('guardlink_annotate', { prompt: 'annotate the api', playbook: 'coverage' });
    expect(a.prompt).not.toContain('## Code-graph worklist');
    const { parseProject } = await import('../src/parser/index.js');
    const { model } = await parseProject({ root: dir, project: 'unknown' });
    expect(a.prompt).toBe(buildAnnotatePrompt('annotate the api', dir, model, 'inline', 'coverage'));
  });

  it('with a graph: the same ranked targets the annotate prompt carries, filterable by file', async () => {
    delete process.env.GUARDLINK_CODEGRAPH;
    const w = await call('guardlink_worklist', {});
    expect(w.code_graph.status).toBe('available');
    expect(w.total).toBe(4);
    // api/books.py is annotated at file level only, so add_book reads as [file], after the [none] handlers.
    expect(w.entries.map((e: any) => [e.name, e.annotated])).toEqual([
      ['delete_user', 'none'], ['run_job', 'none'], ['index', 'none'], ['add_book', 'file'],
    ]);
    const only = await call('guardlink_worklist', { file: 'books' });
    expect(only.entries.map((e: any) => e.name)).toEqual(['add_book']);

    const r = await call('guardlink_reach', { symbol: 'api/admin.py::run_job' });
    expect(r.reaches[0]).toMatchObject({ class: 'exec', example: 'subprocess.run at api/admin.py:9' });
    expect(r.liveness).toBe('live_via_route');

    const a = await call('guardlink_annotate', { prompt: 'annotate the api', playbook: 'coverage' });
    expect(a.prompt).toContain('## Code-graph worklist');
    expect(a.prompt).toContain(' 1. [none] DELETE /users/{name}');
    expect(a.code_graph).toContain('4 entry point(s) ranked');
    const off = await call('guardlink_annotate', { prompt: 'annotate the api', playbook: 'coverage', code_graph: false });
    expect(off.prompt).not.toContain('## Code-graph worklist');
  });
});
