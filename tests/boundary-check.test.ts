/**
 * Declared boundaries checked against a code graph: stated versus measured
 * access, a route handler with no boundary to the outside, and a boundary
 * nothing crosses. Every check is a warning, and with no usable graph there
 * is nothing at all.
 *
 * The model is parsed from a fixture repository; the graph is a stub transport,
 * and for the CLI a stand-in codegraph-mcp, so nothing depends on graph tooling
 * installed on the machine running it.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, chmod } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { loadWorklist, type CodeGraphTransport, type ToolAnswer, type Worklist } from '../src/codegraph/index.js';
import { checkBoundaries, statedAccess, boundaryCheckSummaryLine } from '../src/codegraph/boundary-check.js';
import type { ThreatModel } from '../src/types/index.js';

// ─── The fixture: a model and the graph that measures it ─────────────

const FILES: Record<string, string> = {
  '.guardlink/definitions.ts': [
    '// @asset App.Api (#api) -- "the HTTP api"',
    '// @asset App.Jobs (#jobs) -- "background jobs, triggered over HTTP"',
    '// @asset App.Db (#db) -- "the database"',
    '// @asset External.Payments (#payments) -- "the payment vendor"',
    '// @threat SQL_Injection (#sqli) [high] -- "t"',
    'export {};',
  ].join('\n'),
  'api/users.py': [
    '# @exposes #api to #sqli [high] -- "name concatenated into a query"',
    '# @boundary between Client and #api (#http-boundary) -- "Everything past this point has been authenticated"',
    '# @flows Client -> #api via HTTP -- "requests"',
    '# @flows #api -> #db via orm -- "queries"',
    '# @boundary between #api and #db (#data-boundary) -- "application to persistence"',
    'def delete_user(): pass',
  ].join('\n'),
  'api/export.py': '# @handles internal on #api -- "exports"\ndef export(): pass\n',
  'api/main.py': '# @handles public on #api -- "index"\ndef index(): pass\n',
  'jobs/run.py': '# @handles internal on #jobs -- "job runner"\ndef run_job(): pass\n',
  'lib/plain.py': 'def helper(): pass\n',
  'lib/billing.py': '# @boundary between #db and #payments (#vendor-boundary) -- "card data leaves through the vendor SDK"\n',
};

function sinkClass(cls: string, callee: string, file: string, line: number) {
  return { class: cls, sinks: 1, weighted: 1, min_depth: 1, example: { path: [], sink: { callee, class: cls, file, line } } };
}
function row(rank: number, file: string, name: string, routes: string[], classes: any[] = []) {
  return { rank, score: classes.length, routes, classes, entry: { id: `${file}::${name}`, file, name, line: 2, kind: 'function' } };
}

const SURFACE = {
  verdict: 'sinks_reached', message: 'm', entry_points: { default_rule: 'routes' }, graph_currency: { state: 'current' },
  rows: [
    row(1, 'api/users.py', 'delete_user', ['DELETE /users/{name}'], [sinkClass('data_layer', 'User.query.delete', 'models/user.py', 12)]),
    row(2, 'api/export.py', 'export', ['GET /export'], [sinkClass('data_layer', 'db.query', 'api/export.py', 5)]),
    row(3, 'api/main.py', 'index', ['GET /']),
    row(4, 'jobs/run.py', 'run_job', ['POST /jobs/run'], [sinkClass('exec', 'subprocess.run', 'jobs/run.py', 9)]),
    row(5, 'lib/plain.py', 'helper', ['GET /h'], [sinkClass('network', 'requests.get', 'lib/plain.py', 3)]),
  ],
};
const ROUTES = { routes_total: 5, handlers_unbound: 0, dynamic_paths: 0, routes: [] };

function access(level: string, extra: Record<string, unknown> = {}) {
  return { level, summary: `${level}`, ...extra };
}
const AUTH = {
  verdict: 'classified', verdict_note: 'every route was classified',
  resolver_density: { sufficient: true, edges_per_callable: 3, shortfalls: [] },
  routes: [
    { methods: ['DELETE'], path: '/users/{name}', handler: 'api/users.py::delete_user', access: access('elevated', { basis: 'declared', evidence: [{ text: '@admin_required', at: 'api/users.py:1' }] }) },
    { methods: ['GET'], path: '/export', handler: 'api/export.py::export', access: access('public', { basis: 'absence' }) },
    { methods: ['GET'], path: '/', handler: 'api/main.py::index', access: access('unknown', { unknown_reason: 'ambiguous_handler_check' }) },
    { methods: ['POST'], path: '/jobs/run', handler: 'jobs/run.py::run_job', access: access('authenticated', { basis: 'declared' }) },
    { methods: ['GET'], path: '/h', handler: 'lib/plain.py::helper', access: access('public', { basis: 'absence' }) },
  ],
};

function stub(answers: Record<string, ToolAnswer>): CodeGraphTransport {
  return { via: 'stub', async query(_root, calls) { return calls.map(c => answers[c.tool] ?? { ok: false, message: 'not stubbed' }); } };
}
const GRAPH = {
  codegraph_attack_surface: { ok: true, value: SURFACE },
  codegraph_routes: { ok: true, value: ROUTES },
  codegraph_auth_boundary: { ok: true, value: AUTH },
} as const;

let root: string;
let model: ThreatModel;
const worklist = (answers: Record<string, ToolAnswer> = GRAPH as any): Promise<Worklist> =>
  loadWorklist(root, model, { env: {}, transport: stub(answers) });

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-boundary-check-'));
  for (const [path, text] of Object.entries(FILES)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
  model = (await parseProject({ root, project: 'boundary-check' })).model;
});
afterAll(async () => { await rm(root, { recursive: true, force: true }); });

// ─── Checks ──────────────────────────────────────────────────────────

describe('statedAccess', () => {
  it('reads the level a description states, and quotes the word', () => {
    expect(statedAccess('Everything past this point has been authenticated')).toEqual({ level: 'authenticated', word: 'authenticated' });
    expect(statedAccess('Admin console; RequirePermission gates every route')).toEqual({ level: 'elevated', word: 'Admin' });
    expect(statedAccess('API key checked by middleware')).toEqual({ level: 'authenticated', word: 'API key' });
  });

  it('states nothing for prose about transport, or for a line that says it is open', () => {
    expect(statedAccess('TLS termination, rate limiting at edge')).toBeNull();
    expect(statedAccess('Process boundary: JSON parsed defensively')).toBeNull();
    expect(statedAccess('Unauthenticated public pages')).toBeNull();
    expect(statedAccess('Anonymous callers, no login required')).toBeNull();
    expect(statedAccess('')).toBeNull();
  });
});

describe('checkBoundaries', () => {
  it('reports a stated level a route on the inner side contradicts, naming the route and its measured level', async () => {
    const d = checkBoundaries(model, await worklist());
    const contradicted = d.filter(x => x.code === 'boundary-access-contradicted');
    expect(contradicted).toHaveLength(1);
    expect(contradicted[0]).toMatchObject({ level: 'warning', file: 'api/users.py', line: 2 });
    expect(contradicted[0].message).toContain('#http-boundary says the #api side is authenticated ("authenticated")');
    expect(contradicted[0].message).toContain('GET /export (api/export.py:2 export) is public (absence)');
    // An elevated route satisfies an authenticated claim.
    expect(contradicted[0].message).not.toContain('/users/');
  });

  it('reports an unknown route under a stated level as unchecked, never as public', async () => {
    const d = checkBoundaries(model, await worklist());
    const unknown = d.filter(x => x.code === 'boundary-access-unknown');
    expect(unknown).toHaveLength(1);
    expect(unknown[0].message).toContain('GET / (api/main.py:2 index) is unknown: ambiguous_handler_check');
    expect(unknown[0].message).toContain('the claim is unchecked');
    expect(d.find(x => x.code === 'boundary-access-contradicted')!.message).not.toContain('GET / (');
  });

  it('reports a route handler reaching a sink whose file names no asset with a boundary to the outside', async () => {
    const d = checkBoundaries(model, await worklist());
    const missing = d.filter(x => x.code === 'boundary-missing');
    expect(missing.map(x => x.file)).toEqual(['jobs/run.py']);
    expect(missing[0].message).toContain('(#jobs)');
    expect(missing[0].message).toContain('POST /jobs/run [authenticated (declared)] → run_job reaches exec');
    // A file naming no asset is a coverage gap, reported by the worklist, not here.
    expect(d.some(x => x.file === 'lib/plain.py')).toBe(false);
  });

  it('reports a boundary no declared flow crosses and no recognised entry point reaches', async () => {
    const d = checkBoundaries(model, await worklist());
    const unused = d.filter(x => x.code === 'boundary-unused');
    expect(unused.map(x => x.message.split(' ')[0])).toEqual(['#vendor-boundary']);
    expect(unused[0]).toMatchObject({ file: 'lib/billing.py', line: 1 });
  });

  it('skips the access checks for a boundary whose two sides are both declared inside', async () => {
    const d = checkBoundaries(model, await worklist());
    expect(d.some(x => x.message.includes('#data-boundary'))).toBe(false);
  });

  it('every diagnostic is a warning', async () => {
    const d = checkBoundaries(model, await worklist());
    expect(d.length).toBeGreaterThan(0);
    expect(d.every(x => x.level === 'warning')).toBe(true);
  });

  it('without the classified auth verdict, only the access checks are skipped', async () => {
    const w = await worklist({ ...GRAPH, codegraph_auth_boundary: { ok: true, value: { ...AUTH, verdict: 'insufficient_resolution' } } } as any);
    const d = checkBoundaries(model, w);
    expect(d.map(x => x.code).sort()).toEqual(['boundary-missing', 'boundary-unused']);
    expect(boundaryCheckSummaryLine(w, d)).toContain('stated-versus-measured access skipped');
  });

  it('with no usable graph there is nothing to report', async () => {
    const none = await loadWorklist(root, model, { env: {}, transport: null });
    expect(checkBoundaries(model, none)).toEqual([]);
    expect(checkBoundaries(model, null)).toEqual([]);
    const thin = await worklist({ ...GRAPH, codegraph_attack_surface: { ok: true, value: { ...SURFACE, verdict: 'insufficient_resolution' } } } as any);
    expect(checkBoundaries(model, thin)).toEqual([]);
    expect(boundaryCheckSummaryLine(thin, [])).toContain('not run');
  });
});

// ─── Through the CLI ─────────────────────────────────────────────────

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

function guardlink(cwd: string, env: NodeJS.ProcessEnv, ...args: string[]): Promise<{ status: number; stdout: string; stderr: string }> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, env, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

/** A stand-in codegraph-mcp answering the three worklist queries over MCP stdio. */
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

describe('guardlink validate --code-graph', () => {
  it('is opt-in: without the flag no graph is consulted and nothing about boundaries is printed', async () => {
    const bin = join(root, 'fake-codegraph-mcp');
    await writeFile(bin, fakeMcp({ codegraph_attack_surface: SURFACE, codegraph_routes: ROUTES, codegraph_auth_boundary: AUTH }));
    await chmod(bin, 0o755);
    const env = { ...process.env, GUARDLINK_CODEGRAPH_MCP: bin };
    delete env.GUARDLINK_CODEGRAPH;

    const plain = await guardlink(root, env, 'validate', '.');
    expect(plain.stderr).not.toMatch(/Boundary checks|boundary-|#http-boundary says/);

    const checked = await guardlink(root, env, 'validate', '.', '--code-graph');
    expect(checked.stderr).toContain('Boundary checks (code graph via codegraph-mcp): 5 entry point(s) read, 4 warning(s)');
    expect(checked.stderr).toContain('api/users.py:2: #http-boundary says the #api side is authenticated');
    expect(checked.stderr).toContain('jobs/run.py:2: Route handler(s) here reach classified sinks');
    expect(checked.stderr).toContain('lib/billing.py:1: #vendor-boundary has no declared @flows across it');
    // Warnings never fail validation.
    expect(checked.status).toBe(plain.status);
  }, 60_000);

  it('with the graph switched off, says so and checks nothing', async () => {
    const r = await guardlink(root, { ...process.env, GUARDLINK_CODEGRAPH: 'off' }, 'validate', '.', '--code-graph');
    expect(r.stderr).toContain('Boundary checks: code graph switched off');
    expect(r.stderr).not.toContain('#http-boundary says');
  }, 60_000);
});
