/**
 * GuardLink Code Graph — optional, read-only input from a code graph of the repository.
 *
 * WHY THIS EXISTS
 * The annotate prompt tells an agent to find the entry points and trace each one to
 * its sinks, and the coverage playbook asks for "entry points first". GuardLink has
 * no detector for either: everything the prompt carries about the repository is
 * derived from annotations already written, so on first contact with an
 * unannotated service the agent is told to read the code and nothing ranks where
 * to start.
 *
 * A code graph answers that from the code itself. `codegraph-mcp` publishes the
 * route table (which function serves each HTTP route, for the frameworks it
 * recognises) and, per route handler, the classes of sink it reaches through the
 * call graph — data layer, exec, template, outbound network, filesystem, crypto.
 * This module reads five of its queries:
 *
 *   codegraph_attack_surface  handlers ranked by the sinks they reach (the worklist)
 *   codegraph_routes          the route table (bound and unbound registrations)
 *   codegraph_auth_boundary   who may reach each route: public, authenticated, elevated or unknown
 *   codegraph_reachable_sinks what one function reaches, with one example path per class
 *   codegraph_entry_reach     whether any recognised entry point reaches one function
 *
 * codegraph_auth_boundary is asked as an OPTIONAL call: a graph too old to
 * publish it still yields the worklist, with no access levels. Its routes answer
 * is never asked for access instead, because an older codegraph_routes ignores
 * an unknown `access` argument and returns every route unclassified, which
 * would read as all-public.
 *
 * THE GRAPH IS OPTIONAL, ALWAYS
 * Nothing here is required, installed or built. With no graph tooling, no graph
 * built for this repository, tooling too old to answer these queries, a failed
 * query, or the off switch, every function returns a status saying which, and
 * every consumer treats that exactly as "no graph": the annotate prompt is
 * byte-identical to the one GuardLink builds without this module. Nothing here
 * throws.
 *
 * Discovery order: `$GUARDLINK_CODEGRAPH_MCP` (an explicit codegraph-mcp binary),
 * then `codegraph-mcp` on PATH (spoken to over MCP stdio), then `bravos` on PATH
 * (`bravos graph <verb> --json`, the same server behind a CLI front). Off switch:
 * `GUARDLINK_CODEGRAPH=off`, or `enabled: false` from a caller (`--no-code-graph`).
 *
 * THE HONESTY GATE
 * The ranking is a call-graph walk, and the graph measures whether its own call
 * resolution is dense enough to walk. When it reports `insufficient_resolution`
 * (or any verdict other than `sinks_reached`) the worklist is withheld and the
 * graph's stated reason is carried instead, so an empty or thin list can never be
 * read as a small attack surface.
 *
 * Access levels have a gate of their own: they are carried only when the
 * auth-boundary verdict is `classified`. Under any other verdict the levels are
 * withheld and the graph's note is carried instead, and an `unknown` level is
 * always rendered as unknown with its reason, never as public.
 *
 * @exposes #codegraph to #child-proc-injection [high] cwe:CWE-78 -- "Spawns codegraph-mcp or bravos found on PATH, or the binary named by GUARDLINK_CODEGRAPH_MCP"
 * @mitigates #codegraph against #child-proc-injection using #param-commands -- "spawn/execFile with an argv array and shell:false; the only caller-derived arguments are the project root and a symbol address, each passed as one argv element"
 * @exposes #codegraph to #config-tamper [medium] cwe:CWE-15 -- "GUARDLINK_CODEGRAPH_MCP names the binary to run; whoever controls the environment chooses what executes"
 * @audit #codegraph -- "The override is an operator convenience, as PATH itself is; confirm CI environments do not let untrusted input set GUARDLINK_CODEGRAPH_MCP"
 * @exposes #codegraph to #dos [low] cwe:CWE-400 -- "A wedged or runaway graph server could hold the annotate command or an MCP call open, or stream unbounded output"
 * @mitigates #codegraph against #dos using #resource-limits -- "Every query has a timeout (QUERY_TIMEOUT_MS) and an output cap (MAX_OUTPUT_BYTES); the process is killed when either is hit"
 * @exposes #codegraph to #prompt-injection [medium] cwe:CWE-77 -- "Route paths, symbol names and sink call text come from the repository's own source and are rendered into the annotate prompt"
 * @audit #codegraph -- "Same trust as the source files the agent is told to read; the worklist adds no content the agent could not read itself, but a crafted route string is prose in the prompt"
 * @flows CodeGraphServer -> #codegraph via stdout -- "JSON answers to routes, attack_surface, reachable_sinks, entry_reach"
 * @flows CodeGraphServer -> #codegraph via codegraph_auth_boundary -- "Route access levels with the guard text and file:line each rests on; read only under the classified verdict"
 * @comment -- "Guard evidence text (a decorator or middleware as written) and the boundary suggestions built from it reach the annotate prompt under the same prompt-injection exposure as route paths: source-derived prose the agent could read itself, never an instruction"
 * @flows #codegraph -> CodeGraphServer via spawn -- "Project root and symbol address as argv / tools/call arguments"
 * @boundary between #codegraph and CodeGraphServer (#codegraph-boundary) -- "Process boundary: an external binary's JSON is parsed defensively and never executed"
 * @validates #resource-limits for #codegraph -- "tests/codegraph.test.ts: a stand-in server that never answers costs the timeout and yields status error, not a hung run"
 * @validates #param-commands for #codegraph -- "tests/codegraph.test.ts drives both transports against stand-in executables through argv, with no shell"
 * @comment -- "Never builds a graph and never installs anything; every failure is a status, and a status other than available changes nothing downstream"
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { accessSync, constants as fsConstants } from 'node:fs';
import { delimiter, join } from 'node:path';
import type { ThreatModel } from '../types/index.js';

// ─── Constants ───────────────────────────────────────────────────────

export const ENV_MCP_BIN = 'GUARDLINK_CODEGRAPH_MCP';
export const ENV_SWITCH = 'GUARDLINK_CODEGRAPH';
export const MCP_BIN = 'codegraph-mcp';
export const BRAVOS_BIN = 'bravos';

export const TOOL_ROUTES = 'codegraph_routes';
export const TOOL_SURFACE = 'codegraph_attack_surface';
export const TOOL_SINKS = 'codegraph_reachable_sinks';
export const TOOL_ENTRY_REACH = 'codegraph_entry_reach';
export const TOOL_AUTH_BOUNDARY = 'codegraph_auth_boundary';

/** The one attack-surface verdict under which the ranking is used. */
export const USABLE_VERDICT = 'sinks_reached';
/** The one auth-boundary verdict under which route access levels are used. */
export const ACCESS_USABLE_VERDICT = 'classified';

/**
 * A graph query is a read over an index that already exists. The ceiling is for a
 * wedged process, not a slow answer; exceeding it degrades to "no graph".
 */
export const QUERY_TIMEOUT_MS = 60_000;
/** An attack-surface answer on a large service is a few MB; this is far past that. */
export const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
/** Set at the graph's own caps, so a large application is read whole. */
const ROUTE_LIMIT = 5000;
const SURFACE_LIMIT = 1000;

export type CodeGraphStatus = 'off' | 'unavailable' | 'unsupported' | 'no_graph' | 'error' | 'available';

// ─── Transport ───────────────────────────────────────────────────────

export interface ToolCall {
  tool: string;
  args: Record<string, unknown>;
  /**
   * A server that does not publish this tool answers `ok: false, unsupported: true`
   * for it instead of failing the whole query, so an older graph still answers
   * the calls it does publish.
   */
  optional?: boolean;
}

/** One query's answer: the decoded JSON, or the graph's own refusal (a symbol it could not resolve). */
export type ToolAnswer =
  | { ok: true; value: any }
  | { ok: false; message: string; data?: unknown; unsupported?: boolean };

/** How a query reaches the graph. Tests inject a stub; production discovers one. */
export interface CodeGraphTransport {
  /** Named in every status, so a reader knows which front answered. */
  via: string;
  /**
   * Answer every call, in order. Throws `GraphUnsupported` when the server does not
   * publish a tool, `GraphToolingMissing` when the binary cannot run, and any other
   * error for a transport failure. A per-call refusal is an `ok: false` answer.
   */
  query(root: string, calls: ToolCall[]): Promise<ToolAnswer[]>;
}

export class GraphUnsupported extends Error {}
export class GraphToolingMissing extends Error {}

/** Look a binary up on PATH, the way a shell would, without running a shell. */
function onPath(name: string, env: NodeJS.ProcessEnv): string | null {
  const exts = process.platform === 'win32' ? ['.exe', '.cmd', ''] : [''];
  for (const dir of (env.PATH || '').split(delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      try {
        accessSync(candidate, fsConstants.X_OK);
        return candidate;
      } catch { /* not here */ }
    }
  }
  return null;
}

/**
 * Run a child with argv (never a shell), feed it `input`, and stream its stdout
 * lines to `onLine` until `done()` says every answer is in, the process exits,
 * the timeout fires, or the output cap is hit.
 */
function runChild(
  binary: string, argv: string[], input: string | null, timeoutMs: number,
  onLine: (line: string) => void, done: () => boolean,
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolvePromise, reject) => {
    let child: ChildProcess;
    try {
      child = spawn(binary, argv, { stdio: ['pipe', 'pipe', 'pipe'], shell: false });
    } catch (e) {
      reject(new GraphToolingMissing(`${binary} could not be started: ${(e as Error).message}`));
      return;
    }
    let settled = false;
    let stdout = '';
    let stderr = '';
    let pending = '';
    let bytes = 0;
    const settle = (err: Error | null, code: number | null = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { child.stdin?.end(); } catch { /* already closed */ }
      // A server stops at end of input; one that does not is killed rather than awaited.
      const reaper = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, 2000);
      reaper.unref?.();
      child.once('exit', () => clearTimeout(reaper));
      if (err) reject(err); else resolvePromise({ stdout, stderr, code });
    };
    const timer = setTimeout(() => settle(new Error(`${binary} gave no answer within ${Math.round(timeoutMs / 1000)}s`)), timeoutMs);
    child.on('error', (e: NodeJS.ErrnoException) => {
      settle(e.code === 'ENOENT' || e.code === 'EACCES'
        ? new GraphToolingMissing(`${binary}: ${e.code === 'ENOENT' ? 'not found' : 'not executable'}`)
        : e);
    });
    child.stdin?.on('error', () => { /* the server closed its input early; its exit says why */ });
    child.stderr?.setEncoding('utf-8');
    child.stderr?.on('data', (chunk: string) => { if (stderr.length < 64 * 1024) stderr += chunk; });
    child.stdout?.setEncoding('utf-8');
    child.stdout?.on('data', (chunk: string) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX_OUTPUT_BYTES) {
        settle(new Error(`${binary} answered more than ${MAX_OUTPUT_BYTES} bytes`));
        return;
      }
      stdout += chunk;
      pending += chunk;
      let nl: number;
      while ((nl = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, nl);
        pending = pending.slice(nl + 1);
        onLine(line);
      }
      if (done()) settle(null);
    });
    child.on('close', (code: number | null) => {
      if (pending) { onLine(pending); pending = ''; }
      settle(null, code);
    });
    if (input !== null) child.stdin?.write(input);
    else child.stdin?.end();
  });
}

/**
 * MCP over stdio to one codegraph-mcp process: initialize, tools/list, then each
 * call, in ONE process so every query reads one graph. stdin stays open until
 * every answer has arrived, because the server stops serving at end of input and
 * would drop requests still queued behind the handshake.
 */
export function mcpTransport(binary: string, timeoutMs = QUERY_TIMEOUT_MS): CodeGraphTransport {
  return {
    via: MCP_BIN,
    async query(root, calls) {
      // Every call is sent up front. An optional call to a tool the server does
      // not publish gets the server's error back, and is answered as unsupported
      // once tools/list says so.
      const msgs: object[] = [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'guardlink', version: '1' } } },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', id: 2, method: 'tools/list' },
        ...calls.map((c, i) => ({ jsonrpc: '2.0', id: 3 + i, method: 'tools/call', params: { name: c.tool, arguments: c.args } })),
      ];
      const answers = new Map<number, any>();
      const wanted = [2, ...calls.map((_, i) => 3 + i)];
      await runChild(binary, ['--project-path', root], msgs.map(m => JSON.stringify(m)).join('\n') + '\n', timeoutMs,
        (line) => {
          let msg: any;
          try { msg = JSON.parse(line); } catch { return; }
          if (msg && typeof msg === 'object' && typeof msg.id === 'number') answers.set(msg.id, msg);
        },
        () => wanted.every(id => answers.has(id)));

      const listed = answers.get(2);
      if (!listed) throw new Error(`${binary} did not answer tools/list`);
      const names = new Set<string>(((listed.result?.tools) || []).map((t: any) => t?.name));
      const missing = calls.filter(c => !c.optional).map(c => c.tool).filter(t => !names.has(t));
      if (missing.length) throw new GraphUnsupported([...new Set(missing)].join(', '));

      return calls.map((c, i): ToolAnswer => {
        if (!names.has(c.tool)) return { ok: false, message: `the installed code graph does not answer ${c.tool}`, unsupported: true };
        const msg = answers.get(3 + i);
        if (!msg) return { ok: false, message: `${c.tool} returned no answer` };
        if (msg.error) return { ok: false, message: String(msg.error.message || `${c.tool} failed`), data: msg.error.data };
        const result = msg.result || {};
        const body = ((result.content || []) as any[]).map(p => (p && typeof p.text === 'string' ? p.text : '')).join('');
        if (result.isError) return { ok: false, message: body || `${c.tool} failed` };
        try { return { ok: true, value: JSON.parse(body) }; } catch { return { ok: false, message: `${c.tool} returned an unreadable answer` }; }
      });
    },
  };
}

/**
 * The `bravos graph` front, for a machine that has the bravos wheel and no
 * codegraph-mcp on PATH. The same server underneath, so the answers are
 * identical; only the spelling differs: the verb is the tool name without its
 * `codegraph_` prefix, dashed, and each argument is `--key value`.
 */
export function bravosTransport(binary: string, timeoutMs = QUERY_TIMEOUT_MS): CodeGraphTransport {
  return {
    via: 'bravos graph',
    async query(root, calls) {
      const out: ToolAnswer[] = [];
      for (const c of calls) {
        const verb = c.tool.slice('codegraph_'.length).replace(/_/g, '-');
        const argv = ['graph', '--repo', root, verb, '--json'];
        for (const [key, value] of Object.entries(c.args)) {
          if (value === undefined || value === null || Array.isArray(value)) continue;
          argv.push('--' + key.replace(/_/g, '-'), String(value));
        }
        const { stdout, stderr } = await runChild(binary, argv, null, timeoutMs, () => {}, () => false);
        if (/has no question called/.test(stdout + stderr)) {
          if (!c.optional) throw new GraphUnsupported(c.tool);
          out.push({ ok: false, message: `the installed code graph does not answer ${c.tool}`, unsupported: true });
          continue;
        }
        if (!stdout.trim() && /not installed/.test(stderr)) throw new GraphToolingMissing(stderr.trim().split('\n')[0].slice(0, 300));
        let doc: any = null;
        try { doc = JSON.parse(stdout); } catch { /* handled below */ }
        if (doc && typeof doc === 'object' && 'error' in doc) {
          const message = String(doc.message || doc.error);
          if (doc.error === 'codegraph_unavailable' && doc.kind === 'companion') throw new GraphToolingMissing(message);
          out.push({ ok: false, message, data: doc.candidates });
          continue;
        }
        if (!doc || typeof doc !== 'object' || !('result' in doc)) {
          throw new Error(`bravos graph ${verb} gave no JSON answer`);
        }
        out.push({ ok: true, value: doc.result });
      }
      return out;
    },
  };
}

export interface CodeGraphOptions {
  /** false is the off switch (`--no-code-graph`). The environment switch applies too. */
  enabled?: boolean;
  /** A transport to use instead of discovery — how tests pin one. null means "none found". */
  transport?: CodeGraphTransport | null;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

/** Whether the environment turned the graph off. */
export function graphSwitchedOff(env: NodeJS.ProcessEnv = process.env): boolean {
  return /^(off|0|false|no|none|disabled?)$/i.test((env[ENV_SWITCH] || '').trim());
}

/** Find a transport, or null. Never runs anything. */
export function discoverTransport(env: NodeJS.ProcessEnv = process.env, timeoutMs = QUERY_TIMEOUT_MS): CodeGraphTransport | null {
  const explicit = (env[ENV_MCP_BIN] || '').trim();
  if (explicit) return mcpTransport(explicit, timeoutMs);
  const mcp = onPath(MCP_BIN, env);
  if (mcp) return mcpTransport(mcp, timeoutMs);
  const bravos = onPath(BRAVOS_BIN, env);
  if (bravos) return bravosTransport(bravos, timeoutMs);
  return null;
}

interface StatusFields { status: CodeGraphStatus; via: string; note: string }

/**
 * Run the calls, turning every way it can fail into a status. `answers` is set
 * only when status is `available`.
 */
async function ask(root: string, calls: ToolCall[], opts: CodeGraphOptions): Promise<StatusFields & { answers?: ToolAnswer[] }> {
  const env = opts.env ?? process.env;
  if (opts.enabled === false) return { status: 'off', via: '', note: 'disabled with --no-code-graph' };
  if (graphSwitchedOff(env)) return { status: 'off', via: '', note: `disabled with ${ENV_SWITCH}=${env[ENV_SWITCH]}` };
  const transport = opts.transport !== undefined ? opts.transport : discoverTransport(env, opts.timeoutMs);
  if (!transport) {
    return { status: 'unavailable', via: '', note: `no code graph tooling found (${MCP_BIN} or ${BRAVOS_BIN} on PATH, or $${ENV_MCP_BIN})` };
  }
  const via = transport.via;
  let answers: ToolAnswer[];
  try {
    answers = await transport.query(root, calls);
  } catch (e) {
    if (e instanceof GraphUnsupported) {
      return { status: 'unsupported', via, note: `the installed code graph does not answer ${e.message}; a graph build that publishes it is needed` };
    }
    if (e instanceof GraphToolingMissing) return { status: 'unavailable', via, note: e.message.slice(0, 300) };
    return { status: 'error', via, note: `code graph query failed: ${String((e as Error)?.message ?? e).slice(0, 300)}` };
  }
  const noGraph = answers.find(a => !a.ok && /No CodeGraph/i.test(a.message));
  if (noGraph) {
    return { status: 'no_graph', via, note: `no code graph has been built for this repository; build one (e.g. \`bravos graph build ${root}\`) to use it` };
  }
  return { status: 'available', via, note: '', answers };
}

// ─── Worklist ────────────────────────────────────────────────────────

/** How much of a handler the threat model already covers. */
export type AnnotationState =
  /** Its file carries no annotation at all. */
  | 'none'
  /** Its file is annotated, but no annotation is anchored on this handler. */
  | 'file'
  /** An annotation is anchored on (or inside) this handler. */
  | 'handler';

export interface SinkReach {
  /** data_layer | exec | template | network | filesystem | crypto_secrets */
  class: string;
  /** Distinct sink-touching symbols reached. */
  sinks: number;
  weighted: number;
  min_depth: number | null;
  /** One example: `callee at file:line`. */
  example: string;
}

/** Who may reach one route, as the graph's auth-boundary classifier measured it. */
export interface RouteAccess {
  /** The route, spelt exactly as in `WorklistEntry.routes`. */
  route: string;
  /** public | authenticated | elevated | unknown */
  level: string;
  /** declared | handler | explicit_public | absence; '' when the level is unknown. */
  basis: string;
  /** Why the level is unknown, in the graph's vocabulary; '' otherwise. */
  unknown_reason: string;
  /** The graph's one sentence: the level and what it rests on. */
  evidence_summary: string;
  /** Up to three pieces of evidence, each `what matched at file:line`: the guard to name as the enforcement. */
  evidence: string[];
  /** The graph's own qualifications, e.g. a handler role check that may gate one branch only. */
  caveats: string[];
}

export interface ResolverDensitySummary {
  sufficient: boolean;
  edges_per_callable: number | null;
  shortfalls: string[];
}

export interface WorklistEntry {
  /** 1-based position in the worklist (unannotated first, then heaviest reach). */
  position: number;
  /** The graph's own rank by reach alone. */
  graph_rank: number | null;
  /** The graph address: pass it to guardlink_reach / codegraph_* as-is. */
  handler: string;
  file: string;
  line: number | null;
  name: string;
  /** `METHOD path` for each route this handler serves; empty for a non-route entry (main). */
  routes: string[];
  score: number;
  reaches: SinkReach[];
  annotated: AnnotationState;
  /**
   * The access level of each of `routes` the graph classified, in the same
   * order. Empty when the graph does not classify access, or its auth-boundary
   * verdict is not `classified` (see `Worklist.access_withheld_reason`).
   */
  access: RouteAccess[];
}

export interface Worklist extends StatusFields {
  /** The attack-surface verdict; only `sinks_reached` produces entries. */
  verdict: string;
  /** Why the worklist was withheld, in the graph's own words; empty when it was not. */
  withheld_reason: string;
  /** The graph's one-line summary of the ranking. */
  message: string;
  /** Which entry points were ranked (route handlers, or `main` when there were none). */
  entry_rule: string;
  entries: WorklistEntry[];
  /** Route registrations whose handler the graph could not bind to a function. */
  routes_unbound: number;
  unbound_examples: string[];
  /** Route registrations with a computed path. */
  routes_dynamic: number;
  /** Set when the graph was built from a different tree than the one on disk. */
  currency_caveat: string;
  /**
   * The auth-boundary verdict: `classified`, `insufficient_resolution`,
   * `no_routes`, `not_classified`, `graph_predates_classification`, or '' when
   * the graph does not answer the query at all. Access levels are carried only
   * under `classified`.
   */
  auth_verdict: string;
  /** Why access levels are not carried, in the graph's words where it gave them; '' when they are. */
  access_withheld_reason: string;
  /** The graph's measure of its own call resolution, as the auth-boundary answer reported it. */
  resolver_density: ResolverDensitySummary | null;
}

function emptyWorklist(s: StatusFields): Worklist {
  return {
    ...s, verdict: '', withheld_reason: '', message: '', entry_rule: '', entries: [],
    routes_unbound: 0, unbound_examples: [], routes_dynamic: 0, currency_caveat: '',
    auth_verdict: '', access_withheld_reason: '', resolver_density: null,
  };
}

/** Is the ranking usable? Available, the graph vouched for it, and it ranked something. */
export function worklistUsable(w: Worklist): boolean {
  return w.status === 'available' && w.verdict === USABLE_VERDICT && w.entries.length > 0;
}

/** Are route access levels carried? The ranking is usable and the graph vouched for its classification. */
export function accessUsable(w: Worklist): boolean {
  return worklistUsable(w) && w.auth_verdict === ACCESS_USABLE_VERDICT;
}

interface Span { start: number; end: number; symbol: string | null }

/** Where the model's annotations sit, per file, by the code span each is anchored to. */
function annotationSpans(model: ThreatModel | null): Map<string, Span[]> {
  const byFile = new Map<string, Span[]>();
  if (!model) return byFile;
  for (const [key, value] of Object.entries(model)) {
    if (key === 'external_refs' || !Array.isArray(value)) continue;
    for (const row of value as any[]) {
      const loc = row && typeof row === 'object' ? row.location : null;
      if (!loc || typeof loc.file !== 'string') continue;
      const a = loc.anchor;
      const span: Span = a && a.scope !== 'file'
        ? { start: a.start_line, end: a.end_line, symbol: a.symbol ?? null }
        : { start: -1, end: -1, symbol: null };
      const list = byFile.get(loc.file) ?? [];
      list.push(span);
      byFile.set(loc.file, list);
    }
  }
  return byFile;
}

function annotationState(spans: Map<string, Span[]>, file: string, line: number | null, name: string): AnnotationState {
  const list = spans.get(file);
  if (!list || list.length === 0) return 'none';
  const onHandler = list.some(s =>
    (line != null && s.start >= 0 && s.start <= line && line <= s.end)
    || (!!name && s.symbol === name));
  return onHandler ? 'handler' : 'file';
}

function sinkReach(c: any): SinkReach {
  const sink = c?.example?.sink ?? {};
  return {
    class: String(c?.class ?? ''),
    sinks: Number(c?.sinks ?? 0),
    weighted: Number(c?.weighted ?? 0),
    min_depth: typeof c?.min_depth === 'number' ? c.min_depth : null,
    example: sink.callee ? `${sink.callee} at ${sink.file}:${sink.line}` : '',
  };
}

const STATE_ORDER: Record<AnnotationState, number> = { none: 0, file: 1, handler: 2 };

/**
 * The ranked worklist: every entry point the graph ranked, unannotated handlers
 * first, heaviest reach first within each state. Never throws.
 */
export async function loadWorklist(root: string, model: ThreatModel | null, opts: CodeGraphOptions = {}): Promise<Worklist> {
  const asked = await ask(root, [
    { tool: TOOL_SURFACE, args: { limit: SURFACE_LIMIT } },
    { tool: TOOL_ROUTES, args: { limit: ROUTE_LIMIT } },
    { tool: TOOL_AUTH_BOUNDARY, args: { limit: ROUTE_LIMIT }, optional: true },
  ], opts);
  if (asked.status !== 'available' || !asked.answers) return emptyWorklist(asked);
  try {
    return buildWorklist(asked, asked.answers[0], asked.answers[1], asked.answers[2], model);
  } catch (e) {
    return emptyWorklist({ status: 'error', via: asked.via, note: `unreadable code graph answer: ${String((e as Error)?.message ?? e).slice(0, 300)}` });
  }
}

/**
 * A route as the attack surface labels it: `METHODS path`, methods comma-joined
 * (`ANY` when none), the computed-path expression when there is no template.
 * The join from an auth-boundary row to a worklist route is on this label, so it
 * is spelt the way the graph spells the attack surface's own `routes`.
 */
function routeLabel(r: any): string {
  const methods = Array.isArray(r?.methods) && r.methods.length ? (r.methods as unknown[]).map(String).join(',') : 'ANY';
  return `${methods} ${r?.path ?? r?.path_expr ?? ''}`;
}

function routeAccess(route: string, a: any): RouteAccess {
  const evidence = ((a?.evidence ?? []) as any[]).slice(0, 3)
    .map(e => `${String(e?.text ?? e?.rule ?? '').trim()}${e?.at ? ` at ${e.at}` : ''}`)
    .filter(Boolean);
  return {
    route,
    level: String(a?.level ?? 'unknown'),
    basis: a?.basis ? String(a.basis) : '',
    unknown_reason: a?.unknown_reason ? String(a.unknown_reason) : '',
    evidence_summary: String(a?.summary ?? ''),
    evidence,
    caveats: ((a?.caveats ?? []) as unknown[]).map(String).filter(Boolean),
  };
}

/** Read the auth-boundary answer into the worklist: the verdict always, the levels only when it is `classified`. */
function attachAccess(w: Worklist, authAns: ToolAnswer | undefined): void {
  if (!authAns || !authAns.ok) {
    w.access_withheld_reason = !authAns || authAns.unsupported
      ? `the installed code graph does not classify route access (${TOOL_AUTH_BOUNDARY})`
      : `${TOOL_AUTH_BOUNDARY} failed: ${authAns.message.slice(0, 300)}`;
    return;
  }
  const auth = authAns.value ?? {};
  w.auth_verdict = String(auth.verdict ?? '');
  const density = auth.resolver_density;
  if (density && typeof density === 'object') {
    w.resolver_density = {
      sufficient: density.sufficient === true,
      edges_per_callable: typeof density.edges_per_callable === 'number' ? density.edges_per_callable : null,
      shortfalls: ((density.shortfalls ?? []) as unknown[]).map(String).filter(Boolean),
    };
  }
  if (w.auth_verdict !== ACCESS_USABLE_VERDICT) {
    const note = String(auth.verdict_note ?? '').trim();
    w.access_withheld_reason = `the graph's route access verdict is '${w.auth_verdict || 'none'}'${note ? `: ${note}` : ''}`;
    return;
  }
  const byHandler = new Map<string, Map<string, any>>();
  for (const r of (auth.routes ?? []) as any[]) {
    if (!r?.handler || !r.access) continue;
    const labels = byHandler.get(String(r.handler)) ?? new Map<string, any>();
    labels.set(routeLabel(r), r.access);
    byHandler.set(String(r.handler), labels);
  }
  for (const e of w.entries) {
    const labels = byHandler.get(e.handler);
    if (!labels) continue;
    e.access = e.routes.filter(route => labels.has(route)).map(route => routeAccess(route, labels.get(route)));
  }
}

function buildWorklist(s: StatusFields, surfaceAns: ToolAnswer, routesAns: ToolAnswer, authAns: ToolAnswer | undefined, model: ThreatModel | null): Worklist {
  const w = emptyWorklist(s);
  if (!surfaceAns.ok) {
    return { ...w, status: 'error', note: `${TOOL_SURFACE} failed: ${surfaceAns.message.slice(0, 300)}` };
  }
  const surface = surfaceAns.value ?? {};
  w.verdict = String(surface.verdict ?? '');
  w.message = String(surface.message ?? '');
  w.entry_rule = String(surface.entry_points?.default_rule ?? '');
  const currency = surface.graph_currency?.state ?? (routesAns.ok ? routesAns.value?.graph_currency?.state : undefined);
  if (currency && currency !== 'current') {
    const caveat = surface.graph_currency?.caveat;
    w.currency_caveat = `the graph is ${currency} against the working tree${caveat ? ` (${caveat})` : ''}; answers are from the indexed tree`;
  }
  if (routesAns.ok) {
    const routes = routesAns.value ?? {};
    const unbound = ((routes.routes ?? []) as any[]).filter(r => r && !['bound', 'bound_unique_name'].includes(r.resolution));
    w.routes_unbound = Number(routes.handlers_unbound ?? unbound.length) || 0;
    w.unbound_examples = unbound.slice(0, 5).map(r =>
      `${((r.methods ?? ['ANY']) as string[]).join('|')} ${r.path ?? r.path_expr ?? '(computed)'} registered at ${r.registered_at ?? '?'}`);
    w.routes_dynamic = Number(routes.dynamic_paths ?? 0) || 0;
  }

  if (w.verdict !== USABLE_VERDICT) {
    const shortfalls = ((surface.confidence?.shortfalls ?? []) as unknown[]).map(String).filter(Boolean);
    w.withheld_reason = w.verdict === 'insufficient_resolution'
      ? `the graph reports insufficient call resolution for this repository${shortfalls.length ? ` (${shortfalls.join('; ')})` : ''}, so its reachable-sink ranking would mislead`
      : w.verdict === 'no_entry_points'
        ? 'the graph recognised no entry point in this repository (no route registration in a framework it knows, and no main)'
        : w.verdict === 'no_sinks_reached'
          ? 'no entry point reaches a sink the graph classifies, so a ranking would order nothing'
          : `the attack-surface verdict was '${w.verdict || 'none'}'`;
    return w;
  }

  const spans = annotationSpans(model);
  const rows = ((surface.rows ?? []) as any[]).filter(r => r?.entry?.id);
  const entries: WorklistEntry[] = rows.map(r => {
    const e = r.entry;
    const file = String(e.file ?? '');
    const line = typeof e.line === 'number' ? e.line : null;
    const name = String(e.name ?? '');
    return {
      position: 0,
      graph_rank: typeof r.rank === 'number' ? r.rank : null,
      handler: String(e.id),
      file, line, name,
      routes: ((r.routes ?? []) as unknown[]).map(String),
      score: Number(r.score ?? 0),
      reaches: ((r.classes ?? []) as any[]).map(sinkReach).sort((a, b) => b.weighted - a.weighted),
      annotated: annotationState(spans, file, line, name),
      access: [],
    };
  });
  entries.sort((a, b) =>
    STATE_ORDER[a.annotated] - STATE_ORDER[b.annotated]
    || b.score - a.score
    || (a.graph_rank ?? Infinity) - (b.graph_rank ?? Infinity)
    || a.handler.localeCompare(b.handler));
  entries.forEach((e, i) => { e.position = i + 1; });
  w.entries = entries;
  attachAccess(w, authAns);
  return w;
}

// ─── One function's reach ────────────────────────────────────────────

export interface EntryPath {
  /** The entry point's graph address. */
  entry: string;
  kind: string;
  routes: string[];
  depth: number | null;
  /** Node ids from the entry point to the symbol. */
  path: string[];
}

export interface Reach extends StatusFields {
  symbol: string;
  /** Set when the graph could not resolve `symbol` to exactly one function. */
  refused: string;
  candidates: string[];
  /** live_via_route | live_via_entry | not_reached | unknown ('' when not asked). */
  liveness: string;
  /** Why liveness is unknown, or what `not_reached` cannot see. */
  liveness_note: string;
  entries: EntryPath[];
  /** sinks_reached | no_sinks_reached | insufficient_resolution … */
  sinks_verdict: string;
  /** Withheld with this reason when the verdict is insufficient_resolution. */
  sinks_withheld_reason: string;
  reaches: Array<SinkReach & { path: string[] }>;
  message: string;
}

/**
 * What one function reaches (sink classes, with one example path each) and
 * whether a recognised entry point reaches it. For an agent deciding what to
 * write in an @exposes or a @flows before it writes it. Never throws.
 */
export async function reachFor(root: string, symbol: string, opts: CodeGraphOptions = {}): Promise<Reach> {
  const base: Reach = {
    status: 'available', via: '', note: '', symbol, refused: '', candidates: [], liveness: '', liveness_note: '',
    entries: [], sinks_verdict: '', sinks_withheld_reason: '', reaches: [], message: '',
  };
  const asked = await ask(root, [
    { tool: TOOL_SINKS, args: { symbol } },
    { tool: TOOL_ENTRY_REACH, args: { symbol } },
  ], opts);
  if (asked.status !== 'available' || !asked.answers) return { ...base, ...asked };
  const [sinksAns, entryAns] = asked.answers;
  const r: Reach = { ...base, via: asked.via };
  try {
    const refusal = [sinksAns, entryAns].find(a => !a.ok);
    if (refusal && !refusal.ok) {
      r.refused = refusal.message.slice(0, 500);
      const cands = (refusal.data as any)?.candidates ?? refusal.data;
      r.candidates = Array.isArray(cands) ? cands.map((c: any) => String(c?.id ?? c?.address ?? c)).slice(0, 20) : [];
      return r;
    }
    if (sinksAns.ok) {
      const s = sinksAns.value ?? {};
      r.sinks_verdict = String(s.verdict ?? '');
      r.message = String(s.message ?? '');
      if (r.sinks_verdict === 'insufficient_resolution') {
        const shortfalls = ((s.confidence?.shortfalls ?? s.reach?.confidence?.shortfalls ?? []) as unknown[]).map(String);
        r.sinks_withheld_reason = `the graph reports insufficient call resolution for this repository${shortfalls.length ? ` (${shortfalls.join('; ')})` : ''}; no sinks are listed on purpose — this is not a clean answer`;
      } else {
        r.reaches = ((s.reach?.classes ?? []) as any[]).map(c => ({
          ...sinkReach(c),
          path: ((c?.example?.path ?? []) as any[]).map(p => String(p?.symbol ?? '')).filter(Boolean),
        })).sort((a, b) => b.weighted - a.weighted);
      }
    }
    if (entryAns.ok) {
      const e = entryAns.value ?? {};
      r.liveness = String(e.reach?.liveness ?? '');
      r.liveness_note = r.liveness === 'unknown'
        ? String(e.reach?.unknown_reason ?? 'unknown')
        : r.liveness === 'not_reached' ? String(e.entry_points?.coverage_note ?? '') : '';
      r.entries = ((e.reach?.entries ?? []) as any[]).slice(0, 10).map(x => ({
        entry: String(x?.node_id ?? ''),
        kind: String(x?.kind ?? ''),
        routes: ((x?.routes ?? []) as any[]).map(rt => `${((rt?.methods ?? ['ANY']) as string[]).join('|')} ${rt?.path ?? ''}`.trim()),
        depth: typeof x?.depth === 'number' ? x.depth : null,
        path: ((x?.path ?? []) as unknown[]).map(String),
      }));
    }
    return r;
  } catch (e) {
    return { ...base, status: 'error', via: asked.via, note: `unreadable code graph answer: ${String((e as Error)?.message ?? e).slice(0, 300)}` };
  }
}

// ─── Rendering ───────────────────────────────────────────────────────

/** How many worklist rows the annotate prompt carries. The rest are one MCP call away. */
export const PROMPT_WORKLIST_ROWS = 15;

function describeReaches(reaches: SinkReach[]): string {
  if (reaches.length === 0) return 'no classified sink reached';
  return reaches.map(c => `${c.class} ${c.sinks}${c.example ? ` (e.g. ${c.example})` : ''}`).join('; ');
}

/** `public: absence`, `authenticated: declared`, `unknown: ambiguous_handler_check`. */
function accessTag(a: RouteAccess): string {
  const why = a.level === 'unknown' ? a.unknown_reason : a.basis;
  return why ? `${a.level}: ${why}` : a.level;
}

/**
 * One worklist row as a line of prose. A route the graph classified carries its
 * access level in brackets; with no classification the row reads as it always did.
 */
export function formatWorklistEntry(e: WorklistEntry): string {
  const where = `${e.file}${e.line != null ? `:${e.line}` : ''} ${e.name}`.trim();
  const access = new Map((e.access ?? []).map(a => [a.route, a]));
  const routes = e.routes.length
    ? e.routes.map(r => (access.has(r) ? `${r} [${accessTag(access.get(r)!)}]` : r)).join(', ')
    : '(entry point, no route)';
  return `${String(e.position).padStart(2)}. [${e.annotated}] ${routes} → ${where} — reach ${e.score}: ${describeReaches(e.reaches)}`;
}

/**
 * The kind of trust boundary a sink class sits behind. Template rendering and
 * crypto stay inside the process that calls them, so they suggest none.
 */
export const SINK_BOUNDARY_KIND: Readonly<Record<string, string>> = {
  data_layer: 'data boundary',
  exec: 'process boundary',
  network: 'vendor/egress boundary',
  filesystem: 'filesystem boundary',
};

/** How many routes of one handler get their own caller-boundary line. */
const SUGGESTED_ROUTES_PER_ENTRY = 3;

/** The caller-side boundary one classified route implies, with what holds it. */
function callerBoundaryLine(a: RouteAccess): string {
  const enforced = a.evidence.length ? a.evidence.join('; ') : a.evidence_summary;
  const caveat = a.caveats.length ? ` (the graph's caveat: ${a.caveats.join('; ')})` : '';
  switch (a.level) {
    case 'public':
      return a.basis === 'explicit_public'
        ? `caller boundary, ${a.route}: public by an explicit opt-out (${enforced || 'see the route'}); the line is open on purpose, so say so in the description`
        : `caller boundary, ${a.route}: public — the graph found no guard before or inside the handler; if the route is meant to be open, say so in the description, and if it is not, that is an @exposes, not a boundary`;
    case 'authenticated':
    case 'elevated':
      return `caller boundary, ${a.route}: ${a.level} (${a.basis || 'basis not stated'}) — enforced by ${enforced || 'a guard the graph did not cite'}${caveat}`;
    default:
      return `caller boundary, ${a.route}: access unknown (${a.unknown_reason || 'no reason given'}) — read the guard yourself, and name none the code does not show`;
  }
}

/**
 * The boundaries one worklist row suggests: one per classified route, between
 * an outside caller and the handler, and one per sink class that sits behind a
 * trust change, anchored at the graph's example sink call. Empty when the row
 * suggests none.
 */
export function suggestBoundaries(e: WorklistEntry): string[] {
  const lines: string[] = [];
  const access = e.access ?? [];
  for (const a of access.slice(0, SUGGESTED_ROUTES_PER_ENTRY)) lines.push(callerBoundaryLine(a));
  if (access.length > SUGGESTED_ROUTES_PER_ENTRY) lines.push(`${access.length - SUGGESTED_ROUTES_PER_ENTRY} more route(s) on this handler; guardlink_worklist lists their access`);
  for (const c of e.reaches) {
    const kind = SINK_BOUNDARY_KIND[c.class];
    if (kind) lines.push(`${kind} (${c.class})${c.example ? ` at ${c.example}` : ''}`);
  }
  return lines;
}

/** The boundary-suggestion section for the rows shown, or [] when none of them suggests one. */
function renderBoundarySuggestions(shown: WorklistEntry[]): string[] {
  const blocks: string[] = [];
  for (const e of shown) {
    const lines = suggestBoundaries(e);
    if (lines.length === 0) continue;
    const where = `${e.file}${e.line != null ? `:${e.line}` : ''} ${e.name}`.trim();
    blocks.push(`- ${String(e.position).padStart(2)}. ${where}`, ...lines.map(l => `    ${l}`));
  }
  if (blocks.length === 0) return [];
  return [
    '',
    '### Boundaries the graph suggests',
    'Each row above crosses trust lines the code shows: an outside caller reaching the handler, and the handler reaching storage, a spawned process, the network or the filesystem. '
    + 'Where the model does not already declare one (guardlink_lookup "boundary for <asset>"), write a `@boundary` between the handler\'s asset and the other side — `Client` or an `External.*` asset for a caller, the store, process or vendor for a sink. '
    + 'Write it directed, `@boundary from <outer> to <inner>`, when you know which side is less trusted: a caller is outer (`from Client to #api`), and a store is inner to the code that queries it (`from #api to #db`); write `between` when you do not. '
    + 'Name what enforces the line in its description: the guard the graph cites, once you have read it in source. A suggestion is where to look, not a claim; write none you cannot see in the code.',
    ...blocks,
  ];
}

/**
 * The annotate-prompt section for a worklist, or '' when the graph contributed
 * nothing. A withheld worklist renders as a short statement of why — the graph
 * was present, so the agent should know it was consulted and what it said — and
 * every status other than `available` renders nothing, so the prompt without a
 * graph is byte-identical to the one GuardLink built before this module.
 *
 * @param playbookUse the selected playbook's instruction for using the list, if it has one
 */
export function renderWorklistBlock(w: Worklist | null | undefined, playbookUse = '', rows = PROMPT_WORKLIST_ROWS): string {
  if (!w || w.status !== 'available') return '';
  const lines: string[] = ['## Code-graph worklist'];
  if (!worklistUsable(w)) {
    lines.push(`A code graph of this repository was consulted (via ${w.via}) and its ranking is withheld: ${w.withheld_reason || 'it ranked no entry point'}.`);
    lines.push('No worklist is given. Find the entry points by reading the code, as the method says; do not read the absence of a list as a small attack surface.');
    return lines.join('\n');
  }
  const shown = w.entries.slice(0, Math.max(0, rows));
  lines.push(
    `A code graph of this repository (via ${w.via}) ranks its entry points by the sink classes each one reaches through the call graph. `
    + 'Handlers the threat model does not cover yet come first, heaviest reach first. It is a reading order derived from the code, not a finding: '
    + 'a sink reached is where to look, not proof that attacker input arrives there unchecked — the evidence bar still applies to every claim.',
  );
  lines.push('`[none]` = its file has no annotations; `[file]` = the file does, but none is anchored on this handler; `[handler]` = annotated here.');
  if (accessUsable(w)) {
    lines.push('A route\'s bracket is who may reach it, as the graph classified it from guards in source: `public`, `authenticated` or `elevated`, with the basis (`declared` = middleware, router scope, API spec or decorator; `handler` = a check inside it; `explicit_public` = an opt-out; `absence` = nothing found and everything readable), or `unknown` with the reason. Read unknown as unknown, never as public.');
  } else if (w.auth_verdict) {
    lines.push(`Route access levels are withheld: ${w.access_withheld_reason}.`);
  }
  if (w.currency_caveat) lines.push(`Caveat: ${w.currency_caveat}.`);
  lines.push('');
  lines.push(...shown.map(formatWorklistEntry));
  const more = w.entries.length - shown.length;
  const tail: string[] = [];
  if (more > 0) tail.push(`${more} more ranked entry point(s) not shown — guardlink_worklist (MCP) returns them all.`);
  if (w.routes_unbound > 0) {
    tail.push(`${w.routes_unbound} route registration(s) could not be bound to a handler and are not ranked; read them yourself${w.unbound_examples.length ? `: ${w.unbound_examples.join('; ')}` : ''}.`);
  }
  if (w.routes_dynamic > 0) tail.push(`${w.routes_dynamic} route registration(s) have a computed path and are not addressable here.`);
  tail.push('The list covers only the frameworks the graph recognises; an entry point it does not recognise (a CLI command, a message consumer, another framework) is absent, not safe.');
  tail.push('Before writing an @exposes or @flows for one of these, guardlink_reach(symbol) shows what that function reaches and by which path.');
  lines.push('', ...tail);
  lines.push(...renderBoundarySuggestions(shown));
  if (playbookUse) lines.push('', playbookUse.trim());
  return lines.join('\n');
}

/** One stderr line saying what the graph contributed, for commands that build a prompt. */
export function worklistSummaryLine(w: Worklist): string {
  if (w.status === 'off') return '';
  if (w.status !== 'available') return `Code graph: not used — ${w.note}`;
  if (!worklistUsable(w)) return `Code graph (via ${w.via}): worklist withheld — ${w.withheld_reason}`;
  const open = w.entries.filter(e => e.annotated !== 'handler').length;
  const access = accessUsable(w) ? ', route access classified' : w.auth_verdict ? `, route access withheld (${w.auth_verdict})` : '';
  return `Code graph (via ${w.via}): ${w.entries.length} entry point(s) ranked, ${open} not yet annotated at the handler${access}; worklist added to the prompt`;
}
