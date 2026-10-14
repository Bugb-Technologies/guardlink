/**
 * GuardLink Code Graph — declared agent reach checked against what the graph measured.
 *
 * `@agents`, `@reaches`, `@effects` and `@gates` are claims about code: this tool
 * is held by that agent, this function spends money, a person approves before it
 * lands. GuardLink joins them over the annotations alone (`reach_analysis`: can
 * minus may, and whether a gate covers an effect) and says so — the pure join
 * cannot see whether the code ever calls the gate, or whether a tool the code
 * registers has any declared reach at all. A code graph that implements the
 * reach-check contract can: it walks the call graph from each declared reach's
 * handler and answers five lists. This module reads that answer as an OPTIONAL
 * external input (`codegraph_reach_check`) and turns it into:
 *
 *   gate-not-on-route          the annotations say an effect is gated, and the
 *                              graph measured a route to it that passes through no gate
 *   effect-unreached-by-agent  a declared mutating effect no declared agent reach
 *                              leads to
 *   agent-tool-undeclared      a tool registration no @agents or @reaches covers
 *
 * plus draft `@agents` / `@effects` lines for the undeclared tools, the annotate
 * prompt's list of them, and a measured-route column for the report and dashboard.
 *
 * A CLAIM TO CHECK, NEVER EVIDENCE
 * Every diagnostic is a WARNING, worded as a question for a person. The call
 * graph is order-blind (a gate called after the effect still counts as on the
 * route) and a call its resolver declined looks exactly like a missing one, so
 * nothing here closes, demotes or raises a finding, and nothing changes what
 * GuardLink's own join said: `gated: true` stays true beside a measured bypass.
 * A verdict the graph withholds (`unknown`, with its reason) produces no warning
 * and is counted, never read as a pass or as a bypass.
 *
 * DRAFTS ARE PRINTED, NEVER WRITTEN
 * `reachDrafts` returns text. Nothing here writes a source file or the model, and
 * a draft never contains `@accepts` or `@entitles` — an entitlement is a human's
 * decision, proposed with `guardlink entitle --propose`. The actor and the asset
 * stay placeholders unless the model names exactly one agent actor.
 *
 * THE GRAPH IS OPTIONAL, ALWAYS
 * With no graph tooling, a graph that does not publish the query, a failed query
 * or the off switch, every function returns a status saying which and every
 * consumer prints exactly what it printed before. Nothing here throws.
 *
 * @flows #codegraph -> #cli via loadReachCheck -- "JSON answer to codegraph_reach_check: reach routes, effect gates, unreached effects, undeclared tools, orphan reaches"
 * @flows #cli -> #codegraph via loadReachCheck -- "Project root only; the query takes no caller-supplied argument"
 * @exposes #codegraph to #prompt-injection [low] cwe:CWE-77 -- "UndeclaredTool.tool, .kind, .framework and the sink examples are the graph's reading of the repository's source, and checkReach, reachDrafts and renderUndeclaredToolsBlock interpolate them into warning text, draft lines and the annotate prompt"
 * @mitigates #codegraph against #prompt-injection using #input-sanitize -- "token() admits a tool name onto an annotation line only if it is a plain token, quoted() drops quotes, control characters and anything past a length cap from graph text, oneLine() flattens names in prose; the prompt block labels the list a place to look, not a finding"
 * @comment -- "Reads the same graph process as loadWorklist, through the same transport and limits (timeout, output cap, argv without a shell); a draft is text on stdout and never reaches a file"
 */
import type { ThreatModel, ParseDiagnostic } from '../types/index.js';
import { ask, type CodeGraphOptions, type StatusFields } from './index.js';

// ─── Constants ───────────────────────────────────────────────────────

export const TOOL_REACH_CHECK = 'codegraph_reach_check';

/** The contract version this reader understands; the name before it is the graph's. */
const CONTRACT_VERSION = /reach-check\/v1$/;

/** How many tools the annotate prompt lists before pointing at `guardlink reach --drafts`. */
export const PROMPT_UNDECLARED_ROWS = 15;
/** How many hops of a path a warning quotes. */
const PATH_HOPS = 6;

/** What every surface that draws a measurement says it is. */
export const MEASURED_LABEL = 'Code-graph measurement: a reading of the call graph beside the annotations, order-blind and blind to calls its resolver declined — a claim to check, never evidence.';

// ─── The answer ──────────────────────────────────────────────────────

export interface ClaimRef { file: string; line: number; claim_key: string }

export interface ReachedEffect {
  claim: ClaimRef;
  effect: string;
  mutating: boolean;
  asset: string;
  declared_gating: string;
  depth: number | null;
}

/** One declared `@agents`/`@reaches` and what its handler reaches. */
export interface ReachRoute {
  claim: ClaimRef;
  verb: string;
  actor: string;
  capability: string;
  asset: string;
  /** The tool registration the walk started from, when the graph bound one. */
  tool: string;
  /** measured | no_route | unknown */
  verdict: string;
  unknown_reason: string;
  effects: ReachedEffect[];
}

export interface CoveringGate { claim: ClaimRef; approver: string }

/** One (agent reach, mutating effect) pair: GuardLink's verdict, copied, and the graph's. */
export interface EffectGate {
  effect: ClaimRef;
  effect_kind: string;
  asset: string;
  reach: ClaimRef;
  capability: string;
  declared_gating: string;
  declared_gates: CoveringGate[];
  /** on_every_route | bypassed | no_gate_declared | unknown */
  measured: string;
  reason: string;
  path: string[];
  /** Set when a bypass was withheld because a path declined a call named like the gate. */
  withheld: string;
}

export interface UnreachedEffect {
  effect: ClaimRef;
  effect_kind: string;
  asset: string;
  declared_gating: string;
  /** unreached | unknown */
  state: string;
  reason: string;
  reached_by_other_principals: ClaimRef[];
}

export interface SinkHint { class: string; example: string }

export interface UndeclaredTool {
  /** The tool's registered name; '' when the graph could not read one. */
  tool: string;
  kind: string;
  framework: string;
  file: string;
  line: number;
  /** Whether the graph walked the handler for sinks: `SinksReached`, `NoSinksReached`, or why not. */
  hint_state: string;
  sink_classes: SinkHint[];
  /** Effect words a person may write, as candidates. */
  effect_hints: string[];
}

export interface OrphanReach { claim: ClaimRef; actor: string; capability: string }

export interface ReachCheck extends StatusFields {
  /** checked | insufficient_resolution | no_reach_declared | '' */
  verdict: string;
  verdict_note: string;
  joins: { state: string; freshness: string; reason: string; detail: string };
  coverage_note: string;
  routes: ReachRoute[];
  gates: EffectGate[];
  unreached: UnreachedEffect[];
  undeclared: UndeclaredTool[];
  orphans: OrphanReach[];
}

function empty(s: StatusFields): ReachCheck {
  return {
    ...s, verdict: '', verdict_note: '', coverage_note: '',
    joins: { state: '', freshness: '', reason: '', detail: '' },
    routes: [], gates: [], unreached: [], undeclared: [], orphans: [],
  };
}

/** Is the answer one a consumer may use? The graph answered, in a version this reader knows. */
export function reachCheckUsable(rc: ReachCheck | null | undefined): rc is ReachCheck {
  return !!rc && rc.status === 'available';
}

// ─── Reading the answer ──────────────────────────────────────────────

const str = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : String(v));
const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const list = (v: unknown): any[] => (Array.isArray(v) ? v : []);
const norm = (file: string): string => file.replace(/\\/g, '/').replace(/^\.\//, '');

function claim(c: any): ClaimRef {
  return { file: norm(str(c?.file)), line: num(c?.line), claim_key: str(c?.claim_key) };
}

function buildReachCheck(s: StatusFields, doc: any): ReachCheck {
  const rc = empty(s);
  rc.verdict = str(doc?.verdict);
  rc.verdict_note = str(doc?.verdict_note);
  rc.coverage_note = str(doc?.coverage_note);
  const j = doc?.joins ?? {};
  rc.joins = { state: str(j.state), freshness: str(j.freshness), reason: str(j.reason), detail: str(j.detail) };

  rc.routes = list(doc?.reach_routes).filter(r => r?.claim?.file).map((r): ReachRoute => ({
    claim: claim(r.claim),
    verb: str(r.verb), actor: str(r.actor), capability: str(r.capability), asset: str(r.asset),
    tool: str(r.start?.tool),
    verdict: str(r.verdict), unknown_reason: str(r.unknown_reason),
    effects: list(r.effects).map((e): ReachedEffect => ({
      claim: claim(e?.claim), effect: str(e?.effect), mutating: e?.mutating === true, asset: str(e?.asset),
      declared_gating: str(e?.declared_gating), depth: typeof e?.depth === 'number' ? e.depth : null,
    })),
  }));

  rc.gates = list(doc?.effect_gates).filter(g => g?.effect?.file).map((g): EffectGate => ({
    effect: claim(g.effect), effect_kind: str(g.effect_kind), asset: str(g.asset),
    reach: claim(g.reach), capability: str(g.capability),
    declared_gating: str(g.declared?.gating),
    declared_gates: list(g.declared?.gates).map((x): CoveringGate => ({ claim: claim(x?.claim), approver: str(x?.approver) })),
    measured: str(g.measured?.verdict), reason: str(g.measured?.reason),
    path: list(g.measured?.path).map(str).filter(Boolean),
    withheld: g.measured?.withheld ? `${str(g.measured.withheld.kind)} ${str(g.measured.withheld.call)}`.trim() : '',
  }));

  rc.unreached = list(doc?.unreached_effects).filter(u => u?.effect?.file).map((u): UnreachedEffect => ({
    effect: claim(u.effect), effect_kind: str(u.effect_kind), asset: str(u.asset),
    declared_gating: str(u.declared_gating), state: str(u.state), reason: str(u.reason),
    reached_by_other_principals: list(u.reached_by_other_principals).map(claim),
  }));

  rc.undeclared = list(doc?.undeclared_tools).filter(t => t?.file).map((t): UndeclaredTool => ({
    tool: str(t.tool), kind: oneLine(str(t.kind)), framework: oneLine(str(t.framework)), file: norm(str(t.file)), line: num(t.line),
    hint_state: str(t.hints?.state),
    sink_classes: list(t.hints?.sink_classes).map((c): SinkHint => ({ class: str(c?.class), example: str(c?.example) })),
    effect_hints: list(t.hints?.effect_hints).map(str).filter(Boolean),
  }));

  rc.orphans = list(doc?.orphan_reaches).filter(o => o?.claim?.file).map((o): OrphanReach => ({
    claim: claim(o.claim), actor: str(o.actor), capability: str(o.capability),
  }));
  return rc;
}

/**
 * Ask the installed code graph to check the declared reach. One call, over the
 * same transport and under the same limits as the entry-point worklist. A graph
 * that does not publish the query is `unsupported`, which every consumer treats
 * as "no graph". Never throws.
 */
export async function loadReachCheck(root: string, opts: CodeGraphOptions = {}): Promise<ReachCheck> {
  const asked = await ask(root, [{ tool: TOOL_REACH_CHECK, args: {}, optional: true }], opts);
  if (asked.status !== 'available' || !asked.answers) return empty(asked);
  const answer = asked.answers[0];
  const base: StatusFields = { status: 'available', via: asked.via, note: '' };
  if (!answer || !answer.ok) {
    if (!answer || answer.unsupported) {
      return empty({ ...base, status: 'unsupported', note: `the installed code graph does not answer ${TOOL_REACH_CHECK}; a graph build that publishes it is needed` });
    }
    return empty({ ...base, status: 'error', note: `${TOOL_REACH_CHECK} failed: ${answer.message.slice(0, 300)}` });
  }
  try {
    const doc = answer.value ?? {};
    const contract = str(doc.check);
    if (contract && !CONTRACT_VERSION.test(contract)) {
      return empty({ ...base, status: 'unsupported', note: `${TOOL_REACH_CHECK} answered in a version this GuardLink does not read (${contract.slice(0, 80)})` });
    }
    return buildReachCheck(base, doc);
  } catch (e) {
    return empty({ ...base, status: 'error', note: `unreadable code graph answer: ${String((e as Error)?.message ?? e).slice(0, 300)}` });
  }
}

// ─── Diagnostics ─────────────────────────────────────────────────────

const route = (path: string[]): string => {
  const shown = path.slice(0, PATH_HOPS).join(' → ');
  return path.length > PATH_HOPS ? `${shown} → … (${path.length} nodes)` : shown;
};

function approvers(g: EffectGate): string {
  return [...new Set(g.declared_gates.map(x => x.approver).filter(Boolean))].join(', ');
}

/**
 * Compare the declared reach with the graph's measurement. Empty when the graph
 * gave no usable answer. Every diagnostic is a warning about a claim to check.
 */
export function checkReach(rc: ReachCheck | null | undefined): ParseDiagnostic[] {
  if (!reachCheckUsable(rc)) return [];
  const out: ParseDiagnostic[] = [];

  for (const g of rc.gates) {
    if (g.measured !== 'bypassed') continue;
    const by = approvers(g);
    out.push({
      level: 'warning', code: 'gate-not-on-route', file: g.effect.file, line: g.effect.line,
      message: `The annotations say the ${g.effect_kind} on ${g.asset} is gated${by ? ` by ${by}` : ''}, but the code graph measured a route from the ${g.capability || 'declared'} reach at ${g.reach.file}:${g.reach.line} to it that passes through no gate: ${route(g.path) || 'no path given'}. `
        + 'The graph is order-blind and can miss a call, so this is a claim to check, not a finding — confirm in the code whether the gate is called on every path, or correct the @gates',
    });
  }

  for (const u of rc.unreached) {
    if (u.state !== 'unreached') continue;
    const others = u.reached_by_other_principals.length > 0
      ? ` (principals declared with @reaches do reach it: ${u.reached_by_other_principals.map(c => `${c.file}:${c.line}`).join(', ')})`
      : '';
    out.push({
      level: 'warning', code: 'effect-unreached-by-agent', file: u.effect.file, line: u.effect.line,
      message: `The ${u.effect_kind} on ${u.asset} is declared, but the code graph finds no route to it from any declared agent reach${others}. `
        + 'Either an agent can reach it through a tool that carries no @agents, or the effect is not agent-reachable and the annotation is stale — a claim to check, not a finding',
    });
  }

  for (const t of rc.undeclared) {
    const name = t.tool ? `\`${oneLine(t.tool)}\`` : 'a tool';
    const hint = t.effect_hints.length > 0 ? ` Its handler reaches ${t.sink_classes.map(c => c.class).join(', ')}, so an @effects (${t.effect_hints.join(' or ')}) may be missing too.` : '';
    out.push({
      level: 'warning', code: 'agent-tool-undeclared', file: t.file, line: t.line,
      message: `The code graph finds ${name} registered here (${t.kind}${t.framework ? `, ${t.framework}` : ''}), and no @agents or @reaches covers it, so the model does not say which agent holds it or what it may do.${hint} `
        + '`guardlink reach --drafts` prints a draft to review; the graph can miss a registration, and this one may be dead code — a claim to check, not a finding',
    });
  }
  return out;
}

/**
 * One stderr line saying what the graph contributed to the reach checks. Empty
 * when there was no graph to ask (off, not installed, not built, or one that does
 * not publish the query): the boundary checks beside it already say so, and a
 * run without a graph prints what it always printed. A query that failed on a
 * graph that is there is said.
 */
export function reachCheckSummaryLine(rc: ReachCheck, diagnostics: ParseDiagnostic[]): string {
  if (rc.status === 'error') return `Reach checks: not run — ${rc.note}`;
  if (rc.status !== 'available') return '';
  const parts: string[] = [`${rc.routes.length} declared reach(es) walked`, `${rc.undeclared.length} undeclared tool(s)`, `${diagnostics.length} warning(s)`];
  const withheld = rc.gates.filter(g => g.measured === 'unknown').length;
  const notes: string[] = [];
  if (rc.joins.state === 'unavailable') {
    notes.push(`gate routes not checked (${rc.joins.detail || rc.joins.reason || 'the model export is missing or stale'})`);
  } else if (withheld > 0) {
    notes.push(`${withheld} gate route(s) left unknown`);
  }
  if (rc.verdict === 'insufficient_resolution') notes.push('some routes left unknown: the graph resolved too few calls there');
  return `Reach checks (code graph via ${rc.via}): ${parts.join(', ')}${notes.length ? `; ${notes.join('; ')}` : ''}`;
}

// ─── Drafts ──────────────────────────────────────────────────────────

export interface ReachDraft {
  tool: string;
  kind: string;
  framework: string;
  file: string;
  line: number;
  /** Annotation lines to review. Never written anywhere by GuardLink. */
  lines: string[];
  /** Why there is no `@effects` candidate, when there is none. */
  note: string;
}

/** A name safe to put on an annotation line: a plain token, or nothing. */
function token(name: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/.test(name) ? name : '';
}

/** Graph text quoted into a description: no quote, no control character, bounded. */
function quoted(text: string, max = 120): string {
  return text.replace(/[\p{Cc}"\\]/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** A repository-supplied name in a sentence: one line, control characters gone, bounded. */
function oneLine(text: string, max = 80): string {
  return text.replace(/\p{Cc}/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** The one agent actor the model declares by hand, or null when there are none or several. */
function soleAgent(model: ThreatModel | null | undefined): string | null {
  const actors = new Set<string>();
  for (const r of model?.reaches ?? []) if (r.agent && !r.origin) actors.add(r.actor);
  return actors.size === 1 ? [...actors][0] : null;
}

/**
 * Draft `@agents` and `@effects` lines for each undeclared tool. Text only: the
 * caller prints it. The actor is the model's one hand-declared agent when there
 * is exactly one, and a placeholder otherwise; the asset is always a placeholder,
 * because which asset a tool acts on is the reviewer's call.
 */
export function reachDrafts(rc: ReachCheck | null | undefined, model?: ThreatModel | null): ReachDraft[] {
  if (!reachCheckUsable(rc)) return [];
  const actor = soleAgent(model) ?? '<agent>';
  return rc.undeclared.map((t): ReachDraft => {
    const cap = token(t.tool) || '<tool>';
    const lines = [`@agents ${actor} to ${cap} on <asset> -- "${quoted(`${t.kind}${t.framework ? ` registered with ${t.framework}` : ''}; confirm which agent holds it and what it may do`)}"`];
    let note = '';
    if (t.effect_hints.length > 0) {
      const example = t.sink_classes.find(c => c.example)?.example ?? '';
      for (const word of t.effect_hints) {
        lines.push(`@effects ${word} on <asset> -- "${quoted(`candidate: the handler reaches ${t.sink_classes.map(c => c.class).join(', ') || 'a classified sink'}${example ? ` (e.g. ${example})` : ''}; keep it only if it is true`)}"`);
      }
    } else if (t.hint_state === 'NoSinksReached') {
      note = 'the graph walked the handler and reached no classified sink, so no @effects candidate';
    } else {
      note = `no @effects candidate (${t.hint_state || 'the graph gave no hint'}); read the handler`;
    }
    return { tool: t.tool, kind: t.kind, framework: t.framework, file: t.file, line: t.line, lines, note };
  });
}

/** The drafts as the text `guardlink reach --drafts` prints. */
export function renderDrafts(drafts: ReachDraft[]): string {
  if (drafts.length === 0) return 'No agent tool registration without a declared reach.';
  const out: string[] = [
    `${drafts.length} agent tool registration(s) the code graph finds with no @agents or @reaches.`,
    'Drafts for review. Nothing is written: fill in each <placeholder>, keep an @effects only if it is true, and put what you keep in the doc-block of the code it describes.',
    'GuardLink never drafts @accepts or @entitles — an entitlement is a person\'s decision (`guardlink entitle --propose`).',
  ];
  for (const d of drafts) {
    out.push('', `${d.file}:${d.line}  ${token(d.tool) || '(name not a plain token; read the source)'}  (${oneLine(d.kind)}${d.framework ? `, ${oneLine(d.framework)}` : ''})`);
    for (const l of d.lines) out.push(`  ${l}`);
    if (d.note) out.push(`  # ${d.note}`);
  }
  return out.join('\n');
}

// ─── The annotate prompt ─────────────────────────────────────────────

/**
 * The annotate-prompt section listing agent tools with no declared reach, or ''
 * when the graph contributed none — so a prompt built without a graph is
 * byte-identical to the one built before this module.
 */
export function renderUndeclaredToolsBlock(rc: ReachCheck | null | undefined, rows = PROMPT_UNDECLARED_ROWS): string {
  if (!reachCheckUsable(rc) || rc.undeclared.length === 0) return '';
  const shown = rc.undeclared.slice(0, Math.max(0, rows));
  const lines: string[] = [
    '## Agent tools with no declared reach',
    `A code graph of this repository (via ${rc.via}) finds ${rc.undeclared.length} tool registration(s) an LLM agent can call that no \`@agents\` or \`@reaches\` covers. `
    + 'Read each handler, then write `@agents` on the registration, `@effects` on the code that acts and `@gates` on any approval step that really exists. '
    + 'A listed tool is a place to look, not a finding: the graph can miss that a registration is dead code. Do not write `@accepts` or `@entitles`.',
    '',
  ];
  for (const t of shown) {
    const reaches = t.sink_classes.length > 0 ? ` — handler reaches ${t.sink_classes.map(c => c.class).join(', ')}${t.effect_hints.length ? ` (candidate @effects: ${t.effect_hints.join(' or ')})` : ''}` : '';
    lines.push(`- ${t.file}:${t.line} ${oneLine(t.tool) || '(unnamed tool)'} (${t.kind})${reaches}`);
  }
  if (rc.undeclared.length > shown.length) lines.push(`- ${rc.undeclared.length - shown.length} more; \`guardlink reach --drafts\` lists them all.`);
  return lines.join('\n');
}

// ─── The measured route, for the report and the dashboard ────────────

export interface MeasuredRouteRow {
  file: string;
  line: number;
  actor: string;
  capability: string;
  asset: string;
  /** measured | no_route | unknown | not_measured */
  route: string;
  /** One line a person can read: what the graph measured. */
  text: string;
  /** One line per mutating effect on the route: GuardLink's gating beside the graph's. */
  gates: string[];
}

const locKey = (file: string, line: number): string => `${norm(file)}:${line}`;

function routeText(r: ReachRoute | undefined): { route: string; text: string } {
  if (!r) return { route: 'not_measured', text: 'not measured' };
  switch (r.verdict) {
    case 'measured': {
      const names = [...new Set(r.effects.map(e => `${e.effect} on ${e.asset}`))];
      return { route: 'measured', text: `reaches ${names.join(', ') || 'a declared effect'}` };
    }
    case 'no_route': return { route: 'no_route', text: 'no route to a declared effect' };
    default: return { route: 'unknown', text: `unknown${r.unknown_reason ? ` (${r.unknown_reason})` : ''}` };
  }
}

/**
 * The measured route of each hand-declared reach in the model, in model order.
 * Empty when the graph gave no usable answer, so the section it feeds is absent
 * and the document is exactly what it was without a graph. A reach the graph did
 * not return reads `not measured`; one the graph returned that the model does not
 * hold is dropped (a stale graph, or a feature slice).
 */
export function measuredRoutes(model: ThreatModel, rc: ReachCheck | null | undefined): MeasuredRouteRow[] {
  if (!reachCheckUsable(rc)) return [];
  const byLoc = new Map(rc.routes.map(r => [locKey(r.claim.file, r.claim.line), r] as const));
  const gatesByReach = new Map<string, EffectGate[]>();
  for (const g of rc.gates) {
    const k = locKey(g.reach.file, g.reach.line);
    gatesByReach.set(k, [...(gatesByReach.get(k) ?? []), g]);
  }
  return (model.reaches ?? []).filter(r => !r.origin).map((r): MeasuredRouteRow => {
    const k = locKey(r.location.file, r.location.line);
    const { route: verdict, text } = routeText(byLoc.get(k));
    return {
      file: norm(r.location.file), line: r.location.line, actor: r.actor, capability: r.capability, asset: r.asset ?? '',
      route: verdict, text,
      gates: (gatesByReach.get(k) ?? []).map(g => {
        const why = g.measured === 'unknown' ? ` (${g.reason || 'unknown'})` : '';
        return `${g.effect_kind} on ${g.asset}: declared ${g.declared_gating || 'unknown'}, graph ${g.measured.replace(/_/g, ' ')}${why}`;
      }),
    };
  });
}
