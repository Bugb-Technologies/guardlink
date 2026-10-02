/**
 * GuardLink — what each agent and principal can reach, as one derived view.
 *
 * The dashboard's Agents page and the report's "Agents and LLM Reach" section
 * draw the same pictures: the reach map (actor × asset, with the capability and
 * the effect in each cell), the unentitled reaches, the ungated mutations, the
 * gates, the egress, and the OWASP LLM Top 10 items those add up to. This
 * module computes them once so the two surfaces cannot disagree, and it adds no
 * join of its own: can-minus-may and effects-against-gates both come from
 * `parser/reach.ts`, which `lookup` and `diff` answer from too.
 *
 * ── What it can and cannot tie together ─────────────────────────────
 *
 * An effect lands in an actor's row only where the annotations connect them:
 * the effect and the actor's `@agents`/`@reaches` are bound to the same code
 * (`boundCode`, one doc-block on one declaration). Whether that effect is gated
 * is `classifyEffects`, the join `reach_analysis` and the SARIF export use. An
 * effect reached through calls across handlers has no declared route; it is
 * listed under "not tied to a reach" rather than placed in a row the model
 * never drew.
 *
 * The OWASP mapping (2025 list) keys on `@agents` only, as SPEC §3.2.1 says
 * agent-only checks do:
 *
 *   - LLM06 Excessive Agency — functionality: an unentitled `@agents`;
 *     permissions: an effect running under a different identity than the agent
 *     presents, with no gate between; autonomy: a mutation the agent reaches
 *     with no `@gates` in front of it.
 *   - LLM01 Prompt Injection — input from outside the model (a `@flows` source
 *     that is neither a declared asset nor an actor, with nothing flowing into
 *     it) that reaches an agent which has an ungated mutation.
 *   - LLM05 Improper Output Handling — a write, delete, execute or notify bound
 *     to the same code as the agent's tool registration, so model-written
 *     arguments reach it directly.
 *
 * Each is a target for review or test, never a finding the model has proved.
 *
 * @comment -- "Pure functions over an assembled ThreatModel; no I/O and no input surface. Every row keeps the file:line of the annotation it came from, so each picture can be traced back to source"
 */
import type { ThreatModel, ThreatModelReach, EffectClass, SourceLocation } from '../types/index.js';
import {
  actorResolver, boundCode, findUnentitledReaches, classifyEffects, isMutatingEffect,
  type EffectGating, type GateCoverBlocker, type ReachCoverBlocker,
} from '../parser/reach.js';
import { canonicaliser } from '../parser/canonical-ref.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';

export interface ReachLoc { file: string; line: number }

export interface ReachActorRow {
  /** Resolved identity: the declared id, or the bare ref when undeclared. */
  key: string;
  /** How to write it: `#id` when declared with one, else the name as written. */
  ref: string;
  name: string;
  description?: string;
  /** Named by some `@agents`. */
  agent: boolean;
  /** Declared with `@actor`. */
  declared: boolean;
  reaches: number;
  unentitled: number;
  /** Mutations this actor reaches with no gate in front of its route. */
  ungated: number;
  /** `@gates` naming this actor as the approver. */
  approves: number;
  loc?: ReachLoc;
}

export interface ReachColumn { key: string; ref: string; declared: boolean }

export interface ReachCapabilityChip {
  capability: string;
  entitled: boolean;
  identity?: string;
  loc: ReachLoc;
}

export interface ReachEffectChip {
  effect: EffectClass;
  mutating: boolean;
  /** Null for a read: a gate question only arises for a mutation. */
  gated: boolean | null;
  approvers: string[];
  /** This row's actor's capabilities bound to the same code as the effect; empty in the "not tied to a reach" row. */
  via: string[];
  identity?: string;
  loc: ReachLoc;
}

export interface ReachCell {
  actor: string;
  asset: string;
  capabilities: ReachCapabilityChip[];
  effects: ReachEffectChip[];
}

export interface LooseEffects { asset: string; effects: ReachEffectChip[] }

export interface NearMissRow {
  blocker: ReachCoverBlocker;
  /** The blocker as a sentence a reviewer can act on. */
  reason: string;
  asset?: string;
  citation?: string;
  loc: ReachLoc;
}

export interface UnentitledRow {
  actor: string;
  agent: boolean;
  capability: string;
  asset?: string;
  identity?: string;
  description?: string;
  loc: ReachLoc;
  near_misses: NearMissRow[];
}

export interface UngatedRow {
  effect: EffectClass;
  asset: string;
  identity?: string;
  description?: string;
  loc: ReachLoc;
  /** Reaches bound to the same code; empty when none is. */
  via: { actor: string; agent: boolean; capability: string }[];
  /** Gates on the asset that still do not cover it, and why. */
  gate_near_misses: { approver: string; capability?: string; blocker: GateCoverBlocker; reason: string }[];
  /** True when some agent reaches it. */
  agent: boolean;
}

export interface GateRow {
  asset: string;
  approver: string;
  capability?: string;
  description?: string;
  loc: ReachLoc;
  /** The mutations this gate stands in front of. */
  covers: { effect: EffectClass; asset: string; loc: ReachLoc }[];
}

export interface EgressRow {
  actors: string[];
  source: string;
  target: string;
  mechanism?: string;
  /** The target is no declared asset: the data leaves the model. */
  external: boolean;
  /** Ids of the `@boundary` declared on this hop. */
  boundaries: string[];
  description?: string;
  loc: ReachLoc;
}

export interface InjectionRoute {
  entry: string;
  /** Labels from the entry to the agent's surface, as the `@flows` spell them. */
  chain: string[];
  agent: string;
  /** The hops, each with the `@flows` it came from. */
  hops: ReachLoc[];
  effects: { effect: EffectClass; asset: string; loc: ReachLoc }[];
}

export type OwaspId = 'LLM01' | 'LLM05' | 'LLM06';

export interface OwaspItem {
  /** The part of the OWASP definition this row is evidence for. */
  facet: string;
  agent: string;
  text: string;
  loc: ReachLoc;
}

export interface OwaspRow {
  id: OwaspId;
  title: string;
  /** What GuardLink looks for, in one sentence. */
  basis: string;
  items: OwaspItem[];
}

export interface ReachSummary {
  /** Every actor that is declared, reaches something, or approves something. Agents first. */
  actors: ReachActorRow[];
  /** Assets the reach map has a column for: named by a reach or an effect. */
  columns: ReachColumn[];
  /** Non-empty cells of the reach map. */
  cells: ReachCell[];
  /** Effects no reach is tied to, per asset. */
  loose: LooseEffects[];
  unentitled: UnentitledRow[];
  ungated: UngatedRow[];
  gates: GateRow[];
  egress: EgressRow[];
  injection: InjectionRoute[];
  owasp: OwaspRow[];
  totals: {
    agents: number; principals: number; reaches: number; unentitled: number;
    effects: number; mutations: number; ungated: number; gates: number; egress: number; injection: number;
  };
}

const loc = (l: SourceLocation): ReachLoc => ({ file: l.file, line: l.line });

const GATE_MISS_REASON: Record<GateCoverBlocker, string> = {
  'capability-unknown': 'the gate is for one capability, and no reach on this code says which capability gets here',
  'other-capability': 'the gate is for another capability than the one bound to this code',
};

/**
 * PR-local view of `classifyEffects`: the effect, whether it mutates, the
 * reaches bound to its code, and whether a gate covers it.
 */
interface Gated extends EffectGating { mutating: boolean; gated: boolean }

const NEAR_MISS_REASON: Record<ReachCoverBlocker, string> = {
  uncited: 'the entitlement cites no authorization code, so it covers nothing',
  'no-asset': 'the entitlement names no asset, and this reach names one',
  'other-asset': 'the entitlement is for another asset',
};

/** True when the model carries any reach annotation at all. */
export function hasReach(model: ThreatModel): boolean {
  return (model.reaches ?? []).length > 0 || (model.effects ?? []).length > 0 || (model.gates ?? []).length > 0;
}

export function summarizeReach(rawModel: ThreatModel): ReachSummary {
  // Rows come out in model order, and parse order follows the file walk.
  const model = canonicalizeModelOrder(rawModel);
  const actorKey = actorResolver(model);
  const assetKey = canonicaliser(model);
  const reaches = model.reaches ?? [];
  const gating: Gated[] = classifyEffects(model).map(g => {
    const mutating = isMutatingEffect(g.effect.effect);
    return { ...g, mutating, gated: mutating && g.gates.length > 0 };
  });
  const unentitledReaches = findUnentitledReaches(model);
  const unentitledSet = new Set(unentitledReaches.map(u => u.reach));

  // ── Display labels ──
  const assetRef = new Map<string, { ref: string; declared: boolean }>();
  for (const a of model.assets ?? []) {
    const k = assetKey(a.id || a.path.join('.'));
    assetRef.set(k, { ref: a.id ? `#${a.id}` : a.path.join('.'), declared: true });
  }
  const assetLabel = (ref: string): string => assetRef.get(assetKey(ref))?.ref ?? ref;

  const actorRows = new Map<string, ReachActorRow>();
  for (const ac of model.actors ?? []) {
    const key = actorKey(ac.id ? `#${ac.id}` : ac.name);
    actorRows.set(key, {
      key, ref: ac.id ? `#${ac.id}` : ac.name, name: ac.name, description: ac.description,
      agent: false, declared: true, reaches: 0, unentitled: 0, ungated: 0, approves: 0, loc: loc(ac.location),
    });
  }
  const actorRow = (ref: string): ReachActorRow => {
    const key = actorKey(ref);
    let row = actorRows.get(key);
    if (!row) {
      row = { key, ref, name: ref.replace(/^#/, ''), agent: false, declared: false, reaches: 0, unentitled: 0, ungated: 0, approves: 0 };
      actorRows.set(key, row);
    }
    return row;
  };
  const actorLabel = (ref: string): string => actorRow(ref).ref;

  for (const r of reaches) {
    const row = actorRow(r.actor);
    row.reaches++;
    if (r.agent) row.agent = true;
    if (unentitledSet.has(r)) row.unentitled++;
  }
  for (const g of model.gates ?? []) actorRow(g.approver).approves++;

  // ── Reach map ──
  const columns: ReachColumn[] = [];
  const seenCol = new Set<string>();
  const colRef = new Map<string, string>();
  for (const r of reaches) if (r.asset && !colRef.has(assetKey(r.asset))) colRef.set(assetKey(r.asset), assetLabel(r.asset));
  for (const e of model.effects ?? []) if (!colRef.has(assetKey(e.asset))) colRef.set(assetKey(e.asset), assetLabel(e.asset));
  const addColumn = (k: string) => {
    if (seenCol.has(k)) return;
    seenCol.add(k);
    columns.push({ key: k, ref: colRef.get(k) ?? k, declared: assetRef.get(k)?.declared ?? false });
  };

  const cells = new Map<string, ReachCell>();
  const cell = (actor: string, asset: string): ReachCell => {
    const k = `${actor}\u0000${asset}`;
    let c = cells.get(k);
    if (!c) { c = { actor, asset, capabilities: [], effects: [] }; cells.set(k, c); }
    return c;
  };
  for (const r of reaches) {
    if (!r.asset) continue;
    cell(actorKey(r.actor), assetKey(r.asset)).capabilities.push({
      capability: r.capability, entitled: !unentitledSet.has(r), identity: r.identity, loc: loc(r.location),
    });
  }

  const approversOf = (g: EffectGating) => [...new Set(g.gates.map(x => actorLabel(x.approver)))];
  const loose = new Map<string, ReachEffectChip[]>();
  for (const g of gating) {
    const e = g.effect;
    if (g.colocated_reaches.length === 0) {
      const list = loose.get(assetKey(e.asset)) ?? [];
      list.push({
        effect: e.effect, mutating: g.mutating, gated: g.mutating ? g.gated : null, approvers: approversOf(g),
        via: [], identity: e.identity, loc: loc(e.location),
      });
      loose.set(assetKey(e.asset), list);
      continue;
    }
    // One chip per actor whose reach is bound to the effect's code.
    const byActor = new Map<string, ThreatModelReach[]>();
    for (const r of g.colocated_reaches) {
      const k = actorKey(r.actor);
      byActor.set(k, [...(byActor.get(k) ?? []), r]);
    }
    for (const [actor, rs] of byActor) {
      if (g.mutating && !g.gated) actorRows.get(actor)!.ungated++;
      cell(actor, assetKey(e.asset)).effects.push({
        effect: e.effect, mutating: g.mutating, gated: g.mutating ? g.gated : null,
        approvers: approversOf(g), via: [...new Set(rs.map(r => r.capability))],
        identity: e.identity, loc: loc(e.location),
      });
    }
  }

  // ── Lists ──
  const unentitled: UnentitledRow[] = unentitledReaches.map(({ reach: r, near_misses }) => ({
    actor: actorLabel(r.actor), agent: r.agent, capability: r.capability,
    asset: r.asset ? assetLabel(r.asset) : undefined, identity: r.identity, description: r.description,
    loc: loc(r.location),
    near_misses: near_misses.map(n => ({
      blocker: n.blocker, reason: NEAR_MISS_REASON[n.blocker],
      asset: n.entitlement.asset ? assetLabel(n.entitlement.asset) : undefined,
      citation: n.entitlement.citation?.raw, loc: loc(n.entitlement.location),
    })),
  }));

  const ungated: UngatedRow[] = gating.filter(g => g.mutating && !g.gated).map(g => ({
    effect: g.effect.effect, asset: assetLabel(g.effect.asset), identity: g.effect.identity,
    description: g.effect.description, loc: loc(g.effect.location),
    via: g.colocated_reaches.map(r => ({ actor: actorLabel(r.actor), agent: r.agent, capability: r.capability })),
    gate_near_misses: g.near_misses.map(n => ({
      approver: actorLabel(n.gate.approver), capability: n.gate.capability, blocker: n.blocker, reason: GATE_MISS_REASON[n.blocker],
    })),
    agent: g.colocated_reaches.some(r => r.agent),
  }));

  const gates: GateRow[] = (model.gates ?? []).map(gate => ({
    asset: assetLabel(gate.asset), approver: actorLabel(gate.approver), capability: gate.capability,
    description: gate.description, loc: loc(gate.location),
    covers: gating
      .filter(g => g.mutating && g.gates.includes(gate))
      .map(g => ({ effect: g.effect.effect, asset: assetLabel(g.effect.asset), loc: loc(g.effect.location) })),
  }));

  const egress = findEgress(model, reaches, actorKey, assetKey, actorLabel, assetLabel);
  const injection = findInjectionRoutes(model, gating, actorKey, assetKey, actorLabel, assetLabel);
  const owasp = mapOwasp(unentitled, gating, injection, actorKey, actorLabel, assetLabel);

  const actors = [...actorRows.values()].sort((a, b) =>
    Number(b.agent) - Number(a.agent) || Number(b.reaches > 0) - Number(a.reaches > 0) || a.ref.localeCompare(b.ref));
  // Columns read left to right in row order: each actor's surfaces, then what its tools do; loose effects last.
  const cellList = [...cells.values()];
  for (const a of actors) {
    for (const c of cellList) if (c.actor === a.key && c.capabilities.length > 0) addColumn(c.asset);
    for (const c of cellList) if (c.actor === a.key && c.capabilities.length === 0) addColumn(c.asset);
  }
  for (const k of loose.keys()) addColumn(k);
  const mutations = gating.filter(g => g.mutating).length;

  return {
    actors,
    columns,
    cells: cellList,
    loose: [...loose].map(([asset, effects]) => ({ asset, effects })),
    unentitled,
    ungated,
    gates,
    egress,
    injection,
    owasp,
    totals: {
      agents: actors.filter(a => a.agent).length,
      principals: actors.filter(a => !a.agent && a.reaches > 0).length,
      reaches: reaches.length,
      unentitled: unentitled.length,
      effects: gating.length,
      mutations,
      ungated: ungated.length,
      gates: gates.length,
      egress: egress.length,
      injection: injection.length,
    },
  };
}

type Resolve = (ref: string) => string;

const pairKey = (a: string, b: string): string => [a, b].sort().join('\u0000');

function boundaryIndex(model: ThreatModel, assetKey: Resolve): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const b of model.boundaries ?? []) {
    const k = pairKey(assetKey(b.asset_a), assetKey(b.asset_b));
    out.set(k, [...(out.get(k) ?? []), b.id ? `#${b.id}` : `${b.asset_a} ↔ ${b.asset_b}`]);
  }
  return out;
}

/**
 * Data a principal's surface sends out: a `@flows` from the actor, from an
 * asset it reaches, or bound to the same code as its reach, whose target
 * is no declared asset or whose hop is a declared `@boundary`.
 */
function findEgress(
  model: ThreatModel, reaches: ThreatModelReach[], actorKey: Resolve, assetKey: Resolve,
  actorLabel: Resolve, assetLabel: Resolve,
): EgressRow[] {
  const declared = new Set((model.assets ?? []).map(a => assetKey(a.id || a.path.join('.'))));
  const actorKeys = new Set((model.actors ?? []).map(a => actorKey(a.id ? `#${a.id}` : a.name)));
  const boundaries = boundaryIndex(model, assetKey);
  const out: EgressRow[] = [];
  for (const f of model.flows ?? []) {
    const src = assetKey(f.source);
    const tgt = assetKey(f.target);
    const crossed = boundaries.get(pairKey(src, tgt)) ?? [];
    const external = !declared.has(tgt) && !actorKeys.has(actorKey(f.target));
    if (!external && crossed.length === 0) continue;
    const code = boundCode(f.location);
    const who = new Set<string>();
    for (const r of reaches) {
      if (actorKey(f.source) === actorKey(r.actor)
        || (r.asset && assetKey(r.asset) === src)
        || (code && code === boundCode(r.location))) who.add(actorLabel(r.actor));
    }
    if (who.size === 0) continue;
    out.push({
      actors: [...who], source: assetLabel(f.source), target: assetLabel(f.target), mechanism: f.mechanism,
      external, boundaries: crossed, description: f.description, loc: loc(f.location),
    });
  }
  return out;
}

/**
 * Input from outside the model that reaches an agent with an ungated mutation.
 * Breadth-first over `@flows` from each entry — a source that is neither a
 * declared asset nor an actor, with nothing flowing into it — stopping at the
 * first node that is the agent or an asset it reaches.
 */
function findInjectionRoutes(
  model: ThreatModel, gating: Gated[], actorKey: Resolve, assetKey: Resolve,
  actorLabel: Resolve, assetLabel: Resolve,
): InjectionRoute[] {
  const actorIds = new Set((model.actors ?? []).map(a => actorKey(a.id ? `#${a.id}` : a.name)));
  for (const r of model.reaches ?? []) actorIds.add(actorKey(r.actor));
  // One node id per spelling: an actor resolves to its identity, anything else to its asset key.
  const node = (ref: string): string => (actorIds.has(actorKey(ref)) ? `actor:${actorKey(ref)}` : `asset:${assetKey(ref)}`);
  const declared = new Set((model.assets ?? []).map(a => `asset:${assetKey(a.id || a.path.join('.'))}`));
  const flows = model.flows ?? [];
  const inbound = new Set(flows.map(f => node(f.target)));
  const label = new Map<string, string>();
  for (const f of flows) {
    if (!label.has(node(f.source))) label.set(node(f.source), assetLabel(f.source));
    if (!label.has(node(f.target))) label.set(node(f.target), assetLabel(f.target));
  }
  const entries = [...new Set(flows.map(f => node(f.source)))]
    .filter(n => n.startsWith('asset:') && !declared.has(n) && !inbound.has(n));

  // Each agent's surface, and the ungated mutations it reaches.
  const agents = new Map<string, { surface: Set<string>; effects: InjectionRoute['effects'] }>();
  for (const r of model.reaches ?? []) {
    if (!r.agent) continue;
    const k = actorKey(r.actor);
    const a = agents.get(k) ?? { surface: new Set([`actor:${k}`]), effects: [] };
    if (r.asset) a.surface.add(`asset:${assetKey(r.asset)}`);
    agents.set(k, a);
  }
  for (const g of gating) {
    if (!g.mutating || g.gated) continue;
    for (const r of g.colocated_reaches) {
      const a = agents.get(actorKey(r.actor));
      if (!a || !r.agent) continue;
      if (!a.effects.some(e => e.loc.file === g.effect.location.file && e.loc.line === g.effect.location.line)) {
        a.effects.push({ effect: g.effect.effect, asset: assetLabel(g.effect.asset), loc: loc(g.effect.location) });
      }
    }
  }

  const out: InjectionRoute[] = [];
  for (const entry of entries) {
    const prev = new Map<string, { from: string; flow: ReachLoc }>();
    const seen = new Set([entry]);
    let frontier = [entry];
    const hit = new Map<string, string>();
    while (frontier.length > 0) {
      const next: string[] = [];
      for (const n of frontier) {
        for (const [k, a] of agents) if (!hit.has(k) && a.surface.has(n) && n !== entry) hit.set(k, n);
        for (const f of flows) {
          if (node(f.source) !== n || seen.has(node(f.target))) continue;
          seen.add(node(f.target));
          prev.set(node(f.target), { from: n, flow: loc(f.location) });
          next.push(node(f.target));
        }
      }
      frontier = next;
    }
    for (const [agent, at] of hit) {
      const a = agents.get(agent)!;
      if (a.effects.length === 0) continue;
      const chain: string[] = [];
      const hops: ReachLoc[] = [];
      for (let cur = at; ; cur = prev.get(cur)!.from) {
        chain.unshift(label.get(cur) ?? cur);
        if (!prev.has(cur)) break;
        hops.unshift(prev.get(cur)!.flow);
      }
      out.push({ entry: label.get(entry) ?? entry, chain, agent: actorLabel(agent), hops, effects: a.effects });
    }
  }
  return out;
}

const LLM05_EFFECTS = new Set<EffectClass>(['write', 'delete', 'execute', 'notify']);

function mapOwasp(
  unentitled: UnentitledRow[], gating: Gated[], injection: InjectionRoute[],
  actorKey: Resolve, actorLabel: Resolve, assetLabel: Resolve,
): OwaspRow[] {
  const llm06: OwaspItem[] = [];
  for (const u of unentitled.filter(x => x.agent)) {
    llm06.push({
      facet: 'functionality', agent: u.actor, loc: u.loc,
      text: `can ${u.capability}${u.asset ? ` on ${u.asset}` : ''} and no cited @entitles covers it`,
    });
  }
  for (const g of gating) {
    for (const r of g.colocated_reaches) {
      if (!r.agent) continue;
      const open = g.mutating && !g.gated;
      const e = g.effect;
      if (e.identity && r.identity && actorKey(e.identity) !== actorKey(r.identity) && (!g.mutating || open)) {
        llm06.push({
          facet: 'permissions', agent: actorLabel(r.actor), loc: loc(e.location),
          text: `${r.capability} presents ${r.identity}, and the ${e.effect} on ${assetLabel(e.asset)} runs as ${e.identity}${g.mutating ? ' with no gate between' : ''}`,
        });
      }
      if (open) {
        llm06.push({
          facet: 'autonomy', agent: actorLabel(r.actor), loc: loc(e.location),
          text: `${e.effect} on ${assetLabel(e.asset)} through ${r.capability}, with no @gates in front of it`,
        });
      }
    }
  }

  const llm01: OwaspItem[] = injection.map(route => ({
    facet: 'injection-to-tool route', agent: route.agent, loc: route.hops[0] ?? route.effects[0].loc,
    text: `input from ${route.chain.join(' → ')} reaches it, and it has ${route.effects.length} ungated ${route.effects.length === 1 ? 'mutation' : 'mutations'} (${route.effects.map(e => `${e.effect} on ${e.asset}`).join(', ')})`,
  }));

  const llm05: OwaspItem[] = [];
  for (const g of gating) {
    if (!LLM05_EFFECTS.has(g.effect.effect)) continue;
    for (const r of g.colocated_reaches) {
      if (!r.agent) continue;
      llm05.push({
        facet: 'model output into an effect', agent: actorLabel(r.actor), loc: loc(g.effect.location),
        text: `${r.capability} hands model-written arguments to a ${g.effect.effect} on ${assetLabel(g.effect.asset)} in the same code`,
      });
    }
  }

  const FACETS = ['functionality', 'permissions', 'autonomy'];
  llm06.sort((a, b) => FACETS.indexOf(a.facet) - FACETS.indexOf(b.facet));
  return [
    {
      id: 'LLM06', title: 'Excessive Agency',
      basis: 'Unentitled @agents (functionality), an effect running as a broader identity than the agent presents (permissions), and mutations with no @gates (autonomy).',
      items: llm06,
    },
    {
      id: 'LLM01', title: 'Prompt Injection',
      basis: 'Input from outside the model that @flows into an agent which can reach an ungated mutation.',
      items: llm01,
    },
    {
      id: 'LLM05', title: 'Improper Output Handling',
      basis: 'A write, delete, execute or notify bound to the same code as the agent\'s tool, so model output reaches it directly.',
      items: llm05,
    },
  ];
}
