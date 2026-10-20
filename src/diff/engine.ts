/**
 * GuardLink Diff Engine — Compare two threat models and produce a structured delta.
 *
 * Use cases:
 *   - `guardlink diff HEAD~1` → PR review: what changed in the threat model?
 *   - CI gate: fail if new unmitigated exposures were introduced
 *   - Audit trail: track threat model evolution over time
 *
 * Design:
 *   - Identity keys: assets by path/id, threats/controls by id/canonical_name,
 *     relationships by (asset, threat) or (source, target) composite keys
 *   - Delta categories: added, removed, modified (severity/description changed)
 *   - Risk delta: tracks net change in unmitigated exposure count
 *
 * @comment -- "Pure model-vs-model comparator; no I/O. Entitlement staleness is the one thing it cannot derive from the two models, so the changed-file list is passed in by the caller (see getChangedFiles in git.ts)"
 * @flows ThreatModel -> #diff via diffModels -- "Before/after models compared into a structured delta"
 * @comment -- "Rows generated from agent configuration are diffed apart from annotations: new and removed grants, new bypass modes, new hooks and servers, and a same-named MCP server whose launch changed"
 * @comment -- "A reach that becomes unentitled is reported on its own, like a new unmitigated exposure: newUnentitledReaches comes from findUnentitledReaches, the join lookup answers with"
 */
import { buildReachAttestation, type AttestationRow } from '../attest/index.js';


import type {
  ThreatModel,
  ThreatModelAsset, ThreatModelThreat, ThreatModelControl, ThreatModelActor,
  ThreatModelMitigation, ThreatModelExposure, ThreatModelConfirmed, ThreatModelAcceptance,
  ThreatModelEntitlement, ThreatModelReach, ThreatModelEffect, ThreatModelGate,
  ThreatModelFlow, ThreatModelBoundary, ThreatModelTransfer,
  AgentConfigHook, AgentConfigMcpServer, AgentConfigBundledFile,
} from '../types/index.js';
import { findUnmitigatedExposures, normalizeRef } from '../parser/coverage.js';
import { citationMatchesFile } from '../parser/citation.js';
import { findUnentitledReaches, reachKey as reachKeyIn } from '../parser/reach.js';

// ─── Delta types ─────────────────────────────────────────────────────

export type ChangeKind = 'added' | 'removed' | 'modified';

export interface Change<T> {
  kind: ChangeKind;
  item: T;
  previous?: T;       // Only for 'modified'
  details?: string;    // Human-readable change description
}

export interface ThreatModelDiff {
  /** Summary stats */
  summary: DiffSummary;

  /** Per-category deltas */
  assets: Change<ThreatModelAsset>[];
  threats: Change<ThreatModelThreat>[];
  controls: Change<ThreatModelControl>[];
  actors: Change<ThreatModelActor>[];
  mitigations: Change<ThreatModelMitigation>[];
  exposures: Change<ThreatModelExposure>[];
  confirmed: Change<ThreatModelConfirmed>[];
  acceptances: Change<ThreatModelAcceptance>[];
  entitlements: Change<ThreatModelEntitlement>[];
  /** Reach claims: @agents and @reaches */
  reaches: Change<ThreatModelReach>[];
  effects: Change<ThreatModelEffect>[];
  gates: Change<ThreatModelGate>[];
  flows: Change<ThreatModelFlow>[];
  boundaries: Change<ThreatModelBoundary>[];
  transfers: Change<ThreatModelTransfer>[];

  /** Risk-relevant: new unmitigated exposures introduced */
  newUnmitigatedExposures: ThreatModelExposure[];

  /** Risk-relevant: previously unmitigated exposures now resolved */
  resolvedExposures: ThreatModelExposure[];

  /**
   * Risk-relevant: reaches no cited @entitles covers after the change that were
   * not uncovered before — a new capability nobody approved, or an approval
   * withdrawn from an existing one.
   */
  newUnentitledReaches: ThreatModelReach[];

  /**
   * Entitlements whose cited authorization code changed in this delta (§3.7).
   * Reported as *stale* — the claim survives, but the code it was reviewed
   * against did not, so it needs a fresh human look. Empty unless the caller
   * supplied `changedFiles`.
   */
  staleEntitlements: StaleEntitlement[];

  /**
   * What changed in the repository's coding-agent configuration (SPEC §5.6).
   * Its generated rows are reported here, not in `reaches`, `effects` and
   * `gates`, which stay about annotations.
   */
  agentConfig: AgentConfigDelta;
  reachAttestation?: { kind: string; change: 'added' | 'removed'; row: AttestationRow }[];
}

/** A coding-agent configuration change a reviewer should see in a pull request. */
export interface AgentConfigDelta {
  surfaceChanges?: { change: 'added' | 'removed'; surface: import('../types/index.js').AgentConfigSurface }[];
  /** Capabilities the configuration newly grants a coding agent. */
  newReach: ThreatModelReach[];
  /** Capabilities it no longer grants. */
  removedReach: ThreatModelReach[];
  /** Newly granted modes that turn an agent's prompts off: bypass, auto-approve, auto-accept, trusted servers. */
  newBypass: ThreatModelReach[];
  /**
   * An MCP server that keeps its name while what it starts changes. A developer
   * approved the old command once, and some harnesses do not ask again, so the
   * new one runs on the strength of the old approval.
   */
  launchChanges: { name: string; harness: string; file: string; line: number; before: string; after: string }[];
  newMcpServers: AgentConfigMcpServer[];
  /** Commands the configuration newly runs automatically. */
  newHooks: AgentConfigHook[];
  /**
   * Scripts and code that arrived beside a skill this repository's agents load,
   * or whose content changed. A skill runs what is bundled with it, so a new
   * script needs review even when no configuration key moved.
   */
  bundledChanges: { skill: string; path: string; kind: 'script' | 'code'; change: 'new' | 'changed'; bytes: number }[];
}

export interface StaleEntitlement {
  entitlement: ThreatModelEntitlement;
  /** The changed file that the entitlement's citation points at */
  citedFile: string;
}

export interface DiffOptions {
  /**
   * Files that changed between the two revisions, repo-relative (e.g. from
   * `git diff --name-only <ref>`). Used only to compute `staleEntitlements`.
   */
  changedFiles?: Iterable<string>;
}

export interface DiffSummary {
  totalChanges: number;
  added: number;
  removed: number;
  modified: number;
  newUnmitigated: number;
  resolvedUnmitigated: number;
  riskDelta: 'increased' | 'decreased' | 'unchanged';
  /** Entitlements whose cited authorization code changed */
  staleEntitlements: number;
  /** Reaches newly without a covering entitlement */
  newUnentitledReaches: number;
  /** Coding-agent configuration changes: new and removed reach, new bypass modes, launch changes, new servers and hooks. */
  agentConfigChanges: number;
}

// ─── Diff computation ────────────────────────────────────────────────

export function diffModels(before: ThreatModel, after: ThreatModel, options: DiffOptions = {}): ThreatModelDiff {
  const assets = diffByKey(before.assets, after.assets, assetKey, assetChanged);
  const threats = diffByKey(before.threats, after.threats, threatKey, threatChanged);
  const controls = diffByKey(before.controls, after.controls, controlKey, controlChanged);
  const actors = diffByKey(before.actors || [], after.actors || [], actorKey, actorChanged);
  const entitlements = diffByKey(before.entitlements || [], after.entitlements || [], entitlementKey, entitlementChanged);
  const mitigations = diffByKey(before.mitigations, after.mitigations, mitigationKey);
  const exposures = diffByKey(before.exposures, after.exposures, exposureKey, exposureChanged);
  const confirmed = diffByKey(before.confirmed || [], after.confirmed || [], (c: ThreatModelConfirmed) => `${c.asset}::${c.threat}`, (a: ThreatModelConfirmed, b: ThreatModelConfirmed) => a.severity !== b.severity || a.description !== b.description ? `severity/description changed` : null);
  const acceptances = diffByKey(before.acceptances, after.acceptances, acceptanceKey);
  const flows = diffByKey(before.flows, after.flows, flowKey, flowChanged);
  const boundaries = diffByKey(before.boundaries, after.boundaries, boundaryKey, boundaryChanged);
  const transfers = diffByKey(before.transfers, after.transfers, transferKey);
  // Identity per model: each resolves actor and asset spellings against its own
  // declarations, so renaming `#db` to its dotted path is not a remove plus an add.
  const annotated = <T extends { origin?: unknown }>(xs: T[] | undefined): T[] => (xs ?? []).filter(x => !x.origin);
  const reaches = diffByKey(annotated(before.reaches), annotated(after.reaches), reachKeyIn(before), reachChanged, reachKeyIn(after));
  const effects = diffByKey(annotated(before.effects), annotated(after.effects), effectKey, effectChanged);
  const gates = diffByKey(annotated(before.gates), annotated(after.gates), gateKey, gateChanged);
  const agentConfig = diffAgentConfig(before, after);
  const driftRows = (m: ThreatModel) => {
    const block = m.observed_reach ? buildReachAttestation(m, m.observed_reach, m.tool_pins) : m.reach_attestation;
    return block ? (['observed_not_declared', 'declared_not_observed', 'pin_changed', 'unknown'] as const).flatMap(kind => block[kind].map(row => ({ kind, row }))) : [];
  };
  const oldDrift = driftRows(before), newDrift = driftRows(after);
  const driftKey = (r: { kind: string; row: AttestationRow }) => JSON.stringify(r);
  const oldKeys = new Set(oldDrift.map(driftKey)), newKeys = new Set(newDrift.map(driftKey));
  const reachAttestation = [...newDrift.filter(r => !oldKeys.has(driftKey(r))).map(r => ({ ...r, change: 'added' as const })), ...oldDrift.filter(r => !newKeys.has(driftKey(r))).map(r => ({ ...r, change: 'removed' as const }))];

  const beforeUnentitled = new Set(findUnentitledReaches(before).map(u => reachKeyIn(before)(u.reach)));
  const afterReachKey = reachKeyIn(after);
  const newUnentitledReaches = findUnentitledReaches(after)
    .map(u => u.reach)
    .filter(r => !beforeUnentitled.has(afterReachKey(r)));

  // Compute unmitigated exposure delta
  const beforeUnmitigated = computeUnmitigated(before);
  const afterUnmitigated = computeUnmitigated(after);

  // D36. The risk delta is keyed BY SITE, not by (asset, threat). Once coverage
  // can differ between two exposures on the same pair — one function fixed, its
  // neighbour not — a pair-keyed comparison collapses them and reports "no
  // change" for a state change it cannot see. `exposureKey` keeps its pair
  // identity for the exposures diff itself, where re-anchoring an annotation
  // should not read as a remove plus an add.
  const beforeKeys = new Set(beforeUnmitigated.map(e => unmitigatedKey(e)));
  const afterKeys = new Set(afterUnmitigated.map(e => unmitigatedKey(e)));

  const newUnmitigatedExposures = afterUnmitigated.filter(e => !beforeKeys.has(unmitigatedKey(e)));
  const resolvedExposures = beforeUnmitigated.filter(e => !afterKeys.has(unmitigatedKey(e)));

  const staleEntitlements = findStaleEntitlements(after, options.changedFiles);

  const allChanges = [assets, threats, controls, actors, mitigations, exposures, confirmed, acceptances, entitlements, reaches, effects, gates, flows, boundaries, transfers];
  const totalChanges = allChanges.reduce((sum, c) => sum + c.length, 0);
  const added = allChanges.reduce((sum, c) => sum + c.filter(x => x.kind === 'added').length, 0);
  const removed = allChanges.reduce((sum, c) => sum + c.filter(x => x.kind === 'removed').length, 0);
  const modified = allChanges.reduce((sum, c) => sum + c.filter(x => x.kind === 'modified').length, 0);

  const riskDelta = newUnmitigatedExposures.length > resolvedExposures.length ? 'increased'
    : newUnmitigatedExposures.length < resolvedExposures.length ? 'decreased'
    : 'unchanged';

  return {
    summary: {
      totalChanges, added, removed, modified,
      newUnmitigated: newUnmitigatedExposures.length,
      resolvedUnmitigated: resolvedExposures.length,
      riskDelta,
      staleEntitlements: staleEntitlements.length,
      newUnentitledReaches: newUnentitledReaches.length,
      agentConfigChanges: agentConfig.newReach.length + agentConfig.removedReach.length + agentConfig.launchChanges.length
        + agentConfig.newMcpServers.length + agentConfig.newHooks.length + agentConfig.bundledChanges.length + (agentConfig.surfaceChanges?.length ?? 0),
    },
    assets, threats, controls, actors, mitigations, exposures, confirmed, acceptances, entitlements, reaches, effects, gates, flows, boundaries, transfers,
    newUnmitigatedExposures,
    resolvedExposures,
    newUnentitledReaches,
    staleEntitlements,
    agentConfig,
    ...(before.observed_reach || after.observed_reach ? { reachAttestation } : {}),
  };
}

// ─── Coding-agent configuration (SPEC §5.6) ──────────────────────────

/** Harness rules whose grant switches an agent's prompts off. */
const BYPASS_RULES = new Set([
  'bypass-mode', 'global-auto-approve', 'auto-accept', 'approval-sandbox', 'mcp-server-trusted', 'mcp-server-auto',
  'subagent-permission-mode', 'mcp-autostart',
]);

/** One generated grant: who, what, and the line of configuration that grants it. */
const configReachKey = (r: ThreatModelReach) => `${r.actor}::${r.canonical_capability}::${r.asset ?? ''}::${r.location.file}::${r.source?.raw ?? ''}`;
const serverKey = (m: AgentConfigMcpServer) => `${m.harness}::${m.file}::${m.name}`;
const launchOf = (m: AgentConfigMcpServer) => (m.transport === 'http' ? `http ${m.host ?? ''}` : [m.launch?.command ?? '', ...(m.launch?.args ?? [])].join(' '));
const hookKey = (h: AgentConfigHook) => `${h.harness}::${h.file}::${h.event}::${h.matcher ?? ''}::${h.command}`;
const own = (scope: string) => scope === 'root' || scope === 'nested';

function diffAgentConfig(before: ThreatModel, after: ThreatModel): AgentConfigDelta {
  const generated = (m: ThreatModel) => (m.reaches ?? []).filter(r => r.origin);
  const was = new Set(generated(before).map(configReachKey));
  const now = new Set(generated(after).map(configReachKey));
  const newReach = generated(after).filter(r => !was.has(configReachKey(r)));
  const removedReach = generated(before).filter(r => !now.has(configReachKey(r)));
  const newBypass = newReach.filter(r => BYPASS_RULES.has(r.source?.semantics.rule ?? ''));

  const servers = (m: ThreatModel) => (m.agent_config?.mcp_servers ?? []).filter(x => own(x.scope));
  const oldServers = new Map(servers(before).map(m => [serverKey(m), m]));
  const launchChanges: AgentConfigDelta['launchChanges'] = [];
  const newMcpServers: AgentConfigMcpServer[] = [];
  for (const m of servers(after)) {
    const prev = oldServers.get(serverKey(m));
    if (!prev) { newMcpServers.push(m); continue; }
    if (launchOf(prev) !== launchOf(m)) {
      launchChanges.push({ name: m.name, harness: m.harness, file: m.file, line: m.line, before: launchOf(prev), after: launchOf(m) });
    }
  }

  const oldHooks = new Set((before.agent_config?.hooks ?? []).map(hookKey));
  const newHooks = (after.agent_config?.hooks ?? []).filter(h => own(h.scope) && !oldHooks.has(hookKey(h)));

  // Scripts and code bundled with a skill: new, or the same path with different content.
  const skillFiles = (m: ThreatModel) => (m.agent_config?.instruction_files ?? []).filter(f => f.kind === 'skill' && own(f.scope));
  const oldBundled = new Map<string, AgentConfigBundledFile>();
  for (const f of skillFiles(before)) for (const x of f.bundled ?? []) oldBundled.set(`${f.path}::${x.path}`, x);
  const bundledChanges: AgentConfigDelta['bundledChanges'] = [];
  for (const f of skillFiles(after)) {
    for (const x of f.bundled ?? []) {
      if (x.kind === 'asset') continue;
      const prev = oldBundled.get(`${f.path}::${x.path}`);
      // The digest when both sides have one; otherwise the length is all there is to compare.
      const changed = prev && (prev.sha256 && x.sha256 ? prev.sha256 !== x.sha256 : prev.bytes !== x.bytes);
      if (!prev) bundledChanges.push({ skill: f.path, path: x.path, kind: x.kind, change: 'new', bytes: x.bytes });
      else if (changed) bundledChanges.push({ skill: f.path, path: x.path, kind: x.kind, change: 'changed', bytes: x.bytes });
    }
  }
  const surfaces = (m: ThreatModel) => (m.agent_config?.surfaces ?? []).filter(s => own(s.scope));
  const surfaceKey = (s: import('../types/index.js').AgentConfigSurface) => JSON.stringify([s.family,s.harness,s.file,s.pointer,s.names,s.details]);
  const oldSurfaces = surfaces(before), newSurfaces = surfaces(after);
  const oldSurfaceKeys = new Set(oldSurfaces.map(surfaceKey)), newSurfaceKeys = new Set(newSurfaces.map(surfaceKey));
  const surfaceChanges = [...newSurfaces.filter(s => !oldSurfaceKeys.has(surfaceKey(s))).map(surface => ({ change: 'added' as const, surface })), ...oldSurfaces.filter(s => !newSurfaceKeys.has(surfaceKey(s))).map(surface => ({ change: 'removed' as const, surface }))];
  return { newReach, removedReach, newBypass, launchChanges, newMcpServers, newHooks, bundledChanges, ...(surfaceChanges.length ? { surfaceChanges } : {}) };
}

// ─── Entitlement staleness (§3.7) ────────────────────────────────────

/**
 * An entitlement is a claim about purpose, reviewable only through the authz
 * code it cites. When that code changes the claim is *stale*, not removed —
 * it still stands, but the basis a reviewer accepted it on has moved.
 *
 * Uncited (inert) entitlements are skipped: they have no basis to go stale.
 */
function findStaleEntitlements(after: ThreatModel, changedFiles?: Iterable<string>): StaleEntitlement[] {
  if (!changedFiles) return [];
  const changed = [...changedFiles];
  if (changed.length === 0) return [];

  const stale: StaleEntitlement[] = [];
  for (const en of after.entitlements || []) {
    if (!en.citation) continue;
    const hit = changed.find(f => citationMatchesFile(en.citation!, f));
    if (hit) stale.push({ entitlement: en, citedFile: hit });
  }
  return stale;
}

// ─── Generic key-based diff ──────────────────────────────────────────

function diffByKey<T>(
  before: T[],
  after: T[],
  keyFn: (item: T) => string,
  changedFn?: (a: T, b: T) => string | null,
  afterKeyFn: (item: T) => string = keyFn,
): Change<T>[] {
  const changes: Change<T>[] = [];
  const beforeMap = new Map<string, T>();
  const afterMap = new Map<string, T>();

  for (const item of before) beforeMap.set(keyFn(item), item);
  for (const item of after) afterMap.set(afterKeyFn(item), item);

  // Removed: in before but not in after
  for (const [key, item] of beforeMap) {
    if (!afterMap.has(key)) {
      changes.push({ kind: 'removed', item });
    }
  }

  // Added or modified: in after
  for (const [key, item] of afterMap) {
    const prev = beforeMap.get(key);
    if (!prev) {
      changes.push({ kind: 'added', item });
    } else if (changedFn) {
      const details = changedFn(prev, item);
      if (details) {
        changes.push({ kind: 'modified', item, previous: prev, details });
      }
    }
  }

  return changes;
}

// ─── Key functions (identity) ────────────────────────────────────────

function assetKey(a: ThreatModelAsset): string {
  return a.id || a.path.join('.');
}

function threatKey(t: ThreatModelThreat): string {
  return t.id || t.canonical_name;
}

function controlKey(c: ThreatModelControl): string {
  return c.id || c.canonical_name;
}

function actorKey(a: ThreatModelActor): string {
  return a.id || a.canonical_name;
}

/**
 * The entitlement's identity is the join it makes: `(actor, asset, threat)`
 * (§9.7). What a reader of a diff needs to know is which `(asset, threat)` pairs
 * this actor is now claimed to be entitled on, so retargeting either half is a
 * withdrawn claim plus a new one — reporting that as a modification would let a
 * claim move onto a different pair while the diff said "description changed".
 *
 * Capability is deliberately *not* in the key, though §9.7 lists it among the
 * identifying fields: it is no longer the join (§9.3), and §9.8 asks for a
 * capability edit on one triple to read as a modification, which is only
 * possible if it is compared rather than keyed. It is compared in
 * entitlementChanged below, so no edit to it goes unreported either way.
 *
 * An imprecise claim has no join to be identified by, so it falls back to the
 * capability — the only thing left that distinguishes it. Without that fallback
 * every loose claim by one actor keys the same, and diffByKey keeps one entry per
 * key: the diff would silently drop claims it collided with, and §9.3 requires
 * the loose form to be harmless rather than invisible.
 */
function entitlementKey(e: ThreatModelEntitlement): string {
  const join = `${normalizeActorRef(e.actor)}::${e.asset || ''}::${e.threat || ''}`;
  return e.asset && e.threat ? join : `${join}::${e.canonical_capability}`;
}

function normalizeActorRef(ref: string): string {
  return ref.startsWith('#') ? ref.slice(1) : ref;
}

/** A side effect is identified by what it does to what, and as whom. */
function effectKey(e: ThreatModelEffect): string {
  return `${e.effect}::${normalizeRef(e.asset)}::${normalizeRef(e.identity ?? '')}`;
}

/** A gate is identified by what it guards, who decides, and for which capability. */
function gateKey(g: ThreatModelGate): string {
  return `${normalizeRef(g.asset)}::${normalizeRef(g.approver)}::${g.canonical_capability ?? ''}`;
}

function mitigationKey(m: ThreatModelMitigation): string {
  return `${m.asset}::${m.threat}::${m.control || ''}`;
}

function exposureKey(e: ThreatModelExposure): string {
  return `${e.asset}::${e.threat}`;
}

/**
 * Site identity for the unmitigated delta (D36). Uses the enclosing symbol when
 * there is one — `parent_symbol` for an external block, the anchor's symbol for
 * an inline annotation — and the file:line when there is not, so lines inserted
 * above an unchanged exposure do not turn it into a new one plus a resolved one.
 * Both sides are parsed with anchors, so the two keys are built the same way.
 */
function unmitigatedKey(e: ThreatModelExposure): string {
  const symbol = e.location.parent_symbol ?? e.location.anchor?.symbol;
  const site = symbol ?? `${e.location.file}:${e.location.line}`;
  return `${normalizeRef(e.asset)}::${normalizeRef(e.threat)}::${e.location.file}::${site}`;
}

function acceptanceKey(a: ThreatModelAcceptance): string {
  return `${a.asset}::${a.threat}`;
}

function flowKey(f: ThreatModelFlow): string {
  return `${f.source}->${f.target}::${f.mechanism || ''}`;
}

function boundaryKey(b: ThreatModelBoundary): string {
  return b.id || `${b.asset_a}::${b.asset_b}`;
}

function transferKey(t: ThreatModelTransfer): string {
  return `${t.source}->${t.target}::${t.threat}`;
}

// ─── Change detection ────────────────────────────────────────────────

function assetChanged(a: ThreatModelAsset, b: ThreatModelAsset): string | null {
  if (a.description !== b.description) return `description changed`;
  if (a.path.join('.') !== b.path.join('.')) return `path changed: ${a.path.join('.')} → ${b.path.join('.')}`;
  return null;
}

function threatChanged(a: ThreatModelThreat, b: ThreatModelThreat): string | null {
  const changes: string[] = [];
  if (a.severity !== b.severity) changes.push(`severity: ${a.severity || 'unset'} → ${b.severity || 'unset'}`);
  if (a.description !== b.description) changes.push('description changed');
  if (a.external_refs.join(',') !== b.external_refs.join(',')) changes.push('external refs changed');
  return changes.length > 0 ? changes.join('; ') : null;
}

function controlChanged(a: ThreatModelControl, b: ThreatModelControl): string | null {
  if (a.description !== b.description) return 'description changed';
  return null;
}

function actorChanged(a: ThreatModelActor, b: ThreatModelActor): string | null {
  if (a.description !== b.description) return 'description changed';
  return null;
}

function entitlementChanged(a: ThreatModelEntitlement, b: ThreatModelEntitlement): string | null {
  const changes: string[] = [];
  // Asset and threat are the key, so they cannot differ here. Capability can:
  // it is the justification a reviewer accepted, and rewriting it on a claim that
  // still demotes the same pair is a change to what was agreed to (§9.3).
  // Compared as written, not canonicalised: a reviewer reads the capability, so a
  // rewrite that normalises to the same label is still a change to what they read.
  if (a.capability !== b.capability) changes.push(`capability: ${a.capability} → ${b.capability}`);
  if (a.citation?.raw !== b.citation?.raw) changes.push(`citation: ${a.citation?.raw || 'none'} → ${b.citation?.raw || 'none'}`);
  // Surfaced explicitly: an entitlement that loses its citation stops having any
  // effect on triage, and one that gains a citation starts having one (§3.4).
  if (a.inert !== b.inert) changes.push(b.inert ? 'became inert (citation lost)' : 'no longer inert (citation added)');
  if (a.description !== b.description) changes.push('description changed');
  return changes.length > 0 ? changes.join('; ') : null;
}

/**
 * Actor, capability and asset are the key. What can change under it is the
 * verb — the actor stopped or started being declared an agent — the caller
 * identity, the capability as written, and the description.
 */
function reachChanged(a: ThreatModelReach, b: ThreatModelReach): string | null {
  const changes: string[] = [];
  if (a.agent !== b.agent) changes.push(`verb: ${a.agent ? '@agents' : '@reaches'} → ${b.agent ? '@agents' : '@reaches'}`);
  if (a.identity !== b.identity) changes.push(`identity: ${a.identity || 'none'} → ${b.identity || 'none'}`);
  if (a.capability !== b.capability) changes.push(`capability: ${a.capability} → ${b.capability}`);
  if (a.description !== b.description) changes.push('description changed');
  return changes.length > 0 ? changes.join('; ') : null;
}

function effectChanged(a: ThreatModelEffect, b: ThreatModelEffect): string | null {
  return a.description !== b.description ? 'description changed' : null;
}

function gateChanged(a: ThreatModelGate, b: ThreatModelGate): string | null {
  return a.description !== b.description ? 'description changed' : null;
}

function exposureChanged(a: ThreatModelExposure, b: ThreatModelExposure): string | null {
  const changes: string[] = [];
  if (a.severity !== b.severity) changes.push(`severity: ${a.severity || 'unset'} → ${b.severity || 'unset'}`);
  if (a.description !== b.description) changes.push('description changed');
  return changes.length > 0 ? changes.join('; ') : null;
}

function flowChanged(a: ThreatModelFlow, b: ThreatModelFlow): string | null {
  if (a.mechanism !== b.mechanism) return `mechanism: ${a.mechanism || 'none'} → ${b.mechanism || 'none'}`;
  if (a.description !== b.description) return 'description changed';
  return null;
}

/**
 * Only a change of direction: declaring one, dropping one, or swapping which
 * side is outer. The boundary diff reported nothing on modification before the
 * directed form existed, and an undirected pair still reports nothing.
 */
function boundaryChanged(a: ThreatModelBoundary, b: ThreatModelBoundary): string | null {
  const direction = (x: ThreatModelBoundary) => (x.directed ? `from ${x.asset_a} to ${x.asset_b}` : 'undirected');
  if (!a.directed && !b.directed) return null;
  const before = direction(a);
  const after = direction(b);
  return before === after ? null : `direction: ${before} → ${after}`;
}

// ─── Unmitigated exposure computation ────────────────────────────────

/**
 * D36. Was a local `${asset}::${threat}` set that also did not normalise the
 * leading `#`, so `diff` and `validate` could disagree about what was covered on
 * the same model. Both now answer from one predicate.
 */
function computeUnmitigated(model: ThreatModel): ThreatModelExposure[] {
  return findUnmitigatedExposures(model);
}
