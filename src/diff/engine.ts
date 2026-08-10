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
 */

import type {
  ThreatModel,
  ThreatModelAsset, ThreatModelThreat, ThreatModelControl, ThreatModelActor,
  ThreatModelMitigation, ThreatModelExposure, ThreatModelConfirmed, ThreatModelAcceptance,
  ThreatModelEntitlement,
  ThreatModelFlow, ThreatModelBoundary, ThreatModelTransfer,
} from '../types/index.js';
import { findUnmitigatedExposures, normalizeRef } from '../parser/coverage.js';
import { citationMatchesFile } from '../parser/citation.js';

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
  flows: Change<ThreatModelFlow>[];
  boundaries: Change<ThreatModelBoundary>[];
  transfers: Change<ThreatModelTransfer>[];

  /** Risk-relevant: new unmitigated exposures introduced */
  newUnmitigatedExposures: ThreatModelExposure[];

  /** Risk-relevant: previously unmitigated exposures now resolved */
  resolvedExposures: ThreatModelExposure[];

  /**
   * Entitlements whose cited authorization code changed in this delta (§3.7).
   * Reported as *stale* — the claim survives, but the code it was reviewed
   * against did not, so it needs a fresh human look. Empty unless the caller
   * supplied `changedFiles`.
   */
  staleEntitlements: StaleEntitlement[];
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
  const boundaries = diffByKey(before.boundaries, after.boundaries, boundaryKey);
  const transfers = diffByKey(before.transfers, after.transfers, transferKey);

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

  const allChanges = [assets, threats, controls, actors, mitigations, exposures, confirmed, acceptances, entitlements, flows, boundaries, transfers];
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
    },
    assets, threats, controls, actors, mitigations, exposures, confirmed, acceptances, entitlements, flows, boundaries, transfers,
    newUnmitigatedExposures,
    resolvedExposures,
    staleEntitlements,
  };
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
): Change<T>[] {
  const changes: Change<T>[] = [];
  const beforeMap = new Map<string, T>();
  const afterMap = new Map<string, T>();

  for (const item of before) beforeMap.set(keyFn(item), item);
  for (const item of after) afterMap.set(keyFn(item), item);

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

function mitigationKey(m: ThreatModelMitigation): string {
  return `${m.asset}::${m.threat}::${m.control || ''}`;
}

function exposureKey(e: ThreatModelExposure): string {
  return `${e.asset}::${e.threat}`;
}

/**
 * Site identity for the unmitigated delta (D36). Uses the symbol anchor when
 * there is one and the file:line when there is not, so the key is stable under
 * inline authoring — where no symbol exists — and under external authoring
 * alike.
 */
function unmitigatedKey(e: ThreatModelExposure): string {
  const site = e.location.parent_symbol ?? `${e.location.file}:${e.location.line}`;
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

// ─── Unmitigated exposure computation ────────────────────────────────

/**
 * D36. Was a local `${asset}::${threat}` set that also did not normalise the
 * leading `#`, so `diff` and `validate` could disagree about what was covered on
 * the same model. Both now answer from one predicate.
 */
function computeUnmitigated(model: ThreatModel): ThreatModelExposure[] {
  return findUnmitigatedExposures(model);
}
