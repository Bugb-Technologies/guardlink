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
 */

import type {
  ThreatModel,
  ThreatModelAsset, ThreatModelThreat, ThreatModelControl,
  ThreatModelMitigation, ThreatModelExposure, ThreatModelAcceptance,
  ThreatModelFlow, ThreatModelBoundary, ThreatModelTransfer,
  Severity, SourceLocation,
} from '../types/index.js';

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
  mitigations: Change<ThreatModelMitigation>[];
  exposures: Change<ThreatModelExposure>[];
  acceptances: Change<ThreatModelAcceptance>[];
  flows: Change<ThreatModelFlow>[];
  boundaries: Change<ThreatModelBoundary>[];
  transfers: Change<ThreatModelTransfer>[];

  /** Risk-relevant: new unmitigated exposures introduced */
  newUnmitigatedExposures: ThreatModelExposure[];

  /** Risk-relevant: previously unmitigated exposures now resolved */
  resolvedExposures: ThreatModelExposure[];
}

export interface DiffSummary {
  totalChanges: number;
  added: number;
  removed: number;
  modified: number;
  newUnmitigated: number;
  resolvedUnmitigated: number;
  riskDelta: 'increased' | 'decreased' | 'unchanged';
}

// ─── Diff computation ────────────────────────────────────────────────

export function diffModels(before: ThreatModel, after: ThreatModel): ThreatModelDiff {
  const assets = diffByKey(before.assets, after.assets, assetKey, assetChanged);
  const threats = diffByKey(before.threats, after.threats, threatKey, threatChanged);
  const controls = diffByKey(before.controls, after.controls, controlKey, controlChanged);
  const mitigations = diffByKey(before.mitigations, after.mitigations, mitigationKey);
  const exposures = diffByKey(before.exposures, after.exposures, exposureKey, exposureChanged);
  const acceptances = diffByKey(before.acceptances, after.acceptances, acceptanceKey);
  const flows = diffByKey(before.flows, after.flows, flowKey, flowChanged);
  const boundaries = diffByKey(before.boundaries, after.boundaries, boundaryKey);
  const transfers = diffByKey(before.transfers, after.transfers, transferKey);

  // Compute unmitigated exposure delta
  const beforeUnmitigated = computeUnmitigated(before);
  const afterUnmitigated = computeUnmitigated(after);

  const beforeKeys = new Set(beforeUnmitigated.map(e => exposureKey(e)));
  const afterKeys = new Set(afterUnmitigated.map(e => exposureKey(e)));

  const newUnmitigatedExposures = afterUnmitigated.filter(e => !beforeKeys.has(exposureKey(e)));
  const resolvedExposures = beforeUnmitigated.filter(e => !afterKeys.has(exposureKey(e)));

  const allChanges = [assets, threats, controls, mitigations, exposures, acceptances, flows, boundaries, transfers];
  const totalChanges = allChanges.reduce((sum, c) => sum + c.length, 0);
  const added = allChanges.reduce((sum, c) => sum + c.filter(x => x.kind === 'added').length, 0);
  const removed = allChanges.reduce((sum, c) => sum + c.filter(x => x.kind === 'removed').length, 0);
  const modified = allChanges.reduce((sum, c) => sum + c.filter(x => x.kind === 'modified').length, 0);

  const riskDelta = newUnmitigatedExposures.length > resolvedExposures.length ? 'increased'
    : newUnmitigatedExposures.length < resolvedExposures.length ? 'decreased'
    : 'unchanged';

  return {
    summary: { totalChanges, added, removed, modified, newUnmitigated: newUnmitigatedExposures.length, resolvedUnmitigated: resolvedExposures.length, riskDelta },
    assets, threats, controls, mitigations, exposures, acceptances, flows, boundaries, transfers,
    newUnmitigatedExposures,
    resolvedExposures,
  };
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

function mitigationKey(m: ThreatModelMitigation): string {
  return `${m.asset}::${m.threat}::${m.control || ''}`;
}

function exposureKey(e: ThreatModelExposure): string {
  return `${e.asset}::${e.threat}`;
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

function computeUnmitigated(model: ThreatModel): ThreatModelExposure[] {
  const covered = new Set<string>();
  for (const m of model.mitigations) covered.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) covered.add(`${a.asset}::${a.threat}`);
  return model.exposures.filter(e => !covered.has(`${e.asset}::${e.threat}`));
}
