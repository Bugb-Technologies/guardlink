/**
 * GuardLink Hypotheses — declared boundaries as claims to test.
 *
 * A `@boundary` says trust changes between two sides and, in its description,
 * what holds the line. That is a claim a probe can test: call the inner side
 * as an outer principal and see whether it is refused. The outcome is recorded
 * against the boundary's claim key as `supported` (refused, as the boundary
 * says) or `contradicted` (it got through).
 *
 * Unverified is the absence of an entry, as untested is for an exposure. An
 * outcome holds while the boundary's anchor hash is the one it was recorded
 * against; when the code beneath it moves, a supported outcome lapses to
 * unverified and a contradicted one asks for a retest, the same rule the
 * exposure ledger applies to refuted and confirmed.
 *
 * A boundary outcome never demotes or closes an exposure, and nothing here
 * reads one into the exposure states.
 *
 * @flows ThreatModel -> #cli via classifyBoundaryClaims -- "Declared boundaries joined to the ledger by claim key"
 * @comment -- "Pure over the model and a ledger read, like classifyHypotheses; recording goes through recordBoundaryOutcome in commands.ts, which shares the exposure path's evidence check and upsert"
 */
import type { ThreatModel, SourceLocation } from '../types/index.js';
import { relationRecords, isClaimKey } from '../parser/claim-key.js';
import { isBoundaryEntry, type BoundaryEntry, type BoundaryOutcome, type HypothesesRead, type HypothesisOutcomeRecord } from './ledger.js';

export type BoundaryClaimState = 'unverified' | 'supported' | 'contradicted' | 'retest';

export interface BoundaryClaimRecord {
  key: string;
  claim: string;
  /** The boundary's `#id`, without the `#`; '' when it has none. */
  id: string;
  asset_a: string;
  asset_b: string;
  description: string;
  file: string;
  line: number;
  location: SourceLocation;
  state: BoundaryClaimState;
  entry: BoundaryEntry | null;
  /** The entry no longer applies because the code beneath the boundary changed. */
  expired: boolean;
  previous: HypothesisOutcomeRecord<BoundaryOutcome> | null;
}

export interface BoundaryClaimSummary { unverified: number; supported: number; contradicted: number; retest: number }

export interface BoundaryClaimClassification {
  records: BoundaryClaimRecord[];
  summary: BoundaryClaimSummary;
  ledger: HypothesesRead['status'];
}

export function classifyBoundaryClaims(model: ThreatModel, read: HypothesesRead): BoundaryClaimClassification {
  const entries = new Map<string, BoundaryEntry>();
  for (const e of read.ledger?.entries ?? []) if (isBoundaryEntry(e)) entries.set(e.key, e);
  const byLocation = new Map((model.boundaries ?? []).map(b => [b.location, b]));
  const records: BoundaryClaimRecord[] = [];
  const summary: BoundaryClaimSummary = { unverified: 0, supported: 0, contradicted: 0, retest: 0 };

  for (const src of relationRecords(model)) {
    if (src.verb !== 'boundary') continue;
    const b = byLocation.get(src.location);
    if (!b) continue;
    const base = {
      key: src.key, claim: src.claim, id: b.id ?? '', asset_a: b.asset_a, asset_b: b.asset_b, description: b.description ?? '',
      file: src.location.origin_file ?? src.location.file, line: src.location.origin_line ?? src.location.line, location: src.location,
    };
    const entry = entries.get(src.key) ?? null;
    if (!entry) { records.push({ ...base, state: 'unverified', entry: null, expired: false, previous: null }); summary.unverified++; continue; }
    const hashNow = src.location.anchor?.hash ?? null;
    const holds = entry.anchor !== null && hashNow !== null && entry.anchor.hash === hashNow;
    if (holds) {
      records.push({ ...base, state: entry.outcome, entry, expired: false, previous: null });
      summary[entry.outcome]++;
      continue;
    }
    const state: BoundaryClaimState = entry.outcome === 'contradicted' ? 'retest' : 'unverified';
    const { history: _h, key: _k, claim: _c, file: _f, line: _l, ...previous } = entry;
    records.push({ ...base, state, entry, expired: true, previous });
    summary[state]++;
  }
  return { records, summary, ledger: read.status };
}

/**
 * The boundary a target names: its claim key, its `#id`, or the `file:line` of
 * its `@boundary`. Refuses anything that does not name exactly one.
 */
export function resolveBoundaryTarget(model: ThreatModel, target: string): BoundaryClaimRecord {
  const t = target.trim();
  const records = classifyBoundaryClaims(model, { status: 'absent', ledger: null }).records;
  if (isClaimKey(t)) {
    const hit = records.find(r => r.key === t);
    if (hit) return hit;
    throw new Error(`no @boundary has the claim key ${t}; it may name an exposure (use hypothesis confirm|refute), or the boundary was edited or removed`);
  }
  if (t.startsWith('#')) {
    const id = t.slice(1).toLowerCase();
    const hits = records.filter(r => r.id.toLowerCase() === id);
    if (hits.length === 1) return hits[0];
    if (hits.length === 0) throw new Error(`no @boundary has the id ${t}`);
    throw new Error(`${hits.length} @boundary annotations share the id ${t}; name one by claim key or file:line`);
  }
  const m = /^(.+):(\d+)$/.exec(t);
  if (!m) throw new Error(`Target must be a boundary's claim key, its #id, or the file:line of its @boundary, got ${JSON.stringify(target)}`);
  const file = m[1].replace(/\\/g, '/');
  const line = Number(m[2]);
  const hits = records.filter(r => r.file === file && r.line === line);
  if (hits.length === 1) return hits[0];
  if (hits.length === 0) throw new Error(`no @boundary at ${file}:${line}`);
  throw new Error(`${hits.length} @boundary at ${file}:${line}; name one by claim key`);
}
