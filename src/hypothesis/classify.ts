/**
 * GuardLink Hypotheses — the state of every claim, and the queue.
 *
 * Untested is the absence of an entry. An outcome holds while the claim's
 * anchor hash is the one it was recorded against; when the code beneath the
 * claim moves, a refutation lapses to untested (with the old outcome
 * attached) and a confirmation asks for a retest. A source `@confirmed` is a
 * confirmation with no ledger entry.
 *
 * @flows ThreatModel -> #cli via classifyHypotheses -- "Claims joined to the ledger by key"
 * @flows #cli -> ThreatModel via attachHypotheses -- "The state stamped onto each exposure for the dashboard, the report and the lint"
 * @comment -- "Pure over the model and a ledger read; no clock, no file, no git — ranking is arithmetic on facts the model already holds"
 */
import type { ThreatModel, ThreatModelExposure, ExposureHypothesis, SourceLocation } from '../types/index.js';
import { relationRecords } from '../parser/claim-key.js';
import type { HypothesesRead, HypothesisEntry, HypothesisOutcomeRecord } from './ledger.js';

export type HypothesisState = 'untested' | 'confirmed' | 'refuted' | 'retest';

export interface HypothesisRecord {
  key: string;
  verb: 'exposes' | 'confirmed';
  claim: string;
  asset: string;
  threat: string;
  severity: string;
  /** The exposure's external references (cwe:, owasp:), for the offered @confirmed line. */
  refs: string[];
  file: string;
  line: number;
  location: SourceLocation;
  state: HypothesisState;
  entry: HypothesisEntry | null;
  /** The entry no longer applies because the code beneath the claim changed. */
  expired: boolean;
  /** The lapsed outcome, when `expired`. */
  previous: HypothesisOutcomeRecord | null;
}

export interface HypothesisSummary { untested: number; confirmed: number; refuted: number; retest: number }

export interface HypothesisClassification {
  records: HypothesisRecord[];
  summary: HypothesisSummary;
  ledger: HypothesesRead['status'];
}

export function classifyHypotheses(model: ThreatModel, read: HypothesesRead): HypothesisClassification {
  const entries = new Map<string, HypothesisEntry>();
  for (const e of read.ledger?.entries ?? []) entries.set(e.key, e);
  const records: HypothesisRecord[] = [];
  const summary: HypothesisSummary = { untested: 0, confirmed: 0, refuted: 0, retest: 0 };

  for (const src of relationRecords(model)) {
    if (src.verb !== 'exposes' && src.verb !== 'confirmed') continue;
    const rec = (src.verb === 'exposes' ? model.exposures : model.confirmed || []).find(r => r.location === src.location);
    if (!rec) continue;
    const base = {
      key: src.key, verb: src.verb, claim: src.claim, asset: rec.asset, threat: rec.threat, severity: rec.severity || 'unset', refs: rec.external_refs ?? [],
      file: src.location.origin_file ?? src.location.file, line: src.location.origin_line ?? src.location.line, location: src.location,
    };
    if (src.verb === 'confirmed') {
      records.push({ ...base, state: 'confirmed', entry: null, expired: false, previous: null });
      summary.confirmed++;
      continue;
    }
    const entry = entries.get(src.key) ?? null;
    if (!entry) { records.push({ ...base, state: 'untested', entry: null, expired: false, previous: null }); summary.untested++; continue; }
    const hashNow = src.location.anchor?.hash ?? null;
    const holds = entry.anchor !== null && hashNow !== null && entry.anchor.hash === hashNow;
    if (holds) {
      records.push({ ...base, state: entry.outcome, entry, expired: false, previous: null });
      summary[entry.outcome]++;
      continue;
    }
    const state: HypothesisState = entry.outcome === 'confirmed' ? 'retest' : 'untested';
    const { history: _h, key: _k, claim: _c, file: _f, line: _l, ...previous } = entry;
    records.push({ ...base, state, entry, expired: true, previous });
    summary[state]++;
  }
  return { records, summary, ledger: read.status };
}

/** Stamp the state onto each exposure so surfaces that only see the model can read it. */
export function attachHypotheses(model: ThreatModel, c: HypothesisClassification): void {
  const byLoc = new Map<object, HypothesisRecord>();
  for (const r of c.records) byLoc.set(r.location, r);
  for (const e of model.exposures) {
    const r = byLoc.get(e.location);
    if (!r) continue;
    const src = r.entry ?? null;
    const h: ExposureHypothesis = {
      state: r.state,
      evidence: src?.evidence ?? null,
      by: src?.by ?? null,
      at: src?.at ?? null,
      expired: r.expired,
      previous_outcome: r.previous?.outcome ?? null,
    };
    (e as ThreatModelExposure).hypothesis = h;
  }
}

const SEV_RANK: Record<string, number> = { critical: 0, p0: 0, high: 1, p1: 1, medium: 2, p2: 2, low: 3, p3: 3 };
const sev = (s: string): number => SEV_RANK[s.toLowerCase()] ?? 4;
const bare = (r: string): string => r.trim().replace(/^#/, '').toLowerCase();

export interface RankedHypothesis extends HypothesisRecord {
  /** The asset sits on an undefended source-to-sink path. */
  onPath: boolean;
  /** No @owns names the asset. */
  unowned: boolean;
  rank: number;
}

/**
 * What to test next. `retest` first (a confirmed finding whose code changed),
 * then `untested`; within each: severity, then on an undefended path, then
 * unowned, then file and line. `pathAssets` is the set of asset refs on
 * unmitigated paths (`findUnmitigatedPaths(...).assetsOnPath`), in any form.
 */
export function rankUntested(records: HypothesisRecord[], model: ThreatModel, pathAssets: Set<string> = new Set()): RankedHypothesis[] {
  const canon = new Map<string, string>();
  for (const a of model.assets) {
    const c = a.id ? a.id.toLowerCase() : a.path.join('.').toLowerCase();
    canon.set(a.path.join('.').toLowerCase(), c);
    canon.set(a.path[a.path.length - 1].toLowerCase(), c);
    if (a.id) canon.set(a.id.toLowerCase(), c);
  }
  const of = (r: string): string => canon.get(bare(r)) ?? bare(r);
  const onPath = new Set([...pathAssets].map(of));
  const owned = new Set(model.ownership.map(o => of(o.asset)));
  const queue = records.filter(r => r.state === 'untested' || r.state === 'retest').map(r => ({
    ...r, onPath: onPath.has(of(r.asset)), unowned: !owned.has(of(r.asset)), rank: 0,
  }));
  queue.sort((a, b) => (a.state === 'retest' ? 0 : 1) - (b.state === 'retest' ? 0 : 1)
    || sev(a.severity) - sev(b.severity)
    || (a.onPath ? 0 : 1) - (b.onPath ? 0 : 1)
    || (a.unowned ? 0 : 1) - (b.unowned ? 0 : 1)
    || (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  queue.forEach((r, i) => { r.rank = i + 1; });
  return queue;
}
