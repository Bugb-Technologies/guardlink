// src/parser/verification.ts
/**
 * GuardLink — is this claim still about the code it was verified against?
 *
 * One predicate, called by every surface that answers that question: `ci`,
 * `status`, `verify`, and (in the Act plan) SARIF, report and MCP. A second
 * copy would be a tool that disagrees with `ci` about the same repository,
 * which is the defect coverage.ts (D36) was written to end.
 *
 * Pure. Anchors were attached during parseProject; the ledger was read by the
 * caller. Nothing here touches disk, so the answer is the same on a depth-one
 * CI checkout as on a developer's machine.
 *
 * States, from spec §7.3:
 *   entry present, hash equal ............ verified
 *   entry present, hash differs .......... stale   (+ symbol-renamed hint)
 *   no entry ............................. unverified
 *   entry at another hash version ........ unverified (+ hash-version hint)
 *   entry with no matching claim ......... orphan
 * A claim with no anchor (its file could not be read) is unverified: there is
 * nothing to compare, so it can never be stale. Likewise a claim whose CURRENT
 * anchor fell back to a plain-text hash because the grammar failed to load
 * (`reason: 'grammar-failed'`) is unverified with a `grammar-failed` hint,
 * never stale: comparing a fallback hash against a token hash recorded on a
 * machine where the grammar loaded is meaningless, and treating that as
 * staleness would fail `--strict` builds on a packaging defect rather than a
 * code change.
 *
 * @flows ThreatModel -> #parser via classifyClaims -- "Anchors on every relation record compared with the ledger"
 * @flows LedgerFile -> #parser via classifyClaims -- "Recorded hashes, already read by the caller"
 * @comment -- "Pure function; no I/O. Demotion is a SET of claim keys handed to coverage.ts, never a rewrite of the model"
 */
import type { ThreatModel, SourceLocation, Anchor } from '../types/index.js';
import { relationRecords, type ClaimVerb } from './claim-key.js';
import type { Ledger, LedgerEntry, LedgerRead, LedgerStatus } from './ledger.js';
import { ANCHOR_HASH_VERSION } from '../structure/hash.js';

export type ClaimState = 'verified' | 'stale' | 'unverified';

export interface ClaimRecord {
  key: string;
  verb: ClaimVerb;
  /** Display text of the arguments (claim-key.ts claimText). */
  claim: string;
  state: ClaimState;
  location: SourceLocation;
  /** Null when the logical file could not be read. */
  anchor: Anchor | null;
  /** True for mitigates and accepts — the verbs whose staleness can hide an exposure. */
  demotable: boolean;
  entry?: LedgerEntry;
  hint?: 'symbol-renamed' | 'hash-version' | 'grammar-failed';
}

export interface VerificationReport {
  ledger: LedgerStatus;
  claims: ClaimRecord[];
  orphans: LedgerEntry[];
  summary: {
    verified: number;
    stale: number;
    unverified: number;
    orphans: number;
    stale_by_verb: Partial<Record<ClaimVerb, number>>;
    /** Stale mitigates + accepts: the number `--strict` and demotion act on. */
    demotable_stale: number;
  };
}

export function classifyClaims(model: ThreatModel, read: LedgerRead): VerificationReport {
  const ledger: Ledger | null = read.ledger;
  const versionMismatch = ledger !== null && ledger.anchor_hash_version !== ANCHOR_HASH_VERSION;
  const entries = new Map<string, LedgerEntry>();
  for (const e of ledger?.entries ?? []) entries.set(e.key, e);

  const claims: ClaimRecord[] = [];
  const seen = new Set<string>();
  for (const src of relationRecords(model)) {
    seen.add(src.key);
    const anchor = src.location.anchor ?? null;
    const entry = entries.get(src.key);
    const base = { key: src.key, verb: src.verb, claim: src.claim, location: src.location, anchor, demotable: src.demotable };

    if (!entry || !anchor) { claims.push({ ...base, state: 'unverified', entry }); continue; }
    if (anchor.reason === 'grammar-failed') { claims.push({ ...base, state: 'unverified', entry, hint: 'grammar-failed' }); continue; }
    if (versionMismatch) { claims.push({ ...base, state: 'unverified', entry, hint: 'hash-version' }); continue; }
    if (entry.hash === anchor.hash) { claims.push({ ...base, state: 'verified', entry }); continue; }
    const rec: ClaimRecord = { ...base, state: 'stale', entry };
    if (entry.anchor.symbol !== anchor.symbol) rec.hint = 'symbol-renamed';
    claims.push(rec);
  }

  const orphans = [...entries.values()].filter(e => !seen.has(e.key));

  const summary: VerificationReport['summary'] = {
    verified: 0, stale: 0, unverified: 0, orphans: orphans.length, stale_by_verb: {}, demotable_stale: 0,
  };
  for (const c of claims) {
    summary[c.state] += 1;
    if (c.state === 'stale') {
      summary.stale_by_verb[c.verb] = (summary.stale_by_verb[c.verb] ?? 0) + 1;
      if (c.demotable) summary.demotable_stale += 1;
    }
  }

  return { ledger: read.status, claims, orphans, summary };
}

/** Keys of stale mitigates and accepts — what coverage.ts is told to disregard when demotion is on. */
export function demotionSet(report: VerificationReport): Set<string> {
  return new Set(report.claims.filter(c => c.state === 'stale' && c.demotable).map(c => c.key));
}
