// src/parser/verify.ts
/**
 * GuardLink — decide which claims a verify run touches, and produce the ledger.
 *
 * Two pure steps so the CLI and the MCP tool cannot disagree:
 *   planVerification(report, mode) → which claims to lock, re-lock, prune, skip
 *   applyVerification(ledger, plan, identity) → the new ledger, not yet written
 *
 * Re-locking a stale claim asserts the control still holds, so the default
 * mode never does it; `stale`, `all` and a named target do, and say so.
 *
 * @flows #cli -> LedgerFile via applyVerification -- "The ledger the verify surfaces write"
 * @exposes #cli to #cmd-injection [low] cwe:CWE-78 -- "git is spawned for the verifier name and HEAD"
 * @mitigates #cli against #cmd-injection using #param-commands -- "execFileSync with a fixed argv; no shell, no caller-supplied argument"
 * @comment -- "Identity comes from git config or the OS user, is prefixed human: here and agent: in the MCP tool, and is recorded verbatim so a later gate can key on the prefix"
 */
import { execFileSync } from 'node:child_process';
import { userInfo } from 'node:os';
import type { Ledger, LedgerEntry } from './ledger.js';
import { emptyLedger } from './ledger.js';
import type { ClaimRecord, VerificationReport } from './verification.js';
import { ANCHOR_HASH_VERSION } from '../structure/hash.js';

export interface VerifyTarget { file: string; line?: number }

export type VerifyMode =
  | { kind: 'default' }
  | { kind: 'stale' }
  | { kind: 'all' }
  | { kind: 'targets'; targets: VerifyTarget[] };

export interface VerifyPlan {
  /** Unverified claims to record for the first time. */
  lock: ClaimRecord[];
  /** Stale claims to record again — an assertion that the control still holds. */
  relock: ClaimRecord[];
  /** Ledger entries with no matching claim. */
  prune: LedgerEntry[];
  /** Claims that cannot be recorded because their file could not be read. */
  skipped: { key: string; file: string; line: number; reason: 'no-anchor' }[];
  /** Targets that matched nothing. */
  unmatched: string[];
}

export interface VerifierIdentity {
  verified_by: string;
  verified_at: string;
  commit?: string;
}

const norm = (p: string): string => p.replaceAll('\\', '/').replace(/^\.\//, '');

export function planVerification(report: VerificationReport, mode: VerifyMode): VerifyPlan {
  const plan: VerifyPlan = { lock: [], relock: [], prune: [], skipped: [], unmatched: [] };
  const unverified = report.claims.filter(c => c.state === 'unverified');
  const stale = report.claims.filter(c => c.state === 'stale');

  const lockable = (cs: ClaimRecord[]): ClaimRecord[] => cs.filter(c => {
    if (c.anchor) return true;
    plan.skipped.push({ key: c.key, file: c.location.file, line: c.location.line, reason: 'no-anchor' });
    return false;
  });

  switch (mode.kind) {
    case 'default':
      plan.lock = lockable(unverified);
      plan.prune = report.orphans;
      break;
    case 'stale':
      plan.relock = stale;
      plan.prune = report.orphans;
      break;
    case 'all':
      plan.lock = lockable(unverified);
      plan.relock = stale;
      plan.prune = report.orphans;
      break;
    case 'targets':
      for (const t of mode.targets) {
        const file = norm(t.file);
        const hit = (c: ClaimRecord) => norm(c.location.file) === file && (t.line === undefined || c.location.line === t.line);
        const matchedUnverified = lockable(unverified.filter(hit));
        const matchedStale = stale.filter(hit);
        const matchedOrphans = t.line === undefined ? report.orphans.filter(o => norm(o.file) === file) : [];
        if (matchedUnverified.length + matchedStale.length + matchedOrphans.length === 0
          && !report.claims.some(hit)) {
          plan.unmatched.push(t.line === undefined ? t.file : `${t.file}:${t.line}`);
        }
        plan.lock.push(...matchedUnverified);
        plan.relock.push(...matchedStale);
        plan.prune.push(...matchedOrphans);
      }
      break;
  }
  return plan;
}

function entryFor(c: ClaimRecord, identity: VerifierIdentity): LedgerEntry {
  const a = c.anchor!;
  const e: LedgerEntry = {
    key: c.key, file: c.location.file, verb: c.verb, claim: c.claim,
    anchor: { scope: a.scope, symbol: a.symbol }, hash: a.hash,
    verified_by: identity.verified_by, verified_at: identity.verified_at,
  };
  if (identity.commit) e.commit = identity.commit;
  return e;
}

/**
 * The ledger after the plan. A ledger at another hash version is rebuilt from
 * this run's entries only: its old hashes cannot be compared, and every claim
 * it named was reported unverified, so the default mode re-records them all.
 */
export function applyVerification(current: Ledger | null, plan: VerifyPlan, identity: VerifierIdentity): Ledger {
  const next = emptyLedger();
  const byKey = new Map<string, LedgerEntry>();
  if (current && current.anchor_hash_version === ANCHOR_HASH_VERSION) {
    for (const e of current.entries) byKey.set(e.key, e);
  }
  for (const o of plan.prune) byKey.delete(o.key);
  for (const c of [...plan.lock, ...plan.relock]) byKey.set(c.key, entryFor(c, identity));
  next.entries = [...byKey.values()];
  return next;
}

function git(root: string, ...args: string[]): string | undefined {
  try {
    return execFileSync('git', args, { cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || undefined;
  } catch {
    return undefined;
  }
}

/** `human:<git user.name>`, else `human:<OS user>`. One line, no control characters. */
export function defaultVerifier(root: string): string {
  const name = git(root, 'config', 'user.name') ?? userInfo().username;
  return `human:${name.replace(/[\r\n\t]+/g, ' ').trim() || 'unknown'}`;
}

export function headCommit(root: string): string | undefined {
  return git(root, 'rev-parse', 'HEAD');
}

export function nowIso(): string {
  return new Date().toISOString();
}
