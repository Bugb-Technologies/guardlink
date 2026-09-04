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
  /** Claims that cannot be recorded because they have no anchor (unreadable file, or an un-anchorable claim). */
  skipped: { key: string; file: string; line: number; reason: 'no-anchor' }[];
  /** Targets that matched nothing. */
  unmatched: string[];
  /** Set instead of touching a version-mismatched ledger under `stale` or a `targets` run — see planVerification. */
  refused?: 'hash-version-mismatch';
}

export interface VerifierIdentity {
  verified_by: string;
  verified_at: string;
  commit?: string;
}

const norm = (p: string): string => p.replaceAll('\\', '/').replace(/^\.\//, '');

/** Last write per key wins; used to collapse overlapping targets so a claim matched twice is not planned twice. */
const dedupe = <T extends { key: string }>(items: T[]): T[] => [...new Map(items.map(x => [x.key, x])).values()];

export function planVerification(report: VerificationReport, mode: VerifyMode): VerifyPlan {
  // A mismatched ledger makes every claim unverified for a reason that has nothing to do with
  // its code changing. `stale` would find nothing to re-lock and silently produce an empty plan;
  // a `targets` run would relock only the named file and leave the rest of a mismatched ledger to
  // vanish on the next default run with no record of what left. Only a whole-repository run
  // (`default` or `all`) is allowed to touch it, and it counts what it drops — see lockable below.
  if (report.hash_version_mismatch && (mode.kind === 'stale' || mode.kind === 'targets')) {
    return { lock: [], relock: [], prune: [], skipped: [], unmatched: [], refused: 'hash-version-mismatch' };
  }

  const plan: VerifyPlan = { lock: [], relock: [], prune: [], skipped: [], unmatched: [] };
  const unverified = report.claims.filter(c => c.state === 'unverified');
  const stale = report.claims.filter(c => c.state === 'stale');

  const lockable = (cs: ClaimRecord[]): ClaimRecord[] => cs.filter(c => {
    if (c.anchor) return true;
    plan.skipped.push({ key: c.key, file: c.location.file, line: c.location.line, reason: 'no-anchor' });
    // On a mismatched ledger, applyVerification rebuilds from this run's entries only — nothing
    // carries over. A claim that cannot be re-anchored will not be among them, so its old entry
    // is about to be dropped; count it here so the CLI never reports zero changes while it vanishes.
    if (report.hash_version_mismatch && c.entry) plan.prune.push(c.entry);
    return false;
  });

  switch (mode.kind) {
    case 'default':
      plan.lock = lockable(unverified);
      plan.prune.push(...report.orphans);
      break;
    case 'stale':
      plan.relock = stale;
      plan.prune.push(...report.orphans);
      break;
    case 'all':
      plan.lock = lockable(unverified);
      plan.relock = stale;
      plan.prune.push(...report.orphans);
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
      // Overlapping targets (e.g. a file and a line within it) can match the same claim or
      // orphan more than once; the plan reflects what will change, not how many targets asked for it.
      plan.lock = dedupe(plan.lock);
      plan.relock = dedupe(plan.relock);
      plan.skipped = dedupe(plan.skipped);
      plan.prune = dedupe(plan.prune);
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
 * it named was reported unverified, so a whole-repository run re-records the
 * ones it can re-anchor. That rebuild is reachable only through `default` or
 * `all` — `stale` and a `targets` run refuse a mismatched ledger outright
 * (see planVerification) rather than touch part of it. Any entry the rebuild
 * drops — a claim that could not be re-anchored — is already listed in
 * `plan.prune`, so nothing here disappears uncounted.
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

function osUsername(): string | undefined {
  try {
    return userInfo().username;
  } catch {
    return undefined;
  }
}

/** `human:<git user.name>`, else `human:<OS user>`, else `human:unknown`. One line, no control characters. */
export function defaultVerifier(root: string): string {
  const name = git(root, 'config', 'user.name') ?? osUsername() ?? '';
  // eslint-disable-next-line no-control-regex
  return `human:${name.replace(/[\x00-\x1f\x7f]+/g, ' ').trim() || 'unknown'}`;
}

export function headCommit(root: string): string | undefined {
  return git(root, 'rev-parse', 'HEAD');
}

export function nowIso(): string {
  return new Date().toISOString();
}
