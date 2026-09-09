/**
 * GuardLink — what an acceptance has to be before it counts as one.
 *
 * `@accepts` is the only verb a human writes to make a finding go away without
 * changing any code. Measured on OWASP NodeGoat before this module existed: one
 * generated file of 67 blanket `@accepts` lines plus `guardlink reanchor
 * --apply` took `guardlink ci --strict` from exit 1 to exit 0 — "✓ No
 * unmitigated exposures, no anchor drift" — while eight `@confirmed` reproduced
 * exploits sat untouched in the same model. `guardlink validate` passed at the
 * same moment, merely *advising* that 111 exposures were accepted without
 * mitigation. A gate a team passes by typing is not a gate.
 *
 * So an acceptance now has to be four things, and this file is the one place
 * that says what each of them means:
 *
 *   attributed   `by <who>` — a name a reviewer can go and ask
 *   justified    a real sentence, not a keystroke ("x" accepted a critical
 *                plaintext-password exposure in the measured run)
 *   scoped       it covers the file it was written in, and no other
 *   expiring     `until <date>` — after which it stops covering anything
 *
 * ── Two tiers, and why the line is where it is ──────────────────────
 *
 * SCOPE and EXPIRY are facts about the annotation, so they live in coverage
 * (`coverage.ts`) and are true everywhere: `ci`, `validate`, `sarif`, the
 * dashboard, MCP. They are what closes the measured blast radius, and they have
 * to close it in the SARIF too — that export is the surface cxg probes from, and
 * an acceptance that silences an exposure there stops it from ever being tested.
 *
 * QUALITY — attribution, justification, the presence of an expiry at all — is
 * POLICY, and policy is enforced by the gate (`ci/index.ts`), not by the parser.
 * The thresholds below are numbers someone will argue about and eventually
 * change; if they drove the export, raising `min_justification` by ten
 * characters would silently re-open findings in a pentest queue and lower it
 * would silently close them. A fact can decide what is in the model. A number in
 * a config file should only ever decide whether the build goes red.
 *
 * ── Why an unqualified acceptance is not a parse error ──────────────
 *
 * Because the parser dropping it is exactly the outcome an attacker wants: an
 * annotation the parser cannot see is not a finding, it is nothing at all, and
 * every count above it looks healthier for its absence (the argument
 * `ci/index.ts` already makes about parse diagnostics). An unattributed
 * acceptance parses, lands in the model, and is then NAMED — by the gate, by
 * `validate`, and in the review UI. Loud beats absent.
 *
 * @exposes #parser to #config-tamper [medium] cwe:CWE-15 -- "readAcceptancePolicy reads .guardlink/config.json to decide how strict this project's acceptance rule is, so anyone who can edit that file can lower the bar their own acceptances have to clear"
 * @mitigates #parser against #config-tamper using #config-validation -- "Every field is type- and range-checked and falls back to the built-in default; an absent, unreadable or malformed config yields DEFAULT_ACCEPTANCE_POLICY rather than an off switch, so a broken config cannot disable the policy by being broken"
 * @comment -- "What config CANNOT reach is the point: scope and expiry semantics are not settings. A project can move a threshold; it cannot declare that an acceptance covers a file it was not written in, because that is what the word means rather than a preference"
 * @audit #parser -- "The thresholds here are the price of an acceptance. Lowering min_justification or raising max_horizon_days in a PR is a governance change wearing a config diff, and deserves the same review as the acceptances it will admit"
 * @exposes #parser to #insecure-deser [low] cwe:CWE-502 -- "JSON.parse of a repository file"
 * @mitigates #parser against #insecure-deser using #config-validation -- "Parsed inside try/catch; only four scalar fields are read, each through a type guard, and nothing from the file is executed or used as a path"
 * @flows ThreatModel -> #parser via findAcceptanceDefects -- "Acceptances read and checked against policy"
 * @flows ConfigFile -> #parser via readAcceptancePolicy -- "Per-project policy thresholds, read only"
 * @handles internal on #parser -- "Reads the reviewer name and justification text an acceptance carries"
 * @comment -- "Pure functions apart from readAcceptancePolicy; `now` is a parameter so a test can pin the clock rather than skew it"
 * @comment -- "Scope and expiry are enforced in coverage.ts, not here — this module defines them and answers questions about them, coverage applies them"
 * @comment -- "acceptanceBlastRadius is read by guardlink review BEFORE the justification prompt: a reviewer typing one line sees how many exposures it removes from the gate and from the SARIF a pentest reads"
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ThreatModel, ThreatModelAcceptance, ThreatModelExposure, SourceLocation } from '../types/index.js';
import { normalizeRef } from './coverage.js';
import { canonicaliser } from './canonical-ref.js';

// ─── Policy ─────────────────────────────────────────────────────────

export interface AcceptancePolicy {
  /**
   * Shortest justification that counts as one.
   *
   * 24, and the number is an argument rather than a preference. A justification
   * is read by someone who was not in the room, so it has to survive being the
   * only thing they get. Below roughly twenty characters nothing survives:
   * "wontfix", "known issue", "by design", "legacy" and "x" all fit under 12 and
   * all of them are a category, not a reason. 24 is the shortest bar that
   * refuses every one of those and still admits a real one — "Internal-only
   * admin tool, no PII" is 32. It is not a quality test and does not pretend to
   * be; it is a floor that costs a sentence, which is precisely the cost this
   * whole change exists to introduce.
   */
  min_justification: number;
  /** An acceptance must name the human who made it (`by <who>`). */
  require_author: boolean;
  /** An acceptance must carry `until <YYYY-MM-DD>`. */
  require_expiry: boolean;
  /**
   * Longest lifetime a NEW acceptance may be written with, in days.
   *
   * 365. An acceptance is a decision about a risk as it stands today, and a
   * codebase does not stand still for a year; anything longer is a permanent
   * deletion wearing a date. Only checked when an acceptance is WRITTEN
   * (`guardlink review`) — an existing annotation with a longer horizon is
   * reported by the gate, never rewritten underneath its author.
   */
  max_horizon_days: number;
}

export const DEFAULT_ACCEPTANCE_POLICY: AcceptancePolicy = {
  min_justification: 24,
  require_author: true,
  require_expiry: true,
  max_horizon_days: 365,
};

/**
 * Per-project overrides from `.guardlink/config.json`:
 *
 * ```json
 * { "acceptance": { "min_justification": 40, "max_horizon_days": 90 } }
 * ```
 *
 * Same shape as `readConfiguredMode` and `readDisabledDiagnostics` — one way to
 * ask config.json a question. A missing or unreadable config yields the
 * defaults: a config a team cannot parse must not be able to switch the policy
 * off by being broken.
 *
 * Note what is NOT configurable: scope and expiry semantics. A project can move
 * a threshold; it cannot decide that an acceptance covers a file it was not
 * written in, because that is not a setting, it is what the word means.
 */
export function readAcceptancePolicy(root: string): AcceptancePolicy {
  try {
    const config = JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf-8'));
    const raw = config.acceptance;
    if (!raw || typeof raw !== 'object') return DEFAULT_ACCEPTANCE_POLICY;
    const num = (v: unknown, fallback: number): number =>
      typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : fallback;
    const bool = (v: unknown, fallback: boolean): boolean => (typeof v === 'boolean' ? v : fallback);
    return {
      min_justification: num(raw.min_justification, DEFAULT_ACCEPTANCE_POLICY.min_justification),
      require_author: bool(raw.require_author, DEFAULT_ACCEPTANCE_POLICY.require_author),
      require_expiry: bool(raw.require_expiry, DEFAULT_ACCEPTANCE_POLICY.require_expiry),
      max_horizon_days: num(raw.max_horizon_days, DEFAULT_ACCEPTANCE_POLICY.max_horizon_days),
    };
  } catch {
    return DEFAULT_ACCEPTANCE_POLICY;
  }
}

// ─── Expiry ─────────────────────────────────────────────────────────

/** `2027-03-01` → a Date at UTC midnight, or null if it is not a real calendar day. */
export function parseExpiry(value: string | undefined): Date | null {
  if (!value) return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(Date.UTC(y, mo - 1, d));
  // Round-trip check: Date.UTC rolls 2026-02-30 forward into March rather than
  // rejecting it, so a typo would otherwise parse into a real but wrong day.
  if (date.getUTCFullYear() !== y || date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d) return null;
  return date;
}

/** Today at UTC midnight — the granularity an `until <date>` clause is written at. */
export function utcDay(now: Date = new Date()): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}

export function todayISO(now: Date = new Date()): string {
  return utcDay(now).toISOString().slice(0, 10);
}

/** `until` is inclusive: an acceptance dated today still covers today. */
export function isExpired(acceptance: Pick<ThreatModelAcceptance, 'expires'>, now: Date = new Date()): boolean {
  const until = parseExpiry(acceptance.expires);
  if (!until) return false; // no expiry, or an unreadable one — see `malformed-expiry`
  return until.getTime() < utcDay(now).getTime();
}

/** Whole days from today to `expires`. Negative once it has lapsed. */
export function daysRemaining(acceptance: Pick<ThreatModelAcceptance, 'expires'>, now: Date = new Date()): number | null {
  const until = parseExpiry(acceptance.expires);
  if (!until) return null;
  return Math.round((until.getTime() - utcDay(now).getTime()) / 86_400_000);
}

// ─── Quality ────────────────────────────────────────────────────────

/**
 * What is wrong with an acceptance. One code per defect so the gate can name it
 * and a consumer can count them without matching on prose.
 */
export type AcceptanceDefect =
  /** No `by <who>` — nobody's name is on the decision. */
  | 'unattributed'
  /** The justification is shorter than the policy floor, or absent. */
  | 'unjustified'
  /** No `until <date>` — a permanent deletion rather than a decision. */
  | 'undated'
  /** An `until` clause that is not a real calendar day. */
  | 'malformed-expiry'
  /** `until` is in the past. Reported separately: this one is not a mistake, it is time passing. */
  | 'expired';

export interface AcceptanceFinding {
  acceptance: ThreatModelAcceptance;
  defects: AcceptanceDefect[];
  /** One line naming every defect, in the register `validate` uses. */
  message: string;
  file: string;
  line: number;
  /** Whole days left, or null when there is no readable expiry. */
  days_remaining: number | null;
}

const DEFECT_TEXT: Record<AcceptanceDefect, (p: AcceptancePolicy) => string> = {
  unattributed: () => 'no `by <who>` — an acceptance with nobody\'s name on it cannot be asked about',
  unjustified: p => `justification is under ${p.min_justification} characters — say what makes this risk acceptable, not that it is`,
  undated: () => 'no `until <YYYY-MM-DD>` — an acceptance without a horizon is a deletion, not a decision',
  'malformed-expiry': () => '`until` is not a real calendar date (YYYY-MM-DD)',
  expired: () => 'expired — the horizon its author set has passed; re-decide it or fix the risk',
};

/**
 * Every way this one acceptance falls short, in the order a reader should hear
 * them. Empty means it counts.
 */
export function acceptanceDefects(
  acceptance: ThreatModelAcceptance,
  policy: AcceptancePolicy = DEFAULT_ACCEPTANCE_POLICY,
  now: Date = new Date(),
): AcceptanceDefect[] {
  const defects: AcceptanceDefect[] = [];
  if (policy.require_author && !(acceptance.accepted_by || '').trim()) defects.push('unattributed');
  if ((acceptance.description || '').trim().length < policy.min_justification) defects.push('unjustified');
  if (!acceptance.expires) {
    if (policy.require_expiry) defects.push('undated');
  } else if (!parseExpiry(acceptance.expires)) {
    defects.push('malformed-expiry');
  } else if (isExpired(acceptance, now)) {
    defects.push('expired');
  }
  return defects;
}

/** True when this acceptance meets the policy in full. */
export function isQualified(
  acceptance: ThreatModelAcceptance,
  policy: AcceptancePolicy = DEFAULT_ACCEPTANCE_POLICY,
  now: Date = new Date(),
): boolean {
  return acceptanceDefects(acceptance, policy, now).length === 0;
}

/**
 * Every acceptance in the model that does not meet the policy, with what is
 * wrong with each.
 *
 * This is what `guardlink ci` gates on and what `guardlink validate` warns
 * about — one list, two registers, so the two cannot disagree about which
 * acceptances are real.
 */
export function findAcceptanceDefects(
  model: ThreatModel,
  policy: AcceptancePolicy = DEFAULT_ACCEPTANCE_POLICY,
  now: Date = new Date(),
): AcceptanceFinding[] {
  const findings: AcceptanceFinding[] = [];
  for (const acceptance of model.acceptances) {
    const defects = acceptanceDefects(acceptance, policy, now);
    if (defects.length === 0) continue;
    findings.push({
      acceptance,
      defects,
      message: `@accepts ${acceptance.threat} on ${acceptance.asset}: `
        + defects.map(d => DEFECT_TEXT[d](policy)).join('; '),
      file: acceptance.location.file,
      line: acceptance.location.line,
      days_remaining: daysRemaining(acceptance, now),
    });
  }
  return findings;
}

// ─── Scope, and how far one line reaches ────────────────────────────

/**
 * An acceptance covers the file it was written in.
 *
 * The whole of the scope rule, stated once. `coverage.ts` applies it; every
 * other surface asks here rather than re-deriving it.
 *
 * ── Why the file, and not the pair ──────────────────────────────────
 *
 * Before this, an acceptance was keyed on `(asset, threat)` alone, exactly like
 * a mitigation. Measured on NodeGoat: one `@accepts` at `app/data/user-dao.js:17`
 * also silenced the identical pair at `artifacts/db-reset.js:12` — a site its
 * author never opened — in the gate AND in the SARIF that cxg probes from. One
 * line, an unbounded blast radius, and nothing at the point of writing said so.
 *
 * A mitigation may legitimately reach across files: a control is code, it runs,
 * and the filter at the trust boundary really does defend the handler downstream
 * of it. That is the argument `coverage.ts` makes, with a measured 6-of-6
 * false-positive rate against tightening it, and it is untouched here.
 *
 * An acceptance is not code and does not run. It is a human saying "I read this
 * risk, at this site, and I sign for it". That claim does not travel: whoever
 * signed at `user-dao.js` did not read `db-reset.js`, and the model holds no
 * evidence that they did. So the acceptance covers where its author was looking,
 * and a second site needs a second signature — which is the cost, and the point.
 *
 * ── Why the file and not the line ───────────────────────────────────
 *
 * The file is the finest granularity the model supports in BOTH authoring modes.
 * `guardlink review` writes the `@accepts` a few lines below the `@exposes` it
 * answers, so line equality never holds; symbol anchors exist only in external
 * mode, so a symbol rule would be inert in every inline repo and would silently
 * mean nothing where most annotations live. Same-file is the rule that is true
 * in both, and the same-file-different-symbol narrowing already in `coverage.ts`
 * still applies on top of it wherever anchors do exist — so external repos get
 * the finer answer for free without inline repos getting a fake one.
 */
export function acceptanceCovers(
  acceptance: Pick<ThreatModelAcceptance, 'location' | 'expires'>,
  exposureLocation: SourceLocation,
  now: Date = new Date(),
): boolean {
  if (isExpired(acceptance, now)) return false;
  return normalizeFile(acceptance.location.file) === normalizeFile(exposureLocation.file);
}

function normalizeFile(file: string): string {
  return (file ?? '').replaceAll('\\', '/');
}

export interface BlastRadius {
  /** Exposures this acceptance would stop reporting, at this site. */
  silenced: ThreatModelExposure[];
  /**
   * Exposures on the same `(asset, threat)` that it does NOT reach, because they
   * are in other files. Shown so a reviewer can see the risk is wider than their
   * signature — and that silencing those needs their signature too.
   */
  elsewhere: ThreatModelExposure[];
}

/**
 * What one `@accepts` line, written into `file`, would actually silence.
 *
 * Answers the question a reviewer could not previously ask: how many findings
 * does this keystroke remove, from the gate and from the SARIF cxg probes? The
 * two surfaces share `coverage.ts`, so this one number is true of both, and
 * `guardlink review` prints it BEFORE the justification prompt rather than after
 * the write.
 */
export function acceptanceBlastRadius(
  model: ThreatModel,
  asset: string,
  threat: string,
  file: string,
): BlastRadius {
  const silenced: ThreatModelExposure[] = [];
  const elsewhere: ThreatModelExposure[] = [];
  const here = normalizeFile(file);
  // D47's asset resolver, so `#api` and `App.API` are one asset here exactly as
  // they are in `coverage.ts`. Without it this count would under-report against
  // the predicate it is supposed to describe — a blast radius smaller than the
  // real one is the worst possible direction for this number to be wrong in.
  const assetKey = canonicaliser(model);
  for (const e of model.exposures) {
    if (assetKey(e.asset) !== assetKey(asset) || normalizeRef(e.threat) !== normalizeRef(threat)) continue;
    (normalizeFile(e.location.file) === here ? silenced : elsewhere).push(e);
  }
  return { silenced, elsewhere };
}

/** `2 here, 5 in other files` — the one-line rendering both surfaces print. */
export function formatBlastRadius(radius: BlastRadius): string {
  const here = `${radius.silenced.length} exposure(s) in this file`;
  return radius.elsewhere.length === 0
    ? here
    : `${here}; ${radius.elsewhere.length} more on the same asset+threat elsewhere, which this does NOT cover`;
}
