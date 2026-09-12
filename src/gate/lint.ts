/**
 * GuardLink Gate — the annotation lint.
 *
 * Pure over the model. Each rule mirrors one line of the evidence bar in
 * src/playbooks/evidence.ts: what the prompt demands is what this checks, so
 * an agent that ignored the bar is caught by the same words it ignored.
 *
 * @flows ThreatModel -> #gate via lintAnnotations -- "Claims and their descriptions"
 * @comment -- "Errors are what the gate rejects; warnings are what it reports. Governance verbs (@accepts, @entitles) are errors only for claims under check, because a human may legitimately have written the others"
 */
import type { ThreatModel, ThreatModelExposure, ThreatModelConfirmed } from '../types/index.js';
import { relationRecords } from '../parser/claim-key.js';
import { buildCoverageIndex } from '../parser/coverage.js';

export type LintLevel = 'error' | 'warn';

export type LintRule =
  | 'exposes-no-code-reference'
  | 'exposes-unpaired'
  | 'exposes-severity-above-threat'
  | 'accepts-written'
  | 'entitles-written'
  | 'confirmed-without-evidence'
  | 'mitigates-no-control'
  | 'description-vague';

export interface Violation {
  rule: LintRule;
  level: LintLevel;
  verb: string;
  /** Where the annotation text lives (the sidecar for a .gal claim). */
  file: string;
  line: number;
  /** The claim as written, for the report. */
  claim: string;
  message: string;
  /** The stable claim key, when the record is one `relationRecords` knows. */
  key: string | null;
}

export interface LintOptions {
  /** Restrict to these claim keys (what a run added). Absent: every claim. */
  only?: Set<string>;
  /**
   * How to treat @accepts and @entitles among the claims under check.
   * `error` (default) is the gate's stance: an agent must never write them.
   * `ignore` is for a standalone lint over a tree a person may have edited.
   */
  governance?: 'error' | 'ignore';
}

/** What a rule asks the agent to do instead. Used by the follow-up prompt. */
export const RULE_FIX: Record<LintRule, string> = {
  'exposes-no-code-reference': 'Rewrite the description to name the entry point, the attacker-controlled input, the sink call and the absent control, in the code\'s own names (function names, fields, file:line). If you cannot name all four, replace the @exposes with an @audit on the asset.',
  'exposes-unpaired': 'Pair it: add the @mitigates that covers this asset against this threat (naming the control), or an @audit on the asset saying why nothing does. Never leave an @exposes alone.',
  'exposes-severity-above-threat': 'Lower the severity to the threat\'s declared band, or leave it unset so the threat\'s severity applies. A definition change is a human decision.',
  'accepts-written': 'Remove the @accepts. Accepting a risk is a human decision; write an @audit describing the risk and the decision needed instead.',
  'entitles-written': 'Remove the @entitles. File it with `guardlink entitle --propose` citing the authorization code as file:line; a human\'s acceptance writes the annotation.',
  'confirmed-without-evidence': 'Downgrade to @exposes unless you hold evidence — a request and its response, a reproduction, a scan with proof — and put that evidence in the description.',
  'mitigates-no-control': 'Name the control with `using #control-id`, adding the control to the definitions file if it does not exist.',
  'description-vague': 'Say what the code does, by name: which function, which field, which library, which check.',
};

const SEV_RANK: Record<string, number> = { critical: 4, p0: 4, high: 3, p1: 3, medium: 2, p2: 2, low: 1, p3: 1 };
const sevRank = (s: string | undefined | null): number | null => (s ? SEV_RANK[s.toLowerCase()] ?? null : null);

/** Descriptions that say nothing a reader can check. Compared after lowercasing and stripping punctuation. */
const VAGUE = new Set([
  'input not validated', 'not validated', 'no validation', 'sql injection possible', 'injection possible', 'possible injection',
  'uses encryption', 'security vulnerability exists', 'security vulnerability', 'vulnerability exists', 'handled', 'mitigated',
  'security stuff', 'security issue', 'todo', 'fixme', 'tbd', 'see above', 'see below', 'as above', 'n/a', 'none', 'fixed', 'ok',
]);

const normalise = (d: string): string => d.toLowerCase().replace(/[^a-z0-9/ ]+/g, ' ').replace(/\s+/g, ' ').trim();
const isVague = (d: string | undefined | null): boolean => !d || d.trim().length === 0 || VAGUE.has(normalise(d));

/**
 * Does the description name code? A call, a dotted or path-like name, a
 * camelCase or CONST_CASE or snake_case identifier, or a file:line.
 */
const CODE_REF = [
  /\b[A-Za-z_][A-Za-z0-9_]*\(\)?/,                       // findUser(), query(
  /\b[A-Za-z_][A-Za-z0-9_]+[./][A-Za-z_][A-Za-z0-9_]+/,   // user.email, handler.go, src/a
  /\b[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b/,                  // innerHTML, parseBody
  /\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b/,                        // BIO_FIELD, MAX_SIZE
  /\b[a-z][a-z0-9]*_[a-z0-9_]+\b/,                        // req_body, user_id
  /\b[\w./-]+:\d+\b/,                                     // db.ts:40
];
export const hasCodeReference = (d: string): boolean => CODE_REF.some(r => r.test(d));

/** Words that mark evidence in hand: a request and response, a reproduction, a scan with proof. Shared with the hypothesis ledger. */
export const hasEvidenceWords = (d: string): boolean => EVIDENCE.test(d);

const EVIDENCE = /\b(request|response|http|status \d{3}|payload|reproduc\w*|pentest|scan(ned|ner)?|poc|proof|observed|returned|evidence|curl|cxg|exploited|verified)\b/i;

const bare = (ref: string): string => ref.trim().replace(/^#/, '').toLowerCase();

/** Every name the model uses for an asset, folded onto one canonical string. */
function assetCanon(model: ThreatModel): (ref: string) => string {
  const map = new Map<string, string>();
  for (const a of model.assets) {
    const path = a.path.join('.').toLowerCase();
    const canon = a.id ? a.id.toLowerCase() : path;
    map.set(path, canon);
    map.set(a.path[a.path.length - 1].toLowerCase(), canon);
    if (a.id) map.set(a.id.toLowerCase(), canon);
  }
  return (ref: string): string => map.get(bare(ref)) ?? bare(ref);
}

function threatSeverity(model: ThreatModel): (ref: string) => number | null {
  const map = new Map<string, number | null>();
  for (const t of model.threats) {
    const r = sevRank(t.severity);
    map.set(t.name.toLowerCase(), r);
    map.set(t.canonical_name.toLowerCase(), r);
    if (t.id) map.set(t.id.toLowerCase(), r);
  }
  return (ref: string): number | null => map.get(bare(ref)) ?? null;
}

const where = (loc: { file: string; line: number; origin_file?: string | null; origin_line?: number | null }): { file: string; line: number } =>
  ({ file: loc.origin_file ?? loc.file, line: loc.origin_line ?? loc.line });

export function lintAnnotations(model: ThreatModel, opts: LintOptions = {}): Violation[] {
  const governance = opts.governance ?? 'error';
  const keyOf = new Map<object, string>();
  const claimOf = new Map<object, string>();
  for (const r of relationRecords(model)) { keyOf.set(r.location, r.key); claimOf.set(r.location, r.claim); }
  const under = (loc: object): boolean => !opts.only || opts.only.has(keyOf.get(loc) ?? '');

  const canon = assetCanon(model);
  const threatSev = threatSeverity(model);
  const coverage = buildCoverageIndex(model);
  const audited = new Set(model.audits.map(a => canon(a.asset)));
  // A transfer pairs an exposure without covering it (the exposure stays open in every export), so it is not a coverage key.
  const transferred = new Set(model.transfers.map(t => `${canon(t.source)}::${bare(t.threat)}`));

  const out: Violation[] = [];
  const push = (rule: LintRule, level: LintLevel, verb: string, rec: { location: ThreatModelExposure['location'] }, message: string): void => {
    const w = where(rec.location);
    out.push({ rule, level, verb, file: w.file, line: w.line, claim: claimOf.get(rec.location) ?? '', message, key: keyOf.get(rec.location) ?? null });
  };

  for (const e of model.exposures) {
    if (!under(e.location)) continue;
    const d = e.description ?? '';
    if (isVague(d) || !hasCodeReference(d)) push('exposes-no-code-reference', 'error', 'exposes', e, `"${d || '(no description)'}" names no entry point, input, sink or absent control from the code`);
    // A refuted hypothesis (tested, not exploitable, evidence in the ledger) pairs the exposure without covering it.
    const paired = coverage.isCovered(e) || transferred.has(`${canon(e.asset)}::${bare(e.threat)}`) || audited.has(canon(e.asset)) || e.hypothesis?.state === 'refuted';
    if (!paired) push('exposes-unpaired', 'error', 'exposes', e, `${e.asset} → ${e.threat} has no @mitigates, @audit, @accepts or @transfers beside it`);
    const er = sevRank(e.severity), tr = threatSev(e.threat);
    if (er !== null && tr !== null && er > tr) push('exposes-severity-above-threat', 'error', 'exposes', e, `severity ${e.severity} outranks ${e.threat}'s declared severity (${model.threats.find(t => bare(t.id ?? '') === bare(e.threat) || t.name.toLowerCase() === bare(e.threat))?.severity ?? 'unset'})`);
  }
  for (const c of model.confirmed || []) {
    if (!under(c.location)) continue;
    const d = (c as ThreatModelConfirmed).description ?? '';
    if (!EVIDENCE.test(d)) push('confirmed-without-evidence', 'error', 'confirmed', c, `"${d || '(no description)'}" holds no evidence (a request and response, a reproduction, a scan with proof)`);
  }
  if (governance === 'error') {
    for (const a of model.acceptances) if (under(a.location)) push('accepts-written', 'error', 'accepts', a, `@accepts ${a.threat} on ${a.asset} is a human decision`);
    for (const en of model.entitlements || []) if (under(en.location)) push('entitles-written', 'error', 'entitles', en, `@entitles ${en.actor} is proposed, never written`);
  }
  for (const m of model.mitigations) {
    if (!under(m.location)) continue;
    if (!m.control) push('mitigates-no-control', 'warn', 'mitigates', m, `${m.asset} against ${m.threat} names no control`);
    if (isVague(m.description)) push('description-vague', 'warn', 'mitigates', m, `"${m.description ?? ''}" does not say what the control is`);
  }
  for (const a of model.audits) if (under(a.location) && isVague(a.description)) push('description-vague', 'warn', 'audit', a, `"${a.description ?? ''}" does not say what needs review`);
  for (const c of model.comments) if (under(c.location) && isVague(c.description)) push('description-vague', 'warn', 'comment', c, `"${c.description ?? ''}" says nothing a reader can use`);
  for (const t of model.transfers) if (under(t.location) && isVague(t.description)) push('description-vague', 'warn', 'transfers', t, `"${t.description ?? ''}" does not say who holds the risk or how`);
  for (const a of model.assumptions) if (under(a.location) && isVague(a.description)) push('description-vague', 'warn', 'assumes', a, `"${a.description ?? ''}" does not say what must hold`);

  return out.sort((x, y) => (x.file < y.file ? -1 : x.file > y.file ? 1 : x.line - y.line || x.rule.localeCompare(y.rule)));
}
