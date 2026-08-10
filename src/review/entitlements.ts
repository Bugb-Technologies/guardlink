/**
 * GuardLink — Entitlement proposals (§3.6 of docs/prd/actor-entitlement-design.md).
 *
 * `@entitles` is the one annotation whose error mode is a silent false negative:
 * an over-grant closes a real privilege escalation as by-design and nobody ever
 * sees the finding (§2). So it does not reach source the way the other verbs do.
 * An annotating agent *proposes* into `.guardlink/entitlement-proposals.json`,
 * and only a human acceptance writes the annotation — carrying the name of the
 * person who made the claim, because an entitlement is precisely the kind of
 * claim a maintainer will contest.
 *
 * Three rules are enforced here rather than described in a prompt:
 *
 *   §3.4  An uncited proposal cannot silently become an effective entitlement.
 *         Accepting one requires `acknowledgeInert`, and the annotation that
 *         lands says in source that it is inert.
 *   §3.5  A proposal aimed at an ownership-class threat (IDOR, tenant/namespace
 *         isolation, CWE-639/862/863) is warned about at proposal time and cannot
 *         be accepted without `acknowledgeOwnership` — that is the structural
 *         over-grant the design forbids, and no citation fixes it.
 *   §3.6  An `@entitles` in source with no accepted proposal behind it is a
 *         validation error, so writing one directly is visible rather than free.
 *
 * The ledger is the audit trail: a decision is appended, never a record deleted,
 * so a rejection stays readable next to the claim it refused.
 *
 * @exposes #cli to #arbitrary-write [high] cwe:CWE-73 -- "Accepting a proposal writes an @entitles line into a source file named by the proposal"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "Target must resolve inside the project root and name an existing file with the anchor line in range"
 * @exposes #cli to #insecure-deser [medium] cwe:CWE-502 -- "JSON.parse of .guardlink/entitlement-proposals.json, which an agent or another repo may have written"
 * @mitigates #cli against #insecure-deser using #config-validation -- "parseLedger validates shape field by field and drops nothing silently — a malformed ledger is an error, not a partial read; `inert` is recomputed from the citation rather than trusted from the file"
 * @mitigates #cli against #insecure-deser using #resource-limits -- "Ledger reads are capped at MAX_LEDGER_BYTES"
 * @exposes #cli to #arbitrary-write [high] cwe:CWE-74 -- "Agent-supplied rationale and human decision notes are interpolated into annotation text, where a newline would forge a second annotation"
 * @mitigates #cli against #arbitrary-write using #input-sanitize -- "oneLine() collapses newlines/CR/tabs before escapeDesc, and every built line is re-parsed with parseLine before it is written"
 * @flows AgentProposal -> #cli via proposeEntitlement -- "Agent-side proposal input"
 * @flows #cli -> ProposalLedger via writeFile -- "Proposal artifact output"
 * @flows ProposalLedger -> #cli via readFile -- "Proposal artifact input"
 * @flows #cli -> SourceFiles via applyProposalDecision -- "Accepted entitlement lands as an @entitles annotation"
 * @handles internal on #cli -- "Processes actor/capability claims, authz citations, and the name of the accepting human"
 * @audit #cli -- "Every acceptance records who accepted, when, and where the annotation landed; an inert or ownership-class acceptance records the acknowledgement that was required to make it"
 * @comment -- "There is no MCP accept tool and no agent-callable accept path: the only writer of an accepted entitlement is a human at `guardlink entitle`, which is why the CLI is the surface and this module refuses a decision with no name on it"
 */

import { execFileSync } from 'node:child_process';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { extractCitation } from '../parser/citation.js';
import { normalizeName } from '../parser/normalize.js';
import { parseLine } from '../parser/parse-line.js';
import { escapeDesc, insertAnnotationsAt, type CommentStyle } from './index.js';
import type {
  EntitlementCitation, EntitlesAnnotation, ParseDiagnostic, ThreatModel,
} from '../types/index.js';

// ─── Types ──────────────────────────────────────────────────────────

export type ProposalStatus = 'proposed' | 'accepted' | 'rejected' | 'deferred';

/** A decision a human recorded against a proposal. Kept forever in `history`. */
export interface ProposalDecision {
  status: 'accepted' | 'rejected' | 'deferred';
  /** The human who decided. An entitlement carries a name (§3.6). */
  by: string;
  /** ISO date (YYYY-MM-DD) */
  at: string;
  note?: string;
  /** The `file:line` anchor the @entitles annotation was written against (accepted only).
   *  The annotation lands just below the coupled block at that anchor. */
  written_to?: string;
  /** True when the accepted claim had no citation and the human said so anyway (§3.4) */
  acknowledged_inert?: boolean;
  /** True when the human accepted over an ownership-class warning (§3.5) */
  acknowledged_ownership_class?: boolean;
}

/** Where an accepted @entitles annotation is written. */
export interface ProposalTarget {
  /** Repo-relative path */
  file: string;
  /** 1-indexed line to anchor the annotation to */
  line: number;
}

export interface EntitlementProposal {
  /** Deterministic; keyed on (actor, capability) like `guardlink diff` (§3.1) */
  id: string;
  actor: string;
  capability: string;
  /** §2.10-normalised capability. NOT a join key (§9.3): nothing on the finding side carries a
   *  capability, so it cannot be matched against — the join is (actor, asset, threat). This is the
   *  justification a reviewer reads, and a stable label for grouping claims. */
  canonical_capability: string;
  /** Optional `on <asset>` context */
  asset?: string;
  /** Threat class the proposal is meant to answer for. Optional, but without it
   *  the §3.5 ownership-class check has less to work with. */
  threat?: string;
  /** Why this is by design. Must carry a `file:line` pointer at the authz code. */
  rationale: string;
  citation?: EntitlementCitation;
  /** True when the rationale carries no citation — the annotation would be inert (§3.4) */
  inert: boolean;
  target: ProposalTarget;
  /** Agent or person that filed it, verbatim */
  proposed_by: string;
  proposed_at: string;
  updated_at?: string;
  status: ProposalStatus;
  /** Raised at proposal time and re-shown at decision time. Never auto-clears. */
  warnings: string[];
  /** Latest decision */
  decision?: ProposalDecision;
  /** Every decision ever recorded, oldest first */
  history: ProposalDecision[];
}

export interface ProposalLedger {
  version: string;
  proposals: EntitlementProposal[];
}

export interface ProposeInput {
  actor: string;
  capability: string;
  asset?: string;
  threat?: string;
  rationale: string;
  /** Repo-relative file the accepted annotation should land in */
  file: string;
  /** 1-indexed anchor line in `file` */
  line: number;
  /** Agent or person filing the proposal */
  proposed_by: string;
}

export interface ProposeResult {
  proposal: EntitlementProposal;
  /** False when this replaced an existing undecided proposal for the same claim */
  created: boolean;
  /** Set when an already-decided proposal blocked the filing; the ledger is untouched */
  refused?: string;
  warnings: string[];
}

export interface DecisionInput {
  status: 'accepted' | 'rejected' | 'deferred';
  /** Human name — required; an acceptance with no name is not an acceptance */
  by: string;
  note?: string;
  /** §3.4 override: accept a claim that cites no authz code, knowing it is inert */
  acknowledgeInert?: boolean;
  /** §3.5 override: accept a claim the ownership-class check warned about */
  acknowledgeOwnership?: boolean;
}

export interface DecisionResult {
  proposal: EntitlementProposal;
  /** 0 for reject/defer — a contested proposal never touches source */
  linesInserted: number;
  /** Set only when an annotation was written */
  targetFile?: string;
  /** Ownership-class and inertness notes the human should have seen */
  warnings: string[];
}

// ─── Constants ──────────────────────────────────────────────────────

export const LEDGER_VERSION = '1';
export const PROPOSALS_FILE = 'entitlement-proposals.json';

/** A ledger is a review queue for a dozen role/capability pairs (§3.6), not a database. */
const MAX_LEDGER_BYTES = 512 * 1024;
const MAX_TEXT_LEN = 1000;

/** Mirrors the CAPABILITY fragment in parse-line.ts — the capability is a join key, not prose. */
const CAPABILITY_RE = /^[A-Za-z][A-Za-z0-9_.\-]*$/;

// ─── Paths ──────────────────────────────────────────────────────────

export function proposalsPath(root: string): string {
  return join(root, '.guardlink', PROPOSALS_FILE);
}

/**
 * Resolve a repo-relative path and refuse anything that escapes the root.
 * A proposal is written by an agent, so its `file` is untrusted input into a
 * writer — `../../.ssh/config` must not become an annotation target.
 */
function resolveInsideRoot(root: string, relative: string): string {
  const rootAbs = resolve(root);
  const abs = resolve(rootAbs, relative);
  if (abs !== rootAbs && !abs.startsWith(rootAbs + sep)) {
    throw new Error(`Proposal target "${relative}" resolves outside the project root`);
  }
  return abs;
}

// ─── Text hygiene ───────────────────────────────────────────────────

/**
 * Collapse a free-text field to one line.
 *
 * Annotation descriptions are line-oriented, so an embedded newline in a
 * rationale or a decision note would let the text below it be read back as a
 * separate annotation. Escaping quotes (escapeDesc) is not enough on its own.
 */
export function oneLine(s: string): string {
  return s.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim().slice(0, MAX_TEXT_LEN);
}

// ─── Identity ───────────────────────────────────────────────────────

function bareRef(ref: string): string {
  return ref.startsWith('#') ? ref.slice(1) : ref;
}

/**
 * The identity of an entitlement claim: (actor, capability).
 *
 * Same key `guardlink diff` uses (§3.1), so a proposal that only changes
 * `on <asset>` updates the existing claim rather than filing a second one —
 * and two proposals cannot disagree about the same claim without one of them
 * visibly replacing the other.
 */
export function entitlementKey(actor: string, capability: string): string {
  return `${normalizeName(bareRef(actor))}.${normalizeName(capability)}`;
}

export function proposalId(actor: string, capability: string): string {
  return `ent-${entitlementKey(actor, capability)}`;
}

// ─── §3.5: the ownership-class trap ─────────────────────────────────
//
// Entitlement models capability. For two peers at the same privilege — tenant
// A's admin against tenant B's namespace — both are entitled to the capability,
// and the question was never "which role?" but "whose object?". An entitlement
// there produces the over-grant false negative structurally, so no citation and
// no careful wording makes it safe. All this code can do is say so, loudly, at
// the moment the claim is filed and again when a human is about to accept it.

const OWNERSHIP_CLASS_TOKENS = [
  'idor', 'insecure_direct_object', 'direct_object_reference',
  'namespace_isolation', 'tenant_isolation', 'tenancy', 'multi_tenant',
  'cross_tenant', 'cross_account', 'cross_namespace', 'cross_user',
  'object_level', 'bola', 'broken_object_level',
  'user_controlled_key', 'horizontal_privilege',
];

const OWNERSHIP_CWES = ['CWE-639', 'CWE-862', 'CWE-863', 'CWE-566', 'CWE-1220'];

const OWNERSHIP_PHRASES = [
  'another tenant', 'other tenant', 'cross-tenant', 'cross tenant',
  'another namespace', 'other namespace', 'cross-namespace',
  'another user', "other user's", "someone else's", 'another account',
  'cross-account', 'not their own', 'belonging to', 'any tenant', 'any namespace',
  'per-object', 'object ownership',
];

function looksOwnershipClass(text: string | undefined): boolean {
  if (!text) return false;
  const normalized = normalizeName(text);
  if (OWNERSHIP_CLASS_TOKENS.some(t => normalized.includes(t))) return true;
  const upper = text.toUpperCase();
  return OWNERSHIP_CWES.some(c => upper.includes(c));
}

/**
 * Warnings to attach to a proposal: the ownership-class trap (§3.5) and, when
 * present, the fact that the claim cites nothing and would be inert (§3.4).
 *
 * `model` is optional; when given, an ownership-class exposure already recorded
 * against the proposal's asset is reported too, since that is the exposure the
 * entitlement would be reached for next.
 */
export function proposalWarnings(
  input: Pick<ProposeInput, 'actor' | 'capability' | 'asset' | 'threat' | 'rationale'>,
  model?: ThreatModel,
): string[] {
  const warnings: string[] = [];

  if (looksOwnershipClass(input.threat)) {
    warnings.push(
      `ownership-class: threat ${input.threat} is an ownership question, not a capability question. ` +
      `Both peers hold "${input.capability}"; an entitlement cannot say whose object it was, ` +
      `so it must never demote this class (design §3.5). Use @exposes + @audit instead.`,
    );
  }

  const lowerRationale = input.rationale.toLowerCase();
  const phrase = OWNERSHIP_PHRASES.find(p => lowerRationale.includes(p));
  if (phrase) {
    warnings.push(
      `ownership-class: the rationale argues about object ownership ("${phrase}"). ` +
      `Entitlement models capability only — right capability, wrong object is an IDOR (design §3.5).`,
    );
  }

  if (looksOwnershipClass(input.capability)) {
    warnings.push(
      `ownership-class: capability "${input.capability}" reads as an ownership predicate rather than ` +
      `an action a role performs. Capabilities are actions; ownership stays measured (design §3.5).`,
    );
  }

  if (input.asset && model) {
    for (const e of model.exposures || []) {
      if (bareRef(e.asset) !== bareRef(input.asset)) continue;
      if (!looksOwnershipClass(e.threat)) continue;
      warnings.push(
        `ownership-class: ${e.asset} already carries an ownership-class exposure ` +
        `(${e.threat} at ${e.location.file}:${e.location.line}) that this entitlement may not demote (design §3.5).`,
      );
    }
  }

  return warnings;
}

// ─── Ledger I/O ─────────────────────────────────────────────────────

function emptyLedger(): ProposalLedger {
  return { version: LEDGER_VERSION, proposals: [] };
}

/** True when this project uses the proposal flow at all. */
export async function hasProposalLedger(root: string): Promise<boolean> {
  try {
    await stat(proposalsPath(root));
    return true;
  } catch {
    return false;
  }
}

/**
 * Read and validate the proposal ledger. A missing file is an empty ledger; a
 * malformed one is an error, never a silent partial read — a proposal that
 * disappears because a field had the wrong type is exactly the silence this
 * design exists to prevent.
 */
export async function loadProposals(root: string): Promise<ProposalLedger> {
  const path = proposalsPath(root);
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch {
    return emptyLedger();
  }
  if (raw.length > MAX_LEDGER_BYTES) {
    throw new Error(`${PROPOSALS_FILE} is larger than ${MAX_LEDGER_BYTES} bytes — refusing to parse`);
  }
  return parseLedger(raw, path);
}

export function parseLedger(raw: string, where: string): ProposalLedger {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new Error(`${where} is not valid JSON: ${(err as Error).message}`);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error(`${where}: expected an object with { version, proposals }`);
  }
  const obj = data as Record<string, unknown>;
  if (!Array.isArray(obj.proposals)) {
    throw new Error(`${where}: "proposals" must be an array`);
  }
  return {
    version: typeof obj.version === 'string' ? obj.version : LEDGER_VERSION,
    proposals: obj.proposals.map((p, i) => coerceProposal(p, `${where} proposals[${i}]`)),
  };
}

function str(v: unknown, field: string, where: string): string {
  if (typeof v !== 'string' || !v.trim()) throw new Error(`${where}: "${field}" must be a non-empty string`);
  return v;
}

function coerceProposal(value: unknown, where: string): EntitlementProposal {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${where}: expected an object`);
  }
  const p = value as Record<string, any>;
  const actor = str(p.actor, 'actor', where);
  const capability = str(p.capability, 'capability', where);
  const target = p.target;
  if (!target || typeof target !== 'object') throw new Error(`${where}: "target" must be { file, line }`);
  const file = str(target.file, 'target.file', where);
  const line = Number(target.line);
  if (!Number.isInteger(line) || line < 1) throw new Error(`${where}: "target.line" must be a positive integer`);

  const status: ProposalStatus =
    ['proposed', 'accepted', 'rejected', 'deferred'].includes(p.status) ? p.status : 'proposed';

  return {
    id: typeof p.id === 'string' && p.id ? p.id : proposalId(actor, capability),
    actor,
    capability,
    canonical_capability: typeof p.canonical_capability === 'string' && p.canonical_capability
      ? p.canonical_capability
      : normalizeName(capability),
    asset: typeof p.asset === 'string' && p.asset ? p.asset : undefined,
    threat: typeof p.threat === 'string' && p.threat ? p.threat : undefined,
    rationale: typeof p.rationale === 'string' ? p.rationale : '',
    citation: coerceCitation(p.citation),
    // Recomputed rather than trusted: `inert` is what gates effect (§3.4), so a
    // hand-edited `false` must not make an uncited claim look effective.
    inert: !coerceCitation(p.citation),
    target: { file, line },
    proposed_by: typeof p.proposed_by === 'string' && p.proposed_by ? p.proposed_by : 'unknown',
    proposed_at: typeof p.proposed_at === 'string' ? p.proposed_at : todayISO(),
    updated_at: typeof p.updated_at === 'string' ? p.updated_at : undefined,
    status,
    warnings: Array.isArray(p.warnings) ? p.warnings.filter((w: unknown) => typeof w === 'string') : [],
    decision: coerceDecision(p.decision),
    history: Array.isArray(p.history)
      ? p.history.map(coerceDecision).filter((d): d is ProposalDecision => Boolean(d))
      : [],
  };
}

function coerceCitation(value: unknown): EntitlementCitation | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const c = value as Record<string, unknown>;
  if (typeof c.file !== 'string' || !c.file) return undefined;
  return {
    file: c.file,
    line: typeof c.line === 'number' && Number.isInteger(c.line) ? c.line : undefined,
    raw: typeof c.raw === 'string' && c.raw ? c.raw : c.file,
  };
}

function coerceDecision(value: unknown): ProposalDecision | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const d = value as Record<string, any>;
  if (!['accepted', 'rejected', 'deferred'].includes(d.status)) return undefined;
  if (typeof d.by !== 'string' || !d.by) return undefined;
  return {
    status: d.status,
    by: d.by,
    at: typeof d.at === 'string' ? d.at : todayISO(),
    note: typeof d.note === 'string' && d.note ? d.note : undefined,
    written_to: typeof d.written_to === 'string' && d.written_to ? d.written_to : undefined,
    acknowledged_inert: d.acknowledged_inert === true ? true : undefined,
    acknowledged_ownership_class: d.acknowledged_ownership_class === true ? true : undefined,
  };
}

export async function saveProposals(root: string, ledger: ProposalLedger): Promise<void> {
  const path = proposalsPath(root);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(ledger, null, 2)}\n`, 'utf-8');
}

// ─── Proposing ──────────────────────────────────────────────────────

function todayISO(): string {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Build the `@entitles` body (no comment prefix) for a proposal, and prove it
 * parses before anyone writes it anywhere.
 *
 * Validating with the real parser rather than a second regex is the point: if
 * `guardlink parse` would not read the line back as an entitlement, the claim
 * would be silently absent from the model — the failure this design is about.
 */
// @comment -- "Writes `against <threat>` as well as `on <asset>`, because the join is the triple (design §9.3): a claim missing either clause matches no finding and demotes nothing. Omitting the threat here made acceptance produce a DEAD annotation — the proposal ledger carried it, the written line did not, so the only sanctioned way to create an entitlement produced one that could never work. Observed on a real repository before this fix, not hypothesised."
export function buildEntitlesBody(p: {
  actor: string; capability: string; asset?: string; threat?: string; rationale: string;
}): string {
  const asset = p.asset ? ` on ${p.asset}` : '';
  const threat = p.threat ? ` against ${p.threat}` : '';
  const desc = p.rationale ? ` -- "${escapeDesc(oneLine(p.rationale))}"` : '';
  const body = `@entitles ${p.actor} to ${p.capability}${asset}${threat}${desc}`;

  const parsed = parseLine(body, { file: '<entitlement-proposal>', line: 1 });
  const annotation = parsed.annotation as EntitlesAnnotation | null;
  if (!annotation || annotation.verb !== 'entitles') {
    throw new Error(
      `The annotation this proposal would write does not parse as @entitles: ${body}`,
    );
  }
  return body;
}

/**
 * File a proposal (agent-side entry point).
 *
 * Refuses to overwrite a proposal a human has already accepted or rejected —
 * a decided claim is re-opened by a person, not by an agent re-filing it.
 */
export async function proposeEntitlement(
  root: string,
  input: ProposeInput,
  opts: { model?: ThreatModel } = {},
): Promise<ProposeResult> {
  const actor = oneLine(input.actor);
  const capability = oneLine(input.capability);
  const asset = input.asset ? oneLine(input.asset) : undefined;
  const threat = input.threat ? oneLine(input.threat) : undefined;
  const rationale = oneLine(input.rationale);

  if (!CAPABILITY_RE.test(capability)) {
    throw new Error(
      `Capability "${capability}" is not a single identifier. It is the justification a ` +
      `reviewer reads, not the join key — the join is (actor, asset, threat) — but prose ` +
      `there would not parse and could never be grouped (design §3.1, §9.3).`,
    );
  }

  // Prove the annotation an acceptance would write is well-formed, now, while
  // the proposer is still around to fix it.
  buildEntitlesBody({ actor, capability, asset, threat, rationale });

  // The target must be a real anchor inside this project.
  const abs = resolveInsideRoot(root, input.file);
  const content = await readFile(abs, 'utf-8');
  const lineCount = content.split('\n').length;
  if (!Number.isInteger(input.line) || input.line < 1 || input.line > lineCount) {
    throw new Error(`Proposal target line ${input.line} is out of range in ${input.file} (${lineCount} lines)`);
  }

  const citation = extractCitation(rationale);
  const warnings = proposalWarnings({ actor, capability, asset, threat, rationale }, opts.model);
  if (!citation) {
    warnings.push(
      'uncited: the rationale points at no authorization code, so this entitlement would be ' +
      'inert — parsed and then ignored by triage (design §3.4). Add a file:line pointer at the authz check.',
    );
  }

  const ledger = await loadProposals(root);
  const id = proposalId(actor, capability);
  const existing = ledger.proposals.find(p => p.id === id);

  if (existing && (existing.status === 'accepted' || existing.status === 'rejected')) {
    return {
      proposal: existing,
      created: false,
      refused:
        `Proposal ${id} was already ${existing.status} by ${existing.decision?.by || 'a human'} ` +
        `on ${existing.decision?.at || 'an earlier date'}. A decided claim is re-opened by a person, ` +
        `not by re-filing it. Ledger unchanged.`,
      warnings,
    };
  }

  const proposal: EntitlementProposal = {
    id,
    actor,
    capability,
    canonical_capability: normalizeName(capability),
    asset,
    threat,
    rationale,
    citation,
    inert: !citation,
    target: { file: input.file, line: input.line },
    proposed_by: oneLine(input.proposed_by) || 'unknown',
    proposed_at: existing?.proposed_at || todayISO(),
    updated_at: existing ? todayISO() : undefined,
    status: 'proposed',
    warnings,
    decision: undefined,
    // A deferral stays on the record even after the claim is re-filed.
    history: existing?.history || [],
  };

  if (existing) {
    ledger.proposals = ledger.proposals.map(p => (p.id === id ? proposal : p));
  } else {
    ledger.proposals.push(proposal);
  }
  await saveProposals(root, ledger);

  return { proposal, created: !existing, warnings };
}

// ─── Listing ────────────────────────────────────────────────────────

export interface ListOptions {
  /** Statuses to include; default is every status */
  status?: ProposalStatus[];
}

export async function listProposals(root: string, opts: ListOptions = {}): Promise<EntitlementProposal[]> {
  const { proposals } = await loadProposals(root);
  if (!opts.status || opts.status.length === 0) return proposals;
  const allowed = new Set(opts.status);
  return proposals.filter(p => allowed.has(p.status));
}

export async function findProposal(root: string, id: string): Promise<EntitlementProposal | undefined> {
  const { proposals } = await loadProposals(root);
  return proposals.find(p => p.id === id);
}

// ─── Deciding ───────────────────────────────────────────────────────

/**
 * Raised when an acceptance would land an uncited (inert) entitlement without
 * the human saying, in as many words, that they know it will have no effect.
 * §3.4 is the rule: no citation, no effect.
 */
export class InertProposalError extends Error {
  readonly proposalId: string;
  constructor(proposalId: string) {
    super(
      `Proposal ${proposalId} cites no authorization code. An uncited @entitles is inert: ` +
      `it is parsed, exported and then ignored by triage, so accepting it changes nothing ` +
      `(design §3.4). Add a file:line pointer at the authz check and re-propose, or accept ` +
      `with acknowledgeInert if you want the inert annotation in source anyway.`,
    );
    this.name = 'InertProposalError';
    this.proposalId = proposalId;
  }
}

/**
 * Raised when an acceptance would demote an ownership question with a claim about
 * capability. §3.5: for two peers at the same privilege both are entitled to the
 * capability, and the question was whose object it was — so this is the over-grant
 * arriving structurally, and no citation repairs it. The check is a heuristic, so
 * a human can override it; they cannot do so without seeing it.
 */
export class OwnershipClassProposalError extends Error {
  readonly proposalId: string;
  readonly warnings: string[];
  constructor(proposalId: string, warnings: string[]) {
    super(
      `Proposal ${proposalId} looks like an ownership question, which an entitlement cannot answer ` +
      `(design §3.5): ${warnings.join(' ')} Right capability, wrong object is an IDOR, and ownership ` +
      `stays measured. If the check has misread this claim, accept with acknowledgeOwnership.`,
    );
    this.name = 'OwnershipClassProposalError';
    this.proposalId = proposalId;
    this.warnings = warnings;
  }
}

/**
 * Annotation lines an acceptance writes.
 *
 * The `@comment` is not decoration: §3.3 says a demotion must be arguable, and
 * the only way an over-grant gets caught is a human reading the sentence and
 * disagreeing with it. The name of whoever accepted it belongs next to the claim.
 */
export function buildAcceptedEntitlementLines(
  style: CommentStyle,
  proposal: EntitlementProposal,
  decision: ProposalDecision,
): string[] {
  const { prefix, suffix, indent } = style;
  const line = (body: string) => `${indent}${prefix}${body}${suffix}`;
  const lines = [line(buildEntitlesBody(proposal))];

  if (proposal.inert) {
    lines.push(line(
      `@comment -- "${escapeDesc(oneLine(
        `INERT entitlement: no authorization citation, so this claim will not demote any finding ` +
        `(actor-entitlement design §3.4). Accepted as inert by ${decision.by} on ${decision.at}.`,
      ))}"`,
    ));
  }

  for (const warning of proposal.warnings.filter(w => w.startsWith('ownership-class:'))) {
    lines.push(line(`@comment -- "${escapeDesc(oneLine(
      `${warning} Accepted over this warning by ${decision.by} on ${decision.at}.`,
    ))}"`));
  }

  const note = decision.note ? ` Note: ${decision.note}` : '';
  lines.push(line(
    `@comment -- "${escapeDesc(oneLine(
      `Entitlement accepted by ${decision.by} on ${decision.at} via guardlink entitle (proposal ${proposal.id}).${note}`,
    ))}"`,
  ));

  return lines;
}

/**
 * Record a human decision against a proposal.
 *
 * accept  — writes the @entitles annotation plus the acceptance record, and
 *           stores where it landed
 * reject  — records the refusal and its reason; source is untouched
 * defer   — records that the claim is still contested; source is untouched
 */
export async function applyProposalDecision(
  root: string,
  id: string,
  input: DecisionInput,
): Promise<DecisionResult> {
  const ledger = await loadProposals(root);
  const proposal = ledger.proposals.find(p => p.id === id);
  if (!proposal) {
    throw new Error(`No proposal with id "${id}". Run "guardlink entitle --list" for valid ids.`);
  }

  const by = oneLine(input.by);
  if (!by) {
    throw new Error('A decision must carry the name of the human making it (design §3.6).');
  }
  if (input.status === 'rejected' && !oneLine(input.note || '')) {
    throw new Error('A rejection must say why — the reason is the part a later reader needs.');
  }

  if (input.status === 'accepted') {
    if (proposal.status === 'accepted') {
      throw new Error(
        `Proposal ${id} was already accepted by ${proposal.decision?.by || 'a human'} ` +
        `(${proposal.decision?.written_to || 'annotation already in source'}).`,
      );
    }
    if (proposal.inert && !input.acknowledgeInert) {
      throw new InertProposalError(id);
    }
    const ownership = proposal.warnings.filter(w => w.startsWith('ownership-class:'));
    if (ownership.length > 0 && !input.acknowledgeOwnership) {
      throw new OwnershipClassProposalError(id, ownership);
    }
  }

  const ownershipAcknowledged =
    input.status === 'accepted' && proposal.warnings.some(w => w.startsWith('ownership-class:'));

  const decision: ProposalDecision = {
    status: input.status,
    by,
    at: todayISO(),
    note: oneLine(input.note || '') || undefined,
    acknowledged_inert: input.status === 'accepted' && proposal.inert ? true : undefined,
    acknowledged_ownership_class: ownershipAcknowledged ? true : undefined,
  };

  let linesInserted = 0;
  let targetFile: string | undefined;

  if (input.status === 'accepted') {
    resolveInsideRoot(root, proposal.target.file);
    linesInserted = await insertAnnotationsAt(root, proposal.target, style =>
      buildAcceptedEntitlementLines(style, proposal, decision),
    );
    targetFile = proposal.target.file;
    decision.written_to = `${proposal.target.file}:${proposal.target.line}`;
  }

  proposal.status = input.status;
  proposal.decision = decision;
  proposal.history = [...proposal.history, decision];
  proposal.updated_at = decision.at;

  await saveProposals(root, ledger);

  return { proposal, linesInserted, targetFile, warnings: proposal.warnings };
}

// ─── §3.6 teeth: an entitlement in source needs a human behind it ───

/**
 * Report `@entitles` annotations in source that no accepted proposal explains.
 *
 * This is what stops an annotating agent writing an entitlement straight into a
 * file: the claim still parses, but `guardlink validate` calls it an error, so
 * the over-grant arrives in a diff with a red mark on it rather than silently.
 *
 * Skipped entirely when the project has no ledger — a repo that has not opted
 * into the proposal flow is not retro-actively in violation of it.
 */
export function findUnacceptedEntitlements(
  model: ThreatModel,
  ledger: ProposalLedger,
): ParseDiagnostic[] {
  const accepted = new Set(
    ledger.proposals
      .filter(p => p.status === 'accepted')
      .map(p => entitlementKey(p.actor, p.capability)),
  );

  const diagnostics: ParseDiagnostic[] = [];
  for (const en of model.entitlements || []) {
    if (accepted.has(entitlementKey(en.actor, en.capability))) continue;
    diagnostics.push({
      level: 'error',
      message:
        `@entitles ${en.actor} to ${en.capability} has no accepted proposal behind it. ` +
        `An entitlement is drafted by an agent and accepted by a named human (design §3.6): ` +
        `propose it (guardlink entitle --propose / guardlink_entitlement_propose), then accept it ` +
        `with "guardlink entitle".`,
      file: en.location.file,
      line: en.location.line,
    });
  }
  return diagnostics;
}

/** Convenience wrapper: load the ledger and run the §3.6 check, or nothing. */
export async function checkEntitlementProvenance(
  root: string,
  model: ThreatModel,
): Promise<ParseDiagnostic[]> {
  if (!(await hasProposalLedger(root))) return [];
  const ledger = await loadProposals(root);
  return findUnacceptedEntitlements(model, ledger);
}

// ─── Display ────────────────────────────────────────────────────────

/**
 * Resolve the name a decision is recorded under: an explicit name wins, then
 * git's configured identity, then $USER. Returns undefined when nothing
 * identifies a person — better to ask than to record "unknown" as the
 * maintainer who granted a privilege.
 *
 * @mitigates #cli against #cmd-injection using #param-commands -- "execFileSync with a fixed argv and no shell; nothing user-supplied reaches the command"
 * @flows GitConfig -> #cli via execFileSync -- "Reads the local git identity to attribute a decision"
 */
export function defaultDecider(root: string, explicit?: string): string | undefined {
  const given = oneLine(explicit || '');
  if (given) return given;
  try {
    const name = execFileSync('git', ['config', 'user.name'], {
      cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    const trimmed = oneLine(name);
    if (trimmed) return trimmed;
  } catch {
    // Not a git repo, or no identity configured.
  }
  return oneLine(process.env.USER || process.env.USERNAME || '') || undefined;
}

export function formatProposalForReview(p: EntitlementProposal, index: number, total: number): string {
  const asset = p.asset ? ` on ${p.asset}` : '';
  const lines = [
    `[${index}/${total}] ${p.actor} → ${p.capability}${asset}`,
    `  Id:        ${p.id}`,
    `  Status:    ${p.status}`,
    `  Proposed:  ${p.proposed_by} on ${p.proposed_at}`,
    `  Target:    ${p.target.file}:${p.target.line}`,
    `  Rationale: "${p.rationale || '(none)'}"`,
    `  Citation:  ${p.citation ? p.citation.raw : 'NONE — this entitlement would be inert (§3.4)'}`,
  ];
  if (p.threat) lines.push(`  Answers:   ${p.threat}`);
  for (const w of p.warnings) lines.push(`  ⚠  ${w}`);
  for (const d of p.history) {
    lines.push(`  · ${d.status} by ${d.by} on ${d.at}${d.note ? ` — "${d.note}"` : ''}`);
  }
  return lines.join('\n');
}

export function formatProposalLine(p: EntitlementProposal): string {
  const asset = p.asset ? ` on ${p.asset}` : '';
  const marks = [
    p.inert ? 'inert' : undefined,
    p.warnings.some(w => w.startsWith('ownership-class:')) ? 'ownership-class' : undefined,
  ].filter(Boolean).join(', ');
  const suffix = marks ? `  ⚠ ${marks}` : '';
  const decided = p.decision ? ` (${p.decision.status} by ${p.decision.by})` : '';
  return `${p.id}  ${p.actor} → ${p.capability}${asset}  [${p.status}]${decided}${suffix}`;
}

export function summarizeDecisions(results: DecisionResult[]): string {
  const count = (s: ProposalStatus) => results.filter(r => r.proposal.status === s).length;
  const parts: string[] = [];
  const accepted = count('accepted');
  const rejected = count('rejected');
  const deferred = count('deferred');
  if (accepted > 0) parts.push(`${accepted} accepted`);
  if (rejected > 0) parts.push(`${rejected} rejected`);
  if (deferred > 0) parts.push(`${deferred} deferred`);
  const written = results.reduce((sum, r) => sum + r.linesInserted, 0);
  if (parts.length === 0) return 'No entitlement decisions recorded.';
  return `Entitlement review complete: ${parts.join(', ')}. ${written} annotation line(s) written.`;
}
