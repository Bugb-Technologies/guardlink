// src/parser/claim-key.ts
/**
 * GuardLink — one stable identity per relationship claim.
 *
 * The verification ledger needs to name a claim across every edit that is not
 * the claim: the line it sits on, the code beneath it, and the severity its
 * threat resolves to at assembly time. The key is therefore a digest of the
 * claim's own words — verb, identity arguments, external refs, description —
 * plus the logical file, and nothing else.
 *
 * Severity is deliberately absent: `parseProject` resolves an exposure's
 * severity from the threat definition, so keying on it would re-key every
 * exposure of a threat when that threat's severity changed in definitions.
 * That is also why this is not `annotation-hash.ts`, which does include it —
 * the two answer different questions.
 *
 * Identical claims in one file get an ordinal suffix in document order, so a
 * repeated `@comment` is two ledger entries rather than one that flaps.
 *
 * @comment -- "Pure functions over an assembled ThreatModel; no I/O"
 */
import { createHash } from 'node:crypto';
import type {
  ThreatModel, SourceLocation, AnnotationVerb,
  ThreatModelMitigation, ThreatModelExposure, ThreatModelConfirmed, ThreatModelAcceptance,
  ThreatModelTransfer, ThreatModelFlow, ThreatModelBoundary, ThreatModelValidation,
  ThreatModelAudit, ThreatModelOwnership, ThreatModelDataHandling, ThreatModelAssumption,
  ThreatModelFeature, ThreatModelComment, ThreatModelEntitlement,
} from '../types/index.js';

export type ClaimVerb =
  | 'mitigates' | 'exposes' | 'confirmed' | 'accepts' | 'transfers' | 'flows' | 'boundary'
  | 'validates' | 'audit' | 'owns' | 'handles' | 'assumes' | 'feature' | 'comment' | 'entitles';

/** Verbs whose staleness can hide an exposure: the two that remove one from the export. */
export const DEMOTABLE_VERBS: ReadonlySet<AnnotationVerb> = new Set(['mitigates', 'accepts']);

/**
 * How the claim key travels on the wire, defined once so the exporter, the
 * reader and the operator-facing text cannot drift apart.
 *
 * They already have, four times, and each time the gap moved to whichever
 * dimension was still written twice: the key was emitted under two name
 * conventions and read under one, then emitted into two surfaces and read from
 * one. So both dimensions live here — the names AND the surfaces — and the
 * reader derives its container list rather than listing it. Adding a surface
 * below must widen what the reader accepts with no edit to the reader; a
 * dimension written twice is a dimension that will disagree.
 *
 * `CLAIM_KEY_FINGERPRINT` is the mechanism — the name inside SARIF's own
 * stable-identity map, which other SARIF tooling understands.
 * `CLAIM_KEY_PROPERTY` is the mirror in `properties`, for consumers without a
 * SARIF library. `CLAIM_KEY_SURFACES` pairs each emitted SARIF result member
 * with the name the key carries inside it. `CLAIM_KEY_NAMES` is every name a
 * scan report may carry the key under: those, plus the snake_case the
 * scan-report convention uses.
 *
 * Both orders are the reader's precedence for a report that contradicts itself,
 * and each keeps what was accepted earliest in front, so widening cannot change
 * what an already-accepted report resolves to. The two are therefore SEPARATE
 * orders: `partialFingerprints` was read before `properties` was, while the
 * name `claimKey` was accepted before `guardlink/claimKey` was. Deriving one
 * order from the other satisfies whichever half it happens to match and
 * silently inverts the other.
 */
export const CLAIM_KEY_FINGERPRINT = 'guardlink/claimKey';
export const CLAIM_KEY_PROPERTY = 'claimKey';

export interface ClaimKeySurface {
  /** The SARIF result member the export writes the key into. */
  container: string;
  /** The name the key carries inside that member. */
  name: string;
}

/** Surfaces, in the order each became readable. */
export const CLAIM_KEY_SURFACES: readonly ClaimKeySurface[] = [
  { container: 'partialFingerprints', name: CLAIM_KEY_FINGERPRINT },
  { container: 'properties', name: CLAIM_KEY_PROPERTY },
];

/** Names, in the order each became accepted. */
const NAME_PRECEDENCE: readonly string[] = ['claim_key', CLAIM_KEY_PROPERTY, CLAIM_KEY_FINGERPRINT];

/**
 * Every accepted name: the ones above in acceptance order, then any surface
 * name not among them — a surface added later is newest, so appending it keeps
 * the order honest while still making the set derive from the surfaces.
 */
export const CLAIM_KEY_NAMES: readonly string[] = [
  ...NAME_PRECEDENCE,
  ...CLAIM_KEY_SURFACES.map(s => s.name).filter(n => !NAME_PRECEDENCE.includes(n)),
];

export interface ClaimSource {
  verb: ClaimVerb;
  /** `<sha256 hex>:<ordinal>` — see module note. */
  key: string;
  /** Human rendering of the arguments, for reports and the ledger. Never matched on. */
  claim: string;
  location: SourceLocation;
  demotable: boolean;
}

const FIELD_SEP = String.fromCharCode(1);
const s = (v: unknown): string => (v === undefined || v === null ? '' : String(v));
const f = (file: string): string => s(file).replaceAll('\\', '/');
const refs = (v: string[] | undefined): string => (v ? [...v].map(s).sort().join(',') : '');

type Rec =
  | ['mitigates', ThreatModelMitigation] | ['exposes', ThreatModelExposure] | ['confirmed', ThreatModelConfirmed]
  | ['accepts', ThreatModelAcceptance] | ['transfers', ThreatModelTransfer] | ['flows', ThreatModelFlow]
  | ['boundary', ThreatModelBoundary] | ['validates', ThreatModelValidation] | ['audit', ThreatModelAudit]
  | ['owns', ThreatModelOwnership] | ['handles', ThreatModelDataHandling] | ['assumes', ThreatModelAssumption]
  | ['feature', ThreatModelFeature] | ['comment', ThreatModelComment] | ['entitles', ThreatModelEntitlement];

/** Identity fields per verb, in a fixed order. Description last, file after that. */
function identity([verb, r]: Rec): string[] {
  switch (verb) {
    case 'mitigates': return [s(r.asset), s(r.threat), s(r.control)];
    case 'exposes':   return [s(r.asset), s(r.threat), refs(r.external_refs)];
    case 'confirmed': return [s(r.asset), s(r.threat), refs(r.external_refs)];
    // `by` and `until` are part of the claim's identity, not decoration: a
    // renewed expiry or a different signatory is a DIFFERENT decision, and it
    // should arrive in the ledger unverified rather than inheriting the
    // verification of the acceptance it replaced.
    case 'accepts':   return [s(r.asset), s(r.threat), s(r.accepted_by), s(r.expires)];
    case 'transfers': return [s(r.threat), s(r.source), s(r.target)];
    case 'flows':     return [s(r.source), s(r.target), s(r.mechanism)];
    case 'boundary':  return [s(r.asset_a), s(r.asset_b), s(r.id)];
    case 'validates': return [s(r.control), s(r.asset)];
    case 'audit':     return [s(r.asset)];
    case 'owns':      return [s(r.owner), s(r.asset)];
    case 'handles':   return [s(r.classification), s(r.asset)];
    case 'assumes':   return [s(r.asset)];
    case 'feature':   return [s(r.feature)];
    case 'comment':   return [];
    case 'entitles':  return [s(r.actor), s(r.capability), s(r.asset), s(r.threat)];
  }
}

/** Display text for the arguments, in GAL word order. */
export function claimText(rec: Rec): string {
  const [verb, r] = rec;
  switch (verb) {
    case 'mitigates': return `${r.asset} against ${r.threat}${r.control ? ` using ${r.control}` : ''}`;
    case 'exposes':   return `${r.asset} to ${r.threat}`;
    case 'confirmed': return `${r.threat} on ${r.asset}`;
    case 'accepts':   return `${r.threat} on ${r.asset}${r.accepted_by ? ` by ${r.accepted_by}` : ''}${r.expires ? ` until ${r.expires}` : ''}`;
    case 'transfers': return `${r.threat} from ${r.source} to ${r.target}`;
    case 'flows':     return `${r.source} -> ${r.target}${r.mechanism ? ` via ${r.mechanism}` : ''}`;
    case 'boundary':  return `between ${r.asset_a} and ${r.asset_b}${r.id ? ` (#${r.id})` : ''}`;
    case 'validates': return `${r.control} for ${r.asset}`;
    case 'audit':     return r.asset;
    case 'owns':      return `${r.owner} for ${r.asset}`;
    case 'handles':   return `${r.classification} on ${r.asset}`;
    case 'assumes':   return r.asset;
    case 'feature':   return `"${r.feature}"`;
    case 'comment':   return `"${(r.description ?? '').slice(0, 60)}"`;
    case 'entitles':  return `${r.actor} to ${r.capability}${r.asset ? ` on ${r.asset}` : ''}${r.threat ? ` against ${r.threat}` : ''}`;
  }
}

function baseKey(rec: Rec): string {
  const [verb, r] = rec;
  const parts = [verb, ...identity(rec), s(r.description), f(r.location.file)];
  return createHash('sha256').update(parts.join(FIELD_SEP)).digest('hex');
}

function allRecords(model: ThreatModel): Rec[] {
  const out: Rec[] = [];
  // Every collection is read through `?? []`, for the reason
  // `canonicalAnnotationRecords` states: `ThreatModel` declares most of them
  // required and `parseProject` always populates them, but this is now reached
  // from `generateSarif`, a pure transform callers hand partial models to. An
  // absent collection contributes no claims, which is what an empty one gives.
  for (const r of model.mitigations ?? []) out.push(['mitigates', r]);
  for (const r of model.exposures ?? []) out.push(['exposes', r]);
  for (const r of model.confirmed ?? []) out.push(['confirmed', r]);
  for (const r of model.acceptances ?? []) out.push(['accepts', r]);
  for (const r of model.transfers ?? []) out.push(['transfers', r]);
  for (const r of model.flows ?? []) out.push(['flows', r]);
  for (const r of model.boundaries ?? []) out.push(['boundary', r]);
  for (const r of model.validations ?? []) out.push(['validates', r]);
  for (const r of model.audits ?? []) out.push(['audit', r]);
  for (const r of model.ownership ?? []) out.push(['owns', r]);
  for (const r of model.data_handling ?? []) out.push(['handles', r]);
  for (const r of model.assumptions ?? []) out.push(['assumes', r]);
  for (const r of model.features ?? []) out.push(['feature', r]);
  for (const r of model.comments ?? []) out.push(['comment', r]);
  for (const r of model.entitlements ?? []) out.push(['entitles', r]);
  return out;
}

/**
 * The shape `relationRecords` mints below — a sha256 digest in lowercase hex,
 * then the ordinal. It lives here, next to the `${base}:${ordinal}` that
 * produces it, so a checker cannot drift from the thing it checks.
 *
 * A reader accepts the key under three names in six containers, several of them
 * free-form bags another tool may also write a `claim_key` into. Without this,
 * any non-empty string is taken as our stamp, and a value that was never a
 * claim key diverts a finding that would otherwise have joined.
 */
export const CLAIM_KEY_PATTERN = /^[0-9a-f]{64}:\d+$/;

/** Whether a value is shaped like a key this module mints. */
export const isClaimKey = (v: string): boolean => CLAIM_KEY_PATTERN.test(v);

/** Every relationship record with its stable key, in model order. */
export function relationRecords(model: ThreatModel): ClaimSource[] {
  const recs = allRecords(model);
  // Ordinals in document order: group by base key, sort each group by position.
  const groups = new Map<string, Rec[]>();
  const bases = new Map<Rec, string>();
  for (const rec of recs) {
    const base = baseKey(rec);
    bases.set(rec, base);
    const g = groups.get(base);
    if (g) g.push(rec); else groups.set(base, [rec]);
  }
  const ordinal = new Map<Rec, number>();
  for (const g of groups.values()) {
    g.sort((a, b) => (a[1].location.line - b[1].location.line) || ((a[1].location.origin_line ?? 0) - (b[1].location.origin_line ?? 0)));
    g.forEach((rec, i) => ordinal.set(rec, i));
  }
  return recs.map(rec => ({
    verb: rec[0],
    key: `${bases.get(rec)!}:${ordinal.get(rec)!}`,
    claim: claimText(rec),
    location: rec[1].location,
    demotable: DEMOTABLE_VERBS.has(rec[0]),
  }));
}
