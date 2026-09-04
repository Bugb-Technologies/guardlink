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
    case 'accepts':   return [s(r.asset), s(r.threat)];
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
    case 'accepts':   return `${r.threat} on ${r.asset}`;
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
  for (const r of model.mitigations) out.push(['mitigates', r]);
  for (const r of model.exposures) out.push(['exposes', r]);
  for (const r of model.confirmed || []) out.push(['confirmed', r]);
  for (const r of model.acceptances) out.push(['accepts', r]);
  for (const r of model.transfers) out.push(['transfers', r]);
  for (const r of model.flows) out.push(['flows', r]);
  for (const r of model.boundaries) out.push(['boundary', r]);
  for (const r of model.validations) out.push(['validates', r]);
  for (const r of model.audits) out.push(['audit', r]);
  for (const r of model.ownership) out.push(['owns', r]);
  for (const r of model.data_handling) out.push(['handles', r]);
  for (const r of model.assumptions) out.push(['assumes', r]);
  for (const r of model.features) out.push(['feature', r]);
  for (const r of model.comments) out.push(['comment', r]);
  for (const r of model.entitlements || []) out.push(['entitles', r]);
  return out;
}

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
