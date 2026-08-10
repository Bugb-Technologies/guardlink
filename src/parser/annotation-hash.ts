/**
 * GuardLink — Annotation content hash (GL-101).
 *
 * A stable fingerprint of *what the annotations say*, so any consumer of a
 * derived artifact — an emitted .mmd, a synced CLAUDE.md block, an MCP response,
 * a cached model — can tell whether it still describes the current code.
 *
 * The hash covers annotation content and nothing else. Three exclusions carry
 * the design:
 *
 *   - **Line numbers.** Moving a function changes every line below it. A hash
 *     that flipped on reformatting would be warned about constantly and then
 *     ignored, which is worse than not having one.
 *   - **`origin_file` / `origin_line`.** These record *where the annotation was
 *     written* (the .gal sidecar) rather than what it says. Including them would
 *     make inline and external authoring of the same model hash differently,
 *     and that equality is the correctness test for the GL-507 migration.
 *   - **`parent_symbol`.** Captured only in external mode today, so including it
 *     would break the same equality.
 *
 * `location.file` *is* included: the same claim about a different file is a
 * different claim, and it resolves to the logical source path in both modes.
 *
 * Records are sorted before hashing, so reordering annotations within a file
 * does not change the result. They are sorted as a multiset — duplicates are
 * kept — so deleting one of two identical annotations still changes the hash.
 *
 * @flows ThreatModel -> #parser via computeAnnotationHash -- "Model content read for hashing"
 * @comment -- "Pure function; no I/O; deterministic across machines and annotation modes"
 * @assumes #parser -- "location.file is the logical source path in both inline and external mode (parse-file.ts resolves @source before the model is assembled)"
 * @comment -- "Excludes line, origin_file, origin_line and parent_symbol so inline and external authoring of the same model hash identically"
 * @comment -- "v2 adds @actor and @entitles records. Before that a migration could drop or rewrite every entitlement in a repo and the hash gate would still report the model unchanged — a silent all-clear, which is the failure mode the entitlement design exists to prevent (actor-entitlement design §2)"
 */

import { createHash } from 'node:crypto';
import type { ThreatModel } from '../types/index.js';

/**
 * Bump when the set of hashed fields changes. Two hashes are only comparable at
 * the same algorithm version, so it is part of the emitted string.
 */
export const ANNOTATION_HASH_VERSION = 2;

// Control characters, so that a description containing a pipe, a newline or any
// other printable byte cannot forge a boundary. Without a real field separator
// the fields (ab, c) and (a, bc) would produce the same record.
const FIELD_SEP = String.fromCharCode(1);
const RECORD_SEP = String.fromCharCode(2);

/** Normalize an optional string field to a stable representation. */
const s = (v: unknown): string => (v === undefined || v === null ? '' : String(v));

/** Path separators differ by platform; the annotation does not. */
const f = (file: string): string => s(file).replaceAll('\\', '/');

/** External refs are a set, not a sequence — order of `cwe:` tags is not content. */
const refs = (v: string[] | undefined): string => (v ? [...v].map(s).sort().join(',') : '');

function record(kind: string, ...fields: string[]): string {
  return [kind, ...fields].join(FIELD_SEP);
}

/**
 * Canonical, order-independent list of every annotation in the model.
 * Exported for tests and for callers that want to diff two models field by field.
 */
export function canonicalAnnotationRecords(model: ThreatModel): string[] {
  const out: string[] = [];

  for (const a of model.assets) {
    out.push(record('asset', s(a.id), a.path.join('.'), s(a.description), f(a.location.file)));
  }
  for (const t of model.threats) {
    out.push(record('threat', s(t.id), s(t.canonical_name), s(t.severity), refs(t.external_refs), s(t.description), f(t.location.file)));
  }
  for (const c of model.controls) {
    out.push(record('control', s(c.id), s(c.canonical_name), s(c.description), f(c.location.file)));
  }
  for (const m of model.mitigations) {
    out.push(record('mitigates', s(m.asset), s(m.threat), s(m.control), s(m.description), f(m.location.file)));
  }
  for (const e of model.exposures) {
    out.push(record('exposes', s(e.asset), s(e.threat), s(e.severity), refs(e.external_refs), s(e.description), f(e.location.file)));
  }
  for (const c of model.confirmed || []) {
    out.push(record('confirmed', s(c.asset), s(c.threat), s(c.severity), refs(c.external_refs), s(c.description), f(c.location.file)));
  }
  for (const a of model.acceptances) {
    out.push(record('accepts', s(a.asset), s(a.threat), s(a.description), f(a.location.file)));
  }
  for (const t of model.transfers) {
    out.push(record('transfers', s(t.threat), s(t.source), s(t.target), s(t.description), f(t.location.file)));
  }
  for (const fl of model.flows) {
    out.push(record('flows', s(fl.source), s(fl.target), s(fl.mechanism), s(fl.description), f(fl.location.file)));
  }
  for (const b of model.boundaries) {
    out.push(record('boundary', s(b.asset_a), s(b.asset_b), s(b.id), s(b.description), f(b.location.file)));
  }
  for (const v of model.validations) {
    out.push(record('validates', s(v.control), s(v.asset), s(v.description), f(v.location.file)));
  }
  for (const a of model.audits) {
    out.push(record('audit', s(a.asset), s(a.description), f(a.location.file)));
  }
  for (const o of model.ownership) {
    out.push(record('owns', s(o.owner), s(o.asset), s(o.description), f(o.location.file)));
  }
  for (const d of model.data_handling) {
    out.push(record('handles', s(d.classification), s(d.asset), s(d.description), f(d.location.file)));
  }
  for (const ac of model.actors || []) {
    out.push(record('actor', s(ac.id), s(ac.canonical_name), s(ac.description), f(ac.location.file)));
  }
  // An entitlement is hashed on its authored fields only. `inert` and `imprecise`
  // are derived (from citation, asset and threat) and `citation` is derived from
  // the description, so hashing them would double-count rather than detect more.
  for (const en of model.entitlements || []) {
    out.push(record('entitles', s(en.actor), s(en.canonical_capability), s(en.asset), s(en.threat), s(en.description), f(en.location.file)));
  }
  for (const a of model.assumptions) {
    out.push(record('assumes', s(a.asset), s(a.description), f(a.location.file)));
  }
  for (const sh of model.shields) {
    out.push(record('shield', s(sh.reason), f(sh.location.file)));
  }
  for (const ft of model.features) {
    out.push(record('feature', s(ft.feature), s(ft.description), f(ft.location.file)));
  }
  for (const c of model.comments) {
    out.push(record('comment', s(c.description), f(c.location.file)));
  }

  // Multiset sort: duplicates survive, so deleting one of two identical
  // annotations still moves the hash.
  return out.sort();
}

/**
 * Content hash of the annotation set, as `sha256-v<version>:<hex>`.
 *
 * Identical for the same logical model regardless of authoring mode, file order,
 * annotation order within a file, or surrounding code.
 */
export function computeAnnotationHash(model: ThreatModel): string {
  const digest = createHash('sha256')
    .update(canonicalAnnotationRecords(model).join(RECORD_SEP))
    .digest('hex');
  return `sha256-v${ANNOTATION_HASH_VERSION}:${digest}`;
}
