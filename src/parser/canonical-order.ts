/**
 * GuardLink — Canonical ordering for anything written to disk.
 *
 * `parseProject` walks the tree with fast-glob, which returns files in
 * completion order under concurrency. Within one process that order is stable;
 * across two processes it is not. Measured on this repo: two separate
 * `guardlink sync` runs enumerated `src/analyze/**` and `src/agents/**` in
 * opposite orders, so the synced block's "first 25 exposures" showed a different
 * subset each time.
 *
 * That is invisible until something durable depends on it, and then it is
 * corrosive: every regenerated artifact is a diff, so a real change becomes
 * indistinguishable from a re-run. It is the same disease as putting a timestamp
 * in a tracked file, one level down.
 *
 * `computeAnnotationHash` was already immune — it sorts its records before
 * hashing — which is why the hash stayed stable while the prose around it moved.
 *
 * This sorts at the **emission boundary** rather than in the parser. Parser
 * output order is observable behaviour and changing it is out of scope; what
 * matters is that nothing written to disk inherits an accident of directory
 * enumeration.
 *
 * @flows ThreatModel -> #parser via canonicalizeModelOrder -- "Model ordered deterministically before emission"
 * @comment -- "Pure; returns a new model, mutates nothing. Sort is total, so the result cannot depend on input order."
 */

import type { ThreatModel } from '../types/index.js';

/**
 * Total order over rows carrying a location: file, then line, then the row's own
 * content. The content tiebreak is what makes the sort *total* — two annotations
 * on the same line would otherwise keep their arrival order and reintroduce the
 * instability this exists to remove.
 */
function byLocation<T extends { location: { file: string; line: number } }>(a: T, b: T): number {
  if (a.location.file !== b.location.file) return a.location.file < b.location.file ? -1 : 1;
  if (a.location.line !== b.location.line) return a.location.line - b.location.line;
  const ka = JSON.stringify(a);
  const kb = JSON.stringify(b);
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

const sorted = <T extends { location: { file: string; line: number } }>(rows: T[]): T[] =>
  [...rows].sort(byLocation);

/**
 * A model whose every relation array is in a deterministic order.
 *
 * Apply immediately before writing anything durable — an artifact, a synced
 * block, a committed model.json — so regenerating unchanged input produces
 * byte-identical output.
 */
export function canonicalizeModelOrder(model: ThreatModel): ThreatModel {
  return {
    ...model,
    assets: sorted(model.assets),
    threats: sorted(model.threats),
    controls: sorted(model.controls),
    mitigations: sorted(model.mitigations),
    exposures: sorted(model.exposures),
    confirmed: sorted(model.confirmed || []),
    acceptances: sorted(model.acceptances),
    transfers: sorted(model.transfers),
    flows: sorted(model.flows),
    boundaries: sorted(model.boundaries),
    validations: sorted(model.validations),
    audits: sorted(model.audits),
    ownership: sorted(model.ownership),
    data_handling: sorted(model.data_handling),
    assumptions: sorted(model.assumptions),
    shields: sorted(model.shields),
    features: sorted(model.features),
    comments: sorted(model.comments),
    // Optional like external_refs, so an absent key stays absent rather than
    // becoming an empty array. @actor/@entitles are written into synced agent
    // blocks, so they inherit the same requirement as every other relation:
    // regenerating unchanged input must not produce a diff.
    ...(model.actors ? { actors: sorted(model.actors) } : {}),
    ...(model.entitlements ? { entitlements: sorted(model.entitlements) } : {}),
    annotated_files: [...model.annotated_files].sort(),
    unannotated_files: [...model.unannotated_files].sort(),
    ...(model.external_refs ? { external_refs: sorted(model.external_refs) } : {}),
  };
}
