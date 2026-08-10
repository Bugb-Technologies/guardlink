/**
 * GuardLink — Which annotation storage mode a model was authored in.
 *
 * Observed from the parsed model rather than configured: `.guardlink/config.json`
 * records include/exclude globs but not the mode, so the annotations themselves
 * are the only authority. An annotation carries `location.origin_file` when it
 * was read from a standalone `.gal` sidecar and resolved back to its logical
 * source through `@source`; inline annotations have no origin.
 *
 * @flows ThreatModel -> #parser via detectAnnotationMode -- "Annotation locations read to infer storage mode"
 * @comment -- "Pure function; mixed is a real answer, not an error — a repo mid-migration is genuinely both"
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ThreatModel, SourceLocation } from '../types/index.js';

export type AnnotationMode = 'inline' | 'external' | 'mixed';

export interface AnnotationModeReport {
  mode: AnnotationMode;
  /** Annotations written in source comments. */
  inline: number;
  /** Annotations written in `.gal` sidecars. */
  external: number;
}

/** Every annotation location in the model, across all relation types. */
function allLocations(model: ThreatModel): SourceLocation[] {
  return [
    ...model.assets, ...model.threats, ...model.controls,
    ...model.mitigations, ...model.exposures, ...(model.confirmed || []),
    ...model.acceptances, ...model.transfers, ...model.flows,
    ...model.boundaries, ...model.validations, ...model.audits,
    ...model.ownership, ...model.data_handling, ...model.assumptions,
    ...(model.actors || []), ...(model.entitlements || []),
    ...model.shields, ...model.features, ...model.comments,
  ].map(a => a.location);
}

/**
 * Classify how the model's annotations are stored.
 *
 * An empty model reports `inline` with both counts at zero — there is nothing to
 * observe, and inline is the product default. The counts are returned alongside
 * so a consumer can tell "inferred from nothing" from "inline, measured".
 */
export function detectAnnotationMode(model: ThreatModel): AnnotationModeReport {
  let inline = 0;
  let external = 0;
  for (const loc of allLocations(model)) {
    if (loc.origin_file) external++;
    else inline++;
  }
  const mode: AnnotationMode =
    external > 0 && inline > 0 ? 'mixed'
      : external > 0 ? 'external'
        : 'inline';
  return { mode, inline, external };
}

/**
 * The mode a project *declared* at init, as opposed to the one observed from its
 * annotations.
 *
 * Returns null when the field is absent rather than defaulting to inline: a repo
 * initialised before the field existed has genuinely not declared one, and
 * answering on its behalf would be a guess presented as configuration. A project
 * with no annotations yet has nothing to observe either, which is exactly when
 * the declared value is the only thing worth reporting.
 */
export function readConfiguredMode(root: string): AnnotationMode | null {
  try {
    const config = JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf-8'));
    const mode = config.annotation_mode;
    return mode === 'inline' || mode === 'external' ? mode : null;
  } catch {
    return null;
  }
}
