/**
 * GuardLink — Feature-based filtering.
 *
 * Filters a ThreatModel to only include annotations that belong to
 * specific features. Feature association is determined by file-level
 * proximity: if a file contains @feature "X", all annotations in
 * that file are considered part of feature "X".
 *
 * @comment -- "Pure filtering utility; no I/O"
 */

import type { ThreatModel } from '../types/index.js';

/**
 * Unique feature names found in the model, sorted alphabetically.
 */
export function listFeatures(model: ThreatModel): string[] {
  const names = new Set<string>();
  for (const f of model.features) {
    names.add(f.feature);
  }
  return [...names].sort();
}

/**
 * Build a map of file → Set<feature name> from feature annotations.
 */
function buildFileFeatureMap(model: ThreatModel): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const f of model.features) {
    const file = f.location.file;
    if (!map.has(file)) map.set(file, new Set());
    map.get(file)!.add(f.feature);
  }
  return map;
}

/**
 * Filter a ThreatModel to only annotations in files tagged with
 * one or more of the given feature names.
 *
 * Returns a new ThreatModel with only matching annotations.
 * Feature matching is case-insensitive.
 */
export function filterByFeature(model: ThreatModel, featureNames: string[]): ThreatModel {
  const wantedLower = new Set(featureNames.map(n => n.toLowerCase()));
  const fileFeatureMap = buildFileFeatureMap(model);

  // Determine which files match any of the requested features
  const matchingFiles = new Set<string>();
  for (const [file, features] of fileFeatureMap) {
    for (const f of features) {
      if (wantedLower.has(f.toLowerCase())) {
        matchingFiles.add(file);
        break;
      }
    }
  }

  // Filter helper
  const inFeature = <T extends { location: { file: string } }>(arr: T[]): T[] =>
    arr.filter(item => matchingFiles.has(item.location.file));

  return {
    ...model,
    // Preserve metadata
    annotations_parsed: model.annotations_parsed,
    source_files: model.source_files,
    annotated_files: model.annotated_files.filter(f => matchingFiles.has(f)),
    unannotated_files: model.unannotated_files,

    // Filter each category
    assets: inFeature(model.assets),
    threats: inFeature(model.threats),
    controls: inFeature(model.controls),
    mitigations: inFeature(model.mitigations),
    exposures: inFeature(model.exposures),
    confirmed: inFeature(model.confirmed),
    acceptances: inFeature(model.acceptances),
    transfers: inFeature(model.transfers),
    flows: inFeature(model.flows),
    boundaries: inFeature(model.boundaries),
    validations: inFeature(model.validations),
    audits: inFeature(model.audits),
    ownership: inFeature(model.ownership),
    data_handling: inFeature(model.data_handling),
    assumptions: inFeature(model.assumptions),
    shields: inFeature(model.shields),
    features: inFeature(model.features),
    comments: inFeature(model.comments),
  };
}

/**
 * Summary of a feature: how many annotations of each type it has.
 */
export interface FeatureSummary {
  name: string;
  files: string[];
  annotations: number;
  exposures: number;
  mitigations: number;
  assets: number;
  threats: number;
  flows: number;
  confirmed: number;
}

/**
 * Get summary stats for each feature in the model.
 */
export function getFeatureSummaries(model: ThreatModel): FeatureSummary[] {
  const featureNames = listFeatures(model);
  return featureNames.map(name => {
    const filtered = filterByFeature(model, [name]);
    return {
      name,
      files: [...new Set(model.features.filter(f => f.feature.toLowerCase() === name.toLowerCase()).map(f => f.location.file))],
      annotations: filtered.assets.length + filtered.threats.length + filtered.controls.length +
        filtered.mitigations.length + filtered.exposures.length + filtered.confirmed.length +
        filtered.acceptances.length + filtered.transfers.length + filtered.flows.length +
        filtered.boundaries.length + filtered.validations.length + filtered.audits.length +
        filtered.ownership.length + filtered.data_handling.length + filtered.assumptions.length +
        filtered.features.length + filtered.comments.length + filtered.shields.length,
      exposures: filtered.exposures.length,
      mitigations: filtered.mitigations.length,
      assets: filtered.assets.length,
      threats: filtered.threats.length,
      flows: filtered.flows.length,
      confirmed: filtered.confirmed.length,
    };
  });
}
