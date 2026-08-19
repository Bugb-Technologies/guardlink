/**
 * GuardLink — Feature-based filtering.
 *
 * Filters a ThreatModel to only include annotations that belong to
 * specific features. Feature association is determined by file-level
 * proximity: if a file contains @feature "X", all *relations* in
 * that file are considered part of feature "X".
 *
 * Definitions are the exception. `@asset`/`@threat`/`@control`/`@actor` live in
 * `.guardlink/definitions.*`, which carries no `@feature`, so scoping them by
 * file removed every one of them and left a feature view whose relationships
 * pointed at nothing. They are instead resolved from what the kept relations
 * reference — the node vocabulary follows the edges.
 *
 * @comment -- "Pure filtering utility; no I/O"
 * @comment -- "Relations are file-scoped, definitions are reference-scoped. Filtering definitions by file emptied the asset heatmap, dropped every threat severity and rendered diagrams as bare ids — the same failure selectSubgraph avoids by always keeping the node vocabulary"
 */

import type { ThreatModel } from '../types/index.js';

/**
 * Model keys holding located rows that are NOT annotations.
 *
 * `external_refs` is one row per cross-repo tag *occurrence*, derived from the
 * annotation that mentioned the tag — counting it would count that annotation
 * twice. It is the only such key today; the list exists so that the counter
 * below can work by shape (see `countAnnotations`) instead of by a hardcoded
 * inventory of collection names.
 *
 * @comment -- "Exclusion list for the annotation counter; external_refs is derived from annotations, not an annotation"
 */
const NON_ANNOTATION_LOCATED_KEYS = new Set<string>(['external_refs']);

/** A row is an annotation if it carries a source location. */
function isLocatedRow(v: unknown): v is { location: { file: string } } {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const loc = (v as { location?: unknown }).location;
  return !!loc && typeof loc === 'object' && typeof (loc as { file?: unknown }).file === 'string';
}

/**
 * Count the annotations a model actually holds, optionally restricted to a set
 * of files.
 *
 * Found by SHAPE — every own array whose elements carry a `location` — rather
 * than by a list of collection names. A list beside the return statement rots
 * the first time a verb is added: the new collection ships in the model and is
 * silently missing from the count, which is exactly the class of drift this
 * whole change is fixing. Scalars and `string[]` (`annotated_files`,
 * `unannotated_files`) fail the element test, so only annotation rows count.
 *
 * @comment -- "Derives annotation totals from the model's own shape so a newly added collection is counted the day it lands"
 */
export function countAnnotations(model: ThreatModel, files?: Set<string>): number {
  let n = 0;
  for (const [key, value] of Object.entries(model)) {
    if (!Array.isArray(value) || value.length === 0) continue;
    if (NON_ANNOTATION_LOCATED_KEYS.has(key)) continue;
    if (!value.every(isLocatedRow)) continue;
    n += files ? value.filter(r => files.has(r.location.file)).length : value.length;
  }
  return n;
}

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
 * Returns a new ThreatModel with only matching annotations, whose metadata
 * (`annotations_parsed`, `source_files`, `unannotated_files`, `coverage`)
 * describes the feature rather than the project it was cut from, and which
 * carries `filtered_by_features` so a consumer can say it is showing a slice.
 * Feature matching is case-insensitive; `filtered_by_features` records the
 * names as the caller wrote them.
 *
 * @comment -- "Filtered models must never report project-wide totals — a reader acts on the numbers beside the contents"
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

  // ── Relations: file-scoped, which is what a feature *is* ──
  const mitigations = inFeature(model.mitigations);
  const exposures = inFeature(model.exposures);
  const confirmed = inFeature(model.confirmed);
  const acceptances = inFeature(model.acceptances);
  const transfers = inFeature(model.transfers);
  const flows = inFeature(model.flows);
  const boundaries = inFeature(model.boundaries);
  const validations = inFeature(model.validations);
  const audits = inFeature(model.audits);
  const ownership = inFeature(model.ownership);
  const dataHandling = inFeature(model.data_handling);
  const assumptions = inFeature(model.assumptions);
  const entitlements = inFeature(model.entitlements || []);

  // ── Definitions: resolved from what the kept relations reference ──
  //
  // NOT file-scoped, and this is the whole point. `@asset`/`@threat`/`@control`
  // live in `.guardlink/definitions.*` by project convention, and that file is
  // never tagged with a `@feature` — so filtering definitions by file dropped
  // every one of them. A feature view then rendered relationships whose
  // endpoints had no declaration: no asset names, no threat severities, an empty
  // heatmap and diagrams of bare ids. Measured on this repo, `--feature
  // "Dashboard"` kept 2 exposures and 0 of the 16 assets and 15 threats.
  //
  // Same rule `selectSubgraph` already applies (src/mcp/subgraph.ts): an edge
  // whose endpoint has no definition reads as missing data, not as a filter.
  const bare = (ref: string): string => (ref ?? '').replace(/^#/, '').toLowerCase();

  const assetRefs = new Set<string>();
  for (const r of [...exposures, ...mitigations, ...confirmed, ...acceptances,
    ...audits, ...ownership, ...dataHandling, ...assumptions, ...validations]) assetRefs.add(bare(r.asset));
  for (const f of flows) { assetRefs.add(bare(f.source)); assetRefs.add(bare(f.target)); }
  for (const t of transfers) { assetRefs.add(bare(t.source)); assetRefs.add(bare(t.target)); }
  for (const b of boundaries) { assetRefs.add(bare(b.asset_a)); assetRefs.add(bare(b.asset_b)); }
  for (const en of entitlements) if (en.asset) assetRefs.add(bare(en.asset));

  const threatRefs = new Set<string>();
  for (const r of [...exposures, ...mitigations, ...confirmed, ...acceptances, ...transfers]) threatRefs.add(bare(r.threat));
  for (const en of entitlements) if (en.threat) threatRefs.add(bare(en.threat));

  const controlRefs = new Set<string>();
  for (const m of mitigations) if (m.control) controlRefs.add(bare(m.control));
  for (const v of validations) controlRefs.add(bare(v.control));

  const actorRefs = new Set<string>();
  for (const en of entitlements) actorRefs.add(bare(en.actor));

  const assets = model.assets.filter(a =>
    assetRefs.has(bare(a.id || '')) || assetRefs.has(bare(a.path.join('.'))));
  const threats = model.threats.filter(t =>
    threatRefs.has(bare(t.id || '')) || threatRefs.has(bare(t.canonical_name)));
  const controls = model.controls.filter(c =>
    controlRefs.has(bare(c.id || '')) || controlRefs.has(bare(c.canonical_name)));
  const actors = (model.actors || []).filter(ac =>
    actorRefs.has(bare(ac.id || '')) || actorRefs.has(bare(ac.canonical_name)));

  const annotatedFiles = model.annotated_files.filter(f => matchingFiles.has(f));

  const filtered: ThreatModel = {
    ...model,

    // ── Metadata describes THIS model, not the project it was cut from ──
    //
    // These four came through the spread unchanged while every collection
    // around them was filtered, so a feature view reported the repo's totals
    // beside the feature's contents. Measured on this repo with
    // `--feature "Dashboard"`: 445 annotations and 87 files claimed above an
    // Executive Summary listing 1 asset (the feature holds 15 annotations in 1
    // file). Some numbers were about the repo, some about the feature, and
    // nothing in the output said which was which.

    // Filled in below, once the collections exist to be counted.
    annotations_parsed: 0,
    // The files the feature spans. Every file in `matchingFiles` carries an
    // `@feature`, so it is annotated by construction and this is the feature's
    // whole file inventory.
    source_files: annotatedFiles.length,
    annotated_files: annotatedFiles,
    // "Unannotated" is a project-level notion and has no feature-level meaning:
    // a file joins a feature by carrying an `@feature` annotation, so a file
    // with no annotations can never belong to one. Carrying the project's list
    // through described files this model does not contain.
    unannotated_files: [],
    // Recomputed below for the same reason. Placeholder so the object is a
    // complete ThreatModel at every point.
    coverage: { annotation_count: 0, coverage_percent: 0 },

    // Located like an annotation, and file-scoped for the same reason relations
    // are: a cross-repo reference made in some other feature's file is not part
    // of this feature. Conditional so an absent key stays absent.
    ...(model.external_refs ? { external_refs: model.external_refs.filter(r => matchingFiles.has(r.location.file)) } : {}),

    // ── Deliberately carried through unchanged ──
    //
    // `metadata`  — parse provenance: repo, commit sha, branch, tool version,
    //               annotation_hash. All still true of this model; they describe
    //               the parse it came from, not the slice's contents. The hash
    //               in particular must stay project-wide, since it answers "is
    //               this artifact stale relative to the repo", and a hash of the
    //               slice would answer nothing anyone asks.
    // `prompt`    — the project's threat-model description. Context for reading
    //               any slice of the project, not a count of it.
    // `version` / `project` / `generated_at` — identity of the parse, unchanged.
    //
    // What states that this is a slice is `filtered_by_features`, below; none of
    // the fields above pretend to.
    filtered_by_features: [...featureNames],

    assets,
    threats,
    controls,
    actors,
    entitlements,
    mitigations,
    exposures,
    confirmed,
    acceptances,
    transfers,
    flows,
    boundaries,
    validations,
    audits,
    ownership,
    data_handling: dataHandling,
    assumptions,
    shields: inFeature(model.shields),
    features: inFeature(model.features),
    comments: inFeature(model.comments),
  };

  // Counted from the finished object, so it is by construction the number of
  // annotations a caller finds by summing the arrays themselves — relations,
  // the definitions resolved in above, and features/comments/shields alike.
  filtered.annotations_parsed = countAnnotations(filtered);

  // Coverage, and why it is zeroed rather than recomputed.
  //
  // `coverage_percent` is FILE coverage — annotated files / source files
  // (src/parser/coverage.ts). Recomputing it here can only ever yield 100%: a
  // file joins a feature by carrying an `@feature` annotation, so every file in
  // scope is annotated and the denominator has no unannotated side to lose
  // marks on. A tautological 100% is the worst of the three options, because a
  // reader acts on it — "the Dashboard feature is fully annotated" is a claim
  // nobody measured. The project's own percent is wrong differently: it
  // describes 87 files this model does not contain. So the number is absent
  // (0) rather than fabricated, and a consumer that wants honest coverage
  // computes it over the unfiltered model.
  //
  // `annotation_count` IS recomputed, because it has an honest feature-level
  // value: the annotations this model holds. It also has to be — `annotationCount()`
  // in src/parser/coverage.ts reads this field ahead of `annotations_parsed`,
  // so leaving it alone would have handed every consumer of that helper the
  // project-wide total through the back door after the fix above.
  filtered.coverage = { annotation_count: filtered.annotations_parsed, coverage_percent: 0 };

  return filtered;
}

/**
 * Summary of a feature: how many annotations of each type it has.
 *
 * Two different questions are answered here, and conflating them is what made
 * this misreport once definitions stopped being file-scoped:
 *
 *   - `annotations` counts annotations **tagged to** the feature — the ones in
 *     its files. A definition in `.guardlink/definitions.*` is referenced by the
 *     feature, not part of it, so it is not counted.
 *   - `assets` / `threats` count the definitions the feature **references**.
 *     Before definitions were resolved these were always 0, which said nothing.
 */
export interface FeatureSummary {
  name: string;
  files: string[];
  /** Annotations located in this feature's files */
  annotations: number;
  exposures: number;
  mitigations: number;
  /** Distinct assets this feature's relations reference */
  assets: number;
  /** Distinct threats this feature's relations reference */
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
    const files = [...new Set(model.features
      .filter(f => f.feature.toLowerCase() === name.toLowerCase())
      .map(f => f.location.file))];
    const fileSet = new Set(files);
    return {
      name,
      files,
      // Only what is LOCATED in the feature's files.
      //
      // Deliberately not `filtered.annotations_parsed`, which answers the other
      // question: that counts everything the returned model holds, definitions
      // resolved in from `.guardlink/definitions.*` included, and using it here
      // would report a feature as larger than anything written in it. Passing
      // the file set keeps the two apart while still deriving the count from the
      // model's shape — and unlike the previous hand-summed list, a definition
      // that happens to be declared *inside* a feature's file is now counted,
      // because it genuinely is an annotation located in the feature.
      annotations: countAnnotations(filtered, fileSet),
      exposures: filtered.exposures.length,
      mitigations: filtered.mitigations.length,
      assets: filtered.assets.length,
      threats: filtered.threats.length,
      flows: filtered.flows.length,
      confirmed: filtered.confirmed.length,
    };
  });
}
