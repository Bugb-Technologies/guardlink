/**
 * GuardLink Dashboard — the answers behind the Explore page.
 *
 * Every view the page can show is selected and drawn HERE, at generation time,
 * by the same budget-aware code in `src/graph/views.ts` that the committed
 * artifacts use. The page then shows one of them. Nothing is selected in the
 * browser.
 *
 * That split is deliberate and is what keeps one implementation of "what is a
 * subgraph". Doing the selection client-side would mean porting `selectSubgraph`,
 * the canonical-ref resolver and three Mermaid generators into the page — a
 * second implementation of the model's semantics, in a language with no types,
 * that nothing tests. Doing it here costs bytes instead, and the bytes are
 * small: measured on this repository, all 36 asset diagrams (a threat plane and
 * a flow plane for each of 18 assets) are **37 KB of Mermaid source in 25 ms**,
 * against a dashboard that is already 4.2 MB. Each one is budgeted to 12 nodes,
 * so the cost per view cannot grow with the model — only the number of views
 * can, and that grows with assets rather than with annotations.
 *
 * @exposes #dashboard to #xss [high] cwe:CWE-79 -- "buildExploreData carries asset ids, threat names, file paths and annotation descriptions from the model into strings the Explore page renders"
 * @mitigates #dashboard against #xss using #output-encoding -- "Every value here is raw; pages/explore.ts escapes each one through esc() at the point it is interpolated, including Mermaid source, which is escaped into the <pre> and read back as text"
 * @flows ThreatModel -> #dashboard via buildExploreData -- "Model narrowed into one budgeted answer per view"
 * @comment -- "Pure over an already-parsed model: no file I/O, no user input, no network"
 */
import {
  growWithinBudget, assetThreatPlane, assetsDeclaredIn, boundarySides,
  FLOW_KINDS, type NarrowingStep,
} from '../graph/views.js';
import { checkLegibility, describeLegibility, type LegibilityMeasurement } from '../graph/legibility.js';
import { canonicaliser } from '../mcp/subgraph.js';
import { generateThreatGraph, generateDataFlowDiagram } from './diagrams.js';
import { findUnmitigatedPaths, classifyEndpoints, type PathFinding } from '../paths/index.js';
import type { ChangeSummary } from './analytics.js';
import type { ThreatModel } from '../types/index.js';

/** One drawn (or deliberately undrawn) answer, with everything the panel must say about it. */
export interface ExploreDiagram {
  /** Mermaid source, or '' when there is nothing to draw or drawing was declined. */
  source: string;
  measurement: LegibilityMeasurement;
  legible: boolean;
  /** `9 nodes / 11 edges, within the 12 / 16 legibility budget`. */
  budgetNote: string;
  /** Display labels of the nodes one hop outside the frame. */
  omitted: string[];
  /** Which rung of the narrowing ladder produced this, for the planes that have one. */
  narrowing?: NarrowingStep;
  /** Claims the narrowing hid, when it narrowed by severity. */
  hidden?: number;
  /** Why there is no drawing, when there is none. Empty when there is one. */
  emptyReason?: string;
}

export interface ExploreAsset {
  key: string;
  label: string;
  open: number;
  total: number;
  threatPlane: ExploreDiagram;
  flowPlane: ExploreDiagram;
}

export interface ExploreBoundary {
  /** Stable within one emission: the boundary's index in the canonical model. */
  id: string;
  label: string;
  sides: string[];
  file: string;
  line: number;
  diagram: ExploreDiagram;
}

export interface ExploreFile {
  file: string;
  assets: string[];
  diagram: ExploreDiagram;
}

export interface ExploreDiff {
  ref: string;
  seeds: string[];
  diagram: ExploreDiagram;
}

export interface ExploreData {
  assets: ExploreAsset[];
  boundaries: ExploreBoundary[];
  files: ExploreFile[];
  /** Entry-to-exit routes with no control anywhere along them. The findings. */
  paths: PathFinding[];
  /**
   * Every entry-to-exit route, defended or not.
   *
   * Carried so the view can say what the absence of findings MEANS. "No
   * undefended routes" and "no routes at all" look identical on a page and are
   * opposite facts about a codebase — measured here, 1 of 254.
   */
  pathsTotal: number;
  /** Undeclared flow endpoints, so the paths view can say what it searched between. */
  endpoints: { entries: string[]; exits: string[] };
  /** Absent unless the dashboard was generated with `--since`. */
  diff: ExploreDiff | null;
}

/** Canonical key → the spelling a reader recognises (`#mcp`, or the path for an undeclared endpoint). */
export function assetLabels(model: ThreatModel): Map<string, string> {
  const key = canonicaliser(model);
  const labels = new Map<string, string>();
  for (const f of model.flows) {
    if (!labels.has(key(f.source))) labels.set(key(f.source), f.source);
    if (!labels.has(key(f.target))) labels.set(key(f.target), f.target);
  }
  for (const b of model.boundaries) {
    if (!labels.has(key(b.asset_a))) labels.set(key(b.asset_a), b.asset_a);
    if (!labels.has(key(b.asset_b))) labels.set(key(b.asset_b), b.asset_b);
  }
  // A declared asset overwrites whatever spelling a relation happened to use first.
  for (const a of model.assets) {
    labels.set(key(a.id || a.path.join('.')), a.id ? `#${a.id}` : a.path.join('.'));
  }
  return labels;
}

const THREAT_PLANE = (m: ThreatModel): string => generateThreatGraph(m, { showAll: true, icons: 'none' });
const FLOW_PLANE = (m: ThreatModel): string => generateDataFlowDiagram(m, { icons: 'none' });

/** Wrap a drawn source in everything a panel has to say about it. */
function describe(source: string, omitted: string[], emptyReason: string, extra: Partial<ExploreDiagram> = {}): ExploreDiagram {
  const verdict = checkLegibility(source);
  const drawn = source.length > 0 && verdict.measurement.nodes > 0;
  return {
    source: drawn ? source : '',
    measurement: verdict.measurement,
    legible: verdict.legible,
    budgetNote: describeLegibility(verdict),
    omitted,
    ...(drawn ? {} : { emptyReason }),
    ...extra,
  };
}

/**
 * A flow-plane answer, grown outward from `seeds` until the drawing stops
 * fitting.
 *
 * The same call shape serves the asset view, the boundary view, the file blast
 * radius and the diff view, because they differ only in what they start from.
 * That is the point of bounding the ANSWER rather than the hop count: the four
 * questions want four different starting sets and the same size of picture.
 */
function flowPlane(
  model: ThreatModel, seeds: string[], labels: Map<string, string>, emptyReason: string,
  opts: { derivedSeeds?: boolean } = {},
): ExploreDiagram {
  if (seeds.length === 0) return describe('', [], emptyReason);
  const grown = growWithinBudget(model, {
    seeds, render: FLOW_PLANE, kinds: FLOW_KINDS,
    // A file's components and a diff's components are answers to a question
    // about the file or the diff, so the set may be trimmed to something
    // drawable. A component the reader picked by name may not be.
    trimSeedsToFit: opts.derivedSeeds === true,
  });
  return describe(
    grown.source,
    grown.omitted.map(k => labels.get(k) ?? k),
    grown.seedsAlone
      ? `Too much here to draw legibly — ${grown.verdict.measurement.nodes} nodes and ${grown.verdict.measurement.edges} edges against a budget of ${grown.verdict.budget.nodes} and ${grown.verdict.budget.edges}. Open one component at a time instead.`
      : emptyReason,
  );
}

export interface ExploreInput {
  model: ThreatModel;
  /** Open exposure counts per canonical asset key, for the picker's ordering. */
  openByAsset: Map<string, number>;
  totalByAsset: Map<string, number>;
  changes: ChangeSummary | null;
}

export function buildExploreData({ model, openByAsset, totalByAsset, changes }: ExploreInput): ExploreData {
  const key = canonicaliser(model);
  const labels = assetLabels(model);

  // Every asset that carries a claim, worst first — the order the picker offers
  // them in, so the component a reader most likely came to look at is nearest
  // the top.
  //
  // Declared assets AND the ones only a claim names. An `@exposes` may name a
  // component with no `@asset` definition, and those rows are on the matrix; a
  // cell that had no view to open would be a link into nothing.
  const claimed = new Set<string>(model.assets.map(a => key(a.id || a.path.join('.'))));
  for (const e of model.exposures) claimed.add(key(e.asset));
  for (const m of model.mitigations) claimed.add(key(m.asset));
  for (const c of model.confirmed ?? []) claimed.add(key(c.asset));
  for (const a of model.acceptances) claimed.add(key(a.asset));
  const assetKeys = [...claimed]
    .sort((a, b) => (openByAsset.get(b) ?? 0) - (openByAsset.get(a) ?? 0)
      || (totalByAsset.get(b) ?? 0) - (totalByAsset.get(a) ?? 0)
      || a.localeCompare(b));

  const assets: ExploreAsset[] = assetKeys.map(k => {
    const plane = assetThreatPlane(model, k, THREAT_PLANE);
    return {
      key: k,
      label: labels.get(k) ?? k,
      open: openByAsset.get(k) ?? 0,
      total: totalByAsset.get(k) ?? 0,
      threatPlane: describe(
        plane.source, [],
        plane.narrowing === 'not-drawn'
          ? 'Too many threats and controls on this one component to draw legibly, even narrowed to high and critical. The rows below carry all of them.'
          : 'This component declares no @exposes, @mitigates, @confirmed or @accepts.',
        { narrowing: plane.narrowing, ...(plane.hidden !== undefined ? { hidden: plane.hidden } : {}) },
      ),
      flowPlane: flowPlane(model, [k], labels, 'This component declares no @flows or @boundary, so it has no flow neighbourhood to draw.'),
    };
  });

  const boundaries: ExploreBoundary[] = model.boundaries.map((b, i) => {
    const sides = boundarySides(model, i);
    return {
      id: String(i),
      label: b.description || b.id || `${b.asset_a} ↔ ${b.asset_b}`,
      sides: sides.map(s => labels.get(s) ?? s),
      file: b.location.file,
      line: b.location.line,
      diagram: flowPlane(model, sides, labels, 'Neither side of this boundary carries a @flows, so there is nothing crossing it to draw.'),
    };
  });

  // One blast-radius view per file that names something on the asset plane. A
  // file whose annotations are all classification (@exposes, @comment) has no
  // flow neighbourhood and is left out of the picker rather than offered as an
  // entry that answers nothing.
  //
  // Riskiest first, the same order Code & Annotations uses, so the entry a
  // reader lands on before touching the picker is one worth landing on. A
  // `<select>` types ahead by prefix regardless of order, so nothing is lost in
  // finding a known path.
  const claimsPerFile = new Map<string, number>();
  for (const row of [...model.exposures, ...(model.confirmed ?? []), ...model.mitigations]) {
    claimsPerFile.set(row.location.file, (claimsPerFile.get(row.location.file) ?? 0) + 1);
  }
  const byRisk = [...model.annotated_files].sort((a, b) =>
    (claimsPerFile.get(b) ?? 0) - (claimsPerFile.get(a) ?? 0) || a.localeCompare(b));
  const files: ExploreFile[] = [];
  for (const file of byRisk) {
    const seeds = assetsDeclaredIn(model, file);
    if (seeds.length === 0) continue;
    files.push({
      file,
      assets: seeds.map(s => labels.get(s) ?? s),
      diagram: flowPlane(model, seeds, labels, 'The assets this file names carry no @flows.', { derivedSeeds: true }),
    });
  }

  const diff: ExploreDiff | null = changes
    ? (() => {
      const seeds = [...new Set(changes.newExposures.map(c => key(c.asset)))];
      return {
        ref: changes.ref,
        seeds: seeds.map(s => labels.get(s) ?? s),
        diagram: flowPlane(model, seeds, labels,
          'Nothing this branch added names an asset with a flow, so there is no neighbourhood to draw — the rows below are the whole answer.',
          { derivedSeeds: true }),
      };
    })()
    : null;

  return {
    assets, boundaries, files, diff,
    paths: findUnmitigatedPaths(model),
    pathsTotal: findUnmitigatedPaths(model, { includeMitigated: true }).length,
    endpoints: classifyEndpoints(model),
  };
}
