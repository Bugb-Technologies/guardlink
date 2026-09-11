/**
 * GuardLink — query-driven graph views.
 *
 * One static picture of the whole system is not a view of it. GuardLink's own
 * model is 43 nodes against a measured legibility ceiling of 12
 * (`src/graph/legibility.ts`), so the whole-model diagram has never been
 * readable on the repository the tool ships from — and no layout engine fixes
 * that, because the growth is vertical and Mermaid already trades label
 * collisions away for canvas size.
 *
 * What replaces it: **a reader asks a question, and gets back the part of the
 * graph that answers it.** This module is the catalogue of those questions and
 * the selection that answers each one.
 *
 * ── Three rules, each of them a measured finding ─────────────────────
 *
 * **1. Bound the answer, not the hop count.** `depth` is not a usable control on
 * a real model: measured on this repo, depth 2 from *any* declared asset returns
 * 36–40 nodes against a whole-graph 43, and depth 3 is identical because the
 * walk has saturated. The same `depth: 2` returns 13 nodes from one asset and
 * the entire graph from its neighbour. So `growWithinBudget` walks outward and
 * stops when the DRAWING stops fitting, then says exactly which neighbours were
 * left out. A view is never illegible, and never silently partial.
 *
 * **2. Split the planes.** "What is this exposed to" and "what does this talk
 * to" are different questions on different planes, and fusing them is what makes
 * the existing focus view a hairball at 20 nodes. They get one small diagram
 * each, from the two generators that already exist — `generateThreatGraph` for
 * the classification plane, `generateDataFlowDiagram` for the flow plane.
 *
 * **3. Do not draw the classification layer as a node-link diagram.** Of this
 * repo's 696 annotations, 24% are graph-shaped (`@flows`, `@boundary`,
 * `@transfers`) and 76% classify — this asset has that weakness, this control
 * mitigates it. Drawing a classification as edges is drawing a bipartite
 * incidence matrix as a node-link graph, and that is what manufactures the
 * hubs: one measured sibling project has a single asset carrying 103 edges,
 * which is its incidence ROW drawn as a star.
 *
 * The rule is scoped rather than absolute, because the scale is what breaks it.
 * One asset's own threats and controls is a 4-node star and reads fine; every
 * asset's is the hairball. So: **the classification plane is drawn only when it
 * is scoped to a single asset and fits the budget. At every broader scope it is
 * a matrix or a list**, and `ViewShape` records which, per view, with the reason.
 *
 * ── What a view owes the reader ──────────────────────────────────────
 *
 * `question` is not documentation, it is part of the view. A view that exists
 * because the data allows it is not the same as one somebody wants, and the
 * page renders this string verbatim so a reader can tell which they are looking
 * at before they read the answer.
 *
 * @flows ThreatModel -> #dashboard via growWithinBudget -- "Model narrowed to a neighbourhood that fits the legibility budget"
 * @comment -- "Pure functions over an already-parsed ThreatModel: no file I/O, no user input, no network, and the renderer is injected so this module never depends on the dashboard"
 * @comment -- "Selection goes through selectSubgraph's `nodes` option rather than reimplementing the filter, so a view and an MCP graph query narrow the model the same way"
 */

import { selectSubgraph, graphEdges, canonicaliser, type Direction, type GraphEdge } from '../mcp/subgraph.js';
import { checkLegibility, LEGIBILITY_BUDGET, type LegibilityBudget, type LegibilityVerdict } from './legibility.js';
import type { ThreatModel } from '../types/index.js';

/** How a view's answer is shaped. Only `diagram` is a node-link drawing. */
export type ViewShape = 'diagram' | 'matrix' | 'list' | 'chains';

export interface GraphView {
  id: string;
  label: string;
  /**
   * What the reader is trying to learn, in their words. Rendered on the page.
   */
  question: string;
  shape: ViewShape;
  /**
   * Why this shape. Present wherever a reader might reasonably expect a picture
   * and is not getting one — a list that does not say why it is a list reads as
   * a missing feature rather than as a decision.
   */
  shapeReason?: string;
  /** What the reader picks to scope the view, if anything. */
  subject: 'asset' | 'threat' | 'boundary' | 'file' | 'none';
}

/**
 * The catalogue, ordered by how often a reader wants it.
 *
 * Four of eight answers are not diagrams. That is the finding rather than a
 * limitation: forcing a list-shaped answer into a node-link diagram is the
 * original mistake this whole surface exists to undo.
 */
export const GRAPH_VIEWS: GraphView[] = [
  {
    id: 'overview',
    label: 'Where the risk is',
    question: 'Which components carry which weaknesses, and which of those pairs are still open?',
    shape: 'matrix',
    shapeReason:
      'Every asset against every threat is the classification layer at full scale. Drawn as a node-link graph '
      + 'it is a bipartite incidence matrix with the hubs that shape implies; drawn as a matrix it is the same '
      + 'data, one cell per pair, and it stays readable at sizes where the diagram is an error box. Pick a cell '
      + 'to drop into the diagram for that one component.',
    subject: 'none',
  },
  {
    id: 'asset',
    label: 'One component',
    question: 'What is this component exposed to, what defends it, and what does it talk to?',
    shape: 'diagram',
    shapeReason:
      'Two diagrams, not one. The threat plane and the flow plane answer different questions, and sharing a '
      + 'canvas is what turns a 20-node neighbourhood into a hairball.',
    subject: 'asset',
  },
  {
    id: 'threat',
    label: 'One weakness class',
    question: 'Everywhere this weakness was declared — and where is it still open?',
    shape: 'list',
    shapeReason:
      'One threat across N assets is a star with N spokes, every one of them saying the same word. The picture '
      + 'carries no information the list does not, and stops being readable at a dozen assets.',
    subject: 'threat',
  },
  {
    id: 'boundary',
    label: 'One trust line',
    question: 'What crosses this trust boundary, in which direction, and what defends the crossing?',
    shape: 'diagram',
    shapeReason:
      'Small by construction — a boundary has two sides — so this is the one whole-scope view that is always '
      + 'drawable.',
    subject: 'boundary',
  },
  {
    id: 'paths',
    label: 'Undefended routes',
    question: 'Where does untrusted input reach a sink with no control anywhere along the way?',
    shape: 'chains',
    shapeReason:
      'A path is the one graph shape that stays legible at any length, so each is drawn as the chain it is. '
      + 'These are derived from @flows and @mitigates rather than declared by anyone, so a finding here cannot '
      + 'cite a line that does not exist.',
    subject: 'none',
  },
  {
    id: 'blast',
    label: 'Blast radius from a file',
    question: 'I am about to edit this file — what does it carry, and what else does that reach?',
    shape: 'diagram',
    shapeReason:
      'The flow plane only. A shared threat is a classification, not a coupling: two components exposed to path '
      + 'traversal are not related, they merely have the same kind of weakness, so a hop never transits one.',
    subject: 'file',
  },
  {
    id: 'open',
    label: 'What to fix next',
    question: 'What is still open, worst first?',
    shape: 'list',
    shapeReason: 'A ranking is a list. There is no graph question here.',
    subject: 'none',
  },
  {
    id: 'diff',
    label: 'What this branch touched',
    question: 'Which claims did this branch add, remove or change — and what do they reach?',
    shape: 'diagram',
    shapeReason:
      'The changed claims as rows, plus the flow neighbourhood of the assets they name, so a review can see '
      + 'what a change is adjacent to and not only what it edited.',
    subject: 'none',
  },
];

export const VIEW_BY_ID = new Map(GRAPH_VIEWS.map(v => [v.id, v]));

/** Relation arrays that make up the classification plane of one asset. */
export const CLASSIFICATION_KINDS = [
  'exposures', 'mitigations', 'confirmed', 'acceptances', 'validations', 'audits',
] as const;

/** Relation arrays that make up the flow plane. */
export const FLOW_KINDS = ['flows', 'boundaries', 'transfers'] as const;

// ─── Growing a neighbourhood to fit ──────────────────────────────────

export interface GrowOptions {
  /** Canonical asset keys the view is about. Always included, budget or not. */
  seeds: string[];
  /** Turns a narrowed model into Mermaid. Injected so this module stays pure. */
  render: (model: ThreatModel) => string;
  budget?: LegibilityBudget;
  /** Relation arrays to keep. Defaults to the flow plane. */
  kinds?: readonly string[];
  direction?: Direction;
  /**
   * How far out to consider neighbours. Not a size control — see the module
   * note — only a ceiling on how much of the graph is *examined*. The budget is
   * what decides how much is drawn.
   */
  maxHops?: number;
  /**
   * Drop seeds, in reverse priority order, when the seeds ALONE exceed the
   * budget. Off by default, and the default is the important half.
   *
   * A seed is normally what the reader named — "show me #mcp" — and answering
   * with a different component would be answering a different question. So the
   * default when seeds do not fit is to draw nothing and say so.
   *
   * It is only correct to trim where the seed set was DERIVED rather than
   * named: "the components this file touches" is a question about the file, and
   * a file naming 21 components has no drawing of all 21 that anyone can read.
   * Trimming there answers the question asked, at the size it can be answered;
   * every dropped seed is reported in `omitted` exactly like a dropped
   * neighbour, so the picture still says what it is not showing.
   */
  trimSeedsToFit?: boolean;
}

export interface GrownView {
  /** The narrowed model, ready for any ThreatModel consumer. */
  model: ThreatModel;
  /** Mermaid source for `model`, from the injected renderer. Empty when there is nothing to draw. */
  source: string;
  /** Canonical keys drawn, seeds first then the order they were admitted. */
  included: string[];
  /**
   * Canonical keys ONE HOP from what was drawn, that were not drawn.
   *
   * Adjacency, deliberately, and not everything reachable: "just past the edge
   * of this picture" is a number a reader can act on — open one of these and the
   * frame moves — where "everything within four hops" is, on a connected model,
   * close to the whole graph and says nothing about this view. Measured on this
   * repo, the difference is 52 against about a dozen.
   *
   * Never a silent omission. This is what the page prints under the diagram, and
   * it is what makes "narrowed to fit" a different claim from "this is all there
   * is". Empty means the neighbourhood really is complete.
   */
  omitted: string[];
  verdict: LegibilityVerdict;
  /** True when even the seeds alone exceed the budget — the caller must narrow further. */
  seedsAlone: boolean;
}

/**
 * Grow outward from `seeds` and stop when the drawing stops fitting.
 *
 * The candidate order is (hops from a seed) ascending, then (exposures declared
 * on the asset) descending, then name — deterministic, so the same model always
 * produces the same view, and biased toward the neighbour a security reader is
 * most likely to care about rather than toward whichever one parsed first.
 *
 * Each candidate is admitted by rendering the diagram it would produce and
 * measuring it, not by counting nodes in advance. That is deliberate: a
 * neighbour drags in its own boundary clusters and edge labels, so what a node
 * costs is only knowable from the drawing. The loop is bounded — it stops at the
 * first candidate that does not fit — and each render is a sub-millisecond
 * operation on a model this small.
 *
 * A candidate that does not fit ends the growth rather than being skipped over
 * in favour of a smaller one. Admitting a later, cheaper neighbour while
 * rejecting a nearer, more-connected one would make the view's contents depend
 * on layout arithmetic the reader cannot see, and "these are the nearest N" is a
 * rule a reader can hold.
 */
export function growWithinBudget(model: ThreatModel, options: GrowOptions): GrownView {
  const budget = options.budget ?? LEGIBILITY_BUDGET;
  const kinds = options.kinds ?? FLOW_KINDS;
  const direction = options.direction ?? 'both';
  const maxHops = options.maxHops ?? 4;
  const key = canonicaliser(model);

  const seeds = [...new Set(options.seeds.map(s => key(s)))];
  const edges = graphEdges(model);
  const exposureCount = exposuresByAsset(model);

  const select = (nodes: string[]): ThreatModel =>
    selectSubgraph(model, { nodes, kinds: [...kinds] });

  const ordered = options.trimSeedsToFit
    ? [...seeds].sort((a, b) => (exposureCount.get(b) ?? 0) - (exposureCount.get(a) ?? 0) || a.localeCompare(b))
    : seeds;
  const included = [...ordered];
  const dropped: string[] = [];
  let source = options.render(select(included));
  let verdict = checkLegibility(source, budget);

  if (!verdict.legible && options.trimSeedsToFit) {
    // Shrink the seed set from the least interesting end until the drawing
    // fits. Linear in the seeds, and each render is over a model this small.
    while (included.length > 1 && !verdict.legible) {
      dropped.unshift(included.pop() as string);
      source = options.render(select(included));
      verdict = checkLegibility(source, budget);
    }
  }

  if (!verdict.legible) {
    // Nothing left to drop, or nothing this function is allowed to drop. The
    // answer is that there is no drawing — NOT a drawing nobody can read.
    // Returning `source` here was the original defect in this function, and it
    // reproduced the exact failure the budget exists to prevent: a file naming
    // 21 components handed back a 21-node picture, measured and rejected and
    // then returned anyway.
    return {
      model: select(included), source: '', included,
      omitted: [...new Set([...dropped, ...adjacentTo(edges, included, direction)])].sort(),
      verdict, seedsAlone: true,
    };
  }

  for (const candidate of candidatesOf(edges, included, direction, maxHops, exposureCount)) {
    const trial = [...included, candidate];
    const trialSource = options.render(select(trial));
    const trialVerdict = checkLegibility(trialSource, budget);
    if (!trialVerdict.legible) break;
    included.push(candidate);
    source = trialSource;
    verdict = trialVerdict;
  }

  return {
    model: select(included),
    // A generator returns a drawing with no nodes in it for a model with nothing
    // of that kind — `generateDataFlowDiagram` returns '' outright, while
    // `generateThreatGraph` returns a header and its classDefs. Both mean the
    // same thing and a panel must say so rather than render an empty canvas, so
    // they are collapsed to the same empty answer here.
    source: verdict.measurement.nodes === 0 ? '' : source,
    included,
    omitted: [...new Set([...dropped, ...adjacentTo(edges, included, direction)])].sort(),
    verdict, seedsAlone: false,
  };
}

/** Nodes exactly one hop from `inside`, excluding `inside` itself. */
function adjacentTo(edges: GraphEdge[], inside: string[], direction: Direction): string[] {
  const within = new Set(inside);
  const out = new Set<string>();
  for (const node of inside) {
    for (const edge of edges) {
      const to = stepAlong(edge, node, direction);
      if (to !== null && !within.has(to)) out.add(to);
    }
  }
  return [...out].sort();
}

/**
 * Neighbours of `from`, nearest first, excluding the seeds themselves.
 *
 * A plain BFS over the asset plane. `maxHops` bounds how much of the graph is
 * examined, never how much is drawn.
 */
function candidatesOf(
  edges: GraphEdge[], from: string[], direction: Direction, maxHops: number,
  exposureCount: Map<string, number>,
): string[] {
  const seen = new Set(from);
  const ordered: string[] = [];
  let frontier = [...from];

  for (let hop = 1; hop <= maxHops && frontier.length > 0; hop++) {
    const next: string[] = [];
    for (const node of frontier) {
      for (const edge of edges) {
        const to = stepAlong(edge, node, direction);
        if (to === null || seen.has(to)) continue;
        seen.add(to);
        next.push(to);
      }
    }
    next.sort((a, b) => (exposureCount.get(b) ?? 0) - (exposureCount.get(a) ?? 0) || a.localeCompare(b));
    ordered.push(...next);
    frontier = next;
  }
  return ordered;
}

/** Where an edge leads from `node`, or null when direction forbids the hop. */
function stepAlong(edge: GraphEdge, node: string, direction: Direction): string | null {
  if (!edge.directed) {
    if (edge.from === node) return edge.to;
    if (edge.to === node) return edge.from;
    return null;
  }
  if (edge.from === node && direction !== 'in') return edge.to;
  if (edge.to === node && direction !== 'out') return edge.from;
  return null;
}

function exposuresByAsset(model: ThreatModel): Map<string, number> {
  const key = canonicaliser(model);
  const counts = new Map<string, number>();
  for (const e of model.exposures) counts.set(key(e.asset), (counts.get(key(e.asset)) ?? 0) + 1);
  for (const c of model.confirmed ?? []) counts.set(key(c.asset), (counts.get(key(c.asset)) ?? 0) + 2);
  return counts;
}

// ─── The classification plane of one asset ───────────────────────────

export type NarrowingStep = 'none' | 'high-severity-only' | 'not-drawn';

export interface ThreatPlaneView {
  model: ThreatModel;
  source: string;
  verdict: LegibilityVerdict;
  /**
   * Which rung of the narrowing ladder produced this.
   *
   * `'not-drawn'` is a real answer, not a failure: the rows beneath the panel
   * carry every claim, and a drawing of 30 threats around one asset would carry
   * fewer of them legibly than the table does.
   */
  narrowing: NarrowingStep;
  /** Present on `'high-severity-only'`: how many claims the narrowing hid. */
  hidden?: number;
}

/**
 * One asset's own threats and controls, narrowed until it fits — or not drawn.
 *
 * The ladder, in order:
 *
 *   1. every severity;
 *   2. high and critical only, saying how many lower-severity claims that hides;
 *   3. not drawn, saying so, with the rows as the answer.
 *
 * Step 2 narrows the MODEL and then renders it, rather than asking
 * `generateThreatGraph` for its `showAll: false` behaviour. That option was the
 * obvious lever and it is the wrong one here: its filter is gated on
 * `distinctThreats.size > 12`, which is a statement about a whole-model diagram
 * and is essentially never true of one asset's own plane — measured on this
 * repo, `showAll: false` changed nothing for any of the five assets that needed
 * narrowing, so the ladder fell straight from rung 1 to rung 3. Filtering the
 * model makes the narrowing explicit, makes what it hid countable, and leaves
 * the generator's own heuristic alone.
 *
 * Step 3 is the honest floor. "Offer to narrow, do not render something
 * illegible, and do not refuse" means the reader still gets the answer — it is
 * the *picture* that is declined, never the data. The rows beneath the panel
 * carry every claim, and they carry it better than a 30-node star would.
 */
export function assetThreatPlane(
  model: ThreatModel,
  assetKey: string,
  render: (model: ThreatModel) => string,
  budget: LegibilityBudget = LEGIBILITY_BUDGET,
): ThreatPlaneView {
  const key = canonicaliser(model);
  const canonical = key(assetKey);
  const scoped = selectSubgraph(model, { nodes: [canonical], kinds: [...CLASSIFICATION_KINDS] });

  const full = render(scoped);
  const fullVerdict = checkLegibility(full, budget);
  // A plane with no claims at all is not an illegible plane; it is an empty one.
  if (fullVerdict.measurement.nodes === 0) {
    return { model: scoped, source: '', verdict: fullVerdict, narrowing: 'none' };
  }
  if (fullVerdict.legible) return { model: scoped, source: full, verdict: fullVerdict, narrowing: 'none' };

  const { model: severe, hidden } = keepHighSeverity(scoped);
  if (hidden > 0) {
    const narrowed = render(severe);
    const narrowedVerdict = checkLegibility(narrowed, budget);
    if (narrowedVerdict.legible && narrowedVerdict.measurement.nodes > 0) {
      return { model: severe, source: narrowed, verdict: narrowedVerdict, narrowing: 'high-severity-only', hidden };
    }
  }

  return { model: scoped, source: '', verdict: fullVerdict, narrowing: 'not-drawn' };
}

const HIGH = new Set(['critical', 'p0', 'high', 'p1']);

/**
 * Drop every claim below high severity, and report how many that was.
 *
 * A claim's own `[severity]` wins where it carries one; otherwise the severity
 * is the one its `@threat` definition declares — the same precedence
 * `generateThreatGraph` applies, so the narrowed picture agrees with the one it
 * narrowed. `@mitigates` and `@validates` carry no severity of their own and
 * follow their threat.
 */
export function keepHighSeverity(model: ThreatModel): { model: ThreatModel; hidden: number } {
  const sevOf = new Map<string, string>();
  for (const t of model.threats) {
    const sev = (t.severity || '').toLowerCase();
    if (t.id) sevOf.set(bare(t.id), sev);
    if (t.canonical_name) sevOf.set(bare(t.canonical_name), sev);
  }
  const threatSev = (ref: string) => sevOf.get(bare(ref)) ?? '';
  const isHigh = (own: string | undefined, threat: string) =>
    HIGH.has(((own || '').toLowerCase()) || threatSev(threat));

  const exposures = model.exposures.filter(e => isHigh(e.severity, e.threat));
  const mitigations = model.mitigations.filter(m => isHigh(undefined, m.threat));
  const confirmed = (model.confirmed ?? []).filter(c => isHigh(c.severity, c.threat));
  const acceptances = model.acceptances.filter(a => isHigh(undefined, a.threat));

  const hidden = (model.exposures.length - exposures.length)
    + (model.mitigations.length - mitigations.length)
    + ((model.confirmed ?? []).length - confirmed.length)
    + (model.acceptances.length - acceptances.length);

  // Re-run the selector so threat and control definitions follow the claims that
  // survived: a threat node left behind by its last exposure would render as an
  // orphan, and orphans are exactly the nodes the budget is trying to remove.
  const keptThreats = new Set([...exposures, ...mitigations, ...confirmed, ...acceptances].map(r => bare(r.threat)));
  const keptControls = new Set(mitigations.map(m => m.control).filter(Boolean).map(c => bare(c as string)));

  return {
    hidden,
    model: {
      ...model,
      exposures, mitigations, confirmed, acceptances,
      validations: model.validations.filter(v => keptControls.has(bare(v.control))),
      threats: model.threats.filter(t => keptThreats.has(bare(t.id || '')) || keptThreats.has(bare(t.canonical_name))),
      controls: model.controls.filter(c => keptControls.has(bare(c.id || '')) || keptControls.has(bare(c.canonical_name))),
    },
  };
}

const bare = (s: string) => (s ?? '').replace(/^#/, '').toLowerCase();

// ─── Seed sets for the subject-scoped views ──────────────────────────

/** Canonical asset keys that a file's annotations name. */
export function assetsDeclaredIn(model: ThreatModel, file: string): string[] {
  const want = file.replace(/^\.\//, '').replaceAll('\\', '/').toLowerCase();
  const key = canonicaliser(model);
  const keys = new Set<string>();
  const add = (ref: string | undefined, loc: { file: string }) => {
    if (!ref) return;
    if (loc.file.replaceAll('\\', '/').toLowerCase() !== want) return;
    keys.add(key(ref));
  };
  for (const a of model.assets) add(a.id || a.path.join('.'), a.location);
  for (const e of model.exposures) add(e.asset, e.location);
  for (const m of model.mitigations) add(m.asset, m.location);
  for (const c of model.confirmed ?? []) add(c.asset, c.location);
  for (const f of model.flows) { add(f.source, f.location); add(f.target, f.location); }
  for (const b of model.boundaries) { add(b.asset_a, b.location); add(b.asset_b, b.location); }
  return [...keys].sort();
}

/** The two sides of a boundary, as canonical keys. */
export function boundarySides(model: ThreatModel, index: number): string[] {
  const b = model.boundaries[index];
  if (!b) return [];
  const key = canonicaliser(model);
  return [...new Set([key(b.asset_a), key(b.asset_b)])];
}
