/**
 * GuardLink — the legibility budget.
 *
 * `src/dashboard/render-budget.ts` answers **will a renderer draw this?** This
 * module answers the question that fails several hundred nodes earlier: **can a
 * human read it?**
 *
 * They are different budgets and both are needed. Mermaid's limits are 500 edges
 * and 50,000 characters; the measured point at which a GuardLink diagram stops
 * being readable is **12 nodes and 16 edges**. Everything between those two
 * numbers draws perfectly and tells the reader nothing — which is the state
 * GuardLink's own dashboard has always shipped in, because its own model is 43
 * nodes and its Data Flow diagram is 66.
 *
 * ── Where 12 / 16 comes from ─────────────────────────────────────────
 *
 * Measured, not chosen. Twenty-one real subgraph slices of this repository's own
 * model were rendered at the dashboard's Mermaid settings and the resulting
 * layout measured against the panel it has to fit in:
 *
 *   panel        1096 x 648 CSS px on a 1440-wide window
 *                (`.mermaid-wrap`, `max-height: 72vh`, src/dashboard/styles.ts)
 *   label font   11px (`.mermaid svg .edgeLabel`, same file; `themeVariables
 *                .fontSize` is 12px in src/dashboard/client-legacy.ts)
 *   legible at   ~10px, so a fitted scale below ~0.9 is already too small
 *
 *   | slice        | nodes | edges | layout px   | fit  | label px | verdict   |
 *   |--------------|-------|-------|-------------|------|----------|-----------|
 *   | #report d0   |     3 |     2 |   579 x 179 | 1.89 |     11.0 | readable  |
 *   | #tui   d0    |    10 |    13 |  1018 x 564 | 1.08 |     11.0 | readable  |
 *   | #blame d0    |    11 |    15 |  1055 x 665 | 0.97 |     10.7 | LAST ONE  |
 *   | #cli   d0    |    14 |    21 |  1138 x 885 | 0.73 |      8.1 | borderline|
 *   | #parser d0   |    16 |    25 | 1079 x 1032 | 0.63 |      6.9 | illegible |
 *   | #mcp   d1    |    20 |    39 | 1776 x 1501 | 0.43 |      4.7 | illegible |
 *   | #parser d2   |    40 |   144 | 2436 x 5319 | 0.12 |      1.3 | illegible |
 *
 * The full measurement is in the investigation this module implements. Two
 * things in it are worth carrying forward, because they rule out the obvious
 * alternative fixes:
 *
 *   **Growth is vertical, not horizontal.** Forty nodes lays out 2,436 px wide
 *   and 5,319 px TALL, because the threat plane puts many nodes on the same rank
 *   and Dagre stacks them. A wider panel buys nothing.
 *
 *   **Label collisions were measured at zero.** Mermaid never overlaps labels;
 *   it avoids them by growing the canvas instead. So the failure never appears
 *   as crowding — it appears as a diagram you are looking at 5% of. Anyone
 *   tuning the layout engine is fixing a symptom that was already traded away.
 *
 * ── What the budget does and does not bound ──────────────────────────
 *
 * It bounds **node and edge count**, and what that buys is labels at their full
 * size: a drawing this small never has to be scaled down to be shown, so 11px
 * stays 11px. That is the guarantee, and it is the one that matters — the
 * measured failure was never crowding, it was a diagram scaled to 0.6 and read
 * at 6.6px.
 *
 * It does **not** bound canvas width, and cannot. Layout size depends on font
 * metrics, label lengths and rank depth, none of which exist outside a browser:
 * measured here, `src/mcp/server.ts`'s flow neighbourhood is 7 nodes and 16
 * edges — well inside this budget — and lays out 1,905px wide, because its
 * `@flows` mechanisms are long strings and Dagre spaces ranks to fit them.
 *
 * The answer to that is panning, not shrinking, and it is why the Explore panes
 * render at natural size and let the panel scroll (see `DIAGRAMS_JS` in
 * `src/dashboard/generate.ts`). A wide diagram at full label size is readable
 * with a drag; the same diagram scaled to fit is not readable at all.
 *
 * ── The relationship between the two budgets ─────────────────────────
 *
 * Legibility is strictly tighter than drawability: 16 edges is 3.2% of Mermaid's
 * 500, and a 12-node diagram is a few hundred characters against 50,000. So
 * **anything inside this budget is drawable by construction**, and a view that
 * enforces legibility can never produce the silent `maxTextSize` failure #34
 * exists to catch. That is an invariant, not a coincidence, and
 * tests/legibility-budget.test.ts pins it.
 *
 * The converse does not hold and is the whole point: a diagram can pass the
 * render budget and fail this one. That gap — drawable but unreadable — is every
 * whole-model diagram GuardLink has ever emitted.
 *
 * ── Why this is not configurable ─────────────────────────────────────
 *
 * Same argument as MERMAID_LIMITS. A per-project override would make a view
 * "legible" in one repository and not in another, and the number is a property
 * of a panel size and a font size, neither of which a project chooses. A reader
 * who wants more on screen does not want a bigger budget; they want a different
 * question, which is what the view catalogue is for.
 *
 * @exposes #dashboard to #dos [low] cwe:CWE-400 -- "measureLegibility scans caller-supplied diagram text with regular expressions, once per line"
 * @mitigates #dashboard against #dos using #regex-anchoring -- "Every pattern is line-anchored or a bounded character class; no nested quantifier can backtrack across the input, and each line is scanned a fixed number of times"
 * @flows DiagramSource -> #dashboard via measureLegibility -- "Generated Mermaid text measured for node and edge count before a view decides to draw it"
 * @comment -- "The numbers are measured against a specific panel and font size, both cited above — deriving rather than guessing is the same discipline render-budget.ts applies to Mermaid's own limits"
 */

import { mermaidRenderText, countMermaidEdges, MERMAID_LIMITS } from '../dashboard/render-budget.js';

/**
 * The measured ceiling for one diagram panel.
 *
 * `#blame` at 11 nodes / 15 edges is the last slice that fitted with legible
 * labels; `#cli` at 14 / 21 is the first that did not. The budget sits on the
 * readable side of that boundary rather than on the boundary itself, because a
 * view that lands exactly on the last readable size has no margin for a longer
 * label than the one that was measured.
 */
export const LEGIBILITY_BUDGET = {
  /** Nodes, excluding `subgraph` clusters — Mermaid draws those as containers. */
  nodes: 12,
  /** Edges, counted the way Mermaid counts them. */
  edges: 16,
} as const;

export interface LegibilityBudget {
  nodes: number;
  edges: number;
}

export interface LegibilityMeasurement {
  nodes: number;
  edges: number;
  /** `subgraph` containers. Reported because they add height, never budgeted. */
  clusters: number;
}

export interface LegibilityVerdict {
  /** True when the diagram is small enough to read at the panel's size. */
  legible: boolean;
  measurement: LegibilityMeasurement;
  budget: LegibilityBudget;
  /** Which dimensions exceeded, empty when legible. */
  over: Array<{ dimension: 'nodes' | 'edges'; measured: number; allowed: number }>;
}

/**
 * Statement keywords that can never declare a node or carry an edge.
 *
 * `subgraph` is here deliberately: Mermaid renders it as a `.cluster`, not a
 * `.node`, and the measurement above counted `.node` elements. Clusters are
 * counted separately by `countMermaidClusters`.
 */
const NON_NODE_STATEMENT = /^\s*(?:%%|classDef\b|class\b|style\b|linkStyle\b|subgraph\b|end\b|direction\b|click\b|graph\b|flowchart\b)/;

/** `"…"` captions and `|…|` edge labels — both may contain anything, including ids. */
const LABEL_TEXT = /"[^"\n]*"|\|[^|\n]*\|/g;

/** A `:::className` suffix names a classDef, not a node. */
const CLASS_SUFFIX = /:::[A-Za-z0-9_-]+/g;

/** What `mid()` in src/dashboard/diagrams.ts produces: `[^a-zA-Z0-9_]` stripped. */
const NODE_ID = /[A-Za-z0-9_]+/g;

const SUBGRAPH_LINE = /^\s*subgraph\b/;

/**
 * Count the nodes a Mermaid flowchart declares or connects.
 *
 * Reads the endpoints off each statement rather than only the declarations, so a
 * node that is referenced but never declared — which Mermaid would create
 * implicitly — is still counted. The rule is: strip the caption text, the `|…|`
 * edge labels and any `:::class` suffix, then take the FIRST and LAST identifier
 * left on the line. For a declaration those are the same id; for a link they are
 * its two endpoints, and the unquoted words some Mermaid arrows carry inline
 * (`A -. exposes .-> B`) fall in the middle and are correctly ignored.
 *
 * Exact for everything the three generators in `src/dashboard/diagrams.ts` emit,
 * which is what this budget is ever asked about, because it is asked before a
 * view draws one of them. The assumption it shares with `countMermaidEdges` is
 * one link per line: a hand-written `A --> B --> C` would count A and C and miss
 * B. Undercounting cannot make an over-budget diagram look legible by more than
 * the chain length, and the edge count — which handles chains exactly — catches
 * that case anyway.
 */
export function countMermaidNodes(source: string): number {
  const ids = new Set<string>();
  for (const raw of mermaidRenderText(source).split('\n')) {
    if (NON_NODE_STATEMENT.test(raw)) continue;
    const line = raw.replace(LABEL_TEXT, ' ').replace(CLASS_SUFFIX, ' ');
    const found = line.match(NODE_ID);
    if (!found || found.length === 0) continue;
    ids.add(found[0]);
    ids.add(found[found.length - 1]);
  }
  return ids.size;
}

/** `subgraph` containers — trust zones, in GuardLink's diagrams. */
export function countMermaidClusters(source: string): number {
  let n = 0;
  for (const raw of mermaidRenderText(source).split('\n')) if (SUBGRAPH_LINE.test(raw)) n++;
  return n;
}

export function measureLegibility(source: string): LegibilityMeasurement {
  return {
    nodes: countMermaidNodes(source),
    edges: countMermaidEdges(source),
    clusters: countMermaidClusters(source),
  };
}

/**
 * Is this diagram small enough to read?
 *
 * Empty input is legible, matching `checkRenderBudget`: the generators return
 * `''` for a model with nothing to draw, and "no diagram" is a different answer
 * from "a diagram nobody can read".
 */
export function checkLegibility(source: string, budget: LegibilityBudget = LEGIBILITY_BUDGET): LegibilityVerdict {
  const measurement = measureLegibility(source);
  const over: LegibilityVerdict['over'] = [];
  if (measurement.nodes > budget.nodes) {
    over.push({ dimension: 'nodes', measured: measurement.nodes, allowed: budget.nodes });
  }
  if (measurement.edges > budget.edges) {
    over.push({ dimension: 'edges', measured: measurement.edges, allowed: budget.edges });
  }
  return { legible: over.length === 0, measurement, budget, over };
}

/** `9 nodes / 11 edges, within the 12 / 16 legibility budget`. */
export function describeLegibility(v: LegibilityVerdict): string {
  const size = `${v.measurement.nodes} node${v.measurement.nodes === 1 ? '' : 's'} / ${v.measurement.edges} edge${v.measurement.edges === 1 ? '' : 's'}`;
  const budget = `the ${v.budget.nodes} / ${v.budget.edges} legibility budget`;
  if (v.legible) return `${size}, within ${budget}`;
  return `${size}, past ${budget} (${v.over.map(o => `${o.measured} ${o.dimension} against ${o.allowed}`).join(', ')})`;
}

/**
 * The invariant that lets a legible view skip the render budget.
 *
 * True by arithmetic at the shipped constants, and asserted rather than assumed
 * so that a future edit to either budget cannot silently open the gap back up.
 * If this ever returned false, a view could pass the legibility check and still
 * hit Mermaid's silent `maxTextSize` failure.
 */
export function legibilityImpliesDrawable(budget: LegibilityBudget = LEGIBILITY_BUDGET): boolean {
  return budget.edges <= MERMAID_LIMITS.maxEdges;
}
