/**
 * GuardLink — the Mermaid render budget.
 *
 * Answers one question about a diagram we are about to write or serve: **will a
 * renderer draw it?** That is not the question `guardlink validate --artifacts`
 * was asking. That one asks whether an artifact is CURRENT, and a diagram can be
 * perfectly current and still undrawable — which is the worse failure, because
 * the staleness gate then certifies it.
 *
 * ── Why this is measured and not eyeballed ───────────────────────────
 *
 * Past a size, Mermaid stops drawing, and it stops drawing in two different
 * ways, only one of which announces itself:
 *
 *   maxEdges     the flowchart parser THROWS. The dashboard shows a red syntax
 *                error; a promise-based caller sees a rejection.
 *   maxTextSize  the render SILENTLY succeeds. Mermaid replaces the diagram text
 *                with `graph TB;a[Maximum text size in diagram exceeded]`,
 *                resolves normally, and writes nothing to the console. One pink
 *                box is drawn and every caller believes it worked.
 *
 * The second is what this module exists for. Nothing downstream can detect it,
 * so it has to be caught before the text reaches a renderer.
 *
 * ── Where the two numbers come from ──────────────────────────────────
 *
 * They are Mermaid's, not ours. Both are the documented defaults, and both were
 * read out of the shipped bundle rather than out of the docs, at the version the
 * dashboard loads (`mermaid@11` → 11.17.2 at the time of writing):
 *
 *   `dist/chunks/mermaid.esm.min/chunk-QJSWEUOL.mjs`
 *       …layout:"dagre",maxTextSize:5e4,maxEdges:500,darkMode:!1,…
 *
 *   `dist/mermaid.esm.min.mjs` — the text-size check, in `render`:
 *       e.length>(o?.maxTextSize??yo)&&(e=xo)
 *       var yo=5e4, xo="graph TB;a[Maximum text size in diagram exceeded];style a fill:#faa"
 *
 *   `dist/chunks/mermaid.esm.min/chunk-CLS4B6BI.mjs` — the edge check, in
 *   the flowchart parser's `addSingleLink`:
 *       if(this.edges.length<(this.config.maxEdges??500)) …push… else throw
 *       new Error(`Edge limit exceeded. ${n} edges found, but the limit is ${m}.`)
 *
 * So: a diagram draws iff `textSize <= maxTextSize` and `edges <= maxEdges`.
 *
 * These are also the numbers that apply where we have no say at all. A committed
 * `.mmd` is opened by GitHub, by mermaid.live, by the VS Code preview and by the
 * docs site, none of which we configure — they all take the defaults. The
 * dashboard is the one surface that could raise them, and deliberately does not:
 * `mermaid.initialize` now passes these same constants explicitly, so the
 * dashboard agrees with the artifacts by construction and stops depending on a
 * floating `mermaid@11` CDN default that could move underneath it.
 *
 * Raising them would not help anyway. The measured 257-file threat graph renders
 * at 39,609 × 32,646 px with 0.2% of it visible at the fitted zoom; drawing more
 * of that is not the same as showing it.
 *
 * @exposes #dashboard to #dos [low] -- "Measures caller-supplied diagram text with regular expressions"
 * @mitigates #dashboard against #dos using #regex-anchoring -- "Every pattern is line-anchored or a bounded character class; no nested quantifier can backtrack across the input"
 * @flows DiagramSource -> #dashboard via checkRenderBudget -- "Generated Mermaid text measured before it is written or served"
 * @comment -- "The limits are Mermaid's shipped defaults, read out of mermaid@11.17.2's bundle and cited above — deriving them rather than guessing is the whole point of the module"
 */

/**
 * Mermaid's own limits, at the version the dashboard loads.
 *
 * Not tunable by configuration here on purpose. A per-project override would
 * make an artifact drawable in one repository's dashboard and undrawable in
 * GitHub's viewer, which is the ambiguity this module exists to remove.
 */
export const MERMAID_LIMITS = {
  /** Characters of preprocessed diagram text. Exceeding it fails SILENTLY. */
  maxTextSize: 50_000,
  /** Edges in one flowchart. Exceeding it throws a parse error. */
  maxEdges: 500,
} as const;

/** The Mermaid version the limits above were read from. */
export const MERMAID_LIMITS_SOURCE = 'mermaid@11.17.2 defaults';

export type BudgetLimit = 'maxTextSize' | 'maxEdges';

export interface DiagramMeasurement {
  /** Length of the text Mermaid actually measures — `%%` comments removed. */
  textSize: number;
  /** Edges the flowchart declares. */
  edges: number;
}

export interface BudgetViolation {
  limit: BudgetLimit;
  measured: number;
  allowed: number;
  /** How far past the limit, in the limit's own units. Always > 0. */
  over: number;
  /** What a renderer does when this one is exceeded. */
  symptom: string;
}

export interface RenderBudgetVerdict {
  renderable: boolean;
  measurement: DiagramMeasurement;
  violations: BudgetViolation[];
}

/**
 * Mermaid's `cleanupComments`, copied exactly.
 *
 * `%%` lines are stripped BEFORE the length check, which is why the provenance
 * header GuardLink writes onto every artifact costs nothing against the budget —
 * and why measuring the file's byte length instead would be measuring the wrong
 * number. Verbatim from mermaid@11.17.2:
 *
 *     t => t.replace(/^\s*%%(?!\{)[^\n]+\n?/gm, "").trimStart()
 *
 * The `(?!\{)` exception is real: `%%{init: …}%%` is a directive, not a comment,
 * and Mermaid keeps it. GuardLink emits none, but a diagram measured here may
 * not be one GuardLink wrote.
 *
 * Mermaid also strips YAML frontmatter and extracts directives before this runs;
 * neither appears in anything GuardLink generates, and both would only make the
 * measured text smaller, so skipping them cannot make this report a diagram
 * drawable when it is not.
 */
export function mermaidRenderText(source: string): string {
  return source.replace(/^\s*%%(?!\{)[^\n]+\n?/gm, '').trimStart();
}

/** Statement keywords that can never carry an edge. Cheap and exact. */
const NON_EDGE_STATEMENT = /^\s*(?:%%|classDef\b|class\b|style\b|linkStyle\b|subgraph\b|end\b|direction\b|click\b|graph\b|flowchart\b)/;

/**
 * Every Mermaid flowchart link form, longest first.
 *
 * Ordering matters: `-->` has to be tried before `---`, or the arrowhead is left
 * behind and counted again. Applied to a line whose label text has already been
 * removed, so an arrow inside a node caption cannot be mistaken for a link.
 */
const LINK_TOKEN = /<?[-=]{2,}[>ox]|<?-\.-*[>ox]|<?\.-+[>ox]|-{3,}|={3,}|-\.-+/g;

/** `"…"` node and edge captions, and `|…|` edge labels. Both may contain arrows. */
const LABEL_TEXT = /"[^"\n]*"|\|[^|\n]*\|/g;

/**
 * Count the edges a Mermaid flowchart declares, the way Mermaid counts them.
 *
 * Mermaid counts one edge per `addSingleLink` call, so a chained statement
 * (`A --> B --> C`) is two and an ampersand statement (`A & B --> C`) is two.
 * Both are reproduced here: the line is split on link tokens and each adjacent
 * pair of segments contributes `groups(left) × groups(right)` edges.
 *
 * Exact for everything in `src/dashboard/diagrams.ts`, which writes one link per
 * line and uses neither form — and that is what the budget is asked about, since
 * every diagram it measures is one those generators produced. A hand-written
 * flowchart doing something stranger than the grammar above could still be
 * under-counted; the text-size limit and the client-side catch in
 * `DIAGRAMS_AND_REPORTS_JS` are what cover that case.
 */
export function countMermaidEdges(source: string): number {
  let edges = 0;
  for (const raw of mermaidRenderText(source).split('\n')) {
    if (NON_EDGE_STATEMENT.test(raw)) continue;
    const line = raw.replace(LABEL_TEXT, ' ');
    const segments = line.split(LINK_TOKEN);
    if (segments.length < 2) continue;
    for (let i = 0; i < segments.length - 1; i++) {
      edges += ampersandGroups(segments[i]) * ampersandGroups(segments[i + 1]);
    }
  }
  return edges;
}

/** `A & B` on one side of a link is two nodes, and therefore two edges. */
function ampersandGroups(segment: string): number {
  const groups = segment.split('&').filter(s => s.trim().length > 0).length;
  return groups > 0 ? groups : 1;
}

export function measureDiagram(source: string): DiagramMeasurement {
  return { textSize: mermaidRenderText(source).length, edges: countMermaidEdges(source) };
}

/**
 * Will a renderer draw this?
 *
 * Empty input is renderable — the generators return `''` for a model with
 * nothing to draw, and the callers already treat that as "no diagram", which is
 * a different answer from "a diagram that cannot be drawn".
 */
export function checkRenderBudget(source: string, limits = MERMAID_LIMITS): RenderBudgetVerdict {
  const measurement = measureDiagram(source);
  const violations: BudgetViolation[] = [];

  if (measurement.textSize > limits.maxTextSize) {
    violations.push({
      limit: 'maxTextSize',
      measured: measurement.textSize,
      allowed: limits.maxTextSize,
      over: measurement.textSize - limits.maxTextSize,
      symptom: 'Mermaid resolves the render successfully and draws one box reading '
        + '"Maximum text size in diagram exceeded" — no exception, no console output.',
    });
  }
  if (measurement.edges > limits.maxEdges) {
    violations.push({
      limit: 'maxEdges',
      measured: measurement.edges,
      allowed: limits.maxEdges,
      over: measurement.edges - limits.maxEdges,
      symptom: 'The flowchart parser throws "Edge limit exceeded" and the renderer shows a syntax error.',
    });
  }

  return { renderable: violations.length === 0, measurement, violations };
}

/** `65652` → `65,652`. Locale-independent: these lines end up in test assertions. */
export function groupDigits(n: number): string {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** One line per violation: what exceeded, by how much, in the limit's own units. */
export function describeViolation(v: BudgetViolation): string {
  const unit = v.limit === 'maxTextSize' ? 'characters' : 'edges';
  const percent = Math.round((v.over / v.allowed) * 100);
  return `${groupDigits(v.measured)} ${unit}, over Mermaid's ${v.limit} of ${groupDigits(v.allowed)}`
    + ` by ${groupDigits(v.over)} (+${percent}%)`;
}

/**
 * The diagram written in place of one that cannot be drawn.
 *
 * A drawable diagram that says why the real one is missing. It has to BE a
 * diagram — this text is what goes into the `.mmd` a reviewer opens in GitHub
 * and into the `<pre class="mermaid">` the dashboard renders, and in both places
 * the alternative is the pink box that says nothing actionable.
 *
 * `where` names a surface that still renders this model at this size, so the
 * message ends in an answer rather than an apology. Two of them, because
 * together they are complete and neither is on its own: the Analytics asset ×
 * threat matrix is the readable overview but caps at its 24 worst assets and 14
 * most frequent threats (and says so), and the Threats & Exposures table is the
 * one that lists every claim. Pointing at the matrix alone would be a second
 * confident half-truth, which is the genus of bug this module exists to remove.
 */
export function oversizedStub(name: string, verdict: RenderBudgetVerdict, where: string): string {
  const reasons = verdict.violations.map(describeViolation).join('<br/>');
  return [
    // `graph`, not `flowchart`. The dashboard initialises Mermaid with
    // `defaultRenderer: 'dagre-d3'`, under which `flowchart` resolves to a
    // diagram type mermaid@11 no longer registers and the parse fails with "No
    // diagram type detected" — measured in a real browser against the real page.
    // `graph` is also what the three generators emit, so a stub draws in exactly
    // the places the diagram it replaces would have.
    'graph TB',
    `  budget["⚠ ${name} was not drawn<br/>${reasons}<br/>${where}"]:::over_budget`,
    '  classDef over_budget fill:#3a1010,stroke:#ea1d1d,color:#f0f0f0,stroke-width:1.4px',
    '',
  ].join('\n');
}

/**
 * Where to read this model when the diagram is over budget.
 *
 * Two answers, not one. The matrix is the readable overview and is capped; the
 * list is complete and is a list. A reader who wants the whole model as data has
 * `model.json` beside the artifact.
 */
export const ARTIFACT_FALLBACK = 'Read .guardlink/model.json for the whole model, or open the dashboard: Analytics for the asset x threat matrix, Threats & Exposures for every claim.';
export const DASHBOARD_FALLBACK = 'Open Analytics for the asset × threat matrix, or Threats & Exposures for the full list — both still render at this size.';
