/**
 * GuardLink — Subgraph selection (GL-202). The architectural spine.
 *
 * `selectSubgraph` returns a **ThreatModel**, not a bespoke graph shape. That is
 * the whole point: a subgraph is a filtered model, so the existing renderer
 * consumes it unchanged —
 *
 *     generateThreatGraph(selectSubgraph(model, opts))
 *
 * — and SG-3's `.mmd` artifacts become a disk cache of common selections rather
 * than a second implementation of selection. `filterByFeature` already proved
 * the ThreatModel → ThreatModel shape works; this generalises it.
 *
 * ── Graph semantics, decided rather than inherited ──────────────────
 *
 * **Traversal walks the asset plane only.** Edges are `@flows` (directed),
 * `@boundary` (undirected) and `@transfers` (directed). Threats and controls
 * attach to every visited asset but are never transited *through*.
 *
 * Measured on this repo: `#path-traversal` is declared on 10 distinct assets. If
 * a hop could cross asset → threat → asset, depth 2 from #cli would reach 10 of
 * 16 declared assets — 62% of the graph — because shared threats act as hubs.
 * Depth would stop meaning anything. A threat is a shared *classification*, not
 * a coupling: two components exposed to path traversal are not related, they
 * merely have the same kind of weakness. Blast radius is about where data goes,
 * which is the flow graph.
 *
 * **Boundaries traverse in every direction.** They are undirected by
 * construction (`@boundary between A and B`) and therefore simultaneously in-
 * and out-adjacent. Dropping them from a directional query would silently hide
 * exactly the edges a trust review is looking for. Each hop records whether the
 * edge it crossed was directed, so a caller can tell.
 *
 * **Hop 0 resolves fuzzily; every later hop is exact.** The starting ref goes
 * through `resolveAssetRef` — the same resolution `asset X` performs, with the
 * same tiers, `matched_via` and ambiguity reporting. After that the frontier is
 * made of refs that already exist in the model, and there is no user input left
 * to interpret, so hops walk canonical identity only. Fuzzy matching at hop N
 * would let `#cli` pull in `#llm-client` at every level and the frontier would
 * blow out into everything sharing three characters.
 *
 * @exposes #mcp to #dos [low] cwe:CWE-400 -- "Unbounded depth on a dense graph expands the frontier"
 * @mitigates #mcp against #dos using #resource-limits -- "Depth is clamped; visited set makes every node terminal, so cycles cannot revisit"
 * @exposes #mcp to #info-disclosure [low] cwe:CWE-200 -- "D34: the subgraph spread carried the whole repo's unannotated_files inventory into a neighbourhood answer — 8094 paths, 654.8 KB, on a query that resolved nothing"
 * @mitigates #mcp against #info-disclosure using #resource-limits -- "unannotated_files is filtered to the subgraph's own files here, and dropped entirely by withoutFileInventory at the graph emission boundary"
 * @validates #resource-limits for #mcp -- "tests/graph-sparse-repo.test.ts builds two repos differing only in unannotated file count and pins that payload size does not follow it"
 * @flows ThreatModel -> #mcp via selectSubgraph -- "Model filtered to a neighbourhood"
 * @comment -- "Pure function over the model; returns a ThreatModel so the existing Mermaid generator needs no changes"
 */

import { resolveAssetRef, type MatchKind } from './lookup.js';
import { filterByFeature } from '../parser/feature-filter.js';
import { canonicaliser } from '../parser/canonical-ref.js';
import type { ThreatModel, ThreatModelAsset } from '../types/index.js';

export type Direction = 'in' | 'out' | 'both';

/** Relation arrays `kinds` can select. Assets, threats and controls are the node
 *  vocabulary and are always kept — filtering them out would leave edges whose
 *  endpoints have no definition. */
export const SELECTABLE_KINDS = [
  'exposures', 'mitigations', 'confirmed', 'acceptances', 'transfers',
  'flows', 'boundaries', 'validations', 'audits', 'ownership',
  'data_handling', 'assumptions', 'comments', 'shields', 'features',
] as const;
export type SelectableKind = typeof SELECTABLE_KINDS[number];

/** Hard ceiling on depth. Beyond the graph's diameter another hop adds nothing. */
export const MAX_DEPTH = 10;

/**
 * How complete a traversal result is. Three states, because the two questions
 * a caller actually has — "is there more?" and "can I get it?" — have three
 * answers between them, not two.
 */
export type Completeness =
  /**
   * Every reachable node is present and the frontier was exhausted. There is
   * nothing more to find at any depth. A saturated sink reports this.
   */
  | 'complete'
  /**
   * Complete FOR the requested depth, but the frontier still had unexplored
   * neighbours. Raising `depth` would return more. The result is correct, just
   * bounded by what you asked for.
   */
  | 'depth_limited'
  /**
   * Stopped by a limit the CALLER did not choose — `depth` was clamped to
   * MAX_DEPTH — and there is still more beyond. THE RESULT IS INCOMPLETE and
   * raising `depth` will not help, because the ceiling is already in force.
   */
  | 'truncated';

export interface SubgraphOptions {
  /** Asset ref to start from. Omitted → no traversal, just the pre-filters. */
  from?: string;
  /** Hops from `from`. 0 is the node alone. Clamped to MAX_DEPTH. */
  depth?: number;
  direction?: Direction;
  /** Relation arrays to keep. Omitted → all. */
  kinds?: string[];
  /** Restrict to annotations declared in one file, applied before traversal. */
  file?: string;
  /** Restrict to one or more features, applied before traversal. */
  feature?: string | string[];
}

export interface GraphEdge {
  kind: 'flow' | 'boundary' | 'transfer';
  from: string;
  to: string;
  directed: boolean;
  label?: string;
  file: string;
  line: number;
}

export interface TraversalNode {
  key: string;
  /** Hops from the start. 0 is the start node itself. */
  depth: number;
  declared: boolean;
}

export interface Traversal {
  /** How the starting ref resolved — null when `from` was omitted. */
  start: {
    ref: string;
    canonical: string | null;
    resolved: boolean;
    matched_via?: MatchKind;
    matched_against?: string;
    ambiguous?: boolean;
    candidates?: string[];
  } | null;
  nodes: TraversalNode[];
  /** Edges whose endpoints are both in the node set. */
  edges: GraphEdge[];
  depth_reached: number;
  depth_requested: number;
  /**
   * Whether this result is the whole answer, and if not, why not.
   *
   * Replaces a `truncated: boolean` that conflated "I stopped because a limit
   * was hit" with "I stopped because there was nothing left to reach" — the
   * didn't-run-versus-found-nothing confusion, applied to traversal. Observed:
   * `#llm-client` depth 1 `out` reported `truncated: true` while depth 2 `out`
   * reported `false`, on an identical 4 nodes / 6 edges. The old flag was in
   * fact testing "did the last hop add any nodes", which says nothing at all
   * about whether more exist beyond them.
   */
  completeness: Completeness;
  /**
   * What lies one hop past the boundary — absent when `completeness` is
   * `'complete'`, because then there is nothing.
   *
   * A blast radius that does not say what it omitted is exactly the failure
   * this surface exists to eliminate: an agent reasoning about what a change
   * affects, on a silently partial graph.
   */
  frontier_unexplored?: {
    count: number;
    nodes: string[];
  };
}

/** Canonicalise a ref to one key per asset: `#cli`, `cli` and `GuardLink.CLI` agree. */
// Moved to parser/canonical-ref.ts so parser/coverage.ts can reach it without
// inverting the layering — D47 was the cost of it living here. Re-exported so
// existing callers of `canonicaliser` from this module are unaffected.
export { canonicaliser };

/** Every asset-plane edge in the model, with endpoints canonicalised. */
export function graphEdges(model: ThreatModel): GraphEdge[] {
  const key = canonicaliser(model);
  const edges: GraphEdge[] = [];
  for (const f of model.flows) {
    edges.push({
      kind: 'flow', from: key(f.source), to: key(f.target), directed: true,
      label: f.mechanism, file: f.location.file, line: f.location.line,
    });
  }
  for (const b of model.boundaries) {
    edges.push({
      kind: 'boundary', from: key(b.asset_a), to: key(b.asset_b), directed: false,
      label: b.id, file: b.location.file, line: b.location.line,
    });
  }
  for (const t of model.transfers) {
    edges.push({
      kind: 'transfer', from: key(t.source), to: key(t.target), directed: true,
      label: t.threat, file: t.location.file, line: t.location.line,
    });
  }
  return edges;
}

/** The node an edge leads to from `node`, or null when direction forbids the hop. */
function step(edge: GraphEdge, node: string, direction: Direction): string | null {
  if (!edge.directed) {
    // Undirected: symmetric, so adjacent in every direction.
    if (edge.from === node) return edge.to;
    if (edge.to === node) return edge.from;
    return null;
  }
  if (edge.from === node && direction !== 'in') return edge.to;
  if (edge.to === node && direction !== 'out') return edge.from;
  return null;
}

/**
 * Breadth-first walk of the asset plane.
 *
 * The `visited` map is what makes cycles terminate: a node entering the frontier
 * records the depth it entered at and is never enqueued again, so a cycle walks
 * each of its nodes exactly once regardless of how the edges loop.
 */
export function traverseGraph(model: ThreatModel, options: SubgraphOptions = {}): Traversal {
  const depthRequested = options.depth ?? 2;
  const depth = Math.max(0, Math.min(depthRequested, MAX_DEPTH));
  const direction = options.direction ?? 'both';
  const key = canonicaliser(model);
  const edges = graphEdges(model);

  if (!options.from) {
    return {
      start: null,
      nodes: [], edges: [],
      // No start ref at all: nothing was asked for, so nothing is missing.
      depth_reached: 0, depth_requested: depthRequested, completeness: 'complete',
    };
  }

  // Hop 0 — the only place a ref is interpreted rather than matched literally.
  const resolution = resolveAssetRef(model, options.from);
  const declaredAssets = new Map<string, ThreatModelAsset>();
  for (const a of model.assets) declaredAssets.set(key(a.id || a.path.join('.')), a);

  // The start node is the declared asset when one resolved; otherwise the
  // strongest-tier ref the annotation graph actually contains, so an undeclared
  // endpoint like `LLMProvider` is a legal starting point.
  let startKey: string | null = null;
  if (resolution.declared) {
    startKey = key(resolution.declared.id || resolution.declared.path.join('.'));
  } else {
    const endpoints = new Set<string>();
    for (const e of edges) { endpoints.add(e.from); endpoints.add(e.to); }
    for (const candidate of endpoints) {
      if (resolution.keep(candidate)) { startKey = candidate; break; }
    }
  }

  const start: Traversal['start'] = {
    ref: options.from,
    canonical: startKey,
    resolved: startKey !== null,
    ...(resolution.match ? { matched_via: resolution.match.kind, matched_against: resolution.match.matched_against } : {}),
    ...(resolution.tied.length > 1
      ? { ambiguous: true, candidates: resolution.tied.map(a => a.id || a.path.join('.')) }
      : {}),
  };

  if (startKey === null) {
    // The start ref did not resolve. `start.resolved` is false and carries the
    // reason; completeness describes the traversal, and an unresolved start
    // means there was no traversal to be incomplete about.
    return { start, nodes: [], edges: [], depth_reached: 0, depth_requested: depthRequested, completeness: 'complete' };
  }

  const visited = new Map<string, number>([[startKey, 0]]);
  let frontier = [startKey];
  let reached = 0;

  for (let d = 1; d <= depth && frontier.length > 0; d++) {
    const next: string[] = [];
    for (const node of frontier) {
      for (const edge of edges) {
        const to = step(edge, node, direction);
        if (to === null || visited.has(to)) continue;   // ← cycle termination
        visited.set(to, d);
        next.push(to);
      }
    }
    if (next.length > 0) reached = d;
    frontier = next;
  }

  // What is actually beyond the boundary.
  //
  // The old flag asked `frontier.length > 0`, which is "did the last hop add
  // any nodes" — a question about what we already HAVE, not about what we are
  // missing. Those nodes are in `visited`; they are in the answer. The real
  // question is whether the final frontier has neighbours we never visited, and
  // that takes one more probing hop to establish. It costs one extra edge scan
  // and it is the difference between reporting "there is more" and reporting
  // "the last thing I did was find something".
  const unexplored = new Set<string>();
  for (const node of frontier) {
    for (const edge of edges) {
      const to = step(edge, node, direction);
      if (to !== null && !visited.has(to)) unexplored.add(to);
    }
  }

  // `depth` is `depthRequested` clamped to MAX_DEPTH, so this is true only when
  // a ceiling the caller did not choose cut the walk short. That is the one case
  // where raising `depth` does not help, which is what separates a truncated
  // result from a merely depth-limited one.
  const clampedByCeiling = depth < depthRequested;

  const completeness: Completeness =
    unexplored.size === 0 ? 'complete'
      : clampedByCeiling ? 'truncated'
        : 'depth_limited';

  const nodes: TraversalNode[] = [...visited.entries()]
    .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]))
    .map(([k, d]) => ({ key: k, depth: d, declared: declaredAssets.has(k) }));

  const included = new Set(visited.keys());
  return {
    start,
    nodes,
    edges: edges.filter(e => included.has(e.from) && included.has(e.to)),
    depth_reached: reached,
    depth_requested: depthRequested,
    completeness,
    ...(completeness === 'complete' ? {} : {
      frontier_unexplored: {
        count: unexplored.size,
        nodes: [...unexplored].sort(),
      },
    }),
  };
}

/**
 * Filter a model to a neighbourhood, returning a ThreatModel.
 *
 * The return type is the contract. Anything that consumes a ThreatModel —
 * `generateThreatGraph`, the report writer, SG-3's artifact emission — consumes
 * this without modification.
 */
export function selectSubgraph(model: ThreatModel, options: SubgraphOptions = {}): ThreatModel {
  // Pre-filters compose before traversal, so `feature` and `file` narrow the
  // graph that is then walked rather than the answer that comes back.
  let base = model;
  if (options.feature) {
    const names = Array.isArray(options.feature) ? options.feature : [options.feature];
    base = filterByFeature(base, names);
  }
  if (options.file) {
    const want = options.file.replace(/^\.\//, '').replaceAll('\\', '/').toLowerCase();
    const inFile = <T extends { location: { file: string } }>(arr: T[]): T[] =>
      arr.filter(r => r.location.file.toLowerCase() === want);
    base = {
      ...base,
      assets: inFile(base.assets), threats: inFile(base.threats), controls: inFile(base.controls),
      mitigations: inFile(base.mitigations), exposures: inFile(base.exposures),
      confirmed: inFile(base.confirmed), acceptances: inFile(base.acceptances),
      transfers: inFile(base.transfers), flows: inFile(base.flows),
      boundaries: inFile(base.boundaries), validations: inFile(base.validations),
      audits: inFile(base.audits), ownership: inFile(base.ownership),
      data_handling: inFile(base.data_handling), assumptions: inFile(base.assumptions),
      shields: inFile(base.shields), features: inFile(base.features), comments: inFile(base.comments),
    };
  }

  const selected = options.from ? nodeSetOf(base, options) : null;
  const kinds = options.kinds?.length ? new Set(options.kinds) : null;

  const key = canonicaliser(base);
  const inSet = (ref: string) => selected === null || selected.has(key(ref));
  const bothIn = (a: string, b: string) => inSet(a) && inSet(b);
  const wanted = (kind: SelectableKind) => !kinds || kinds.has(kind);
  const pick = <T>(kind: SelectableKind, rows: T[]) => (wanted(kind) ? rows : []);

  const exposures    = pick('exposures',    base.exposures.filter(e => inSet(e.asset)));
  const mitigations  = pick('mitigations',  base.mitigations.filter(m => inSet(m.asset)));
  const confirmed    = pick('confirmed',    (base.confirmed || []).filter(c => inSet(c.asset)));
  const acceptances  = pick('acceptances',  base.acceptances.filter(a => inSet(a.asset)));
  const transfers    = pick('transfers',    base.transfers.filter(t => bothIn(t.source, t.target)));
  const flows        = pick('flows',        base.flows.filter(f => bothIn(f.source, f.target)));
  const boundaries   = pick('boundaries',   base.boundaries.filter(b => bothIn(b.asset_a, b.asset_b)));
  const validations  = pick('validations',  base.validations.filter(v => inSet(v.asset)));
  const audits       = pick('audits',       base.audits.filter(a => inSet(a.asset)));
  const ownership    = pick('ownership',    base.ownership.filter(o => inSet(o.asset)));
  const dataHandling = pick('data_handling', base.data_handling.filter(d => inSet(d.asset)));
  const assumptions  = pick('assumptions',  base.assumptions.filter(a => inSet(a.asset)));

  // Node definitions are always kept: an edge whose endpoint has no declaration
  // renders as a bare id and reads as missing data rather than as a filter.
  const assets = base.assets.filter(a => inSet(a.id || a.path.join('.')));

  const threatRefs = new Set<string>();
  for (const r of [...exposures, ...mitigations, ...confirmed, ...acceptances]) threatRefs.add(bare(r.threat));
  for (const t of transfers) threatRefs.add(bare(t.threat));
  const threats = base.threats.filter(t => threatRefs.has(bare(t.id || '')) || threatRefs.has(bare(t.canonical_name)));

  const controlRefs = new Set<string>();
  for (const m of mitigations) if (m.control) controlRefs.add(bare(m.control));
  for (const v of validations) controlRefs.add(bare(v.control));
  const controls = base.controls.filter(c => controlRefs.has(bare(c.id || '')) || controlRefs.has(bare(c.canonical_name)));

  // @comment, @shield and @feature carry no ref, so they follow the files that
  // contributed something — the same file-proximity rule filterByFeature uses.
  const files = new Set<string>();
  for (const row of [...assets, ...threats, ...controls, ...exposures, ...mitigations,
    ...confirmed, ...acceptances, ...transfers, ...flows, ...boundaries, ...validations,
    ...audits, ...ownership, ...dataHandling, ...assumptions]) files.add(row.location.file);
  const byFile = <T extends { location: { file: string } }>(rows: T[]) => rows.filter(r => files.has(r.location.file));

  const comments = pick('comments', byFile(base.comments));
  const shields  = pick('shields',  byFile(base.shields));
  const features = pick('features', byFile(base.features));

  const arrays = [assets, threats, controls, mitigations, exposures, confirmed,
    acceptances, transfers, flows, boundaries, validations, audits, ownership,
    dataHandling, assumptions, shields, features, comments];

  return {
    ...base,
    // Recomputed, not carried over: a subgraph reporting the whole model's
    // annotation count would misdescribe what it contains.
    annotations_parsed: arrays.reduce((n, a) => n + a.length, 0),
    annotated_files: base.annotated_files.filter(f => files.has(f)),
    // D34. The spread carried this one through untouched while every relation
    // array around it was filtered, so a neighbourhood query returned the whole
    // repo's file inventory. Measured on specter-v1: 8094 rows, 654.8 KB — 92%
    // of a resolved depth-2 payload, and 95% of one that resolved NOTHING.
    // `files` is built from annotation locations, so an unannotated file can
    // never be in it and this is always []. That is the honest value for a
    // subgraph — an unannotated file contributes no node and no edge — and it is
    // exactly why the graph tool omits the key at emission rather than shipping
    // an empty array that reads as "this repo is fully annotated".
    unannotated_files: base.unannotated_files.filter(f => files.has(f)),
    assets, threats, controls, mitigations, exposures, confirmed, acceptances,
    transfers, flows, boundaries, validations, audits, ownership,
    data_handling: dataHandling, assumptions, shields, features, comments,
  };
}

const bare = (s: string) => (s ?? '').replace(/^#/, '').toLowerCase();

// ─── Detail level ────────────────────────────────────────────────────

export type GraphDetail = 'summary' | 'full';

/**
 * Every relation array plus the node vocabulary. The summary transform walks
 * this list rather than the object's own keys, so a scalar field on the model
 * (`source_files`, `annotation_hash`) is never mistaken for a row array.
 */
const ALL_ROW_ARRAYS = [
  'assets', 'threats', 'controls',
  ...SELECTABLE_KINDS,
] as const;

/**
 * Strip the payload, not the graph.
 *
 * Measured on this repo at depth 2 from `#cli`: `description` and `location`
 * together are 43.7% of the response, and the proportion barely moves with
 * depth (32.7% / 43.7% / 39.1% at depths 1/2/3). The cost is what hangs off each
 * node, not how many nodes there are — which is why the answer is not a smaller
 * default depth. Depth 1 makes the tool redundant with `asset X`, and defaulting
 * `direction` to `out` is an arbitrary asymmetry that would silently hide
 * everything upstream of the asset you asked about.
 *
 * This is a PURE POST-TRANSFORM over an already-selected subgraph. It cannot add
 * or remove a node or an edge, because it never sees the traversal options — the
 * topology-identity property the tests pin is structural, not a coincidence that
 * needs maintaining. A summary mode that quietly dropped nodes would be a
 * silent-wrong-answer path, which is the failure this whole surface exists to
 * eliminate.
 *
 * `location: {file, line}` becomes `at: "file:line"` rather than disappearing:
 * an agent still needs to know where a fact was declared to go read it. What it
 * does not need, to reason about blast radius, is the prose explaining why.
 */
export function summariseGraphPayload(payload: { traversal: Traversal; model: ThreatModel }): unknown {
  const compactRow = (row: Record<string, unknown>): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(row)) {
      if (k === 'description') continue;
      if (k === 'location' && v && typeof v === 'object') {
        const loc = v as { file?: string; line?: number };
        out.at = `${loc.file ?? '?'}:${loc.line ?? '?'}`;
        continue;
      }
      out[k] = v;
    }
    return out;
  };

  const model: Record<string, unknown> = { ...(payload.model as unknown as Record<string, unknown>) };
  for (const name of ALL_ROW_ARRAYS) {
    const rows = model[name];
    if (Array.isArray(rows)) model[name] = rows.map(r => compactRow(r as Record<string, unknown>));
  }

  return {
    traversal: {
      ...payload.traversal,
      edges: payload.traversal.edges.map(e => {
        const { file, line, ...rest } = e;
        return { ...rest, at: `${file}:${line}` };
      }),
    },
    model,
    detail: 'summary',
    detail_note:
      'description text and full location objects omitted; `at` is "file:line". '
      + 'Node and edge sets are identical to detail:"full" — only per-node detail differs. '
      + 'Use detail:"full" for the complete records, or when you need a valid ThreatModel.',
  };
}

/**
 * Drop the repo file inventory from a graph payload at the emission boundary.
 *
 * This is GL-205's ruling, not a second policy: `guardlink_parse` already decided
 * that `unannotated_files` is a flat path list carrying nothing about the threat
 * model, that it is the field which scales with repo size while the model does
 * not, and that the answer is to omit it by default and name the tool that owns
 * it. `guardlink_graph` shipped two commits later and reintroduced the field
 * through a spread (D34). Same field, same reasoning, same shape of answer —
 * including the `_omitted` marker, because absent-because-omitted and
 * absent-because-empty are different facts and a caller that cannot tell them
 * apart will read a large repo as fully annotated.
 *
 * `annotated_files` stays. It is already filtered to the files that contributed
 * a node or an edge, it is proportionate to the subgraph rather than to the repo
 * (measured: 45 rows / 1.2 KB against 8094 rows / 654.8 KB), and it answers a
 * question a caller actually has — where do I go to read this.
 *
 * Applied to the payload rather than to the model so `selectSubgraph` keeps
 * returning a ThreatModel: the type is the contract every other consumer relies on.
 */
export function withoutFileInventory(payload: unknown, repoUnannotatedCount: number): unknown {
  const p = payload as { model?: Record<string, unknown> };
  if (!p?.model) return payload;
  const { unannotated_files: _dropped, ...model } = p.model;
  return {
    ...p,
    model: {
      ...model,
      unannotated_files_omitted: {
        count: repoUnannotatedCount,
        scope: 'whole repository, not this subgraph',
        reason: 'A subgraph is about relations; an unannotated file contributes no node and no edge. Call guardlink_unannotated, which owns this data.',
      },
    },
  };
}

/** Canonical keys reachable under `options`, or null when there is no start. */
function nodeSetOf(model: ThreatModel, options: SubgraphOptions): Set<string> | null {
  const traversal = traverseGraph(model, options);
  if (!traversal.start?.resolved) return new Set();
  return new Set(traversal.nodes.map(n => n.key));
}

// ─── Path queries ────────────────────────────────────────────────────

export interface PathHop {
  from: string;
  to: string;
  via: GraphEdge;
}

export interface PathResult {
  from: { ref: string; canonical: string | null; resolved: boolean };
  to: { ref: string; canonical: string | null; resolved: boolean };
  found: boolean;
  hops: PathHop[];
  /** Present when no path exists, explaining which of the two failure modes it is. */
  reason?: string;
}

/**
 * Shortest path between two assets, or an explicit no-path answer.
 *
 * Directed edges are followed forwards — the question "can data get from X to Y"
 * is directional — while boundaries, being undirected, are crossable either way.
 *
 * An unresolvable endpoint and a genuinely disconnected pair are different
 * answers and are reported as such: returning `found: false` for both would tell
 * a caller its graph is disconnected when in fact it typed a name that does not
 * exist.
 */
export function findPath(model: ThreatModel, fromRef: string, toRef: string): PathResult {
  const key = canonicaliser(model);
  const edges = graphEdges(model);
  const endpoints = new Set<string>();
  for (const e of edges) { endpoints.add(e.from); endpoints.add(e.to); }

  const resolveEnd = (ref: string) => {
    const r = resolveAssetRef(model, ref);
    if (r.declared) {
      return { ref, canonical: key(r.declared.id || r.declared.path.join('.')), resolved: true };
    }
    for (const candidate of endpoints) {
      if (r.keep(candidate)) return { ref, canonical: candidate, resolved: true };
    }
    return { ref, canonical: null, resolved: false };
  };

  const from = resolveEnd(fromRef);
  const to = resolveEnd(toRef);

  if (!from.resolved || !to.resolved) {
    const missing = [!from.resolved ? fromRef : null, !to.resolved ? toRef : null].filter(Boolean);
    return {
      from, to, found: false, hops: [],
      reason: `Unresolved: ${missing.join(' and ')}. No asset or annotation endpoint of that name exists, so no path could be attempted.`,
    };
  }

  if (from.canonical === to.canonical) {
    return { from, to, found: true, hops: [] };
  }

  // BFS, so the first path found is a shortest one.
  const prev = new Map<string, PathHop>();
  const seen = new Set([from.canonical!]);
  let frontier = [from.canonical!];

  while (frontier.length > 0) {
    const next: string[] = [];
    for (const node of frontier) {
      for (const edge of edges) {
        const onward = edge.directed
          ? (edge.from === node ? edge.to : null)
          : (edge.from === node ? edge.to : edge.to === node ? edge.from : null);
        if (onward === null || seen.has(onward)) continue;
        seen.add(onward);
        prev.set(onward, { from: node, to: onward, via: edge });
        if (onward === to.canonical) {
          const hops: PathHop[] = [];
          for (let at = to.canonical!; prev.has(at); at = prev.get(at)!.from) hops.unshift(prev.get(at)!);
          return { from, to, found: true, hops };
        }
        next.push(onward);
      }
    }
    frontier = next;
  }

  return {
    from, to, found: false, hops: [],
    reason: `Both endpoints exist, but no directed path runs from ${from.canonical} to ${to.canonical}. Boundaries are crossable in either direction; flows and transfers are followed forwards only.`,
  };
}
