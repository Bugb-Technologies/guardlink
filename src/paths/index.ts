/**
 * GuardLink Paths — derived source-to-sink analysis over the flow graph.
 *
 * Every other exposure in the model is an opinion someone formed while reading
 * a file. A path finding is not: it is a consequence of `@flows` and
 * `@mitigates` annotations that are already committed, computed with no model
 * in the loop, so it cannot cite a line that does not exist.
 *
 * Entry and exit are structural rather than a hardcoded vocabulary of scary
 * names. A declared `@asset` is a part of the system; an endpoint that appears
 * in the flow graph without being declared is therefore something outside it,
 * and which side it sits on follows from its degree — no inbound flow means
 * data originates there, no outbound flow means data terminates there. On this
 * repo that lands on UserPrompt/EnvVars/RawStdin and FileSystem/Commands/
 * TempDir without naming any of them here.
 *
 * @flows ThreatModel -> #parser via findUnmitigatedPaths -- "Reads flows, assets, mitigations and boundaries from the parsed model"
 * @comment -- "Pure analyzer: no file I/O, no user input, no network. Operates only on an already-parsed ThreatModel, which is why it needs no @exposes of its own"
 * @comment -- "Walks flow edges only. @boundary edges are undirected and used for crossing detection, and @transfers moves responsibility rather than data, so neither is a hop a path may take"
 */

import { graphEdges } from '../mcp/subgraph.js';
import { canonicaliser } from '../parser/canonical-ref.js';
import type { PathHop } from '../mcp/subgraph.js';
import type { ThreatModel } from '../types/index.js';

export interface EndpointClassification {
  /** Undeclared flow endpoints with no inbound flow — where data enters. */
  entries: string[];
  /** Undeclared flow endpoints with no outbound flow — where data leaves. */
  exits: string[];
}

export interface PathFinding {
  /** Display label of the undeclared endpoint the path starts at. */
  entry: string;
  /** Display label of the undeclared endpoint the path ends at. */
  exit: string;
  /** Every hop, in order, each carrying the file:line of its `@flows`. */
  hops: PathHop[];
  /**
   * Display labels for every node on the path, entry first, exit last.
   *
   * Hops hold canonical keys — lowercased and `#`-stripped — so a consumer that
   * rebuilt labels from them would render `api` where the model says `#api`.
   * Resolving once here keeps that decision in the one place that has the map.
   */
  chain: string[];
  /** Declared assets the path runs through, in order. */
  assetsOnPath: string[];
  /** True when any asset on this path carries a `@mitigates`. */
  mitigated: boolean;
  /** Controls defending assets on this path, deduped, in path order. */
  controlsOnPath: string[];
  /** True when a single hop of this path is declared a `@boundary`. */
  crossesBoundary: boolean;
  /** Ids of the boundaries crossed, in path order. */
  boundariesCrossed: string[];
}

export interface PathOptions {
  /**
   * Report paths that a control already defends. Off by default: the finding
   * a path query exists to surface is the undefended one, and this repo's 110
   * flows produce far more defended routes than undefended ones.
   */
  includeMitigated?: boolean;
}

/**
 * Display label for a canonical key.
 *
 * Declared assets render as `#id` so a finding can be pasted straight into a
 * `guardlink_lookup`; undeclared endpoints keep the spelling their annotation
 * used, because that string is the only name they have anywhere.
 */
function displayMap(model: ThreatModel): Map<string, string> {
  const key = canonicaliser(model);
  const display = new Map<string, string>();
  for (const f of model.flows ?? []) {
    if (!display.has(key(f.source))) display.set(key(f.source), f.source);
    if (!display.has(key(f.target))) display.set(key(f.target), f.target);
  }
  // Declared assets overwrite whatever spelling a flow happened to use first.
  for (const a of model.assets ?? []) {
    const canonical = key(a.id || a.path.join('.'));
    display.set(canonical, a.id ? `#${a.id}` : a.path.join('.'));
  }
  return display;
}

function declaredKeys(model: ThreatModel): Set<string> {
  const key = canonicaliser(model);
  return new Set((model.assets ?? []).map(a => key(a.id || a.path.join('.'))));
}

/** Flow edges only — see the module note on why boundaries and transfers are excluded. */
function flowEdges(model: ThreatModel) {
  return graphEdges(model).filter(e => e.kind === 'flow');
}

/**
 * Split the flow graph's endpoints into the ways data gets in and the ways it
 * gets out, by declaredness and degree.
 */
export function classifyEndpoints(model: ThreatModel): EndpointClassification {
  const declared = declaredKeys(model);
  const display = displayMap(model);
  const edges = flowEdges(model);

  const inDeg = new Map<string, number>();
  const outDeg = new Map<string, number>();
  for (const e of edges) {
    outDeg.set(e.from, (outDeg.get(e.from) ?? 0) + 1);
    inDeg.set(e.to, (inDeg.get(e.to) ?? 0) + 1);
  }

  const entries: string[] = [];
  const exits: string[] = [];
  const nodes = new Set([...inDeg.keys(), ...outDeg.keys()]);
  for (const n of [...nodes].sort()) {
    if (declared.has(n)) continue;
    const label = display.get(n) ?? n;
    if ((outDeg.get(n) ?? 0) > 0 && (inDeg.get(n) ?? 0) === 0) entries.push(label);
    if ((inDeg.get(n) ?? 0) > 0 && (outDeg.get(n) ?? 0) === 0) exits.push(label);
  }
  return { entries, exits };
}

/**
 * Every shortest entry-to-exit path that runs through at least one declared
 * asset.
 *
 * The declared-asset requirement is what separates a finding from noise: two
 * loose endpoints wired directly to each other describe nothing the project
 * owns, so there is no control that could have been missing from it.
 */
export function findUnmitigatedPaths(model: ThreatModel, options: PathOptions = {}): PathFinding[] {
  const key = canonicaliser(model);
  const declared = declaredKeys(model);
  const display = displayMap(model);
  const edges = flowEdges(model);

  // Controls indexed by the canonical asset they defend, so "is this path
  // defended" is a lookup per node rather than a scan per path.
  const controlsByAsset = new Map<string, string[]>();
  for (const m of model.mitigations ?? []) {
    const k = key(m.asset);
    const label = m.control || m.threat;
    const list = controlsByAsset.get(k) ?? [];
    if (!list.includes(label)) list.push(label);
    controlsByAsset.set(k, list);
  }

  // Boundaries indexed by unordered node pair — `@boundary` is undirected, so
  // an annotation naming the pair either way round must match the one hop.
  // Sorted so the pair is unordered, and NUL-joined because an endpoint label
  // may contain a space but can never contain a NUL.
  const pairKey = (a: string, b: string) => [a, b].sort().join('\u0000');
  const boundaryByPair = new Map<string, string>();
  for (const b of model.boundaries ?? []) {
    boundaryByPair.set(pairKey(key(b.asset_a), key(b.asset_b)), b.id || `${b.asset_a}↔${b.asset_b}`);
  }

  const canonicalOf = new Map<string, string>();
  for (const [canonical, label] of display) canonicalOf.set(label, canonical);

  const { entries, exits } = classifyEndpoints(model);
  const exitKeys = new Set(exits.map(l => canonicalOf.get(l) ?? key(l)));

  const findings: PathFinding[] = [];

  for (const entryLabel of entries) {
    const start = canonicalOf.get(entryLabel) ?? key(entryLabel);

    // BFS from the entry, so the first time an exit is reached is by a
    // shortest path. One walk per entry covers every exit it can reach.
    const prev = new Map<string, PathHop>();
    const seen = new Set([start]);
    let frontier = [start];

    while (frontier.length > 0) {
      const next: string[] = [];
      for (const node of frontier) {
        for (const edge of edges) {
          if (edge.from !== node || seen.has(edge.to)) continue;
          seen.add(edge.to);
          prev.set(edge.to, { from: node, to: edge.to, via: edge });
          next.push(edge.to);
        }
      }
      frontier = next;
    }

    for (const exitKey of exitKeys) {
      if (!prev.has(exitKey)) continue;

      const hops: PathHop[] = [];
      for (let at = exitKey; prev.has(at); at = prev.get(at)!.from) hops.unshift(prev.get(at)!);
      if (hops.length === 0) continue;

      const assetsOnPath = hops
        .map(h => h.from)
        .concat(exitKey)
        .filter(n => declared.has(n))
        .map(n => display.get(n) ?? n);

      if (assetsOnPath.length === 0) continue;

      const controlsOnPath: string[] = [];
      for (const n of hops.map(h => h.from).concat(exitKey)) {
        for (const c of controlsByAsset.get(n) ?? []) {
          if (!controlsOnPath.includes(c)) controlsOnPath.push(c);
        }
      }

      const boundariesCrossed: string[] = [];
      for (const h of hops) {
        const id = boundaryByPair.get(pairKey(h.from, h.to));
        if (id && !boundariesCrossed.includes(id)) boundariesCrossed.push(id);
      }

      const mitigated = controlsOnPath.length > 0;
      if (mitigated && !options.includeMitigated) continue;

      const chain = [hops[0].from, ...hops.map(h => h.to)].map(n => display.get(n) ?? n);

      findings.push({
        entry: entryLabel,
        exit: display.get(exitKey) ?? exitKey,
        hops,
        chain,
        assetsOnPath,
        mitigated,
        controlsOnPath,
        crossesBoundary: boundariesCrossed.length > 0,
        boundariesCrossed,
      });
    }
  }

  // A route that leaves a trust zone is the one worth reading first; among
  // equals the shorter path is the more direct claim about the system.
  return findings.sort((a, b) =>
    Number(b.crossesBoundary) - Number(a.crossesBoundary)
    || a.hops.length - b.hops.length
    || a.entry.localeCompare(b.entry)
    || a.exit.localeCompare(b.exit));
}
