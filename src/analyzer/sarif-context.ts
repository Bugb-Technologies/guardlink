/**
 * GuardLink SARIF — the declared context around each finding.
 *
 * `sarif.ts` decides WHICH results exist and what each one says. This module
 * adds what the model already declares around them, as SARIF members no
 * existing consumer reads:
 *
 *   - `locations[0].logicalLocations` and `properties['guardlink/anchor']`:
 *     the code the claim is attached to
 *   - `taxa`, with `run.taxonomies`: the claim's `cwe:` and `owasp:` refs
 *   - `relatedLocations`: `@boundary`, `@assumes`, `@handles`, `@transfers`
 *     and `@audit` annotations on the claim's asset
 *   - `codeFlows`: the declared `@flows` chain into the claim, only when the
 *     chain's last hop is declared on the claim's own handler or file
 *   - `run.graphs[0]`: every `@flows` and `@boundary`, with ids and claim keys
 *
 * ── Additive only ───────────────────────────────────────────────────
 *
 * Downstream consumers key on the result index, on `message.text`, on rule
 * ids and on `partialFingerprints`, so nothing here may insert, reorder or
 * rewrite a result. Every member is appended after the ones `sarif.ts` wrote,
 * and deleting the members added here gives back the export byte for byte
 * (tests/sarif-enrichment.test.ts proves it against an export cut before this
 * module existed).
 *
 * ── Never a guessed chain ───────────────────────────────────────────
 *
 * `@flows` hops are not linked by call site: the model says `Client -> #api`
 * and `#api -> #db`, not which handler of `#api` makes the second call. So only
 * the LAST hop of a chain can be tied to the claim, by the same handler-scope
 * rule route attribution uses (SPEC §3.6.2). A chain whose last hop is not tied
 * that way is not emitted at all, and each upstream hop says it was joined by
 * graph adjacency alone (`guardlink/hopAttribution: "graph"`).
 *
 * ── Never derived from @entitles or @actor ──────────────────────────
 *
 * SPEC §6.1: an entitlement changes no byte of `results` or `tool`. Nothing in
 * this module reads `model.entitlements` or `model.actors`, and the claim-key
 * lookup skips the `entitles` verb, so neither a relatedLocation nor a graph
 * node can come from one.
 *
 * @flows ThreatModel -> #sarif via buildSarifContext -- "Flows, boundaries, assets and context annotations read from the parsed model"
 * @exposes #sarif to #dos [low] cwe:CWE-400 -- "Enumerating upstream @flows chains is combinatorial in a dense flow graph"
 * @mitigates #sarif against #dos using #resource-limits -- "Chain walk is capped by depth, by chains collected and by a step budget; at most three chains are emitted per result"
 * @comment -- "Pure transform over the parsed model: no I/O. Reads nothing from @entitles or @actor (SPEC §6.1)"
 */

import type {
  ThreatModel, SourceLocation, ThreatModelFlow, ThreatModelBoundary,
} from '../types/index.js';
import { canonicaliser } from '../parser/canonical-ref.js';
import { handlerScope, scopeEncloses } from '../parser/handler-scope.js';
import { relationRecords, claimText } from '../parser/claim-key.js';
import { parseRouteChannel } from '../parser/route.js';

// ─── SARIF 2.1.0 member types (the subset written here) ─────────────

export interface SarifMessage { text: string }

export interface SarifPhysicalLocation {
  artifactLocation: { uri: string };
  region: { startLine: number; startColumn?: number };
}

export interface SarifLogicalLocation { name: string }

export interface SarifLocation {
  id?: number;
  physicalLocation: SarifPhysicalLocation;
  logicalLocations?: SarifLogicalLocation[];
  message?: SarifMessage;
  properties?: Record<string, unknown>;
}

export interface SarifTaxonReference {
  id: string;
  index: number;
  toolComponent: { name: string; index: number };
}

export interface SarifThreadFlowLocation {
  location: SarifLocation;
  kinds: string[];
  importance?: 'essential' | 'important' | 'unimportant';
  webRequest?: { method: string; target: string };
  properties?: Record<string, unknown>;
}

export interface SarifCodeFlow {
  message: SarifMessage;
  threadFlows: { locations: SarifThreadFlowLocation[] }[];
  properties?: Record<string, unknown>;
}

export interface SarifGraph {
  description: SarifMessage;
  nodes: { id: string; label: SarifMessage; location?: SarifLocation; properties: Record<string, unknown> }[];
  edges: { id: string; sourceNodeId: string; targetNodeId: string; label?: SarifMessage; properties: Record<string, unknown> }[];
}

export interface SarifTaxonomy {
  name: string;
  organization?: string;
  informationUri: string;
  isComprehensive: false;
  taxa: { id: string }[];
}

/** The members a finding result can gain. Every one is optional and appended. */
export interface EnrichableResult {
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
  taxa?: SarifTaxonReference[];
  relatedLocations?: SarifLocation[];
  codeFlows?: SarifCodeFlow[];
}

/** The fields of an `@exposes` or `@confirmed` claim this module reads. */
export interface FindingClaim {
  asset: string;
  threat: string;
  external_refs: string[];
  location: SourceLocation;
}

export interface SarifContext {
  /** Append the declared context to one exposure or confirmed result. */
  enrich(result: EnrichableResult, claim: FindingClaim, verb: 'exposes' | 'confirmed'): void;
  /** `run.taxonomies` for the taxa the enriched results referenced, in first-use order. */
  taxonomies(): SarifTaxonomy[];
  /** `run.graphs[0]`, or null when the model declares no asset, flow or boundary. */
  graph(): SarifGraph | null;
}

// ─── Bounds ─────────────────────────────────────────────────────────

/** Longest upstream chain walked, in hops. */
const MAX_CHAIN_HOPS = 6;
/** Chains collected per claim before ranking. */
const MAX_CHAINS_COLLECTED = 200;
/** Graph steps per claim; a dense flow graph cannot turn one export into a hang. */
const MAX_WALK_STEPS = 20_000;
/** Chains emitted per result. */
const MAX_CHAINS_EMITTED = 3;

// ─── Helpers ────────────────────────────────────────────────────────

export function physicalLocation(file: string, line: number): SarifPhysicalLocation {
  // SARIF uses forward-slash URIs
  return { artifactLocation: { uri: file.replace(/\\/g, '/') }, region: { startLine: line } };
}

const bareRef = (ref: string): string => (ref ?? '').trim().replace(/^#/, '').toLowerCase();

/** Unordered pair key: `@boundary` is undirected. NUL cannot occur in a ref. */
const pairKey = (a: string, b: string): string => [a, b].sort().join('\u0000');

/**
 * A `cwe:` or `owasp:` ref as a taxon, or null for any other scheme.
 *
 *   cwe:CWE-89, cwe:89   → CWE   "89"   (the id form the MITRE CWE taxonomy uses)
 *   owasp:A03:2021       → OWASP "A03:2021"
 *   owasp:A03            → OWASP "A03"
 */
function taxonOf(ref: string): { taxonomy: 'CWE' | 'OWASP'; id: string } | null {
  const cwe = /^cwe:\s*(?:cwe-)?(\d+)$/i.exec(ref.trim());
  if (cwe) return { taxonomy: 'CWE', id: String(Number(cwe[1])) };
  const owasp = /^owasp:\s*(a\d{1,2})(?::(\d{4}))?$/i.exec(ref.trim());
  if (owasp) return { taxonomy: 'OWASP', id: owasp[2] ? `${owasp[1].toUpperCase()}:${owasp[2]}` : owasp[1].toUpperCase() };
  return null;
}

const TAXONOMY_INFO: Record<'CWE' | 'OWASP', Omit<SarifTaxonomy, 'taxa'>> = {
  CWE: { name: 'CWE', organization: 'MITRE', informationUri: 'https://cwe.mitre.org/', isComprehensive: false },
  OWASP: { name: 'OWASP', organization: 'OWASP Foundation', informationUri: 'https://owasp.org/Top10/', isComprehensive: false },
};

type HopTier = 'handler' | 'file';

/**
 * Is a `@flows` hop tied to the claim, and how strongly — the route-attribution
 * ladder of SPEC §3.6.2 applied to a flow instead of a route.
 *
 *   handler — the flow is declared on the claim's handler, or on code enclosing it
 *   file    — the flow is declared for the claim's whole file, or the claim is
 *             file-level and the flow sits somewhere in that file
 *   null    — another file, or a SIBLING handler in the claim's file: tying it
 *             to this claim would be a guess
 */
function hopTier(flow: SourceLocation, claim: SourceLocation): HopTier | null {
  if (flow.file !== claim.file) return null;
  const own = handlerScope(claim);
  const at = handlerScope(flow);
  if (own && at && scopeEncloses(at, own)) return 'handler';
  if (!at || !own) return 'file';
  return null;
}

const TIER_RANK: Record<HopTier, number> = { handler: 2, file: 1 };

// ─── Builder ────────────────────────────────────────────────────────

export function buildSarifContext(model: ThreatModel): SarifContext {
  const key = canonicaliser(model);
  const flows: ThreatModelFlow[] = model.flows ?? [];
  const boundaries: ThreatModelBoundary[] = model.boundaries ?? [];

  // Claim keys for every relation the results can point at — never `entitles`.
  const claimKeyOf = new Map<object, string>();
  for (const r of relationRecords(model)) {
    if (r.verb !== 'entitles') claimKeyOf.set(r.location, r.key);
  }

  // ── Nodes: declared assets first, then undeclared endpoints in first-seen order ──
  const declared = new Set<string>();
  const nodes = new Map<string, SarifGraph['nodes'][number]>();
  for (const a of model.assets ?? []) {
    const label = a.id ? `#${a.id}` : a.path.join('.');
    const id = key(label);
    if (!id || nodes.has(id)) continue;
    declared.add(id);
    nodes.set(id, {
      id,
      label: { text: label },
      location: { physicalLocation: physicalLocation(a.location.file, a.location.line) },
      properties: { 'guardlink/declared': true, 'guardlink/path': a.path.join('.') },
    });
  }
  const nodeFor = (ref: string): string => {
    const id = key(ref);
    if (!nodes.has(id)) nodes.set(id, { id, label: { text: ref }, properties: { 'guardlink/declared': false } });
    return id;
  };

  // ── Boundary edges, indexed by unordered pair for crossing detection ──
  const boundaryEdgeIds = new Map<string, string[]>();
  const boundaryLabel = new Map<string, string>();
  const edges: SarifGraph['edges'] = [];
  const crossingsOf = new Map<string, string[]>();
  boundaries.forEach((b, i) => {
    const id = `boundary:${i}`;
    const a = nodeFor(b.asset_a);
    const c = nodeFor(b.asset_b);
    const pair = pairKey(a, c);
    boundaryEdgeIds.set(pair, [...(boundaryEdgeIds.get(pair) ?? []), id]);
    boundaryLabel.set(id, b.id ? `#${b.id}` : `${b.asset_a} and ${b.asset_b}`);
    crossingsOf.set(id, []);
    // The convention SPEC §3.2 gives `guardlink paths`: an undeclared endpoint
    // is outside the system. With exactly one undeclared side, that side is
    // outer; otherwise the annotation does not say, and neither do we.
    const outer = [a, c].filter(n => !declared.has(n));
    const side = outer.length === 1
      ? { basis: 'undeclared-endpoint', outer: outer[0], inner: outer[0] === a ? c : a }
      : { basis: 'unknown' };
    edges.push({
      id, sourceNodeId: a, targetNodeId: c,
      label: { text: b.description || `@boundary ${claimText(['boundary', b])}` },
      properties: {
        'guardlink/kind': 'boundary',
        'guardlink/directed': false,
        'guardlink/boundaryId': b.id ?? null,
        'guardlink/claimKey': claimKeyOf.get(b.location) ?? null,
        'guardlink/location': { physicalLocation: physicalLocation(b.location.file, b.location.line) },
        'guardlink/side': side,
        'guardlink/crossings': crossingsOf.get(id),
      },
    });
  });

  // ── Flow edges ──
  const crossedBy = (f: ThreatModelFlow): string[] => boundaryEdgeIds.get(pairKey(key(f.source), key(f.target))) ?? [];
  flows.forEach((f, i) => {
    const id = `flow:${i}`;
    const route = f.route ?? parseRouteChannel(f.mechanism);
    const crosses = crossedBy(f);
    for (const b of crosses) crossingsOf.get(b)!.push(id);
    edges.push({
      id, sourceNodeId: nodeFor(f.source), targetNodeId: nodeFor(f.target),
      ...(f.mechanism ? { label: { text: f.mechanism } } : {}),
      properties: {
        'guardlink/kind': 'flow',
        'guardlink/directed': true,
        'guardlink/claimKey': claimKeyOf.get(f.location) ?? null,
        'guardlink/location': { physicalLocation: physicalLocation(f.location.file, f.location.line) },
        ...(route ? { 'guardlink/route': { http_method: route.method, http_path: route.path } } : {}),
        ...(crosses.length ? { 'guardlink/crosses': crosses } : {}),
      },
    });
  });

  // ── Upstream chains ──
  const inbound = new Map<string, number[]>();
  flows.forEach((f, i) => {
    const t = key(f.target);
    inbound.set(t, [...(inbound.get(t) ?? []), i]);
  });

  /**
   * Simple chains of flow indexes from an entry to `asset`, entry first,
   * shortest first. An entry is an undeclared endpoint (outside the system,
   * SPEC §3.2) or a declared asset nothing flows into.
   *
   * Breadth-first, so the step budget is spent on short chains before long
   * ones: depth-first spent it all inside a dense cluster and never came back
   * up to the one-hop entry beside it.
   */
  const chainsInto = (asset: string): number[][] => {
    const goal = key(asset);
    const found: number[][] = [];
    // Each partial chain is upstream-first: hops[0] flows into `goal`.
    let frontier: { at: string; hops: number[]; seen: Set<string> }[] = [{ at: goal, hops: [], seen: new Set([goal]) }];
    let steps = 0;
    while (frontier.length > 0) {
      const next: typeof frontier = [];
      for (const { at, hops, seen } of frontier) {
        if (++steps > MAX_WALK_STEPS || found.length >= MAX_CHAINS_COLLECTED) return found;
        const into = inbound.get(at) ?? [];
        if (hops.length > 0 && (into.length === 0 || !declared.has(at))) {
          found.push([...hops].reverse());
          continue;
        }
        if (hops.length >= MAX_CHAIN_HOPS) continue;
        for (const i of into) {
          const from = key(flows[i].source);
          if (seen.has(from)) continue;
          // Queued partial chains count against the budget too, so the next
          // level of a dense graph cannot grow without bound.
          if (++steps > MAX_WALK_STEPS) return found;
          next.push({ at: from, hops: [...hops, i], seen: new Set(seen).add(from) });
        }
      }
      frontier = next;
    }
    return found;
  };

  // ── Taxonomies, filled as results reference them ──
  const taxonomies = new Map<'CWE' | 'OWASP', { index: number; taxa: Map<string, number> }>();
  const taxonRef = (ref: string): SarifTaxonReference | null => {
    const t = taxonOf(ref);
    if (!t) return null;
    let tax = taxonomies.get(t.taxonomy);
    if (!tax) { tax = { index: taxonomies.size, taxa: new Map() }; taxonomies.set(t.taxonomy, tax); }
    if (!tax.taxa.has(t.id)) tax.taxa.set(t.id, tax.taxa.size);
    return { id: t.id, index: tax.taxa.get(t.id)!, toolComponent: { name: t.taxonomy, index: tax.index } };
  };

  // ── Related annotations on an asset ──
  const describe = (text: string, description?: string): string => description ? `${text}: ${description}` : text;
  const relatedFor = (claim: FindingClaim): SarifLocation[] => {
    const asset = key(claim.asset);
    const threat = bareRef(claim.threat);
    const out: { at: SourceLocation; text: string; verb: string; extra?: Record<string, unknown> }[] = [];
    boundaries.forEach((b, i) => {
      if (key(b.asset_a) === asset || key(b.asset_b) === asset) {
        out.push({ at: b.location, verb: 'boundary', text: describe(`@boundary ${claimText(['boundary', b])}`, b.description), extra: { 'guardlink/edge': `boundary:${i}` } });
      }
    });
    for (const s of model.assumptions ?? []) {
      if (key(s.asset) === asset) out.push({ at: s.location, verb: 'assumes', text: describe(`@assumes ${claimText(['assumes', s])}`, s.description) });
    }
    for (const h of model.data_handling ?? []) {
      if (key(h.asset) === asset) out.push({ at: h.location, verb: 'handles', text: describe(`@handles ${claimText(['handles', h])}`, h.description) });
    }
    for (const t of model.transfers ?? []) {
      if (key(t.source) === asset && bareRef(t.threat) === threat) {
        out.push({ at: t.location, verb: 'transfers', text: describe(`@transfers ${claimText(['transfers', t])}`, t.description) });
      }
    }
    for (const a of model.audits ?? []) {
      if (key(a.asset) === asset) out.push({ at: a.location, verb: 'audit', text: describe(`@audit ${claimText(['audit', a])}`, a.description) });
    }
    return out.map((r, n) => ({
      id: n + 1,
      physicalLocation: physicalLocation(r.at.file, r.at.line),
      message: { text: r.text },
      properties: {
        'guardlink/verb': r.verb,
        ...(claimKeyOf.has(r.at) ? { 'guardlink/claimKey': claimKeyOf.get(r.at) } : {}),
        ...r.extra,
      },
    }));
  };

  // ── Code flows into a claim ──
  const codeFlowsFor = (claim: FindingClaim, verb: 'exposes' | 'confirmed'): { tier: HopTier; flows: SarifCodeFlow[] } | null => {
    const ranked = chainsInto(claim.asset).map((chain, order) => {
      const last = hopTier(flows[chain[chain.length - 1]].location, claim.location);
      const upstreamOnHandler = chain.slice(0, -1).filter(i => hopTier(flows[i].location, claim.location) === 'handler').length;
      const crossings = chain.filter(i => crossedBy(flows[i]).length > 0).length;
      return { chain, last, score: [last ? TIER_RANK[last] : 0, upstreamOnHandler, crossings, -chain.length, -order] };
    }).sort((x, y) => {
      for (let n = 0; n < x.score.length; n++) if (x.score[n] !== y.score[n]) return y.score[n] - x.score[n];
      return 0;
    });
    const tier = ranked[0]?.last;
    if (!tier) return null;

    const claimMessage = verb === 'exposes'
      ? `@exposes ${claim.asset} to ${claim.threat}`
      : `@confirmed ${claim.threat} on ${claim.asset}`;
    const chosen = ranked.filter(r => r.last === tier).slice(0, MAX_CHAINS_EMITTED);
    return {
      tier,
      flows: chosen.map(({ chain }) => {
        const locations: SarifThreadFlowLocation[] = chain.map((i, n) => {
          const f = flows[i];
          const route = f.route ?? parseRouteChannel(f.mechanism);
          const crosses = crossedBy(f);
          const via = f.mechanism ? ` via ${f.mechanism}` : '';
          const note = crosses.length ? ` [crosses ${crosses.map(b => boundaryLabel.get(b)).join(', ')}]` : '';
          const hop = n === chain.length - 1 ? tier : (hopTier(f.location, claim.location) ?? 'graph');
          return {
            location: {
              physicalLocation: physicalLocation(f.location.file, f.location.line),
              message: { text: `${f.source} -> ${f.target}${via}${note}` },
            },
            kinds: crosses.length ? ['flow', 'boundary-crossing'] : ['flow'],
            ...(route ? { webRequest: { method: route.method, target: route.path } } : {}),
            properties: {
              'guardlink/edge': `flow:${i}`,
              ...(claimKeyOf.has(f.location) ? { 'guardlink/claimKey': claimKeyOf.get(f.location) } : {}),
              'guardlink/hopAttribution': hop,
              ...(crosses.length ? { 'guardlink/crosses': crosses } : {}),
            },
          };
        });
        locations.push({
          location: {
            physicalLocation: physicalLocation(claim.location.file, claim.location.line),
            message: { text: claimMessage },
          },
          kinds: ['claim'],
          importance: 'essential',
        });
        return {
          message: { text: `Declared @flows chain from ${flows[chain[0]].source} to ${claim.asset}; the last hop is declared on the claim's ${tier === 'handler' ? 'handler' : 'file'}` },
          threadFlows: [{ locations }],
          properties: { 'guardlink/flowAttribution': tier },
        };
      }),
    };
  };

  return {
    enrich(result, claim, verb) {
      const loc = claim.location;
      const symbol = loc.parent_symbol || (loc.anchor && loc.anchor.scope !== 'file' ? loc.anchor.symbol : null);
      if (symbol) result.locations[0].logicalLocations = [{ name: symbol }];

      const props = result.properties ?? (result.properties = {});
      if (loc.anchor) {
        props['guardlink/anchor'] = {
          scope: loc.anchor.scope, symbol: loc.anchor.symbol,
          start_line: loc.anchor.start_line, end_line: loc.anchor.end_line,
        };
      }

      const chains = codeFlowsFor(claim, verb);
      if (chains) props['guardlink/flowAttribution'] = chains.tier;

      const seen = new Set<string>();
      const taxa: SarifTaxonReference[] = [];
      for (const ref of claim.external_refs ?? []) {
        const t = taxonRef(ref);
        if (!t) continue;
        const k = `${t.toolComponent.name}\u0000${t.id}`;
        if (seen.has(k)) continue;
        seen.add(k);
        taxa.push(t);
      }
      if (taxa.length) result.taxa = taxa;

      const related = relatedFor(claim);
      if (related.length) result.relatedLocations = related;

      if (chains) result.codeFlows = chains.flows;
    },

    taxonomies() {
      return [...taxonomies.entries()].map(([name, t]) => ({
        ...TAXONOMY_INFO[name],
        taxa: [...t.taxa.keys()].map(id => ({ id })),
      }));
    },

    graph() {
      if (nodes.size === 0) return null;
      return {
        description: { text: 'GuardLink declared threat model: @flows edges (directed) and @boundary edges (undirected). Edge ids are local to this export; guardlink/claimKey is the stable identity.' },
        nodes: [...nodes.values()],
        edges,
      };
    },
  };
}
