/**
 * GuardLink Lookup — Query the threat model graph.
 *
 * Supports structured queries:
 *   - "asset #config" or "asset Config" → find asset by ID or path
 *   - "threat #sqli" → find threat by ID
 *   - "control #rbac" → find control by ID
 *   - "threats for #auth" → threats targeting an asset (via exposures)
 *   - "controls for #auth" → controls protecting an asset (via mitigations)
 *   - "flows into #engine" → data flows with target = engine
 *   - "flows from #config" → data flows with source = config
 *   - "unmitigated" → all unmitigated exposures
 *   - "confirmed" → @confirmed verified exploitable findings
 *   - "actors" → declared principals (@actor) with the capabilities each is entitled to
 *   - "entitlements" / "entitlements for #actor" → @entitles claims, with citation and inert flag
 *   - "boundary #config" → boundaries involving asset
 *   - Free text → fuzzy match across assets, threats, controls
 *
 * @exposes #mcp to #redos [low] cwe:CWE-1333 -- "Regex patterns applied to query strings"
 * @mitigates #mcp against #redos using #regex-anchoring -- "Patterns are simple and bounded"
 * @flows QueryString -> #mcp via lookup -- "Query input path"
 * @comment -- "Pure function; no I/O; operates on in-memory ThreatModel"
 */

import type {
  ThreatModel, ThreatModelAsset, ThreatModelThreat, ThreatModelControl,
  ThreatModelExposure, ThreatModelMitigation, ThreatModelFlow,
  ThreatModelBoundary, ThreatModelTransfer, ThreatModelAcceptance,
  SourceLocation, DataClassification,
} from '../types/index.js';

export interface LookupResult {
  query: string;
  type: string;
  count: number;
  results: any[];
  /**
   * How the query's reference was resolved. Present on every form that resolves
   * a ref. `substring` means the answer came from a partial match and should be
   * treated as a suggestion, not an identification.
   */
  matched_via?: MatchKind;
  /** What the ref actually matched against — the thing to check when `matched_via` is `substring`. */
  matched_against?: string;
  /**
   * Set when more than one declared record tied at the winning tier. The result
   * holds the first by declaration order; `candidates` names the whole tie so
   * the caller can re-query precisely instead of trusting an arbitrary pick.
   */
  ambiguous?: boolean;
  /** Identifiers of every record tied with the one returned. Present only when `ambiguous`. */
  candidates?: string[];
  /**
   * GL-204 — present when the query was an external identifier (cwe:, owasp:).
   * Read `external_id.declared` before treating `count: 0` as "nothing exposed":
   * it also distinguishes "this model has never heard of that weakness class".
   */
  external_id?: ExternalIdSummary;
}

export interface LookupQuery {
  raw: string;
}

/**
 * Every query form `lookup` understands. Returned verbatim when a query is not
 * recognised, so the caller can retry with something that exists rather than
 * acting on a fuzzy hit for a question that was never parsed.
 */
export const SUPPORTED_QUERY_FORMS = [
  'unmitigated',
  'confirmed',
  'features',
  'asset <id>',
  'threat <id>',
  'control <id>',
  'threats for <asset>',
  'controls for <asset>',
  'exposures for <asset>',
  'mitigations for <asset>',
  'flows into <asset>',
  'flows from <asset>',
  'boundary for <asset>',
  'owner of <asset>          (also: who owns <asset>)',
  'handles <classification>  (pii, phi, financial, secrets, internal, public — or the bare word)',
  'handles for <asset>',
  'assumptions for <asset>',
  'audits [for <asset>]',
  'validations for <asset-or-control>',
  'acceptances [for <asset>]',
  'transfers [for <threat-or-asset>]',
  'comments [for <file-or-asset>]',
  'shields [for <file-or-asset>]',
  'cross-repo refs [for <repo-or-tag>]  (sibling-repo tags from workspace.yaml — NOT cwe:/owasp: — accepts `external refs` as an alias)',
  'cwe:CWE-89 | owasp:A03 | CWE-89  (external identifiers declared on threats — the scanner bridge)',
  '<id>            (bare identifier, fuzzy match across all categories)',
] as const;

/**
 * Expand a ref to every alias the model knows for it — id to dotted path and back.
 * Extracted so anything resolving a ref uses the same alias set `lookup` does.
 */
export function buildResolver(model: ThreatModel): Resolver {
  const idToPath = new Map<string, string>();
  const pathToId = new Map<string, string>();
  for (const a of model.assets) {
    const path = a.path.join('.');
    if (a.id) {
      idToPath.set(a.id.toLowerCase(), path.toLowerCase());
      pathToId.set(path.toLowerCase(), a.id.toLowerCase());
    }
  }
  for (const t of model.threats) {
    if (t.id) idToPath.set(t.id.toLowerCase(), t.canonical_name.toLowerCase());
  }
  for (const c of model.controls) {
    if (c.id) idToPath.set(c.id.toLowerCase(), c.canonical_name.toLowerCase());
  }
  return (ref: string): string[] => {
    const r = ref.toLowerCase().replace(/^#/, '');
    const aliases = [r];
    if (idToPath.has(r)) aliases.push(idToPath.get(r)!);
    if (pathToId.has(r)) aliases.push(pathToId.get(r)!);
    return aliases;
  };
}

/** What `asset X` decided a ref names, and how. */
export interface AssetResolution {
  /** The declared asset, when the ref resolved to one at scope tier. */
  declared: ThreatModelAsset | undefined;
  /** Admits relation refs belonging to the resolved identity. */
  keep: (value: string) => boolean;
  match: RefMatch | null;
  /** Declared assets tied at the winning tier. More than one means ambiguous. */
  tied: ThreatModelAsset[];
}

/**
 * Resolve an asset ref exactly as `asset X` does.
 *
 * The single entry point for anything outside this module that needs to agree
 * with lookup about which asset a ref names — graph traversal above all, where a
 * second resolver would put a D18 at hop 0 and compound it at every hop after.
 */
export function resolveAssetRef(model: ThreatModel, ref: string): AssetResolution {
  const aliases = buildResolver(model)(ref);
  const declared = findBest(model.assets, assetIdentityOf, ref, aliases);
  const scope = resolveScope(declared, assetIdentityOf, assetRelationRefs(model), ref, aliases);
  return { declared: scope.declaredItem, keep: scope.keep, match: scope.match, tied: scope.tied };
}

export function lookup(model: ThreatModel, query: string): LookupResult {
  // A trailing question mark is punctuation, not part of the identifier. Left in
  // place it degrades an otherwise exact ref to a substring match.
  const q = query.trim().toLowerCase().replace(/\?+$/, '').trim();

  const resolve = buildResolver(model);

  // ── "cwe:CWE-89" / "owasp:A03" / bare "CWE-89" — the CXG bridge ──
  //
  // Checked before everything else: an identifier is unambiguous, and letting it
  // reach lookupFuzzy would answer a scanner's question with a substring guess.
  const externalId = parseExternalId(query.trim());
  if (externalId) return lookupExternalId(model, query, externalId);

  // ── "unmitigated" ──
  if (/^unmitigated/.test(q)) {
    return lookupUnmitigated(model, query);
  }

  // ── "confirmed" (verified exploitable @confirmed annotations) ──
  if (/^confirmed(\s|$)/.test(q)) {
    return lookupConfirmed(model, query);
  }

  // ── "actors" (declared principals) ──
  if (/^actors?(\s|$)/.test(q)) {
    return lookupActors(model, query);
  }

  // ── "entitlements [for <actor>]" ──
  const entitlementsQ = q.match(/^entitlements?(?:\s+(?:for|of|on)\s+(.+))?$/);
  if (entitlementsQ) {
    return lookupEntitlements(model, query, entitlementsQ[1]?.trim());
  }

  // ── "features" ──
  if (/^features?(\s|$)/.test(q)) {
    const byName = new Map<string, { name: string; files: Set<string>; description?: string }>();
    for (const f of (model.features || [])) {
      const key = f.feature.toLowerCase();
      if (!byName.has(key)) {
        byName.set(key, { name: f.feature, files: new Set(), description: f.description });
      }
      byName.get(key)!.files.add(f.location.file);
    }
    const results = [...byName.values()]
      .sort((a, b) => a.name.localeCompare(b.name))
      .map(v => ({ feature: v.name, files: [...v.files], description: v.description }));
    return { query, type: 'features', count: results.length, results };
  }

  // ── "threats for <asset>" ──
  const threatsFor = q.match(/^threats?\s+(?:for|targeting|on)\s+(.+)/);
  if (threatsFor) return lookupThreatsFor(model, query, threatsFor[1].trim(), resolve);

  // ── "controls for <asset>" ──
  const controlsFor = q.match(/^controls?\s+(?:for|protecting|on)\s+(.+)/);
  if (controlsFor) return lookupControlsFor(model, query, controlsFor[1].trim(), resolve);

  // ── "flows into <asset>" ──
  const flowsInto = q.match(/^flows?\s+(?:into|to)\s+(.+)/);
  if (flowsInto) return lookupFlows(model, query, 'into', flowsInto[1].trim(), resolve);

  // ── "flows from <asset>" ──
  const flowsFrom = q.match(/^flows?\s+(?:from|out\s+of)\s+(.+)/);
  if (flowsFrom) return lookupFlows(model, query, 'from', flowsFrom[1].trim(), resolve);

  // ── "boundary <asset>" ──
  const boundaryQ = q.match(/^boundar(?:y|ies)\s+(?:for|involving|of)?\s*(.+)/);
  if (boundaryQ) return lookupBoundaries(model, query, boundaryQ[1].trim(), resolve);

  // ── "asset <id>" ──
  const assetQ = q.match(/^asset\s+(.+)/);
  if (assetQ) return lookupAsset(model, query, assetQ[1].trim(), resolve);

  // ── "threat <id>" ──
  const threatQ = q.match(/^threat\s+(.+)/);
  if (threatQ) return lookupThreat(model, query, threatQ[1].trim(), resolve);

  // ── "control <id>" ──
  const controlQ = q.match(/^control\s+(.+)/);
  if (controlQ) return lookupControl(model, query, controlQ[1].trim(), resolve);

  // ── "exposures for <asset>" ──
  const exposuresFor = q.match(/^exposures?\s+(?:for|on)\s+(.+)/);
  if (exposuresFor) return lookupExposuresFor(model, query, exposuresFor[1].trim(), resolve);

  // ── "mitigations for <asset>" ──
  const mitigationsFor = q.match(/^mitigations?\s+(?:for|on)\s+(.+)/);
  if (mitigationsFor) return lookupMitigationsFor(model, query, mitigationsFor[1].trim(), resolve);

  // ── GL-203: the nine relation types that had no query form ────────
  //
  // Every asset-scoped form routes through lookupAssetRelation, which resolves
  // the ref exactly as `asset X` does. Same tiers, same identity join, same
  // ambiguity reporting — a form that resolved refs its own way would be D18
  // again.

  // "owner of X" / "who owns X" / "ownership for X"
  const ownerOf = q.match(/^(?:owner|owners|ownership)\s+(?:of|for)\s+(.+)/)
    || q.match(/^who\s+owns\s+(.+)/);
  if (ownerOf) {
    return lookupAssetRelation(model, query, 'ownership', ownerOf[1].trim(), resolve,
      model.ownership, o => o.asset,
      o => ({ owner: o.owner, asset: o.asset, description: o.description, ...loc(o.location) }));
  }

  // "handles <classification>" / bare "pii" / "handles for X"
  const handlesClass = q.match(/^handles\s+(\S+)$/);
  if (handlesClass && CLASSIFICATIONS.includes(handlesClass[1] as DataClassification)) {
    return lookupByClassification(model, query, handlesClass[1]);
  }
  if (CLASSIFICATIONS.includes(q as DataClassification)) {
    return lookupByClassification(model, query, q);
  }
  const handlesFor = q.match(/^handles\s+(?:for|on)\s+(.+)/);
  if (handlesFor) {
    return lookupAssetRelation(model, query, 'data_handling', handlesFor[1].trim(), resolve,
      model.data_handling, d => d.asset,
      d => ({ classification: d.classification, asset: d.asset, description: d.description, ...loc(d.location) }));
  }

  // "assumptions for X"
  const assumesFor = q.match(/^(?:assumptions?|assumes)\s+(?:for|on|about)\s+(.+)/);
  if (assumesFor) {
    return lookupAssetRelation(model, query, 'assumptions', assumesFor[1].trim(), resolve,
      model.assumptions, a => a.asset,
      a => ({ asset: a.asset, description: a.description, ...loc(a.location) }));
  }

  // "audits" / "audits for X"
  const auditsQ = q.match(/^audits?(?:\s+(?:for|on)\s+(.+))?$/);
  if (auditsQ) {
    const projectAudit = (a: typeof model.audits[number]) =>
      ({ asset: a.asset, description: a.description, ...loc(a.location) });
    if (!auditsQ[1]) {
      return { query, type: 'audits', count: model.audits.length, results: model.audits.map(projectAudit) };
    }
    return lookupAssetRelation(model, query, 'audits', auditsQ[1].trim(), resolve,
      model.audits, a => a.asset, projectAudit);
  }

  // "validations for X" — X may be the asset validated or the control validated
  const validationsFor = q.match(/^(?:validations?|validates)\s+(?:for|on)\s+(.+)/);
  if (validationsFor) {
    const target = validationsFor[1].trim();
    const project = (v: typeof model.validations[number]) =>
      ({ control: v.control, asset: v.asset, description: v.description, ...loc(v.location) });
    const byAsset = lookupAssetRelation(model, query, 'validations', target, resolve,
      model.validations, v => v.asset, project);
    if (byAsset.count > 0) return byAsset;
    // Fall back to the control side, so `validations for #prepared-stmts` works.
    const aliases = resolve(target);
    const { keep, match } = selectStrongest(model.validations.map(v => v.control), target, aliases);
    const results = model.validations.filter(v => keep(v.control)).map(project);
    return { query, type: 'validations', count: results.length, results, ...provenance(match) };
  }

  // "acceptances" / "acceptances for X" — governance decisions, human-only to write
  const acceptsQ = q.match(/^(?:acceptances?|accepted)(?:\s+(?:for|on)\s+(.+))?$/);
  if (acceptsQ) {
    const project = (a: ThreatModelAcceptance) =>
      ({ asset: a.asset, threat: a.threat, description: a.description, ...loc(a.location) });
    if (!acceptsQ[1]) {
      return { query, type: 'acceptances', count: model.acceptances.length, results: model.acceptances.map(project) };
    }
    return lookupAssetRelation(model, query, 'acceptances', acceptsQ[1].trim(), resolve,
      model.acceptances, a => a.asset, project);
  }

  // "transfers" / "transfers for X" — X may be the threat, the source or the target
  const transfersQ = q.match(/^transfers?(?:\s+(?:for|of|on)\s+(.+))?$/);
  if (transfersQ) {
    const project = (t: ThreatModelTransfer) =>
      ({ threat: t.threat, source: t.source, target: t.target, description: t.description, ...loc(t.location) });
    if (!transfersQ[1]) {
      return { query, type: 'transfers', count: model.transfers.length, results: model.transfers.map(project) };
    }
    const target = transfersQ[1].trim();
    const aliases = resolve(target);
    const ends = model.transfers.flatMap(t => [t.threat, t.source, t.target]);
    const { keep, match, matched } = selectStrongest(ends, target, aliases);
    const results = model.transfers
      .filter(t => keep(t.threat) || keep(t.source) || keep(t.target))
      .map(project);
    return { query, type: 'transfers', count: results.length, results, ...provenance(match), ...ambiguity(matched, v => v) };
  }

  // "comments" / "comments for <file-or-asset>"
  const commentsQ = q.match(/^comments?(?:\s+(?:for|in|on)\s+(.+))?$/);
  if (commentsQ) {
    return lookupCoLocated(model, query, 'comments', model.comments, commentsQ[1]?.trim(), resolve);
  }

  // "shields" / "shields for <file-or-asset>"
  const shieldsQ = q.match(/^shields?(?:\s+(?:for|in|on)\s+(.+))?$/);
  if (shieldsQ) {
    return lookupCoLocated(model, query, 'shields', model.shields, shieldsQ[1]?.trim(), resolve,
      s => ({ reason: s.reason }));
  }

  // "cross-repo refs [for <repo-or-tag>]" — sibling-repo tags, NOT cwe:/owasp:
  //
  // The bare "refs" alias is gone: a caller typing it while thinking of CWE
  // identifiers would have been handed cross-repo tags and an empty list, which
  // is the D20 confusion made reachable by one word.
  const refsQ = q.match(/^(?:cross[\s_-]?repo[\s_-]?refs?|external[\s_-]?refs?)(?:\s+(?:for|from|in)\s+(.+))?$/);
  if (refsQ) return lookupExternalRefs(model, query, refsQ[1]?.trim());

  // ── Unrecognised multi-word form → say so; never guess ──
  //
  // Falling through to fuzzy matching here is what made `owner of #cli`,
  // `assumptions for #cli` and `comments for #cli` return byte-identical
  // `count: 1` payloads holding the #cli asset record and none of the requested
  // data: matchRef's reverse-substring rule matched the *query string* against
  // the asset id, because "owner of #cli".includes("cli").
  //
  // Identifiers never contain whitespace, so a phrase that matched no form above
  // is a question we did not understand. Say that instead of answering it.
  // (Reaching the orphaned relation types is GL-203, not this fix.)
  if (/\s/.test(q)) {
    return {
      query, type: 'no_match', count: 0,
      results: [{
        hint: `Unrecognised query form: \`${query}\`. This is not a supported form, so no result was guessed.`,
        supported_forms: [...SUPPORTED_QUERY_FORMS],
      }],
    };
  }

  // ── Bare #id or name → try all categories ──
  return lookupFuzzy(model, query, q);
}

// ─── Lookup implementations ──────────────────────────────────────────

function lookupUnmitigated(model: ThreatModel, query: string): LookupResult {
  const covered = new Set<string>();
  for (const m of model.mitigations) covered.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) covered.add(`${a.asset}::${a.threat}`);
  const results = model.exposures
    .filter(e => !covered.has(`${e.asset}::${e.threat}`))
    .map(e => ({
      asset: e.asset, threat: e.threat, severity: e.severity,
      description: e.description, file: e.location.file, line: e.location.line,
    }));
  return { query, type: 'unmitigated_exposures', count: results.length, results };
}

/**
 * Declared principals, each with the capabilities it is entitled to. Answers the
 * question the entitled-principal rubric asks: what is this role allowed to do
 * by design?
 */
function lookupActors(model: ThreatModel, query: string): LookupResult {
  const results = (model.actors || []).map(ac => {
    // Both sides go through bareRef so the join is case-insensitive, the way
    // every other ref match in this module is. Comparing a raw `ac.id` against a
    // normalised ref silently returned no entitlements for any actor whose id
    // carried an uppercase letter.
    const key = bareRef(ac.id || ac.canonical_name);
    const held = (model.entitlements || []).filter(en => bareRef(en.actor) === key);
    return {
      name: ac.name,
      id: ac.id,
      canonical_name: ac.canonical_name,
      description: ac.description,
      file: ac.location.file,
      line: ac.location.line,
      entitled_to: held.map(en => ({
        capability: en.canonical_capability,
        asset: en.asset,
        citation: en.citation?.raw,
        inert: en.inert,
      })),
    };
  });
  return { query, type: 'actors', count: results.length, results };
}

/**
 * @entitles claims. `inert` is surfaced on every row on purpose: an uncited
 * entitlement must never be read as one that can demote a finding (§3.4).
 */
function lookupEntitlements(model: ThreatModel, query: string, actorRef?: string): LookupResult {
  const wanted = actorRef ? bareRef(actorRef) : undefined;
  const results = (model.entitlements || [])
    .filter(en => !wanted || bareRef(en.actor) === wanted)
    .map(en => ({
      actor: en.actor,
      capability: en.canonical_capability,
      capability_as_written: en.capability,
      asset: en.asset,
      description: en.description,
      citation: en.citation?.raw,
      cited_file: en.citation?.file,
      cited_line: en.citation?.line,
      inert: en.inert,
      file: en.location.file,
      line: en.location.line,
    }));
  return { query, type: 'entitlements', count: results.length, results };
}

function lookupConfirmed(model: ThreatModel, query: string): LookupResult {
  const results = (model.confirmed || []).map(c => ({
    asset: c.asset,
    threat: c.threat,
    severity: c.severity,
    description: c.description,
    external_refs: c.external_refs,
    file: c.location.file,
    line: c.location.line,
  }));
  return { query, type: 'confirmed_exploitable', count: results.length, results };
}

type Resolver = (ref: string) => string[];

/**
 * Admit only the entries matching at the strongest tier present in `values`.
 * Keeps every `... for <asset>` form agreeing with `asset <id>` about which
 * annotations belong to the asset.
 */
function keepStrongest(values: string[], ref: string, aliases: string[]): (v: string) => boolean {
  return selectStrongest(values, ref, aliases).keep;
}

/**
 * As `keepStrongest`, plus the match itself and the distinct refs admitted, so
 * the caller can report how it resolved and whether the ref was ambiguous.
 *
 * `flows into llm` admits both `#llm-client` and `LLMProvider` at substring
 * tier. The relational forms return the whole set rather than picking one, so
 * that is visible rather than silent — but naming it keeps every form honest in
 * the same way.
 */
function selectStrongest(values: string[], ref: string, aliases: string[]) {
  const match = strongestMatch(values, ref, aliases);
  const keep = atTier(ref, aliases, match ? TIER[match.kind] : null);
  const matched = [...new Set(values.filter(v => v && keep(v)))];
  return { keep, match, matched };
}

function lookupThreatsFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const { keep, match, matched } = selectStrongest(model.exposures.map(e => e.asset), assetRef, aliases);
  const exposures = model.exposures.filter(e => keep(e.asset));
  const threatIds = new Set(exposures.map(e => e.threat));
  const threats = model.threats.filter(t => (t.id && threatIds.has(t.id)) || threatIds.has(t.canonical_name));

  // Also include direct exposures info
  const results = exposures.map(e => {
    const threat = model.threats.find(t => t.id === e.threat || t.canonical_name === e.threat);
    return {
      threat: e.threat,
      severity: e.severity || threat?.severity,
      description: e.description || threat?.description,
      mitigated: model.mitigations.some(m => m.asset === e.asset && m.threat === e.threat),
      accepted: model.acceptances.some(a => a.asset === e.asset && a.threat === e.threat),
    };
  });
  return { query, type: 'threats_for_asset', count: results.length, results, ...provenance(match), ...ambiguity(matched, v => v) };
}

function lookupControlsFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const { keep, match, matched } = selectStrongest(model.mitigations.map(m => m.asset), assetRef, aliases);
  const mits = model.mitigations.filter(m => keep(m.asset));
  const results = mits.map(m => {
    const control = model.controls.find(c => c.id === m.control || c.canonical_name === m.control);
    return {
      control: m.control, threat: m.threat,
      description: m.description || control?.description,
      file: m.location.file, line: m.location.line,
    };
  });
  return { query, type: 'controls_for_asset', count: results.length, results, ...provenance(match), ...ambiguity(matched, v => v) };
}

function lookupFlows(model: ThreatModel, query: string, direction: 'into' | 'from', assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const ends = model.flows.map(f => direction === 'into' ? f.target : f.source);
  const { keep, match, matched } = selectStrongest(ends, assetRef, aliases);
  const results = model.flows
    .filter(f => keep(direction === 'into' ? f.target : f.source))
    .map(f => ({
      source: f.source, target: f.target, mechanism: f.mechanism,
      description: f.description, file: f.location.file, line: f.location.line,
    }));
  return { query, type: `flows_${direction}`, count: results.length, results, ...provenance(match), ...ambiguity(matched, v => v) };
}

function lookupBoundaries(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const { keep, match, matched } = selectStrongest(model.boundaries.flatMap(b => [b.asset_a, b.asset_b]), assetRef, aliases);
  const results = model.boundaries
    .filter(b => keep(b.asset_a) || keep(b.asset_b))
    .map(b => ({
      asset_a: b.asset_a, asset_b: b.asset_b, description: b.description,
      file: b.location.file, line: b.location.line,
    }));
  return { query, type: 'boundaries', count: results.length, results, ...provenance(match), ...ambiguity(matched, v => v) };
}

/** How an asset is identified, wherever an asset is looked up. */
const assetIdentityOf = (a: ThreatModelAsset) => [a.id || '', a.path.join('.')];

/**
 * Every asset ref the model names, across every relation that carries one.
 *
 * One list, so `asset X` and each `<relation> for X` form resolve X's identity
 * from the same evidence and therefore at the same tier. Computing it per-form
 * from only that form's own array would let `owner of X` and `asset X` disagree
 * about which asset X is — the disagreement class D18 was.
 */
function assetRelationRefs(model: ThreatModel): string[] {
  return [
    ...model.exposures.map(e => e.asset),
    ...model.mitigations.map(m => m.asset),
    ...model.flows.map(f => f.target),
    ...model.flows.map(f => f.source),
    ...(model.confirmed || []).map(c => c.asset),
    ...model.acceptances.map(a => a.asset),
    ...model.audits.map(a => a.asset),
    ...model.boundaries.flatMap(b => [b.asset_a, b.asset_b]),
    ...model.ownership.map(o => o.asset),
    ...model.data_handling.map(d => d.asset),
    ...model.assumptions.map(a => a.asset),
    ...model.validations.map(v => v.asset),
    ...model.transfers.flatMap(t => [t.source, t.target]),
  ];
}

/** `file`/`line`, plus the `.gal` origin when the annotation was written externally. */
function loc(l: SourceLocation) {
  return {
    file: l.file,
    line: l.line,
    ...(l.origin_file ? { origin_file: l.origin_file, origin_line: l.origin_line } : {}),
  };
}

/**
 * Project one asset-scoped relation array, resolving the ref exactly as
 * `asset X` does.
 *
 * Every GL-203 form that takes an asset goes through here, so they all inherit
 * one tier resolution, one identity join and one ambiguity report. A form that
 * resolved refs its own way would be a D18 waiting to happen.
 */
function lookupAssetRelation<R>(
  model: ThreatModel,
  query: string,
  type: string,
  ref: string,
  resolve: Resolver,
  rows: R[],
  refOf: (row: R) => string,
  project: (row: R) => any,
): LookupResult {
  const aliases = resolve(ref);
  const declared = findBest(model.assets, assetIdentityOf, ref, aliases);
  const scope = resolveScope(declared, assetIdentityOf, assetRelationRefs(model), ref, aliases);
  const results = rows.filter(r => scope.keep(refOf(r))).map(project);
  return {
    query, type, count: results.length, results,
    ...provenance(scope.match),
    ...ambiguity(scope.tied, a => a.id || a.path.join('.')),
  };
}

const CLASSIFICATIONS: DataClassification[] = ['pii', 'phi', 'financial', 'secrets', 'internal', 'public'];

/** `@handles <classification>` — every asset processing data of that class. */
function lookupByClassification(model: ThreatModel, query: string, classification: string): LookupResult {
  const results = model.data_handling
    .filter(d => String(d.classification).toLowerCase() === classification)
    .map(d => ({ classification: d.classification, asset: d.asset, description: d.description, ...loc(d.location) }));
  return {
    query, type: 'data_handling', count: results.length, results,
    matched_via: 'exact', matched_against: classification,
  };
}

/**
 * `@comment` and `@shield` carry no asset reference — only a description and a
 * location. There is no declared relation to join on, so they are reached by
 * *where they are*: a file path, or the files in which a given asset is
 * annotated.
 *
 * The second join is an inference, not a recorded fact, so it says so:
 * `join: 'co-located'` means "these sit in the same files as annotations naming
 * that asset", not "these are about that asset". Presenting a proximity join as
 * a declared one is the confident-wrong-answer shape this surface exists to
 * avoid.
 */
function lookupCoLocated<R extends { location: SourceLocation; description?: string }>(
  model: ThreatModel,
  query: string,
  type: string,
  rows: R[],
  scope: string | undefined,
  resolve: Resolver,
  extra: (row: R) => Record<string, unknown> = () => ({}),
): LookupResult {
  const project = (r: R, join?: string) => ({
    ...extra(r), description: r.description, ...loc(r.location), ...(join ? { join } : {}),
  });

  if (!scope) {
    return { query, type, count: rows.length, results: rows.map(r => project(r)) };
  }

  // A path-shaped scope selects by file.
  if (scope.includes('/') || /\.[a-z0-9]+$/i.test(scope)) {
    const want = scope.replace(/^\.\//, '').replaceAll('\\', '/').toLowerCase();
    const hit = (f: string) => f.toLowerCase() === want || f.toLowerCase().endsWith('/' + want);
    const results = rows.filter(r => hit(r.location.file)).map(r => project(r));
    return {
      query, type, count: results.length, results,
      matched_via: results.length ? 'exact' : undefined, matched_against: scope,
    };
  }

  // Otherwise treat it as an asset ref and return what shares a file with it.
  const aliases = resolve(scope);
  const declared = findBest(model.assets, assetIdentityOf, scope, aliases);
  const assetScope = resolveScope(declared, assetIdentityOf, assetRelationRefs(model), scope, aliases);

  const files = new Set<string>();
  const addIf = (ref: string, l: SourceLocation) => { if (assetScope.keep(ref)) files.add(l.file); };
  for (const e of model.exposures) addIf(e.asset, e.location);
  for (const m of model.mitigations) addIf(m.asset, m.location);
  for (const a of model.audits) addIf(a.asset, a.location);
  for (const o of model.ownership) addIf(o.asset, o.location);
  for (const d of model.data_handling) addIf(d.asset, d.location);
  for (const a of model.assumptions) addIf(a.asset, a.location);
  for (const v of model.validations) addIf(v.asset, v.location);
  for (const f of model.flows) { addIf(f.source, f.location); addIf(f.target, f.location); }
  for (const b of model.boundaries) { addIf(b.asset_a, b.location); addIf(b.asset_b, b.location); }
  for (const a of model.assets) {
    if (assetScope.keep(a.id ? `#${a.id}` : a.path.join('.'))) files.add(a.location.file);
  }

  const results = rows.filter(r => files.has(r.location.file)).map(r => project(r, 'co-located'));
  return {
    query, type, count: results.length, results,
    ...provenance(assetScope.match),
    ...ambiguity(assetScope.tied, a => a.id || a.path.join('.')),
  };
}

// ─── GL-204: external identifiers (the CXG bridge) ───────────────────
//
// D20: two unrelated things are called "external refs".
//
//   model.external_refs   cross-repo sibling tags, built by detectExternalRefs
//                         from workspace.yaml. Queried by `cross-repo refs`.
//   threat.external_refs  cwe:/owasp: identifiers declared on threats,
//                         exposures and confirmed findings. Queried here.
//
// They share a name and nothing else. A caller who picks the wrong one gets a
// confidently empty answer — the D12 shape — so the two query forms are named
// so that neither can be reached by accident, and each says what the other is.

/** A parsed external identifier. `scheme` is null when the query omitted it. */
export interface ParsedExternalId {
  scheme: string | null;
  id: string;
  normalized: string;
}

/** Identifier schemes recognised without a prefix, so bare `CWE-89` resolves. */
const BARE_ID = /^(?:cwe|cve|capec)-[0-9]+(?:-[0-9]+)?$/i;

/**
 * Parse `cwe:CWE-89`, `CWE-89` or `owasp:A03` into a comparable form.
 *
 * OWASP category codes are deliberately NOT recognised bare: `A03` is three
 * characters of alphanumeric that could as easily be an asset id, and silently
 * reinterpreting it as an OWASP category would be a guess. `owasp:A03` works.
 */
export function parseExternalId(raw: string): ParsedExternalId | null {
  const text = raw.trim();
  const withScheme = text.match(/^([a-z][a-z0-9_-]*)\s*:\s*(\S+)$/i);
  if (withScheme) {
    const scheme = withScheme[1].toLowerCase();
    if (!['cwe', 'owasp', 'cve', 'capec', 'nist', 'asvs'].includes(scheme)) return null;
    return { scheme, id: withScheme[2], normalized: withScheme[2].toLowerCase() };
  }
  if (BARE_ID.test(text)) return { scheme: null, id: text, normalized: text.toLowerCase() };
  return null;
}

/** Does a declared `cwe:CWE-89` satisfy the query? Scheme is ignored when unstated. */
function externalIdMatches(declared: string, want: ParsedExternalId): boolean {
  const parsed = parseExternalId(declared) ?? { scheme: null, id: declared, normalized: declared.toLowerCase() };
  if (parsed.normalized !== want.normalized) return false;
  return want.scheme === null || parsed.scheme === null || parsed.scheme === want.scheme;
}

export interface ExternalIdSummary {
  scheme: string | null;
  id: string;
  normalized: string;
  /**
   * Whether ANY annotation in this model declares the identifier.
   *
   * The single most important field for a scanner integration. `false` means
   * GuardLink has no declared knowledge of this weakness class at all; it does
   * NOT mean "we know about it and nothing is exposed". Those two answers demand
   * opposite responses from a caller, and collapsing them into an empty result
   * is exactly the confidently-empty failure D12 was.
   */
  declared: boolean;
  threats: { id?: string; name: string; severity?: string; external_refs: string[] }[];
  totals: { confirmed: number; accepted: number; mitigated: number; open: number };
}

/**
 * Where a weakness class appears, and what has been done about it.
 *
 * Sites come from `@exposes` and `@confirmed` — the places a weakness is
 * declared to exist. Mitigations and acceptances are status, not sites.
 *
 * `status` applies a fixed precedence: confirmed > accepted > mitigated > open.
 * Confirmed wins because verified exploitability is the strongest evidence
 * present and a caller must not have it hidden by a control that may be
 * incomplete. The individual booleans are returned alongside so a consumer that
 * disagrees can apply its own ordering rather than being stuck with ours.
 */
function lookupExternalId(model: ThreatModel, query: string, want: ParsedExternalId): LookupResult {
  const threats = model.threats.filter(t => (t.external_refs || []).some(r => externalIdMatches(r, want)));
  const threatKeys = new Set<string>();
  for (const t of threats) {
    if (t.id) threatKeys.add(bareRef(t.id));
    threatKeys.add(bareRef(t.canonical_name));
  }

  const namesThisId = (ownRefs: string[] | undefined, threatRef: string) =>
    (ownRefs || []).some(r => externalIdMatches(r, want)) || threatKeys.has(bareRef(threatRef));

  const mitigated = new Set<string>();
  for (const m of model.mitigations) mitigated.add(`${bareRef(m.asset)}::${bareRef(m.threat)}`);
  const accepted = new Set<string>();
  for (const a of model.acceptances) accepted.add(`${bareRef(a.asset)}::${bareRef(a.threat)}`);
  const confirmedPairs = new Set<string>();
  for (const c of model.confirmed || []) confirmedPairs.add(`${bareRef(c.asset)}::${bareRef(c.threat)}`);

  const seen = new Set<string>();
  const results: any[] = [];
  const totals = { confirmed: 0, accepted: 0, mitigated: 0, open: 0 };

  const addSite = (asset: string, threat: string, severity: string | undefined,
                   description: string | undefined, location: SourceLocation, origin: 'exposes' | 'confirmed') => {
    const dedupe = `${bareRef(asset)}::${bareRef(threat)}::${location.file}:${location.line}`;
    if (seen.has(dedupe)) return;
    seen.add(dedupe);

    const pair = `${bareRef(asset)}::${bareRef(threat)}`;
    const isConfirmed = origin === 'confirmed' || confirmedPairs.has(pair);
    const isAccepted = accepted.has(pair);
    const isMitigated = mitigated.has(pair);
    const status = isConfirmed ? 'confirmed' : isAccepted ? 'accepted' : isMitigated ? 'mitigated' : 'open';
    totals[status]++;

    results.push({
      status, asset, threat, severity, description,
      confirmed: isConfirmed, accepted: isAccepted, mitigated: isMitigated,
      controls: model.mitigations
        .filter(m => bareRef(m.asset) === bareRef(asset) && bareRef(m.threat) === bareRef(threat) && m.control)
        .map(m => m.control),
      ...loc(location),
    });
  };

  for (const e of model.exposures) {
    if (namesThisId(e.external_refs, e.threat)) {
      addSite(e.asset, e.threat, e.severity, e.description, e.location, 'exposes');
    }
  }
  for (const c of model.confirmed || []) {
    if (namesThisId(c.external_refs, c.threat)) {
      addSite(c.asset, c.threat, c.severity, c.description, c.location, 'confirmed');
    }
  }

  const declaredAnywhere = threats.length > 0 || results.length > 0;
  const summary: ExternalIdSummary = {
    scheme: want.scheme, id: want.id, normalized: want.normalized,
    declared: declaredAnywhere,
    threats: threats.map(t => ({
      id: t.id, name: t.canonical_name, severity: t.severity, external_refs: t.external_refs || [],
    })),
    totals,
  };

  return {
    query, type: 'external_id', count: results.length, results,
    external_id: summary,
    ...(declaredAnywhere ? {} : {
      hint: `No threat, exposure or confirmed finding in this model declares \`${want.id}\`. GuardLink has no declared knowledge of it. This is NOT the same as a declared threat with nothing exposed — check external_id.declared before reading count: 0 as coverage.`,
    } as any),
  };
}

const bareRef = (s: string) => (s ?? '').replace(/^#/, '').toLowerCase();

/** Cross-repo tag references detected during parsing. */
function lookupExternalRefs(model: ThreatModel, query: string, scope?: string): LookupResult {
  const rows = model.external_refs || [];
  const filtered = scope
    ? rows.filter(r => r.tag.toLowerCase().includes(scope.toLowerCase())
        || (r.inferred_repo || '').toLowerCase() === scope.toLowerCase())
    : rows;
  const results = filtered.map(r => ({
    tag: r.tag, context_verb: r.context_verb, inferred_repo: r.inferred_repo ?? null, ...loc(r.location),
  }));
  return {
    query, type: 'external_refs', count: results.length, results,
    ...(results.length === 0 && rows.length === 0
      ? { hint: 'No cross-repo tag references. These are only detected when .guardlink/workspace.yaml declares sibling repos.' } as any
      : {}),
  };
}

function lookupAsset(model: ThreatModel, query: string, ref: string, resolve: Resolver): LookupResult {
  const aliases = resolve(ref);
  const declared = findBest(model.assets, assetIdentityOf, ref, aliases);

  // Resolve the asset's identity at the strongest tier available anywhere in
  // scope — the declaration if there is one, plus every annotation that names an
  // asset — then admit only relationships matching at that same tier.
  //
  // Without this, `lookup("asset cli")` reported 14 exposures for #cli: only 5
  // are declared on it, and all 9 of #llm-client's were merged in unmarked
  // because "llm-client".includes("cli"). Inbound and outbound flows were
  // contaminated the same way.
  const relationRefs = assetRelationRefs(model);
  // A declaration that only matched more weakly than the annotation graph is not
  // this ref's asset — `declaredItem` is undefined there and we fall through to
  // the referenced-but-undeclared branch.
  const scope = resolveScope(declared, assetIdentityOf, relationRefs, ref, aliases);
  const { keep, match: scopeMatch } = scope;
  const asset = scope.declaredItem;
  const ambiguous = ambiguity(scope.tied, a => a.id || a.path.join('.'));

  const exposures = model.exposures.filter(e => keep(e.asset));
  const mitigations = model.mitigations.filter(m => keep(m.asset));
  const inFlows = model.flows.filter(f => keep(f.target));
  const outFlows = model.flows.filter(f => keep(f.source));
  const confirmed = (model.confirmed || []).filter(c => keep(c.asset));
  const acceptances = model.acceptances.filter(a => keep(a.asset));
  const audits = model.audits.filter(a => keep(a.asset));
  const boundaries = model.boundaries.filter(b => keep(b.asset_a) || keep(b.asset_b));

  // Asset is declared in definitions.ts — return the full record.
  if (asset) {
    return {
      query, type: 'asset', count: 1,
      ...provenance(scopeMatch),
      ...ambiguous,
      results: [{
        ...asset,
        declared: true,
        relationships: {
          exposures: exposures.map(e => ({ threat: e.threat, severity: e.severity })),
          mitigations: mitigations.map(m => ({ threat: m.threat, control: m.control })),
          confirmed: confirmed.map(c => ({ threat: c.threat, severity: c.severity })),
          inbound_flows: inFlows.map(f => ({ from: f.source, mechanism: f.mechanism })),
          outbound_flows: outFlows.map(f => ({ to: f.target, mechanism: f.mechanism })),
        },
      }],
    };
  }

  // Asset is undeclared but referenced by one or more annotations — synthesize
  // a stub record so the query agrees with `threats for #id`, `unmitigated`,
  // `confirmed`, etc., which all join through the referencing annotations.
  const referencedIn: string[] = [];
  if (exposures.length)   referencedIn.push('exposures');
  if (mitigations.length) referencedIn.push('mitigations');
  if (confirmed.length)   referencedIn.push('confirmed');
  if (acceptances.length) referencedIn.push('acceptances');
  if (audits.length)      referencedIn.push('audits');
  if (inFlows.length || outFlows.length) referencedIn.push('flows');
  if (boundaries.length)  referencedIn.push('boundaries');

  if (referencedIn.length === 0) {
    return { query, type: 'asset', count: 0, results: [] };
  }

  const id = ref.replace(/^#/, '');
  return {
    query, type: 'asset', count: 1,
    ...provenance(scopeMatch),
    ...ambiguous,
    results: [{
      id,
      path: [id],
      declared: false,
      referenced_in: referencedIn,
      relationships: {
        exposures: exposures.map(e => ({ threat: e.threat, severity: e.severity })),
        mitigations: mitigations.map(m => ({ threat: m.threat, control: m.control })),
        confirmed: confirmed.map(c => ({ threat: c.threat, severity: c.severity })),
        inbound_flows: inFlows.map(f => ({ from: f.source, mechanism: f.mechanism })),
        outbound_flows: outFlows.map(f => ({ to: f.target, mechanism: f.mechanism })),
      },
    }],
  };
}

function lookupThreat(model: ThreatModel, query: string, ref: string, resolve: Resolver): LookupResult {
  const aliases = resolve(ref);
  const threatIdentity = (t: ThreatModelThreat) => [t.id || '', t.canonical_name];
  const declared = findBest(model.threats, threatIdentity, ref, aliases);

  const relationRefs = [
    ...model.exposures.map(e => e.threat),
    ...model.mitigations.map(m => m.threat),
    ...(model.confirmed || []).map(c => c.threat),
    ...model.acceptances.map(a => a.threat),
    ...model.transfers.map(t => t.threat),
  ];
  // Only relationships naming this threat at the same tier the threat itself
  // resolved at. `threat dos` resolves #dos exactly, so #redos exposures — a
  // substring hit — are no longer folded into its affected_assets. And because
  // the tier is composed rather than re-derived, `threat denial` still resolves
  // #dos at substring tier instead of collapsing to nothing.
  const scope = resolveScope(declared, threatIdentity, relationRefs, ref, aliases);
  const { keep, match: scopeMatch } = scope;
  const ambiguous = ambiguity(scope.tied, t => t.id || t.canonical_name);

  const exposures = model.exposures.filter(e => keep(e.threat));
  const mitigations = model.mitigations.filter(m => keep(m.threat));
  const confirmed = (model.confirmed || []).filter(c => keep(c.threat));
  const acceptances = model.acceptances.filter(a => keep(a.threat));
  const transfers = model.transfers.filter(t => keep(t.threat));

  const affected = exposures.map(e => ({
    asset: e.asset, severity: e.severity,
    mitigated: mitigations.some(m => m.asset === e.asset),
  }));

  // Declared in definitions — full record.
  if (scope.declaredItem) {
    return {
      query, type: 'threat', count: 1,
      ...provenance(scopeMatch),
      ...ambiguous,
      results: [{ ...scope.declaredItem, declared: true, affected_assets: affected }],
    };
  }

  // Referenced by annotations but never declared. `lookupAsset` has always drawn
  // this distinction; threats and controls returned a bare `count: 0`, which made
  // "no such threat" and "declared but unused" indistinguishable — and disagreed
  // with `unmitigated`, which happily reports exposures naming an undeclared threat.
  const referencedIn: string[] = [];
  if (exposures.length)   referencedIn.push('exposures');
  if (mitigations.length) referencedIn.push('mitigations');
  if (confirmed.length)   referencedIn.push('confirmed');
  if (acceptances.length) referencedIn.push('acceptances');
  if (transfers.length)   referencedIn.push('transfers');

  if (referencedIn.length === 0) return { query, type: 'threat', count: 0, results: [] };

  return {
    query, type: 'threat', count: 1,
    ...provenance(scopeMatch),
    ...ambiguous,
    results: [{
      id: ref.replace(/^#/, ''),
      canonical_name: ref.replace(/^#/, ''),
      declared: false,
      referenced_in: referencedIn,
      affected_assets: affected,
    }],
  };
}

function lookupControl(model: ThreatModel, query: string, ref: string, resolve: Resolver): LookupResult {
  const aliases = resolve(ref);
  const controlIdentity = (c: ThreatModelControl) => [c.id || '', c.canonical_name];
  const declared = findBest(model.controls, controlIdentity, ref, aliases);

  const relationRefs = [
    ...model.mitigations.map(m => m.control || ''),
    ...model.validations.map(v => v.control),
  ];
  const scope = resolveScope(declared, controlIdentity, relationRefs, ref, aliases);
  const { keep, match: scopeMatch } = scope;
  const ambiguous = ambiguity(scope.tied, c => c.id || c.canonical_name);

  const mitigations = model.mitigations.filter(m => keep(m.control || ''));
  const validations = model.validations.filter(v => keep(v.control));
  const protects = mitigations.map(m => ({ asset: m.asset, threat: m.threat }));

  if (scope.declaredItem) {
    return {
      query, type: 'control', count: 1,
      ...provenance(scopeMatch),
      ...ambiguous,
      results: [{ ...scope.declaredItem, declared: true, protects }],
    };
  }

  const referencedIn: string[] = [];
  if (mitigations.length) referencedIn.push('mitigations');
  if (validations.length) referencedIn.push('validations');

  if (referencedIn.length === 0) return { query, type: 'control', count: 0, results: [] };

  return {
    query, type: 'control', count: 1,
    ...provenance(scopeMatch),
    ...ambiguous,
    results: [{
      id: ref.replace(/^#/, ''),
      canonical_name: ref.replace(/^#/, ''),
      declared: false,
      referenced_in: referencedIn,
      protects,
    }],
  };
}

function lookupExposuresFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const { keep, match, matched } = selectStrongest(model.exposures.map(e => e.asset), assetRef, aliases);
  const results = model.exposures
    .filter(e => keep(e.asset))
    .map(e => ({
      asset: e.asset, threat: e.threat, severity: e.severity,
      description: e.description, file: e.location.file, line: e.location.line,
    }));
  return { query, type: 'exposures_for_asset', count: results.length, results, ...provenance(match), ...ambiguity(matched, v => v) };
}

function lookupMitigationsFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const { keep, match, matched } = selectStrongest(model.mitigations.map(m => m.asset), assetRef, aliases);
  const results = model.mitigations
    .filter(m => keep(m.asset))
    .map(m => ({
      asset: m.asset, threat: m.threat, control: m.control,
      description: m.description, file: m.location.file, line: m.location.line,
    }));
  return { query, type: 'mitigations_for_asset', count: results.length, results, ...provenance(match), ...ambiguity(matched, v => v) };
}

function lookupFuzzy(model: ThreatModel, query: string, q: string): LookupResult {
  const ref = q.replace(/^#/, '');
  const results: any[] = [];

  // Prefer the strongest tier present across every declared identifier, so a bare
  // `dos` resolves #dos alone rather than returning it alongside #redos.
  const declaredRefs = [
    ...model.assets.flatMap(a => [a.id || '', a.path.join('.')]),
    ...model.threats.flatMap(t => [t.id || '', t.canonical_name]),
    ...model.controls.flatMap(c => [c.id || '', c.canonical_name]),
  ];
  const keepDeclared = keepStrongest(declaredRefs, ref, []);

  // Try declared assets
  for (const a of model.assets) {
    if (keepDeclared(a.id || '') || keepDeclared(a.path.join('.'))) {
      results.push({ type: 'asset', id: a.id, path: a.path.join('.'), description: a.description, declared: true });
    }
  }
  // Try declared threats
  for (const t of model.threats) {
    if (keepDeclared(t.id || '') || keepDeclared(t.canonical_name)) {
      results.push({ type: 'threat', id: t.id, name: t.canonical_name, severity: t.severity, declared: true });
    }
  }
  // Try declared controls
  for (const c of model.controls) {
    if (keepDeclared(c.id || '') || keepDeclared(c.canonical_name)) {
      results.push({ type: 'control', id: c.id, name: c.canonical_name, declared: true });
    }
  }

  // Fall back to referenced-but-undeclared identifiers across the annotation
  // graph. Without this, `unmitigated` returns #login-sqli but bare #login-sqli
  // says no_match — two queries disagreeing about the same identifier.
  if (results.length === 0) {
    const referencedRefs = [
      ...model.exposures.flatMap(e => [e.asset, e.threat]),
      ...(model.confirmed || []).flatMap(c => [c.asset, c.threat]),
      ...model.mitigations.flatMap(m => [m.asset, m.threat, m.control || '']),
      ...model.acceptances.flatMap(a => [a.asset, a.threat]),
      ...model.flows.flatMap(f => [f.source, f.target]),
      ...model.boundaries.flatMap(b => [b.asset_a, b.asset_b]),
    ];
    const keepReferenced = keepStrongest(referencedRefs, ref, []);

    const seen = new Set<string>();
    const addRef = (kind: string, id: string, source: string, extra: Record<string, unknown> = {}) => {
      const key = `${kind}::${id}`;
      if (seen.has(key)) return;
      seen.add(key);
      results.push({ type: kind, id, path: id, declared: false, referenced_in: [source], ...extra });
    };
    const matchAndAdd = (kind: string, value: string, source: string, extra: Record<string, unknown> = {}) => {
      if (!value) return;
      const v = value.replace(/^#/, '');
      if (keepReferenced(value)) addRef(kind, v, source, extra);
    };

    for (const e of model.exposures) {
      matchAndAdd('asset',  e.asset,  'exposures', { severity: e.severity });
      matchAndAdd('threat', e.threat, 'exposures', { severity: e.severity });
    }
    for (const c of (model.confirmed || [])) {
      matchAndAdd('asset',  c.asset,  'confirmed', { severity: c.severity });
      matchAndAdd('threat', c.threat, 'confirmed', { severity: c.severity });
    }
    for (const m of model.mitigations) {
      matchAndAdd('asset',   m.asset,        'mitigations');
      matchAndAdd('threat',  m.threat,       'mitigations');
      matchAndAdd('control', m.control || '', 'mitigations');
    }
    for (const a of model.acceptances) {
      matchAndAdd('asset',  a.asset,  'acceptances');
      matchAndAdd('threat', a.threat, 'acceptances');
    }
    for (const f of model.flows) {
      matchAndAdd('asset', f.source, 'flows');
      matchAndAdd('asset', f.target, 'flows');
    }
    for (const b of model.boundaries) {
      matchAndAdd('asset', b.asset_a, 'boundaries');
      matchAndAdd('asset', b.asset_b, 'boundaries');
    }
  }

  if (results.length === 0) {
    // Hint travels through two JSON.stringify passes (MCP content wrap +
    // JSON-RPC envelope). Embedded double quotes get escaped to \\\" and
    // render as literal backslashes in clients that print the raw text —
    // use backticks around examples instead.
    return { query, type: 'no_match', count: 0, results: [{
      hint: `No match for ${query}. Try: \`asset <name>\`, \`threats for <asset>\`, \`unmitigated\`, \`flows into <asset>\``,
    }] };
  }

  return { query, type: 'mixed', count: results.length, results };
}

// ─── Ref matching ────────────────────────────────────────────────────

/**
 * How a value matched a reference, strongest first.
 *
 *   exact     — the value is the ref (or its last dotted segment is)
 *   alias     — the value is a resolved alias of the ref (id ↔ path)
 *   substring — one contains the other, at >= 3 characters
 */
export type MatchKind = 'exact' | 'alias' | 'substring';

const TIER: Record<MatchKind, number> = { exact: 0, alias: 1, substring: 2 };

export interface RefMatch {
  kind: MatchKind;
  /** The candidate string the value actually matched against. */
  matched_against: string;
}

const bare = (s: string) => s.toLowerCase().replace(/^#/, '');

/**
 * Classify how `value` matches `ref`, or null when it does not match at all.
 *
 * The predicate is identical to the historical `matchRef` — nothing that matched
 * before stops matching. What this adds is the *tier*, so callers can prefer an
 * exact hit over a substring one instead of taking whichever came first in
 * declaration order.
 *
 * Without tiers, `lookup("threat dos")` returned #redos: `"redos".includes("dos")`
 * is true and #redos is declared before #dos, so `.find()` short-circuited before
 * ever testing the exactly-declared #dos.
 */
function classifyRef(value: string, ref: string, aliases?: string[]): RefMatch | null {
  if (!value || !ref) return null;
  const v = bare(value);
  const r = bare(ref);
  const extras = aliases ? aliases.map(bare).filter(a => a !== r) : [];
  const all = [r, ...extras];
  const lastSeg = v.split('.').pop() || '';

  // 1. Exact on the ref as typed.
  if (v === r || lastSeg === r) return { kind: 'exact', matched_against: r };

  // 2. Exact on a resolved alias (id ↔ dotted path).
  for (const candidate of extras) {
    if (v === candidate || lastSeg === candidate) return { kind: 'alias', matched_against: candidate };
  }

  // 3. Substring, either direction, at >= 3 characters.
  for (const candidate of all) {
    if (candidate.length >= 3 && v.includes(candidate)) return { kind: 'substring', matched_against: candidate };
    if (v.length >= 3 && candidate.includes(v)) return { kind: 'substring', matched_against: candidate };
  }

  return null;
}

/** Fuzzy match: #id refs, dotted paths, partial case-insensitive match */
function matchRef(value: string, ref: string, aliases?: string[]): boolean {
  return classifyRef(value, ref, aliases) !== null;
}

const tierOf = (m: RefMatch | null): number => (m === null ? Infinity : TIER[m.kind]);

/**
 * Strongest match any of `values` makes against `ref`, or null if none match.
 * Used to discard weaker matches once a stronger one exists anywhere in scope,
 * and to report how the query resolved.
 */
function strongestMatch(values: Iterable<string>, ref: string, aliases?: string[]): RefMatch | null {
  let best: RefMatch | null = null;
  for (const v of values) {
    const m = classifyRef(v, ref, aliases);
    if (m && tierOf(m) < tierOf(best)) best = m;
    if (best && TIER[best.kind] === 0) break;
  }
  return best;
}

/**
 * The stronger of two matches; ties keep the first.
 *
 * Composing matches by comparing tiers is the *only* safe way to combine them.
 * Re-deriving a tier by classifying a match's `matched_against` is not: that
 * field is the **ref** side of the comparison, not the value side, so
 * `classifyRef(m.matched_against, ref)` compares the ref against itself and
 * always returns `exact`. A substring match fed back that way silently promotes
 * itself to exact — which is precisely how D18 dropped every threat and control
 * that was only reachable by substring.
 */
function strongerOf(a: RefMatch | null, b: RefMatch | null): RefMatch | null {
  if (!a) return b;
  if (!b) return a;
  return TIER[b.kind] < TIER[a.kind] ? b : a;
}

/** The `matched_via` / `matched_against` pair for a resolved match, or nothing. */
function provenance(match: RefMatch | null): Pick<LookupResult, 'matched_via' | 'matched_against'> {
  return match ? { matched_via: match.kind, matched_against: match.matched_against } : {};
}

interface ScopeResolution<T> {
  /** How the *query* resolved — the declaration or the annotation graph, whichever was stronger. */
  match: RefMatch | null;
  /** Admits only relation values belonging to the resolved identity. */
  keep: (value: string) => boolean;
  /** Distinct relation refs admitted. More than one means the join was ambiguous. */
  matched: string[];
  /** The declared record, when it matched at the scope tier — otherwise undefined. */
  declaredItem: T | undefined;
  /** Every declared record tied at the winning tier. More than one means the ref is ambiguous. */
  tied: T[];
}

/**
 * Resolve what a ref identifies, and at what strength.
 *
 * Assets, threats and controls all answer the same three questions — which
 * declared record is this, how strongly did it match, and which annotations
 * belong to it — so they share one implementation. They previously had three,
 * and D18 was the two that drifted: `lookupAsset` composed tiers correctly while
 * `lookupThreat` and `lookupControl` round-tripped through `matched_against`.
 * One code path means that divergence cannot recur.
 */
function resolveScope<T>(
  declared: { item: T; match: RefMatch; candidates: T[] } | null,
  identityOf: (item: T) => string[],
  relationRefs: string[],
  ref: string,
  aliases: string[],
): ScopeResolution<T> {
  // Step 1 — identity. How strongly did the *query* pin something down? A
  // declaration that matched more weakly than the annotation graph is not this
  // ref's record: `asset #login` prefers the exactly-referenced undeclared
  // #login over a declared asset that merely contains "login".
  const match = strongerOf(declared?.match ?? null, strongestMatch(relationRefs, ref, aliases));
  const tier = match ? TIER[match.kind] : null;
  const declaredAtScope = !!declared && TIER[declared.match.kind] === tier;

  // Step 2 — join. Once a record is resolved, its relations are found through
  // *its own* identifiers, not through the query string. Annotations write
  // `@exposes ... to #dos`, but the query may have arrived as `denial`, which
  // matches the canonical_name and nothing else. Joining on the query left the
  // record correct and its relations empty — a quieter failure than D18, and
  // one that predates this work.
  const identity = declaredAtScope ? identityOf(declared!.item).filter(Boolean) : [];
  const join = identity.length
    ? selectStrongest(relationRefs, identity[0], identity)
    : selectStrongest(relationRefs, ref, aliases);

  return {
    match,
    keep: join.keep,
    matched: join.matched,
    declaredItem: declaredAtScope ? declared!.item : undefined,
    tied: declaredAtScope ? declared!.candidates : [],
  };
}

/**
 * Name an ambiguous resolution rather than letting declaration order decide.
 *
 * When several records tie at the winning tier, `findBest` returns the first.
 * That is deterministic but arbitrary — `asset client` matches both #cli and
 * #llm-client by substring, and picking one silently is the same class of
 * confident-wrong-answer this work exists to remove. Reporting the tie lets the
 * caller re-query precisely instead.
 */
function ambiguity<T>(tied: T[], idOf: (item: T) => string): Pick<LookupResult, 'ambiguous' | 'candidates'> {
  return tied.length > 1 ? { ambiguous: true, candidates: tied.map(idOf) } : {};
}

/** Predicate admitting only values that match at exactly `tier`. */
function atTier(ref: string, aliases: string[] | undefined, tier: number | null) {
  if (tier === null) return () => false;
  return (v: string) => tierOf(classifyRef(v, ref, aliases)) === tier;
}

/**
 * Pick the entry whose strongest matching ref beats every other entry's, and
 * report every entry tied with it at that tier.
 *
 * `item` resolves ties by declaration order, preserving previous behaviour
 * within a tier; `candidates` exposes the tie so the caller can say so rather
 * than pretending the first was the answer.
 */
function findBest<T>(
  items: T[],
  refsOf: (item: T) => string[],
  ref: string,
  aliases?: string[],
): { item: T; match: RefMatch; candidates: T[] } | null {
  const scored: { item: T; match: RefMatch }[] = [];

  for (const item of items) {
    let best: RefMatch | null = null;
    for (const candidate of refsOf(item)) {
      const m = classifyRef(candidate, ref, aliases);
      if (m && tierOf(m) < tierOf(best)) best = m;
    }
    if (best) scored.push({ item, match: best });
  }

  if (scored.length === 0) return null;

  const bestTier = Math.min(...scored.map(s => TIER[s.match.kind]));
  const tied = scored.filter(s => TIER[s.match.kind] === bestTier);
  return { item: tied[0].item, match: tied[0].match, candidates: tied.map(t => t.item) };
}
