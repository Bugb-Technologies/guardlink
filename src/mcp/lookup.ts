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
} from '../types/index.js';

export interface LookupResult {
  query: string;
  type: string;
  count: number;
  results: any[];
}

export interface LookupQuery {
  raw: string;
}

export function lookup(model: ThreatModel, query: string): LookupResult {
  const q = query.trim().toLowerCase();

  // Build ID ↔ path resolution maps
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

  // Create a resolver that expands a ref to all known aliases
  const resolve = (ref: string): string[] => {
    const r = ref.toLowerCase().replace(/^#/, '');
    const aliases = [r];
    if (idToPath.has(r)) aliases.push(idToPath.get(r)!);
    if (pathToId.has(r)) aliases.push(pathToId.get(r)!);
    return aliases;
  };

  // ── "unmitigated" ──
  if (/^unmitigated/.test(q)) {
    return lookupUnmitigated(model, query);
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

type Resolver = (ref: string) => string[];

function lookupThreatsFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const exposures = model.exposures.filter(e => matchRef(e.asset, assetRef, aliases));
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
  return { query, type: 'threats_for_asset', count: results.length, results };
}

function lookupControlsFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const mits = model.mitigations.filter(m => matchRef(m.asset, assetRef, aliases));
  const results = mits.map(m => {
    const control = model.controls.find(c => c.id === m.control || c.canonical_name === m.control);
    return {
      control: m.control, threat: m.threat,
      description: m.description || control?.description,
      file: m.location.file, line: m.location.line,
    };
  });
  return { query, type: 'controls_for_asset', count: results.length, results };
}

function lookupFlows(model: ThreatModel, query: string, direction: 'into' | 'from', assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const results = model.flows
    .filter(f => direction === 'into' ? matchRef(f.target, assetRef, aliases) : matchRef(f.source, assetRef, aliases))
    .map(f => ({
      source: f.source, target: f.target, mechanism: f.mechanism,
      description: f.description, file: f.location.file, line: f.location.line,
    }));
  return { query, type: `flows_${direction}`, count: results.length, results };
}

function lookupBoundaries(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const results = model.boundaries
    .filter(b => matchRef(b.asset_a, assetRef, aliases) || matchRef(b.asset_b, assetRef, aliases))
    .map(b => ({
      asset_a: b.asset_a, asset_b: b.asset_b, description: b.description,
      file: b.location.file, line: b.location.line,
    }));
  return { query, type: 'boundaries', count: results.length, results };
}

function lookupAsset(model: ThreatModel, query: string, ref: string, resolve: Resolver): LookupResult {
  const aliases = resolve(ref);
  const asset = model.assets.find(a => matchRef(a.id || '', ref, aliases) || matchRef(a.path.join('.'), ref, aliases));
  if (!asset) return { query, type: 'asset', count: 0, results: [] };

  const exposures = model.exposures.filter(e => matchRef(e.asset, ref, aliases));
  const mitigations = model.mitigations.filter(m => matchRef(m.asset, ref, aliases));
  const inFlows = model.flows.filter(f => matchRef(f.target, ref, aliases));
  const outFlows = model.flows.filter(f => matchRef(f.source, ref, aliases));

  return {
    query, type: 'asset', count: 1,
    results: [{
      ...asset,
      relationships: {
        exposures: exposures.map(e => ({ threat: e.threat, severity: e.severity })),
        mitigations: mitigations.map(m => ({ threat: m.threat, control: m.control })),
        inbound_flows: inFlows.map(f => ({ from: f.source, mechanism: f.mechanism })),
        outbound_flows: outFlows.map(f => ({ to: f.target, mechanism: f.mechanism })),
      },
    }],
  };
}

function lookupThreat(model: ThreatModel, query: string, ref: string, resolve: Resolver): LookupResult {
  const aliases = resolve(ref);
  const threat = model.threats.find(t => matchRef(t.id || '', ref, aliases) || matchRef(t.canonical_name, ref, aliases));
  if (!threat) return { query, type: 'threat', count: 0, results: [] };

  const exposures = model.exposures.filter(e => matchRef(e.threat, ref, aliases));
  const mitigations = model.mitigations.filter(m => matchRef(m.threat, ref, aliases));

  return {
    query, type: 'threat', count: 1,
    results: [{
      ...threat,
      affected_assets: exposures.map(e => ({ asset: e.asset, severity: e.severity, mitigated: mitigations.some(m => m.asset === e.asset) })),
    }],
  };
}

function lookupControl(model: ThreatModel, query: string, ref: string, resolve: Resolver): LookupResult {
  const aliases = resolve(ref);
  const control = model.controls.find(c => matchRef(c.id || '', ref, aliases) || matchRef(c.canonical_name, ref, aliases));
  if (!control) return { query, type: 'control', count: 0, results: [] };

  const mitigations = model.mitigations.filter(m => matchRef(m.control || '', ref, aliases));

  return {
    query, type: 'control', count: 1,
    results: [{
      ...control,
      protects: mitigations.map(m => ({ asset: m.asset, threat: m.threat })),
    }],
  };
}

function lookupExposuresFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const results = model.exposures
    .filter(e => matchRef(e.asset, assetRef, aliases))
    .map(e => ({
      asset: e.asset, threat: e.threat, severity: e.severity,
      description: e.description, file: e.location.file, line: e.location.line,
    }));
  return { query, type: 'exposures_for_asset', count: results.length, results };
}

function lookupMitigationsFor(model: ThreatModel, query: string, assetRef: string, resolve: Resolver): LookupResult {
  const aliases = resolve(assetRef);
  const results = model.mitigations
    .filter(m => matchRef(m.asset, assetRef, aliases))
    .map(m => ({
      asset: m.asset, threat: m.threat, control: m.control,
      description: m.description, file: m.location.file, line: m.location.line,
    }));
  return { query, type: 'mitigations_for_asset', count: results.length, results };
}

function lookupFuzzy(model: ThreatModel, query: string, q: string): LookupResult {
  const ref = q.replace(/^#/, '');
  const results: any[] = [];

  // Try assets
  for (const a of model.assets) {
    if (matchRef(a.id || '', ref) || matchRef(a.path.join('.'), ref)) {
      results.push({ type: 'asset', id: a.id, path: a.path.join('.'), description: a.description });
    }
  }
  // Try threats
  for (const t of model.threats) {
    if (matchRef(t.id || '', ref) || matchRef(t.canonical_name, ref)) {
      results.push({ type: 'threat', id: t.id, name: t.canonical_name, severity: t.severity });
    }
  }
  // Try controls
  for (const c of model.controls) {
    if (matchRef(c.id || '', ref) || matchRef(c.canonical_name, ref)) {
      results.push({ type: 'control', id: c.id, name: c.canonical_name });
    }
  }

  if (results.length === 0) {
    return { query, type: 'no_match', count: 0, results: [{ hint: `No match for "${query}". Try: "asset <name>", "threats for <asset>", "unmitigated", "flows into <asset>"` }] };
  }

  return { query, type: 'mixed', count: results.length, results };
}

// ─── Ref matching ────────────────────────────────────────────────────

/** Fuzzy match: #id refs, dotted paths, partial case-insensitive match */
function matchRef(value: string, ref: string, aliases?: string[]): boolean {
  if (!value || !ref) return false;
  const v = value.toLowerCase().replace(/^#/, '');
  const r = ref.toLowerCase().replace(/^#/, '');

  // Check all aliases (resolved ID ↔ path)
  const refs = aliases ? [r, ...aliases.map(a => a.toLowerCase().replace(/^#/, ''))] : [r];

  for (const candidate of refs) {
    // Exact match
    if (v === candidate) return true;
    // Partial: ref matches last segment of dotted path
    const lastSeg = v.split('.').pop() || '';
    if (lastSeg === candidate) return true;
    // Substring match for short refs
    if (candidate.length >= 3 && v.includes(candidate)) return true;
    // Reverse: value is substring of candidate
    if (v.length >= 3 && candidate.includes(v)) return true;
  }

  return false;
}
