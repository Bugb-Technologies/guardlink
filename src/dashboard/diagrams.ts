/**
 * GuardLink Dashboard — diagram generators.
 *
 * Three Mermaid diagrams and one structured topology dataset.
 *   - generateThreatGraph      — LR flowchart of assets, threats, controls, mitigations
 *   - generateDataFlowDiagram  — LR flow graph with trust boundary groupings
 *   - generateAttackSurface    — TB grouping of exposures per asset, severity-coloured
 *   - generateTopologyData     — structured graph data powering the interactive D3 view
 *
 * All four generators share a single alias map so that #id, bare id, name, and
 * path.join() forms of an asset/threat/control collapse onto the same node.
 * This removes the long-standing duplicate-node bug that made the Mermaid
 * diagrams render the same asset twice whenever sources mixed ref forms.
 *
 * @flows ThreatModel -> #dashboard via generateThreatGraph -- "Threat model relationships rendered as Mermaid source"
 * @flows ThreatModel -> #dashboard via generateTopologyData -- "Threat model relationships rendered as structured D3 graph data"
 * @mitigates #dashboard against #xss using #output-encoding -- "Diagram labels are sanitized for Mermaid and emitted to D3 as text data"
 * @comment -- "Alias map collapses #id / name / path-joined ref forms so Mermaid and D3 views agree on identity"
 */

import type { ThreatModel } from '../types/index.js';

/* ══════════════════════════════════════════════════════════════════════════
 * Shared sanitizers and ranking utilities
 * ══════════════════════════════════════════════════════════════════════════ */

/** Sanitize IDs for Mermaid (no dots, spaces, hashes). */
function mid(s: string): string {
  return s.replace(/[^a-zA-Z0-9_]/g, '_');
}

/** Truncate long labels and sanitize for Mermaid (strip syntax-breaking characters). */
function label(s: string, max = 40): string {
  const clean = s.replace(/"/g, "'").replace(/[\[\]{}()|`;]/g, '');
  return clean.length > max ? clean.slice(0, max - 1) + '…' : clean;
}

/** Sanitize labels without truncation (for long edge text/mechanisms). */
function labelFull(s: string): string {
  return s.replace(/"/g, "'").replace(/[\[\]{}()|`;]/g, '');
}

/** Normalize a ref: strip leading # so that "#sqli" and "sqli" compare equal. */
function normalizeRef(ref: string): string {
  return ref.startsWith('#') ? ref.slice(1) : ref;
}

function refKey(ref: string): string {
  return normalizeRef(ref).trim().toLowerCase();
}

const severityRank: Record<string, number> = { critical: 0, p0: 0, high: 1, p1: 1, medium: 2, p2: 2, low: 3, p3: 3, unset: 4 };
const statusRank: Record<string, number> = { confirmed: 0, open: 1, accepted: 2, mitigated: 3, none: 4 };

function normalizeSeverity(severity?: string): string {
  const s = (severity || '').toLowerCase();
  return s && severityRank[s] !== undefined ? s : 'unset';
}

function strongerSeverity(a: string, b: string): string {
  return (severityRank[b] ?? 4) < (severityRank[a] ?? 4) ? b : a;
}

function strongerStatus(a: string, b: string): string {
  return (statusRank[b] ?? 4) < (statusRank[a] ?? 4) ? b : a;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Alias map — single source of truth for ref → canonical node resolution.
 * Every diagram generator routes asset/threat/control references through this
 * map so that `#api`, `api`, and `App.API` all collapse onto the same node.
 * ══════════════════════════════════════════════════════════════════════════ */

type NodeKind = 'asset' | 'threat' | 'control';

interface AliasNode {
  key: string;       // canonical node key (stable across ref forms)
  label: string;     // best display label
  id?: string;       // raw id if defined
  kind: NodeKind;
  severity: string;
  externalRefs: string[];
}

interface ModelAliases {
  resolve(kind: NodeKind, ref: string): AliasNode;
  getExisting(kind: NodeKind, ref: string): AliasNode | undefined;
  getAll(kind: NodeKind): AliasNode[];
}

function buildAliases(model: ThreatModel): ModelAliases {
  const byKey: Record<NodeKind, Map<string, AliasNode>> = { asset: new Map(), threat: new Map(), control: new Map() };
  const byRef: Record<NodeKind, Map<string, AliasNode>> = { asset: new Map(), threat: new Map(), control: new Map() };

  const register = (kind: NodeKind, node: AliasNode, refs: Array<string | undefined>): void => {
    byKey[kind].set(node.key, node);
    for (const r of refs) {
      if (!r) continue;
      const k = refKey(r);
      if (!k) continue;
      const existing = byRef[kind].get(k);
      if (!existing) byRef[kind].set(k, node);
    }
  };

  const upsert = (kind: NodeKind, key: string, displayLabel: string, refs: Array<string | undefined>, opts?: { id?: string; severity?: string; externalRefs?: string[] }): AliasNode => {
    let node = byKey[kind].get(key);
    if (!node) {
      node = {
        key,
        label: displayLabel || key,
        id: opts?.id,
        kind,
        severity: normalizeSeverity(opts?.severity),
        externalRefs: opts?.externalRefs ? [...opts.externalRefs] : [],
      };
    } else {
      if (displayLabel && displayLabel.length > node.label.length) node.label = displayLabel;
      if (opts?.id && !node.id) node.id = opts.id;
      if (opts?.severity) node.severity = strongerSeverity(node.severity, normalizeSeverity(opts.severity));
      if (opts?.externalRefs) for (const r of opts.externalRefs) if (!node.externalRefs.includes(r)) node.externalRefs.push(r);
    }
    register(kind, node, refs);
    return node;
  };

  // Pre-register defined entities. #id takes priority over display label as the canonical key
  // so that any later ref using the id resolves to the same node.
  for (const a of model.assets) {
    const display = a.path.join('.');
    const key = a.id ? refKey(a.id) : refKey(display);
    upsert('asset', key, display, [a.id, a.id ? `#${a.id}` : undefined, display, ...a.path], { id: a.id });
  }
  for (const t of model.threats) {
    const key = t.id ? refKey(t.id) : refKey(t.name);
    upsert('threat', key, t.name, [t.id, t.id ? `#${t.id}` : undefined, t.name, t.canonical_name], {
      id: t.id,
      severity: t.severity,
      externalRefs: t.external_refs,
    });
  }
  for (const c of model.controls) {
    const key = c.id ? refKey(c.id) : refKey(c.name);
    upsert('control', key, c.name, [c.id, c.id ? `#${c.id}` : undefined, c.name, c.canonical_name], { id: c.id });
  }

  // Sweep exposures/mitigations to pick up severities for undefined threats and external refs.
  for (const e of model.exposures) {
    const threat = byRef.threat.get(refKey(e.threat));
    if (threat) {
      if (e.severity) threat.severity = strongerSeverity(threat.severity, normalizeSeverity(e.severity));
      for (const r of e.external_refs) if (!threat.externalRefs.includes(r)) threat.externalRefs.push(r);
    }
  }

  const resolve = (kind: NodeKind, ref: string): AliasNode => {
    const k = refKey(ref);
    const existing = byRef[kind].get(k);
    if (existing) return existing;
    const display = normalizeRef(ref) || 'unknown';
    return upsert(kind, k || display.toLowerCase(), display, [ref, display]);
  };

  return {
    resolve,
    getExisting: (kind, ref) => byRef[kind].get(refKey(ref)),
    getAll: (kind) => [...byKey[kind].values()],
  };
}

/* ══════════════════════════════════════════════════════════════════════════
 * Topology data (interactive D3 view)
 * ══════════════════════════════════════════════════════════════════════════ */

export interface DiagramTopologyNode {
  id: string;
  label: string;
  kind: 'asset' | 'threat' | 'control';
  severity: string;
  status: string;
  exposures: number;
  openExposures: number;
  mitigations: number;
  flows: number;
  confirmed: number;
  riskScore: number;
  classifications: string[];
  owner?: string;
  refs: string[];
}

export interface DiagramTopologyLink {
  source: string;
  target: string;
  kind: 'exposes' | 'confirmed' | 'mitigates' | 'protects' | 'accepts' | 'transfers' | 'flows' | 'boundary' | 'validates';
  label: string;
  severity: string;
  status: string;
  count: number;
}

export interface DiagramTopology {
  nodes: DiagramTopologyNode[];
  links: DiagramTopologyLink[];
  summary: {
    assets: number;
    threats: number;
    controls: number;
    links: number;
    open: number;
    mitigated: number;
    accepted: number;
    confirmed: number;
    criticalAssets: number;
  };
}

const topoId = (kind: NodeKind, key: string): string => `${kind}:${key || 'unknown'}`;

/**
 * Build the structured graph consumed by the dashboard's native D3 topology.
 * Shares an alias map with the Mermaid generators so #id/name/path forms agree.
 */
export function generateTopologyData(model: ThreatModel): DiagramTopology {
  const aliases = buildAliases(model);

  const nodes = new Map<string, DiagramTopologyNode>();
  const links = new Map<string, DiagramTopologyLink>();

  const materialize = (alias: AliasNode): DiagramTopologyNode => {
    const id = topoId(alias.kind, alias.key);
    let node = nodes.get(id);
    if (!node) {
      node = {
        id,
        label: alias.label,
        kind: alias.kind,
        severity: alias.severity,
        status: 'none',
        exposures: 0,
        openExposures: 0,
        mitigations: 0,
        flows: 0,
        confirmed: 0,
        riskScore: 0,
        classifications: [],
        refs: [alias.label, alias.id, alias.id ? `#${alias.id}` : undefined].filter(Boolean) as string[],
      };
      nodes.set(id, node);
    } else {
      node.severity = strongerSeverity(node.severity, alias.severity);
      if (alias.label.length > node.label.length) node.label = alias.label;
    }
    return node;
  };

  const resolve = (kind: NodeKind, ref: string): DiagramTopologyNode => materialize(aliases.resolve(kind, ref));

  const addLink = (
    source: string,
    target: string,
    kind: DiagramTopologyLink['kind'],
    labelText: string,
    severity: string = 'unset',
    status: string = 'none',
  ): void => {
    if (!source || !target || source === target) return;
    const key = `${source}|${target}|${kind}|${labelText}`;
    const sev = normalizeSeverity(severity);
    let link = links.get(key);
    if (!link) {
      link = { source, target, kind, label: labelText, severity: sev, status, count: 0 };
      links.set(key, link);
    }
    link.count++;
    link.severity = strongerSeverity(link.severity, sev);
    link.status = strongerStatus(link.status, status);
  };

  const markNode = (node: DiagramTopologyNode, severity: string, status: string): void => {
    node.severity = strongerSeverity(node.severity, normalizeSeverity(severity));
    node.status = strongerStatus(node.status, status);
  };

  // Pre-seed nodes for every defined entity so the graph reflects the full model,
  // not just what relationships happen to reference.
  for (const a of aliases.getAll('asset')) materialize(a);
  for (const t of aliases.getAll('threat')) materialize(t);
  for (const c of aliases.getAll('control')) materialize(c);

  // Classifications + ownership
  for (const h of model.data_handling) {
    const asset = resolve('asset', h.asset);
    const classification = h.classification.toUpperCase();
    if (!asset.classifications.includes(classification)) asset.classifications.push(classification);
  }
  for (const o of model.ownership) {
    resolve('asset', o.asset).owner = o.owner;
  }

  // Compute per-pair resolution status for exposure links
  const mitigatedPairs = new Set<string>();
  const acceptedPairs = new Set<string>();
  for (const m of model.mitigations) {
    const asset = resolve('asset', m.asset);
    const threat = resolve('threat', m.threat);
    mitigatedPairs.add(`${asset.id}::${threat.id}`);
  }
  for (const a of model.acceptances) {
    const asset = resolve('asset', a.asset);
    const threat = resolve('threat', a.threat);
    acceptedPairs.add(`${asset.id}::${threat.id}`);
  }

  for (const e of model.exposures) {
    const asset = resolve('asset', e.asset);
    const threat = resolve('threat', e.threat);
    const pair = `${asset.id}::${threat.id}`;
    const status = acceptedPairs.has(pair) ? 'accepted' : mitigatedPairs.has(pair) ? 'mitigated' : 'open';
    const severity = normalizeSeverity(e.severity);
    asset.exposures++;
    threat.exposures++;
    if (status === 'open') {
      asset.openExposures++;
      threat.openExposures++;
    }
    markNode(asset, severity, status);
    markNode(threat, severity, status);
    addLink(asset.id, threat.id, 'exposes', 'exposes', severity, status);
  }

  for (const c of model.confirmed || []) {
    const asset = resolve('asset', c.asset);
    const threat = resolve('threat', c.threat);
    const severity = normalizeSeverity(c.severity);
    asset.confirmed++;
    threat.confirmed++;
    markNode(asset, severity, 'confirmed');
    markNode(threat, severity, 'confirmed');
    addLink(asset.id, threat.id, 'confirmed', 'confirmed', severity, 'confirmed');
  }

  for (const m of model.mitigations) {
    const asset = resolve('asset', m.asset);
    const threat = resolve('threat', m.threat);
    asset.mitigations++;
    threat.mitigations++;
    markNode(asset, 'unset', 'mitigated');
    markNode(threat, 'unset', 'mitigated');
    if (m.control) {
      const control = resolve('control', m.control);
      control.mitigations++;
      addLink(control.id, threat.id, 'mitigates', 'mitigates', threat.severity, 'mitigated');
      addLink(control.id, asset.id, 'protects', 'protects', 'unset', 'mitigated');
    } else {
      addLink(asset.id, threat.id, 'mitigates', 'mitigates', threat.severity, 'mitigated');
    }
  }

  for (const a of model.acceptances) {
    const asset = resolve('asset', a.asset);
    const threat = resolve('threat', a.threat);
    markNode(asset, threat.severity, 'accepted');
    markNode(threat, threat.severity, 'accepted');
    addLink(asset.id, threat.id, 'accepts', 'accepts', threat.severity, 'accepted');
  }

  for (const t of model.transfers) {
    const source = resolve('asset', t.source);
    const target = resolve('asset', t.target);
    const threat = resolve('threat', t.threat);
    addLink(source.id, target.id, 'transfers', `transfers ${threat.label}`, threat.severity, 'none');
  }

  for (const f of model.flows) {
    const source = resolve('asset', f.source);
    const target = resolve('asset', f.target);
    source.flows++;
    target.flows++;
    addLink(source.id, target.id, 'flows', f.mechanism || 'flows', 'unset', 'none');
  }

  for (const b of model.boundaries) {
    const a = resolve('asset', b.asset_a);
    const z = resolve('asset', b.asset_b);
    addLink(a.id, z.id, 'boundary', b.description || b.id || 'trust boundary', 'unset', 'none');
  }

  for (const v of model.validations) {
    const control = resolve('control', v.control);
    const asset = resolve('asset', v.asset);
    addLink(control.id, asset.id, 'validates', 'validates', 'unset', 'mitigated');
  }

  // Risk score: exposures weighted by severity, amplified by confirmed hits.
  const sevWeight: Record<string, number> = { critical: 10, p0: 10, high: 6, p1: 6, medium: 3, p2: 3, low: 1, p3: 1, unset: 1 };
  for (const n of nodes.values()) {
    n.riskScore = n.openExposures * (sevWeight[n.severity] ?? 1) + n.confirmed * 12;
  }

  const nodeList = [...nodes.values()]
    .map(n => ({ ...n, classifications: [...n.classifications].sort(), refs: [...n.refs].sort() }))
    .sort((a, b) => {
      const kindOrder = { asset: 0, threat: 1, control: 2 };
      const byKind = kindOrder[a.kind] - kindOrder[b.kind];
      if (byKind !== 0) return byKind;
      const byRisk = b.riskScore - a.riskScore;
      if (byRisk !== 0) return byRisk;
      const bySeverity = (severityRank[a.severity] ?? 4) - (severityRank[b.severity] ?? 4);
      if (bySeverity !== 0) return bySeverity;
      return a.label.localeCompare(b.label);
    });
  const linkList = [...links.values()].sort((a, b) => a.kind.localeCompare(b.kind) || b.count - a.count || a.label.localeCompare(b.label));

  const openCount = model.exposures.filter(e => {
    const assetId = topoId('asset', aliases.resolve('asset', e.asset).key);
    const threatId = topoId('threat', aliases.resolve('threat', e.threat).key);
    const pair = `${assetId}::${threatId}`;
    return !mitigatedPairs.has(pair) && !acceptedPairs.has(pair);
  }).length;
  const mitigatedCount = model.exposures.filter(e => {
    const assetId = topoId('asset', aliases.resolve('asset', e.asset).key);
    const threatId = topoId('threat', aliases.resolve('threat', e.threat).key);
    return mitigatedPairs.has(`${assetId}::${threatId}`);
  }).length;
  const acceptedCount = model.exposures.filter(e => {
    const assetId = topoId('asset', aliases.resolve('asset', e.asset).key);
    const threatId = topoId('threat', aliases.resolve('threat', e.threat).key);
    return acceptedPairs.has(`${assetId}::${threatId}`);
  }).length;

  return {
    nodes: nodeList,
    links: linkList,
    summary: {
      assets: nodeList.filter(n => n.kind === 'asset').length,
      threats: nodeList.filter(n => n.kind === 'threat').length,
      controls: nodeList.filter(n => n.kind === 'control').length,
      links: linkList.length,
      open: openCount,
      mitigated: mitigatedCount,
      accepted: acceptedCount,
      confirmed: (model.confirmed || []).length,
      criticalAssets: nodeList.filter(n => n.kind === 'asset' && (n.severity === 'critical' || n.severity === 'p0') && n.status !== 'mitigated').length,
    },
  };
}

/* ══════════════════════════════════════════════════════════════════════════
 * Mermaid helpers
 * ══════════════════════════════════════════════════════════════════════════ */

/** Heuristic icon for data-flow assets to make diagrams easier to scan. */
function assetIcon(name: string): string {
  const n = normalizeRef(name).toLowerCase();
  if (/(user|client|browser|mobile|frontend|ui)/.test(n)) return '👤';
  if (/(external|internet|partner|vendor|public|third[_-]?party)/.test(n)) return '🌐';
  if (/(queue|topic|kafka|pubsub|amqp|broker|stream)/.test(n)) return '📨';
  if (/(db|database|store|storage|bucket|cache|redis|s3|blob)/.test(n)) return '🗄️';
  if (/(api|service|backend|server|worker|lambda|function|processor|gateway)/.test(n)) return '🖥️';
  return '🧩';
}

/** Heuristic icon for flow mechanisms/protocols. */
function flowIcon(mechanism: string): string {
  const m = mechanism.toLowerCase();
  if (/(https|tls|ssl|mtls|ssh)/.test(m)) return '🔐';
  if (/(http|grpc|rest|graphql|websocket|ws|rpc)/.test(m)) return '🌐';
  if (/(kafka|queue|amqp|pubsub|stream|event)/.test(m)) return '📨';
  if (/(sql|db|database|redis|cache|s3|blob|file)/.test(m)) return '🗄️';
  return '📡';
}

function severityIcon(sev: string): string {
  if (sev === 'critical' || sev === 'p0') return '🔴';
  if (sev === 'high' || sev === 'p1') return '🟠';
  if (sev === 'medium' || sev === 'p2') return '🟡';
  if (sev === 'low' || sev === 'p3') return '🔵';
  return '⚪';
}

function severityClass(sev: string): string {
  if (sev === 'critical' || sev === 'p0') return 'sev_crit';
  if (sev === 'high' || sev === 'p1') return 'sev_high';
  if (sev === 'medium' || sev === 'p2') return 'sev_med';
  if (sev === 'low' || sev === 'p3') return 'sev_low';
  return 'sev_unset';
}

/* ══════════════════════════════════════════════════════════════════════════
 * Diagram 1: Threat Model Graph
 * ══════════════════════════════════════════════════════════════════════════ */

interface ThreatGraphOptions {
  /** Show all threats regardless of severity. Defaults to auto-filter when >12 distinct threats are exposed. */
  showAll?: boolean;
}

/**
 * LR flowchart: assets (boxes), threats (red), controls (green), and relationships.
 * All refs are canonicalized through buildAliases so mixed #id/name usage collapses.
 */
export function generateThreatGraph(model: ThreatModel, opts: ThreatGraphOptions = {}): string {
  const aliases = buildAliases(model);
  const resolve = (kind: NodeKind, ref: string) => aliases.resolve(kind, ref);

  // Auto-filter to high/critical if the diagram would otherwise be overwhelming.
  const distinctThreats = new Set<string>();
  for (const e of model.exposures) distinctThreats.add(resolve('threat', e.threat).key);
  const filterHigh = opts.showAll ? false : distinctThreats.size > 12;

  const isHighSev = (sev: string): boolean => sev === 'critical' || sev === 'p0' || sev === 'high' || sev === 'p1';

  const usedAssetKeys = new Set<string>();   // key → seen
  const usedThreatKeys = new Set<string>();
  const usedControlKeys = new Set<string>();

  const registerAsset = (ref: string): AliasNode => {
    const n = resolve('asset', ref);
    usedAssetKeys.add(n.key);
    return n;
  };
  const registerThreat = (ref: string): AliasNode => {
    const n = resolve('threat', ref);
    usedThreatKeys.add(n.key);
    return n;
  };
  const registerControl = (ref: string): AliasNode => {
    const n = resolve('control', ref);
    usedControlKeys.add(n.key);
    return n;
  };

  // Walk relationships and canonicalize usage
  for (const e of model.exposures) {
    const threat = resolve('threat', e.threat);
    const effectiveSev = e.severity ? normalizeSeverity(e.severity) : threat.severity;
    if (filterHigh && !isHighSev(effectiveSev)) continue;
    registerAsset(e.asset);
    registerThreat(e.threat);
  }
  for (const m of model.mitigations) {
    const threat = resolve('threat', m.threat);
    if (filterHigh && !isHighSev(threat.severity)) continue;
    registerAsset(m.asset);
    registerThreat(m.threat);
    if (m.control) registerControl(m.control);
  }
  for (const a of model.acceptances) {
    const threat = resolve('threat', a.threat);
    if (filterHigh && !isHighSev(threat.severity)) continue;
    registerAsset(a.asset);
    registerThreat(a.threat);
  }
  for (const t of model.transfers) {
    const threat = resolve('threat', t.threat);
    if (filterHigh && !isHighSev(threat.severity)) continue;
    registerAsset(t.source);
    registerAsset(t.target);
    registerThreat(t.threat);
  }
  for (const v of model.validations) {
    registerAsset(v.asset);
    registerControl(v.control);
  }
  for (const c of model.confirmed || []) {
    registerAsset(c.asset);
    registerThreat(c.threat);
  }

  // Classifications + ownership lookup (keyed on asset key)
  const dataClassByKey = new Map<string, string[]>();
  for (const h of model.data_handling) {
    const node = resolve('asset', h.asset);
    const list = dataClassByKey.get(node.key) ?? [];
    const cls = h.classification.toUpperCase();
    if (!list.includes(cls)) list.push(cls);
    dataClassByKey.set(node.key, list);
  }
  const ownerByKey = new Map<string, string>();
  for (const o of model.ownership) ownerByKey.set(resolve('asset', o.asset).key, o.owner);

  // Trust-zone grouping: pair up each boundary's two sides into a shared subgraph
  // titled by the boundary description. An asset may appear in multiple zones, but
  // we dedupe by putting it into its first-seen zone to keep Mermaid valid.
  const zoneById = new Map<string, { label: string; members: Set<string> }>();
  const assetZoneByKey = new Map<string, string>();
  let zIdx = 0;
  for (const b of model.boundaries) {
    const aKey = resolve('asset', b.asset_a).key;
    const bKey = resolve('asset', b.asset_b).key;
    if (!usedAssetKeys.has(aKey) && !usedAssetKeys.has(bKey)) continue;
    const zoneId = `TZ${zIdx++}`;
    const desc = b.description || b.id || 'trust boundary';
    const zone = { label: desc, members: new Set<string>() };
    if (usedAssetKeys.has(aKey) && !assetZoneByKey.has(aKey)) { zone.members.add(aKey); assetZoneByKey.set(aKey, zoneId); }
    if (usedAssetKeys.has(bKey) && !assetZoneByKey.has(bKey)) { zone.members.add(bKey); assetZoneByKey.set(bKey, zoneId); }
    if (zone.members.size > 0) zoneById.set(zoneId, zone);
  }

  const lines: string[] = [
    // rankSpacing controls horizontal distance between columns in LR graphs — bump it
    // to keep the diagram wide instead of cramming everything into a narrow strip.
    '%%{init: {"flowchart": {"nodeSpacing": 55, "rankSpacing": 150, "curve": "monotoneX", "htmlLabels": false, "padding": 24}}}%%',
    'graph LR',
  ];

  const assetLabelFor = (node: AliasNode): string => {
    const classes = dataClassByKey.get(node.key);
    const owner = ownerByKey.get(node.key);
    let suffix = '';
    if (classes && classes.length > 0) suffix += ` [${classes.join(', ')}]`;
    if (owner) suffix += ` (${label(owner, 15)})`;
    return `🔷 ${label(node.label)}${suffix}`;
  };

  // Emit subgraphs first
  const emittedAssets = new Set<string>();
  for (const [zoneId, zone] of zoneById) {
    lines.push(`  subgraph ${zoneId}["🧱 ${label(zone.label, 40)}"]`);
    for (const key of zone.members) {
      const node = [...aliases.getAll('asset')].find(n => n.key === key);
      if (!node) continue;
      lines.push(`    ${mid(node.key)}["${assetLabelFor(node)}"]`);
      emittedAssets.add(key);
    }
    lines.push('  end');
  }

  // Standalone assets
  for (const key of usedAssetKeys) {
    if (emittedAssets.has(key)) continue;
    const node = [...aliases.getAll('asset')].find(n => n.key === key);
    if (!node) continue;
    lines.push(`  ${mid(node.key)}["${assetLabelFor(node)}"]`);
  }

  // Threat nodes
  for (const key of usedThreatKeys) {
    const node = [...aliases.getAll('threat')].find(n => n.key === key);
    if (!node) continue;
    const icon = severityIcon(node.severity);
    const refSuffix = node.externalRefs.length > 0 ? ` (${node.externalRefs.slice(0, 2).join(', ')})` : '';
    lines.push(`  ${mid(node.key)}["${icon} ${label(node.label, 35)}${refSuffix}"]:::threat`);
  }

  // Control nodes
  for (const key of usedControlKeys) {
    const node = [...aliases.getAll('control')].find(n => n.key === key);
    if (!node) continue;
    lines.push(`  ${mid(node.key)}["🛡️ ${label(node.label)}"]:::control`);
  }

  // Edge emission (deduped)
  const edgeKeys = new Set<string>();
  const edge = (sourceKey: string, targetKey: string, kind: string, syntax: string) => {
    const k = `${sourceKey}|${targetKey}|${kind}`;
    if (edgeKeys.has(k)) return;
    edgeKeys.add(k);
    lines.push(`  ${syntax}`);
  };

  for (const e of model.exposures) {
    const threat = resolve('threat', e.threat);
    const asset = resolve('asset', e.asset);
    const effectiveSev = e.severity ? normalizeSeverity(e.severity) : threat.severity;
    if (filterHigh && !isHighSev(effectiveSev)) continue;
    edge(asset.key, threat.key, 'exp', `${mid(asset.key)} -. exposes .-> ${mid(threat.key)}`);
  }
  for (const c of model.confirmed || []) {
    const asset = resolve('asset', c.asset);
    const threat = resolve('threat', c.threat);
    edge(asset.key, threat.key, 'conf', `${mid(asset.key)} == "💥 confirmed" ==> ${mid(threat.key)}`);
  }
  for (const m of model.mitigations) {
    const threat = resolve('threat', m.threat);
    const asset = resolve('asset', m.asset);
    if (filterHigh && !isHighSev(threat.severity)) continue;
    if (m.control) {
      const control = resolve('control', m.control);
      edge(control.key, threat.key, 'mit', `${mid(control.key)} -- mitigates --> ${mid(threat.key)}`);
      edge(control.key, asset.key, 'prot', `${mid(control.key)} -. protects .-> ${mid(asset.key)}`);
    } else {
      edge(asset.key, threat.key, 'mit', `${mid(asset.key)} -. mitigates .-> ${mid(threat.key)}`);
    }
  }
  for (const a of model.acceptances) {
    const threat = resolve('threat', a.threat);
    const asset = resolve('asset', a.asset);
    if (filterHigh && !isHighSev(threat.severity)) continue;
    edge(asset.key, threat.key, 'acc', `${mid(asset.key)} -- accepts --> ${mid(threat.key)}`);
  }
  for (const t of model.transfers) {
    const threat = resolve('threat', t.threat);
    const source = resolve('asset', t.source);
    const target = resolve('asset', t.target);
    if (filterHigh && !isHighSev(threat.severity)) continue;
    edge(source.key, target.key, `xfer:${threat.key}`, `${mid(source.key)} -- "transfers risk: ${label(threat.label, 26)}" --> ${mid(target.key)}`);
  }
  for (const v of model.validations) {
    const control = resolve('control', v.control);
    const asset = resolve('asset', v.asset);
    edge(control.key, asset.key, 'val', `${mid(control.key)} -. validates .-> ${mid(asset.key)}`);
  }
  for (const f of model.flows) {
    const source = resolve('asset', f.source);
    const target = resolve('asset', f.target);
    if (!usedAssetKeys.has(source.key) || !usedAssetKeys.has(target.key)) continue;
    if (f.mechanism) {
      edge(source.key, target.key, `flow:${f.mechanism}`, `${mid(source.key)} -- "${flowIcon(f.mechanism)} ${label(f.mechanism, 22)}" --> ${mid(target.key)}`);
    } else {
      edge(source.key, target.key, 'flow', `${mid(source.key)} --> ${mid(target.key)}`);
    }
  }
  for (const b of model.boundaries) {
    const a = resolve('asset', b.asset_a);
    const z = resolve('asset', b.asset_b);
    if (!usedAssetKeys.has(a.key) || !usedAssetKeys.has(z.key)) continue;
    const desc = b.description ? label(b.description, 26) : 'trust boundary';
    edge(a.key, z.key, 'bnd', `${mid(a.key)} -.-|🧱 ${desc}| ${mid(z.key)}`);
  }

  lines.push('  classDef threat fill:#3a1010,stroke:#ea1d1d,color:#f0f0f0,stroke-width:1.3px');
  lines.push('  classDef control fill:#102a24,stroke:#33d49d,color:#f0f0f0,stroke-width:1.3px');

  return lines.join('\n');
}

/* ══════════════════════════════════════════════════════════════════════════
 * Diagram 2: Data Flow Diagram
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * LR flow graph. Each @boundary produces a paired subgraph (both sides appear
 * inside a single zone) labelled by the boundary description; the boundary
 * itself is drawn as a purple dashed edge between the two sides. Assets that
 * are not touched by any boundary render as standalone nodes.
 */
export function generateDataFlowDiagram(model: ThreatModel): string {
  if (model.flows.length === 0) return '';

  const aliases = buildAliases(model);
  const resolve = (ref: string) => aliases.resolve('asset', ref);

  // Dynamic spacing based on longest mechanism label so mermaid doesn't crush long edges.
  const maxMechanismLen = model.flows.reduce((max, f) => Math.max(max, (f.mechanism || '').length), 0);
  const spacingBoost = Math.max(0, Math.min(140, (maxMechanismLen - 24) * 3));
  const nodeSpacing = 44 + Math.floor(spacingBoost * 0.4);
  const rankSpacing = 58 + spacingBoost;

  const lines: string[] = [
    `%%{init: {"flowchart": {"nodeSpacing": ${nodeSpacing}, "rankSpacing": ${rankSpacing}, "curve": "basis", "htmlLabels": false}}}%%`,
    'graph LR',
  ];

  // Data handling badges keyed on canonical asset key
  const handlingByKey = new Map<string, string[]>();
  for (const h of model.data_handling) {
    const node = resolve(h.asset);
    const list = handlingByKey.get(node.key) ?? [];
    if (!list.includes(h.classification)) list.push(h.classification);
    handlingByKey.set(node.key, list);
  }

  const nodeLabel = (n: AliasNode): string => {
    const badges = handlingByKey.get(n.key);
    const suffix = badges && badges.length > 0 ? ` · ${badges.join(', ')}` : '';
    return `${assetIcon(n.label)} ${labelFull(n.label)}${suffix}`;
  };

  // Collect the set of assets actually used by flows (or boundaries)
  const usedAssets = new Map<string, AliasNode>();
  for (const f of model.flows) {
    const s = resolve(f.source);
    const t = resolve(f.target);
    usedAssets.set(s.key, s);
    usedAssets.set(t.key, t);
  }

  // Emit one subgraph PER SIDE of each boundary (A and B live in different trust zones).
  // Label combines the boundary description with the side's asset so the visual
  // cleanly conveys "this zone is on one side of <boundary>".
  const placedAssets = new Set<string>();
  let zIdx = 0;
  const emitSide = (node: AliasNode, desc: string): void => {
    if (placedAssets.has(node.key)) return;
    const zoneId = `Z${zIdx++}`;
    const zoneLabel = desc === node.label ? node.label : `${node.label} · ${desc}`;
    lines.push(`  subgraph ${zoneId}["🧱 ${labelFull(zoneLabel)}"]`);
    lines.push(`    ${mid(node.key)}["${nodeLabel(node)}"]`);
    lines.push('  end');
    placedAssets.add(node.key);
    usedAssets.set(node.key, node);
  };
  for (const b of model.boundaries) {
    const a = resolve(b.asset_a);
    const z = resolve(b.asset_b);
    if (!usedAssets.has(a.key) && !usedAssets.has(z.key)) continue;
    const desc = b.description || b.id || 'trust boundary';
    emitSide(a, desc);
    emitSide(z, desc);
  }

  // Standalone nodes (flow endpoints not inside any boundary zone)
  for (const node of usedAssets.values()) {
    if (placedAssets.has(node.key)) continue;
    lines.push(`  ${mid(node.key)}["${nodeLabel(node)}"]`);
    placedAssets.add(node.key);
  }

  // Boundary edges: a visual connector between the two sides
  const emittedBoundaries = new Set<string>();
  for (const b of model.boundaries) {
    const a = resolve(b.asset_a);
    const z = resolve(b.asset_b);
    const k = `${a.key}|${z.key}`;
    if (emittedBoundaries.has(k)) continue;
    emittedBoundaries.add(k);
    const desc = b.description ? labelFull(b.description) : 'trust boundary';
    lines.push(`  ${mid(a.key)} -.-|🧱 ${desc}| ${mid(z.key)}`);
  }

  // Flow edges
  const emittedFlows = new Set<string>();
  for (const f of model.flows) {
    const s = resolve(f.source);
    const t = resolve(f.target);
    const k = `${s.key}|${t.key}|${f.mechanism || ''}`;
    if (emittedFlows.has(k)) continue;
    emittedFlows.add(k);
    if (f.mechanism) {
      lines.push(`  ${mid(s.key)} -- "${flowIcon(f.mechanism)} ${labelFull(f.mechanism)}" --> ${mid(t.key)}`);
    } else {
      lines.push(`  ${mid(s.key)} --> ${mid(t.key)}`);
    }
  }

  return lines.join('\n');
}

/* ══════════════════════════════════════════════════════════════════════════
 * Diagram 3: Attack Surface Map
 * ══════════════════════════════════════════════════════════════════════════ */

interface AttackSurfaceEntry {
  threatLabel: string;
  severity: string;
  count: number;
  status: 'open' | 'mitigated' | 'accepted' | 'confirmed';
}

/**
 * TB grouping: exposures per asset, coloured by severity and marked by status.
 *   - ⚠️  open
 *   - ✅  mitigated
 *   - 🟦  accepted
 *   - 💥  confirmed (raises severity to critical)
 */
export function generateAttackSurface(model: ThreatModel): string {
  if (model.exposures.length === 0 && (!model.confirmed || model.confirmed.length === 0)) return '';

  const aliases = buildAliases(model);
  const resolveAsset = (ref: string) => aliases.resolve('asset', ref);
  const resolveThreat = (ref: string) => aliases.resolve('threat', ref);

  // Compute per-pair resolution using canonical keys
  const mitigatedPairs = new Set<string>();
  const acceptedPairs = new Set<string>();
  for (const m of model.mitigations) mitigatedPairs.add(`${resolveAsset(m.asset).key}::${resolveThreat(m.threat).key}`);
  for (const a of model.acceptances) acceptedPairs.add(`${resolveAsset(a.asset).key}::${resolveThreat(a.threat).key}`);
  const confirmedPairs = new Set<string>();
  for (const c of model.confirmed || []) confirmedPairs.add(`${resolveAsset(c.asset).key}::${resolveThreat(c.threat).key}`);

  // Group by canonical asset key → canonical threat key → entry
  type AssetGroup = { label: string; threats: Map<string, AttackSurfaceEntry>; openCount: number; mitigatedCount: number; confirmedCount: number };
  const byAsset = new Map<string, AssetGroup>();

  const getGroup = (assetRef: string): AssetGroup => {
    const node = resolveAsset(assetRef);
    let g = byAsset.get(node.key);
    if (!g) {
      g = { label: node.label, threats: new Map(), openCount: 0, mitigatedCount: 0, confirmedCount: 0 };
      byAsset.set(node.key, g);
    }
    return g;
  };

  for (const e of model.exposures) {
    const group = getGroup(e.asset);
    const threatNode = resolveThreat(e.threat);
    const pair = `${resolveAsset(e.asset).key}::${threatNode.key}`;
    const sev = normalizeSeverity(e.severity || threatNode.severity);
    const existing = group.threats.get(threatNode.key);
    const isConfirmed = confirmedPairs.has(pair);
    const status: AttackSurfaceEntry['status'] = isConfirmed ? 'confirmed' : acceptedPairs.has(pair) ? 'accepted' : mitigatedPairs.has(pair) ? 'mitigated' : 'open';
    const escalated = isConfirmed ? 'critical' : sev;
    if (!existing) {
      group.threats.set(threatNode.key, { threatLabel: threatNode.label, severity: escalated, count: 1, status });
    } else {
      existing.count++;
      existing.severity = strongerSeverity(existing.severity, escalated);
      existing.status = status === 'confirmed' ? 'confirmed' : status === 'open' && existing.status === 'mitigated' ? 'open' : existing.status;
    }
  }

  // Make sure confirmed-only rows (no matching exposure) still appear
  for (const c of model.confirmed || []) {
    const group = getGroup(c.asset);
    const threatNode = resolveThreat(c.threat);
    const existing = group.threats.get(threatNode.key);
    const sev = normalizeSeverity(c.severity || 'critical');
    if (!existing) {
      group.threats.set(threatNode.key, { threatLabel: threatNode.label, severity: sev, count: 1, status: 'confirmed' });
    } else {
      existing.status = 'confirmed';
      existing.severity = strongerSeverity(existing.severity, sev);
    }
  }

  // Roll up counts per group
  for (const g of byAsset.values()) {
    for (const t of g.threats.values()) {
      if (t.status === 'open') g.openCount++;
      else if (t.status === 'mitigated' || t.status === 'accepted') g.mitigatedCount++;
      if (t.status === 'confirmed') g.confirmedCount++;
    }
  }

  // Sort assets: confirmed first, then by open count desc, then by label
  const assetsSorted = [...byAsset.entries()].sort(([, a], [, b]) => {
    if (a.confirmedCount !== b.confirmedCount) return b.confirmedCount - a.confirmedCount;
    if (a.openCount !== b.openCount) return b.openCount - a.openCount;
    return a.label.localeCompare(b.label);
  });

  const lines: string[] = [
    '%%{init: {"flowchart": {"nodeSpacing": 38, "rankSpacing": 48, "curve": "linear", "htmlLabels": false}}}%%',
    'graph TB',
  ];

  let eIdx = 0;
  for (const [assetKey, group] of assetsSorted) {
    const totalThreats = group.threats.size;
    const coverage = totalThreats === 0 ? 0 : Math.round((group.mitigatedCount / totalThreats) * 100);
    const statusSuffix = group.confirmedCount > 0
      ? ` · 💥 ${group.confirmedCount} confirmed`
      : group.openCount > 0
        ? ` · ⚠ ${group.openCount} open`
        : ` · ✅ ${coverage}% covered`;

    lines.push(`  subgraph A_${mid(assetKey)}["${label(group.label)}${statusSuffix}"]`);
    lines.push(`    direction TB`);

    const sorted = [...group.threats.values()].sort((a, b) => (severityRank[a.severity] ?? 4) - (severityRank[b.severity] ?? 4));

    for (const entry of sorted) {
      const cls = severityClass(entry.severity);
      const icon = entry.status === 'confirmed' ? '💥'
        : entry.status === 'mitigated' ? '✅'
          : entry.status === 'accepted' ? '🟦'
            : '⚠️';
      const threatLabel = label(entry.threatLabel, 30);
      const countSuffix = entry.count > 1 ? ` ×${entry.count}` : '';
      lines.push(`    E${eIdx}["${icon} ${threatLabel}${countSuffix}"]:::${cls}`);
      eIdx++;
    }
    lines.push('  end');
  }

  lines.push('  classDef sev_crit fill:#3a1010,stroke:#ea1d1d,color:#f0f0f0,stroke-width:1.4px');
  lines.push('  classDef sev_high fill:#402019,stroke:#ea1d1d,color:#f0f0f0,stroke-width:1.2px');
  lines.push('  classDef sev_med fill:#1f3943,stroke:#55899e,color:#f0f0f0');
  lines.push('  classDef sev_low fill:#10263b,stroke:#0360a2,color:#f0f0f0');
  lines.push('  classDef sev_unset fill:#223942,stroke:#3b6779,color:#f0f0f0');

  return lines.join('\n');
}
