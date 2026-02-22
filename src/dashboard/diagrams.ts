/**
 * GuardLink Dashboard — Mermaid diagram generators.
 *
 * Three diagram types:
 * 1. Threat Model Graph — assets, threats, controls, relationships
 * 2. Data Flow Diagram — @flows with trust boundaries
 * 3. Attack Surface — exposures grouped by severity
 */

import type { ThreatModel } from '../types/index.js';

/** Sanitize IDs for Mermaid (no dots, spaces, hashes) */
function mid(s: string): string {
  return s.replace(/[^a-zA-Z0-9_]/g, '_');
}

/** Truncate long labels and sanitize for Mermaid (strip syntax-breaking characters) */
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

/**
 * Diagram 1: Threat Model Graph
 * Shows assets (boxes), threats (red), controls (green), and relationships.
 */
export function generateThreatGraph(model: ThreatModel): string {
  // Filter to critical+high severity threats to keep diagram readable
  const highSevThreats = new Set<string>();
  const sevMap = new Map<string, string>();
  const threatLabelMap = new Map<string, string>();
  const sevRank: Record<string, number> = { critical: 0, p0: 0, high: 1, p1: 1, medium: 2, p2: 2, low: 3, p3: 3, unset: 4 };

  const setThreatSeverity = (ref: string, severity: string): void => {
    if (!ref || !severity) return;
    const norm = normalizeRef(ref);
    const current = sevMap.get(ref) || sevMap.get(norm);
    if (!current || (sevRank[severity] ?? 4) < (sevRank[current] ?? 4)) {
      sevMap.set(ref, severity);
      sevMap.set(norm, severity);
    }
  };

  const setThreatLabel = (ref: string, display: string): void => {
    if (!ref || !display) return;
    const norm = normalizeRef(ref);
    const existing = threatLabelMap.get(ref) || threatLabelMap.get(norm);
    // Prefer richer labels (e.g., canonical threat name) over terse id-like refs.
    if (!existing || display.length > existing.length) {
      threatLabelMap.set(ref, display);
      threatLabelMap.set(norm, display);
    }
  };

  for (const t of model.threats) {
    const s = (t.severity || '').toLowerCase();
    if (t.id) {
      setThreatSeverity(`#${t.id}`, s);
      setThreatSeverity(t.id, s);
      setThreatLabel(`#${t.id}`, t.name);
      setThreatLabel(t.id, t.name);
    }
    setThreatSeverity(t.name, s);
    setThreatLabel(t.name, t.name);
    if (s === 'critical' || s === 'p0' || s === 'high' || s === 'p1') {
      if (t.id) { highSevThreats.add(`#${t.id}`); highSevThreats.add(t.id); }
      highSevThreats.add(t.name);
      highSevThreats.add(normalizeRef(t.name));
    }
  }

  // Exposure-level severity can exist even when a threat definition doesn't.
  for (const e of model.exposures) {
    const s = (e.severity || '').toLowerCase();
    setThreatSeverity(e.threat, s);
    setThreatLabel(e.threat, e.threat.replace('#', ''));
    if (s === 'critical' || s === 'p0' || s === 'high' || s === 'p1') {
      highSevThreats.add(e.threat);
      highSevThreats.add(normalizeRef(e.threat));
    }
  }

  const isHighThreat = (ref: string): boolean => highSevThreats.has(ref) || highSevThreats.has(normalizeRef(ref));

  // If very many threats, filter to critical+high only
  const totalThreats = new Set<string>();
  for (const e of model.exposures) totalThreats.add(e.threat);
  const filterHigh = totalThreats.size > 12;

  const lines: string[] = ['graph LR'];
  const usedAssets = new Set<string>();
  const usedThreats = new Set<string>();
  const usedControls = new Set<string>();
  const edges = new Set<string>();

  for (const e of model.exposures) {
    if (filterHigh && !isHighThreat(e.threat)) continue;
    usedAssets.add(e.asset);
    usedThreats.add(e.threat);
  }
  for (const m of model.mitigations) {
    if (filterHigh && !isHighThreat(m.threat)) continue;
    usedAssets.add(m.asset); usedThreats.add(m.threat);
    if (m.control) usedControls.add(m.control);
  }
  for (const a of model.acceptances) {
    if (filterHigh && !isHighThreat(a.threat)) continue;
    usedAssets.add(a.asset); usedThreats.add(a.threat);
  }
  for (const t of model.transfers) {
    if (filterHigh && !isHighThreat(t.threat)) continue;
    usedAssets.add(t.source); usedAssets.add(t.target); usedThreats.add(t.threat);
  }
  for (const v of model.validations) {
    usedAssets.add(v.asset);
    usedControls.add(v.control);
  }

  // ── Build data-classification map (asset → classification badges) ──
  const dataClassMap = new Map<string, string[]>();
  for (const h of model.data_handling) {
    const norm = normalizeRef(h.asset);
    if (!dataClassMap.has(h.asset)) dataClassMap.set(h.asset, []);
    dataClassMap.get(h.asset)!.push(h.classification.toUpperCase());
    if (norm !== h.asset) {
      if (!dataClassMap.has(norm)) dataClassMap.set(norm, []);
      dataClassMap.get(norm)!.push(h.classification.toUpperCase());
    }
  }

  // ── Build ownership map (asset → owner) ──
  const ownerMap = new Map<string, string>();
  for (const o of model.ownership) {
    ownerMap.set(o.asset, o.owner);
    ownerMap.set(normalizeRef(o.asset), o.owner);
  }

  // ── Build external-refs map (threat → CWE/refs) ──
  const extRefMap = new Map<string, string[]>();
  const addExtRefs = (ref: string, refs: string[]) => {
    if (!refs || refs.length === 0) return;
    const norm = normalizeRef(ref);
    for (const r of [ref, norm]) {
      if (!extRefMap.has(r)) extRefMap.set(r, []);
      for (const er of refs) {
        if (!extRefMap.get(r)!.includes(er)) extRefMap.get(r)!.push(er);
      }
    }
  };
  for (const t of model.threats) {
    if (t.external_refs.length > 0) {
      addExtRefs(t.name, t.external_refs);
      if (t.id) { addExtRefs(`#${t.id}`, t.external_refs); addExtRefs(t.id, t.external_refs); }
    }
  }
  for (const e of model.exposures) {
    if (e.external_refs.length > 0) addExtRefs(e.threat, e.external_refs);
  }

  // ── Determine trust-boundary groupings for used assets ──
  const assetZone = new Map<string, string>();  // asset → zone id
  const zoneAssets = new Map<string, Set<string>>(); // zone id → assets
  const zoneLabel = new Map<string, string>(); // zone id → label
  let zIdx = 0;
  for (const b of model.boundaries) {
    // Only include boundaries where at least one side is a used asset
    const aUsed = usedAssets.has(b.asset_a) || usedAssets.has(normalizeRef(b.asset_a));
    const bUsed = usedAssets.has(b.asset_b) || usedAssets.has(normalizeRef(b.asset_b));
    if (!aUsed && !bUsed) continue;

    // Assign each side to a zone if not already assigned
    for (const side of [b.asset_a, b.asset_b]) {
      if (!assetZone.has(side) && !assetZone.has(normalizeRef(side))) {
        const zId = `TZ${zIdx++}`;
        assetZone.set(side, zId);
        assetZone.set(normalizeRef(side), zId);
        zoneAssets.set(zId, new Set([side]));
        zoneLabel.set(zId, side);
      }
    }
  }

  // ── Emit trust-boundary subgraphs ──
  const inSubgraph = new Set<string>();
  for (const [zId, members] of zoneAssets) {
    const rep = zoneLabel.get(zId) || [...members][0];
    lines.push(`  subgraph ${zId}["🧱 ${label(rep)}"]`);
    for (const m of members) {
      if (!usedAssets.has(m) && !usedAssets.has(normalizeRef(m))) continue;
      const badges = dataClassMap.get(m) || dataClassMap.get(normalizeRef(m));
      const owner = ownerMap.get(m) || ownerMap.get(normalizeRef(m));
      let suffix = '';
      if (badges && badges.length > 0) suffix += ` [${badges.join(', ')}]`;
      if (owner) suffix += ` (${label(owner, 15)})`;
      lines.push(`    ${mid(m)}["🔷 ${label(m)}${suffix}"]`);
      inSubgraph.add(m);
      inSubgraph.add(normalizeRef(m));
    }
    lines.push('  end');
  }

  // ── Asset nodes (not already in a subgraph) ──
  for (const a of usedAssets) {
    if (inSubgraph.has(a) || inSubgraph.has(normalizeRef(a))) continue;
    const badges = dataClassMap.get(a) || dataClassMap.get(normalizeRef(a));
    const owner = ownerMap.get(a) || ownerMap.get(normalizeRef(a));
    let suffix = '';
    if (badges && badges.length > 0) suffix += ` [${badges.join(', ')}]`;
    if (owner) suffix += ` (${label(owner, 15)})`;
    lines.push(`  ${mid(a)}["🔷 ${label(a)}${suffix}"]`);
  }
  // Threat nodes (with CWE/external-ref badges)
  for (const t of usedThreats) {
    const sev = sevMap.get(t) || sevMap.get(normalizeRef(t)) || '';
    const display = threatLabelMap.get(t) || threatLabelMap.get(normalizeRef(t)) || t.replace('#', '');
    const icon = sev === 'critical' || sev === 'p0' ? '🔴' : sev === 'high' || sev === 'p1' ? '🟠' : '🟡';
    const refs = extRefMap.get(t) || extRefMap.get(normalizeRef(t));
    const refSuffix = refs && refs.length > 0 ? ` (${refs.slice(0, 2).join(', ')})` : '';
    lines.push(`  ${mid(t)}["${icon} ${label(display, 35)}${refSuffix}"]:::threat`);
  }
  // Control nodes
  for (const c of usedControls) {
    lines.push(`  ${mid(c)}["🛡️ ${label(c.replace('#', ''))}"]:::control`);
  }

  // Exposure edges (deduplicated)
  for (const e of model.exposures) {
    if (filterHigh && !isHighThreat(e.threat)) continue;
    const key = `${mid(e.asset)}->exp->${mid(e.threat)}`;
    if (!edges.has(key)) {
      edges.add(key);
      lines.push(`  ${mid(e.asset)} -. exposed .-> ${mid(e.threat)}`);
    }
  }
  // Mitigation edges
  for (const m of model.mitigations) {
    if (filterHigh && !isHighThreat(m.threat)) continue;
    if (m.control) {
      const k1 = `${mid(m.control)}->mit->${mid(m.threat)}`;
      if (!edges.has(k1)) { edges.add(k1); lines.push(`  ${mid(m.control)} -- mitigates --> ${mid(m.threat)}`); }
      const k2 = `${mid(m.control)}->on->${mid(m.asset)}`;
      if (!edges.has(k2)) { edges.add(k2); lines.push(`  ${mid(m.control)} -.- ${mid(m.asset)}`); }
    } else {
      const key = `${mid(m.asset)}->mit->${mid(m.threat)}`;
      if (!edges.has(key)) { edges.add(key); lines.push(`  ${mid(m.asset)} -. mitigates .-> ${mid(m.threat)}`); }
    }
  }
  // Acceptance edges
  for (const a of model.acceptances) {
    if (filterHigh && !isHighThreat(a.threat)) continue;
    const key = `${mid(a.asset)}->acc->${mid(a.threat)}`;
    if (!edges.has(key)) { edges.add(key); lines.push(`  ${mid(a.asset)} -- accepts --> ${mid(a.threat)}`); }
  }
  // Transfer edges (risk moved between parties for a specific threat)
  for (const t of model.transfers) {
    if (filterHigh && !isHighThreat(t.threat)) continue;
    const threatDisplay = threatLabelMap.get(t.threat) || threatLabelMap.get(normalizeRef(t.threat)) || t.threat.replace('#', '');
    const key = `${mid(t.source)}->xfer->${mid(t.target)}::${mid(t.threat)}`;
    if (!edges.has(key)) {
      edges.add(key);
      lines.push(`  ${mid(t.source)} -- "transfers risk: ${label(threatDisplay, 26)}" --> ${mid(t.target)}`);
    }
  }
  // Validation edges (controls validating assets)
  for (const v of model.validations) {
    const key = `${mid(v.control)}->val->${mid(v.asset)}`;
    if (!edges.has(key)) { edges.add(key); lines.push(`  ${mid(v.control)} -. validates .-> ${mid(v.asset)}`); }
  }
  // Data-flow edges (only between assets already in the graph)
  for (const f of model.flows) {
    const srcIn = usedAssets.has(f.source) || usedAssets.has(normalizeRef(f.source));
    const tgtIn = usedAssets.has(f.target) || usedAssets.has(normalizeRef(f.target));
    if (!srcIn || !tgtIn) continue;
    const key = `${mid(f.source)}->flow->${mid(f.target)}`;
    if (!edges.has(key)) {
      edges.add(key);
      if (f.mechanism) {
        lines.push(`  ${mid(f.source)} -- "${flowIcon(f.mechanism)} ${label(f.mechanism, 22)}" --> ${mid(f.target)}`);
      } else {
        lines.push(`  ${mid(f.source)} --> ${mid(f.target)}`);
      }
    }
  }
  // Trust-boundary crossing edges (dashed purple line between zones)
  for (const b of model.boundaries) {
    const aIn = usedAssets.has(b.asset_a) || usedAssets.has(normalizeRef(b.asset_a));
    const bIn = usedAssets.has(b.asset_b) || usedAssets.has(normalizeRef(b.asset_b));
    if (!aIn || !bIn) continue;
    const key = `${mid(b.asset_a)}->boundary->${mid(b.asset_b)}`;
    if (!edges.has(key)) {
      edges.add(key);
      const desc = b.description ? label(b.description, 26) : 'trust boundary';
      lines.push(`  ${mid(b.asset_a)} -.-|🧱 ${desc}| ${mid(b.asset_b)}`);
    }
  }

  lines.push('  classDef threat fill:#991b1b,stroke:#ef4444,color:#fecaca');
  lines.push('  classDef control fill:#065f46,stroke:#10b981,color:#a7f3d0');

  return lines.join('\n');
}

/**
 * Diagram 2: Data Flow Diagram
 * Shows @flows between components with @boundary as subgraphs.
 */
export function generateDataFlowDiagram(model: ThreatModel): string {
  if (model.flows.length === 0) return '';

  const maxMechanismLen = model.flows.reduce((max, f) => {
    const len = (f.mechanism || '').length;
    return len > max ? len : max;
  }, 0);
  const spacingBoost = Math.max(0, Math.min(140, (maxMechanismLen - 24) * 3));
  const nodeSpacing = 40 + Math.floor(spacingBoost * 0.4);
  const rankSpacing = 50 + spacingBoost;

  const lines: string[] = [
    `%%{init: {"flowchart": {"nodeSpacing": ${nodeSpacing}, "rankSpacing": ${rankSpacing}, "curve": "basis"}}}%%`,
    'graph LR',
  ];

  // Collect boundary zones: each side of a boundary is a separate zone
  // An asset may appear in multiple boundaries, so track zone membership
  const assetZone = new Map<string, string>(); // asset -> zone label
  const zones = new Map<string, Set<string>>(); // zone label -> members
  const boundaryEdges: { a: string; b: string; desc: string }[] = [];
  let zIdx = 0;

  for (const b of model.boundaries) {
    const desc = b.description || b.id || `${b.asset_a}/${b.asset_b}`;
    // Assign each side to its own zone if not already in one
    if (!assetZone.has(b.asset_a)) {
      const zoneLabel = `Z${zIdx++}`;
      assetZone.set(b.asset_a, zoneLabel);
      zones.set(zoneLabel, new Set([b.asset_a]));
    }
    if (!assetZone.has(b.asset_b)) {
      const zoneLabel = `Z${zIdx++}`;
      assetZone.set(b.asset_b, zoneLabel);
      zones.set(zoneLabel, new Set([b.asset_b]));
    }
    boundaryEdges.push({ a: b.asset_a, b: b.asset_b, desc });
  }

  // Emit zone subgraphs
  const inBoundary = new Set<string>();
  for (const [zoneId, members] of zones) {
    const representative = [...members][0];
    lines.push(`  subgraph ${zoneId}["🧱 Trust Zone · ${labelFull(representative)}"]`);
    for (const m of members) {
      lines.push(`    ${mid(m)}["${assetIcon(m)} ${labelFull(m)}"]`);
      inBoundary.add(m);
    }
    lines.push('  end');
  }

  // Emit boundary edges between zones (thick dashed line)
  for (const be of boundaryEdges) {
    lines.push(`  ${mid(be.a)} -.-|🧱 ${labelFull(be.desc)}| ${mid(be.b)}`);
  }

  // Data handling badges
  const handling = new Map<string, string[]>();
  for (const h of model.data_handling) {
    if (!handling.has(h.asset)) handling.set(h.asset, []);
    handling.get(h.asset)!.push(h.classification);
  }

  // Standalone nodes (not in any boundary)
  const allNodes = new Set<string>();
  for (const f of model.flows) { allNodes.add(f.source); allNodes.add(f.target); }
  for (const n of allNodes) {
    if (!inBoundary.has(n)) {
      const badges = handling.get(n);
      const suffix = badges ? ` · ${badges.join(', ')}` : '';
      lines.push(`  ${mid(n)}["${assetIcon(n)} ${labelFull(n)}${suffix}"]`);
    }
  }

  // Flow edges
  for (const f of model.flows) {
    if (f.mechanism) {
      lines.push(`  ${mid(f.source)} -- "${flowIcon(f.mechanism)} ${labelFull(f.mechanism)}" --> ${mid(f.target)}`);
    } else {
      lines.push(`  ${mid(f.source)} --> ${mid(f.target)}`);
    }
  }

  return lines.join('\n');
}

/**
 * Diagram 3: Attack Surface Map
 * Groups exposures by asset, colored by severity.
 */
export function generateAttackSurface(model: ThreatModel): string {
  if (model.exposures.length === 0) return '';

  const lines: string[] = ['graph LR'];

  // Build set of mitigated/accepted (normalize refs for consistent matching)
  const resolved = new Set<string>();
  for (const m of model.mitigations) resolved.add(`${normalizeRef(m.asset)}::${normalizeRef(m.threat)}`);
  for (const a of model.acceptances) resolved.add(`${normalizeRef(a.asset)}::${normalizeRef(a.threat)}`);

  // Group exposures by asset, deduplicate by threat, keep highest severity
  const sevOrder: Record<string, number> = { critical: 0, p0: 0, high: 1, p1: 1, medium: 2, p2: 2, low: 3, p3: 3, unset: 4 };
  const byAsset = new Map<string, Map<string, { threat: string; severity: string; count: number; resolved: boolean }>>();

  for (const e of model.exposures) {
    if (!byAsset.has(e.asset)) byAsset.set(e.asset, new Map());
    const assetMap = byAsset.get(e.asset)!;
    const existing = assetMap.get(e.threat);
    const sev = (e.severity || 'unset').toLowerCase();
    const isResolved = resolved.has(`${normalizeRef(e.asset)}::${normalizeRef(e.threat)}`);
    if (!existing || (sevOrder[sev] ?? 4) < (sevOrder[existing.severity] ?? 4)) {
      assetMap.set(e.threat, { threat: e.threat, severity: sev, count: (existing?.count || 0) + 1, resolved: isResolved });
    } else {
      existing.count++;
    }
  }

  let eIdx = 0;
  for (const [asset, threatMap] of byAsset) {
    // Sort threats by severity (critical first)
    const sorted = [...threatMap.values()].sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

    lines.push(`  subgraph A_${mid(asset)}["${label(asset)}"]`);
    lines.push(`    direction TB`);
    for (const entry of sorted) {
      let cls = 'sev_unset';
      if (entry.severity === 'critical' || entry.severity === 'p0') cls = 'sev_crit';
      else if (entry.severity === 'high' || entry.severity === 'p1') cls = 'sev_high';
      else if (entry.severity === 'medium' || entry.severity === 'p2') cls = 'sev_med';
      else if (entry.severity === 'low' || entry.severity === 'p3') cls = 'sev_low';

      const icon = entry.resolved ? '✅' : '⚠️';
      const threatLabel = label(entry.threat.replace('#', ''), 30);
      const countSuffix = entry.count > 1 ? ` x${entry.count}` : '';
      lines.push(`    E${eIdx}["${icon} ${threatLabel}${countSuffix}"]:::${cls}`);
      eIdx++;
    }
    lines.push('  end');
  }

  lines.push('  classDef sev_crit fill:#7f1d1d,stroke:#ef4444,color:#fecaca');
  lines.push('  classDef sev_high fill:#7c2d12,stroke:#f97316,color:#fed7aa');
  lines.push('  classDef sev_med fill:#78350f,stroke:#f59e0b,color:#fef3c7');
  lines.push('  classDef sev_low fill:#1e3a5f,stroke:#3b82f6,color:#bfdbfe');
  lines.push('  classDef sev_unset fill:#374151,stroke:#9ca3af,color:#e5e7eb');

  return lines.join('\n');
}

