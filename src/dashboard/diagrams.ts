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

/** Truncate long labels and sanitize for Mermaid (strip brackets/braces/pipes that conflict with syntax) */
function label(s: string, max = 40): string {
  const clean = s.replace(/"/g, "'").replace(/[\[\]{}|]/g, '');
  return clean.length > max ? clean.slice(0, max - 1) + '…' : clean;
}

/**
 * Diagram 1: Threat Model Graph
 * Shows assets (boxes), threats (red), controls (green), and relationships.
 */
export function generateThreatGraph(model: ThreatModel): string {
  // Filter to critical+high severity threats to keep diagram readable
  const highSevThreats = new Set<string>();
  const sevMap = new Map<string, string>();
  for (const t of model.threats) {
    const s = (t.severity || '').toLowerCase();
    sevMap.set(`#${t.id}`, s);
    sevMap.set(t.name, s);
    if (s === 'critical' || s === 'p0' || s === 'high' || s === 'p1') {
      highSevThreats.add(`#${t.id}`);
      highSevThreats.add(t.name);
    }
  }

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
    if (filterHigh && !highSevThreats.has(e.threat)) continue;
    usedAssets.add(e.asset);
    usedThreats.add(e.threat);
  }
  for (const m of model.mitigations) {
    if (filterHigh && !highSevThreats.has(m.threat)) continue;
    usedAssets.add(m.asset); usedThreats.add(m.threat);
    if (m.control) usedControls.add(m.control);
  }
  for (const a of model.acceptances) {
    if (filterHigh && !highSevThreats.has(a.threat)) continue;
    usedAssets.add(a.asset); usedThreats.add(a.threat);
  }

  // Asset nodes
  for (const a of usedAssets) {
    lines.push(`  ${mid(a)}["🔷 ${label(a)}"]`);
  }
  // Threat nodes
  for (const t of usedThreats) {
    const sev = sevMap.get(t) || '';
    const icon = sev === 'critical' || sev === 'p0' ? '🔴' : sev === 'high' || sev === 'p1' ? '🟠' : '🟡';
    lines.push(`  ${mid(t)}["${icon} ${label(t.replace('#', ''), 35)}"]:::threat`);
  }
  // Control nodes
  for (const c of usedControls) {
    lines.push(`  ${mid(c)}["🛡️ ${label(c.replace('#', ''))}"]:::control`);
  }

  // Exposure edges (deduplicated)
  for (const e of model.exposures) {
    if (filterHigh && !highSevThreats.has(e.threat)) continue;
    const key = `${mid(e.asset)}->exp->${mid(e.threat)}`;
    if (!edges.has(key)) {
      edges.add(key);
      lines.push(`  ${mid(e.asset)} -. exposed .-> ${mid(e.threat)}`);
    }
  }
  // Mitigation edges
  for (const m of model.mitigations) {
    if (filterHigh && !highSevThreats.has(m.threat)) continue;
    if (m.control) {
      const k1 = `${mid(m.control)}->mit->${mid(m.threat)}`;
      if (!edges.has(k1)) { edges.add(k1); lines.push(`  ${mid(m.control)} -- mitigates --> ${mid(m.threat)}`); }
      const k2 = `${mid(m.control)}->on->${mid(m.asset)}`;
      if (!edges.has(k2)) { edges.add(k2); lines.push(`  ${mid(m.control)} -.- ${mid(m.asset)}`); }
    }
  }
  // Acceptance edges
  for (const a of model.acceptances) {
    if (filterHigh && !highSevThreats.has(a.threat)) continue;
    const key = `${mid(a.asset)}->acc->${mid(a.threat)}`;
    if (!edges.has(key)) { edges.add(key); lines.push(`  ${mid(a.asset)} -- accepts --> ${mid(a.threat)}`); }
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

  const lines: string[] = ['graph LR'];

  // Collect boundary memberships
  const boundaryMembers = new Map<string, Set<string>>();
  for (const b of model.boundaries) {
    const bName = b.id || `${b.asset_a}_${b.asset_b}`;
    if (!boundaryMembers.has(bName)) boundaryMembers.set(bName, new Set());
    boundaryMembers.get(bName)!.add(b.asset_a);
    boundaryMembers.get(bName)!.add(b.asset_b);
  }

  // Emit boundary subgraphs
  const inBoundary = new Set<string>();
  let bIdx = 0;
  for (const [bName, members] of boundaryMembers) {
    const desc = model.boundaries.find(b => (b.id || `${b.asset_a}_${b.asset_b}`) === bName)?.description || bName;
    lines.push(`  subgraph B${bIdx}["🔒 ${label(desc, 50)}"]`);
    for (const m of members) {
      lines.push(`    ${mid(m)}["${label(m)}"]`);
      inBoundary.add(m);
    }
    lines.push('  end');
    bIdx++;
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
      lines.push(`  ${mid(n)}["${label(n)}${suffix}"]`);
    }
  }

  // Flow edges
  for (const f of model.flows) {
    if (f.mechanism) {
      lines.push(`  ${mid(f.source)} -- ${label(f.mechanism, 28)} --> ${mid(f.target)}`);
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

  // Build set of mitigated/accepted
  const resolved = new Set<string>();
  for (const m of model.mitigations) resolved.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) resolved.add(`${a.asset}::${a.threat}`);

  // Group exposures by asset, deduplicate by threat, keep highest severity
  const sevOrder: Record<string, number> = { critical: 0, p0: 0, high: 1, p1: 1, medium: 2, p2: 2, low: 3, p3: 3, unset: 4 };
  const byAsset = new Map<string, Map<string, { threat: string; severity: string; count: number; resolved: boolean }>>();

  for (const e of model.exposures) {
    if (!byAsset.has(e.asset)) byAsset.set(e.asset, new Map());
    const assetMap = byAsset.get(e.asset)!;
    const existing = assetMap.get(e.threat);
    const sev = (e.severity || 'unset').toLowerCase();
    const isResolved = resolved.has(`${e.asset}::${e.threat}`);
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

