/**
 * GuardLink Report — Mermaid diagram generator.
 *
 * Design principles:
 * 1. DFD-style: Show data flows between assets, trust boundaries, and threats
 * 2. Only connected nodes: Assets with no flows/exposures are omitted
 * 3. Controls stay in tables: Don't add control nodes — they clutter the graph
 * 4. Threat markers on edges: Show exposures as red dotted edges, not separate nodes
 * 5. Distinct shapes: Actors (()), Processes [], Data stores [()]
 * 6. Deduplicate: One node per asset, one label per data classification
 * 7. Top-down layout: External → boundary → internal → data
 */

import type { ThreatModel } from '../types/index.js';

/** Sanitize for Mermaid node IDs */
function nid(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_');
}

/** Short display name from dotted path or #id */
function shortName(s: string): string {
  if (s.startsWith('#')) return s.slice(1);
  return s.split('.').pop() || s;
}

/** Escape for Mermaid labels */
function esc(s: string): string {
  return s.replace(/"/g, '#quot;').replace(/\n/g, ' ');
}

/** Truncate */
function trunc(s: string, max = 30): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

export function generateMermaid(model: ThreatModel): string {
  const lines: string[] = [];

  // ── Build mitigation coverage map ──
  const mitigatedPairs = new Set<string>();
  const acceptedPairs = new Set<string>();
  for (const m of model.mitigations) mitigatedPairs.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) acceptedPairs.add(`${a.asset}::${a.threat}`);

  const unmitigatedAssets = new Set<string>();
  const unmitigatedExposures: { asset: string; threat: string; severity?: string }[] = [];
  for (const e of model.exposures) {
    const key = `${e.asset}::${e.threat}`;
    if (!mitigatedPairs.has(key) && !acceptedPairs.has(key)) {
      unmitigatedAssets.add(e.asset);
      unmitigatedExposures.push({ asset: e.asset, threat: e.threat, severity: e.severity });
    }
  }

  // ── Decide rendering mode based on complexity ──
  // High-exposure models (>15 unmitigated) get compact mode: exposure counts on assets, no threat fan-out
  const COMPACT_THRESHOLD = 15;
  const isCompact = unmitigatedExposures.length > COMPACT_THRESHOLD;

  lines.push('graph TD');

  // ── Collect connected assets ──
  const connectedAssets = new Set<string>();
  for (const f of model.flows) {
    connectedAssets.add(f.source);
    connectedAssets.add(f.target);
  }
  for (const e of model.exposures) connectedAssets.add(e.asset);
  for (const t of model.transfers) {
    connectedAssets.add(t.source);
    connectedAssets.add(t.target);
  }
  for (const b of model.boundaries) {
    connectedAssets.add(b.asset_a);
    connectedAssets.add(b.asset_b);
  }
  if (connectedAssets.size === 0) {
    for (const a of model.assets) connectedAssets.add(a.path.join('.'));
  }

  // ── Data classification ──
  const dataClasses = new Map<string, Set<string>>();
  for (const h of model.data_handling) {
    if (!dataClasses.has(h.asset)) dataClasses.set(h.asset, new Set());
    dataClasses.get(h.asset)!.add(h.classification);
  }

  // ── Exposure counts per asset (for compact mode labels) ──
  const assetExposureCounts = new Map<string, { p0: number; p1: number; p2: number; p3: number; total: number }>();
  for (const exp of unmitigatedExposures) {
    if (!assetExposureCounts.has(exp.asset)) {
      assetExposureCounts.set(exp.asset, { p0: 0, p1: 0, p2: 0, p3: 0, total: 0 });
    }
    const c = assetExposureCounts.get(exp.asset)!;
    c.total++;
    const sev = (exp.severity || '').toLowerCase();
    if (sev.includes('p0') || sev.includes('critical')) c.p0++;
    else if (sev.includes('p1') || sev.includes('high')) c.p1++;
    else if (sev.includes('p2') || sev.includes('medium')) c.p2++;
    else c.p3++;
  }

  // ── Group assets by boundary ──
  const boundaryGroups = new Map<string, { label: string; members: Set<string> }>();

  for (const b of model.boundaries) {
    const label = b.description || b.id || `${shortName(b.asset_a)} - ${shortName(b.asset_b)}`;
    const key = b.id || label;
    if (!boundaryGroups.has(key)) {
      boundaryGroups.set(key, { label, members: new Set() });
    }
    const group = boundaryGroups.get(key)!;
    if (connectedAssets.has(b.asset_a)) group.members.add(b.asset_a);
    if (connectedAssets.has(b.asset_b)) group.members.add(b.asset_b);
  }

  // ── Emit boundary subgraphs ──
  const emittedNodes = new Set<string>();

  for (const [, group] of boundaryGroups) {
    if (group.members.size === 0) continue;
    const subId = nid(group.label);
    lines.push(`  subgraph ${subId}["${esc(trunc(group.label, 50))}"]`);
    lines.push(`    direction LR`);
    for (const asset of group.members) {
      emitNode(asset, lines, dataClasses, unmitigatedAssets, isCompact ? assetExposureCounts : undefined);
      emittedNodes.add(asset);
    }
    lines.push('  end');
    lines.push(`  style ${subId} fill:none,stroke:#666,stroke-width:2px,stroke-dasharray:5 5`);
  }

  // ── Emit remaining connected assets ──
  for (const asset of connectedAssets) {
    if (!emittedNodes.has(asset)) {
      emitNode(asset, lines, dataClasses, unmitigatedAssets, isCompact ? assetExposureCounts : undefined);
      emittedNodes.add(asset);
    }
  }

  lines.push('');

  // ── Data flow edges ──
  for (const f of model.flows) {
    if (!connectedAssets.has(f.source) || !connectedAssets.has(f.target)) continue;
    const src = nid(f.source);
    const tgt = nid(f.target);
    const label = f.mechanism ? trunc(f.mechanism, 25) : '';
    if (label) {
      lines.push(`  ${src} -->|"${esc(label)}"| ${tgt}`);
    } else {
      lines.push(`  ${src} --> ${tgt}`);
    }
  }

  // ── Transfer edges (dotted) ──
  for (const t of model.transfers) {
    if (!connectedAssets.has(t.source) || !connectedAssets.has(t.target)) continue;
    const label = t.threat.startsWith('#') ? t.threat.slice(1) : t.threat;
    lines.push(`  ${nid(t.source)} -.->|"${esc(trunc(label))}"| ${nid(t.target)}`);
  }

  // ── Unmitigated threats ──
  const threatTargets = new Map<string, string[]>();
  for (const exp of unmitigatedExposures) {
    const tid = exp.threat.startsWith('#') ? exp.threat.slice(1) : exp.threat;
    if (!threatTargets.has(tid)) threatTargets.set(tid, []);
    threatTargets.get(tid)!.push(exp.asset);
  }

  if (threatTargets.size > 0) {
    lines.push('');

    if (isCompact) {
      // ── COMPACT MODE: Single summary node, no fan-out edges ──
      // Asset labels already contain exposure counts. Just add a summary threat node.
      lines.push('  %% Compact mode — exposure counts embedded in asset labels');
      const p0 = unmitigatedExposures.filter(e => {
        const s = (e.severity || '').toLowerCase();
        return s.includes('p0') || s.includes('critical');
      }).length;
      const summaryLabel = `${unmitigatedExposures.length} unmitigated exposures across ${threatTargets.size} threats`;
      const severityNote = p0 > 0 ? ` — ${p0} critical` : '';
      lines.push(`  _threat_summary{{"⚠ ${esc(summaryLabel + severityNote)}"}}`);

      // Connect summary to most-exposed assets (top 3 only)
      const topAssets = [...assetExposureCounts.entries()]
        .sort((a, b) => b[1].total - a[1].total)
        .slice(0, 3);
      for (const [asset] of topAssets) {
        if (emittedNodes.has(asset)) {
          lines.push(`  _threat_summary -. "see report" .-> ${nid(asset)}`);
        }
      }
    } else {
      // ── NORMAL MODE: Individual threat nodes with edges ──
      lines.push('  %% Unmitigated threats');
      for (const [threat, assets] of threatTargets) {
        const tid = nid(`threat_${threat}`);
        lines.push(`  ${tid}(("⚠ ${esc(trunc(threat, 20))}"))`);
        for (const asset of assets) {
          lines.push(`  ${tid} -. "exposes" .-> ${nid(asset)}`);
        }
      }
    }
  }

  // ── Styling ──
  lines.push('');

  // Red border for unmitigated assets
  for (const a of unmitigatedAssets) {
    if (emittedNodes.has(a)) {
      lines.push(`  style ${nid(a)} stroke:#e74c3c,stroke-width:3px`);
    }
  }

  // Red/orange fill for threat nodes
  if (threatTargets.size > 0) {
    if (isCompact) {
      lines.push(`  style _threat_summary fill:#fce4e4,stroke:#e74c3c,color:#c0392b`);
    } else {
      const tids = [...threatTargets.keys()].map(t => nid(`threat_${t}`));
      lines.push(`  style ${tids.join(',')} fill:#fce4e4,stroke:#e74c3c,color:#c0392b`);
    }
  }

  return lines.join('\n');
}

function emitNode(
  asset: string,
  lines: string[],
  dataClasses: Map<string, Set<string>>,
  unmitigatedAssets: Set<string>,
  exposureCounts?: Map<string, { p0: number; p1: number; p2: number; p3: number; total: number }>,
): void {
  const id = nid(asset);
  const name = shortName(asset);
  const classes = dataClasses.get(asset);

  // Build label
  let label = name;
  if (classes && classes.size > 0) {
    const classStr = [...classes].join(', ');
    label += ` (${classStr})`;
  }

  // In compact mode, append exposure count to label
  if (exposureCounts) {
    const counts = exposureCounts.get(asset);
    if (counts && counts.total > 0) {
      const parts: string[] = [];
      if (counts.p0 > 0) parts.push(`${counts.p0} crit`);
      if (counts.p1 > 0) parts.push(`${counts.p1} high`);
      if (counts.p2 > 0) parts.push(`${counts.p2} med`);
      if (counts.p3 > 0) parts.push(`${counts.p3} low`);
      label += ` | ${parts.join(', ')}`;
    }
  }

  // Choose shape based on naming heuristics
  const lower = name.toLowerCase();
  const isDataStore = /(?:db|database|store|cache|file|credential|config|secret|storage|filesystem)/i.test(lower);
  const isActor = /(?:user|browser|client|external|attacker)/i.test(lower);

  if (isDataStore) {
    lines.push(`  ${id}[("${esc(label)}")]`);
  } else if (isActor) {
    lines.push(`  ${id}(("${esc(label)}"))`);
  } else {
    lines.push(`  ${id}["${esc(label)}"]`);
  }
}
