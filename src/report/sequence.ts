/**
 * GuardLink Report — Mermaid sequence diagram generator.
 * Builds a sequence diagram from @flows annotations showing
 * the step-by-step interactions between system participants.
 *
 * @comment -- "Pure function: transforms ThreatModel flows to Mermaid sequence diagram"
 * @flows ThreatModel -> #report via generateSequenceDiagram -- "Sequence diagram generation"
 */

import type { ThreatModel } from '../types/index.js';

/** Sanitize participant name for Mermaid sequence diagrams */
function participantId(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_');
}

/** Short display name */
function displayName(s: string): string {
  if (s.startsWith('#')) return s.slice(1);
  return s.split('.').pop() || s;
}

/** Escape for Mermaid labels */
function esc(s: string): string {
  return s.replace(/"/g, "'").replace(/\n/g, ' ');
}

/** Truncate */
function trunc(s: string, max = 40): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

export function generateSequenceDiagram(model: ThreatModel): string {
  const lines: string[] = [];
  lines.push('sequenceDiagram');

  if (model.flows.length === 0) {
    lines.push('  Note over System: No data flows annotated');
    return lines.join('\n');
  }

  // Collect all participants in order of first appearance
  const participantOrder: string[] = [];
  const seen = new Set<string>();
  for (const f of model.flows) {
    if (!seen.has(f.source)) {
      seen.add(f.source);
      participantOrder.push(f.source);
    }
    if (!seen.has(f.target)) {
      seen.add(f.target);
      participantOrder.push(f.target);
    }
  }

  // Classify participants for styling
  const assetIds = new Set(model.assets.map(a => a.id || a.path.join('.')));
  const actorPattern = /user|browser|client|external|attacker|customer|operator/i;
  const dataStorePattern = /db|database|store|cache|file|credential|config|secret|storage|filesystem/i;

  // Emit participants with appropriate types
  for (const p of participantOrder) {
    const id = participantId(p);
    const name = displayName(p);
    const lower = name.toLowerCase();

    if (actorPattern.test(lower)) {
      lines.push(`  actor ${id} as ${esc(name)}`);
    } else if (dataStorePattern.test(lower)) {
      lines.push(`  participant ${id} as ${esc(name)} [DB]`);
    } else {
      lines.push(`  participant ${id} as ${esc(name)}`);
    }
  }

  lines.push('');

  // Group flows by chains for better visual grouping
  // First, check if we can identify logical groups from the flow descriptions
  const flowGroups = groupFlowsByContext(model.flows);

  for (const group of flowGroups) {
    // Add activation boxes for flow groups > 1
    if (group.label && flowGroups.length > 1) {
      lines.push(`  rect rgb(240, 248, 255)`);
      lines.push(`  Note right of ${participantId(group.flows[0].source)}: ${esc(trunc(group.label, 30))}`);
    }

    for (const f of group.flows) {
      const src = participantId(f.source);
      const tgt = participantId(f.target);
      const label = f.mechanism
        ? trunc(f.mechanism, 35)
        : f.description
          ? trunc(f.description, 35)
          : '';

      // Use different arrow types
      if (label) {
        lines.push(`  ${src}->>+${tgt}: ${esc(label)}`);
      } else {
        lines.push(`  ${src}->>+${tgt}: data`);
      }

      // Check if there's a return flow (target -> source)
      const returnFlow = model.flows.find(rf =>
        rf.source === f.target && rf.target === f.source && rf !== f,
      );
      if (returnFlow) {
        const retLabel = returnFlow.mechanism
          ? trunc(returnFlow.mechanism, 35)
          : returnFlow.description
            ? trunc(returnFlow.description, 35)
            : 'response';
        lines.push(`  ${tgt}-->>-${src}: ${esc(retLabel)}`);
      } else {
        lines.push(`  deactivate ${tgt}`);
      }
    }

    if (group.label && flowGroups.length > 1) {
      lines.push(`  end`);
    }
  }

  return lines.join('\n');
}

interface FlowGroup {
  label: string;
  flows: ThreatModel['flows'];
}

/** Group related flows together for visual clarity */
function groupFlowsByContext(flows: ThreatModel['flows']): FlowGroup[] {
  // Try to group flows that share the same source or form a chain
  if (flows.length <= 5) {
    // Small number of flows — just one group
    return [{ label: '', flows }];
  }

  // Group by starting source (external entity)
  const allTargets = new Set(flows.map(f => f.target));
  const bySource = new Map<string, typeof flows>();

  for (const f of flows) {
    // Find root source for this flow
    const root = !allTargets.has(f.source) ? f.source : f.source;
    if (!bySource.has(root)) bySource.set(root, []);
    bySource.get(root)!.push(f);
  }

  // If grouping resulted in reasonable groups, use them
  const groups: FlowGroup[] = [];
  for (const [source, groupFlows] of bySource) {
    if (groupFlows.length > 0) {
      groups.push({
        label: displayName(source),
        flows: groupFlows,
      });
    }
  }

  return groups.length > 1 ? groups : [{ label: '', flows }];
}
