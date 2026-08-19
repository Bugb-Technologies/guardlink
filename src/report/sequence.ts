/**
 * GuardLink Report — Mermaid sequence diagram generator.
 * Builds a sequence diagram from @flows annotations showing
 * the step-by-step interactions between system participants.
 *
 * @comment -- "Pure function: transforms ThreatModel flows to Mermaid sequence diagram"
 * @comment -- "Titles itself from filtered_by_features when the model is a --feature slice: a sequence of three participants reads as the system's interactions unless the picture says which slice it is"
 * @flows ThreatModel -> #report via generateSequenceDiagram -- "Sequence diagram generation"
 */

import type { ThreatModel } from '../types/index.js';

/**
 * Feature names this model was narrowed to, or `[]`. Read structurally so an
 * unfiltered model — or one built before the field existed — takes the original
 * path unchanged.
 */
function filteredFeatures(model: ThreatModel): string[] {
  const raw = (model as ThreatModel & { filtered_by_features?: string[] }).filtered_by_features;
  if (!Array.isArray(raw)) return [];
  return raw.filter((n): n is string => typeof n === 'string' && n.trim().length > 0);
}

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

  // @flows FeatureName -> #report via filtered_by_features -- "A @feature name written in source reaches the sequence diagram title"
  // @mitigates #report against #xss using #output-encoding -- "Quote-escaped before entering the YAML frontmatter scalar, and the `:` that would terminate a Note label is stripped below — a feature name is model data, not markup"
  const features = filteredFeatures(model);
  if (features.length > 0) {
    lines.push('---');
    lines.push(`title: "Feature slice — ${features.map(f => f.replace(/"/g, "'")).join(', ')} (not the whole project)"`);
    lines.push('---');
  }

  lines.push('sequenceDiagram');

  if (model.flows.length === 0) {
    // `Note over System` referenced a participant that was never declared, which
    // Mermaid rejects — the "nothing to show" case rendered as a parse error.
    // Declaring it first makes the empty answer readable, and under a filter it
    // says which slice is empty rather than implying the project has no flows.
    lines.push('  participant System');
    lines.push(features.length > 0
      ? `  Note over System: No @flows in feature ${features.map(f => f.replace(/:/g, ' ')).join(', ')}`
      : '  Note over System: No data flows annotated');
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
