/**
 * GuardLink Report — Markdown report generator.
 * Produces a human-readable threat model report with
 * embedded Mermaid diagram, finding tables, and coverage stats.
 *
 * @comment -- "Pure function: transforms ThreatModel to markdown string"
 * @comment -- "No file I/O; caller (CLI/MCP) handles write"
 * @flows ThreatModel -> #report via generateReport -- "Model input"
 * @flows #report -> Markdown via return -- "Report output"
 */

import type { ThreatModel, ThreatModelExposure, Severity } from '../types/index.js';
import { generateMermaid } from './mermaid.js';
import { generateSequenceDiagram } from './sequence.js';

export function generateReport(model: ThreatModel): string {
  const lines: string[] = [];

  // ── Pre-compute shared data ──
  const mitigatedPairs = new Set<string>();
  const acceptedPairs = new Set<string>();
  for (const m of model.mitigations) mitigatedPairs.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) acceptedPairs.add(`${a.asset}::${a.threat}`);

  const unmitigated = model.exposures.filter(e => {
    const key = `${e.asset}::${e.threat}`;
    return !mitigatedPairs.has(key) && !acceptedPairs.has(key);
  });

  const severityCounts = countBySeverity(unmitigated);
  const hasAI = detectAI(model);

  // ── Header ──
  lines.push(`# Threat Model Report — ${model.project}`);
  lines.push('');
  lines.push(`> Generated: ${model.generated_at}  `);
  lines.push(`> Files scanned: ${model.source_files} | Annotations: ${model.annotations_parsed}`);
  if (model.metadata?.guardlink_version) {
    lines.push(`> GuardLink version: ${model.metadata.guardlink_version}`);
  }
  if (model.metadata?.commit_sha) {
    lines.push(`> Commit: ${model.metadata.commit_sha}${model.metadata.branch ? ` (${model.metadata.branch})` : ''}`);
  }
  lines.push('');

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 1: Application Overview
  // ══════════════════════════════════════════════════════════════════════
  lines.push('## Application Overview');
  lines.push('');
  emitApplicationOverview(model, unmitigated, severityCounts, hasAI, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 2: Scope
  // ══════════════════════════════════════════════════════════════════════
  lines.push('## Scope of This Threat Model');
  lines.push('');
  emitScope(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 3: Architecture
  // ══════════════════════════════════════════════════════════════════════
  lines.push('## Architecture');
  lines.push('');
  emitArchitecture(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 4: Key Flows & Sequence
  // ══════════════════════════════════════════════════════════════════════
  if (model.flows.length > 0) {
    lines.push('## Key Flows & Sequence');
    lines.push('');
    emitKeyFlows(model, lines);
  }

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 5: Data Inventory
  // ══════════════════════════════════════════════════════════════════════
  if (model.data_handling.length > 0 || model.assets.length > 0) {
    lines.push('## Data Inventory');
    lines.push('');
    emitDataInventory(model, hasAI, lines);
  }

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 6: Roles & Access
  // ══════════════════════════════════════════════════════════════════════
  lines.push('## Roles & Access');
  lines.push('');
  emitRolesAccess(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 7: Dependencies
  // ══════════════════════════════════════════════════════════════════════
  lines.push('## Dependencies');
  lines.push('');
  emitDependencies(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 8: Secrets, Keys & Credential Management
  // ══════════════════════════════════════════════════════════════════════
  lines.push('## Secrets, Keys & Credential Management');
  lines.push('');
  emitSecretsManagement(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 9: Logging, Monitoring & Audit
  // ══════════════════════════════════════════════════════════════════════
  lines.push('## Logging, Monitoring & Audit');
  lines.push('');
  emitLoggingAudit(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 10: AI/ML System Details (conditional)
  // ══════════════════════════════════════════════════════════════════════
  if (hasAI) {
    lines.push('## AI/ML System Details');
    lines.push('');
    emitAIDetails(model, lines);
  }

  // ══════════════════════════════════════════════════════════════════════
  // EXISTING SECTIONS: Executive Summary + Findings
  // ══════════════════════════════════════════════════════════════════════

  // ── Executive Summary ──
  lines.push('## Executive Summary');
  lines.push('');

  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Assets | ${model.assets.length} |`);
  lines.push(`| Threats defined | ${model.threats.length} |`);
  lines.push(`| Controls defined | ${model.controls.length} |`);
  lines.push(`| Active mitigations | ${model.mitigations.length} |`);
  lines.push(`| Accepted risks | ${model.acceptances.length} |`);
  lines.push(`| **Unmitigated exposures** | **${unmitigated.length}** |`);
  if ((model.confirmed || []).length > 0) lines.push(`| **🔴 Confirmed exploitable** | **${model.confirmed.length}** |`);
  if (severityCounts.critical > 0) lines.push(`| ↳ Critical (P0) | ${severityCounts.critical} |`);
  if (severityCounts.high > 0) lines.push(`| ↳ High (P1) | ${severityCounts.high} |`);
  if (severityCounts.medium > 0) lines.push(`| ↳ Medium (P2) | ${severityCounts.medium} |`);
  if (severityCounts.low > 0) lines.push(`| ↳ Low (P3) | ${severityCounts.low} |`);
  lines.push(`| Data flows | ${model.flows.length} |`);
  lines.push(`| Trust boundaries | ${model.boundaries.length} |`);
  lines.push(`| Risk transfers | ${model.transfers.length} |`);
  lines.push(`| Validations | ${model.validations.length} |`);
  lines.push(`| Ownership records | ${model.ownership.length} |`);
  if (model.shields.length > 0) lines.push(`| Shielded regions | ${model.shields.length} |`);
  lines.push('');

  // ── Threat Model Diagram ──
  lines.push('## Threat Model Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push(generateMermaid(model));
  lines.push('```');
  lines.push('');

  // ── Unmitigated Exposures ──
  if (unmitigated.length > 0) {
    lines.push('## Unmitigated Exposures');
    lines.push('');
    lines.push('These exposures have no matching `@mitigates` or `@accepts` and require attention.');
    lines.push('');
    lines.push('| Severity | Asset | Threat | Description | Location |');
    lines.push('|----------|-------|--------|-------------|----------|');
    for (const e of sortBySeverity(unmitigated)) {
      const sev = severityBadge(e.severity);
      const desc = e.description ? truncate(e.description, 60) : '—';
      const loc = `${e.location.file}:${e.location.line}`;
      lines.push(`| ${sev} | ${e.asset} | ${e.threat} | ${desc} | ${loc} |`);
    }
    lines.push('');
  }

  // ── Confirmed Exploitable ──
  if ((model.confirmed || []).length > 0) {
    lines.push('## 🔴 Confirmed Exploitable');
    lines.push('');
    lines.push('These threats have been verified through testing — **not false positives**. Immediate remediation required.');
    lines.push('');
    lines.push('| Severity | Asset | Threat | Evidence | Location |');
    lines.push('|----------|-------|--------|----------|----------|');
    for (const c of model.confirmed) {
      const sev = severityBadge(c.severity);
      const desc = c.description ? truncate(c.description, 60) : '—';
      lines.push(`| ${sev} | ${c.asset} | ${c.threat} | ${desc} | ${c.location.file}:${c.location.line} |`);
    }
    lines.push('');
  }

  // ── Accepted Risks ──
  if (model.acceptances.length > 0) {
    lines.push('## Accepted Risks');
    lines.push('');
    lines.push('| Asset | Threat | Rationale | Location |');
    lines.push('|-------|--------|-----------|----------|');
    for (const a of model.acceptances) {
      const desc = a.description ? truncate(a.description, 60) : '—';
      lines.push(`| ${a.asset} | ${a.threat} | ${desc} | ${a.location.file}:${a.location.line} |`);
    }
    lines.push('');
  }

  // ── Active Mitigations ──
  if (model.mitigations.length > 0) {
    lines.push('## Active Mitigations');
    lines.push('');
    lines.push('| Asset | Threat | Control | Description | Location |');
    lines.push('|-------|--------|---------|-------------|----------|');
    for (const m of model.mitigations) {
      const desc = m.description ? truncate(m.description, 50) : '—';
      const ctrl = m.control || '—';
      lines.push(`| ${m.asset} | ${m.threat} | ${ctrl} | ${desc} | ${m.location.file}:${m.location.line} |`);
    }
    lines.push('');
  }

  // ── Trust Boundaries ──
  if (model.boundaries.length > 0) {
    lines.push('## Trust Boundaries');
    lines.push('');
    lines.push('| Side A | Side B | Boundary ID | Description | Location |');
    lines.push('|--------|--------|-------------|-------------|----------|');
    for (const b of model.boundaries) {
      const desc = b.description ? truncate(b.description, 50) : '—';
      const id = b.id || '—';
      lines.push(`| ${b.asset_a} | ${b.asset_b} | ${id} | ${desc} | ${b.location.file}:${b.location.line} |`);
    }
    lines.push('');
  }

  // ── Data Flows ──
  if (model.flows.length > 0) {
    lines.push('## Data Flows');
    lines.push('');
    lines.push('| Source | Target | Mechanism | Description |');
    lines.push('|--------|--------|-----------|-------------|');
    for (const f of model.flows) {
      const mech = f.mechanism || '—';
      const desc = f.description ? truncate(f.description, 50) : '—';
      lines.push(`| ${f.source} | ${f.target} | ${mech} | ${desc} |`);
    }
    lines.push('');
  }

  // ── Data Handling ──
  if (model.data_handling.length > 0) {
    lines.push('## Data Classification');
    lines.push('');
    lines.push('| Asset | Classification | Description |');
    lines.push('|-------|---------------|-------------|');
    for (const h of model.data_handling) {
      const desc = h.description ? truncate(h.description, 60) : '—';
      lines.push(`| ${h.asset} | ${classificationBadge(h.classification)} | ${desc} |`);
    }
    lines.push('');
  }

  // ── Risk Transfers ──
  if (model.transfers.length > 0) {
    lines.push('## Risk Transfers');
    lines.push('');
    lines.push('| Source | Threat | Target | Description | Location |');
    lines.push('|--------|--------|--------|-------------|----------|');
    for (const t of model.transfers) {
      const desc = t.description ? truncate(t.description, 50) : '—';
      lines.push(`| ${t.source} | ${t.threat} | ${t.target} | ${desc} | ${t.location.file}:${t.location.line} |`);
    }
    lines.push('');
  }

  // ── Validations ──
  if (model.validations.length > 0) {
    lines.push('## Validations');
    lines.push('');
    lines.push('| Control | Asset | Description | Location |');
    lines.push('|---------|-------|-------------|----------|');
    for (const v of model.validations) {
      const desc = v.description ? truncate(v.description, 50) : '—';
      lines.push(`| ${v.control} | ${v.asset} | ${desc} | ${v.location.file}:${v.location.line} |`);
    }
    lines.push('');
  }

  // ── Ownership ──
  if (model.ownership.length > 0) {
    lines.push('## Ownership');
    lines.push('');
    for (const o of model.ownership) {
      const desc = o.description ? ` — ${o.description}` : '';
      lines.push(`- **${o.asset}** owned by **${o.owner}**${desc} (${o.location.file}:${o.location.line})`);
    }
    lines.push('');
  }

  // ── Audit Items ──
  if (model.audits.length > 0) {
    lines.push('## Audit Items');
    lines.push('');
    for (const a of model.audits) {
      const desc = a.description || 'Needs review';
      lines.push(`- **${a.asset}** — ${desc} (${a.location.file}:${a.location.line})`);
    }
    lines.push('');
  }

  // ── Assumptions ──
  if (model.assumptions.length > 0) {
    lines.push('## Assumptions');
    lines.push('');
    lines.push('These are unverified assumptions that should be periodically reviewed.');
    lines.push('');
    for (const a of model.assumptions) {
      const desc = a.description || 'Unverified assumption';
      lines.push(`- **${a.asset}** — ${desc} (${a.location.file}:${a.location.line})`);
    }
    lines.push('');
  }

  // ── Shielded Regions ──
  if (model.shields.length > 0) {
    lines.push('## Shielded Regions');
    lines.push('');
    lines.push('Code regions where annotations are intentionally suppressed via `@shield`.');
    lines.push('');
    for (const s of model.shields) {
      const reason = s.reason || 'No reason provided';
      lines.push(`- ${reason} (${s.location.file}:${s.location.line})`);
    }
    lines.push('');
  }

  // ── Features ──
  if (model.features.length > 0) {
    const uniqueFeatures = new Map<string, { name: string; files: Set<string>; description?: string }>();
    for (const f of model.features) {
      const key = f.feature.toLowerCase();
      if (!uniqueFeatures.has(key)) {
        uniqueFeatures.set(key, { name: f.feature, files: new Set(), description: f.description });
      }
      uniqueFeatures.get(key)!.files.add(f.location.file);
    }
    lines.push('## Feature Tags');
    lines.push('');
    lines.push('Annotations are tagged with the following features via `@feature`.');
    lines.push('');
    lines.push('| Feature | Files | Description |');
    lines.push('|---------|-------|-------------|');
    for (const [, entry] of [...uniqueFeatures.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name))) {
      const desc = entry.description ? truncate(entry.description, 60) : '—';
      lines.push(`| ${entry.name} | ${entry.files.size} | ${desc} |`);
    }
    lines.push('');
  }

  // ── Developer Comments ──
  if (model.comments.length > 0) {
    lines.push('## Developer Comments');
    lines.push('');
    lines.push('Security-relevant notes left by developers via `@comment`.');
    lines.push('');
    for (const c of model.comments) {
      const desc = c.description || 'No description';
      lines.push(`- ${desc} (${c.location.file}:${c.location.line})`);
    }
    lines.push('');
  }

  // ── Footer ──
  lines.push('---');
  lines.push(`*Generated from security annotations on ${model.generated_at}.*`);

  return lines.join('\n');
}

// ═══════════════════════════════════════════════════════════════════════
// New Section Emitters
// ═══════════════════════════════════════════════════════════════════════

function emitApplicationOverview(
  model: ThreatModel,
  unmitigated: ThreatModelExposure[],
  severityCounts: { critical: number; high: number; medium: number; low: number },
  hasAI: boolean,
  lines: string[],
): void {
  // If user provided a project description via .guardlink/prompt.md, use it
  if (model.prompt) {
    lines.push(model.prompt);
    lines.push('');
  } else {
    // Fallback: derive overview from annotations
    const topLevelGroups = new Map<string, string[]>();
    for (const a of model.assets) {
      const group = a.path[0] || 'Unknown';
      if (!topLevelGroups.has(group)) topLevelGroups.set(group, []);
      topLevelGroups.get(group)!.push(a.path.slice(1).join('.') || a.path[0]);
    }

    lines.push(`**${model.project}** is composed of **${model.assets.length} assets** across **${model.source_files} source files** ` +
      `with **${model.annotations_parsed} security annotations**.`);
    lines.push('');

    if (topLevelGroups.size > 0) {
      lines.push('**Component groups:**');
      lines.push('');
      for (const [group, members] of topLevelGroups) {
        lines.push(`- **${group}**: ${members.join(', ')}`);
      }
      lines.push('');
    }
  }

  // Risk posture summary — always shown
  const totalExposures = model.exposures.length;
  const mitigatedCount = model.mitigations.length;
  const acceptedCount = model.acceptances.length;
  const coveragePct = totalExposures > 0
    ? Math.round(((mitigatedCount + acceptedCount) / totalExposures) * 100)
    : 100;

  lines.push('**Risk posture at a glance:**');
  lines.push('');
  lines.push(`| Indicator | Value |`);
  lines.push(`|-----------|-------|`);
  lines.push(`| Exposure coverage | ${coveragePct}% addressed (${mitigatedCount} mitigated, ${acceptedCount} accepted) |`);
  lines.push(`| Unmitigated exposures | ${unmitigated.length} (${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium, ${severityCounts.low} low) |`);
  lines.push(`| Trust boundaries | ${model.boundaries.length} |`);
  lines.push(`| Data flows tracked | ${model.flows.length} |`);
  if (hasAI) lines.push(`| AI/ML components | Yes |`);
  lines.push('');
}

function emitScope(model: ThreatModel, lines: string[]): void {
  // Scope intro — summarize what's modeled based on annotations
  const annotatedCount = model.annotated_files.length;
  const totalFiles = model.source_files;
  const assetCount = model.assets.length;
  const threatCount = model.threats.length;
  lines.push(`This threat model covers **${assetCount} assets** and **${threatCount} threat categories** ` +
    `derived from **${model.annotations_parsed} annotations** across **${annotatedCount}** of **${totalFiles}** source files.`);
  lines.push('');

  // What's in scope: annotated files / assets / threat categories
  const threatCategories = [...new Set(model.threats.map(t => t.canonical_name || t.name))];
  const assetNames = model.assets.map(a => a.id ? `\`${a.id}\`` : `\`${a.path.join('.')}\``);

  lines.push('### Assets in Scope');
  lines.push('');
  if (assetNames.length > 0) {
    for (const name of assetNames) {
      const asset = model.assets.find(a => (a.id ? `\`${a.id}\`` : `\`${a.path.join('.')}\``) === name);
      const desc = asset?.description ? ` — ${truncate(asset.description, 80)}` : '';
      lines.push(`- ${name}${desc}`);
    }
  } else {
    lines.push('_No explicit assets defined. Consider adding `@asset` definitions._');
  }
  lines.push('');

  lines.push('### Threat Categories Addressed');
  lines.push('');
  if (threatCategories.length > 0) {
    const severityMap = new Map<string, string>();
    for (const t of model.threats) {
      severityMap.set(t.canonical_name || t.name, t.severity || 'unset');
    }
    for (const cat of threatCategories) {
      const sev = severityMap.get(cat) || 'unset';
      lines.push(`- **${cat}** (${sev})`);
    }
  } else {
    lines.push('_No explicit threats defined._');
  }
  lines.push('');

  // Coverage gaps
  lines.push('### Coverage');
  lines.push('');
  const covAnnotated = model.annotated_files.length;
  const covTotal = model.source_files;
  const unannotatedCount = model.unannotated_files.length;
  lines.push(`- **${covAnnotated}** of **${covTotal}** files have security annotations (${covTotal > 0 ? Math.round((covAnnotated / covTotal) * 100) : 0}%)`);
  if (unannotatedCount > 0) {
    lines.push(`- **${unannotatedCount}** files have no annotations`);
  }
  if (model.coverage.unannotated_critical.length > 0) {
    lines.push(`- **${model.coverage.unannotated_critical.length}** unannotated security-critical symbols detected:`);
    for (const sym of model.coverage.unannotated_critical.slice(0, 10)) {
      lines.push(`  - \`${sym.name}\` (${sym.kind}) at ${sym.file}:${sym.line}`);
    }
    if (model.coverage.unannotated_critical.length > 10) {
      lines.push(`  - ... and ${model.coverage.unannotated_critical.length - 10} more`);
    }
  }
  lines.push('');
}

function emitArchitecture(model: ThreatModel, lines: string[]): void {
  // ── Components ──
  lines.push('### Components');
  lines.push('');
  if (model.assets.length > 0) {
    lines.push('| Component | ID | Description | Defined At |');
    lines.push('|-----------|-----|-------------|------------|');
    for (const a of model.assets) {
      const name = a.path.join('.');
      const id = a.id || '—';
      const desc = a.description ? truncate(a.description, 50) : '—';
      lines.push(`| ${name} | ${id} | ${desc} | ${a.location.file}:${a.location.line} |`);
    }
  } else {
    lines.push('_No components defined via `@asset`._');
  }
  lines.push('');

  // ── Entrypoints ──
  lines.push('### Entrypoints');
  lines.push('');
  // Build asset name set matching both "#id" and "id" forms
  const assetNames = new Set<string>();
  for (const a of model.assets) {
    const id = a.id || a.path.join('.');
    assetNames.add(id);
    assetNames.add(`#${id}`);
    assetNames.add(a.path.join('.'));
    assetNames.add(`#${a.path.join('.')}`);
  }

  const flowTargets = new Set(model.flows.map(f => f.target));
  const flowSources = new Set(model.flows.map(f => f.source));

  // External sources: flow sources that are NOT defined assets
  const externalSources = new Set<string>();
  for (const src of flowSources) {
    if (!assetNames.has(src)) externalSources.add(src);
  }

  // Entrypoints: assets that receive flows from external sources
  const entrypoints = new Set<string>();
  for (const f of model.flows) {
    if (externalSources.has(f.source) && assetNames.has(f.target)) {
      entrypoints.add(f.target);
    }
  }

  // Also: assets that appear in exposures but not as flow targets from internal sources
  if (entrypoints.size === 0) {
    // Fallback: assets with exposures are likely entrypoints
    for (const e of model.exposures) {
      if (assetNames.has(e.asset)) entrypoints.add(e.asset);
    }
  }

  if (entrypoints.size > 0) {
    lines.push('Assets receiving external input:');
    lines.push('');
    for (const ep of entrypoints) {
      const incomingFlows = model.flows.filter(f => f.target === ep && externalSources.has(f.source));
      const mechanisms = incomingFlows.map(f => `${f.source} via ${f.mechanism || 'unspecified'}`).join(', ');
      lines.push(`- **${ep}**${mechanisms ? `: ${mechanisms}` : ''}`);
    }
  } else {
    lines.push('_No explicit entrypoints identified. Add `@flows` from external sources to assets._');
  }
  lines.push('');

  // ── Callers (external entities) ──
  if (externalSources.size > 0) {
    lines.push('### External Callers');
    lines.push('');
    for (const src of externalSources) {
      const targets = model.flows.filter(f => f.source === src).map(f => f.target);
      lines.push(`- **${src}** → ${[...new Set(targets)].join(', ')}`);
    }
    lines.push('');
  }

  // ── Architecture Diagram ──
  lines.push('### Architecture Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push(generateMermaid(model));
  lines.push('```');
  lines.push('');

  // ── Trust Boundaries / Network Zones ──
  if (model.boundaries.length > 0) {
    lines.push('### Network Zones & Trust Boundaries');
    lines.push('');
    for (const b of model.boundaries) {
      const desc = b.description || b.id || 'Unnamed boundary';
      lines.push(`- **${desc}**: ${shortName(b.asset_a)} ↔ ${shortName(b.asset_b)}`);
    }
    lines.push('');
  }

  // ── Multi-tenancy ──
  lines.push('### Multi-tenancy');
  lines.push('');
  const tenantAnnotations = [
    ...model.comments.filter(c => /tenant|multi.?tenant|isolat/i.test(c.description || '')),
    ...model.assumptions.filter(a => /tenant|multi.?tenant|isolat/i.test(a.description || '')),
  ];
  if (tenantAnnotations.length > 0) {
    for (const a of tenantAnnotations) {
      lines.push(`- ${a.description} (${a.location.file}:${a.location.line})`);
    }
  } else {
    lines.push('_No multi-tenancy annotations found. If this is a multi-tenant application, consider adding `@comment` or `@boundary` annotations describing tenant isolation._');
  }
  lines.push('');

  // ── Compliance ──
  lines.push('### Compliance');
  lines.push('');
  const complianceAnnotations = [
    ...model.comments.filter(c => /complian|gdpr|hipaa|soc|pci|iso|fedramp|ccpa/i.test(c.description || '')),
    ...model.assumptions.filter(a => /complian|gdpr|hipaa|soc|pci|iso|fedramp|ccpa/i.test(a.description || '')),
  ];
  const hasPII = model.data_handling.some(h => h.classification === 'pii');
  const hasPHI = model.data_handling.some(h => h.classification === 'phi');
  const hasFinancial = model.data_handling.some(h => h.classification === 'financial');

  if (complianceAnnotations.length > 0) {
    for (const a of complianceAnnotations) {
      lines.push(`- ${a.description} (${a.location.file}:${a.location.line})`);
    }
  }
  if (hasPII) lines.push('- Handles **PII** — consider GDPR, CCPA compliance requirements');
  if (hasPHI) lines.push('- Handles **PHI** — consider HIPAA compliance requirements');
  if (hasFinancial) lines.push('- Handles **Financial data** — consider PCI-DSS compliance requirements');
  if (complianceAnnotations.length === 0 && !hasPII && !hasPHI && !hasFinancial) {
    lines.push('_No compliance-related annotations found._');
  }
  lines.push('');
}

function emitKeyFlows(model: ThreatModel, lines: string[]): void {
  // Group flows into chains (sequences of connected flows)
  const chains = buildFlowChains(model.flows);

  // Emit sequence diagram
  lines.push('### Sequence Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push(generateSequenceDiagram(model));
  lines.push('```');
  lines.push('');

  // Emit step-by-step for each chain
  lines.push('### Flow Details');
  lines.push('');
  let chainIdx = 0;
  for (const chain of chains) {
    chainIdx++;
    lines.push(`**Flow ${chainIdx}:** ${chain[0].source} → ${chain[chain.length - 1].target}`);
    lines.push('');
    let step = 0;
    for (const f of chain) {
      step++;
      const mech = f.mechanism ? ` via **${f.mechanism}**` : '';
      const desc = f.description ? ` — ${f.description}` : '';
      lines.push(`${step}. **${f.source}** → **${f.target}**${mech}${desc}`);
    }
    lines.push('');
  }
}

function emitDataInventory(model: ThreatModel, hasAI: boolean, lines: string[]): void {
  // ── Data Types ──
  if (model.data_handling.length > 0) {
    lines.push('### Data Types');
    lines.push('');
    const byClassification = new Map<string, string[]>();
    for (const h of model.data_handling) {
      if (!byClassification.has(h.classification)) byClassification.set(h.classification, []);
      byClassification.get(h.classification)!.push(`${h.asset}${h.description ? ` (${truncate(h.description, 40)})` : ''}`);
    }
    for (const [cls, items] of byClassification) {
      lines.push(`**${classificationBadge(cls)}:**`);
      for (const item of items) {
        lines.push(`- ${item}`);
      }
      lines.push('');
    }
  }

  // ── Top Data Assets ──
  lines.push('### Top Data Assets');
  lines.push('');
  // Assets that handle the most data flows
  const assetFlowCount = new Map<string, number>();
  for (const f of model.flows) {
    assetFlowCount.set(f.target, (assetFlowCount.get(f.target) || 0) + 1);
    assetFlowCount.set(f.source, (assetFlowCount.get(f.source) || 0) + 1);
  }
  const topDataAssets = [...assetFlowCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  if (topDataAssets.length > 0) {
    lines.push('Assets by data flow volume:');
    lines.push('');
    lines.push('| Asset | Data Flows | Classifications |');
    lines.push('|-------|-----------|-----------------|');
    for (const [asset, count] of topDataAssets) {
      const classes = model.data_handling
        .filter(h => h.asset === asset)
        .map(h => h.classification)
        .join(', ') || '—';
      lines.push(`| ${asset} | ${count} | ${classes} |`);
    }
    lines.push('');
  } else {
    lines.push('_No data flow volume data available._');
    lines.push('');
  }

  // ── AI-Specific Data Questions ──
  if (hasAI) {
    lines.push('### AI-Specific Data Considerations');
    lines.push('');
    const aiFlows = model.flows.filter(f =>
      isAIRelated(f.source) || isAIRelated(f.target),
    );
    const aiHandling = model.data_handling.filter(h => isAIRelated(h.asset));
    const aiComments = model.comments.filter(c =>
      /prompt|model|train|inference|embed|token|llm|ai|ml/i.test(c.description || ''),
    );

    if (aiFlows.length > 0) {
      lines.push('**Data flowing to/from AI components:**');
      lines.push('');
      for (const f of aiFlows) {
        lines.push(`- ${f.source} → ${f.target} via ${f.mechanism || 'unspecified'}${f.description ? ` — ${f.description}` : ''}`);
      }
      lines.push('');
    }

    if (aiHandling.length > 0) {
      lines.push('**Data classifications on AI components:**');
      lines.push('');
      for (const h of aiHandling) {
        lines.push(`- ${h.asset}: ${classificationBadge(h.classification)}${h.description ? ` — ${h.description}` : ''}`);
      }
      lines.push('');
    }

    if (aiComments.length > 0) {
      lines.push('**AI-related notes:**');
      lines.push('');
      for (const c of aiComments) {
        lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
      }
      lines.push('');
    }

    // Checklist
    lines.push('**AI data checklist:**');
    lines.push('');
    lines.push('- [ ] Are prompts logged? If so, is PII scrubbed?');
    lines.push('- [ ] Is user data used for training/fine-tuning?');
    lines.push('- [ ] What is the data retention policy for AI inputs/outputs?');
    lines.push('- [ ] Are embeddings stored? Can they be reversed to recover source data?');
    lines.push('');
  }
}

function emitRolesAccess(model: ThreatModel, lines: string[]): void {
  // ── Owners / Internal Actors ──
  if (model.ownership.length > 0) {
    lines.push('### Ownership & Internal Actors');
    lines.push('');
    const byOwner = new Map<string, string[]>();
    for (const o of model.ownership) {
      if (!byOwner.has(o.owner)) byOwner.set(o.owner, []);
      byOwner.get(o.owner)!.push(o.asset);
    }
    for (const [owner, assets] of byOwner) {
      lines.push(`- **${owner}**: ${assets.join(', ')}`);
    }
    lines.push('');
  }

  // ── Actors from flows ──
  const actors = new Set<string>();
  const actorPattern = /user|admin|client|browser|operator|attacker|customer|tenant|role/i;
  for (const f of model.flows) {
    if (actorPattern.test(f.source)) actors.add(f.source);
    if (actorPattern.test(f.target)) actors.add(f.target);
  }
  // Also check assets for actor-like patterns
  for (const a of model.assets) {
    const name = a.path.join('.');
    if (actorPattern.test(name)) actors.add(a.id || name);
  }

  if (actors.size > 0) {
    lines.push('### Customer / External Roles');
    lines.push('');
    for (const actor of actors) {
      const flows = model.flows.filter(f => f.source === actor || f.target === actor);
      const interacts = [...new Set(flows.map(f => f.source === actor ? f.target : f.source))];
      lines.push(`- **${actor}** interacts with: ${interacts.join(', ') || '—'}`);
    }
    lines.push('');
  }

  // ── Cross-Tenant Gut Check ──
  lines.push('### Cross-Tenant Gut Check');
  lines.push('');
  const boundaryCount = model.boundaries.length;
  const hasTenantBoundaries = model.boundaries.some(b =>
    /tenant|isolat/i.test(b.description || '') || /tenant|isolat/i.test(b.id || ''),
  );
  if (hasTenantBoundaries) {
    lines.push('Tenant isolation boundaries are defined:');
    lines.push('');
    for (const b of model.boundaries.filter(b => /tenant|isolat/i.test(b.description || '') || /tenant|isolat/i.test(b.id || ''))) {
      lines.push(`- ${b.description || b.id} (${b.asset_a} ↔ ${b.asset_b})`);
    }
  } else if (boundaryCount > 0) {
    lines.push(`${boundaryCount} trust boundaries defined, but none explicitly mention tenant isolation. If this is multi-tenant, verify that cross-tenant data access is prevented at each boundary.`);
  } else {
    lines.push('_No trust boundaries defined. If multi-tenant, add `@boundary` annotations to document tenant isolation._');
  }
  lines.push('');
}

function emitDependencies(model: ThreatModel, lines: string[]): void {
  // Build asset ID set that matches both "#id" and "id" forms used in flows
  const assetIds = new Set<string>();
  for (const a of model.assets) {
    const id = a.id || a.path.join('.');
    assetIds.add(id);
    assetIds.add(`#${id}`);
    // Also add the dotted path form
    const path = a.path.join('.');
    assetIds.add(path);
    assetIds.add(`#${path}`);
  }

  // ── Internal services: assets that are flow targets from other assets ──
  lines.push('### Internal Services');
  lines.push('');
  const internalDeps = new Set<string>();
  for (const f of model.flows) {
    if (assetIds.has(f.source) && assetIds.has(f.target) && f.source !== f.target) {
      internalDeps.add(`${f.source} → ${f.target}`);
    }
  }
  if (internalDeps.size > 0) {
    for (const dep of internalDeps) {
      lines.push(`- ${dep}`);
    }
  } else {
    lines.push('_No internal service dependencies detected from flows._');
  }
  lines.push('');

  // ── External / Cloud / AI Vendors ──
  lines.push('### External & Cloud Dependencies');
  lines.push('');
  const externalNodes = new Set<string>();
  for (const f of model.flows) {
    if (!assetIds.has(f.source)) externalNodes.add(f.source);
    if (!assetIds.has(f.target)) externalNodes.add(f.target);
  }
  // Also from transfers
  for (const t of model.transfers) {
    if (!assetIds.has(t.target)) externalNodes.add(t.target);
    if (!assetIds.has(t.source)) externalNodes.add(t.source);
  }
  // Also external_refs
  if (model.external_refs) {
    for (const ref of model.external_refs) {
      if (ref.inferred_repo) externalNodes.add(ref.inferred_repo);
    }
  }

  if (externalNodes.size > 0) {
    const aiVendors: string[] = [];
    const cloudVendors: string[] = [];
    const otherVendors: string[] = [];
    for (const node of externalNodes) {
      if (isAIRelated(node)) {
        aiVendors.push(node);
      } else if (/aws|gcp|azure|cloud|s3|lambda|cdn|redis|postgres|mysql|mongo|kafka|rabbit|elastic/i.test(node)) {
        cloudVendors.push(node);
      } else {
        otherVendors.push(node);
      }
    }
    if (aiVendors.length > 0) {
      lines.push('**AI/ML Vendors:**');
      for (const v of aiVendors) lines.push(`- ${v}`);
      lines.push('');
    }
    if (cloudVendors.length > 0) {
      lines.push('**Cloud/Infrastructure:**');
      for (const v of cloudVendors) lines.push(`- ${v}`);
      lines.push('');
    }
    if (otherVendors.length > 0) {
      lines.push('**Other External:**');
      for (const v of otherVendors) lines.push(`- ${v}`);
      lines.push('');
    }
  } else {
    lines.push('_No external dependencies detected from flows or transfers._');
    lines.push('');
  }

  // Risk transfers to external parties
  if (model.transfers.length > 0) {
    lines.push('### Risk Transfers to Dependencies');
    lines.push('');
    for (const t of model.transfers) {
      lines.push(`- **${t.threat}** transferred from ${t.source} → ${t.target}${t.description ? ` — ${t.description}` : ''}`);
    }
    lines.push('');
  }
}

function emitSecretsManagement(model: ThreatModel, lines: string[]): void {
  // ── Secret Inventory ──
  const secretHandling = model.data_handling.filter(h => h.classification === 'secrets');
  const keyExposures = model.exposures.filter(e =>
    /key|secret|cred|token|password|api.?key/i.test(e.threat) ||
    /key|secret|cred|token|password|api.?key/i.test(e.description || ''),
  );
  const keyMitigations = model.mitigations.filter(m =>
    /key|secret|cred|token|password|api.?key|redact|encrypt/i.test(m.control || '') ||
    /key|secret|cred|token|password|api.?key/i.test(m.description || ''),
  );
  const keyComments = model.comments.filter(c =>
    /key|secret|cred|token|password|api.?key|rotat|vault|kms/i.test(c.description || ''),
  );

  lines.push('### Secret Inventory');
  lines.push('');
  if (secretHandling.length > 0) {
    lines.push('| Asset | Description | Location |');
    lines.push('|-------|-------------|----------|');
    for (const h of secretHandling) {
      lines.push(`| ${h.asset} | ${h.description || '—'} | ${h.location.file}:${h.location.line} |`);
    }
    lines.push('');
  } else {
    lines.push('_No assets classified as `secrets` via `@handles`. Consider adding `@handles secrets on <asset>` annotations._');
    lines.push('');
  }

  // ── Leak Impact ──
  lines.push('### Leak Impact Analysis');
  lines.push('');
  if (keyExposures.length > 0) {
    lines.push('Key/credential-related exposures:');
    lines.push('');
    for (const e of keyExposures) {
      lines.push(`- ${severityBadge(e.severity)} **${e.asset}** exposed to **${e.threat}**${e.description ? ` — ${e.description}` : ''} (${e.location.file}:${e.location.line})`);
    }
    lines.push('');
  }
  if (keyMitigations.length > 0) {
    lines.push('Active credential protections:');
    lines.push('');
    for (const m of keyMitigations) {
      lines.push(`- **${m.control || 'control'}** on ${m.asset}${m.description ? ` — ${m.description}` : ''}`);
    }
    lines.push('');
  }
  if (keyExposures.length === 0 && keyMitigations.length === 0) {
    lines.push('_No credential-related exposures or mitigations found._');
    lines.push('');
  }

  // ── Rotation Strategy ──
  lines.push('### Rotation Strategy');
  lines.push('');
  if (keyComments.length > 0) {
    for (const c of keyComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push('_No rotation strategy documented. Consider adding `@comment` annotations describing key rotation policies._');
  }
  lines.push('');
}

function emitLoggingAudit(model: ThreatModel, lines: string[]): void {
  // ── What's Logged ──
  const loggingComments = model.comments.filter(c =>
    /log|audit|trace|monitor|alert|metric|observ/i.test(c.description || ''),
  );

  lines.push('### Logging & Observability');
  lines.push('');
  if (loggingComments.length > 0) {
    for (const c of loggingComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push('_No logging-related annotations found. Consider documenting what security events are logged._');
  }
  lines.push('');

  // ── Incident Reconstruction ──
  lines.push('### Incident Reconstruction');
  lines.push('');
  if (model.audits.length > 0) {
    lines.push(`**${model.audits.length} audit items** flagged for review:`);
    lines.push('');
    for (const a of model.audits.slice(0, 10)) {
      lines.push(`- **${a.asset}**: ${a.description || 'Needs review'} (${a.location.file}:${a.location.line})`);
    }
    if (model.audits.length > 10) {
      lines.push(`- ... and ${model.audits.length - 10} more (see Audit Items section)`);
    }
  } else {
    lines.push('_No `@audit` items. Consider flagging security-critical code paths for review._');
  }
  lines.push('');

  // ── Alerting ──
  lines.push('### Alerting');
  lines.push('');
  const alertComments = model.comments.filter(c =>
    /alert|page|notify|incident|on.?call/i.test(c.description || ''),
  );
  if (alertComments.length > 0) {
    for (const c of alertComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push('_No alerting annotations found. Consider documenting alerting strategies via `@comment`._');
  }
  lines.push('');
}

function emitAIDetails(model: ThreatModel, lines: string[]): void {
  // ── Model Inventory ──
  const aiAssets = model.assets.filter(a => isAIRelated(a.id || a.path.join('.')));
  const aiExposures = model.exposures.filter(e =>
    isAIRelated(e.asset) || /prompt.?inject|model|adversarial/i.test(e.threat),
  );
  const aiMitigations = model.mitigations.filter(m =>
    isAIRelated(m.asset) || /prompt.?inject|model|adversarial/i.test(m.threat),
  );
  const aiComments = model.comments.filter(c =>
    /prompt|model|llm|ai|ml|inference|embed|token|train|fine.?tun|rag|vector/i.test(c.description || ''),
  );

  lines.push('### Model Inventory');
  lines.push('');
  if (aiAssets.length > 0) {
    lines.push('| Component | ID | Description |');
    lines.push('|-----------|-----|-------------|');
    for (const a of aiAssets) {
      lines.push(`| ${a.path.join('.')} | ${a.id || '—'} | ${a.description || '—'} |`);
    }
  } else {
    lines.push('_AI usage detected in annotations but no AI-specific assets defined._');
  }
  lines.push('');

  // ── Safety Guardrails ──
  lines.push('### Safety Guardrails');
  lines.push('');
  if (aiMitigations.length > 0) {
    for (const m of aiMitigations) {
      lines.push(`- **${m.control || 'control'}** on ${m.asset} against ${m.threat}${m.description ? ` — ${m.description}` : ''}`);
    }
  } else {
    lines.push('_No AI-specific mitigations found._');
  }
  lines.push('');

  // ── Prompt Injection Handling ──
  lines.push('### Prompt Injection Handling');
  lines.push('');
  const promptInjectionExposures = aiExposures.filter(e =>
    /prompt.?inject/i.test(e.threat),
  );
  const promptInjectionMitigations = aiMitigations.filter(m =>
    /prompt.?inject/i.test(m.threat),
  );
  if (promptInjectionExposures.length > 0 || promptInjectionMitigations.length > 0) {
    if (promptInjectionExposures.length > 0) {
      lines.push('**Exposures:**');
      for (const e of promptInjectionExposures) {
        lines.push(`- ${severityBadge(e.severity)} ${e.asset}${e.description ? ` — ${e.description}` : ''} (${e.location.file}:${e.location.line})`);
      }
      lines.push('');
    }
    if (promptInjectionMitigations.length > 0) {
      lines.push('**Mitigations:**');
      for (const m of promptInjectionMitigations) {
        lines.push(`- ${m.control || 'control'} on ${m.asset}${m.description ? ` — ${m.description}` : ''}`);
      }
      lines.push('');
    }
  } else {
    lines.push('_No prompt injection exposures or mitigations documented._');
    lines.push('');
  }

  // ── Data Retention ──
  lines.push('### Data Retention & AI Notes');
  lines.push('');
  if (aiComments.length > 0) {
    for (const c of aiComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push('_No AI data retention notes found. Consider documenting prompt logging, training data handling, and model output storage._');
  }
  lines.push('');
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

function shortName(s: string): string {
  if (s.startsWith('#')) return s.slice(1);
  return s.split('.').pop() || s;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function severityBadge(sev?: Severity): string {
  switch (sev) {
    case 'critical': return '🔴 Critical';
    case 'high':     return '🟠 High';
    case 'medium':   return '🟡 Medium';
    case 'low':      return '🔵 Low';
    default:         return '⚪ Unset';
  }
}

function classificationBadge(c: string): string {
  switch (c) {
    case 'pii':       return '🔒 PII';
    case 'phi':       return '🏥 PHI';
    case 'financial': return '💰 Financial';
    case 'secrets':   return '🔑 Secrets';
    case 'internal':  return '🏢 Internal';
    case 'public':    return '🌐 Public';
    default:          return c;
  }
}

function sortBySeverity(exposures: ThreatModelExposure[]): ThreatModelExposure[] {
  return [...exposures].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity || 'low'] ?? 4;
    const sb = SEVERITY_ORDER[b.severity || 'low'] ?? 4;
    return sa - sb;
  });
}

function countBySeverity(exposures: ThreatModelExposure[]): { critical: number; high: number; medium: number; low: number } {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const e of exposures) {
    if (e.severity && e.severity in counts) {
      counts[e.severity as keyof typeof counts]++;
    }
  }
  return counts;
}

/** Detect if the project uses AI/ML based on annotations */
function detectAI(model: ThreatModel): boolean {
  // Strict patterns — avoid false positives from "model" (data model), "token" (auth token), etc.
  const aiAssetPattern = /\bllm\b|(?:^|\W)ai(?:\W|$)|\bml\b|\binference\b|\bembed(?:ding)?\b|\bopenai\b|\banthropic\b|\bgpt\b|\bclaude\b|\bgemini\b|\brag\b|\bvector.?(?:db|store)\b|\bneural\b/i;
  const aiFlowPattern = /\bllm\b|\bopenai\b|\banthropic\b|\bgpt\b|\bclaude\b|\bgemini\b|\binference\b|\bembed(?:ding)?\b|\brag\b|\bvector.?(?:db|store)\b|\bchat.?completion\b/i;

  for (const a of model.assets) {
    if (aiAssetPattern.test(a.id || '') || aiAssetPattern.test(a.path.join('.'))) return true;
    if (aiAssetPattern.test(a.description || '')) return true;
  }
  for (const t of model.threats) {
    if (/prompt.?inject/i.test(t.name) || /prompt.?inject/i.test(t.canonical_name)) return true;
  }
  for (const f of model.flows) {
    if (aiFlowPattern.test(f.source) || aiFlowPattern.test(f.target)) return true;
    if (aiFlowPattern.test(f.mechanism || '')) return true;
  }
  return false;
}

/** Check if a name is AI-related (strict) */
function isAIRelated(name: string): boolean {
  return /\bllm\b|\bopenai\b|\banthropic\b|\bgpt\b|\bclaude\b|\bgemini\b|\binference\b|\bembed(?:ding)?\b|\brag\b|\bvector.?(?:db|store)\b|\bneural\b|\bchat.?completion\b/i.test(name);
}


/** Build connected flow chains from individual flow edges */
function buildFlowChains(flows: ThreatModel['flows']): ThreatModel['flows'][] {
  if (flows.length === 0) return [];

  // Build adjacency: source -> list of flows
  const adj = new Map<string, typeof flows>();
  for (const f of flows) {
    if (!adj.has(f.source)) adj.set(f.source, []);
    adj.get(f.source)!.push(f);
  }

  // Find chain starting points: sources that are not targets of other flows
  const allTargets = new Set(flows.map(f => f.target));
  const startNodes = new Set<string>();
  for (const f of flows) {
    if (!allTargets.has(f.source)) startNodes.add(f.source);
  }
  // If no clear start points, use all sources
  if (startNodes.size === 0) {
    for (const f of flows) startNodes.add(f.source);
  }

  const visited = new Set<string>();
  const chains: typeof flows[] = [];

  for (const start of startNodes) {
    if (visited.has(start)) continue;
    const chain: typeof flows[number][] = [];
    let current = start;
    const chainVisited = new Set<string>();

    while (adj.has(current) && !chainVisited.has(current)) {
      chainVisited.add(current);
      visited.add(current);
      const nextFlows = adj.get(current)!;
      const next = nextFlows[0]; // Take first path
      chain.push(next);
      current = next.target;
    }

    if (chain.length > 0) chains.push(chain);
  }

  // Add any isolated flows not in chains
  const chainedFlows = new Set(chains.flat().map(f => `${f.source}::${f.target}`));
  const isolated = flows.filter(f => !chainedFlows.has(`${f.source}::${f.target}`));
  for (const f of isolated) {
    chains.push([f]);
  }

  return chains;
}
