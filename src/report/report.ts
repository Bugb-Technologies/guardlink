/**
 * GuardLink Report — Markdown report generator.
 * Produces a human-readable threat model report with
 * embedded Mermaid diagram, finding tables, and coverage stats.
 *
 * @exposes #report to #arbitrary-write [high] cwe:CWE-73 -- "Report written to user-specified output path"
 * @exposes #report to #info-disclosure [low] cwe:CWE-200 -- "Report contains detailed threat model information"
 * @accepts #info-disclosure on #report -- "Detailed threat model report is the intended output"
 * @mitigates #report against #arbitrary-write using #path-validation -- "CLI resolves output path before passing to report generator"
 * @flows #parser -> #report via ThreatModel -- "Report generator receives parsed threat model"
 * @flows #report -> Filesystem via writeFile -- "Generated markdown written to disk by CLI"
 * @handles internal on #report -- "Processes and formats security-sensitive threat model data"
 */

import type { ThreatModel, ThreatModelExposure, Severity } from '../types/index.js';
import { generateMermaid } from './mermaid.js';

export function generateReport(model: ThreatModel): string {
  const lines: string[] = [];

  // ── Header ──
  lines.push(`# Threat Model Report — ${model.project}`);
  lines.push('');
  lines.push(`> Generated: ${model.generated_at}  `);
  lines.push(`> Files scanned: ${model.source_files} | Annotations: ${model.annotations_parsed}`);
  lines.push('');

  // ── Executive Summary ──
  lines.push('## Executive Summary');
  lines.push('');

  const mitigatedPairs = new Set<string>();
  const acceptedPairs = new Set<string>();
  for (const m of model.mitigations) mitigatedPairs.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) acceptedPairs.add(`${a.asset}::${a.threat}`);

  const unmitigated = model.exposures.filter(e => {
    const key = `${e.asset}::${e.threat}`;
    return !mitigatedPairs.has(key) && !acceptedPairs.has(key);
  });

  const severityCounts = countBySeverity(unmitigated);

  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Assets | ${model.assets.length} |`);
  lines.push(`| Threats defined | ${model.threats.length} |`);
  lines.push(`| Controls defined | ${model.controls.length} |`);
  lines.push(`| Active mitigations | ${model.mitigations.length} |`);
  lines.push(`| Accepted risks | ${model.acceptances.length} |`);
  lines.push(`| **Unmitigated exposures** | **${unmitigated.length}** |`);
  if (severityCounts.critical > 0) lines.push(`| ↳ Critical (P0) | ${severityCounts.critical} |`);
  if (severityCounts.high > 0) lines.push(`| ↳ High (P1) | ${severityCounts.high} |`);
  if (severityCounts.medium > 0) lines.push(`| ↳ Medium (P2) | ${severityCounts.medium} |`);
  if (severityCounts.low > 0) lines.push(`| ↳ Low (P3) | ${severityCounts.low} |`);
  lines.push(`| Data flows | ${model.flows.length} |`);
  lines.push(`| Trust boundaries | ${model.boundaries.length} |`);
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
    lines.push('## ⚠ Unmitigated Exposures');
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

  // ── Accepted Risks ──
  if (model.acceptances.length > 0) {
    lines.push('## ✅ Accepted Risks');
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
    lines.push('## 🛡 Active Mitigations');
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

  // ── Data Flows ──
  if (model.flows.length > 0) {
    lines.push('## 📊 Data Flows');
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
    lines.push('## 📋 Data Classification');
    lines.push('');
    lines.push('| Asset | Classification | Description |');
    lines.push('|-------|---------------|-------------|');
    for (const h of model.data_handling) {
      const desc = h.description ? truncate(h.description, 60) : '—';
      lines.push(`| ${h.asset} | ${classificationBadge(h.classification)} | ${desc} |`);
    }
    lines.push('');
  }

  // ── Audit Items ──
  if (model.audits.length > 0) {
    lines.push('## 🔍 Audit Items');
    lines.push('');
    for (const a of model.audits) {
      const desc = a.description || 'Needs review';
      lines.push(`- **${a.asset}** — ${desc} (${a.location.file}:${a.location.line})`);
    }
    lines.push('');
  }

  // ── Assumptions ──
  if (model.assumptions.length > 0) {
    lines.push('## ⚡ Assumptions');
    lines.push('');
    lines.push('These are unverified assumptions that should be periodically reviewed.');
    lines.push('');
    for (const a of model.assumptions) {
      const desc = a.description || 'Unverified assumption';
      lines.push(`- **${a.asset}** — ${desc} (${a.location.file}:${a.location.line})`);
    }
    lines.push('');
  }

  // ── Developer Comments ──
  if (model.comments.length > 0) {
    lines.push('## 💬 Developer Comments');
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
  lines.push(`*Generated by [GuardLink](https://guardlink.bugb.io) — Security annotations for code.*`);

  return lines.join('\n');
}

// ─── Helpers ─────────────────────────────────────────────────────────

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
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
