/**
 * GuardLink Diff — Human-readable output formatter.
 */

import type { ThreatModelDiff, Change } from './engine.js';

export function formatDiff(diff: ThreatModelDiff): string {
  const lines: string[] = [];
  const s = diff.summary;

  // ── Header ──
  if (s.totalChanges === 0) {
    lines.push('No threat model changes detected.');
    return lines.join('\n');
  }

  lines.push(`Threat Model Diff: ${s.totalChanges} change(s)`);
  lines.push(`  +${s.added} added  -${s.removed} removed  ~${s.modified} modified`);
  lines.push('');

  // ── Risk assessment ──
  if (s.newUnmitigated > 0) {
    lines.push(`⚠  ${s.newUnmitigated} NEW unmitigated exposure(s) — risk ${s.riskDelta}`);
  } else if (s.resolvedUnmitigated > 0) {
    lines.push(`✓  ${s.resolvedUnmitigated} exposure(s) resolved — risk ${s.riskDelta}`);
  } else {
    lines.push(`•  Risk ${s.riskDelta}`);
  }
  lines.push('');

  // ── New unmitigated exposures (most important) ──
  if (diff.newUnmitigatedExposures.length > 0) {
    lines.push('── New Unmitigated Exposures ──');
    for (const e of diff.newUnmitigatedExposures) {
      const sev = e.severity ? `[${e.severity}]` : '';
      lines.push(`  + ${e.asset} → ${e.threat} ${sev} (${e.location.file}:${e.location.line})`);
    }
    lines.push('');
  }

  // ── Resolved exposures ──
  if (diff.resolvedExposures.length > 0) {
    lines.push('── Resolved Exposures ──');
    for (const e of diff.resolvedExposures) {
      lines.push(`  ✓ ${e.asset} → ${e.threat} (${e.location.file}:${e.location.line})`);
    }
    lines.push('');
  }

  // ── Category changes ──
  emitSection('Assets', diff.assets, lines, a => a.id || a.path.join('.'));
  emitSection('Threats', diff.threats, lines, t => `${t.id || t.canonical_name}${t.severity ? ` [${t.severity}]` : ''}`);
  emitSection('Controls', diff.controls, lines, c => c.id || c.canonical_name);
  emitSection('Mitigations', diff.mitigations, lines, m => `${m.asset} ← ${m.control || '?'} against ${m.threat}`);
  emitSection('Exposures', diff.exposures, lines, e => `${e.asset} → ${e.threat}${e.severity ? ` [${e.severity}]` : ''}`);
  emitSection('Acceptances', diff.acceptances, lines, a => `${a.asset} accepts ${a.threat}`);
  emitSection('Flows', diff.flows, lines, f => `${f.source} → ${f.target}${f.mechanism ? ` via ${f.mechanism}` : ''}`);
  emitSection('Boundaries', diff.boundaries, lines, b => `${b.asset_a} ↔ ${b.asset_b}`);
  emitSection('Transfers', diff.transfers, lines, t => `${t.source} → ${t.target} (${t.threat})`);

  return lines.join('\n');
}

function emitSection<T>(label: string, changes: Change<T>[], lines: string[], describe: (item: T) => string): void {
  if (changes.length === 0) return;

  lines.push(`── ${label} ──`);
  for (const c of changes) {
    const prefix = c.kind === 'added' ? '+' : c.kind === 'removed' ? '-' : '~';
    let line = `  ${prefix} ${describe(c.item)}`;
    if (c.details) line += ` (${c.details})`;
    lines.push(line);
  }
  lines.push('');
}

/**
 * Format diff as markdown for PR comments.
 */
export function formatDiffMarkdown(diff: ThreatModelDiff): string {
  const lines: string[] = [];
  const s = diff.summary;

  if (s.totalChanges === 0) {
    lines.push('### ✅ No threat model changes');
    return lines.join('\n');
  }

  // Header with risk badge
  const badge = s.newUnmitigated > 0 ? '🔴' : s.resolvedUnmitigated > 0 ? '🟢' : '⚪';
  lines.push(`### ${badge} Threat Model Delta: ${s.totalChanges} change(s)`);
  lines.push('');
  lines.push(`| | Count |`);
  lines.push(`|---|---|`);
  lines.push(`| Added | +${s.added} |`);
  lines.push(`| Removed | -${s.removed} |`);
  lines.push(`| Modified | ~${s.modified} |`);
  lines.push(`| **New unmitigated** | **${s.newUnmitigated}** |`);
  lines.push(`| Resolved | ${s.resolvedUnmitigated} |`);
  lines.push('');

  if (diff.newUnmitigatedExposures.length > 0) {
    lines.push('#### ⚠ New Unmitigated Exposures');
    lines.push('');
    lines.push('| Severity | Asset | Threat | Location |');
    lines.push('|----------|-------|--------|----------|');
    for (const e of diff.newUnmitigatedExposures) {
      const sev = e.severity || 'unset';
      lines.push(`| ${sev} | ${e.asset} | ${e.threat} | \`${e.location.file}:${e.location.line}\` |`);
    }
    lines.push('');
  }

  if (diff.resolvedExposures.length > 0) {
    lines.push('#### ✅ Resolved Exposures');
    lines.push('');
    for (const e of diff.resolvedExposures) {
      lines.push(`- ~~${e.asset} → ${e.threat}~~`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
