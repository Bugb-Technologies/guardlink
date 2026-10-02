/**
 * GuardLink Diff — Human-readable output formatter.
 *
 * @comment -- "Pure string formatting; no I/O. Stale entitlements print even when the delta is otherwise empty — a claim whose cited authz code moved is exactly the thing that must not disappear quietly (actor-entitlement design §3.3)"
 */

import type { ThreatModelDiff, Change } from './engine.js';

export function formatDiff(diff: ThreatModelDiff): string {
  const lines: string[] = [];
  const s = diff.summary;

  // ── Header ──
  // A stale entitlement is not a model change, so report it even when the delta
  // is otherwise empty — the code its claim rests on moved without it.
  if (s.totalChanges === 0 && diff.staleEntitlements.length === 0) {
    lines.push('No threat model changes detected.');
    return lines.join('\n');
  }
  if (s.totalChanges === 0) {
    lines.push('No threat model changes detected.');
    lines.push('');
  } else {
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
  }

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

  // ── New unentitled reaches ──
  // Next to new unmitigated exposures for the same reason: a capability the
  // harness hands out that no human approved is the reach a reviewer must see.
  if (diff.newUnentitledReaches.length > 0) {
    lines.push('── New Unentitled Reaches (no cited @entitles covers them) ──');
    for (const r of diff.newUnentitledReaches) {
      lines.push(`  + ${describeReach(r)} (${r.location.file}:${r.location.line})`);
    }
    lines.push('');
  }

  // ── Stale entitlements ──
  // Not a "change" in the model — the claim is unchanged; the authz code it was
  // reviewed against is not. Surfaced so a human re-checks the citation (§3.7).
  if (diff.staleEntitlements.length > 0) {
    lines.push('── Stale Entitlements (cited authz code changed) ──');
    for (const s of diff.staleEntitlements) {
      const e = s.entitlement;
      lines.push(`  ! ${e.actor} → ${e.capability} — cites ${e.citation?.raw} (${s.citedFile} changed)`);
    }
    lines.push('');
  }

  // ── Category changes ──
  emitSection('Assets', diff.assets, lines, a => a.id || a.path.join('.'));
  emitSection('Actors', diff.actors, lines, a => a.id || a.canonical_name);
  emitSection('Threats', diff.threats, lines, t => `${t.id || t.canonical_name}${t.severity ? ` [${t.severity}]` : ''}`);
  emitSection('Controls', diff.controls, lines, c => c.id || c.canonical_name);
  emitSection('Mitigations', diff.mitigations, lines, m => `${m.asset} ← ${m.control || '?'} against ${m.threat}`);
  emitSection('Exposures', diff.exposures, lines, e => `${e.asset} → ${e.threat}${e.severity ? ` [${e.severity}]` : ''}`);
  emitSection('Acceptances', diff.acceptances, lines, a => `${a.asset} accepts ${a.threat}`);
  emitSection('Entitlements', diff.entitlements, lines, e =>
    `${e.actor} entitled to ${e.capability}${e.asset ? ` on ${e.asset}` : ''}${e.threat ? ` against ${e.threat}` : ''}`
    + entitlementCaveat(e));
  emitSection('Reaches', diff.reaches, lines, describeReach);
  emitSection('Effects', diff.effects, lines, e => `${e.effect} on ${e.asset}${e.identity ? ` as ${e.identity}` : ''}`);
  emitSection('Gates', diff.gates, lines, g => `${g.asset} by ${g.approver}${g.capability ? ` for ${g.capability}` : ''}`);
  emitSection('Flows', diff.flows, lines, f => `${f.source} → ${f.target}${f.mechanism ? ` via ${f.mechanism}` : ''}`);
  emitSection('Boundaries', diff.boundaries, lines, b => (b.directed ? `${b.asset_a} → ${b.asset_b} (outer → inner)` : `${b.asset_a} ↔ ${b.asset_b}`));
  emitSection('Transfers', diff.transfers, lines, t => `${t.source} → ${t.target} (${t.threat})`);

  return lines.join('\n');
}

/** A reach in its own words: `@agents #bot to run-sql on #api as #svc`. */
function describeReach(r: { agent: boolean; actor: string; capability: string; asset?: string; identity?: string }): string {
  return `${r.agent ? '@agents' : '@reaches'} ${r.actor} to ${r.capability}${r.asset ? ` on ${r.asset}` : ''}${r.identity ? ` as ${r.identity}` : ''}`;
}

/** Why a claim cannot demote, or '' when it can. Both halves of the join are
 *  named (§9.3): two claims differing only by threat must not read identically. */
function entitlementCaveat(e: { inert: boolean; asset?: string; threat?: string }): string {
  const reasons = [
    e.inert && 'no citation',
    !e.asset && 'no asset',
    !e.threat && 'no threat',
  ].filter(Boolean);
  return reasons.length ? ` (ineffective: ${reasons.join(', ')})` : '';
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

  if (s.totalChanges === 0 && diff.staleEntitlements.length === 0) {
    lines.push('### ✅ No threat model changes');
    return lines.join('\n');
  }
  if (s.totalChanges === 0) {
    lines.push('### ⏳ No threat model changes, but an entitlement citation went stale');
    lines.push('');
    emitStaleEntitlementsMarkdown(diff, lines);
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

  if (diff.entitlements.length > 0) {
    lines.push('#### 🔑 Entitlements');
    lines.push('');
    lines.push('| | Actor | Capability | Asset | Threat | Citation | Effect |');
    lines.push('|---|-------|------------|-------|--------|----------|--------|');
    for (const c of diff.entitlements) {
      const e = c.item;
      const mark = c.kind === 'added' ? '+' : c.kind === 'removed' ? '-' : '~';
      const cite = e.citation?.raw ? `\`${e.citation.raw}\`` : '**none**';
      const caveat = entitlementCaveat(e);
      const effect = caveat ? `**${caveat.replace(/^ \(|\)$/g, '')}**` : 'can demote';
      lines.push(`| ${mark} | ${e.actor} | ${e.capability} | ${e.asset || '—'} | ${e.threat || '—'} | ${cite} | ${effect} |`);
    }
    lines.push('');
    lines.push('> An entitlement changes only what triage *recommends*. It never suppresses a finding and never gates testing.');
    lines.push('');
  }

  if (diff.newUnentitledReaches.length > 0) {
    lines.push('#### 🧰 New Unentitled Reaches');
    lines.push('');
    lines.push('No cited `@entitles` covers these: a capability the code hands out that nobody approved.');
    lines.push('');
    lines.push('| Verb | Actor | Capability | Asset | Location |');
    lines.push('|------|-------|------------|-------|----------|');
    for (const r of diff.newUnentitledReaches) {
      lines.push(`| ${r.agent ? '@agents' : '@reaches'} | ${r.actor} | ${r.capability} | ${r.asset || '—'} | \`${r.location.file}:${r.location.line}\` |`);
    }
    lines.push('');
  }

  if (diff.reaches.length + diff.effects.length + diff.gates.length > 0) {
    lines.push('#### Reach, effects and gates');
    lines.push('');
    const mark = (k: string) => (k === 'added' ? '+' : k === 'removed' ? '-' : '~');
    for (const c of diff.reaches) lines.push(`- ${mark(c.kind)} ${describeReach(c.item)}${c.details ? ` (${c.details})` : ''}`);
    for (const c of diff.effects) lines.push(`- ${mark(c.kind)} @effects ${c.item.effect} on ${c.item.asset}${c.item.identity ? ` as ${c.item.identity}` : ''}`);
    for (const c of diff.gates) lines.push(`- ${mark(c.kind)} @gates ${c.item.asset} by ${c.item.approver}${c.item.capability ? ` for ${c.item.capability}` : ''}`);
    lines.push('');
  }

  emitStaleEntitlementsMarkdown(diff, lines);

  return lines.join('\n');
}

function emitStaleEntitlementsMarkdown(diff: ThreatModelDiff, lines: string[]): void {
  if (diff.staleEntitlements.length === 0) return;

  lines.push('#### ⏳ Stale Entitlements');
  lines.push('');
  lines.push('The authorization code these claims cite changed in this delta — re-check that the entitlement still holds.');
  lines.push('');
  for (const s of diff.staleEntitlements) {
    const e = s.entitlement;
    lines.push(`- ${e.actor} → \`${e.capability}\` cites \`${e.citation?.raw}\` — \`${s.citedFile}\` changed`);
  }
  lines.push('');
}
