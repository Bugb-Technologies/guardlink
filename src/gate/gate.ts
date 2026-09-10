/**
 * GuardLink Gate — what a run added, whether it passes, and what to do when
 * it does not.
 *
 * `runGate` diffs claim keys (content-derived, so a line move is not a change)
 * to find what the run added, lints only those, and reports. The follow-up is
 * the re-prompt. The strip removes the lines of added claims that still fail,
 * after checking each line really holds the verb, and returns them so nothing
 * is lost.
 *
 * @exposes #gate to #arbitrary-write [medium] cwe:CWE-73 -- "stripViolations rewrites source files named by the model's locations"
 * @mitigates #gate against #arbitrary-write using #path-validation -- "Every path is resolved under root and refused outside it; a line is removed only when its text carries the annotation verb the model says is there"
 * @flows ThreatModel -> #gate via runGate -- "The model before and after an agent run"
 * @flows #gate -> AgentPrompt via buildGateFollowUp -- "The violations as a re-prompt"
 * @flows #gate -> SourceFiles via stripViolations -- "Rejected annotation lines removed"
 * @comment -- "Never edits an annotation's text: a rejected claim is re-prompted, then removed; rewriting would hide that it was wrong"
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import type { ThreatModel } from '../types/index.js';
import { relationRecords, type ClaimSource } from '../parser/claim-key.js';
import { lintAnnotations, RULE_FIX, type Violation, type LintOptions } from './lint.js';

export interface GateReport {
  /** Claims present after the run and absent before it. */
  added: ClaimSource[];
  /** Claims present before and absent after (a run that deleted something). */
  removed: number;
  violations: Violation[];
  errors: number;
  warnings: number;
  ok: boolean;
}

export function runGate(before: ThreatModel | null, after: ThreatModel, opts: Omit<LintOptions, 'only'> = {}): GateReport {
  const beforeKeys = new Set(before ? relationRecords(before).map(r => r.key) : []);
  const afterRecs = relationRecords(after);
  const added = before ? afterRecs.filter(r => !beforeKeys.has(r.key)) : afterRecs;
  const afterKeys = new Set(afterRecs.map(r => r.key));
  const removed = [...beforeKeys].filter(k => !afterKeys.has(k)).length;
  const violations = lintAnnotations(after, { ...opts, only: new Set(added.map(r => r.key)) });
  const errors = violations.filter(v => v.level === 'error').length;
  const warnings = violations.length - errors;
  return { added, removed, violations, errors, warnings, ok: errors === 0 };
}

export function formatGateReport(r: GateReport): string {
  const lines: string[] = [];
  lines.push(`Gate: ${r.added.length} claim${r.added.length === 1 ? '' : 's'} added, ${r.removed} removed — ${r.errors} error${r.errors === 1 ? '' : 's'}, ${r.warnings} warning${r.warnings === 1 ? '' : 's'}`);
  for (const v of r.violations) lines.push(`  ${v.level === 'error' ? '✗' : '!'} ${v.file}:${v.line}  ${v.rule}  ${v.message}`);
  if (r.ok && r.violations.length === 0) lines.push('  every added claim meets the evidence bar');
  return lines.join('\n');
}

/**
 * The re-prompt: each violation with where it is and what to do instead.
 * Scoped so the agent touches only these lines.
 */
export function buildGateFollowUp(r: GateReport): string {
  const errs = r.violations.filter(v => v.level === 'error');
  const warns = r.violations.filter(v => v.level === 'warn');
  const item = (v: Violation): string => `- \`${v.file}:${v.line}\` (${v.verb}) — ${v.message}.\n  Fix: ${RULE_FIX[v.rule]}`;
  return `The annotations you added were checked against the evidence bar. ${errs.length} of them failed and must be fixed before this run is accepted; ${warns.length} carry warnings.

## Must fix
${errs.map(item).join('\n')}
${warns.length > 0 ? `\n## Should fix\n${warns.map(item).join('\n')}\n` : ''}
## Rules for this pass
- Edit only the lines listed above. Do not rewrite, move or delete any other annotation, and do not write executable code.
- Do not write \`@accepts\` or \`@entitles\` anywhere — remove any you added.
- An \`@exposes\` you cannot back with an entry point, an input, a sink and an absent control becomes an \`@audit\` on the asset.
- When you are done, run \`guardlink validate .\` and stop.`;
}

const VERB_TAG: Record<string, string> = { exposes: '@exposes', confirmed: '@confirmed', accepts: '@accepts', entitles: '@entitles', mitigates: '@mitigates', audit: '@audit', comment: '@comment', transfers: '@transfers', assumes: '@assumes' };

export interface Stripped { file: string; line: number; text: string }

/**
 * Remove the annotation lines of added claims that still carry an error.
 * Warnings stay. Returns what was removed.
 */
export function stripViolations(root: string, r: GateReport): { removed: Stripped[]; refused: string[] } {
  const addedKeys = new Set(r.added.map(a => a.key));
  const targets = r.violations.filter(v => v.level === 'error' && v.key !== null && addedKeys.has(v.key));
  const byFile = new Map<string, Violation[]>();
  for (const v of targets) { const l = byFile.get(v.file) ?? []; l.push(v); byFile.set(v.file, l); }
  const removed: Stripped[] = [];
  const refused: string[] = [];
  const rootAbs = resolve(root);
  for (const [file, list] of byFile) {
    const abs = resolve(rootAbs, file);
    if (abs !== rootAbs && !abs.startsWith(rootAbs + sep)) { refused.push(`${file}: outside the project root`); continue; }
    let lines: string[];
    try { lines = readFileSync(abs, 'utf8').split('\n'); } catch { refused.push(`${file}: unreadable`); continue; }
    const lineNos = [...new Set(list.map(v => v.line))].sort((a, b) => b - a);
    const verbsAt = new Map<number, Set<string>>();
    for (const v of list) { const s = verbsAt.get(v.line) ?? new Set(); s.add(VERB_TAG[v.verb] ?? `@${v.verb}`); verbsAt.set(v.line, s); }
    let changed = false;
    for (const n of lineNos) {
      const text = lines[n - 1];
      if (text === undefined) { refused.push(`${file}:${n}: no such line`); continue; }
      const tags = [...(verbsAt.get(n) ?? [])];
      if (!tags.some(t => text.includes(t))) { refused.push(`${file}:${n}: line does not carry ${tags.join('/')}`); continue; }
      lines.splice(n - 1, 1);
      removed.push({ file, line: n, text: text.trim() });
      changed = true;
    }
    if (changed) writeFileSync(abs, lines.join('\n'));
  }
  return { removed: removed.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line)), refused };
}
