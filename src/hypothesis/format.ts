/**
 * GuardLink Hypotheses — text for the terminal.
 *
 * @handles internal on #cli -- "Evidence strings printed to the terminal"
 * @comment -- "Plain padded tables like printStatus; nothing here reads a file"
 */
import type { HypothesisClassification, HypothesisRecord, RankedHypothesis } from './classify.js';
import type { HypothesisEntry } from './ledger.js';
import type { ImportResult } from './commands.js';

const pad = (s: string, n: number): string => (s.length >= n ? s : s + ' '.repeat(n - s.length));
const short = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function formatHypothesisList(c: HypothesisClassification, state?: string): string {
  const rows = state ? c.records.filter(r => r.state === state) : c.records;
  const s = c.summary;
  const lines = [`${s.untested} untested · ${s.confirmed} confirmed · ${s.refuted} refuted · ${s.retest} retest${c.ledger === 'corrupt' ? '   (ledger unreadable — every claim shown untested)' : ''}`, ''];
  lines.push(`  ${pad('state', 10)}${pad('severity', 10)}${pad('asset', 18)}${pad('threat', 22)}${pad('where', 34)}outcome`);
  for (const r of rows) {
    const e = r.entry;
    const outcome = r.state === 'untested' && r.previous ? `previously ${r.previous.outcome} ${r.previous.at.slice(0, 10)} by ${r.previous.by} — code changed since`
      : r.state === 'retest' && e ? `confirmed ${e.at.slice(0, 10)} by ${e.by} — code changed since, retest`
      : e ? `${e.at.slice(0, 10)} by ${e.by}` : r.verb === 'confirmed' ? 'in source (@confirmed)' : '';
    lines.push(`  ${pad(r.state, 10)}${pad(r.severity, 10)}${pad(short(r.asset, 17), 18)}${pad(short(r.threat, 21), 22)}${pad(short(`${r.file}:${r.line}`, 33), 34)}${outcome}`);
  }
  if (rows.length === 0) lines.push('  (none)');
  return lines.join('\n');
}

export function formatQueue(q: RankedHypothesis[]): string {
  if (q.length === 0) return 'Nothing to test: every exposure has an outcome that still holds.';
  const lines = [`${q.length} to test`, '', `  ${pad('#', 4)}${pad('state', 9)}${pad('severity', 10)}${pad('asset', 18)}${pad('threat', 22)}${pad('where', 34)}why`];
  for (const r of q) {
    const why = [r.onPath ? 'on an undefended path' : null, r.unowned ? 'unowned' : null, r.state === 'retest' ? 'confirmed, code changed' : null].filter(Boolean).join(', ');
    lines.push(`  ${pad(String(r.rank), 4)}${pad(r.state, 9)}${pad(r.severity, 10)}${pad(short(r.asset, 17), 18)}${pad(short(r.threat, 21), 22)}${pad(short(`${r.file}:${r.line}`, 33), 34)}${why}`);
  }
  lines.push('', 'Ranked by severity, then an undefended path from `guardlink paths`, then unowned. Retests come first.');
  return lines.join('\n');
}

/** The queue as a brief `bugb intake` can take. */
export function formatIntake(q: RankedHypothesis[], project: string): string {
  const lines = [`# Test plan for ${project} — from guardlink hypothesis next`, '', 'Test these exposures in order. Each is a GuardLink claim; record the result with `guardlink hypothesis confirm|refute <file:line> --evidence "…"` or import the scan with `--from-scan`.', ''];
  for (const r of q) {
    lines.push(`${r.rank}. ${r.asset} → ${r.threat} [${r.severity}] at ${r.file}:${r.line}${r.state === 'retest' ? ' (previously confirmed; code changed — retest)' : ''}${r.onPath ? ' — on an undefended path' : ''}${r.unowned ? ' — no owner' : ''}`);
    lines.push(`   claim: ${r.claim}`);
  }
  lines.push('', 'Hand this to `bugb intake "<brief>"`; an operator approves the plan before anything runs.');
  return lines.join('\n');
}

export function formatOutcome(record: HypothesisRecord, entry: HypothesisEntry, offered?: string): string {
  const head = entry.outcome === 'confirmed' ? 'Confirmed' : 'Refuted';
  const lines = [
    `${head}  ${record.asset} → ${record.threat}  (${record.file}:${record.line})`,
    `  by        ${entry.by}  on ${entry.at.slice(0, 10)}${entry.source.kind === 'scan' ? `  (scan ${entry.source.scan_id}, confidence ${entry.source.confidence ?? 'n/a'})` : ''}`,
    `  evidence  ${short(entry.evidence, 160)}`,
    `  code      ${entry.anchor ? `${entry.anchor.hash.slice(0, 22)}…  (the outcome is tied to this version of the code)` : 'no anchor — the outcome cannot expire on its own'}`,
    `  key       ${entry.key.slice(0, 16)}…  (.guardlink/hypotheses.json)`,
  ];
  if (entry.history.length > 0) lines.push(`  history   ${entry.history.length} earlier ${entry.history.length === 1 ? 'outcome' : 'outcomes'} kept`);
  if (offered) lines.push('', 'Ready to write, if you want it in the source:', `  ${record.file}:${record.line + 1}`, `  ${offered}`, '', '  add --write to insert it');
  return lines.join('\n');
}

export function formatImport(r: ImportResult): string {
  const lines = [`${r.confirmed.length} ${r.confirmed.length === 1 ? 'finding' : 'findings'} joined to a claim, ${r.ambiguous.length} ambiguous, ${r.unmatched.length} unmatched  (scan ${r.scanId})`];
  for (const c of r.confirmed) lines.push('', formatOutcome(c.record, c.entry), `  joined    by ${c.joinedBy}`);
  for (const a of r.ambiguous) {
    lines.push('', `Ambiguous  ${a.finding.id} (${a.finding.template_id}) fits ${a.candidates.length} claims — pick one and record it by hand:`);
    for (const c of a.candidates) lines.push(`  guardlink hypothesis confirm ${c.file}:${c.line} --evidence "…"`);
  }
  for (const u of r.unmatched) lines.push('', `Unmatched  ${u.id} (${u.template_id}, ${u.title || 'no title'}): no claim carries this location, asset/threat or CWE. If it is real, annotate it first.`);
  return lines.join('\n');
}
