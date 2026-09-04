/**
 * GuardLink Blame — terminal rendering. Pure.
 *
 * One group per file, one block per claim, then the two summary tables and
 * the quarterly trend. Plain `padEnd` columns and no colour, so the output
 * pipes cleanly and the TUI can indent it.
 *
 * @handles pii on #blame -- "Identity strings printed to the terminal"
 * @flows #blame -> #cli via formatBlameText -- "Human-readable attribution"
 * @comment -- "Every degraded status is printed next to the claim it degrades, so a reader never mistakes an unattributed claim for a clean one"
 * @comment -- "A rate with no denominator (no commit counts, or an identity with no commits) prints as a dash, never as 0: an absent number must not read as a good one"
 */
import type { AgentSummaryRow, BlameEntry, BlamePayload, CommitRef, HumanSummaryRow, TrendBucket } from './types.js';

function who(ref: CommitRef | null): string {
  if (!ref) return '—';
  const ai = ref.assisted_by.map(a => (a.model ? `${a.tool} (${a.model})` : a.tool));
  const co = ref.co_authors.length > 0 ? ` +${ref.co_authors.join(', ')}` : '';
  return `${ref.sha.slice(0, 8)} ${ref.date.slice(0, 10)}  ${ref.author}${co}${ai.length > 0 ? `  +ai ${ai.join(', ')}` : ''}`;
}

function table(headers: string[], rows: string[][], numeric: boolean[]): string[] {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map(r => r[i].length)));
  const cell = (v: string, i: number): string => (numeric[i] ? v.padStart(widths[i]) : v.padEnd(widths[i]));
  return [
    `  ${headers.map(cell).join('  ')}`,
    ...rows.map(r => `  ${r.map(cell).join('  ')}`),
  ];
}

const num = (n: number | null): string => (n === null ? '—' : String(n));

const COUNT_HEADERS = ['commits', 'introduced', 'per 100', 'fixed', 'open', 'touched', 'lines', 'median days to fix'];

const countCells = (r: HumanSummaryRow | AgentSummaryRow): string[] =>
  [num(r.commits), String(r.introduced), num(r.per_100_commits), String(r.fixed), String(r.open), String(r.touched), String(r.lines), num(r.median_time_to_fix_days)];

function humanRows(rows: HumanSummaryRow[]): string[] {
  if (rows.length === 0) return ['  (no one attributed)'];
  return table(
    ['identity', ...COUNT_HEADERS],
    rows.map(r => [r.identity, ...countCells(r)]),
    [false, ...COUNT_HEADERS.map(() => true)],
  );
}

function agentRows(rows: AgentSummaryRow[]): string[] {
  if (rows.length === 0) return ['  (no AI tool credited on any attributed commit)'];
  return table(
    ['tool', 'model', ...COUNT_HEADERS],
    rows.map(r => [r.tool, r.model ?? '—', ...countCells(r)]),
    [false, false, ...COUNT_HEADERS.map(() => true)],
  );
}

function quarterLines(trends: TrendBucket[]): string[] {
  if (trends.length === 0) return ['  (no dated claims)'];
  return trends.map(t => `  ${t.period}  introduced ${t.introduced} (${t.introduced_ai} AI)  fixed ${t.fixed}  open ${t.open_end}`);
}

function claimLines(e: BlameEntry): string[] {
  const sev = e.severity ? ` [${e.severity}]` : '';
  const flag = e.blame.status === 'ok' ? '' : `   (${e.blame.status}${e.blame.error ? `: ${e.blame.error}` : ''})`;
  const out = [`  ${e.verb.padEnd(10)} ${e.asset} → ${e.threat}${sev}   line ${e.line}   ${e.granularity}${flag}`];
  if (e.blame.kind === 'exposure') {
    const b = e.blame;
    out.push(`    introduced  ${who(b.introduced_by)}${b.introduced_by?.lower_bound ? '  (lower bound)' : ''}`);
    out.push(`    found       ${who(b.found_by)}`);
    out.push(`    fixed       ${b.fixed_by ? `${who(b.fixed_by)}${b.time_to_fix_days !== null ? `  after ${b.time_to_fix_days} days` : ''}` : '— open'}`);
  } else {
    out.push(`    declared    ${who(e.blame.declared_by)}`);
  }
  if (e.blame.contributors.length > 1) {
    out.push(`    contributors ${e.blame.contributors.map(c => `${c.sha.slice(0, 8)}×${c.lines}`).join(', ')}`);
  }
  return out;
}

export function formatBlameText(p: BlamePayload): string {
  const lines: string[] = [];
  const head = p.head ? p.head.slice(0, 8) : 'no HEAD';
  lines.push(`GuardLink blame — ${p.root} @ ${head}  (identity: ${p.identity_mode})`);

  if (p.status === 'no-git') {
    lines.push('', '  This directory is not a git checkout, so nothing can be attributed.');
    return `${lines.join('\n')}\n`;
  }
  if (p.status === 'shallow') {
    lines.push('  Shallow clone: every "introduced" is a lower bound — the true commit may be older.');
  }

  const byFile = new Map<string, BlameEntry[]>();
  for (const e of p.entries) {
    const list = byFile.get(e.file);
    if (list) list.push(e); else byFile.set(e.file, [e]);
  }
  for (const [file, entries] of byFile) {
    lines.push('', file);
    for (const e of entries) lines.push(...claimLines(e));
  }

  lines.push('', 'By person', ...humanRows(p.summary.by_human));
  lines.push('', 'By AI tool', ...agentRows(p.summary.by_agent));
  lines.push('', 'By quarter', ...quarterLines(p.summary.trends));
  return `${lines.join('\n')}\n`;
}
