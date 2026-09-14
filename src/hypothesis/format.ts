/**
 * GuardLink Hypotheses — text for the terminal.
 *
 * @handles internal on #cli -- "Evidence strings printed to the terminal"
 * @comment -- "Plain padded tables like printStatus; nothing here reads a file"
 * @comment -- "A contested join — more than one well-formed claim key on one finding, naming different claims — is labelled with its own words and its losing keys are listed, because 'key-verified' is a claim about what happened and a precedence tiebreak establishes less than agreement does"
 * @comment -- "formatImport() prints the stale and malformed buckets beside ambiguous and unmatched. A finding whose stamped claim key names no claim in the model says so and offers no by-hand target, because every claim it could name there is a different claim; a finding whose stamp is not a claim key at all names the value and the field it arrived in, so the producer can be fixed. Each confirmation is labelled with the identity that joined it, and a report carrying no stamps at all says that the weaker join was used — a key-verified confirmation and an unverified one must not read the same"
 */
import type { HypothesisClassification, HypothesisRecord, RankedHypothesis } from './classify.js';
import type { HypothesisEntry } from './ledger.js';
import type { ImportResult, ScanFinding } from './commands.js';
import { CLAIM_KEY_FINGERPRINT, CLAIM_KEY_PATTERN } from '../parser/claim-key.js';

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

/**
 * How a scan finding was joined to its claim, said in words rather than left as
 * a token. `claim-key` named the claim; the rest matched something it sits at,
 * which a claim that moved onto the tested line also matches — so those are
 * labelled as unverified rather than printed identically to a verified join.
 *
 * A contested join gets its own words for the same reason. "Key-verified" is a
 * claim about what happened, and a winner picked by precedence from keys that
 * disagreed establishes less than an uncontested stamp; printing both the same
 * way would overstate one of them.
 */
function joinNote(source: HypothesisEntry['source']): string | null {
  if (source.kind !== 'scan') return null;
  switch (source.joined_by) {
    case 'claim-key': return '  joined    by claim-key — the stamp named this exact claim';
    case 'claim-key-contested': return '  joined    by claim-key, CONTESTED — the report carried more than one claim key and they named different claims; this one won on precedence, not agreement';
    case undefined: return '  joined    by an unrecorded match — NOT key-verified';
    default: return `  joined    by ${source.joined_by} — NOT key-verified: this finding carried no claim key, so it matches where the claim sits, not which claim it is`;
  }
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
  const join = joinNote(entry.source);
  if (join) lines.push(join);
  if (entry.history.length > 0) lines.push(`  history   ${entry.history.length} earlier ${entry.history.length === 1 ? 'outcome' : 'outcomes'} kept`);
  if (offered) lines.push('', 'Ready to write, if you want it in the source:', `  ${record.file}:${record.line + 1}`, `  ${offered}`, '', '  add --write to insert it');
  return lines.join('\n');
}

export function formatImport(r: ImportResult): string {
  const lines = [`${r.confirmed.length} ${r.confirmed.length === 1 ? 'finding' : 'findings'} joined to a claim, ${r.ambiguous.length} ambiguous, ${r.stale.length} stale, ${r.malformed.length} malformed, ${r.unmatched.length} unmatched  (scan ${r.scanId})`];
  // Whether the REPORT carried a stamp is a property of every finding the import
  // saw, not of the ones that happened to confirm: a stamped finding whose claim
  // is gone lands in `stale`, never in `confirmed`.
  const findings = [...r.confirmed.map(c => c.finding), ...r.ambiguous.map(a => a.finding), ...r.stale.map(s => s.finding), ...r.malformed.map(m => m.finding), ...r.unmatched];
  const anyStamp = findings.some(f => f.claim_key);
  const stamped = r.confirmed.filter(c => c.joinedBy === 'claim-key' || c.joinedBy === 'claim-key-contested').length;
  if (r.confirmed.length > 0 && !anyStamp) {
    lines.push('', `⚠  No finding in this report carried a claim key, so every join below matched where a claim sits rather than which claim it is. A claim that came to occupy a tested line cannot be told from the claim that was tested. Have the scanner forward ${CLAIM_KEY_FINGERPRINT} from the SARIF export.`);
  } else if (stamped < r.confirmed.length) {
    lines.push('', `⚠  ${r.confirmed.length - stamped} of ${r.confirmed.length} findings carried no claim key and were joined on the weaker match; each is labelled below.`);
  }
  for (const c of r.confirmed) lines.push('', formatOutcome(c.record, c.entry));
  for (const a of r.ambiguous) {
    lines.push('', `Ambiguous  ${a.finding.id} (${a.finding.template_id}) fits ${a.candidates.length} claims — pick one and record it by hand:`);
    for (const c of a.candidates) lines.push(`  guardlink hypothesis confirm ${c.file}:${c.line} --evidence "…"`);
  }
  for (const s of r.stale) {
    const at = s.finding.annotation ? `, stamped at ${s.finding.annotation.file}:${s.finding.annotation.line}` : '';
    lines.push('', `Stale      ${s.finding.id} (${s.finding.template_id}) was tested against a claim that is no longer in the model — deleted, or its asset, threat, refs, description or file edited.`);
    lines.push(`           claim key ${short(s.finding.claim_key ?? '', 24)}${at}`);
    lines.push(`           Nothing was recorded. Any claim standing there now is a different claim, so this evidence does not belong to it — re-test against the tree as it is (guardlink hypothesis next).`);
  }
  for (const m of r.malformed) {
    lines.push('', `Malformed  ${m.finding.id} (${m.finding.template_id}) carried ${JSON.stringify(short(m.stamp.value, 40))} in ${m.stamp.field}, which is not a claim key (expected ${CLAIM_KEY_PATTERN.source}).`);
    lines.push(`           Nothing was recorded and no weaker join was tried: the value says nothing about which claim was tested, so a confirmation from it would rest on what was just rejected. Whatever produced this report is emitting something else under a guardlink name — fix that, or drop the field and the coarse joins apply again.`);
  }
  for (const u of r.unmatched) lines.push('', `Unmatched  ${u.id} (${u.template_id}, ${u.title || 'no title'}): no claim carries this location, asset/threat or CWE. If it is real, annotate it first.`);
  // A note, never a refusal: the valid key was used and the join stands. But a
  // producer putting something else under a guardlink name is worth saying out
  // loud — selecting the good key silently is the hiding already rejected once.
  const junk = findings.flatMap(f => f.junk_stamps.map(s => ({ f, s })));
  if (junk.length > 0) {
    lines.push('', `Note       a valid claim key was used, but ${junk.length} other ${junk.length === 1 ? 'value' : 'values'} arrived under a guardlink name and ${junk.length === 1 ? 'is' : 'are'} not claim keys. The joins above are unaffected; whatever wrote these should stop:`);
    for (const { f, s } of junk) lines.push(`  ${f.id}: ${JSON.stringify(short(s.value, 40))} in ${s.field}`);
  }
  // A conflict is louder than junk: an extra key that is WELL-FORMED is likelier
  // to be trusted than an obviously broken one, and it names a different claim,
  // so it changes which exposure gets confirmed rather than merely being noise.
  //
  // Split by what actually happened. A contest on a finding that CONFIRMED has
  // an outcome above, labelled CONTESTED, with its write withheld. A contest on
  // one that did not confirm has none of those — its own bucket above already
  // said what became of it — so it must not be told it has an outcome.
  //
  // One rival KEY is one disagreement, however many surfaces carried it — the
  // winner path already treats the same key in two surfaces as agreement, and
  // the rivals have to be read the same way. The headers count findings, which
  // is what they say they count.
  const rivalsOf = (fs: ScanFinding[]) => fs.flatMap(f => {
    const fieldsByValue = new Map<string, string[]>();
    for (const s of f.rival_stamps) fieldsByValue.set(s.value, [...(fieldsByValue.get(s.value) ?? []), s.field]);
    return [...fieldsByValue].map(([value, fields]) => ({ f, value, fields }));
  });
  const decided = rivalsOf(r.confirmed.map(c => c.finding));
  const undecided = rivalsOf(findings.filter(f => !r.confirmed.some(c => c.finding === f)));
  const count = (g: { f: ScanFinding }[]) => new Set(g.map(x => x.f)).size;
  if (decided.length > 0) {
    lines.push('', `⚠  Contested  ${count(decided) === 1 ? 'a finding' : `${count(decided)} findings`} carried more than one claim key, naming different claims — the report contradicts itself about which exposure was tested. The winner above was chosen by precedence, not by agreement, so it is labelled CONTESTED and no @confirmed is written to source for it. The key used is listed on the outcome; the ones it beat:`);
    for (const { f, value, fields } of decided) lines.push(`  ${f.id}: also claimed ${short(value, 24)} in ${fields.join(', ')}`);
    lines.push(`           Fix whatever emits two keys for one finding. To record one of these deliberately: guardlink hypothesis confirm <file:line> --evidence "…" --write`);
  }
  if (undecided.length > 0) {
    const n = count(undecided);
    lines.push('', `⚠  Contested  ${n === 1 ? 'a finding that was not recorded' : `${n} findings that were not recorded`} also carried more than one claim key, naming different claims. Nothing was confirmed for ${n === 1 ? 'it' : 'them'} — see above for why — so there is no outcome and no write to withhold; the contest is reported because whatever emits two keys for one finding is still wrong:`);
    for (const { f, value, fields } of undecided) lines.push(`  ${f.id}: used ${short(f.claim_key ?? '', 24)}, also claimed ${short(value, 24)} in ${fields.join(', ')}`);
  }
  return lines.join('\n');
}
