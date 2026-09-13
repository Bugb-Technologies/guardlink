/**
 * GuardLink Hypotheses — recording outcomes.
 *
 * `recordOutcome` writes one result with its evidence and the claim's current
 * anchor. `importScan` joins a cxg report's findings to claims and records
 * the confirmed ones. `confirmedLine` and `writeConfirmedLine` offer, and on
 * request insert, the `@confirmed` annotation that reflects a confirmation
 * in the source, right beneath its `@exposes`.
 *
 * @exposes #cli to #arbitrary-write [medium] cwe:CWE-73 -- "writeConfirmedLine() edits the source file a claim's location names; importScan() reads the scan path the user passed"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "Both paths are resolved under the project root and refused outside it; the edit inserts one line beneath an @exposes whose text is checked before anything is written"
 * @exposes #cli to #insecure-deser [low] cwe:CWE-502 -- "importScan() JSON.parses a scan report"
 * @mitigates #cli against #insecure-deser using #config-validation -- "Only the fields the loader reads are taken, each coerced to its type; evidence goes through redactEvidence before it is stored"
 * @flows ScanReport -> #cli via importScan -- "cxg findings joined to claims"
 * @flows #cli -> SourceFiles via writeConfirmedLine -- "The @confirmed line, on --write"
 * @handles internal on #cli -- "Request and response evidence from scans, redacted"
 * @comment -- "A confirmation is held to the same evidence bar the gate holds @confirmed to; a refutation needs evidence too, just not the same words, because 'the validator rejected it' is evidence of absence"
 * @comment -- "importScan() resolves a finding carrying a claim_key against the whole record set BEFORE the location/asset-threat/CWE tiers, which run only for an unstamped finding; a key that names no claim is stale, never re-joined by a coarser tier. The key names the claim itself, so it survives a line move and an edit to the code beneath it, and separates a sibling claim that landed on the tested line. Two byte-identical claims in one file share a digest and are told apart only by an ordinal in document order, so deleting the earlier one hands its key to the survivor"
 * @comment -- "The claim key is read under every name in CLAIM_KEY_NAMES and from every container generated from CLAIM_KEY_SURFACES (src/parser/claim-key.ts) — the same definition guardlink sarif emits through — so the finding's top level, its annotation object, and either emitted surface nested under its own name at either level all resolve. Names AND surfaces live in that one definition because each time only one dimension was shared the disagreement simply moved to the other, and an unrecognised stamp takes the weaker join while the output tells the operator to start sending the stamp they already sent"
 * @comment -- "The @validates below sits here rather than on its test on purpose: .guardlink/config.json excludes the tests directory and every nested one from the scan, so an annotation moved into tests/hypothesis.test.ts is never parsed — it would leave the threat model entirely and a lookup of the validations for #cli would answer nothing instead of pointing anywhere. Every validation in this repo lives with the implementation it proves and names its test in the description; see src/parser/parse-file.ts, src/parser/comment-strip.ts and src/mcp/subgraph.ts. Do not move it"
 * @validates #config-validation for #cli -- "tests/hypothesis.test.ts forwards a real generateSarif result's emitted surfaces into the scan finding without naming a field, in every placement generated from CLAIM_KEY_SURFACES, so neither the names nor the containers the reader accepts can drift from what the export writes"
 * @comment -- "A stamp is only taken as ours when it matches CLAIM_KEY_PATTERN; three names across six containers include free-form bags another tool may also write a claim_key into. All candidates are collected first and the shape check partitions them AFTER, because validating only the first hit checked the wrong candidate — a foreign placeholder sorting ahead of our own emitted claimKey in the same forwarded bag buried a valid key. The key is the first VALID candidate in precedence order; only when none is valid is the finding refused as malformed, and unshaped values found beside a good key are reported as a note that changes neither the join nor the exit status"
 * @comment -- "confirmedLine() states the join provenance in a scan-derived @confirmed, because that line is a claim in someone's repository that this exposure was tested, not a report line. The CLI refuses to write one that was not key-verified; the provenance in the text is what keeps that refusal meaningful after the caller changes"
 * @exposes #cli to #arbitrary-write [high] cwe:CWE-74 -- "scanEvidence() interpolates scan-report-controlled strings — template_id, title, matched_patterns, request, response — into the @confirmed description writeConfirmedLine() splices into a source file; a newline in any of them ends the annotation and places report-controlled text on the next line of someone's doc-block, in the syntax their threat model is parsed from"
 * @mitigates #cli against #arbitrary-write using #input-sanitize -- "Every scan-controlled value passes through oneLine() at the one boundary it enters through (scanEvidence) rather than per interpolation, then escapeDesc() for quotes and backslashes; and writeConfirmedLine() re-parses the assembled line with parseLine and refuses anything that is not exactly one @confirmed, so a value that broke out of its quotes or its line is never written"
 * @validates #input-sanitize for #cli -- "tests/hypothesis.test.ts drives a scan finding whose title, template_id and matched_patterns each carry a real newline through the real write path and asserts the file gains one annotation line that parses back as one @confirmed"
 * @audit #cli -- "The stale bucket refuses a join rather than guessing it, and offers no by-hand target on purpose: the claims the coarse tiers would have named are different claims, so recording this evidence against one is the confirmation the key just refused. The malformed bucket refuses for the same reason one level earlier. The CLI exits non-zero when any finding lands in either"
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import type { ThreatModel } from '../types/index.js';
import { hasEvidenceWords } from '../gate/lint.js';
import { redactEvidence } from '../analyze/format.js';
import { CLAIM_KEY_NAMES, CLAIM_KEY_SURFACES, isClaimKey } from '../parser/claim-key.js';
import { parseLine } from '../parser/parse-line.js';
// `oneLine` and `escapeDesc` are the treatment this repo already applies at every
// annotation write site; reused rather than re-implemented so a third copy cannot
// drift. No cycle: src/review only imports parser modules and types.
import { oneLine, escapeDesc } from '../review/index.js';
import { readHypotheses, writeHypotheses, emptyHypotheses, type HypothesisEntry, type HypothesisOutcome, type HypothesisSource, type HypothesesLedger, type JoinedBy } from './ledger.js';
import { classifyHypotheses, type HypothesisRecord } from './classify.js';

export interface OutcomeInput {
  evidence: string;
  by: string;
  /** ISO 8601. The caller supplies it so the ledger stays deterministic under test. */
  at: string;
  source?: HypothesisSource;
}

const inside = (root: string, p: string): string => {
  const rootAbs = resolve(root);
  const abs = resolve(rootAbs, p);
  if (abs !== rootAbs && !abs.startsWith(rootAbs + sep)) throw new Error(`${p} is outside the project root`);
  return abs;
};

/** The exposure at `file:line`, or an error that says what is there instead. */
export function resolveTarget(model: ThreatModel, target: string): HypothesisRecord {
  const m = /^(.+):(\d+)$/.exec(target.trim());
  if (!m) throw new Error(`Target must be file:line, got ${JSON.stringify(target)}`);
  const file = m[1].replace(/\\/g, '/');
  const line = Number(m[2]);
  const c = classifyHypotheses(model, { status: 'absent', ledger: null });
  const hits = c.records.filter(r => r.verb === 'exposes' && r.file === file && r.line === line);
  if (hits.length === 1) return hits[0];
  if (hits.length === 0) throw new Error(`no @exposes at ${file}:${line}`);
  throw new Error(`${hits.length} @exposes at ${file}:${line}; the parser keeps one annotation per line, so this file needs a look`);
}

function checkEvidence(outcome: HypothesisOutcome, evidence: string): void {
  if (!evidence || evidence.trim().length === 0) throw new Error(`An outcome needs evidence: what was tried and what came back.`);
  if (outcome === 'confirmed' && !hasEvidenceWords(evidence)) {
    throw new Error('A confirmation needs evidence in hand: a request and its response, a reproduction, a scan with proof. Say what was sent and what came back.');
  }
}

function upsert(ledger: HypothesesLedger, record: HypothesisRecord, outcome: HypothesisOutcome, input: OutcomeInput): HypothesisEntry {
  const anchor = record.location.anchor ? { scope: record.location.anchor.scope, symbol: record.location.anchor.symbol, hash: record.location.anchor.hash } : null;
  const fresh = { outcome, evidence: input.evidence.trim(), by: input.by, at: input.at, anchor, source: input.source ?? { kind: 'manual' as const } };
  const i = ledger.entries.findIndex(e => e.key === record.key);
  if (i >= 0) {
    const old = ledger.entries[i];
    const { history, key: _k, claim: _c, file: _f, line: _l, ...prior } = old;
    const entry: HypothesisEntry = { key: record.key, claim: record.claim, file: record.file, line: record.line, ...fresh, history: [prior, ...history] };
    ledger.entries[i] = entry;
    return entry;
  }
  const entry: HypothesisEntry = { key: record.key, claim: record.claim, file: record.file, line: record.line, ...fresh, history: [] };
  ledger.entries.push(entry);
  return entry;
}

function loadForWrite(root: string): HypothesesLedger {
  const read = readHypotheses(root);
  if (read.status === 'corrupt') throw new Error(`.guardlink/hypotheses.json is unreadable (${read.error}); fix or remove it before recording an outcome`);
  return read.ledger ?? emptyHypotheses();
}

/** Record one outcome for the exposure at `target` (file:line). */
export function recordOutcome(root: string, model: ThreatModel, target: string, outcome: HypothesisOutcome, input: OutcomeInput): { record: HypothesisRecord; entry: HypothesisEntry } {
  checkEvidence(outcome, input.evidence);
  const record = resolveTarget(model, target);
  const ledger = loadForWrite(root);
  const entry = upsert(ledger, record, outcome, input);
  writeHypotheses(root, ledger);
  return { record, entry };
}

export interface ScanFinding {
  id: string;
  template_id: string;
  severity: string;
  confidence: number | string | null;
  title: string;
  cwe_ids: string[];
  annotation: { file: string; line: number } | null;
  asset: string | null;
  threat: string | null;
  /**
   * The claim key the export stamped onto the finding, when it carries one, read
   * under every name in `CLAIM_KEY_NAMES` and from every container a consumer
   * puts it in — see `findingStamp`. A stamp guardlink fails to recognise is
   * worse than no stamp: it takes the weaker join, and the report that carried
   * the discriminator gets told to start sending one.
   *
   * Null when the finding carried no stamp AND when EVERY stamp it carried is
   * unshaped — the latter lands in `malformed_stamp` instead, so the two are
   * never confused for each other.
   */
  claim_key: string | null;
  /**
   * Candidates were present under our names and NONE was shaped like a claim
   * key. Its own state: a producer emitting something else under our name is
   * neither "unstamped" nor "the claim is gone", and folding it into either
   * loses the one thing worth knowing about it.
   */
  malformed_stamp: ScanStamp | null;
  /**
   * Unshaped candidates found ALONGSIDE a valid key, which was used. Reported as
   * a note and nothing more: selecting the good key must not silently hide that
   * something is emitting garbage under a guardlink name, but it is not grounds
   * to refuse a join the report identified precisely.
   */
  junk_stamps: ScanStamp[];
  evidence: { request: string | null; response: string | null; matched_patterns: string[]; data: Record<string, unknown> };
}

/** A value found under one of the claim key's accepted names, and where. */
export interface ScanStamp {
  value: string;
  /** The path it arrived under, e.g. `annotation.properties.claimKey`. */
  field: string;
}

export type { JoinedBy } from './ledger.js';

export interface ImportResult {
  scanId: string;
  confirmed: { finding: ScanFinding; record: HypothesisRecord; entry: HypothesisEntry; joinedBy: JoinedBy }[];
  ambiguous: { finding: ScanFinding; candidates: HypothesisRecord[] }[];
  /**
   * The finding's claim key names no claim in the model: the claim it was tested
   * against is gone. No candidates are offered — whatever the coarse tiers would
   * have matched is a different claim, and recording this evidence against it by
   * hand is the exact confirmation the key just refused.
   */
  stale: { finding: ScanFinding }[];
  /**
   * A stamp arrived under one of our names that is not a claim key. Reported,
   * never joined: it says nothing about which claim was tested, so guessing from
   * the coarse tiers would be a confirmation resting on a value we rejected.
   */
  malformed: { finding: ScanFinding; stamp: ScanStamp }[];
  unmatched: ScanFinding[];
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);
const bare = (r: string): string => r.trim().replace(/^#/, '').toLowerCase();
const bag = (v: unknown): Record<string, unknown> | undefined => (v && typeof v === 'object' ? v as Record<string, unknown> : undefined);

/**
 * The stamp a scan report carries, under any name in `CLAIM_KEY_NAMES` and in
 * any container a real consumer puts it in, with the field it arrived in so a
 * value that is not a claim key can be reported precisely.
 *
 * The containers are GENERATED, not listed: each level a key can sit at — the
 * finding itself, its `annotation` object — carrying the key directly, or
 * carrying any emitted surface in `CLAIM_KEY_SURFACES` nested under that
 * surface's own name, which is what copying a SARIF result member wholesale
 * produces. Adding a surface to that definition widens this with no edit here.
 * A hand-written list is how the reader came to refuse a shape the export
 * advertised.
 *
 * EVERY candidate is collected, in the precedence those two definitions fix,
 * and the shape check partitions them afterwards. Validating only the first hit
 * checked the wrong candidate: several of these containers are free-form bags
 * another tool may also write a `claim_key` into, so a foreign placeholder
 * sorting earlier than our own emitted `claimKey` — in the same object, from the
 * same forwarded bag — buried a perfectly good key and the finding was refused.
 * A validity check placed after a selection step validates the wrong thing.
 *
 * The key is therefore the first VALID candidate in precedence order, so a
 * report that contradicts itself resolves the way it always did.
 */
function findingStamps(o: Record<string, unknown>, ann: Record<string, unknown> | undefined): ScanStamp[] {
  const found: ScanStamp[] = [];
  for (const [level, at] of [[o, ''], [ann, 'annotation.']] as const) {
    if (!level) continue;
    const containers: [Record<string, unknown> | undefined, string][] = [[level, at]];
    for (const s of CLAIM_KEY_SURFACES) containers.push([bag(level[s.container]), `${at}${s.container}.`]);
    for (const [c, prefix] of containers) {
      if (!c) continue;
      for (const name of CLAIM_KEY_NAMES) {
        const v = str(c[name]);
        if (v) found.push({ value: v, field: `${prefix}${name}` });
      }
    }
  }
  return found;
}

function coerceFinding(raw: unknown, i: number): ScanFinding | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const ann = (o.annotation ?? o.location) as Record<string, unknown> | undefined;
  const ev = (o.evidence ?? {}) as Record<string, unknown>;
  const cwe = Array.isArray(o.cwe_ids) ? o.cwe_ids.filter((c): c is string => typeof c === 'string') : [];
  const stamps = findingStamps(o, ann);
  const valid = stamps.filter(s => isClaimKey(s.value));
  const invalid = stamps.filter(s => !isClaimKey(s.value));
  return {
    id: str(o.id) ?? `finding-${i + 1}`,
    template_id: str(o.template_id) ?? 'unknown-template',
    severity: str(o.severity) ?? 'unset',
    confidence: typeof o.confidence === 'number' || typeof o.confidence === 'string' ? o.confidence : null,
    title: str(o.title) ?? '',
    cwe_ids: cwe,
    annotation: ann && typeof ann.file === 'string' && typeof ann.line === 'number' ? { file: ann.file, line: ann.line } : null,
    asset: str(o.asset) ?? str(ann?.asset),
    threat: str(o.threat) ?? str(ann?.threat),
    claim_key: valid[0]?.value ?? null,
    malformed_stamp: valid.length === 0 ? invalid[0] ?? null : null,
    junk_stamps: valid.length > 0 ? invalid : [],
    evidence: {
      request: str(ev.request), response: str(ev.response),
      matched_patterns: Array.isArray(ev.matched_patterns) ? ev.matched_patterns.filter((p): p is string => typeof p === 'string') : [],
      data: ev.data && typeof ev.data === 'object' ? (ev.data as Record<string, unknown>) : {},
    },
  };
}

/**
 * Evidence text for the ledger: what the template sent and what came back,
 * redacted, plus the scan id.
 *
 * EVERY value here comes out of a scan report, and this string can be written
 * into someone's source as an `@confirmed` description. So all of them go
 * through `one()` — the single boundary they can enter through — rather than
 * each interpolation remembering. A per-field helper is exactly how
 * `template_id`, `title` and `matched_patterns` came to be interpolated raw
 * while only `request` and `response` were collapsed, and a newline in any of
 * them ends our line and puts report-controlled text on the next one, in the
 * syntax the threat model is parsed from.
 */
export function scanEvidence(scanId: string, f: ScanFinding): string {
  const red = redactEvidence({ ...f.evidence, timestamp: undefined }) as { request: string | null; response: string | null; matched_patterns: string[] };
  const one = (s: string | null | undefined, fallback: string): string => {
    const flat = oneLine(s ?? '').slice(0, 240);
    return flat.length > 0 ? flat : fallback;
  };
  const parts = [
    `${one(f.template_id, 'unknown-template')}: ${one(f.title, 'finding')}`,
    `request: ${one(red.request, '(none)')}`,
    `response: ${one(red.response, '(none)')}`,
  ];
  if (red.matched_patterns.length > 0) parts.push(`matched: ${one(red.matched_patterns.join(', '), '(none)')}`);
  parts.push(`(scan ${one(scanId, 'scan')})`);
  return parts.join('; ');
}

/**
 * Join each finding to a claim and record the confirmed ones.
 *
 * A claim key RESOLVES the join; it does not narrow one. A finding that carries
 * a key is looked up against the whole record set, and that lookup is the whole
 * answer: it hits exactly one claim (keys are unique within a model) or it hits
 * none, in which case the claim it named is gone and the finding is stale. The
 * coarse tiers — annotation location, then asset and threat, then CWE — run
 * ONLY for a finding that carries no key, and a finding that fits more than one
 * of them is reported as ambiguous, never guessed.
 *
 * The order matters and is not an optimisation. Were the tiers to run first,
 * the location tier would pick whatever claim now sits on the tested line and
 * the key would only get to veto it — so a claim that merely DRIFTED (its file
 * edited above it, moving its line) would be reported stale while it is alive
 * and holding the stamped key, and a finding carrying nothing but a key — the
 * most precise identifier in the system — would be reported unmatched. A wrong
 * location match must never beat a correct key.
 *
 * The key is the one the ledger already keys an entry on: a digest of the
 * claim's own words, so it survives every edit that is not the claim — a line
 * move, and an edit to the code beneath it. That is what separates a finding
 * from a sibling claim that landed on the line it was tested at: same file,
 * same line, same asset, same threat, therefore the same threat id, and nothing
 * else on the finding tells them apart.
 *
 * The bound: two BYTE-IDENTICAL claims in one file — same verb, asset, threat,
 * external refs and description — share a digest and are told apart only by an
 * ordinal in document order. Delete the earlier one and the survivor inherits
 * `…:0`, the deleted claim's exact key, so a finding stamped against the first
 * joins to the second. That is the shape this function exists to refuse,
 * surviving at a strictly narrower population. Separately, rewording a claim's
 * own description re-keys it, so a stamp from before the rewording is refused.
 *
 * Every confirmation records WHICH identity joined it (`joined_by`), because a
 * key-verified confirmation and one taken on the coarse tiers must not be
 * indistinguishable after the fact.
 */
export function importScan(root: string, model: ThreatModel, scanPath: string, input: { by: string; at: string }): ImportResult {
  const abs = inside(root, scanPath);
  if (!existsSync(abs)) throw new Error(`No such scan report: ${scanPath}`);
  let data: unknown;
  try { data = JSON.parse(readFileSync(abs, 'utf-8')); } catch (e) { throw new Error(`Scan report is not JSON: ${(e as Error).message}`); }
  const o = (data && typeof data === 'object' ? data : {}) as Record<string, unknown>;
  const scanId = str(o.scan_id) ?? 'scan';
  const findings = (Array.isArray(o.findings) ? o.findings : []).map(coerceFinding).filter((f): f is ScanFinding => f !== null);

  const records = classifyHypotheses(model, { status: 'absent', ledger: null }).records.filter(r => r.verb === 'exposes');
  const canon = new Map<string, string>();
  for (const a of model.assets) {
    const c = a.id ? a.id.toLowerCase() : a.path.join('.').toLowerCase();
    canon.set(a.path.join('.').toLowerCase(), c); canon.set(a.path[a.path.length - 1].toLowerCase(), c); if (a.id) canon.set(a.id.toLowerCase(), c);
  }
  const assetOf = (r: string): string => canon.get(bare(r)) ?? bare(r);
  const threatCanon = new Map<string, string>();
  const threatCwes = new Map<string, Set<string>>();
  for (const t of model.threats) {
    const c = t.id ? t.id.toLowerCase() : t.canonical_name.toLowerCase();
    threatCanon.set(t.name.toLowerCase(), c); threatCanon.set(t.canonical_name.toLowerCase(), c); if (t.id) threatCanon.set(t.id.toLowerCase(), c);
    threatCwes.set(c, new Set(t.external_refs.filter(x => /^cwe:/i.test(x)).map(x => x.slice(4).toUpperCase())));
  }
  const threatOf = (r: string): string => threatCanon.get(bare(r)) ?? bare(r);
  const cwesOf = (r: HypothesisRecord): Set<string> => {
    const own = new Set((model.exposures.find(e => e.location === r.location)?.external_refs ?? []).filter(x => /^cwe:/i.test(x)).map(x => x.slice(4).toUpperCase()));
    for (const c of threatCwes.get(threatOf(r.threat)) ?? []) own.add(c);
    return own;
  };

  const result: ImportResult = { scanId, confirmed: [], ambiguous: [], stale: [], malformed: [], unmatched: [] };
  const ledger = loadForWrite(root);
  const byKey = new Map(records.map(r => [r.key, r]));
  for (const f of findings) {
    let candidates: HypothesisRecord[] = [];
    let joinedBy: JoinedBy | null = null;
    if (f.malformed_stamp) { result.malformed.push({ finding: f, stamp: f.malformed_stamp }); continue; }
    if (f.claim_key) {
      const named = byKey.get(f.claim_key);
      if (!named) { result.stale.push({ finding: f }); continue; }
      candidates = [named];
      joinedBy = 'claim-key';
    } else {
      if (f.annotation) {
        const file = f.annotation.file.replace(/\\/g, '/');
        candidates = records.filter(r => r.file === file && r.line === f.annotation!.line);
        if (candidates.length > 0) joinedBy = 'location';
      }
      if (!joinedBy && (f.asset || f.threat)) {
        candidates = records.filter(r => (!f.asset || assetOf(r.asset) === assetOf(f.asset)) && (!f.threat || threatOf(r.threat) === threatOf(f.threat)));
        if (candidates.length > 0) joinedBy = 'asset-threat';
      }
      if (!joinedBy && f.cwe_ids.length > 0) {
        const want = new Set(f.cwe_ids.map(c => c.toUpperCase()));
        candidates = records.filter(r => [...cwesOf(r)].some(c => want.has(c)));
        if (candidates.length > 0) joinedBy = 'cwe';
      }
      if (!joinedBy) { result.unmatched.push(f); continue; }
      if (candidates.length > 1) { result.ambiguous.push({ finding: f, candidates }); continue; }
    }
    const record = candidates[0];
    const entry = upsert(ledger, record, 'confirmed', {
      evidence: scanEvidence(scanId, f), by: `${input.by}:${f.template_id}`, at: input.at,
      source: { kind: 'scan', scan_id: scanId, template_id: f.template_id, confidence: f.confidence, joined_by: joinedBy },
    });
    result.confirmed.push({ finding: f, record, entry, joinedBy });
  }
  if (result.confirmed.length > 0) writeHypotheses(root, ledger);
  return result;
}

/** The `@confirmed` annotation that reflects a confirmation, ready to paste. */
export function confirmedLine(record: HypothesisRecord, entry: HypothesisEntry): string {
  const cwe = record.refs;
  const sev = record.severity && record.severity !== 'unset' ? ` [${record.severity}]` : '';
  const desc = escapeDesc(oneLine(`${entry.evidence}${writtenProvenance(entry)}`));
  return `@confirmed ${record.threat} on ${record.asset}${sev}${cwe.length ? ` ${cwe.join(' ')}` : ''} -- "${desc}"`;
}

/**
 * What an `@confirmed` written from a scan says about how it was established.
 *
 * An `@confirmed` in source is not a report line — it is a claim in the
 * repository that this exposure was tested and proven, read by every later scan
 * and by reviewers, and a coarse-joined one may be about a different exposure
 * entirely. So a scan-derived line states that its evidence reached this claim
 * by the claim's own key. Without that, the rule refusing to write the others
 * lives only in the caller, and the next person to loosen the join silently
 * reuses a path that writes unmarked claims into someone's source.
 *
 * A manual confirmation renders unchanged: it is human evidence about a named
 * target, there is no join, and nothing about it is in question.
 */
function writtenProvenance(entry: HypothesisEntry): string {
  if (entry.source.kind !== 'scan' || entry.source.joined_by !== 'claim-key') return '';
  return '; key-verified: the scan stamped this claim\'s own claim key';
}

/**
 * Insert the line directly beneath the @exposes, with the same comment
 * prefix. Refuses when a @confirmed for the pair already sits there, and
 * refuses a line that does not parse back as one `@confirmed`.
 *
 * The re-parse is the structural half of the same guard `confirmedLine`'s
 * collapse gives: the description is assembled from a scan report, and a value
 * that broke out of its quotes or its line would land in source as something
 * the next parse reads differently from what we thought we wrote. Checking here
 * rather than in the caller means no caller can skip it. Same reason, and the
 * same pairing, as `buildAcceptLines` in `src/review/index.ts`.
 */
export function writeConfirmedLine(root: string, record: HypothesisRecord, line: string): { file: string; line: number } {
  const parsed = parseLine(line, { file: record.file, line: record.line + 1 });
  if (parsed.annotation?.verb !== 'confirmed') {
    throw new Error(`Refusing to write a line that does not parse back as one @confirmed: ${JSON.stringify(line.slice(0, 120))}`);
  }
  const abs = inside(root, record.file);
  const lines = readFileSync(abs, 'utf-8').split('\n');
  const idx = record.line - 1;
  const src = lines[idx];
  if (src === undefined || !src.includes('@exposes')) throw new Error(`${record.file}:${record.line} does not carry an @exposes any more; re-parse and try again`);
  const pair = `@confirmed ${record.threat} on ${record.asset}`;
  if (lines.slice(idx + 1, idx + 6).some(l => l.includes(pair))) throw new Error(`${record.file}:${record.line + 1} already carries ${pair}`);
  const prefix = src.slice(0, src.indexOf('@exposes'));
  lines.splice(idx + 1, 0, `${prefix}${line}`);
  writeFileSync(abs, lines.join('\n'));
  return { file: record.file, line: record.line + 1 };
}
