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
 * @comment -- "importScan() joins a finding carrying a claim_key only to the claim whose key is that key, and reports the rest as stale rather than confirming them; the key names the claim itself, so it survives a line move and an edit to the code beneath it, and separates a sibling claim that landed on the tested line. Two byte-identical claims in one file share a digest and are told apart only by an ordinal in document order, so deleting the earlier one hands its key to the survivor"
 * @audit #cli -- "The stale bucket refuses a join rather than guessing it; a human decides whether to re-test or record the outcome by hand, and needs to see these — the CLI exits non-zero when any finding lands there"
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import type { ThreatModel } from '../types/index.js';
import { hasEvidenceWords } from '../gate/lint.js';
import { redactEvidence } from '../analyze/format.js';
import { readHypotheses, writeHypotheses, emptyHypotheses, type HypothesisEntry, type HypothesisOutcome, type HypothesisSource, type HypothesesLedger } from './ledger.js';
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
  /** The claim key the export stamped onto the finding (`guardlink/claimKey`), when it carries one. */
  claim_key: string | null;
  evidence: { request: string | null; response: string | null; matched_patterns: string[]; data: Record<string, unknown> };
}

export type JoinedBy = 'location' | 'asset-threat' | 'cwe';

export interface ImportResult {
  scanId: string;
  confirmed: { finding: ScanFinding; record: HypothesisRecord; entry: HypothesisEntry; joinedBy: JoinedBy }[];
  ambiguous: { finding: ScanFinding; candidates: HypothesisRecord[] }[];
  /** The finding's claim key matches no candidate's: the claim it was tested against is not in the model any more. */
  stale: { finding: ScanFinding; candidates: HypothesisRecord[] }[];
  unmatched: ScanFinding[];
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);
const bare = (r: string): string => r.trim().replace(/^#/, '').toLowerCase();

function coerceFinding(raw: unknown, i: number): ScanFinding | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const ann = (o.annotation ?? o.location) as Record<string, unknown> | undefined;
  const ev = (o.evidence ?? {}) as Record<string, unknown>;
  const cwe = Array.isArray(o.cwe_ids) ? o.cwe_ids.filter((c): c is string => typeof c === 'string') : [];
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
    claim_key: str(o.claim_key) ?? str(ann?.claim_key),
    evidence: {
      request: str(ev.request), response: str(ev.response),
      matched_patterns: Array.isArray(ev.matched_patterns) ? ev.matched_patterns.filter((p): p is string => typeof p === 'string') : [],
      data: ev.data && typeof ev.data === 'object' ? (ev.data as Record<string, unknown>) : {},
    },
  };
}

/** Evidence text for the ledger: what the template sent and what came back, redacted, plus the scan id. */
export function scanEvidence(scanId: string, f: ScanFinding): string {
  const red = redactEvidence({ ...f.evidence, timestamp: undefined }) as { request: string | null; response: string | null; matched_patterns: string[] };
  const cut = (s: string | null): string => (s ? s.replace(/\s+/g, ' ').trim().slice(0, 240) : '(none)');
  const parts = [`${f.template_id}: ${f.title || 'finding'}`, `request: ${cut(red.request)}`, `response: ${cut(red.response)}`];
  if (red.matched_patterns.length > 0) parts.push(`matched: ${red.matched_patterns.join(', ')}`);
  parts.push(`(scan ${scanId})`);
  return parts.join('; ');
}

/**
 * Join each finding to a claim — by annotation location, then by asset and
 * threat, then by CWE — and record the confirmed ones. A finding that fits
 * more than one claim is reported as ambiguous, never guessed.
 *
 * A finding that carries a claim key joins only to the claim whose key is that
 * key. The key comes from the SARIF export (`guardlink/claimKey`) and is the
 * one the ledger already keys an entry on: a digest of the claim's own words,
 * so it survives every edit that is not the claim — a line move, and an edit to
 * the code beneath it. That is what separates a finding from a sibling claim
 * that landed on the line it was tested at: same file, same line, same asset,
 * same threat, therefore the same threat id, and nothing else on the finding
 * tells them apart. Every claim has a key, so there is no unstamped-claim case:
 * a key that matches nothing means the claim it named is gone, and the finding
 * is reported as stale rather than joined to whatever else is standing there.
 *
 * Two consequences worth naming. A key matches at most one claim — keys are
 * unique within a model — so this never leaves an ambiguous set behind; and it
 * can narrow a set that the asset-and-threat join had left ambiguous down to
 * the one claim the stamp names.
 *
 * The bound: two BYTE-IDENTICAL claims in one file — same verb, asset, threat,
 * external refs and description — share a digest and are told apart only by an
 * ordinal in document order. Delete the earlier one and the survivor inherits
 * `…:0`, the deleted claim's exact key, so a finding stamped against the first
 * joins to the second. That is the shape this function exists to refuse,
 * surviving at a strictly narrower population. Separately, rewording a claim's
 * own description re-keys it, so a stamp from before the rewording is refused.
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

  const result: ImportResult = { scanId, confirmed: [], ambiguous: [], stale: [], unmatched: [] };
  const ledger = loadForWrite(root);
  for (const f of findings) {
    let candidates: HypothesisRecord[] = [];
    let joinedBy: JoinedBy | null = null;
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
    if (f.claim_key) {
      const same = candidates.filter(r => r.key === f.claim_key);
      if (same.length === 0) { result.stale.push({ finding: f, candidates }); continue; }
      candidates = same;
    }
    if (candidates.length > 1) { result.ambiguous.push({ finding: f, candidates }); continue; }
    const record = candidates[0];
    const entry = upsert(ledger, record, 'confirmed', {
      evidence: scanEvidence(scanId, f), by: `${input.by}:${f.template_id}`, at: input.at,
      source: { kind: 'scan', scan_id: scanId, template_id: f.template_id, confidence: f.confidence },
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
  const desc = entry.evidence.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `@confirmed ${record.threat} on ${record.asset}${sev}${cwe.length ? ` ${cwe.join(' ')}` : ''} -- "${desc}"`;
}

/**
 * Insert the line directly beneath the @exposes, with the same comment
 * prefix. Refuses when a @confirmed for the pair already sits there.
 */
export function writeConfirmedLine(root: string, record: HypothesisRecord, line: string): { file: string; line: number } {
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
