/**
 * GuardLink Hypotheses — the ledger file.
 *
 * `.guardlink/hypotheses.json` records what happened when an exposure was
 * tested against reality: confirmed or refuted, with the evidence, by whom,
 * when, and the code hash beneath the claim at that moment. It is the sibling
 * of `verified.json`, which records that a claim matches its code; this one
 * records that a claim was checked against the world.
 *
 * @exposes #cli to #arbitrary-write [low] cwe:CWE-73 -- "writeHypotheses() writes .guardlink/hypotheses.json under the root the caller resolved"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "The path is fixed relative to the project root (HYPOTHESES_FILE); nothing in an entry chooses where the file goes"
 * @flows LedgerFile -> #cli via readHypotheses -- "Outcomes read back for classification"
 * @flows #cli -> LedgerFile via writeHypotheses -- "Outcomes recorded"
 * @handles internal on #cli -- "Evidence strings from tests and scans; scan evidence is redacted before it is written"
 * @comment -- "A corrupt file is reported, never rebuilt in place: an outcome ledger that quietly emptied itself would turn refuted findings back into open ones"
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { AnchorScope } from '../types/index.js';
import { ANCHOR_HASH_VERSION } from '../structure/hash.js';

export const HYPOTHESES_FILE = '.guardlink/hypotheses.json';
export const HYPOTHESES_SCHEMA = 'guardlink.hypotheses/v1';

export type HypothesisOutcome = 'confirmed' | 'refuted';

export type HypothesisSource =
  | { kind: 'manual' }
  | { kind: 'scan'; scan_id: string; template_id: string; confidence: number | string | null };

export interface HypothesisAnchor { scope: AnchorScope; symbol: string | null; hash: string }

export interface HypothesisOutcomeRecord {
  outcome: HypothesisOutcome;
  evidence: string;
  /** `human:<name>` or `cxg:<template>`. */
  by: string;
  /** ISO 8601, UTC. */
  at: string;
  /** The claim's anchor when the outcome was recorded; null when the claim had none. */
  anchor: HypothesisAnchor | null;
  source: HypothesisSource;
}

export interface HypothesisEntry extends HypothesisOutcomeRecord {
  /** Stable claim key from `relationRecords`. */
  key: string;
  /** Display only; never matched on. */
  claim: string;
  file: string;
  line: number;
  /** Earlier outcomes for the same key, newest first. */
  history: HypothesisOutcomeRecord[];
}

export interface HypothesesLedger {
  schema: typeof HYPOTHESES_SCHEMA;
  anchor_hash_version: number;
  entries: HypothesisEntry[];
}

export type HypothesesStatus = 'present' | 'absent' | 'corrupt';

export interface HypothesesRead {
  status: HypothesesStatus;
  ledger: HypothesesLedger | null;
  error?: string;
}

export function emptyHypotheses(): HypothesesLedger {
  return { schema: HYPOTHESES_SCHEMA, anchor_hash_version: ANCHOR_HASH_VERSION, entries: [] };
}

const OUTCOMES = new Set<string>(['confirmed', 'refuted']);

function isOutcomeRecord(v: unknown): v is HypothesisOutcomeRecord {
  if (!v || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  const anchor = o.anchor as Record<string, unknown> | null | undefined;
  const source = o.source as Record<string, unknown> | undefined;
  return OUTCOMES.has(String(o.outcome)) && typeof o.evidence === 'string' && typeof o.by === 'string' && typeof o.at === 'string'
    && (anchor === null || (!!anchor && typeof anchor === 'object' && typeof anchor.hash === 'string' && typeof anchor.scope === 'string'))
    && !!source && typeof source === 'object' && (source.kind === 'manual' || (source.kind === 'scan' && typeof source.scan_id === 'string' && typeof source.template_id === 'string'));
}

function isEntry(v: unknown): v is HypothesisEntry {
  if (!isOutcomeRecord(v)) return false;
  const o = v as unknown as Record<string, unknown>;
  return typeof o.key === 'string' && typeof o.claim === 'string' && typeof o.file === 'string' && typeof o.line === 'number'
    && Array.isArray(o.history) && o.history.every(isOutcomeRecord);
}

export function readHypotheses(root: string): HypothesesRead {
  const path = join(root, HYPOTHESES_FILE);
  if (!existsSync(path)) return { status: 'absent', ledger: null };
  let raw: string;
  try { raw = readFileSync(path, 'utf-8'); } catch (e) { return { status: 'corrupt', ledger: null, error: `unreadable: ${(e as Error).message}` }; }
  let data: unknown;
  try { data = JSON.parse(raw); } catch (e) { return { status: 'corrupt', ledger: null, error: `not JSON: ${(e as Error).message}` }; }
  if (!data || typeof data !== 'object') return { status: 'corrupt', ledger: null, error: 'not an object' };
  const o = data as Record<string, unknown>;
  if (o.schema !== HYPOTHESES_SCHEMA) return { status: 'corrupt', ledger: null, error: `schema ${JSON.stringify(o.schema ?? null)}, expected ${HYPOTHESES_SCHEMA}` };
  if (typeof o.anchor_hash_version !== 'number' || !Array.isArray(o.entries) || !o.entries.every(isEntry)) return { status: 'corrupt', ledger: null, error: 'entries do not match the schema' };
  return { status: 'present', ledger: { schema: HYPOTHESES_SCHEMA, anchor_hash_version: o.anchor_hash_version, entries: o.entries as HypothesisEntry[] } };
}

/** Deterministic serialisation: entries by file, line, key. */
export function serializeHypotheses(ledger: HypothesesLedger): string {
  const entries = [...ledger.entries].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)));
  return JSON.stringify({ schema: ledger.schema, anchor_hash_version: ledger.anchor_hash_version, entries }, null, 2) + '\n';
}

export function writeHypotheses(root: string, ledger: HypothesesLedger): void {
  const path = join(root, HYPOTHESES_FILE);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, serializeHypotheses(ledger));
}
