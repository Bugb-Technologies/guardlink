/**
 * GuardLink — the verification ledger, `.guardlink/verified.json`.
 *
 * One entry per source-anchored claim: the claim's key, the anchor hash at the
 * moment someone verified it, who, and when. Committed, so it travels with the
 * code and needs no git history to read. Written only by `guardlink verify`
 * and the `guardlink_verify` MCP tool; every other command reads.
 *
 * Entries are sorted by file then key and serialised one per line, so two
 * branches that verify different files merge without conflict and two that
 * verify the same claim conflict on exactly one line.
 *
 * A file that exists but does not parse, or names another schema, or holds an
 * entry of the wrong shape, is CORRUPT — reported once through a diagnostic
 * and otherwise treated as absent. It is never silently rewritten: `verify`
 * refuses to write over it without `--force`.
 *
 * @exposes #parser to #insecure-deser [low] cwe:CWE-502 -- "JSON.parse on a committed file under .guardlink/"
 * @mitigates #parser against #insecure-deser using #config-validation -- "Shape is validated field by field before any entry is trusted; anything else is corrupt, not partially loaded"
 * @exposes #cli to #arbitrary-write [low] cwe:CWE-73 -- "writeLedger writes one fixed path under root"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "The path is the constant LEDGER_FILE joined to root; no caller supplies a path"
 * @flows LedgerFile -> #parser via readLedger -- "Recorded hashes and verifiers"
 * @flows #cli -> LedgerFile via writeLedger -- "The only write the verify surfaces perform"
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { AnchorScope, AnnotationVerb, ParseDiagnostic } from '../types/index.js';
import { ANCHOR_HASH_VERSION } from '../structure/hash.js';

export const LEDGER_FILE = '.guardlink/verified.json';
export const LEDGER_SCHEMA = 'guardlink.verified/v1';

export interface LedgerEntry {
  key: string;
  file: string;
  verb: AnnotationVerb;
  /** Display only; never used for matching. */
  claim: string;
  anchor: { scope: AnchorScope; symbol: string | null };
  hash: string;
  /** `human:<name>` or `agent:<client name>`. The prefix is what a future gate keys on. */
  verified_by: string;
  /** ISO 8601, UTC. */
  verified_at: string;
  /** HEAD at verify time, present only when git was available. */
  commit?: string;
}

export interface Ledger {
  schema: typeof LEDGER_SCHEMA;
  anchor_hash_version: number;
  entries: LedgerEntry[];
}

export type LedgerStatus = 'present' | 'absent' | 'corrupt';

export interface LedgerRead {
  status: LedgerStatus;
  ledger: Ledger | null;
  /** Present only when status is 'corrupt'. */
  diagnostic?: ParseDiagnostic;
}

export function emptyLedger(): Ledger {
  return { schema: LEDGER_SCHEMA, anchor_hash_version: ANCHOR_HASH_VERSION, entries: [] };
}

const SCOPES: ReadonlySet<string> = new Set(['symbol', 'block', 'file']);

function isEntry(v: unknown): v is LedgerEntry {
  if (!v || typeof v !== 'object') return false;
  const e = v as Record<string, unknown>;
  const anchor = e.anchor as Record<string, unknown> | undefined;
  return typeof e.key === 'string' && typeof e.file === 'string' && typeof e.verb === 'string'
    && typeof e.claim === 'string' && typeof e.hash === 'string'
    && typeof e.verified_by === 'string' && typeof e.verified_at === 'string'
    && (e.commit === undefined || typeof e.commit === 'string')
    && !!anchor && typeof anchor === 'object' && SCOPES.has(String(anchor.scope))
    && (anchor.symbol === null || typeof anchor.symbol === 'string');
}

function corrupt(message: string): LedgerRead {
  return {
    status: 'corrupt', ledger: null,
    diagnostic: { level: 'error', code: 'ledger-corrupt', file: LEDGER_FILE, line: 0, message: `${LEDGER_FILE}: ${message}` },
  };
}

export function readLedger(root: string): LedgerRead {
  const path = join(root, LEDGER_FILE);
  if (!existsSync(path)) return { status: 'absent', ledger: null };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf-8'));
  } catch (err) {
    return corrupt(`not valid JSON (${(err as Error).message}). Run guardlink verify --all --force to rebuild it.`);
  }
  if (!raw || typeof raw !== 'object') return corrupt('not an object');
  const obj = raw as Record<string, unknown>;
  if (obj.schema !== LEDGER_SCHEMA) return corrupt(`schema is ${JSON.stringify(obj.schema)}, expected ${LEDGER_SCHEMA}`);
  if (typeof obj.anchor_hash_version !== 'number') return corrupt('anchor_hash_version is not a number');
  if (!Array.isArray(obj.entries)) return corrupt('entries is not an array');
  for (const [i, e] of obj.entries.entries()) {
    if (!isEntry(e)) return corrupt(`entry ${i} has the wrong shape`);
  }
  const ledger: Ledger = { schema: LEDGER_SCHEMA, anchor_hash_version: obj.anchor_hash_version, entries: sortEntries(obj.entries as LedgerEntry[]) };
  return { status: 'present', ledger };
}

function sortEntries(entries: LedgerEntry[]): LedgerEntry[] {
  return [...entries].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

/** Valid JSON, one entry per line, sorted, trailing newline. */
export function serializeLedger(ledger: Ledger): string {
  const lines = sortEntries(ledger.entries).map(e => '    ' + JSON.stringify(e));
  if (lines.length === 0) {
    return [
      '{',
      `  "schema": ${JSON.stringify(ledger.schema)},`,
      `  "anchor_hash_version": ${ledger.anchor_hash_version},`,
      '  "entries": []',
      '}',
      '',
    ].join('\n');
  }
  return [
    '{',
    `  "schema": ${JSON.stringify(ledger.schema)},`,
    `  "anchor_hash_version": ${ledger.anchor_hash_version},`,
    '  "entries": [',
    lines.join(',\n'),
    '  ]',
    '}',
    '',
  ].join('\n');
}

export function writeLedger(root: string, ledger: Ledger): void {
  const path = join(root, LEDGER_FILE);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, serializeLedger(ledger));
}
