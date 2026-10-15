/**
 * Offline observations and the single observed-minus-declared join.
 * @exposes #parser to #insecure-deser [medium] -- "Observation and pin files are untrusted JSON"
 * @mitigates #parser against #insecure-deser using #config-validation -- "Closed schema and bounded input; identity and supplied claim keys are checked against model rows"
 * @exposes #parser to #path-traversal [medium] -- "Reads and stores local attestation files"
 * @mitigates #parser against #path-traversal using #path-validation -- "Local metadata realpaths must remain under the selected repository; writes reject symlink destinations"
 * @flows ProjectFiles -> #parser via readObservedState -- "Local names, hashes and observation coverage, never server execution"
 */
import { readFileSync, existsSync, realpathSync, lstatSync, mkdirSync, writeFileSync, statSync } from 'node:fs';
import { resolve, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv } from 'ajv';
import addFormats from 'ajv-formats';
import type { ThreatModel, ThreatModelReach } from '../types/index.js';
import { actorResolver } from '../parser/reach.js';
import { normalizeName } from '../parser/normalize.js';
import { relationRecords } from '../parser/claim-key.js';
import type { ObservedReach, Observation, ObservedIdentity, ToolPins } from './types.js';
export type * from './types.js';
const ajv = new Ajv({ strict: true });
(addFormats as unknown as (a: Ajv) => void)(ajv);
const schema = JSON.parse(readFileSync(fileURLToPath(new URL('../../conformance/observed-reach/schema.json', import.meta.url)), 'utf8'));
const validate = ajv.compile(schema);
const HASH = /^sha256:[a-f0-9]{64}$/;
const MAX_BYTES = 8 * 1024 * 1024;
export const identityKey = (i: ObservedIdentity): string => JSON.stringify([i.actor, i.server ?? null, i.harness ?? null, i.file ?? null, i.scope ?? null]);

export function parseObservedReach(value: unknown): ObservedReach {
  if (!validate(value)) throw new Error(`Invalid observed reach: ${ajv.errorsText(validate.errors)}`);
  const doc = value as ObservedReach;
  for (const o of doc.observations) {
    if (['otel', 'probe'].includes(o.source) && !o.window) throw new Error('Call observations require a window');
    if (o.window && Date.parse(o.window.from) > Date.parse(o.window.to)) throw new Error('Reversed observation window');
    if (o.identity.file && (o.identity.file.startsWith('/') || o.identity.file.includes('\\') || o.identity.file.split('/').includes('..'))) throw new Error('Identity file must be repository relative');
    for (const t of o.tools_available) if (t.description_sha256 === null && !t.description_unknown) throw new Error('Unknown description requires a reason');
    for (const list of [o.tools_available, o.tools_called]) if (new Set(list.map(t => t.name)).size !== list.length) throw new Error('Duplicate tool name within observation');
    if (o.coverage.available === 'not_collected' && o.tools_available.length || o.coverage.called === 'not_collected' && o.tools_called.length) throw new Error('Not-collected coverage contains tools');
  }
  return doc;
}
export function parseToolPins(value: unknown): ToolPins {
  if (!value || typeof value !== 'object') throw new Error('Invalid tool pins');
  const p = value as ToolPins;
  if (p.schema !== 'guardlink.tool-pins/v1' || !Array.isArray(p.pins) || p.pins.length > 20000 || Object.keys(p).some(k => !['schema','pins'].includes(k))) throw new Error('Invalid tool pins');
  const seen = new Set<string>();
  for (const pin of p.pins) {
    if (!pin || typeof pin.name !== 'string' || !pin.name || !HASH.test(pin.description_sha256) || Object.keys(pin).some(k => !['identity','name','description_sha256'].includes(k))) throw new Error('Invalid description pin');
    parseObservedReach({ schema: 'guardlink.observed-reach/v1', observations: [{ identity: pin.identity, source: 'static', coverage: { available: 'complete', called: 'not_collected', truncated: false }, tools_available: [], tools_called: [] }] });
    const key = identityKey(pin.identity) + pin.name;
    if (seen.has(key)) throw new Error('Duplicate description pin');
    seen.add(key);
  }
  return p;
}
function readJson(file: string): unknown {
  if (statSync(file).size > MAX_BYTES) throw new Error('Observation input exceeds size limit');
  return JSON.parse(readFileSync(file, 'utf8'));
}
/** Only fixed metadata paths use this containment rule; explicit CLI input may be anywhere. */
function localPath(root: string, name: string): string {
  const base = realpathSync(root);
  const file = resolve(base, '.guardlink', name);
  const parent = dirname(file);
  if (existsSync(parent)) {
    const real = realpathSync(parent);
    if (real !== base && !real.startsWith(base + sep)) throw new Error('Attestation directory leaves repository');
  }
  try {
    if (lstatSync(file).isSymbolicLink()) throw new Error('Attestation metadata must not be a symlink');
  } catch (err) { if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err; }
  return file;
}
export function readObservedState(root: string): { observed?: ObservedReach; pins?: ToolPins } {
  const doc = localPath(root, 'observed-reach.json');
  const pins = localPath(root, 'tool-pins.json');
  return { ...(existsSync(doc) ? { observed: parseObservedReach(readJson(doc)) } : {}), ...(existsSync(pins) ? { pins: parseToolPins(readJson(pins)) } : {}) };
}
export function storeObservedReach(root: string, input: string): ObservedReach {
  const doc = parseObservedReach(readJson(resolve(input)));
  const file = localPath(root, 'observed-reach.json');
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(doc, null, 2) + '\n', { flag: 'w' });
  return doc;
}
export interface AttestationRow {
  observation: number;
  identity: ObservedIdentity;
  source: Observation['source'];
  coverage: Observation['coverage'];
  window: Observation['window'] | null;
  name: string;
  claim_keys: string[];
  basis?: 'available' | 'called';
  before?: string;
  after?: string;
  reason?: string;
}
export interface ReachAttestation {
  version: 1;
  observed_not_declared: AttestationRow[];
  declared_not_observed: AttestationRow[];
  pin_changed: AttestationRow[];
  unknown: AttestationRow[];
  summary: { observations: number; matched_tools: number; unpinned_tools: number };
}
export function buildReachAttestation(model: ThreatModel, doc: ObservedReach, pins?: ToolPins): ReachAttestation {
  const out: ReachAttestation = { version: 1, observed_not_declared: [], declared_not_observed: [], pin_changed: [], unknown: [], summary: { observations: doc.observations.length, matched_tools: 0, unpinned_tools: 0 } };
  const actor = actorResolver(model);
  const keys = new Map(relationRecords(model).map(r => [r.location, r.key]));
  const knownActors = new Set((model.actors ?? []).map(a => actor(a.id ?? a.name)));
  for (const [index, o] of doc.observations.entries()) {
    const row = (name: string, rs: ThreatModelReach[] = []): AttestationRow => ({ observation: index, identity: o.identity, source: o.source, coverage: o.coverage, window: o.window ?? null, name, claim_keys: rs.map(r => keys.get(r.location)).filter((k): k is string => !!k) });
    const candidates = (model.reaches ?? []).filter(r => actor(r.actor) === actor(o.identity.actor)
      && (!o.identity.harness || r.source?.harness === o.identity.harness)
      && (!o.identity.file || r.location.file === o.identity.file)
      && (!o.identity.scope || r.source?.scope === o.identity.scope));
    const cap = (name: string) => normalizeName(o.identity.server ? `mcp.${o.identity.server}.${name}` : name);
    const matches = (name: string) => candidates.filter(r => r.canonical_capability === cap(name) || (o.identity.server && r.canonical_capability === cap('all-tools')));
    if (!knownActors.has(actor(o.identity.actor))) { out.unknown.push({ ...row(''), reason: 'unresolved_actor' }); continue; }
    for (const name of new Set([...o.tools_available.map(t => t.name), ...o.tools_called.map(t => t.name)])) {
      const rs = matches(name);
      const rr = row(name, rs);
      const hints = [...(o.tools_available.find(t => t.name === name)?.claim_keys ?? []), ...(o.tools_called.find(t => t.name === name)?.claim_keys ?? [])];
      if (hints.some(k => !rr.claim_keys.includes(k))) out.unknown.push({ ...rr, reason: 'claim_key_mismatch' });
      if (rs.length) out.summary.matched_tools++; else out.observed_not_declared.push(rr);
    }
    const basis = o.coverage.available === 'complete' && !o.coverage.truncated ? 'available'
      : o.window && o.coverage.called === 'complete' && !o.coverage.truncated ? 'called' : null;
    if (basis) {
      const names = new Set((basis === 'available' ? o.tools_available : o.tools_called).map(t => cap(t.name)));
      for (const r of candidates) {
        const prefix = o.identity.server ? normalizeName(`mcp.${o.identity.server}.`) : '';
        if (prefix && !r.canonical_capability.startsWith(prefix)) continue;
        if (r.canonical_capability.endsWith(normalizeName('all-tools'))) continue;
        if (!names.has(r.canonical_capability)) out.declared_not_observed.push({ ...row(r.capability, [r]), basis });
      }
    }
    for (const t of o.tools_available) {
      const pin = pins?.pins.find(p => identityKey(p.identity) === identityKey(o.identity) && p.name === t.name);
      const rr = row(t.name, matches(t.name));
      if (!pin) out.summary.unpinned_tools++;
      if (!t.description_sha256) out.unknown.push({ ...rr, reason: `description:${t.description_unknown}` });
      else if (pin && pin.description_sha256 !== t.description_sha256) out.pin_changed.push({ ...rr, before: pin.description_sha256, after: t.description_sha256 });
    }
    if (o.coverage.truncated || ['partial','unknown'].includes(o.coverage.available)) out.unknown.push({ ...row(''), reason: o.coverage.reason ?? 'incomplete_coverage' });
  }
  return out;
}
