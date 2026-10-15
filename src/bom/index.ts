/**
 * CycloneDX inventory of agents, MCP servers and instruction bundles.
 * @mitigates #report against #api-key-exposure using #key-redaction -- "Exports only selected inventory and reach slots; command arguments, endpoints, raw rules and credential values are omitted"
 * @flows ThreatModel -> #report via generateAiBom -- "Deterministic format conversion; no analysis or execution"
 */
import { createHash } from 'node:crypto';
import type { ThreatModel } from '../types/index.js';
import { relationRecords } from '../parser/claim-key.js';
interface Property { name: string; value: string }
interface Component { type: 'application' | 'file'; 'bom-ref': string; name: string; properties: Property[]; hashes?: { alg: 'SHA-256'; content: string }[] }
const ref = (kind: string, id: string) => `guardlink:${kind}:${createHash('sha256').update(id).digest('hex')}`;
const props = (v: Record<string, unknown>): Property[] => Object.entries(v).filter(([, value]) => value !== undefined).map(([name, value]) => ({ name: `guardlink:${name}`, value: typeof value === 'string' ? value : JSON.stringify(value) }));
export function generateAiBom(model: ThreatModel) {
  const components: Component[] = [];
  const dependencies: { ref: string; dependsOn: string[] }[] = [];
  const claims = new Map(relationRecords(model).map(r => [r.location, r.key]));
  for (const a of model.actors ?? []) {
    const id = a.id ?? a.canonical_name;
    const reaches = (model.reaches ?? []).filter(r => r.actor.replace(/^#/, '') === id);
    components.push({ type: 'application', 'bom-ref': ref('actor', id), name: a.name, properties: props({ kind: 'agent', origin: a.origin ?? 'annotation', reaches: reaches.map(r => ({ capability: r.capability, asset: r.asset, identity: r.identity, file: r.location.file, line: r.location.line, claim_key: claims.get(r.location), harness: r.source?.harness, scope: r.source?.scope, gated: r.source?.gated })) }) });
  }
  for (const s of model.agent_config?.mcp_servers ?? []) components.push({ type: 'application', 'bom-ref': ref('mcp', JSON.stringify([s.harness,s.file,s.name])), name: s.name, properties: props({ kind: 'mcp-server', harness: s.harness, file: s.file, line: s.line, scope: s.scope, transport: s.transport, disabled: s.disabled, credential_names: s.credential_env, package: s.package?.spec, resolves_to: s.resolves_to?.file }) });
  const files = new Map<string, Component>();
  const addFile = (path: string, properties: Record<string, unknown>, sha?: string) => {
    if (!files.has(path)) files.set(path, { type: 'file', 'bom-ref': ref('file', path), name: path, properties: props(properties), ...(sha && /^sha256-v1:[a-f0-9]{64}$/.test(sha) ? { hashes: [{ alg: 'SHA-256', content: sha.slice('sha256-v1:'.length) }] } : {}) });
  };
  for (const f of model.agent_config?.instruction_files ?? []) {
    addFile(f.path, { kind: f.kind, scope: f.scope, harnesses: f.harnesses, bytes: f.bytes, model_invocable: f.skill?.model_invocable });
    for (const b of f.bundled ?? []) addFile(b.path, { kind: b.kind, bundled_from: f.path, bytes: b.bytes }, b.sha256);
    dependencies.push({ ref: ref('file', f.path), dependsOn: (f.bundled ?? []).map(b => ref('file', b.path)) });
  }
  components.push(...files.values());
  components.sort((a,b) => a['bom-ref'].localeCompare(b['bom-ref'], 'en'));
  dependencies.sort((a,b) => a.ref.localeCompare(b.ref, 'en'));
  return { $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json', bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, metadata: { component: { type: 'application', 'bom-ref': ref('project', model.project), name: model.project }, properties: props({ inventory: 'agent-configuration-and-declared-reach', agent_config_hash: model.agent_config?.agent_config_hash }) }, components, dependencies };
}
