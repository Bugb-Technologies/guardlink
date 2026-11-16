/**
 * Selected application semantic views. Reads checked-out source; never builds, fetches or executes member code.
 *
 * @flows ConfigFile -> #workspace-config via collectApplicationView -- "The explicit expected set and aliases bind the application receipt"
 * @flows ProjectRoot -> #parser via collectApplicationView -- "Parse each selected checkout with its own configuration and preserve member evidence"
 * @mitigates #workspace-config against #config-tamper using #config-validation -- "Selection shapes, duplicate ids, containment and symlinks are checked before member data is read; missing and mixed snapshots are explicit partial receipts"
 * @mitigates #parser against #path-traversal using #path-validation -- "Real selected checkout paths must remain under the application root; private absolute paths are not emitted in public receipts"
 * @flows GitRepo -> #workspace-config via readRevision -- "Fixed argv read-only git queries capture branch, commit, base and dirty state"
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync, lstatSync, readdirSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import fg from 'fast-glob';
import type { ThreatModel, SourceLocation, ParseDiagnostic, AgentConfigBlock } from '../types/index.js';
import type { ApplicationManifest, ApplicationManifestMember, ApplicationMemberData, ApplicationMemberReceipt, ApplicationModelData, ApplicationReceipt, ApplicationReference, ApplicationRevision, ApplicationView } from './application-types.js';
import { loadWorkspaceConfig, readVersionControl } from './metadata.js';
import { combineModels } from './merge.js';
import { parseProject, DEFAULT_EXCLUDE, DEFAULT_INCLUDE } from '../parser/parse-project.js';
import { relationRecords, tagReferences } from '../parser/claim-key.js';
import { computeAnnotationHash } from '../parser/annotation-hash.js';
import { readLedger } from '../parser/ledger.js';
import { classifyClaims, type VerificationReport } from '../parser/verification.js';
import { emptyHypotheses, readHypotheses, type HypothesesRead } from '../hypothesis/ledger.js';
import { attachHypotheses, classifyHypotheses } from '../hypothesis/classify.js';
import { linksFromRemote } from '../dashboard/links.js';
import { normalizeName } from '../parser/normalize.js';
import { getPackageVersion } from '../version.js';

export const APPLICATION_VIEW_SCHEMA = 'guardlink.application-view/v1';
export const APPLICATION_RECEIPT_SCHEMA = 'bravos.application-view/v1';
export const APPLICATION_MANIFEST_ENV = 'GUARDLINK_APPLICATION_MANIFEST';
export const applicationViewCapabilities = () => ({ schema: 'guardlink.application-view-capabilities/v1', contractVersion: 1, viewSchema: APPLICATION_VIEW_SCHEMA, receiptSchema: APPLICATION_RECEIPT_SCHEMA, manifestSchemas: ['guardlink.application-manifest/v1', 'bravos.workspace-consumer/v1'], partialResults: true, memberProvenance: true });
const hash = (value: unknown): string => `sha256-v1:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
const posix = (value: string): string => value.replaceAll('\\', '/');
const within = (root: string, path: string): boolean => { const r = relative(root, path); return !!r && !r.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && r !== '..' && !isAbsolute(r); };
const git = (root: string, args: string[]): string | null => { try { return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: 'pipe', timeout: 10000 }).trim(); } catch { return null; } };

/** Resolve selection only; a repository stays a repository unless application input was supplied. */
export function discoverApplicationManifest(root: string, explicit?: string | ApplicationManifest): ApplicationManifest | null {
  if (explicit) {
    const content = typeof explicit === 'string' ? readFileSync(resolve(explicit), 'utf8') : undefined;
    if (content && content.length > 64 * 1024 * 1024) throw new Error('Selected manifest exceeds 64 MiB; omit embedded models and select source checkouts instead');
    const raw: unknown = content !== undefined ? JSON.parse(content) : explicit;
    if (!raw || typeof raw !== 'object') throw new Error('Application manifest must be an object');
    const m = raw as ApplicationManifest;
    if (!['guardlink.application-manifest/v1', 'bravos.workspace-consumer/v1'].includes(m.schema) || typeof m.name !== 'string' || !Array.isArray(m.members)) throw new Error('Unsupported or invalid selected application manifest');
    return m;
  }
  if (loadWorkspaceConfig(root)) return null;
  const consumer = join(root, '.bravos/workspace/consumer-manifest.json');
  if (existsSync(consumer)) return discoverApplicationManifest(root, consumer);
  const found: Array<{ path: string; config: NonNullable<ReturnType<typeof loadWorkspaceConfig>> }> = [];
  try {
    for (const e of readdirSync(root, { withFileTypes: true })) {
      if (!e.isDirectory() || e.name.startsWith('.') || ['node_modules', 'dist', 'build', 'vendor'].includes(e.name)) continue;
      const config = loadWorkspaceConfig(join(root, e.name));
      if (config) found.push({ path: e.name, config });
    }
  } catch { return null; }
  if (!found.length) return null;
  found.sort((a, b) => a.path.localeCompare(b.path));
  const config = found[0].config;
  const members: ApplicationManifestMember[] = [];
  for (const repo of config.repos) {
    const matches = found.filter(f => f.config.workspace === config.workspace && f.config.this_repo === repo.name);
    if (!matches.length) members.push({ id: repo.name, guardlinkIdentity: repo.name, relativePath: repo.name });
    for (const m of matches) members.push({ id: repo.name, guardlinkIdentity: repo.name, relativePath: m.path });
  }
  return { schema: 'guardlink.application-manifest/v1', name: config.workspace, members };
}

async function inputFiles(root: string): Promise<Array<[string, string]>> {
  const extra = ['.guardlink/**', '.claude/**', '.agents/**', '.codex/**', '.cursor/**', '.mcp.json', 'AGENTS.md', 'CLAUDE.md', '.gitignore', '.gitattributes', 'package.json', '*lock*', 'requirements*.txt', 'pyproject.toml', 'Cargo.toml', 'go.mod'];
  const files = await fg([...DEFAULT_INCLUDE, ...extra], { cwd: root, dot: true, onlyFiles: true, ignore: [...DEFAULT_EXCLUDE, '.guardlink/graph/**', '.guardlink/model.json', '.guardlink/report.json', '.guardlink/threat-reports/**', '.guardlink/analyses/**'] });
  const result: Array<[string, string]> = [];
  for (const file of [...new Set(files)].sort()) {
    try {
      if (!within(realpathSync(root), realpathSync(join(root, file)))) continue;
      result.push([posix(file), createHash('sha256').update(readFileSync(join(root, file))).digest('hex')]);
    } catch { result.push([posix(file), 'unreadable']); }
  }
  return result;
}
async function readRevision(root: string, member: ApplicationManifestMember, annotationDigest = 'unknown'): Promise<ApplicationRevision> {
  const files = await inputFiles(root);
  const top = git(root, ['rev-parse', '--show-toplevel']);
  const isGit = !!top && resolve(top) === resolve(root);
  const commit = isGit ? git(root, ['rev-parse', 'HEAD']) : null;
  const branch = isGit ? git(root, ['symbolic-ref', '--quiet', '--short', 'HEAD']) : null;
  const baseRef = isGit && typeof member.baseRef === 'string' ? member.baseRef : null;
  const baseInput = baseRef ?? (typeof member.baseCommit === 'string' ? member.baseCommit : null);
  const baseCommit = isGit && baseInput ? git(root, ['rev-parse', '--verify', '--end-of-options', `${baseInput}^{commit}`]) : null;
  return { vcs: isGit ? 'git' : 'none', commit, branch, detached: isGit ? !branch : null, baseRef, baseCommit,
    dirty: isGit ? !!git(root, ['status', '--porcelain', '--untracked-files=normal']) : null,
    contentDigest: hash(files), annotationDigest,
    configDigest: hash([files.filter(([f]) => f.startsWith('.') || /(?:json|lock|toml|mod|requirements.*txt)$/.test(f)), { baseRef: member.baseRef ?? null, baseCommit: member.baseCommit ?? null }]),
  };
}
const revisionInput = (r: ApplicationRevision | null): unknown => r && { ...r, annotationDigest: undefined };

/** Native claim keys/evidence stay attached to their owning member while file paths become app-relative. */
function provenance(model: ThreatModel, memberId: string): void {
  for (const value of Object.values(model)) if (Array.isArray(value)) for (const row of value) {
    if (row && typeof row === 'object' && row.location) row.location = { ...row.location };
  }
  for (const record of relationRecords(model)) record.location.claimKey = record.key;
  for (const value of Object.values(model)) if (Array.isArray(value)) for (const row of value) {
    if (row && typeof row === 'object' && row.location) {
      row.location.memberId = memberId; row.location.memberFile = row.location.file;
    }
  }
}
function scopeGenerated(model: ThreatModel, memberId: string): Record<string, string> {
  const map: Record<string, string> = {};
  const scoped = (id: string) => `agent-config-${createHash('sha256').update(memberId).digest('hex').slice(0, 12)}-${id.replace(/^#/, '')}`;
  for (const actor of model.actors ?? []) if (actor.origin === 'agent-config' && actor.id) map[actor.id] = scoped(actor.id);
  for (const a of model.agent_config?.assets ?? []) map[a.id.replace(/^#/, '')] = scoped(a.id);
  const rewrite = (ref: string): string => map[ref.replace(/^#/, '')] ? `#${map[ref.replace(/^#/, '')]}` : ref;
  for (const a of model.actors ?? []) if (a.origin && a.id) { a.id = map[a.id]; a.name = `${memberId}: ${a.name}`; a.canonical_name = normalizeName(a.name); }
  for (const rows of [model.reaches ?? [], model.effects ?? [], model.gates ?? [], model.entitlements ?? []]) for (const row of rows) {
    for (const field of ['actor', 'asset', 'identity', 'approver'] as const) if (field in row) {
      const r = row as unknown as Record<string, string>; if (r[field]) r[field] = rewrite(r[field]);
    }
  }
  if (model.agent_config) {
    for (const a of model.agent_config.assets) a.id = rewrite(a.id);
    for (const source of model.agent_config.untrusted_sources) source.agents = source.agents.map(rewrite);
  }
  return map;
}
function prefixConfig(config: AgentConfigBlock, prefix: string): AgentConfigBlock {
  const c = structuredClone(config);
  for (const rows of [c.files, c.mcp_servers, c.hooks, c.instruction_files, c.denies, c.untrusted_sources, c.unreadable, c.surfaces ?? []]) for (const row of rows) {
    if ('file' in row) row.file = `${prefix}/${row.file}`;
    if ('path' in row) row.path = `${prefix}/${row.path}`;
  }
  return c;
}

export interface CollectApplicationOptions { root: string; manifest: string | ApplicationManifest; memberId?: string; anchors?: boolean; agentConfig?: boolean; beforeRecheck?: () => void | Promise<void> }
export async function collectApplicationView(options: CollectApplicationOptions): Promise<ApplicationView> {
  const requestedRoot = resolve(options.root);
  const root = existsSync(requestedRoot) ? realpathSync(requestedRoot) : requestedRoot;
  const selectionSnapshot = () => hash(typeof options.manifest === 'string' ? readFileSync(resolve(options.manifest), 'utf8') : options.manifest);
  const selectionBefore = selectionSnapshot();
  const manifest = structuredClone(discoverApplicationManifest(root, options.manifest)!);
  const generatedAt = new Date().toISOString();
  const ids = manifest.members.map(m => m.id ?? m.name ?? '');
  const expected = [...new Set(ids)].sort();
  if (expected.some(id => !id || /[\r\n\0]/.test(id))) throw new Error('Every selected member needs a stable non-empty id');
  const receipts: ApplicationMemberReceipt[] = [];
  const details: ApplicationMemberData[] = [];
  const reports: Array<{ repo: string; model: ThreatModel; source_path: string }> = [];
  const native = new Map<string, { model: ThreatModel; root: string; verification: VerificationReport; hypotheses: HypothesesRead; revision: ApplicationRevision; member: ApplicationManifestMember }>();
  const diagnostics: ParseDiagnostic[] = [];
  const paths = new Set<string>();
  for (const id of expected) {
    const choices = manifest.members.filter(m => (m.id ?? m.name) === id);
    const spec = choices[0];
    let rel = spec.relativePath ?? spec.path ?? '';
    if (isAbsolute(rel)) rel = relative(manifest.root ? resolve(manifest.root) : root, rel);
    rel = posix(rel);
    const path = resolve(root, rel);
    let identity = spec.guardlinkIdentity ?? id;
    const receipt: ApplicationMemberReceipt = { id, guardlinkIdentity: identity, service: spec.service ?? id, relativePath: rel, revision: null, state: 'available', components: {} };
    receipts.push(receipt);
    const data: ApplicationMemberData = { id, coverage: null, generatedIdentities: {}, diagnostics: [] }; details.push(data);
    const fail = (state: ApplicationMemberReceipt['state'], reasonCode: string, reason: string) => {
      receipt.state = state; receipt.reasonCode = reasonCode; receipt.reason = reason;
      receipt.components.model = { state: state === 'missing' ? 'missing' : 'failed', reason };
      const diagnostic: ParseDiagnostic = { level: 'error', code: 'workspace-incomplete', file: `${rel}/.guardlink/workspace.yaml`, line: 1, message: `${id}: ${reason}` };
      data.diagnostics.push(diagnostic); diagnostics.push(diagnostic);
    };
    if (choices.length > 1) { fail('invalid', 'ambiguous-member', `Duplicate selected member identity ${id}: ${choices.map(m => m.relativePath ?? m.path ?? '(no path)').join(', ')}. Select exactly one checkout.`); continue; }
    if (!rel || !within(root, path) || paths.has(path)) { fail('invalid', 'member-out-of-root', 'Selected checkout is outside the application root, duplicated, or is the root itself.'); continue; }
    paths.add(path);
    if (!existsSync(path)) { fail('missing', 'member-missing', `Selected checkout ${rel} is missing.`); continue; }
    try {
      if (!lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink() || realpathSync(path) !== path || !within(realpathSync(root), realpathSync(path))) { fail('invalid', 'member-symlink', 'Selected checkout must be a real contained directory, not a symlink.'); continue; }
      const linked = loadWorkspaceConfig(path, { strict: true });
      identity = spec.guardlinkIdentity ?? linked?.this_repo ?? id;
      receipt.guardlinkIdentity = identity;
      if (!linked || linked.workspace !== manifest.name || linked.this_repo !== identity) {
        // A selected standalone checkout is valid only when its identity was explicitly supplied.
        if (existsSync(join(path, '.guardlink/workspace.yaml')) || !spec.guardlinkIdentity) { fail('invalid', 'member-manifest-invalid', `Manifest ${rel}/.guardlink/workspace.yaml is unreadable or does not match the selected identity/application.`); continue; }
      }
      const before = await readRevision(path, spec);
      const parsed = await parseProject({ root: path, project: id, anchors: options.anchors, agentConfig: options.agentConfig, checkSiblings: false, application: false });
      data.diagnostics.push(...parsed.diagnostics.map(d => ({ ...d, file: `${rel}/${d.file}` })));
      diagnostics.push(...data.diagnostics);
      if (parsed.diagnostics.some(d => d.level === 'error' || d.level === 'fatal')) { fail('invalid', 'member-parse-failed', `Model parse failed in ${rel}; inspect member diagnostics.`); continue; }
      const model = parsed.model;
      const verification = classifyClaims(model, readLedger(path));
      const hypotheses = readHypotheses(path);
      attachHypotheses(model, classifyHypotheses(model, hypotheses));
      before.annotationDigest = computeAnnotationHash(model);
      receipt.revision = before;
      const vcs = before.vcs === 'git' ? readVersionControl(path) : null; if (vcs) receipt.repositoryUri = vcs.repositoryUri;
      receipt.components.model = { state: 'present', indexedRevision: before };
      receipt.components.hypotheses = { state: hypotheses.status === 'corrupt' ? 'partial' : 'present', ...(hypotheses.error ? { reason: hypotheses.error } : {}) };
      receipt.components.verification = { state: verification.ledger === 'corrupt' ? 'partial' : 'present' };
      data.coverage = { annotatedFiles: model.annotated_files.length, sourceFiles: model.source_files, percent: model.coverage.coverage_percent, excluded: model.annotation_scope?.excluded ?? [] };
      data.verification = verification; data.hypotheses = hypotheses;
      native.set(id, { model, root: path, verification, hypotheses, revision: before, member: spec });
      provenance(model, id);
      data.generatedIdentities = scopeGenerated(model, id);
      if (model.agent_config) data.agentConfig = prefixConfig(model.agent_config, rel);
      if (!options.memberId || options.memberId === id) reports.push({ repo: rel, model, source_path: path });
    } catch (error) { fail('invalid', 'member-read-failed', `Could not read selected checkout ${rel}: ${(error as Error).message.replaceAll(path, rel)}`); }
  }
  if (options.memberId && !expected.includes(options.memberId)) throw new Error(`Member ${options.memberId} is not in the selected application`);
  const combined = combineModels(reports, { preserveConflicts: true }); combined.project = options.memberId ?? manifest.name;
  const active = receipts.filter(m => !options.memberId || m.id === options.memberId);
  const data: ApplicationModelData = {
    receipt: { schema: APPLICATION_RECEIPT_SCHEMA, scope: options.memberId ? { kind: 'repository', applicationId: manifest.name, memberId: options.memberId } : { kind: 'application', applicationId: manifest.name, memberIds: expected }, generatedAt, inputDigest: '', expectedMemberIds: expected, members: receipts, completeness: 'complete', revisions: Object.fromEntries(receipts.map(m => [m.id, m.revision])), tools: { guardlink: { version: getPackageVersion(), contractVersion: APPLICATION_VIEW_SCHEMA } } },
    members: details, occurrences: [], definitions: [], conflicts: [], references: [], flowGroups: [],
    coverage: { kind: 'annotation-files', known: { annotatedFiles: combined.annotated_files.length, sourceFiles: combined.source_files, percent: combined.coverage.coverage_percent }, overallPercent: null, unknownMemberIds: active.filter(m => m.state !== 'available').map(m => m.id) },
  };
  combined.application = data;
  // Shared declarations retain every site; conflicting declarations are never picked by array order.
  for (const [kind, rows] of [['asset', combined.assets], ['threat', combined.threats], ['control', combined.controls], ['actor', combined.actors ?? []], ['boundary', combined.boundaries]] as const) {
    const groups = new Map<string, Array<(typeof rows)[number]>>();
    for (const row of rows) if (row.id) groups.set(row.id, [...(groups.get(row.id) ?? []), row]);
    for (const [id, versions] of groups) {
      const declarations = versions.flatMap(r => (r as typeof r & { declarations?: SourceLocation[] }).declarations ?? [r.location]);
      const conflicting = versions.length > 1;
      data.definitions.push({ kind, id, declarations, conflicting });
      if (conflicting) data.conflicts.push({ kind, id, memberIds: [...new Set(declarations.map(d => d.memberId!))], declarations });
    }
  }
  for (const [memberId, n] of native) {
    for (const record of relationRecords(n.model)) data.occurrences.push({ id: hash([memberId, record.location.claimKey ?? record.key]), memberId, file: record.location.memberFile ?? record.location.file, line: record.location.line, verb: record.verb, claimKey: record.location.claimKey ?? record.key, location: { ...record.location } });
  }
  const definitions = new Map<string, { owners: string[]; ambiguous: boolean }>();
  for (const d of data.definitions) definitions.set(d.id, { owners: [...new Set(d.declarations.map(s => s.memberId!))], ambiguous: d.conflicting });
  for (const member of details) for (const asset of member.agentConfig?.assets ?? []) definitions.set(asset.id.replace(/^#/, ''), { owners: [member.id], ambiguous: false });
  const hasUnknown = active.some(m => m.state !== 'available');
  for (const ref of tagReferences(combined)) {
    const def = definitions.get(ref.tag.slice(1));
    data.references.push({ tag: ref.tag, memberId: ref.location.memberId!, file: ref.location.memberFile ?? ref.location.file, line: ref.location.line, verb: ref.context_verb, state: def?.ambiguous ? 'ambiguous' : def ? 'resolved' : hasUnknown ? 'unchecked' : 'unresolved', owners: def?.owners ?? [], ...(ref.tag.includes('.') ? { legacy: true } : {}) });
  }
  const flowGroups = new Map<string, ApplicationModelData['flowGroups'][number]>();
  for (const flow of combined.flows) {
    const key = hash([flow.source, flow.target, flow.mechanism, flow.route ?? null]);
    const group = flowGroups.get(key) ?? { id: key, source: flow.source, target: flow.target, mechanism: flow.mechanism ?? '', route: flow.route ?? null, declarations: [] };
    group.declarations.push({ memberId: flow.location.memberId!, file: flow.location.memberFile ?? flow.location.file, line: flow.location.line, claimKey: flow.location.claimKey }); flowGroups.set(key, group);
  }
  data.flowGroups = [...flowGroups.values()].sort((a, b) => a.id.localeCompare(b.id));
  // Rebind each member's original ledger keys to application occurrences without changing on-disk evidence.
  const combinedRecords = relationRecords(combined);
  const byNative = new Map(combinedRecords.map(r => [`${r.location.memberId}:${r.location.claimKey}`, r]));
  const hypotheses = emptyHypotheses();
  const verification: VerificationReport = { ledger: 'absent', claims: [], orphans: [], hash_version_mismatch: false, summary: { verified: 0, stale: 0, unverified: 0, orphans: 0, stale_by_verb: {}, demotable_stale: 0 } };
  let anyHypotheses = false;
  for (const [memberId, n] of native) {
    if (options.memberId && options.memberId !== memberId) continue;
    if (n.verification.ledger !== 'absent') verification.ledger = n.verification.ledger === 'corrupt' ? 'corrupt' : verification.ledger === 'corrupt' ? 'corrupt' : 'present';
    verification.orphans.push(...n.verification.orphans);
    verification.summary.orphans += n.verification.summary.orphans;
    verification.hash_version_mismatch ||= n.verification.hash_version_mismatch;
    for (const claim of n.verification.claims) {
      const rec = byNative.get(`${memberId}:${claim.key}`); if (!rec) continue;
      verification.claims.push({ ...claim, key: rec.key, location: rec.location });
      verification.summary[claim.state]++;
      if (claim.state === 'stale') { verification.summary.stale_by_verb[claim.verb] = (verification.summary.stale_by_verb[claim.verb] ?? 0) + 1; if (claim.demotable) verification.summary.demotable_stale++; }
    }
    if (n.hypotheses.status === 'present') anyHypotheses = true;
    for (const entry of n.hypotheses.ledger?.entries ?? []) {
      const rec = byNative.get(`${memberId}:${entry.key}`); if (rec) hypotheses.entries.push({ ...entry, key: rec.key, file: rec.location.file });
    }
  }
  data.verification = verification;
  data.hypotheses = { status: anyHypotheses ? 'present' : 'absent', ledger: anyHypotheses ? hypotheses : null };
  attachHypotheses(combined, classifyHypotheses(combined, data.hypotheses));
  // Agent configuration inventory is preserved alongside the correctly scoped generated rows.
  const configs = details.flatMap(d => d.agentConfig ? [d.agentConfig] : []);
  if (configs.length) combined.agent_config = { version: 1, agent_config_hash: hash(configs.map(c => c.agent_config_hash)), semantics: Object.assign({}, ...configs.map(c => c.semantics)), files: configs.flatMap(c => c.files), mcp_servers: configs.flatMap(c => c.mcp_servers), hooks: configs.flatMap(c => c.hooks), instruction_files: configs.flatMap(c => c.instruction_files), assets: configs.flatMap(c => c.assets), denies: configs.flatMap(c => c.denies), untrusted_sources: configs.flatMap(c => c.untrusted_sources), unreadable: configs.flatMap(c => c.unreadable), surfaces: configs.flatMap(c => c.surfaces ?? []) };
  await options.beforeRecheck?.();
  const changed: string[] = [];
  for (const [id, n] of native) {
    const after = await readRevision(n.root, n.member, n.revision.annotationDigest);
    if (JSON.stringify(revisionInput(after)) !== JSON.stringify(revisionInput(n.revision))) { changed.push(id); const m = receipts.find(m => m.id === id)!; m.components.model.state = 'partial'; m.components.model.reason = 'Member changed during collection; model may contain a mixed snapshot.'; }
  }
  const incomplete = active.some(m => m.state !== 'available' || Object.values(m.components).some(c => c.state !== 'present')) || data.conflicts.length > 0;
  data.receipt.completeness = active.every(m => m.state !== 'available') ? 'unavailable' : incomplete ? 'partial' : 'complete';
  data.coverage.overallPercent = incomplete ? null : data.coverage.known.percent;
  let selectionChanged = false;
  try { selectionChanged = selectionBefore !== selectionSnapshot(); } catch { selectionChanged = true; }
  if (selectionChanged) {
    data.receipt.completeness = data.receipt.completeness === 'unavailable' ? 'unavailable' : 'partial';
    data.coverage.overallPercent = null;
    for (const id of expected) if (!changed.includes(id)) changed.push(id);
  }
  const observedDigest = hash([data.receipt.scope, data.receipt.tools, manifest.members.map(m => [m.id ?? m.name, m.baseRef ?? null, m.baseCommit ?? null]), receipts.map(m => [m.id, m.guardlinkIdentity, m.service, m.relativePath, m.revision, m.state])]);
  data.receipt.inputDigest = observedDigest;
  data.receipt.observedInputDigest = observedDigest;
  data.receipt.currency = { state: changed.length ? 'stale' : 'current', reasonCodes: selectionChanged ? ['mixed-selection'] : changed.length ? ['mixed-snapshot'] : [], memberIds: changed };
  if (manifest.receipt) {
    if (manifest.receipt.schema !== APPLICATION_RECEIPT_SCHEMA || JSON.stringify([...manifest.receipt.expectedMemberIds].sort()) !== JSON.stringify(expected)) throw new Error('Supplied application receipt does not describe the selected member set');
    data.receipt.inputDigest = manifest.receipt.inputDigest;
    const mismatch = expected.filter(id => JSON.stringify(manifest.receipt!.revisions[id]) !== JSON.stringify(data.receipt.revisions[id]));
    if (mismatch.length) { data.receipt.currency = { state: 'stale', reasonCodes: ['input-receipt-mismatch'], memberIds: mismatch }; data.receipt.completeness = data.receipt.completeness === 'unavailable' ? 'unavailable' : 'partial'; data.coverage.overallPercent = null; }
  }
  return { schema: APPLICATION_VIEW_SCHEMA, receipt: data.receipt, model: combined, diagnostics, references: data.references, flowGroups: data.flowGroups };
}

/** Resolve a member-owned hosted source link at the assessed commit, never app-root HEAD. */
export function applicationSourceLink(model: ThreatModel, file: string, line?: number): string | null {
  const members = model.application?.receipt.members ?? [];
  const matches = members.filter(m => file.startsWith(`${m.relativePath}/`));
  if (matches.length !== 1) return null;
  const member = matches[0]; if (!member.repositoryUri || !member.revision?.commit) return null;
  const links = linksFromRemote(member.repositoryUri); if (!links) return null;
  return links.file(file.slice(member.relativePath.length + 1), line).replace('/HEAD/', `/${member.revision.commit}/`);
}
