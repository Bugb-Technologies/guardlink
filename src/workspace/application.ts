/**
 * Selected application semantic views. Reads checked-out source; never builds, fetches or executes member code.
 *
 * @flows ConfigFile -> #workspace-config via collectApplicationView -- "The explicit expected set and aliases bind the application receipt"
 * @flows ProjectRoot -> #parser via collectApplicationView -- "Parse each selected checkout with its own configuration and preserve member evidence"
 * @mitigates #workspace-config against #config-tamper using #config-validation -- "Selection shapes, duplicate member ids and GuardLink identities, containment and symlinks are checked before member data is read; missing and mixed snapshots are explicit partial receipts"
 * @mitigates #parser against #path-traversal using #path-validation -- "Real selected checkout paths must remain under the application root; private absolute paths are not emitted in public receipts"
 * @flows GitRepo -> #workspace-config via readMemberRevision -- "Fixed argv read-only git queries capture branch, commit, base and dirty state"
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync, lstatSync, readdirSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import fg from 'fast-glob';
import type { ThreatModel, SourceLocation, ParseDiagnostic, AgentConfigBlock } from '../types/index.js';
import type { ApplicationManifest, ApplicationManifestMember, ApplicationMemberData, ApplicationMemberReceipt, ApplicationModelData, ApplicationRevision, ApplicationView } from './application-types.js';
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
    if (!m.members.length || m.members.some(member => !member || typeof member !== 'object' || typeof (member.id ?? member.name) !== 'string' || typeof (member.relativePath ?? member.path) !== 'string')) throw new Error('Application manifest members require string ids and checkout paths');
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
  if (new Set(found.map(f => f.config.workspace)).size > 1) throw new Error('Conflicting linked workspace manifests: multiple applications are present. Supply an explicit selected application manifest.');
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
  files.push(...await fg(['.guardlink/annotations/**/*.[gG][aA][lL]'], { cwd: root, dot: true, onlyFiles: true, ignore: ['**/node_modules/**', '**/.git/**'] }));
  const result: Array<[string, string]> = [];
  for (const file of [...new Set(files)].sort()) {
    try {
      if (!within(realpathSync(root), realpathSync(join(root, file)))) continue;
      result.push([posix(file), createHash('sha256').update(readFileSync(join(root, file))).digest('hex')]);
    } catch { result.push([posix(file), 'unreadable']); }
  }
  return result;
}
export async function readMemberRevision(root: string, member: ApplicationManifestMember, annotationDigest = 'unknown'): Promise<ApplicationRevision> {
  const files = await inputFiles(root);
  const top = git(root, ['rev-parse', '--show-toplevel']);
  const isGit = (!!top && resolve(top) === resolve(root)) || existsSync(join(root, '.git'));
  // An unreadable worktree pointer is unknown git provenance, not a non-git
  // member and not a reason to discard otherwise readable source annotations.
  const commit = isGit ? git(root, ['rev-parse', 'HEAD']) : null;
  const branch = isGit ? git(root, ['symbolic-ref', '--quiet', '--short', 'HEAD']) : null;
  const dirtyState = isGit ? git(root, ['status', '--porcelain', '--untracked-files=normal']) : null;
  const baseRef = isGit && typeof member.baseRef === 'string' ? member.baseRef : null;
  const baseInput = baseRef ?? (typeof member.baseCommit === 'string' ? member.baseCommit : null);
  const baseCommit = isGit && baseInput ? git(root, ['rev-parse', '--verify', '--end-of-options', `${baseInput}^{commit}`]) : null;
  return { vcs: isGit ? 'git' : 'none', commit, branch, detached: isGit ? !branch : null, baseRef, baseCommit,
    dirty: dirtyState === null ? null : !!dirtyState,
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

function selectedRelativePath(root: string, manifest: ApplicationManifest, member: ApplicationManifestMember): string {
  const path = member.relativePath ?? member.path ?? '';
  return posix(isAbsolute(path) ? relative(manifest.root ? resolve(manifest.root) : root, path) : path);
}

/** Resolve only selection metadata, before parsing any member source or evidence. */
function selectedIdentities(root: string, manifest: ApplicationManifest, snapshots: boolean): Map<ApplicationManifestMember, string> {
  const identities = new Map<ApplicationManifestMember, string>();
  for (const member of manifest.members) {
    const id = member.id ?? member.name;
    if (manifest.members.filter(m => (m.id ?? m.name) === id).length !== 1) continue;
    const path = resolve(root, selectedRelativePath(root, manifest, member));
    if (!within(root, path)) continue;
    let identity = member.guardlinkIdentity ?? member.id ?? member.name!;
    if (!snapshots) {
      try {
        if (!lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink() || realpathSync(path) !== path) continue;
        if (!member.guardlinkIdentity) identity = loadWorkspaceConfig(path)?.this_repo ?? identity;
      } catch { continue; } // Strict member validation reports missing/unreadable metadata below.
    }
    identities.set(member, identity);
  }
  return identities;
}

export interface CollectApplicationOptions { root: string; manifest: string | ApplicationManifest; memberId?: string; anchors?: boolean; agentConfig?: boolean; snapshots?: Array<{ model: ThreatModel; identity: string }>; selectionProbe?: () => ApplicationManifest | null; beforeRecheck?: () => void | Promise<void> }
export async function collectApplicationView(options: CollectApplicationOptions): Promise<ApplicationView> {
  const requestedRoot = resolve(options.root);
  const root = existsSync(requestedRoot) ? realpathSync(requestedRoot) : requestedRoot;
  const selectionSnapshot = () => hash(options.selectionProbe ? options.selectionProbe() : typeof options.manifest === 'string' ? readFileSync(resolve(options.manifest), 'utf8') : options.manifest);
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
  const identities = selectedIdentities(root, manifest, !!options.snapshots);
  const identitiesToMembers = new Map<string, ApplicationManifestMember[]>();
  for (const [member, identity] of identities) identitiesToMembers.set(identity, [...(identitiesToMembers.get(identity) ?? []), member]);
  for (const id of expected) {
    const choices = manifest.members.filter(m => (m.id ?? m.name) === id);
    const spec = choices[0];
    const rel = selectedRelativePath(root, manifest, spec);
    const path = resolve(root, rel);
    let identity = identities.get(spec) ?? spec.guardlinkIdentity ?? id;
    const receipt: ApplicationMemberReceipt = { id, guardlinkIdentity: identity, service: spec.service ?? id, relativePath: rel, revision: null, state: 'available', components: {} };
    receipts.push(receipt);
    const data: ApplicationMemberData = { id, coverage: null, generatedIdentities: {}, diagnostics: [] }; details.push(data);
    const fail = (state: ApplicationMemberReceipt['state'], reasonCode: string, reason: string) => {
      receipt.state = state; receipt.reasonCode = reasonCode; receipt.reason = reason;
      receipt.components.model = { state: state === 'missing' ? 'missing' : 'failed', reason };
      const diagnostic: ParseDiagnostic = { level: 'error', code: reasonCode === 'ambiguous-member' || reasonCode === 'ambiguous-guardlink-identity' ? 'workspace-config-invalid' : 'workspace-incomplete', file: `${rel}/.guardlink/workspace.yaml`, line: 1, message: `${id}: ${reason}` };
      data.diagnostics.push(diagnostic); diagnostics.push(diagnostic);
    };
    if (choices.length > 1) { fail('invalid', 'ambiguous-member', `Duplicate linked member identity "${id}": ${choices.map(m => { const p = m.relativePath ?? m.path; return !p ? '(no path)' : isAbsolute(p) ? posix(relative(manifest.root ? resolve(manifest.root) : root, p)) : p; }).join(', ')}. Keep one checkout, move the other outside this application, or relink distinct services with distinct member names.`); continue; }
    const sharingIdentity = identitiesToMembers.get(identity) ?? [];
    if (sharingIdentity.length > 1) {
      fail('invalid', 'ambiguous-guardlink-identity', `Duplicate GuardLink identity "${identity}": ${sharingIdentity.map(m => `${m.id ?? m.name} (${selectedRelativePath(root, manifest, m)})`).join(', ')}. Select one checkout for this identity, or relink distinct members with distinct GuardLink identities.`);
      continue;
    }
    if (!rel || !within(root, path) || paths.has(path)) { fail('invalid', 'member-out-of-root', 'Selected checkout is outside the application root, duplicated, or is the root itself.'); continue; }
    paths.add(path);
    if (options.snapshots) {
      const candidates = options.snapshots.filter(s => s.identity === identity);
      if (candidates.length !== 1 || !candidates[0].model.member_snapshot) { fail(candidates.length ? 'invalid' : 'missing', 'member-snapshot-unavailable', 'Exactly one report with native revision and evidence provenance is required for this selected member.'); continue; }
      const model = structuredClone(candidates[0].model);
      const snapshot = model.member_snapshot!;
      if (snapshot.schema !== 'guardlink.member-snapshot/v1' || snapshot.id !== identity || snapshot.workspace !== manifest.name || !snapshot.revision || !['git', 'none'].includes(snapshot.revision.vcs) || ![snapshot.revision.contentDigest, snapshot.revision.configDigest, snapshot.revision.annotationDigest].every(d => typeof d === 'string') || !snapshot.verification?.summary || !Array.isArray(snapshot.verification.claims) || !snapshot.hypotheses || (snapshot.hypotheses.ledger && !Array.isArray(snapshot.hypotheses.ledger.entries))) {
        fail('invalid', 'member-snapshot-invalid', 'Report native snapshot is malformed or belongs to a different selected member/application. Regenerate the member report.'); continue;
      }
      receipt.revision = snapshot.revision;
      receipt.components = { model: { state: snapshot.mixed ? 'partial' : 'present', indexedRevision: snapshot.revision, ...(snapshot.mixed ? { reason: 'Member inputs changed while this native report was collected; regenerate the member report.' } : {}) }, verification: { state: snapshot.verification.ledger === 'corrupt' ? 'partial' : 'present' }, hypotheses: { state: snapshot.hypotheses.status === 'corrupt' ? 'partial' : 'present' } };
      if (snapshot.revision.vcs === 'git' && (snapshot.revision.commit === null || snapshot.revision.dirty === null)) receipt.components.provenance = { state: 'partial', reason: 'Historical git provenance is incomplete.' };
      if (snapshot.repositoryUri) receipt.repositoryUri = linksFromRemote(snapshot.repositoryUri)?.web;
      data.coverage = { annotatedFiles: model.annotated_files.length, sourceFiles: model.source_files, percent: model.coverage.coverage_percent, excluded: model.annotation_scope?.excluded ?? [] };
      data.verification = snapshot.verification; data.hypotheses = snapshot.hypotheses;
      native.set(id, { model, root: path, verification: snapshot.verification, hypotheses: snapshot.hypotheses, revision: snapshot.revision, member: spec });
      provenance(model, id); data.generatedIdentities = scopeGenerated(model, id);
      if (model.agent_config) data.agentConfig = prefixConfig(model.agent_config, rel);
      if (!options.memberId || options.memberId === id) reports.push({ repo: rel, model, source_path: rel });
      continue;
    }
    if (!existsSync(path)) { fail('missing', 'member-missing', `Selected checkout ${rel} is missing.`); continue; }
    try {
      if (!lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink() || realpathSync(path) !== path || !within(realpathSync(root), realpathSync(path))) { fail('invalid', 'member-symlink', 'Selected checkout must be a real contained directory, not a symlink.'); continue; }
      const before = await readMemberRevision(path, spec);
      const linked = loadWorkspaceConfig(path, { strict: true });
      identity = spec.guardlinkIdentity ?? linked?.this_repo ?? id;
      if (identity !== identities.get(spec)) { fail('invalid', 'member-identity-changed', `GuardLink identity at ${rel} changed during selection validation. Retry with stable member manifests.`); continue; }
      receipt.guardlinkIdentity = identity;
      if (!linked || linked.workspace !== manifest.name || linked.this_repo !== identity) {
        // A selected standalone checkout is valid only when its identity was explicitly supplied.
        if (existsSync(join(path, '.guardlink/workspace.yaml')) || !spec.guardlinkIdentity) { fail('invalid', 'member-manifest-invalid', `Manifest ${rel}/.guardlink/workspace.yaml is unreadable or does not match the selected identity/application.`); continue; }
      }
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
      if (before.vcs === 'git' && (before.commit === null || before.dirty === null)) receipt.components.provenance = { state: 'partial', reason: 'Git commit or dirty state is unavailable; snapshot provenance is incomplete.' };
      if ((spec.baseRef || spec.baseCommit) && !before.baseCommit) receipt.components.baseline = { state: 'partial', reason: `Requested base ${spec.baseRef ?? spec.baseCommit} cannot be resolved locally; fetch or supply the assessed base commit.` };
      receipt.components.hypotheses = { state: hypotheses.status === 'corrupt' ? 'partial' : 'present', reason: hypotheses.error ?? `Member ledger is ${hypotheses.status}` };
      receipt.components.verification = { state: verification.ledger === 'corrupt' ? 'partial' : 'present', reason: `Member ledger is ${verification.ledger}` };
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
  for (const record of relationRecords(combined)) {
    const memberId = record.location.memberId!;
    data.occurrences.push({ id: hash([memberId, record.location.claimKey ?? record.key]), memberId, file: record.location.memberFile ?? record.location.file, line: record.location.line, verb: record.verb, claimKey: record.location.claimKey ?? record.key, ...(record.location.origin_file ? { origin: record.location.origin_file } : {}), location: { ...record.location } });
  }
  for (const id of new Set(data.definitions.map(d => d.id))) {
    const kinds = data.definitions.filter(d => d.id === id);
    if (kinds.length > 1) data.conflicts.push({ kind: 'mixed-definition-kinds', id, memberIds: [...new Set(kinds.flatMap(d => d.declarations.map(l => l.memberId!)))], declarations: kinds.flatMap(d => d.declarations) });
  }
  const definitions = new Map<string, { owners: string[]; ambiguous: boolean }>();
  for (const d of data.definitions) definitions.set(d.id, { owners: [...new Set(d.declarations.map(s => s.memberId!))], ambiguous: d.conflicting || data.conflicts.some(c => c.id === d.id) });
  if (options.memberId) {
    for (const [memberId, n] of native) if (memberId !== options.memberId) {
      for (const rows of [n.model.assets, n.model.threats, n.model.controls, n.model.actors ?? [], n.model.boundaries]) for (const row of rows) if (row.id) {
        const known = definitions.get(row.id);
        if (!known) definitions.set(row.id, { owners: [memberId], ambiguous: false });
        else if (!known.owners.includes(memberId)) known.owners.push(memberId);
      }
    }
  }
  for (const member of details) for (const asset of member.agentConfig?.assets ?? []) definitions.set(asset.id.replace(/^#/, ''), { owners: [member.id], ambiguous: false });
  const versionsById = new Map<string, Set<string>>();
  for (const n of native.values()) for (const [kind, rows] of [['asset', n.model.assets], ['threat', n.model.threats], ['control', n.model.controls], ['actor', n.model.actors ?? []], ['boundary', n.model.boundaries]] as const) for (const row of rows) if (row.id) {
    const signatures = versionsById.get(row.id) ?? new Set<string>();
    signatures.add(JSON.stringify({ ...row, location: undefined, declarations: undefined, kind })); versionsById.set(row.id, signatures);
  }
  for (const [id, versions] of versionsById) if (versions.size > 1 && definitions.has(id)) definitions.get(id)!.ambiguous = true;
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
  for (const group of flowGroups.values()) {
    group.sourceMemberIds = definitions.get(group.source.replace(/^#/, ''))?.owners ?? [];
    group.targetMemberIds = definitions.get(group.target.replace(/^#/, ''))?.owners ?? [];
    group.crossMember = group.sourceMemberIds.length === 1 && group.targetMemberIds.length === 1 && group.sourceMemberIds[0] !== group.targetMemberIds[0];
  }
  data.flowGroups = [...flowGroups.values()].sort((a, b) => a.id.localeCompare(b.id));
  // Rebind each member's original ledger keys to application occurrences without changing on-disk evidence.
  const combinedRecords = relationRecords(combined);
  const byNative = new Map(combinedRecords.map(r => [`${r.location.memberId}:${r.location.claimKey}`, r]));
  const hypotheses = emptyHypotheses();
  const verification: VerificationReport = { ledger: 'absent', claims: [], orphans: [], hash_version_mismatch: false, summary: { verified: 0, stale: 0, unverified: 0, orphans: 0, stale_by_verb: {}, demotable_stale: 0 } };
  let anyHypotheses = false;
  const corruptHypotheses: string[] = [];
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
    if (n.hypotheses.status === 'corrupt') corruptHypotheses.push(memberId);
    for (const entry of n.hypotheses.ledger?.entries ?? []) {
      const rec = byNative.get(`${memberId}:${entry.key}`); if (rec) hypotheses.entries.push({ ...entry, key: rec.key, file: rec.location.file });
    }
  }
  data.verification = verification;
  data.hypotheses = { status: corruptHypotheses.length ? 'corrupt' : anyHypotheses ? 'present' : 'absent', ledger: anyHypotheses ? hypotheses : null, ...(corruptHypotheses.length ? { error: `Corrupt hypothesis ledger in: ${corruptHypotheses.join(', ')}` } : {}) };
  attachHypotheses(combined, classifyHypotheses(combined, data.hypotheses));
  // Agent configuration inventory is preserved alongside the correctly scoped generated rows.
  const configs = details.flatMap(d => d.agentConfig ? [d.agentConfig] : []);
  if (configs.length) combined.agent_config = { version: 1, agent_config_hash: hash(configs.map(c => c.agent_config_hash)), semantics: Object.assign({}, ...configs.map(c => c.semantics)), files: configs.flatMap(c => c.files), mcp_servers: configs.flatMap(c => c.mcp_servers), hooks: configs.flatMap(c => c.hooks), instruction_files: configs.flatMap(c => c.instruction_files), assets: configs.flatMap(c => c.assets), denies: configs.flatMap(c => c.denies), untrusted_sources: configs.flatMap(c => c.untrusted_sources), unreadable: configs.flatMap(c => c.unreadable), surfaces: configs.flatMap(c => c.surfaces ?? []) };
  await options.beforeRecheck?.();
  const changed: string[] = [];
  for (const [id, n] of options.snapshots ? [] : native) {
    let after: ApplicationRevision;
    try { after = await readMemberRevision(n.root, n.member, n.revision.annotationDigest); } catch { changed.push(id); const m = receipts.find(m => m.id === id)!; m.components.model = { state: 'partial', reason: 'Member provenance became unavailable during collection.' }; continue; }
    if (JSON.stringify(revisionInput(after)) !== JSON.stringify(revisionInput(n.revision))) { changed.push(id); const m = receipts.find(m => m.id === id)!; m.components.model.state = 'partial'; m.components.model.reason = 'Member changed during collection; model may contain a mixed snapshot.'; }
  }
  const incomplete = active.some(m => m.state !== 'available' || Object.values(m.components).some(c => c.state !== 'present')) || data.conflicts.length > 0 || data.references.some(r => r.state === 'ambiguous');
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
  data.receipt.currency = { state: changed.length ? 'stale' : options.snapshots || active.some(m => m.components.provenance?.state === 'partial') ? 'unknown' : 'current', reasonCodes: selectionChanged ? ['mixed-selection'] : changed.length ? ['mixed-snapshot'] : [], memberIds: changed };
  if (manifest.receipt) {
    if (manifest.receipt.schema !== APPLICATION_RECEIPT_SCHEMA || JSON.stringify([...manifest.receipt.expectedMemberIds].sort()) !== JSON.stringify(expected)) throw new Error('Supplied application receipt does not describe the selected member set');
    data.receipt.inputDigest = manifest.receipt.inputDigest;
    const guardlinkDigests = manifest.receipt.tools?.guardlink?.contractVersion === APPLICATION_VIEW_SCHEMA;
    const comparable = (r: ApplicationRevision | null | undefined) => !r ? null : guardlinkDigests ? r : { vcs: r.vcs, commit: r.commit, branch: r.branch, detached: r.detached, baseRef: r.baseRef, baseCommit: r.baseCommit, dirty: r.dirty };
    const selector = (member: ApplicationMemberReceipt | undefined) => member && { id: member.id, guardlinkIdentity: member.guardlinkIdentity, service: member.service, relativePath: member.relativePath };
    const mismatch = expected.filter(id => JSON.stringify(comparable(manifest.receipt!.revisions[id])) !== JSON.stringify(comparable(data.receipt.revisions[id])) || JSON.stringify(selector(manifest.receipt!.members.find(m => m.id === id))) !== JSON.stringify(selector(receipts.find(m => m.id === id))));
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

/** Capture evidence from this member only; no inferred application root or sibling ledger. */
export async function captureMemberSnapshot(root: string, model: ThreatModel, before?: ApplicationRevision): Promise<void> {
  const config = loadWorkspaceConfig(root, { strict: true });
  if (!config || model.application) return;
  const revision = await readMemberRevision(root, {}, computeAnnotationHash(model));
  model.member_snapshot = { schema: 'guardlink.member-snapshot/v1', id: config.this_repo, workspace: config.workspace, expectedMemberIds: config.repos.map(m => m.name).sort(), revision, verification: classifyClaims(model, readLedger(root)), hypotheses: readHypotheses(root), capturedAt: new Date().toISOString(), mixed: model.member_snapshot?.mixed === true || (!!before && JSON.stringify(revisionInput(before)) !== JSON.stringify(revisionInput(revision))), ...(revision.vcs === 'git' && readVersionControl(root)?.repositoryUri ? { repositoryUri: readVersionControl(root)!.repositoryUri } : {}) };
}
