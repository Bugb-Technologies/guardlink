import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';
import { applicationSourceLink } from '../src/workspace/application.js';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { generateDashboardHTML } from '../src/dashboard/generate.js';
import { computeActions, computeLedgerStates } from '../src/dashboard/data.js';
import { generateReport } from '../src/report/report.js';
import { generateMermaid } from '../src/report/mermaid.js';
import { generateSarif } from '../src/analyzer/sarif.js';
import { collectApplicationView } from '../src/workspace/application.js';
import { parseProject } from '../src/parser/parse-project.js';
import { recordOutcome, emptyHypotheses, writeHypotheses } from '../src/hypothesis/index.js';
import { classifyClaims } from '../src/parser/verification.js';
import { emptyLedger, writeLedger } from '../src/parser/ledger.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { loadThreatReportsForDashboard, serializeModelCompact } from '../src/analyze/index.js';
import { mergeReports } from '../src/workspace/merge.js';
import { populateMetadata } from '../src/workspace/metadata.js';
import { linkProject } from '../src/workspace/link.js';

let root: string;
const put = (file: string, data: string) => writeFileSync(file, data);
function member(name: string, source: string) {
  const dir = join(root, name); mkdirSync(join(dir, '.guardlink'), { recursive: true });
  put(join(dir, '.guardlink/config.json'), JSON.stringify({ include: ['app.ts'] }));
  put(join(dir, 'app.ts'), source); return dir;
}
function scaffold() {
  const api = member('api', '// @asset Shop.API (#api)\n// @threat Injection (#injection) [high]\n// @control Bound_Query (#guard)\n// @exposes #api to #injection [high] -- "fixture query"\n// @flows #api -> #auth via HTTP\n');
  const auth = member('auth', '// @asset Shop.Auth (#auth)\n// @mitigates #api against #injection using #guard\n// @flows #api -> #auth via HTTP\n');
  linkProject({ workspace: 'shop', repoPaths: [api, auth] });
  const manifest = join(root, 'selected.json');
  put(manifest, JSON.stringify({ schema: 'guardlink.application-manifest/v1', name: 'shop', members: [
    { id: 'api', guardlinkIdentity: 'api', relativePath: 'api', service: 'api' },
    { id: 'auth', guardlinkIdentity: 'auth', relativePath: 'auth', service: 'auth' },
  ] }));
  return { api, auth, manifest };
}
const collect = (manifest: string) => parseProject({ root, applicationManifest: manifest, anchors: false });
beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'gl-application-view-')); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('application semantic view contract', () => {
  it('advertises its versioned capability at the real CLI boundary', () => {
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');
    const json = execFileSync(process.execPath, [tsx, cli, 'application-view', '--capabilities'], { encoding: 'utf8' });
    expect(JSON.parse(json).receiptSchema).toBe('bravos.application-view/v1');
  });
  it('keeps the selected roster, occurrence provenance and every grouped flow declaration', async () => {
    const { manifest } = scaffold(); member('unselected', '// @asset Other (#other)');
    const { model } = await collect(manifest);
    expect(model.application?.receipt).toMatchObject({ schema: 'bravos.application-view/v1', expectedMemberIds: ['api', 'auth'], completeness: 'complete' });
    expect(model.assets.some(a => a.id === 'other')).toBe(false);
    expect(model.exposures[0].location).toMatchObject({ memberId: 'api', memberFile: 'app.ts' });
    expect(model.application?.flowGroups).toHaveLength(1);
    expect(model.application?.flowGroups[0].declarations).toHaveLength(2);
    expect(model.application?.receipt.members.every(m => m.revision?.vcs === 'none' && m.revision.commit === null)).toBe(true);
  });
  it('retains available content and every expected member when one checkout is missing', async () => {
    const { auth, manifest } = scaffold(); rmSync(auth, { recursive: true });
    const { model } = await collect(manifest);
    expect(model.exposures).toHaveLength(1);
    expect(model.application?.receipt.completeness).toBe('partial');
    expect(model.application?.receipt.members.find(m => m.id === 'auth')).toMatchObject({ state: 'missing', revision: null });
    expect(model.application?.coverage.overallPercent).toBeNull();
    expect(model.application?.coverage.known.annotatedFiles).toBeGreaterThan(0);
  });
  it('keeps generated permissions and their auxiliary inventory scoped to each member', async () => {
    const { api, auth, manifest } = scaffold();
    for (const dir of [api, auth]) { mkdirSync(join(dir, '.claude'), { recursive: true }); put(join(dir, '.claude/settings.json'), '{"permissions":{"allow":["Bash(echo:*)"]}}'); }
    const { model } = await collect(manifest);
    const actors = model.actors?.filter(a => a.origin === 'agent-config') ?? [];
    expect(new Set(actors.map(a => a.id)).size).toBe(2);
    expect(model.application?.members.every(m => m.agentConfig?.files.length)).toBe(true);
    expect(model.reaches?.filter(r => r.origin === 'agent-config').every(r => r.location.memberId)).toBe(true);
  });
  it('shares its receipt and member-owned source paths across offline projections', async () => {
    const { auth, manifest } = scaffold(); rmSync(auth, { recursive: true });
    const { model } = await collect(manifest);
    const receipt = model.application!.receipt;
    const html = generateDashboardHTML(model, root);
    expect(html.includes('application-receipt')).toBe(true);
    expect(html.includes(receipt.inputDigest)).toBe(true);
    expect(html.includes('Known subtotal')).toBe(true);
    expect(html.includes('<span class="tn-v">unknown</span>')).toBe(true);
    expect(html.includes('Evidence stays in this member')).toBe(true);
    expect(generateReport(model)).toContain(receipt.inputDigest);
    expect(generateMermaid(model)).toContain(receipt.inputDigest);
    const sarif = generateSarif(model);
    expect(sarif.runs[0].properties).toMatchObject({ application_receipt: receipt });
    const result = sarif.runs[0].results.find(r => r.ruleId === 'guardlink/unmitigated-exposure') ?? sarif.runs[0].results[0];
    expect(JSON.stringify(result)).toContain('GUARDLINK_MEMBER_');
  });
  it('shows member verification counts and commands instead of cloning the application total', async () => {
    const counts = { api: 9, auth: 5, worker: 5, web: 5 };
    const dirs = Object.entries(counts).map(([id, count]) => member(id, `// @asset App.${id} (#${id})\n` +
      Array.from({ length: count }, (_, i) => `// @flows #${id} -> #${id} via step${i}`).join('\n')));
    linkProject({ workspace: 'shop', repoPaths: dirs });
    const { model } = await parseProject({ root, anchors: false });
    const verification = computeLedgerStates(model).report;
    expect(verification.summary.unverified).toBe(24);
    const actions = computeActions({ model, verification, exposures: [], confirmed: [], attribution: null, scope: null });
    expect(Object.fromEntries(actions.filter(a => a.id.startsWith('start-verifying:')).map(a => [a.id, a.count]))).toEqual(
      Object.fromEntries(Object.entries(counts).map(([id, count]) => [`start-verifying:${id}`, count])));
    const html = generateDashboardHTML(model, root);
    for (const [id, count] of Object.entries(counts)) {
      const action = actions.find(a => a.id === `start-verifying:${id}`)!;
      expect(action.command).toBe(`guardlink verify '${id}' --all`);
      expect(action.detail).toContain(`${count} claims in this model have never been checked`);
      expect(html).toContain(action.detail);
    }
    expect(html).not.toContain('24 claims in this model have never been checked');
    const manifest = { schema: 'guardlink.application-manifest/v1' as const, name: 'shop', members: Object.keys(counts).map(id => ({ id, relativePath: id })) };
    const scoped = (await collectApplicationView({ root, manifest, memberId: 'api', anchors: false })).model;
    const scopedActions = computeActions({ model: scoped, verification: computeLedgerStates(scoped).report, exposures: [], confirmed: [], attribution: null, scope: null });
    expect(scopedActions.filter(a => a.id.startsWith('start-verifying:')).map(a => [a.id, a.count])).toEqual([['start-verifying:api', 9]]);
    delete model.application!.members.find(m => m.id === 'api')!.verification;
    const unknown = computeActions({ model, verification, exposures: [], confirmed: [], attribution: null, scope: null });
    expect(unknown.find(a => a.id === 'verification-unknown:api')).toMatchObject({ count: 0, title: 'api: Verification state is unavailable' });
    expect(unknown.some(a => a.id === 'start-verifying:api')).toBe(false);
  });
  it.each(['stale', 'corrupt', 'verified'] as const)('keeps %s ledger actions local without hiding another member missing baseline', async (state) => {
    const { auth, manifest } = scaffold();
    if (state === 'corrupt') put(join(auth, '.guardlink/verified.json'), '{invalid');
    else {
      const parsed = (await parseProject({ root: auth, application: false, checkSiblings: false })).model;
      const ledger = emptyLedger();
      for (const r of relationRecords(parsed)) if (r.location.anchor) ledger.entries.push({ key: r.key, file: r.location.file, verb: r.verb, claim: r.claim, anchor: { scope: r.location.anchor.scope, symbol: r.location.anchor.symbol }, hash: state === 'verified' ? r.location.anchor.hash : '0'.repeat(64), verified_by: 'human:fixture', verified_at: '2026-01-01T00:00:00Z' });
      writeLedger(auth, ledger);
    }
    const { model } = await collectApplicationView({ root, manifest });
    const actions = computeActions({ model, verification: computeLedgerStates(model).report, exposures: [], confirmed: [], attribution: null, scope: null });
    const api = model.application!.members.find(m => m.id === 'api')!.verification!;
    const native = model.application!.members.find(m => m.id === 'auth')!.verification!;
    expect(actions.find(a => a.id === 'start-verifying:api')).toMatchObject({ count: api.summary.unverified, command: "guardlink verify 'api' --all" });
    if (state === 'stale') {
      expect(native.summary.stale).toBe(2);
      expect(actions.find(a => a.id === 'stale-claims:auth')).toMatchObject({ count: 2, title: 'auth: 2 claims went stale', command: "guardlink verify 'auth' --stale" });
    } else if (state === 'corrupt') expect(actions.find(a => a.id === 'ledger-corrupt:auth')).toMatchObject({ command: "guardlink validate 'auth'" });
    else {
      expect(native.summary.verified).toBe(2);
      expect(actions.some(a => a.id.endsWith(':auth'))).toBe(false);
    }
    expect(actions.some(a => a.id === 'stale-claims:api' || a.id === 'ledger-corrupt:api' || a.id === 'start-verifying:auth')).toBe(false);
  });
  it('marks concurrent member edits and selection edits as mixed snapshots', async () => {
    const { api, manifest } = scaffold();
    const view = await collectApplicationView({ root, manifest, anchors: false, beforeRecheck: () => put(join(api, 'app.ts'), '// @asset Changed (#changed)') });
    expect(view.receipt.completeness).toBe('partial');
    expect(view.receipt.currency?.reasonCodes).toContain('mixed-snapshot');
  });
  it('keeps conflicting definitions and marks references ambiguous rather than suppressing exposures', async () => {
    const { auth, manifest } = scaffold();
    put(join(auth, 'app.ts'), '// @asset Different.API (#api)\n// @mitigates #api against #injection using #guard');
    const { model } = await collect(manifest);
    expect(model.application?.conflicts.some(c => c.id === 'api')).toBe(true);
    expect(model.application?.references.some(r => r.tag === '#api' && r.state === 'ambiguous')).toBe(true);
    expect(generateSarif(model).runs[0].results.length).toBeGreaterThan(0);
  });

  it('echoes a frozen caller receipt without comparing incompatible producer digests', async () => {
    const { manifest } = scaffold();
    const first = await collectApplicationView({ root, manifest, anchors: false });
    const selected = JSON.parse(readFileSync(manifest, 'utf8'));
    const receipt = structuredClone(first.receipt);
    receipt.tools = { bravos: { version: 'test', contractVersion: '1' } };
    receipt.inputDigest = 'caller-frozen-digest';
    for (const r of Object.values(receipt.revisions)) if (r) { r.contentDigest = 'different-algorithm'; r.annotationDigest = 'different-algorithm'; r.configDigest = 'different-algorithm'; }
    selected.receipt = receipt;
    const next = await collectApplicationView({ root, manifest: selected, anchors: false });
    expect(next.receipt.inputDigest).toBe('caller-frozen-digest');
    expect(next.receipt.completeness).toBe('complete');
    expect(next.receipt.currency?.state).toBe('current');
  });

  it('preserves native verification and refutation evidence without a root ledger', async () => {
    const { api, manifest } = scaffold();
    const parsed = (await parseProject({ root: api, application: false, checkSiblings: false })).model;
    const ledger = emptyLedger();
    for (const r of relationRecords(parsed)) if (r.location.anchor) ledger.entries.push({ key: r.key, file: r.location.file, verb: r.verb, claim: r.claim, anchor: { scope: r.location.anchor.scope, symbol: r.location.anchor.symbol }, hash: r.location.anchor.hash, verified_by: 'human:fixture', verified_at: '2026-01-01T00:00:00Z' });
    writeLedger(api, ledger);
    recordOutcome(api, parsed, 'app.ts:4', 'refuted', { evidence: 'Synthetic fixture result', by: 'human:fixture', at: '2026-01-01T00:00:00Z' });
    const view = await collectApplicationView({ root, manifest });
    expect(view.model.exposures[0].hypothesis?.state).toBe('refuted');
    const verification = classifyClaims(view.model, { status: 'absent', ledger: null });
    expect(verification.summary.verified).toBeGreaterThan(0);
    expect(verification.claims.find(c => c.verb === 'exposes')?.location).toMatchObject({ memberId: 'api', file: 'api/app.ts' });
    const sarif = generateSarif(view.model, [], [], { profile: 'pentest' });
    expect(JSON.stringify(sarif).includes('refuted')).toBe(true);
    expect(JSON.parse(serializeModelCompact(view.model)).application.receipt.inputDigest).toBe(view.receipt.inputDigest);
  });
  it('detects branch-only, base and untracked configuration changes independently of source bytes', async () => {
    const { api, manifest } = scaffold();
    const git = (...args: string[]) => execFileSync('git', ['-C', api, ...args], { stdio: 'pipe', encoding: 'utf8' });
    git('init', '-b', 'main'); git('add', '.'); git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture');
    const first = await collectApplicationView({ root, manifest, anchors: false });
    git('checkout', '-b', 'same-files');
    const branch = await collectApplicationView({ root, manifest, anchors: false });
    expect(branch.receipt.revisions.api?.commit).toBe(first.receipt.revisions.api?.commit);
    expect(branch.receipt.inputDigest).not.toBe(first.receipt.inputDigest);
    const selection = JSON.parse(readFileSync(manifest, 'utf8')); selection.members[0].baseRef = 'main';
    const base = await collectApplicationView({ root, manifest: selection, anchors: false });
    expect(base.receipt.revisions.api?.baseCommit).toBe(first.receipt.revisions.api?.commit);
    expect(base.receipt.inputDigest).not.toBe(branch.receipt.inputDigest);
    put(join(api, '.guardlink/prompt.md'), 'changed context');
    const changed = await collectApplicationView({ root, manifest, anchors: false });
    expect(changed.receipt.revisions.api?.configDigest).not.toBe(branch.receipt.revisions.api?.configDigest);
  });
  it('retains invalid roster entries for duplicate, outside and symlink selections', async () => {
    const { manifest } = scaffold(); const selection = JSON.parse(readFileSync(manifest, 'utf8'));
    selection.members.push({ id: 'outside', guardlinkIdentity: 'outside', relativePath: '../outside' });
    selection.members.push({ id: 'api', relativePath: 'auth' });
    symlinkSync(join(root, 'auth'), join(root, 'alias'));
    selection.members.push({ id: 'alias', guardlinkIdentity: 'auth', relativePath: 'alias' });
    const view = await collectApplicationView({ root, manifest: selection, anchors: false });
    expect(view.receipt.members.filter(m => m.state === 'invalid').map(m => m.id).sort()).toEqual(['alias', 'api', 'outside']);
    expect(view.receipt.completeness).toBe('partial');
    expect(JSON.stringify(view.receipt).includes(root)).toBe(false);
  });
  it('keeps per-member saved reports and their historical assessed receipt', async () => {
    const { api, manifest } = scaffold();
    const { model } = await collect(manifest);
    const dir = join(api, '.guardlink/threat-reports'); mkdirSync(dir, { recursive: true });
    put(join(dir, '2026-01-01T00-00-00-stride.md'), '---\nmodel: fixture\napplication_receipt: ' + JSON.stringify({ ...model.application!.receipt, inputDigest: 'old-assessment' }) + '\n---\n# Prior report\nHistorical analysis');
    const reports = loadThreatReportsForDashboard(root, model);
    expect(reports).toHaveLength(1);
    expect(reports[0]).toMatchObject({ memberId: 'api', currency: 'stale', assessedReceipt: { inputDigest: 'old-assessment' } });
    expect(model.application?.reportLibrary).toMatchObject({ loaded: 1, total: 1, omitted: 0 });
  });

  it('projects native report snapshots offline without replacing their historical revisions', async () => {
    const { api, auth, manifest } = scaffold();
    const direct = await collectApplicationView({ root, manifest });
    const files = [];
    for (const dir of [api, auth]) {
      const parsed = await parseProject({ root: dir, application: false, checkSiblings: false, memberSnapshot: true });
      const path = join(root, dir === api ? 'api.json' : 'auth.json');
      put(path, JSON.stringify(populateMetadata(parsed.model, dir, parsed.diagnostics))); files.push(path);
    }
    put(join(api, 'app.ts'), '// @asset Changed (#changed)');
    const merged = await mergeReports(files, { applicationManifest: JSON.parse(readFileSync(manifest, 'utf8')) });
    expect(merged.model.assets.some(a => a.id === 'changed')).toBe(false);
    expect(merged.model.application?.receipt.inputDigest).toBe(direct.receipt.inputDigest);
    expect(merged.model.application?.receipt.currency?.state).toBe('unknown');
    expect(merged.model.application?.receipt.completeness).toBe('complete');
    expect(merged.model.flows).toHaveLength(direct.model.flows.length);
  });

  it('serves the explicit selected receipt through MCP without a different-root envelope', async () => {
    const { manifest } = scaffold(); const server = createServer();
    const client = new Client({ name: 'fixture', version: '1' });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), client.connect(ct)]);
    try {
      const response = await client.callTool({ name: 'guardlink_application_view', arguments: { root, manifest } });
      const content = response.content as Array<{ text: string }>;
      const view = JSON.parse(content[0].text);
      expect(view.receipt.completeness).toBe('complete');
      expect(JSON.parse(content[1].text).guardlink.application_receipt.inputDigest).toBe(view.receipt.inputDigest);
      const graph = await client.callTool({ name: 'guardlink_graph', arguments: { root, from: '#api' } });
      const graphEnvelope = JSON.parse((graph.content as Array<{ text: string }>).at(-1)!.text).guardlink;
      expect(graphEnvelope.application_receipt?.inputDigest).toBe(view.receipt.inputDigest);
      const workspace = await client.callTool({ name: 'guardlink_workspace_info', arguments: { root } });
      expect(JSON.parse((workspace.content as Array<{ text: string }>)[0].text)).toMatchObject({ this_repo: null, id_convention: 'flat-globally-unique' });
    } finally { await client.close(); }
  });
  it('pins source links to each assessed member commit and strips remote credentials', async () => {
    const { api, manifest } = scaffold();
    const git = (...args: string[]) => execFileSync('git', ['-C', api, ...args], { stdio: 'pipe', encoding: 'utf8' });
    git('init', '-b', 'main'); git('add', '.'); git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture');
    git('remote', 'add', 'origin', 'https://user:secret@github.com/example/api.git');
    const view = await collectApplicationView({ root, manifest, anchors: false });
    const sha = view.receipt.revisions.api!.commit;
    expect(applicationSourceLink(view.model, 'api/app.ts', 4)).toBe(`https://github.com/example/api/blob/${sha}/app.ts#L4`);
    expect(JSON.stringify(view.receipt).includes('secret')).toBe(false);
    expect(applicationSourceLink(view.model, 'auth/app.ts', 1)).toBeNull();
  });

  it('reports corrupt member evidence as partial while retaining readable siblings', async () => {
    const { api, manifest } = scaffold(); put(join(api, '.guardlink/hypotheses.json'), '{broken');
    const view = await collectApplicationView({ root, manifest, anchors: false });
    expect(view.receipt.completeness).toBe('partial');
    expect(view.model.application?.hypotheses?.status).toBe('corrupt');
    expect(view.model.assets).toHaveLength(2);
    expect(view.model.application?.coverage.overallPercent).toBeNull();
  });
  it('uses weighted file counts and keeps repository projection counts scoped', async () => {
    const { api, manifest } = scaffold();
    put(join(api, '.guardlink/config.json'), JSON.stringify({ include: ['*.ts'] }));
    put(join(api, 'second.ts'), 'export const second = true;');
    put(join(api, 'third.ts'), 'export const third = true;');
    const app = await collectApplicationView({ root, manifest, anchors: false });
    expect(app.model.application?.coverage.known).toEqual({ annotatedFiles: 2, sourceFiles: 4, percent: 50 });
    const repo = await collectApplicationView({ root, manifest, memberId: 'auth', anchors: false });
    expect(repo.receipt.scope).toMatchObject({ kind: 'repository', memberId: 'auth' });
    expect(repo.model.exposures).toHaveLength(0);
    expect(repo.model.application?.coverage.known).toEqual({ annotatedFiles: 1, sourceFiles: 1, percent: 100 });
    expect(repo.references.every(r => r.state === 'resolved')).toBe(true);
    expect(repo.model.application?.occurrences.every(o => o.memberId === 'auth')).toBe(true);
  });
  it('marks an edited selection manifest and unresolved requested base explicitly', async () => {
    const { manifest } = scaffold(); const spec = JSON.parse(readFileSync(manifest, 'utf8')); spec.members[0].baseRef = 'missing-base';
    const base = await collectApplicationView({ root, manifest: spec, anchors: false });
    expect(base.receipt.completeness).toBe('partial');
    expect(base.receipt.members[0].components.baseline.state).toBe('partial');
    const mixed = await collectApplicationView({ root, manifest, anchors: false, beforeRecheck: () => put(manifest, JSON.stringify({ ...spec, name: 'changed' })) });
    expect(mixed.receipt.currency?.reasonCodes).toContain('mixed-selection');
    expect(mixed.receipt.completeness).toBe('partial');
  });

  it('invalidates a frozen receipt when service mapping changes without source changes', async () => {
    const { manifest } = scaffold(); const first = await collectApplicationView({ root, manifest, anchors: false });
    const spec = JSON.parse(readFileSync(manifest, 'utf8')); spec.receipt = first.receipt;
    spec.members[0].service = 'different-service';
    const changed = await collectApplicationView({ root, manifest: spec, anchors: false });
    expect(changed.receipt.inputDigest).toBe(first.receipt.inputDigest);
    expect(changed.receipt.completeness).toBe('partial');
    expect(changed.receipt.currency?.reasonCodes).toContain('input-receipt-mismatch');
  });

  it('rechecks native report configuration after first-run prompt migration', () => {
    const { api } = scaffold();
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');
    const run = () => { execFileSync(process.execPath, [tsx, cli, 'report', api, '-f', 'json', '-o', '.guardlink/report.json'], { stdio: 'pipe' }); return JSON.parse(readFileSync(join(api, '.guardlink/report.json'), 'utf8')); };
    const first = run();
    expect(first.member_snapshot.mixed).toBe(true);
    expect(run().member_snapshot.mixed).toBe(false);
  });

  it.each(['explicit', 'mixed', 'inferred'] as const)('B6: rejects duplicate GuardLink identities with %s selection metadata', async (kind) => {
    const { api, auth, manifest } = scaffold();
    put(join(auth, '.guardlink/workspace.yaml'), readFileSync(join(api, '.guardlink/workspace.yaml'), 'utf8'));
    const selected = JSON.parse(readFileSync(manifest, 'utf8'));
    selected.members[1].guardlinkIdentity = 'api';
    if (kind !== 'explicit') delete selected.members[1].guardlinkIdentity;
    if (kind === 'inferred') delete selected.members[0].guardlinkIdentity;
    const view = await collectApplicationView({ root, manifest: selected, anchors: false });
    expect(view.receipt.completeness).toBe('unavailable');
    expect(view.receipt.members).toHaveLength(2);
    for (const member of view.receipt.members) {
      expect(member).toMatchObject({ state: 'invalid', reasonCode: 'ambiguous-guardlink-identity', guardlinkIdentity: 'api', revision: null });
      expect(member.reason).toContain('api (api)');
      expect(member.reason).toContain('auth (auth)');
    }
    expect(view.model.assets).toHaveLength(0);
    expect(view.model.application?.coverage.overallPercent).toBeNull();
    expect(JSON.stringify(view.receipt).includes(root)).toBe(false);
  });

  it('B6: retains a ready member while all duplicate identity selections are ambiguous', async () => {
    const { api, auth, manifest } = scaffold();
    const billing = member('billing', '// @asset Shop.Billing (#billing)');
    linkProject({ workspace: 'shop', repoPaths: [api, auth, billing] });
    put(join(auth, '.guardlink/workspace.yaml'), readFileSync(join(api, '.guardlink/workspace.yaml'), 'utf8'));
    const selected = JSON.parse(readFileSync(manifest, 'utf8'));
    selected.members[1].guardlinkIdentity = 'api';
    selected.members.push({ id: 'billing', guardlinkIdentity: 'billing', relativePath: 'billing' });
    const view = await collectApplicationView({ root, manifest: selected, anchors: false });
    expect(view.receipt.completeness).toBe('partial');
    expect(view.receipt.members.filter(m => m.reasonCode === 'ambiguous-guardlink-identity').map(m => m.id)).toEqual(['api', 'auth']);
    expect(view.model.assets.map(a => a.id)).toEqual(['billing']);
    expect(view.model.application?.coverage.overallPercent).toBeNull();
  });
  it('B6: refuses to project one historical member identity twice under different registry ids', async () => {
    const { api, manifest } = scaffold();
    const parsed = await parseProject({ root: api, application: false, checkSiblings: false, memberSnapshot: true });
    const selected = JSON.parse(readFileSync(manifest, 'utf8')); selected.members[1].guardlinkIdentity = 'api';
    const view = await collectApplicationView({ root, manifest: selected, snapshots: [{ identity: 'api', model: parsed.model }], anchors: false });
    expect(view.receipt.completeness).toBe('unavailable');
    expect(view.receipt.members.every(m => m.reasonCode === 'ambiguous-guardlink-identity')).toBe(true);
    expect(view.model.assets).toHaveLength(0);
  });
  it('B6: the real CLI names both paths and fails strict collection', () => {
    const { api, auth, manifest } = scaffold();
    put(join(auth, '.guardlink/workspace.yaml'), readFileSync(join(api, '.guardlink/workspace.yaml'), 'utf8'));
    const selected = JSON.parse(readFileSync(manifest, 'utf8')); selected.members[1].guardlinkIdentity = 'api'; put(manifest, JSON.stringify(selected));
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');
    try {
      execFileSync(process.execPath, [tsx, cli, 'application-view', root, '--manifest', manifest, '--strict'], { encoding: 'utf8', stdio: 'pipe' });
      expect.fail('duplicate GuardLink identity must fail strict collection');
    } catch (error) {
      const result = error as { status: number; stdout: string };
      expect(result.status).toBe(1);
      const view = JSON.parse(result.stdout);
      expect(view.receipt.members.every((m: { reasonCode: string }) => m.reasonCode === 'ambiguous-guardlink-identity')).toBe(true);
      expect(result.stdout).toContain('api (api), auth (auth)');
    }
  });

  it.each(['live', 'historical'] as const)('M1: reports missing evidence ledgers as absent in %s views', async (mode) => {
    const { api, auth, manifest } = scaffold();
    const snapshots = mode === 'historical' ? await Promise.all([api, auth].map(async (path, index) => ({ identity: index === 0 ? 'api' : 'auth', model: (await parseProject({ root: path, application: false, checkSiblings: false, memberSnapshot: true, anchors: false })).model }))) : undefined;
    const view = await collectApplicationView({ root, manifest, snapshots, anchors: false });
    for (const member of view.receipt.members) {
      expect(member.components.hypotheses.state).toBe('absent');
      expect(member.components.verification.state).toBe('absent');
      expect(member.components.model.state).toBe('present');
    }
    expect(view.receipt.completeness).toBe('complete');
    expect(view.model.application?.verification?.summary.verified).toBe(0);
    expect(view.model.application?.verification?.summary.unverified).toBeGreaterThan(0);
    expect(view.model.application?.hypotheses?.status).toBe('absent');
  });
  it('M1: distinguishes present empty ledgers from missing ledgers', async () => {
    const { api, manifest } = scaffold();
    writeLedger(api, emptyLedger()); writeHypotheses(api, emptyHypotheses());
    const view = await collectApplicationView({ root, manifest, anchors: false });
    expect(view.receipt.members.find(m => m.id === 'api')?.components).toMatchObject({ hypotheses: { state: 'present' }, verification: { state: 'present' } });
    expect(view.receipt.members.find(m => m.id === 'auth')?.components).toMatchObject({ hypotheses: { state: 'absent' }, verification: { state: 'absent' } });
    expect(view.receipt.completeness).toBe('complete');
    expect(view.model.application?.verification?.summary.verified).toBe(0);
  });

});
