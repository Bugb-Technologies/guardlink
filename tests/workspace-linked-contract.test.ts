import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';
import { parseProject } from '../src/parser/parse-project.js';
import { findDanglingRefs } from '../src/parser/validate.js';
import { linkProject, removeFromWorkspace, loadWorkspaceConfig } from '../src/workspace/index.js';
import { mergeReports } from '../src/workspace/merge.js';

let root: string;
const put = (path: string, content: string) => writeFileSync(path, content);
const parse = (name: string) => parseProject({ root: join(root, name), project: name, anchors: false, agentConfig: false });
function member(name: string, source: string, config = {}) {
  const dir = join(root, name);
  mkdirSync(join(dir, '.guardlink'), { recursive: true });
  mkdirSync(join(dir, 'src'));
  put(join(dir, '.guardlink/config.json'), JSON.stringify(config));
  put(join(dir, 'src/app.ts'), source);
  put(join(dir, 'CLAUDE.md'), '# Project\n');
  return dir;
}
function linked() {
  const auth = member('auth', '// @control Session_Check (#session-check)\n');
  const orders = member('orders', '// @asset Orders (#orders)\n// @threat Injection (#injection) [high]\n// @mitigates #orders against #injection using #session-check\n');
  linkProject({ workspace: 'shop', repoPaths: [auth, orders] });
  return { auth, orders };
}
beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'gl-linked-contract-')); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

describe('linked workspace contracts', () => {
  it('W3: MCP and generated instructions teach flat globally unique ids', async () => {
    const { orders } = linked();
    const server = createServer();
    const client = new Client({ name: 'workspace-test', version: '1' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(b), client.connect(a)]);
    try {
      const result = await client.callTool({ name: 'guardlink_workspace_info', arguments: { root: orders } });
      const info = JSON.parse((result.content as Array<{ text: string }>)[0].text);
      expect(info.id_convention).toBe('flat-globally-unique');
      expect(info.cross_repo_annotation_rules.join('\n')).toContain('#auth-endpoint');
      expect(info.cross_repo_annotation_rules.join('\n')).not.toContain('#auth.endpoint');
      expect(readFileSync(join(orders, 'CLAUDE.md'), 'utf8')).toContain('globally unique');
    } finally { await client.close(); }
  });

  it('E1: counts a flat sibling control, independently of external_refs in older reports', async () => {
    linked();
    const files: string[] = [];
    for (const name of ['auth', 'orders']) {
      const { model } = await parse(name);
      model.external_refs = [];
      const file = join(root, name, 'report.json');
      put(file, JSON.stringify(model));
      files.push(file);
    }
    const merged = await mergeReports(files);
    expect(merged.totals.external_refs_resolved).toBe(1);
    expect(merged.totals.external_refs_unresolved).toBe(0);
    const auth = JSON.parse(readFileSync(files[0], 'utf8'));
    auth.controls[0].id = 'renamed-check';
    put(files[0], JSON.stringify(auth));
    const broken = await mergeReports(files);
    expect(broken.totals.external_refs_resolved).toBe(0);
    expect(broken.totals.external_refs_unresolved).toBe(1);
    expect(broken.unresolved_refs[0]).toMatchObject({ tag: '#session-check', source_repo: 'orders' });
  });

  it('member validate distinguishes a resolved sibling control from an undefined one', async () => {
    const { auth } = linked();
    const healthy = findDanglingRefs((await parse('orders')).model);
    expect(healthy.some(d => d.code === 'dangling-ref')).toBe(false);
    put(join(auth, 'src/app.ts'), '// @control Renamed_Check (#renamed-check)\n');
    const broken = findDanglingRefs((await parse('orders')).model);
    expect(broken.some(d => d.code === 'dangling-ref' && d.message.includes('#session-check'))).toBe(true);
  });

  it('member names default to directories and explicit names survive discovery', async () => {
    const web = member('web', 'export {};');
    const community = member('community', 'export {};');
    put(join(web, 'package.json'), '{"name":"different-web-package"}');
    const first = linkProject({ workspace: 'shop', repoPaths: [web, community] });
    expect(first.linked).toEqual(['web', 'community']);
    linkProject({ workspace: 'shop', repoPaths: [web, community], memberNames: { [web]: 'frontend', [community]: 'forum' } });
    expect(loadWorkspaceConfig(web)?.this_repo).toBe('frontend');
    const parsed = await parseProject({ root, anchors: false, agentConfig: false });
    expect(parsed.model.unannotated_files).toContain('web/src/app.ts');
  });

  it('F16/E17: parent parse uses only selected members and preserves member scope', async () => {
    const { auth, orders } = linked();
    member('unselected', '// @asset Excluded (#excluded)\n');
    put(join(auth, '.guardlink/config.json'), JSON.stringify({ mode: 'external', include: ['src/**'] }));
    put(join(auth, 'generated.ts'), 'export {};');
    const parent = await parseProject({ root, anchors: false, agentConfig: false });
    const members = await Promise.all(['auth', 'orders'].map(parse));
    expect(parent.model.assets.some(a => a.id === 'excluded')).toBe(false);
    expect(parent.model.source_files).toBe(members.reduce((n, m) => n + m.model.source_files, 0));
    expect(parent.model.unannotated_files).not.toContain('auth/generated.ts');
    expect(parent.model.mitigations[0].location.file).toBe('orders/src/app.ts');
    expect(orders).toBeTruthy();
  });

  it('last-partner removal explains how to unlink a two-member workspace', () => {
    const { orders } = linked();
    const result = removeFromWorkspace({ existingRepoPath: orders, repoName: 'auth' });
    expect(result.skipped[0].reason).toContain('.guardlink/workspace.yaml');
    expect(result.skipped[0].reason).toContain('Workspace Context');
  });
});

describe('all relationship reference positions participate in flat workspace resolution', () => {
  const cases: Array<[string, number]> = [
    ['@mitigates #orders against #remote-threat using #session-check', 2],
    ['@exposes #orders to #remote-threat [high]', 1],
    ['@confirmed #remote-threat on #orders [high]', 1],
    ['@accepts #remote-threat on #orders by "Fixture" until 2099-01-01', 1],
    ['@ticket #remote-threat on #orders TASK-1', 1],
    ['@transfers #remote-threat from #orders to #remote-asset', 2],
    ['@flows #orders -> #remote-asset', 1],
    ['@boundary from #orders to #remote-asset (#boundary)', 1],
    ['@validates #session-check for #orders', 1],
    ['@audit #remote-asset', 1],
    ['@owns Team for #remote-asset', 1],
    ['@handles pii on #remote-asset', 1],
    ['@assumes #remote-asset -- "test premise"', 1],
    ['@entitles #remote-actor to read on #orders against #remote-threat', 2],
    ['@agents #remote-actor to read on #orders as #remote-asset', 2],
    ['@reaches #remote-actor to read on #orders as #remote-asset', 2],
    ['@effects read on #remote-asset as #remote-identity', 2],
    ['@gates #remote-asset by #remote-actor for read', 2],
  ];
  it.each(cases)('%s', async (line, count) => {
    const auth = member('auth', '// @control Session_Check (#session-check)\n// @threat Remote_Threat (#remote-threat) [high]\n// @asset Remote.Asset (#remote-asset)\n// @asset Remote.Identity (#remote-identity)\n// @actor Remote_Actor (#remote-actor)\n');
    const orders = member('orders', `// @asset Orders (#orders)\n// ${line}\n`);
    linkProject({ workspace: 'shop', repoPaths: [auth, orders] });
    const files = [];
    for (const name of ['auth', 'orders']) {
      const { model, diagnostics } = await parse(name);
      expect(diagnostics).toEqual([]);
      const file = join(root, name, 'report.json');
      put(file, JSON.stringify(model));
      files.push(file);
    }
    const merged = await mergeReports(files);
    expect(merged.totals.external_refs_resolved).toBe(count);
    expect(merged.totals.external_refs_unresolved).toBe(0);
    const remote = JSON.parse(readFileSync(files[0], 'utf8'));
    remote.assets = []; remote.controls = []; remote.threats = []; remote.actors = [];
    put(files[0], JSON.stringify(remote));
    const broken = await mergeReports(files);
    expect(broken.totals.external_refs_unresolved).toBe(count);
    expect(broken.unresolved_refs.every(r => r.source_repo === 'orders')).toBe(true);
  });
});

describe('incomplete and legacy workspace evidence', () => {
  it('reports unavailable siblings as unchecked and fails an explicit complete check', async () => {
    const { auth } = linked();
    rmSync(auth, { recursive: true });
    const partial = await parse('orders');
    expect(partial.model.external_refs?.[0]).toMatchObject({ resolution: 'not_checked', unchecked_members: ['auth'] });
    expect(findDanglingRefs(partial.model).some(d => d.code === 'linked-ref' && d.message.includes('not checked'))).toBe(true);
    const checked = await parseProject({ root: join(root, 'orders'), requireSiblings: true, anchors: false, agentConfig: false });
    expect(checked.diagnostics.some(d => d.code === 'workspace-incomplete' && d.level === 'error')).toBe(true);
    const app = await parseProject({ root, anchors: false, agentConfig: false });
    expect(app.model.application?.receipt).toMatchObject({ completeness: 'partial', expectedMemberIds: ['auth', 'orders'] });
    expect(app.model.assets.length).toBeGreaterThan(0);
    const server = createServer();
    const client = new Client({ name: 'incomplete-workspace', version: '1' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(b), client.connect(a)]);
    try {
      const response = await client.callTool({ name: 'guardlink_parse', arguments: { root } });
      expect(response.isError).toBe(true);
      expect(JSON.stringify(response.content)).toContain('Application incomplete');
    } finally { await client.close(); }
    member('auth', '// @control Session_Check (#session-check)\n');
    linkProject({ workspace: 'shop', repoPaths: [auth, join(root, 'orders')] });
    put(join(root, 'orders/src/app.ts'), '// @mitigates #orders against\n');
    const invalid = await parseProject({ root, anchors: false, agentConfig: false });
    expect(invalid.model.application?.receipt.members.find(m => m.id === 'orders')).toMatchObject({ state: 'invalid', reasonCode: 'member-parse-failed' });
    expect(invalid.model.application?.receipt.completeness).toBe('partial');
  });

  it('preserves external sidecar origins and the member coverage denominator', async () => {
    const { auth } = linked();
    put(join(auth, 'src/app.ts'), 'export const check = true;\n');
    mkdirSync(join(auth, '.guardlink/annotations/src'), { recursive: true });
    put(join(auth, '.guardlink/annotations/src/app.ts.gal'), '@source file:src/app.ts line:1\n@control Session_Check (#session-check)\n');
    put(join(auth, '.guardlink/config.json'), JSON.stringify({ mode: 'external', include: ['src/**'] }));
    put(join(auth, 'outside.ts'), 'export {};');
    const a = await parse('auth');
    const b = await parse('orders');
    const parent = await parseProject({ root, anchors: false, agentConfig: false });
    expect(parent.model.source_files).toBe(a.model.source_files + b.model.source_files);
    expect(parent.model.coverage.coverage_percent).toBe(100);
    expect(parent.model.controls[0].location.origin_file).toBe('auth/.guardlink/annotations/src/app.ts.gal');
    expect(parent.model.annotation_scope?.excluded.some(e => e.file === 'auth/outside.ts')).toBe(true);
  });

  it('keeps dotted references readable and identifies them as legacy without rewriting them', async () => {
    const { auth, orders } = linked();
    put(join(auth, 'src/app.ts'), '// @asset Auth.Endpoint (#endpoint)\n');
    put(join(orders, 'src/app.ts'), '// @asset Orders (#orders)\n// @flows #orders -> #auth.endpoint\n');
    const refs = (await parse('orders')).model.external_refs;
    expect(refs?.[0]).toMatchObject({ tag: '#auth.endpoint', legacy: true, resolution: 'unresolved' });
    const files = [];
    for (const name of ['auth', 'orders']) {
      const file = join(root, name, 'report.json');
      put(file, JSON.stringify((await parse(name)).model)); files.push(file);
    }
    const merged = await mergeReports(files);
    expect(merged.totals.external_refs_resolved).toBe(0);
    expect(merged.totals.external_refs_unresolved).toBe(1);
    expect(merged.warnings.some(w => w.code === 'legacy_ref')).toBe(true);
    expect(merged.model.flows[0].target).toBe('#auth.endpoint');
  });

  it('changes the fingerprint when a sibling definition or member scope changes', async () => {
    const { fingerprintProject } = await import('../src/parser/fingerprint.js');
    const { auth, orders } = linked();
    const before = await fingerprintProject(orders);
    put(join(auth, 'src/app.ts'), '// @control Different_Check (#other-check)\n');
    expect(await fingerprintProject(orders)).not.toBe(before);
    const parent = await fingerprintProject(root);
    put(join(auth, '.guardlink/config.json'), '{"include":["src/**"]}');
    expect(await fingerprintProject(root)).not.toBe(parent);
  });

  it('fails explicitly when manifests disagree instead of guessing the application membership', async () => {
    const { auth } = linked();
    const config = readFileSync(join(auth, '.guardlink/workspace.yaml'), 'utf8');
    put(join(auth, '.guardlink/workspace.yaml'), config.replace('workspace: shop', 'workspace: other'));
    await expect(parseProject({ root, anchors: false, agentConfig: false })).rejects.toThrow('Conflicting linked workspace manifests');
  });
});

describe('workspace CLI contracts', () => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');
  const run = (...args: string[]) => execFileSync(process.execPath, [tsx, cli, ...args], { cwd: root, encoding: 'utf8', stdio: 'pipe' });

  it('accepts registry names through repeatable --member arguments', () => {
    const web = member('web', 'export {};');
    const auth = member('auth', 'export {};');
    run('link-project', '--workspace', 'shop', '--member', `frontend=${web}`, '--member', `accounts=${auth}`);
    expect(loadWorkspaceConfig(web)?.this_repo).toBe('frontend');
    expect(loadWorkspaceConfig(auth)?.this_repo).toBe('accounts');
  });

  it('validate --workspace succeeds with siblings and fails after a control rename or missing checkout', () => {
    const { auth, orders } = linked();
    expect(() => run('validate', orders, '--workspace')).not.toThrow();
    expect(() => run('validate', root, '--workspace')).not.toThrow();
    put(join(auth, 'src/app.ts'), '// @control Other_Check (#other-check)\n');
    expect(() => run('validate', orders, '--workspace')).toThrow();
    rmSync(auth, { recursive: true });
    expect(() => run('validate', orders, '--workspace')).toThrow();
  }, 30_000);

  it('parent parsing reads selected worktree members with .git files', async () => {
    const { auth, orders } = linked();
    put(join(auth, '.git'), 'gitdir: /nonexistent/fixture\n');
    put(join(orders, '.git'), 'gitdir: /nonexistent/fixture\n');
    const parsed = await parseProject({ root, anchors: false, agentConfig: false });
    expect(parsed.model.controls.some(c => c.id === 'session-check')).toBe(true);
    expect(parsed.model.mitigations).toHaveLength(1);
  });
});

describe('workspace manifests written by other YAML clients', () => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');

  it('reads JSON-form YAML after linking, then parses and validates both members', async () => {
    const { auth, orders } = linked();
    for (const dir of [auth, orders]) {
      const config = loadWorkspaceConfig(dir)!;
      put(join(dir, '.guardlink/workspace.yaml'), JSON.stringify(config, null, 2));
    }
    expect(loadWorkspaceConfig(orders)?.this_repo).toBe('orders');
    expect((await parse('orders')).model.external_refs?.[0].resolution).toBe('resolved');
    for (const dir of [auth, orders]) for (const command of ['parse', 'validate']) {
      expect(() => execFileSync(process.execPath, [tsx, cli, command, dir], { cwd: root, stdio: 'pipe' })).not.toThrow();
    }
  }, 30_000);

  it('reads ordinary YAML flow collections, quoted scalars, comments and aliases', async () => {
    const { parseWorkspaceYaml, serializeWorkspaceYaml } = await import('../src/workspace/metadata.js');
    const parsed = parseWorkspaceYaml('workspace: &label "shop: #1"\nthis_repo: orders\nrepos: [{name: orders}, {name: auth, registry: "https://example.test/auth#main"}] # members\nshared_definitions: *label\n');
    expect(parsed.workspace).toBe('shop: #1');
    expect(parsed.repos).toHaveLength(2);
    expect(parsed.shared_definitions).toBe('shop: #1');
    expect(parseWorkspaceYaml(serializeWorkspaceYaml(parsed))).toEqual(parsed);
  });

  it('reports an invalid manifest with its filename and YAML problem, without an uncaught stack', async () => {
    const { orders } = linked();
    put(join(orders, '.guardlink/workspace.yaml'), 'workspace: [unterminated\n');
    const parsed = await parse('orders');
    expect(parsed.diagnostics).toContainEqual(expect.objectContaining({ code: 'workspace-config-invalid', level: 'error', file: '.guardlink/workspace.yaml' }));
    expect(parsed.diagnostics[0].message).toMatch(/flow sequence|\]/i);
    for (const command of ['parse', 'validate']) {
      try {
        execFileSync(process.execPath, [tsx, cli, command, orders], { cwd: root, stdio: 'pipe' });
        expect.fail('invalid manifest must fail the CLI');
      } catch (error) {
        const result = error as { status: number; stderr: Buffer };
        expect(result.status).toBe(1);
        const stderr = result.stderr.toString();
        expect(stderr).toContain('.guardlink/workspace.yaml');
        expect(stderr).toMatch(/flow sequence|\]/i);
        expect(stderr).not.toMatch(/\n\s+at (?:\w|file:)/);
      }
    }
  }, 30_000);

  it('names schema errors and keeps unreadable sibling references unchecked', async () => {
    const { auth } = linked();
    put(join(auth, '.guardlink/workspace.yaml'), JSON.stringify({ workspace: 'shop', this_repo: 'auth', repos: 'invalid-list' }));
    const parsed = await parse('orders');
    expect(parsed.model.external_refs?.[0].resolution).toBe('not_checked');
    expect(parsed.diagnostics.some(d => d.file.endsWith('auth/.guardlink/workspace.yaml') && d.message.includes('repos'))).toBe(true);
    const checked = await parseProject({ root: join(root, 'orders'), requireSiblings: true, anchors: false, agentConfig: false });
    expect(checked.diagnostics.some(d => d.level === 'error' && d.code === 'workspace-config-invalid')).toBe(true);
  });
});

describe('unreadable workspace files and bounded YAML decoding', () => {
  it('turns a filesystem read error into a named manifest diagnostic', async () => {
    const { orders } = linked();
    const path = join(orders, '.guardlink/workspace.yaml');
    rmSync(path);
    mkdirSync(path);
    const result = await parse('orders');
    expect(result.diagnostics[0]).toMatchObject({ level: 'error', code: 'workspace-config-invalid', file: '.guardlink/workspace.yaml' });
    expect(result.diagnostics[0].message).toMatch(/EISDIR|directory/i);
    const server = createServer();
    const client = new Client({ name: 'unreadable-workspace', version: '1' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(b), client.connect(a)]);
    try {
      const response = await client.callTool({ name: 'guardlink_parse', arguments: { root: orders } });
      expect(response.isError).toBe(true);
      expect(JSON.stringify(response.content)).toContain('workspace.yaml');
      expect(JSON.stringify(response.content)).toMatch(/EISDIR|directory/i);
    } finally { await client.close(); }
  });

  it('refuses excessive alias expansion while accepting ordinary YAML aliases', async () => {
    const { parseWorkspaceYaml } = await import('../src/workspace/metadata.js');
    const aliases = (name: string) => Array.from({ length: 20 }, () => `*${name}`).join(', ');
    const document = `workspace: shop\nthis_repo: orders\nrepos: [{name: orders}, {name: auth}]\na: &a [one, two, three]\nb: &b [${aliases('a')}]\nc: &c [${aliases('b')}]\nd: [${aliases('c')}]\n`;
    expect(() => parseWorkspaceYaml(document)).toThrow(/alias/i);
  });
});

describe('duplicate member checkouts', () => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');

  it('names both checkouts and a recovery action, without a stack, for member validation and container parsing', async () => {
    const { orders } = linked();
    const extra = member('orders-fix', 'export {};');
    put(join(extra, '.guardlink/workspace.yaml'), readFileSync(join(orders, '.guardlink/workspace.yaml'), 'utf8'));
    const parsed = await parseProject({ root, anchors: false, agentConfig: false });
    expect(parsed.diagnostics).toContainEqual(expect.objectContaining({ level: 'error', code: 'workspace-config-invalid' }));
    for (const args of [['validate', orders, '--workspace'], ['parse', root]]) {
      try {
        execFileSync(process.execPath, [tsx, cli, ...args], { cwd: root, encoding: 'utf8', stdio: 'pipe' });
        expect.fail('ambiguous membership must fail');
      } catch (error) {
        const result = error as { status: number; stderr: string };
        expect(result.status).toBe(1);
        expect(result.stderr).toContain('Duplicate linked member identity "orders"');
        expect(result.stderr).toContain(args[0] === 'parse' ? 'orders' : orders);
        expect(result.stderr).toContain(args[0] === 'parse' ? 'orders-fix' : extra);
        expect(result.stderr).toMatch(/move.*outside|relink/i);
        expect(result.stderr).not.toMatch(/\n\s+at (?:\w|file:)/);
      }
    }
    // Resolving the ambiguity restores the normal read path.
    rmSync(extra, { recursive: true });
    expect(() => execFileSync(process.execPath, [tsx, cli, 'validate', orders, '--workspace'], { cwd: root, stdio: 'pipe' })).not.toThrow();
  }, 30_000);
});
