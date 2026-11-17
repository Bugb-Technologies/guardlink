/**
 * GuardLink 2.7.1 regressions from the 2.6.0 → 2.7.0 review (rr-guardlink-270):
 *
 *   F1 — a repository whose direct child folders carry linked workspace manifests was replaced by an
 *        application view of those children, so its own exposures vanished from validate, diff and lint.
 *   F2 — an undecodable manifest (root, child or Bravos consumer manifest) produced an empty model or
 *        an uncaught stack trace instead of the repository's model with a named diagnostic.
 *   F5 — one duplicate member checkout made every MCP call in every sibling member fail.
 *
 * Each fixture follows the report's appendix; where 2.6.0's behaviour was the safe one it is asserted.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync, appendFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';
import { parseProject } from '../src/parser/parse-project.js';
import { findUnmitigatedExposures } from '../src/parser/validate.js';
import { fingerprintProject } from '../src/parser/fingerprint.js';
import { linkProject } from '../src/workspace/index.js';

const tsx = createRequire(import.meta.url).resolve('tsx/cli');
const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');
let root: string;
const put = (path: string, content: string) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, content); };
const git = (dir: string, ...args: string[]) => execFileSync('git', ['-C', dir, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', ...args], { stdio: 'pipe' });
const run = (cwd: string, ...args: string[]) => {
  try { return { code: 0, stdout: execFileSync(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf8', stdio: 'pipe' }), stderr: '' }; }
  catch (error) { const r = error as { status: number; stdout: string; stderr: string }; return { code: r.status, stdout: r.stdout, stderr: r.stderr }; }
};
const parse = (dir: string) => parseProject({ root: dir, anchors: false, agentConfig: false });

/** The report's demo app: one unmitigated high exposure, one mitigated route. */
function demo(dir: string): string {
  put(join(dir, '.guardlink/config.json'), JSON.stringify({ version: '1.1.0', project: 'demo', annotation_mode: 'inline', definitions: 'definitions.js' }));
  put(join(dir, '.guardlink/definitions.js'), [
    '// @asset Notes.API (#notes-api) -- "Notes HTTP API"',
    '// @threat IDOR (#idor) [high] cwe:CWE-639 -- "Reading another user\'s note"',
    '// @threat Path_Traversal (#path-traversal) [high] cwe:CWE-22 -- "Escaping the help directory"',
    '// @control Path_Allowlist (#path-allowlist) -- "Only names on the allowlist are served"', ''].join('\n'));
  put(join(dir, 'src/server.js'), [
    '/**', ' * @exposes #notes-api to #idor [high] cwe:CWE-639 -- "GET /notes/:id has no owner check"', ' * @audit #notes-api -- "Owner check missing"', ' */',
    'function getNote(req, res) { res.end("note"); }',
    '/**', ' * @mitigates #notes-api against #path-traversal using #path-allowlist -- "Allowlisted help names only"', ' */',
    'function getHelp(req, res) { res.end("help"); }', ''].join('\n'));
  return dir;
}
const exportNote = (dir: string) => appendFileSync(join(dir, 'src/server.js'), [
  '/**', ' * @exposes #notes-api to #path-traversal [high] cwe:CWE-22 -- "exportNote writes to a caller-named path"', ' * @audit #notes-api -- "Export path not validated"', ' */',
  'function exportNote(req, res) { res.end("export"); }', ''].join('\n'));
/** Two linked services inside `dir`, each with one asset and one mitigation. */
function services(dir: string, workspace = 'mono'): string[] {
  const paths = ['svc-a', 'svc-b'].map(name => {
    const path = join(dir, name);
    put(join(path, 'src/index.js'), `// @asset Svc.${name.replace('-', '_')} (#${name}-api)\n// @mitigates #${name}-api against #idor using #path-allowlist\n`);
    return path;
  });
  linkProject({ workspace, repoPaths: paths });
  return paths;
}

beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'gl-root-selection-')); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

describe('F1: a repository root keeps its own model when child folders are linked', () => {
  it('parses the root, not an application of its linked children', async () => {
    const mono = demo(join(root, 'mono'));
    services(mono);
    const { model, diagnostics } = await parse(mono);
    expect(model.application).toBeUndefined();
    expect(model.exposures.map(e => e.threat)).toEqual(['#idor']);
    expect(findUnmitigatedExposures(model)).toHaveLength(1);
    expect(diagnostics.filter(d => d.level === 'error')).toEqual([]);
  });

  it('validate --strict, diff --fail-on-new and lint --since see the root exposure, as under 2.6.0', () => {
    const mono = demo(join(root, 'mono'));
    services(mono);
    git(mono, 'init', '-q', '-b', 'main'); git(mono, 'add', '.'); git(mono, 'commit', '-qm', 'base');
    const strict = run(mono, 'validate', '.', '--strict');
    expect(strict.code).toBe(1);
    expect(strict.stdout + strict.stderr).toContain('#idor');

    git(mono, 'checkout', '-qb', 'feature'); exportNote(mono); git(mono, 'commit', '-qam', 'export');
    const diff = run(mono, 'diff', 'main', '--json');
    expect(JSON.parse(diff.stdout).newUnmitigatedExposures.map((e: { threat: string }) => e.threat)).toEqual(['#path-traversal']);
    expect(run(mono, 'diff', 'main', '--fail-on-new').code).toBe(1);
    expect(JSON.parse(run(mono, 'lint', '.', '--since', 'main', '--json').stdout).scope.claims).toBe(2);
  }, 60_000);

  it('still honours an explicit application selection at a repository root', async () => {
    const mono = demo(join(root, 'mono'));
    services(mono);
    const manifest = join(root, 'selected.json');
    writeFileSync(manifest, JSON.stringify({ schema: 'guardlink.application-manifest/v1', name: 'mono', members: [
      { id: 'svc-a', relativePath: 'svc-a' }, { id: 'svc-b', relativePath: 'svc-b' }] }));
    const { model } = await parseProject({ root: mono, applicationManifest: manifest, anchors: false, agentConfig: false });
    expect(model.application?.receipt.members.map(m => m.id)).toEqual(['svc-a', 'svc-b']);
  });

  it('ignores a valid Bravos consumer manifest inside a repository', async () => {
    const repo = demo(join(root, 'repo'));
    services(join(root, 'apps'));
    put(join(repo, '.bravos/workspace/consumer-manifest.json'), JSON.stringify({ schema: 'bravos.workspace-consumer/v1', name: 'apps', members: [{ id: 'svc-a', path: '../apps/svc-a' }] }));
    const { model } = await parse(repo);
    expect(model.application).toBeUndefined();
    expect(model.exposures).toHaveLength(1);
  });

  it('reads child manifests only from folders the scan set reads', async () => {
    // A folder of checkouts (not itself a repository) is still an application, as in 2.7.0 ...
    const app = join(root, 'app');
    services(app);
    expect((await parse(app)).model.application).toBeDefined();
    // ... but not when its only linked children sit under excluded names (tests/, vendor/).
    const excluded = join(root, 'excluded');
    for (const name of ['tests', 'vendor']) {
      const path = join(excluded, name);
      put(join(path, 'src/index.js'), '// @asset Pruned (#pruned)\n');
      put(join(path, '.guardlink/workspace.yaml'), `workspace: pruned\nthis_repo: ${name}\nrepos:\n  - name: tests\n  - name: vendor\n`);
    }
    expect((await parse(excluded)).model.application).toBeUndefined();
    // Inside a git checkout, a child holding a .git FILE (a submodule or linked worktree) is another
    // checkout, skipped exactly as scanIgnore skips it.
    const umbrella = join(root, 'umbrella');
    const [a, b] = services(umbrella);
    put(join(a, '.git'), 'gitdir: /nonexistent/fixture\n');
    put(join(b, '.git'), 'gitdir: /nonexistent/fixture\n');
    git(umbrella, 'init', '-q', '-b', 'main');
    expect((await parse(umbrella)).model.application).toBeUndefined();
  });
});

describe('F2: an undecodable manifest is a diagnostic beside the real model, never an empty one', () => {
  it('a malformed child manifest in a repository is a warning; validate passes as under 2.6.0', async () => {
    const repo = demo(join(root, 'repo'));
    put(join(repo, 'examples/.guardlink/workspace.yaml'), 'workspace: [oops\n');
    const { model, diagnostics } = await parse(repo);
    expect(model.exposures).toHaveLength(1);
    expect(diagnostics).toContainEqual(expect.objectContaining({ level: 'warning', code: 'workspace-config-invalid', file: 'examples/.guardlink/workspace.yaml' }));
    expect(diagnostics.filter(d => d.level === 'error')).toEqual([]);

    git(repo, 'init', '-q', '-b', 'main'); git(repo, 'add', '.'); git(repo, 'commit', '-qm', 'base');
    git(repo, 'checkout', '-qb', 'feature'); exportNote(repo); git(repo, 'commit', '-qam', 'export');
    expect(run(repo, 'validate', '.').code).toBe(0);
    expect(JSON.parse(run(repo, 'diff', 'main', '--json').stdout).newUnmitigatedExposures).toHaveLength(1);
    const ci = JSON.parse(run(repo, 'ci', '-f', 'json').stdout);
    expect(ci.summary.exposures).toBe(2);
  }, 60_000);

  it('a malformed root manifest fails validate and parse but keeps the model, and parse -o writes it whole', async () => {
    const repo = demo(join(root, 'repo'));
    put(join(repo, '.guardlink/workspace.yaml'), 'workspace: [unclosed\n');
    const { model, diagnostics } = await parse(repo);
    expect(diagnostics[0]).toMatchObject({ level: 'error', code: 'workspace-config-invalid', file: '.guardlink/workspace.yaml' });
    expect(model.exposures).toHaveLength(1);
    expect(model.assets).toHaveLength(1);

    const parsed = run(repo, 'parse', '.', '-o', '.guardlink/report.json');
    expect(parsed.code).toBe(1);
    expect(parsed.stderr).toContain('.guardlink/workspace.yaml');
    expect(parsed.stderr).not.toMatch(/\n\s+at (?:\w|file:)/);
    const report = JSON.parse(readFileSync(join(repo, '.guardlink/report.json'), 'utf8'));
    expect(report.exposures).toHaveLength(1);
    expect(report.source_files).toBeGreaterThan(0);
  }, 30_000);

  it('a malformed Bravos consumer manifest is a named error, not a stack trace', async () => {
    const app = join(root, 'app');
    put(join(app, 'src/index.js'), '// @asset App (#app)\n');
    put(join(app, '.bravos/workspace/consumer-manifest.json'), '{bad');
    const { model, diagnostics } = await parse(app);
    expect(diagnostics[0]).toMatchObject({ level: 'error', code: 'workspace-config-invalid', file: '.bravos/workspace/consumer-manifest.json' });
    expect(model.assets.map(a => a.id)).toEqual(['app']);
    const validate = run(app, 'validate', '.');
    expect(validate.code).toBe(1);
    expect(validate.stdout + validate.stderr).toContain('consumer-manifest.json');
    expect(validate.stderr).not.toMatch(/\n\s+at (?:\w|file:)/);
    // A repository never reads the consumer manifest at all.
    const repo = demo(join(root, 'repo'));
    put(join(repo, '.bravos/workspace/consumer-manifest.json'), '{bad');
    expect(run(repo, 'validate', '.').code).toBe(0);
  }, 30_000);

  it('a malformed member manifest in a folder of checkouts fails, with the folder still parsed', async () => {
    const app = join(root, 'app');
    const [a, b] = services(app);
    // One broken member: the readable member's view, with the broken one an explicit error.
    put(join(a, '.guardlink/workspace.yaml'), 'workspace: [oops\n');
    const partial = await parse(app);
    expect(partial.diagnostics).toContainEqual(expect.objectContaining({ level: 'error', file: 'svc-a/.guardlink/workspace.yaml' }));
    expect(partial.model.assets.map(x => x.id)).toContain('svc-b-api');
    // Every member broken: no application can be selected, so the folder is parsed as it stands.
    put(join(b, '.guardlink/workspace.yaml'), 'workspace: [oops\n');
    const { model, diagnostics } = await parse(app);
    expect(diagnostics[0]).toMatchObject({ level: 'error', code: 'workspace-config-invalid' });
    expect(model.assets.map(x => x.id).sort()).toEqual(['svc-a-api', 'svc-b-api']);
  });
});

describe('F5: a duplicate member checkout does not break MCP in its siblings', () => {
  it('fingerprints the member and answers MCP calls with the duplicate as a warning', async () => {
    const app = join(root, 'shop');
    const notes = join(app, 'notes'); const auth = join(app, 'auth');
    put(join(notes, '.guardlink/config.json'), '{}'); put(join(notes, 'src/notes.js'), '// @asset Notes (#notes)\n// @mitigates #notes against #idor using #session\n');
    put(join(auth, '.guardlink/config.json'), '{}'); put(join(auth, 'src/auth.js'), '// @control Session (#session)\n// @threat IDOR (#idor) [high]\n// @asset Auth (#auth)\n// @mitigates #auth against #idor using #session\n');
    linkProject({ workspace: 'shop', repoPaths: [notes, auth] });
    cpSync(notes, join(app, 'notes-old'), { recursive: true });
    expect(existsSync(join(app, 'notes-old/.guardlink/workspace.yaml'))).toBe(true);

    await expect(fingerprintProject(auth)).resolves.toMatch(/^[0-9a-f]{64}$/);
    const server = createServer();
    const client = new Client({ name: 'duplicate-member', version: '1' });
    const [x, y] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(y), client.connect(x)]);
    try {
      for (const [name, args] of [['guardlink_validate', { root: auth }], ['guardlink_context', { root: auth, file: 'src/auth.js' }], ['guardlink_validate', { root: notes }]] as const) {
        const response = await client.callTool({ name, arguments: args });
        expect(response.isError, `${name} ${args.root}`).toBeFalsy();
      }
    } finally { await client.close(); }
  }, 30_000);
});
