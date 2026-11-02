import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import { spawnSync } from 'node:child_process';
import { validateProbeIdentities } from '../src/agents/translate-probe.js';
import { validateScannerYaml } from '../src/agents/translate-yaml.js';
import { buildTranslatePrompt, loadProbeGuide } from '../src/agents/prompts.js';
import { translateHeadless } from '../src/agents/translate-headless.js';
import { buildTranslateContext } from '../src/agents/translate-context.js';
import { QUERY_TIMEOUT_MS, graphQueryTimeout } from '../src/codegraph/index.js';
import { parseProject } from '../src/parser/index.js';

const dirs: string[] = [];
function directory() { const root = mkdtempSync(join(tmpdir(), 'guardlink-translate-regression-')); dirs.push(root); return root; }
afterEach(() => { vi.unstubAllEnvs(); for (const root of dirs.splice(0)) rmSync(root, { recursive: true, force: true }); });

async function project() {
  const root = directory();
  mkdirSync(join(root, '.guardlink'));
  writeFileSync(join(root, '.guardlink', 'definitions.ts'), '// @asset API (#api) -- "API"\n// @threat MissingAuth (#missing-auth) [high] -- "Protected records disclosed"\n');
  writeFileSync(join(root, 'api.ts'), 'export const app = 1;\n/**\n * @exposes #api to #missing-auth [high] -- "getRecords returns protected records anonymously"\n * @audit #api -- "Verify getRecords authorization"\n */\nexport function getRecords() {}');
  return { root, model: (await parseProject({ root, project: 'fixture' })).model };
}

describe('translate authoring regression paths', () => {
  it('loads the probe guide from the relocated cxg installation home', () => {
    const root = directory();
    vi.stubEnv('CERT_X_GEN_HOME', root);
    vi.stubEnv('GUARDLINK_CXG_ROOT', join(root, 'templates', 'official'));
    const guideDir = join(root, '.cert-x-gen', 'pentest', 'docs');
    mkdirSync(guideDir, { recursive: true });
    writeFileSync(join(guideDir, 'TEMPLATES.md'), 'installed-guide-marker: cxg.fetch(path, options)');
    expect(buildTranslatePrompt('', root, null, { contract: 'probe' })).toContain('installed-guide-marker');
  });

  it('refuses probe authoring when no readable nonempty guide is installed', () => {
    const root = directory();
    vi.stubEnv('CERT_X_GEN_HOME', root);
    vi.stubEnv('GUARDLINK_CXG_ROOT', root);
    expect(() => buildTranslatePrompt('', root, null, { contract: 'probe' })).toThrow(/probe.*guide.*not found/i);
  });

  it('allows graph queries taking longer than a minute and reports skipped graph packs', async () => {
    expect(QUERY_TIMEOUT_MS).toBeGreaterThan(62000);
    const { root, model } = await project();
    const onStatus = vi.fn();
    await buildTranslateContext(root, model, { enabled: false, onStatus });
    expect(onStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'skipped', reason: expect.stringContaining('disabled') }));
  });

  it('requires protected-resource evidence and a negative control, and fixes scalar-author skeletons', () => {
    const root = directory();
    vi.stubEnv('GUARDLINK_CXG_ROOT', root);
    vi.stubEnv('GUARDLINK_CXG_SKELETON_DIR', root);
    writeFileSync(join(root, 'yaml-template-skeleton.yaml'), 'id: example\nauthor: Security Team\nhttp: []\n');
    const prompt = buildTranslatePrompt('', root, null);
    expect(prompt).toContain('protected resource named by the threat');
    expect(prompt).toContain('root/banner/health');
    expect(prompt).toContain('negative control');
    expect(prompt).toContain('author:\n  name: Security Team');
    expect(prompt).not.toContain('author: Security Team');
  });

  it('returns the exact per-threat template directory and refuses invalid YAML author metadata', async () => {
    const { root, model } = await project();
    const report = await translateHeadless({ root, model, agent: 'codex', userPrompt: '', out: 'generated', contract: 'scanner' }, async (_agent, _prompt, _root, out) => {
      writeFileSync(join(out, 'bad.yaml'), 'id: missing-auth\nname: Missing auth\nauthor: Security Team\nseverity: high\ndescription: protected records\nlanguage: yaml\nhttp: []\n');
      return { exitCode: 0 };
    });
    expect(report.results[0].template_dir).toBe(join(root, 'generated', report.results[0].templates[0].split('/').at(-2)!));
    expect(report.results[0].status).toBe('failed');
    expect(report.failures[0].error).toMatch(/author.*(object|mapping|name)/i);
  });
  it('finds the default installed guide and honors a source-root override first', () => {
    const root = directory();
    const installed = join(root, '.cert-x-gen', 'pentest', 'docs');
    const source = join(root, 'source', 'pentest', 'docs');
    mkdirSync(installed, { recursive: true }); mkdirSync(source, { recursive: true });
    writeFileSync(join(installed, 'TEMPLATES.md'), 'installed guide');
    writeFileSync(join(source, 'TEMPLATES.md'), 'source guide');
    expect(loadProbeGuide({}, root).content).toBe('installed guide');
    expect(loadProbeGuide({ GUARDLINK_CXG_ROOT: join(root, 'source') }, root).content).toBe('source guide');
  });

  it('refuses probe authoring before running the agent when the installed guide is empty', async () => {
    const { root, model } = await project();
    vi.stubEnv('CERT_X_GEN_HOME', root); vi.stubEnv('GUARDLINK_CXG_ROOT', root);
    const guideDir = join(root, '.cert-x-gen', 'pentest', 'docs'); mkdirSync(guideDir, { recursive: true });
    writeFileSync(join(guideDir, 'TEMPLATES.md'), '  ');
    const run = vi.fn();
    const report = await translateHeadless({ root, model, agent: 'codex', userPrompt: '', out: 'generated', contract: 'probe' }, run);
    expect(run).not.toHaveBeenCalled();
    expect(report.failures[0].error).toMatch(/guide not found or empty/i);
    expect(report.results[0].status).toBe('failed');
  });

  it('propagates an environment-configured graph deadline and timeout reason through the real transport', async () => {
    expect(graphQueryTimeout({ GUARDLINK_CODEGRAPH_TIMEOUT_MS: '240000' })).toBe(240000);
    expect(graphQueryTimeout({ GUARDLINK_CODEGRAPH_TIMEOUT_MS: '240000' }, 90000)).toBe(90000);
    expect(() => graphQueryTimeout({ GUARDLINK_CODEGRAPH_TIMEOUT_MS: 'invalid' })).toThrow(/positive integer/);
    const { root, model } = await project();
    const binary = join(root, 'slow-graph');
    writeFileSync(binary, `#!${process.execPath}\nprocess.stdin.resume(); setTimeout(() => {}, 10000);`); chmodSync(binary, 0o755);
    const onStatus = vi.fn();
    await buildTranslateContext(root, model, { env: { GUARDLINK_CODEGRAPH_MCP: binary, GUARDLINK_CODEGRAPH_TIMEOUT_MS: '50' }, onStatus });
    expect(onStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'skipped', reason: expect.stringContaining('no answer within') }));
  });

  it('CLI refuses probe authoring with structured failures and never starts the agent without a guide', async () => {
    const { root } = await project();
    const binary = join(root, 'codex'); const marker = join(root, 'agent-ran');
    writeFileSync(binary, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)},'ran');`); chmodSync(binary, 0o755);
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--dir', root, '--headless', '--agent', 'codex', '--contract', 'probe', '--no-code-graph'], {
      encoding: 'utf8', env: { ...process.env, CERT_X_GEN_HOME: root, GUARDLINK_CXG_ROOT: root, PATH: root + delimiter + process.env.PATH },
    });
    expect(result.status).toBe(1);
    expect(JSON.parse(result.stdout).failures[0].error).toMatch(/guide not found or empty/i);
    expect(existsSync(marker)).toBe(false);
  });

  it('checks AuthorInfo itself, invokes the CXG schema validator, and propagates schema errors even on exit zero', () => {
    const root = directory();
    const binary = join(root, 'cxg'); const marker = join(root, 'validator-ran');
    writeFileSync(binary, `#!${process.execPath}\nconst fs=require('node:fs');fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify(process.argv.slice(2))); console.log('Validator banner\\n'+JSON.stringify([{passed:!process.env.SCHEMA_FAIL,diagnostics:process.env.SCHEMA_FAIL?[{severity:'error',message:'http.path must be a sequence'}]:[]}]))`); chmodSync(binary, 0o755);
    vi.stubEnv('PATH', root + delimiter + process.env.PATH);
    const file = join(root, 'check.yaml');
    writeFileSync(file, 'id: check\nname: Check\nauthor:\n  name: Security Team\nseverity: high\ndescription: protected records\nlanguage: yaml\nhttp: []\n');
    expect(validateScannerYaml(file)).toEqual([]);
    expect(JSON.parse(readFileSync(marker, 'utf8'))).toEqual(['template', 'validate', file, '--json', '--disable-update-check']);
    vi.stubEnv('SCHEMA_FAIL', '1');
    expect(validateScannerYaml(file)[0]).toContain('http.path must be a sequence');
    writeFileSync(file, 'author: Security Team');
    expect(validateScannerYaml(file)[0]).toContain('AuthorInfo');
    writeFileSync(file, 'author: {name: Security Team, email: 4}');
    expect(validateScannerYaml(file)[0]).toContain('author.email');
  });

});

describe('portable replay contracts', () => {
  it('constrains named bindings to supplied profiles and reserves anonymous without counting it as authenticated', () => {
    const root = directory();
    const guide = join(root, '.cert-x-gen', 'pentest', 'docs'); mkdirSync(guide, { recursive: true });
    writeFileSync(join(guide, 'TEMPLATES.md'), 'Use cxg.identities for named roles.');
    vi.stubEnv('CERT_X_GEN_HOME', root); vi.stubEnv('GUARDLINK_CXG_ROOT', root);
    const prompt = buildTranslatePrompt('', root, null, { contract: 'probe' });
    expect(prompt).toContain('@requires_identities');
    expect(prompt).toContain('identity.available');
    expect(prompt).toContain('"anonymous"');
    expect(prompt).toContain('only non-anonymous bindings');
    expect(prompt).toContain('Never invent profile names');
    expect(prompt).toContain('legacy numeric');
  });

  it('requires an exact source-threat header for every scanner language', async () => {
    const { root, model } = await project();
    const prompt = buildTranslatePrompt('', root, model, { contract: 'scanner' });
    expect(prompt).toContain('@guardlink_threat: <exact-source-threat-or-exposure-id>');
    expect(prompt).toContain('YAML/Python/shell');
    expect(prompt).toContain('JavaScript/Go/Rust');
    expect(prompt).toContain('missing-auth@api.ts:');
  });

  it('normalizes target-origin skeleton placeholders and refuses unresolved YAML HTTP paths before the old validator can accept them', () => {
    const root = directory();
    vi.stubEnv('GUARDLINK_CXG_ROOT', root); vi.stubEnv('GUARDLINK_CXG_SKELETON_DIR', root);
    writeFileSync(join(root, 'yaml-template-skeleton.yaml'), 'author: Security Team\nhttp:\n  - path: ["{{BaseURL}}/tasks"]\n');
    const prompt = buildTranslatePrompt('', root, null);
    expect(prompt).toContain('relative HTTP paths');
    expect(prompt).not.toContain('"{{BaseURL}}/tasks"');
    const file = join(root, 'invalid.yaml');
    writeFileSync(file, 'id: check\nname: Check\nauthor: {name: Security Team}\nseverity: high\ndescription: record\nlanguage: yaml\nhttp:\n  - path: ["{{BaseURL}}/tasks"]\n');
    expect(validateScannerYaml(file)[0]).toMatch(/placeholder|relative HTTP path/i);
  });

  it('retains route/auth/entry facts when no classified sink exists, while keeping sink absence explicit', async () => {
    const { root, model } = await project();
    const answers: Record<string, any> = {
      codegraph_attack_surface: { verdict: 'no_sinks_reached', rows: [] },
      codegraph_routes: { routes: [{ resolution: 'bound', handler: 'api.ts::getRecords', methods: ['GET'], path: '/records' }] },
      codegraph_auth_boundary: { verdict: 'classified', routes: [{ resolution: 'bound', handler: 'api.ts::getRecords', methods: ['GET'], path: '/records', access: { level: 'authenticated', basis: 'declared', summary: 'login required' } }] },
      codegraph_reachable_sinks: { verdict: 'no_sinks_reached', reach: { classes: [] } },
      codegraph_entry_reach: { reach: { liveness: 'live_via_route', entries: [{ node_id: 'api.ts::getRecords', path: ['api.ts::getRecords'], routes: [{ methods: ['GET'], path: '/records' }] }] } },
    };
    const context = await buildTranslateContext(root, model, { env: {}, transport: { via: 'stub', async query(_root, calls) { return calls.map(c => ({ ok: true as const, value: answers[c.tool] })); } } });
    expect(context?.threats[0].route).toEqual({ method: 'GET', path: '/records', handler: 'api.ts::getRecords' });
    expect(context?.threats[0].graph_facts?.join('\n')).toContain('no_sinks_reached');
    expect(context?.threats[0].graph_facts?.join('\n')).toContain('authenticated');
    expect(context?.threats[0].codegraph_path).toEqual(['api.ts::getRecords']);
    expect(context?.threats[0].sink).toBeUndefined();
    answers.codegraph_entry_reach.reach.entries.push({ node_id: 'cli.ts::main', path: ['cli.ts::main', 'api.ts::getRecords'], routes: [] });
    answers.codegraph_routes.routes.push({ resolution: 'bound', handler: 'api.ts::getRecords', methods: ['POST'], path: '/records/search' });
    const more = await buildTranslateContext(root, model, { env: {}, transport: { via: 'stub', async query(_root, calls) { return calls.map(c => ({ ok: true as const, value: answers[c.tool] })); } } });
    expect(more?.threats[0].graph_facts?.join('\n')).toContain('cli.ts::main');
    expect(more?.threats[0].graph_facts?.join('\n')).toContain('POST /records/search');
  });
  it('accepts supplied slot names plus an anonymous arm, preserves legacy numeric declarations, and rejects invented bindings', async () => {
    const { root, model } = await project();
    const context = { version: 1 as const, threats: [{ id: 'missing-auth', identity: { available: [{ name: 'a-member', role: 'member' }] } }] };
    const file = join(root, 'probe.js');
    const source = '// @requires_identities: {"entitled":"a-member","attacker":"anonymous"}\n// @requires_auth_count: 1\nasync function cxgProbe(cxg) { return []; }';
    writeFileSync(file, source);
    expect(validateProbeIdentities(file, model, context)).toEqual([]);
    expect(readFileSync(file, 'utf8')).toBe(source); // Binding validation never rewrites a committed kit.
    writeFileSync(file, source.replace('a-member', 'unprovided-local-profile'));
    expect(validateProbeIdentities(file, model, context)[0]).toContain('not supplied by context identity.available');
    writeFileSync(file, source.replace('@requires_auth_count: 1', '@requires_auth_count: 2'));
    expect(validateProbeIdentities(file, model, context)[0]).toContain('anonymous roles do not count');
    writeFileSync(file, '// @requires_auth_count: 6\nasync function cxgProbe(cxg) { return []; }');
    expect(validateProbeIdentities(file, model)).toEqual([]);
    writeFileSync(file, '// @requires_identities: {"attacker":"anonymous"}\n// @requires_auth_count: 0');
    expect(validateProbeIdentities(file, model)).toEqual([]);
  });

  it('emits scanner source identity deterministically while preserving shebangs and existing matching headers', async () => {
    const { root, model } = await project();
    const run = async (_agent: string, _prompt: string, _root: string, out: string) => {
      writeFileSync(join(out, 'check.py'), '#!/usr/bin/env python3\n# coding: utf-8\nraise RuntimeError("must never execute")\n');
      return { exitCode: 0 };
    };
    const report = await translateHeadless({ root, model, agent: 'codex', userPrompt: '', out: 'generated', contract: 'scanner' }, run);
    expect(report.failures).toEqual([]);
    const source = readFileSync(report.results[0].templates[0], 'utf8');
    expect(source.split('\n').slice(0, 3)).toEqual(['#!/usr/bin/env python3', '# coding: utf-8', `# @guardlink_threat: ${report.results[0].threat}`]);
    const unchanged = await translateHeadless({ root, model, agent: 'codex', userPrompt: '', out: 'generated', contract: 'scanner' }, async (_agent, _prompt, _root, out) => {
      writeFileSync(join(out, 'check.py'), source); return { exitCode: 0 };
    });
    expect(unchanged.failures).toEqual([]);
    expect(readFileSync(report.results[0].templates[0], 'utf8')).toBe(source);
    const conflicting = await translateHeadless({ root, model, agent: 'codex', userPrompt: '', out: 'generated', contract: 'scanner' }, async (_agent, _prompt, _root, out) => {
      writeFileSync(join(out, 'check.py'), '# @guardlink_threat: another-exposure\n'); return { exitCode: 0 };
    });
    expect(conflicting.results[0].status).toBe('failed');
    expect(conflicting.failures[0].error).toContain('refusing to relabel');
  });

  it('clipboard guidance names the requested output directory without touching the real clipboard', async () => {
    const { root } = await project();
    for (const name of ['pbcopy', 'xclip', 'xsel', 'clip']) {
      const file = join(root, name);
      writeFileSync(file, `#!${process.execPath}\nprocess.stdin.resume();`); chmodSync(file, 0o755);
    }
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--dir', root, '--clipboard', '--out', 'chosen-output', '--no-code-graph'], {
      encoding: 'utf8', env: { ...process.env, PATH: root + delimiter + process.env.PATH },
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('When done, review chosen-output');
  });

});
