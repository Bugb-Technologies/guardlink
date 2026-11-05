/** These cases also run against the optional scanner-conversion and translate-stdout extension. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
const helpResult = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--help'], { encoding: 'utf8' });
if (helpResult.status !== 0)
  throw Error('Translate help failed: ' + helpResult.stderr);
const help = helpResult.stdout;
if (process.env.GUARDLINK_TEST_TRANSLATE_EXTENSIONS === '1' && (!help.includes('--from') || !help.includes('--stdout')))
  throw Error('Expected translate conversion/stdout extensions are unavailable');
const temporary: string[] = [];
afterEach(() => { vi.unstubAllEnvs(); for (const root of temporary.splice(0))
  rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'guardlink-integration-scenario-'));
  temporary.push(root);
  mkdirSync(join(root, '.guardlink'));
  writeFileSync(join(root, '.guardlink', 'definitions.ts'), '// @asset API (#api) -- "API"\n// @threat Auth (#auth) [high] -- "Missing auth"\n');
  writeFileSync(join(root, 'api.ts'), '// @exposes #api to #auth [high] -- "records returns protected data"\nexport function records() {}');
  const guide = join(root, 'guide', 'pentest', 'docs');
  mkdirSync(guide, { recursive: true });
  writeFileSync(join(guide, 'TEMPLATES.md'), 'Use cxgProbe(cxg), engine primitives and documented proof.');
  vi.stubEnv('GUARDLINK_CXG_ROOT', join(root, 'guide'));
  vi.stubEnv('CERT_X_GEN_HOME', join(root, 'guide'));
  const source = join(root, 'scanner.py'), ref = 'auth@api.ts:1';
  writeFileSync(source, `# @id: records\n# @guardlink_threat: ${ref}\n`);
  return { root, source, ref };
}
describe.skipIf(!help.includes('--from'))('conversion completion scenarios', () => {
  it.each(['success', 'refusal', 'empty'] as const)('preserves %s author outcome during scanner conversion', outcome => {
    const { root, source, ref } = fixture();
    const binary = join(root, 'claude');
    const envelope = { type: 'result', subtype: 'success', is_error: false, stop_reason: outcome === 'refusal' ? 'refusal' : 'end_turn', safety_stops: 2, result: 'Draft written.' };
    const probe = `// @id: records\n// @vuln_class: idor\n// @attach_scheme: path\n// @guardlink_threat: ${ref}\nasync function cxgProbe(cxg) {return [];}`;
    writeFileSync(binary, `#!${process.execPath}\nconst fs=require('node:fs'),path=require('node:path'),prompt=fs.readFileSync(0,'utf8'),match=prompt.match(/Write JavaScript files under ("[^\\n]+")\\./),out=JSON.parse(match[1]);fs.writeFileSync(path.join(out,'probe.js'),${JSON.stringify(probe)});fs.writeFileSync(path.join(out,'conversion.json'),JSON.stringify({version:1,sources:[{source:${JSON.stringify(source)},threat_ref:${JSON.stringify(ref)},probes:[{file:'probe.js',oracle:'engine.cross_identity_overlap',rationale:'Compare owned records through entitled and attacker engine-routed arms',prerequisites:['entitled identity','attacker identity']}]}]}));${outcome === 'empty' ? '' : `console.log(${JSON.stringify(JSON.stringify(envelope))});`}`);
    chmodSync(binary, 0o755);
    vi.stubEnv('PATH', root + delimiter + process.env.PATH);
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--dir', root, '--headless', '--agent', 'claude', '--contract', 'probe', '--from', source, '--no-code-graph'], { encoding: 'utf8', env: { ...process.env } });
    const report = JSON.parse(result.stdout);
    expect(result.status, result.stderr).toBe(outcome === 'success' ? 0 : 1);
    expect(report.results[0].status).toBe(outcome === 'success' ? 'written' : 'failed');
    expect(report.results[0].source).toBe(source);
    if (outcome === 'empty')
      expect(report.results[0].completion.status).toBe('unknown');
    else {
      expect(report.results[0].completion.safety_stops).toBe(2);
      expect(report.warnings[0].safety_stops).toBe(2);
    }
  });
});
describe.skipIf(!help.includes('--stdout'))('translate stdout completion boundary', () => {
  it('prints a prompt without launching an author or requiring completion metadata', () => {
    const { root } = fixture(), marker = join(root, 'author-called'), binary = join(root, 'claude');
    writeFileSync(binary, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)},'called');`);
    chmodSync(binary, 0o755);
    vi.stubEnv('PATH', root + delimiter + process.env.PATH);
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--dir', root, '--stdout', '--contract', 'probe', '--no-code-graph'], { encoding: 'utf8', env: { ...process.env } });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('cxgProbe(cxg)');
    expect(existsSync(marker)).toBe(false);
  });

  it('prints only the prompt: no launch banner and no templates written', () => {
    const { root } = fixture();
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', 'the api', '--dir', root, '--stdout', '--no-code-graph'], { encoding: 'utf8', env: { ...process.env } });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('the api');
    expect(result.stdout).not.toMatch(/Launching|will take over this terminal|session ended|copied to clipboard/);
    expect(existsSync(join(root, '.guardlink', 'cxg-templates'))).toBe(false);
  });

  it.each([['--headless', '--agent', 'claude'], ['--claude-code'], ['--clipboard']])('refuses --stdout with %s', (...flags) => {
    const { root } = fixture();
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--dir', root, '--stdout', ...flags, '--no-code-graph'], { encoding: 'utf8', env: { ...process.env } });
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain('--stdout prints the prompt for the calling agent');
  });
});
