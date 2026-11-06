import { afterEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { parseProject } from '../src/parser/index.js';
import { readAgentCompletion } from '../src/agents/translate-completion.js';
import { runTranslateAgent, translateHeadless } from '../src/agents/translate-headless.js';
const temporary: string[] = [];
function directory() { const root = mkdtempSync(join(tmpdir(), 'guardlink-author-scenarios-')); temporary.push(root); return root; }
afterEach(() => { vi.unstubAllEnvs(); for (const root of temporary.splice(0))
  rmSync(root, { recursive: true, force: true }); });
const claude = (extra: Record<string, unknown> = {}) => ({ type: 'result', subtype: 'success', is_error: false, stop_reason: 'end_turn', result: 'Drafts written.', ...extra });
const json = (value: unknown) => JSON.stringify(value);
const jsonl = (...values: unknown[]) => values.map(json).join('\n');
const nativeCases: Array<[
  string,
  string,
  string
]> = [
  ['claude success safety zero', json(claude({ safety_stops: 0 })), 'completed'],
  ['claude success positive safety telemetry', json(claude({ safety_stops: 2 })), 'completed'],
  ['claude is_error', json(claude({ is_error: true })), 'failed'],
  ['claude error subtype', json(claude({ subtype: 'error_max_turns' })), 'failed'],
  ['claude refusal stop', json(claude({ stop_reason: 'refusal' })), 'refused'],
  ['claude max_tokens stop', json(claude({ stop_reason: 'max_tokens' })), 'failed'],
  ['claude pause_turn stop', json(claude({ stop_reason: 'pause_turn' })), 'failed'],
  ['legacy JSON array of native events', json([{ type: 'system', subtype: 'init' }, claude()]), 'completed'],
  ['structured output is data rather than a provider outcome', json(claude({ structured_output: { refusal: true, is_error: true } })), 'completed'],
  ['claude stream-json success', jsonl({ type: 'system', subtype: 'init' }, { type: 'assistant', message: { role: 'assistant', content: [{ type: 'text', text: 'Drafting.' }], stop_reason: 'tool_use' } }, claude()), 'completed'],
  ['claude partial stream max_tokens', jsonl({ type: 'stream_event', event: { type: 'message_delta', delta: { stop_reason: 'max_tokens' } } }, claude()), 'failed'],
  ['claude nested subagent refusal is not parent outcome', jsonl({ ...claude({ stop_reason: 'refusal' }), parent_tool_use_id: 'child-call' }, claude()), 'completed'],
  ['claude subagent result alone is not parent completion', json({ ...claude(), parent_tool_use_id: 'child-call' }), 'unknown'],
  ['codex JSONL success', jsonl({ type: 'thread.started', thread_id: 'thread-a' }, { type: 'turn.started' }, { type: 'item.completed', item: { type: 'agent_message', text: 'Drafts written.' } }, { type: 'turn.completed', usage: {} }), 'completed'],
  ['codex turn failed', json({ type: 'turn.failed', error: { message: 'Provider failed' } }), 'failed'],
  ['codex unrecoverable stream error', jsonl({ type: 'error', message: 'Stream failed' }, { type: 'turn.completed', usage: {} }), 'failed'],
  ['codex refusal message', jsonl({ type: 'item.completed', item: { type: 'agent_message', text: 'I cannot assist with that request.' } }, { type: 'turn.completed', usage: {} }), 'refused'],
  ['codex unfinished later turn', jsonl({ type: 'turn.started' }, { type: 'turn.completed', usage: {} }, { type: 'turn.started' }), 'failed'],
  ['gemini JSON success', json({ response: 'Drafts written.', stats: {} }), 'completed'],
  ['gemini JSON failure', json({ error: { message: 'Provider failed' }, stats: {} }), 'failed'],
  ['gemini JSON refusal', json({ response: 'I cannot assist with that request.', stats: {} }), 'refused'],
  ['gemini stream-json success', jsonl({ type: 'init', session_id: 'session-a' }, { type: 'message', role: 'assistant', content: 'Drafts written.' }, { type: 'result', status: 'success', stats: {} }), 'completed'],
  ['gemini stream-json refusal', jsonl({ type: 'message', role: 'assistant', content: 'I cannot assist with that request.' }, { type: 'result', status: 'success', stats: {} }), 'refused'],
  ['gemini stream-json failure', json({ type: 'result', status: 'error', error: { message: 'Provider failed' } }), 'failed'],
  ['gemini nonfatal warning', jsonl({ type: 'error', severity: 'warning', message: 'Retrying connection' }, { type: 'result', status: 'success', stats: {} }), 'completed'],
  ['normalized relay completion', json(claude({ safety_stops: 2 })), 'completed'],
  ['banner then pretty JSON', 'Author starting\n' + JSON.stringify(claude(), null, 2) + '\nAuthor finished', 'completed'],
  ['pretty JSON with a relay prefix on every line', JSON.stringify(claude(), null, 2).split('\n').map(line => '[relay] ' + line).join('\n'), 'completed'],
  ['unknown error envelope cannot be hidden', jsonl({ type: 'wrapper.error', is_error: true, error: { message: 'Transport failed' } }, claude()), 'failed'],
  ['provider managed retry warning is not a final failure', jsonl({ type: 'system', subtype: 'api_retry', error: { message: 'Transient API error' } }, claude()), 'completed'],
  ['known relay line prefix', '[relay] ' + json(claude()), 'completed'],
  ['UTF8 BOM and ANSI logger prefix', '\uFEFF\u001b[32m[claude]\u001b[0m ' + json(claude()), 'completed'],
  ['unknown prose prefix is not a protocol', 'Example: ' + json(claude()), 'failed'],
  ['unknown prefixed error cannot be hidden', 'Unrecognized wrapper: ' + json(claude({ is_error: true })) + '\n' + json(claude()), 'failed'],
  ['codex error cannot be relabeled as warning', jsonl({ type: 'error', severity: 'warning', message: 'Fatal stream error' }, { type: 'turn.completed', usage: {} }), 'failed'],
  ['gemini nonfatal nested warning', jsonl({ type: 'error', severity: 'warning', error: { code: 'TEMPORARY' }, message: 'Transient warning' }, { type: 'result', status: 'success', stats: {} }), 'completed'],
  ['malformed provider stop reason', json(claude({ stop_reason: { unexpected: true } })), 'failed'],
  ['terminal tool request is incomplete', json(claude({ stop_reason: 'tool_use' })), 'failed'],
  ['failure cannot be erased by later success', jsonl(claude({ is_error: true }), claude()), 'failed'],
  ['truncated only JSON', '{"type":"result","subtype":', 'failed'],
  ['truncated after successful terminal', jsonl(claude()) + '\n{"type":"result","is_error":', 'failed'],
  ['non-JSON text', 'Drafts written.', 'unknown'],
  ['empty stdout', '', 'unknown'],
  ['unrecognized envelope retains telemetry without claiming success', json({ completed: true, safety_stops: 2 }), 'unknown'],
  ['unrecognized explicit refusal is rejected', json({ type: 'wrapper.reply', refusal: 'Provider refused', safety_stops: 2 }), 'refused'],
  ['untyped result object', json({ type: 'result', result: 'Drafts written.' }), 'unknown'],
  ['tool result cannot forge completion', json({ type: 'tool_result', response: 'Drafts written.', stats: {}, result: claude() }), 'unknown'],
  ['tool error cannot fail provider', jsonl({ type: 'tool_result', error: { message: 'Fixture error' }, metadata: { refusal: true } }, claude()), 'completed'],
  ['conflicting native sessions', jsonl(claude({ session_id: 'session-a' }), claude({ session_id: 'session-b' })), 'failed'],
];
describe('completion scenario matrix', () => {
  it.each(nativeCases)('%s', (name, stdout, status) => {
    const provider = name.startsWith('codex') ? 'codex' : name.startsWith('gemini') ? 'gemini' : name.startsWith('claude') ? 'claude' : undefined;
    const completion = readAgentCompletion(stdout, provider);
    expect(completion.status, name).toBe(status);
    if (name === 'unrecognized envelope retains telemetry without claiming success')
      expect(completion.safety_stops).toBe(2);
  });
});
describe('telemetry schema scenarios', () => {
  it.each(['safety_stops', 'num_safety_stops', 'safety_stop_count', 'safetyStops'])('preserves the %s telemetry alias', field => {
    expect(readAgentCompletion(json(claude({ [field]: 2 })))).toMatchObject({ status: 'completed', safety_stops: 2 });
  });
  it.each([null, '2', -1, 0.5, false, {}, []])('warns without changing provider success for malformed telemetry %j', value => {
    const result = readAgentCompletion(json(claude({ safety_stops: value })));
    expect(result.status).toBe('completed');
    expect(result.safety_stops).toBeUndefined();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings?.[0]).toContain('telemetry');
  });
});
function executable(root: string, name: string, body: string) {
  const file = join(root, name);
  writeFileSync(file, `#!${process.execPath}\nconst fs=require('node:fs');fs.readFileSync(0,'utf8');\n${body}`);
  chmodSync(file, 0o755);
  vi.stubEnv('PATH', root + delimiter + process.env.PATH);
  return file;
}
describe('author process scenarios', () => {
  it('times out even when the child ignores graceful termination', async () => {
    const root = directory();
    executable(root, 'claude', `process.on('SIGTERM',()=>fs.writeFileSync(${JSON.stringify(join(root,'ignored-term'))},'ignored'));setTimeout(()=>{console.log(${JSON.stringify(json(claude()))});process.exit(0)},10000);`);
    const result = await runTranslateAgent('claude', 'Author', root, root, { timeoutMs: 1000 });
    expect(result.timedOut).toBe(true);
    if (process.platform !== 'win32') expect(existsSync(join(root, 'ignored-term'))).toBe(true);
    expect(result.error).toContain('timed out');
  });
  it('rejects a killed process even after a valid terminal was written', async () => {
    const root = directory();
    executable(root, 'claude', `process.stdout.write(${JSON.stringify(json(claude({ safety_stops: 2 })))},()=>process.kill(process.pid,'SIGTERM'));`);
    const result = await runTranslateAgent('claude', 'Author', root, root);
    expect(result.error).toBeTruthy();
    expect(result.exitCode).not.toBe(0);
    expect(result.completion?.safety_stops).toBe(2);
  });
  it('refuses file-only outcomes rather than guessing completion from generated files', async () => {
    const root = directory();
    executable(root, 'claude', `fs.writeFileSync(${JSON.stringify(join(root, 'completion.json'))},${JSON.stringify(json(claude()))});`);
    const result = await runTranslateAgent('claude', 'Author', root, root);
    expect(existsSync(join(root, 'completion.json'))).toBe(true);
    expect(result.completion?.status).toBe('unknown');
    expect(result.error).toBeTruthy();
  });
  it('recognizes a relay that forwards its SDK envelope file on stdout', async () => {
    const root = directory();
    executable(root, 'claude', `const file=${JSON.stringify(join(root, 'sdk-result.json'))};fs.writeFileSync(file,${JSON.stringify(json(claude({ safety_stops: 2 })))});process.stdout.write(fs.readFileSync(file));`);
    const result = await runTranslateAgent('claude', 'Author', root, root);
    expect(result.error).toBeUndefined();
    expect(result.completion).toMatchObject({ status: 'completed', safety_stops: 2 });
  });
  it('rejects stderr-only completion metadata', async () => {
    const root = directory();
    executable(root, 'claude', `process.stderr.write(${JSON.stringify(json(claude()))});`);
    const result = await runTranslateAgent('claude', 'Author', root, root);
    expect(result.completion?.status).toBe('unknown');
    expect(result.error).toBeTruthy();
  });
  it('bounds excessive process output even if the author keeps running', async () => {
    const root = directory();
    executable(root, 'claude', `process.stdout.write('x'.repeat(8*1024*1024+1));setTimeout(()=>process.exit(0),5000);`);
    const result = await runTranslateAgent('claude', 'Author', root, root);
    expect(result.error).toContain('8 MiB');
    expect(result.completion?.status).toBe('failed');
  });
  it('fails a missing author binary without inventing a completion', async () => {
    const root = directory();
    vi.stubEnv('PATH', root);
    const result = await runTranslateAgent('claude', 'Author', root, root);
    expect(result.exitCode).toBeNull();
    expect(result.error).toBeTruthy();
  });
  it.each([0, -1, 0.5, NaN, Infinity, 2147483648])('rejects unsafe timeout configuration %s', async (timeoutMs) => {
    const root = directory();
    await expect(runTranslateAgent('claude', 'Author', root, root, { timeoutMs })).rejects.toThrow(/timeout/i);
  });
});
async function project(exposures = 1) {
  const root = directory();
  mkdirSync(join(root, '.guardlink'));
  writeFileSync(join(root, '.guardlink', 'definitions.ts'), '// @asset API (#api) -- "API"\n// @threat Auth (#auth) [high] -- "Missing authorization"\n');
  for (let i = 0; i < exposures; i++)
    writeFileSync(join(root, `api${i}.ts`), `// @exposes #api to #auth [high] -- "records${i} returns protected data"\nexport function records${i}() {}`);
  mkdirSync(join(root, 'guide', 'pentest', 'docs'), { recursive: true });
  writeFileSync(join(root, 'guide', 'pentest', 'docs', 'TEMPLATES.md'), 'Use async function cxgProbe(cxg), return an array of findings, and use documented engine proof.');
  vi.stubEnv('GUARDLINK_CXG_ROOT', join(root, 'guide'));
  vi.stubEnv('CERT_X_GEN_HOME', join(root, 'guide'));
  const validator = join(root, 'cxg');
  writeFileSync(validator, `#!${process.execPath}\nconsole.log(JSON.stringify([{passed:true}]));`);
  chmodSync(validator, 0o755);
  vi.stubEnv('PATH', root + delimiter + process.env.PATH);
  return { root, model: (await parseProject({ root, project: 'fixture' })).model };
}
const validYaml = 'id: records\nname: Protected records\nlanguage: yaml\nauthor: {name: Security Team}\nseverity: high\ndescription: Protected records\nhttp:\n  - method: GET\n    path: ["/records"]\n    matchers: [{type: status, status: [200]}]\n';
const validProbe = '// @id: records\n// @vuln_class: auth_api\n// @severity: high\n// @description: Protected records\n// @requires_auth_count: 0\n// @destructive_priority: 0\n// @attach_scheme: path\nasync function cxgProbe(cxg) { return []; }';
describe('authoring workflow scenarios', () => {
  it.each(['probe', 'scanner'] as const)('accepts %s success with zero telemetry and valid drafts', async (contract) => {
    const { root, model } = await project();
    const report = await translateHeadless({ root, model, agent: 'claude', userPrompt: '', contract, out: 'drafts' }, async (_a, _p, _r, out) => {
      writeFileSync(join(out, contract === 'probe' ? 'probe.js' : 'probe.yaml'), contract === 'probe' ? validProbe : validYaml);
      return { exitCode: 0, completion: readAgentCompletion(json(claude({ safety_stops: 0 }))) };
    });
    expect(report.results[0]).toMatchObject({ status: 'written', completion: { status: 'completed', safety_stops: 0 } });
    expect(report.failures).toEqual([]);
    expect(report.warnings).toEqual([]);
  });
  it.each(['probe', 'scanner'] as const)('accepts %s success with positive telemetry and valid drafts', async (contract) => {
    const { root, model } = await project();
    const report = await translateHeadless({ root, model, agent: 'claude', userPrompt: '', contract, out: 'drafts' }, async (_a, _p, _r, out) => {
      writeFileSync(join(out, contract === 'probe' ? 'probe.js' : 'probe.yaml'), contract === 'probe' ? validProbe : validYaml);
      return { exitCode: 0, completion: readAgentCompletion(json(claude({ safety_stops: 2 }))) };
    });
    expect(report.results[0]).toMatchObject({ status: 'written', completion: { status: 'completed', safety_stops: 2 } });
    expect(report.failures).toEqual([]);
    expect(report.warnings[0].safety_stops).toBe(2);
  });
  it.each(['probe', 'scanner'] as const)('reports %s audit-only success as no_templates with positive telemetry', async (contract) => {
    const { root, model } = await project();
    const report = await translateHeadless({ root, model, agent: 'claude', userPrompt: '', contract, out: 'drafts' }, async (_a, _p, _r, out) => {
      writeFileSync(join(out, 'README.md'), 'Audit-only: no supported observable proof mechanism.');
      return { exitCode: 0, completion: readAgentCompletion(json(claude({ safety_stops: 2 }))) };
    });
    expect(report.results[0]).toMatchObject({ status: 'no_templates', templates: [], completion: { status: 'completed', safety_stops: 2 } });
    expect(report.failures).toEqual([]);
    expect(report.warnings[0].safety_stops).toBe(2);
  });
  it.each(['probe', 'scanner'] as const)('rejects invalid %s drafts despite positive success telemetry', async (contract) => {
    const { root, model } = await project();
    const report = await translateHeadless({ root, model, agent: 'claude', userPrompt: '', contract, out: 'drafts' }, async (_a, _p, _r, out) => {
      writeFileSync(join(out, contract === 'probe' ? 'probe.js' : 'probe.yaml'), contract === 'probe' ? '// @requires_identities: {"attacker":"not-supplied"}\n' + validProbe : validYaml.replace('author: {name: Security Team}', 'author: Security Team'));
      return { exitCode: 0, completion: readAgentCompletion(json(claude({ safety_stops: 2 }))) };
    });
    expect(report.results[0]).toMatchObject({ status: 'failed', completion: { status: 'completed', safety_stops: 2 } });
    expect(report.failures[0].error).toContain('Invalid');
    expect(report.warnings[0].safety_stops).toBe(2);
  });
  it.each(['failure', 'exit', 'refusal', 'timeout', 'signal', 'signal-exit'] as const)('handles mixed outcomes when the second author has a %s', async (outcome) => {
    const { root, model } = await project(3);
    let calls = 0;
    const report = await translateHeadless({ root, model, agent: 'claude', userPrompt: '', contract: 'scanner', out: 'drafts' }, async (_a, _p, _r, out) => {
      const index = calls++;
      writeFileSync(join(out, 'probe.py'), '# draft');
      if (index !== 1)
        return { exitCode: 0, completion: readAgentCompletion(json(claude({ safety_stops: 2 }))) };
      if (outcome === 'failure')
        return { exitCode: 0, completion: readAgentCompletion(json(claude({ is_error: true }))) };
      if (outcome === 'exit')
        return { exitCode: 7, error: 'Agent exited with code 7', completion: readAgentCompletion(json(claude())) };
      if (outcome === 'refusal')
        return { exitCode: 0, completion: readAgentCompletion(json(claude({ stop_reason: 'refusal' }))) };
      if (outcome === 'signal-exit')
        return { exitCode: 143, error: 'Agent exited with code 143', completion: readAgentCompletion(json(claude())) };
      if (outcome === 'timeout')
        return { exitCode: null, timedOut: true, error: 'Agent timed out' };
      return { exitCode: null, signal: 'SIGTERM', error: 'Agent terminated by SIGTERM' };
    });
    expect(report.results.map(r => r.status)).toEqual(['written', 'failed', ['failure', 'exit'].includes(outcome) ? 'written' : 'failed']);
    expect(calls).toBe(['failure', 'exit'].includes(outcome) ? 3 : 2);
    expect(report.failures).toHaveLength(['failure', 'exit'].includes(outcome) ? 1 : 2);
    if (!['failure', 'exit'].includes(outcome)) {
      expect(report.results[2].templates).toEqual([]);
      expect(readFileSync(report.results[1].templates[0], 'utf8')).toBe('# draft');
    }
  });
  it('passes the configured timeout to an injected relay runner', async () => {
    const { root, model } = await project();
    await translateHeadless({ root, model, agent: 'claude', userPrompt: '', contract: 'scanner', out: 'drafts', agentTimeoutMs: 3210 }, async (_a, _p, _r, _out, options) => {
      expect(options?.timeoutMs).toBe(3210);
      return { exitCode: 0, completion: readAgentCompletion(json(claude())) };
    });
  });
  it('applies a CLI author deadline and emits one failed JSON report', async () => {
    const { root } = await project();
    executable(root, 'claude', `setTimeout(()=>console.log(${JSON.stringify(json(claude()))}),2200);`);
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--dir', root, '--headless', '--agent', 'claude', '--agent-timeout', '100', '--no-code-graph'], { encoding: 'utf8', env: { ...process.env } });
    expect(result.status).toBe(1);
    const report = JSON.parse(result.stdout);
    expect(report.results[0].status).toBe('failed');
    expect(report.failures[0].error).toContain('timed out');
  });
  it.each(['0', '-1', 'NaN', '0.5', '2147483648'])('refuses invalid CLI author deadline %s before launching an author', async (timeout) => {
    const { root } = await project();
    const marker = join(root, 'called');
    executable(root, 'claude', `fs.writeFileSync(${JSON.stringify(marker)},'called');`);
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'translate', '--dir', root, '--headless', '--agent', 'claude', '--agent-timeout', timeout, '--no-code-graph'], { encoding: 'utf8', env: { ...process.env } });
    expect(result.status).toBe(1);
    expect(JSON.parse(result.stdout).failures[0].error).toMatch(/timeout/i);
    expect(existsSync(marker)).toBe(false);
  });
});
describe('prompt-only completion boundaries', () => {
  it('does not launch an author for MCP translate', async () => {
    const { root } = await project();
    const marker = join(root, 'author-called');
    executable(root, 'claude', `fs.writeFileSync(${JSON.stringify(marker)},'called');`);
    const [{ Client }, { InMemoryTransport }, { createServer }] = await Promise.all([import('@modelcontextprotocol/sdk/client/index.js'), import('@modelcontextprotocol/sdk/inMemory.js'), import('../src/mcp/server.js')]);
    const client = new Client({ name: 'scenario', version: '1' });
    const server = createServer();
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([client.connect(ct), server.connect(st)]);
    try {
      const result = await client.callTool({ name: 'guardlink_translate', arguments: { root, contract: 'probe', code_graph: false } });
      const content = result.content;
      if (!Array.isArray(content) || content[0]?.type !== 'text')
        throw Error('Expected MCP text');
      const payload = JSON.parse(content[0].text);
      expect(payload.mode).toBe('agent');
      expect(payload.prompt).toContain('cxgProbe(cxg)');
      expect(existsSync(marker)).toBe(false);
    }
    finally {
      await client.close();
    }
  });
  it('does not launch an author for annotate --stdout', async () => {
    const { root } = await project();
    const marker = join(root, 'author-called');
    executable(root, 'claude', `fs.writeFileSync(${JSON.stringify(marker)},'called');`);
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'annotate', root, '--stdout'], { encoding: 'utf8', env: { ...process.env } });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('GuardLink');
    expect(existsSync(marker)).toBe(false);
  // It starts the CLI through tsx, which a loaded 2-CPU CI runner takes more than the 5 s default to transpile.
  }, 30_000);
});
