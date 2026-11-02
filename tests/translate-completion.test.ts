import { afterEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { tmpdir } from 'node:os';
import { runTranslateAgent, translateHeadless, type TranslateAgent } from '../src/agents/translate-headless.js';
import { readAgentCompletion, MAX_COMPLETION_BYTES } from '../src/agents/translate-completion.js';
import { parseProject } from '../src/parser/index.js';

const dirs: string[] = [];
function directory() { const dir = mkdtempSync(join(tmpdir(), 'guardlink-completion-')); dirs.push(dir); return dir; }
afterEach(() => { vi.unstubAllEnvs(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function frame(agent: TranslateAgent, text: string, metadata: Record<string, unknown> = {}) {
  if (agent === 'claude') return JSON.stringify({ type: 'result', subtype: 'success', is_error: false, result: text, ...metadata });
  if (agent === 'gemini') return JSON.stringify({ response: text, stats: metadata });
  return [JSON.stringify({ type: 'item.completed', item: { type: 'agent_message', text } }), JSON.stringify({ type: 'turn.completed', usage: {}, ...metadata })].join('\n');
}
function binary(agent: TranslateAgent, output: string, exitCode = 0) {
  const root = directory();
  const file = join(root, agent);
  writeFileSync(file, `#!${process.execPath}\nconst fs=require('node:fs'); fs.readFileSync(0,'utf8'); fs.writeFileSync(${JSON.stringify(join(root, 'args.json'))},JSON.stringify(process.argv.slice(2))); process.stdout.write(${JSON.stringify(output)}); process.exit(${exitCode});`);
  chmodSync(file, 0o755);
  vi.stubEnv('PATH', root + delimiter + process.env.PATH);
  return root;
}

describe('headless structured completion', () => {
  it.each(['claude', 'codex', 'gemini'] as const)('rejects %s safety stops even when its completion and process say success', async agent => {
    const root = binary(agent, frame(agent, 'Files written.', { safety_stops: 2 }));
    const result = await runTranslateAgent(agent, 'Author templates', root, root);
    expect(result.error).toMatch(/safety/i);
    expect(result.completion).toMatchObject({ status: 'safety_stopped', safety_stops: 2 });
  });

  it.each(['claude', 'codex', 'gemini'] as const)('requests and accepts %s native structured success', async agent => {
    const root = binary(agent, frame(agent, 'Generated templates.'));
    const result = await runTranslateAgent(agent, 'Author templates', root, root);
    expect(result.error).toBeUndefined();
    expect(result.completion?.status).toBe('completed');
    const args: string[] = JSON.parse(readFileSync(join(root, 'args.json'), 'utf8'));
    expect(args).toContain(agent === 'codex' ? '--json' : '--output-format');
    if (agent !== 'codex') expect(args[args.indexOf('--output-format') + 1]).toBe('json');
  });

  it.each(['claude', 'codex', 'gemini'] as const)('reports a short %s refusal in its answer channel', async agent => {
    const root = binary(agent, frame(agent, 'I cannot assist with that request.'));
    const result = await runTranslateAgent(agent, 'Author templates', root, root);
    expect(result.error).toMatch(/refus/i);
    expect(result.completion?.status).toBe('refused');
  });

  it('preserves audit-only completion and does not interpret quoted source/tool text as a refusal', async () => {
    const output = JSON.stringify({ type: 'item.completed', item: { type: 'command_execution', aggregated_output: 'I cannot assist with that request.' } }) + '\n' + frame('codex', 'Audit-only: this governance claim has no executable test; see README.md.');
    const root = binary('codex', output);
    expect((await runTranslateAgent('codex', 'Author templates', root, root)).error).toBeUndefined();
  });

  it('preserves an explicit audit-only limitation even when the author says it cannot generate an executable test', () => {
    expect(readAgentCompletion(frame('claude', 'I cannot generate an executable template for this governance-only claim. Audit-only rationale is in README.md.')).status).toBe('completed');
  });

  it('does not let a later success erase an earlier structural refusal', async () => {
    const root = binary('codex', JSON.stringify({ type: 'item.completed', item: { type: 'agent_message', stop_reason: 'refusal' } }) + '\n' + frame('codex', 'Done.'));
    expect((await runTranslateAgent('codex', 'Author templates', root, root)).completion?.status).toBe('refused');
  });

  it('fails closed on absent structured completion, preserving nonzero process exits', async () => {
    const root = binary('codex', 'file written');
    expect((await runTranslateAgent('codex', 'Author templates', root, root)).error).toMatch(/structured completion/i);
    const failed = binary('codex', frame('codex', 'Done.'), 6);
    expect((await runTranslateAgent('codex', 'Author templates', failed, failed)).error).toContain('code 6');
  });

  it.each(['counter', 'completion'] as const)('keeps written paths and halts later authors after a %s safety stop', async location => {
    const root = directory(); mkdirSync(join(root, '.guardlink'));
    writeFileSync(join(root, '.guardlink', 'definitions.ts'), '// @asset API (#api) -- "API"\n// @threat Auth (#auth) [high] -- "Missing auth"\n');
    writeFileSync(join(root, 'api.ts'), '// @exposes #api to #auth [high] -- "getRecords returns protected records"\nexport function getRecords() {}');
    writeFileSync(join(root, 'other.ts'), '// @exposes #api to #auth [high] -- \"other returns protected records\"\nexport function other() {}');
    const model = (await parseProject({ root, project: 'fixture' })).model;
    let calls = 0;
    const report = await translateHeadless({ root, model, agent: 'codex', userPrompt: '', contract: 'scanner', out: 'generated' }, async (_agent, _prompt, _root, out) => {
      calls++;
      writeFileSync(join(out, 'probe.py'), '# draft only\n');
      return location === 'counter' ? { exitCode: 0, safety_stops: 2 } : { exitCode: 0, completion: { status: 'completed', safety_stops: 2 } };
    });
    expect(report.results[0]).toMatchObject({ status: 'failed', templates: [expect.stringContaining('probe.py')], completion: { status: 'safety_stopped', safety_stops: 2 } });
    expect(report.failures[0].error).toMatch(/safety/i);
    expect(readFileSync(report.results[0].templates[0], 'utf8')).toBe('# draft only\n');
    expect(calls).toBe(1);
    expect(report.results).toHaveLength(2);
    expect(report.results[1]).toMatchObject({status:'failed',templates:[]});
    expect(report.failures[1].error).toMatch(/earlier safety stop/i);
  });
});


describe('completion protocol boundaries', () => {
  it('ignores tool payload metadata while retaining an audit-only success', () => {
    const tool = {type:'item.completed',item:{type:'mcp_tool_call',result:{safety_stops:7,refusal:true,error:'source fixture'}}};
    expect(readAgentCompletion(JSON.stringify(tool)+'\n'+frame('codex','Audit-only: no executable template.')).status).toBe('completed');
  });
  it('rejects provider errors, max-turn results, invalid counters and oversized transcripts', () => {
    expect(readAgentCompletion(JSON.stringify({type:'result',subtype:'error_max_turns',is_error:true})).status).toBe('failed');
    expect(readAgentCompletion(JSON.stringify({error:{message:'provider failed'},response:''})).status).toBe('failed');
    expect(readAgentCompletion(frame('claude','Done.',{safety_stops:null})).status).toBe('failed');
    expect(readAgentCompletion('x'.repeat(MAX_COMPLETION_BYTES+1)).status).toBe('failed');
    expect(readAgentCompletion('{invalid JSON').status).toBe('unknown');
    expect(readAgentCompletion(frame('claude', "I'm sorry, but I can't assist with that request.")).status).toBe('refused');
    expect(readAgentCompletion(frame('gemini', "I’m unable to provide that template.")).status).toBe('refused');
    expect(() => readAgentCompletion(JSON.stringify({message:{role:'assistant',content:{}},type:'turn.completed'}))).not.toThrow();
  });
});
