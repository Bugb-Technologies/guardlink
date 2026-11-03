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
  if (agent === 'claude') return JSON.stringify({ type: 'result', subtype: 'success', is_error: false, stop_reason: 'end_turn', result: text, ...metadata });
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
  it('uses supported Codex exec flags with bounded writes and no interactive approvals', async () => {
    const root = directory(), out = join(root, 'drafts'); mkdirSync(out);
    const file = join(root, 'codex');
    // Model the current CLI parser: reject obsolete or unsafe modes before any author work.
    writeFileSync(file, `#!${process.execPath}\nconst fs=require('node:fs'),path=require('node:path'),args=process.argv.slice(2); const prompt=fs.readFileSync(0,'utf8');
      const valued=new Set(['--sandbox','-c','--add-dir','--color']);
      for(let i=1;i<args.length;i++) {
        if(valued.has(args[i])) {if(args[++i]===undefined) process.exit(2);continue;}
        if(!['--json','--skip-git-repo-check','-'].includes(args[i])) {console.error("error: unexpected argument '"+args[i]+"' found");process.exit(2);}
      }
      if(args.includes('--dangerously-bypass-approvals-and-sandbox') || args[args.indexOf('--sandbox')+1]!=='workspace-write' || args[args.indexOf('-c')+1]!=='approval_policy="never"') process.exit(3);
      if(args[0]!=='exec' || !args.includes('--json') || args.at(-1)!=='-' || !prompt.includes('Author templates') || process.stdin.isTTY) process.exit(4);
      fs.writeFileSync(path.join(args[args.indexOf('--add-dir')+1],'draft.py'),'# authored draft');
      console.log(JSON.stringify({type:'turn.completed',usage:{}}));`);
    chmodSync(file, 0o755); vi.stubEnv('PATH', root + delimiter + process.env.PATH);
    const result = await runTranslateAgent('codex', 'Author templates', root, out);
    expect(result).toMatchObject({exitCode:0,completion:{status:'completed'}});
    expect(result.error).toBeUndefined();
    expect(readFileSync(join(out,'draft.py'),'utf8')).toBe('# authored draft');
  });

  it.each(['claude', 'codex', 'gemini'] as const)('accepts successful %s completion while preserving its safety telemetry', async agent => {
    const root = binary(agent, frame(agent, 'Files written.', { safety_stops: 2 }));
    const result = await runTranslateAgent(agent, 'Author templates', root, root);
    expect(result.error).toBeUndefined();
    expect(result.completion).toMatchObject({ status: 'completed', safety_stops: 2 });
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

  it.each(['claude','codex','gemini'] as const)('still rejects %s provider errors with a positive safety counter', async agent => {
    const output = agent==='claude' ? JSON.stringify({type:'result',subtype:'error_during_execution',is_error:true,safety_stops:2})
      : agent==='codex' ? JSON.stringify({type:'turn.failed',error:{message:'Provider failed'},usage:{safety_stops:2}})
      : JSON.stringify({error:{message:'Provider failed'},stats:{safety_stops:2}});
    const root = binary(agent,output);
    const result = await runTranslateAgent(agent,'Author templates',root,root);
    expect(result.error).toBeTruthy();
    expect(result.completion).toMatchObject({status:'failed',safety_stops:2});
  });

  it.each(['refused','safety_stopped'] as const)('keeps an explicit %s provider outcome failed and skips later authors', async status => {
    const root=directory();mkdirSync(join(root,'.guardlink'));
    writeFileSync(join(root,'.guardlink','definitions.ts'),'// @asset API (#api) -- "API"\n// @threat Auth (#auth) [high] -- "Missing auth"\n');
    for(const file of ['first','second']) writeFileSync(join(root,file+'.ts'),'// @exposes #api to #auth [high] -- "'+file+' returns protected records"\nexport function '+file+'() {}');
    const model=(await parseProject({root,project:'fixture'})).model;
    let calls=0;
    const report=await translateHeadless({root,model,agent:'claude',userPrompt:'',contract:'scanner',out:'generated'},async(_agent,_prompt,_root,out)=>{
      calls++;writeFileSync(join(out,'draft.py'),'# raw draft');
      return {exitCode:0,completion:{status,safety_stops:2,reason:'Provider explicitly '+status}};
    });
    expect(calls).toBe(1);expect(report.failures).toHaveLength(2);
    expect(report.results[0]).toMatchObject({status:'failed',completion:{status,safety_stops:2}});
    expect(readFileSync(report.results[0].templates[0],'utf8')).toBe('# raw draft');
    expect(report.results[1]).toMatchObject({status:'failed',templates:[]});
    expect(report.warnings[0].safety_stops).toBe(2);
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

  it.each(['counter', 'completion'] as const)('warns and continues after successful authoring with a %s safety counter', async location => {
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
    expect(report.results).toHaveLength(2);
    expect(calls).toBe(2);
    expect(report.failures).toEqual([]);
    for (const row of report.results) {
      expect(row).toMatchObject({status:'written',completion:{status:'completed',safety_stops:2}});
      expect(readFileSync(row.templates[0],'utf8')).toContain('@guardlink_threat: '+row.threat);
    }
    expect(report.warnings).toHaveLength(2);
    expect(report.warnings[0]).toMatchObject({threat:report.results[0].threat,safety_stops:2,message:expect.stringContaining('safety_stops=2')});
  });
});


describe('completion protocol boundaries', () => {
  it('ignores tool payload metadata while retaining an audit-only success', () => {
    const tool = {type:'item.completed',item:{type:'mcp_tool_call',result:{safety_stops:7,refusal:true,error:'source fixture'}}};
    expect(readAgentCompletion(JSON.stringify(tool)+'\n'+frame('codex','Audit-only: no executable template.')).status).toBe('completed');
  });
  it('rejects provider errors, max-turn results and oversized transcripts while warning on malformed telemetry', () => {
    expect(readAgentCompletion(JSON.stringify({type:'result',subtype:'error_max_turns',is_error:true})).status).toBe('failed');
    expect(readAgentCompletion(JSON.stringify({error:{message:'provider failed'},response:''})).status).toBe('failed');
    expect(readAgentCompletion(frame('claude','Done.',{safety_stops:null}))).toMatchObject({status:'completed',warnings:[expect.stringContaining('safety_stops')]});
    expect(readAgentCompletion(frame('claude','Done.',{stop_reason:'max_tokens',safety_stops:2}))).toMatchObject({status:'failed',safety_stops:2});
    expect(readAgentCompletion(frame('claude','Done.',{stop_reason:'refusal',safety_stops:2}))).toMatchObject({status:'refused',safety_stops:2});
    expect(readAgentCompletion(frame('claude','Done.',{safety_stop:true,safety_stops:2}))).toMatchObject({status:'safety_stopped',safety_stops:2});
    expect(readAgentCompletion('x'.repeat(MAX_COMPLETION_BYTES+1)).status).toBe('failed');
    expect(readAgentCompletion('{invalid JSON').status).toBe('unknown');
    expect(readAgentCompletion(frame('claude', "I'm sorry, but I can't assist with that request.")).status).toBe('refused');
    expect(readAgentCompletion(frame('gemini', "I’m unable to provide that template.")).status).toBe('refused');
    expect(() => readAgentCompletion(JSON.stringify({message:{role:'assistant',content:{}},type:'turn.completed'}))).not.toThrow();
  });
});
