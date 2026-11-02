/**
 * Non-interactive template authoring. Generated code is never loaded or executed.
 * @exposes #agent-launcher to #child-proc-injection [high] -- "runTranslateAgent spawns a PATH-resolved agent CLI"
 * @mitigates #agent-launcher against #child-proc-injection using #param-commands -- "runTranslateAgent fixes binary names, passes options as argv and prompts through stdin, with shell disabled"
 * @exposes #agent-launcher to #arbitrary-write [high] -- "runTranslateAgent hands prompt and cwd to an author CLI whose Write/Edit tools can modify files beyond the requested out directory"
 * @audit #agent-launcher -- "Headless authoring requires the operator's explicit --headless and --agent; output instructions do not sandbox the agent"
 * @flows #agent-launcher -> AgentProcess via runTranslateAgent -- "Prompt, project cwd and chosen output directory"
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { buildTranslatePrompt, translateContract } from './prompts.js';
import { defaultTranslateExposures, exposureId, type TranslateContextPack, type TranslateContract } from './translate-context.js';
import { translateDraftOutput, type TranslateSources } from './translate-source.js';
import type { ThreatModel } from '../types/index.js';

export type TranslateAgent = 'claude' | 'codex' | 'gemini';
export interface TranslateAgentResult { exitCode: number | null; error?: string }
export type TranslateRunner = (agent: TranslateAgent, prompt: string, root: string, out: string) => Promise<TranslateAgentResult>;

/**
 * @effects execute on #agent-launcher -- "Runs an author CLI without a TTY, with closed stdin and captured output"
 * @audit #agent-launcher -- "Author runs with its CLI editing permissions; GuardLink never runs a generated template"
 */
export const runTranslateAgent: TranslateRunner = async (agent, prompt, root, out) => {
  const commands = {
    claude: ['claude', ['-p', '--dangerously-skip-permissions', '--allowedTools', 'Read,Write,Edit,Glob,Grep', '--output-format', 'text']],
    codex: ['codex', ['exec', '--full-auto', '--skip-git-repo-check', '--add-dir', out, '--color', 'never', '-']],
    gemini: ['gemini', ['--prompt', 'Author templates according to the instructions on stdin.', '--approval-mode', 'auto_edit']],
  } as const;
  const [command, args] = commands[agent];
  return new Promise(resolveResult => {
    const child = spawn(command, [...args], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'], shell: false, env: { ...process.env, NO_COLOR: '1' } });
    // Pipe the prompt so multi-megabyte context packs do not exceed argv limits.
    child.stdin.on('error', () => {}); // An early process exit can close the pipe before the write.
    child.stdin.end(prompt);
    let stderr = '';
    // Drain output without accumulating an unbounded agent transcript.
    child.stdout.on('data', () => {});
    child.stderr.on('data', (data: Buffer) => { stderr = (stderr + data.toString()).slice(-4000); });
    child.on('error', error => resolveResult({ exitCode: null, error: error.message }));
    child.on('close', (code, signal) => resolveResult({ exitCode: code, ...(code !== 0 ? { error: `Agent ${agent} ${signal ? `terminated by ${signal}` : `exited with code ${code}`}${stderr ? ': ' + stderr : ''}` } : {}) }));
  });
};

/** Walk only regular files, never symlinks; exclude author indexes from template results. */
function templates(dir: string): Map<string, string> {
  const found = new Map<string, string>();
  for (const item of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, item.name);
    if (item.isDirectory()) {
      for (const [file, hash] of templates(path)) found.set(file, hash);
    } else if (item.isFile() && /\.(yaml|yml|py|js|mjs|ts|go|rs|rb|sh)$/i.test(item.name)) {
      found.set(path, `${statSync(path).mtimeMs}:${createHash('sha256').update(readFileSync(path)).digest('hex')}`);
    }
  }
  return found;
}

export interface TranslateHeadlessOptions {
  root: string; model: ThreatModel; agent: TranslateAgent; out: string;
  userPrompt: string; context?: TranslateContextPack; contract?: TranslateContract;
  sources?: TranslateSources;
  /** An explicit threat selection includes mitigated exposures too. */
  selected?: boolean;
}
export interface TranslateHeadlessReport {
  version: 1;
  results: Array<TranslateIdentity & { contract: TranslateContract; templates: string[]; status: 'written' | 'no_templates' | 'failed' }>;
  failures: Array<TranslateIdentity & { error: string; exit_code: number | null }>;
}
type TranslateIdentity = { threat: string; source?: never } | { source: string; threat?: never };

/**
 * @exposes #agent-launcher to #path-traversal [medium] -- "translateHeadless creates directories below the caller-selected output root"
 * @mitigates #agent-launcher against #path-traversal using #input-sanitize -- "translateHeadless child names use a sanitized exposure or source label plus a hash; context ids are never path components"
 * @flows AgentProcess -> #agent-launcher via templates -- "Inventory changed regular template files per exposure or conversion source, without evaluating them"
 */
export async function translateHeadless(options: TranslateHeadlessOptions, run: TranslateRunner = runTranslateAgent): Promise<TranslateHeadlessReport> {
  const report: TranslateHeadlessReport = { version: 1, results: [], failures: [] };
  if (options.sources) {
    if (options.contract !== 'probe') throw new Error('--from requires --contract probe');
    translateDraftOutput(options.root, options.out);
    for (const failure of options.sources.failures) {
      report.results.push({ source: failure.source, contract: 'probe', templates: [], status: 'failed' });
      report.failures.push({ ...failure, exit_code: null });
    }
  }
  const exposures = options.selected ? options.model.exposures : defaultTranslateExposures(options.model);
  const candidates = options.sources
    ? options.sources.sources.map(source => ({ id: source.path, label: basename(source.path), source, model: options.model }))
    : exposures.map(exposure => ({ id: exposureId(exposure), label: exposure.threat, source: undefined, model: { ...options.model, exposures: [exposure] } }));
  if (!candidates.length && !report.failures.length) throw new Error('No in-scope translate candidates');
  for (const { id, label, source, model } of candidates) {
    const identity: TranslateIdentity = source ? { source: id } : { threat: id };
    const contract = translateContract(model, { contract: options.contract, context: options.context });
    const suffix = createHash('sha256').update(id).digest('hex').slice(0, 12);
    const dir = resolve(options.root, options.out, `${label.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80)}-${suffix}`);
    let written: string[] = [];
    try {
      if (source) translateDraftOutput(options.root, dir);
      mkdirSync(dir, { recursive: true });
      const before = templates(dir);
      const prompt = buildTranslatePrompt(options.userPrompt, options.root, model, { context: options.context, contract, out: dir,
        sources: source ? [source] : undefined,
        threats: source ? (options.selected ? model.exposures.map(exposureId) : undefined) : [id] })
        + '\nHeadless authoring: write files directly. Do not ask questions or perform CLI usage discovery. Return when authoring is complete.';
      const result = await run(options.agent, prompt, options.root, dir);
      written = [...templates(dir)].filter(([file, hash]) => before.get(file) !== hash && (!source || /\.(js|mjs)$/i.test(file))).map(([file]) => file).sort();
      if (result.error || result.exitCode !== 0 || (source && !written.length)) {
        report.failures.push({ ...identity, error: result.error || (result.exitCode !== 0 ? 'Agent did not exit successfully' : 'Author exited without writing a JavaScript probe; consult README.md for conversion limitations'), exit_code: result.exitCode });
        report.results.push({ ...identity, contract, templates: written, status: 'failed' });
      } else {
        report.results.push({ ...identity, contract, templates: written, status: written.length ? 'written' : 'no_templates' });
      }
    } catch (error) {
      report.failures.push({ ...identity, error: (error as Error).message, exit_code: null });
      report.results.push({ ...identity, contract, templates: written, status: 'failed' });
    }
  }
  return report;
}
