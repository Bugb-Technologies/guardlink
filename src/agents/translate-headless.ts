/**
 * Non-interactive template authoring. Generated code is never loaded or executed.
 * @exposes #agent-launcher to #child-proc-injection [high] -- "runTranslateAgent spawns a PATH-resolved agent CLI"
 * @mitigates #agent-launcher against #child-proc-injection using #param-commands -- "runTranslateAgent fixes binary names, passes options as argv and prompts through stdin, with shell disabled"
 * @exposes #agent-launcher to #arbitrary-write [high] -- "runTranslateAgent hands prompt and cwd to an author CLI whose Write/Edit tools can modify files beyond the requested out directory"
 * @audit #agent-launcher -- "Headless authoring requires the operator's explicit --headless and --agent; output instructions do not sandbox the agent"
 * @flows #agent-launcher -> AgentProcess via runTranslateAgent -- "Prompt, project cwd and chosen output directory"
 */
import { readAgentCompletion, MAX_COMPLETION_BYTES, type AgentCompletion } from './translate-completion.js';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { validateProbeIdentities } from './translate-probe.js';
import { validateScannerYaml } from './translate-yaml.js';
import { buildTranslatePrompt, translateContract } from './prompts.js';
import { defaultTranslateExposures, exposureId, type TranslateContextPack, type TranslateContract } from './translate-context.js';
import { convertedThreatRefError, translateDraftOutput, type TranslateSources } from './translate-source.js';
import { readConversionPlan, type ConversionProofPlan } from './translate-conversion.js';
import type { ThreatModel } from '../types/index.js';

export type TranslateAgent = 'claude' | 'codex' | 'gemini';
export interface TranslateAgentResult { exitCode: number | null; error?: string; completion?: AgentCompletion; safety_stops?: number }
export type TranslateRunner = (agent: TranslateAgent, prompt: string, root: string, out: string) => Promise<TranslateAgentResult>;

/**
 * @effects execute on #agent-launcher -- "Runs an author CLI without a TTY, with closed stdin and captured output"
 * @audit #agent-launcher -- "Author runs with its CLI editing permissions; GuardLink never runs a generated template"
 */
export const runTranslateAgent: TranslateRunner = async (agent, prompt, root, out) => {
  const commands = {
    claude: ['claude', ['-p', '--dangerously-skip-permissions', '--allowedTools', 'Read,Write,Edit,Glob,Grep', '--output-format', 'json']],
    codex: ['codex', ['exec', '--json', '--full-auto', '--skip-git-repo-check', '--add-dir', out, '--color', 'never', '-']],
    gemini: ['gemini', ['--prompt', 'Author templates according to the instructions on stdin.', '--approval-mode', 'auto_edit', '--output-format', 'json']],
  } as const;
  const [command, args] = commands[agent];
  return new Promise(resolveResult => {
    const child = spawn(command, [...args], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'], shell: false, env: { ...process.env, NO_COLOR: '1' } });
    // Pipe the prompt so multi-megabyte context packs do not exceed argv limits.
    child.stdin.on('error', () => {}); // An early process exit can close the pipe before the write.
    child.stdin.end(prompt);
    let stderr = '';
    let stdout = '';
    let bytes = 0;
    let overflow = false;
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (data: string) => {
      bytes += Buffer.byteLength(data);
      if (bytes > MAX_COMPLETION_BYTES) { overflow = true; child.kill(); return; }
      stdout += data;
    });
    child.stderr.on('data', (data: Buffer) => { stderr = (stderr + data.toString()).slice(-4000); });
    child.on('error', error => resolveResult({ exitCode: null, error: error.message }));
    child.on('close', (code, signal) => {
      const completion: AgentCompletion = overflow ? { status: 'failed', reason: 'Agent structured output exceeds 8 MiB' } : readAgentCompletion(stdout);
      const errors = [code !== 0 ? `Agent ${agent} ${signal ? `terminated by ${signal}` : `exited with code ${code}`}${stderr ? ': ' + stderr : ''}` : '',
        completion.status !== 'completed' ? completion.reason || 'Agent completion failed' : ''].filter(Boolean);
      resolveResult({ exitCode: code, completion, ...(errors.length ? { error: errors.join('; ') } : {}) });
    });
  });
};

/** Walk only regular files, never symlinks; exclude author indexes from template results. */
export function snapshotTemplates(dir: string): Map<string, string> {
  const found = new Map<string, string>();
  if (!existsSync(dir)) return found;
  for (const item of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, item.name);
    if (item.isDirectory()) {
      for (const [file, hash] of snapshotTemplates(path)) found.set(file, hash);
    } else if (item.isFile() && /\.(yaml|yml|py|js|mjs|ts|go|rs|rb|sh)$/i.test(item.name)) {
      found.set(path, `${statSync(path).mtimeMs}:${createHash('sha256').update(readFileSync(path)).digest('hex')}`);
    }
  }
  return found;
}

/**
 * @effects write on #agent-launcher -- "stampScannerThreatHeader adds source identity only to templates changed during this author run; existing matching headers remain byte-identical"
 * @audit #agent-launcher -- "The operator chooses the output directory; a header records authoring scope, not proof of the template's logic"
 */
function stampScannerThreatHeader(file: string, id: string): string[] {
  const source = readFileSync(file, 'utf8');
  const headers = [...source.matchAll(/^\s*(?:#|\/\/)\s*@guardlink_threat:\s*(.*)$/gm)];
  if (headers.length) return headers.length === 1 && headers[0][1].trim().replace(/^#/, '') === id
    ? [] : ['Scanner source header does not match the selected exposure; refusing to relabel it'];
  const comment = /\.(yaml|yml|py|rb|sh)$/i.test(file) ? '#' : '//';
  const lines = source.split('\n');
  // Preserve executable shebangs and Python encoding declarations at the start.
  let position = lines[0]?.startsWith('#!') ? 1 : 0;
  if (/\.py$/i.test(file) && /^#.*coding[:=]/.test(lines[position] || '')) position++;
  lines.splice(position, 0, `${comment} @guardlink_threat: ${id}`);
  writeFileSync(file, lines.join('\n'));
  return [];
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
  results: Array<TranslateIdentity & { contract: TranslateContract; template_dir: string; templates: string[]; completion?: AgentCompletion; status: 'written' | 'no_templates' | 'failed'; threat_ref?: string | null; proof_plan?: ConversionProofPlan }>;
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
      report.results.push({ source: failure.source, contract: 'probe', template_dir: resolve(options.root, options.out), templates: [], status: 'failed' });
      report.failures.push({ ...failure, exit_code: null });
    }
  }
  const exposures = options.selected ? options.model.exposures : defaultTranslateExposures(options.model);
  const candidates = options.sources
    ? options.sources.sources.map(source => ({ id: source.path, label: basename(source.path), source, model: options.model }))
    : exposures.map(exposure => ({ id: exposureId(exposure), label: exposure.threat, source: undefined, model: { ...options.model, exposures: [exposure] } }));
  if (!candidates.length && !report.failures.length) throw new Error('No in-scope translate candidates');
  let safetyStop: string | undefined;
  for (const { id, label, source, model } of candidates) {
    const identity: TranslateIdentity = source ? { source: id } : { threat: id };
    const contract = translateContract(model, { contract: options.contract, context: options.context });
    const suffix = createHash('sha256').update(id).digest('hex').slice(0, 12);
    const dir = resolve(options.root, options.out, `${label.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80)}-${suffix}`);
    let written: string[] = [];
    if (safetyStop) {
      report.failures.push({ ...identity, error: `Not authored after earlier safety stop/refusal: ${safetyStop}`, exit_code: null });
      report.results.push({ ...identity, contract, template_dir: dir, templates: [], status: 'failed' });
      continue;
    }
    try {
      if (source) translateDraftOutput(options.root, dir);
      mkdirSync(dir, { recursive: true });
      const before = snapshotTemplates(dir);
      const prompt = buildTranslatePrompt(options.userPrompt, options.root, model, { context: options.context, contract, out: dir,
        sources: source ? [source] : undefined,
        threats: source ? (options.selected ? model.exposures.map(exposureId) : undefined) : [id] })
        + '\nHeadless authoring: write files directly. Do not ask questions or perform CLI usage discovery. Return when authoring is complete.';
      const result = await run(options.agent, prompt, options.root, dir);
      written = [...snapshotTemplates(dir)].filter(([file, hash]) => before.get(file) !== hash && (!source || /\.(js|mjs)$/i.test(file))).map(([file]) => file).sort();
      const reportedStops = Math.max(result.safety_stops ?? 0, result.completion?.safety_stops ?? 0);
      const completion: AgentCompletion | undefined = reportedStops > 0
        ? { status: 'safety_stopped', safety_stops: reportedStops, reason: `Provider reported ${reportedStops} safety stops` } : result.completion;
      if (completion?.status === 'safety_stopped' || completion?.status === 'refused') {
        safetyStop = completion.reason || 'Provider reported a safety stop/refusal';
        report.failures.push({ ...identity, error: safetyStop, exit_code: result.exitCode });
        report.results.push({ ...identity, contract, template_dir: dir, templates: written, completion, status: 'failed' });
        continue;
      }
      const sourceErrors = contract === 'scanner' ? written.flatMap(file => stampScannerThreatHeader(file, id).map(error => `${file}: ${error}`)) : [];
      const invalid = [...sourceErrors, ...(contract === 'scanner' ? written.filter(file => /\.ya?ml$/i.test(file))
        .flatMap(file => validateScannerYaml(file).map(error => `${file}: ${error}`))
        : written.filter(file => /\.(js|mjs)$/i.test(file)).flatMap(file => validateProbeIdentities(file, model, options.context).map(error => `${file}: ${error}`)))];
      if (invalid.length) {
        report.failures.push({ ...identity, error: `Invalid ${contract === 'scanner' ? sourceErrors.length ? 'scanner source metadata' : 'scanner YAML' : 'probe identity metadata'}: ${invalid.join('; ')}`, exit_code: result.exitCode });
      }
      const identityErrors = source ? written.flatMap(file => {
        const error = convertedThreatRefError(source, readFileSync(file, 'utf8'));
        return error ? [`${file}: ${error}`] : [];
      }) : [];
      const proof_plan = source ? readConversionPlan(dir, source, written) : undefined;
      const attribution = source ? { threat_ref: source.threat_ref ?? null, proof_plan } : {};
      const proofError = proof_plan && proof_plan.status !== 'declared'
        ? (proof_plan.status === 'missing' && !written.length
          ? `Author exited without writing a JavaScript probe; ${proof_plan.reason}` : proof_plan.reason) : undefined;
      const error = [result.error, ...identityErrors, proofError].filter(Boolean).join('; ');
      if (error || result.exitCode !== 0 || (completion && completion.status !== 'completed') || (source && !written.length)) {
        report.failures.push({ ...identity, error: error || completion?.reason || (result.exitCode !== 0 ? 'Agent did not exit successfully' : 'Author exited without writing a JavaScript probe; consult README.md for conversion limitations'), exit_code: result.exitCode });
        report.results.push({ ...identity, ...attribution, contract, template_dir: dir, templates: written, completion, status: 'failed' });
      } else {
        report.results.push({ ...identity, ...attribution, contract, template_dir: dir, templates: written, completion, status: invalid.length ? 'failed' : written.length ? 'written' : 'no_templates' });
      }
    } catch (error) {
      report.failures.push({ ...identity, error: (error as Error).message, exit_code: null });
      report.results.push({ ...identity, contract, template_dir: dir, templates: written, status: 'failed' });
    }
  }
  return report;
}
