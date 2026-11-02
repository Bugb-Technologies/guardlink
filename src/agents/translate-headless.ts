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
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { validateProbeIdentities } from './translate-probe.js';
import { validateScannerYaml } from './translate-yaml.js';
import { buildTranslatePrompt, translateContract } from './prompts.js';
import { defaultTranslateExposures, exposureId, type TranslateContextPack, type TranslateContract } from './translate-context.js';
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
  /** An explicit threat selection includes mitigated exposures too. */
  selected?: boolean;
}
export interface TranslateHeadlessReport {
  version: 1;
  results: Array<{ threat: string; contract: TranslateContract; template_dir: string; templates: string[]; status: 'written' | 'no_templates' | 'failed' }>;
  failures: Array<{ threat: string; error: string; exit_code: number | null }>;
}

/**
 * @exposes #agent-launcher to #path-traversal [medium] -- "translateHeadless creates directories below the caller-selected output root"
 * @mitigates #agent-launcher against #path-traversal using #input-sanitize -- "Per-exposure child names use a sanitized label plus a hash; context ids are never path components"
 * @flows AgentProcess -> #agent-launcher via templates -- "Inventory changed regular template files per exposure, without evaluating them"
 */
export async function translateHeadless(options: TranslateHeadlessOptions, run: TranslateRunner = runTranslateAgent): Promise<TranslateHeadlessReport> {
  const report: TranslateHeadlessReport = { version: 1, results: [], failures: [] };
  const exposures = options.selected ? options.model.exposures : defaultTranslateExposures(options.model);
  if (!exposures.length) throw new Error('No in-scope translate exposure candidates');
  for (const exposure of exposures) {
    const id = exposureId(exposure);
    const model = { ...options.model, exposures: [exposure] };
    const contract = translateContract(model, options);
    const suffix = createHash('sha256').update(id).digest('hex').slice(0, 12);
    const dir = resolve(options.root, options.out, `${exposure.threat.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80)}-${suffix}`);
    let written: string[] = [];
    try {
      mkdirSync(dir, { recursive: true });
      const before = snapshotTemplates(dir);
      const prompt = buildTranslatePrompt(options.userPrompt, options.root, model, { context: options.context, contract, out: dir, threats: [id] })
        + '\nHeadless authoring: write files directly. Do not ask questions or perform CLI usage discovery. Return when authoring is complete.';
      const result = await run(options.agent, prompt, options.root, dir);
      written = [...snapshotTemplates(dir)].filter(([file, hash]) => before.get(file) !== hash).map(([file]) => file).sort();
      const sourceErrors = contract === 'scanner' ? written.flatMap(file => stampScannerThreatHeader(file, id).map(error => `${file}: ${error}`)) : [];
      const invalid = [...sourceErrors, ...(contract === 'scanner' ? written.filter(file => /\.ya?ml$/i.test(file))
        .flatMap(file => validateScannerYaml(file).map(error => `${file}: ${error}`))
        : written.filter(file => /\.(js|mjs)$/i.test(file)).flatMap(file => validateProbeIdentities(file, model, options.context).map(error => `${file}: ${error}`)))];
      if (invalid.length) {
        report.failures.push({ threat: id, error: `Invalid ${contract === 'scanner' ? sourceErrors.length ? 'scanner source metadata' : 'scanner YAML' : 'probe identity metadata'}: ${invalid.join('; ')}`, exit_code: result.exitCode });
      }
      if (result.error || result.exitCode !== 0) {
        report.failures.push({ threat: id, error: result.error || 'Agent did not exit successfully', exit_code: result.exitCode });
        report.results.push({ threat: id, contract, template_dir: dir, templates: written, status: 'failed' });
      } else {
        report.results.push({ threat: id, contract, template_dir: dir, templates: written, status: invalid.length ? 'failed' : written.length ? 'written' : 'no_templates' });
      }
    } catch (error) {
      report.failures.push({ threat: id, error: (error as Error).message, exit_code: null });
      report.results.push({ threat: id, contract, template_dir: dir, templates: written, status: 'failed' });
    }
  }
  return report;
}
