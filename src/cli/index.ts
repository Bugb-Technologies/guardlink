#!/usr/bin/env node

/**
 * GuardLink CLI — Reference Implementation
 *
 * Usage:
 *   guardlink init [dir]        Initialize GuardLink in a project
 *   guardlink parse [dir]       Parse annotations, output ThreatModel JSON
 *   guardlink status [dir]      Show annotation coverage summary
 *   guardlink validate [dir]    Check for syntax errors and dangling refs
 *   guardlink analyze [framework] AI-powered threat analysis (STRIDE, DREAD, etc.)
 *   guardlink annotate <prompt>  Launch coding agent for annotation
 *   guardlink config <action>    Manage LLM provider configuration
 *
 * @exposes #cli to #path-traversal [high] cwe:CWE-22 -- "Accepts directory paths from command line arguments"
 * @exposes #cli to #arbitrary-write [high] cwe:CWE-73 -- "Writes reports and SARIF to user-specified output paths"
 * @accepts #arbitrary-write on #cli -- "Intentional feature: users specify output paths for reports"
 * @mitigates #cli against #path-traversal using #path-validation -- "resolve() normalizes paths before passing to submodules"
 * @boundary between #cli and #parser (#cli-parser-boundary) -- "CLI is the primary user input trust boundary"
 * @flows User -> #cli via argv -- "User provides directory paths and options via command line"
 * @flows #cli -> #parser via parseProject -- "CLI dispatches parsed commands to parser"
 * @flows #cli -> #report via generateReport -- "CLI writes report output"
 * @flows #cli -> #init via initProject -- "CLI initializes project structure"
 */

import { Command } from 'commander';
import { resolve, basename } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { parseProject, findDanglingRefs, findUnmitigatedExposures } from '../parser/index.js';
import { initProject, detectProject, promptAgentSelection } from '../init/index.js';
import { generateReport, generateMermaid } from '../report/index.js';
import { diffModels, formatDiff, formatDiffMarkdown, parseAtRef, getCurrentRef } from '../diff/index.js';
import { generateSarif } from '../analyzer/index.js';
import { startStdioServer } from '../mcp/index.js';
import { generateThreatReport, listThreatReports, loadThreatReportsForDashboard, buildConfig, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, serializeModel, buildUserMessage, type AnalysisFramework } from '../analyze/index.js';
import { generateDashboardHTML } from '../dashboard/index.js';
import { AGENTS, agentFromOpts, launchAgent, buildAnnotatePrompt } from '../agents/index.js';
import { resolveConfig, saveProjectConfig, saveGlobalConfig, loadProjectConfig, loadGlobalConfig, maskKey, describeConfigSource } from '../agents/config.js';
import type { ThreatModel, ParseDiagnostic } from '../types/index.js';
import gradient from 'gradient-string';

const program = new Command();

const ASCII_LOGO = `
 ██████  ██    ██  █████  ██████  ██████  ██      ██ ███    ██ ██   ██ 
██       ██    ██ ██   ██ ██   ██ ██   ██ ██      ██ ████   ██ ██  ██  
██   ███ ██    ██ ███████ ██████  ██   ██ ██      ██ ██ ██  ██ █████   
██    ██ ██    ██ ██   ██ ██   ██ ██   ██ ██      ██ ██  ██ ██ ██  ██  
 ██████   ██████  ██   ██ ██   ██ ██████  ███████ ██ ██   ████ ██   ██ 
`;

/** Generic placeholder names produced by scaffolding tools (v0, CRA, Vite, etc.) */
const GENERIC_PKG_NAMES = new Set([
  'my-v0-project', 'my-app', 'my-project', 'my-next-app', 'vite-project',
  'react-app', 'create-react-app', 'starter', 'app', 'project', 'unknown',
]);

/** Auto-detect project name from git remote, package.json, Cargo.toml, or directory name */
function detectProjectName(root: string, explicit?: string): string {
  if (explicit && explicit !== 'unknown') return explicit;
  try {
    const gitConfigPath = resolve(root, '.git', 'config');
    if (existsSync(gitConfigPath)) {
      const gitConfig = readFileSync(gitConfigPath, 'utf-8');
      const m = gitConfig.match(/url\s*=\s*.*[/:]([^/\s]+?)(?:\.git)?\s*$/m);
      if (m) return m[1];
    }
  } catch {}
  try {
    const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf-8'));
    if (pkg.name && !GENERIC_PKG_NAMES.has(pkg.name)) return pkg.name;
  } catch {}
  try {
    const cargo = readFileSync(resolve(root, 'Cargo.toml'), 'utf-8');
    const m = cargo.match(/^name\s*=\s*"([^"]+)"/m);
    if (m) return m[1];
  } catch {}
  return basename(root) || 'unknown';
}

program
  .name('guardlink')
  .description('GuardLink — Security annotations for code. Threat modeling that lives in your codebase.')
  .version('1.0.0')
  .addHelpText('before', gradient(['#00ff41', '#00d4ff'])(ASCII_LOGO));

// ─── init ────────────────────────────────────────────────────────────

program
  .command('init')
  .description('Initialize GuardLink in a project — creates .guardlink/ and updates agent instruction files')
  .argument('[dir]', 'Project directory', '.')
  .option('-p, --project <n>', 'Override project name')
  .option('-a, --agent <agents>', 'Agent(s) to create files for: claude,cursor,codex,copilot,windsurf,cline,none (comma-separated)')
  .option('--skip-agent-files', 'Only create .guardlink/, skip agent file updates')
  .option('--force', 'Overwrite existing GuardLink config and instructions')
  .option('--dry-run', 'Show what would be created without writing files')
  .action(async (dir: string, opts: { project?: string; agent?: string; skipAgentFiles?: boolean; force?: boolean; dryRun?: boolean }) => {
    const root = resolve(dir);

    // Show detection results first
    const info = detectProject(root);
    console.log(`Detected: ${info.language} project "${info.name}"`);

    const existingAgentFiles = info.agentFiles.filter(f => f.exists);
    if (existingAgentFiles.length > 0) {
      console.log(`Found:    ${existingAgentFiles.map(f => f.path).join(', ')}`);
    }

    if (info.alreadyInitialized && !opts.force) {
      console.log(`\n.guardlink/ already exists. Use --force to reinitialize.`);
    }

    // Determine agent IDs — always show picker in interactive mode
    let agentIds: string[] | undefined;
    if (!opts.skipAgentFiles) {
      if (opts.agent) {
        // From --agent flag
        agentIds = opts.agent.split(',').map(s => s.trim().toLowerCase());
      } else if (process.stdin.isTTY) {
        // Interactive picker — shows detected + optional agents
        agentIds = await promptAgentSelection(info.agentFiles);
      } else {
        // Non-interactive (CI), default to claude
        agentIds = ['claude'];
      }
    }

    console.log('');

    // Run init
    const result = initProject({
      root,
      project: opts.project,
      skipAgentFiles: opts.skipAgentFiles,
      force: opts.force,
      dryRun: opts.dryRun,
      agentIds,
    });

    const prefix = opts.dryRun ? '(dry run) ' : '';

    for (const f of result.created) {
      console.log(`${prefix}Created:  ${f}`);
    }
    for (const f of result.updated) {
      console.log(`${prefix}Updated:  ${f}`);
    }
    for (const f of result.skipped) {
      console.log(`${prefix}Skipped:  ${f}`);
    }

    if (!opts.dryRun && (result.created.length > 0 || result.updated.length > 0)) {
      console.log(`\n✓ GuardLink initialized. Next steps:`);
      console.log(`  1. Review .guardlink/definitions${info.definitionsExt} — remove threats/controls not relevant to your project`);
      console.log(`  2. Add annotations to your source files (or ask your coding agent to do it)`);
      console.log(`  3. Run: guardlink validate .`);
    }
  });

// ─── parse ───────────────────────────────────────────────────────────

program
  .command('parse')
  .description('Parse all GuardLink annotations and output the threat model as JSON')
  .argument('[dir]', 'Project directory to scan', '.')
  .option('-p, --project <name>', 'Project name', 'unknown')
  .option('-o, --output <file>', 'Write JSON to file instead of stdout')
  .option('--pretty', 'Pretty-print JSON output', true)
  .action(async (dir: string, opts: { project: string; output?: string; pretty: boolean }) => {
    const root = resolve(dir);
    const { model, diagnostics } = await parseProject({ root, project: opts.project });

    // Print diagnostics to stderr
    printDiagnostics(diagnostics);

    // Output model
    const json = JSON.stringify(model, null, opts.pretty ? 2 : 0);
    if (opts.output) {
      const { writeFile } = await import('node:fs/promises');
      await writeFile(opts.output, json + '\n');
      console.error(`Wrote threat model to ${opts.output}`);
    } else {
      console.log(json);
    }

    process.exit(diagnostics.some(d => d.level === 'error') ? 1 : 0);
  });

// ─── status ──────────────────────────────────────────────────────────

program
  .command('status')
  .description('Show annotation coverage summary')
  .argument('[dir]', 'Project directory to scan', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .action(async (dir: string, opts: { project: string }) => {
    const root = resolve(dir);
    const { model, diagnostics } = await parseProject({ root, project: opts.project });

    printDiagnostics(diagnostics);
    printStatus(model);
  });

// ─── validate ────────────────────────────────────────────────────────

program
  .command('validate')
  .description('Check annotations for syntax errors and dangling references')
  .argument('[dir]', 'Project directory to scan', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .option('--strict', 'Also fail on unmitigated exposures (for CI gates)')
  .action(async (dir: string, opts: { project: string; strict?: boolean }) => {
    const root = resolve(dir);
    const { model, diagnostics } = await parseProject({ root, project: opts.project });

    // Check for dangling refs
    const danglingDiags = findDanglingRefs(model);
    const allDiags = [...diagnostics, ...danglingDiags];

    // Check for unmitigated exposures
    const unmitigated = findUnmitigatedExposures(model);

    printDiagnostics(allDiags);

    if (unmitigated.length > 0) {
      console.error(`\n⚠  ${unmitigated.length} unmitigated exposure(s):`);
      for (const u of unmitigated) {
        console.error(`   ${u.asset} → ${u.threat} [${u.severity || 'unset'}] (${u.location.file}:${u.location.line})`);
      }
    }

    const errorCount = allDiags.filter(d => d.level === 'error').length;
    const hasUnmitigated = unmitigated.length > 0;

    if (errorCount === 0 && !hasUnmitigated) {
      console.error('\n✓ All annotations valid, no unmitigated exposures.');
    } else if (errorCount === 0 && hasUnmitigated) {
      console.error(`\nValidation passed with ${unmitigated.length} unmitigated exposure(s).`);
    }

    // Exit 1 on errors always; also on unmitigated if --strict
    process.exit(errorCount > 0 || (opts.strict && hasUnmitigated) ? 1 : 0);
  });

// ─── report ──────────────────────────────────────────────────────────

program
  .command('report')
  .description('Generate a threat model report with Mermaid diagram')
  .argument('[dir]', 'Project directory to scan', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .option('-o, --output <file>', 'Write report to file (default: threat-model.md)')
  .option('--diagram-only', 'Output only the Mermaid diagram, no report wrapper')
  .option('--json', 'Also output threat-model.json alongside the report')
  .action(async (dir: string, opts: { project: string; output?: string; diagramOnly?: boolean; json?: boolean }) => {
    const root = resolve(dir);
    const { model, diagnostics } = await parseProject({ root, project: opts.project });

    // Show errors if any
    const errors = diagnostics.filter(d => d.level === 'error');
    if (errors.length > 0) {
      printDiagnostics(errors);
      console.error(`Fix errors above before generating report.\n`);
    }

    if (opts.diagramOnly) {
      // Just output Mermaid
      const mermaid = generateMermaid(model);
      if (opts.output) {
        const { writeFile } = await import('node:fs/promises');
        await writeFile(opts.output, mermaid + '\n');
        console.error(`Wrote Mermaid diagram to ${opts.output}`);
      } else {
        console.log(mermaid);
      }
    } else {
      // Full report
      const report = generateReport(model);
      const outFile = opts.output || 'threat-model.md';
      const { writeFile } = await import('node:fs/promises');
      await writeFile(resolve(root, outFile), report + '\n');
      console.error(`✓ Wrote threat model report to ${outFile}`);

      if (opts.json) {
        const jsonFile = outFile.replace(/\.md$/, '.json');
        await writeFile(resolve(root, jsonFile), JSON.stringify(model, null, 2) + '\n');
        console.error(`✓ Wrote threat model JSON to ${jsonFile}`);
      }
    }
  });

// ─── diff ────────────────────────────────────────────────────────────

program
  .command('diff')
  .description('Compare threat model against a git ref — find what changed')
  .argument('[ref]', 'Git ref to compare against (commit, branch, tag, HEAD~1)', 'HEAD~1')
  .option('-d, --dir <dir>', 'Project directory', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .option('--markdown', 'Output as markdown (for PR comments)')
  .option('--json', 'Output as JSON')
  .option('--fail-on-new', 'Exit 1 if new unmitigated exposures found (CI mode)')
  .action(async (ref: string, opts: { dir: string; project: string; markdown?: boolean; json?: boolean; failOnNew?: boolean }) => {
    const root = resolve(opts.dir);

    // Parse current state
    console.error(`Parsing current threat model...`);
    const { model: current } = await parseProject({ root, project: opts.project });

    // Parse at ref
    console.error(`Parsing threat model at ${ref}...`);
    let previous: ThreatModel;
    try {
      previous = await parseAtRef(root, ref, opts.project);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }

    // Compute diff
    const diff = diffModels(previous, current);

    // Output
    if (opts.json) {
      console.log(JSON.stringify(diff, null, 2));
    } else if (opts.markdown) {
      console.log(formatDiffMarkdown(diff));
    } else {
      console.log(formatDiff(diff));
    }

    // CI gate
    if (opts.failOnNew && diff.newUnmitigatedExposures.length > 0) {
      process.exit(1);
    }
  });

// ─── sarif ───────────────────────────────────────────────────────────

program
  .command('sarif')
  .description('Export findings as SARIF 2.1.0 for GitHub Advanced Security, VS Code, etc.')
  .argument('[dir]', 'Project directory to scan', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .option('-o, --output <file>', 'Write SARIF to file (default: stdout)')
  .option('--min-severity <sev>', 'Only include exposures at or above this severity (critical|high|medium|low)')
  .option('--no-diagnostics', 'Exclude parse errors from SARIF output')
  .action(async (dir: string, opts: { project: string; output?: string; minSeverity?: string; diagnostics?: boolean }) => {
    const root = resolve(dir);
    const { model, diagnostics } = await parseProject({ root, project: opts.project });

    // Compute dangling refs (reuse validate logic)
    const danglingDiags = findDanglingRefs(model);

    const sarif = generateSarif(
      model,
      diagnostics,
      danglingDiags,
      {
        includeDiagnostics: opts.diagnostics !== false,
        includeDanglingRefs: true,
        minSeverity: opts.minSeverity as any,
      },
    );

    const json = JSON.stringify(sarif, null, 2);

    if (opts.output) {
      const { writeFile } = await import('node:fs/promises');
      await writeFile(resolve(root, opts.output), json + '\n');
      console.error(`✓ Wrote SARIF to ${opts.output}`);
    } else {
      console.log(json);
    }

    // Summary to stderr
    const resultCount = sarif.runs[0]?.results.length ?? 0;
    const errors = sarif.runs[0]?.results.filter(r => r.level === 'error').length ?? 0;
    const warnings = sarif.runs[0]?.results.filter(r => r.level === 'warning').length ?? 0;
    console.error(`SARIF: ${resultCount} result(s) — ${errors} error(s), ${warnings} warning(s)`);
  });

// ─── threat-report ───────────────────────────────────────────────────

program
  .command('threat-report')
  .description('Generate an AI threat report using a security framework (STRIDE, DREAD, PASTA, etc.)')
  .argument('[framework]', 'Framework: stride, dread, pasta, attacker, rapid, general', 'general')
  .argument('[dir]', 'Project directory', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .option('--provider <provider>', 'LLM provider: anthropic, openai, openrouter, deepseek (auto-detected from env)')
  .option('--model <model>', 'Model name (default: provider-specific)')
  .option('--api-key <key>', 'API key (default: from env variable)')
  .option('--no-stream', 'Disable streaming output')
  .option('--custom <prompt>', 'Custom analysis prompt (replaces framework prompt header)')
  .option('--claude-code', 'Launch Claude Code in foreground')
  .option('--codex', 'Launch Codex CLI in foreground')
  .option('--gemini', 'Launch Gemini CLI in foreground')
  .option('--cursor', 'Open Cursor IDE with prompt on clipboard')
  .option('--windsurf', 'Open Windsurf IDE with prompt on clipboard')
  .option('--clipboard', 'Copy threat report prompt to clipboard only')
  .action(async (framework: string, dir: string, opts: {
    project: string; provider?: string; model?: string; apiKey?: string;
    stream?: boolean; custom?: string;
    claudeCode?: boolean; codex?: boolean; gemini?: boolean;
    cursor?: boolean; windsurf?: boolean; clipboard?: boolean;
  }) => {
    const root = resolve(dir);
    const project = detectProjectName(root, opts.project);

    // Validate framework
    const validFrameworks = ['stride', 'dread', 'pasta', 'attacker', 'rapid', 'general'];
    if (!validFrameworks.includes(framework)) {
      console.error(`Unknown framework: ${framework}`);
      console.error(`Available: ${validFrameworks.join(', ')}`);
      process.exit(1);
    }

    const fw = framework as AnalysisFramework;

    // Parse project
    const { model, diagnostics } = await parseProject({ root, project });
    const errors = diagnostics.filter(d => d.level === 'error');
    if (errors.length > 0) printDiagnostics(errors);

    if (model.annotations_parsed === 0) {
      console.error('No annotations found. Run: guardlink init . && add annotations first.');
      process.exit(1);
    }

    // Resolve agent (same pattern as annotate)
    const agent = agentFromOpts(opts);

    // ── Agent path: build prompt, launch agent ──
    if (agent) {
      const serialized = serializeModel(model);
      const systemPrompt = FRAMEWORK_PROMPTS[fw] || FRAMEWORK_PROMPTS.general;
      const userMessage = buildUserMessage(serialized, fw, opts.custom);
      const fullPrompt = `${systemPrompt}\n\n${userMessage}\n\nAlso read the source files to understand code context. Save the report to .guardlink/threat-reports/ as a markdown file.`;

      console.log(`Generating ${FRAMEWORK_LABELS[fw]} via ${agent.name}...`);
      if (agent.cmd) {
        console.log(`${agent.name} will take over this terminal. Exit the agent to return.\n`);
      }

      const result = launchAgent(agent, fullPrompt, root);

      if (result.clipboardCopied) {
        console.log(`✓ Prompt copied to clipboard (${fullPrompt.length.toLocaleString()} chars)`);
      }

      if (result.error) {
        console.error(`✗ ${result.error}`);
        if (result.clipboardCopied) {
          console.log('Prompt is on your clipboard — paste it manually.');
        }
        process.exit(1);
      }

      if (agent.cmd && result.launched) {
        console.log(`\n✓ ${agent.name} session ended.`);
        console.log('  Run: guardlink threat-reports  to see saved reports.');
      } else if (agent.app && result.launched) {
        console.log(`✓ ${agent.name} launched with project: ${project}`);
        console.log('\nPaste (Cmd+V) the prompt in the AI chat panel.');
        console.log('When done, run: guardlink threat-reports');
      } else if (agent.id === 'clipboard') {
        console.log('\nPaste the prompt into your preferred AI tool.');
        console.log('When done, run: guardlink threat-reports');
      }
      return;
    }

    // ── API path: direct LLM call (no agent flag) ──
    const llmConfig = buildConfig({
      provider: opts.provider,
      model: opts.model,
      apiKey: opts.apiKey,
    });

    if (!llmConfig) {
      // No agent, no API key — show usage like annotate does
      console.error('No agent or API key specified. Use one of:');
      for (const a of AGENTS) {
        console.error(`  ${a.flag.padEnd(16)} ${a.name}`);
      }
      console.error('');
      console.error('Or set an API key: ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.');
      console.error('Or use: --provider anthropic --api-key sk-...');
      process.exit(1);
    }

    console.error(`\n🔍 ${FRAMEWORK_LABELS[fw]}`);
    console.error(`   Provider: ${llmConfig.provider} | Model: ${llmConfig.model}`);
    console.error(`   Annotations: ${model.annotations_parsed} | Exposures: ${model.exposures.length}\n`);

    try {
      const result = await generateThreatReport({
        root,
        model,
        framework: fw,
        llmConfig,
        customPrompt: opts.custom,
        stream: opts.stream !== false,
        onChunk: opts.stream !== false ? (text) => process.stdout.write(text) : undefined,
      });

      if (opts.stream !== false) {
        process.stdout.write('\n');
      } else {
        console.log(result.content);
      }

      console.error(`\n✓ Report saved to ${result.savedTo}`);
      if (result.inputTokens || result.outputTokens) {
        console.error(`  Tokens: ${result.inputTokens || '?'} in / ${result.outputTokens || '?'} out`);
      }
    } catch (err: any) {
      console.error(`\n✗ Threat report generation failed: ${err.message}`);
      process.exit(1);
    }
  });

// ─── threat-reports (list) ───────────────────────────────────────────

program
  .command('threat-reports')
  .description('List saved AI threat reports')
  .option('-d, --dir <dir>', 'Project directory', '.')
  .action(async (opts: { dir: string }) => {
    const root = resolve(opts.dir);
    const reports = listThreatReports(root);
    if (reports.length === 0) {
      console.log('No saved threat reports found.');
      console.log('Run: guardlink threat-report <framework>  (e.g., guardlink threat-report stride --claude-code)');
      return;
    }
    console.log('Saved threat reports:\n');
    for (const r of reports) {
      const dirLabel = r.dirName || 'threat-reports';
      console.log(`  ${r.timestamp}  ${r.label.padEnd(28)} ${r.model || ''}`);
      console.log(`  ${' '.repeat(21)}→ .guardlink/${dirLabel}/${r.filename}`);
    }
    console.log(`\n${reports.length} report(s)`);
  });

// ─── annotate ────────────────────────────────────────────────────────

program
  .command('annotate')
  .description('Launch a coding agent to add GuardLink security annotations')
  .argument('<prompt>', 'Annotation instructions (e.g., "annotate auth endpoints for OWASP Top 10")')
  .argument('[dir]', 'Project directory', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .option('--claude-code', 'Launch Claude Code in foreground')
  .option('--codex', 'Launch Codex CLI in foreground')
  .option('--gemini', 'Launch Gemini CLI in foreground')
  .option('--cursor', 'Open Cursor IDE with prompt on clipboard')
  .option('--windsurf', 'Open Windsurf IDE with prompt on clipboard')
  .option('--clipboard', 'Copy annotation prompt to clipboard only')
  .action(async (prompt: string, dir: string, opts: {
    project: string;
    claudeCode?: boolean; codex?: boolean; gemini?: boolean;
    cursor?: boolean; windsurf?: boolean; clipboard?: boolean;
  }) => {
    const root = resolve(dir);
    const project = detectProjectName(root, opts.project);

    // Resolve agent
    const agent = agentFromOpts(opts);
    if (!agent) {
      console.error('No agent specified. Use one of:');
      for (const a of AGENTS) {
        console.error(`  ${a.flag.padEnd(16)} ${a.name}`);
      }
      process.exit(1);
    }

    // Parse model (optional — annotations may not exist yet)
    let model: ThreatModel | null = null;
    try {
      const result = await parseProject({ root, project });
      if (result.model.annotations_parsed > 0) {
        model = result.model;
      }
    } catch { /* no model yet — that's fine */ }

    // Build prompt
    const fullPrompt = buildAnnotatePrompt(prompt, root, model);

    // Launch agent
    console.log(`Launching ${agent.name} for annotation...`);
    if (agent.cmd) {
      console.log(`${agent.name} will take over this terminal. Exit the agent to return.\n`);
    }

    const result = launchAgent(agent, fullPrompt, root);

    if (result.clipboardCopied) {
      console.log(`✓ Prompt copied to clipboard (${fullPrompt.length.toLocaleString()} chars)`);
    }

    if (result.error) {
      console.error(`✗ ${result.error}`);
      if (result.clipboardCopied) {
        console.log('Prompt is on your clipboard — paste it manually.');
      }
      process.exit(1);
    }

    if (agent.cmd && result.launched) {
      // Agent exited — suggest next step
      console.log(`\n✓ ${agent.name} session ended.`);
      console.log('  Run: guardlink parse  to update the threat model.');
    } else if (agent.app && result.launched) {
      console.log(`✓ ${agent.name} launched with project: ${project}`);
      console.log('\nPaste (Cmd+V) the prompt in the AI chat panel.');
      console.log('When done, run: guardlink parse');
    } else if (agent.id === 'clipboard') {
      console.log('\nPaste the prompt into your preferred AI tool.');
      console.log('When done, run: guardlink parse');
    }
  });

// ─── config ──────────────────────────────────────────────────────────

program
  .command('config')
  .description('Manage LLM provider configuration')
  .argument('<action>', 'Action: set, show, clear')
  .argument('[key]', 'Config key: provider, api-key, model')
  .argument('[value]', 'Value to set')
  .option('--global', 'Use global config (~/.config/guardlink/) instead of project')
  .action(async (action: string, key?: string, value?: string, opts?: { global?: boolean }) => {
    const root = resolve('.');
    const isGlobal = opts?.global ?? false;

    switch (action) {
      case 'show': {
        const config = resolveConfig(root);
        const source = describeConfigSource(root);
        if (config) {
          console.log(`Provider:  ${config.provider}`);
          console.log(`Model:     ${config.model}`);
          console.log(`API Key:   ${maskKey(config.apiKey)}`);
          console.log(`Source:    ${source}`);
        } else {
          console.log('No LLM configuration found.');
          console.log('\nSet one with:');
          console.log('  guardlink config set provider anthropic');
          console.log('  guardlink config set api-key sk-ant-...');
          console.log('\nOr set environment variables:');
          console.log('  export GUARDLINK_LLM_KEY=sk-ant-...');
          console.log('  export GUARDLINK_LLM_PROVIDER=anthropic');
        }
        break;
      }

      case 'set': {
        if (!key || !value) {
          console.error('Usage: guardlink config set <key> <value>');
          console.error('Keys: provider, api-key, model');
          process.exit(1);
        }

        const existing = isGlobal
          ? loadGlobalConfig() || {}
          : loadProjectConfig(root) || {};

        switch (key) {
          case 'provider':
            if (!['anthropic', 'openai', 'openrouter', 'deepseek'].includes(value)) {
              console.error(`Unknown provider: ${value}`);
              console.error('Available: anthropic, openai, openrouter, deepseek');
              process.exit(1);
            }
            (existing as any).provider = value;
            break;
          case 'api-key':
            (existing as any).apiKey = value;
            break;
          case 'model':
            (existing as any).model = value;
            break;
          default:
            console.error(`Unknown config key: ${key}. Use: provider, api-key, model`);
            process.exit(1);
        }

        if (isGlobal) {
          saveGlobalConfig(existing);
          console.log(`✓ Saved to ~/.config/guardlink/config.json`);
        } else {
          saveProjectConfig(root, existing);
          console.log(`✓ Saved to .guardlink/config.json`);
        }
        break;
      }

      case 'clear': {
        const emptyConfig = {};
        if (isGlobal) {
          saveGlobalConfig(emptyConfig);
          console.log('✓ Global config cleared.');
        } else {
          saveProjectConfig(root, emptyConfig);
          console.log('✓ Project config cleared.');
        }
        break;
      }

      default:
        console.error(`Unknown action: ${action}. Use: show, set, clear`);
        process.exit(1);
    }
  });

// ─── dashboard ───────────────────────────────────────────────────────

program
  .command('dashboard')
  .description('Generate an interactive HTML threat model dashboard with diagrams')
  .argument('[dir]', 'Project directory to scan', '.')
  .option('-p, --project <n>', 'Project name', 'unknown')
  .option('-o, --output <file>', 'Output file (default: threat-dashboard.html)')
  .option('--light', 'Default to light theme instead of dark')
  .action(async (dir: string, opts: { project: string; output?: string; light?: boolean }) => {
    const root = resolve(dir);
    const project = detectProjectName(root, opts.project);
    const { model, diagnostics } = await parseProject({ root, project });

    const errors = diagnostics.filter(d => d.level === 'error');
    if (errors.length > 0) printDiagnostics(errors);

    if (model.annotations_parsed === 0) {
      console.error('No annotations found. Add GuardLink annotations first.');
      process.exit(1);
    }

    const analyses = loadThreatReportsForDashboard(root);
    let html = generateDashboardHTML(model, root, analyses);

    // Switch default theme if requested
    if (opts.light) {
      html = html.replace('data-theme="dark"', 'data-theme="light"');
    }

    const outFile = opts.output || 'threat-dashboard.html';
    const { writeFile } = await import('node:fs/promises');
    await writeFile(resolve(root, outFile), html);
    console.error(`✓ Dashboard generated: ${outFile}`);
    console.error(`  Open in browser to view. Toggle ☀️/🌙 for light/dark mode.`);
  });

// ─── mcp ─────────────────────────────────────────────────────────────

program
  .command('mcp')
  .description('Start GuardLink MCP server (stdio transport) — for Claude Code, Cursor, etc.')
  .action(async () => {
    await startStdioServer();
  });

program
  .command('tui')
  .description('Interactive TUI — slash commands, AI chat, exposure triage')
  .argument('[dir]', 'project directory', '.')
  .option('--provider <provider>', 'LLM provider for this session (anthropic, openai, openrouter, deepseek)')
  .option('--api-key <key>', 'LLM API key for this session (not persisted)')
  .option('--model <model>', 'LLM model override')
  .action(async (dir: string, opts: { provider?: string; apiKey?: string; model?: string }) => {
    // Pass session-level LLM config to TUI via environment
    if (opts.apiKey) process.env.GUARDLINK_LLM_KEY = opts.apiKey;
    if (opts.provider) process.env.GUARDLINK_LLM_PROVIDER = opts.provider;
    const { startTui } = await import('../tui/index.js');
    await startTui(dir);
  });

program
  .command('gal')
  .description('Display GuardLink Annotation Language (GAL) quick reference')
  .action(() => {
    import('chalk').then(({ default: c }) => {
      console.log(gradient(['#00ff41', '#00d4ff'])(ASCII_LOGO));
      console.log(`${c.bold.bgCyan.black(' GUARDLINK ANNOTATION LANGUAGE (GAL) ')}\n`);
      console.log(`${c.bold('Syntax:')}`);
      console.log(`  // @verb <args> [qualifiers] [refs] -- "description"\n`);
      
      console.log(`${c.bold('Definition Verbs:')}`);
      console.log(`  ${c.green('@asset')}    <path> (#id)         ${c.gray('Declare a component')}`);
      console.log(`  ${c.green('@threat')}   <name> (#id) [sev]   ${c.gray('Declare a threat')}`);
      console.log(`  ${c.green('@control')}  <name> (#id)         ${c.gray('Declare a security control')}\n`);

      console.log(`${c.bold('Relationship Verbs:')}`);
      console.log(`  ${c.green('@mitigates')} <asset> against <threat> using <control>`);
      console.log(`  ${c.green('@exposes')}   <asset> to <threat> [severity]`);
      console.log(`  ${c.green('@flows')}     <source> -> <target> via <mechanism>`);
      console.log(`  ${c.green('@boundary')}  between <asset-a> and <asset-b> (#id)\n`);

      console.log(`${c.bold('Lifecycle & Metadata:')}`);
      console.log(`  ${c.green('@handles')}   <data> on <asset>    ${c.gray('Data classification')}`);
      console.log(`  ${c.green('@owns')}      <owner> for <asset>  ${c.gray('Security ownership')}`);
      console.log(`  ${c.green('@assumes')}   <asset>              ${c.gray('Security assumption')}`);
      console.log(`  ${c.green('@shield')}    [-- "reason"]        ${c.gray('AI exclusion marker')}\n`);

      console.log(`${c.bold('Severity Levels:')}`);
      console.log(`  [critical] | [high] | [medium] | [low]`);
      console.log(`  [P0]       | [P1]   | [P2]     | [P3]\n`);

      console.log(`${c.bold('Data Classifications:')}`);
      console.log(`  pii | secrets | financial | phi | internal | public\n`);

      console.log(`${c.bold('Example:')}`);
      console.log(`  ${c.gray('// @mitigates #api against #sqli using #prepared-stmts -- "Parameterized query"')}\n`);
    });
  });

// If no subcommand given, launch TUI
if (process.argv.length <= 2) {
  import('../tui/index.js').then(({ startTui }) => startTui('.'));
} else {
  program.parse();
}

// ─── Helpers ─────────────────────────────────────────────────────────

function printDiagnostics(diagnostics: ParseDiagnostic[]) {
  for (const d of diagnostics) {
    const prefix = d.level === 'error' ? '✗' : '⚠';
    console.error(`${prefix} ${d.file}:${d.line}: ${d.message}`);
    if (d.raw) console.error(`  → ${d.raw}`);
  }
  if (diagnostics.length > 0) {
    const errors = diagnostics.filter(d => d.level === 'error').length;
    const warnings = diagnostics.filter(d => d.level === 'warning').length;
    console.error(`\n${errors} error(s), ${warnings} warning(s)\n`);
  }
}

function printStatus(model: ThreatModel) {
  console.log(`GuardLink Status: ${model.project}`);
  console.log(`${'─'.repeat(40)}`);
  console.log(`Files scanned:    ${model.source_files}`);
  console.log(`Annotations:      ${model.annotations_parsed}`);
  console.log(`${'─'.repeat(40)}`);
  console.log(`Assets:           ${model.assets.length}`);
  console.log(`Threats:          ${model.threats.length}`);
  console.log(`Controls:         ${model.controls.length}`);
  console.log(`Mitigations:      ${model.mitigations.length}`);
  console.log(`Exposures:        ${model.exposures.length}`);
  console.log(`Acceptances:      ${model.acceptances.length}`);
  console.log(`Transfers:        ${model.transfers.length}`);
  console.log(`Flows:            ${model.flows.length}`);
  console.log(`Boundaries:       ${model.boundaries.length}`);
  console.log(`Validations:      ${model.validations.length}`);
  console.log(`Audits:           ${model.audits.length}`);
  console.log(`Ownership:        ${model.ownership.length}`);
  console.log(`Data handling:    ${model.data_handling.length}`);
  console.log(`Assumptions:      ${model.assumptions.length}`);
  console.log(`Comments:         ${model.comments.length}`);
  console.log(`Shields:          ${model.shields.length}`);
}

