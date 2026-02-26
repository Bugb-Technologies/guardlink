#!/usr/bin/env node

/**
 * GuardLink TUI — Interactive terminal interface.
 *
 * Claude Code-style inline REPL: stays in your terminal,
 * slash commands + freeform AI chat, Ctrl+C to exit.
 *
 */

import { createInterface, type Interface } from 'node:readline';
import { resolve, basename } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { parseProject } from '../parser/index.js';
import { C, computeGrade, gradeColored, severityText } from './format.js';
import { computeSeverity } from '../dashboard/data.js';
import { resolveLLMConfig, loadTuiConfig } from './config.js';
import { InputBox, type CommandEntry } from './input.js';
import gradient from 'gradient-string';
import {
  type TuiContext,
  refreshModel,
  cmdHelp,
  cmdStatus,
  cmdAssets,
  cmdFiles,
  cmdView,
  cmdInit,
  cmdParse,
  cmdValidate,
  cmdDiff,
  cmdSarif,
  cmdModel,
  cmdThreatReport,
  cmdThreatReports,
  cmdAnnotate,
  cmdChat,
  cmdClear,
  cmdSync,
  cmdReport,
  cmdDashboard,
  cmdGal,
} from './commands.js';

// ─── Command registry ────────────────────────────────────────────────

const COMMANDS = [
  '/help', '/gal', '/init', '/parse', '/run', '/status',
  '/validate', '/diff', '/sarif',
  '/assets', '/files', '/view',
  '/threat-report', '/threat-reports', '/annotate', '/model',
  '/clear', '/sync',
  '/report', '/dashboard',
  '/quit',
];

const ANALYZE_FRAMEWORKS = ['stride', 'dread', 'pasta', 'attacker', 'rapid', 'general'];

const ASCII_LOGO = `
 ██████  ██    ██  █████  ██████  ██████  ██      ██ ███    ██ ██   ██ 
██       ██    ██ ██   ██ ██   ██ ██   ██ ██      ██ ████   ██ ██  ██  
██   ███ ██    ██ ███████ ██████  ██   ██ ██      ██ ██ ██  ██ █████   
██    ██ ██    ██ ██   ██ ██   ██ ██   ██ ██      ██ ██  ██ ██ ██  ██  
 ██████   ██████  ██   ██ ██   ██ ██████  ███████ ██ ██   ████ ██   ██ 
`;

/** Command palette entries for InputBox */
const PALETTE_COMMANDS: CommandEntry[] = [
  { command: '/init',       label: 'Initialize project' },
  { command: '/parse',      label: 'Parse annotations',    aliases: ['/run'] },
  { command: '/status',     label: 'Risk grade + stats' },
  { command: '/validate',   label: 'Syntax + ref checks' },
  { command: '/exposures',  label: 'List open exposures by severity' },
  { command: '/show',       label: 'Detail view for an exposure' },
  { command: '/scan',       label: 'Annotation coverage scanner' },
  { command: '/assets',     label: 'Asset tree' },
  { command: '/files',      label: 'Annotated file tree' },
  { command: '/view',       label: 'File annotations + code' },
  { command: '/threat-report',  label: 'AI threat report' },
  { command: '/threat-reports', label: 'List saved threat reports' },
  { command: '/annotate',   label: 'Launch coding agent' },
  { command: '/model',      label: 'Set AI provider' },
  { command: '/clear',      label: 'Remove all annotations from source files' },
  { command: '/sync',       label: 'Sync agent instructions with current threat model' },
  { command: '/report',     label: 'Generate markdown report' },
  { command: '/dashboard',  label: 'HTML dashboard' },
  { command: '/diff',       label: 'Compare vs git ref' },
  { command: '/sarif',      label: 'Export SARIF 2.1.0' },
  { command: '/gal',        label: 'GAL annotation language guide' },
  { command: '/help',       label: 'Show all commands' },
  { command: '/quit',       label: 'Exit GuardLink CLI',   aliases: ['/exit', '/q'] },
];

// ─── Welcome banner ──────────────────────────────────────────────────

function printBanner(ctx: TuiContext): void {
  console.log(gradient(['#00ff41', '#00d4ff'])(ASCII_LOGO));
  const version = getVersion();
  const LW = 34;  // left column inner width
  const RW = 34;  // right column inner width
  // Total visible box width: │ _(LW)_ │ _(RW)_ │ = LW+RW+7
  const W = LW + RW + 7;

  // Box-drawing helpers
  const pad = (s: string, visLen: number, w: number) => s + ' '.repeat(Math.max(0, w - visLen));

  // Borders — all exactly W visible chars (Bravos teal theme)
  const title = ` GuardLink v${version} `;
  const topDashes = W - 3 - title.length;  // 3 = ┌─ (2) + ┐ (1)
  const topBorder = C.teal('┌─') + C.bold(title) + C.teal('─'.repeat(Math.max(0, topDashes)) + '┐');
  const midBorder = C.teal('├' + '─'.repeat(LW + 2) + '┼' + '─'.repeat(RW + 2) + '┤');
  const botBorder = C.teal('└' + '─'.repeat(W - 2) + '┘');

  // Row helper: │ left(LW) │ right(RW) │
  const row = (left: string, leftVis: number, right: string, rightVis: number) => {
    return C.teal('│') + ' ' + pad(left, leftVis, LW) + ' ' + C.teal('│') + ' ' + pad(right, rightVis, RW) + ' ' + C.teal('│');
  };
  const emptyRow = () => row('', 0, '', 0);

  // Build left & right column content
  const leftLines: { text: string; vis: number }[] = [];
  const rightLines: { text: string; vis: number }[] = [];

  if (ctx.model) {
    const sev = computeSeverity(ctx.model);
    const open = sev.critical + sev.high + sev.medium + sev.low;
    const grade = computeGrade(ctx.model.exposures.length, ctx.model.mitigations.length);

    // Left: project identity
    const projLine = ctx.projectName;
    leftLines.push({ text: C.bold(projLine), vis: projLine.length });
    const gradeVis = `Grade: ${grade} · ${open} open exposures`;
    leftLines.push({ text: `Grade: ${gradeColored(grade)} · ${open} open exposures`, vis: gradeVis.length });

    leftLines.push({ text: '', vis: 0 });  // spacer

    // Severity breakdown
    const sevParts: { text: string; vis: string }[] = [];
    if (sev.critical > 0) sevParts.push({ text: C.red.bold(String(sev.critical)) + ' critical', vis: `${sev.critical} critical` });
    if (sev.high > 0) sevParts.push({ text: C.yellow.bold(String(sev.high)) + ' high', vis: `${sev.high} high` });
    if (sev.medium > 0) sevParts.push({ text: C.yellow(String(sev.medium)) + ' medium', vis: `${sev.medium} medium` });
    if (sev.low > 0) sevParts.push({ text: C.blue(String(sev.low)) + ' low', vis: `${sev.low} low` });

    if (sevParts.length <= 2) {
      const sevLine = sevParts.map(p => p.text).join(C.dim(' · '));
      const sevVis = sevParts.map(p => p.vis).join(' · ');
      leftLines.push({ text: sevLine, vis: sevVis.length });
    } else {
      const l1 = sevParts.slice(0, 2);
      const l2 = sevParts.slice(2);
      leftLines.push({ text: l1.map(p => p.text).join(C.dim(' · ')), vis: l1.map(p => p.vis).join(' · ').length });
      leftLines.push({ text: l2.map(p => p.text).join(C.dim(' · ')), vis: l2.map(p => p.vis).join(' · ').length });
    }

    leftLines.push({ text: '', vis: 0 });  // spacer

    // Stats
    const s1 = `${ctx.model.assets.length} assets · ${ctx.model.threats.length} threats`;
    leftLines.push({ text: C.dim(s1), vis: s1.length });
    const s2 = `${ctx.model.controls.length} controls · ${ctx.model.annotations_parsed} ann`;
    leftLines.push({ text: C.dim(s2), vis: s2.length });

    // Right: top threats
    const threatFreq = new Map<string, { count: number; sev: string }>();
    for (const e of ctx.model.exposures) {
      const prev = threatFreq.get(e.threat);
      if (prev) { prev.count++; } else {
        const def = ctx.model.threats.find(t => t.id === e.threat);
        threatFreq.set(e.threat, { count: 1, sev: def?.severity || 'medium' });
      }
    }
    const topThreats = [...threatFreq.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 3);

    if (topThreats.length) {
      rightLines.push({ text: C.yellow.bold('Top threats'), vis: 'Top threats'.length });
      for (const [id, { count, sev: s }] of topThreats) {
        const sevC = s === 'critical' ? C.red : s === 'high' ? C.yellow : C.dim;
        const countStr = `x${count}`;
        const gap = Math.max(2, RW - id.length - countStr.length);
        rightLines.push({ text: sevC(id) + ' '.repeat(gap) + C.dim(countStr), vis: id.length + gap + countStr.length });
      }
      rightLines.push({ text: '', vis: 0 });
    }

    // Right: quick start
    rightLines.push({ text: C.cyan.bold('Quick start'), vis: 'Quick start'.length });
    const tips: [string, string][] = [
      ['/init',      'Initialize project'],
      ['/validate',  'Check annotations'],
      ['/files',     'Browse files'],
      ['/assets',    'Asset tree'],
      ['/threat-report', 'AI threat report'],
    ];
    for (const [cmd, desc] of tips) {
      const tipVis = cmd + '  ' + desc;
      rightLines.push({ text: C.bold(cmd) + '  ' + C.dim(desc), vis: tipVis.length });
    }
  } else {
    // No model state
    leftLines.push({ text: C.bold(ctx.projectName || 'No project'), vis: (ctx.projectName || 'No project').length });
    leftLines.push({ text: C.dim('No threat model found'), vis: 'No threat model found'.length });
    leftLines.push({ text: '', vis: 0 });
    leftLines.push({ text: C.dim('Run /init to get started'), vis: 'Run /init to get started'.length });

    rightLines.push({ text: C.cyan.bold('Getting started'), vis: 'Getting started'.length });
    const tips: [string, string][] = [
      ['/init',     'Initialize project'],
      ['/annotate', 'Add annotations'],
      ['/parse',    'Build threat model'],
    ];
    for (const [cmd, desc] of tips) {
      const tipVis = cmd + '  ' + desc;
      rightLines.push({ text: C.bold(cmd) + '  ' + C.dim(desc), vis: tipVis.length });
    }
  }

  // AI provider or CLI agent (bottom of left column)
  const tuiCfg = loadTuiConfig(ctx.root);
  const llm = resolveLLMConfig(ctx.root);
  if (tuiCfg?.aiMode === 'cli-agent' && tuiCfg?.cliAgent) {
    const CLI_AGENT_NAMES: Record<string, string> = {
      'claude-code': 'Claude Code',
      'codex': 'Codex CLI',
      'gemini': 'Gemini CLI',
    };
    const agentName = CLI_AGENT_NAMES[tuiCfg.cliAgent] || tuiCfg.cliAgent;
    leftLines.push({ text: '', vis: 0 });
    const aiVis = `AI: ${agentName} (CLI)`;
    leftLines.push({ text: C.dim('AI: ') + C.cyan(agentName) + C.dim(' (CLI)'), vis: aiVis.length });
  } else if (llm) {
    leftLines.push({ text: '', vis: 0 });
    const aiVis = `AI: ${llm.provider}/${llm.model}`;
    leftLines.push({ text: C.dim('AI: ') + C.cyan(`${llm.provider}/${llm.model}`), vis: aiVis.length });
  }

  // Equalize heights
  const maxRows = Math.max(leftLines.length, rightLines.length);
  while (leftLines.length < maxRows) leftLines.push({ text: '', vis: 0 });
  while (rightLines.length < maxRows) rightLines.push({ text: '', vis: 0 });

  // Render
  console.log('');
  console.log(topBorder);
  console.log(emptyRow());  // breathing room below title
  for (let i = 0; i < maxRows; i++) {
    console.log(row(leftLines[i].text, leftLines[i].vis, rightLines[i].text, rightLines[i].vis));
  }
  console.log(botBorder);
  console.log('');
  console.log(C.dim('  GuardLink CLI · /help for commands · /gal for annotation guide · Ctrl+C to exit.'));
  console.log('');
}

function getVersion(): string {
  try {
    // Try relative to this file
    const dir = new URL('.', import.meta.url).pathname;
    const pkgPath = resolve(dir, '../../package.json');
    if (existsSync(pkgPath)) {
      return JSON.parse(readFileSync(pkgPath, 'utf-8')).version || '0.0.0';
    }
  } catch { /* ignore */ }
  try {
    // Try from cwd
    const cwdPkg = resolve(process.cwd(), 'node_modules/guardlink/package.json');
    if (existsSync(cwdPkg)) {
      return JSON.parse(readFileSync(cwdPkg, 'utf-8')).version || '0.0.0';
    }
  } catch { /* ignore */ }
  return '0.0.0';
}

// ─── Compact command list (shown on bare "/") ───────────────────────

function printCommandList(): void {
    const cmds: [string, string][] = [
    ['/init',       'Initialize project'],
    ['/parse',      'Parse annotations'],
    ['/status',     'Risk grade + stats'],
    ['/validate',   'Syntax + ref checks'],
    ['/exposures',  'List open exposures'],
    ['/show <n>',   'Detail + code context'],
    ['/scan',       'Coverage scanner'],
    ['/assets',     'Asset tree'],
    ['/files',      'Annotated file tree'],
    ['/view <file>','File annotations + code'],
    ['/threat-report','AI threat report'],
    ['/threat-reports','List saved reports'],
    ['/annotate',   'Launch coding agent'],
    ['/model',      'Set AI provider'],
    ['/clear',      'Clear all annotations'],
    ['/sync',       'Sync agent instructions'],
    ['/report',     'Generate reports'],
    ['/dashboard',  'HTML dashboard'],
    ['/diff [ref]', 'Compare vs git ref'],
    ['/sarif',      'Export SARIF'],
    ['/gal',        'GAL annotation guide'],
    ['/help',       'Full help'],
    ['/quit',       'Exit GuardLink CLI'],
  ];
  console.log('');
  for (const [cmd, desc] of cmds) {
    console.log(`  ${C.cyan(cmd.padEnd(16))}${C.dim(desc)}`);
  }
  console.log('');
}

// ─── Command dispatch ────────────────────────────────────────────────

async function dispatch(input: string, ctx: TuiContext): Promise<boolean> {
  const trimmed = input.trim();
  if (!trimmed) return true; // continue

  // Quit
  if (trimmed === '/quit' || trimmed === '/exit' || trimmed === '/q') {
    return false;
  }

  // Slash commands
  if (trimmed.startsWith('/')) {
    // Bare "/" — show command list inline
    if (trimmed === '/') {
      printCommandList();
      return true;
    }

    const spaceIdx = trimmed.indexOf(' ');
    const cmd = spaceIdx === -1 ? trimmed.toLowerCase() : trimmed.slice(0, spaceIdx).toLowerCase();
    const args = spaceIdx === -1 ? '' : trimmed.slice(spaceIdx + 1);

    try {
      switch (cmd) {
        case '/help':     cmdHelp(); break;
        case '/gal':      cmdGal(); break;
        case '/status':   cmdStatus(ctx); break;
        case '/assets':   cmdAssets(ctx); break;
        case '/files':    cmdFiles(ctx); break;
        case '/view':     cmdView(args, ctx); break;
        case '/init':     await cmdInit(args, ctx); break;
        case '/parse':
        case '/run':      await cmdParse(ctx); break;
        case '/validate': await cmdValidate(ctx); break;
        case '/diff':     await cmdDiff(args, ctx); break;
        case '/sarif':    await cmdSarif(args, ctx); break;
        case '/model':    await cmdModel(ctx); break;
        case '/threat-report':  await cmdThreatReport(args, ctx); break;
        case '/threat-reports': cmdThreatReports(ctx); break;
        case '/annotate': await cmdAnnotate(args, ctx); break;
        case '/clear':    await cmdClear(args, ctx); break;
        case '/sync':     await cmdSync(ctx); break;
        case '/report':   await cmdReport(ctx); break;
        case '/dashboard': await cmdDashboard(ctx); break;
        default:
          // Fuzzy match
          const matches = COMMANDS.filter(c => c.startsWith(cmd));
          if (matches.length === 1) {
            // Re-dispatch with full command
            return dispatch(matches[0] + ' ' + args, ctx);
          } else if (matches.length > 1) {
            console.log(C.warn(`  Ambiguous: ${matches.join(', ')}`));
          } else {
            console.log(C.warn(`  Unknown command: ${cmd}. Type /help.`));
          }
      }
    } catch (err: any) {
      console.log(C.error(`  Error: ${err.message}`));
    }
    return true;
  }

  // Freeform text → AI chat
  await cmdChat(trimmed, ctx);
  return true;
}

// ─── Main entry point ────────────────────────────────────────────────

let exiting = false;

export async function startTui(dir?: string): Promise<void> {
  const root = resolve(dir || process.cwd());
  const projectName = detectProjectName(root);

  // Create a readline interface for sub-prompts (ask() in commands)
  // This is only used when InputBox is paused during command execution
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: process.stdin.isTTY ?? false,
  });
  rl.pause(); // starts paused — InputBox handles primary input

  const ctx: TuiContext = {
    root,
    model: null,
    projectName,
    rl,
    lastExposures: [],
  };

  // Try loading existing model
  try {
    const { model } = await parseProject({ root, project: projectName });
    if (model.annotations_parsed > 0) {
      ctx.model = model;
    }
  } catch {
    // No model yet — that's fine
  }

  // Welcome
  printBanner(ctx);

  // Create InputBox
  const inputBox = new InputBox({
    placeholder: 'Type a command or ask a question...',
    prompt: '›',
    commands: PALETTE_COMMANDS,
    maxPaletteItems: 21,
  });

  function goodbye(): void {
    if (exiting) return;
    exiting = true;
    process.exit(0);
  }

  inputBox.start(
    // onSubmit — called when user presses Enter
    async (line: string) => {
      inputBox.pause();

      const shouldContinue = await dispatch(line, ctx);
      if (shouldContinue) {
        inputBox.resume();
      } else {
        goodbye();
      }
    },
    // onClose — called on Ctrl+C
    () => goodbye(),
  );
}

const GENERIC_PKG_NAMES = new Set([
  'my-v0-project', 'my-app', 'my-project', 'my-next-app', 'vite-project',
  'react-app', 'create-react-app', 'starter', 'app', 'project', 'unknown',
]);

function detectProjectName(root: string): string {
  // Try git remote origin URL first (most reliable repo name)
  try {
    const gitConfigPath = resolve(root, '.git', 'config');
    if (existsSync(gitConfigPath)) {
      const gitConfig = readFileSync(gitConfigPath, 'utf-8');
      const m = gitConfig.match(/url\s*=\s*.*[/:]([^/\s]+?)(?:\.git)?\s*$/m);
      if (m) return m[1];
    }
  } catch { /* ignore */ }
  // Try package.json (skip generic scaffold names)
  const pkgPath = resolve(root, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      if (pkg.name && !GENERIC_PKG_NAMES.has(pkg.name)) return pkg.name;
    } catch { /* ignore */ }
  }
  // Try Cargo.toml
  const cargoPath = resolve(root, 'Cargo.toml');
  if (existsSync(cargoPath)) {
    try {
      const cargo = readFileSync(cargoPath, 'utf-8');
      const match = cargo.match(/name\s*=\s*"([^"]+)"/);
      if (match) return match[1];
    } catch { /* ignore */ }
  }
  return basename(root);
}

// Allow direct execution
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('/tui/index.ts') || process.argv[1]?.endsWith('/tui/index.js')) {
  startTui(process.argv[2]).catch(console.error);
}
