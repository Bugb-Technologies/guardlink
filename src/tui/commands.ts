/**
 * GuardLink TUI — Command implementations.
 *
 * Each command function takes (args, ctx) and prints output directly.
 * Returns void. Throws on fatal errors.
 */

import { resolve, basename, isAbsolute } from 'node:path';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { parseProject, findDanglingRefs, findUnmitigatedExposures } from '../parser/index.js';
import { initProject, detectProject, promptAgentSelection } from '../init/index.js';
import { generateReport, generateMermaid } from '../report/index.js';
import { generateDashboardHTML } from '../dashboard/index.js';
import { computeStats, computeSeverity, computeExposures } from '../dashboard/data.js';
import { generateThreatReport, serializeModel, listThreatReports, loadThreatReportsForDashboard, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage, type AnalysisFramework } from '../analyze/index.js';
import { diffModels, formatDiff, parseAtRef } from '../diff/index.js';
import { generateSarif } from '../analyzer/index.js';
import type { ThreatModel, ParseDiagnostic, ThreatModelExposure } from '../types/index.js';
import { C, severityBadge, severityText, severityTextPad, severityOrder, computeGrade, gradeColored, formatTable, readCodeContext, trunc, bar, fileLink, fileLinkTrunc } from './format.js';
import { resolveLLMConfig, saveTuiConfig, loadTuiConfig } from './config.js';
import { AGENTS, parseAgentFlag, launchAgent, copyToClipboard, buildAnnotatePrompt, type AgentEntry } from '../agents/index.js';
import { describeConfigSource } from '../agents/config.js';

// ─── Shared context ──────────────────────────────────────────────────

/** Prompt user to pick an agent interactively (TUI only) */
async function pickAgent(ctx: TuiContext): Promise<AgentEntry | null> {
  console.log('  Which agent?');
  AGENTS.forEach((a, i) => console.log(`    ${C.bold(String(i + 1))} ${a.name}`));
  console.log('');

  const choice = await ask(ctx, `  Agent [1-${AGENTS.length}]: `);
  const idx = parseInt(choice, 10) - 1;
  if (idx < 0 || idx >= AGENTS.length) {
    console.log(C.warn('  Cancelled.'));
    return null;
  }
  return AGENTS[idx] as AgentEntry;
}

export interface TuiContext {
  root: string;
  model: ThreatModel | null;
  projectName: string;
  /** Cached exposure list for /show references */
  lastExposures: ThreatModelExposure[];
  /** readline interface for prompting */
  rl: import('node:readline').Interface;
  /** Guard: true while ask() is waiting for sub-prompt input */
  _askActive?: boolean;
}

/** Re-parse the project and update context */
export async function refreshModel(ctx: TuiContext): Promise<void> {
  const { model } = await parseProject({ root: ctx.root, project: ctx.projectName });
  ctx.model = model;
}

/** Prompt the user for input (single line).
 *  Uses once('line') instead of rl.question() to avoid double-echo
 *  when the main REPL's on('line') handler is also registered. */
function ask(ctx: TuiContext, prompt: string): Promise<string> {
  return new Promise(res => {
    ctx._askActive = true;
    process.stdout.write(prompt);
    ctx.rl.resume();
    ctx.rl.once('line', (answer: string) => {
      ctx._askActive = false;
      ctx.rl.pause();
      res(answer.trim());
    });
  });
}

// ─── /help ───────────────────────────────────────────────────────────

export function cmdHelp(): void {
  console.log('');
  console.log(C.bold('  Commands'));
  console.log('');

  const cmds: [string, string][] = [
    ['/init [name]',            'Initialize GuardLink in this project'],
    ['/parse',                  'Parse annotations, build threat model'],
    ['/status',                 'Risk grade + summary stats'],
    ['/validate [--strict]',    'Check for syntax errors + dangling refs'],
    ['', ''],
    ['/assets',                 'Asset tree with threat/control counts'],
    ['/files',                  'Annotated file tree with exposure counts'],
    ['/view <file>',            'Show all annotations in a file with code context'],
    ['', ''],
    ['/threat-report <fw>',    'AI threat report (stride|dread|pasta|attacker|rapid|general)'],
    ['/threat-reports',         'List saved AI threat reports'],
    ['/annotate <prompt>',      'Launch coding agent to annotate codebase'],
    ['/model',                  'Set AI provider + API key'],
    ['(freeform text)',         'Chat about your threat model with AI'],
    ['', ''],
    ['/report',                 'Generate markdown + JSON report'],
    ['/dashboard',              'Generate HTML dashboard + open browser'],
    ['/diff [ref]',             'Compare model against a git ref (default: HEAD~1)'],
    ['/sarif [-o file]',        'Export SARIF 2.1.0 for GitHub / VS Code'],
    ['', ''],
    ['/help',                   'This help'],
    ['/quit',                   'Exit'],
  ];

  for (const [cmd, desc] of cmds) {
    if (!cmd) { console.log(''); continue; }
    console.log(`  ${C.bold(cmd.padEnd(24))} ${C.dim(desc)}`);
  }

  console.log('');
  console.log(C.dim('  Tab to autocomplete · ↑↓ history · /gal for annotation guide · Ctrl+C to exit'));
  console.log('');
}

// ─── /gal ────────────────────────────────────────────────────────────

export function cmdGal(): void {
  const H = (s: string) => C.bold(C.teal(s));
  const V = (s: string) => C.bold(C.cyan(s));
  const K = (s: string) => C.yellow(s);
  const D = (s: string) => C.dim(s);
  const EX = (s: string) => C.green(s);

  console.log('');
  console.log(H('  ══════════════════════════════════════════════════════════'));
  console.log(H('  GAL — GuardLink Annotation Language'));
  console.log(H('  ══════════════════════════════════════════════════════════'));
  console.log('');
  console.log(D('  Annotations live in source code comments. GuardLink parses'));
  console.log(D('  them to build a live threat model from your codebase.'));
  console.log('');
  console.log(D('  Syntax:  @verb  subject  [preposition  object]  [: description]'));
  console.log('');

  // ── DEFINITIONS ──────────────────────────────────────────────────
  console.log(H('  ── Definitions ─────────────────────────────────────────────'));
  console.log('');

  console.log(`  ${V('@asset')}  ${K('<path>')}  ${D('[: description]')}`);
  console.log(D('    Declare a named asset (component, service, data store).'));
  console.log(D('    Path uses dot notation for hierarchy.'));
  console.log(EX('    // @asset  api.auth.token_store  : Stores JWT refresh tokens'));
  console.log(EX('    // @asset  db.users'));
  console.log('');

  console.log(`  ${V('@threat')}  ${K('<name>')}  ${D('[severity: critical|high|medium|low]  [: description]')}`);
  console.log(D('    Declare a named threat. Severity aliases: P0=critical P1=high P2=medium P3=low.'));
  console.log(EX('    // @threat  SQL Injection  severity:high  : Unsanitized input reaches DB'));
  console.log(EX('    // @threat  Token Theft  severity:P0'));
  console.log('');

  console.log(`  ${V('@control')}  ${K('<name>')}  ${D('[: description]')}`);
  console.log(D('    Declare a security control (mitigation mechanism).'));
  console.log(EX('    // @control  Input Validation  : Sanitize all user-supplied strings'));
  console.log(EX('    // @control  Rate Limiting'));
  console.log('');

  // ── RELATIONSHIPS ─────────────────────────────────────────────────
  console.log(H('  ── Relationships ───────────────────────────────────────────'));
  console.log('');

  console.log(`  ${V('@exposes')}  ${K('<asset>')}  ${D('to')}  ${K('<threat>')}  ${D('[severity: ...]  [: description]')}`);
  console.log(D('    Mark an asset as exposed to a threat at this code location.'));
  console.log(D('    This is the primary annotation — every exposure creates a finding.'));
  console.log(EX('    // @exposes  api.auth  to  SQL Injection  severity:high'));
  console.log(EX('    // @exposes  db.users  to  Token Theft  severity:critical  : No token rotation'));
  console.log('');

  console.log(`  ${V('@mitigates')}  ${K('<asset>')}  ${D('against')}  ${K('<threat>')}  ${D('[with')}  ${K('<control>')}${D(']  [: description]')}`);
  console.log(D('    Mark that a control mitigates a threat on an asset.'));
  console.log(D('    Closes the exposure — removes it from open findings.'));
  console.log(EX('    // @mitigates  api.auth  against  SQL Injection  with  Input Validation'));
  console.log(EX('    // @mitigates  db.users  against  Token Theft  : Rotation implemented in v2'));
  console.log('');

  console.log(`  ${V('@accepts')}  ${K('<threat>')}  ${D('on')}  ${K('<asset>')}  ${D('[: reason]')}`);
  console.log(D('    Explicitly accept a risk. Removes it from open findings.'));
  console.log(D('    Use when the risk is known and intentionally not mitigated.'));
  console.log(EX('    // @accepts  Timing Attack  on  api.auth  : Acceptable for current threat model'));
  console.log('');

  console.log(`  ${V('@transfers')}  ${K('<threat>')}  ${D('from')}  ${K('<source>')}  ${D('to')}  ${K('<target>')}  ${D('[: description]')}`);
  console.log(D('    Transfer responsibility for a threat to another asset/team.'));
  console.log(EX('    // @transfers  DDoS  from  api.gateway  to  cdn.cloudflare  : Handled by CDN layer'));
  console.log('');

  // ── DATA FLOWS ────────────────────────────────────────────────────
  console.log(H('  ── Data Flows & Boundaries ─────────────────────────────────'));
  console.log('');

  console.log(`  ${V('@flows')}  ${K('<source>')}  ${D('to')}  ${K('<target>')}  ${D('[via')}  ${K('<mechanism>')}${D(']  [: description]')}`);
  console.log(D('    Document data movement between components.'));
  console.log(D('    Appears in the Data Flow Diagram.'));
  console.log(EX('    // @flows  api.auth  to  db.users  via  TLS 1.3'));
  console.log(EX('    // @flows  mobile.app  to  api.gateway  via  HTTPS  : User credentials'));
  console.log('');

  console.log(`  ${V('@boundary')}  ${K('<asset_a>')}  ${D('and')}  ${K('<asset_b>')}  ${D('[: description]')}`);
  console.log(D('    Declare a trust boundary between two assets.'));
  console.log(D('    Groups assets in the Data Flow Diagram.'));
  console.log(EX('    // @boundary  internet  and  api.gateway  : Public-facing edge'));
  console.log(EX('    // @boundary  api.gateway  and  db.users  : Internal network boundary'));
  console.log('');

  // ── LIFECYCLE ─────────────────────────────────────────────────────
  console.log(H('  ── Lifecycle & Governance ──────────────────────────────────'));
  console.log('');

  console.log(`  ${V('@handles')}  ${K('<classification>')}  ${D('on')}  ${K('<asset>')}  ${D('[: description]')}`);
  console.log(D('    Declare data classification handled by an asset.'));
  console.log(D('    Classifications: pii  phi  financial  secrets  internal  public'));
  console.log(EX('    // @handles  pii  on  db.users  : Stores name, email, phone'));
  console.log(EX('    // @handles  secrets  on  api.auth.token_store'));
  console.log('');

  console.log(`  ${V('@owns')}  ${K('<owner>')}  ${K('<asset>')}  ${D('[: description]')}`);
  console.log(D('    Assign ownership of an asset to a team or person.'));
  console.log(EX('    // @owns  platform-team  api.auth'));
  console.log('');

  console.log(`  ${V('@validates')}  ${K('<control>')}  ${D('on')}  ${K('<asset>')}  ${D('[: description]')}`);
  console.log(D('    Assert that a control has been validated/tested on an asset.'));
  console.log(EX('    // @validates  Input Validation  on  api.auth  : Pen-tested 2024-Q3'));
  console.log('');

  console.log(`  ${V('@audit')}  ${K('<asset>')}  ${D('[: description]')}`);
  console.log(D('    Mark that this code path is an audit trail point.'));
  console.log(EX('    // @audit  db.users  : All writes logged to audit_log table'));
  console.log('');

  console.log(`  ${V('@assumes')}  ${K('<asset>')}  ${D('[: description]')}`);
  console.log(D('    Document a security assumption about an asset.'));
  console.log(EX('    // @assumes  api.gateway  : Upstream WAF filters malformed requests'));
  console.log('');

  console.log(`  ${V('@comment')}  ${D('[: description]')}`);
  console.log(D('    Free-form developer security note (no structural effect).'));
  console.log(EX('    // @comment  : TODO — add rate limiting before v2 launch'));
  console.log('');

  // ── SHIELD BLOCKS ─────────────────────────────────────────────────
  console.log(H('  ── Shield Blocks ───────────────────────────────────────────'));
  console.log('');
  console.log(`  ${V('@shield:begin')}  ${D('/')}  ${V('@shield:end')}`);
  console.log(D('    Wrap a code block to mark it as security-sensitive.'));
  console.log(D('    GuardLink will flag unannotated symbols inside the block.'));
  console.log(EX('    // @shield:begin'));
  console.log(EX('    function verifyToken(token: string) { ... }'));
  console.log(EX('    // @shield:end'));
  console.log('');

  // ── TIPS ──────────────────────────────────────────────────────────
  console.log(H('  ── Tips ────────────────────────────────────────────────────'));
  console.log('');
  console.log(D('  • Annotations work in any comment style: // /* # -- <!-- -->'));
  console.log(D('  • Place annotations on the line ABOVE the code they describe'));
  console.log(D('  • Asset names are case-insensitive and normalized (spaces→underscores)'));
  console.log(D('  • Threat/control names can reference IDs with #id syntax'));
  console.log(D('  • Run /parse after adding annotations to update the threat model'));
  console.log(D('  • Run /validate to check for syntax errors and dangling references'));
  console.log(D('  • Run /annotate to have an AI agent add annotations automatically'));
  console.log('');
  console.log(H('  ══════════════════════════════════════════════════════════'));
  console.log('');
}

// ─── /status ─────────────────────────────────────────────────────────

export function cmdStatus(ctx: TuiContext): void {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /init then /run first.'));
    return;
  }
  const m = ctx.model;
  const stats = computeStats(m);
  const sev = computeSeverity(m);
  const grade = computeGrade(stats.exposures, stats.mitigations);
  const total = sev.critical + sev.high + sev.medium + sev.low + sev.unset;

  console.log('');
  console.log(`  ${C.bold('Risk Grade:')} ${gradeColored(grade)}  ${C.dim(`(${stats.exposures} open, ${stats.mitigations} mitigated)`)}`);
  console.log('');

  // Severity bars
  if (total > 0) {
    const bw = 15;
    console.log(`  ${C.red.bold(String(sev.critical).padStart(3))} critical  ${C.red(bar(sev.critical, total, bw))}`);
    console.log(`  ${C.yellow.bold(String(sev.high).padStart(3))} high      ${C.yellow(bar(sev.high, total, bw))}`);
    console.log(`  ${C.yellow(String(sev.medium).padStart(3))} medium    ${C.yellow(bar(sev.medium, total, bw))}`);
    console.log(`  ${C.blue(String(sev.low).padStart(3))} low       ${C.blue(bar(sev.low, total, bw))}`);
    if (sev.unset > 0) {
      console.log(`  ${C.gray(String(sev.unset).padStart(3))} unset     ${C.gray(bar(sev.unset, total, bw))}`);
    }
    console.log('');
  }

  console.log(`  ${C.dim('Assets:')} ${stats.assets}  ${C.dim('Threats:')} ${stats.threats}  ${C.dim('Controls:')} ${stats.controls}`);
  console.log(`  ${C.dim('Flows:')} ${stats.flows}  ${C.dim('Boundaries:')} ${stats.boundaries}  ${C.dim('Annotations:')} ${stats.annotations}`);
  console.log(`  ${C.dim('Coverage:')} ${stats.coverageAnnotated}/${stats.coverageTotal} symbols (${stats.coveragePercent}%)`);

  // Top threats
  if (m.exposures.length > 0) {
    const threatCounts = new Map<string, { count: number; maxSev: string }>();
    for (const e of m.exposures) {
      const key = e.threat;
      const existing = threatCounts.get(key);
      if (!existing) {
        threatCounts.set(key, { count: 1, maxSev: e.severity || '' });
      } else {
        existing.count++;
        if (severityOrder(e.severity) < severityOrder(existing.maxSev)) {
          existing.maxSev = e.severity || '';
        }
      }
    }

    const sorted = [...threatCounts.entries()]
      .sort((a, b) => a[1].count > b[1].count ? -1 : 1)
      .slice(0, 5);

    console.log('');
    console.log(`  ${C.bold('Top threats:')}`);
    for (const [threat, info] of sorted) {
      console.log(`    ${threat.padEnd(22)} ×${String(info.count).padEnd(4)} (${severityText(info.maxSev)})`);
    }
  }

  console.log('');
}

// ─── /exposures ──────────────────────────────────────────────────────

export function cmdExposures(args: string, ctx: TuiContext): void {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const rows = computeExposures(ctx.model);
  let filtered = rows.filter(r => !r.mitigated && !r.accepted); // open only by default

  // Parse flags
  const parts = args.split(/\s+/).filter(Boolean);
  let showAll = false;
  for (let i = 0; i < parts.length; i++) {
    const flag = parts[i];
    const val = parts[i + 1];
    if (flag === '--asset' && val) { filtered = filtered.filter(r => r.asset.includes(val)); i++; }
    else if (flag === '--severity' && val) { filtered = filtered.filter(r => r.severity === val.toLowerCase()); i++; }
    else if (flag === '--file' && val) { filtered = filtered.filter(r => r.file.includes(val)); i++; }
    else if (flag === '--threat' && val) { filtered = filtered.filter(r => r.threat.includes(val)); i++; }
    else if (flag === '--all') { filtered = rows; showAll = true; }
  }

  // Sort by severity
  filtered.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

  // Cache for /show
  ctx.lastExposures = filtered.map(r => {
    const original = ctx.model!.exposures.find(e =>
      e.asset === r.asset && e.threat === r.threat && e.location.file === r.file && e.location.line === r.line
    );
    return original!;
  }).filter(Boolean);

  if (filtered.length === 0) {
    console.log(C.green('  No matching exposures found.'));
    return;
  }

  console.log('');

  // Determine terminal width for adaptive layout
  const termWidth = process.stdout.columns || 100;

  // Manual table (we need colored cells which formatTable can't do directly)
  const header = `  ${C.dim('#'.padEnd(4))}${C.dim('SEVERITY'.padEnd(12))}${C.dim('ASSET'.padEnd(18))}${C.dim('THREAT'.padEnd(20))}${C.dim('FILE'.padEnd(30))}${C.dim('LINE')}`;
  console.log(header);
  console.log(C.dim('  ' + '─'.repeat(Math.min(termWidth - 4, 96))));

  for (const [i, r] of filtered.entries()) {
    const num = String(i + 1).padEnd(4);
    const sev = severityTextPad(r.severity, 12);
    const asset = trunc(r.asset, 16).padEnd(18);
    const threat = trunc(r.threat, 18).padEnd(20);
    const linkedFile = fileLinkTrunc(r.file, 28, r.line, ctx.root);
    const filePad = ' '.repeat(Math.max(0, 30 - trunc(r.file, 28).length));
    const line = `  ${num}${sev}${asset}${threat}${linkedFile}${filePad}${r.line}`;
    console.log(line);
  }

  console.log('');
  const countMsg = showAll
    ? `  ${filtered.length} exposure(s) total`
    : `  ${filtered.length} open exposure(s)`;
  console.log(C.dim(countMsg + '  ·  /show <n> for detail  ·  --asset --severity --threat --file to filter'));
  console.log('');
}

// ─── /show ───────────────────────────────────────────────────────────

export function cmdShow(args: string, ctx: TuiContext): void {
  const num = parseInt(args.trim(), 10);
  if (!num || num < 1 || num > ctx.lastExposures.length) {
    console.log(C.warn(`  Usage: /show <n> where n is 1-${ctx.lastExposures.length || '?'}. Run /exposures first.`));
    return;
  }

  const exp = ctx.lastExposures[num - 1];
  console.log('');
  console.log(`  ${C.cyan('┌')} ${exp.asset} → ${exp.threat} ${severityBadge(exp.severity)}`);
  if (exp.description) {
    console.log(`  ${C.cyan('│')} ${exp.description}`);
  }
  if (exp.external_refs.length > 0) {
    console.log(`  ${C.cyan('│')} ${C.dim(exp.external_refs.join(' · '))}`);
  }
  console.log(`  ${C.cyan('│')} ${C.dim(fileLink(exp.location.file, exp.location.line, ctx.root))}`);
  console.log(`  ${C.cyan('│')}`);

  // Code context
  const { lines } = readCodeContext(exp.location.file, exp.location.line, ctx.root);
  for (const l of lines) {
    console.log(`  ${C.cyan('│')} ${l}`);
  }
  console.log(`  ${C.cyan('└')}`);
  console.log('');
}

// ─── /assets ─────────────────────────────────────────────────────────

export function cmdAssets(ctx: TuiContext): void {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const m = ctx.model;

  // Build asset → exposure/mitigation counts
  const assetNames = new Set<string>();
  for (const a of m.assets) assetNames.add(a.path.join('.'));
  for (const e of m.exposures) assetNames.add(e.asset);
  for (const mi of m.mitigations) assetNames.add(mi.asset);

  const sorted = [...assetNames].sort();

  console.log('');
  console.log(`  ${C.bold('Assets')} (${sorted.length})`);
  console.log('');

  for (const name of sorted) {
    const exposures = m.exposures.filter(e => e.asset === name);
    const mitigations = m.mitigations.filter(mi => mi.asset === name);
    const open = exposures.length - mitigations.length;
    const flowCount = m.flows.filter(f => f.source === name || f.target === name).length;

    let statusIcon = C.green('✓');
    if (open > 0) statusIcon = open >= 3 ? C.red('✗') : C.warn('⚠');

    console.log(`  ${statusIcon} ${C.bold(name)}`);
    console.log(`    ${C.dim('Exposures:')} ${exposures.length}  ${C.dim('Mitigated:')} ${mitigations.length}  ${C.dim('Open:')} ${open > 0 ? C.red(String(open)) : C.green('0')}  ${C.dim('Flows:')} ${flowCount}`);

    // Show threats for this asset
    const threats = new Map<string, string>();
    for (const e of exposures) {
      if (!threats.has(e.threat)) threats.set(e.threat, e.severity || 'unset');
    }
    if (threats.size > 0) {
      const threatList = [...threats.entries()]
        .sort((a, b) => severityOrder(a[1]) - severityOrder(b[1]))
        .map(([t, s]) => `${severityText(s)} ${t}`)
        .join(C.dim(' · '));
      console.log(`    ${C.dim('Threats:')} ${threatList}`);
    }
    console.log('');
  }
}

// ─── /files ──────────────────────────────────────────────────────────

export function cmdFiles(ctx: TuiContext): void {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const m = ctx.model;

  // Collect per-file stats from all annotation sources
  const fileStats = new Map<string, { annotations: number; exposures: number; maxSev: string; threats: Set<string> }>();

  const touch = (file: string) => {
    if (!fileStats.has(file)) fileStats.set(file, { annotations: 0, exposures: 0, maxSev: 'low', threats: new Set() });
    return fileStats.get(file)!;
  };

  // Count from exposures
  for (const e of m.exposures) {
    const s = touch(e.location.file);
    s.annotations++;
    s.exposures++;
    s.threats.add(e.threat);
    if (severityOrder(e.severity) < severityOrder(s.maxSev)) s.maxSev = e.severity || 'unset';
  }
  // Count from mitigations
  for (const mi of m.mitigations) { touch(mi.location.file).annotations++; }
  // Count from other annotation types
  for (const a of m.acceptances) { touch(a.location.file).annotations++; }
  for (const t of m.transfers) { touch(t.location.file).annotations++; }
  for (const f of m.flows) { touch(f.location.file).annotations++; }

  // Sort: files with exposures first (by severity), then alphabetically
  const sorted = [...fileStats.entries()].sort((a, b) => {
    if (a[1].exposures !== b[1].exposures) return b[1].exposures - a[1].exposures;
    if (a[1].maxSev !== b[1].maxSev) return severityOrder(a[1].maxSev) - severityOrder(b[1].maxSev);
    return a[0].localeCompare(b[0]);
  });

  console.log('');
  console.log(`  ${C.bold('Annotated files')} (${sorted.length})`);
  console.log('');

  // Group by directory
  let lastDir = '';
  for (const [file, stats] of sorted) {
    const parts = file.split('/');
    const dir = parts.slice(0, -1).join('/');
    const name = parts[parts.length - 1];

    if (dir !== lastDir) {
      if (lastDir !== '') console.log('');
      console.log(`  ${C.dim(dir + '/')}`);
      lastDir = dir;
    }

    // Status indicator
    let icon = C.dim('·');
    if (stats.exposures > 0) {
      icon = severityOrder(stats.maxSev) <= 1 ? C.red('●') : C.yellow('●');
    }

    // Counts
    const expLabel = stats.exposures > 0
      ? ` ${C.red(String(stats.exposures) + ' exp')}`
      : '';
    const annLabel = C.dim(`${stats.annotations} ann`);

    // Threat badges (top 2)
    const threatList = [...stats.threats].slice(0, 2).map(t => C.dim(t)).join(C.dim(', '));
    const threatSuffix = threatList ? `  ${threatList}` : '';

    console.log(`    ${icon} ${fileLink(file, undefined, ctx.root, name)}  ${annLabel}${expLabel}${threatSuffix}`);
  }

  console.log('');
  console.log(C.dim(`  /view <file> to see annotations in a file`));
  console.log('');
}

// ─── /view ───────────────────────────────────────────────────────────

export function cmdView(args: string, ctx: TuiContext): void {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const query = args.trim();
  if (!query) {
    console.log(C.warn('  Usage: /view <file>  (partial path match works)'));
    return;
  }

  const m = ctx.model;

  // Collect all annotations with locations
  type AnnotationEntry = {
    type: string;
    summary: string;
    severity?: string;
    file: string;
    line: number;
    refs: string[];
  };

  const allAnnotations: AnnotationEntry[] = [];

  for (const e of m.exposures) {
    allAnnotations.push({
      type: 'exposes',
      summary: `${e.asset} → ${e.threat}${e.description ? ': ' + e.description : ''}`,
      severity: e.severity,
      file: e.location.file,
      line: e.location.line,
      refs: e.external_refs,
    });
  }
  for (const mi of m.mitigations) {
    allAnnotations.push({
      type: 'mitigates',
      summary: `${mi.asset}: ${mi.threat}${mi.control ? ' via ' + mi.control : ''}`,
      file: mi.location.file,
      line: mi.location.line,
      refs: [],
    });
  }
  for (const a of m.acceptances) {
    allAnnotations.push({
      type: 'accepts',
      summary: `${a.asset}: ${a.threat}`,
      file: a.location.file,
      line: a.location.line,
      refs: [],
    });
  }
  for (const f of m.flows) {
    allAnnotations.push({
      type: 'flows',
      summary: `${f.source} → ${f.target}${f.mechanism ? ' (' + f.mechanism + ')' : ''}`,
      file: f.location.file,
      line: f.location.line,
      refs: [],
    });
  }

  // Find files matching query
  const matchingFiles = [...new Set(allAnnotations.map(a => a.file))]
    .filter(f => f.includes(query));

  if (matchingFiles.length === 0) {
    console.log(C.warn(`  No annotated files matching "${query}".`));
    console.log(C.dim('  Run /files to see all annotated files.'));
    return;
  }

  if (matchingFiles.length > 1) {
    console.log('');
    console.log(`  ${C.bold('Multiple matches')} — be more specific:`);
    for (const f of matchingFiles.slice(0, 10)) {
      console.log(`    ${fileLink(f, undefined, ctx.root)}`);
    }
    if (matchingFiles.length > 10) console.log(C.dim(`    ... and ${matchingFiles.length - 10} more`));
    console.log('');
    return;
  }

  const targetFile = matchingFiles[0];
  const fileAnns = allAnnotations
    .filter(a => a.file === targetFile)
    .sort((a, b) => a.line - b.line);

  console.log('');
  console.log(`  ${C.bold(fileLink(targetFile, undefined, ctx.root))}  ${C.dim(`(${fileAnns.length} annotations)`)}`);
  console.log(C.dim('  ' + '─'.repeat(56)));

  for (const ann of fileAnns) {
    // Type badge
    let badge: string;
    if (ann.type === 'exposes') badge = ann.severity ? severityBadge(ann.severity) : C.red(' EXP  ');
    else if (ann.type === 'mitigates') badge = C.green(' MIT  ');
    else if (ann.type === 'accepts') badge = C.yellow(' ACC  ');
    else if (ann.type === 'flows') badge = C.cyan(' FLOW ');
    else badge = C.dim(` ${ann.type.toUpperCase().padEnd(4)} `);

    console.log('');
    console.log(`  ${badge} ${ann.summary}`);
    if (ann.refs.length > 0) {
      console.log(`  ${C.dim('       ' + ann.refs.join(' · '))}`);
    }

    // Code context (±3 lines for compact view)
    const { lines } = readCodeContext(ann.file, ann.line, ctx.root, 3);
    for (const l of lines) {
      console.log(`  ${l}`);
    }
  }

  console.log('');
  console.log(C.dim('  ' + '─'.repeat(56)));
  console.log('');
}

// ─── /init ───────────────────────────────────────────────────────────

export async function cmdInit(args: string, ctx: TuiContext): Promise<void> {
  const info = detectProject(ctx.root);
  console.log(`  ${C.dim('Detected:')} ${info.language} project "${info.name}"`);

  if (info.alreadyInitialized) {
    console.log(C.warn('  .guardlink/ already exists. Skipping init.'));
    return;
  }

  // Agent selection
  let agentIds: string[] | undefined;
  if (process.stdin.isTTY) {
    agentIds = await promptAgentSelection(info.agentFiles);
  } else {
    agentIds = ['claude'];
  }

  const name = args.trim() || info.name || basename(ctx.root);
  const result = initProject({
    root: ctx.root,
    project: name,
    agentIds,
  });

  console.log('');
  for (const f of result.created) console.log(`  ${C.green('Created:')} ${f}`);
  for (const f of result.updated) console.log(`  ${C.green('Updated:')} ${f}`);
  for (const f of result.skipped) console.log(`  ${C.dim('Skipped:')} ${f}`);

  if (result.created.length > 0 || result.updated.length > 0) {
    ctx.projectName = name;
    console.log('');
    console.log(C.success('  ✓ GuardLink initialized.'));
    console.log(C.dim('  Run /annotate to add annotations, or /run if annotations already exist.'));
  }
  console.log('');
}

// ─── /parse (was /run) ───────────────────────────────────────────────

export async function cmdParse(ctx: TuiContext): Promise<void> {
  console.log(C.dim('  Parsing annotations...'));
  try {
    const { model, diagnostics } = await parseProject({ root: ctx.root, project: ctx.projectName });
    ctx.model = model;

    // Print errors/warnings
    const errors = diagnostics.filter(d => d.level === 'error');
    const warnings = diagnostics.filter(d => d.level === 'warning');
    if (errors.length > 0) {
      for (const d of errors) console.log(`  ${C.red('✗')} ${d.file}:${d.line}: ${d.message}`);
    }
    if (warnings.length > 0 && warnings.length <= 5) {
      for (const d of warnings) console.log(`  ${C.warn('⚠')} ${d.file}:${d.line}: ${d.message}`);
    } else if (warnings.length > 5) {
      console.log(`  ${C.warn('⚠')} ${warnings.length} warnings (run guardlink validate for details)`);
    }

    const grade = computeGrade(model.exposures.length, model.mitigations.length);
    console.log('');
    console.log(`  ${C.success('✓')} Parsed ${C.bold(String(model.annotations_parsed))} annotations from ${model.source_files} files`);
    console.log(`    ${model.assets.length} assets · ${model.threats.length} threats · ${model.controls.length} controls`);
    console.log(`    ${model.exposures.length} exposures · ${model.mitigations.length} mitigations · Grade: ${gradeColored(grade)}`);
    console.log('');
  } catch (err: any) {
    console.log(C.error(`  ✗ Parse failed: ${err.message}`));
  }
}

// ─── /scan ───────────────────────────────────────────────────────────

export function cmdScan(ctx: TuiContext): void {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const cov = ctx.model.coverage;
  const pct = cov.coverage_percent;
  console.log('');
  console.log(`  ${C.bold('Coverage:')} ${cov.annotated_symbols}/${cov.total_symbols} symbols (${pct}%)`);

  const unannotated = cov.unannotated_critical || [];
  if (unannotated.length === 0) {
    console.log(C.green('  All security-relevant symbols are annotated!'));
  } else {
    console.log(C.warn(`  ${unannotated.length} unannotated symbol(s):`));
    console.log('');
    const show = unannotated.slice(0, 25);
    for (const u of show) {
      console.log(`    ${C.dim(fileLink(u.file, u.line, ctx.root))}  ${u.kind} ${C.bold(u.name)}`);
    }
    if (unannotated.length > 25) {
      console.log(C.dim(`    ... and ${unannotated.length - 25} more`));
    }
  }
  console.log('');
}

// ─── /validate ───────────────────────────────────────────────────────

export async function cmdValidate(ctx: TuiContext): Promise<void> {
  console.log(C.dim('  Checking annotations...'));
  try {
    const { model, diagnostics } = await parseProject({ root: ctx.root, project: ctx.projectName });
    ctx.model = model;

    // Dangling refs
    const danglingDiags = findDanglingRefs(model);
    const allDiags = [...diagnostics, ...danglingDiags];

    // Unmitigated exposures
    const unmitigated = findUnmitigatedExposures(model);

    // Print diagnostics
    const errors = allDiags.filter(d => d.level === 'error');
    const warnings = allDiags.filter(d => d.level === 'warning');

    if (allDiags.length > 0) {
      console.log('');
      for (const d of allDiags) {
        const prefix = d.level === 'error' ? C.error('  ✗') : C.warn('  ⚠');
        const loc = d.file ? `${fileLink(d.file, d.line, ctx.root)}` : '';
        console.log(`${prefix} ${d.message}${loc ? `  ${C.dim(loc)}` : ''}`);
      }
    }

    if (unmitigated.length > 0) {
      console.log('');
      console.log(C.warn(`  ${unmitigated.length} unmitigated exposure(s):`));
      for (const u of unmitigated) {
        const sev = u.severity ? severityBadge(u.severity) : C.dim('unset');
        console.log(`    ${sev} ${u.asset} → ${u.threat}  ${C.dim(fileLink(u.location.file, u.location.line, ctx.root))}`);
      }
    }

    console.log('');
    if (errors.length === 0 && unmitigated.length === 0) {
      console.log(C.success('  ✓ All annotations valid, no unmitigated exposures.'));
    } else {
      const parts: string[] = [];
      if (errors.length > 0) parts.push(`${errors.length} error(s)`);
      if (warnings.length > 0) parts.push(`${warnings.length} warning(s)`);
      if (unmitigated.length > 0) parts.push(`${unmitigated.length} unmitigated`);
      console.log(`  ${parts.join(', ')}`);
    }
  } catch (err: any) {
    console.log(C.error(`  ✗ ${err.message}`));
  }
  console.log('');
}

// ─── /diff ───────────────────────────────────────────────────────────

export async function cmdDiff(args: string, ctx: TuiContext): Promise<void> {
  const ref = args.trim() || 'HEAD~1';
  console.log(C.dim(`  Comparing against ${ref}...`));
  try {
    const { model: current } = await parseProject({ root: ctx.root, project: ctx.projectName });
    ctx.model = current;

    let previous: ThreatModel;
    try {
      previous = await parseAtRef(ctx.root, ref, ctx.projectName);
    } catch (err: any) {
      console.log(C.error(`  ✗ Could not parse at ${ref}: ${err.message}`));
      console.log(C.dim('    Make sure you have git history and the ref exists.'));
      return;
    }

    const diff = diffModels(previous, current);
    const output = formatDiff(diff);
    console.log('');
    // Indent each line
    for (const line of output.split('\n')) {
      console.log(`  ${line}`);
    }
  } catch (err: any) {
    console.log(C.error(`  ✗ ${err.message}`));
  }
  console.log('');
}

// ─── /sarif ──────────────────────────────────────────────────────────

export async function cmdSarif(args: string, ctx: TuiContext): Promise<void> {
  const outputFile = args.replace(/-o\s+/, '').trim() || null;

  if (!ctx.model) {
    console.log(C.dim('  Parsing annotations first...'));
    try {
      const { model } = await parseProject({ root: ctx.root, project: ctx.projectName });
      ctx.model = model;
    } catch (err: any) {
      console.log(C.error(`  ✗ ${err.message}`));
      return;
    }
  }

  try {
    const { diagnostics } = await parseProject({ root: ctx.root, project: ctx.projectName });
    const danglingDiags = findDanglingRefs(ctx.model);

    const sarif = generateSarif(ctx.model, diagnostics, danglingDiags, {
      includeDiagnostics: true,
      includeDanglingRefs: true,
    });

    const json = JSON.stringify(sarif, null, 2);
    const resultCount = sarif.runs[0]?.results?.length ?? 0;

    if (outputFile) {
      const outPath = resolve(ctx.root, outputFile);
      writeFileSync(outPath, json + '\n');
      console.log(C.success(`  ✓ Wrote SARIF to ${outputFile}`));
    } else {
      const defaultPath = resolve(ctx.root, 'guardlink.sarif.json');
      writeFileSync(defaultPath, json + '\n');
      console.log(C.success(`  ✓ Wrote SARIF to guardlink.sarif.json`));
    }
    console.log(C.dim(`    ${resultCount} result(s)`));
  } catch (err: any) {
    console.log(C.error(`  ✗ ${err.message}`));
  }
  console.log('');
}


// ─── /model ──────────────────────────────────────────────────────────

const CLI_AGENT_OPTIONS = [
  { id: 'claude-code', name: 'Claude Code' },
  { id: 'codex',       name: 'Codex CLI' },
  { id: 'gemini',      name: 'Gemini CLI' },
] as const;

const CLI_AGENT_NAMES: Record<string, string> = {
  'claude-code': 'Claude Code',
  'codex': 'Codex CLI',
  'gemini': 'Gemini CLI',
};

export async function cmdModel(ctx: TuiContext): Promise<void> {
  const current = resolveLLMConfig(ctx.root);
  const tuiCfg = loadTuiConfig(ctx.root);
  const source = describeConfigSource(ctx.root);

  // Show current configuration
  if (tuiCfg?.aiMode === 'cli-agent' && tuiCfg?.cliAgent) {
    const agentName = CLI_AGENT_NAMES[tuiCfg.cliAgent] || tuiCfg.cliAgent;
    console.log(`  ${C.dim('Current:')} ${agentName} ${C.dim('(CLI Agent)')}`);  
    console.log(`  ${C.dim('Source:')}  ${source}`);
    console.log('');
  } else if (current) {
    console.log(`  ${C.dim('Current:')} ${current.provider} / ${current.model}`);
    console.log(`  ${C.dim('Source:')}  ${source}`);
    console.log('');

    if (source.includes('env var')) {
      const override = await ask(ctx, '  Override with project config? (y/N): ');
      if (override.toLowerCase() !== 'y') {
        console.log(C.dim('  Keeping environment configuration.'));
        return;
      }
    }
  } else {
    console.log(C.dim('  No AI provider configured.'));
    console.log('');
  }

  // Step 1: Choose mode — CLI Agents or API
  console.log('  How would you like to use AI?');
  console.log(`    ${C.bold('1')} CLI Agents  ${C.dim('(terminal-based coding agents)')}`);
  console.log(`    ${C.bold('2')} API         ${C.dim('(direct LLM API calls)')}`);
  console.log('');

  const modeChoice = await ask(ctx, '  Choice [1-2]: ');
  const modeIdx = parseInt(modeChoice, 10);
  if (modeIdx < 1 || modeIdx > 2) {
    console.log(C.warn('  Cancelled.'));
    return;
  }

  if (modeIdx === 1) {
    // ── CLI Agent selection ──
    console.log('');
    console.log('  Select CLI Agent:');
    CLI_AGENT_OPTIONS.forEach((a, i) => console.log(`    ${C.bold(String(i + 1))} ${a.name}`));
    console.log('');

    const agentChoice = await ask(ctx, `  Agent [1-${CLI_AGENT_OPTIONS.length}]: `);
    const agentIdx = parseInt(agentChoice, 10) - 1;
    if (agentIdx < 0 || agentIdx >= CLI_AGENT_OPTIONS.length) {
      console.log(C.warn('  Cancelled.'));
      return;
    }

    const selectedAgent = CLI_AGENT_OPTIONS[agentIdx];
    saveTuiConfig(ctx.root, {
      aiMode: 'cli-agent',
      cliAgent: selectedAgent.id,
    });

    console.log('');
    console.log(`  ${C.success('✓')} Configured: ${C.bold(selectedAgent.name)} ${C.dim('(CLI Agent)')}`);
    console.log(C.dim('    Saved to .guardlink/config.json'));
    console.log(C.dim(`    Use /threat-report or /annotate — they will launch ${selectedAgent.name} automatically.`));
    console.log('');
  } else {
    // ── API provider selection ──
    const providers = ['anthropic', 'openai', 'deepseek', 'openrouter', 'ollama'] as const;
    console.log('');
    console.log('  Select provider:');
    providers.forEach((p, i) => console.log(`    ${C.bold(String(i + 1))} ${p}`));
    console.log('');

    const choice = await ask(ctx, `  Provider [1-${providers.length}]: `);
    const idx = parseInt(choice, 10) - 1;
    if (idx < 0 || idx >= providers.length) {
      console.log(C.warn('  Cancelled.'));
      return;
    }

    const provider = providers[idx] as any;

    // API key
    let apiKey = '';
    if (provider !== 'ollama') {
      apiKey = await ask(ctx, '  API Key: ');
      if (!apiKey) {
        console.log(C.warn('  Cancelled — no API key provided.'));
        return;
      }
    } else {
      apiKey = 'ollama-local';
    }

    // Model selection
    const defaults: Record<string, string> = {
      anthropic: 'claude-sonnet-4-5-20250929',
      openai: 'gpt-4o',
      openrouter: 'anthropic/claude-sonnet-4-5-20250929',
      deepseek: 'deepseek-chat',
      ollama: 'llama3.2',
    };
    const model = await ask(ctx, `  Model [${defaults[provider]}]: `);

    saveTuiConfig(ctx.root, {
      aiMode: 'api',
      provider,
      model: model || defaults[provider],
      apiKey,
    });

    const displayKey = apiKey.length > 8 ? apiKey.slice(0, 6) + '•'.repeat(8) : '•'.repeat(8);
    console.log('');
    console.log(`  ${C.success('✓')} Configured: ${C.bold(model || defaults[provider])} (${provider})`);
    console.log(`    Key: ${displayKey}`);
    console.log(C.dim('    Saved to .guardlink/config.json'));
    console.log('');
  }
}

// ─── /threat-report ──────────────────────────────────────────────────

export async function cmdThreatReport(args: string, ctx: TuiContext): Promise<void> {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const { agent, cleanArgs } = parseAgentFlag(args);
  const framework = cleanArgs.trim().toLowerCase() || '';
  const validFrameworks = ['stride', 'dread', 'pasta', 'attacker', 'rapid', 'general'];

  if (!framework) {
    console.log('');
    console.log(`  ${C.bold('Threat report frameworks:')}`);
    for (const fw of validFrameworks) {
      console.log(`    ${C.bold('/threat-report ' + fw.padEnd(12))} ${C.dim(FRAMEWORK_LABELS[fw as AnalysisFramework])}`);
    }
    console.log('');
    console.log(C.dim('  Flags: --claude-code  --codex  --gemini  --cursor  --windsurf  --clipboard'));
    console.log(C.dim('  Without flag: uses configured API provider (see /model)'));
    console.log(C.dim('  Example: /threat-report stride --claude-code'));
    console.log('');
    return;
  }

  const isStandard = validFrameworks.includes(framework);
  const fw = (isStandard ? framework : 'general') as AnalysisFramework;
  const customPrompt = isStandard ? undefined : cleanArgs.trim();

  // ── Agent path: spawn CLI agent or copy to clipboard ──
  if (agent) {
    const modelJson = serializeModel(ctx.model);
    const systemPrompt = FRAMEWORK_PROMPTS[fw];
    const userMessage = buildUserMessage(modelJson, fw, customPrompt);

    const analysisPrompt = `You are analyzing a codebase with GuardLink security annotations.
You have access to the full source code in the current directory.

${systemPrompt}

## Task
Read the source code and GuardLink annotations, then produce a thorough ${FRAMEWORK_LABELS[fw]}.

## Threat Model (serialized from annotations)
${userMessage}

## Instructions
1. Read the actual source files to understand the code — don't just rely on the serialized model above
2. Cross-reference the annotations with the real code to validate findings
3. Produce the full report as markdown
4. Save the output to .guardlink/threat-reports/ with a timestamped filename
5. Be specific — reference actual files, functions, and line numbers from the codebase`;

    console.log(`  ${C.dim('Sending')} ${FRAMEWORK_LABELS[fw]} ${C.dim('to')} ${agent.name}${C.dim('...')}`);
    console.log('');

    // Use shared launcher — foreground for terminal agents, IDE open for others
    if (agent.cmd) {
      const copied = copyToClipboard(analysisPrompt);
      if (copied) {
        console.log(C.success(`  ✓ Prompt copied to clipboard (${analysisPrompt.length.toLocaleString()} chars)`));
      }
      console.log(`  ${C.dim('Launching')} ${agent.name} ${C.dim('in foreground...')}`);
      console.log('');
      const result = launchAgent(agent, analysisPrompt, ctx.root);
      if (result.error) {
        console.log(C.error(`  ✗ ${result.error}`));
      } else {
        console.log(`\n  ${C.success('✓')} ${agent.name} session ended.`);
        console.log(`  Run ${C.bold('/threat-reports')} to see saved results.`);
      }
    } else {
      const result = launchAgent(agent, analysisPrompt, ctx.root);
      if (result.clipboardCopied) {
        console.log(C.success(`  ✓ Prompt copied to clipboard (${analysisPrompt.length.toLocaleString()} chars)`));
      }
      if (result.launched && agent.app) {
        console.log(`  ${C.success('✓')} ${agent.name} launched with project: ${ctx.projectName}`);
        console.log(`\n  Paste (Cmd+V) the prompt in ${agent.name}.`);
      } else if (result.error) {
        console.log(C.error(`  ✗ ${result.error}`));
      }
    }
    console.log('');
    return;
  }

  // ── API path: direct LLM call ──
  const llmConfig = resolveLLMConfig(ctx.root);
  if (!llmConfig) {
    console.log(C.warn('  No AI provider configured. Run /model first, or use --claude-code / --codex.'));
    console.log(C.dim('  Or set ANTHROPIC_API_KEY / OPENAI_API_KEY in environment.'));
    return;
  }

  console.log(`  ${C.dim('Generating report with')} ${llmConfig.model}${C.dim('...')}`);
  console.log('');

  try {
    const result = await generateThreatReport({
      root: ctx.root,
      model: ctx.model,
      framework: fw,
      llmConfig,
      customPrompt,
      stream: true,
      onChunk: (text) => process.stdout.write(text),
    });

    process.stdout.write('\n');
    console.log('');
    console.log(`  ${C.success('✓')} Report saved to ${result.savedTo}`);
    if (result.inputTokens || result.outputTokens) {
      console.log(C.dim(`    Tokens: ${result.inputTokens || '?'} in / ${result.outputTokens || '?'} out`));
    }
    console.log('');
  } catch (err: any) {
    console.log(C.error(`\n  ✗ Threat report failed: ${err.message}`));
    console.log('');
  }
}

// ─── /threat-reports ─────────────────────────────────────────────────

export function cmdThreatReports(ctx: TuiContext): void {
  const reports = listThreatReports(ctx.root);
  if (reports.length === 0) {
    console.log('');
    console.log(C.dim('  No saved threat reports yet.'));
    console.log(C.dim('  Run /threat-report <framework> to generate one.'));
    console.log('');
    return;
  }

  console.log('');
  console.log(C.bold(`  ${reports.length} saved threat report(s)`));
  console.log('');

  for (const r of reports) {
    const model = r.model ? C.dim(` (${r.model})`) : '';
    const dirLabel = r.dirName || 'threat-reports';
    const path = `.guardlink/${dirLabel}/${r.filename}`;
    console.log(`  ${C.cyan(r.timestamp)}  ${C.bold(r.label)}${model}`);
    console.log(`    ${C.dim(fileLink(path, undefined, ctx.root))}`);
  }
  console.log('');
}

// ─── /annotate ───────────────────────────────────────────────────────

export async function cmdAnnotate(args: string, ctx: TuiContext): Promise<void> {
  const { agent: flagAgent, cleanArgs } = parseAgentFlag(args);

  if (!cleanArgs.trim()) {
    console.log(C.warn('  Usage: /annotate <prompt> [--claude-code|--codex|--gemini|--cursor|--windsurf|--clipboard]'));
    console.log(C.dim('  Example: /annotate "annotate auth endpoints for OWASP Top 10" --claude-code'));
    return;
  }

  console.log('');

  // Resolve agent: flag takes priority, otherwise interactive picker
  const agent = flagAgent || await pickAgent(ctx);
  if (!agent) return;

  // Build context prompt using shared builder
  const prompt = buildAnnotatePrompt(cleanArgs.trim(), ctx.root, ctx.model);

  // For terminal agents: foreground spawn (agent takes over terminal)
  if (agent.cmd) {
    const copied = copyToClipboard(prompt);
    if (copied) {
      console.log(C.success(`  ✓ Prompt copied to clipboard (${prompt.length.toLocaleString()} chars)`));
    }
    console.log(`  ${C.dim('Launching')} ${agent.name} ${C.dim('in foreground...')}`);
    console.log(`  ${C.dim('Exit the agent to return to GuardLink TUI.')}`);
    console.log('');

    const result = launchAgent(agent, prompt, ctx.root);

    if (result.error) {
      console.log(C.error(`  ✗ ${result.error}`));
      if (result.clipboardCopied) {
        console.log(C.dim('  Prompt is on your clipboard — paste it manually.'));
      }
    } else {
      console.log('');
      console.log(C.success(`  ✓ ${agent.name} session ended.`));
      console.log(`  Run ${C.bold('/parse')} to update the threat model.`);
    }
  } else {
    // IDE or clipboard — copies + opens app
    const result = launchAgent(agent, prompt, ctx.root);

    if (result.clipboardCopied) {
      console.log(C.success(`  ✓ Prompt copied to clipboard (${prompt.length.toLocaleString()} chars)`));
    }

    if (result.launched && agent.app) {
      console.log(`  ${C.success('✓')} ${agent.name} launched with project: ${ctx.projectName}`);
      console.log('');
      console.log(`  ${C.bold('1.')} In ${agent.name}, open the AI Chat/Composer panel`);
      console.log(`  ${C.bold('2.')} ${C.green('Paste (Cmd+V)')} the prompt`);
      console.log(`  ${C.bold('3.')} When done, run ${C.bold('/parse')} to update the model`);
    } else if (result.error) {
      console.log(C.error(`  ✗ ${result.error}`));
    } else if (agent.id === 'clipboard') {
      console.log(C.dim('  Paste the prompt into your preferred AI tool.'));
      console.log(`  When done, run ${C.bold('/parse')} to update the model.`);
    }
  }
  console.log('');
}

// ─── Freeform AI Chat ────────────────────────────────────────────────

export async function cmdChat(text: string, ctx: TuiContext): Promise<void> {
  const llmConfig = resolveLLMConfig(ctx.root);
  if (!llmConfig) {
    console.log(C.warn('  No AI provider configured. Run /model first, or set an API key in environment.'));
    return;
  }

  // Build system prompt with model context
  let systemPrompt = `You are a security expert helping a developer understand their project's threat model.
Answer concisely and directly. Reference specific assets, threats, and exposures from the model when relevant.
Keep responses under 500 words unless the user asks for detail.`;

  let userMessage = text;
  if (ctx.model) {
    // Serialize compact model for context
    const compact: any = {
      project: ctx.model.project,
      annotations: ctx.model.annotations_parsed,
      assets: ctx.model.assets.map(a => a.path.join('.')),
      threats: ctx.model.threats.map(t => ({ name: t.name, id: t.id, severity: t.severity })),
      exposures: ctx.model.exposures.map(e => ({ asset: e.asset, threat: e.threat, severity: e.severity, file: e.location.file })),
      mitigations: ctx.model.mitigations.map(m => ({ asset: m.asset, threat: m.threat, control: m.control })),
      controls: ctx.model.controls.map(c => ({ name: c.name, id: c.id })),
      flows: ctx.model.flows.map(f => ({ source: f.source, target: f.target, mechanism: f.mechanism })),
    };
    userMessage = `Threat model context:\n${JSON.stringify(compact, null, 2)}\n\nUser question: ${text}`;
  }

  console.log('');
  console.log(C.dim(`  Thinking via ${llmConfig.model}...`));
  console.log('');

  try {
    const { chatCompletion } = await import('../analyze/llm.js');
    const response = await chatCompletion(
      llmConfig,
      systemPrompt,
      userMessage,
      (chunk) => process.stdout.write(chunk),
    );

    process.stdout.write('\n\n');
  } catch (err: any) {
    console.log(C.error(`  ✗ AI request failed: ${err.message}`));
    console.log('');
  }
}

// ─── /report ─────────────────────────────────────────────────────────

export async function cmdReport(ctx: TuiContext): Promise<void> {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const report = generateReport(ctx.model);
  const outFile = resolve(ctx.root, 'threat-model.md');
  const { writeFile } = await import('node:fs/promises');
  await writeFile(outFile, report + '\n');
  console.log(`  ${C.success('✓')} Report written to threat-model.md`);

  // Also write JSON
  const jsonFile = resolve(ctx.root, 'threat-model.json');
  await writeFile(jsonFile, JSON.stringify(ctx.model, null, 2) + '\n');
  console.log(`  ${C.success('✓')} JSON written to threat-model.json`);
  console.log('');
}

// ─── /dashboard ──────────────────────────────────────────────────────

export async function cmdDashboard(ctx: TuiContext): Promise<void> {
  if (!ctx.model) {
    console.log(C.warn('  No threat model. Run /parse first.'));
    return;
  }

  const analyses = loadThreatReportsForDashboard(ctx.root);
  const html = generateDashboardHTML(ctx.model, ctx.root, analyses);
  const outFile = resolve(ctx.root, 'threat-dashboard.html');
  const { writeFile } = await import('node:fs/promises');
  await writeFile(outFile, html);
  console.log(`  ${C.success('✓')} Dashboard generated: threat-dashboard.html`);

  // Open in browser
  try {
    const { exec } = await import('node:child_process');
    const openCmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    exec(`${openCmd} "${outFile}"`);
    console.log(C.dim('    Opened in browser.'));
  } catch {
    console.log(C.dim('    Open the file in your browser.'));
  }
  console.log('');
}
