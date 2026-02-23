/**
 * GuardLink Threat Reports — AI-powered threat model analysis.
 *
 * Serializes the threat model, sends it to an LLM with a framework-
 * specific prompt, streams the response, and saves timestamped results
 * to .guardlink/threat-reports/.
 *
 * @exposes #llm-client to #arbitrary-write [high] cwe:CWE-73 -- "Writes threat reports to .guardlink/threat-reports/"
 * @exposes #llm-client to #prompt-injection [medium] cwe:CWE-77 -- "Serialized threat model embedded in LLM prompt"
 * @accepts #prompt-injection on #llm-client -- "Core feature: threat model serialized as LLM prompt for analysis"
 * @mitigates #llm-client against #arbitrary-write using #path-validation -- "Reports written to fixed .guardlink/threat-reports/ subdirectory"
 * @flows #parser -> #llm-client via ThreatModel -- "Parsed model data serialized for LLM analysis"
 * @flows #llm-client -> Filesystem via writeFileSync -- "Analysis results saved as markdown files"
 * @handles internal on #llm-client -- "Processes security-sensitive threat model for AI analysis"
 */

import { existsSync, mkdirSync, writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import type { ThreatModel } from '../types/index.js';
import { type AnalysisFramework, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage } from './prompts.js';
import { type LLMConfig, buildConfig, chatCompletion } from './llm.js';
import { GUARDLINK_TOOLS, createToolExecutor } from './tools.js';

export { type AnalysisFramework, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage } from './prompts.js';
export { type LLMConfig, type LLMProvider, buildConfig, autoDetectConfig } from './llm.js';
export { GUARDLINK_TOOLS, createToolExecutor } from './tools.js';
export type { ToolDefinition, ToolCall, ToolResult, ToolExecutor } from './llm.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface ThreatReportOptions {
  root: string;
  model: ThreatModel;
  framework: AnalysisFramework;
  llmConfig: LLMConfig;
  customPrompt?: string;
  stream?: boolean;
  onChunk?: (text: string) => void;
  /** Max lines of context to include around each annotated line (default: 8) */
  snippetContext?: number;
  /** Max total characters for all code snippets combined (default: 40000) */
  snippetBudget?: number;
  /** Enable web search grounding (OpenAI Responses API) */
  webSearch?: boolean;
  /** Enable extended thinking (Anthropic) / reasoning (DeepSeek) */
  extendedThinking?: boolean;
  /** Token budget for thinking (default: 10000) */
  thinkingBudget?: number;
  /** Enable agentic tool use (CVE lookup, model validation, codebase search) */
  enableTools?: boolean;
}

export interface ThreatReportResult {
  framework: AnalysisFramework;
  label: string;
  content: string;
  model: string;
  timestamp: string;
  savedTo?: string;
  inputTokens?: number;
  outputTokens?: number;
  /** Thinking/reasoning content (if extended thinking was enabled) */
  thinking?: string;
  thinkingTokens?: number;
}

// ─── Project context builder ─────────────────────────────────────────

/**
 * Collect project-level context for the LLM: language/framework, key
 * dependencies, and deployment signals (Dockerfile, CI, etc.).
 * Keeps output compact — targets ~2-4 KB.
 */
export function buildProjectContext(root: string): string {
  const lines: string[] = [];

  // package.json — language, framework, key deps
  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      lines.push(`## package.json`);
      if (pkg.name) lines.push(`name: ${pkg.name}`);
      if (pkg.version) lines.push(`version: ${pkg.version}`);
      if (pkg.description) lines.push(`description: ${pkg.description}`);

      const allDeps: Record<string, string> = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };
      if (Object.keys(allDeps).length) {
        lines.push(`dependencies (${Object.keys(allDeps).length} total):`);
        // Include all deps — LLM needs them to reason about known-vulnerable packages
        for (const [name, ver] of Object.entries(allDeps)) {
          lines.push(`  ${name}: ${ver}`);
        }
      }

      if (pkg.scripts && Object.keys(pkg.scripts).length) {
        lines.push(`scripts: ${Object.keys(pkg.scripts).join(', ')}`);
      }
      if (pkg.engines) lines.push(`engines: ${JSON.stringify(pkg.engines)}`);
      lines.push('');
    } catch { /* skip malformed */ }
  }

  // requirements.txt — Python projects
  const reqPath = join(root, 'requirements.txt');
  if (existsSync(reqPath)) {
    try {
      const reqs = readFileSync(reqPath, 'utf-8').trim();
      lines.push('## requirements.txt');
      lines.push(reqs);
      lines.push('');
    } catch { /* skip */ }
  }

  // pyproject.toml — Python projects
  const pyprojectPath = join(root, 'pyproject.toml');
  if (existsSync(pyprojectPath)) {
    try {
      const content = readFileSync(pyprojectPath, 'utf-8');
      // Extract just the [tool.poetry.dependencies] or [project] section
      const depsMatch = content.match(/\[(?:tool\.poetry\.)?dependencies\][\s\S]*?(?=\[|$)/m);
      if (depsMatch) {
        lines.push('## pyproject.toml (dependencies)');
        lines.push(depsMatch[0].trim());
        lines.push('');
      }
    } catch { /* skip */ }
  }

  // go.mod — Go projects
  const gomodPath = join(root, 'go.mod');
  if (existsSync(gomodPath)) {
    try {
      const content = readFileSync(gomodPath, 'utf-8');
      lines.push('## go.mod');
      lines.push(content.trim());
      lines.push('');
    } catch { /* skip */ }
  }

  // Dockerfile — deployment model
  for (const name of ['Dockerfile', 'Dockerfile.prod', 'Dockerfile.production']) {
    const dfPath = join(root, name);
    if (existsSync(dfPath)) {
      try {
        const content = readFileSync(dfPath, 'utf-8').trim();
        lines.push(`## ${name}`);
        lines.push(content);
        lines.push('');
        break;
      } catch { /* skip */ }
    }
  }

  // docker-compose.yml — service topology
  for (const name of ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']) {
    const dcPath = join(root, name);
    if (existsSync(dcPath)) {
      try {
        const content = readFileSync(dcPath, 'utf-8').trim();
        lines.push(`## ${name}`);
        // Cap at 100 lines to avoid blowing token budget
        const dcLines = content.split('\n');
        lines.push(dcLines.slice(0, 100).join('\n'));
        if (dcLines.length > 100) lines.push(`... (${dcLines.length - 100} more lines)`);
        lines.push('');
        break;
      } catch { /* skip */ }
    }
  }

  // CI config — deployment signals
  const ciFiles = [
    '.github/workflows',
    '.gitlab-ci.yml',
    '.circleci/config.yml',
    'Jenkinsfile',
    '.travis.yml',
  ];
  for (const ci of ciFiles) {
    const ciPath = join(root, ci);
    if (existsSync(ciPath)) {
      lines.push(`## CI/CD: ${ci} (detected)`);
      // Don't include full CI content — just note its presence
    }
  }

  // .env.example — environment variable signals
  for (const name of ['.env.example', '.env.sample', '.env.template']) {
    const envPath = join(root, name);
    if (existsSync(envPath)) {
      try {
        const content = readFileSync(envPath, 'utf-8').trim();
        lines.push(`## ${name} (environment variables)`);
        lines.push(content);
        lines.push('');
        break;
      } catch { /* skip */ }
    }
  }

  return lines.join('\n').trim();
}

// ─── Code snippet extractor ──────────────────────────────────────────

/**
 * Extract source code snippets around annotated lines.
 *
 * For each annotation that has a file + line location, reads the
 * surrounding `contextLines` lines from disk and returns a formatted
 * block. Deduplicates overlapping ranges within the same file.
 * Respects a total character budget to keep token usage bounded.
 */
export function extractCodeSnippets(
  root: string,
  model: ThreatModel,
  contextLines = 8,
  budgetChars = 40_000,
): string {
  // Collect all (file, line) pairs from security-relevant annotations.
  // Prioritize: exposures > mitigations > acceptances > assumptions > flows/boundaries
  type AnnotationRef = { file: string; line: number; label: string };
  const refs: AnnotationRef[] = [];

  for (const e of model.exposures) {
    refs.push({ file: e.location.file, line: e.location.line, label: `@exposes ${e.asset} to ${e.threat} [${e.severity ?? 'unset'}]` });
  }
  for (const m of model.mitigations) {
    refs.push({ file: m.location.file, line: m.location.line, label: `@mitigates ${m.asset} against ${m.threat}` });
  }
  for (const a of model.acceptances) {
    refs.push({ file: a.location.file, line: a.location.line, label: `@accepts ${a.threat} on ${a.asset}` });
  }
  for (const a of model.assumptions) {
    refs.push({ file: a.location.file, line: a.location.line, label: `@assumes on ${a.asset}` });
  }
  for (const b of model.boundaries) {
    refs.push({ file: b.location.file, line: b.location.line, label: `@boundary ${b.asset_a} | ${b.asset_b}` });
  }
  for (const f of model.flows) {
    refs.push({ file: f.location.file, line: f.location.line, label: `@flows ${f.source} -> ${f.target}` });
  }

  // Group by file, merge overlapping line ranges
  const byFile = new Map<string, Array<{ start: number; end: number; labels: string[] }>>();
  for (const ref of refs) {
    if (!ref.file || !ref.line) continue;
    const absFile = ref.file.startsWith('/') ? ref.file : join(root, ref.file);
    const start = Math.max(1, ref.line - contextLines);
    const end = ref.line + contextLines;

    if (!byFile.has(absFile)) byFile.set(absFile, []);
    const ranges = byFile.get(absFile)!;

    // Merge with existing range if overlapping
    let merged = false;
    for (const r of ranges) {
      if (start <= r.end + 1 && end >= r.start - 1) {
        r.start = Math.min(r.start, start);
        r.end = Math.max(r.end, end);
        r.labels.push(ref.label);
        merged = true;
        break;
      }
    }
    if (!merged) ranges.push({ start, end, labels: [ref.label] });
  }

  const blocks: string[] = [];
  let totalChars = 0;

  for (const [absFile, ranges] of byFile) {
    if (totalChars >= budgetChars) break;
    if (!existsSync(absFile)) continue;

    let fileLines: string[];
    try {
      fileLines = readFileSync(absFile, 'utf-8').split('\n');
    } catch { continue; }

    const relPath = relative(root, absFile);
    ranges.sort((a, b) => a.start - b.start);

    for (const range of ranges) {
      if (totalChars >= budgetChars) break;

      const from = Math.max(0, range.start - 1);
      const to = Math.min(fileLines.length, range.end);
      const snippet = fileLines.slice(from, to)
        .map((l, i) => `${String(from + i + 1).padStart(4)} | ${l}`)
        .join('\n');

      const uniqueLabels = [...new Set(range.labels)];
      const block = `### ${relPath}:${range.start}-${range.end}
// Annotations: ${uniqueLabels.join('; ')}
\`\`\`
${snippet}
\`\`\``;

      if (totalChars + block.length > budgetChars) {
        // Include a truncated note and stop
        blocks.push(`### ${relPath}:${range.start}-${range.end}
// [snippet omitted — budget exhausted]`);
        totalChars = budgetChars;
        break;
      }

      blocks.push(block);
      totalChars += block.length;
    }
  }

  return blocks.join('\n\n');
}

// ─── Serialization ───────────────────────────────────────────────────

/**
 * Serialize the threat model to a compact representation for LLM context.
 * Includes file:line locations for all security-relevant annotations so
 * the LLM can cross-reference with code snippets.
 */
export function serializeModel(model: ThreatModel): string {
  const compact: Record<string, any> = {
    project: model.project,
    annotations: model.annotations_parsed,
    source_files: model.source_files,
  };

  // Only include non-empty sections
  if (model.assets.length) compact.assets = model.assets.map(a => ({
    path: a.path.join('.'), id: a.id, description: a.description,
    file: a.location.file, line: a.location.line,
  }));
  if (model.threats.length) compact.threats = model.threats.map(t => ({
    name: t.name, id: t.id, severity: t.severity,
    refs: t.external_refs.length ? t.external_refs : undefined,
    description: t.description,
    file: t.location.file, line: t.location.line,
  }));
  if (model.controls.length) compact.controls = model.controls.map(c => ({
    name: c.name, id: c.id, description: c.description,
    file: c.location.file, line: c.location.line,
  }));
  if (model.mitigations.length) compact.mitigations = model.mitigations.map(m => ({
    asset: m.asset, threat: m.threat, control: m.control,
    description: m.description,
    file: m.location.file, line: m.location.line,
  }));
  if (model.exposures.length) compact.exposures = model.exposures.map(e => ({
    asset: e.asset, threat: e.threat, severity: e.severity,
    refs: e.external_refs.length ? e.external_refs : undefined,
    description: e.description,
    file: e.location.file, line: e.location.line,
  }));
  if (model.acceptances.length) compact.acceptances = model.acceptances.map(a => ({
    asset: a.asset, threat: a.threat, description: a.description,
    file: a.location.file, line: a.location.line,
  }));
  if (model.transfers.length) compact.transfers = model.transfers.map(t => ({
    threat: t.threat, source: t.source, target: t.target,
    file: t.location.file, line: t.location.line,
  }));
  if (model.flows.length) compact.flows = model.flows.map(f => ({
    source: f.source, target: f.target, mechanism: f.mechanism,
    file: f.location.file, line: f.location.line,
  }));
  if (model.boundaries.length) compact.boundaries = model.boundaries.map(b => ({
    a: b.asset_a, b: b.asset_b, id: b.id, description: b.description,
    file: b.location.file, line: b.location.line,
  }));
  if (model.data_handling.length) compact.data_handling = model.data_handling.map(h => ({
    classification: h.classification, asset: h.asset,
    file: h.location.file, line: h.location.line,
  }));
  if (model.assumptions.length) compact.assumptions = model.assumptions.map(a => ({
    asset: a.asset, description: a.description,
    file: a.location.file, line: a.location.line,
  }));
  if (model.comments.length) compact.comments = model.comments.map(c => ({
    description: c.description, file: c.location.file, line: c.location.line,
  }));
  if (model.validations.length) compact.validations = model.validations.map(v => ({
    control: v.control, asset: v.asset,
    file: v.location.file, line: v.location.line,
  }));

  // Coverage summary — include unannotated critical symbols so LLM sees gaps
  compact.coverage = {
    total_symbols: model.coverage.total_symbols,
    annotated: model.coverage.annotated_symbols,
    percent: model.coverage.coverage_percent,
    unannotated_critical: model.coverage.unannotated_critical,
  };

  // Unmitigated exposures summary
  const mitigatedSet = new Set<string>();
  for (const m of model.mitigations) mitigatedSet.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) mitigatedSet.add(`${a.asset}::${a.threat}`);
  const unmitigated = model.exposures.filter(e => !mitigatedSet.has(`${e.asset}::${e.threat}`));
  if (unmitigated.length) {
    compact.unmitigated_exposures = unmitigated.map(e => ({
      asset: e.asset, threat: e.threat, severity: e.severity,
      file: e.location.file, line: e.location.line,
    }));
  }

  return JSON.stringify(compact, null, 2);
}

/**
 * Compact serialization for MCP agent mode.
 *
 * Designed to minimize token usage (~2-3k tokens vs ~10k for full)
 * while giving the agent everything it needs:
 *   - Stats summary (one line)
 *   - Asset list (compact)
 *   - ALL unmitigated exposures (the actionable stuff)
 *   - Threat severity index (deduped)
 *   - Flows & boundaries (structural context)
 *   - Data handling classifications
 *
 * Omits: resolved mitigations, acceptances, working controls,
 * full descriptions (capped at 80 chars), per-exposure file paths,
 * comments, validations, assumptions (low signal for analysis).
 *
 * The agent can call guardlink_parse or read guardlink://model
 * for full detail if needed.
 */
export function serializeModelCompact(model: ThreatModel): string {
  // Compute unmitigated set
  const covered = new Set<string>();
  for (const m of model.mitigations) covered.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) covered.add(`${a.asset}::${a.threat}`);
  const unmitigated = model.exposures.filter(e => !covered.has(`${e.asset}::${e.threat}`));

  const cap = (s: string | undefined, n = 80) =>
    s && s.length > n ? s.slice(0, n - 1) + '…' : s;

  // Severity counts
  const sevCounts: Record<string, number> = {};
  for (const e of unmitigated) {
    const s = e.severity || 'unset';
    sevCounts[s] = (sevCounts[s] || 0) + 1;
  }

  const compact: Record<string, any> = {
    project: model.project,
    summary: `${model.annotations_parsed} annotations, ${model.assets.length} assets, ${model.threats.length} threats, ${model.controls.length} controls, ${model.exposures.length} exposures (${unmitigated.length} unmitigated), ${model.mitigations.length} mitigations`,
    severity_breakdown: sevCounts,
  };

  // Assets — just path + id, no descriptions
  if (model.assets.length) {
    compact.assets = model.assets.map(a => a.id || a.path.join('.'));
  }

  // Unmitigated exposures — grouped by asset for compactness
  if (unmitigated.length) {
    const byAsset: Record<string, any[]> = {};
    for (const e of unmitigated) {
      const key = e.asset;
      if (!byAsset[key]) byAsset[key] = [];
      const entry: Record<string, any> = { threat: e.threat, severity: e.severity };
      if (e.external_refs.length) entry.refs = e.external_refs;
      if (e.description) entry.desc = cap(e.description);
      byAsset[key].push(entry);
    }
    compact.unmitigated = byAsset;
  }

  // Threat index — deduped, severity + refs only
  if (model.threats.length) {
    compact.threats = model.threats.map(t => {
      const entry: Record<string, any> = { id: t.id, severity: t.severity };
      if (t.external_refs.length) entry.refs = t.external_refs;
      return entry;
    });
  }

  // Flows & boundaries — structural context for attack path analysis
  if (model.flows.length) {
    compact.flows = model.flows.map(f => `${f.source} → ${f.target}${f.mechanism ? ' via ' + f.mechanism : ''}`);
  }
  if (model.boundaries.length) {
    compact.boundaries = model.boundaries.map(b => `${b.asset_a} | ${b.asset_b}${b.description ? ': ' + cap(b.description, 40) : ''}`);
  }

  // Data handling — classification matters for compliance analysis
  if (model.data_handling.length) {
    compact.data_handling = model.data_handling.map(h => `${h.asset}: ${h.classification}`);
  }

  // Mitigation count per asset (not full details — just "how defended is each asset?")
  if (model.mitigations.length) {
    const mitByAsset: Record<string, number> = {};
    for (const m of model.mitigations) mitByAsset[m.asset] = (mitByAsset[m.asset] || 0) + 1;
    compact.mitigations_per_asset = mitByAsset;
  }

  return JSON.stringify(compact, null, 2);
}

// ─── Threat report generation ────────────────────────────────────────

/** Storage directory for threat reports (new path) */
const THREAT_REPORTS_DIR = 'threat-reports';
/** Legacy storage directory (read fallback) */
const LEGACY_ANALYSES_DIR = 'analyses';

export async function generateThreatReport(opts: ThreatReportOptions): Promise<ThreatReportResult> {
  const { root, model, framework, llmConfig, customPrompt } = opts;
  const snippetContext = opts.snippetContext ?? 8;
  const snippetBudget = opts.snippetBudget ?? 40_000;

  const modelJson = serializeModel(model);
  const projectContext = buildProjectContext(root);
  const codeSnippets = extractCodeSnippets(root, model, snippetContext, snippetBudget);
  const systemPrompt = FRAMEWORK_PROMPTS[framework];
  const userMessage = buildUserMessage(modelJson, framework, customPrompt, projectContext || undefined, codeSnippets || undefined);

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

  // Build enhanced config with optional upgrades
  const enhancedConfig: LLMConfig = { ...llmConfig };
  if (opts.webSearch) enhancedConfig.webSearch = true;
  if (opts.extendedThinking) {
    enhancedConfig.extendedThinking = true;
    if (opts.thinkingBudget) enhancedConfig.thinkingBudget = opts.thinkingBudget;
  }
  if (opts.enableTools !== false) {
    enhancedConfig.tools = GUARDLINK_TOOLS;
    enhancedConfig.toolExecutor = createToolExecutor(root, model);
  }

  // Call LLM
  const response = await chatCompletion(
    enhancedConfig,
    systemPrompt,
    userMessage,
    opts.stream ? opts.onChunk : undefined,
  );

  // Save to .guardlink/threat-reports/
  const reportsDir = join(root, '.guardlink', THREAT_REPORTS_DIR);
  if (!existsSync(reportsDir)) {
    mkdirSync(reportsDir, { recursive: true });
  }

  const filename = `${timestamp}-${framework}.md`;
  const filepath = join(reportsDir, filename);

  const header = `---
framework: ${framework}
label: ${FRAMEWORK_LABELS[framework]}
model: ${response.model}
timestamp: ${new Date().toISOString()}
input_tokens: ${response.inputTokens || 'unknown'}
output_tokens: ${response.outputTokens || 'unknown'}
project: ${model.project}
annotations: ${model.annotations_parsed}
---

# ${FRAMEWORK_LABELS[framework]}

> Generated by \`guardlink threat-report ${framework}\` on ${new Date().toISOString().slice(0, 10)}
> Model: ${response.model} | Project: ${model.project} | Annotations: ${model.annotations_parsed}

`;

  writeFileSync(filepath, header + response.content + '\n');

  return {
    framework,
    label: FRAMEWORK_LABELS[framework],
    content: response.content,
    model: response.model,
    timestamp,
    savedTo: `.guardlink/${THREAT_REPORTS_DIR}/${filename}`,
    inputTokens: response.inputTokens,
    outputTokens: response.outputTokens,
    thinking: response.thinking,
    thinkingTokens: response.thinkingTokens,
  };
}

// ─── List saved threat reports ───────────────────────────────────────

export interface SavedThreatReport {
  filename: string;
  framework: string;
  timestamp: string;
  label: string;
  model?: string;
  /** Which directory this report was found in */
  dirName?: string;
}

/** Read .md files from a .guardlink subdirectory */
function readReportsFromDir(dirPath: string, dirName: string): SavedThreatReport[] {
  if (!existsSync(dirPath)) return [];
  return readdirSync(dirPath)
    .filter(f => f.endsWith('.md'))
    .map(filename => {
      const match = filename.match(/^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})-(\w+)\.md$/);
      const framework = match?.[2] || 'unknown';
      const timestamp = match?.[1]?.replace(/T/, ' ').replace(/-/g, (m, offset) => offset > 9 ? ':' : '-') || filename;

      let model: string | undefined;
      try {
        const content = readFileSync(join(dirPath, filename), 'utf-8');
        const modelMatch = content.match(/^model:\s*(.+)$/m);
        if (modelMatch) model = modelMatch[1].trim();
      } catch { /* ignore */ }

      return {
        filename,
        framework,
        timestamp,
        label: FRAMEWORK_LABELS[framework as AnalysisFramework] || framework,
        model,
        dirName,
      };
    });
}

export function listThreatReports(root: string): SavedThreatReport[] {
  // Read from new path first, then legacy, merge and dedup by filename
  const newDir = join(root, '.guardlink', THREAT_REPORTS_DIR);
  const legacyDir = join(root, '.guardlink', LEGACY_ANALYSES_DIR);

  const reports = readReportsFromDir(newDir, THREAT_REPORTS_DIR);
  const legacy = readReportsFromDir(legacyDir, LEGACY_ANALYSES_DIR);

  // Merge: new path takes precedence if same filename exists in both
  const seen = new Set(reports.map(r => r.filename));
  for (const l of legacy) {
    if (!seen.has(l.filename)) reports.push(l);
  }

  return reports.sort((a, b) => b.filename.localeCompare(a.filename));
}

// ─── Load reports with content (for dashboard embedding) ─────────────

export interface ThreatReportWithContent extends SavedThreatReport {
  content: string;
}

const MAX_REPORTS_IN_DASHBOARD = 50;

export function loadThreatReportsForDashboard(root: string): ThreatReportWithContent[] {
  const entries = listThreatReports(root).slice(0, MAX_REPORTS_IN_DASHBOARD);
  const result: ThreatReportWithContent[] = [];

  for (const entry of entries) {
    const dir = join(root, '.guardlink', entry.dirName || THREAT_REPORTS_DIR);
    try {
      const raw = readFileSync(join(dir, entry.filename), 'utf-8');
      const content = raw.replace(/^---[\s\S]*?---\n*/, '').trim();
      if (content) result.push({ ...entry, content });
    } catch { /* skip unreadable files */ }
  }

  return result;
}
