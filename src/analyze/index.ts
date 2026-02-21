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
import { join } from 'node:path';
import type { ThreatModel } from '../types/index.js';
import { type AnalysisFramework, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage } from './prompts.js';
import { type LLMConfig, buildConfig, chatCompletion } from './llm.js';

export { type AnalysisFramework, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage } from './prompts.js';
export { type LLMConfig, type LLMProvider, buildConfig, autoDetectConfig } from './llm.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface ThreatReportOptions {
  root: string;
  model: ThreatModel;
  framework: AnalysisFramework;
  llmConfig: LLMConfig;
  customPrompt?: string;
  stream?: boolean;
  onChunk?: (text: string) => void;
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
}

// ─── Serialization ───────────────────────────────────────────────────

/**
 * Serialize the threat model to a compact representation for LLM context.
 * Strips empty arrays and location details to save tokens.
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
  }));
  if (model.threats.length) compact.threats = model.threats.map(t => ({
    name: t.name, id: t.id, severity: t.severity,
    refs: t.external_refs.length ? t.external_refs : undefined,
    description: t.description,
  }));
  if (model.controls.length) compact.controls = model.controls.map(c => ({
    name: c.name, id: c.id, description: c.description,
  }));
  if (model.mitigations.length) compact.mitigations = model.mitigations.map(m => ({
    asset: m.asset, threat: m.threat, control: m.control,
    description: m.description, file: m.location.file,
  }));
  if (model.exposures.length) compact.exposures = model.exposures.map(e => ({
    asset: e.asset, threat: e.threat, severity: e.severity,
    refs: e.external_refs.length ? e.external_refs : undefined,
    description: e.description, file: e.location.file,
  }));
  if (model.acceptances.length) compact.acceptances = model.acceptances.map(a => ({
    asset: a.asset, threat: a.threat, description: a.description,
  }));
  if (model.transfers.length) compact.transfers = model.transfers.map(t => ({
    threat: t.threat, source: t.source, target: t.target,
  }));
  if (model.flows.length) compact.flows = model.flows.map(f => ({
    source: f.source, target: f.target, mechanism: f.mechanism,
  }));
  if (model.boundaries.length) compact.boundaries = model.boundaries.map(b => ({
    a: b.asset_a, b: b.asset_b, id: b.id, description: b.description,
  }));
  if (model.data_handling.length) compact.data_handling = model.data_handling.map(h => ({
    classification: h.classification, asset: h.asset,
  }));
  if (model.assumptions.length) compact.assumptions = model.assumptions.map(a => ({
    asset: a.asset, description: a.description,
  }));
  if (model.comments.length) compact.comments = model.comments.map(c => ({
    description: c.description, file: c.location.file,
  }));
  if (model.validations.length) compact.validations = model.validations.map(v => ({
    control: v.control, asset: v.asset,
  }));

  // Coverage summary
  compact.coverage = {
    total_symbols: model.coverage.total_symbols,
    annotated: model.coverage.annotated_symbols,
    percent: model.coverage.coverage_percent,
  };

  // Unmitigated exposures summary
  const mitigatedSet = new Set<string>();
  for (const m of model.mitigations) mitigatedSet.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) mitigatedSet.add(`${a.asset}::${a.threat}`);
  const unmitigated = model.exposures.filter(e => !mitigatedSet.has(`${e.asset}::${e.threat}`));
  if (unmitigated.length) {
    compact.unmitigated_exposures = unmitigated.map(e => ({
      asset: e.asset, threat: e.threat, severity: e.severity,
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

  const modelJson = serializeModel(model);
  const systemPrompt = FRAMEWORK_PROMPTS[framework];
  const userMessage = buildUserMessage(modelJson, framework, customPrompt);

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

  // Call LLM
  const response = await chatCompletion(
    llmConfig,
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
