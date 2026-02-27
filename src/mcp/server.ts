/**
 * GuardLink MCP Server — Model Context Protocol integration (§8.2).
 *
 * Tools:
 *   guardlink_parse    — Parse annotations, return threat model
 *   guardlink_status   — Coverage stats and unmitigated exposures
 *   guardlink_validate — Syntax errors and dangling references
 *   guardlink_suggest  — Given a code diff or file, suggest annotations
 *   guardlink_lookup   — Query the threat model graph
 *   guardlink_threat_report — AI threat report generation (STRIDE, DREAD, etc.)
 *   guardlink_annotate — Build annotation prompt for the calling agent
 *   guardlink_report   — Generate markdown report + JSON
 *   guardlink_dashboard — Generate HTML threat model dashboard
 *   guardlink_sarif    — Export SARIF 2.1.0
 *   guardlink_diff     — Compare threat model against a git ref
 *   guardlink_threat_reports — List saved AI threat report files
 *
 * Resources:
 *   guardlink://model        — Full ThreatModel JSON
 *   guardlink://definitions  — Assets, threats, controls
 *   guardlink://unmitigated  — Unmitigated exposures list
 *
 * Transport: stdio (for Claude Code .mcp.json, Cursor, etc.)
 *
 * @exposes #mcp to #path-traversal [high] cwe:CWE-22 -- "Tool arguments include 'root' directory path from external client"
 * @mitigates #mcp against #path-traversal using #path-validation -- "Zod schema validates root; resolve() canonicalizes"
 * @exposes #mcp to #arbitrary-write [high] cwe:CWE-73 -- "report, dashboard, sarif tools write files"
 * @mitigates #mcp against #arbitrary-write using #path-validation -- "Output paths resolved relative to validated root"
 * @exposes #mcp to #prompt-injection [medium] cwe:CWE-77 -- "annotate and threat_report tools pass user prompts to LLM"
 * @audit #mcp -- "User prompts passed to LLM; model context is read-only"
 * @exposes #mcp to #api-key-exposure [medium] cwe:CWE-798 -- "threat_report tool uses API keys from environment"
 * @mitigates #mcp against #api-key-exposure using #key-redaction -- "Keys from env only; never logged or returned"
 * @exposes #mcp to #data-exposure [medium] cwe:CWE-200 -- "Resources expose full threat model to MCP clients"
 * @audit #mcp -- "Threat model data intentionally exposed to connected agents"
 * @flows MCPClient -> #mcp via tool_call -- "Tool invocation input"
 * @flows #mcp -> FileSystem via writeFile -- "Report/dashboard output"
 * @flows #mcp -> #llm-client via generateThreatReport -- "LLM API call path"
 * @flows #mcp -> MCPClient via resource -- "Threat model data output"
 * @boundary #mcp and MCPClient (#mcp-tool-boundary) -- "Trust boundary at tool argument parsing"
 * @handles internal on #mcp -- "Processes project annotations and threat model data"
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { parseProject, findDanglingRefs, findUnmitigatedExposures, clearAnnotations } from '../parser/index.js';
import { getReviewableExposures, applyReviewAction, type ReviewableExposure } from '../review/index.js';
import { generateSarif } from '../analyzer/index.js';
import { generateReport } from '../report/index.js';
import { generateDashboardHTML } from '../dashboard/index.js';
import { diffModels, parseAtRef, formatDiffMarkdown } from '../diff/index.js';
import { lookup, type LookupQuery } from './lookup.js';
import { suggestAnnotations } from './suggest.js';
import { generateThreatReport, listThreatReports, loadThreatReportsForDashboard, buildConfig, serializeModel, serializeModelCompact, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage, type AnalysisFramework } from '../analyze/index.js';
import { buildAnnotatePrompt } from '../agents/prompts.js';
import { syncAgentFiles } from '../init/index.js';
import type { ThreatModel } from '../types/index.js';

// ─── Cached model ────────────────────────────────────────────────────

let cachedModel: ThreatModel | null = null;
let cachedDiagnostics: any[] = [];
let cachedRoot: string = '';

async function getModel(root: string): Promise<{ model: ThreatModel; diagnostics: any[] }> {
  if (cachedModel && cachedRoot === root) {
    return { model: cachedModel, diagnostics: cachedDiagnostics };
  }
  const result = await parseProject({ root, project: 'unknown' });
  cachedModel = result.model;
  cachedDiagnostics = result.diagnostics;
  cachedRoot = root;
  return result;
}

function invalidateCache() {
  cachedModel = null;
  cachedDiagnostics = [];
}

// ─── Server setup ────────────────────────────────────────────────────

export function createServer(): McpServer {
  const server = new McpServer({
    name: 'guardlink',
    version: '1.1.0',
  });

  // ── Tool: guardlink_parse ──
  server.tool(
    'guardlink_parse',
    'Parse GuardLink annotations from the project and return the full threat model as JSON',
    { root: z.string().describe('Project root directory').default('.') },
    async ({ root }) => {
      invalidateCache();
      const { model } = await getModel(root);
      return {
        content: [{ type: 'text', text: JSON.stringify(model, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_status ──
  server.tool(
    'guardlink_status',
    'Return coverage statistics: asset/threat/control counts, unmitigated exposures, coverage percentage',
    { root: z.string().describe('Project root directory').default('.') },
    async ({ root }) => {
      const { model } = await getModel(root);

      const unmitigated = findUnmitigatedExposures(model);

      const status = {
        assets: model.assets.length,
        threats: model.threats.length,
        controls: model.controls.length,
        mitigations: model.mitigations.length,
        exposures: model.exposures.length,
        acceptances: model.acceptances.length,
        flows: model.flows.length,
        boundaries: model.boundaries.length,
        unmitigated: unmitigated.map(e => ({
          asset: e.asset,
          threat: e.threat,
          severity: e.severity,
          file: e.location.file,
          line: e.location.line,
        })),
        coverage: model.coverage,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(status, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_validate ──
  server.tool(
    'guardlink_validate',
    'Check annotations for syntax errors, duplicate IDs, and dangling references. Returns structured error list.',
    { root: z.string().describe('Project root directory').default('.') },
    async ({ root }) => {
      invalidateCache();
      const { model, diagnostics } = await getModel(root);

      // Compute dangling refs using shared validation
      const danglingDiags = findDanglingRefs(model);
      const allDiags = [...diagnostics, ...danglingDiags];

      const errors = allDiags.filter(d => d.level === 'error');
      const warnings = allDiags.filter(d => d.level === 'warning');

      const result = {
        valid: errors.length === 0,
        errors: errors.map(d => ({ file: d.file, line: d.line, message: d.message })),
        warnings: warnings.map(d => ({ file: d.file, line: d.line, message: d.message })),
        summary: `${errors.length} error(s), ${warnings.length} warning(s)`,
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_suggest ──
  server.tool(
    'guardlink_suggest',
    'Given a file path or code diff, suggest appropriate GuardLink annotations based on code patterns, imports, and function signatures',
    {
      root: z.string().describe('Project root directory').default('.'),
      file: z.string().describe('File path relative to root to analyze').optional(),
      diff: z.string().describe('Git diff text to analyze for new code needing annotations').optional(),
    },
    async ({ root, file, diff }) => {
      const { model } = await getModel(root);
      const suggestions = await suggestAnnotations({ root, model, file, diff });
      return {
        content: [{ type: 'text', text: JSON.stringify(suggestions, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_lookup ──
  server.tool(
    'guardlink_lookup',
    'Query the threat model graph. Find assets, threats, controls, flows, exposures by ID or relationship. Examples: "what threats target #auth?", "flows into Scanner", "unmitigated exposures"',
    {
      root: z.string().describe('Project root directory').default('.'),
      query: z.string().describe('Natural language or structured query: asset ID, threat ID, "flows into X", "threats for X", "unmitigated", "controls for X"'),
    },
    async ({ root, query }) => {
      const { model } = await getModel(root);
      const result = lookup(model, query);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_threat_report ──
  server.tool(
    'guardlink_threat_report',
    'Generate an AI threat report using a security framework (STRIDE, DREAD, PASTA, attacker, rapid, general). If an LLM API key is set in environment, runs analysis internally and saves result. If no API key is set, returns the framework prompt and serialized threat model for the calling agent to analyze directly — write the result as markdown to .guardlink/threat-reports/.',
    {
      root: z.string().describe('Project root directory').default('.'),
      framework: z.enum(['stride', 'dread', 'pasta', 'attacker', 'rapid', 'general']).describe('Analysis framework').default('general'),
      provider: z.string().describe('LLM provider: anthropic, openai, google, openrouter, deepseek (auto-detected from env)').optional(),
      model: z.string().describe('Model name override').optional(),
      custom_prompt: z.string().describe('Custom analysis prompt to replace the framework header').optional(),
      web_search: z.boolean().describe('Enable web search grounding for real-time vulnerability intelligence (OpenAI)').optional(),
      thinking: z.boolean().describe('Enable extended thinking / reasoning mode (Anthropic, DeepSeek)').optional(),
    },
    async ({ root, framework, provider, model: modelName, custom_prompt, web_search, thinking }) => {
      const { model: threatModel } = await getModel(root);
      if (threatModel.annotations_parsed === 0) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            error: 'No annotations found. Add GuardLink annotations to your code first.',
          }) }],
        };
      }

      const fw = framework as AnalysisFramework;
      const llmConfig = buildConfig({ provider, model: modelName });

      // Agent mode: no API key — return prompt + compact model for the calling agent
      if (!llmConfig) {
        const serialized = serializeModelCompact(threatModel);
        const systemPrompt = FRAMEWORK_PROMPTS[fw] || FRAMEWORK_PROMPTS.general;
        const userMessage = buildUserMessage(serialized, fw, custom_prompt);

        return {
          content: [{ type: 'text', text: JSON.stringify({
            mode: 'agent',
            message: 'No LLM API key found. Returning the threat report prompt and threat model for you to generate directly. Write the report as markdown and save it to .guardlink/threat-reports/. Call guardlink_parse or read guardlink://model for full detail if needed.',
            framework,
            label: FRAMEWORK_LABELS[fw],
            system_prompt: systemPrompt,
            user_prompt: userMessage,
            save_to: `.guardlink/threat-reports/${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}-${framework}.md`,
          }, null, 2) }],
        };
      }

      // API mode: call LLM internally
      try {
        const result = await generateThreatReport({
          root,
          model: threatModel,
          framework: fw,
          llmConfig,
          customPrompt: custom_prompt,
          stream: false,
          webSearch: web_search,
          extendedThinking: thinking,
        });

        return {
          content: [{ type: 'text', text: JSON.stringify({
            mode: 'api',
            framework: result.framework,
            label: result.label,
            model: result.model,
            savedTo: result.savedTo,
            inputTokens: result.inputTokens,
            outputTokens: result.outputTokens,
            content: result.content,
          }, null, 2) }],
        };
      } catch (err: any) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }) }],
        };
      }
    },
  );

  // ── Tool: guardlink_annotate ──
  server.tool(
    'guardlink_annotate',
    'Build an annotation prompt with project context, GuardLink reference docs, and GAL syntax guidelines. The calling agent should use this prompt to read source files and add security annotations directly. Returns the prompt text — the agent should then read files, decide annotation placement, and write comments.',
    {
      root: z.string().describe('Project root directory').default('.'),
      prompt: z.string().describe('Annotation instructions (e.g., "annotate auth endpoints for OWASP Top 10")'),
    },
    async ({ root, prompt }) => {
      let model: ThreatModel | null = null;
      try {
        const result = await getModel(root);
        if (result.model.annotations_parsed > 0) {
          model = result.model;
        }
      } catch { /* no model yet — fine */ }

      const annotatePrompt = buildAnnotatePrompt(prompt, root, model);

      return {
        content: [{ type: 'text', text: JSON.stringify({
          mode: 'agent',
          message: 'Annotation prompt built with project context. Read the source files in the project directory, then add GuardLink annotations as code comments following the guidelines in the prompt. After annotating, call guardlink_parse to verify the annotations were parsed correctly.',
          prompt: annotatePrompt,
          guidelines: [
            'Add annotations as comments directly above security-relevant code',
            'Use the project\'s comment style (// for TS/JS/Rust/Go, # for Python/Ruby/Shell)',
            'After annotating, call guardlink_parse to verify results',
          ],
        }, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_report ──
  server.tool(
    'guardlink_report',
    'Generate a markdown threat model report with Mermaid diagram. Also writes threat-model.json alongside.',
    {
      root: z.string().describe('Project root directory').default('.'),
      output: z.string().describe('Output filename (default: threat-model.md)').default('threat-model.md'),
    },
    async ({ root, output }) => {
      const { model } = await getModel(root);
      if (model.annotations_parsed === 0) {
        return { content: [{ type: 'text', text: JSON.stringify({ error: 'No annotations found.' }) }] };
      }
      const { writeFile } = await import('node:fs/promises');
      const { resolve } = await import('node:path');
      const report = generateReport(model);
      await writeFile(resolve(root, output), report + '\n');
      const jsonFile = output.replace(/\.md$/, '.json');
      await writeFile(resolve(root, jsonFile), JSON.stringify(model, null, 2) + '\n');
      return {
        content: [{ type: 'text', text: JSON.stringify({
          report: output,
          json: jsonFile,
          annotations: model.annotations_parsed,
          exposures: model.exposures.length,
        }) }],
      };
    },
  );

  // ── Tool: guardlink_dashboard ──
  server.tool(
    'guardlink_dashboard',
    'Generate an interactive HTML threat model dashboard with diagrams, charts, code annotations, and heatmap.',
    {
      root: z.string().describe('Project root directory').default('.'),
      output: z.string().describe('Output filename (default: threat-dashboard.html)').default('threat-dashboard.html'),
    },
    async ({ root, output }) => {
      const { model } = await getModel(root);
      if (model.annotations_parsed === 0) {
        return { content: [{ type: 'text', text: JSON.stringify({ error: 'No annotations found.' }) }] };
      }
      const { writeFile } = await import('node:fs/promises');
      const { resolve } = await import('node:path');
      const analyses = loadThreatReportsForDashboard(root);
      const html = generateDashboardHTML(model, root, analyses);
      await writeFile(resolve(root, output), html);
      return {
        content: [{ type: 'text', text: JSON.stringify({
          dashboard: output,
          annotations: model.annotations_parsed,
          exposures: model.exposures.length,
        }) }],
      };
    },
  );

  // ── Tool: guardlink_sarif ──
  server.tool(
    'guardlink_sarif',
    'Export findings as SARIF 2.1.0 for GitHub Advanced Security, VS Code, and other SARIF consumers.',
    {
      root: z.string().describe('Project root directory').default('.'),
      output: z.string().describe('Output filename (default: guardlink.sarif.json)').default('guardlink.sarif.json'),
    },
    async ({ root, output }) => {
      invalidateCache();
      const { model, diagnostics } = await getModel(root);
      const { writeFile } = await import('node:fs/promises');
      const { resolve } = await import('node:path');
      const sarif = generateSarif(model, diagnostics, [], { includeDiagnostics: true, includeDanglingRefs: true });
      await writeFile(resolve(root, output), JSON.stringify(sarif, null, 2) + '\n');
      const resultCount = sarif.runs[0]?.results?.length ?? 0;
      return {
        content: [{ type: 'text', text: JSON.stringify({
          sarif: output,
          results: resultCount,
        }) }],
      };
    },
  );

  // ── Tool: guardlink_diff ──
  server.tool(
    'guardlink_diff',
    'Compare the current threat model against a git ref (commit, branch, tag). Shows added/removed/changed annotations, new unmitigated exposures.',
    {
      root: z.string().describe('Project root directory').default('.'),
      ref: z.string().describe('Git ref to compare against (e.g. HEAD~1, main, v1.0)').default('HEAD~1'),
    },
    async ({ root, ref }) => {
      try {
        const { model: current } = await getModel(root);
        const previous = await parseAtRef(root, ref, 'unknown');
        const diff = diffModels(previous, current);
        return {
          content: [{ type: 'text', text: JSON.stringify(diff, null, 2) }],
        };
      } catch (err: any) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: err.message }) }],
        };
      }
    },
  );

  // ── Tool: guardlink_threat_reports ──
  server.tool(
    'guardlink_threat_reports',
    'List saved AI threat reports from .guardlink/threat-reports/ (and legacy .guardlink/analyses/). Returns filename, framework, timestamp, and model used.',
    {
      root: z.string().describe('Project root directory').default('.'),
    },
    async ({ root }) => {
      const reports = listThreatReports(root);
      return {
        content: [{ type: 'text', text: JSON.stringify(reports, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_sync ──
  server.tool(
    'guardlink_sync',
    'Sync all agent instruction files (CLAUDE.md, .cursorrules, etc.) with the current threat model. Injects live asset/threat/control IDs, open exposures, and data flows so every coding agent knows the current security posture. Run after adding or changing annotations.',
    {
      root: z.string().describe('Project root directory').default('.'),
    },
    async ({ root }) => {
      const { model } = await getModel(root);
      const result = syncAgentFiles({ root, model });
      const summary = [
        `Synced ${result.updated.length} agent instruction file(s): ${result.updated.join(', ')}`,
        result.skipped.length > 0 ? `Skipped: ${result.skipped.join(', ')}` : '',
        `Model: ${model.assets.length} assets, ${model.threats.length} threats, ${model.controls.length} controls, ${model.exposures.length} exposures`,
      ].filter(Boolean).join('\n');
      return {
        content: [{ type: 'text', text: summary }],
      };
    },
  );

  // ── Tool: guardlink_clear ──
  server.tool(
    'guardlink_clear',
    'Remove all GuardLink annotations from source files. Use --dry-run to preview without modifying files. WARNING: destructive operation — requires explicit user confirmation before calling without dry-run.',
    {
      root: z.string().describe('Project root directory').default('.'),
      dry_run: z.boolean().describe('If true, only show what would be removed').default(true),
      include_definitions: z.boolean().describe('Also clear .guardlink/definitions files').default(false),
    },
    async ({ root, dry_run, include_definitions }) => {
      const result = await clearAnnotations({
        root,
        dryRun: dry_run,
        includeDefinitions: include_definitions,
      });

      if (result.totalRemoved === 0) {
        return { content: [{ type: 'text', text: 'No GuardLink annotations found in source files.' }] };
      }

      const fileList = Array.from(result.perFile.entries())
        .map(([file, count]) => `  ${file} (${count} line${count > 1 ? 's' : ''})`)
        .join('\n');

      const mode = dry_run ? '(DRY RUN) Would remove' : 'Removed';
      return {
        content: [{ type: 'text', text: `${mode} ${result.totalRemoved} annotation line(s) from ${result.modifiedFiles.length} file(s):\n${fileList}` }],
      };
    },
  );

  // ── Tool: guardlink_unannotated ──
  server.tool(
    'guardlink_unannotated',
    'List source files that have no GuardLink annotations. Useful for identifying coverage gaps. Not all files need annotations — only those touching security boundaries (endpoints, auth, data access, I/O, crypto).',
    {
      root: z.string().describe('Project root directory').default('.'),
    },
    async ({ root }) => {
      const { model } = await getModel(root);
      const unannotated = model.unannotated_files || [];
      const annotated = model.annotated_files || [];
      const total = annotated.length + unannotated.length;

      if (unannotated.length === 0) {
        return { content: [{ type: 'text', text: `All ${total} source files have GuardLink annotations.` }] };
      }

      const fileList = unannotated.map(f => `  ${f}`).join('\n');
      return {
        content: [{ type: 'text', text: `${annotated.length} of ${total} files annotated. ${unannotated.length} file(s) with no annotations:\n${fileList}\n\nNot all files need annotations — only those touching security boundaries.` }],
      };
    },
  );

  // ── Tool: guardlink_review_list ──
  server.tool(
    'guardlink_review_list',
    'List all unmitigated exposures eligible for governance review, sorted by severity. Returns exposure IDs, details, and severity. Use guardlink_review_accept to record decisions. IMPORTANT: Acceptance decisions require explicit human confirmation — do not accept exposures without asking the user first.',
    {
      root: z.string().describe('Project root directory').default('.'),
      severity: z.string().optional().describe('Filter by severity: "critical,high" etc.'),
    },
    async ({ root, severity }) => {
      invalidateCache();
      const { model } = await getModel(root);
      let exposures = getReviewableExposures(model);

      if (severity) {
        const allowed = new Set(severity.split(',').map((s: string) => s.trim().toLowerCase()));
        exposures = exposures.filter(e => allowed.has(e.exposure.severity || 'low'));
        exposures = exposures.map((e, i) => ({ ...e, index: i + 1 }));
      }

      if (exposures.length === 0) {
        return { content: [{ type: 'text', text: 'No unmitigated exposures to review.' }] };
      }

      const items = exposures.map(r => ({
        id: r.id,
        index: r.index,
        asset: r.exposure.asset,
        threat: r.exposure.threat,
        severity: r.exposure.severity,
        file: r.exposure.location.file,
        line: r.exposure.location.line,
        description: r.exposure.description,
      }));

      return { content: [{ type: 'text', text: JSON.stringify(items, null, 2) }] };
    },
  );

  // ── Tool: guardlink_review_accept ──
  server.tool(
    'guardlink_review_accept',
    'Record a governance decision for an unmitigated exposure. Writes @accepts + @audit (for accept) or @audit (for remediate) directly into the source file. IMPORTANT: This modifies source files. Only call after explicit human confirmation of the decision and justification.',
    {
      root: z.string().describe('Project root directory').default('.'),
      exposure_id: z.string().describe('Exposure ID from guardlink_review_list (format: "file:line")'),
      decision: z.enum(['accept', 'remediate', 'skip']).describe('accept = risk acknowledged; remediate = planned fix; skip = no action'),
      justification: z.string().describe('Required explanation for accept/remediate decisions'),
    },
    async ({ root, exposure_id, decision, justification }) => {
      if (decision !== 'skip' && !justification.trim()) {
        return { content: [{ type: 'text', text: 'Error: Justification is required for accept and remediate decisions.' }] };
      }

      invalidateCache();
      const { model } = await getModel(root);
      const exposures = getReviewableExposures(model);
      const target = exposures.find(e => e.id === exposure_id);

      if (!target) {
        return { content: [{ type: 'text', text: `Error: Exposure "${exposure_id}" not found. Use guardlink_review_list to get valid IDs.` }] };
      }

      const result = await applyReviewAction(root, target, { decision, justification });
      invalidateCache();

      if (decision === 'skip') {
        return { content: [{ type: 'text', text: `Skipped: ${target.exposure.asset} → ${target.exposure.threat}` }] };
      }

      // Sync agent files after modification
      try {
        const { model: newModel } = await getModel(root);
        syncAgentFiles({ root, model: newModel });
      } catch {}

      const verb = decision === 'accept' ? 'Accepted' : 'Marked for remediation';
      return {
        content: [{ type: 'text', text: `${verb}: ${target.exposure.asset} → ${target.exposure.threat} [${target.exposure.severity}]\nJustification: ${justification}\n${result.linesInserted} annotation line(s) written to ${target.exposure.location.file}` }],
      };
    },
  );

  // ── Resource: guardlink://model ──
  server.resource(
    'threat-model',
    'guardlink://model',
    { description: 'Full ThreatModel JSON for the current project' },
    async () => {
      const { model } = await getModel(cachedRoot || '.');
      return {
        contents: [{ uri: 'guardlink://model', mimeType: 'application/json', text: JSON.stringify(model, null, 2) }],
      };
    },
  );

  // ── Resource: guardlink://definitions ──
  server.resource(
    'definitions',
    'guardlink://definitions',
    { description: 'All defined assets, threats, and controls with their IDs' },
    async () => {
      const { model } = await getModel(cachedRoot || '.');
      const defs = {
        assets: model.assets.map(a => ({ id: a.id, path: a.path.join('.'), description: a.description })),
        threats: model.threats.map(t => ({ id: t.id, name: t.canonical_name, severity: t.severity, description: t.description })),
        controls: model.controls.map(c => ({ id: c.id, name: c.canonical_name, description: c.description })),
      };
      return {
        contents: [{ uri: 'guardlink://definitions', mimeType: 'application/json', text: JSON.stringify(defs, null, 2) }],
      };
    },
  );

  // ── Resource: guardlink://unmitigated ──
  server.resource(
    'unmitigated',
    'guardlink://unmitigated',
    { description: 'List of unmitigated exposures — assets exposed to threats with no @mitigates or @accepts' },
    async () => {
      const { model } = await getModel(cachedRoot || '.');
      const covered = new Set<string>();
      for (const m of model.mitigations) covered.add(`${m.asset}::${m.threat}`);
      for (const a of model.acceptances) covered.add(`${a.asset}::${a.threat}`);
      const unmitigated = model.exposures
        .filter(e => !covered.has(`${e.asset}::${e.threat}`))
        .map(e => ({ asset: e.asset, threat: e.threat, severity: e.severity, file: e.location.file, line: e.location.line }));
      return {
        contents: [{ uri: 'guardlink://unmitigated', mimeType: 'application/json', text: JSON.stringify(unmitigated, null, 2) }],
      };
    },
  );

  return server;
}
