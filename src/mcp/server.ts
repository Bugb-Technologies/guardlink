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
 * @exposes #mcp to #path-traversal [high] cwe:CWE-22 -- "All tools accept root param from external AI agents"
 * @exposes #mcp to #prompt-injection [medium] cwe:CWE-77 -- "guardlink_suggest output fed back to calling LLM"
 * @exposes #mcp to #arbitrary-write [high] cwe:CWE-73 -- "guardlink_report and guardlink_dashboard write files"
 * @exposes #mcp to #data-exposure [medium] cwe:CWE-200 -- "Exposes threat model details to connected agents"
 * @accepts #path-traversal on #mcp -- "MCP clients (Claude Code, Cursor) are trusted local agents"
 * @accepts #arbitrary-write on #mcp -- "MCP clients are trusted local agents with filesystem access"
 * @accepts #prompt-injection on #mcp -- "Suggest output is intended for LLM consumption"
 * @accepts #data-exposure on #mcp -- "Exposing threat model to agents is the core MCP feature"
 * @boundary between #mcp and External_AI_Agents (#mcp-boundary) -- "Primary trust boundary: external AI agents invoke tools over stdio"
 * @flows External_AI_Agents -> #mcp via stdio -- "Tool calls received from AI agent over stdio transport"
 * @flows #mcp -> #parser via getModel -- "MCP tools invoke parser to build threat model"
 * @flows #mcp -> External_AI_Agents via response -- "Tool results returned to calling agent"
 * @handles internal on #mcp -- "Processes and exposes security-sensitive threat model data"
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { parseProject } from '../parser/index.js';
import { generateSarif } from '../analyzer/index.js';
import { generateReport } from '../report/index.js';
import { generateDashboardHTML } from '../dashboard/index.js';
import { diffModels, parseAtRef, formatDiffMarkdown } from '../diff/index.js';
import { lookup, type LookupQuery } from './lookup.js';
import { suggestAnnotations } from './suggest.js';
import { generateThreatReport, listThreatReports, loadThreatReportsForDashboard, buildConfig, serializeModel, serializeModelCompact, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage, type AnalysisFramework } from '../analyze/index.js';
import { buildAnnotatePrompt } from '../agents/prompts.js';
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
    version: '1.0.0',
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

      const mitigated = new Set<string>();
      const accepted = new Set<string>();
      for (const m of model.mitigations) mitigated.add(`${m.asset}::${m.threat}`);
      for (const a of model.acceptances) accepted.add(`${a.asset}::${a.threat}`);
      const unmitigated = model.exposures.filter(
        e => !mitigated.has(`${e.asset}::${e.threat}`) && !accepted.has(`${e.asset}::${e.threat}`),
      );

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

      // Compute dangling refs
      const definedIds = new Set<string>();
      for (const a of model.assets) { if (a.id) definedIds.add(a.id); definedIds.add(a.path.join('.')); }
      for (const t of model.threats) { if (t.id) definedIds.add(t.id); }
      for (const c of model.controls) { if (c.id) definedIds.add(c.id); }

      const errors = diagnostics.filter(d => d.level === 'error');
      const warnings = diagnostics.filter(d => d.level === 'warning');

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
      provider: z.string().describe('LLM provider: anthropic, openai, openrouter, deepseek (auto-detected from env)').optional(),
      model: z.string().describe('Model name override').optional(),
      custom_prompt: z.string().describe('Custom analysis prompt to replace the framework header').optional(),
    },
    async ({ root, framework, provider, model: modelName, custom_prompt }) => {
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
