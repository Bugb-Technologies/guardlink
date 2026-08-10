/**
 * GuardLink MCP Server — Model Context Protocol integration (§8.2).
 *
 * Tools:
 *   guardlink_parse    — Parse annotations, return threat model
 *   guardlink_status   — Coverage stats, unmitigated exposures, confirmed count
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
 *   guardlink_workspace_info — Workspace config, siblings, tag prefixes
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
 * @feature "MCP Integration" -- "Model Context Protocol server for AI agent tooling"
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { parseProject, findDanglingRefs, findUnmitigatedExposures, clearAnnotations, applyAnnotations, findAnchorDrift, applyReanchor, crossRepoTag } from '../parser/index.js';
import { fingerprintProject } from '../parser/fingerprint.js';
import { buildEnvelope, degradedEnvelope, envelopeBlock } from './freshness.js';
import { getReviewableExposures, applyReviewAction, type ReviewableExposure } from '../review/index.js';
import { generateSarif } from '../analyzer/index.js';
import { generateReport } from '../report/index.js';
import { generateDashboardHTML, generateThreatGraph } from '../dashboard/index.js';
import { diffModels, parseAtRef, formatDiffMarkdown } from '../diff/index.js';
import { lookup, type LookupQuery } from './lookup.js';
import { fileContext, normalizeContextPath } from './context.js';
import { selectSubgraph, traverseGraph, findPath, summariseGraphPayload } from './subgraph.js';
import { buildServerInstructions, readConfiguredMode } from './instructions.js';
import { suggestAnnotations } from './suggest.js';
import { generateThreatReport, listThreatReports, loadThreatReportsForDashboard, buildConfig, serializeModel, serializeModelCompact, FRAMEWORK_LABELS, FRAMEWORK_PROMPTS, buildUserMessage, type AnalysisFramework } from '../analyze/index.js';
import { buildAnnotatePrompt } from '../agents/prompts.js';
import { syncAgentFiles } from '../init/index.js';
import { loadWorkspaceConfig } from '../workspace/index.js';
import { getPackageVersion } from '../version.js';
import type { ThreatModel } from '../types/index.js';

// ─── Per-server model cache ──────────────────────────────────────────

type TextBlock = { type: 'text'; text: string };

/**
 * The cache belongs to one server, not to the module.
 *
 * It used to be four module-level `let`s, so every server built in a process
 * shared one cached model and one `cachedRoot`. A stdio deployment runs one
 * server per process and never noticed, but the state is what the resources use
 * to decide *which repo they answer for* — sharing that across instances is the
 * same wrong-repo failure as D9, one level up. Scoping it per server also means
 * a second server in the same process starts genuinely cold.
 */
function createModelCache() {
  let cachedModel: ThreatModel | null = null;
  let cachedDiagnostics: any[] = [];
  let cachedRoot = '';
  let cachedFingerprint: string | null = null;

  /**
   * Return the parsed model, re-parsing when anything on disk has moved.
   *
   * The cache used to be keyed on `root` alone and never expired, so a session
   * that had called any tool once served that first answer for the rest of its
   * life — the agent edits a file, asks again, and is told the old thing. Only
   * five of the eighteen tools invalidated explicitly, which left the other
   * thirteen and all three resources stale.
   *
   * The fingerprint closes that without a watcher: it is directory metadata only
   * (path, size, mtime), so it costs a glob walk rather than a parse. It is also
   * the only mechanism that can catch an edit GuardLink did not make itself —
   * which is the common case, since `guardlink_annotate` hands a prompt to the
   * agent and the writes land afterwards, outside any tool call.
   */
  async function getModel(root: string): Promise<{ model: ThreatModel; diagnostics: any[] }> {
    const fingerprint = await fingerprintProject(root);
    if (cachedModel && cachedRoot === root && cachedFingerprint === fingerprint) {
      return { model: cachedModel, diagnostics: cachedDiagnostics };
    }
    const result = await parseProject({ root, project: 'unknown' });
    cachedModel = result.model;
    cachedDiagnostics = result.diagnostics;
    cachedRoot = root;
    cachedFingerprint = fingerprint;
    return result;
  }

  function invalidateCache(): void {
    cachedModel = null;
    cachedDiagnostics = [];
    cachedFingerprint = null;
  }

  /**
   * Which repo the resources answer for, and how confidently.
   *
   * The resources take no `root` argument and used to fall back to
   * `cachedRoot || '.'`. Two problems lived in that expression. `'.'` is the
   * *server's* cwd, which for a stdio server is wherever the client happened to
   * spawn it — an arbitrary directory, silently answered for. And once any tool
   * had run, `cachedRoot` pinned the resources to that repo with nothing in the
   * response saying so, which in a linked workspace means reading a sibling's
   * model believing it is yours.
   *
   * Behaviour is preserved — a resource read before any tool call still answers
   * for the working directory, because refusing would break the common case
   * where the server was spawned in the project root. What changes is that the
   * answer now says which root it used and whether it was established or assumed.
   */
  function resourceRoot(): { root: string; source: 'tool_call' | 'server_cwd' } {
    return cachedRoot
      ? { root: cachedRoot, source: 'tool_call' }
      : { root: process.cwd(), source: 'server_cwd' };
  }

  /** Envelope for `root`, degrading to a labelled stub if the model cannot be parsed. */
  async function envelopeFor(root: string) {
    try {
      const { model } = await getModel(root);
      return buildEnvelope(root, model);
    } catch (err: any) {
      return degradedEnvelope(root, err?.message ?? 'model unavailable');
    }
  }

  return { getModel, invalidateCache, resourceRoot, envelopeFor };
}

type ModelCache = ReturnType<typeof createModelCache>;

// ─── Freshness envelope (GL-102) ─────────────────────────────────────

/**
 * Register a tool whose result always carries the envelope.
 *
 * Wrapping at registration rather than editing 18 return statements is what makes
 * "all 18 tools" true by construction instead of by inspection — including the
 * error branches inside handlers, which are the returns most likely to be missed.
 */
function registerTool(
  server: McpServer,
  cache: ModelCache,
  name: string,
  description: string,
  schema: z.ZodRawShape,
  handler: (args: any) => Promise<{ content: TextBlock[] }>,
): void {
  server.tool(name, description, schema, (async (args: any) => {
    const result = await handler(args);
    const root = typeof args?.root === 'string' && args.root ? args.root : cache.resourceRoot().root;
    return { content: [...result.content, envelopeBlock(await cache.envelopeFor(root))] };
  }) as any);
}

/** Register a resource whose read always carries the envelope and names its root. */
function registerResource(
  server: McpServer,
  cache: ModelCache,
  name: string,
  uri: string,
  metadata: { description: string },
  handler: (root: string) => Promise<{ contents: any[] }>,
): void {
  server.resource(name, uri, metadata, (async () => {
    const { root, source } = cache.resourceRoot();
    const result = await handler(root);
    const envelope = { ...(await cache.envelopeFor(root)), root_source: source };
    return {
      contents: [
        ...result.contents,
        {
          uri: 'guardlink://freshness',
          mimeType: 'application/json',
          text: JSON.stringify({ guardlink: envelope }, null, 2),
        },
      ],
    };
  }) as any);
}

// ─── Server setup ────────────────────────────────────────────────────

export function createServer(): McpServer {
  // Instructions must be built before any tool is registered — the SDK stores
  // them privately at construction. See instructions.ts on how the tool names in
  // that text are kept honest.
  const cwd = process.cwd();
  const server = new McpServer(
    { name: 'guardlink', version: getPackageVersion() },
    {
      instructions: buildServerInstructions({
        mode: readConfiguredMode(cwd),
        definitionsPath: '.guardlink/definitions.*',
      }),
    },
  );

  const cache = createModelCache();
  const { getModel, invalidateCache } = cache;

  // ── Tool: guardlink_parse ──
  registerTool(
    server, cache,
    'guardlink_parse',
    'Parse GuardLink annotations and return the threat model as JSON. Omits unannotated_files by default — on a large repo that list is ~90% of the payload and carries no threat-model information; use guardlink_unannotated, which exists for exactly that data, or set include_unannotated. Prefer guardlink_context for a single file and guardlink_lookup for a specific question; this is the expensive call for when you genuinely need the whole model.',
    {
      root: z.string().describe('Project root directory').default('.'),
      compact: z.boolean().describe('Return the compact serialization: stats, assets, ALL unmitigated exposures, threat severity index, flows, boundaries and data classifications, with descriptions capped. Omits resolved mitigations, working controls, comments and validations.').default(false),
      include_unannotated: z.boolean().describe('Include the unannotated_files list. Off by default; guardlink_unannotated is the dedicated tool for it.').default(false),
    },
    async ({ root, compact, include_unannotated }) => {
      invalidateCache();
      const { model } = await getModel(root);

      if (compact) {
        return { content: [{ type: 'text', text: serializeModelCompact(model) }] };
      }

      // The one non-additive change in this epic: the default payload drops a
      // key. Measured on specter-v1, unannotated_files alone was 646,200 B —
      // 90.1% of the dump — a flat path list with nothing about the threat
      // model in it. Model content does not scale with repo size; the file
      // inventory does.
      if (include_unannotated) {
        return { content: [{ type: 'text', text: JSON.stringify(model, null, 2) }] };
      }
      const { unannotated_files, ...rest } = model;
      // Say the key was dropped. Absent-because-omitted and absent-because-empty
      // are different facts, and a consumer that cannot tell them apart will
      // read a large repo as fully annotated.
      const payload = {
        ...rest,
        unannotated_files_omitted: {
          count: unannotated_files.length,
          reason: 'Omitted by default — call guardlink_unannotated, or pass include_unannotated: true.',
        },
      };
      return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
    },
  );

  // ── Tool: guardlink_status ──
  registerTool(
    server, cache,
    'guardlink_status',
    'Return coverage statistics: asset/threat/control counts, unmitigated exposures, @confirmed count, coverage percentage',
    { root: z.string().describe('Project root directory').default('.') },
    async ({ root }) => {
      const { model } = await getModel(root);

      const unmitigated = findUnmitigatedExposures(model);

      const uniqueFeatures = new Set((model.features || []).map(f => f.feature));

      const status = {
        assets: model.assets.length,
        threats: model.threats.length,
        controls: model.controls.length,
        mitigations: model.mitigations.length,
        exposures: model.exposures.length,
        confirmed: (model.confirmed || []).length,
        acceptances: model.acceptances.length,
        flows: model.flows.length,
        boundaries: model.boundaries.length,
        features: [...uniqueFeatures].sort(),
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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
    'guardlink_lookup',
    'Query the threat model graph. Reaches every relation type the model carries: assets, threats, controls, mitigations, exposures, confirmed, acceptances, transfers, flows, boundaries, validations, audits, ownership, data classification, assumptions, shields, features, comments and cross-repo refs. Examples: "threats for #auth", "owner of #api", "handles pii", "assumptions for #api", "flows into Scanner", "unmitigated". A query that is not one of the supported forms returns no_match listing them — it is never answered by guesswork.',
    {
      root: z.string().describe('Project root directory').default('.'),
      query: z.string().describe('A supported query form: "unmitigated", "confirmed", "features", "asset <id>", "threat <id>", "control <id>", "threats for <asset>", "controls for <asset>", "exposures for <asset>", "mitigations for <asset>", "flows into <asset>", "flows from <asset>", "boundary for <asset>", "owner of <asset>", "handles <pii|phi|financial|secrets|internal|public>", "handles for <asset>", "assumptions for <asset>", "audits [for <asset>]", "validations for <asset-or-control>", "acceptances [for <asset>]", "transfers [for <threat-or-asset>]", "comments [for <file-or-asset>]", "shields [for <file-or-asset>]", or a bare identifier. TWO DIFFERENT REF QUERIES, do not confuse them: "cwe:CWE-89" / "CWE-89" / "owasp:A03" asks about external identifiers declared on threats — the scanner bridge, and returns external_id.declared so you can tell \'never heard of this weakness\' from \'declared, nothing exposed\'; "cross-repo refs" asks about sibling-repo tags from workspace.yaml and is unrelated. @comment and @shield record no asset, so scoping them by an asset joins by co-location (same file) and the result says so. Free-form questions are not parsed.'),
    },
    async ({ root, query }) => {
      const { model } = await getModel(root);
      const result = lookup(model, query);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_context ──
  registerTool(
    server, cache,
    'guardlink_context',
    'Everything GuardLink knows about one file: the annotations declared there, the assets they name with each asset\'s depth-1 neighbourhood, open exposures and @confirmed findings, controls the file upholds, and its @assumes/@handles/@owns. Call this when you open or are about to edit a file. Accepts the source path or, in external mode, the .gal path that annotates it. An empty result is explicit about WHY: `scanned_without_annotations` means the file is genuinely clean, `not_scanned` means the parser never read it, `not_found` means nothing is there — do not read them as the same answer. Does not tell you where to write a NEW annotation; the .gal path convention is not yet codified in code (GL-501), so only origin_file for annotations that already exist is reported.',
    {
      root: z.string().describe('Project root directory').default('.'),
      file: z.string().describe('File to describe. Absolute, relative or ./-prefixed; resolved against root. In external mode the .gal path resolves to the source file it annotates.'),
      line: z.number().describe('Optional line number. Narrows to the enclosing symbol where the annotation recorded one (@source symbol:). Reports symbol_scope.applied = "unavailable" when no annotation for the file records a symbol, rather than silently returning the whole file.').optional(),
    },
    async ({ root, file, line }) => {
      const { model } = await getModel(root);
      const rel = normalizeContextPath(root, file);

      if (rel === null) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            file, status: 'outside_root',
            hint: 'That path resolves outside the project root. Paths are interpreted relative to root; nothing outside it is read.',
          }, null, 2) }],
        };
      }

      const { existsSync } = await import('node:fs');
      const { resolve } = await import('node:path');
      const context = fileContext(model, { file: rel, exists: existsSync(resolve(root, rel)), line });

      return { content: [{ type: 'text', text: JSON.stringify(context, null, 2) }] };
    },
  );

  // ── Tool: guardlink_graph ──
  registerTool(
    server, cache,
    'guardlink_graph',
    'Blast radius: the neighbourhood around an asset, or the path between two. Traversal walks the ASSET plane only — @flows (directed), @boundary (undirected, crossable either way) and @transfers (directed). It does NOT hop through shared threats: #path-traversal alone is declared on 10 assets here, so crossing threats would make depth 2 reach most of the graph and depth would stop meaning anything. Threats and controls are still returned for every asset in the neighbourhood, they just are not transited through. Returns a filtered ThreatModel, so the result is a model like any other. Use format: "mermaid" for a diagram, or path_to for a route between two assets.',
    {
      root: z.string().describe('Project root directory').default('.'),
      from: z.string().describe('Asset to start from. Resolved exactly as "asset X" is — same tiers, same ambiguity reporting. Later hops match canonical identity only, never fuzzily.'),
      path_to: z.string().describe('If set, return the shortest path from `from` to this asset instead of a neighbourhood. Directed edges are followed forwards; boundaries either way. An unresolvable endpoint and a genuinely disconnected pair are reported differently.').optional(),
      depth: z.number().describe('Hops from `from`. 0 is the asset alone, 1 matches what "asset X" reports. Clamped to 10. Check `traversal.completeness` on the result: "complete" means there is nothing more to find at any depth, "depth_limited" means raising this would return more (and `frontier_unexplored` names what is immediately beyond), "truncated" means the depth-10 ceiling cut it short and the result is INCOMPLETE.').default(2),
      direction: z.enum(['in', 'out', 'both']).describe('Which way directed edges are followed. Boundaries are undirected and are crossed in every direction regardless.').default('both'),
      kinds: z.array(z.string()).describe('Relation arrays to keep in the returned model. Filters the OUTPUT, not the traversal — excluding "flows" still walks flows, it just omits them from the result. Assets, threats and controls are always kept as the node vocabulary.').optional(),
      format: z.enum(['json', 'mermaid']).describe('json returns the filtered ThreatModel plus traversal detail; mermaid renders it with the same generator the dashboard uses.').default('json'),
      detail: z.enum(['summary', 'full']).describe('How much per-node detail to return. summary (default) drops `description` prose and compacts `location` to an `at: "file:line"` string — measured at roughly 40% of the payload, and the graph is the same graph either way: identical nodes, identical edges. full returns the complete records and is the only mode whose `model` is a valid ThreatModel.').default('summary'),
      feature: z.string().describe('Restrict to one feature before traversing.').optional(),
      file: z.string().describe('Restrict to annotations declared in one file before traversing.').optional(),
    },
    async ({ root, from, path_to, depth, direction, kinds, format, detail, feature, file }) => {
      const { model } = await getModel(root);

      if (path_to) {
        const path = findPath(model, from, path_to);
        return { content: [{ type: 'text', text: JSON.stringify(path, null, 2) }] };
      }

      const options = { from, depth, direction, kinds, feature, file };
      const traversal = traverseGraph(model, options);
      const sub = selectSubgraph(model, options);

      if (format === 'mermaid') {
        // showAll: the caller already scoped this graph. generateThreatGraph
        // otherwise drops everything below high severity once a model names more
        // than 12 distinct threats, which on a deliberately narrowed subgraph
        // would silently remove data that was explicitly asked for.
        return {
          content: [{ type: 'text', text: generateThreatGraph(sub, { showAll: true }) }],
        };
      }

      // detail is applied AFTER selection, so it cannot change which nodes or
      // edges came back — only how much is said about each.
      const payload = detail === 'full'
        ? { traversal, model: sub }
        : summariseGraphPayload({ traversal, model: sub });

      return {
        content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_annotate_apply ──
  registerTool(
    server, cache,
    'guardlink_annotate_apply',
    'Write a validated @source block into the annotation sidecar for a file. Unlike guardlink_annotate — which returns a prompt for you to act on — this writes the annotations itself, into .guardlink/annotations/, never into source. Every line is re-parsed before anything touches disk; malformed input is rejected with the reason. Idempotent: re-applying the same block is a no-op, not a duplicate. Refuses @accepts, which is a human governance decision.',
    {
      root: z.string().describe('Project root directory').default('.'),
      file: z.string().describe('Source file the annotations describe. The sidecar path is derived from it; you do not choose where it is written.'),
      line: z.number().describe('Line in that file the block anchors to'),
      symbol: z.string().describe('Enclosing symbol name. Strongly recommended — it is what lets guardlink_reanchor detect drift after a refactor.').optional(),
      annotations: z.array(z.string()).describe('Raw GAL lines with no comment prefix, e.g. [\'@exposes #api to #sqli [critical] -- "concatenated"\']. Do NOT include @source; the header is generated.'),
      dry_run: z.boolean().describe('Validate and return the diff without writing').default(false),
    },
    async ({ root, file, line, symbol, annotations, dry_run }) => {
      const result = applyAnnotations({ root, file, line, symbol, annotations, dryRun: dry_run });
      // Any tool that writes must invalidate — the D11/D5 lesson.
      if (result.status === 'written' && !dry_run) invalidateCache();
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    },
  );

  // ── Tool: guardlink_reanchor ──
  registerTool(
    server, cache,
    'guardlink_reanchor',
    'Find @source blocks whose recorded file:line no longer holds the symbol they name — the drift external annotations accumulate after a refactor. Reports and proposes; it does not rewrite anything unless you pass apply: true, and it never invents an anchor for a symbol that has disappeared.',
    {
      root: z.string().describe('Project root directory').default('.'),
      apply: z.boolean().describe('Rewrite @source lines to the proposed positions. Only blocks whose symbol was found elsewhere are moved; a vanished symbol is always left for a human.').default(false),
    },
    async ({ root, apply }) => {
      const { model } = await getModel(root);
      const drifts = findAnchorDrift(root, model);

      if (!apply) {
        return { content: [{ type: 'text', text: JSON.stringify({
          drifted: drifts.length,
          anchored_blocks_checked: model.exposures.filter(e => e.location.parent_symbol).length,
          drifts,
          ...(drifts.length > 0 ? { next: 'Review these, then call again with apply: true to move the ones marked "moved".' } : {}),
        }, null, 2) }] };
      }

      const { updated, skipped } = applyReanchor(root, drifts);
      if (updated.length > 0) invalidateCache();
      return { content: [{ type: 'text', text: JSON.stringify({
        updated, skipped,
        note: skipped.length > 0
          ? 'Skipped blocks need a human: their symbol was renamed or removed, so there is no correct line to move them to.'
          : undefined,
      }, null, 2) }] };
    },
  );

  // ── Tool: guardlink_threat_report ──
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
    'guardlink_annotate',
    'Build an annotation prompt with project context, GuardLink reference docs, and GAL syntax guidelines. The calling agent should use this prompt to read source files and add security annotations directly. Returns the prompt text — the agent should then read files, decide annotation placement, and write comments.',
    {
      root: z.string().describe('Project root directory').default('.'),
      prompt: z.string().describe('Annotation instructions (e.g., "annotate auth endpoints for OWASP Top 10")'),
      mode: z.enum(['inline', 'external']).describe('Annotation placement mode — inline (default) or external (externalized .gal files)').default('inline'),
    },
    async ({ root, prompt, mode }) => {
      let model: ThreatModel | null = null;
      try {
        const result = await getModel(root);
        if (result.model.annotations_parsed > 0) {
          model = result.model;
        }
      } catch { /* no model yet — fine */ }

      const annotatePrompt = buildAnnotatePrompt(prompt, root, model, mode);

      return {
        content: [{ type: 'text', text: JSON.stringify({
          mode: 'agent',
          message: `Annotation prompt built with project context. Read the source files in the project directory, then add GuardLink annotations using ${mode === 'external' ? 'associated .gal files' : 'inline source comments'} following the guidelines in the prompt. After annotating, call guardlink_parse to verify the annotations were parsed correctly.`,
          prompt: annotatePrompt,
          guidelines: [
            mode === 'external'
              ? 'Write externalized annotations into associated .gal files using @source blocks'
              : 'Add annotations as comments directly above security-relevant code',
            mode === 'external'
              ? 'Keep definitions in .guardlink/definitions.* and use raw GAL lines without comment prefixes'
              : 'Use the project\'s comment style (// for TS/JS/Rust/Go, # for Python/Ruby/Shell)',
            'After annotating, call guardlink_parse to verify results',
          ],
        }, null, 2) }],
      };
    },
  );

  // ── Tool: guardlink_report ──
  registerTool(
    server, cache,
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
      const { writeFile, readFile } = await import('node:fs/promises');
      const { resolve } = await import('node:path');

      // Load project description from .guardlink/prompt.md if it exists
      try {
        const promptContent = await readFile(resolve(root, '.guardlink', 'prompt.md'), 'utf-8');
        if (promptContent.trim()) model.prompt = promptContent.trim();
      } catch { /* no prompt file */ }

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
  registerTool(
    server, cache,
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
      // `.html` is in the parser's DEFAULT_INCLUDE, so the file just written
      // joins the scan set. It carries no annotations, but it does change
      // source_files / unannotated_files — leaving the cache in place makes
      // guardlink_unannotated disagree with a fresh CLI run for the session.
      invalidateCache();
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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
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

      // A non-dry-run clear strips annotation lines from source files. Without
      // this the cached model keeps describing annotations that are no longer on
      // disk for the rest of the session — the one tool that knows the model
      // just changed was the only mutating tool not saying so.
      if (!dry_run) invalidateCache();

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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
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
  registerTool(
    server, cache,
    'guardlink_review_accept',
    'Record a governance decision for an unmitigated exposure. Writes @accepts + @audit (for accept) or @audit (for remediate) directly into the source file. IMPORTANT: This modifies source files. Only call after explicit human confirmation of the decision and justification.',
    {
      root: z.string().describe('Project root directory').default('.'),
      exposure_id: z.string().describe('Exposure ID from guardlink_review_list'),
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
        content: [{ type: 'text', text: `${verb}: ${target.exposure.asset} → ${target.exposure.threat} [${target.exposure.severity}]\nJustification: ${justification}\n${result.linesInserted} annotation line(s) written to ${result.targetFile}` }],
      };
    },
  );

  // ── Tool: guardlink_workspace_info ──
  registerTool(
    server, cache,
    'guardlink_workspace_info',
    'Get workspace configuration for multi-repo threat modeling. Returns workspace name, this repo\'s identity, sibling repos, and their tag prefixes. Use this to understand cross-repo references when writing annotations. Returns null fields if the repo is not part of a workspace.',
    {
      root: z.string().describe('Project root directory').default('.'),
    },
    async ({ root }) => {
      const config = loadWorkspaceConfig(root);

      if (!config) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            workspace: null,
            message: 'This repo is not part of a workspace. Use "guardlink link-project" to create one.',
          }, null, 2) }],
        };
      }

      const siblings = config.repos.filter(r => r.name !== config.this_repo);

      // D19: every example here is BUILT from the parser's own tag grammar
      // rather than typed as a string. Both rules this tool used to emit were
      // hand-written and neither parsed — the `#a.b` form was unwritable
      // unquoted, and the @flows example used a `from … to …` syntax the
      // grammar has never had. The tool whose job is teaching this syntax was
      // teaching syntax that fails.
      const sibling = siblings[0]?.name || 'sibling';
      const ours = crossRepoTag(config.this_repo, 'component');
      const theirs = crossRepoTag(sibling, 'endpoint');

      return {
        content: [{ type: 'text', text: JSON.stringify({
          workspace: config.workspace,
          this_repo: config.this_repo,
          tag_prefix: `#${config.this_repo}.`,
          siblings: siblings.map(r => ({
            name: r.name,
            tag_prefix: `#${r.name}.`,
            registry: r.registry || null,
          })),
          total_repos: config.repos.length,
          cross_repo_annotation_rules: [
            `Use ${ours} for assets defined in this repo`,
            `Reference sibling assets, threats and controls by their tag prefix (e.g. ${theirs})`,
            'Do not redefine assets that belong to another repo — reference by tag',
            `Cross-repo @flows are encouraged: @flows ${ours} -> ${theirs} -- "what crosses"`,
            `Threats and controls take the same qualified form: @exposes ${ours} to ${crossRepoTag(sibling, 'injection')} [high] -- "why"`,
            'Qualified tags need no quoting. Quote a reference only if it contains spaces.',
            'External refs resolve during workspace merge, not local validation',
          ],
        }, null, 2) }],
      };
    },
  );

  // ── Resource: guardlink://model ──
  registerResource(
    server, cache,
    'threat-model',
    'guardlink://model',
    { description: 'Full ThreatModel JSON for the current project' },
    async (root: string) => {
      const { model } = await getModel(root);
      return {
        contents: [{ uri: 'guardlink://model', mimeType: 'application/json', text: JSON.stringify(model, null, 2) }],
      };
    },
  );

  // ── Resource: guardlink://definitions ──
  registerResource(
    server, cache,
    'definitions',
    'guardlink://definitions',
    { description: 'All defined assets, threats, and controls with their IDs' },
    async (root: string) => {
      const { model } = await getModel(root);
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
  registerResource(
    server, cache,
    'unmitigated',
    'guardlink://unmitigated',
    { description: 'List of unmitigated exposures — assets exposed to threats with no @mitigates or @accepts' },
    async (root: string) => {
      const { model } = await getModel(root);
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
