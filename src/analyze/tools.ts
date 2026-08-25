/**
 * GuardLink — Tool definitions for LLM function calling.
 *
 * Defines tools that the LLM can invoke during threat analysis:
 *   - lookup_cve: Search for CVE details (via web fetch)
 *   - validate_finding: Cross-reference a finding against the parsed model
 *   - search_codebase: Search project files for patterns
 *
 * @exposes #llm-client to #ssrf [medium] cwe:CWE-918 -- "lookupCve fetches from NVD API with user-controlled CVE ID"
 * @mitigates #llm-client against #ssrf using #input-sanitize -- "CVE ID validated with strict regex; URL hardcoded to NVD"
 * @exposes #llm-client to #path-traversal [medium] cwe:CWE-22 -- "searchCodebase reads files from project root"
 * @mitigates #llm-client against #path-traversal using #glob-filtering -- "skipDirs excludes sensitive directories; relative() bounds output"
 * @exposes #llm-client to #dos [low] cwe:CWE-400 -- "searchCodebase reads many files; the LLM now sets max_results itself"
 * @mitigates #llm-client against #dos using #resource-limits -- "clampMaxResults bounds the caller's limit to [1, HARD_MAX_RESULTS] and turns a non-numeric argument into the default rather than NaN; stat.size < 500KB filter"
 * @comment -- "The old `parseInt(args.max_results || '20', 10)` yielded NaN on a malformed argument, and `results.length >= NaN` is false forever — so the bound vanished and the walk covered the whole tree. Clamping is what makes the limit a limit"
 * @flows LLMToolCall -> #llm-client via createToolExecutor -- "Tool invocation input"
 * @flows #llm-client -> NVD via fetch -- "CVE lookup API call"
 * @flows ProjectFiles -> #llm-client via readFileSync -- "Codebase search reads"
 * @boundary #llm-client and NVD (#nvd-api-boundary) -- "Trust boundary at external API"
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import type { ToolDefinition, ToolExecutor } from './llm.js';
import type { ThreatModel } from '../types/index.js';
import { buildCoverageIndex } from '../parser/coverage.js';

// ─── Tool definitions ────────────────────────────────────────────────

/**
 * Result ceilings for `search_codebase`.
 *
 * `max_results` was read by the executor but never declared in the schema, so
 * the model could not set it and every search returned exactly 20 rows — with
 * no signal that more existed. `file_glob` had the same shape of bug AND a
 * second one: it was applied as `entry.endsWith(glob)`, so the natural thing to
 * pass (`*.ts`) matched nothing at all, silently, and read as "no matches in
 * this codebase".
 */
const DEFAULT_MAX_RESULTS = 50;
const HARD_MAX_RESULTS = 500;

/**
 * Clamp a caller-supplied limit into range.
 *
 * The old expression was `parseInt(args.max_results || '20', 10)`, which turns a
 * non-numeric argument into NaN — and `results.length >= NaN` is false forever,
 * so a malformed limit removed the bound entirely and walked the whole tree.
 */
function clampMaxResults(raw: unknown): number {
  const n = typeof raw === 'number' ? raw : parseInt(String(raw ?? ''), 10);
  if (!Number.isFinite(n)) return DEFAULT_MAX_RESULTS;
  return Math.max(1, Math.min(Math.floor(n), HARD_MAX_RESULTS));
}

/**
 * Compile `file_glob` into basename matchers.
 *
 * Three spellings reach the same place because a model will use all three:
 * `ts` and `.ts` are extension suffixes, and anything containing `*` or `?` is
 * a glob over the basename. Comma-separated for several at once.
 */
function compileFileGlob(fileGlob?: string): RegExp[] | null {
  if (!fileGlob || !fileGlob.trim()) return null;
  const patterns = fileGlob.split(',').map(p => p.trim()).filter(Boolean);
  if (!patterns.length) return null;

  return patterns.map(p => {
    if (/[*?]/.test(p)) {
      // Escape regex metacharacters, then restore the two glob wildcards.
      const body = p.replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replaceAll('*', '[^/]*')
        .replaceAll('?', '[^/]');
      return new RegExp(`^${body}$`, 'i');
    }
    const ext = p.startsWith('.') ? p : `.${p}`;
    return new RegExp(`${ext.replace(/[.+^${}()|[\]\\]/g, '\\$&')}$`, 'i');
  });
}

export const GUARDLINK_TOOLS: ToolDefinition[] = [
  {
    name: 'lookup_cve',
    description: 'Look up a CVE identifier to get vulnerability details including severity, description, and affected products. Use this when analyzing exposures that reference specific CWEs or when you need current vulnerability intelligence.',
    parameters: {
      type: 'object',
      properties: {
        cve_id: { type: 'string', description: 'CVE identifier (e.g., CVE-2024-1234)' },
      },
      required: ['cve_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'validate_finding',
    description: 'Cross-reference a potential finding against the parsed threat model. Check if an exposure, mitigation, or control already exists for a given asset+threat pair.',
    parameters: {
      type: 'object',
      properties: {
        asset: { type: 'string', description: 'Asset ID or path (e.g., #auth-api or Server.Auth)' },
        threat: { type: 'string', description: 'Threat ID or name (e.g., #sqli or SQL_Injection)' },
        check: { type: 'string', description: 'What to check', enum: ['exposure_exists', 'mitigation_exists', 'is_unmitigated'] },
      },
      required: ['asset', 'threat', 'check'],
      additionalProperties: false,
    },
  },
  {
    name: 'search_codebase',
    description: `Search project source files for a pattern (case-insensitive substring match). Returns matching lines with file paths and line numbers, and reports whether the result set was truncated. Use this to verify code-level claims during threat analysis.`,
    parameters: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Search pattern (substring, case-insensitive)' },
        file_glob: {
          type: 'string',
          description: `Restrict the search to matching filenames. Comma-separated. Accepts extensions ("ts", ".ts"), globs against the basename ("*.test.ts", "auth*.py"), or several at once ("ts,tsx"). Omit to search every source file.`,
        },
        max_results: {
          type: 'integer',
          description: `Maximum matching lines to return. Default ${DEFAULT_MAX_RESULTS}, capped at ${HARD_MAX_RESULTS}. Raise it when a broad pattern is expected to match widely — a truncated result set reports truncated: true, and reasoning over it as if it were complete is the failure this exists to prevent.`,
          minimum: 1,
          maximum: HARD_MAX_RESULTS,
        },
      },
      required: ['pattern'],
      additionalProperties: false,
    },
  },
];

// ─── Tool executor ───────────────────────────────────────────────────

/**
 * Create a tool executor bound to a project root and threat model.
 * The executor handles all GuardLink tool calls.
 */
export function createToolExecutor(root: string, model: ThreatModel | null): ToolExecutor {
  return async (name: string, args: Record<string, any>): Promise<string> => {
    switch (name) {
      case 'lookup_cve':
        return lookupCve(args.cve_id);
      case 'validate_finding':
        return validateFinding(model, args.asset, args.threat, args.check);
      case 'search_codebase':
        return searchCodebase(root, args.pattern, args.file_glob, clampMaxResults(args.max_results));
      default:
        return `Unknown tool: ${name}`;
    }
  };
}

// ─── Tool implementations ────────────────────────────────────────────

/** Fetch CVE details from NVD API */
async function lookupCve(cveId: string): Promise<string> {
  if (!cveId || !cveId.match(/^CVE-\d{4}-\d{4,}$/i)) {
    return `Invalid CVE ID format: ${cveId}. Expected format: CVE-YYYY-NNNNN`;
  }

  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId.toUpperCase())}`;
    const res = await fetch(url, {
      headers: { 'User-Agent': 'GuardLink/1.0 (threat-modeling-tool)' },
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      return `NVD API returned ${res.status} for ${cveId}`;
    }

    const data = await res.json() as any;
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return `No data found for ${cveId}`;

    const desc = vuln.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description';
    const metrics = vuln.metrics?.cvssMetricV31?.[0]?.cvssData || vuln.metrics?.cvssMetricV40?.[0]?.cvssData;
    const score = metrics?.baseScore || 'N/A';
    const severity = metrics?.baseSeverity || 'N/A';

    const cwes = vuln.weaknesses?.flatMap((w: any) =>
      w.description?.map((d: any) => d.value)
    )?.filter(Boolean) || [];

    return JSON.stringify({
      id: cveId.toUpperCase(),
      description: desc.slice(0, 500),
      cvss_score: score,
      severity,
      cwes,
      published: vuln.published,
      last_modified: vuln.lastModified,
    });
  } catch (err: any) {
    return `CVE lookup failed: ${err.message}`;
  }
}

/** Validate a finding against the parsed threat model */
function validateFinding(
  model: ThreatModel | null,
  asset: string,
  threat: string,
  check: string,
): string {
  if (!model) return 'No threat model available. Run guardlink parse first.';

  const normalizeId = (s: string) => s.replace(/^#/, '').toLowerCase();
  const assetId = normalizeId(asset);
  const threatId = normalizeId(threat);

  const matchAsset = (a: string) => normalizeId(a) === assetId;
  const matchThreat = (t: string) => normalizeId(t) === threatId;

  switch (check) {
    case 'exposure_exists': {
      const found = model.exposures.filter(e => matchAsset(e.asset) && matchThreat(e.threat));
      if (found.length) {
        return JSON.stringify({
          exists: true,
          count: found.length,
          exposures: found.map(e => ({
            severity: e.severity,
            description: e.description,
            file: e.location.file,
            line: e.location.line,
          })),
        });
      }
      return JSON.stringify({ exists: false });
    }
    case 'mitigation_exists': {
      const found = model.mitigations.filter(m => matchAsset(m.asset) && matchThreat(m.threat));
      if (found.length) {
        return JSON.stringify({
          exists: true,
          count: found.length,
          mitigations: found.map(m => ({
            control: m.control,
            description: m.description,
            file: m.location.file,
            line: m.location.line,
          })),
        });
      }
      return JSON.stringify({ exists: false });
    }
    case 'is_unmitigated': {
      // D57: this is the "is it already handled?" question the LLM tool loop
      // asks, and it answered by matching mitigations against the QUERY rather
      // than against the matched exposures — so a mitigation anywhere on the
      // asset/threat pair answered for every site of it. Now the coverage
      // question is asked per matched exposure, which is what makes the answer
      // site-aware and `#`-normalised like every other surface.
      //
      // Entitlements are deliberately NOT consulted here. @entitles carries no
      // export or suppression semantics (design §3.2): an entitled exposure is
      // still unmitigated, still probed, still reported. Only downstream triage
      // may soften the recommendation. Do not add it to this check.
      const matching = model.exposures.filter(e => matchAsset(e.asset) && matchThreat(e.threat));
      const coverage = buildCoverageIndex(model);
      const exposed = matching.length > 0;
      return JSON.stringify({
        exposed,
        mitigated: matching.some(e => coverage.isMitigated(e)),
        accepted: matching.some(e => coverage.isAccepted(e)),
        unmitigated: matching.some(e => !coverage.isCovered(e)),
      });
    }
    default:
      return `Unknown check type: ${check}. Use: exposure_exists, mitigation_exists, is_unmitigated`;
  }
}

/** Search project source files for a pattern */
function searchCodebase(
  root: string,
  pattern: string,
  fileGlob?: string,
  maxResults = DEFAULT_MAX_RESULTS,
): string {
  if (!pattern) return 'No search pattern provided';

  const results: { file: string; line: number; text: string }[] = [];
  const pat = pattern.toLowerCase();
  const globs = compileFileGlob(fileGlob);
  // Whether the walk stopped early. A caller that cannot tell a complete result
  // set from a capped one will read "3 matches" as "3 matches exist".
  let truncated = false;

  // Walk source files (skip node_modules, .git, dist, etc.)
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', '.guardlink', '__pycache__', '.next', 'vendor', 'target', '.bravos', '.bugb']);

  function walk(dir: string) {
    if (results.length >= maxResults) { truncated = true; return; }
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }

    for (const entry of entries) {
      if (results.length >= maxResults) { truncated = true; return; }
      const full = join(dir, entry);
      let stat;
      try { stat = statSync(full); } catch { continue; }

      if (stat.isDirectory()) {
        if (!skipDirs.has(entry) && !entry.startsWith('.')) walk(full);
      } else if (stat.isFile()) {
        if (globs && !globs.some(g => g.test(entry))) continue;
        // Skip binary / large files
        if (stat.size > 500_000) continue;
        if (/\.(png|jpg|gif|ico|woff|ttf|eot|svg|mp[34]|zip|tar|gz|lock|map)$/i.test(entry)) continue;

        try {
          const content = readFileSync(full, 'utf-8');
          const lines = content.split('\n');
          for (let i = 0; i < lines.length && results.length < maxResults; i++) {
            if (lines[i].toLowerCase().includes(pat)) {
              results.push({
                file: relative(root, full),
                line: i + 1,
                text: lines[i].trim().slice(0, 200),
              });
            }
          }
        } catch { /* skip unreadable */ }
      }
    }
  }

  walk(root);

  if (!results.length) {
    return JSON.stringify({
      matches: [],
      truncated: false,
      note: globs
        ? `No matches for "${pattern}" in files matching "${fileGlob}". The filter may be excluding the files you want — retry without file_glob to confirm.`
        : `No matches found for "${pattern}".`,
    });
  }

  return JSON.stringify({
    matches: results,
    count: results.length,
    truncated,
    ...(truncated
      ? { note: `Stopped at the max_results limit of ${maxResults}. More matches exist — this result set is INCOMPLETE. Raise max_results (up to ${HARD_MAX_RESULTS}) or narrow the pattern before concluding anything about coverage.` }
      : {}),
  });
}
