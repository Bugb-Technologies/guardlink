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
 * @exposes #llm-client to #dos [low] cwe:CWE-400 -- "searchCodebase reads many files; bounded by maxResults"
 * @mitigates #llm-client against #dos using #resource-limits -- "maxResults caps output; stat.size < 500KB filter"
 * @flows LLMToolCall -> #llm-client via createToolExecutor -- "Tool invocation input"
 * @flows #llm-client -> NVD via fetch -- "CVE lookup API call"
 * @flows ProjectFiles -> #llm-client via readFileSync -- "Codebase search reads"
 * @boundary #llm-client and NVD (#nvd-api-boundary) -- "Trust boundary at external API"
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import type { ToolDefinition, ToolExecutor } from './llm.js';
import type { ThreatModel } from '../types/index.js';

// ─── Tool definitions ────────────────────────────────────────────────

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
    description: 'Search project source files for a pattern (case-insensitive substring match). Returns matching lines with file paths and line numbers. Use this to verify code-level claims during threat analysis.',
    parameters: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Search pattern (substring, case-insensitive)' },
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
        return searchCodebase(root, args.pattern, args.file_glob, parseInt(args.max_results || '20', 10));
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
      const exposed = model.exposures.some(e => matchAsset(e.asset) && matchThreat(e.threat));
      const mitigated = model.mitigations.some(m => matchAsset(m.asset) && matchThreat(m.threat));
      const accepted = model.acceptances.some(a => matchAsset(a.asset) && matchThreat(a.threat));
      return JSON.stringify({ exposed, mitigated, accepted, unmitigated: exposed && !mitigated && !accepted });
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
  maxResults = 20,
): string {
  if (!pattern) return 'No search pattern provided';

  const results: { file: string; line: number; text: string }[] = [];
  const pat = pattern.toLowerCase();
  const ext = fileGlob ? fileGlob.toLowerCase() : null;

  // Walk source files (skip node_modules, .git, dist, etc.)
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', '.guardlink', '__pycache__', '.next', 'vendor', 'target']);

  function walk(dir: string) {
    if (results.length >= maxResults) return;
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }

    for (const entry of entries) {
      if (results.length >= maxResults) return;
      const full = join(dir, entry);
      let stat;
      try { stat = statSync(full); } catch { continue; }

      if (stat.isDirectory()) {
        if (!skipDirs.has(entry) && !entry.startsWith('.')) walk(full);
      } else if (stat.isFile()) {
        if (ext && !entry.toLowerCase().endsWith(ext)) continue;
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

  if (!results.length) return `No matches found for "${pattern}"`;
  return JSON.stringify(results);
}
