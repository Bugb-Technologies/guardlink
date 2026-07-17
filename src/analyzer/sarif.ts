/**
 * GuardLink SARIF — Convert threat model findings to SARIF 2.1.0.
 *
 * SARIF (Static Analysis Results Interchange Format) is consumed by:
 *   - GitHub Advanced Security (code scanning alerts)
 *   - VS Code SARIF Viewer extension
 *   - Azure DevOps
 *   - SonarQube, Snyk, etc.
 *
 * We emit results for:
 *   1. Unmitigated exposures (the primary security findings)
 *   2. @confirmed verified exploitable annotations (always error-level)
 *   3. Parse errors (annotation syntax problems)
 *   4. Dangling references (broken #id refs)
 *
 * @exposes #sarif to #data-exposure [low] cwe:CWE-200 -- "Exposes threat model findings to SARIF consumers"
 * @audit #sarif -- "SARIF output intentionally reveals security findings for CI/CD integration"
 * @comment -- "Pure function: transforms ThreatModel to SARIF JSON; no I/O"
 * @comment -- "Exposure and confirmed results carry codegraph_reachability{http_method,http_path} derived from the asset's inbound @flows route so downstream HTTP consumers (e.g. cert-x-gen) can target the endpoint; emitted verbatim from the annotation, no base path assumed"
 * @flows ThreatModel -> #sarif via generateSarif -- "Model input"
 * @flows #sarif -> SarifLog via return -- "SARIF output"
 */

import type { ThreatModel, ThreatModelExposure, ParseDiagnostic, Severity } from '../types/index.js';

// ─── SARIF 2.1.0 types (subset) ─────────────────────────────────────

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note';
  };
  properties?: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: {
      startLine: number;
      startColumn?: number;
    };
  };
}

// ─── Rule definitions ────────────────────────────────────────────────

const RULES: SarifRule[] = [
  {
    id: 'guardlink/unmitigated-exposure',
    name: 'UnmitigatedExposure',
    shortDescription: { text: 'Asset exposed to threat with no mitigation or acceptance' },
    fullDescription: { text: 'An @exposes annotation exists but no matching @mitigates or @accepts covers this (asset, threat) pair. This represents an acknowledged but unaddressed security risk.' },
    helpUri: 'https://guardlink.bugb.io/docs/exposures',
    defaultConfiguration: { level: 'warning' },
  },
  {
    id: 'guardlink/unmitigated-critical',
    name: 'UnmitigatedCriticalExposure',
    shortDescription: { text: 'Critical/high severity exposure with no mitigation' },
    fullDescription: { text: 'A critical or high severity exposure exists without mitigation. This should be addressed before deployment.' },
    helpUri: 'https://guardlink.bugb.io/docs/exposures',
    defaultConfiguration: { level: 'error' },
  },
  {
    id: 'guardlink/confirmed-exploitable',
    name: 'ConfirmedExploitable',
    shortDescription: { text: 'Threat verified exploitable through testing' },
    fullDescription: { text: 'A @confirmed annotation marks this threat as verified through pentest, scanning, or manual reproduction. This is not a false positive and requires immediate remediation.' },
    helpUri: 'https://guardlink.bugb.io/docs/confirmed',
    defaultConfiguration: { level: 'error' },
  },
  {
    id: 'guardlink/parse-error',
    name: 'AnnotationParseError',
    shortDescription: { text: 'Malformed GuardLink annotation' },
    fullDescription: { text: 'A GuardLink annotation could not be parsed. Check syntax against the specification.' },
    helpUri: 'https://guardlink.bugb.io/docs/syntax',
    defaultConfiguration: { level: 'error' },
  },
  {
    id: 'guardlink/dangling-ref',
    name: 'DanglingReference',
    shortDescription: { text: 'Reference to undefined threat, control, or asset ID' },
    fullDescription: { text: 'An annotation references a #id that is not defined anywhere in the project.' },
    helpUri: 'https://guardlink.bugb.io/docs/definitions',
    defaultConfiguration: { level: 'warning' },
  },
];

// ─── Generator ───────────────────────────────────────────────────────

export interface SarifOptions {
  /** Include parse diagnostics as results */
  includeDiagnostics?: boolean;
  /** Include dangling reference warnings */
  includeDanglingRefs?: boolean;
  /** Only include unmitigated exposures at or above this severity */
  minSeverity?: Severity;
}

export function generateSarif(
  model: ThreatModel,
  diagnostics: ParseDiagnostic[] = [],
  danglingRefs: ParseDiagnostic[] = [],
  options: SarifOptions = {},
): SarifLog {
  const { includeDiagnostics = true, includeDanglingRefs = true } = options;

  const results: SarifResult[] = [];

  // ── Unmitigated exposures ──
  const mitigated = new Set<string>();
  const accepted = new Set<string>();
  for (const m of model.mitigations) mitigated.add(`${m.asset}::${m.threat}`);
  for (const a of model.acceptances) accepted.add(`${a.asset}::${a.threat}`);

  // Route lookup so each finding can carry the HTTP endpoint it is reachable
  // through. Routes live on @flows (mechanism "METHOD./path"); index them by the
  // flow's source file and by its target asset, then match each finding below.
  const routeByFile = new Map<string, HttpRoute>();
  const routeByAsset = new Map<string, HttpRoute>();
  for (const f of model.flows) {
    const route = extractRoute(f.mechanism);
    if (!route) continue;
    if (f.location?.file && !routeByFile.has(f.location.file)) routeByFile.set(f.location.file, route);
    if (f.target && !routeByAsset.has(f.target)) routeByAsset.set(f.target, route);
  }
  const reachabilityFor = (asset: string, file: string) => {
    // Prefer the route from the same handler file (an asset often fronts several
    // routes); fall back to the asset's inbound route.
    const route = routeByFile.get(file) ?? routeByAsset.get(asset);
    return route ? { codegraph_reachability: { http_method: route.method, http_path: route.path } } : {};
  };

  for (const e of model.exposures) {
    const key = `${e.asset}::${e.threat}`;
    if (mitigated.has(key) || accepted.has(key)) continue;

    // Severity filter
    if (options.minSeverity && !meetsMinSeverity(e.severity, options.minSeverity)) continue;

    const isCritical = e.severity === 'critical' || e.severity === 'high';
    const ruleId = isCritical ? 'guardlink/unmitigated-critical' : 'guardlink/unmitigated-exposure';
    const level = isCritical ? 'error' as const : 'warning' as const;

    const threat = e.threat.startsWith('#') ? e.threat.slice(1) : e.threat;
    const desc = e.description ? `: ${e.description}` : '';

    results.push({
      ruleId,
      level,
      message: { text: `${e.asset} is exposed to ${threat}${desc}` },
      locations: [locationFrom(e.location.file, e.location.line)],
      properties: {
        severity: e.severity || 'unset',
        asset: e.asset,
        threat: e.threat,
        ...(e.external_refs.length > 0 ? { externalRefs: e.external_refs } : {}),
        ...reachabilityFor(e.asset, e.location.file),
      },
    });
  }

  // ── Confirmed exploitable ──
  for (const c of (model.confirmed || [])) {
    const threat = c.threat.startsWith('#') ? c.threat.slice(1) : c.threat;
    const desc = c.description ? `: ${c.description}` : '';

    results.push({
      ruleId: 'guardlink/confirmed-exploitable',
      level: 'error',
      message: { text: `CONFIRMED: ${c.asset} exploitable via ${threat}${desc}` },
      locations: [locationFrom(c.location.file, c.location.line)],
      properties: {
        severity: c.severity || 'unset',
        asset: c.asset,
        threat: c.threat,
        ...(c.external_refs.length > 0 ? { externalRefs: c.external_refs } : {}),
        ...reachabilityFor(c.asset, c.location.file),
      },
    });
  }

  // ── Parse errors ──
  if (includeDiagnostics) {
    for (const d of diagnostics) {
      if (d.level !== 'error') continue;
      results.push({
        ruleId: 'guardlink/parse-error',
        level: 'error',
        message: { text: d.message },
        locations: [locationFrom(d.file, d.line)],
      });
    }
  }

  // ── Dangling refs ──
  if (includeDanglingRefs) {
    for (const d of danglingRefs) {
      results.push({
        ruleId: 'guardlink/dangling-ref',
        level: 'warning',
        message: { text: d.message },
        locations: [locationFrom(d.file, d.line)],
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'GuardLink',
          version: '1.4.3',
          informationUri: 'https://guardlink.bugb.io',
          rules: RULES,
        },
      },
      results,
    }],
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────

interface HttpRoute {
  method: string;
  path: string;
}

const ROUTE_MECHANISM_RE = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\.(\/\S*)/i;

/**
 * Parse a @flows mechanism such as "GET./websocket/attach?endpointId&id" or
 * "POST./restore (multipart)" into { method, path }. Returns undefined when the
 * mechanism is not an HTTP route (e.g. "tar.NewReader"). The path is emitted
 * verbatim from the annotation — no base path (e.g. /api) is assumed.
 */
function extractRoute(mechanism?: string): HttpRoute | undefined {
  if (!mechanism) return undefined;
  const m = ROUTE_MECHANISM_RE.exec(mechanism.trim());
  if (!m) return undefined;
  const path = m[2].split('?')[0].replace(/\s*\(.*?\)\s*/g, '').trim();
  if (!path) return undefined;
  return { method: m[1].toUpperCase(), path };
}

function locationFrom(file: string, line: number): SarifLocation {
  // SARIF uses forward-slash URIs
  const uri = file.replace(/\\/g, '/');
  return {
    physicalLocation: {
      artifactLocation: { uri },
      region: { startLine: line },
    },
  };
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function meetsMinSeverity(actual?: Severity, min?: Severity): boolean {
  if (!actual || !min) return true;
  return (SEV_ORDER[actual] ?? 4) <= (SEV_ORDER[min] ?? 4);
}
