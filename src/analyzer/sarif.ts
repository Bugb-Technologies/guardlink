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
 *   2. Parse errors (annotation syntax problems)
 *   3. Dangling references (broken #id refs)
 *
 * @exposes #sarif to #info-disclosure [low] cwe:CWE-200 -- "SARIF output contains detailed threat model findings"
 * @accepts #info-disclosure on #sarif -- "SARIF export for security tools is the intended feature"
 * @exposes #sarif to #arbitrary-write [high] cwe:CWE-73 -- "SARIF written to user-specified output path"
 * @mitigates #sarif against #arbitrary-write using #path-validation -- "CLI resolves output path before write"
 * @flows #parser -> #sarif via ThreatModel -- "SARIF generator receives parsed threat model"
 * @flows #sarif -> External_Security_Tools via SARIF_JSON -- "Output consumed by GitHub, VS Code, etc."
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
          version: '1.1.0',
          informationUri: 'https://guardlink.bugb.io',
          rules: RULES,
        },
      },
      results,
    }],
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────

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
