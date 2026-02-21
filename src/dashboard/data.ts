/**
 * GuardLink Dashboard — Data transformation.
 * Converts ThreatModel into dashboard-ready statistics.
 */

import type { ThreatModel } from '../types/index.js';

/** Normalize a ref: strip leading # so that "#sqli" and "sqli" compare equal. */
function normalizeRef(ref: string): string {
  return ref.startsWith('#') ? ref.slice(1) : ref;
}

export interface DashboardStats {
  annotations: number;
  sourceFiles: number;
  assets: number;
  threats: number;
  controls: number;
  mitigations: number;
  exposures: number;
  acceptances: number;
  transfers: number;
  flows: number;
  boundaries: number;
  comments: number;
  coveragePercent: number;
  coverageAnnotated: number;
  coverageTotal: number;
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unset: number;
}

export interface ExposureRow {
  asset: string;
  threat: string;
  severity: string;
  description: string;
  file: string;
  line: number;
  mitigated: boolean;
  accepted: boolean;
}

export interface AssetHeatmapEntry {
  name: string;
  exposures: number;
  mitigations: number;
  flows: number;
  dataHandling: string[];
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
}

export function computeStats(model: ThreatModel): DashboardStats {
  return {
    annotations: model.annotations_parsed,
    sourceFiles: model.source_files,
    assets: model.assets.length,
    threats: model.threats.length,
    controls: model.controls.length,
    mitigations: model.mitigations.length,
    exposures: model.exposures.length,
    acceptances: model.acceptances.length,
    transfers: model.transfers.length,
    flows: model.flows.length,
    boundaries: model.boundaries.length,
    comments: model.comments.length,
    coveragePercent: model.coverage.coverage_percent,
    coverageAnnotated: model.coverage.annotated_symbols,
    coverageTotal: model.coverage.total_symbols,
  };
}

export function computeSeverity(model: ThreatModel): SeverityBreakdown {
  const result: SeverityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, unset: 0 };
  for (const e of model.exposures) {
    const sev = (e.severity || '').toLowerCase();
    if (sev === 'critical' || sev === 'p0') result.critical++;
    else if (sev === 'high' || sev === 'p1') result.high++;
    else if (sev === 'medium' || sev === 'p2') result.medium++;
    else if (sev === 'low' || sev === 'p3') result.low++;
    else result.unset++;
  }
  return result;
}

export function computeExposures(model: ThreatModel): ExposureRow[] {
  const mitigatedSet = new Set<string>();
  for (const m of model.mitigations) mitigatedSet.add(`${normalizeRef(m.asset)}::${normalizeRef(m.threat)}`);
  const acceptedSet = new Set<string>();
  for (const a of model.acceptances) acceptedSet.add(`${normalizeRef(a.asset)}::${normalizeRef(a.threat)}`);

  return model.exposures.map(e => {
    const key = `${normalizeRef(e.asset)}::${normalizeRef(e.threat)}`;
    return {
      asset: e.asset,
      threat: e.threat,
      severity: e.severity || 'unset',
      description: e.description || '',
      file: e.location.file,
      line: e.location.line,
      mitigated: mitigatedSet.has(key),
      accepted: acceptedSet.has(key),
    };
  });
}

export function computeAssetHeatmap(model: ThreatModel): AssetHeatmapEntry[] {
  const assetNames = new Set<string>();
  for (const a of model.assets) assetNames.add(a.path.join('.'));
  // Also collect assets referenced in exposures/mitigations
  for (const e of model.exposures) assetNames.add(e.asset);
  for (const m of model.mitigations) assetNames.add(m.asset);
  for (const f of model.flows) { assetNames.add(f.source); assetNames.add(f.target); }

  return Array.from(assetNames).map(name => {
    const exposures = model.exposures.filter(e => e.asset === name).length;
    const mitigations = model.mitigations.filter(m => m.asset === name).length;
    const flows = model.flows.filter(f => f.source === name || f.target === name).length;
    const dataHandling = model.data_handling.filter(h => h.asset === name).map(h => h.classification);
    const unmitigated = exposures - mitigations;

    let riskLevel: AssetHeatmapEntry['riskLevel'] = 'none';
    if (unmitigated >= 3) riskLevel = 'critical';
    else if (unmitigated >= 2) riskLevel = 'high';
    else if (unmitigated >= 1) riskLevel = 'medium';
    else if (exposures > 0) riskLevel = 'low';

    return { name, exposures, mitigations, flows, dataHandling, riskLevel };
  }).sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
    return order[a.riskLevel] - order[b.riskLevel];
  });
}
