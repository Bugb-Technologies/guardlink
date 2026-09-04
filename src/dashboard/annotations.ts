/**
 * GuardLink Dashboard — the per-file annotation list behind the Code page
 * and its drawer, with a few lines of source context around each annotation.
 *
 * @exposes #dashboard to #path-traversal [medium] cwe:CWE-22 -- "readFileSync reads the file each annotation's location names, for the code context"
 * @mitigates #dashboard against #path-traversal using #path-validation -- "Relative locations are resolved against root; an absolute location is read as given because it came from the parser, not from a caller"
 * @flows SourceFiles -> #dashboard via readFileSync -- "Code snippet reads"
 * @comment -- "Ported unchanged from the first generate.ts; a file that cannot be read yields an empty context, never a failed page"
 */
import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import type { ThreatModel } from '../types/index.js';
import type { ExposureRow } from './data.js';

export interface FileAnnotation {
  kind: string;
  line: number;
  summary: string;
  description: string;
  raw: string;
  /** Surrounding source lines with line numbers. */
  codeContext: string[];
  /** Which index in codeContext is the annotation line. */
  annLineIdx: number;
}

export interface FileAnnotationGroup {
  file: string;
  annotations: FileAnnotation[];
}

/** Read source file lines and extract context around a given line. */
export function readCodeContext(filePath: string, line: number, root?: string, contextLines = 5): { lines: string[]; annIdx: number } {
  try {
    const abs = root && !isAbsolute(filePath) ? resolve(root, filePath) : filePath;
    const content = readFileSync(abs, 'utf-8');
    const allLines = content.split('\n');
    const start = Math.max(0, line - 1 - contextLines);
    const end = Math.min(allLines.length, line + contextLines);
    const slice = allLines.slice(start, end).map((l, i) => `${String(start + i + 1).padStart(4)} │ ${l}`);
    return { lines: slice, annIdx: line - 1 - start };
  } catch {
    return { lines: [], annIdx: 0 };
  }
}

type Located = { location?: { file: string; line: number; raw_text?: string }; description?: string };

export function buildFileAnnotations(model: ThreatModel, root?: string): FileAnnotationGroup[] {
  const byFile = new Map<string, FileAnnotation[]>();

  const addEntry = (kind: string, item: Located, summary: string): void => {
    if (!item.location) return;
    const file = item.location.file;
    if (!byFile.has(file)) byFile.set(file, []);
    const { lines: codeContext, annIdx } = readCodeContext(file, item.location.line, root);
    byFile.get(file)!.push({
      kind,
      line: item.location.line,
      summary,
      description: item.description || '',
      raw: item.location.raw_text || '',
      codeContext,
      annLineIdx: annIdx,
    });
  };

  const as = (x: unknown): Located => x as Located;
  for (const a of model.assets) addEntry('asset', as(a), a.path.join('.'));
  for (const t of model.threats) addEntry('threat', as(t), t.name);
  for (const c of model.controls) addEntry('control', as(c), c.name);
  for (const e of model.exposures) addEntry('exposes', as(e), `${e.asset} → ${e.threat}`);
  for (const cf of model.confirmed || []) addEntry('confirmed', as(cf), `${cf.asset} confirmed ${cf.threat}`);
  for (const m of model.mitigations) addEntry('mitigates', as(m), `${m.control} mitigates ${m.threat}`);
  for (const a of model.acceptances) addEntry('accepts', as(a), `${a.asset} accepts ${a.threat}`);
  for (const t of model.transfers) addEntry('transfers', as(t), `${t.source} → ${t.target}`);
  for (const f of model.flows) addEntry('flow', as(f), `${f.source} → ${f.target}`);
  for (const b of model.boundaries) addEntry('boundary', as(b), `${b.asset_a} ↔ ${b.asset_b}`);
  for (const h of model.data_handling) addEntry('handles', as(h), `${h.asset}: ${h.classification}`);
  for (const v of model.validations) addEntry('validates', as(v), `${v.control} validates ${v.asset}`);
  for (const o of model.ownership) addEntry('owns', as(o), `${o.owner} owns ${o.asset}`);
  for (const a of model.audits) addEntry('audit', as(a), `Audit: ${a.asset}`);
  for (const a of model.assumptions) addEntry('assumes', as(a), `Assumes: ${a.asset}`);
  for (const ac of model.actors || []) addEntry('actor', as(ac), `Actor: ${ac.name}`);
  for (const en of model.entitlements || []) addEntry('entitles', as(en), `${en.actor} entitled to ${en.capability}${en.inert ? ' (inert)' : ''}`);
  for (const s of model.shields) addEntry('shield', as(s), s.reason || 'Shielded region');
  for (const c of model.comments) addEntry('comment', as(c), c.description || 'Developer note');

  const result: FileAnnotationGroup[] = [];
  for (const [file, anns] of [...byFile.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    result.push({ file, annotations: anns.sort((a, b) => a.line - b.line) });
  }
  return result;
}

/** The three exposure subsets the legacy drawer and feature filter index into. */
export function buildAnalysisData(exposures: ExposureRow[]): { openExposures: ExposureRow[]; mitigatedExposures: ExposureRow[]; acceptedExposures: ExposureRow[] } {
  return {
    openExposures: exposures.filter(e => !e.mitigated && !e.accepted),
    mitigatedExposures: exposures.filter(e => e.mitigated),
    acceptedExposures: exposures.filter(e => e.accepted),
  };
}
