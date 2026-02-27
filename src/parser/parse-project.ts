/**
 * GuardLink — Project-level parser.
 * Walks a directory, parses all source files, and assembles a ThreatModel.
 *
 * @exposes #parser to #path-traversal [high] cwe:CWE-22 -- "Glob patterns could escape root directory"
 * @mitigates #parser against #path-traversal using #glob-filtering -- "DEFAULT_EXCLUDE blocks node_modules, .git; fast-glob cwd constrains scan"
 * @exposes #parser to #dos [medium] cwe:CWE-400 -- "Large projects with many files could exhaust memory"
 * @mitigates #parser against #dos using #resource-limits -- "DEFAULT_EXCLUDE skips build artifacts, tests; limits effective file count"
 * @flows ProjectRoot -> #parser via fast-glob -- "Directory traversal path"
 * @flows #parser -> ThreatModel via assembleModel -- "Aggregated threat model output"
 * @boundary #parser and FileSystem (#fs-boundary) -- "Trust boundary between parser and disk I/O"
 */

import fg from 'fast-glob';
import { relative } from 'node:path';
import type {
  Annotation, ThreatModel, ParseResult, ParseDiagnostic,
  AssetAnnotation, ThreatAnnotation, ControlAnnotation,
  MitigatesAnnotation, ExposesAnnotation, AcceptsAnnotation,
  TransfersAnnotation, FlowsAnnotation, BoundaryAnnotation,
  ValidatesAnnotation, AuditAnnotation, OwnsAnnotation,
  HandlesAnnotation, AssumesAnnotation, ShieldAnnotation,
  CommentAnnotation,
  DataClassification,
  ExternalRef, AnnotationVerb, SourceLocation,
} from '../types/index.js';
import { parseFile } from './parse-file.js';
import { loadWorkspaceConfig } from '../workspace/index.js';

export interface ParseProjectOptions {
  /** Root directory to scan */
  root: string;
  /** Glob patterns to include (default: common source files) */
  include?: string[];
  /** Glob patterns to exclude (default: node_modules, dist, .git) */
  exclude?: string[];
  /** Project name for the ThreatModel */
  project?: string;
}

const DEFAULT_INCLUDE = [
  '**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx',
  '**/*.py', '**/*.rb', '**/*.go', '**/*.rs',
  '**/*.java', '**/*.kt', '**/*.scala',
  '**/*.c', '**/*.cpp', '**/*.cc', '**/*.h', '**/*.hpp',
  '**/*.cs', '**/*.swift', '**/*.dart',
  '**/*.sql', '**/*.lua', '**/*.hs',
  '**/*.tf', '**/*.hcl',
  '**/*.yaml', '**/*.yml',
  '**/*.sh', '**/*.bash',
  '**/*.html', '**/*.xml', '**/*.svg',
  '**/*.css',
  '**/*.ex', '**/*.exs',
];

const DEFAULT_EXCLUDE = [
  '**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**',
  '**/__pycache__/**', '**/target/**', '**/vendor/**', '**/.next/**',
  '**/tests/**', '**/test/**', '**/__tests__/**',
];

/**
 * Parse an entire project directory and return a ThreatModel.
 */
export async function parseProject(options: ParseProjectOptions): Promise<{
  model: ThreatModel;
  diagnostics: ParseDiagnostic[];
}> {
  const {
    root,
    include = DEFAULT_INCLUDE,
    exclude = DEFAULT_EXCLUDE,
    project = 'unknown',
  } = options;

  // Discover files (dot: true to include .guardlink/ definitions)
  const files = await fg(include, {
    cwd: root,
    ignore: exclude,
    absolute: true,
    dot: true,
  });

  // Parse all files
  const allAnnotations: Annotation[] = [];
  const allDiagnostics: ParseDiagnostic[] = [];
  const filesWithAnnotations = new Set<string>();

  for (const file of files) {
    const result = await parseFile(file);
    const relPath = relative(root, file);
    // Normalize file paths to relative
    for (const ann of result.annotations) {
      ann.location.file = relPath;
    }
    for (const diag of result.diagnostics) {
      diag.file = relPath;
    }
    if (result.annotations.length > 0) {
      filesWithAnnotations.add(relPath);
    }
    allAnnotations.push(...result.annotations);
    allDiagnostics.push(...result.diagnostics);
  }

  // Check for duplicate identifiers
  const idMap = new Map<string, Annotation>();
  for (const ann of allAnnotations) {
    const id = getAnnotationId(ann);
    if (id) {
      if (idMap.has(id)) {
        const prev = idMap.get(id)!;
        allDiagnostics.push({
          level: 'error',
          message: `Duplicate identifier #${id} (first defined at ${prev.location.file}:${prev.location.line})`,
          file: ann.location.file,
          line: ann.location.line,
        });
      } else {
        idMap.set(id, ann);
      }
    }
  }

  // Compute annotated vs unannotated files (exclude .guardlink/ definitions from unannotated)
  const allRelPaths = files.map(f => relative(root, f));
  const annotatedFiles = [...filesWithAnnotations].sort();
  const unannotatedFiles = allRelPaths
    .filter(f => !filesWithAnnotations.has(f) && !f.startsWith('.guardlink/') && !f.startsWith('.guardlink\\'))
    .sort();

  // Assemble ThreatModel
  const model = assembleModel(allAnnotations, files.length, project, annotatedFiles, unannotatedFiles);

  // Detect cross-repo tag references (requires workspace.yaml)
  model.external_refs = detectExternalRefs(model, root);

  return { model, diagnostics: allDiagnostics };
}

function getAnnotationId(ann: Annotation): string | undefined {
  if ('id' in ann) return (ann as any).id;
  return undefined;
}

function assembleModel(annotations: Annotation[], fileCount: number, project: string, annotatedFiles: string[], unannotatedFiles: string[]): ThreatModel {
  const model: ThreatModel = {
    version: '1.1.0',
    project,
    generated_at: new Date().toISOString(),
    source_files: fileCount,
    annotations_parsed: annotations.length,
    annotated_files: annotatedFiles,
    unannotated_files: unannotatedFiles,
    assets: [],
    threats: [],
    controls: [],
    mitigations: [],
    exposures: [],
    acceptances: [],
    transfers: [],
    flows: [],
    boundaries: [],
    validations: [],
    audits: [],
    ownership: [],
    data_handling: [],
    assumptions: [],
    shields: [],
    comments: [],
    coverage: {
      total_symbols: 0,
      annotated_symbols: annotations.length,
      coverage_percent: 0,
      unannotated_critical: [],
    },
  };

  for (const ann of annotations) {
    switch (ann.verb) {
      case 'asset': {
        const a = ann as AssetAnnotation;
        model.assets.push({
          path: a.path.split('.'),
          id: a.id,
          description: a.description,
          location: a.location,
        });
        break;
      }
      case 'threat': {
        const t = ann as ThreatAnnotation;
        model.threats.push({
          name: t.name,
          canonical_name: t.canonical_name,
          id: t.id,
          severity: t.severity,
          external_refs: t.external_refs,
          description: t.description,
          location: t.location,
        });
        break;
      }
      case 'control': {
        const c = ann as ControlAnnotation;
        model.controls.push({
          name: c.name,
          canonical_name: c.canonical_name,
          id: c.id,
          description: c.description,
          location: c.location,
        });
        break;
      }
      case 'mitigates': {
        const m = ann as MitigatesAnnotation;
        model.mitigations.push({
          asset: m.asset, threat: m.threat, control: m.control,
          description: m.description, location: m.location,
        });
        break;
      }
      case 'exposes': {
        const e = ann as ExposesAnnotation;
        model.exposures.push({
          asset: e.asset, threat: e.threat, severity: e.severity,
          external_refs: e.external_refs,
          description: e.description, location: e.location,
        });
        break;
      }
      case 'accepts': {
        const a = ann as AcceptsAnnotation;
        model.acceptances.push({
          threat: a.threat, asset: a.asset,
          description: a.description, location: a.location,
        });
        break;
      }
      case 'transfers': {
        const t = ann as TransfersAnnotation;
        model.transfers.push({
          threat: t.threat, source: t.source, target: t.target,
          description: t.description, location: t.location,
        });
        break;
      }
      case 'flows': {
        const f = ann as FlowsAnnotation;
        model.flows.push({
          source: f.source, target: f.target, mechanism: f.mechanism,
          description: f.description, location: f.location,
        });
        break;
      }
      case 'boundary': {
        const b = ann as BoundaryAnnotation;
        model.boundaries.push({
          asset_a: b.asset_a, asset_b: b.asset_b, id: b.id,
          description: b.description, location: b.location,
        });
        break;
      }
      case 'validates': {
        const v = ann as ValidatesAnnotation;
        model.validations.push({
          control: v.control, asset: v.asset,
          description: v.description, location: v.location,
        });
        break;
      }
      case 'audit': {
        const a = ann as AuditAnnotation;
        model.audits.push({
          asset: a.asset,
          description: a.description, location: a.location,
        });
        break;
      }
      case 'owns': {
        const o = ann as OwnsAnnotation;
        model.ownership.push({
          owner: o.owner, asset: o.asset,
          description: o.description, location: o.location,
        });
        break;
      }
      case 'handles': {
        const h = ann as HandlesAnnotation;
        model.data_handling.push({
          classification: h.classification as DataClassification,
          asset: h.asset,
          description: h.description, location: h.location,
        });
        break;
      }
      case 'assumes': {
        const a = ann as AssumesAnnotation;
        model.assumptions.push({
          asset: a.asset,
          description: a.description, location: a.location,
        });
        break;
      }
      case 'comment': {
        const c = ann as CommentAnnotation;
        model.comments.push({
          description: c.description, location: c.location,
        });
        break;
      }
      case 'shield':
      case 'shield:begin':
      case 'shield:end': {
        const s = ann as ShieldAnnotation;
        model.shields.push({
          reason: s.description,
          location: s.location,
        });
        break;
      }
    }
  }

  // Second pass: resolve exposure severity from threat definitions
  // when the @exposes annotation has no inline severity
  const threatSeverityMap = new Map<string, string>();
  for (const t of model.threats) {
    if (t.id && t.severity) threatSeverityMap.set(`#${t.id}`, t.severity);
    if (t.id && t.severity) threatSeverityMap.set(t.id, t.severity);
  }
  for (const e of model.exposures) {
    if (!e.severity) {
      e.severity = threatSeverityMap.get(e.threat) as any;
    }
  }

  // Detect external (cross-repo) tag references
  // (moved to parseProject where root is available)

  return model;
}

// ─── External ref detection ──────────────────────────────────────────

/**
 * Detect tag references that point to definitions in sibling repos.
 *
 * A tag like `#auth-lib.token-verify` is external if:
 *   - It contains a dot separator
 *   - The prefix before the first dot matches a sibling repo name
 *   - The tag is not defined locally (not in this repo's assets/threats/controls)
 *
 * Requires workspace.yaml to be present — returns [] if not in a workspace.
 */
function detectExternalRefs(model: ThreatModel, root: string): ExternalRef[] {
  const config = loadWorkspaceConfig(root);
  if (!config) return [];

  // Sibling repo names (exclude this repo)
  const siblingNames = new Set(
    config.repos
      .filter(r => r.name !== config.this_repo)
      .map(r => r.name),
  );
  if (siblingNames.size === 0) return [];

  // Local definitions — both with and without # prefix
  const localIds = new Set<string>();
  for (const a of model.assets) {
    if (a.id) { localIds.add(a.id); localIds.add(`#${a.id}`); }
  }
  for (const t of model.threats) {
    if (t.id) { localIds.add(t.id); localIds.add(`#${t.id}`); }
  }
  for (const c of model.controls) {
    if (c.id) { localIds.add(c.id); localIds.add(`#${c.id}`); }
  }

  const refs: ExternalRef[] = [];
  const seen = new Set<string>(); // dedup by tag+file+line

  function checkTag(tag: string | undefined, verb: AnnotationVerb, location: SourceLocation) {
    if (!tag) return;
    const key = `${tag}:${location.file}:${location.line}`;
    if (seen.has(key)) return;

    // Skip if locally defined
    if (localIds.has(tag)) return;

    // Strip leading # for prefix extraction
    const bare = tag.startsWith('#') ? tag.slice(1) : tag;
    const dotIdx = bare.indexOf('.');
    if (dotIdx < 1) return; // no dot or starts with dot — not a repo prefix

    const prefix = bare.slice(0, dotIdx);
    if (!siblingNames.has(prefix)) return;

    seen.add(key);
    refs.push({
      tag,
      context_verb: verb,
      location,
      inferred_repo: prefix,
    });
  }

  // Scan all relationship annotations for cross-repo tags
  for (const m of model.mitigations) {
    checkTag(m.asset, 'mitigates', m.location);
    checkTag(m.threat, 'mitigates', m.location);
    if (m.control) checkTag(m.control, 'mitigates', m.location);
  }
  for (const e of model.exposures) {
    checkTag(e.asset, 'exposes', e.location);
    checkTag(e.threat, 'exposes', e.location);
  }
  for (const a of model.acceptances) {
    checkTag(a.asset, 'accepts', a.location);
    checkTag(a.threat, 'accepts', a.location);
  }
  for (const t of model.transfers) {
    checkTag(t.source, 'transfers', t.location);
    checkTag(t.target, 'transfers', t.location);
    checkTag(t.threat, 'transfers', t.location);
  }
  for (const f of model.flows) {
    checkTag(f.source, 'flows', f.location);
    checkTag(f.target, 'flows', f.location);
  }
  for (const b of model.boundaries) {
    checkTag(b.asset_a, 'boundary', b.location);
    checkTag(b.asset_b, 'boundary', b.location);
  }

  return refs;
}
