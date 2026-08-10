/**
 * GuardLink MCP — File-anchored context (GL-201).
 *
 * Answers the question an agent asks most often and could not ask at all: "what
 * does GuardLink know about the file I just opened?"
 *
 * This is a projection, not new data. Every relation record already carries
 * `location.file`, and `@source` resolves that to the *logical* source file
 * before the model is assembled (parse-file.ts), so one grouping serves both
 * annotation modes. The only mode-specific value is `origin_file`, which names
 * the `.gal` an annotation was written in.
 *
 * The status vocabulary is the load-bearing part. "No annotations" and "never
 * looked at" are different answers, and returning an empty result for both is
 * how a caller concludes a file is clean when the parser simply never read it.
 *
 * @exposes #mcp to #path-traversal [medium] cwe:CWE-22 -- "Caller-supplied file path is resolved against the project root"
 * @mitigates #mcp against #path-traversal using #path-validation -- "Paths are resolved then required to stay inside root; outside paths are reported, never read"
 * @flows MCPClient -> #mcp via guardlink_context -- "File path input"
 * @flows ThreatModel -> #mcp via fileContext -- "Model grouped by location.file"
 * @comment -- "Pure projection over the parsed model; the only I/O is an existence check performed by the caller"
 */

import { isAbsolute, relative, resolve as resolvePath } from 'node:path';
import { lookup, type LookupResult } from './lookup.js';
import { buildCoverageIndex } from '../parser/coverage.js';
import type {
  ThreatModel, SourceLocation,
} from '../types/index.js';

/**
 * Why a file has no annotations — or whether "no annotations" is even the right
 * reading of the answer.
 */
export type FileContextStatus =
  /** Parsed, and it has annotations. */
  | 'annotated'
  /** Parsed, and it genuinely has none. The file is clean. */
  | 'scanned_without_annotations'
  /** Exists, but the parser never reads it — excluded, or not a scanned extension. */
  | 'not_scanned'
  /** Nothing at this path. */
  | 'not_found'
  /** Path resolved outside the project root. */
  | 'outside_root'
  /** The path is a `.gal` covering several source files; caller must pick one. */
  | 'ambiguous_origin';

export interface ContextAnnotation {
  verb: string;
  line: number;
  /** Set when the annotation was written in a `.gal` sidecar. */
  origin_file?: string;
  origin_line?: number;
  /** Enclosing symbol, when the `@source` block recorded one. */
  parent_symbol?: string;
  description?: string;
  /** Verb-specific fields — asset, threat, control, classification, owner, and so on. */
  [field: string]: unknown;
}

export interface FileContext {
  file: string;
  status: FileContextStatus;
  /** Where annotations for this file live. Null when there are none to observe. */
  annotation_source: 'inline' | 'external' | 'mixed' | null;
  /** `.gal` files that contribute annotations to this source file. */
  origin_files: string[];
  /** Set when the caller passed a `.gal` path and we resolved it to its source file. */
  resolved_from?: string;
  /** Set on `ambiguous_origin` — the source files that `.gal` covers. */
  logical_files?: string[];
  /** Narrowing applied when `line` was supplied. */
  symbol_scope?: {
    line: number;
    symbol: string | null;
    /** 'narrowed' when a symbol was found; 'unavailable' when no annotation here records one. */
    applied: 'narrowed' | 'unavailable';
    reason?: string;
  };
  counts: Record<string, number>;
  annotations: ContextAnnotation[];
  /** Assets this file's annotations name, each with its depth-1 neighbourhood. */
  assets: {
    ref: string;
    declared: boolean;
    matched_via?: string;
    relationships?: unknown;
    ambiguous?: boolean;
    candidates?: string[];
  }[];
  /** Exposures declared here that have no mitigation or acceptance anywhere. */
  open_exposures: ContextAnnotation[];
  hint?: string;
}

/** Extensions the parser scans, derived from the parser's own DEFAULT_INCLUDE. */
const SCANNED_EXTENSIONS = new Set([
  'ts', 'tsx', 'js', 'jsx', 'py', 'rb', 'go', 'rs', 'java', 'kt', 'scala',
  'c', 'cpp', 'cc', 'h', 'hpp', 'cs', 'swift', 'dart', 'sql', 'lua', 'hs',
  'tf', 'hcl', 'yaml', 'yml', 'sh', 'bash', 'html', 'xml', 'svg', 'css',
  'ex', 'exs', 'gal',
]);

function hasScannedExtension(path: string): boolean {
  const ext = path.slice(path.lastIndexOf('.') + 1).toLowerCase();
  return SCANNED_EXTENSIONS.has(ext);
}

/**
 * Reduce any caller-supplied path to the repo-relative form the model uses.
 *
 * Accepts absolute paths, `./`-prefixed paths, backslash separators and plain
 * relative paths. Returns null when the path escapes the root — reported rather
 * than silently clamped, because a path outside the project is a different
 * answer from a path with no annotations.
 */
export function normalizeContextPath(root: string, input: string): string | null {
  const cleaned = input.trim().replaceAll('\\', '/').replace(/^\.\//, '');
  const abs = isAbsolute(cleaned) ? cleaned : resolvePath(root, cleaned);
  const rel = relative(resolvePath(root), abs).replaceAll('\\', '/');
  if (rel === '' || rel.startsWith('../')) return null;
  return rel;
}

/** Every annotation in the model, flattened with its verb and location. */
function allRecords(model: ThreatModel): { verb: string; location: SourceLocation; row: any }[] {
  const out: { verb: string; location: SourceLocation; row: any }[] = [];
  const add = (verb: string, rows: { location: SourceLocation }[] | undefined) => {
    for (const row of rows || []) out.push({ verb, location: row.location, row });
  };
  add('asset', model.assets);
  add('threat', model.threats);
  add('control', model.controls);
  add('mitigates', model.mitigations);
  add('exposes', model.exposures);
  add('confirmed', model.confirmed);
  add('accepts', model.acceptances);
  add('transfers', model.transfers);
  add('flows', model.flows);
  add('boundary', model.boundaries);
  add('validates', model.validations);
  add('audit', model.audits);
  add('owns', model.ownership);
  add('handles', model.data_handling);
  add('assumes', model.assumptions);
  add('shield', model.shields);
  add('feature', model.features);
  add('comment', model.comments);
  return out;
}

/** Verb-specific fields, minus the location we surface separately. */
function projectRow(verb: string, row: any): ContextAnnotation {
  const { location, ...rest } = row;
  const ann: ContextAnnotation = { verb, line: location.line, ...rest };
  if (location.origin_file) ann.origin_file = location.origin_file;
  if (location.origin_line) ann.origin_line = location.origin_line;
  if (location.parent_symbol) ann.parent_symbol = location.parent_symbol;
  if (verb === 'asset' && Array.isArray(row.path)) ann.path = row.path.join('.');
  return ann;
}

/** Asset refs an annotation names, in whatever field the verb puts them. */
function assetRefsOf(verb: string, row: any): string[] {
  switch (verb) {
    case 'asset':     return [row.id ? `#${row.id}` : (row.path || []).join('.')];
    case 'exposes':
    case 'mitigates':
    case 'confirmed':
    case 'accepts':
    case 'audit':
    case 'owns':
    case 'handles':
    case 'assumes':
    case 'validates': return [row.asset];
    case 'flows':
    case 'transfers': return [row.source, row.target];
    case 'boundary':  return [row.asset_a, row.asset_b];
    default:          return [];
  }
}

export interface FileContextInput {
  /** Repo-relative path, already normalised. */
  file: string;
  /** Whether anything exists at that path on disk. */
  exists: boolean;
  /** Optional line to narrow to the enclosing symbol. */
  line?: number;
}

/**
 * Everything the model knows about one file.
 *
 * `exists` is injected rather than read here so the projection stays pure and
 * testable against a hand-built model.
 */
export function fileContext(model: ThreatModel, input: FileContextInput): FileContext {
  const { file, exists, line } = input;

  const records = allRecords(model);

  // A `.gal` path resolves to the source file it annotates, so the caller gets
  // the same answer whichever of the two they hold.
  const asOrigin = records.filter(r => r.location.origin_file === file);
  if (asOrigin.length > 0) {
    const logical = [...new Set(asOrigin.map(r => r.location.file))].sort();
    if (logical.length > 1) {
      return emptyContext(file, 'ambiguous_origin', {
        logical_files: logical,
        hint: `\`${file}\` carries @source blocks for ${logical.length} source files. Ask for one of them by name.`,
      });
    }
    return { ...fileContext(model, { file: logical[0], exists: true, line }), resolved_from: file };
  }

  const mine = records.filter(r => r.location.file === file);

  if (mine.length === 0) {
    const scanned = model.annotated_files.includes(file) || model.unannotated_files.includes(file)
      // `unannotated_files` drops the `.guardlink/` prefix (parse-project.ts),
      // so a scanned-but-unannotated file there appears in neither list.
      || (file.startsWith('.guardlink/') && hasScannedExtension(file) && exists);

    if (scanned) {
      return emptyContext(file, 'scanned_without_annotations', {
        hint: 'This file was parsed and has no GuardLink annotations. Not every file needs them — only those crossing a security boundary.',
      });
    }
    if (!exists) {
      return emptyContext(file, 'not_found', {
        hint: `Nothing exists at \`${file}\`. Check the path — it is resolved relative to the project root.`,
      });
    }
    return emptyContext(file, 'not_scanned', {
      hint: hasScannedExtension(file)
        ? `\`${file}\` exists but is not in the parser's scan set — it is under an excluded directory (node_modules, dist, build, test, tests, __tests__, vendor, target, .bravos, .bugb). Its annotations, if any, were never read.`
        : `\`${file}\` exists but its extension is not scanned, so it was never parsed. An empty result here does NOT mean the file is clean.`,
    });
  }

  // ── Symbol narrowing ──────────────────────────────────────────────
  let scoped = mine;
  let symbol_scope: FileContext['symbol_scope'];

  if (line !== undefined) {
    const anchored = mine.filter(r => r.location.parent_symbol);
    if (anchored.length === 0) {
      symbol_scope = {
        line, symbol: null, applied: 'unavailable',
        reason: 'No annotation for this file records a parent_symbol. @source blocks capture one; inline annotations do not, so there is nothing to narrow against.',
      };
    } else {
      // The enclosing symbol is the one anchored at or above the requested line.
      const enclosing = anchored
        .filter(r => r.location.line <= line)
        .sort((a, b) => b.location.line - a.location.line)[0]
        ?? anchored.sort((a, b) => a.location.line - b.location.line)[0];
      const symbol = enclosing.location.parent_symbol!;
      scoped = mine.filter(r => r.location.parent_symbol === symbol);
      symbol_scope = { line, symbol, applied: 'narrowed' };
    }
  }

  const annotations = scoped.map(r => projectRow(r.verb, r.row));

  // ── Annotation source ─────────────────────────────────────────────
  const external = scoped.filter(r => r.location.origin_file).length;
  const annotation_source: FileContext['annotation_source'] =
    external === 0 ? 'inline' : external === scoped.length ? 'external' : 'mixed';
  const origin_files = [...new Set(scoped.map(r => r.location.origin_file).filter(Boolean) as string[])].sort();

  // ── Assets named here, each with its depth-1 neighbourhood ────────
  //
  // Resolved through `lookup` rather than re-joining by hand, so the tier
  // semantics, identity join and ambiguity reporting are the ones every other
  // query already uses. A second implementation here is how D18 happened.
  const refs = [...new Set(scoped.flatMap(r => assetRefsOf(r.verb, r.row)).filter(Boolean))].sort();
  const assets = refs.map(ref => {
    const res: LookupResult = lookup(model, `asset ${ref}`);
    const rec = res.results[0];
    return {
      ref,
      declared: Boolean(rec?.declared),
      ...(res.matched_via ? { matched_via: res.matched_via } : {}),
      ...(res.ambiguous ? { ambiguous: true, candidates: res.candidates } : {}),
      ...(rec?.relationships ? { relationships: rec.relationships } : {}),
    };
  });

  // ── Open exposures declared here ──────────────────────────────────
  // D36. The exposure rows here carry their own location, so an exposure on one
  // symbol is no longer answered for by a mitigation on another in the same file.
  // This is the tool CLAUDE.md tells an agent to call before editing a file, so
  // an open_exposures of [] on a file with a live injection was the worst
  // instance of the defect.
  const coverage = buildCoverageIndex(model);
  const open_exposures = scoped
    .filter(r => r.verb === 'exposes'
      && !coverage.isCovered(r.row as unknown as { asset: string; threat: string; location: SourceLocation }))
    .map(r => projectRow(r.verb, r.row));

  const counts: Record<string, number> = {};
  for (const a of annotations) counts[a.verb] = (counts[a.verb] || 0) + 1;

  return {
    file,
    status: 'annotated',
    annotation_source,
    origin_files,
    ...(symbol_scope ? { symbol_scope } : {}),
    counts,
    annotations,
    assets,
    open_exposures,
  };
}

function emptyContext(
  file: string,
  status: FileContextStatus,
  extra: Partial<FileContext> = {},
): FileContext {
  return {
    file,
    status,
    annotation_source: null,
    origin_files: [],
    counts: {},
    annotations: [],
    assets: [],
    open_exposures: [],
    ...extra,
  };
}
