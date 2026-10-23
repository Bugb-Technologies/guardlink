/**
 * GuardLink — the annotation worklist: every file in the repository, sorted
 * into the ones that still need annotating, the ones already annotated, and
 * the ones left out with the reason each was left out.
 *
 * The parsed model already carries the first two (`unannotated_files`,
 * `annotated_files`) and the scanned files it left out (`annotation_scope`).
 * This adds the repository's other files — what git tracks, or the directory
 * walk outside a work tree — classified by the same rules, so a consumer
 * planning annotation work gets one partition with nothing unaccounted for and
 * applies no scope policy of its own. `guardlink unannotated --json` prints it.
 *
 * @exposes #parser to #child-proc-injection [low] cwe:CWE-78 -- "`repositoryFiles` hands `execFileSync` a git ls-files call in the project root"
 * @mitigates #parser against #child-proc-injection using #param-commands -- "execFileSync with a fixed argument array and cwd; no shell, no user-controlled arguments"
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "`repositoryFiles` lists every tracked file, or `fg.sync` walks the whole tree outside a work tree"
 * @mitigates #parser against #dos using #glob-filtering -- "The walk skips node_modules and .git and does not follow symbolic links; git lists ignored directories as one entry"
 * @flows ProjectRoot -> #parser via buildAnnotationWorklist -- "Repository file list classified into worklist, annotated and excluded"
 */

import { execFileSync } from 'node:child_process';
import fg from 'fast-glob';
import type { ThreatModel } from '../types/index.js';
import { annotationScope, type ScopeExclusionReason, type ScopeView } from './annotation-scope.js';
import { DEFAULT_EXCLUDE } from './parse-project.js';

export const WORKLIST_SCHEMA = 'guardlink.annotation-worklist/v1';

export interface WorklistFile {
  path: string;
  /** `unannotated`: in scope, nothing declared yet. */
  reason: 'unannotated';
}

export interface ExcludedFile {
  path: string;
  reason: ScopeExclusionReason;
  detail: string;
  /** The file declares annotations, which are in the model regardless. */
  annotated?: true;
}

export interface AnnotationWorklist {
  schema: typeof WORKLIST_SCHEMA;
  view: ScopeView;
  summary: {
    worklist: number;
    annotated: number;
    excluded: number;
    excluded_by_reason: Partial<Record<ScopeExclusionReason, number>>;
  };
  /** In scope, unannotated: the files that still need annotation work. */
  worklist: WorklistFile[];
  /** In scope and already annotated. */
  annotated: string[];
  /** Left out of annotation work, each with why. */
  excluded: ExcludedFile[];
}

function repositoryFiles(root: string): string[] {
  try {
    const out = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      cwd: root,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 256 * 1024 * 1024,
    });
    return out.split('\0').filter(Boolean);
  } catch {
    return fg.sync('**/*', {
      cwd: root,
      ignore: ['**/node_modules/**', '**/.git/**'],
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
      suppressErrors: true,
    });
  }
}

const byPath = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The worklist for `root`, given the model `parseProject` built for it.
 *
 * Scanned files keep exactly the classification the model recorded, so this
 * and `unannotated_files` cannot disagree. Every other repository file is
 * classified here.
 */
export function buildAnnotationWorklist(root: string, model: ThreatModel): AnnotationWorklist {
  const annotated = new Set(model.annotated_files);
  const excluded = new Map<string, ExcludedFile>();
  for (const x of model.annotation_scope?.excluded ?? []) {
    excluded.set(x.file, { path: x.file, reason: x.reason as ScopeExclusionReason, detail: x.detail });
  }
  const known = new Set([...model.unannotated_files, ...model.annotated_files, ...excluded.keys()]);

  const rest = repositoryFiles(root).filter(f => !known.has(f));
  const scope = annotationScope(root, [...rest, ...model.annotated_files], { builtInExclude: DEFAULT_EXCLUDE });
  const inScopeAnnotated: string[] = [];
  for (const f of model.annotated_files) {
    // An annotated file the scan did not reach (a sidecar's source under
    // test/) is classified like any other file.
    const why = excluded.get(f) ?? scope.classify(f);
    if (why) excluded.set(f, { path: f, reason: why.reason, detail: why.detail });
    else inScopeAnnotated.push(f);
  }
  for (const f of rest) {
    const why = scope.classify(f);
    // A file git lists that the scan did not read and no rule excludes: a
    // link to a file the scan read at its own path, or a submodule entry.
    excluded.set(f, why
      ? { path: f, reason: why.reason, detail: why.detail }
      : { path: f, reason: 'not-scanned', detail: 'listed by git but not reached by the parser\'s scan' });
  }
  for (const x of excluded.values()) if (annotated.has(x.path)) x.annotated = true;

  const excludedList = [...excluded.values()].sort((a, b) => byPath(a.path, b.path));
  const byReason: Partial<Record<ScopeExclusionReason, number>> = {};
  for (const x of excludedList) byReason[x.reason] = (byReason[x.reason] ?? 0) + 1;

  return {
    schema: WORKLIST_SCHEMA,
    view: model.annotation_scope?.view ?? scope.view,
    summary: {
      worklist: model.unannotated_files.length,
      annotated: inScopeAnnotated.length,
      excluded: excludedList.length,
      excluded_by_reason: byReason,
    },
    worklist: [...model.unannotated_files].sort(byPath).map(path => ({ path, reason: 'unannotated' as const })),
    annotated: inScopeAnnotated.sort(byPath),
    excluded: excludedList,
  };
}
