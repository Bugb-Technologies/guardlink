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
 * @flows #workspace-config -> #parser via localWorkspaceMembers -- "Linked member manifests select the application scan and available sibling reference checks"
 * @comment -- "Scans standalone .gal files in addition to comment-based source annotations"
 * @comment -- "Every @entitles gets its citation resolved at assembly time and carries inert:true when uncited, so no consumer can read an uncited privilege claim as an effective one by forgetting to check (actor-entitlement design §3.4)"
 * @comment -- "Same reasoning for imprecise:true when the claim omits `on <asset>` or `against <threat>`, plus canEntitlementDemote/entitlementDemotionBlockers so the cited-and-precise test is written once here rather than re-derived by every consumer — a consumer that checks only !inert would demote on an entitlement that joins nothing (actor-entitlement design §9.7)"
 * @boundary #parser and FileSystem (#fs-boundary) -- "Trust boundary between parser and disk I/O"
 */
import { captureMemberSnapshot, readMemberRevision, collectApplicationView, discoverApplicationManifest, APPLICATION_MANIFEST_ENV } from '../workspace/application.js';
import type { ApplicationManifest } from '../workspace/application-types.js';
import { readSecurityTestsDir } from './security-tests.js';
import { localWorkspaceMembers, workspaceContainer } from '../workspace/discovery.js';
import { WorkspaceConfigError } from '../workspace/metadata.js';
import { combineModels, buildTagRegistry } from '../workspace/merge.js';
import { relationRecords, tagReferences, definitionIds } from './claim-key.js';
import { readObservedState, buildReachAttestation } from '../attest/index.js';


import fg from 'fast-glob';
import { GAL_GLOB, sourceGlobs } from './languages.js';
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import type {
  Annotation, ThreatModel, ParseDiagnostic,
  AssetAnnotation, ThreatAnnotation, ControlAnnotation, ActorAnnotation,
  MitigatesAnnotation, ExposesAnnotation, ConfirmedAnnotation, TicketAnnotation, AcceptsAnnotation,
  EntitlesAnnotation, ReachesAnnotation, EffectsAnnotation, GatesAnnotation,
  TransfersAnnotation, FlowsAnnotation, BoundaryAnnotation,
  ValidatesAnnotation, AuditAnnotation, OwnsAnnotation,
  HandlesAnnotation, AssumesAnnotation, ShieldAnnotation,
  FeatureAnnotation, CommentAnnotation,
  DataClassification,
  ExternalRef,
  ThreatModelEntitlement, EntitlementDemotionBlocker, AnnotationScopeRecord,
} from '../types/index.js';
import { parseFile } from './parse-file.js';
import { isKnownVerb } from './parse-line.js';
import { extractCitation } from './citation.js';
import { loadWorkspaceConfig } from '../workspace/index.js';
import { ANNOTATIONS_DIR } from './gal-path.js';
import { fileCoveragePercent } from './coverage.js';
import { readDisabledDiagnostics, readAgentConfigEnabled } from './annotation-mode.js';
import { readAgentConfig, type AgentConfigResult } from '../agentconfig/index.js';
import { computeAnnotationHash } from './annotation-hash.js';
import { attachAnchors } from '../structure/attach.js';
import { onePathPerFile } from './scan-files.js';
import { annotationScope } from './annotation-scope.js';
import { NESTED_CHECKOUT_GLOBS, scanIgnore } from './nested-checkouts.js';
import { parseRouteChannel } from './route.js';

/** A standalone annotation sidecar, not a source file. */
const isGalPath = (p: string): boolean => /\.gal$/i.test(p);

/**
 * Why a `.gal` sidecar that exists produced no annotation — when nothing else
 * has already said why.
 *
 * A sidecar is a file a developer created on purpose, at a path that names the
 * source file it is for. Reading one and getting nothing back is therefore
 * never routine, and until this existed it was also never reported: an empty
 * sidecar and a sidecar full of prose both left `guardlink validate` printing
 * "✓ All annotations valid", which is the same confident zero the consuming
 * surfaces print for a sidecar they never read at all.
 *
 * Three causes, three messages, because the fix differs:
 *
 * - **empty** — the file was created and never written. Nothing is wrong with
 *   GuardLink and nothing is wrong with the annotations; there are none.
 * - **unrecognised** — the file holds text that mentions no GuardLink verb.
 *   Notes, a paste from somewhere else, or a house convention GAL does not
 *   speak. The content is real and is contributing nothing.
 * - **neither** — the file holds verb-shaped lines that failed to parse. This
 *   function returns null for that case on purpose: `parseLine` has already
 *   emitted `malformed-annotation`, `prose-like` or `unknown-verb` naming the
 *   exact line, and a second, vaguer diagnostic over the top of a precise one
 *   is noise. The rule is "nothing came out **and** nothing said why".
 */
function emptySidecarDiagnostic(absolute: string, relPath: string): ParseDiagnostic | null {
  let content: string;
  try {
    content = readFileSync(absolute, 'utf-8');
  } catch {
    // Unreadable at this point means it was readable moments ago when the
    // parser opened it. Say nothing rather than invent a cause.
    return null;
  }

  if (content.trim().length === 0) {
    return {
      level: 'warning',
      code: 'empty-gal',
      message: `\`${relPath}\` is an empty annotation sidecar — it contributes nothing to the `
        + `threat model. Delete it, or write the annotations for `
        + `\`${sourceFileForGalOrSelf(relPath)}\` into it.`,
      file: relPath,
      line: 1,
    };
  }

  if (mentionsKnownVerb(content)) return null;

  return {
    level: 'warning',
    code: 'unrecognised-gal',
    message: `\`${relPath}\` holds text but no GuardLink annotation — no line in it names a verb `
      + `this parser knows, so the whole file contributes nothing to the threat model. `
      + `If it is notes, that is fine and this warning is the only trace of it; if it was meant `
      + `to be annotations, check the syntax with \`guardlink gal\`.`,
    file: relPath,
    line: 1,
  };
}

/** Whether any line in a sidecar names a verb this parser implements. */
function mentionsKnownVerb(content: string): boolean {
  for (const match of content.matchAll(/@(?:g\.)?([a-zA-Z][a-zA-Z0-9_-]*)/g)) {
    if (isKnownVerb(match[1])) return true;
  }
  return false;
}

/** The source file a sidecar path names, falling back to the path itself. */
function sourceFileForGalOrSelf(relPath: string): string {
  const norm = relPath.replaceAll('\\', '/');
  const prefix = `${ANNOTATIONS_DIR}/`;
  if (norm.startsWith(prefix) && norm.endsWith('.gal')) {
    const source = norm.slice(prefix.length, -'.gal'.length);
    if (source.length > 0) return source;
  }
  return norm;
}

/**
 * `@source` blocks naming a file that is not on disk.
 *
 * A sidecar's whole job is to point at code it does not live in, so a `@source`
 * that points at nothing is the one way an external annotation can be read
 * perfectly and still describe no code. Today it is worse than silent: the
 * named path is counted as an *annotated file*, so a repository gains coverage
 * for a file that does not exist.
 *
 * Existence on disk is the test, deliberately — not "was it scanned". A source
 * file under `test/` is excluded from the scan and is still a legitimate
 * `@source` target (GL-503 rescued exactly that case), so keying this on the
 * scan set would fire on correct annotations.
 *
 * One diagnostic per (sidecar, missing path) pair: a sidecar with twelve
 * annotations for one moved file is one mistake, not twelve.
 *
 * @exposes #parser to #path-traversal [low] cwe:CWE-22 -- "`@source file:` is author-controlled text and is joined onto the project root to test existence"
 * @mitigates #parser against #path-traversal using #path-validation -- "Existence only: no read, no write, and the result reaches the model as a warning string that echoes the path the author already wrote"
 * @flows AnnotationSource -> #parser via existsSync -- "Declared @source paths probed for existence"
 * @comment -- "A traversing path is already a broken annotation and this is the diagnostic that says so; refusing to stat it would return the silence this function exists to remove"
 */
function missingSourceDiagnostics(root: string, annotations: Annotation[]): ParseDiagnostic[] {
  const seen = new Set<string>();
  const diagnostics: ParseDiagnostic[] = [];
  for (const ann of annotations) {
    const origin = ann.location.origin_file;
    const target = ann.location.file;
    if (!origin || target === origin) continue;
    const key = `${origin}\u0000${target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (existsSync(join(root, target))) continue;
    diagnostics.push({
      level: 'warning',
      code: 'missing-gal-source',
      message: `\`${origin}\` declares \`@source file:${target}\`, and that file is not on disk. `
        + `Its annotations parse and are counted, but they describe no code: nothing anchors, `
        + `and \`${target}\` is reported as an annotated file that does not exist. `
        + `Point the block at the file's current path, or delete it if the code is gone.`,
      file: origin,
      line: ann.location.origin_line ?? 1,
    });
  }
  return diagnostics.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

export interface ParseProjectOptions {
  /** Root directory to scan */
  root: string;
  /** Glob patterns to include (default: common source files) */
  include?: string[];
  /** Glob patterns to exclude (default: node_modules, dist, .git) */
  exclude?: string[];
  /** Project name for the ThreatModel */
  project?: string;
  /**
   * Attach a structure-layer `anchor` to every annotation location (default
   * true). Set false for callers that only need the annotations — the diff
   * engine's historical parses, for instance — to skip grammar loading.
   */
  anchors?: boolean;
  /**
   * Read the repository's coding-agent configuration into the model (SPEC
   * §5.6). Defaults to `.guardlink/config.json`'s `agent_config.enabled`,
   * which defaults to true; `false` here wins over the file.
   */
  agentConfig?: boolean;
  /** Check available linked sibling checkouts (default true); false prevents recursive sibling reads. */
  applicationManifest?: string | ApplicationManifest;
  application?: boolean;
  memberSnapshot?: boolean;
  checkSiblings?: boolean;
  /** Treat unavailable siblings and unresolved sibling refs as errors (validate --workspace). */
  requireSiblings?: boolean;
}

/**
 * Every file the parser opens by default: one glob per language in the marker
 * table, plus standalone GAL sidecars.
 *
 * Derived rather than listed. This used to be a hand-maintained list that had
 * drifted from `stripCommentPrefix`'s marker set, so an annotation in a `.php`
 * or `.kts` file was read by nothing and reported by nothing — see
 * `parser/languages.ts` for the measurement.
 */
export const DEFAULT_INCLUDE = [...sourceGlobs(), GAL_GLOB];

/**
 * Files GuardLink itself writes. Never scan input.
 *
 * D17: the `.html` glob is in DEFAULT_INCLUDE, so `guardlink dashboard` wrote
 * `threat-dashboard.html` straight into its own scan set. It yields zero
 * annotations, but it does move `source_files` and `unannotated_files` — the
 * tool measuring the repo was measuring its own output. Measured here:
 * `docs/examples/threat-dashboard.html` was one of 23 `unannotated_files`.
 *
 * Excluded by name rather than by dropping `.html` from DEFAULT_INCLUDE.
 * Dropping the extension would silently stop parsing annotations in
 * server-rendered templates (Django, Jinja, ERB, Handlebars), which carry them
 * in `<!-- -->` comments perfectly well — a silent-loss-by-convention fix in the
 * same family as D4, traded for a narrower problem. The generated names are
 * fixed and few, so naming them costs nothing and loses nothing.
 *
 * Matched by basename anywhere in the tree, because these are written wherever
 * `-o` points, not only at the root.
 *
 * This is the same list `.gitignore` gets on init — see GITIGNORE_ENTRY in
 * init/templates.ts, which is built from it. One list, so a new output format
 * cannot be added to one and forgotten in the other.
 */
export const GENERATED_OUTPUT_FILES = [
  'threat-dashboard.html',
  'threat-model.md',
  'threat-model.json',
  'guardlink.sarif.json',
];

export const DEFAULT_EXCLUDE = [
  '**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**',
  '**/__pycache__/**', '**/target/**', '**/vendor/**', '**/.next/**',
  '**/tests/**', '**/test/**', '**/__tests__/**',
  // Bugb's own artifact dirs inside a scanned repo. `dot: true` (for .guardlink/) would
  // otherwise walk these: .bravos holds agent rollback backups of annotated source, so
  // re-parsing them double-counts every exposure in the original; .bugb is siete's session store.
  '**/.bravos/**', '**/.bugb/**',
  // @comment -- "Another checkout nested in the tree: Claude Code's per-session worktrees under .claude/worktrees/, each a full copy of the repository with its own definitions, which parsed as source made every definition id a duplicate and every exposure count twice. This is the by-name half of the rule; the .git-file half cannot be a glob and is applied by scanIgnore (nested-checkouts.ts)"
  ...NESTED_CHECKOUT_GLOBS,
  // D17 — our own generated outputs.
  ...GENERATED_OUTPUT_FILES.map(f => `**/${f}`),
];

/**
 * `GUARDLINK_AGENT_CONFIG=off` leaves agent configuration out of every parse in
 * the process; the CLI's `--no-agent-config` sets it.
 */
export const AGENT_CONFIG_ENV = 'GUARDLINK_AGENT_CONFIG';

/**
 * Parse an entire project directory and return a ThreatModel.
 */
export async function parseProject(options: ParseProjectOptions): Promise<{
  model: ThreatModel;
  diagnostics: ParseDiagnostic[];
  config: { security_tests_dir: string };
}> {
  const {
    root,
    include = DEFAULT_INCLUDE,
    exclude = DEFAULT_EXCLUDE,
    project = 'unknown',
    anchors = true,
  } = options;

  const config = { security_tests_dir: readSecurityTestsDir(root) };
  const selected = options.applicationManifest ?? (options.application !== false ? process.env[APPLICATION_MANIFEST_ENV] : undefined);
  if (options.application !== false && selected) {
    const view = await collectApplicationView({ root, manifest: selected, anchors: options.anchors, agentConfig: options.agentConfig });
    return { model: view.model, diagnostics: [...view.diagnostics, ...(options.requireSiblings ? view.references.filter(r => r.state !== 'resolved').map(r => ({ level: 'error' as const, code: 'dangling-ref' as const, file: `${view.receipt.members.find(m => m.id === r.memberId)?.relativePath ?? r.memberId}/${r.file}`, line: r.line, message: `Workspace reference ${r.tag} is ${r.state} in the selected member set.` })) : [])], config };
  }

  if (options.application !== false) {
    const manifest = discoverApplicationManifest(root);
    if (manifest) {
      const view = await collectApplicationView({ root, manifest, anchors: options.anchors, agentConfig: options.agentConfig, selectionProbe: () => discoverApplicationManifest(root) });
      return { model: view.model, diagnostics: [...view.diagnostics, ...(options.requireSiblings ? view.references.filter(r => r.state !== 'resolved').map(r => ({ level: 'error' as const, code: 'dangling-ref' as const, file: `${view.receipt.members.find(m => m.id === r.memberId)?.relativePath ?? r.memberId}/${r.file}`, line: r.line, message: `Workspace reference ${r.tag} is ${r.state} in the selected member set.` })) : [])], config };
    }
  }
  let container: ReturnType<typeof workspaceContainer>;
  try { container = workspaceContainer(root); }
  catch (error) {
    if (!(error instanceof WorkspaceConfigError)) throw error;
    return {
      model: assembleModel([], 0, project, [], []),
      diagnostics: [workspaceConfigDiagnostic(error, root)], config,
    };
  }
  if (container) {
    if (container.missing.length) {
      throw new Error(`Application incomplete: linked member checkouts unavailable: ${container.missing.join(', ')}.`);
    }
    const results = await Promise.all(container.members.map(async member => ({
      member,
      parsed: await parseProject({ ...options, root: member.path, project: member.name, checkSiblings: false, requireSiblings: false }),
    })));
    const unreadable = results.filter(({ parsed }) => parsed.diagnostics.some(d => d.level === 'error' || d.level === 'fatal'));
    if (unreadable.length) {
      throw new Error(`Application incomplete: linked members have parse errors: ${unreadable.map(r => r.member.name).join(', ')}. Validate each member for details.`);
    }
    const reports = results.map(({ member, parsed }) => ({
      repo: relative(root, member.path).replaceAll('\\', '/'), model: parsed.model, source_path: member.path,
    }));
    const model = combineModels(reports);
    model.project = options.project && options.project !== 'unknown' ? options.project : container.config.workspace;
    const diagnostics = results.flatMap(({ member, parsed }) => parsed.diagnostics.map(d => ({
      ...d, file: `${relative(root, member.path).replaceAll('\\', '/')}/${d.file}`,
    })));
    for (const warning of buildTagRegistry(reports).warnings) diagnostics.push({
      level: 'warning', code: 'duplicate-id', file: '.guardlink/workspace.yaml', line: 1, message: warning.message,
    });
    // References now resolve against the combined application rather than the member's local scope.
    model.external_refs = [];
    if (options.requireSiblings) {
      const defined = definitionIds(model);
      for (const ref of tagReferences(model)) if (!defined.has(ref.tag.slice(1))) diagnostics.push({
        level: 'error', code: 'dangling-ref', ...ref.location,
        message: `Workspace reference ${ref.tag} is not defined in any linked member.`,
      });
    }
    return { model, diagnostics, config };
  }

  const memberBefore = options.memberSnapshot && loadWorkspaceConfig(root) ? await readMemberRevision(root, {}) : undefined;

  // Discover files (dot: true to include .guardlink/ definitions)
  // @comment -- "scanIgnore adds one ignore per nested checkout found under root (a directory holding a .git FILE: a linked worktree or a submodule), so another checkout's source and definitions are never read as this repository's. The same call bounds clear, the fingerprint and init's scope, so the four walks keep one scan set"
  const scanned = await fg(include, {
    cwd: root,
    ignore: scanIgnore(root, exclude),
    absolute: true,
    dot: true,
  });

  // GL-503 — rescue annotation sidecars under excluded directories.
  //
  // DEFAULT_EXCLUDE drops test/, tests/, __tests__/, vendor/, build/, dist/ and
  // target/ at any depth, which also matched INSIDE .guardlink/annotations/. A
  // sidecar written at the documented convention path for a source file under
  // test/ was silently dropped: no warning, no diagnostic, and the annotation
  // count simply did not move (measured, Phase 0 §8).
  //
  // Those exclusions exist to skip *source* the model should not describe. They
  // have no business inside .guardlink/annotations/, which contains nothing but
  // GuardLink's own data. The source file stays excluded; only its sidecar is
  // rescued — annotating a test file is a deliberate act, and losing the
  // annotation because of where the code lives is not a policy anyone chose.
  const sidecars = await fg([`${ANNOTATIONS_DIR}/**/*.[gG][aA][lL]`], {
    cwd: root,
    ignore: ['**/node_modules/**', '**/.git/**'],
    absolute: true,
    dot: true,
  });

  // fast-glob walks directories concurrently, so the order it returns varies
  // from run to run on an identical tree. Every model array inherits file
  // order, so sort here — by code unit, not locale — or the same project
  // parses to differently ordered models. Sidecars stay after source files.
  // A file reached through a symlink as well as at its own path is parsed
  // once, or every #id it defines is reported as a duplicate of itself.
  const files = onePathPerFile(root, [...scanned.sort(), ...sidecars.sort()]);

  // Parse all files
  const allAnnotations: Annotation[] = [];
  const allDiagnostics: ParseDiagnostic[] = [];
  const filesWithAnnotations = new Set<string>();

  for (const file of files) {
    const result = await parseFile(file);
    const relPath = relative(root, file);
    // Normalize file paths to relative
    for (const ann of result.annotations) {
      ann.location.file = normalizeLocationPath(ann.location.file, file, root);
      if (ann.location.origin_file) {
        ann.location.origin_file = normalizeLocationPath(ann.location.origin_file, file, root);
      }
    }
    for (const diag of result.diagnostics) {
      diag.file = relPath;
    }
    if (result.annotations.length > 0) {
      // GL-502 — count the LOGICAL source, never the sidecar.
      //
      // This used to add both relPath and ann.location.file. In inline mode they
      // are the same string and the second add is a no-op; in external mode they
      // are the .gal and the source it annotates, so every externally annotated
      // file was counted twice (measured: annotated_files 3 -> 5 on an identical
      // logical model). location.file is already the logical source in both
      // modes, so adding it alone is both simpler and correct.
      for (const ann of result.annotations) {
        filesWithAnnotations.add(ann.location.file);
      }
      // A .gal with no @source block leaves location.file pointing at the .gal
      // itself; it is still a real annotation, just not attributable to a source
      // file. Keep the physical path in that case so the annotation is not orphaned.
      if (!isGalPath(relPath)) filesWithAnnotations.add(relPath);
    } else if (isGalPath(relPath) && result.diagnostics.length === 0) {
      // A sidecar that yielded nothing and explained nothing. See
      // `emptySidecarDiagnostic` for why silence here is the defect: a sidecar
      // exists because someone put it there, and a confident zero over the top
      // of it is indistinguishable from a model with nothing to say.
      const diag = emptySidecarDiagnostic(file, relPath);
      if (diag) allDiagnostics.push(diag);
    }
    allAnnotations.push(...result.annotations);
    allDiagnostics.push(...result.diagnostics);
  }

  // `@source` blocks pointing at files that are not there. Runs over every
  // annotation at once rather than per file, so one moved source file reported
  // from two sidecars is two diagnostics and not two hundred.
  allDiagnostics.push(...missingSourceDiagnostics(root, allAnnotations));

  // The code beneath each claim (spec §5). Locations are already logical,
  // root-relative paths, and assembleModel shares each location object by
  // reference, so the anchor set here reaches every model record.
  if (anchors) await attachAnchors(root, allAnnotations);

  // Check for duplicate identifiers
  const idMap = new Map<string, Annotation>();
  for (const ann of allAnnotations) {
    const id = getAnnotationId(ann);
    if (id) {
      if (idMap.has(id)) {
        const prev = idMap.get(id)!;
        allDiagnostics.push({
          level: 'error',
          code: 'duplicate-id',
          message: `Duplicate identifier #${id} (first defined at ${prev.location.file}:${prev.location.line})`,
          file: ann.location.file,
          line: ann.location.line,
        });
      } else {
        idMap.set(id, ann);
      }
    }
  }

  // Compute annotated vs unannotated files. Unannotated is the annotation
  // worklist: scanned files in the annotation scope (annotation-scope.ts) with
  // nothing declared. A file out of scope was still parsed above, so what it
  // declares is in the model and it can still be an annotated file.
  const allRelPaths = files.map(f => relative(root, f).replaceAll('\\', '/'));
  const annotatedFiles = [...filesWithAnnotations].filter(f => !isGalPath(f)).sort();
  const candidates = allRelPaths.filter(f => !isGalPath(f) && !f.startsWith('.guardlink/'));
  const scope = annotationScope(root, candidates, { builtInExclude: exclude });
  const inScope: string[] = [];
  const outOfScope: AnnotationScopeRecord['excluded'] = [];
  for (const f of candidates) {
    const why = scope.classify(f);
    if (why) outOfScope.push({ file: f, ...why });
    else inScope.push(f);
  }
  const unannotatedFiles = inScope.filter(f => !filesWithAnnotations.has(f)).sort();

  // GL-502 — the denominator is source files, and a sidecar is not one.
  //
  // `files.length` counted .gal sidecars as source, inflating the denominator by
  // one per externally annotated file (measured: source_files 7 -> 9 on an
  // identical logical model) and making coverage incomparable across modes.
  //
  // The union with annotated files matters for the case GL-503 just unlocked: a
  // source file under test/ is excluded from the scan but can still be annotated
  // through its sidecar. Without the union it would appear in annotated_files
  // while missing from the denominator, so annotated could exceed scanned.
  //
  // The annotation scope narrows the denominator the same way: in-scope files,
  // plus every annotated file wherever it sits.
  const sourceFiles = new Set(inScope);
  for (const f of annotatedFiles) sourceFiles.add(f);

  // Assemble ThreatModel
  const model = assembleModel(allAnnotations, sourceFiles.size, project, annotatedFiles, unannotatedFiles);
  model.annotation_scope = {
    view: scope.view,
    excluded: outOfScope.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0)),
  };

  // Detect cross-repo tag references (requires workspace.yaml)
  model.external_refs = await detectExternalRefs(model, root, options, allDiagnostics);

  // Warning-level diagnostics a project has switched off in config.json.
  // Errors are never suppressible — see readDisabledDiagnostics.
  // The repository's coding-agent configuration: generated reach rows and the
  // agent_config inventory block (SPEC §5.6).
  if (options.agentConfig ?? (process.env[AGENT_CONFIG_ENV] !== 'off' && readAgentConfigEnabled(root))) {
    mergeAgentConfig(model, readAgentConfig(root));
  }

  const observedState = readObservedState(root);
  if (observedState.observed) {
    model.observed_reach = observedState.observed;
    if (observedState.pins) model.tool_pins = observedState.pins;
    model.reach_attestation = buildReachAttestation(model, observedState.observed, observedState.pins);
  }

  const disabled = readDisabledDiagnostics(root);
  const diagnostics = disabled.size === 0
    ? allDiagnostics
    : allDiagnostics.filter(d => !(d.level === 'warning' && d.code && disabled.has(d.code)));

  if (options.memberSnapshot) await captureMemberSnapshot(root, model, memberBefore);
  return { model, diagnostics, config };
}

/**
 * Merge what the config reader generated into an assembled model.
 *
 * Generated rows go into the same arrays as annotated ones, marked
 * `origin: "agent-config"`, so every join over reaches, effects and gates reads
 * them with no rule of its own. A generated actor is added only when no
 * annotation declares one with the same id: a person who wrote
 * `@actor Claude_Code (#claude-code)` keeps their own description.
 *
 * Each GuardLink block's stamp is judged here, once the annotation hash is
 * known: current when it names this model's annotation hash and this
 * configuration's hash.
 *
 * @flows #agent-config -> #parser via mergeAgentConfig -- "Generated reach rows, actors and the agent_config block join the assembled model"
 */
export function mergeAgentConfig(model: ThreatModel, ac: AgentConfigResult): ThreatModel {
  const declared = new Set((model.actors ?? []).map(a => a.id).filter(Boolean));
  model.actors = [...(model.actors ?? []), ...ac.actors.filter(a => !declared.has(a.id))];
  model.reaches = [...(model.reaches ?? []), ...ac.reaches];
  model.effects = [...(model.effects ?? []), ...ac.effects];
  model.gates = [...(model.gates ?? []), ...ac.gates];
  const claimRows = relationRecords(model);
  for (const surface of ac.block.surfaces ?? []) surface.claim_keys = claimRows
    .filter(r => r.location.file === surface.file && r.location.binding === surface.pointer)
    .map(r => r.key);
  const annotationHash = computeAnnotationHash(model);
  for (const f of ac.block.instruction_files) {
    if (f.guardlink_block) {
      f.guardlink_block.current = f.guardlink_block.stamp === annotationHash
        && f.guardlink_block.agent_config_stamp === ac.block.agent_config_hash;
    }
  }
  model.agent_config = ac.block;
  return model;
}

function normalizeLocationPath(locationFile: string, physicalFile: string, root: string): string {
  if (locationFile === physicalFile) return relative(root, physicalFile);
  if (isAbsolute(locationFile)) return relative(root, locationFile);
  return locationFile.replaceAll('\\', '/');
}

function getAnnotationId(ann: Annotation): string | undefined {
  if ('id' in ann) return (ann as any).id;
  return undefined;
}

function assembleModel(annotations: Annotation[], fileCount: number, project: string, annotatedFiles: string[], unannotatedFiles: string[]): ThreatModel {
  const model: ThreatModel = {
    version: '1.2.0',
    project,
    generated_at: new Date().toISOString(),
    source_files: fileCount,
    annotations_parsed: annotations.length,
    annotated_files: annotatedFiles,
    unannotated_files: unannotatedFiles,
    assets: [],
    threats: [],
    controls: [],
    actors: [],
    entitlements: [],
    reaches: [],
    effects: [],
    gates: [],
    mitigations: [],
    exposures: [],
    confirmed: [],
    tickets: [],
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
    features: [],
    comments: [],
    coverage: {
      annotation_count: annotations.length,
      // D14 — file coverage, actually computed. This was a hardcoded 0 that three
      // consumers rendered as "0%" on fully annotated projects. Meaningful only
      // because GL-502 made both sides of the ratio exclude sidecars, so the
      // number no longer moves when a repo changes annotation mode.
      coverage_percent: fileCoveragePercent(annotatedFiles.length, fileCount),
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
      case 'actor': {
        const ac = ann as ActorAnnotation;
        model.actors!.push({
          name: ac.name,
          canonical_name: ac.canonical_name,
          id: ac.id,
          description: ac.description,
          location: ac.location,
        });
        break;
      }
      case 'entitles': {
        const en = ann as EntitlesAnnotation;
        // §3.4 — an uncited entitlement is inert: it stays in the model (so a
        // reviewer can see the claim) but must not demote a finding.
        const citation = extractCitation(en.description);
        model.entitlements!.push({
          actor: en.actor,
          capability: en.capability,
          canonical_capability: en.canonical_capability,
          asset: en.asset,
          threat: en.threat,
          description: en.description,
          citation,
          inert: !citation,
          // §9.3 — the same treatment for the other way a claim can be
          // ineffective: without both halves of the (actor, asset, threat) join
          // there is nothing to match a finding against.
          imprecise: !en.asset || !en.threat,
          location: en.location,
        });
        break;
      }
      // Both reach verbs land in one collection: they are one claim about
      // two kinds of principal, and the unentitled-reach join spans both.
      case 'agents':
      case 'reaches': {
        const r = ann as ReachesAnnotation;
        model.reaches!.push({
          actor: r.actor, agent: r.verb === 'agents',
          capability: r.capability, canonical_capability: r.canonical_capability,
          asset: r.asset, identity: r.identity,
          description: r.description, location: r.location,
        });
        break;
      }
      case 'effects': {
        const ef = ann as EffectsAnnotation;
        model.effects!.push({
          effect: ef.effect, asset: ef.asset, identity: ef.identity,
          description: ef.description, location: ef.location,
        });
        break;
      }
      case 'gates': {
        const g = ann as GatesAnnotation;
        model.gates!.push({
          asset: g.asset, approver: g.approver,
          capability: g.capability, canonical_capability: g.canonical_capability,
          description: g.description, location: g.location,
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
      case 'confirmed': {
        const cf = ann as ConfirmedAnnotation;
        model.confirmed.push({
          threat: cf.threat, asset: cf.asset, severity: cf.severity,
          external_refs: cf.external_refs,
          description: cf.description, location: cf.location,
        });
        break;
      }
      case 'ticket': {
        const t = ann as TicketAnnotation;
        model.tickets!.push({
          threat: t.threat, asset: t.asset, ref: t.ref,
          sla: t.sla, assignee: t.assignee, due: t.due,
          description: t.description, location: t.location,
        });
        break;
      }
      case 'accepts': {
        const a = ann as AcceptsAnnotation;
        model.acceptances.push({
          threat: a.threat, asset: a.asset,
          accepted_by: a.accepted_by, expires: a.expires,
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
          route: parseRouteChannel(f.mechanism),
          description: f.description, location: f.location,
        });
        break;
      }
      case 'boundary': {
        const b = ann as BoundaryAnnotation;
        model.boundaries.push({
          asset_a: b.asset_a, asset_b: b.asset_b, id: b.id,
          ...(b.directed ? { directed: true as const } : {}),
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
      case 'feature': {
        const feat = ann as FeatureAnnotation;
        model.features.push({
          feature: feat.feature,
          description: feat.description, location: feat.location,
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

// ─── Can this entitlement demote? (§9.7) ─────────────────────────────
//
// Computed here, once, next to the assembly that produces `inert` and
// `imprecise` — rather than left to each consumer to derive. An entitlement is
// the one annotation whose error mode is a silent false negative (§2), and the
// way that false negative actually arrives is not a maliciously wrong claim but
// a consumer that checked `!inert`, forgot the join was a triple, and demoted a
// real escalation on an entitlement that named no threat. So the check has one
// implementation and a name, and a consumer that wants to demote has to call it.

/**
 * True when this entitlement is allowed to demote a finding: it is cited (§3.4)
 * **and** it names both halves of the `(actor, asset, threat)` join (§9.3).
 *
 * This is necessary and not sufficient. The consumer must still match the
 * finding's asset and threat, must have *measured* minimum privilege and matched
 * the measured role against `actor` (§3.3 of the triage design), and must refuse
 * to demote an ownership-class threat however exact the match (§3.5, §9.6).
 * Nothing in guardlink can check those, which is why this function answers only
 * the question guardlink owns.
 */
export function canEntitlementDemote(entitlement: ThreatModelEntitlement): boolean {
  return entitlementDemotionBlockers(entitlement).length === 0;
}

/**
 * Every reason this entitlement may not demote, in the order a reviewer would
 * fix them. Empty means `canEntitlementDemote` is true.
 *
 * Uncited and imprecise are reported as separate blockers on purpose (§9.8): a
 * single boolean tells a reviewer the claim does nothing, which is exactly the
 * information they already have — what they need is *which* part is missing, and
 * an imprecise claim is neither an error nor a warning anywhere else, so this is
 * the only place it is said.
 */
export function entitlementDemotionBlockers(
  entitlement: ThreatModelEntitlement,
): EntitlementDemotionBlocker[] {
  const blockers: EntitlementDemotionBlocker[] = [];
  if (entitlement.inert) blockers.push('uncited');
  if (!entitlement.asset) blockers.push('no-asset');
  if (!entitlement.threat) blockers.push('no-threat');
  return blockers;
}

// ─── External ref detection ──────────────────────────────────────────

/** A malformed manifest is data to diagnose, not an unhandled parser exception. */
function workspaceConfigDiagnostic(error: WorkspaceConfigError, root: string, level: 'error' | 'warning' = 'error'): ParseDiagnostic {
  return {
    level, code: 'workspace-config-invalid', file: relative(root, error.file).replaceAll('\\', '/'), line: error.line,
    message: `Cannot read workspace manifest: ${error.problem}`,
  };
}

/** Resolve every nonlocal relationship id against readable sibling checkouts; missing data stays unchecked. */
async function detectExternalRefs(
  model: ThreatModel, root: string, options: ParseProjectOptions, diagnostics: ParseDiagnostic[],
): Promise<ExternalRef[]> {
  const config = loadWorkspaceConfig(root);
  if (!config) return [];
  const local = definitionIds(model);
  const candidates = tagReferences(model).filter(r => !local.has(r.tag.slice(1)));
  if (candidates.length === 0 && !options.requireSiblings) return [];
  const siblings = config.repos.filter(r => r.name !== config.this_repo);
  let members: ReturnType<typeof localWorkspaceMembers> = [];
  if (options.checkSiblings !== false) {
    try { members = localWorkspaceMembers(root, config).filter(m => m.name !== config.this_repo); }
    catch (error) {
      if (!(error instanceof WorkspaceConfigError)) throw error;
      diagnostics.push(workspaceConfigDiagnostic(error, root, options.requireSiblings ? 'error' : 'warning'));
    }
  }
  const definitions = new Map<string, string[]>();
  const kinds = new Map<string, Set<string>>();
  const checked: string[] = [];
  for (const member of members) {
    const parsed = await parseProject({ root: member.path, anchors: false, agentConfig: false, checkSiblings: false });
    if (parsed.diagnostics.some(d => d.level === 'error' || d.level === 'fatal')) continue;
    checked.push(member.name);
    for (const [kind, rows] of [
      ['asset', parsed.model.assets], ['threat', parsed.model.threats], ['control', parsed.model.controls],
      ['actor', parsed.model.actors ?? []], ['boundary', parsed.model.boundaries],
    ] as const) {
      for (const row of rows) if (row.id) {
        const set = kinds.get(row.id) ?? new Set<string>();
        set.add(kind); kinds.set(row.id, set);
      }
    }
    for (const id of definitionIds(parsed.model)) {
      definitions.set(id, [...(definitions.get(id) ?? []), member.name]);
    }
  }
  const missing = siblings.filter(s => !checked.includes(s.name)).map(s => s.name);
  if (options.requireSiblings && missing.length) diagnostics.push({
    level: 'error', code: 'workspace-incomplete', file: '.guardlink/workspace.yaml', line: 1,
    message: `Workspace check incomplete: unavailable or unreadable sibling checkouts: ${missing.join(', ')}.`,
  });
  return candidates.map(ref => {
    const owners = definitions.get(ref.tag.slice(1));
    const prefix = ref.tag.slice(1).split('.')[0];
    const legacy = ref.tag.includes('.') && siblings.some(s => s.name === prefix);
    const resolution = owners?.length ? 'resolved' : missing.length ? 'not_checked' : 'unresolved';
    if (options.requireSiblings && resolution === 'unresolved') diagnostics.push({
      level: 'error', code: 'dangling-ref', ...ref.location,
      message: `Workspace reference ${ref.tag} is not defined in any linked member.`,
    });
    return {
      ...ref, ...(legacy ? { legacy: true, inferred_repo: prefix } : {}),
      ...(owners?.length ? { defined_in: owners, inferred_repo: owners[0], definition_kinds: [...(kinds.get(ref.tag.slice(1)) ?? [])] } : {}),
      resolution, ...(missing.length ? { unchecked_members: missing } : {}),
    };
  });
}
