/**
 * GuardLink — Derived artifact emission (GL-301, GL-302).
 *
 * Writes the model and its diagrams to `.guardlink/` as plain files, so a
 * developer can diff them, a reviewer can see a threat model change in a PR, and
 * an agent with no MCP connection can read the graph without parsing a 1.4 MB
 * HTML dashboard of which the diagrams are 1.35%.
 *
 * Nothing here generates anything. The three diagram generators and the subgraph
 * selector already exist and are called once each; emission is the fan-out.
 *
 * ── The central risk ────────────────────────────────────────────────
 *
 * **A `.mmd` sitting in a repo looks like source.** A reader who opens
 * `threat-graph.mmd` has no way to know it was generated, when, or from what —
 * and a confidently wrong dataflow diagram is worse than no diagram, because the
 * reader will not go and verify it. Every artifact therefore carries a `%%`
 * provenance header naming the annotation hash it was built from, and
 * `guardlink validate --artifacts` recomputes that hash and fails on mismatch.
 *
 * Ordering is canonicalised before anything is written. Parse order varies
 * across processes (fast-glob completion order, D23), so without it every
 * regeneration would be a diff and a real change would be indistinguishable from
 * a re-run — which would make the staleness signal useless in exactly the files
 * that exist to carry it.
 *
 * @exposes #dashboard to #arbitrary-write [medium] cwe:CWE-73 -- "Writes .mmd, model.json and MANIFEST.json under a caller-supplied root"
 * @mitigates #dashboard against #arbitrary-write using #path-validation -- "Every write is join(root, '.guardlink', …); feature names are slugified before use as filenames"
 * @flows ThreatModel -> #dashboard via emitArtifacts -- "Model rendered to disk artifacts"
 * @flows #dashboard -> FileSystem via writeFileSync -- "Artifact write path"
 * @comment -- "Artifacts carry a provenance header so a stale one is detectable rather than merely wrong"
 * @comment -- "by-feature/*.mmd declare themselves partial in the header: a narrowed diagram that does not say it is narrowed reads as a complete one that is missing things"
 * @comment -- "annotation_hash stays project-wide on per-feature files — it records the state the view was cut from, which is what keeps `validate --artifacts` a single comparison for every artifact"
 */

import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from '../dashboard/index.js';
import {
  checkRenderBudget, oversizedStub, describeViolation,
  ARTIFACT_FALLBACK, MERMAID_LIMITS, MERMAID_LIMITS_SOURCE, groupDigits,
  type RenderBudgetVerdict, type DiagramMeasurement, type BudgetViolation,
} from '../dashboard/render-budget.js';
import { checkLegibility, describeLegibility, LEGIBILITY_BUDGET } from '../graph/legibility.js';
import {
  growWithinBudget, assetThreatPlane, boundarySides, FLOW_KINDS,
} from '../graph/views.js';
import { canonicaliser } from '../mcp/subgraph.js';
import { listFeatures, filterByFeature } from '../parser/feature-filter.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';
import { computeAnnotationHash } from '../parser/annotation-hash.js';
import { readGitSha } from '../workspace/metadata.js';
import { getPackageVersion } from '../version.js';
import type { ThreatModel } from '../types/index.js';

/**
 * Bump when the emitted layout changes in a way a consumer would notice.
 *
 * 2 — every `.mmd` entry in MANIFEST.json now carries `renderable` and a
 *     `render` measurement, and a diagram over the Mermaid render budget is
 *     written as a stub that says so instead of as a diagram nothing can draw.
 */
export const ARTIFACT_SCHEMA_VERSION = 2;

/**
 * What a written artifact records about where it came from.
 *
 * Content-derived only. `generated_at` and `git_sha` were here and are gone:
 * these files are COMMITTED (GL-304) and a pre-commit hook regenerates them, so
 * a field that moves for reasons unrelated to the diagram would guarantee a diff
 * on every single commit. Measured: with `generated_at` present, two consecutive
 * regenerations of unchanged annotations produced two different files; without
 * it, they are byte-identical.
 *
 * That is the same argument as F1 for the synced agent block, and the same
 * resolution — volatile facts are reported where they are computed (here, on
 * `guardlink artifacts` stdout) rather than written into tracked files.
 * `generator` stays: it changes only on a version bump, which is a real reason
 * for output to differ.
 */
export interface ArtifactProvenance {
  annotation_hash: string;
  generator: string;
}

/** Volatile provenance, reported at emission and never written to disk. */
export interface EmissionInfo {
  generated_at: string;
  git_sha: string | null;
}

export interface ManifestEntry {
  path: string;
  bytes: number;
  annotation_hash: string;
  /**
   * `.mmd` only: is this file within the Mermaid render budget?
   *
   * Separate from the hash on purpose. The hash answers *is this current*; this
   * answers *will anything draw it*, and the second fails first. A manifest that
   * carried only the hash is what let a repository commit a 62 KB threat graph
   * no renderer would draw and have `validate --artifacts` call it fine.
   */
  renderable?: boolean;
  /**
   * `.mmd` only: what the budget measured, in Mermaid's units — characters of
   * comment-stripped text and flowchart edges.
   *
   * When `renderable` is false this describes the diagram that was REJECTED, not
   * the stub that was written in its place; `bytes` above is the file on disk.
   * That is the pairing a reader wants: how far past the limit the real diagram
   * was, and how small the thing standing in for it is.
   */
  render?: { text_size: number; edges: number };
}

/** A diagram that was over the render budget, and what was written instead. */
export interface UndrawableArtifact {
  path: string;
  verdict: RenderBudgetVerdict;
}

export interface EmitResult {
  written: string[];
  provenance: ArtifactProvenance;
  /** Reported to the caller; deliberately absent from every written file. */
  emission: EmissionInfo;
  manifest: ManifestEntry[];
  /**
   * Diagrams replaced by a stub because they exceeded the render budget.
   * Empty on every project small enough to draw, which is nearly all of them.
   */
  undrawable: UndrawableArtifact[];
}

/** Feature names become filenames; keep them boring and collision-free. */
export function featureSlug(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return slug || 'unnamed';
}

/**
 * The `%%` header every emitted `.mmd` carries.
 *
 * Mermaid treats `%%` as a comment, so this survives into any viewer without
 * affecting the render — the reader sees provenance, the parser sees nothing.
 *
 * ── `feature`: what a by-feature file has to say about itself ─────────
 *
 * A `.mmd` in a repo looks like source; a NARROWED `.mmd` in a repo looks like
 * the source of truth for something it deliberately leaves out. Two claims the
 * header therefore has to make out loud, because the diagram cannot:
 *
 *   1. It is partial. A node that is absent from `by-feature/checkout.mmd` is
 *      absent from that feature's relations, not from the project.
 *   2. `annotation_hash` is the WHOLE PROJECT's hash, not a hash of the
 *      narrowed content. Kept deliberately — see the note in the emitted text.
 *      A per-feature hash would churn less but would be a weaker claim (current
 *      w.r.t. a slice) and would split one drift gate into one per artifact,
 *      since `checkArtifactDrift` compares every file against a single expected
 *      hash. Left project-wide, and now stated rather than left to be inferred
 *      from a value that happens to be identical in every file.
 */
export function mermaidHeader(name: string, p: ArtifactProvenance, feature?: string, scope?: string): string {
  return [
    `%% GENERATED FILE — do not edit. Regenerate with: guardlink artifacts .`,
    `%% artifact:        ${name}`,
    ...(feature ? [`%% scope:           PARTIAL — @feature "${feature}" only, not the whole model`] : []),
    // A by-asset or by-boundary slice makes the same claim a by-feature file
    // makes, about a different axis: it is one question's answer, and a node it
    // omits is one that question does not reach.
    ...(scope ? [`%% scope:           PARTIAL — ${scope}`] : []),
    // Kept a bare `hash` value on its own line: `readArtifactHash` and the CI
    // gate both match `^%% annotation_hash:\s*(\S+)\s*$`, so anything appended
    // here would be read as part of the hash. Commentary goes below.
    `%% annotation_hash: ${p.annotation_hash}`,
    `%% generator:       ${p.generator}`,
    // NOT a bare `%%`: a line containing exactly that is read as the start of a
    // `%%{init}%%` directive and fails to parse. Verified against mermaid@11.16.1.
    `%% ---`,
    `%% This diagram is derived from the annotations in this repository. If`,
    `%% annotation_hash above differs from what \`guardlink status .\` reports, the`,
    `%% diagram is STALE — regenerate rather than trusting it.`,
    ...(feature ? [
      `%% ---`,
      `%% NARROWED VIEW. The edges below are the relations annotated in files`,
      `%% tagged @feature "${feature}"; the nodes are the assets, threats and`,
      `%% controls those relations reference, resolved from their definitions`,
      `%% wherever those are declared. A node missing from this file is one this`,
      `%% feature does not touch — it is NOT missing from the threat model. For`,
      `%% that, read ../threat-graph.mmd.`,
      `%% annotation_hash above is the hash of the WHOLE project's annotations —`,
      `%% the state this view was cut from — not of the narrowing. It is shared by`,
      `%% every artifact in the same emission on purpose: it is what makes one`,
      `%% \`guardlink validate . --artifacts\` check answer for all of them, and it`,
      `%% lets this file be lined up against model.json from the same run.`,
    ] : []),
    `%% When it was generated and at which commit: ask git. Those move for reasons`,
    `%% unrelated to the diagram, so they are reported at emission time, not stored.`,
    '',
  ].join('\n');
}

/** Strip the provenance header, leaving the diagram the generator produced. */
export function stripHeader(text: string): string {
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length && lines[i].startsWith('%% ')) i++;
  while (i < lines.length && lines[i] === '') i++;
  return lines.slice(i).join('\n');
}

/**
 * Read the `annotation_hash` an artifact claims, or null if it carries none.
 *
 * Three carriers, because the artifacts are three formats and a hash that only
 * one of them can hold is a gate that only covers one of them (R10):
 *
 *   `.mmd`   a `%%` provenance header — Mermaid reads it as a comment
 *   JSON     `provenance.annotation_hash` (model.json) or `metadata.annotation_hash`
 *            (report.json) or `runs[0].properties.annotation_hash` (SARIF)
 *   Markdown the `- \`annotation_hash\`: \`sha256-…\`` line the synced agent block writes
 *
 * Sniffed rather than dispatched on extension, so an artifact renamed or piped
 * to a different name still answers. Returns null rather than throwing on
 * anything unreadable: "no provenance" is a finding the caller reports, not an
 * error that stops the sweep.
 */
export function readArtifactHash(text: string): string | null {
  const mermaid = text.match(/^%% annotation_hash:\s*(\S+)\s*$/m);
  if (mermaid) return mermaid[1];

  const trimmed = text.trimStart();
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(text) as {
        annotation_hash?: unknown;
        provenance?: { annotation_hash?: unknown };
        metadata?: { annotation_hash?: unknown };
        runs?: Array<{ properties?: { annotation_hash?: unknown } }>;
      };
      for (const candidate of [
        parsed.annotation_hash,               // MANIFEST.json
        parsed.provenance?.annotation_hash,   // model.json
        parsed.metadata?.annotation_hash,     // report.json
        parsed.runs?.[0]?.properties?.annotation_hash, // findings.sarif
      ]) {
        if (typeof candidate === 'string' && candidate) return candidate;
      }
    } catch {
      // Unreadable JSON reports as unheadered, which is what it is from here.
    }
    return null;
  }

  // The synced agent block's freshness line (src/init/templates.ts).
  const markdown = text.match(/^-\s+`annotation_hash`:\s*`([^`]+)`\s*$/m);
  return markdown ? markdown[1] : null;
}

export interface EmitOptions {
  root: string;
  model: ThreatModel;
  dryRun?: boolean;
}

/**
 * Write `model.json` and `graph/` for a project.
 *
 * The model is canonically ordered first, so regenerating unchanged annotations
 * produces byte-identical files apart from `generated_at`.
 */
export function emitArtifacts({ root, model, dryRun = false }: EmitOptions): EmitResult {
  const ordered = canonicalizeModelOrder(model);
  const provenance: ArtifactProvenance = {
    annotation_hash: computeAnnotationHash(ordered),
    generator: `guardlink@${getPackageVersion()}`,
  };
  const emission: EmissionInfo = {
    generated_at: new Date().toISOString(),
    git_sha: readGitSha(root),
  };

  const guardlinkDir = join(root, '.guardlink');
  const graphDir = join(guardlinkDir, 'graph');
  const byFeatureDir = join(graphDir, 'by-feature');
  const byAssetDir = join(graphDir, 'by-asset');
  const byBoundaryDir = join(graphDir, 'by-boundary');

  const written: string[] = [];
  const manifest: ManifestEntry[] = [];
  const undrawable: UndrawableArtifact[] = [];

  const write = (absolute: string, relative: string, content: string, render?: RenderBudgetVerdict) => {
    if (!dryRun) writeFileSync(absolute, content);
    written.push(relative);
    manifest.push({
      path: relative,
      bytes: Buffer.byteLength(content),
      annotation_hash: provenance.annotation_hash,
      ...(render ? {
        renderable: render.renderable,
        render: { text_size: render.measurement.textSize, edges: render.measurement.edges },
      } : {}),
    });
  };

  /**
   * Write a diagram, or — when nothing would draw it — write a diagram that says
   * so instead.
   *
   * The stub is not a smaller version of the graph and does not try to be. It is
   * a one-node flowchart carrying the measurement, the limit and where to read
   * the same model, so the file a reviewer opens in GitHub says what happened
   * rather than rendering one pink box with no explanation and no console
   * output. The `%%` preamble above it says the same thing in prose, for the
   * reader who opens the file as text — `%%` lines cost nothing against the
   * budget, because Mermaid strips them before it measures.
   *
   * Deliberately NOT a new path: the stub replaces the content of the artifact
   * that would have been written, so `expectedArtifactPaths`, the manifest, the
   * `%%` header and the whole staleness machinery are untouched. Drawability is
   * a second question about the same file, not a second file.
   */
  const writeDiagram = (name: string, relative: string, absolute: string, body: string, feature?: string, scope?: string) => {
    const verdict = checkRenderBudget(body);
    const header = mermaidHeader(name, provenance, feature, scope);
    if (verdict.renderable) {
      // Drawable is not the same as readable, and a committed `.mmd` has no
      // page around it to say which it is: GitHub renders the file and nothing
      // else. So a diagram past the legibility budget carries the measurement
      // in its own `%%` header, where a reader who opens the file as text sees
      // it and Mermaid does not. `%%` lines are stripped before the render
      // budget measures, so saying this costs nothing against the limit it is
      // not about.
      write(absolute, relative, header + legibilityPreamble(name, body) + body, verdict);
      return;
    }
    undrawable.push({ path: relative, verdict });
    write(absolute, relative, header + budgetPreamble(name, verdict) + oversizedStub(name, verdict, ARTIFACT_FALLBACK), verdict);
  };

  if (!dryRun) {
    mkdirSync(graphDir, { recursive: true });
    mkdirSync(byFeatureDir, { recursive: true });
    mkdirSync(byAssetDir, { recursive: true });
    mkdirSync(byBoundaryDir, { recursive: true });
  }

  // The three canonical diagrams. Each generator is called exactly once.
  //
  // showAll: these are the whole model, so the >12-distinct-threat auto-filter
  // would silently drop everything below high severity from a file whose entire
  // purpose is to be the complete picture.
  const diagrams: [string, string][] = [
    ['threat-graph.mmd', generateThreatGraph(ordered, { showAll: true })],
    ['dataflow.mmd', generateDataFlowDiagram(ordered)],
    ['attack-surface.mmd', generateAttackSurface(ordered)],
  ];
  for (const [name, body] of diagrams) {
    writeDiagram(name, `.guardlink/graph/${name}`, join(graphDir, name), body);
  }

  // Per-feature graphs. Near-free — filterByFeature already exists and each is a
  // fraction of the whole — and the hedge against a model dense enough that the
  // top-level graph stops being legible.
  //
  // The narrowed model keeps the definitions its relations reference even though
  // `.guardlink/definitions.*` carries no @feature tag. Without that these files
  // rendered every node as a bare id with unknown severity — `xss["⚪ xss"]`
  // instead of `xss["🟠 Cross_Site_Scripting (cwe:CWE-79)"]` — which reads as a
  // model that lost its vocabulary, not as a view that was narrowed.
  const features = listFeatures(ordered);
  const expectedFeatureFiles = new Set(features.map(f => `${featureSlug(f)}.mmd`));
  for (const feature of features) {
    const name = `${featureSlug(feature)}.mmd`;
    const body = generateThreatGraph(filterByFeature(ordered, [feature]), { showAll: true });
    writeDiagram(`by-feature/${name}`, `.guardlink/graph/by-feature/${name}`,
      join(byFeatureDir, name), body, feature);
  }

  // Per-asset and per-boundary slices: the set that is readable rather than
  // merely drawable. See `sliceArtifacts` for what each answers and why the
  // planes are separate files.
  const slices = sliceArtifacts(ordered);
  for (const slice of slices) {
    const dir = slice.path.includes('/by-asset/') ? byAssetDir : byBoundaryDir;
    writeDiagram(slice.name, slice.path, join(dir, slice.file), slice.body, undefined, slice.scope);
  }

  // A renamed or deleted @feature, asset or boundary must not leave its diagram
  // behind claiming to describe something the model no longer has.
  const sweepStale = (dir: string, keep: Set<string>) => {
    if (dryRun || !existsSync(dir)) return;
    for (const stale of readdirSync(dir)) {
      if (stale.endsWith('.mmd') && !keep.has(stale)) rmSync(join(dir, stale));
    }
  };
  sweepStale(byFeatureDir, expectedFeatureFiles);
  sweepStale(byAssetDir, new Set(slices.filter(x => x.path.includes('/by-asset/')).map(x => x.file)));
  sweepStale(byBoundaryDir, new Set(slices.filter(x => x.path.includes('/by-boundary/')).map(x => x.file)));

  // The model itself, canonically ordered so a diff is a real change.
  //
  // `generated_at` is dropped for the same reason it is absent from the .mmd
  // headers, and harder here: model.json is the artifact GL-304 justified
  // committing SPECIFICALLY so that "this PR added an exposure" shows up in
  // review. A permanent one-line diff on every commit would train reviewers to
  // skip the one file whose diffs were supposed to matter.
  //
  // `anchor` is stripped for a related but distinct reason. It is a content hash
  // of the code beneath a claim, present on every one of the model's locations,
  // and the annotation hash EXCLUDES it by design — so the drift check cannot
  // see it move. Written here, several hundred hashes would rot on the next code
  // edit and turn every `guardlink artifacts` run into a large diff that no
  // check explains. Anchors belong to the ledger comparison (`.guardlink/
  // verified.json`, which records them deliberately and is re-locked by
  // `guardlink verify`), not to the durable artifact.
  //
  // `blame` is stripped for the same reason as `anchor`: git attribution attached
  // by `--blame` describes history the annotation hash cannot see and moves with
  // every commit. The reader who asked for it has it on stdout; the committed
  // artifact stays content-derived.
  //
  // R10: `provenance` is stamped INTO the JSON. model.json was the one artifact
  // the drift check could only ask "does it exist?" of — every `.mmd` beside it
  // carried a `%%` header naming its annotation hash, and the file holding the
  // actual model carried nothing. So a `model.json` from three commits ago sat
  // in a repo looking exactly like a current one, and `validate --artifacts`
  // said "Artifacts are current" because the diagrams happened to be.
  const { generated_at, ...durableModel } = ordered;
  write(join(guardlinkDir, 'model.json'), '.guardlink/model.json',
    JSON.stringify({ provenance, ...durableModel }, (key, value) => (key === 'anchor' || key === 'blame' || key === 'blame_context' ? undefined : value), 2) + '\n');

  // Committed, so content-derived only — same rule as the .mmd headers.
  const manifestBody = JSON.stringify({
    schema_version: ARTIFACT_SCHEMA_VERSION,
    ...provenance,
    artifacts: manifest,
  }, null, 2) + '\n';
  if (!dryRun) writeFileSync(join(graphDir, 'MANIFEST.json'), manifestBody);
  written.push('.guardlink/graph/MANIFEST.json');

  if (!dryRun) writeFileSync(join(graphDir, 'README.md'), graphReadme(provenance, features));
  written.push('.guardlink/graph/README.md');

  // The file a human opens first. Every fence in it is a link rather than a
  // diagram, so it renders on GitHub and on a docs site at any model size —
  // which is the property the whole-model diagrams lost.
  if (!dryRun) writeFileSync(join(graphDir, 'index.md'), graphIndex(ordered, provenance, features, slices, manifest));
  written.push('.guardlink/graph/index.md');

  return { written, provenance, emission, manifest, undrawable };
}

/**
 * One committed slice: a question, and the diagram that answers it.
 */
export interface SliceArtifact {
  /** Artifact name for the `%%` header. */
  name: string;
  /** Repo-relative path, for the manifest and the drift check. */
  path: string;
  /** Filename within its directory. */
  file: string;
  /** The `%% scope:` line — what this file leaves out, and why that is correct. */
  scope: string;
  body: string;
}

/**
 * What the committed `.mmd` files should contain now that an interactive view exists.
 *
 * The static artifacts have a job the dashboard cannot do: survive in a git
 * clone, read as text, render in GitHub and in editors nobody configured, and
 * show a threat-model change in a pull request diff. None of that is replaced by
 * a query page, so the answer is not to emit fewer files — it is to change what
 * they are pictures OF.
 *
 * The three top-level diagrams are the whole model in one frame. They stay,
 * because on a small repository they are the right picture and because they are
 * the file a newcomer opens first. But this repository's own threat graph is 43
 * nodes against a measured legibility ceiling of 12, so on anything real they
 * are a picture of a hairball — drawable, current, correct and unreadable, which
 * is the state no existing check could describe. Those three now say their own
 * size in their header.
 *
 * Beside them go the slices that ARE readable, one per question:
 *
 *   `by-asset/<id>.threats.mmd`  what is this component exposed to, and what
 *                                defends it
 *   `by-asset/<id>.flows.mmd`    what does it talk to
 *   `by-boundary/<id>.mmd`       what crosses this trust line
 *
 * Three properties make this worth committing rather than leaving to the
 * dashboard:
 *
 *   **Each one is budgeted.** Every file here is selected by the same
 *   `growWithinBudget` / `assetThreatPlane` code the Explore page uses, so a
 *   file is emitted only if it draws at a size a person can read. A slice that
 *   cannot be narrowed to fit is not written at all — see below.
 *
 *   **A change to one component touches one file.** The whole-graph artifacts
 *   move whenever anything moves; `attack-surface.mmd` rewrites 200 lines for a
 *   single added asset. A per-asset slice diffs where the change was, which is
 *   what committing these files was for.
 *
 *   **It works on repositories that never write `@feature`.** `by-feature/` was
 *   already the density hedge and it is gated on a tag most projects never
 *   apply — this repository has two features, the sibling project measured
 *   alongside it has none. Assets and boundaries are not optional.
 *
 * The planes are separate files because they are separate questions and because
 * a `.mmd` holds exactly one diagram. Fusing them is what makes a 20-node
 * neighbourhood a hairball; a file per plane is the same split the Explore page
 * makes, for the same reason.
 *
 * **A slice that cannot be made legible is not emitted.** That is the one case
 * where writing nothing beats writing something: a stub in `by-asset/` would be
 * a file that exists to say a smaller file could not be made smaller, and the
 * rows that answer the question are in `model.json` and on the Threats page.
 * `index.md` lists what was skipped and why, so the absence is stated rather
 * than left to be noticed.
 */
export function sliceArtifacts(model: ThreatModel): SliceArtifact[] {
  const key = canonicaliser(model);
  const out: SliceArtifact[] = [];

  // Declared assets only. An undeclared endpoint (`UserPrompt`, `FileSystem`)
  // has no `@asset` to name a file after and no identity that survives a
  // rename, so committing a file per one of those would churn on spelling.
  const assetKeys = [...new Set(model.assets.map(a => key(a.id || a.path.join('.'))))].sort();

  for (const asset of assetKeys) {
    const label = model.assets.find(a => key(a.id || a.path.join('.')) === asset);
    const display = label ? (label.id ? `#${label.id}` : label.path.join('.')) : asset;
    const slug = featureSlug(asset);

    const threats = assetThreatPlane(model, asset, m => generateThreatGraph(m, { showAll: true }));
    if (threats.source) {
      out.push({
        name: `by-asset/${slug}.threats.mmd`,
        path: `.guardlink/graph/by-asset/${slug}.threats.mmd`,
        file: `${slug}.threats.mmd`,
        scope: `${display} only — its own threats and controls`
          + (threats.narrowing === 'high-severity-only'
            ? `, narrowed to high and critical (${threats.hidden ?? 0} lower-severity claim(s) omitted to keep it readable)`
            : ''),
        body: threats.source,
      });
    }

    const flows = growWithinBudget(model, {
      seeds: [asset], render: m => generateDataFlowDiagram(m), kinds: FLOW_KINDS,
    });
    if (flows.source) {
      out.push({
        name: `by-asset/${slug}.flows.mmd`,
        path: `.guardlink/graph/by-asset/${slug}.flows.mmd`,
        file: `${slug}.flows.mmd`,
        scope: `${display} and its flow neighbourhood, grown until the drawing stopped fitting`
          + (flows.omitted.length > 0 ? ` — ${flows.omitted.length} neighbour(s) one hop out are not shown` : ''),
        body: flows.source,
      });
    }
  }

  // Boundaries are named by their `@boundary (#id)` where one was declared and
  // by their two sides otherwise, so the filename survives an edit to the
  // description. Small by construction — a boundary has two sides — which makes
  // this the one whole-scope picture that is always drawable.
  const seenBoundary = new Set<string>();
  for (let i = 0; i < model.boundaries.length; i++) {
    const b = model.boundaries[i];
    const sides = boundarySides(model, i);
    const slug = featureSlug(b.id || sides.join('-to-'));
    if (seenBoundary.has(slug)) continue;
    seenBoundary.add(slug);

    const grown = growWithinBudget(model, {
      seeds: sides, render: m => generateDataFlowDiagram(m), kinds: FLOW_KINDS,
    });
    if (!grown.source) continue;
    out.push({
      name: `by-boundary/${slug}.mmd`,
      path: `.guardlink/graph/by-boundary/${slug}.mmd`,
      file: `${slug}.mmd`,
      scope: `the ${b.description || b.id || 'trust boundary'} between ${sides.join(' and ')}, and what flows across it`,
      body: grown.source,
    });
  }

  return out;
}

/**
 * The `%%` note above a diagram that draws but cannot be read.
 *
 * Empty for every slice, by construction — they are selected against this exact
 * budget — and present on the three whole-model diagrams of any real
 * repository. It exists because a committed `.mmd` is opened somewhere we do
 * not control: GitHub renders it with no page around it, so if the file does
 * not say it is too big to read, nothing does.
 *
 * Not a refusal. The diagram is still written and still correct; what changes is
 * that it stops being presented as though its size were fine, and it names the
 * files that answer the same question at a size that is.
 */
export function legibilityPreamble(name: string, body: string): string {
  const verdict = checkLegibility(body);
  if (verdict.legible) return '';
  return [
    `%% ---`,
    `%% DRAWS, BUT IS TOO BIG TO READ. ${name} is ${describeLegibility(verdict)}.`,
    `%% ${LEGIBILITY_BUDGET.nodes} nodes and ${LEGIBILITY_BUDGET.edges} edges is what fits a dashboard diagram panel at its`,
    `%% label size; past it a layered layout grows taller than the panel and`,
    `%% fitting it shrinks the labels below reading size. Mermaid will draw this`,
    `%% — it is well inside the limits in the header above — so nothing will`,
    `%% report an error. It is simply not a picture anyone can use.`,
    `%% This is the whole model in one frame, which is the right thing on a small`,
    `%% repository. For one that is not: by-asset/ has this component's threats`,
    `%% and its flow neighbourhood as separate, budgeted diagrams, by-boundary/`,
    `%% has one per trust line, and index.md says which question each answers.`,
    '',
  ].join('\n');
}

/**
 * The `%%` block that sits above a stub, for the reader who opens the file as
 * text rather than rendering it.
 *
 * Says the number, the limit, where the limit comes from and what to read
 * instead. A stub with no prose would be a second kind of confidently-wrong
 * file: small, drawable, and silent about the model it is standing in for.
 */
export function budgetPreamble(name: string, verdict: RenderBudgetVerdict): string {
  return [
    `%% ---`,
    `%% NOT A DIAGRAM. ${name} exceeded the Mermaid render budget, so the graph`,
    `%% below is a stub. The real one was not written, because nothing would have`,
    `%% drawn it — and a .mmd that renders as one pink box reading "Maximum text`,
    `%% size in diagram exceeded" is worse than a file that says what happened.`,
    ...verdict.violations.map(v => `%%   ${describeViolation(v)}`),
    ...verdict.violations.map(v => `%%   ${v.symptom}`),
    `%% The limits are Mermaid's own defaults (${MERMAID_LIMITS_SOURCE}:`,
    `%% maxTextSize ${MERMAID_LIMITS.maxTextSize}, maxEdges ${MERMAID_LIMITS.maxEdges}), so they apply in GitHub, in`,
    `%% mermaid.live and in the VS Code preview exactly as they do here.`,
    `%% ${ARTIFACT_FALLBACK}`,
    `%% Narrow the picture instead: tag code with @feature and`,
    `%% .guardlink/graph/by-feature/ gets one drawable graph per feature.`,
    '',
  ].join('\n');
}

// ─── Drift check (GL-302) ────────────────────────────────────────────

export interface DriftFinding {
  path: string;
  /** 'stale' — the header's hash disagrees with the model. 'missing' — never emitted. 'unheadered' — no provenance. */
  kind: 'stale' | 'missing' | 'unheadered';
  expected?: string;
  found?: string | null;
}

/**
 * Every artifact path `emitArtifacts` produces for a given model.
 *
 * Derived from the model, so the emitter and the drift check agree by
 * construction rather than by both being maintained. The check needs this
 * because "which files should exist" cannot be answered by listing the files
 * that do exist — see below.
 */
export function expectedArtifactPaths(model: ThreatModel): string[] {
  const ordered = canonicalizeModelOrder(model);
  return [
    '.guardlink/graph/threat-graph.mmd',
    '.guardlink/graph/dataflow.mmd',
    '.guardlink/graph/attack-surface.mmd',
    ...listFeatures(ordered).map(f => `.guardlink/graph/by-feature/${featureSlug(f)}.mmd`),
    // Derived from the same function that writes them, so a slice that is not
    // emitted (because it could not be made legible) is not then reported
    // missing — the emitter and the check agree by construction rather than by
    // both being maintained.
    ...sliceArtifacts(ordered).map(x => x.path),
    '.guardlink/model.json',
    '.guardlink/graph/MANIFEST.json',
  ];
}

/**
 * Compare emitted artifacts against the current model.
 *
 * Compares the recorded `annotation_hash`, not the file bytes: a diagram is
 * stale when the annotations moved underneath it, and only then. Comparing bytes
 * would flag a generator upgrade as drift and, worse, would go quiet if someone
 * hand-edited an artifact to match.
 *
 * Found while wiring D28's CI gate: this used to enumerate the `.mmd` files
 * PRESENT on disk and hash-check those, so a deleted artifact was not stale, it
 * was simply never looked at — `rm .guardlink/graph/dataflow.mmd` reported
 * "Artifacts are current" and exited 0. `kind: 'missing'` existed but only fired
 * when the whole `graph/` directory was gone. A gate that cannot see a deletion
 * is not a gate, so the check now starts from what SHOULD exist.
 */
export function checkArtifactDrift(root: string, model: ThreatModel): DriftFinding[] {
  const expected = computeAnnotationHash(canonicalizeModelOrder(model));
  const graphDir = join(root, '.guardlink', 'graph');
  const findings: DriftFinding[] = [];

  if (!existsSync(graphDir)) {
    return [{ path: '.guardlink/graph/', kind: 'missing', expected }];
  }

  // 1. Everything the model says should be there, is.
  //
  // R10: `model.json` is hash-checked now, not merely counted. It used to be
  // the one expected artifact this loop looked at and then skipped, because the
  // `.endsWith('.mmd')` test was the only way it knew how to read a hash — so
  // the file carrying the actual model was the one file whose staleness the
  // staleness gate could not see. The check now covers the 19 diagrams AND the
  // three artifacts anything downstream actually consumes.
  const files: string[] = [];
  for (const relative of expectedArtifactPaths(model)) {
    const absolute = join(root, relative);
    if (!existsSync(absolute)) findings.push({ path: relative, kind: 'missing', expected });
    else files.push(absolute);
  }

  // 2. Plus any other .mmd sitting in graph/. A leftover from a renamed
  //    feature still claims to describe the model, so it is checked too.
  const alsoCheck = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir)) {
      if (!entry.endsWith('.mmd')) continue;
      const absolute = join(dir, entry);
      if (!files.includes(absolute)) files.push(absolute);
    }
  };
  alsoCheck(graphDir);
  alsoCheck(join(graphDir, 'by-feature'));
  alsoCheck(join(graphDir, 'by-asset'));
  alsoCheck(join(graphDir, 'by-boundary'));

  for (const file of files) {
    const relative = file.slice(root.length + 1).replaceAll('\\', '/');
    const found = readArtifactHash(readFileSync(file, 'utf-8'));
    if (found === null) findings.push({ path: relative, kind: 'unheadered', expected });
    else if (found !== expected) findings.push({ path: relative, kind: 'stale', expected, found });
  }

  // 3. Plus every OPTIONAL stamped artifact that happens to be present.
  //
  //    Optional in a precise sense: absence is not drift. Nothing obliges a repo
  //    to keep a `report.json`, to have run `guardlink sarif -o`, or to carry
  //    every agent's instruction file — but a repo that HAS one and lets it rot
  //    is publishing a threat model that is not this one. `findings.sarif` is the
  //    sharpest of them: it is what a pentest reads, so a stale one decides which
  //    exposures get tested at all.
  //
  //    STALE only, never `unheadered`. An optional artifact with no hash makes no
  //    claim about which annotations it came from, and it was almost certainly
  //    written by a binary that predates the stamping — failing a repo for that
  //    would be punishing the wrong thing, and it fixes itself the next time the
  //    command that writes it is run. A WRONG hash is a false claim, and that is
  //    what this catches.
  for (const relative of OPTIONAL_STAMPED_ARTIFACTS) {
    const absolute = join(root, relative);
    if (!existsSync(absolute) || files.includes(absolute)) continue;
    const found = readArtifactHash(readFileSync(absolute, 'utf-8'));
    if (found !== null && found !== expected) {
      findings.push({ path: relative, kind: 'stale', expected, found });
    }
  }

  return findings;
}

// ─── Drawability check ───────────────────────────────────────────────

export interface RenderFinding {
  path: string;
  measurement: DiagramMeasurement;
  violations: BudgetViolation[];
}

/**
 * Every committed `.mmd` that no renderer will draw.
 *
 * Deliberately a SECOND function beside `checkArtifactDrift`, not a new
 * `DriftFinding.kind`. They answer different questions — *is this current* and
 * *will anything draw it* — and folding the second into the first would repeat
 * the mistake that made this necessary: one check, one verdict, and the
 * drawability half invisible inside it. A diagram can be perfectly current and
 * undrawable, which is the case `validate --artifacts` used to certify as fine.
 *
 * Measured from the bytes on disk rather than read out of MANIFEST.json's
 * `renderable` field, for two reasons. An artifact written by a GuardLink that
 * predates the budget carries no such field and is exactly the file this needs
 * to catch; and a check that trusts the manifest is trusting the same emission
 * it is supposed to be checking.
 *
 * Silent about files that are absent — that is `checkArtifactDrift`'s question,
 * and answering it twice would double every missing-file line in the output.
 */
export function checkArtifactRenderability(root: string): RenderFinding[] {
  const graphDir = join(root, '.guardlink', 'graph');
  const findings: RenderFinding[] = [];

  const sweep = (dir: string, prefix: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir).sort()) {
      if (!entry.endsWith('.mmd')) continue;
      const verdict = checkRenderBudget(readFileSync(join(dir, entry), 'utf-8'));
      if (!verdict.renderable) {
        findings.push({ path: `${prefix}${entry}`, measurement: verdict.measurement, violations: verdict.violations });
      }
    }
  };
  sweep(graphDir, '.guardlink/graph/');
  sweep(join(graphDir, 'by-feature'), '.guardlink/graph/by-feature/');
  sweep(join(graphDir, 'by-asset'), '.guardlink/graph/by-asset/');
  sweep(join(graphDir, 'by-boundary'), '.guardlink/graph/by-boundary/');

  return findings;
}

/**
 * Artifacts that carry an `annotation_hash` when they exist, and are checked
 * when they do (R10).
 *
 * Separate from `expectedArtifactPaths` because these are not emitted by
 * `guardlink artifacts` — they are written by `sarif`, by `report --format
 * json`, and by `sync`. A missing one is a repo that never ran that command; a
 * STALE one is a published artifact that no longer describes this tree, which
 * is the whole point of having a hash.
 *
 * The agent instruction files are the reason this list is not just the two JSON
 * exports: they are the eight files a coding agent reads to learn this repo's
 * asset and threat vocabulary, they already carry the hash in their synced
 * block, and nothing checked it — so an agent could be reading last month's
 * vocabulary and reusing ids the model no longer declares.
 */
export const OPTIONAL_STAMPED_ARTIFACTS: readonly string[] = [
  // Machine-readable exports, at the paths the CLI's own help and the
  // downstream tooling use.
  '.guardlink/report.json',
  '.guardlink/findings.sarif',
  'threat-model.json',
  'guardlink-pentest.sarif',
  // The eight files `guardlink sync` writes, plus the generated graph README.
  'CLAUDE.md',
  'AGENTS.md',
  '.clinerules',
  '.windsurfrules',
  '.cursor/rules/guardlink.mdc',
  '.gemini/GEMINI.md',
  '.github/copilot-instructions.md',
  '.guardlink/README.md',
];

// ─── graph/index.md ──────────────────────────────────────────────────

// @shield:begin -- "graph/index example content, excluded from parsing"
/**
 * A table of slices and the question each one answers.
 *
 * This is the file to open first, and it is deliberately Markdown rather than a
 * diagram. It renders natively on GitHub and on a docs site at any model size,
 * because it holds links and a table rather than a picture — the one form that
 * does not have a legibility ceiling. The three whole-model diagrams are listed
 * with their measured size, so a reader learns which of them is worth opening
 * BEFORE opening it.
 *
 * Slices that were skipped are named. An absent `by-asset/<id>.flows.mmd` means
 * that component declares no `@flows`, which is a fact about the model and not
 * an emission that failed; leaving it unexplained would make the directory
 * listing read as incomplete.
 */
function graphIndex(
  model: ThreatModel, p: ArtifactProvenance, features: string[],
  slices: SliceArtifact[], manifest: ManifestEntry[],
): string {
  const key = canonicaliser(model);
  const measured = new Map(manifest.map(m => [m.path, m]));

  const topLevel = [
    ['threat-graph.mmd', 'Every component, the threats declared on it, and the controls that answer them.'],
    ['dataflow.mmd', 'Every `@flows` between components, with trust boundaries drawn as zones.'],
    ['attack-surface.mmd', 'Exposures per component, worst first.'],
  ] as const;

  const sizeOf = (path: string): string => {
    const entry = measured.get(path);
    if (!entry?.render) return '—';
    if (entry.renderable === false) return `**not drawn** — ${groupDigits(entry.render.text_size)} chars / ${entry.render.edges} edges`;
    const legible = entry.render.edges <= LEGIBILITY_BUDGET.edges;
    return `${entry.render.edges} edges${legible ? '' : ' — **past the readable size**'}`;
  };

  const assetSlices = slices.filter(x => x.path.includes('/by-asset/'));
  const boundarySlices = slices.filter(x => x.path.includes('/by-boundary/'));

  const declared = [...new Set(model.assets.map(a => key(a.id || a.path.join('.'))))].sort();
  const noThreats = declared.filter(a => !assetSlices.some(x => x.file === `${featureSlug(a)}.threats.mmd`));
  const noFlows = declared.filter(a => !assetSlices.some(x => x.file === `${featureSlug(a)}.flows.mmd`));

  const rows = (xs: SliceArtifact[]) => xs
    .map(x => `| [\`${x.file}\`](${x.path.replace('.guardlink/graph/', '')}) | ${x.scope} |`)
    .join('\n');

  return `# Threat model diagrams — what to open, and for which question

**Every file here is generated. Do not edit any of them.** Regenerate with
\`guardlink artifacts .\`; check them with \`guardlink validate . --artifacts\`.

## Start here

These are budgeted: each is selected and drawn only if it comes out at a size a
person can read — at most ${LEGIBILITY_BUDGET.nodes} nodes and ${LEGIBILITY_BUDGET.edges} edges, which is what fits a diagram
panel at its label size. A file that could not be made to fit is not written, and
is named at the bottom of this page instead.

### One component at a time

\`.threats.mmd\` answers *what is this exposed to, and what defends it*.
\`.flows.mmd\` answers *what does it talk to*. They are separate files because
they are separate questions: fusing the two planes onto one canvas is what turns
a small neighbourhood into a hairball.

${assetSlices.length > 0
    ? `| File | What it shows |\n|---|---|\n${rows(assetSlices)}`
    : '_No component slices: this model declares no `@asset` carrying a claim or a flow._'}

### One trust line at a time

${boundarySlices.length > 0
    ? `| File | What it shows |\n|---|---|\n${rows(boundarySlices)}`
    : '_No boundary slices: this model declares no `@boundary`._'}

## The whole model in one frame

Correct, current, and — past about a dozen components — not readable. Kept
because on a small repository they are the right picture, and listed with their
size so you know which you are about to open.

| File | What it shows | Size |
|---|---|---|
${topLevel.map(([file, what]) => `| [\`${file}\`](${file}) | ${what} | ${sizeOf(`.guardlink/graph/${file}`)} |`).join('\n')}

${features.length > 0
    ? `## One feature at a time\n\n${features.map(f => `- [\`by-feature/${featureSlug(f)}.mmd\`](by-feature/${featureSlug(f)}.mmd) — the threat graph narrowed to \`@feature "${f}"\`. **Partial by construction**: a node it does not show is one that feature does not touch, not one the project lacks.`).join('\n')}`
    : '## One feature at a time\n\nThis project declares no `@feature` annotations, so `by-feature/` is empty. The\ncomponent and boundary slices above need no tagging and are always emitted.'}

## Also here

- [\`MANIFEST.json\`](MANIFEST.json) — per-artifact size, the annotation hash each was built from, and whether anything will draw it.
- [\`../model.json\`](../model.json) — the whole parsed model, canonically ordered. Every claim is in it, whether or not a diagram could show it.
- [\`README.md\`](README.md) — how staleness and drawability are checked, and how to resolve a merge conflict in this directory.
${noThreats.length > 0 ? `\n## Components with no threat diagram\n\n${noThreats.map(a => `- \`${a}\` — declares no \`@exposes\`, \`@mitigates\`, \`@confirmed\` or \`@accepts\`, or carries too many to draw legibly even narrowed to high and critical. Its claims, if any, are in \`../model.json\`.`).join('\n')}` : ''}
${noFlows.length > 0 ? `\n## Components with no flow diagram\n\n${noFlows.map(a => `- \`${a}\` — declares no \`@flows\` or \`@boundary\`, so it has no neighbourhood to draw.`).join('\n')}` : ''}

---

Generated by ${p.generator} from annotation hash \`${p.annotation_hash}\`. If that
differs from what \`guardlink status .\` reports, everything here is stale —
regenerate rather than trusting it.
`;
}
// @shield:end

// ─── graph/README.md ─────────────────────────────────────────────────

// @shield:begin -- "graph/README example content, excluded from parsing"
function graphReadme(p: ArtifactProvenance, features: string[]): string {
  return `# .guardlink/graph/ — generated diagrams

**Every file here is generated. Do not edit any of them.** Regenerate with:

\`\`\`sh
guardlink artifacts .
\`\`\`

## What these are

| File | What it shows |
|---|---|
| \`threat-graph.mmd\` | Assets, the threats they are exposed to, and the controls that mitigate them. |
| \`dataflow.mmd\` | \`@flows\` between components, with trust boundaries. |
| \`attack-surface.mmd\` | Entry points and what an attacker reaches from them. |
| \`by-feature/<name>.mmd\` | The threat graph narrowed to one \`@feature\`. **Partial by construction** — a node it does not show is one that feature does not touch, not one the project lacks. Its \`annotation_hash\` is the whole project's, the state the view was cut from. |
| \`MANIFEST.json\` | Per-artifact size and the annotation hash each was built from. |
| \`../model.json\` | The whole parsed threat model, canonically ordered. |

${features.length ? `Features in this project: ${features.map(f => `\`${f}\``).join(', ')}.` : 'This project declares no `@feature` annotations, so `by-feature/` is empty.'}

These are Mermaid. Paste one into any Mermaid viewer, or read it as text — the
syntax is legible without rendering.

## Staleness

Each \`.mmd\` opens with a \`%%\` header naming the \`annotation_hash\` it was built
from. Mermaid treats \`%%\` as a comment, so it renders as if it were not there.

**A generated diagram in a repository looks like source.** That is the risk these
headers exist to answer: a reader who does not know a file is derived will not
think to check whether it is current, and a confidently wrong dataflow diagram is
worse than no diagram at all.

To check:

\`\`\`sh
guardlink validate . --artifacts     # exits non-zero if any artifact is stale or undrawable
\`\`\`

If it reports drift, regenerate. Never hand-edit an artifact to make the check
pass — the hash describes the annotations, so editing the file makes it lie.

## Drawability

Staleness is not the only way one of these files can be wrong. Past a size
Mermaid stops drawing, and the worse of its two limits fails **silently**: over
\`maxTextSize\` (${MERMAID_LIMITS.maxTextSize} characters) the render resolves normally, writes nothing to
the console, and draws a single box reading "Maximum text size in diagram
exceeded". Over \`maxEdges\` (${MERMAID_LIMITS.maxEdges}) the parser throws and you get a syntax error.
Both are Mermaid's own defaults, so they apply in GitHub, in mermaid.live and in
the VS Code preview, not only here.

\`guardlink artifacts\` measures every diagram against those limits before writing
it. A diagram that would exceed them is **not written as a diagram**: the file
gets a stub naming what exceeded and by how much, \`MANIFEST.json\` records
\`renderable: false\` for it, and \`validate . --artifacts\` fails. That is
deliberate — the alternative is a committed file that looks like a diagram,
cannot be drawn, and passes the freshness check.

If you hit it: the model is not lost, only this picture of it. Read
\`../model.json\` for all of it, or open the dashboard — Analytics for the
asset × threat matrix (readable at this size, capped at its worst 24 assets and
says so) and Threats & Exposures for every claim. Tagging code with \`@feature\`
also helps: each feature gets its own, much smaller, graph in \`by-feature/\`.

## Merge conflicts

Resolve by regenerating, never by hand-merging. Both sides of a conflict are
derived from annotations that have already been merged in the source files:

\`\`\`sh
git checkout --ours .guardlink/graph/ && guardlink artifacts .
\`\`\`

\`.gitattributes\` marks these \`linguist-generated\`, so they are collapsed in pull
request diffs and excluded from language statistics.

## Why they are committed

A fresh clone gets the threat model without running anything, and a change to the
model shows up in review — "this PR added an exposure" is visible in the diff
rather than requiring a reviewer to know to look.

---

Generated by ${p.generator}. For when, ask git — a timestamp here would
rewrite this file on every commit and tell you less than \`git log\` does.
`;
}
// @shield:end
