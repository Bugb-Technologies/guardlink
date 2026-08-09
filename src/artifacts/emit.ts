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
 */

import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { generateThreatGraph, generateDataFlowDiagram, generateAttackSurface } from '../dashboard/index.js';
import { listFeatures, filterByFeature } from '../parser/feature-filter.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';
import { computeAnnotationHash } from '../parser/annotation-hash.js';
import { readGitSha } from '../workspace/metadata.js';
import { getPackageVersion } from '../version.js';
import type { ThreatModel } from '../types/index.js';

/** Bump when the emitted layout changes in a way a consumer would notice. */
export const ARTIFACT_SCHEMA_VERSION = 1;

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
}

export interface EmitResult {
  written: string[];
  provenance: ArtifactProvenance;
  /** Reported to the caller; deliberately absent from every written file. */
  emission: EmissionInfo;
  manifest: ManifestEntry[];
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
 */
export function mermaidHeader(name: string, p: ArtifactProvenance): string {
  return [
    `%% GENERATED FILE — do not edit. Regenerate with: guardlink artifacts .`,
    `%% artifact:        ${name}`,
    `%% annotation_hash: ${p.annotation_hash}`,
    `%% generator:       ${p.generator}`,
    // NOT a bare `%%`: a line containing exactly that is read as the start of a
    // `%%{init}%%` directive and fails to parse. Verified against mermaid@11.16.1.
    `%% ---`,
    `%% This diagram is derived from the annotations in this repository. If`,
    `%% annotation_hash above differs from what \`guardlink status .\` reports, the`,
    `%% diagram is STALE — regenerate rather than trusting it.`,
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

/** Read the annotation_hash a `.mmd` header claims, or null if it has none. */
export function readArtifactHash(text: string): string | null {
  const m = text.match(/^%% annotation_hash:\s*(\S+)\s*$/m);
  return m ? m[1] : null;
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

  const written: string[] = [];
  const manifest: ManifestEntry[] = [];

  const write = (absolute: string, relative: string, content: string) => {
    if (!dryRun) writeFileSync(absolute, content);
    written.push(relative);
    manifest.push({
      path: relative,
      bytes: Buffer.byteLength(content),
      annotation_hash: provenance.annotation_hash,
    });
  };

  if (!dryRun) {
    mkdirSync(graphDir, { recursive: true });
    mkdirSync(byFeatureDir, { recursive: true });
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
    write(join(graphDir, name), `.guardlink/graph/${name}`, mermaidHeader(name, provenance) + body);
  }

  // Per-feature graphs. Near-free — filterByFeature already exists and each is a
  // fraction of the whole — and the hedge against a model dense enough that the
  // top-level graph stops being legible.
  const features = listFeatures(ordered);
  const expectedFeatureFiles = new Set(features.map(f => `${featureSlug(f)}.mmd`));
  for (const feature of features) {
    const name = `${featureSlug(feature)}.mmd`;
    const body = generateThreatGraph(filterByFeature(ordered, [feature]), { showAll: true });
    write(join(byFeatureDir, name), `.guardlink/graph/by-feature/${name}`,
      mermaidHeader(`by-feature/${name} (@feature "${feature}")`, provenance) + body);
  }

  // A renamed or deleted @feature must not leave its diagram behind claiming to
  // describe something the model no longer has.
  if (!dryRun && existsSync(byFeatureDir)) {
    for (const stale of readdirSync(byFeatureDir)) {
      if (stale.endsWith('.mmd') && !expectedFeatureFiles.has(stale)) {
        rmSync(join(byFeatureDir, stale));
      }
    }
  }

  // The model itself, canonically ordered so a diff is a real change.
  write(join(guardlinkDir, 'model.json'), '.guardlink/model.json',
    JSON.stringify(ordered, null, 2) + '\n');

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

  return { written, provenance, emission, manifest };
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
 * Compare emitted artifacts against the current model.
 *
 * Compares the recorded `annotation_hash`, not the file bytes: a diagram is
 * stale when the annotations moved underneath it, and only then. Comparing bytes
 * would flag a generator upgrade as drift and, worse, would go quiet if someone
 * hand-edited an artifact to match.
 */
export function checkArtifactDrift(root: string, model: ThreatModel): DriftFinding[] {
  const expected = computeAnnotationHash(canonicalizeModelOrder(model));
  const graphDir = join(root, '.guardlink', 'graph');
  const findings: DriftFinding[] = [];

  if (!existsSync(graphDir)) {
    return [{ path: '.guardlink/graph/', kind: 'missing', expected }];
  }

  const files: string[] = [];
  for (const entry of readdirSync(graphDir)) {
    if (entry.endsWith('.mmd')) files.push(join(graphDir, entry));
  }
  const byFeatureDir = join(graphDir, 'by-feature');
  if (existsSync(byFeatureDir)) {
    for (const entry of readdirSync(byFeatureDir)) {
      if (entry.endsWith('.mmd')) files.push(join(byFeatureDir, entry));
    }
  }

  for (const file of files) {
    const relative = file.slice(root.length + 1).replaceAll('\\', '/');
    const found = readArtifactHash(readFileSync(file, 'utf-8'));
    if (found === null) findings.push({ path: relative, kind: 'unheadered', expected });
    else if (found !== expected) findings.push({ path: relative, kind: 'stale', expected, found });
  }

  return findings;
}

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
| \`by-feature/<name>.mmd\` | The threat graph narrowed to one \`@feature\`. |
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
guardlink validate . --artifacts     # exits non-zero if any artifact is stale
\`\`\`

If it reports drift, regenerate. Never hand-edit an artifact to make the check
pass — the hash describes the annotations, so editing the file makes it lie.

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
