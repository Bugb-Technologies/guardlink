/**
 * GuardLink MCP — Freshness envelope (GL-102).
 *
 * Every tool result and every resource read carries provenance describing the
 * model it was computed from, so a consumer can tell a current answer from a
 * stale one without a second call.
 *
 * The envelope is a **sibling** of the payload, never merged into it: it is
 * appended as an additional content block, so byte-for-byte every existing
 * payload is unchanged and `content[0]` still means what it always meant.
 * Merging it into the JSON would have been a breaking change for every consumer
 * that reads a known shape.
 *
 * Before this there was no metadata on the MCP surface at all — `populateMetadata`
 * runs only in the CLI report path, and the tools returned bare payloads.
 *
 * @exposes #mcp to #info-disclosure [low] cwe:CWE-200 -- "Envelope discloses the absolute project root and git SHA to the connected client"
 * @audit #mcp -- "Root and SHA are disclosed deliberately: without them a client cannot tell which repo answered (D9). Client is already trusted with the full threat model."
 * @flows ThreatModel -> #mcp via buildEnvelope -- "Model content hashed for the freshness envelope"
 * @flows GitRepo -> #mcp via readFileSync -- "HEAD read directly from .git, no subprocess"
 * @comment -- "git SHA is read from .git/HEAD rather than spawned via execSync: this runs on every tool call"
 */

import { resolve } from 'node:path';
import { readGitSha } from '../workspace/metadata.js';
import { computeAnnotationHash } from '../parser/annotation-hash.js';
import { detectAnnotationMode, type AnnotationMode } from '../parser/annotation-mode.js';
import { getPackageVersion } from '../version.js';
import type { ThreatModel } from '../types/index.js';

// Re-exported for the tools that already import it from here.
export { readGitSha };

export interface FreshnessEnvelope {
  /** Content hash of the annotation set (GL-101). Moves only when annotations change. */
  annotation_hash: string;
  /** Git commit SHA of the answering repo, or null outside a git checkout. */
  git_sha: string | null;
  /** When this response was produced. */
  generated_at: string;
  /** Where the annotations live: source comments, `.gal` sidecars, or both. */
  mode: AnnotationMode;
  /** Absolute path of the repo this answer describes. */
  root: string;
  /** GuardLink version that produced it. */
  guardlink_version: string;
}


/** Build the envelope for a model that parsed successfully. */
export function buildEnvelope(root: string, model: ThreatModel): FreshnessEnvelope {
  return {
    annotation_hash: computeAnnotationHash(model),
    git_sha: readGitSha(root),
    generated_at: new Date().toISOString(),
    mode: detectAnnotationMode(model).mode,
    root: resolve(root),
    guardlink_version: getPackageVersion(),
  };
}

/**
 * Envelope for the case where the model could not be produced.
 *
 * A tool that failed still owes the caller provenance — silently dropping the
 * envelope would make "no envelope" ambiguous between an old server and a
 * broken parse.
 */
export function degradedEnvelope(root: string, reason: string): FreshnessEnvelope & { unavailable: string } {
  return {
    annotation_hash: 'unavailable',
    git_sha: readGitSha(root),
    generated_at: new Date().toISOString(),
    mode: 'inline',
    root: resolve(root),
    guardlink_version: getPackageVersion(),
    unavailable: reason,
  };
}

/** The envelope as the text of its own content block, under a single namespaced key. */
export function envelopeBlock(envelope: FreshnessEnvelope): { type: 'text'; text: string } {
  return { type: 'text', text: JSON.stringify({ guardlink: envelope }, null, 2) };
}
