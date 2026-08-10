/**
 * GuardLink — Cheap project fingerprint (GL-103).
 *
 * A hash of *which files exist and when they last changed*, computed without
 * reading or parsing any of them. Callers that cache a parsed model compare
 * fingerprints to decide whether the cache is still valid.
 *
 * This is deliberately not the annotation hash. The annotation hash answers
 * "did the threat model change", and computing it requires a full parse — which
 * is the work the cache exists to avoid. This answers the cheaper question
 * "could anything have changed", and is allowed to be conservative: an mtime
 * touch with no content edit costs one needless re-parse, which is correct
 * behaviour at a small price. The reverse error — missing a real edit — is the
 * one that makes a tool lie for a whole session.
 *
 * External mode is the reason this matters more than it looks. When annotations
 * live in `.guardlink/annotations/**.gal`, the sidecar changes while the source
 * file does not, so nothing incidental signals that the model moved.
 *
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "Fingerprint globs the project tree on every call"
 * @mitigates #parser against #dos using #resource-limits -- "Reuses DEFAULT_EXCLUDE; stats come from the glob walk, no extra stat() calls, no file reads"
 * @flows ProjectRoot -> #parser via fast-glob -- "Directory metadata scan for cache validity"
 * @comment -- "Metadata only: path, size, mtime. File contents are never read."
 */

import fg from 'fast-glob';
import { createHash } from 'node:crypto';
import { DEFAULT_INCLUDE, DEFAULT_EXCLUDE } from './parse-project.js';

// Control characters, so a path containing any printable byte cannot forge a
// field or record boundary.
const FIELD_SEP = String.fromCharCode(1);
const RECORD_SEP = String.fromCharCode(2);

export interface FingerprintOptions {
  include?: string[];
  exclude?: string[];
}

/**
 * Fingerprint every file the parser would scan, from directory metadata alone.
 *
 * Returns a stable hex digest. Two calls return the same value if and only if
 * the same set of files exists with the same sizes and modification times.
 */
export async function fingerprintProject(root: string, options: FingerprintOptions = {}): Promise<string> {
  const { include = DEFAULT_INCLUDE, exclude = DEFAULT_EXCLUDE } = options;

  // `stats: true` gets size and mtime from the walk itself — no second stat()
  // pass over the tree.
  const entries = await fg(include, {
    cwd: root,
    ignore: exclude,
    absolute: true,
    dot: true,
    stats: true,
    suppressErrors: true,
  });

  const parts = entries
    .map(e => [e.path, e.stats?.size ?? 0, Math.trunc(e.stats?.mtimeMs ?? 0)].join(FIELD_SEP))
    .sort();

  return createHash('sha256').update(parts.join(RECORD_SEP)).digest('hex');
}
