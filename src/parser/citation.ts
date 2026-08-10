/**
 * GuardLink — Citation extraction for @entitles descriptions.
 *
 * §3.4 of docs/prd/actor-entitlement-design.md: an entitlement whose description
 * does not point at the authorization code that grants it is *inert* — parsed and
 * carried in the model, but it may never demote a finding. This module decides
 * whether a citation is present and, when it is, exposes the cited file so
 * `guardlink diff` can report the entitlement as stale once that file changes.
 *
 * A citation is a `path/to/file.ext` token, optionally suffixed `:<line>`:
 *
 *   "By design: the archival URI is namespace configuration.
 *    Authz: ScopeCluster/AccessAdmin at common/api/metadata.go:189"
 *                                        ^^^^^^^^^^^^^^^^^^^^^^^^^
 *
 * @comment -- "Pure function over annotation text; no I/O, no filesystem check — a citation is a claim about where authz lives, and verifying the path exists is a reviewer's job (§3.4)"
 * @mitigates #parser against #redos using #regex-anchoring -- "Tokenizes on whitespace first, then matches each path segment with an anchored, quantifier-free-nesting pattern — no backtracking over the whole description"
 */

import type { EntitlementCitation } from '../types/index.js';

// ─── Token patterns ──────────────────────────────────────────────────
// Each is anchored and applied to a single short token, never to prose.

/** A path segment: no slashes, no whitespace. */
const SEGMENT_RE = /^[A-Za-z0-9_.\-]+$/;

/** The final segment must look like a filename: `name.ext`, ext 1–10 alpha-num starting with a letter. */
const FILENAME_RE = /^[A-Za-z0-9_\-][A-Za-z0-9_.\-]*\.[A-Za-z][A-Za-z0-9]{0,9}$/;

const LINE_RE = /^\d{1,7}$/;

/** Trailing/leading prose punctuation that can cling to a citation token. */
const TRIM_RE = /^[("'`\[<]+|[)"'`\]>.,;:!?]+$/g;

// ─── Extraction ──────────────────────────────────────────────────────

/**
 * Extract the first citation from an annotation description.
 * Returns undefined when the description carries no `file[:line]` pointer —
 * which makes the entitlement inert.
 */
export function extractCitation(description?: string): EntitlementCitation | undefined {
  if (!description) return undefined;

  for (const rawToken of description.split(/\s+/)) {
    const token = rawToken.replace(TRIM_RE, '');
    if (!token) continue;
    const citation = parseCitationToken(token);
    if (citation) return citation;
  }
  return undefined;
}

/** Parse one whitespace-delimited token as `path/to/file.ext[:line]`. */
function parseCitationToken(token: string): EntitlementCitation | undefined {
  // A URL is a reference, not a pointer into this repository's authz code.
  if (token.includes('://')) return undefined;

  let path = token;
  let line: number | undefined;

  const colonIdx = token.lastIndexOf(':');
  if (colonIdx > 0) {
    const tail = token.slice(colonIdx + 1);
    if (LINE_RE.test(tail)) {
      path = token.slice(0, colonIdx);
      line = Number(tail);
    } else {
      // A non-numeric suffix after `:` means this is something else
      // (e.g. `Authz:ScopeCluster`, `cwe:CWE-89`).
      return undefined;
    }
  }

  const segments = path.split('/');
  const filename = segments.pop();
  if (!filename || !FILENAME_RE.test(filename)) return undefined;

  for (const segment of segments) {
    // Reject empty (`a//b`, leading `/`) and relative (`..`) segments — a
    // citation is a repo-relative path, and `..` would let a claim point
    // outside the tree it is meant to be reviewable against.
    if (!segment || segment === '.' || segment === '..') return undefined;
    if (!SEGMENT_RE.test(segment)) return undefined;
  }

  return { file: [...segments, filename].join('/'), line, raw: token };
}

/**
 * True when `changedFile` (a repo-relative path, e.g. from `git diff --name-only`)
 * is the file a citation points at. Citations are often written relative to a
 * subdirectory, so a path suffix match counts.
 */
export function citationMatchesFile(citation: EntitlementCitation, changedFile: string): boolean {
  const changed = changedFile.replaceAll('\\', '/');
  const cited = citation.file.replaceAll('\\', '/');
  if (changed === cited) return true;
  return changed.endsWith(`/${cited}`) || cited.endsWith(`/${changed}`);
}
