/**
 * GuardLink — The `.gal` path convention (GL-501).
 *
 * In external mode, annotations for `src/auth/login.ts` live in
 * `.guardlink/annotations/src/auth/login.ts.gal` — the source path mirrored under
 * `annotations/`, with `.gal` appended.
 *
 * That sentence previously existed in exactly one place: inside an LLM prompt
 * string, phrased as an example (`agents/prompts.ts`). There was no constant, no
 * resolver and no validator, and `DEFAULT_INCLUDE` globs `**\/*.gal` anywhere in
 * the tree, so any placement parsed and nothing caught drift. **The layout of the
 * primary annotation store was enforced by a language model following an
 * example.** This module is that layout, as code; the prompt is now generated
 * from it.
 *
 * Appending `.gal` rather than replacing the extension is deliberate: it keeps
 * the mapping total and reversible. `login.ts` and `login.js` in one directory
 * map to distinct sidecars, which a replace-the-extension scheme would collide.
 *
 * @flows SourceFile -> #parser via resolveGalPath -- "Source path mapped to its annotation sidecar"
 * @comment -- "Pure path arithmetic; no I/O. The inverse is exact, which is what makes migration reversible."
 */

import { isAbsolute, join, relative, resolve } from 'node:path';

/** Where externalised annotations live, relative to the project root. */
export const ANNOTATIONS_DIR = '.guardlink/annotations';

/** One-line statement of the convention, for prompts, warnings and docs. */
export const GAL_CONVENTION = `${ANNOTATIONS_DIR}/<source path>.gal — the source path mirrored, with .gal appended`;

const norm = (p: string): string => p.replaceAll('\\', '/').replace(/^\.\//, '');

/**
 * The repo-relative `.gal` path for a source file.
 *
 * `sourceFile` may be absolute or repo-relative; the result is always
 * repo-relative and forward-slashed, so it is comparable across platforms.
 */
export function galPathFor(sourceFile: string, root?: string): string {
  let rel = norm(sourceFile);
  if (isAbsolute(sourceFile) && root) rel = norm(relative(resolve(root), sourceFile));
  return `${ANNOTATIONS_DIR}/${rel}.gal`;
}

/** The absolute `.gal` path for a source file in a given project. */
export function resolveGalPath(root: string, sourceFile: string): string {
  return join(root, galPathFor(sourceFile, root));
}

/**
 * The source file a conventional `.gal` path annotates, or null if the path is
 * not on-convention.
 *
 * Exact inverse of `galPathFor`, which is what lets migration round-trip.
 */
export function sourceFileForGal(galPath: string): string | null {
  const rel = norm(galPath);
  const prefix = `${ANNOTATIONS_DIR}/`;
  if (!rel.startsWith(prefix) || !rel.endsWith('.gal')) return null;
  const source = rel.slice(prefix.length, -'.gal'.length);
  return source.length > 0 ? source : null;
}

/** Whether a `.gal` file sits where the convention says it should. */
export function isConventionalGalPath(galPath: string): boolean {
  return sourceFileForGal(galPath) !== null;
}

/**
 * Human-readable guidance for a `.gal` that is off-convention.
 *
 * Names the expected path rather than only complaining, because the whole point
 * of codifying the convention is that nobody should have to infer it.
 */
export function offConventionMessage(galPath: string, declaredSources: string[]): string {
  const rel = norm(galPath);
  if (declaredSources.length === 1) {
    return `\`${rel}\` is not at the conventional path. Annotations for `
      + `\`${declaredSources[0]}\` belong in \`${galPathFor(declaredSources[0])}\`. `
      + `It is still parsed — this is a convention, not a requirement.`;
  }
  if (declaredSources.length > 1) {
    return `\`${rel}\` is not at the conventional path and carries @source blocks for `
      + `${declaredSources.length} files. The convention is one sidecar per source file: `
      + `${GAL_CONVENTION}. It is still parsed — this is a convention, not a requirement.`;
  }
  return `\`${rel}\` is not at the conventional path (${GAL_CONVENTION}). `
    + `It is still parsed — this is a convention, not a requirement.`;
}
