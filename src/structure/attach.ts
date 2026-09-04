/**
 * GuardLink structure layer — put an anchor on every annotation location.
 *
 * Runs once per parse, after locations are normalised to logical root-relative
 * paths and before the model is assembled. `assembleModel` shares each
 * location object by reference, so an anchor set here is the anchor every
 * surface sees. Files are grouped by LOGICAL path: in external mode that is
 * the source the sidecar describes, never the sidecar.
 *
 * @exposes #parser to #path-traversal [low] cwe:CWE-22 -- "Reads the file each annotation's location names, and a .gal @source path is author-supplied text that survives normalisation with ../ intact"
 * @mitigates #parser against #path-traversal using #path-validation -- "Each logical path is resolved against root and skipped unless it is root or lies under root + sep; the file is never opened otherwise, so nothing outside the scanned tree is read"
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "One structure parse per annotated file"
 * @mitigates #parser against #dos using #resource-limits -- "Only files that carry annotations are parsed, once each, and the tree is released immediately"
 * @flows SourceFiles -> #parser via attachAnchors -- "Annotated files re-read for structure"
 * @comment -- "A file that cannot be read or cannot be parsed nulls that file's anchors and warns once; it never fails the parse, because one pathological file must not take down every command in the repository"
 */
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import type { Annotation } from '../types/index.js';
import { parseStructure } from './index.js';

const isGalPath = (p: string): boolean => /\.gal$/i.test(p);

/**
 * One warning per file per process.
 *
 * `parseProject` runs many times in a long-lived process — the MCP server, the
 * TUI, a watch loop — and a file that fails to parse fails on every one of them.
 * Keyed by absolute path so two roots holding the same relative path each get
 * their own warning.
 */
const warnedFiles = new Set<string>();

function warnOnce(key: string, file: string, err: unknown): void {
  if (warnedFiles.has(key)) return;
  warnedFiles.add(key);
  const message = err instanceof Error ? err.message : String(err);
  console.error(`⚠ GuardLink: could not resolve anchors in ${file}: ${message}. Its claims read as unverified.`);
}

export async function attachAnchors(root: string, annotations: Annotation[]): Promise<void> {
  const byFile = new Map<string, Annotation[]>();
  for (const a of annotations) {
    const file = a.location?.file;
    if (!file || isGalPath(file)) continue;
    const list = byFile.get(file);
    if (list) list.push(a); else byFile.set(file, [a]);
  }

  const base = resolve(root);
  for (const [file, anns] of byFile) {
    // Containment. Inline locations are the parser's own root-relative paths, but
    // an external `@source file:../../etc/hostname` is author-supplied text that
    // normalisation leaves alone — so the join is checked, not trusted. Outside
    // root is not an error to report here: the claim simply has no anchor, and
    // `validate` already has the diagnostic for an off-convention sidecar.
    const abs = resolve(root, file);
    if (abs !== base && !abs.startsWith(base + sep)) {
      for (const a of anns) a.location.anchor = null;
      continue;
    }

    let content: string;
    try {
      content = await readFile(abs, 'utf-8');
    } catch {
      for (const a of anns) a.location.anchor = null;
      continue;
    }

    // A structure failure is contained to its file. `parseStructure` can throw
    // on a pathological tree or a broken grammar load, and before this every
    // such file rejected parseProject — which meant validate, ci, status, the
    // MCP server and the TUI all failed on that repository rather than on that
    // file. dispose() belongs to the success path: it must not run when
    // parseStructure threw before returning a structure to dispose.
    try {
      const structure = await parseStructure(file, content);
      try {
        for (const a of anns) {
          const named = a.location.parent_symbol ? structure.symbolNamed(a.location.parent_symbol) : null;
          a.location.anchor = named ?? structure.anchorForLine(a.location.line);
        }
      } finally {
        structure.dispose();
      }
    } catch (err) {
      for (const a of anns) a.location.anchor = null;
      warnOnce(abs, file, err);
    }
  }
}
