/**
 * GuardLink structure layer — put an anchor on every annotation location.
 *
 * Runs once per parse, after locations are normalised to logical root-relative
 * paths and before the model is assembled. `assembleModel` shares each
 * location object by reference, so an anchor set here is the anchor every
 * surface sees. Files are grouped by LOGICAL path: in external mode that is
 * the source the sidecar describes, never the sidecar.
 *
 * @exposes #parser to #path-traversal [low] cwe:CWE-22 -- "Reads the file each annotation's location names, joined under root"
 * @mitigates #parser against #path-traversal using #path-validation -- "Paths are the parser's own normalised, root-relative locations; joined to root and skipped when unreadable; nothing outside the scanned set is opened"
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "One structure parse per annotated file"
 * @mitigates #parser against #dos using #resource-limits -- "Only files that carry annotations are parsed, once each, and the tree is released immediately"
 * @flows SourceFiles -> #parser via attachAnchors -- "Annotated files re-read for structure"
 */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Annotation } from '../types/index.js';
import { parseStructure } from './index.js';

const isGalPath = (p: string): boolean => /\.gal$/i.test(p);

export async function attachAnchors(root: string, annotations: Annotation[]): Promise<void> {
  const byFile = new Map<string, Annotation[]>();
  for (const a of annotations) {
    const file = a.location?.file;
    if (!file || isGalPath(file)) continue;
    const list = byFile.get(file);
    if (list) list.push(a); else byFile.set(file, [a]);
  }

  for (const [file, anns] of byFile) {
    let content: string;
    try {
      content = await readFile(resolve(root, file), 'utf-8');
    } catch {
      for (const a of anns) a.location.anchor = null;
      continue;
    }
    const structure = await parseStructure(file, content);
    try {
      for (const a of anns) {
        const named = a.location.parent_symbol ? structure.symbolNamed(a.location.parent_symbol) : null;
        a.location.anchor = named ?? structure.anchorForLine(a.location.line);
      }
    } finally {
      structure.dispose();
    }
  }
}
