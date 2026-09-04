/**
 * GuardLink structure layer — public API.
 *
 * `parseStructure` is the only entry point the rest of the product uses. It
 * returns a per-file object that answers "which code does the comment on this
 * line describe" and "where is the declaration called X", both as `Anchor`s
 * carrying a content hash. Files without a grammar answer with a file-scope
 * anchor over a plain-text hash, so every caller gets an anchor and no caller
 * has to know whether tree-sitter was involved.
 *
 * @flows SourceFile -> #parser via parseStructure -- "File content already read by the parser, parsed again for structure"
 * @comment -- "Takes content, not a path to read: the parser owns file I/O and its path validation; this layer never opens a file"
 */
import { extname } from 'node:path';
import type { Tree, Node } from 'web-tree-sitter';
import type { Anchor, AnchorReason } from '../types/index.js';
import { languageForExtension } from './grammars.js';
import { loadLanguage, parseWith } from './runtime.js';
import { hashNode, hashPlainText } from './hash.js';
import { resolveAnchor, findNamed } from './anchor.js';

export { ANCHOR_HASH_VERSION } from './hash.js';
export { languageForExtension, GRAMMARS, GRAMMARS_UNAVAILABLE, EXTENSION_LANGUAGE } from './grammars.js';
export type { Anchor, AnchorScope, AnchorReason } from '../types/index.js';

export interface FileStructure {
  /** Grammar used, or null when every line resolves to file scope. */
  language: string | null;
  anchorForLine(line: number): Anchor;
  /** External mode: resolve a `@source … symbol:<name>` by declaration name. */
  symbolNamed(name: string): Anchor | null;
  /** Release the syntax tree. Safe to call twice; anchorForLine and symbolNamed throw after this. */
  dispose(): void;
}

function fileOnly(language: string | null, content: string, reason: AnchorReason): FileStructure {
  const lineCount = content.split('\n').length;
  const hash = hashPlainText(content);
  const anchor: Anchor = { scope: 'file', symbol: null, start_line: 1, end_line: lineCount, hash, reason };
  return { language, anchorForLine: () => ({ ...anchor }), symbolNamed: () => null, dispose: () => {} };
}

export async function parseStructure(filePath: string, content: string): Promise<FileStructure> {
  const language = languageForExtension(extname(filePath));
  if (!language) return fileOnly(null, content, 'no-grammar');
  const loaded = await loadLanguage(language);
  if (!loaded.ok) return fileOnly(language, content, loaded.reason);

  let tree: Tree | null = parseWith(loaded.language, content);
  const rootNode: Node = tree.rootNode;
  let root: Node | null = rootNode;
  const lines = content.split('\n');

  // Every file-scope anchor in this file is the same hash of the same root, and
  // a file header commonly carries a dozen claims. Computed at most once per
  // FileStructure, on first demand — a file with no file-scope claim never pays
  // for it at all. Safe to hold the value: the tree is immutable for the life of
  // this object, and callers are refused after dispose().
  let rootHash: string | null = null;
  const fileHash = (): string => (rootHash ??= hashNode(rootNode));

  return {
    language,
    anchorForLine: (line) => {
      if (!root) throw new Error('FileStructure used after dispose()');
      return resolveAnchor(root, language, lines, line, fileHash);
    },
    symbolNamed: (name) => {
      if (!root) throw new Error('FileStructure used after dispose()');
      return findNamed(root, name);
    },
    dispose: () => { if (tree) { tree.delete(); tree = null; } root = null; },
  };
}
