/**
 * GuardLink structure layer — a hash of what a node says, not how it is laid out.
 *
 * The digest covers the leaf tokens of a subtree in document order, with every
 * comment node skipped. Whitespace between tokens is never a token, so
 * reformatting is invisible; a comment is skipped wholesale, so editing an
 * annotation above or inside a body is invisible; a renamed identifier or a
 * removed statement changes the token sequence, so it moves the hash.
 *
 * Tokens are joined with a control character rather than concatenated, so the
 * sequences (ab, c) and (a, bc) cannot collide — the same reasoning as
 * annotation-hash.ts.
 *
 * @comment -- "Pure functions over an in-memory syntax tree or a string; no I/O"
 */
import { createHash } from 'node:crypto';
import type { Node } from 'web-tree-sitter';

/** Bump when token selection or the separator changes. Part of every emitted hash. */
export const ANCHOR_HASH_VERSION = 1;

const SEP = String.fromCharCode(1);

/** Every grammar names its comment nodes with the word in them: comment, line_comment, block_comment, documentation_comment. */
export function isCommentType(type: string): boolean {
  return type.includes('comment');
}

/** Non-comment leaf tokens of a subtree, in order. Empty and whitespace-only leaves are dropped. */
export function leafTokens(node: Node, out: string[] = []): string[] {
  if (isCommentType(node.type)) return out;
  if (node.childCount === 0) {
    const text = node.text;
    if (text.trim() !== '') out.push(text);
    return out;
  }
  for (const child of node.children) {
    if (child) leafTokens(child, out);
  }
  return out;
}

export function hashTokens(tokens: string[]): string {
  return `sha256-v${ANCHOR_HASH_VERSION}:` + createHash('sha256').update(tokens.join(SEP)).digest('hex');
}

export function hashNode(node: Node): string {
  return hashTokens(leafTokens(node));
}

/**
 * For files with no grammar: whitespace-separated tokens. Comments are NOT
 * skipped here, because without a grammar there is no way to know what one is.
 * Documented in the spec as the file-scope limitation for markup and SQL.
 */
export function hashPlainText(content: string): string {
  return hashTokens(content.split(/\s+/).filter(Boolean));
}
