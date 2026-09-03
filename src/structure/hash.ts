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

/**
 * Every grammar names its comment nodes with the word in them: comment,
 * line_comment, block_comment, documentation_comment. Haskell is the exception —
 * tree-sitter-haskell calls its doc comments `haddock`, with no `comment` in the
 * type — so it is named here rather than left to silently move the hash whenever
 * a Haddock block is edited.
 */
export function isCommentType(type: string): boolean {
  return type.includes('comment') || type === 'haddock';
}

/**
 * Non-comment leaf tokens of a subtree, in document order. Empty and
 * whitespace-only leaves are dropped.
 *
 * Walked with an explicit tree-sitter cursor rather than by recursion. Depth
 * here is source depth, not file size: a single deeply nested expression — a
 * generated parser table, a long chain of parenthesised or ternary
 * subexpressions, a minified bundle — is thousands of frames deep, and a
 * `RangeError: Maximum call stack size exceeded` raised here does not stay
 * local. It propagates out of `parseStructure`, out of `parseProject`, and
 * every command that parses the project fails on that repository. The cursor
 * keeps the walk O(1) in stack.
 *
 * The traversal is the same one the recursion performed: pre-order, all
 * children (named and anonymous), comment subtrees skipped without descending.
 * Token selection and order are unchanged, so the emitted hash is unchanged —
 * see ANCHOR_HASH_VERSION.
 */
export function leafTokens(node: Node, out: string[] = []): string[] {
  if (isCommentType(node.type)) return out;
  const cursor = node.walk();
  try {
    // `descending` distinguishes arriving at a node from returning to it: a node
    // reached by gotoParent has already had its children emitted.
    let descending = true;
    for (;;) {
      if (descending) {
        if (isCommentType(cursor.nodeType)) {
          // Skip the whole comment subtree — do not descend into it.
        } else if (cursor.gotoFirstChild()) {
          continue;
        } else {
          const text = cursor.nodeText;
          if (text.trim() !== '') out.push(text);
        }
      }
      if (cursor.gotoNextSibling()) { descending = true; continue; }
      // gotoParent returns false at the node the cursor was built from: done.
      if (!cursor.gotoParent()) break;
      descending = false;
    }
  } finally {
    cursor.delete();
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
