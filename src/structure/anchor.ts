/**
 * GuardLink structure layer — which code a comment on a given line describes.
 *
 * The rules are the spec's §6.2, applied to the uniform shape of a tree-sitter
 * tree rather than to per-language lists of declaration types: a comment's
 * anchor is its next named sibling, stepping over other comments and
 * attributes, descending through wrappers such as `export_statement` and
 * `decorated_definition`. Names come from the `name` field almost every
 * grammar defines, with one level of descent for the declarator shape
 * (`const x = …`, Go `type_spec`).
 *
 * The order of the special cases matters and is the spec's: no grammar, then
 * first-node, then no-sibling, then import-sibling, then YAML, then the
 * general rule. First match wins.
 *
 * @comment -- "Pure functions over an in-memory tree; no I/O, no user input beyond the source text already read by the parser"
 */
import type { Node } from 'web-tree-sitter';
import type { Anchor, AnchorReason } from '../types/index.js';
import { hashNode, isCommentType } from './hash.js';

/** Node types that sit between a comment and the thing it describes. */
const SKIPPABLE = /comment|attribute|hash_bang/;
/** Node types that mark a file header: the claim describes the module. */
const MODULE_HEADER = /import|package_clause|package_declaration|use_declaration|using_directive/;
/** Wrapper fields to descend through to reach the declaration. */
const DESCEND_FIELDS = ['declaration', 'definition'] as const;

function nameOf(node: Node): string | null {
  const own = node.childForFieldName('name');
  if (own) return own.text;
  for (const child of node.namedChildren) {
    if (!child) continue;
    const inner = child.childForFieldName('name');
    if (inner) return inner.text;
  }
  return null;
}

/** Nearest ancestor below the root that has a `name` field. */
function enclosingNamed(node: Node): Node | null {
  let p = node.parent;
  while (p && p.parent) {
    if (p.childForFieldName('name')) return p;
    p = p.parent;
  }
  return null;
}

/** The comment node whose range contains line (1-based), or null. */
function commentAt(root: Node, lines: string[], line: number): Node | null {
  const text = lines[line - 1];
  if (text === undefined) return null;
  const column = Math.max(0, text.search(/\S/));
  let n: Node | null = root.descendantForPosition({ row: line - 1, column });
  while (n && !isCommentType(n.type)) n = n.parent;
  return n;
}

function fileAnchor(root: Node, lineCount: number, reason: AnchorReason): Anchor {
  return { scope: 'file', symbol: null, start_line: 1, end_line: lineCount, hash: hashNode(root), reason };
}

function symbolAnchor(node: Node, symbol: string | null, reason?: AnchorReason): Anchor {
  const a: Anchor = {
    scope: 'symbol', symbol,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
    hash: hashNode(node),
  };
  if (reason) a.reason = reason;
  return a;
}

/** YAML: the first mapping pair at or below `node` that starts after `afterRow`. */
function yamlPair(node: Node, afterRow: number): Node | null {
  if (node.type === 'block_mapping_pair' && node.startPosition.row > afterRow) return node;
  for (const child of node.namedChildren) {
    if (!child) continue;
    const found = yamlPair(child, afterRow);
    if (found) return found;
  }
  return null;
}

export function resolveAnchor(root: Node, language: string, lines: string[], line: number): Anchor {
  const comment = commentAt(root, lines, line);
  if (!comment) return fileAnchor(root, lines.length, 'no-sibling');

  // Rule 2 — first-node: nothing but comments/shebang before it, and not inside a declaration.
  let prev = comment.previousNamedSibling;
  let onlySkippableBefore = true;
  while (prev) {
    if (!SKIPPABLE.test(prev.type)) { onlySkippableBefore = false; break; }
    prev = prev.previousNamedSibling;
  }
  if (onlySkippableBefore && enclosingNamed(comment) === null) return fileAnchor(root, lines.length, 'first-node');

  // Rule 3 — no-sibling: a trailing comment binds to what encloses it.
  let cand = comment.nextNamedSibling;
  while (cand && SKIPPABLE.test(cand.type)) cand = cand.nextNamedSibling;
  if (!cand) {
    const enc = enclosingNamed(comment);
    return enc ? symbolAnchor(enc, nameOf(enc), 'no-sibling') : fileAnchor(root, lines.length, 'no-sibling');
  }

  // Rule 4 — import-sibling.
  if (MODULE_HEADER.test(cand.type)) return fileAnchor(root, lines.length, 'import-sibling');

  // Rule 5 — YAML block.
  if (language === 'yaml') {
    const pair = yamlPair(cand, comment.startPosition.row);
    if (!pair) return fileAnchor(root, lines.length, 'no-sibling');
    const key = pair.childForFieldName('key');
    // tree-sitter-yaml extends the last mapping pair in a block to column 0 of
    // the row after its content (it absorbs the trailing newline) when nothing
    // follows it at the same indentation. That row has no content of the
    // pair's own, so it is not part of the anchor's line range.
    const endRow = pair.endPosition.column === 0 && pair.endPosition.row > pair.startPosition.row
      ? pair.endPosition.row - 1
      : pair.endPosition.row;
    return {
      scope: 'block', symbol: key ? key.text : null,
      start_line: pair.startPosition.row + 1, end_line: endRow + 1,
      hash: hashNode(pair),
    };
  }

  // General rule — descend through wrappers, then name it.
  for (const field of DESCEND_FIELDS) {
    const inner = cand.childForFieldName(field);
    if (inner) { cand = inner; break; }
  }
  const symbol = nameOf(cand) ?? (enclosingNamed(cand) ? nameOf(enclosingNamed(cand)!) : null);
  return symbolAnchor(cand, symbol);
}

/** External mode: the declaration named `name`, searched top-down, first match. */
export function findNamed(root: Node, name: string): Anchor | null {
  const stack: Node[] = [root];
  while (stack.length > 0) {
    const node = stack.shift()!;
    for (const child of node.namedChildren) {
      if (!child || isCommentType(child.type)) continue;
      let target = child;
      for (const field of DESCEND_FIELDS) {
        const inner = target.childForFieldName(field);
        if (inner) { target = inner; break; }
      }
      if (target.childForFieldName('name')?.text === name) return symbolAnchor(target, name);
      stack.push(child);
    }
  }
  return null;
}
