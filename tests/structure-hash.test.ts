/**
 * The anchor hash must move when code moves and stay still when only its
 * presentation moves. Each case below is one edit a developer actually makes.
 */
import { describe, it, expect } from 'vitest';
import { loadLanguage, parseWith } from '../src/structure/runtime.js';
import { parseStructure } from '../src/structure/index.js';
import { hashNode, hashPlainText, isCommentType, ANCHOR_HASH_VERSION } from '../src/structure/hash.js';

async function hashTs(source: string): Promise<string> {
  const r = await loadLanguage('typescript');
  if (!r.ok) throw new Error('typescript grammar missing');
  const tree = parseWith(r.language, source);
  const h = hashNode(tree.rootNode);
  tree.delete();
  return h;
}

const BASE = `export function resolveRoot(p: string) {
  assertInside(root, p);
  return resolve(p);
}
`;

describe('anchor hash', () => {
  it('carries the version prefix', async () => {
    expect(await hashTs(BASE)).toMatch(new RegExp(`^sha256-v${ANCHOR_HASH_VERSION}:[0-9a-f]{64}$`));
  });

  it('ignores reformatting, reindenting and CRLF', async () => {
    const base = await hashTs(BASE);
    expect(await hashTs('export function resolveRoot(p: string) { assertInside(root, p); return resolve(p); }')).toBe(base);
    expect(await hashTs(BASE.replace(/\n/g, '\r\n'))).toBe(base);
    expect(await hashTs(BASE.replace(/^ {2}/gm, '\t\t'))).toBe(base);
  });

  it('ignores comments, including annotation lines, inside and above the body', async () => {
    const base = await hashTs(BASE);
    const commented = `/**
 * @mitigates #mcp against #path-traversal using #path-validation -- "resolve then prefix check"
 */
export function resolveRoot(p: string) {
  // keep the check
  assertInside(root, p);
  return resolve(p); /* trailing */
}
`;
    expect(await hashTs(commented)).toBe(base);
  });

  it('changes when a token changes', async () => {
    const base = await hashTs(BASE);
    expect(await hashTs(BASE.replace('assertInside(root, p);\n', ''))).not.toBe(base);
    expect(await hashTs(BASE.replace('resolveRoot', 'resolveRoot2'))).not.toBe(base);
    expect(await hashTs(BASE.replace('resolve(p)', 'resolve(p, root)'))).not.toBe(base);
  });

  it('treats Haskell haddock nodes as comments', () => {
    // tree-sitter-haskell is the one grammar whose doc-comment node has no
    // `comment` in its type, so it needs naming rather than matching.
    expect(isCommentType('haddock')).toBe(true);
    expect(isCommentType('line_comment')).toBe(true);
    expect(isCommentType('identifier')).toBe(false);
  });

  it('hashes a pathologically deep expression without overflowing the stack', async () => {
    // Depth here is source depth, not file size. Recursing once per node threw
    // RangeError out of parseStructure, which rejected parseProject and failed
    // every command on the repository — not just this file.
    const depth = 30000;
    const src = `// @comment -- "deep"\nconst x = ${'('.repeat(depth)}1${')'.repeat(depth)};\n`;
    const structure = await parseStructure('/x/deep.ts', src);
    try {
      const anchor = structure.anchorForLine(1);
      expect(anchor.hash).toMatch(new RegExp(`^sha256-v${ANCHOR_HASH_VERSION}:[0-9a-f]{64}$`));
    } finally {
      structure.dispose();
    }
  }, 60000);

  it('gives every file-scope claim in one file the same memoised hash', async () => {
    // `alpha` resolves by the first-node rule, `beta` by the import-sibling
    // rule; both are file scope over the same root, so both must read the same
    // hash — which is what makes computing it once per file sound.
    const src = `// alpha
import a from 'a';

export const x = 1;

// beta
import b from 'b';
`;
    const structure = await parseStructure('/x/headers.ts', src);
    try {
      const first = structure.anchorForLine(1);
      const second = structure.anchorForLine(6);
      expect(first.scope).toBe('file');
      expect(second.scope).toBe('file');
      expect(second.hash).toBe(first.hash);
    } finally {
      structure.dispose();
    }
  });

  it('hashes plain text by whitespace-separated tokens', () => {
    expect(hashPlainText('a  b\n\tc')).toBe(hashPlainText('a b c'));
    expect(hashPlainText('a b c')).not.toBe(hashPlainText('a b d'));
    expect(hashPlainText('x')).toMatch(/^sha256-v1:/);
  });
});
