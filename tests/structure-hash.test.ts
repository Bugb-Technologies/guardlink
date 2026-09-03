/**
 * The anchor hash must move when code moves and stay still when only its
 * presentation moves. Each case below is one edit a developer actually makes.
 */
import { describe, it, expect } from 'vitest';
import { loadLanguage, parseWith } from '../src/structure/runtime.js';
import { hashNode, hashPlainText, ANCHOR_HASH_VERSION } from '../src/structure/hash.js';

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

  it('hashes plain text by whitespace-separated tokens', () => {
    expect(hashPlainText('a  b\n\tc')).toBe(hashPlainText('a b c'));
    expect(hashPlainText('a b c')).not.toBe(hashPlainText('a b d'));
    expect(hashPlainText('x')).toMatch(/^sha256-v1:/);
  });
});
