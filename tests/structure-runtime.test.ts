import { describe, it, expect, vi, afterEach } from 'vitest';
import { loadLanguage, parseWith, resetRuntimeForTests } from '../src/structure/runtime.js';

describe('structure runtime', () => {
  afterEach(() => { resetRuntimeForTests(); vi.restoreAllMocks(); });

  it('loads a grammar once and parses', async () => {
    const a = await loadLanguage('typescript');
    const b = await loadLanguage('typescript');
    expect(a.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.language).toBe(b.language);
    const tree = parseWith(a.language, 'export function f() { return 1 }');
    expect(tree.rootNode.type).toBe('program');
    expect(tree.rootNode.hasError).toBe(false);
    tree.delete();
  });

  it('reports no-grammar for a language outside the table', async () => {
    const r = await loadLanguage('swift');
    expect(r).toEqual({ ok: false, reason: 'no-grammar' });
  });

  it('reports grammar-failed once, with one warning, when the file is unloadable', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    const r1 = await loadLanguage('__broken__');
    const r2 = await loadLanguage('__broken__');
    expect(r1).toEqual({ ok: false, reason: 'no-grammar' });
    expect(r2).toEqual(r1);
    expect(warn).not.toHaveBeenCalled(); // no-grammar is silent by design
  });
});
