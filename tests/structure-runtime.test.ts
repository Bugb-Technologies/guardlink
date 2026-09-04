import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadLanguage, parseWith, resetRuntimeForTests } from '../src/structure/runtime.js';
import { grammarPath } from '../src/structure/grammars.js';

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

  it('no-grammar is silent for a language outside the table', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    const r = await loadLanguage('swift');
    expect(r).toEqual({ ok: false, reason: 'no-grammar' });
    expect(warn).not.toHaveBeenCalled();
  });

  it('reports grammar-failed once, with one warning, when the file is corrupt', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'guardlink-test-'));
    writeFileSync(join(tmpDir, 'typescript.wasm'), Buffer.alloc(16)); // 16 bytes of garbage
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});

    resetRuntimeForTests({ grammarsDir: tmpDir });
    const r1 = await loadLanguage('typescript');
    const r2 = await loadLanguage('typescript');

    expect(r1).toEqual({ ok: false, reason: 'grammar-failed' });
    expect(r2).toEqual(r1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toContain('typescript');
  });

  it('warns once when a language in GRAMMARS is missing from disk', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'guardlink-test-'));
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});

    resetRuntimeForTests({ grammarsDir: tmpDir });
    const r1 = await loadLanguage('typescript');
    const r2 = await loadLanguage('typescript');

    expect(r1).toEqual({ ok: false, reason: 'grammar-failed' });
    expect(r2).toEqual(r1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toContain('typescript');
  });

  it('loads a hand-placed WASM for a language outside GRAMMARS', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'guardlink-test-'));
    copyFileSync(grammarPath('typescript'), join(tmpDir, 'swift.wasm'));

    resetRuntimeForTests({ grammarsDir: tmpDir });
    const r = await loadLanguage('swift');

    expect(r.ok).toBe(true);
  });

  it('no-grammar, silently, when a language outside GRAMMARS has no hand-placed file', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'guardlink-test-'));
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});

    resetRuntimeForTests({ grammarsDir: tmpDir });
    const r = await loadLanguage('swift');

    expect(r).toEqual({ ok: false, reason: 'no-grammar' });
    expect(warn).not.toHaveBeenCalled();
  });
});
