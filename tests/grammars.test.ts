/**
 * Every grammar the table promises must exist on disk, load into the pinned
 * runtime, and parse an empty document. An ABI mismatch between a grammar and
 * web-tree-sitter fails here, in CI, rather than in a user's terminal as a
 * silent fall-back to file scope.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync } from 'node:fs';
import { Parser, Language } from 'web-tree-sitter';
import { GRAMMARS, grammarPath, languageForExtension } from '../src/structure/grammars.js';

describe('grammar set', () => {
  beforeAll(async () => { await Parser.init(); });

  for (const language of Object.keys(GRAMMARS)) {
    it(`${language}: exists, loads, parses`, async () => {
      const path = grammarPath(language);
      expect(existsSync(path), `${path} missing — run npm run build:grammars`).toBe(true);
      const lang = await Language.load(path);
      const parser = new Parser();
      parser.setLanguage(lang);
      const tree = parser.parse('');
      expect(tree).not.toBeNull();
      expect(tree!.rootNode.hasError).toBe(false);
      tree!.delete();
    });
  }

  it('maps every DEFAULT_INCLUDE extension', async () => {
    const { DEFAULT_INCLUDE } = await import('../src/parser/parse-project.js');
    const exts = DEFAULT_INCLUDE
      .map(g => g.replace('**/*', ''))
      .filter(e => !/\[/.test(e)); // skip the case-insensitive .gal pattern
    for (const ext of exts) {
      // null is a valid answer (file-scope by design); undefined is a gap in the table.
      expect(languageForExtension(ext), `no mapping for ${ext}`).not.toBeUndefined();
    }
  });
});
