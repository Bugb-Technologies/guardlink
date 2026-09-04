/**
 * GuardLink structure layer — the one place that talks to web-tree-sitter.
 *
 * The runtime initialises once per process and each grammar loads once, both
 * lazily: a repository with only TypeScript never pays for the Go grammar.
 * A language outside both `GRAMMARS` and `GRAMMARS_UNAVAILABLE` is `no-grammar`
 * and silent — that is the designed fallback. A language in `GRAMMARS` with no
 * file on disk is `grammar-failed` and warned once per language — that is a
 * packaging defect. A language in `GRAMMARS_UNAVAILABLE` (Swift, Kotlin, Dart)
 * has no pinned WASM to fetch, but a hand-placed file at `grammars/<language>.wasm`
 * is still attempted — silent `no-grammar` when absent, `grammar-failed` and
 * warned once if present but unloadable. A file that exists but fails to load is
 * always `grammar-failed` and warned once, because that is a runtime packaging
 * defect, not a fallback.
 *
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "Grammar WASM is loaded into memory per language; a pathological source file costs one parse"
 * @mitigates #parser against #dos using #resource-limits -- "One runtime init and one load per language per process; trees are parsed on demand and deleted by callers"
 * @flows GrammarFile -> #parser via Language.load -- "Bundled WASM read from the package's grammars/ directory"
 * @comment -- "Paths come only from grammarPath(language) over the package's own grammars/ directory; no caller-supplied path reaches Language.load"
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Parser, Language } from 'web-tree-sitter';
import type { Tree } from 'web-tree-sitter';
import { GRAMMARS, GRAMMARS_UNAVAILABLE, GRAMMARS_DIR } from './grammars.js';

export type LoadResult =
  | { ok: true; language: Language }
  | { ok: false; reason: 'no-grammar' | 'grammar-failed' };

let initPromise: Promise<void> | null = null;
const loads = new Map<string, Promise<LoadResult>>();
const warned = new Set<string>();
let grammarsDirOverride: string | null = null;

function resolveGrammarPath(language: string): string {
  return join(grammarsDirOverride ?? GRAMMARS_DIR, `${language}.wasm`);
}

function init(): Promise<void> {
  if (!initPromise) initPromise = Parser.init();
  return initPromise;
}

function warnOnce(language: string, message: string): void {
  if (warned.has(language)) return;
  warned.add(language);
  console.error(`⚠ GuardLink: ${message}`);
}

/** Load a grammar by language id. Cached for the life of the process. */
export function loadLanguage(language: string): Promise<LoadResult> {
  let pending = loads.get(language);
  if (!pending) {
    pending = (async (): Promise<LoadResult> => {
      const path = resolveGrammarPath(language);
      if (language in GRAMMARS) {
        if (!existsSync(path)) {
          warnOnce(language, `grammar file for ${language} is missing at ${path}; run npm run build:grammars. Falling back to file-scope anchors.`);
          return { ok: false, reason: 'grammar-failed' };
        }
      } else if ((GRAMMARS_UNAVAILABLE as readonly string[]).includes(language)) {
        // No pinned WASM to fetch, but a hand-placed file makes this language
        // symbol-scoped (spec §6.4). Absent, it is the designed silent fallback.
        if (!existsSync(path)) return { ok: false, reason: 'no-grammar' };
      } else {
        return { ok: false, reason: 'no-grammar' };
      }
      try {
        await init();
        return { ok: true, language: await Language.load(path) };
      } catch (err) {
        warnOnce(language, `grammar for ${language} failed to load from ${path}: ${(err as Error).message}. Falling back to file-scope anchors.`);
        return { ok: false, reason: 'grammar-failed' };
      }
    })();
    loads.set(language, pending);
  }
  return pending;
}

/** Parse source with an already-loaded grammar. The caller owns the tree and must `delete()` it. */
export function parseWith(language: Language, source: string): Tree {
  const parser = new Parser();
  parser.setLanguage(language);
  const tree = parser.parse(source);
  parser.delete();
  if (!tree) throw new Error('web-tree-sitter returned no tree');
  return tree;
}

/** Drop caches so a test can observe first-load behaviour again. */
export function resetRuntimeForTests(options?: { grammarsDir?: string }): void {
  loads.clear();
  warned.clear();
  grammarsDirOverride = options?.grammarsDir ?? null;
}
