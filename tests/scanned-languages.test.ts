/**
 * The languages §2.9 claims to support, and whether a file in one is ever opened.
 *
 * `stripCommentPrefix` recognises `//`, `#`, `--`, `%`, `;`, `REM`, `'`,
 * `/* *\/`, `(* *)`, `{- -}` and `<!-- -->`. SPEC §2.9 tabulates the languages
 * that write them. The scan globs listed the extensions of six of them.
 *
 * So the marker was stripped correctly and the file was never handed to the
 * stripper. An annotation written into a `.php`, `.pyi`, `.kts`, `.erl`, `.clj`
 * or `.vb` file reached no threat model and produced **no diagnostic of any
 * kind** — not `uncommented-annotation` (the line is a comment), not
 * `unrecognised-comment-form` (the marker parses); the file simply was not in
 * the glob. Measured before this fix: an `@exposes` written in the language's
 * own comment syntax was read in 6 of 43 extensions.
 *
 * That is the silent loss §2.12 exists to prevent, arriving one layer earlier
 * than the diagnostics can see. It is also what made `bravos annotate`
 * unusable on a PHP or Kotlin repository: the agent's analysis was sound, the
 * annotation landed in the file, and the model stayed empty.
 *
 * Two things have to hold at once and both are tested here:
 *
 *   1. Every language §2.9 names is scanned, and an annotation written in its
 *      own comment syntax reaches the model.
 *   2. Nothing that is not a comment became an annotation, and no file the
 *      scan set has no business opening was added to reach (1). The negative
 *      cases are as load-bearing as the positive ones — widening the glob is
 *      only safe because what counts as a *comment* did not move.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { SCANNED_EXTENSIONS } from '../src/parser/languages.js';
import { commentStyleForExt } from '../src/parser/comment-strip.js';
import { languageForExtension } from '../src/structure/grammars.js';

const EXPOSES = '@exposes #api to #sqli [high] cwe:CWE-89 -- "query built by concatenation"';

const DEFINITIONS = [
  '// @asset Probe.API (#api) -- "front door"',
  '// @threat SQL_Injection (#sqli) [high] -- "untrusted input reaches the query"',
  '// @control Prepared_Statements (#prepared) -- "placeholders only"',
  '',
].join('\n');

/** `EXPOSES` written as a comment in the language that `marker` belongs to. */
function asComment(marker: string, body: string): string {
  switch (marker) {
    case '<!--': return `<!-- ${body} -->`;
    case '/*': return `/* ${body} */`;
    case '(*': return `(* ${body} *)`;
    case '{-': return `{- ${body} -}`;
    case 'REM': return `REM ${body}`;
    default: return `${marker} ${body}`;
  }
}

/** A repo carrying one annotated file per entry of `files`. */
function buildRepo(files: ReadonlyArray<[name: string, content: string]>): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-langs-'));
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  for (const [name, content] of files) writeFileSync(join(root, name), content);
  return root;
}

/**
 * SPEC §2.9's table, transcribed. This is the test's source of truth on
 * purpose: asserting the scan set against `COMMENT_STYLE_BY_EXT` would only
 * prove the registry equals itself, and would have been green throughout the
 * bug. Each row is `[extension, marker, the language that writes it]`.
 */
const SPEC_LANGUAGES: ReadonlyArray<[ext: string, marker: string, language: string]> = [
  // §2.9 `//`
  ['.c', '//', 'C'], ['.h', '//', 'C header'],
  ['.cpp', '//', 'C++'], ['.cc', '//', 'C++'], ['.cxx', '//', 'C++'],
  ['.hpp', '//', 'C++ header'], ['.hh', '//', 'C++ header'],
  ['.cs', '//', 'C#'],
  ['.java', '//', 'Java'],
  ['.js', '//', 'JavaScript'], ['.jsx', '//', 'JSX'],
  ['.mjs', '//', 'ES module'], ['.cjs', '//', 'CommonJS module'],
  ['.ts', '//', 'TypeScript'], ['.tsx', '//', 'TSX'],
  ['.mts', '//', 'TypeScript ES module'], ['.cts', '//', 'TypeScript CommonJS'],
  ['.go', '//', 'Go'], ['.rs', '//', 'Rust'], ['.swift', '//', 'Swift'],
  ['.kt', '//', 'Kotlin'], ['.kts', '//', 'Kotlin script'],
  ['.scala', '//', 'Scala'], ['.dart', '//', 'Dart'],
  ['.php', '//', 'PHP'],
  ['.m', '//', 'Objective-C'], ['.mm', '//', 'Objective-C++'],
  // §2.9 `#`
  ['.py', '#', 'Python'], ['.pyi', '#', 'Python stub'],
  ['.rb', '#', 'Ruby'],
  ['.sh', '#', 'Shell'], ['.bash', '#', 'Bash'],
  ['.pl', '#', 'Perl'], ['.pm', '#', 'Perl module'],
  ['.yaml', '#', 'YAML'], ['.yml', '#', 'YAML'],
  ['.tf', '#', 'Terraform'], ['.hcl', '#', 'HCL'],
  ['.r', '#', 'R'],
  ['.ex', '#', 'Elixir'], ['.exs', '#', 'Elixir script'],
  ['.nim', '#', 'Nim'],
  // §2.9 `--`
  ['.hs', '--', 'Haskell'], ['.lua', '--', 'Lua'], ['.sql', '--', 'SQL'],
  ['.adb', '--', 'Ada body'], ['.ads', '--', 'Ada spec'],
  ['.vhd', '--', 'VHDL'], ['.vhdl', '--', 'VHDL'],
  // §2.9 `/* */`
  ['.css', '/*', 'CSS'],
  // §2.9 `(* *)`
  ['.ml', '(*', 'OCaml'], ['.mli', '(*', 'OCaml interface'],
  ['.pas', '(*', 'Pascal'], ['.pp', '(*', 'Pascal'],
  // §2.9 `%`
  ['.tex', '%', 'LaTeX'], ['.erl', '%', 'Erlang'], ['.hrl', '%', 'Erlang header'],
  // §2.9 `;`
  ['.lisp', ';', 'Lisp'], ['.cl', ';', 'Common Lisp'],
  ['.clj', ';', 'Clojure'], ['.cljs', ';', 'ClojureScript'], ['.cljc', ';', 'Clojure common'],
  ['.asm', ';', 'Assembly'], ['.s', ';', 'Assembly'],
  ['.ini', ';', 'INI'],
  // §2.9 `<!-- -->`
  ['.html', '<!--', 'HTML'], ['.htm', '<!--', 'HTML'],
  ['.xml', '<!--', 'XML'], ['.svg', '<!--', 'SVG'],
  // §2.9 `REM`
  ['.bat', 'REM', 'Batch'], ['.cmd', 'REM', 'Batch'],
  // §2.9 `'`
  ['.vb', "'", 'VB.NET'], ['.bas', "'", 'VBA'],
];

describe('SPEC §2.9 — every language it names is a language the scan opens', () => {
  const roots: string[] = [];
  afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

  /**
   * The regression, stated as one repo rather than 70 test cases.
   *
   * Before the fix this listed 37 unread extensions, `.php` `.pyi` `.kts`
   * among them — an annotation written into the file, in the file's own comment
   * syntax, that the model never saw and no diagnostic named.
   */
  it('reads an @exposes written in every language §2.9 names', async () => {
    const files = SPEC_LANGUAGES.map(([ext, marker]): [string, string] => [
      `probe${ext}`,
      `${asComment(marker, EXPOSES)}\n`,
    ]);
    const root = buildRepo(files);
    roots.push(root);

    const { model } = await parseProject({ root, anchors: false });
    const read = new Set(model.exposures.map(e => e.location.file));
    const unread = SPEC_LANGUAGES
      .filter(([ext]) => !read.has(`probe${ext}`))
      .map(([ext, , language]) => `${ext} (${language})`);

    expect(unread, `annotation written but never read in ${unread.length} language(s)`).toEqual([]);
    expect(read.size).toBe(SPEC_LANGUAGES.length);
  });

  it('scans every extension §2.9 names, and no extension it does not', () => {
    // Both directions. The forward one is the bug this test exists for. The
    // reverse one is what keeps the spec honest afterwards: an extension added
    // to the registry with no row in §2.9 is a language GuardLink reads and
    // does not admit to reading, which is the same class of surprise as one it
    // admits to and does not read.
    const missing = SPEC_LANGUAGES
      .filter(([ext]) => !SCANNED_EXTENSIONS.includes(ext))
      .map(([ext]) => ext);
    expect(missing, `§2.9 names these, the scan set omits them: ${missing.join(' ')}`).toEqual([]);

    const specExts = SPEC_LANGUAGES.map(([ext]) => ext);
    const undeclared = SCANNED_EXTENSIONS.filter(ext => !specExts.includes(ext));
    expect(undeclared, `scanned but absent from §2.9: ${undeclared.join(' ')}`).toEqual([]);
  });

  it('prefers the marker §2.9 assigns the language when writing one', () => {
    // The write side (`guardlink review`, `guardlink migrate`) falls back to
    // this when there is no neighbouring comment to copy the style from, so a
    // wrong answer here edits the user's source into something that does not
    // compile. `.m` is the known exception, resolved to Objective-C.
    for (const [ext, marker, language] of SPEC_LANGUAGES) {
      expect(commentStyleForExt(ext), `${ext} (${language})`).toBe(marker);
    }
  });

  for (const ext of ['.php', '.pyi', '.cs', '.kt', '.kts', '.h', '.tf', '.sql'] as const) {
    it(`scans ${ext} — named in the release-readiness measurement`, () => {
      expect(SCANNED_EXTENSIONS, `${ext} missing from the scan set`).toContain(ext);
    });
  }

  it('gives every scanned extension a structure-layer answer', () => {
    // `null` is a valid answer — file scope, with reason `no-grammar`.
    // `undefined` means the extension reached the scan set and never reached
    // this table, and the anchor layer then has no answer to fall back to.
    for (const ext of SCANNED_EXTENSIONS) {
      expect(languageForExtension(ext), `no structure mapping for ${ext}`).not.toBeUndefined();
    }
  });
});

describe('widening the glob did not widen what counts as an annotation', () => {
  const roots: string[] = [];
  afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

  it('does not read an @exposes that is not in a comment, but names it', async () => {
    // The same verb, in the same newly-scanned file, on a line with no marker.
    const root = buildRepo([['bare.php', `<?php\n${EXPOSES}\n`]]);
    roots.push(root);

    const { model, diagnostics } = await parseProject({ root, anchors: false });
    expect(model.exposures).toEqual([]);
    // Named rather than dropped — §2.9.3's diagnostic now reaches PHP too,
    // which it could not do while the file was never opened.
    expect(diagnostics.some(d => d.code === 'uncommented-annotation')).toBe(true);
  });

  it('says nothing about a verb quoted inside a string', async () => {
    // §2.9.3's diagnostic is scoped to lines that BEGIN with a known verb, so
    // prose and string literals that quote the syntax stay silent. Widening
    // the scan set brought PHP, LaTeX and INI files into range of that rule;
    // it must not have brought them into range of a warning per mention.
    const root = buildRepo([['quoted.php', `<?php\n$doc = "${EXPOSES}";\n`]]);
    roots.push(root);

    const { model, diagnostics } = await parseProject({ root, anchors: false });
    expect(model.exposures).toEqual([]);
    expect(diagnostics).toEqual([]);
  });

  it('does not read an @exposes from a Python docstring', async () => {
    // SPEC §2.9.3: a docstring is a string expression, not a comment. The
    // annotation is not parsed — but it is reported, which is the difference
    // between a narrow parser and a silent one.
    const root = buildRepo([[
      'doc.py',
      `def login(email):\n    """Log in.\n\n    ${EXPOSES}\n    """\n    return email\n`,
    ]]);
    roots.push(root);

    const { model, diagnostics } = await parseProject({ root, anchors: false });
    expect(model.exposures).toEqual([]);
    expect(diagnostics.some(d => d.code === 'uncommented-annotation')).toBe(true);
  });

  it('leaves lock files, minified bundles and binaries out of the scan set', () => {
    for (const ext of ['.lock', '.min.js', '.png', '.pdf', '.zip', '.wasm', '.map']) {
      expect(SCANNED_EXTENSIONS).not.toContain(ext);
    }
  });

  it('keeps one source of truth for the scan set', async () => {
    // Three lists used to answer "which files does GuardLink read": the parser's
    // glob, `clear`'s glob, and the MCP context layer's extension set. They
    // drifted, and a language added to one was invisible through the others.
    const { DEFAULT_INCLUDE } = await import('../src/parser/parse-project.js');
    const globbed = DEFAULT_INCLUDE
      .map(g => g.replace('**/*', ''))
      .filter(e => !/\[/.test(e)); // the case-insensitive .gal pattern
    expect(new Set(globbed)).toEqual(new Set(SCANNED_EXTENSIONS));
  });
});
