/**
 * Doc-comment forms, and the diagnostics for the forms that stay unread.
 *
 * `stripCommentPrefix` used to remove exactly one comment marker, and
 * `parseLine` then required the very next character to be `@`. Every
 * doc-comment convention is a marker plus one character, so every one of them
 * landed one character too far in and was dropped — silently, with `validate`
 * green and the claim in no threat model. Measured on a 2,400-file repository:
 * 54 real annotations invisible, among them 32 `@mitigates` and 6 `@exposes`.
 *
 * Two things have to hold at once and both are tested here:
 *
 *   1. Each form in SPEC §2.9.1 parses — as a strip, and end to end.
 *   2. Nothing that is not a comment became one. The negative cases are as
 *      load-bearing as the positive ones: this change is only safe because it
 *      grew what is consumed *after* a recognised marker and left the set of
 *      markers alone.
 */
import { describe, it, expect } from 'vitest';
import { stripCommentPrefix } from '../src/parser/comment-strip.js';
import { parseString } from '../src/parser/parse-file.js';

const EXPOSES = '@exposes #api to #sqli [critical] -- "email concatenated into SQL"';

/** Every form SPEC §2.9.1 requires, with the language that writes it. */
const DOC_FORMS: ReadonlyArray<[form: string, language: string, line: string]> = [
  ['///', 'Rust doc, C#, Swift, Dart', `/// ${EXPOSES}`],
  ['//!', 'Rust inner doc, Doxygen', `//! ${EXPOSES}`],
  ['//!<', 'Doxygen trailing member', `//!< ${EXPOSES}`],
  ['///<', 'Doxygen trailing member', `///< ${EXPOSES}`],
  ['////', 'a marker repeated past convention', `//// ${EXPOSES}`],
  ['/** (opening line)', 'JS/TS/Java', `/** ${EXPOSES}`],
  ['/*! (opening line)', 'Doxygen block', `/*! ${EXPOSES}`],
  ['/**< (opening line)', 'Doxygen block', `/**< ${EXPOSES}`],
  ['##', 'Python, Bash, YAML banner', `## ${EXPOSES}`],
  ['###', 'Python banner', `### ${EXPOSES}`],
  [';;', 'Lisp, Clojure', `;; ${EXPOSES}`],
  [';;;', 'Lisp top-level', `;;; ${EXPOSES}`],
  ['%%', 'Erlang module comment', `%% ${EXPOSES}`],
  ['---', 'Lua LDoc', `--- ${EXPOSES}`],
  ['-- |', 'Haskell Haddock (follows)', `-- | ${EXPOSES}`],
  ['-- ^', 'Haskell Haddock (precedes)', `-- ^ ${EXPOSES}`],
  ["'''", 'VB.NET XML doc', `''' ${EXPOSES}`],
];

describe('SPEC §2.9.1 — repeated and decorated markers are the same marker', () => {
  for (const [form, language, line] of DOC_FORMS) {
    it(`strips ${form} (${language})`, () => {
      expect(stripCommentPrefix(line)).toBe(EXPOSES);
    });
  }

  for (const [form, , line] of DOC_FORMS) {
    it(`parses an annotation written with ${form}`, () => {
      const { annotations, diagnostics } = parseString(`${line}\nfn login() {}\n`, 'a.rs');
      expect(annotations).toHaveLength(1);
      expect(annotations[0].verb).toBe('exposes');
      expect(annotations[0].line ?? annotations[0].location.line).toBe(1);
      // A form that parses must not also complain about itself.
      expect(diagnostics).toEqual([]);
    });
  }

  it('reads the whole Rust doc-block GuardLink tells authors to write', () => {
    const src = [
      '/// Authenticate a user.',
      '///',
      `/// ${EXPOSES}`,
      '/// @mitigates #api against #sqli using #prepared-stmts -- "parameterized via sqlx"',
      '/// @flows User -> #api via HTTPS -- "login request"',
      'pub fn login(email: &str) {}',
    ].join('\n');
    const { annotations, diagnostics } = parseString(src, 'login.rs');
    expect(annotations.map(a => a.verb)).toEqual(['exposes', 'mitigates', 'flows']);
    expect(diagnostics).toEqual([]);
  });

  it('reads a JSDoc block from its opening line, not just its continuations', () => {
    const src = [
      `/** ${EXPOSES}`,
      ' * @mitigates #api against #sqli using #prepared-stmts -- "parameterized via pg"',
      ' */',
      'export function login(email: string) {}',
    ].join('\n');
    const { annotations } = parseString(src, 'login.ts');
    expect(annotations.map(a => a.verb)).toEqual(['exposes', 'mitigates']);
  });
});

describe('the marker set did not grow — near misses are still not comments', () => {
  const NOT_COMMENTS = [
    ['plain code', 'const x = 1;'],
    ['a decorator', '@Component({ selector: "app" })'],
    ['a Python decorator', '@classmethod'],
    ['a bare verb at column 0', '@exposes #api to #sqli -- "in a docstring"'],
    ['a docstring delimiter with double quotes', '""" @exposes #api to #sqli -- "x"'],
    ['an operator that starts like a marker', 'x = a<-b'],
    ['a JSX fragment', '<div>@exposes</div>'],
    ['an annotation trailing real code', 'let x = 1; // @exposes #api to #sqli -- "x"'],
  ] as const;

  for (const [what, line] of NOT_COMMENTS) {
    it(`returns null for ${what}`, () => {
      expect(stripCommentPrefix(line)).toBeNull();
    });
  }

  it('a decorated marker that is not a marker yields no annotation', () => {
    const { annotations } = parseString(`@exposes #api to #sqli -- "no marker"\n`, 'a.py');
    expect(annotations).toEqual([]);
  });
});

describe('the paths that already worked behave exactly as before', () => {
  it('single-line HTML comments', () => {
    expect(stripCommentPrefix('<!-- @asset Foo -->')).toBe('@asset Foo');
  });
  it('single-line block comments', () => {
    expect(stripCommentPrefix('/* @asset Foo */')).toBe('@asset Foo');
    expect(stripCommentPrefix('/** @asset Foo */')).toBe('@asset Foo');
  });
  it('Javadoc continuations', () => {
    expect(stripCommentPrefix(' * @asset Foo')).toBe('@asset Foo');
    expect(stripCommentPrefix(' */')).toBeNull();
  });
  it('Haskell and OCaml single-line blocks', () => {
    expect(stripCommentPrefix('{- @asset Foo -}')).toBe('@asset Foo');
    expect(stripCommentPrefix('(* @asset Foo *)')).toBe('@asset Foo');
  });
  it('a .gal sidecar still reads raw lines with no marker at all', () => {
    const { annotations, diagnostics } = parseString(
      `@source file:src/a.ts line:1\n${EXPOSES}\n`,
      '.guardlink/annotations/src/a.ts.gal',
    );
    expect(annotations.map(a => a.verb)).toEqual(['exposes']);
    expect(diagnostics).toEqual([]);
  });
  it('description continuation lines still attach', () => {
    const { annotations } = parseString(
      '// @exposes #api to #sqli -- "first half"\n// -- "second half"\n',
      'a.ts',
    );
    expect(annotations).toHaveLength(1);
    expect(annotations[0].description).toBe('first half second half');
  });
});

// ─── The silence, made loud ──────────────────────────────────────────

describe('uncommented-annotation — the forms SPEC §2.9.3 does not read', () => {
  it('names an annotation written inside a Python docstring', () => {
    const src = [
      'def login(email):',
      '    """Authenticate a user.',
      '',
      `    ${EXPOSES}`,
      '    """',
      '    ...',
    ].join('\n');
    const { annotations, diagnostics } = parseString(src, 'login.py');
    expect(annotations).toEqual([]);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0].code).toBe('uncommented-annotation');
    expect(diagnostics[0].level).toBe('warning');
    expect(diagnostics[0].line).toBe(4);
  });

  it('names one inside a Ruby =begin block', () => {
    const src = ['=begin', EXPOSES, '=end', 'def login(email); end'].join('\n');
    const { diagnostics } = parseString(src, 'login.rb');
    expect(diagnostics.map(d => d.code)).toEqual(['uncommented-annotation']);
  });

  it('collapses a block of them to one diagnostic carrying the count', () => {
    const src = [
      '"""',
      EXPOSES,
      '@mitigates #api against #sqli using #prepared-stmts -- "x"',
      '@audit #api -- "y"',
      '"""',
    ].join('\n');
    const { diagnostics } = parseString(src, 'a.py');
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0].message).toContain('3 occurrences in this file');
    expect(diagnostics[0].line).toBe(2);
  });

  it('stays quiet without structural evidence — prose is not an annotation', () => {
    const { diagnostics } = parseString('@exposes was renamed in v1.2 and reads better now\n', 'a.md.ts');
    expect(diagnostics).toEqual([]);
  });

  it('stays quiet inside a @shield region', () => {
    const src = [
      '// @shield:begin -- "syntax examples"',
      EXPOSES,
      '// @shield:end',
    ].join('\n');
    const { diagnostics } = parseString(src, 'a.ts');
    expect(diagnostics).toEqual([]);
  });
});

describe('unrecognised-comment-form — a marker this parser has not learned', () => {
  it('names a known verb sitting behind punctuation the stripper left', () => {
    // Julia's `#=` block opener: `#` is consumed as a comment marker, `=` is
    // not a decoration §2.9.1 lists, so the annotation never reaches parseLine.
    const { annotations, diagnostics } = parseString(`#= ${EXPOSES}\n`, 'a.jl.py');
    expect(annotations).toEqual([]);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0].code).toBe('unrecognised-comment-form');
    expect(diagnostics[0].level).toBe('warning');
    expect(diagnostics[0].message).toContain('@exposes');
  });

  it('stays quiet on a backticked mention in prose', () => {
    const { diagnostics } = parseString(
      '// `@handles <classification>` — every asset processing data of that class\n',
      'a.ts',
    );
    expect(diagnostics).toEqual([]);
  });

  it('stays quiet on a section rule', () => {
    const { diagnostics } = parseString('// ── @asset ──\n', 'a.ts');
    expect(diagnostics).toEqual([]);
  });

  it('stays quiet when the residue is itself a whole comment marker', () => {
    // A TypeScript string literal opening with `'` is read as a VB.NET comment;
    // the `//` inside it is source, not a decoration nobody taught the parser.
    const { diagnostics } = parseString(`'// ${EXPOSES}',\n`, 'a.ts');
    expect(diagnostics).toEqual([]);
  });

  it('stays quiet without structural evidence', () => {
    const { diagnostics } = parseString('// != @comment is the verb for context\n', 'a.ts');
    expect(diagnostics).toEqual([]);
  });
});

describe('the scoping that makes loudness safe', () => {
  /**
   * The measured argument, as a test. Comment lines beginning `@token` number
   * 750 on juice-shop, 2,330 on ghostfolio and 3,176 on bkeeper; of those, 0,
   * 0 and 3 are a known GuardLink verb. A blanket "unparsed @ line" warning
   * would emit 2,330 warnings on a repository that has never heard of
   * GuardLink. This is the shape of that traffic, and none of it may fire.
   */
  const THIRD_PARTY = [
    '/// @param email the address to authenticate',
    '/// @returns a session token',
    '//! @file login.rs',
    '## @author someone',
    '/** @deprecated use loginV2 */',
    '// @ts-expect-error the types disagree',
    '@Component({ selector: "app-login" })',
    '@Injectable()',
    '@classmethod',
    '@jwt_required()',
    '// @see https://example.com/docs',
    '/// @brief authenticate a user',
    '-- | @param is not ours either',
    '@if (loading) {',
  ].join('\n');

  it('emits nothing on doc tags and framework decorators', () => {
    const { annotations, diagnostics } = parseString(THIRD_PARTY, 'vendor.ts');
    expect(annotations).toEqual([]);
    expect(diagnostics).toEqual([]);
  });
});
