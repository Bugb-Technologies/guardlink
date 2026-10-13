/**
 * GL-507 — annotation mode migration.
 *
 * The gate is annotation_hash identity. The hash deliberately excludes line,
 * origin_file and parent_symbol — exactly the fields a migration is allowed to
 * change — so if it moves, the migration altered the threat model, which is the
 * one thing it must not do.
 *
 * The second gate is a byte-identical round trip of the EXTERNAL state:
 * external → inline → external reproduces every source file and every sidecar.
 * "Equivalent" is not good enough: a migration that reformats your source
 * while relocating annotations makes an unreviewable diff, and nobody will run
 * it twice. The other direction may change layout once — removal takes the
 * separators and emptied comments that held the annotations, and restoring
 * writes a canonical layout back — and holds the hash.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrateAnnotationMode, annotationsLeftBehind } from '../src/parser/migrate-mode.js';
import { parseProject } from '../src/parser/parse-project.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { initProject } from '../src/init/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.DB (#db) -- "Database"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 * @actor Helper_Bot (#helper-bot) -- "Assistant embedded in the app"
 * @actor Reviewer (#reviewer) -- "Human who approves refunds"
 * @actor Build_Runner (#builder) -- "CI principal"
 */
export {};
`;

/** Doc-block annotations, a lone line-comment annotation, and a shielded example. */
const SOURCE = `import express from 'express';

/**
 * Login handler.
 *
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "req.body.email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 * @flows User -> #api via HTTPS -- "Login request path"
 */
export function login(req) {
  return req.body;
}

// @audit #api -- "Token rotation needs crypto review"
export function refresh() {
  return 1;
}

/**
 * Docs for the annotation language.
 *
 * @shield:begin -- "Example annotations, excluded from parsing"
 * @exposes #db to #sqli [critical] -- "THIS IS AN EXAMPLE, NOT REAL"
 * @audit #db -- "ALSO AN EXAMPLE"
 * @shield:end
 */
export const DOCS = 'x';
`;

/** One of each comment shape an annotation can sit in, inside and around prose. */
const SHAPES = `// @audit #api -- "first line of the file"

import x from "y";

/** @audit #api -- "self-contained doc comment" */
export const a = 1;

import z from "w";

// @audit #api -- "standalone between blank lines"

export const d = 1;

/**
 * @audit #api -- "only annotation"
 */
export const e = 1;

/**
 * Summary.
 *
 * @exposes #api to #sqli [critical] -- "trailing group"
 *
 */
export const f = 1;

/**
 * @audit #api -- "leading group"
 *
 * Summary below.
 */
export const g = 1;

/**
 * Before.
 *
 * @audit #api -- "middle group"
 *
 * After.
 */
export const h = 1;

/**
 * @audit #api -- "one"
 *
 * @audit #api -- "two"
 */
export const i = 1;

export class K {
  /**
   * Method docs.
   *
   * @audit #api -- "indented"
   */
  m() {
    // @audit #api -- "inside a body"
    return 1;
  }
}
// @audit #api -- "at end of file"
`;

/** SHAPES as if it had never been annotated. */
const SHAPES_STRIPPED = `import x from "y";

export const a = 1;

import z from "w";

export const d = 1;

export const e = 1;

/**
 * Summary.
 */
export const f = 1;

/**
 * Summary below.
 */
export const g = 1;

/**
 * Before.
 *
 * After.
 */
export const h = 1;

export const i = 1;

export class K {
  /**
   * Method docs.
   */
  m() {
    return 1;
  }
}
`;

/** Rust doc comments, inner and outer, with a continuation line. */
const RUST = `//! Crate docs.
//!
//! @comment -- "crate level"

/// Renders.
///
/// @exposes #api to #sqli [critical] -- "template"
/// @mitigates #api against #sqli using #prepared-stmts -- "escaped"
pub fn render() {}

/// @audit #api -- "doc comment of only annotations"
/// -- "continued"
pub fn other() {}
`;

const RUST_STRIPPED = `//! Crate docs.

/// Renders.
pub fn render() {}

pub fn other() {}
`;

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-migrate-mode-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'auth.ts'), SOURCE);
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const parse = () => parseProject({ root, project: 'test' });
const hash = async () => computeAnnotationHash((await parse()).model);
const migrate = async (to: 'inline' | 'external', dryRun = false) => {
  const { model, diagnostics } = await parse();
  return migrateAnnotationMode({ root, to, model, diagnostics, dryRun });
};

const GAL = ['.guardlink', 'annotations', 'src', 'auth.ts.gal'];

describe('GL-507 — inline → external', () => {
  it('holds annotation_hash across the migration', async () => {
    const before = await hash();
    await migrate('external');
    expect(await hash()).toBe(before);
  });

  it('moves the annotations into the conventional sidecar', async () => {
    const result = await migrate('external');
    expect(result.galFiles).toContain('.guardlink/annotations/src/auth.ts.gal');
    expect(existsSync(join(root, ...GAL))).toBe(true);
    const gal = await readFile(join(root, ...GAL), 'utf-8');
    expect(gal).toContain('@source file:src/auth.ts');
    expect(gal).toContain('@exposes #api to #sqli [critical] cwe:CWE-89 -- "req.body.email concatenated into SQL"');
  });

  it('leaves the source free of annotations', async () => {
    await migrate('external');
    const src = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    expect(src).not.toContain('@exposes #api');
    expect(src).not.toContain('@mitigates');
    expect(src).not.toContain('@flows');
    expect(src).not.toContain('@audit #api');
    expect(src).toContain('export function login(req)');   // code untouched
    // The shielded examples stay — see the @shield block below.
    expect(src).toContain('@exposes #db');
  });

  it('groups a contiguous run under one @source header', async () => {
    await migrate('external');
    const gal = await readFile(join(root, ...GAL), 'utf-8');
    const headers = gal.split('\n').filter(l => l.startsWith('@source'));
    // One for the three-line doc block, one for the lone line comment.
    expect(headers).toHaveLength(2);
  });

  it('moves annotation text verbatim rather than re-serialising it', async () => {
    await migrate('external');
    const gal = await readFile(join(root, ...GAL), 'utf-8');
    for (const line of SOURCE.split('\n')) {
      const inner = line.replace(/^\s*(\*|\/\/)\s?/, '').trim();
      if (inner.startsWith('@') && !inner.startsWith('@shield') && !gal.includes('THIS IS AN EXAMPLE')) {
        if (inner.startsWith('@exposes #db') || inner.startsWith('@audit #db')) continue;
        expect(gal).toContain(inner);
      }
    }
  });

  it('never migrates .guardlink/definitions — the vocabulary stays where every tool looks', async () => {
    const before = await readFile(join(root, '.guardlink', 'definitions.ts'), 'utf-8');
    const result = await migrate('external');
    expect(await readFile(join(root, '.guardlink', 'definitions.ts'), 'utf-8')).toBe(before);
    expect(result.galFiles.some(f => f.includes('definitions'))).toBe(false);
  });

  it('refuses to overwrite an existing sidecar, and names every annotation it left', async () => {
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, ...GAL), '@source file:src/auth.ts line:1\n@audit #api -- "pre-existing"\n');
    const before = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    const result = await migrate('external');
    expect(result.unmigrated.map(u => `${u.file}:${u.line}`)).toEqual(
      ['src/auth.ts:6', 'src/auth.ts:7', 'src/auth.ts:8', 'src/auth.ts:14']);
    expect(result.unmigrated.every(u => /already exists/.test(u.reason))).toBe(true);
    expect(await readFile(join(root, 'src', 'auth.ts'), 'utf-8')).toBe(before);
  });

  it('dryRun reports without writing', async () => {
    const before = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    const result = await migrate('external', true);
    expect(result.annotationsMoved).toBeGreaterThan(0);
    expect(existsSync(join(root, ...GAL))).toBe(false);
    expect(await readFile(join(root, 'src', 'auth.ts'), 'utf-8')).toBe(before);
  });
});

describe('GL-507 — @shield never migrates', () => {
  it('leaves both markers in the source', async () => {
    await migrate('external');
    const src = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    expect(src).toContain('@shield:begin');
    expect(src).toContain('@shield:end');
  });

  it('leaves the shielded examples inside the region, still unparsed', async () => {
    await migrate('external');
    const src = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    expect(src).toContain('THIS IS AN EXAMPLE, NOT REAL');
    const gal = await readFile(join(root, ...GAL), 'utf-8');
    expect(gal).not.toContain('THIS IS AN EXAMPLE');
    expect(gal).not.toContain('ALSO AN EXAMPLE');
  });

  it('does not fabricate annotations by pulling examples out of the region', async () => {
    const before = (await parse()).model;
    await migrate('external');
    const after = (await parse()).model;
    expect(after.annotations_parsed).toBe(before.annotations_parsed);
    // The specific failure this guards: #db is referenced ONLY inside the
    // shielded block, so it must never appear as a real exposure.
    expect(after.exposures.some(e => e.asset === '#db')).toBe(false);
  });

  it('a file holding only shields is skipped, and says so', async () => {
    await writeFile(join(root, 'src', 'docs.ts'),
      '/**\n * @shield:begin -- "examples"\n * @audit #api -- "example"\n * @shield:end\n */\nexport const x = 1;\n');
    const result = await migrate('external');
    const skip = result.skipped.find(s => s.file === 'src/docs.ts');
    expect(skip?.reason).toContain('@shield');
  });
});

describe('GL-507 — external → inline', () => {
  it('holds annotation_hash', async () => {
    await migrate('external');
    const mid = await hash();
    await migrate('inline');
    expect(await hash()).toBe(mid);
  });

  it('restores annotations into the source and deletes the sidecar', async () => {
    await migrate('external');
    await migrate('inline');
    const src = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    expect(src).toContain('@exposes #api to #sqli');
    expect(existsSync(join(root, ...GAL))).toBe(false);
  });

  it('prunes the empty annotations directory rather than leaving scaffolding', async () => {
    await migrate('external');
    await migrate('inline');
    expect(existsSync(join(root, '.guardlink', 'annotations'))).toBe(false);
  });

  it('re-commenting matches the block it rejoins', async () => {
    await migrate('external');
    await migrate('inline');
    const src = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    expect(src).toContain(' * @exposes #api to #sqli');   // Javadoc continuation
    expect(src).toContain('// @audit #api');              // line comment
  });
});

describe('GL-507 — round trip reproduces the original', () => {
  /** Every file under root, so a sidecar that changed is caught as surely as a source file. */
  const snapshot = async (): Promise<Map<string, string>> => {
    const { readdir } = await import('node:fs/promises');
    const out = new Map<string, string>();
    const walk = async (dir: string): Promise<void> => {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const p = join(dir, entry.name);
        if (entry.isDirectory()) await walk(p);
        else out.set(p.slice(root.length), await readFile(p, 'utf-8'));
      }
    };
    await walk(root);
    return out;
  };

  it('external → inline → external is byte-identical, sidecars included', async () => {
    await migrate('external');
    const external = await snapshot();
    const externalHash = await hash();
    await migrate('inline');
    await migrate('external');
    expect(await snapshot()).toEqual(external);
    expect(await hash()).toBe(externalHash);
  });

  it('inline → external → inline holds the hash', async () => {
    const beforeHash = await hash();
    await migrate('external');
    await migrate('inline');
    expect(await hash()).toBe(beforeHash);
  });

  it('inline → external → inline is byte-identical where the source already has the canonical layout', async () => {
    await writeFile(join(root, 'src', 'auth.ts'), `/**
 * Login handler.
 *
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "req.body.email concatenated into SQL"
 */
export function login(req) {
  return req.body;
}
`);
    const before = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    await migrate('external');
    await migrate('inline');
    expect(await readFile(join(root, 'src', 'auth.ts'), 'utf-8')).toBe(before);
  });

  it('holds for a file whose annotations sit at the very first line', async () => {
    await writeFile(join(root, 'src', 'top.ts'),
      '// @audit #api -- "first line"\nexport const x = 1;\n');
    const before = await readFile(join(root, 'src', 'top.ts'), 'utf-8');
    await migrate('external');
    await migrate('inline');
    expect(await readFile(join(root, 'src', 'top.ts'), 'utf-8')).toBe(before);
  });

  it('holds for an indented annotation inside a nested block', async () => {
    await writeFile(join(root, 'src', 'nested.ts'),
      'export class A {\n  /**\n   * Method.\n   *\n   * @audit #api -- "indented"\n   */\n  m() { return 1; }\n}\n');
    const before = await readFile(join(root, 'src', 'nested.ts'), 'utf-8');
    await migrate('external');
    await migrate('inline');
    expect(await readFile(join(root, 'src', 'nested.ts'), 'utf-8')).toBe(before);
  });

  it('holds across several files and every comment shape at once', async () => {
    await writeFile(join(root, 'src', 'shapes.ts'), SHAPES);
    await writeFile(join(root, 'src', 'lib.rs'), RUST);
    await writeFile(join(root, 'src', 'c.ts'), '// @comment -- "c"\nexport const c = 2;\n');
    await migrate('external');
    const external = await snapshot();
    await migrate('inline');
    await migrate('external');
    expect(await snapshot()).toEqual(external);
  });
});

describe('GL-507 — existing repos keep their mode', () => {
  it('nothing migrates without an explicit call', async () => {
    const before = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    await parse();
    expect(await readFile(join(root, 'src', 'auth.ts'), 'utf-8')).toBe(before);
  });

  it('re-running init over an inline repo does not flip its recorded mode', async () => {
    await writeFile(join(root, '.guardlink', 'config.json'),
      JSON.stringify({ version: '1.1.0', project: 'test', annotation_mode: 'inline' }, null, 2) + '\n');
    initProject({ root, agentIds: [] });   // defaults to external since GL-506
    const cfg = JSON.parse(await readFile(join(root, '.guardlink', 'config.json'), 'utf-8'));
    expect(cfg.annotation_mode).toBe('inline');
  });

  it('migrating a file already in the target mode leaves it alone', async () => {
    await migrate('external');
    const gal = await readFile(join(root, ...GAL), 'utf-8');
    const result = await migrate('external');
    expect(result.alreadyThere).toContain('.guardlink/annotations/src/auth.ts.gal');
    expect(result.annotationsMoved).toBe(0);
    expect(await readFile(join(root, ...GAL), 'utf-8')).toBe(gal);
  });
});

describe('GL-507 — a mixed repo converges', () => {
  it('half inline, half external → all external, hash held', async () => {
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'ext.ts'), 'export const e = 1;\n');
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'ext.ts.gal'),
      '@source file:src/ext.ts line:1 symbol:e\n@comment -- "already external"\n');
    const before = await hash();

    const result = await migrate('external');
    expect(result.alreadyThere).toContain('.guardlink/annotations/src/ext.ts.gal');
    expect(await hash()).toBe(before);

    const { model } = await parse();
    expect(model.annotated_files.every(f => !f.endsWith('.gal'))).toBe(true);
  });
});

describe('migrate fidelity — every annotation moves, only annotations move, nothing is left behind', () => {
  it('moves a file whose only annotations are @agents, @reaches, @effects and @gates', async () => {
    // These four record kinds were missing from the list migrate chose files
    // from, so this file was never touched. Nothing said so: the annotations
    // stayed inline, still parsed, and annotation_hash held.
    await writeFile(join(root, 'src', 'tools.ts'), `import { register } from './registry';

// @agents #helper-bot to query-db on #db -- "query tool handed to the assistant"
register('query', q => q);

// @reaches #builder to deploy on #api -- "the pipeline deploys"
export function refund() {
  // @gates #db by #reviewer for issue-refund -- "a human approves every refund"
  // @effects write on #db -- "writes the refund row"
  return 1;
}
`);
    const before = await hash();
    const result = await migrate('external');
    expect(result.sourceFiles).toContain('src/tools.ts');
    expect(result.unmigrated).toEqual([]);
    expect(await readFile(join(root, 'src', 'tools.ts'), 'utf-8')).not.toContain('@');
    expect(await hash()).toBe(before);
    expect(annotationsLeftBehind((await parse()).model, 'external')).toEqual([]);

    // And back: a sidecar holding only these kinds is restored, not stranded.
    await migrate('inline');
    expect(await hash()).toBe(before);
    expect(annotationsLeftBehind((await parse()).model, 'inline')).toEqual([]);
    expect(existsSync(join(root, '.guardlink', 'annotations'))).toBe(false);
  });

  it('leaves a comment that merely begins with an at-sign word exactly where it is', async () => {
    // `@page` is CSS, not GuardLink. The second one sits inside a string literal,
    // so deleting it would change what the program prints.
    const rust = `// @page margins are set by the print stylesheet below.
pub const PRINT_CSS: &str = r#"
/* @page margins: keep a gutter for binding */
body { font-size: 12pt; }
"#;

/// Renders a page.
///
/// @audit #api -- "template text reaches the renderer"
pub fn render() {}
`;
    await writeFile(join(root, 'src', 'print.rs'), rust);
    await migrate('external');
    expect(await readFile(join(root, 'src', 'print.rs'), 'utf-8'))
      .toBe(rust.replace('///\n/// @audit #api -- "template text reaches the renderer"\n', ''));
    const gal = await readFile(join(root, '.guardlink', 'annotations', 'src', 'print.rs.gal'), 'utf-8');
    expect(gal).not.toContain('@page');
    expect(gal).toContain('@audit #api -- "template text reaches the renderer"');
  });

  it('removes the layout that held the annotations, and nothing else', async () => {
    await writeFile(join(root, 'src', 'shapes.ts'), SHAPES);
    await writeFile(join(root, 'src', 'lib.rs'), RUST);
    const before = await hash();
    await migrate('external');
    expect(await readFile(join(root, 'src', 'shapes.ts'), 'utf-8')).toBe(SHAPES_STRIPPED);
    expect(await readFile(join(root, 'src', 'lib.rs'), 'utf-8')).toBe(RUST_STRIPPED);
    expect(await hash()).toBe(before);
  });

  it('records each block at the line of the stripped source it sits above', async () => {
    await writeFile(join(root, 'src', 'lib.rs'), RUST);
    await migrate('external');
    const gal = await readFile(join(root, '.guardlink', 'annotations', 'src', 'lib.rs.gal'), 'utf-8');
    const lines = RUST_STRIPPED.split('\n');
    const at = [...gal.matchAll(/line:(\d+)/g)].map(m => lines[Number(m[1]) - 1]);
    expect(at).toEqual(['', 'pub fn render() {}', 'pub fn other() {}']);
  });

  it('keeps CRLF line endings on every line it leaves', async () => {
    const crlf = 'use a;\r\n\r\n/// Docs.\r\n///\r\n/// @audit #api -- "crlf"\r\npub fn f() {}\r\n';
    await writeFile(join(root, 'src', 'crlf.rs'), crlf);
    await migrate('external');
    expect(await readFile(join(root, 'src', 'crlf.rs'), 'utf-8')).toBe('use a;\r\n\r\n/// Docs.\r\npub fn f() {}\r\n');
  });

  it('moves a -- continuation with the annotation it extends', async () => {
    await writeFile(join(root, 'src', 'cont.ts'),
      '/**\n * @audit #api -- "first half"\n *   -- "second half"\n */\nexport const g = 1;\n');
    const before = await hash();
    await migrate('external');
    expect(await readFile(join(root, 'src', 'cont.ts'), 'utf-8')).toBe('export const g = 1;\n');
    expect(await hash()).toBe(before);
    const audit = (await parse()).model.audits.find(a => a.location.file === 'src/cont.ts');
    expect(audit?.description).toBe('first half second half');

    await migrate('inline');
    expect(await hash()).toBe(before);
  });

  it('refuses an annotation that shares its line with a comment delimiter, names it, and leaves its file whole', async () => {
    const opener = '/** @audit #api -- "on the opener"\n * more prose\n */\nexport const b = 1;\n';
    const closer = '/**\n * Prose.\n * @audit #api -- "on the closer" */\nexport const c = 1;\n';
    await writeFile(join(root, 'src', 'opener.ts'), opener);
    await writeFile(join(root, 'src', 'closer.ts'), closer);
    const result = await migrate('external');
    expect(result.unmigrated.map(u => `${u.file}:${u.line}`)).toEqual(['src/closer.ts:3', 'src/opener.ts:1']);
    expect(result.unmigrated[0].reason).toMatch(/closer `\*\/`/);
    expect(result.unmigrated[1].reason).toMatch(/opener `\/\*`/);
    expect(await readFile(join(root, 'src', 'opener.ts'), 'utf-8')).toBe(opener);
    expect(await readFile(join(root, 'src', 'closer.ts'), 'utf-8')).toBe(closer);
    // The rest of the repo still moves.
    expect(result.sourceFiles).toContain('src/auth.ts');
  });

  it('refuses a malformed annotation rather than leaving it behind in an external repo', async () => {
    await writeFile(join(root, 'src', 'bad.ts'), '// @audit #api -- "fine"\n// @mitigates #api against #sqli using -- "no control"\nexport const x = 1;\n');
    const result = await migrate('external');
    expect(result.unmigrated).toEqual([expect.objectContaining({ file: 'src/bad.ts', line: 2, reason: expect.stringMatching(/malformed/) })]);
    expect(result.sourceFiles).not.toContain('src/bad.ts');
  });

  it('restores a sidecar block above the source line its @source names', async () => {
    await writeFile(join(root, 'src', 'four.ts'), 'export const a = 1;\nexport const b = 2;\nexport const c = 3;\nexport const d = 4;\n');
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'four.ts.gal'),
      '@source file:src/four.ts line:2\n@audit #api -- "above b"\n\n@source file:src/four.ts line:4\n@audit #api -- "above d"\n');
    await migrate('inline');
    expect(await readFile(join(root, 'src', 'four.ts'), 'utf-8')).toBe(
      'export const a = 1;\n// @audit #api -- "above b"\nexport const b = 2;\nexport const c = 3;\n// @audit #api -- "above d"\nexport const d = 4;\n');
  });
});

describe('guardlink migrate — the command never reports success over an annotation it left', () => {
  const cli = join(fileURLToPath(new URL('..', import.meta.url)), 'dist', 'cli', 'index.js');
  const run = (...args: string[]): { status: number; stderr: string } => {
    try {
      execFileSync('node', [cli, 'migrate', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return { status: 0, stderr: '' };
    } catch (err) {
      const e = err as { status: number; stderr: string };
      return { status: e.status, stderr: e.stderr };
    }
  };
  // Each case spawns the built CLI, whose process start is slow on a busy runner.
  const CLI_SPAWN_TIMEOUT_MS = 30_000;

  beforeEach(async () => {
    await writeFile(join(root, '.guardlink', 'config.json'),
      JSON.stringify({ version: '1.1.0', project: 'test', annotation_mode: 'inline' }, null, 2) + '\n');
    await writeFile(join(root, 'src', 'opener.ts'), '/** @audit #api -- "on the opener"\n * more prose\n */\nexport const b = 1;\n');
  });

  it('exits non-zero, names each annotation by file and line, and keeps annotation_mode', () => {
    const { status, stderr } = run('--to', 'external');
    expect(status).toBe(1);
    expect(stderr).toContain('src/opener.ts:1');
    expect(stderr).toContain('Migration incomplete');
    expect(JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf-8')).annotation_mode).toBe('inline');
  }, CLI_SPAWN_TIMEOUT_MS);

  it('a dry run that would leave an annotation exits non-zero too', () => {
    const { status, stderr } = run('--to', 'external', '--dry-run');
    expect(status).toBe(1);
    expect(stderr).toContain('src/opener.ts:1');
  }, CLI_SPAWN_TIMEOUT_MS);

  it('exits zero once every annotation has moved', async () => {
    await writeFile(join(root, 'src', 'opener.ts'), '/**\n * @audit #api -- "on its own line"\n * more prose\n */\nexport const b = 1;\n');
    const { status } = run('--to', 'external');
    expect(status).toBe(0);
    expect(JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf-8')).annotation_mode).toBe('external');
  }, CLI_SPAWN_TIMEOUT_MS);
});
