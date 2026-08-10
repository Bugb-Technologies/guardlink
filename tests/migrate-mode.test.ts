/**
 * GL-507 — annotation mode migration.
 *
 * The gate is annotation_hash identity. The hash deliberately excludes line,
 * origin_file and parent_symbol — exactly the fields a migration is allowed to
 * change — so if it moves, the migration altered the threat model, which is the
 * one thing it must not do.
 *
 * The second gate is a byte-identical round trip. "Equivalent" is not good
 * enough: a migration that reformats your source while relocating annotations
 * makes an unreviewable diff, and nobody will run it twice.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrateAnnotationMode } from '../src/parser/migrate-mode.js';
import { parseProject } from '../src/parser/parse-project.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { initProject } from '../src/init/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.DB (#db) -- "Database"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
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
const migrate = async (to: 'inline' | 'external', dryRun = false) =>
  migrateAnnotationMode({ root, to, model: (await parse()).model, dryRun });

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

  it('refuses to overwrite an existing sidecar', async () => {
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, ...GAL), '@source file:src/auth.ts line:1\n@audit #api -- "pre-existing"\n');
    const result = await migrate('external');
    expect(result.skipped.some(s => s.file === 'src/auth.ts' && /already exists/.test(s.reason))).toBe(true);
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
  it('inline → external → inline is byte-identical', async () => {
    const before = await readFile(join(root, 'src', 'auth.ts'), 'utf-8');
    const beforeHash = await hash();
    await migrate('external');
    await migrate('inline');
    expect(await readFile(join(root, 'src', 'auth.ts'), 'utf-8')).toBe(before);
    expect(await hash()).toBe(beforeHash);
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
      'export class A {\n  /**\n   * @audit #api -- "indented"\n   */\n  m() { return 1; }\n}\n');
    const before = await readFile(join(root, 'src', 'nested.ts'), 'utf-8');
    await migrate('external');
    await migrate('inline');
    expect(await readFile(join(root, 'src', 'nested.ts'), 'utf-8')).toBe(before);
  });

  it('holds across several files at once', async () => {
    await writeFile(join(root, 'src', 'b.ts'), '/**\n * @audit #api -- "b"\n */\nexport const b = 1;\n');
    await writeFile(join(root, 'src', 'c.ts'), '// @comment -- "c"\nexport const c = 2;\n');
    const before = new Map<string, string>();
    for (const f of ['auth.ts', 'b.ts', 'c.ts']) {
      before.set(f, await readFile(join(root, 'src', f), 'utf-8'));
    }
    await migrate('external');
    await migrate('inline');
    for (const [f, text] of before) {
      expect(await readFile(join(root, 'src', f), 'utf-8')).toBe(text);
    }
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
