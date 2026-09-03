/**
 * The anchor must reach the model through the normal parse, in both annotation
 * modes, and be absent when a caller asks for a cheap parse.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const SOURCE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }

export function other() { return 1; }
`;

async function scratch(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `guardlink-${prefix}-`));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  return root;
}

describe('anchors attached by parseProject', () => {
  it('inline mode: every relation carries the symbol beneath its doc block', async () => {
    const root = await scratch('attach-inline');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.mitigations[0].location.anchor).toMatchObject({ scope: 'symbol', symbol: 'login', start_line: 7, end_line: 7 });
    expect(model.exposures[0].location.anchor?.hash).toBe(model.mitigations[0].location.anchor?.hash);
    // definitions are anchored too, harmlessly: file scope of definitions.ts
    expect(model.assets[0].location.anchor?.scope).toBe('file');
  });

  it('external mode: a @source symbol resolves by name, not by recorded line', async () => {
    const root = await scratch('attach-external');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace(/\/\*\*[\s\S]*?\*\/\n/, ''));
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'api.ts.gal'),
      '@source file:src/api.ts line:1 symbol:other\n@mitigates #api against #sqli using #prepared-stmts -- "bound"\n');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.mitigations[0].location.anchor).toMatchObject({ scope: 'symbol', symbol: 'other' });
  });

  it('anchors: false leaves locations untouched', async () => {
    const root = await scratch('attach-off');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    const { model } = await parseProject({ root, project: 'test', anchors: false });
    expect(model.mitigations[0].location.anchor).toBeUndefined();
  });

  it('a pathologically deep file still anchors, rather than failing the whole parse', async () => {
    // 30,000 nested parentheses. Recursing once per node threw RangeError out of
    // parseStructure, which rejected parseProject — so one file like this failed
    // validate, ci, status, MCP and the TUI on the entire repository.
    const root = await scratch('attach-deep');
    const depth = 30000;
    await writeFile(join(root, 'src', 'api.ts'),
      `/**\n * @audit #api -- "deep file"\n */\nconst x = ${'('.repeat(depth)}1${')'.repeat(depth)};\n`);
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.audits).toHaveLength(1);
    expect(model.audits[0].location.anchor).toBeTruthy();
    expect(model.audits[0].location.anchor?.hash).toMatch(/^sha256-v1:/);
  }, 60000);

  it('a @source path that escapes the root is never opened', async () => {
    // `@source file:` is author-supplied text and normalisation leaves `../`
    // intact, so without a containment check attachAnchors would read and hash
    // a file outside the scanned tree.
    const root = await scratch('attach-escape');
    await writeFile(join(root, '..', `outside-${basename(root)}.ts`), 'export function x() { return 1; }\n');
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'api.ts.gal'),
      `@source file:../outside-${basename(root)}.ts line:1 symbol:x\n@audit #api -- "escapes the root"\n`);
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.audits).toHaveLength(1);
    expect(model.audits[0].location.file).toBe(`../outside-${basename(root)}.ts`);
    expect(model.audits[0].location.anchor).toBeNull();
  });

  it('a logical file that cannot be read yields a null anchor', async () => {
    const root = await scratch('attach-missing');
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'gone.ts.gal'),
      '@source file:src/gone.ts line:1 symbol:x\n@audit #api -- "orphaned sidecar"\n');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.audits[0].location.anchor).toBeNull();
  });
});
