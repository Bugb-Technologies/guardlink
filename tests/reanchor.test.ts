/**
 * GL-505 — @source drift detection.
 *
 * The scenario that matters is a real refactor, so that is what these build:
 * write a repo, parse it, edit the source the way an editor would (insert
 * imports above, rename a function, delete a file), re-parse, and check what
 * the detector says. Hand-assembling a drifted model would test the reporting
 * and skip the detection.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { findAnchorDrift, applyReanchor } from '../src/parser/reanchor.js';
import { parseProject } from '../src/parser/parse-project.js';
import type { AnchorDrift } from '../src/parser/reanchor.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 */
export {};
`;

const ORIGINAL_SOURCE = `export function handler(req) {
  return req;
}

export function other() {
  return 1;
}
`;

/** handler now at line 8, other at line 12 — six imports pushed everything down. */
const REFACTORED_SOURCE = `import a from 'a';
import b from 'b';
import c from 'c';
import d from 'd';
import e from 'e';
import f from 'f';

export function handler(req) {
  return req;
}

export function other() {
  return 1;
}
`;

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-reanchor-'));
  await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), ORIGINAL_SOURCE);
  await writeFile(join(root, '.guardlink', 'annotations', 'src', 'api.ts.gal'),
    '@source file:src/api.ts line:1 symbol:handler\n'
    + '@exposes #api to #sqli [critical] -- "req interpolated into SQL"\n'
    + '\n'
    + '@source file:src/api.ts line:5 symbol:other\n'
    + '@audit #api -- "Needs review"\n');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function drifts(): Promise<AnchorDrift[]> {
  const { model } = await parseProject({ root, project: 'test' });
  return findAnchorDrift(root, model);
}

const galPath = () => join(root, '.guardlink', 'annotations', 'src', 'api.ts.gal');

describe('GL-505 — detects blocks whose file:line no longer holds the symbol', () => {
  it('reports nothing when every anchor is still correct', async () => {
    expect(await drifts()).toEqual([]);
  });

  it('detects both blocks after imports are inserted above them', async () => {
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    const found = await drifts();
    expect(found).toHaveLength(2);
    expect(found.every(d => d.kind === 'moved')).toBe(true);
  });

  it('proposes the line where the symbol actually is now', async () => {
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    const found = await drifts();
    const handler = found.find(d => d.symbol === 'handler')!;
    const other = found.find(d => d.symbol === 'other')!;
    expect(handler.recorded_line).toBe(1);
    expect(handler.suggested_line).toBe(8);
    expect(other.recorded_line).toBe(5);
    expect(other.suggested_line).toBe(12);
  });

  it('names the sidecar that carries the stale block', async () => {
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    expect((await drifts())[0].gal_file).toBe('.guardlink/annotations/src/api.ts.gal');
  });

  it('does not fire when a symbol merely appears on more lines but still covers the anchor', async () => {
    // A second reference to handler is added BELOW; the recorded line is still
    // a line where the symbol appears, so this is not drift.
    await writeFile(join(root, 'src', 'api.ts'), ORIGINAL_SOURCE + '\nconst alias = handler;\n');
    expect(await drifts()).toEqual([]);
  });

  it('offers the other candidates when a symbol appears in several places', async () => {
    await writeFile(join(root, 'src', 'api.ts'),
      `const x = 1;\n${REFACTORED_SOURCE}\nconst alias = handler;\n`);
    const handler = (await drifts()).find(d => d.symbol === 'handler')!;
    expect(handler.candidates!.length).toBeGreaterThan(1);
    expect(handler.candidates).toContain(handler.suggested_line);
  });

  it('picks the occurrence nearest the recorded line', async () => {
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE + '\nconst alias = handler;\n');
    const handler = (await drifts()).find(d => d.symbol === 'handler')!;
    expect(handler.suggested_line).toBe(8);   // the declaration, not the far alias
    expect(handler.candidates!.length).toBe(2);
    expect(Math.max(...handler.candidates!)).toBeGreaterThan(8);
  });
});

describe('GL-505 — distinguishes the cases a human must resolve', () => {
  it('a renamed symbol is symbol_gone, with no proposed line', async () => {
    await writeFile(join(root, 'src', 'api.ts'), ORIGINAL_SOURCE.replace(/\bother\b/, 'renamed'));
    const found = await drifts();
    const gone = found.find(d => d.symbol === 'other')!;
    expect(gone.kind).toBe('symbol_gone');
    expect(gone.suggested_line).toBeUndefined();
    expect(gone.message).toContain('rewriting');
  });

  it('a deleted file is file_gone', async () => {
    await rm(join(root, 'src', 'api.ts'));
    const found = await drifts();
    expect(found).toHaveLength(2);
    expect(found.every(d => d.kind === 'file_gone')).toBe(true);
    expect(found[0].suggested_line).toBeUndefined();
  });

  it('a file truncated above the anchor is line_gone', async () => {
    // Symbol removed AND the file shortened past the recorded line: the anchor
    // has nowhere to point, and neither branch may invent one.
    await writeFile(join(root, 'src', 'api.ts'), 'export function handler(req) {\n  return req;\n}\n');
    const found = await drifts();
    const other = found.find(d => d.symbol === 'other')!;
    expect(other.kind).toBe('line_gone');
    expect(other.suggested_line).toBeUndefined();
  });

  it('skips blocks with no symbol: rather than guessing at them', async () => {
    await writeFile(galPath(), '@source file:src/api.ts line:1\n@audit #api -- "no symbol"\n');
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    expect(await drifts()).toEqual([]);
  });

  it('ignores inline annotations entirely — they move with their code', async () => {
    await rm(galPath());
    await writeFile(join(root, 'src', 'inline.ts'),
      '/**\n * @audit #api -- "inline"\n */\nexport function thing() { return 1; }\n');
    expect(await drifts()).toEqual([]);
  });
});

describe('GL-505 — reports, does not repair', () => {
  it('findAnchorDrift leaves the sidecar untouched', async () => {
    const before = await readFile(galPath(), 'utf-8');
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    await drifts();
    expect(await readFile(galPath(), 'utf-8')).toBe(before);
  });

  it('applyReanchor with dryRun reports the file but writes nothing', async () => {
    const before = await readFile(galPath(), 'utf-8');
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    const { updated } = applyReanchor(root, await drifts(), true);
    expect(updated).toEqual(['.guardlink/annotations/src/api.ts.gal']);
    expect(await readFile(galPath(), 'utf-8')).toBe(before);
  });
});

describe('GL-505 — applyReanchor, when explicitly confirmed', () => {
  it('rewrites the @source lines and the drift is then gone', async () => {
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    const { updated, skipped } = applyReanchor(root, await drifts());
    expect(updated).toEqual(['.guardlink/annotations/src/api.ts.gal']);
    expect(skipped).toEqual([]);

    const after = await readFile(galPath(), 'utf-8');
    expect(after).toContain('@source file:src/api.ts line:8 symbol:handler');
    expect(after).toContain('@source file:src/api.ts line:12 symbol:other');
    expect(await drifts()).toEqual([]);
  });

  it('the annotations themselves survive the rewrite unchanged', async () => {
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    applyReanchor(root, await drifts());
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(1);
    expect(model.exposures[0].description).toBe('req interpolated into SQL');
    expect(model.exposures[0].location.line).toBe(8);
    expect(model.audits).toHaveLength(1);
    expect(model.audits[0].location.line).toBe(12);
  });

  it('never fabricates an anchor for a vanished symbol — it skips it', async () => {
    await writeFile(join(root, 'src', 'api.ts'),
      REFACTORED_SOURCE.replace(/\bother\b/, 'renamed'));
    const found = await drifts();
    const { updated, skipped } = applyReanchor(root, found);
    expect(updated).toEqual(['.guardlink/annotations/src/api.ts.gal']);
    expect(skipped).toHaveLength(1);
    expect(skipped[0].symbol).toBe('other');

    const after = await readFile(galPath(), 'utf-8');
    expect(after).toContain('@source file:src/api.ts line:8 symbol:handler');
    expect(after).toContain('@source file:src/api.ts line:5 symbol:other');  // untouched
  });

  it('is idempotent — a second apply finds nothing left to do', async () => {
    await writeFile(join(root, 'src', 'api.ts'), REFACTORED_SOURCE);
    applyReanchor(root, await drifts());
    expect(applyReanchor(root, await drifts()).updated).toEqual([]);
  });
});
