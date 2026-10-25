/**
 * Each physical file is scanned once, whatever path reaches it.
 *
 * fast-glob follows directory symlinks, so a repository that links one
 * directory into another (`proxy/enterprise -> ../../enterprise`) put every
 * file under the link in the scan twice: once at its own path and once
 * through the link. The second copy re-declared every `#id` defined there, so
 * `validate` failed with `Duplicate identifier` errors pointing at the same
 * line of the same file, and the file counts carried the linked files twice.
 *
 * The scan now keeps one path per real path, preferring the file's own path.
 * A link is still followed, so a file reachable only through one — a link to a
 * directory the scan excludes, or a link to a single file — keeps its
 * annotations.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { clearAnnotations } from '../src/parser/clear.js';

const DEFS = `/**
 * @asset Gateway (#gateway) -- "Request gateway"
 * @threat Prompt_Injection (#prompt-injection) -- "Hostile model input"
 */
export {};
`;

const GUARD = `/**
 * @control Model_Guard (#model-guard) -- "Screens model input"
 * @mitigates #gateway against #prompt-injection using #model-guard
 */
export function guard() {}
`;

let root: string;

function write(rel: string, body: string): void {
  const abs = join(root, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, body);
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'guardlink-symlink-'));
  write('.guardlink/definitions.ts', DEFS);
  write('enterprise/guard.ts', GUARD);
  write('src/app.ts', 'export const app = 1;\n');
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('scanning a project with symlinks', () => {
  it('scans a file reached through a directory symlink once, at its own path', async () => {
    mkdirSync(join(root, 'src/proxy'), { recursive: true });
    symlinkSync('../../enterprise', join(root, 'src/proxy/enterprise'));

    const { model, diagnostics } = await parseProject({ root, project: 't' });

    expect(diagnostics.filter(d => d.code === 'duplicate-id')).toEqual([]);
    expect(model.controls.map(c => c.id)).toEqual(['model-guard']);
    expect(model.mitigations).toHaveLength(1);
    expect(model.mitigations[0].location.file).toBe('enterprise/guard.ts');
    expect(model.annotated_files).toEqual(['.guardlink/definitions.ts', 'enterprise/guard.ts']);
    expect(model.unannotated_files).toEqual(['src/app.ts']);
    // definitions.ts, enterprise/guard.ts, src/app.ts — not four.
    expect(model.source_files).toBe(3);
  });

  it('prefers the file\'s own path over a link path that sorts before it', async () => {
    symlinkSync('enterprise', join(root, 'app'));

    const { model, diagnostics } = await parseProject({ root, project: 't' });

    expect(diagnostics.filter(d => d.code === 'duplicate-id')).toEqual([]);
    expect(model.mitigations.map(m => m.location.file)).toEqual(['enterprise/guard.ts']);
    expect(model.source_files).toBe(3);
  });

  it('keeps annotations a file has only through a link into an excluded directory', async () => {
    // tests/ is excluded by default; the link is the only path the scan sees.
    write('tests/helpers/guard.ts', GUARD);
    rmSync(join(root, 'enterprise'), { recursive: true });
    symlinkSync('../tests/helpers', join(root, 'src/helpers'));

    const { model, diagnostics } = await parseProject({ root, project: 't' });

    expect(diagnostics.filter(d => d.level === 'error')).toEqual([]);
    expect(model.controls.map(c => c.id)).toEqual(['model-guard']);
    expect(model.mitigations[0].location.file).toBe('src/helpers/guard.ts');
  });

  it('keeps annotations a file has only through a file symlink', async () => {
    write('shared/guard.ts.txt', GUARD);
    rmSync(join(root, 'enterprise'), { recursive: true });
    symlinkSync('../shared/guard.ts.txt', join(root, 'src/guard.ts'));

    const { model } = await parseProject({ root, project: 't' });

    expect(model.controls.map(c => c.id)).toEqual(['model-guard']);
    expect(model.mitigations[0].location.file).toBe('src/guard.ts');
  });

  it('scans a file linked from two places under one of them', async () => {
    write('tests/guard.ts', GUARD);
    rmSync(join(root, 'enterprise'), { recursive: true });
    symlinkSync('../tests/guard.ts', join(root, 'src/b.ts'));
    symlinkSync('../tests/guard.ts', join(root, 'src/a.ts'));

    const { model, diagnostics } = await parseProject({ root, project: 't' });

    expect(diagnostics.filter(d => d.code === 'duplicate-id')).toEqual([]);
    expect(model.mitigations.map(m => m.location.file)).toEqual(['src/a.ts']);
  });

  it('clears a file reached through a directory symlink once', async () => {
    mkdirSync(join(root, 'src/proxy'), { recursive: true });
    symlinkSync('../../enterprise', join(root, 'src/proxy/enterprise'));

    const result = await clearAnnotations({ root, dryRun: true });

    expect(result.modifiedFiles).toEqual(['enterprise/guard.ts']);
    expect(readFileSync(join(root, 'enterprise/guard.ts'), 'utf-8')).toBe(GUARD);
  });
});
