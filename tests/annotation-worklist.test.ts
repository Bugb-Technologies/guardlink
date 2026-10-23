/**
 * The annotation worklist: which scanned files still need annotating, and why
 * every other file is left out — without narrowing what the parser reads.
 *
 * The coverage inventory (`unannotated_files`) used to be the scan set minus
 * the annotated files, so it listed a gitignored scratch file, files
 * `.gitattributes` marks linguist-generated or linguist-vendored, a file
 * `.guardlink/config.json` excludes, a minified bundle, a Next.js export and
 * an SVG logo, all as work to do. The fixture below is that case, one file per
 * rule; each is now left out with a reason, and an annotation already written
 * in a left-out file is still in the model.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { compileScopePattern } from '../src/parser/annotation-scope.js';
import { buildAnnotationWorklist, WORKLIST_SCHEMA } from '../src/parser/annotation-worklist.js';
import { fileContext } from '../src/mcp/context.js';
import { buildAnnotatePrompt } from '../src/agents/prompts.js';

let root: string;

function write(rel: string, body: string): void {
  const abs = join(root, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, body);
}

function git(...args: string[]): void {
  execFileSync('git', args, { cwd: root, stdio: 'ignore' });
}

const DEFS = `// @asset Api (#api) -- "Request handler"
// @threat Injection (#injection) -- "Hostile input"
export {};
`;

/** The reported case: one file per rule, staged in a fresh work tree. */
function fixture(config: object = { exclude: ['configured.py'] }): void {
  write('.guardlink/definitions.ts', DEFS);
  write('.guardlink/config.json', JSON.stringify(config));
  write('.gitignore', 'ignored.py\n');
  write('.gitattributes', 'generated.ts linguist-generated\nvendored.js linguist-vendored\n');
  write('app.py', 'def handler(): pass\n');
  write('ignored.py', 'def scratch(): pass\n');
  write('configured.py', 'def configured(): pass\n');
  write('generated.ts', 'export const generated = 1;\n');
  write('vendored.js', 'var vendored = 1;\n');
  write('app.min.js', 'var a=1;\n');
  write('out/index.html', '<html></html>\n');
  write('out/_next/static/chunks/main.js', 'var m=1;\n');
  write('assets/logo.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n');
  git('init', '-q');
  git('add', '-A');
}

const reasons = (model: Awaited<ReturnType<typeof parseProject>>['model']) =>
  Object.fromEntries((model.annotation_scope?.excluded ?? []).map(x => [x.file, x.reason]));

beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'guardlink-worklist-')); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('the annotation worklist', () => {
  it('leaves out every file the reported fixture should not have listed, each with its reason', async () => {
    fixture();
    const { model } = await parseProject({ root, project: 't' });

    expect(model.unannotated_files).toEqual(['app.py']);
    expect(model.annotation_scope?.view).toBe('git');
    expect(reasons(model)).toEqual({
      'app.min.js': 'generated-output',
      'assets/logo.svg': 'asset',
      'configured.py': 'config-exclude',
      'generated.ts': 'linguist-generated',
      'ignored.py': 'gitignored',
      'out/_next/static/chunks/main.js': 'generated-output',
      'out/index.html': 'generated-output',
      'vendored.js': 'linguist-vendored',
    });
    // The denominator is the scope: app.py plus the annotated definitions file.
    expect(model.source_files).toBe(2);
  });

  it('still parses a left-out file: what it already declares stays in the model', async () => {
    fixture();
    write('generated.ts', '// @exposes #api to #injection [high] -- "Generated client passes input through"\nexport const generated = 1;\n');
    write('ignored.py', '# @exposes #api to #injection [low] -- "Scratch handler"\ndef scratch(): pass\n');
    git('add', 'generated.ts');

    const { model } = await parseProject({ root, project: 't' });
    expect(model.exposures.map(e => e.location.file).sort()).toEqual(['generated.ts', 'ignored.py']);
    expect(model.annotated_files).toEqual(expect.arrayContaining(['generated.ts', 'ignored.py']));
    expect(model.unannotated_files).toEqual(['app.py']);

    const worklist = buildAnnotationWorklist(root, model);
    const byPath = new Map(worklist.excluded.map(x => [x.path, x]));
    expect(byPath.get('generated.ts')).toMatchObject({ reason: 'linguist-generated', annotated: true });
    expect(byPath.get('ignored.py')).toMatchObject({ reason: 'gitignored', annotated: true });
  });

  it('reads config.json include: a scanned file no include names is left out', async () => {
    fixture({ include: ['**/*.py'], exclude: ['configured.py'] });
    const { model } = await parseProject({ root, project: 't' });
    expect(model.unannotated_files).toEqual(['app.py']);
    expect(reasons(model)['generated.ts']).toBe('linguist-generated');
    expect(reasons(model)['vendored.js']).toBe('linguist-vendored');
    write('lib/util.rb', 'def util; end\n');
    const again = await parseProject({ root, project: 't' });
    expect(reasons(again.model)['lib/util.rb']).toBe('outside-config-include');
  });

  it('reads config.json exclude the way init writes it: a bare name at any depth, a path and everything under it', async () => {
    write('src/gen/client.ts', 'export {};\n');
    write('pkg/dist2/x.ts', 'export {};\n');
    write('pkg/keep.ts', 'export {};\n');
    write('.guardlink/config.json', JSON.stringify({ exclude: ['dist2', 'src/gen'] }));
    const { model } = await parseProject({ root, project: 't' });
    expect(model.unannotated_files).toEqual(['pkg/keep.ts']);
    expect(reasons(model)).toEqual({ 'pkg/dist2/x.ts': 'config-exclude', 'src/gen/client.ts': 'config-exclude' });
  });

  it('lets the user override the default rules: -linguist-generated and worklist.keep', async () => {
    fixture({ worklist: { keep: ['assets/*.svg'] } });
    write('.gitattributes', 'app.min.js -linguist-generated\n');
    git('add', '-A');
    const { model } = await parseProject({ root, project: 't' });
    expect(model.unannotated_files).toEqual(expect.arrayContaining(['app.min.js', 'assets/logo.svg', 'configured.py']));
  });

  it('does not exclude SVG as a format: one outside an asset directory is work', async () => {
    write('templates/badge.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n');
    write('public/icon.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n');
    const { model } = await parseProject({ root, project: 't' });
    expect(model.unannotated_files).toEqual(['templates/badge.svg']);
    expect(reasons(model)).toEqual({ 'public/icon.svg': 'asset' });
  });

  it('calls a directory a Next.js export only when it holds _next/ beside its own HTML', async () => {
    write('web/out/404.html', '<html></html>\n');
    write('web/out/_next/static/app.js', 'var a=1;\n');
    write('src/out/handler.ts', 'export {};\n');
    const { model } = await parseProject({ root, project: 't' });
    expect(model.unannotated_files).toEqual(['src/out/handler.ts']);
    expect(reasons(model)).toEqual({ 'web/out/404.html': 'generated-output', 'web/out/_next/static/app.js': 'generated-output' });
  });

  it('keeps a tracked file in scope even when a .gitignore pattern matches it', async () => {
    fixture();
    git('add', '-f', 'ignored.py');
    const { model } = await parseProject({ root, project: 't' });
    expect(model.unannotated_files).toEqual(['app.py', 'ignored.py']);
  });

  it('outside a work tree there is no .gitignore to honour, and the view says so', async () => {
    write('.gitignore', 'ignored.py\n');
    write('ignored.py', 'def scratch(): pass\n');
    const { model } = await parseProject({ root, project: 't' });
    expect(model.annotation_scope?.view).toBe('walk');
    expect(model.unannotated_files).toEqual(['ignored.py']);
  });

  it('builds one partition of the repository for a consumer, agreeing with the model', async () => {
    fixture();
    write('docs/guide.md', '# Guide\n');
    write('assets/photo.png', 'png');
    write('tests/app_test.py', 'def test(): pass\n');
    git('add', '-A');
    const { model } = await parseProject({ root, project: 't' });
    const w = buildAnnotationWorklist(root, model);

    expect(w.schema).toBe(WORKLIST_SCHEMA);
    expect(w.worklist).toEqual([{ path: 'app.py', reason: 'unannotated' }]);
    expect(w.annotated).toEqual([]);
    const byPath = Object.fromEntries(w.excluded.map(x => [x.path, x.reason]));
    expect(byPath).toMatchObject({
      'docs/guide.md': 'unsupported-extension',
      'assets/photo.png': 'asset',
      'tests/app_test.py': 'built-in-exclude',
      '.guardlink/definitions.ts': 'guardlink-data',
      'ignored.py': 'gitignored',
    });
    for (const x of model.annotation_scope!.excluded) expect(byPath[x.file]).toBe(x.reason);
    expect(w.summary.excluded).toBe(w.excluded.length);
    expect(Object.values(w.summary.excluded_by_reason).reduce((a, b) => a! + b!, 0)).toBe(w.excluded.length);
  });

  it('answers file context for a left-out file as scanned, with the reason', async () => {
    fixture();
    const { model } = await parseProject({ root, project: 't' });
    const ctx = fileContext(model, { file: 'generated.ts', exists: true });
    expect(ctx.status).toBe('scanned_without_annotations');
    expect(ctx.hint).toMatch(/linguist-generated/);
  });

  it('carries the worklist into the coverage prompt, and the left-out files by reason only', async () => {
    fixture();
    const { model } = await parseProject({ root, project: 't' });
    const prompt = buildAnnotatePrompt('annotate the unannotated files', root, model, 'inline', 'coverage');
    expect(prompt).toContain('## Annotation worklist');
    expect(prompt).toContain('  app.py');
    expect(prompt).not.toContain('  vendored.js');
    expect(prompt).toMatch(/Left out of annotation work: 8 scanned file\(s\)/);
    expect(buildAnnotatePrompt('find exploitable bugs', root, model, 'inline', 'exploitable')).not.toContain('## Annotation worklist');
  });
});

describe('scope patterns', () => {
  const m = (pattern: string, path: string) => compileScopePattern(pattern)!(path);

  it('reads a pattern with no slash as a segment at any depth', () => {
    expect(m('dist', 'dist/a.js')).toBe(true);
    expect(m('dist', 'pkg/dist/a.js')).toBe(true);
    expect(m('dist', 'distro/a.js')).toBe(false);
    expect(m('*.min.js', 'web/app.min.js')).toBe(true);
  });

  it('reads a pattern with a slash relative to the root, matching everything under a directory', () => {
    expect(m('**/*.ts', 'a.ts')).toBe(true);
    expect(m('**/*.ts', 'src/deep/a.ts')).toBe(true);
    expect(m('**/*.ts', 'src/a.tsx')).toBe(false);
    expect(m('src/gen', 'src/gen/x.ts')).toBe(true);
    expect(m('/src/gen/', 'lib/src/gen/x.ts')).toBe(false);
    expect(m('**/tests/**', 'a/tests/b.py')).toBe(true);
  });

  it('supports braces and classes', () => {
    expect(m('**/*.{py,rb}', 'x/y.rb')).toBe(true);
    expect(m('**/*.{py,rb}', 'x/y.go')).toBe(false);
    expect(m('v[0-9].ts', 'v1.ts')).toBe(true);
    expect(m('v[!0-9].ts', 'v1.ts')).toBe(false);
  });

  it('ignores an empty pattern', () => {
    expect(compileScopePattern('  ')).toBeNull();
    expect(compileScopePattern('/')).toBeNull();
  });
});
