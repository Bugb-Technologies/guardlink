import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseProject } from '../src/parser/parse-project.js';
import { applyReviewAction, getReviewableExposures } from '../src/review/index.js';

describe('review with externalized annotations', () => {
  it('writes review annotations back to the .gal source file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-review-gal-'));

    try {
      await mkdir(join(root, '.guardlink', 'annotations'), { recursive: true });
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(
        join(root, '.guardlink', 'definitions.ts'),
        [
          '// @asset App.API (#api) -- "Standalone API asset"',
          '// @threat XSS (#xss) [high] cwe:CWE-79 -- "Unescaped output"',
        ].join('\n'),
      );
      await writeFile(
        join(root, '.guardlink', 'annotations', 'security.gal'),
        [
          '@source file:src/api.ts line:1 symbol:renderProfile',
          '@exposes #api to #xss [high] -- "Rendered HTML lacks output encoding"',
        ].join('\n'),
      );
      await writeFile(join(root, 'src', 'api.ts'), 'export function renderProfile() { return "<div>"; }\n');

      const { model } = await parseProject({ root, project: 'tmp' });
      const [reviewable] = getReviewableExposures(model);
      expect(reviewable).toBeDefined();

      await applyReviewAction(root, reviewable, {
        decision: 'remediate',
        justification: 'Add output encoding before release',
      });

      const galContent = await readFile(join(root, '.guardlink', 'annotations', 'security.gal'), 'utf-8');
      const sourceContent = await readFile(join(root, 'src', 'api.ts'), 'utf-8');

      expect(galContent).toContain('@audit #api -- "Planned remediation: Add output encoding before release');
      expect(sourceContent).not.toContain('@audit');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not cross into the next @source block during review writeback', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-review-source-block-'));

    try {
      await mkdir(join(root, '.guardlink', 'annotations'), { recursive: true });
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(
        join(root, '.guardlink', 'definitions.ts'),
        [
          '// @asset App.API (#api) -- "Standalone API asset"',
          '// @threat XSS (#xss) [high] cwe:CWE-79 -- "Unescaped output"',
        ].join('\n'),
      );
      await writeFile(
        join(root, '.guardlink', 'annotations', 'security.gal'),
        [
          '@source file:src/api.ts line:1 symbol:firstHandler',
          '@exposes #api to #xss [high] -- "First exposure"',
          '@source file:src/api.ts line:10 symbol:secondHandler',
          '@exposes #api to #xss [high] -- "Second exposure"',
        ].join('\n'),
      );
      await writeFile(join(root, 'src', 'api.ts'), 'export const api = true;\n');

      const { model } = await parseProject({ root, project: 'tmp' });
      const [firstReviewable] = getReviewableExposures(model);

      await applyReviewAction(root, firstReviewable, {
        decision: 'remediate',
        justification: 'Fix the first block only',
      });

      const galLines = (await readFile(join(root, '.guardlink', 'annotations', 'security.gal'), 'utf-8')).split('\n');
      const firstAuditIndex = galLines.findIndex(line => line.includes('Fix the first block only'));
      const secondSourceIndex = galLines.findIndex(line => line.startsWith('@source file:src/api.ts line:10'));

      expect(firstAuditIndex).toBeGreaterThan(0);
      expect(firstAuditIndex).toBeLessThan(secondSourceIndex);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('assigns unique review IDs to multiple exposures at the same logical source location', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-review-ids-'));

    try {
      await mkdir(join(root, '.guardlink', 'annotations'), { recursive: true });
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(
        join(root, '.guardlink', 'definitions.ts'),
        [
          '// @asset App.API (#api) -- "Standalone API asset"',
          '// @threat XSS (#xss) [high] cwe:CWE-79 -- "Unescaped output"',
          '// @threat Info_Disclosure (#info-disclosure) [low] cwe:CWE-200 -- "Sensitive output"',
        ].join('\n'),
      );
      await writeFile(
        join(root, '.guardlink', 'annotations', 'security.gal'),
        [
          '@source file:src/api.ts line:1 symbol:renderProfile',
          '@exposes #api to #xss [high] -- "First exposure"',
          '@exposes #api to #info-disclosure [low] -- "Second exposure"',
        ].join('\n'),
      );
      await writeFile(join(root, 'src', 'api.ts'), 'export function renderProfile() { return "<div>"; }\n');

      const { model } = await parseProject({ root, project: 'tmp' });
      const reviewables = getReviewableExposures(model);

      expect(reviewables).toHaveLength(2);
      expect(new Set(reviewables.map(r => r.id)).size).toBe(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not treat decorators as GuardLink annotations during writeback', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-review-decorator-'));

    try {
      await mkdir(join(root, '.guardlink'), { recursive: true });
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(
        join(root, '.guardlink', 'definitions.ts'),
        [
          '// @asset App.API (#api) -- "Decorator-backed API asset"',
          '// @threat XSS (#xss) [high] cwe:CWE-79 -- "Unescaped output"',
        ].join('\n'),
      );
      await writeFile(
        join(root, 'src', 'api.ts'),
        [
          '// @exposes #api to #xss [high] -- "Decorator-backed endpoint"',
          '@Component()',
          'export class ApiController {}',
        ].join('\n'),
      );

      const { model } = await parseProject({ root, project: 'tmp' });
      const [reviewable] = getReviewableExposures(model);
      await applyReviewAction(root, reviewable, {
        decision: 'remediate',
        justification: 'Keep remediation above decorator',
      });

      const sourceLines = (await readFile(join(root, 'src', 'api.ts'), 'utf-8')).split('\n');
      expect(sourceLines[1]).toContain('@audit #api');
      expect(sourceLines[2]).toBe('@Component()');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('uses valid HTML comment syntax when writing back review annotations', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-review-html-'));

    try {
      await mkdir(join(root, '.guardlink'), { recursive: true });
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(
        join(root, '.guardlink', 'definitions.ts'),
        [
          '// @asset App.Web (#web) -- "HTML rendering asset"',
          '// @threat XSS (#xss) [high] cwe:CWE-79 -- "Unescaped output"',
        ].join('\n'),
      );
      await writeFile(
        join(root, 'src', 'index.html'),
        [
          '<!-- @exposes #web to #xss [high] -- "Unsafe HTML rendering" -->',
          '<div>Hello</div>',
        ].join('\n'),
      );

      const { model } = await parseProject({ root, project: 'tmp' });
      const [reviewable] = getReviewableExposures(model);
      await applyReviewAction(root, reviewable, {
        decision: 'remediate',
        justification: 'Escape output before rendering',
      });

      const htmlContent = await readFile(join(root, 'src', 'index.html'), 'utf-8');
      expect(htmlContent).toContain('<!-- @audit #web -- "Planned remediation: Escape output before rendering');
      expect(htmlContent).not.toContain('// @audit');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps raw .gal continuation lines in the same review block', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-review-gal-continuation-'));

    try {
      await mkdir(join(root, '.guardlink', 'annotations'), { recursive: true });
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(
        join(root, '.guardlink', 'definitions.ts'),
        [
          '// @asset App.API (#api) -- "Standalone API asset"',
          '// @threat XSS (#xss) [high] cwe:CWE-79 -- "Unescaped output"',
        ].join('\n'),
      );
      await writeFile(
        join(root, '.guardlink', 'annotations', 'security.gal'),
        [
          '@source file:src/api.ts line:1 symbol:renderProfile',
          '@exposes #api to #xss [high] -- "First sentence"',
          '-- "Second sentence"',
          '@comment -- "Block context"',
        ].join('\n'),
      );
      await writeFile(join(root, 'src', 'api.ts'), 'export function renderProfile() { return "<div>"; }\n');

      const { model } = await parseProject({ root, project: 'tmp' });
      const [reviewable] = getReviewableExposures(model);
      await applyReviewAction(root, reviewable, {
        decision: 'remediate',
        justification: 'Preserve continuation lines',
      });

      const galLines = (await readFile(join(root, '.guardlink', 'annotations', 'security.gal'), 'utf-8')).split('\n');
      const continuationIndex = galLines.findIndex(line => line === '-- "Second sentence"');
      const auditIndex = galLines.findIndex(line => line.includes('Preserve continuation lines'));

      expect(continuationIndex).toBeGreaterThan(0);
      expect(auditIndex).toBeGreaterThan(continuationIndex);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
