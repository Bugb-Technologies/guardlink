import { execSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAtRef } from '../src/diff/index.js';

describe('parseAtRef', () => {
  it('includes standalone .gal files from git refs', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-diff-'));

    try {
      execSync('git init', { cwd: root, stdio: 'pipe' });
      execSync('git config user.name "GuardLink Tests"', { cwd: root, stdio: 'pipe' });
      execSync('git config user.email "guardlink-tests@example.com"', { cwd: root, stdio: 'pipe' });

      await mkdir(join(root, '.guardlink', 'annotations'), { recursive: true });
      await writeFile(
        join(root, '.guardlink', 'definitions.ts'),
        [
          '// @asset App.API (#api) -- "Main API"',
          '// @threat XSS (#xss) [high] cwe:CWE-79 -- "Unescaped output"',
        ].join('\n'),
      );
      await writeFile(
        join(root, '.guardlink', 'annotations', 'edge.ANNOTATIONS.GAL'),
        '@exposes #api to #xss -- "Rendered HTML lacks output encoding"\n',
      );

      execSync('git add .', { cwd: root, stdio: 'pipe' });
      execSync('git commit -m "Add standalone GAL annotations"', { cwd: root, stdio: 'pipe' });

      const model = await parseAtRef(root, 'HEAD', 'tmp');

      expect(model.assets.map(a => a.id)).toContain('api');
      expect(model.exposures).toHaveLength(1);
      expect(model.exposures[0].location.file).toBe('.guardlink/annotations/edge.ANNOTATIONS.GAL');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
