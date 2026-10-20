import { execSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAtRef, diffModels, formatDiff } from '../src/diff/index.js';
import { parseProject } from '../src/parser/parse-project.js';

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

describe('diff against a base ref in an inline-mode repository', () => {
  const run = (root: string, cmd: string) => execSync(cmd, { cwd: root, stdio: 'pipe' });

  async function inlineRepo(): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-diff-inline-'));
    run(root, 'git init');
    run(root, 'git config user.name "GuardLink Tests"');
    run(root, 'git config user.email "guardlink-tests@example.com"');
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await writeFile(
      join(root, '.guardlink', 'definitions.py'),
      [
        '# @asset Svc.Db (#db) -- "Storage"',
        '# @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input reaches the query"',
        '# @control Parameterized_Queries (#prepared) -- "Bound parameters"',
      ].join('\n'),
    );
    // One file: the exposure sits in one function, the same-pair mitigation in another.
    // The docstring comes first because a file's first comment binds to the whole file.
    await writeFile(
      join(root, 'db.py'),
      [
        '"""Expense queries."""',
        '',
        '',
        '# @exposes #db to #sqli [critical] cwe:CWE-89 -- "category is formatted into the SELECT"',
        'def find_expenses(category):',
        '    return q("SELECT * FROM e WHERE c = \'%s\'" % category)',
        '',
        '',
        '# @mitigates #db against #sqli using #prepared -- "the INSERT binds its parameters"',
        'def insert_expense(amount):',
        '    return q("INSERT INTO e VALUES (?)", (amount,))',
        '',
      ].join('\n'),
    );
    await writeFile(join(root, 'other.py'), 'def unrelated():\n    return 1\n');
    run(root, 'git add .');
    run(root, 'git commit -m base');
    return root;
  }

  it('does not report an unchanged exposure as new when its same-pair mitigation is in another function', async () => {
    const root = await inlineRepo();
    try {
      // The head differs from the base only in a file with no annotations.
      await writeFile(join(root, 'other.py'), 'def unrelated():\n    return 2\n');
      run(root, 'git commit -am head');

      const { model: head } = await parseProject({ root, project: 'tmp' });
      const base = await parseAtRef(root, 'HEAD~1', 'tmp');
      const diff = diffModels(base, head);

      expect(diff.newUnmitigatedExposures).toEqual([]);
      expect(diff.resolvedExposures).toEqual([]);
      expect(diff.summary.newUnmitigated).toBe(0);
      expect(diff.summary.riskDelta).toBe('unchanged');
      expect(formatDiff(diff)).toBe('No threat model changes detected.');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('still reports an exposure added in another function as new', async () => {
    const root = await inlineRepo();
    try {
      await writeFile(
        join(root, 'db.py'),
        [
          '"""Expense queries."""',
          '',
          '',
          '# @exposes #db to #sqli [critical] cwe:CWE-89 -- "category is formatted into the SELECT"',
          'def find_expenses(category):',
          '    return q("SELECT * FROM e WHERE c = \'%s\'" % category)',
          '',
          '',
          '# @exposes #db to #sqli [critical] cwe:CWE-89 -- "the name is formatted into the DELETE"',
          'def delete_expense(name):',
          '    return q("DELETE FROM e WHERE n = \'%s\'" % name)',
          '',
          '',
          '# @mitigates #db against #sqli using #prepared -- "the INSERT binds its parameters"',
          'def insert_expense(amount):',
          '    return q("INSERT INTO e VALUES (?)", (amount,))',
          '',
        ].join('\n'),
      );
      run(root, 'git commit -am head');

      const { model: head } = await parseProject({ root, project: 'tmp' });
      const base = await parseAtRef(root, 'HEAD~1', 'tmp');
      const diff = diffModels(base, head);

      expect(diff.newUnmitigatedExposures).toHaveLength(1);
      expect(diff.newUnmitigatedExposures[0].location.line).toBe(9);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
