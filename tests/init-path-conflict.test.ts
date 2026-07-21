/**
 * Regression tests for agent-file path-type conflicts during init/sync.
 *
 * Repro: a project ships an OLDER single-file `.cursor/rules` (a FILE) while GuardLink
 * expects the NEWER `.cursor/rules/` directory layout and tries to write
 * `.cursor/rules/guardlink.mdc`. Pre-fix this threw a raw `ENOTDIR` and aborted the whole
 * init. Post-fix: init skips just that agent file (with a reason) and completes.
 *
 * Also covers the mirror case (a directory where a file is expected -> EISDIR) and
 * confirms `.guardlink/` and non-conflicting agent files are still created.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject } from '../src/init/index.js';

describe('init — agent-file path-type conflicts', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'guardlink-pathconflict-'));
    // Minimal project marker so detectProject has something to work with.
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0' }));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('does NOT throw when .cursor/rules exists as a FILE (the reported ENOTDIR repro)', () => {
    // Recreate the exact juice-shop-copy situation: .cursor/ is a dir, .cursor/rules is a FILE.
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), 'old single-file cursor rules\n');

    // Pre-fix this threw ENOTDIR. Post-fix it must complete without throwing.
    expect(() => initProject({ root: tmp })).not.toThrow();
  });

  it('still creates .guardlink/ and skips only the conflicting agent file', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), 'old single-file cursor rules\n');

    const result = initProject({ root: tmp });

    // Core scaffold still created.
    expect(existsSync(join(tmp, '.guardlink'))).toBe(true);
    expect(existsSync(join(tmp, '.guardlink', 'config.json'))).toBe(true);

    // The conflicting .mdc write was skipped with a reason mentioning the path.
    const skippedText = result.skipped.join('\n');
    expect(skippedText).toMatch(/rules/);

    // The pre-existing single-file .cursor/rules is left untouched (not clobbered into a dir).
    expect(statSync(join(tmp, '.cursor', 'rules')).isFile()).toBe(true);
  });

  it('creates other, non-conflicting agent files normally', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), 'old single-file cursor rules\n');

    const result = initProject({ root: tmp });

    // A markdown agent file with no path conflict should still be created.
    const madeSomething =
      result.created.some(f => f.endsWith('.md')) ||
      existsSync(join(tmp, 'CLAUDE.md')) ||
      existsSync(join(tmp, 'AGENTS.md'));
    expect(madeSomething).toBe(true);
  });

  it('handles the MIRROR case: a target agent FILE path that exists as a DIRECTORY', () => {
    // CLAUDE.md exists as a directory -> writeFileSync would throw EISDIR pre-fix.
    mkdirSync(join(tmp, 'CLAUDE.md'));

    expect(() => initProject({ root: tmp })).not.toThrow();

    const result = initProject({ root: tmp, force: true });
    const skippedText = result.skipped.join('\n');
    expect(skippedText).toMatch(/CLAUDE\.md/);
    // The directory is left as-is, not clobbered.
    expect(statSync(join(tmp, 'CLAUDE.md')).isDirectory()).toBe(true);
  });

  it('is idempotent — running init twice on a conflicted repo still does not throw', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), 'old single-file cursor rules\n');

    expect(() => {
      initProject({ root: tmp });
      initProject({ root: tmp });
      initProject({ root: tmp, force: true });
    }).not.toThrow();
  });

  it('a clean repo (no conflicts) still initializes with zero path-conflict skips', () => {
    const result = initProject({ root: tmp });
    expect(existsSync(join(tmp, '.guardlink', 'config.json'))).toBe(true);
    // No skip reason should mention a path-type conflict on a clean repo.
    const conflictSkips = result.skipped.filter(s => /conflict|exists as a (file|directory)/.test(s));
    expect(conflictSkips).toEqual([]);
  });
});
