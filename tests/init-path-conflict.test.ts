/**
 * Regression tests for agent-file path-type conflicts during init/sync.
 *
 * Context: Cursor supports multiple rules layouts — legacy single-file `.cursorrules`,
 * legacy single-file `.cursor/rules`, and the newer `.cursor/rules/` directory of `.mdc`.
 * GuardLink writes `.cursor/rules/guardlink.mdc`. When `.cursor/rules` already exists as a
 * FILE (legacy layout), pre-fix init threw a raw ENOTDIR and aborted.
 *
 * Fixed behavior:
 *   CASE A (mergeable): `.cursor/rules` is a FILE -> merge GuardLink's block INTO that file
 *     (marker-based, preserves user content, idempotent). init completes.
 *   CASE B (unmergeable): an agent path like `CLAUDE.md` exists as a DIRECTORY -> skip with
 *     a clear reason (no safe merge). init completes.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject } from '../src/init/index.js';

describe('init — agent-file path-type conflicts', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'guardlink-pathconflict-'));
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0' }));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  // ── CASE A: legacy single-file .cursor/rules → merge, don't crash, don't skip ──

  const LEGACY = 'my custom cursor rules\nalways use tabs\n';

  it('does NOT throw when .cursor/rules exists as a FILE (the reported ENOTDIR repro)', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), LEGACY);
    expect(() => initProject({ root: tmp })).not.toThrow();
  });

  it('MERGES GuardLink into the existing .cursor/rules file, preserving user content', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), LEGACY);

    initProject({ root: tmp });

    const rulesPath = join(tmp, '.cursor', 'rules');
    // Still a file (not clobbered into a directory).
    expect(statSync(rulesPath).isFile()).toBe(true);
    const after = readFileSync(rulesPath, 'utf-8');
    // User's original content survives.
    expect(after).toContain('my custom cursor rules');
    expect(after).toContain('always use tabs');
    // GuardLink block was injected.
    expect(after).toContain('GuardLink');
  });

  it('merge is idempotent — running init twice does not duplicate the GuardLink block', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), LEGACY);

    initProject({ root: tmp });
    initProject({ root: tmp, force: true });

    const after = readFileSync(join(tmp, '.cursor', 'rules'), 'utf-8');
    // Marker appears exactly once.
    const occurrences = after.split('guardlink:begin').length - 1;
    expect(occurrences).toBe(1);
    // User content still intact.
    expect(after).toContain('my custom cursor rules');
  });

  it('still creates .guardlink/ and other agent files alongside the merge', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), LEGACY);

    const result = initProject({ root: tmp });
    expect(existsSync(join(tmp, '.guardlink', 'config.json'))).toBe(true);
    const madeAgentFile = existsSync(join(tmp, 'CLAUDE.md')) || existsSync(join(tmp, 'AGENTS.md'));
    expect(madeAgentFile).toBe(true);
    // The merge is reported as an update, not a skip.
    const merged = result.updated.some(u => /merged into existing \.cursor\/rules/.test(u));
    expect(merged).toBe(true);
  });

  // ── CASE B: unmergeable directory-where-file-expected → skip, don't crash ──

  it('handles the MIRROR case: an agent FILE path that exists as a DIRECTORY (skip, no crash)', () => {
    mkdirSync(join(tmp, 'CLAUDE.md'));

    expect(() => initProject({ root: tmp })).not.toThrow();

    const result = initProject({ root: tmp, force: true });
    const skippedText = result.skipped.join('\n');
    expect(skippedText).toMatch(/CLAUDE\.md/);
    // Directory left as-is, not clobbered.
    expect(statSync(join(tmp, 'CLAUDE.md')).isDirectory()).toBe(true);
  });

  // ── General robustness ──

  it('is idempotent across mixed conflicts — repeated init never throws', () => {
    mkdirSync(join(tmp, '.cursor'));
    writeFileSync(join(tmp, '.cursor', 'rules'), LEGACY);
    mkdirSync(join(tmp, 'CLAUDE.md'));

    expect(() => {
      initProject({ root: tmp });
      initProject({ root: tmp });
      initProject({ root: tmp, force: true });
    }).not.toThrow();
  });

  it('a clean repo (no conflicts) initializes with zero path-conflict skips', () => {
    const result = initProject({ root: tmp });
    expect(existsSync(join(tmp, '.guardlink', 'config.json'))).toBe(true);
    const conflictSkips = result.skipped.filter(s => /exists as a (file|directory)/.test(s));
    expect(conflictSkips).toEqual([]);
  });
});
