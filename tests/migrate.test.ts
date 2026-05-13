/**
 * Tests for the migration helpers — specifically ensurePromptMd, which is
 * the v1.4.x → v1.5.x migration path for projects that have `.guardlink/`
 * but not `.guardlink/prompt.md`.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensurePromptMd } from '../src/init/migrate.js';

describe('ensurePromptMd', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'guardlink-migrate-'));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('returns "skipped-no-guardlink-dir" when .guardlink does not exist', () => {
    const result = ensurePromptMd(tmp);
    expect(result).toBe('skipped-no-guardlink-dir');
    expect(existsSync(join(tmp, '.guardlink'))).toBe(false);
    expect(existsSync(join(tmp, '.guardlink', 'prompt.md'))).toBe(false);
  });

  it('returns "created" and writes prompt.md when .guardlink exists but prompt.md does not', () => {
    // Simulate a v1.4.x project: .guardlink/ exists, but no prompt.md
    mkdirSync(join(tmp, '.guardlink'));
    writeFileSync(join(tmp, '.guardlink', 'definitions.ts'), '// definitions\n');

    const result = ensurePromptMd(tmp);
    expect(result).toBe('created');

    const promptPath = join(tmp, '.guardlink', 'prompt.md');
    expect(existsSync(promptPath)).toBe(true);
    expect(readFileSync(promptPath, 'utf-8').length).toBeGreaterThan(0);
  });

  it('returns "exists" and does NOT modify existing prompt.md content', () => {
    mkdirSync(join(tmp, '.guardlink'));
    const promptPath = join(tmp, '.guardlink', 'prompt.md');
    const userContent = '# My Custom Application Description\n\nDo not overwrite this.\n';
    writeFileSync(promptPath, userContent);

    const result = ensurePromptMd(tmp);
    expect(result).toBe('exists');

    // User content preserved exactly
    expect(readFileSync(promptPath, 'utf-8')).toBe(userContent);
  });

  it('is idempotent — second call returns "exists" and is a no-op', () => {
    mkdirSync(join(tmp, '.guardlink'));

    const first = ensurePromptMd(tmp);
    expect(first).toBe('created');
    const firstContent = readFileSync(join(tmp, '.guardlink', 'prompt.md'), 'utf-8');

    const second = ensurePromptMd(tmp);
    expect(second).toBe('exists');
    const secondContent = readFileSync(join(tmp, '.guardlink', 'prompt.md'), 'utf-8');

    expect(secondContent).toBe(firstContent);
  });

  it('does NOT create .guardlink/ directory if missing — defers to init', () => {
    // No .guardlink/ at all; ensurePromptMd should not partial-bootstrap the project.
    const result = ensurePromptMd(tmp);
    expect(result).toBe('skipped-no-guardlink-dir');
    expect(existsSync(join(tmp, '.guardlink'))).toBe(false);
  });
});
