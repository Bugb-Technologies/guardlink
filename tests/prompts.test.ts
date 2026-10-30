import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildAnnotatePrompt, buildTranslatePrompt } from '../src/agents/prompts.js';

describe('buildAnnotatePrompt', () => {
  it('builds inline-specific guidance', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-prompt-inline-'));

    try {
      const prompt = buildAnnotatePrompt('annotate auth code', root, null, 'inline');
      expect(prompt).toContain('This run MUST produce annotations as inline source comments.');
      expect(prompt).toContain('You MUST write annotations inline in the source code comments.');
      expect(prompt).toContain('Do NOT externalize annotations into `.gal` files when this mode is selected');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('builds external-specific guidance', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-prompt-external-'));

    try {
      const prompt = buildAnnotatePrompt('annotate auth code', root, null, 'external');
      expect(prompt).toContain('This run MUST produce annotations as externalized .gal files.');
      expect(prompt).toContain('You MUST write annotations into associated standalone `.gal` files');
      expect(prompt).toContain('.guardlink/annotations/');
      expect(prompt).toContain('@source file:<path> line:<n> [symbol:<name>]');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('buildTranslatePrompt', () => {
  it('frames the repeatable developer check while preserving the author-only mission', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-prompt-translate-'));
    try {
      const prompt = buildTranslatePrompt('check changed auth code', root, null);
      expect(prompt).toContain('check changed auth code');
      expect(prompt).toContain('fast, per-change prompt-builder');
      expect(prompt).toContain('dev testing without Bravos');
      expect(prompt).toContain('keeping annotations accurate after each round');
      expect(prompt).toContain('the developer runs the generated tests separately');
      expect(prompt).toContain('A quick check is not a full\npentest');
      expect(prompt).toContain('runs that can take hours');
      expect(prompt).toContain('Do NOT execute templates. Only author template files.');
      expect(prompt).toContain('Do not run active scans unless user explicitly asks.');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
