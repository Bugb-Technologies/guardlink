import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildTranslatePrompt, SCANNER_SAFETY_REQUIREMENTS } from '../src/agents/prompts.js';

const fingerprint = (text: string) => createHash('sha256').update(text).digest('hex');

describe('reviewed scanner workflow fingerprint', () => {
  it('pins the compatibility boundary and the complete prompt without weakening the default contract', () => {
    const references = mkdtempSync(join(tmpdir(), 'guardlink-fingerprint-'));
    vi.stubEnv('GUARDLINK_CXG_ROOT', references);
    vi.stubEnv('GUARDLINK_CXG_SKELETON_DIR', references);
    try {
      // Offline prompt construction is supported; no project directory is created.
      const prompt = buildTranslatePrompt('Generate templates', '/project', null);
      expect(prompt).toContain(SCANNER_SAFETY_REQUIREMENTS);
      // Change these reviewed baselines only with intentional prompt changes.
      expect(fingerprint(prompt.replace(SCANNER_SAFETY_REQUIREMENTS, '')))
        .toBe('4ed3254447cab4bdf9eafdf97f2c1ab33e02e1c9f1d7064d2525495d566d3a6e');
      expect(fingerprint(prompt)).toBe('b4543e71377a5054e58c879704676fcfc8b210ae5b98f1cf79e69be398ebe6a3');
      expect(buildTranslatePrompt('Generate templates', '/project', null, { contract: 'scanner' })).toBe(prompt);
    } finally {
      vi.unstubAllEnvs();
      rmSync(references, { recursive: true, force: true });
    }
  });
});
