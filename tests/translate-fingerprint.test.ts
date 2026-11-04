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
        .toBe('cabbf79346d99f114fdb7ca3e2bd19e226fc7cd55794642a93ecd4b75dc501cb');
      expect(fingerprint(prompt)).toBe('9cfd6b5a9041ce993dceea48e017f7f6e7b4b9dce35295e550f94ceefb3ce77e');
      expect(buildTranslatePrompt('Generate templates', '/project', null, { contract: 'scanner' })).toBe(prompt);
    } finally {
      vi.unstubAllEnvs();
      rmSync(references, { recursive: true, force: true });
    }
  });
});
