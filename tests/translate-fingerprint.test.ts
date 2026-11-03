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
        .toBe('fdf242e4116e1b51e291f84b5c13c4f44dc6514181b9aa1b2edc1442ab08177b');
      expect(fingerprint(prompt)).toBe('50a92202821761eba046a39131c8024bb55531b7572eee4b281a83eb4fd0a58c');
      expect(buildTranslatePrompt('Generate templates', '/project', null, { contract: 'scanner' })).toBe(prompt);
    } finally {
      vi.unstubAllEnvs();
      rmSync(references, { recursive: true, force: true });
    }
  });
});
