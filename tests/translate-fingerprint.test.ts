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
        .toBe('a8c60a1f38644bcf0ecc17d3c674a27f031365365a432154421a8bca8803ab1a');
      expect(fingerprint(prompt)).toBe('d40e96a316b41c82c45a649f7cf646a1bb96bd2416e7768089cdf6a5064c8c3c');
      expect(buildTranslatePrompt('Generate templates', '/project', null, { contract: 'scanner' })).toBe(prompt);
    } finally {
      vi.unstubAllEnvs();
      rmSync(references, { recursive: true, force: true });
    }
  });
});
