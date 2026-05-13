import { describe, expect, it } from 'vitest';
import { parseAnnotationModeFlag, resolveAnnotationMode } from '../src/agents/index.js';

describe('annotation mode parsing', () => {
  it('parses --mode external', () => {
    const parsed = parseAnnotationModeFlag('annotate auth --mode external --claude-code');
    expect(parsed.mode).toBe('external');
    expect(parsed.cleanArgs).toBe('annotate auth --claude-code');
    expect(parsed.error).toBeUndefined();
  });

  it('parses --mode inline', () => {
    const parsed = parseAnnotationModeFlag('annotate auth --mode inline --claude-code');
    expect(parsed.mode).toBe('inline');
    expect(parsed.cleanArgs).toBe('annotate auth --claude-code');
    expect(parsed.error).toBeUndefined();
  });

  it('returns an error for invalid --mode values', () => {
    const parsed = parseAnnotationModeFlag('annotate auth --mode wrong --claude-code');
    expect(parsed.error).toBe('Invalid --mode value. Use --mode inline or --mode external.');
  });

  it('rejects invalid CLI mode values', () => {
    expect(() => resolveAnnotationMode('wrong')).toThrow('Invalid annotation mode "wrong". Use "inline" or "external".');
  });
});
