import { describe, it, expect } from 'vitest';
import { formatConfidence } from '../src/analyze/format.js';

describe('formatConfidence', () => {
  // ── number input ──
  it('formats integer percentage as N%', () => {
    expect(formatConfidence(50)).toBe('50%');
    expect(formatConfidence(0)).toBe('0%');
    expect(formatConfidence(100)).toBe('100%');
  });

  it('rounds floats and clamps out-of-range numbers', () => {
    expect(formatConfidence(72.6)).toBe('73%');
    expect(formatConfidence(-5)).toBe('0%');
    expect(formatConfidence(150)).toBe('100%');
  });

  it('rejects non-finite numbers as missing', () => {
    expect(formatConfidence(NaN)).toBe('—');
    expect(formatConfidence(Infinity)).toBe('—');
  });

  // ── string input ──
  it('uppercases severity-style strings', () => {
    expect(formatConfidence('high')).toBe('HIGH');
    expect(formatConfidence('medium')).toBe('MEDIUM');
    expect(formatConfidence('Low')).toBe('LOW');
  });

  it('treats numeric strings as percentages', () => {
    expect(formatConfidence('50')).toBe('50%');
    expect(formatConfidence('50%')).toBe('50%');
    expect(formatConfidence('  72  ')).toBe('72%');
  });

  it('returns em-dash for empty / whitespace strings', () => {
    expect(formatConfidence('')).toBe('—');
    expect(formatConfidence('   ')).toBe('—');
  });

  // ── missing / unknown ──
  it('returns em-dash for null and undefined', () => {
    expect(formatConfidence(null)).toBe('—');
    expect(formatConfidence(undefined)).toBe('—');
  });

  it('returns em-dash for non-renderable types instead of leaking [object Object]', () => {
    expect(formatConfidence({})).toBe('—');
    expect(formatConfidence([])).toBe('—');
    expect(formatConfidence(true)).toBe('—');
  });

  // ── never throws on adversarial input ──
  it('never throws regardless of input shape', () => {
    const adversarial: unknown[] = [
      Symbol('x'), () => 1, BigInt(1), new Date(), /regex/, new Error('boom'),
    ];
    for (const v of adversarial) {
      expect(() => formatConfidence(v)).not.toThrow();
    }
  });
});
