/**
 * Tests for parser diagnostic helpers — specifically diagnosticIcon, which
 * centralizes the level → icon character mapping used by both the CLI
 * (printDiagnostics) and the TUI (status command's diagnostic printer).
 *
 * Also exercises the type contract of ParseDiagnostic.level — constructing
 * one of each level shape catches a missing union member at compile time.
 */
import { describe, it, expect } from 'vitest';
import { diagnosticIcon } from '../src/parser/format.js';
import type { ParseDiagnostic } from '../src/types/index.js';

describe('diagnosticIcon', () => {
  it('returns ✗ for error', () => {
    expect(diagnosticIcon('error')).toBe('✗');
  });

  it('returns ⚠ for warning', () => {
    expect(diagnosticIcon('warning')).toBe('⚠');
  });

  it('returns ✗✗ for fatal (visually distinct from error)', () => {
    expect(diagnosticIcon('fatal')).toBe('✗✗');
  });

  it('all three icons are distinct', () => {
    const icons = new Set([
      diagnosticIcon('error'),
      diagnosticIcon('warning'),
      diagnosticIcon('fatal'),
    ]);
    expect(icons.size).toBe(3);
  });
});

describe('ParseDiagnostic type contract', () => {
  // These are compile-time assertions: if `level` ever stops accepting one
  // of these three string literals, TypeScript fails to build this file.
  // No runtime assertions needed — the test passes as long as it compiles.

  it('accepts a record with level: "error"', () => {
    const d: ParseDiagnostic = {
      level: 'error',
      message: 'malformed annotation',
      file: 'src/auth.ts',
      line: 42,
    };
    expect(d.level).toBe('error');
  });

  it('accepts a record with level: "warning"', () => {
    const d: ParseDiagnostic = {
      level: 'warning',
      message: 'unknown verb',
      file: 'src/auth.ts',
      line: 42,
    };
    expect(d.level).toBe('warning');
  });

  it('accepts a record with level: "fatal"', () => {
    // Vocabulary check — fatal is a valid level in the type even though
    // no code path currently emits one. Reserved for v1.6+ conditions
    // where the model is unsafe to render and the consumer must abort.
    const d: ParseDiagnostic = {
      level: 'fatal',
      message: 'schema version mismatch — model cannot be loaded',
      file: '.guardlink/threat-model.json',
      line: 0,
    };
    expect(d.level).toBe('fatal');
  });
});
