/**
 * D29 — prose that starts with a verb must not fail the build.
 *
 * Every line beginning with `@<known-verb>` that failed to parse was an error,
 * so writing documentation ABOUT GuardLink inside a GuardLink-annotated repo
 * broke that repo's own `validate`. It bit this codebase twice during the defect
 * sweep, once by accident, in an ordinary code comment.
 *
 * The fix is a split on structural evidence, not silence: "you wrote this
 * annotation wrong" is the most useful signal the parser produces, and dropping
 * it would trade a loud wrong answer for a quiet one.
 *
 * The regression that must never happen is in the last describe block: a
 * genuinely malformed annotation still errors.
 */
import { describe, it, expect } from 'vitest';
import { parseLine, structuralEvidence } from '../src/parser/parse-line.js';
import { parseString } from '../src/parser/parse-file.js';

const at = { file: 'p.ts', line: 1 };
const diag = (line: string) => parseLine(line, at).diagnostic;

/** Realistic prose about GuardLink, of the kind that appears in design docs. */
const PROSE = [
  '@feature flag rollout is described below',
  '@exposes was renamed in v1.2',
  '@feature still claims to describe the model, so it is checked too.',
  '@audit annotations are reviewed quarterly by the security team',
  '@exposes is the verb you reach for first',
  '@flows describes how data moves between components',
  '@mitigates and @exposes are opposites',
  '@shield should be avoided unless a human asks',
  '@boundary is used to mark a trust change',
  '@comment can hold anything the other verbs cannot',
];

/** Annotations someone started and got wrong. */
const MALFORMED = [
  '@exposes #api to',
  '@mitigates #api against',
  '@flows #a ->',
  '@boundary between #api and',
  '@exposes App.API to',
  '@mitigates App.API against #sqli using',
  '@validates #ps for',
  '@audit App.API --',
  '@mitigates',
  '@feature',
];

describe('D29 — prose warns, and does not fail validation', () => {
  it.each(PROSE)('%s', (line) => {
    const d = diag(line);
    expect(d, 'must still be reported — never silently dropped').not.toBeNull();
    expect(d!.level).toBe('warning');
    expect(d!.code).toBe('prose-like');
  });

  it('the warning names @shield as the remedy', () => {
    expect(diag(PROSE[0])!.message).toMatch(/@shield:begin/);
  });

  it('the raw line is preserved so the author can see what was skipped', () => {
    expect(diag(PROSE[1])!.raw).toBe(PROSE[1]);
  });
});

describe('D29 — a genuinely malformed annotation still errors (must not regress)', () => {
  it.each(MALFORMED)('%s', (line) => {
    const d = diag(line);
    expect(d, `no diagnostic at all for: ${line}`).not.toBeNull();
    expect(d!.level).toBe('error');
    expect(d!.code).toBe('malformed-annotation');
  });

  it('the error states what convinced it', () => {
    expect(diag('@exposes #api to')!.message).toMatch(/#reference/);
    expect(diag('@exposes App.API to')!.message).toMatch(/`to` keyword/);
    expect(diag('@audit App.API --')!.message).toMatch(/`--` delimiter/);
    expect(diag('@mitigates')!.message).toMatch(/no arguments at all/);
  });
});

describe('D29 — the keyword set is per verb, not global', () => {
  it('`to` is structural for @exposes, which has it in its grammar', () => {
    expect(structuralEvidence('exposes', 'App.API to')).toMatch(/to/);
  });

  it('`to` is NOT structural for @feature, which does not', () => {
    // The measurement that argued against the ruling's global keyword list:
    // this is the exact line that broke this repo's validate during the sweep.
    expect(structuralEvidence('feature', 'still claims to describe the model')).toBeNull();
  });

  it('`from` is structural for @transfers, which owns it', () => {
    expect(structuralEvidence('transfers', '#sqli from #api to #db')).not.toBeNull();
  });

  it('a spaced -- is evidence; an unspaced double hyphen is not', () => {
    expect(structuralEvidence('audit', 'App.API -- "why"')).not.toBeNull();
    expect(structuralEvidence('audit', 'is well--understood by the team')).toBeNull();
  });
});

describe('D29 — unaffected behaviour', () => {
  it('a valid annotation still parses with no diagnostic', () => {
    const r = parseLine('@exposes #api to #sqli [high] -- "x"', at);
    expect(r.annotation).not.toBeNull();
    expect(r.diagnostic).toBeNull();
  });

  it('a non-GuardLink @tag is still ignored entirely', () => {
    expect(diag('@param name The user name')).toBeNull();
    expect(diag('@returns a promise')).toBeNull();
  });

  it('@shield:begin/end still suppresses everything between them', () => {
    const { diagnostics } = parseString([
      '// @shield:begin -- "docs"',
      '// @exposes was renamed in v1.2',
      '// @exposes #api to',
      '// @shield:end',
    ].join('\n'));
    expect(diagnostics).toEqual([]);
  });
});

describe('D29 — a file of prose does not fail, a file with one break does', () => {
  const PROSE_FILE = ['/**', ...PROSE.map(p => ` * ${p}`), ' */', 'export const x = 1;'].join('\n');

  it('prose only: warnings, zero errors', () => {
    const { diagnostics } = parseString(PROSE_FILE, 'notes.ts');
    expect(diagnostics).toHaveLength(PROSE.length);
    expect(diagnostics.filter(d => d.level === 'error')).toHaveLength(0);
  });

  it('one truncated annotation among the prose: exactly one error', () => {
    const { diagnostics } = parseString(
      PROSE_FILE.replace('export const x = 1;', '/**\n * @exposes #api to\n */\nexport const y = 1;'),
      'notes.ts',
    );
    const errors = diagnostics.filter(d => d.level === 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0].raw).toBe('@exposes #api to');
    expect(diagnostics.filter(d => d.level === 'warning')).toHaveLength(PROSE.length);
  });
});
