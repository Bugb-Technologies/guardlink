/**
 * The hidden-Unicode corpus (`conformance/hidden-unicode.json`) against this
 * repository's detector. Other readers of agent configuration test against the
 * same file, so a change to a rule in `src/agentconfig/hidden-unicode.ts` and
 * the corpus case that pins it land in one change, or this fails.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { findHiddenUnicode } from '../src/agentconfig/hidden-unicode.js';

interface Case { id: string; rule: string; about: string; text: string; expect: unknown[] }
const corpus = JSON.parse(readFileSync(new URL('../conformance/hidden-unicode.json', import.meta.url), 'utf8')) as {
  corpus: string; version: number; cases: Case[];
};

describe('conformance/hidden-unicode.json', () => {
  it('names itself and its format version', () => {
    expect(corpus.corpus).toBe('guardlink-hidden-unicode-conformance');
    expect(corpus.version).toBe(1);
  });

  it('gives every case a unique id', () => {
    const ids = corpus.cases.map(c => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('covers every kind, an exemption for each, and a case with no record', () => {
    const rules = new Set(corpus.cases.map(c => c.rule));
    for (const r of ['unicode-tags', 'variation-selectors', 'bidi-control', 'zero-width']) expect(rules.has(r)).toBe(true);
    expect(corpus.cases.filter(c => c.id.endsWith('-exempt')).length).toBeGreaterThanOrEqual(4);
    expect(corpus.cases.some(c => c.expect.length === 0)).toBe(true);
  });

  for (const c of corpus.cases) {
    it(`${c.id}: ${c.about}`, () => {
      expect(findHiddenUnicode(c.text)).toEqual(c.expect);
    });
  }
});
