/**
 * The fourth diagnostic tier: a token that looks like a GuardLink verb but is not one.
 *
 * The three existing tiers were error (known verb, structural, unparseable),
 * warning (known verb, prose-like) and silence (everything else). Silence was
 * doing two jobs: correctly ignoring `@param`, and incorrectly swallowing
 * `@flow` — a one-character slip from `@flows` that the README itself shipped
 * twice. Neither an annotation nor a word came out, and nothing said so.
 *
 * The discriminator is edit distance, and the threshold is length-scaled
 * because a flat one fails in both directions: 1 misses `@migitates`
 * (mitigates is two substitutions away, non-adjacent, so Damerau does not help)
 * and 2 claims `@author` (two from `actor`, and a real JSDoc tag).
 */
import { describe, it, expect } from 'vitest';
import { parseString } from '../src/parser/parse-file.js';

function diagnose(line: string) {
  const { diagnostics } = parseString(`// ${line}\n`, 'probe.ts');
  return diagnostics;
}

function unknownVerbDiag(line: string) {
  return diagnose(line).find(d => d.code === 'unknown-verb');
}

describe('unknown-verb — near misses warn', () => {
  it('@flow suggests @flows', () => {
    const d = unknownVerbDiag('@flow #api -> #database via "wire protocol"');
    expect(d).toBeDefined();
    expect(d!.level).toBe('warning');
    expect(d!.message).toContain('did you mean @flows?');
  });

  it('@migitates suggests @mitigates — distance 2, not 1', () => {
    const d = unknownVerbDiag('@migitates #api against #sqli using #prepared-stmts -- "x"');
    expect(d).toBeDefined();
    expect(d!.message).toContain('did you mean @mitigates?');
  });

  it('warns, never errors — a guess does not fail a build', () => {
    for (const line of ['@flow #a -> #b', '@migitates #a against #b', '@exposees #a to #b']) {
      expect(diagnose(line).every(d => d.level !== 'error')).toBe(true);
    }
  });

  it('the raw line is carried so a renderer can show it', () => {
    expect(unknownVerbDiag('@flow #api -> #database')!.raw).toBe('@flow #api -> #database');
  });
});

describe('unknown-verb — everything else stays silent', () => {
  it('@param and the rest of JSDoc produce no diagnostic', () => {
    for (const line of ['@param name the user name', '@returns nothing', '@throws on failure',
      '@deprecated use x', '@example foo()', '@author Jane', '@since 1.0', '@see other']) {
      expect(diagnose(line)).toEqual([]);
    }
  });

  it('@author is two edits from actor and still silent — short tokens need distance 1', () => {
    expect(diagnose('@author Jane Doe')).toEqual([]);
  });

  it('a verb named in prose is not a typo of itself', () => {
    // Real line from src/mcp/subgraph.ts. The trailing comma made `comment,`
    // an unknown token one edit from `comment`; naming a verb is not misusing it.
    expect(diagnose('@comment, @shield and @feature carry no ref, so they follow the files')).toEqual([]);
  });

  it('but a typo still survives the punctuation strip', () => {
    expect(unknownVerbDiag('@flowss, #a -> #b')!.message).toContain('did you mean @flows?');
  });

  it('a known verb is never reported as unknown', () => {
    for (const line of ['@exposes #api to #sqli [high] -- "x"', '@flows #a -> #b', '@comment -- "x"']) {
      expect(diagnose(line).some(d => d.code === 'unknown-verb')).toBe(false);
    }
  });

  it('non-lowercase leads are out of scope', () => {
    expect(diagnose('@TODO fix this')).toEqual([]);
    expect(diagnose('@1234')).toEqual([]);
  });
});

describe('unknown-verb does not disturb the existing tiers', () => {
  it('a known verb with structure that fails to parse is still a hard error', () => {
    const d = diagnose('@exposes #api to').find(x => x.code === 'malformed-annotation');
    expect(d).toBeDefined();
    expect(d!.level).toBe('error');
  });

  it('a known verb with no structure is still prose-like, not unknown-verb', () => {
    const ds = diagnose('@feature still claims to describe the model');
    expect(ds.some(d => d.code === 'prose-like')).toBe(true);
    expect(ds.some(d => d.code === 'unknown-verb')).toBe(false);
  });
});

describe('containment — the tier must not flood a codebase it was not tuned for', () => {
  it('a namespace separator before the verb is a dialect, not a typo', () => {
    // Measured: @g.comment accounted for 1,340 of 1,365 warnings across four
    // corpora. `g.comment` is two deletions from `comment`, so the
    // length-scaled tier admitted it before this rule existed.
    for (const line of ['@g.comment -- "x"', '@g.mitigates #a against #b', '@gl:exposes #a to #b',
      '@my-ns.flows #a -> #b']) {
      expect(diagnose(line)).toEqual([]);
    }
  });

  it('a bare verb is still checked — the rule keys on the separator, not the length', () => {
    expect(unknownVerbDiag('@migitates #a against #b')).toBeDefined();
  });

  it('documentation vocabularies are excluded by name, not by distance', () => {
    for (const tag of ['param', 'returns', 'brief', 'retval', 'rtype', 'tparam', 'copydoc',
      'packagedocumentation', 'property-read', 'ivar', 'inheritdoc', 'yields']) {
      expect(diagnose(`@${tag} something`)).toEqual([]);
    }
  });
});
