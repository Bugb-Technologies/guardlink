/**
 * Trailer and identity parsing — pure, table-driven.
 *
 * The rule under test: AI attribution is DECLARED, never detected. A commit
 * is credited to an AI tool only when its author or a `Co-authored-by` /
 * `Assisted-by` trailer matches a tool rule. A `Co-authored-by` that matches
 * nothing is a human co-author, never an unknown AI.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { compileRules, DEFAULT_TOOL_RULES } from '../src/blame/config.js';
import {
  parseTrailerBlock, splitPerson, identityFor, attributeCommit, parseAssistedBy,
} from '../src/blame/trailers.js';
import type { RawCommit } from '../src/blame/types.js';

const rules = compileRules(DEFAULT_TOOL_RULES);

function commit(over: Partial<RawCommit>): RawCommit {
  return {
    sha: 'a'.repeat(40),
    authorName: 'Animesh Srivastava',
    authorEmail: 'animesh@example.com',
    date: '2026-08-10T14:29:38+05:30',
    committerName: 'Animesh Srivastava',
    trailers: '',
    ...over,
  };
}

describe('splitPerson', () => {
  it('splits "Name <email>" and keeps the raw text', () => {
    expect(splitPerson('Claude Opus 5 (1M context) <noreply@anthropic.com>'))
      .toEqual({ name: 'Claude Opus 5 (1M context)', email: 'noreply@anthropic.com', raw: 'Claude Opus 5 (1M context) <noreply@anthropic.com>' });
  });
  it('treats a value without angle brackets as a bare name', () => {
    expect(splitPerson('  Copilot ')).toEqual({ name: 'Copilot', email: '', raw: 'Copilot' });
  });
  it('keeps markup in a name verbatim — escaping is the renderer\'s job', () => {
    expect(splitPerson('<script>alert(1)</script> <a@b.c>').name).toBe('<script>alert(1)</script>');
  });
});

describe('parseTrailerBlock', () => {
  it('reads only Co-authored-by and Assisted-by, in any key case, and ignores every other key', () => {
    const block = [
      'Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>',
      'Claude-Session: https://claude.ai/code/session_x',
      'co-authored-by: jpmo <jordi.murgo@gft.com>',
      'Assisted-by: Codex:gpt-5.2 [coccinelle]',
      'Signed-off-by: Someone <s@x.y>',
    ].join('\n');
    const parsed = parseTrailerBlock(block);
    expect(parsed.coAuthors.map(p => p.email)).toEqual(['noreply@anthropic.com', 'jordi.murgo@gft.com']);
    expect(parsed.assistedBy).toEqual(['Codex:gpt-5.2 [coccinelle]']);
  });
  it('returns nothing for an empty block', () => {
    expect(parseTrailerBlock('')).toEqual({ coAuthors: [], assistedBy: [] });
  });
});

describe('identityFor', () => {
  it('name mode prefixes human: and strips control characters', () => {
    expect(identityFor('Ja\x01ne\x7f Doe ', 'jane@example.com', 'name')).toBe('human:Jane Doe');
  });
  it('email mode shows the email; hash mode shows 12 hex of sha256 of the lowercased email', () => {
    expect(identityFor('Jane', 'Jane@Example.com', 'email')).toBe('human:Jane@Example.com');
    const hash = createHash('sha256').update('jane@example.com').digest('hex').slice(0, 12);
    expect(identityFor('Jane', 'Jane@Example.com', 'hash')).toBe(`human:${hash}`);
  });
  it('falls back to the name when the email is empty, and to unknown when both are', () => {
    expect(identityFor('Jane', '', 'hash')).toBe('human:Jane');
    expect(identityFor('', '', 'name')).toBe('human:unknown');
  });
});

describe('attributeCommit — the eight conventions', () => {
  it('claude-code: co-author trailer names the model', () => {
    const ref = attributeCommit(commit({ trailers: 'Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>' }), rules, 'name');
    expect(ref.author).toBe('human:Animesh Srivastava');
    expect(ref.co_authors).toEqual([]);
    expect(ref.assisted_by).toEqual([{ tool: 'claude-code', model: 'Claude Opus 5 (1M context)', raw: 'Claude Opus 5 (1M context) <noreply@anthropic.com>' }]);
  });

  it('copilot coding agent: the bot is the author and the human is the co-author', () => {
    const ref = attributeCommit(commit({
      authorName: 'Copilot', authorEmail: '223556219+Copilot@users.noreply.github.com',
      trailers: 'Co-authored-by: Jane Doe <jane@example.com>',
    }), rules, 'name');
    expect(ref.author).toBe('human:Jane Doe');
    expect(ref.co_authors).toEqual([]);
    expect(ref.assisted_by).toEqual([{ tool: 'copilot', model: null, raw: 'Copilot <223556219+Copilot@users.noreply.github.com>' }]);
  });

  it('copilot with no human co-author: the author is the agent and no human is invented', () => {
    const ref = attributeCommit(commit({ authorName: 'Copilot', authorEmail: '223556219+Copilot@users.noreply.github.com' }), rules, 'name');
    expect(ref.author).toBe('agent:copilot');
    expect(ref.assisted_by.map(a => a.tool)).toEqual(['copilot']);
  });

  it('codex, cursor and warp: co-author trailers without a model', () => {
    for (const [trailer, tool] of [
      ['Co-authored-by: Codex <noreply@openai.com>', 'codex'],
      ['Co-authored-by: Cursor <cursoragent@cursor.com>', 'cursor'],
      ['Co-Authored-By: Warp <agent@warp.dev>', 'warp'],
    ] as const) {
      const ref = attributeCommit(commit({ trailers: trailer }), rules, 'name');
      expect(ref.assisted_by).toEqual([{ tool, model: null, raw: trailer.replace(/^[^:]+:\s*/, '') }]);
      expect(ref.co_authors).toEqual([]);
    }
  });

  it('gemini-cli: the model is what follows the tool token', () => {
    const recommended = attributeCommit(commit({ trailers: 'Co-authored-by: gemini-cli Gemini 2.5 Pro <218195315+gemini-cli@users.noreply.github.com>' }), rules, 'name');
    expect(recommended.assisted_by[0]).toMatchObject({ tool: 'gemini-cli', model: 'Gemini 2.5 Pro' });
    const variant = attributeCommit(commit({ trailers: 'Co-Authored-By: Gemini 3 <gemini-code-assist@google.com>' }), rules, 'name');
    expect(variant.assisted_by[0]).toMatchObject({ tool: 'gemini-cli', model: '3' });
  });

  it('aider: the author-name suffix credits aider and the human keeps their name', () => {
    const ref = attributeCommit(commit({ authorName: 'Jane Doe (aider)', authorEmail: 'jane@example.com' }), rules, 'name');
    expect(ref.author).toBe('human:Jane Doe');
    expect(ref.assisted_by).toEqual([{ tool: 'aider', model: null, raw: 'Jane Doe (aider) <jane@example.com>' }]);
  });

  it('aider: a co-author trailer carries the model in parentheses', () => {
    const ref = attributeCommit(commit({ trailers: 'Co-authored-by: aider (gpt-4o) <noreply@aider.chat>' }), rules, 'name');
    expect(ref.assisted_by).toEqual([{ tool: 'aider', model: 'gpt-4o', raw: 'aider (gpt-4o) <noreply@aider.chat>' }]);
  });

  it('kernel-style Assisted-by: AGENT:MODEL maps the agent through the rules', () => {
    expect(parseAssistedBy('Codex:gpt-5.2 [coccinelle]', rules)).toEqual({ tool: 'codex', model: 'gpt-5.2', raw: 'Codex:gpt-5.2 [coccinelle]' });
    expect(parseAssistedBy('Claude:claude-opus-5', rules)).toEqual({ tool: 'claude-code', model: 'claude-opus-5', raw: 'Claude:claude-opus-5' });
    expect(parseAssistedBy('SomeNewTool:v9', rules)).toEqual({ tool: 'somenewtool', model: 'v9', raw: 'SomeNewTool:v9' });
    expect(parseAssistedBy('SomeNewTool', rules)).toEqual({ tool: 'somenewtool', model: null, raw: 'SomeNewTool' });
    expect(parseAssistedBy('  ', rules)).toEqual({ tool: 'unknown', model: null, raw: '' });
  });
});

describe('attributeCommit — humans stay human', () => {
  it('a Co-authored-by that matches no rule is a human co-author, not an unknown AI', () => {
    const ref = attributeCommit(commit({ trailers: 'Co-authored-by: jpmo <jordi.murgo@gft.com>' }), rules, 'name');
    expect(ref.assisted_by).toEqual([]);
    expect(ref.co_authors).toEqual(['human:jpmo']);
  });

  it('a commit with no trailer has an empty assisted_by — never a default of AI', () => {
    const ref = attributeCommit(commit({}), rules, 'name');
    expect(ref).toMatchObject({ sha: 'a'.repeat(40), date: '2026-08-10T14:29:38+05:30', author: 'human:Animesh Srivastava', co_authors: [], assisted_by: [] });
  });

  it('ignores every trailer key other than Co-authored-by and Assisted-by', () => {
    const ref = attributeCommit(commit({ trailers: 'Claude-Session: https://claude.ai/code/session_x\nSigned-off-by: X <x@y.z>' }), rules, 'name');
    expect(ref.assisted_by).toEqual([]);
    expect(ref.co_authors).toEqual([]);
  });

  it('applies the identity mode to author and human co-authors alike', () => {
    const ref = attributeCommit(commit({ trailers: 'Co-authored-by: jpmo <jordi.murgo@gft.com>' }), rules, 'email');
    expect(ref.author).toBe('human:animesh@example.com');
    expect(ref.co_authors).toEqual(['human:jordi.murgo@gft.com']);
  });

  it('keeps markup from a trailer verbatim in the identity string', () => {
    const ref = attributeCommit(commit({ trailers: 'Co-Authored-By: <script>alert(1)</script> <a@b.c>' }), rules, 'name');
    expect(ref.co_authors).toEqual(['human:<script>alert(1)</script>']);
  });

  it('credits each tool+model once even when the trailer repeats', () => {
    const t = 'Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>';
    const ref = attributeCommit(commit({ trailers: `${t}\n${t}` }), rules, 'name');
    expect(ref.assisted_by).toHaveLength(1);
  });
});
