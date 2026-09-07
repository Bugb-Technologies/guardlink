/**
 * `blame` config: the optional `blame` key in `.guardlink/config.json`.
 * Absent, unreadable or malformed config must yield the shipped defaults —
 * an unparseable config must never silently change who gets attributed.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readBlameConfig, compileRules, DEFAULT_TOOL_RULES } from '../src/blame/config.js';

async function scratch(config?: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-blame-config-'));
  if (config !== undefined) {
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'config.json'), config);
  }
  return root;
}

describe('readBlameConfig', () => {
  it('returns the shipped defaults when there is no config file', async () => {
    const root = await scratch();
    const cfg = readBlameConfig(root);
    expect(cfg.identity).toBe('name');
    expect(cfg.tools).toEqual(DEFAULT_TOOL_RULES);
    expect(cfg.ignore_revs).toBe('.git-blame-ignore-revs');
  });

  it('returns the defaults when the config is not valid JSON', async () => {
    const root = await scratch('{ not json');
    expect(readBlameConfig(root)).toEqual(readBlameConfig(await scratch()));
  });

  it('accepts identity name | email | hash and falls back to name otherwise', async () => {
    expect(readBlameConfig(await scratch('{"blame":{"identity":"hash"}}')).identity).toBe('hash');
    expect(readBlameConfig(await scratch('{"blame":{"identity":"email"}}')).identity).toBe('email');
    expect(readBlameConfig(await scratch('{"blame":{"identity":"phone"}}')).identity).toBe('name');
    expect(readBlameConfig(await scratch('{"blame":{"identity":42}}')).identity).toBe('name');
  });

  it('prepends user tool rules so they win over the shipped ones', async () => {
    const root = await scratch('{"blame":{"tools":[{"tool":"corp-bot","email":"bot@corp\\\\.example"}, {"email":"no-tool-name"}]}}');
    const cfg = readBlameConfig(root);
    expect(cfg.tools[0]).toEqual({ tool: 'corp-bot', email: 'bot@corp\\.example' });
    // the row without a `tool` name is dropped; the defaults follow
    expect(cfg.tools).toHaveLength(DEFAULT_TOOL_RULES.length + 1);
    expect(cfg.tools.slice(1)).toEqual(DEFAULT_TOOL_RULES);
  });

  it('keeps ignore_revs only when it stays inside the project root', async () => {
    expect(readBlameConfig(await scratch('{"blame":{"ignore_revs":"tools/ignore-revs"}}')).ignore_revs).toBe('tools/ignore-revs');
    expect(readBlameConfig(await scratch('{"blame":{"ignore_revs":"../outside"}}')).ignore_revs).toBeNull();
    expect(readBlameConfig(await scratch('{"blame":{"ignore_revs":"/etc/passwd"}}')).ignore_revs).toBeNull();
    expect(readBlameConfig(await scratch('{"blame":{"ignore_revs":false}}')).ignore_revs).toBeNull();
  });
});

describe('compileRules', () => {
  it('compiles patterns anchored and case-insensitive', () => {
    const [rule] = compileRules([{ tool: 'x', email: 'a@b\\.c', name: 'Bot' }]);
    expect(rule.tool).toBe('x');
    expect(rule.email!.test('A@B.C')).toBe(true);
    expect(rule.email!.test('xa@b.c')).toBe(false);
    expect(rule.email!.test('a@b.cx')).toBe(false);
    expect(rule.name!.test('bot')).toBe(true);
    expect(rule.name!.test('robot')).toBe(false);
  });

  it('drops a rule whose pattern is invalid or longer than 256 characters', () => {
    const compiled = compileRules([
      { tool: 'bad-regex', email: '(' },
      { tool: 'too-long', name: 'a'.repeat(257) },
      { tool: 'nothing-to-match' },
      { tool: 'good', name: 'Good' },
    ]);
    expect(compiled.map(r => r.tool)).toEqual(['good']);
  });

  it('ships defaults that all compile', () => {
    expect(compileRules(DEFAULT_TOOL_RULES)).toHaveLength(DEFAULT_TOOL_RULES.length);
  });
});
