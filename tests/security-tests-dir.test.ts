import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { readSecurityTestsDir, parseProject } from '../src/parser/index.js';
import { initProject, syncAgentFiles } from '../src/init/index.js';
import { buildTranslatePrompt } from '../src/agents/prompts.js';
import { createServer } from '../src/mcp/server.js';

const roots: string[] = [];
function repo(): string {
  const root = mkdtempSync(join(tmpdir(), 'guardlink-security-dir-'));
  roots.push(root);
  return root;
}
function config(root: string, value: unknown): void {
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  writeFileSync(join(root, '.guardlink/config.json'), JSON.stringify(value));
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('committed security-test directory configuration', () => {
  it('defaults to security with or without a config and is exposed by parsing', async () => {
    const root = repo();
    expect(readSecurityTestsDir(root)).toBe('security');
    config(root, {});
    expect(readSecurityTestsDir(root)).toBe('security');
    expect((await parseProject({ root })).config).toEqual({ security_tests_dir: 'security' });
    initProject({ root, agentIds: [] });
    expect(JSON.parse(readFileSync(join(root, '.guardlink/config.json'), 'utf8'))).not.toHaveProperty('security_tests_dir');
  });

  it('normalizes an override without creating or moving tests', async () => {
    const root = repo();
    config(root, { security_tests_dir: './checks\\security//' });
    expect(readSecurityTestsDir(root)).toBe('checks/security');
    expect((await parseProject({ root })).config).toEqual({ security_tests_dir: 'checks/security' });
  });

  it.each([
    '/tmp/security', 'C:\\security', 'C:security', '\\\\server\\share', '\\security',
    '../security', 'checks/../../outside', 'checks/../security', '..\\outside',
    '', ' ', '.', './', null, false, 7, [], {},
    'checks/`evil`', 'checks/<!--evil-->', 'checks/line\nbreak', 'checks/\u200bevil', '\ufeffchecks', 'checks/line\u2028break', 'checks/line\u2029break',
  ])('refuses invalid directory %j with a named config error', value => {
    const root = repo();
    config(root, { security_tests_dir: value });
    expect(() => readSecurityTestsDir(root)).toThrow(/security_tests_dir:/);
  });

  it('refuses escaping symlinks for overrides, missing children, and the default', () => {
    const root = repo();
    const outside = repo();
    symlinkSync(outside, join(root, 'security'));
    expect(() => readSecurityTestsDir(root)).toThrow(/outside the repository/);
    config(root, { security_tests_dir: 'security/missing/child' });
    expect(() => readSecurityTestsDir(root)).toThrow(/outside the repository/);
  });

  it('accepts in-repository symlinks and refuses dangling ones and file components', () => {
    const root = repo();
    mkdirSync(join(root, 'checks'));
    symlinkSync(join(root, 'checks'), join(root, 'suite'));
    config(root, { security_tests_dir: 'suite/new' });
    expect(readSecurityTestsDir(root)).toBe('suite/new');
    symlinkSync(join(root, 'missing'), join(root, 'dangling'));
    config(root, { security_tests_dir: 'dangling/new' });
    expect(() => readSecurityTestsDir(root)).toThrow(/dangling symlink/);
    writeFileSync(join(root, 'file'), 'not a directory');
    config(root, { security_tests_dir: 'file' });
    expect(() => readSecurityTestsDir(root)).toThrow(/not a directory/);
  });

  it('does not replace malformed configuration with a default', () => {
    const root = repo();
    config(root, {});
    writeFileSync(join(root, '.guardlink/config.json'), '{');
    expect(() => readSecurityTestsDir(root)).toThrow(/security_tests_dir: cannot read configuration/);
  });

  for (const mode of ['inline', 'external'] as const) {
    it(`uses an override in init and sync guidance and the translate handoff (${mode})`, async () => {
      const root = repo();
      config(root, { security_tests_dir: 'checks/security', pre_pr: [{ command: 'other-tool check' }] });
      initProject({ root, mode, agentIds: ['claude', 'cursor', 'codex'] });
      const read = (file: string) => readFileSync(join(root, file), 'utf8');
      for (const file of ['CLAUDE.md', 'AGENTS.md', '.cursor/rules/guardlink.mdc', '.guardlink/README.md']) {
        expect(read(file), file).toContain('`checks/security/`');
        expect(read(file), file).not.toMatch(/root `security\/`/);
        expect(read(file).toLowerCase(), file).toContain('only verified templates deliberately promoted as security test cases');
      }
      expect(read('docs/GUARDLINK_REFERENCE.md')).toContain('security_tests_dir');
      expect(read('.claude/skills/guardlink-translate/SKILL.md')).toContain('`checks/security/`');
      expect(read('.claude/skills/guardlink-translate/SKILL.md')).not.toMatch(/root `security\/`/);
      expect(read('CLAUDE.md').indexOf('`checks/security/`')).toBeLessThan(read('CLAUDE.md').indexOf('other-tool check'));
      const { model } = await parseProject({ root });
      const prompt = buildTranslatePrompt('Review changed paths', root, model);
      expect(prompt).toContain('deliberately promote selected templates as security test cases into `checks/security/`');
      expect(prompt).not.toMatch(/root `security\/`/);
      expect(prompt).toContain('Create templates under: `.guardlink/cxg-templates/`');
      expect(prompt).toContain('Do NOT run scans or execute generated templates');
      config(root, { security_tests_dir: 'regressions', annotation_mode: mode });
      syncAgentFiles({ root, model });
      for (const file of ['CLAUDE.md', 'AGENTS.md', '.cursor/rules/guardlink.mdc', '.guardlink/README.md', '.claude/skills/guardlink-translate/SKILL.md']) {
        expect(read(file), file).toContain('`regressions/`');
        expect(read(file), file).not.toContain('`checks/security/`');
      }
    });
  }

  it('exposes the override in actual MCP initialization and parse responses', async () => {
    const root = repo();
    config(root, { security_tests_dir: 'checks/security' });
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(root);
    const server = createServer();
    cwd.mockRestore();
    const client = new Client({ name: 'security-dir-test', version: '0' });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), client.connect(ct)]);
    try {
      expect(client.getInstructions()).toContain('checks/security/ suite');
      for (const args of [{}, { compact: true }, { include_unannotated: true }]) {
        const result = await client.callTool({ name: 'guardlink_parse', arguments: { root, ...args } });
        expect(result.isError).not.toBe(true);
        const text = (result.content as { type: string; text: string }[])[0].text;
        expect(JSON.parse(text).config).toEqual({ security_tests_dir: 'checks/security' });
      }
    } finally {
      await client.close();
      await server.close();
    }
  });
});
