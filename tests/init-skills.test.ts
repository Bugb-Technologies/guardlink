/**
 * `guardlink init` ships the playbooks as Claude Code skills, and never
 * overwrites a skill file a person wrote.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject, syncAgentFiles } from '../src/init/index.js';
import { ANNOTATE_PLAYBOOKS, REPORT_SHAPES } from '../src/playbooks/index.js';

describe('init skills', () => {
  it('writes one SKILL.md per playbook for Claude Code and keeps an authored one', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-skills-'));
    await writeFile(join(root, 'package.json'), '{"name":"s"}');
    await mkdir(join(root, '.claude', 'skills', 'guardlink-annotate-map'), { recursive: true });
    await writeFile(join(root, '.claude', 'skills', 'guardlink-annotate-map', 'SKILL.md'), '---\nname: guardlink-annotate-map\ndescription: mine\n---\nhand written\n');

    const result = initProject({ root, agentIds: ['claude'] });
    const dirs = (await readdir(join(root, '.claude', 'skills'))).sort();
    const want = [...ANNOTATE_PLAYBOOKS.map(p => `guardlink-annotate-${p.id}`), ...REPORT_SHAPES.filter(s => s.id !== 'full').map(s => `guardlink-report-${s.id}`), 'guardlink-translate'].sort();
    expect(dirs).toEqual(want);
    const mine = await readFile(join(root, '.claude', 'skills', 'guardlink-annotate-map', 'SKILL.md'), 'utf8');
    expect(mine).toBe('---\nname: guardlink-annotate-map\ndescription: mine\n---\nhand written\n');
    expect(result.skipped.some(s => s.includes('guardlink-annotate-map'))).toBe(true);
    expect(result.created.filter(c => c.includes('.claude/skills/')).length).toBe(want.length - 1);
    const ex = await readFile(join(root, '.claude', 'skills', 'guardlink-annotate-exploitable', 'SKILL.md'), 'utf8');
    expect(ex).toMatch(/^---\nname: guardlink-annotate-exploitable\n/);
    expect(ex).toContain('<!-- guardlink:generated -->');
  });

  it('writes no skills when Claude Code is not among the agents', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-skills-'));
    await writeFile(join(root, 'package.json'), '{"name":"s"}');
    initProject({ root, agentIds: ['codex'] });
    expect(existsSync(join(root, '.claude', 'skills'))).toBe(false);
  });
  it('sync refreshes managed skills, adds translate and preserves authored files', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-skills-sync-'));
    try {
      await writeFile(join(root, 'package.json'), '{"name":"s"}');
      initProject({ root, agentIds: ['claude'] });
      const managed = join(root, '.claude/skills/guardlink-annotate-diff/SKILL.md');
      const authored = join(root, '.claude/skills/guardlink-annotate-map/SKILL.md');
      const translate = join(root, '.claude/skills/guardlink-translate/SKILL.md');
      await writeFile(managed, '<!-- guardlink:generated -->\nold generated text');
      await writeFile(authored, 'my authored method');
      await rm(translate);
      syncAgentFiles({ root, model: null, dryRun: true });
      expect(await readFile(managed, 'utf8')).toContain('old generated text');
      expect(existsSync(translate)).toBe(false);
      const result = syncAgentFiles({ root, model: null });
      expect(await readFile(managed, 'utf8')).toContain('## Method — Diff');
      expect(await readFile(authored, 'utf8')).toBe('my authored method');
      expect(await readFile(translate, 'utf8')).toContain('Generation is complete');
      expect(result.updated).toContain('.claude/skills/guardlink-translate/SKILL.md');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

});
