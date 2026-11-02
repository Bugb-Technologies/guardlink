/**
 * `guardlink init` ships the playbooks as Claude Code skills, and never
 * overwrites a skill file a person wrote.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject, syncAgentFiles } from '../src/init/index.js';
import { parseProject } from '../src/parser/index.js';
import { ANNOTATE_PLAYBOOKS, REPORT_SHAPES } from '../src/playbooks/index.js';

const DEFS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQLi (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 */
export {};
`;
const SRC = `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "concat query"
 */
export const x = 1;
`;

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
    // Everything in `want` is created except the pre-authored annotate-map.
    expect(result.created.filter(c => c.includes('.claude/skills/')).length).toBe(want.length - 1);
    const ex = await readFile(join(root, '.claude', 'skills', 'guardlink-annotate-exploitable', 'SKILL.md'), 'utf8');
    expect(ex).toMatch(/^---\nname: guardlink-annotate-exploitable\n/);
    expect(ex).toContain('<!-- guardlink:generated -->');
    // The one translate skill ships alongside the playbooks, with the marker and
    // the hard rules, and no per-run model summary baked in.
    const tr = await readFile(join(root, '.claude', 'skills', 'guardlink-translate', 'SKILL.md'), 'utf8');
    expect(tr).toMatch(/^---\nname: guardlink-translate\n/);
    expect(tr).toContain('<!-- guardlink:generated -->');
    expect(tr).toContain('cxg template validate');
    expect(tr).toContain('.guardlink/cxg-templates/');
    expect(tr).toContain('guardlink translate --stdout');
    expect(tr).not.toMatch(/Unmitigated exposure candidates/);
    expect(tr).not.toMatch(/annotations_parsed/);
  });

  it('writes no skills when Claude Code is not among the agents', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-skills-'));
    await writeFile(join(root, 'package.json'), '{"name":"s"}');
    initProject({ root, agentIds: ['codex'] });
    expect(existsSync(join(root, '.claude', 'skills'))).toBe(false);
  });

  it('sync refreshes a generated translate skill and leaves an authored one alone', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-skills-'));
    await writeFile(join(root, 'package.json'), '{"name":"s"}');
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFS);
    await writeFile(join(root, 'src', 'a.ts'), SRC);
    initProject({ root, agentIds: ['claude'] });

    const skillPath = join(root, '.claude', 'skills', 'guardlink-translate', 'SKILL.md');
    const { model } = await parseProject({ root, project: 's' });

    // An authored file (no marker) is the person's — sync keeps it verbatim.
    const authored = '---\nname: guardlink-translate\ndescription: mine\n---\nhand written, no marker\n';
    await writeFile(skillPath, authored);
    const kept = syncAgentFiles({ root, model });
    expect(await readFile(skillPath, 'utf8')).toBe(authored);
    expect(kept.skipped.some(s => s.includes('guardlink-translate') && s.includes('authored'))).toBe(true);

    // A generated file (marker present) that went stale is rewritten.
    await writeFile(skillPath, '---\nname: guardlink-translate\ndescription: stale\n---\n<!-- guardlink:generated -->\nSTALE BODY\n');
    const res = syncAgentFiles({ root, model });
    const after = await readFile(skillPath, 'utf8');
    expect(after).toContain('<!-- guardlink:generated -->');
    expect(after).toContain('## Mission');
    expect(after).toContain('cxg template validate');
    expect(after).not.toContain('STALE BODY');
    expect(res.updated).toContain('.claude/skills/guardlink-translate/SKILL.md');
  });
});
