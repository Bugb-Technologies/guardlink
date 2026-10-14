/**
 * Skill inventory in the agent_config block (SPEC §5.6): a skill's own
 * invocation metadata, the files bundled beside it, the bundle list in
 * agent_config_hash, and the boundaries the walk keeps — symbolic links are not
 * followed, nothing outside the skill's directory is listed.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { readAgentConfig, computeAgentConfigHash, discover } from '../src/agentconfig/index.js';
import { bundledKind, collectBundle, MAX_BUNDLED } from '../src/agentconfig/bundle.js';
import { parseProject } from '../src/parser/parse-project.js';
import { parseAtRef } from '../src/diff/git.js';
import { diffModels } from '../src/diff/engine.js';
import { formatDiff, formatDiffMarkdown } from '../src/diff/format.js';

const roots: string[] = [];
afterEach(() => { for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true }); });

function repo(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-skill-'));
  roots.push(root);
  write(root, files);
  return root;
}
function write(root: string, files: Record<string, string>) {
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
}
const git = (root: string, ...args: string[]) =>
  execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.test', '-c', 'commit.gpgsign=false', ...args], { cwd: root, encoding: 'utf-8' });
const sha = (text: string) => `sha256-v1:${createHash('sha256').update(text).digest('hex')}`;

/** No git filtering: these trees are not repositories. */
const read = (root: string) => readAgentConfig(root, { carried: null });
const skillOf = (r: ReturnType<typeof read>, path: string) => r.block.instruction_files.find(f => f.path === path)!;

const SKILL = '---\nname: s\n---\nDo it.\n';

describe('skill metadata', () => {
  it('records that a skill the model may start is model-invocable, and the line of allowed-tools', () => {
    const r = read(repo({ '.claude/skills/a/SKILL.md': '---\nname: a\nallowed-tools: Read\n---\nx\n' }));
    expect(skillOf(r, '.claude/skills/a/SKILL.md').skill).toEqual({ model_invocable: true, allowed_tools_line: 3 });
  });

  it('records disable-model-invocation: true as not model-invocable, with its line', () => {
    const r = read(repo({ '.claude/skills/a/SKILL.md': '---\nname: a\ndisable-model-invocation: true # manual only\n---\nx\n' }));
    expect(skillOf(r, '.claude/skills/a/SKILL.md').skill).toEqual({ model_invocable: false, disable_model_invocation_line: 3 });
  });

  it('reads quoted and capitalised booleans, and treats false as invocable while keeping the line', () => {
    const r = read(repo({
      '.claude/skills/q/SKILL.md': '---\ndisable-model-invocation: "True"\n---\n',
      '.claude/skills/f/SKILL.md': '---\ndisable-model-invocation: false\n---\n',
    }));
    expect(skillOf(r, '.claude/skills/q/SKILL.md').skill?.model_invocable).toBe(false);
    expect(skillOf(r, '.claude/skills/f/SKILL.md').skill).toEqual({ model_invocable: true, disable_model_invocation_line: 2 });
  });

  it('is on skills only: other instruction files carry neither field', () => {
    const r = read(repo({ 'AGENTS.md': 'x', '.claude/commands/c.md': '---\ndisable-model-invocation: true\n---\n', '.claude/skills/a/SKILL.md': SKILL }));
    for (const p of ['AGENTS.md', '.claude/commands/c.md']) {
      const f = skillOf(r, p);
      expect(f).not.toHaveProperty('skill');
      expect(f).not.toHaveProperty('bundled');
    }
  });
});

describe('bundled files', () => {
  it('lists the files beside SKILL.md with kind, length and digest, sorted by path', () => {
    const r = read(repo({
      '.claude/skills/a/SKILL.md': SKILL,
      '.claude/skills/a/run.sh': 'echo hi\n',
      '.claude/skills/a/lib/tool.py': 'print(1)\n',
      '.claude/skills/a/assets/logo.png': 'not really a png',
      '.claude/skills/a/references/notes.md': '# notes\n',
    }));
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled).toEqual([
      { path: '.claude/skills/a/assets/logo.png', kind: 'asset', bytes: 16, sha256: sha('not really a png') },
      { path: '.claude/skills/a/lib/tool.py', kind: 'code', bytes: 9, sha256: sha('print(1)\n') },
      { path: '.claude/skills/a/references/notes.md', kind: 'asset', bytes: 8, sha256: sha('# notes\n') },
      { path: '.claude/skills/a/run.sh', kind: 'script', bytes: 8, sha256: sha('echo hi\n') },
    ]);
  });

  it('an empty bundle is [] and is not the same as no bundle', () => {
    const r = read(repo({ '.claude/skills/a/SKILL.md': SKILL }));
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled).toEqual([]);
  });

  it('classifies by file name', () => {
    expect(['x.sh', 'x.PS1', 'x.bat'].map(bundledKind)).toEqual(['script', 'script', 'script']);
    expect(['x.py', 'x.ts', 'x.mjs', 'x.rb', 'x.go'].map(bundledKind)).toEqual(['code', 'code', 'code', 'code', 'code']);
    expect(['x.md', 'x.json', 'x.png', 'Makefile', '.env', 'sh'].map(bundledKind)).toEqual(['asset', 'asset', 'asset', 'asset', 'asset', 'asset']);
  });

  it('leaves another skill\'s files to that skill, and skips dependency directories', () => {
    const r = read(repo({
      '.claude/skills/a/SKILL.md': SKILL,
      '.claude/skills/a/helper.sh': 'a\n',
      '.claude/skills/a/inner/SKILL.md': SKILL,
      '.claude/skills/a/inner/inner.sh': 'b\n',
      '.claude/skills/a/node_modules/dep/index.js': 'c\n',
    }));
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled!.map(b => b.path)).toEqual(['.claude/skills/a/helper.sh']);
    expect(skillOf(r, '.claude/skills/a/inner/SKILL.md').bundled!.map(b => b.path)).toEqual(['.claude/skills/a/inner/inner.sh']);
  });

  it('lists a file above the read cap by length, without a digest', () => {
    const root = repo({ '.claude/skills/a/SKILL.md': SKILL, '.claude/skills/a/big.bin': 'x'.repeat(2 * 1024 * 1024 + 1) });
    expect(skillOf(read(root), '.claude/skills/a/SKILL.md').bundled).toEqual([
      { path: '.claude/skills/a/big.bin', kind: 'asset', bytes: 2 * 1024 * 1024 + 1 },
    ]);
  });

  it('lists at most MAX_BUNDLED files and says the rest were not listed', () => {
    const files: Record<string, string> = { '.claude/skills/a/SKILL.md': SKILL };
    for (let i = 0; i < MAX_BUNDLED + 3; i++) files[`.claude/skills/a/f${String(i).padStart(4, '0')}.txt`] = 'x';
    const r = read(repo(files));
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled).toHaveLength(MAX_BUNDLED);
    expect(r.block.unreadable).toMatchObject([{ file: '.claude/skills/a/SKILL.md', message: expect.stringContaining('were not listed') }]);
  });

  it('does not look beside a fixture skill, or a SKILL.md at the repository root', () => {
    const r = read(repo({
      'tests/fixtures/s/SKILL.md': SKILL, 'tests/fixtures/s/run.sh': 'x\n',
      'SKILL.md': SKILL, 'src/index.ts': 'export {};\n',
    }));
    expect(skillOf(r, 'tests/fixtures/s/SKILL.md')).not.toHaveProperty('bundled');
    expect(skillOf(r, 'SKILL.md')).not.toHaveProperty('bundled');
    expect(skillOf(r, 'SKILL.md').skill).toEqual({ model_invocable: true });
  });

  it('inventories a packaged skill\'s bundle too', () => {
    const r = read(repo({ 'plugins/kit/skills/a/SKILL.md': SKILL, 'plugins/kit/skills/a/run.sh': 'x\n' }));
    const f = skillOf(r, 'plugins/kit/skills/a/SKILL.md');
    expect(f.scope).toBe('packaged');
    expect(f.bundled!.map(b => b.path)).toEqual(['plugins/kit/skills/a/run.sh']);
  });

  it('names a skill reached through a symlinked directory once, with bundle paths under the name it has', () => {
    const root = repo({ '.agents/skills/setup/SKILL.md': SKILL, '.agents/skills/setup/go.sh': 'x\n' });
    mkdirSync(join(root, '.claude'), { recursive: true });
    symlinkSync('../.agents/skills', join(root, '.claude', 'skills'));
    const r = read(root);
    expect(r.block.instruction_files).toHaveLength(1);
    expect(r.block.instruction_files[0].bundled!.map(b => b.path)).toEqual(['.agents/skills/setup/go.sh']);
  });
});

describe('path boundaries', () => {
  it('rejects a skill directory outside the repository before walking it', () => {
    const root = repo({ 'AGENTS.md': 'x' });
    const outside = repo({ 'SKILL.md': SKILL, 'secret.sh': 'exfil\n' });
    const skill = discover(outside).files.find(f => f.path === 'SKILL.md')!;
    const result = collectBundle(skill, root, null)!;
    expect(result.bundled).toEqual([]);
    expect(result.unreadable).toMatchObject([{ file: 'SKILL.md', message: expect.stringContaining('outside repository root') }]);
  });

  it('does not follow or list a symlink to a file outside the repository, and reports it', () => {
    const outside = repo({ 'secret.sh': 'exfil\n' });
    const root = repo({ '.claude/skills/a/SKILL.md': SKILL, '.claude/skills/a/ok.sh': 'ok\n' });
    symlinkSync(join(outside, 'secret.sh'), join(root, '.claude/skills/a/leak.sh'));
    const r = read(root);
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled!.map(b => b.path)).toEqual(['.claude/skills/a/ok.sh']);
    expect(r.block.unreadable).toMatchObject([{ file: '.claude/skills/a/leak.sh', message: expect.stringContaining('symbolic link') }]);
  });

  it('does not follow or list a symlinked directory outside the repository', () => {
    const outside = repo({ 'lib/x.py': 'x\n' });
    const root = repo({ '.claude/skills/a/SKILL.md': SKILL });
    symlinkSync(join(outside, 'lib'), join(root, '.claude/skills/a/lib'));
    const r = read(root);
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled).toEqual([]);
    expect(r.block.unreadable.map(u => u.file)).toEqual(['.claude/skills/a/lib']);
  });

  it('does not list a symlink to another file inside the repository either', () => {
    const root = repo({ '.claude/skills/a/SKILL.md': SKILL, 'scripts/shared.sh': 'x\n' });
    symlinkSync('../../../scripts/shared.sh', join(root, '.claude/skills/a/shared.sh'));
    const r = read(root);
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled).toEqual([]);
    expect(r.block.unreadable.map(u => u.file)).toEqual(['.claude/skills/a/shared.sh']);
  });

  it('does not read a skill whose SKILL.md links outside the repository', () => {
    const outside = repo({ 'SKILL.md': SKILL });
    const root = repo({ 'AGENTS.md': 'x' });
    mkdirSync(join(root, '.claude/skills/a'), { recursive: true });
    symlinkSync(join(outside, 'SKILL.md'), join(root, '.claude/skills/a/SKILL.md'));
    expect(read(root).block.instruction_files.map(f => f.path)).toEqual(['AGENTS.md']);
  });

  it('leaves out the files git does not carry, so the list is the same on every clone', () => {
    const root = repo({
      '.gitignore': '__pycache__/\n',
      '.claude/skills/a/SKILL.md': SKILL,
      '.claude/skills/a/run.sh': 'x\n',
      '.claude/skills/a/__pycache__/run.pyc': 'compiled',
    });
    git(root, 'init', '-q');
    const r = readAgentConfig(root);
    expect(skillOf(r, '.claude/skills/a/SKILL.md').bundled!.map(b => b.path)).toEqual(['.claude/skills/a/run.sh']);
  });
});

describe('agent_config_hash', () => {
  const hashOf = (files: Record<string, string>) => read(repo(files)).block.agent_config_hash;
  const base = { '.claude/skills/a/SKILL.md': SKILL };

  it('moves when a script is added, and when its content changes at the same length', () => {
    const none = hashOf(base);
    const one = hashOf({ ...base, '.claude/skills/a/run.sh': 'echo a\n' });
    const edited = hashOf({ ...base, '.claude/skills/a/run.sh': 'echo b\n' });
    expect(new Set([none, one, edited]).size).toBe(3);
  });

  it('is the same for the same bundle, wherever the repository lives', () => {
    const files = { ...base, '.claude/skills/a/run.sh': 'echo a\n', '.claude/skills/a/t.py': 'x\n' };
    expect(hashOf(files)).toBe(hashOf(files));
  });

  it('is unchanged for skills with nothing bundled: the key is absent, not empty', () => {
    const r = read(repo(base));
    const stripped = { ...r, block: { ...r.block, instruction_files: r.block.instruction_files.map(({ bundled: _b, ...f }) => f) } };
    expect(computeAgentConfigHash(stripped)).toBe(r.block.agent_config_hash);
  });

  it('does not cover SKILL.md text, which the GuardLink block in an instruction file could never match', () => {
    expect(hashOf(base)).toBe(hashOf({ '.claude/skills/a/SKILL.md': '---\nname: s\n---\nDifferent words.\n' }));
  });
});

describe('diff: scripts bundled with a skill', () => {
  async function pair(before: Record<string, string>, after: Record<string, string | null>) {
    const root = repo(before);
    git(root, 'init', '-q');
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'base');
    for (const [rel, text] of Object.entries(after)) {
      if (text === null) rmSync(join(root, rel)); else write(root, { [rel]: text });
    }
    const was = await parseAtRef(root, 'HEAD', 'p');
    const { model: now } = await parseProject({ root, project: 'p' });
    return { was, now, d: diffModels(was, now) };
  }

  it('reports a new script, a new code file, and an edit at the same length, but not an unchanged or asset file', async () => {
    const { was, d } = await pair(
      { '.claude/skills/a/SKILL.md': SKILL, '.claude/skills/a/run.sh': 'echo a\n', '.claude/skills/a/keep.sh': 'k\n', '.claude/skills/a/notes.md': 'one\n' },
      { '.claude/skills/a/run.sh': 'echo b\n', '.claude/skills/a/new.py': 'print(1)\n', '.claude/skills/a/notes.md': 'two\n', '.claude/skills/a/logo.png': 'png' },
    );
    // The skill is read at the ref exactly as it is now: nothing spurious.
    expect(was.agent_config!.instruction_files[0].bundled!.map(b => b.path)).toEqual([
      '.claude/skills/a/keep.sh', '.claude/skills/a/notes.md', '.claude/skills/a/run.sh',
    ]);
    expect(d.agentConfig.bundledChanges).toEqual([
      { skill: '.claude/skills/a/SKILL.md', path: '.claude/skills/a/new.py', kind: 'code', change: 'new', bytes: 9 },
      { skill: '.claude/skills/a/SKILL.md', path: '.claude/skills/a/run.sh', kind: 'script', change: 'changed', bytes: 7 },
    ]);
    expect(d.summary.agentConfigChanges).toBe(2);
    expect(formatDiff(d)).toContain('── Scripts and Code Bundled With a Skill ──');
    expect(formatDiff(d)).toContain('+ .claude/skills/a/new.py (code, 9 bytes, skill .claude/skills/a/SKILL.md)');
    expect(formatDiff(d)).toContain('~ .claude/skills/a/run.sh');
    expect(formatDiffMarkdown(d)).toContain('new `.claude/skills/a/new.py`');
  });

  it('reports every script of a new skill, and nothing for a removed one', async () => {
    const added = await pair({ 'AGENTS.md': 'x' }, { '.claude/skills/n/SKILL.md': SKILL, '.claude/skills/n/go.sh': 'go\n' });
    expect(added.d.agentConfig.bundledChanges.map(c => `${c.change} ${c.path}`)).toEqual(['new .claude/skills/n/go.sh']);
    const removed = await pair({ '.claude/skills/n/SKILL.md': SKILL, '.claude/skills/n/go.sh': 'go\n' }, { '.claude/skills/n/go.sh': null });
    expect(removed.d.agentConfig.bundledChanges).toEqual([]);
  });

  it('says nothing for a packaged skill, which this repository\'s agents do not load', async () => {
    const { d } = await pair({ 'AGENTS.md': 'x' }, { 'plugins/kit/skills/a/SKILL.md': SKILL, 'plugins/kit/skills/a/go.sh': 'go\n' });
    expect(d.agentConfig.bundledChanges).toEqual([]);
  });

  it('reads the same bundle at a ref as in the working tree when a binary asset sits beside it', async () => {
    const root = repo({ '.claude/skills/a/SKILL.md': SKILL, '.claude/skills/a/run.sh': 'x\n' });
    writeFileSync(join(root, '.claude/skills/a/blob.bin'), Buffer.from([0xff, 0xfe, 0x00, 0x80, 0xc3]));
    git(root, 'init', '-q');
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'base');
    const was = await parseAtRef(root, 'HEAD', 'p');
    const { model: now } = await parseProject({ root, project: 'p' });
    expect(was.agent_config!.instruction_files[0].bundled).toEqual(now.agent_config!.instruction_files[0].bundled);
    expect(was.agent_config!.agent_config_hash).toBe(now.agent_config!.agent_config_hash);
  });

  it('compares an older export without skill inventory using the additive fields', async () => {
    const { was, now } = await pair({ '.claude/skills/a/SKILL.md': SKILL, '.claude/skills/a/go.sh': 'go\n' }, {});
    for (const f of was.agent_config!.instruction_files) {
      delete f.skill;
      delete f.bundled;
    }
    expect(diffModels(was, now).agentConfig.bundledChanges).toEqual([
      { skill: '.claude/skills/a/SKILL.md', path: '.claude/skills/a/go.sh', kind: 'script', change: 'new', bytes: 3 },
    ]);
  });
});
