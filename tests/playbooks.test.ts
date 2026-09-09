/**
 * Playbooks: the tool owns the method, the user supplies scope and intent.
 * Selection is rule-based and deterministic; the prompt says which playbook
 * governs; the same body ships as a skill file.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { ANNOTATE_PLAYBOOKS, REPORT_SHAPES, selectAnnotatePlaybook, selectReportShape, getPlaybook, skillFileFor, EVIDENCE_BAR } from '../src/playbooks/index.js';
import { buildAnnotatePrompt } from '../src/agents/prompts.js';

const ids = ANNOTATE_PLAYBOOKS.map(p => p.id);

describe('selection', () => {
  it('is rule-based, deterministic, and defaults to the evidence-bar playbook', () => {
    expect(ids).toEqual(['map', 'exploitable', 'chains', 'diff', 'coverage', 'verify']);
    const cases: [string, string][] = [
      ['Annotate all the threats in my codebase', 'exploitable'],
      ['Annotate only real threats which can be actually exploited, find chained threats as deep as possible', 'chains'],
      ['map the architecture and data flows only', 'map'],
      ['annotate the files changed on this branch', 'diff'],
      ['cover the unannotated files', 'coverage'],
      ['check the existing annotations are still accurate', 'verify'],
      ['', 'exploitable'],
    ];
    for (const [prompt, want] of cases) {
      const a = selectAnnotatePlaybook(prompt);
      const b = selectAnnotatePlaybook(prompt);
      expect(a.id, prompt).toBe(want);
      expect(b).toEqual(a);
      expect(a.reason.length).toBeGreaterThan(0);
    }
  });

  it('an explicit id wins over the rules and an unknown id is refused', () => {
    expect(selectAnnotatePlaybook('find chained threats', 'map').id).toBe('map');
    expect(() => selectAnnotatePlaybook('x', 'deep')).toThrow(/Unknown playbook/);
    expect(getPlaybook('exploitable').kind).toBe('annotate');
  });

  it('report shapes: full by default, explicit shape, and the framework word never selects a shape', () => {
    expect(REPORT_SHAPES.map(s => s.id)).toEqual(['full', 'executive', 'pr', 'audit']);
    expect(selectReportShape(undefined).id).toBe('full');
    expect(selectReportShape('executive').id).toBe('executive');
    expect(() => selectReportShape('slides')).toThrow(/Unknown report shape/);
  });
});

describe('the prompt', () => {
  it('names the playbook, puts the method above the generic rules, and carries the evidence bar', () => {
    const p = buildAnnotatePrompt('auth and session code', '/nonexistent', null, 'inline', 'exploitable');
    expect(p).toContain('Playbook: exploitable');
    expect(p).toContain('## Scope and intent');
    expect(p).toContain('auth and session code');
    expect(p).toContain('## Method — Exploitable');
    expect(p.indexOf('## Method — Exploitable')).toBeLessThan(p.indexOf('## HOW TO THINK'));
    expect(p).toContain(EVIDENCE_BAR.trim().split('\n')[0]);
    expect(p).toMatch(/write nothing until/i);
    expect(p).not.toContain('## Your Task');
  });

  it('infers the playbook when none is given, and says so', () => {
    const p = buildAnnotatePrompt('find chained threats as deep as possible', '/nonexistent', null, 'inline');
    expect(p).toContain('Playbook: chains');
    expect(p).toContain('## Method — Chains');
  });

  it('every annotate playbook has a body, a summary, and forbids @accepts and @entitles', () => {
    for (const pb of ANNOTATE_PLAYBOOKS) {
      expect(pb.body.length).toBeGreaterThan(400);
      expect(pb.summary.length).toBeGreaterThan(20);
      expect(pb.body).toMatch(/@accepts/);
      expect(pb.body).toMatch(/@entitles/);
    }
    expect(getPlaybook('map').body).toMatch(/no @exposes|do not write @exposes/i);
  });
});

describe('skills', () => {
  it('renders one SKILL.md per playbook with frontmatter the loader reads and the same body', () => {
    const f = skillFileFor(getPlaybook('exploitable'));
    expect(f.path).toBe('.claude/skills/guardlink-annotate-exploitable/SKILL.md');
    expect(f.content).toMatch(/^---\nname: guardlink-annotate-exploitable\ndescription: .+\n---\n/);
    expect(f.content).toContain('<!-- guardlink:generated -->');
    expect(f.content).toContain(getPlaybook('exploitable').body.trim());
    expect(skillFileFor(getPlaybook('executive')).path).toBe('.claude/skills/guardlink-report-executive/SKILL.md');
  });
});

describe('the CLI', () => {
  it('--stdout --playbook chains prints the prompt with that method', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-pb-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), '/**\n * @asset App.API (#api) -- "API"\n */\nexport {};\n');
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
    const out = await new Promise<{ stdout: string; stderr: string }>((res, rej) =>
      execFile(process.execPath, [tsx, cli, 'annotate', 'the api', '.', '--stdout', '--playbook', 'chains'], { cwd: root, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => (err ? rej(err) : res({ stdout, stderr }))));
    expect(out.stdout).toContain('Playbook: chains');
    expect(out.stdout).toContain('## Method — Chains');
    expect(out.stderr).toMatch(/Playbook: chains/);
  }, 60_000);
});
