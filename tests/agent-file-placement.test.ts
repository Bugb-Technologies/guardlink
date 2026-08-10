/**
 * D27 — every agent instruction file must name where annotations go.
 *
 * `agentInstructions(project)` took no mode parameter, so no agent file COULD
 * state it. Verified on a fresh default-init repo: `config.json` said
 * `annotation_mode: external`, while `CLAUDE.md` contained zero occurrences of
 * `.gal`, `annotations/`, `sidecar` or `@source` — its one "external" was
 * "external API calls". `.guardlink/README.md` said it correctly, but that is
 * the cold-start path, not the file an agent reads every turn.
 *
 * Consequence under the new external default: an agent reads inline syntax with
 * no placement guidance, writes inline, and the repo silently goes mixed.
 *
 * Every assertion here is on FILE CONTENT after a real init or sync. Asserting
 * that the template function ran is what let this ship — the function ran fine,
 * it just had nothing to say.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject, syncAgentFiles } from '../src/init/index.js';
import { annotationPlacementSection } from '../src/init/templates.js';
import { parseProject } from '../src/parser/parse-project.js';
import { parseString } from '../src/parser/parse-file.js';

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-d27-'));
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
  await writeFile(join(root, 'src', 'auth.ts'), 'export const login = (e: string) => e.length > 0;\n');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const read = (...p: string[]) => readFile(join(root, ...p), 'utf-8');

/** Files that carry the markdown instruction block. */
const MARKDOWN_AGENT_FILES = [
  'CLAUDE.md',
  'AGENTS.md',
  '.github/copilot-instructions.md',
  '.gemini/GEMINI.md',
];
/** Files that carry the flat cursor-rules block. */
const FLAT_AGENT_FILES = ['.clinerules', '.windsurfrules'];

const ALL_AGENTS = ['claude', 'codex', 'copilot', 'gemini', 'cline', 'windsurf', 'cursor'];

describe('D27 — external mode names the sidecar location', () => {
  beforeEach(() => {
    initProject({ root, mode: 'external', agentIds: ALL_AGENTS });
  });

  it('config.json records external', async () => {
    expect(JSON.parse(await read('.guardlink', 'config.json')).annotation_mode).toBe('external');
  });

  it.each(MARKDOWN_AGENT_FILES)('%s names .gal, annotations/ and @source', async (file) => {
    if (!existsSync(join(root, file))) return; // agent not selected in this build
    const content = await read(file);
    expect(content).toMatch(/\.gal/);
    expect(content).toMatch(/\.guardlink\/annotations\//);
    expect(content).toMatch(/@source/);
    // The exact regression: the only "external" in the file was "external API calls".
    expect(content).toMatch(/annotation mode: `external`/i);
  });

  it.each(FLAT_AGENT_FILES)('%s names .gal and annotations/', async (file) => {
    if (!existsSync(join(root, file))) return;
    const content = await read(file);
    expect(content).toMatch(/\.gal/);
    expect(content).toMatch(/\.guardlink\/annotations\//);
  });

  it('.cursor/rules/guardlink.mdc names the sidecar location', async () => {
    const p = join(root, '.cursor', 'rules', 'guardlink.mdc');
    if (!existsSync(p)) return;
    const content = await readFile(p, 'utf-8');
    expect(content).toMatch(/\.gal/);
    expect(content).toMatch(/\.guardlink\/annotations\//);
  });

  it('does not tell the agent to write annotations into source comments', async () => {
    const content = await read('CLAUDE.md');
    expect(content).toMatch(/not edit source files to add annotations in this mode|Do\s*\n?not edit source files/i);
  });
});

describe('D27 — inline mode names source comments', () => {
  beforeEach(() => {
    initProject({ root, mode: 'inline', agentIds: ALL_AGENTS });
  });

  it('config.json records inline', async () => {
    expect(JSON.parse(await read('.guardlink', 'config.json')).annotation_mode).toBe('inline');
  });

  it.each(MARKDOWN_AGENT_FILES)('%s states inline and forbids sidecars', async (file) => {
    if (!existsSync(join(root, file))) return;
    const content = await read(file);
    expect(content).toMatch(/annotation mode: `inline`/i);
    expect(content).toMatch(/source-file comments/i);
    expect(content).toMatch(/Do not create `\.gal` sidecars/);
  });

  it('the doc-block example is present', async () => {
    expect(await read('CLAUDE.md')).toMatch(/export function login/);
  });
});

describe('D27 — the two modes actually differ in the emitted file', () => {
  it('CLAUDE.md is not byte-identical across modes', async () => {
    initProject({ root, mode: 'external', agentIds: ['claude'] });
    const external = await read('CLAUDE.md');

    await rm(join(root, '.guardlink'), { recursive: true, force: true });
    await rm(join(root, 'CLAUDE.md'), { force: true });
    initProject({ root, mode: 'inline', agentIds: ['claude'] });
    const inline = await read('CLAUDE.md');

    expect(external).not.toBe(inline);
    expect(external).toMatch(/annotation mode: `external`/i);
    expect(inline).toMatch(/annotation mode: `inline`/i);
    // Inline mode does name `.guardlink/annotations/` — to forbid it. What it
    // must not do is hand the agent the sidecar convention as the way to write.
    expect(external).toMatch(/@source file:/);
    expect(inline).not.toMatch(/@source file:/);
  });
});

describe('D27 — sync keeps the statement true', () => {
  it('sync re-states the configured mode rather than dropping it', async () => {
    initProject({ root, mode: 'external', agentIds: ['claude'] });
    const { model } = await parseProject({ root, project: 'demo' });

    syncAgentFiles({ root, model });

    const content = await read('CLAUDE.md');
    expect(content).toMatch(/annotation mode: `external`/i);
    expect(content).toMatch(/@source/);
  });

  it('the README and the agent file carry the SAME placement text', async () => {
    initProject({ root, mode: 'external', agentIds: ['claude'] });
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });

    const shared = annotationPlacementSection(
      { ...(await import('../src/init/detect.js')).detectProject(root) },
      'external',
    );
    const marker = shared.split('\n').find(l => l.includes('login.ts.gal'))!;

    expect(await read('CLAUDE.md')).toContain(marker);
    expect(await read('.guardlink', 'README.md')).toContain(marker);
  });
});

describe('D27 — the mixed and unrecorded cases are stated, not guessed', () => {
  it('mixed says so and refuses to pick', () => {
    const project = { commentPrefix: '//', definitionsExt: '.ts' } as never;
    const s = annotationPlacementSection(project, 'mixed');
    expect(s).toMatch(/MIXED/);
    expect(s).toMatch(/guardlink migrate --to/);
  });

  it('an unrecorded mode still gives placement, labelled as a default', () => {
    const project = { commentPrefix: '//', definitionsExt: '.ts' } as never;
    const s = annotationPlacementSection(project, null);
    expect(s).toMatch(/\.gal/);
    expect(s).toMatch(/not recorded/i);
  });

  it('a python project gets a python example, not a TypeScript one', () => {
    const project = { commentPrefix: '#', definitionsExt: '.py' } as never;
    const s = annotationPlacementSection(project, 'inline');
    expect(s).toMatch(/def login/);
    expect(s).not.toMatch(/export function/);
  });
});

describe('D22 — the placement examples must not parse as real annotations', () => {
  it('templates.ts contributes no annotations from the placement section', async () => {
    const src = await readFile(
      new URL('../src/init/templates.ts', import.meta.url),
      'utf-8',
    );
    const parsed = parseString(src, 'templates.ts');
    const leaked = parsed.annotations.filter(a =>
      JSON.stringify(a).includes('#sqli') ||
      JSON.stringify(a).includes('prepared-stmts') ||
      JSON.stringify(a).includes('CWE-89'),
    );
    // Any that survive must be inside a shield, which the parser drops.
    expect(leaked).toEqual([]);
  });

  it('the initialised repo declares no #sqli / #api from our own templates', async () => {
    initProject({ root, mode: 'inline', agentIds: ALL_AGENTS });
    const { model } = await parseProject({ root, project: 'demo' });
    const ids = [
      ...model.assets.map(a => a.id),
      ...model.threats.map(t => t.id),
      ...model.controls.map(c => c.id),
    ];
    expect(ids).not.toContain('sqli');
    expect(ids).not.toContain('api');
    expect(ids).not.toContain('prepared-stmts');
  });
});
