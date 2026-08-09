/**
 * GL-402 — `.guardlink/README.md`, the cold-start backstop.
 *
 * Under external-mode default this is the ONLY surviving discovery path: init
 * skips the agent instruction files and moves `.mcp.json` where clients do not
 * auto-discover it. So the tests that matter most here are "written in both
 * modes" and "regenerated without drift" — a README that only appears in inline
 * mode, or that rots, is worse than none, because the other two paths are gone.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject, syncAgentFiles } from '../src/init/index.js';
import { parseProject } from '../src/parser/parse-project.js';
import { guardlinkReadmeContent } from '../src/init/templates.js';
import { detectProject } from '../src/init/detect.js';

async function scratch(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `guardlink-${prefix}-`));
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
  await writeFile(join(root, 'src', 'auth.ts'), 'export function login(e: string) { return e.length > 0; }\n');
  return root;
}

describe('GL-402 — init writes the README in BOTH modes', () => {
  it.each(['inline', 'external'] as const)('%s mode gets a README', async (mode) => {
    const root = await scratch(`readme-${mode}`);
    try {
      const result = initProject({ root, mode, skipAgentFiles: true });
      expect(result.created).toContain('.guardlink/README.md');
      expect(existsSync(join(root, '.guardlink', 'README.md'))).toBe(true);
      const text = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
      expect(text.length).toBeGreaterThan(2000);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('external mode still gets it even though everything else outside .guardlink/ is skipped', async () => {
    const root = await scratch('readme-ext-only');
    try {
      initProject({ root, mode: 'external' });
      // The discovery paths that vanish under external default…
      expect(existsSync(join(root, 'CLAUDE.md'))).toBe(false);
      expect(existsSync(join(root, '.mcp.json'))).toBe(false);
      // …leaving this one, which must therefore exist.
      expect(existsSync(join(root, '.guardlink', 'README.md'))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('records the annotation mode in config.json so it can be stated, not guessed', async () => {
    const root = await scratch('readme-cfg');
    try {
      initProject({ root, mode: 'external', skipAgentFiles: true });
      const cfg = JSON.parse(await readFile(join(root, '.guardlink', 'config.json'), 'utf-8'));
      expect(cfg.annotation_mode).toBe('external');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('GL-402 — sync regenerates it without drift', () => {
  let root: string;

  beforeAll(async () => {
    root = await scratch('readme-sync');
    initProject({ root, mode: 'external', skipAgentFiles: true });
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'auth.ts.gal'),
      '@source file:src/auth.ts line:1 symbol:login\n'
      + '@exposes App.Auth to #injection [high] cwe:CWE-89 -- "concatenated SQL"\n'
      + '@flows User -> App.Auth via HTTPS -- "login request"\n');
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('two consecutive syncs produce a byte-identical README', async () => {
    // It carries no wall-clock timestamp deliberately: this is a tracked file
    // regenerated on every sync, and a clock would churn the diff on every run
    // while telling the reader nothing annotation_hash does not.
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const first = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    syncAgentFiles({ root, model });
    const second = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    expect(second).toBe(first);
  });

  it('the regenerated README reflects the real model, not init-time placeholders', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const text = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    expect(text).toContain(`${model.annotations_parsed} annotations`);
    expect(text).toMatch(/Content hash: `sha256-v\d+:/);
  });

  it('the content hash moves when the annotations do', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const before = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');

    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'auth.ts.gal'),
      '@source file:src/auth.ts line:1 symbol:login\n'
      + '@exposes App.Auth to #injection [low] cwe:CWE-89 -- "concatenated SQL"\n');
    const { model: after } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model: after });
    const text = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    expect(text).not.toBe(before);
  });
});

describe('GL-402 — content an agent needs', () => {
  const project = { name: 'demo', language: 'typescript', definitionsExt: '.ts' } as ReturnType<typeof detectProject>;
  const base = { model: null, annotationHash: null, modeSource: 'config' as const };

  const inline = () => guardlinkReadmeContent(project, { ...base, mode: 'inline', mcpAtRoot: true });
  const external = () => guardlinkReadmeContent(project, { ...base, mode: 'external', mcpAtRoot: false });

  it('addresses an agent reader explicitly', () => {
    expect(inline()).toMatch(/If you are an AI coding agent/);
  });

  it('leads with a worked question answered end to end', () => {
    const text = inline();
    expect(text).toMatch(/one real question, answered end to end/i);
    expect(text).toContain('guardlink_context(file: "src/auth/login.ts")');
    // …and the shell path, for a reader with no MCP at all.
    expect(text).toMatch(/guardlink parse \./);
  });

  it('teaches the empty-vs-never-read distinction', () => {
    const text = inline();
    for (const status of ['annotated', 'scanned_without_annotations', 'not_scanned', 'not_found']) {
      expect(text, status).toContain(status);
    }
    expect(text).toMatch(/easiest way to draw a wrong conclusion/);
  });

  it('explains where .gal files live and how paths map to source', () => {
    const text = external();
    expect(text).toContain('.guardlink/annotations/src/auth/login.ts.gal');
    expect(text).toMatch(/@source file:/);
    expect(text).toMatch(/raw GAL lines/);
  });

  it('states the D4 gap rather than documenting a convention that loses data', () => {
    const text = external();
    expect(text).toMatch(/Known gap/);
    expect(text).toMatch(/silently dropped/);
    expect(text).toMatch(/test\//);
    expect(text).toMatch(/GL-503/);
  });

  it('lists CLI commands and MCP tools, and how to enable MCP', () => {
    const text = inline();
    for (const cmd of ['guardlink status', 'guardlink parse', 'guardlink validate', 'guardlink diff']) {
      expect(text, cmd).toContain(cmd);
    }
    for (const tool of ['guardlink_context', 'guardlink_graph', 'guardlink_lookup', 'guardlink_diff']) {
      expect(text, tool).toContain(tool);
    }
    expect(text).toMatch(/Enabling the MCP tools/);
  });

  it('tells an external-mode reader that .mcp.json is not auto-discovered there', () => {
    expect(external()).toMatch(/do \*\*not\*\* auto-discover/);
    expect(inline()).toMatch(/auto-discover it, such as Claude Code/);
  });

  it('says never to write @accepts', () => {
    expect(inline()).toMatch(/Never write `@accepts`/);
  });

  it('explains how to read matched_via and external_id.declared', () => {
    const text = inline();
    expect(text).toMatch(/matched_via/);
    expect(text).toMatch(/substring match is a suggestion/);
    expect(text).toMatch(/external_id\.declared/);
  });

  it('an unrecorded mode is admitted rather than guessed', () => {
    const text = guardlinkReadmeContent(project, { ...base, mode: null, modeSource: 'default', mcpAtRoot: true });
    expect(text).toMatch(/Not recorded/);
  });

  it('says it is generated and must not be hand-edited', () => {
    expect(inline()).toMatch(/generated.*guardlink sync.*do not edit/is);
  });

  it('does not advertise the graph\\/ artifacts, which do not exist yet', () => {
    // SG-3 is unbuilt. Documenting a directory init never creates would send a
    // cold agent looking for files that are not there.
    expect(inline()).not.toMatch(/graph\//);
    expect(inline()).not.toMatch(/MANIFEST\.json/);
  });
});
