/**
 * GL-506 — `--mode` and `--no-root-files` are independent axes.
 *
 * Before this, `--mode external` meant two unrelated things at once: annotations
 * go in sidecars, AND init writes nothing outside `.guardlink/`. Choosing the
 * first cost you the second, so "keep annotations out of my source" silently
 * removed MCP auto-discovery and every agent instruction file — the things that
 * make an agent aware GuardLink exists.
 *
 * The matrix is tested as a matrix, because the bug was that two of the four
 * cells were unreachable.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject } from '../src/init/index.js';

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-init-mode-'));
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
  await writeFile(join(root, 'src', 'auth.ts'), 'export function login(e: string) { return e.length > 0; }\n');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const has = (...parts: string[]) => existsSync(join(root, ...parts));
const configMode = async () =>
  JSON.parse(await readFile(join(root, '.guardlink', 'config.json'), 'utf-8')).annotation_mode;

const MODES = ['inline', 'external'] as const;

describe('GL-506 — mode decides where annotations live, and only that', () => {
  it.each(MODES)('%s is recorded in config.json', async (mode) => {
    initProject({ root, mode, agentIds: [] });
    expect(await configMode()).toBe(mode);
  });

  it.each(MODES)('%s mode still gets a root .mcp.json by default', (mode) => {
    initProject({ root, mode, agentIds: [] });
    expect(has('.mcp.json')).toBe(true);
    expect(has('.guardlink', '.mcp.json')).toBe(false);
  });

  it.each(MODES)('%s mode still gets agent instruction files by default', (mode) => {
    initProject({ root, mode, agentIds: ['claude'] });
    expect(has('CLAUDE.md')).toBe(true);
  });

  it.each(MODES)('%s mode still gets docs/ and .gitattributes by default', (mode) => {
    initProject({ root, mode, agentIds: [] });
    expect(has('docs', 'GUARDLINK_REFERENCE.md')).toBe(true);
    expect(has('.gitattributes')).toBe(true);
  });
});

describe('GL-506 — rootFiles decides the footprint, and only that', () => {
  it.each(MODES)('%s + --no-root-files writes nothing outside .guardlink/', (mode) => {
    initProject({ root, mode, rootFiles: false, agentIds: ['claude'] });
    expect(has('.mcp.json')).toBe(false);
    expect(has('CLAUDE.md')).toBe(false);
    expect(has('docs')).toBe(false);
    expect(has('.gitattributes')).toBe(false);
  });

  it.each(MODES)('%s + --no-root-files still records its own mode', async (mode) => {
    initProject({ root, mode, rootFiles: false, agentIds: [] });
    expect(await configMode()).toBe(mode);
  });

  it('--no-root-files relocates rather than drops the reference doc and MCP config', () => {
    initProject({ root, rootFiles: false, agentIds: [] });
    expect(has('.guardlink', 'GUARDLINK_REFERENCE.md')).toBe(true);
    expect(has('.guardlink', '.mcp.json')).toBe(true);
  });

  it('--no-root-files leaves an existing .gitignore alone', async () => {
    await writeFile(join(root, '.gitignore'), 'node_modules\n');
    initProject({ root, rootFiles: false, agentIds: [] });
    expect(await readFile(join(root, '.gitignore'), 'utf-8')).toBe('node_modules\n');
  });

  it('the default DOES append to an existing .gitignore', async () => {
    await writeFile(join(root, '.gitignore'), 'node_modules\n');
    initProject({ root, agentIds: [] });
    expect(await readFile(join(root, '.gitignore'), 'utf-8')).toContain('GuardLink');
  });
});

describe('GL-506 — the new default', () => {
  it('is external annotations WITH root files', async () => {
    const result = initProject({ root, agentIds: ['claude'] });
    expect(await configMode()).toBe('external');
    expect(has('.mcp.json')).toBe(true);
    expect(has('CLAUDE.md')).toBe(true);
    expect(result.created).toContain('.mcp.json');
  });

  it('README states the mode it was actually initialised in', async () => {
    initProject({ root, agentIds: [] });
    const text = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    expect(text).toMatch(/external/);
  });

  it('all four cells of the matrix are reachable and distinct', async () => {
    const shapes: string[] = [];
    for (const mode of MODES) {
      for (const rootFiles of [true, false]) {
        // Each cell needs its own clean root — init skips what already exists,
        // so reusing one would make every cell after the first look identical.
        const cell = await mkdtemp(join(tmpdir(), 'guardlink-matrix-'));
        await writeFile(join(cell, 'package.json'), '{"name":"demo"}\n');
        initProject({ root: cell, mode, rootFiles, agentIds: ['claude'] });
        const cfg = JSON.parse(await readFile(join(cell, '.guardlink', 'config.json'), 'utf-8'));
        shapes.push([
          cfg.annotation_mode,
          existsSync(join(cell, '.mcp.json')) ? 'root-mcp' : 'no-root-mcp',
          existsSync(join(cell, 'CLAUDE.md')) ? 'agent-files' : 'no-agent-files',
        ].join('/'));
        await rm(cell, { recursive: true, force: true });
      }
    }
    expect(shapes).toEqual([
      'inline/root-mcp/agent-files',
      'inline/no-root-mcp/no-agent-files',
      'external/root-mcp/agent-files',
      'external/no-root-mcp/no-agent-files',
    ]);
  });
});
