/**
 * D24 — `init --force` must not destroy a populated definitions file.
 *
 * Observed in Phase 4: `--force` overwrote 38 declarations with the empty
 * template, plus `config.json`, with no warning and no prompt. It was
 * recoverable only because the file happened to be committed.
 *
 * The tests below assert on FILE CONTENT after the run, not on the result
 * object, because the defect was that the bytes on disk changed — a result
 * object claiming "created" is exactly what it reported while doing it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initProject } from '../src/init/index.js';
import { definitionsArePopulated, configIsCustomised, declarationIds } from '../src/init/preserve.js';

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-init-force-'));
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const defsPath = () => join(root, '.guardlink', 'definitions.js');
const configPath = () => join(root, '.guardlink', 'config.json');
const read = (p: string) => readFile(p, 'utf-8');

/** A definitions file with real declarations, in the host comment syntax. */
const POPULATED_DEFS = `// GuardLink Shared Definitions — demo
// @asset Demo.API (#api) -- "The REST surface"
// @asset Demo.Database (#db) -- "Primary store"
// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Unsanitised input reaches SQL"
// @control Parameterized_Queries (#prepared-stmts) -- "Bound parameters only"
`;

describe('D24 — --force preserves a populated definitions file', () => {
  it('does not overwrite declarations, and says it did not', async () => {
    initProject({ root, agentIds: ['claude'] });
    await writeFile(defsPath(), POPULATED_DEFS);

    const result = initProject({ root, force: true, agentIds: ['claude'] });

    expect(await read(defsPath())).toBe(POPULATED_DEFS);
    expect(result.preserved.join('\n')).toMatch(/definitions\.js/);
    expect(result.preserved.join('\n')).toMatch(/--reset/);
    // Not reported as created or updated — the caller must not be told it wrote.
    expect([...result.created, ...result.updated].join('\n')).not.toMatch(/definitions\.js/);
  });

  it('still re-scaffolds everything else on --force', async () => {
    initProject({ root, agentIds: ['claude'] });
    await writeFile(defsPath(), POPULATED_DEFS);
    await writeFile(join(root, 'CLAUDE.md'), '# hand-edited\n');

    const result = initProject({ root, force: true, agentIds: ['claude'] });

    // The point of --force survives: agent files are rewritten.
    expect(await read(join(root, 'CLAUDE.md'))).toMatch(/guardlink:begin/);
    expect(result.preserved).toHaveLength(1);
  });

  it('--reset does overwrite, because that is what it is for', async () => {
    initProject({ root, agentIds: ['claude'] });
    await writeFile(defsPath(), POPULATED_DEFS);

    const result = initProject({ root, reset: true, agentIds: ['claude'] });

    const after = await read(defsPath());
    expect(after).not.toBe(POPULATED_DEFS);
    expect(after).toMatch(/Your Definitions/);
    expect(result.preserved).toHaveLength(0);
    expect(result.updated.join('\n')).toMatch(/definitions\.js/);
  });

  it('--force overwrites a definitions file that is still the untouched template', async () => {
    initProject({ root, agentIds: ['claude'] });
    const pristine = await read(defsPath());
    await writeFile(defsPath(), pristine + '\n// a note, no declarations\n');

    const result = initProject({ root, force: true, agentIds: ['claude'] });

    expect(await read(defsPath())).toBe(pristine);
    expect(result.preserved).toHaveLength(0);
  });

  it('--dry-run with a populated file writes nothing at all', async () => {
    initProject({ root, agentIds: ['claude'] });
    await writeFile(defsPath(), POPULATED_DEFS);

    const result = initProject({ root, reset: true, dryRun: true, agentIds: ['claude'] });

    expect(await read(defsPath())).toBe(POPULATED_DEFS);
    expect(result.updated.join('\n')).toMatch(/definitions\.js/);
  });
});

describe('D24 — --force preserves a customised config.json', () => {
  it('keeps user exclude rules', async () => {
    initProject({ root, agentIds: ['claude'] });
    const cfg = JSON.parse(await read(configPath()));
    cfg.exclude = [...cfg.exclude, 'legacy/**'];
    cfg.llm = { provider: 'anthropic' };
    await writeFile(configPath(), JSON.stringify(cfg, null, 2) + '\n');

    const result = initProject({ root, force: true, agentIds: ['claude'] });

    const after = JSON.parse(await read(configPath()));
    expect(after.exclude).toContain('legacy/**');
    expect(after.llm).toEqual({ provider: 'anthropic' });
    expect(result.preserved.join('\n')).toMatch(/config\.json/);
  });

  it('a recorded annotation_mode is authored content — --force does not flip it', async () => {
    initProject({ root, mode: 'inline', agentIds: ['claude'] });

    initProject({ root, mode: 'external', force: true, agentIds: ['claude'] });

    expect(JSON.parse(await read(configPath())).annotation_mode).toBe('inline');
  });

  it('an untouched config is rewritten by --force', async () => {
    initProject({ root, agentIds: ['claude'] });

    const result = initProject({ root, force: true, agentIds: ['claude'] });

    expect(result.preserved.join('\n')).not.toMatch(/config\.json/);
    expect(result.updated.join('\n')).toMatch(/config\.json/);
  });
});

describe('D24 — the guards themselves', () => {
  it('the shipped template declares nothing, so any declaration is authored', async () => {
    initProject({ root, agentIds: ['claude'] });
    const template = await read(defsPath());
    expect(declarationIds(template, 'definitions.js').size).toBe(0);
    expect(definitionsArePopulated(POPULATED_DEFS, template, 'definitions.js')).toBe(true);
    expect(definitionsArePopulated(template, template, 'definitions.js')).toBe(false);
  });

  it('unparseable config counts as customised rather than as empty', () => {
    expect(configIsCustomised('{ not json', '{}')).toBe(true);
  });

  it('key order and formatting are not customisation', () => {
    expect(configIsCustomised('{"b":2,"a":1}', '{"a":1,"b":2}')).toBe(false);
  });
});
