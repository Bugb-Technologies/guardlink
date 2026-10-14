/**
 * GL-403 — the synced agent-instruction block.
 *
 * The block was well-built and badly framed: it opened with an obligation, its
 * truncated lists led nowhere, it carried no freshness marker, and it never
 * mentioned the two commands that answer the questions agents actually have
 * ("what is this file?" and "did I make it worse?").
 *
 * It is now a short, stamped pointer (SPEC §5.6): what holds here, where
 * annotations go, the rules a person must never have taken from them, and
 * where to ask. The live model is not copied into it — `buildModelContext`
 * still renders that view for callers who want it, and its tests stay below —
 * and every block carries a provenance stamp `guardlink validate` checks.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { buildModelContext, agentInstructions, agentInstructionsWithModel } from '../src/init/templates.js';
import { detectProject } from '../src/init/detect.js';
import { initProject, syncAgentFiles, blockStamp } from '../src/init/index.js';
import { findAgentConfigDiagnostics } from '../src/parser/validate.js';
import { parseStamp } from '../src/agentconfig/read.js';
import { existsSync } from 'node:fs';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const project = { name: 'demo', language: 'typescript', definitionsExt: '.ts' } as ReturnType<typeof detectProject>;

/**
 * A model with something in it. Every GL-403 assertion below is about the block
 * a repository gets once it HAS a threat model — the claim it opens with is
 * rendered on that condition now, because a repository with no annotations was
 * getting it too and it was false there (caveat 7; see
 * `agent-block-empty-model.test.ts` for the other branch).
 */
const populatedModel = {
  version: '1.0.0', project: 'demo', generated_at: '', source_files: 2,
  annotated_files: ['a.ts'], unannotated_files: ['b.ts'], annotations_parsed: 12,
  assets: [], threats: [], controls: [], mitigations: [], exposures: [], confirmed: [],
  acceptances: [], transfers: [], flows: [], boundaries: [], validations: [], audits: [],
  ownership: [], data_handling: [], assumptions: [], shields: [], features: [], comments: [],
  coverage: { annotation_count: 12, coverage_percent: 50 },
} as ThreatModel;

describe('GL-403 — weakness 1: leads with capability, not obligation', () => {
  const text = agentInstructions(project, null, { model: populatedModel });

  it('opens by saying what the model gives you', () => {
    const head = text.slice(0, 700);
    expect(head).toMatch(/Ask it instead of inferring security context/);
    // The obligation still exists — it just is not the first thing a cold agent reads.
    expect(head).not.toMatch(/you MUST add/i);
  });

  it('the obligation follows, framed as reciprocity', () => {
    expect(text).toMatch(/What you owe it back/);
    expect(text.indexOf('Ask it instead')).toBeLessThan(text.indexOf('What you owe it back'));
  });

  it('the opening names the trigger moments', () => {
    for (const trigger of ['before you\nedit a file', 'change a shared component', 'scanner finding', 'Before you finish']) {
      expect(text, trigger).toContain(trigger);
    }
  });

  it('offers the CLI path for an agent with no MCP', () => {
    expect(text).toMatch(/Without MCP, `guardlink status \.`\s+and `guardlink parse \.` answer the same/);
  });
});

describe('GL-403 — weakness 4: the block names context, graph, the CWE bridge and diff', () => {
  const text = agentInstructions(project, null, { model: populatedModel });

  it('mentions guardlink_context and guardlink diff', () => {
    expect(text).toContain('guardlink_context');
    expect(text).toContain('guardlink diff HEAD~1');
  });

  it('names the graph and the CWE bridge', () => {
    expect(text).toContain('guardlink_graph');
    expect(text).toMatch(/cwe:CWE-89/);
  });
});

describe('the block is a pointer, not a copy of the model', () => {
  const text = agentInstructions(project, 'inline', { model: populatedModel });

  it('stays short: about 30 lines', () => {
    // 25 before the pre-PR step (SPEC §8.1); each `pre_pr` entry adds one more,
    // and init/pre-pr.ts renders at most five.
    expect(text.trimEnd().split('\n').length).toBeLessThanOrEqual(31);
  });

  it('points at the reference document and the README for everything it leaves out', () => {
    expect(text).toContain('docs/GUARDLINK_REFERENCE.md');
    expect(text).toContain('.guardlink/README.md');
  });

  it('keeps the two decisions an agent must never take for a person', () => {
    expect(text).toMatch(/Never write `@accepts` or `@entitles`/);
    expect(text).toContain('guardlink entitle --propose');
  });

  it('says the agent configuration is part of the threat model, and points at the lookup rather than restating reach', () => {
    expect(text).toContain('guardlink lookup "agent config"');
    expect(text).toMatch(/never write `@agents` or `@reaches` for Claude Code, Cursor, Copilot, Codex or Gemini/);
  });

  it('copies no model content that would go stale between syncs', () => {
    const withLists = agentInstructionsWithModel(project, {
      ...populatedModel,
      assets: [{ path: ['App', 'Secret'], id: 'secret-asset', location: { file: 'a.ts', line: 1 } }],
    } as ThreatModel);
    expect(withLists).not.toContain('secret-asset');
    expect(withLists).not.toMatch(/Open Exposures|Existing Data Flows|Model Stats/);
  });
});

describe('GL-403 — weakness 2: truncated lists name their retrieval', () => {
  function modelWith(counts: { exposures: number; flows: number; confirmed: number }): ThreatModel {
    const loc = { file: 'a.ts', line: 1 };
    return {
      version: '1.0.0', project: 'test', generated_at: '', source_files: 0,
      annotated_files: [], unannotated_files: [], annotations_parsed: 999,
      assets: [], threats: [], controls: [], mitigations: [],
      exposures: Array.from({ length: counts.exposures }, (_, i) => ({ asset: `#a${i}`, threat: '#t', location: loc })),
      confirmed: Array.from({ length: counts.confirmed }, (_, i) => ({ asset: `#c${i}`, threat: '#t', location: loc })),
      acceptances: [], transfers: [],
      flows: Array.from({ length: counts.flows }, (_, i) => ({ source: `#s${i}`, target: '#t', location: loc })),
      boundaries: [], validations: [], audits: [], ownership: [], data_handling: [],
      assumptions: [], shields: [], features: [], comments: [],
      coverage: { annotation_count: 0, coverage_percent: 0 },
    } as ThreatModel;
  }

  it('an over-length exposure list points at the query that returns the rest', () => {
    const text = buildModelContext(modelWith({ exposures: 40, flows: 0, confirmed: 0 }));
    expect(text).toMatch(/… and 15 more/);
    expect(text).toMatch(/guardlink_lookup\("unmitigated"\)/);
  });

  it('an over-length flow list points at lookup AND graph', () => {
    const text = buildModelContext(modelWith({ exposures: 0, flows: 35, confirmed: 0 }));
    expect(text).toMatch(/… and 15 more/);
    expect(text).toMatch(/flows into X/);
    expect(text).toMatch(/guardlink_graph/);
  });

  it('an over-length confirmed list points at its query', () => {
    const text = buildModelContext(modelWith({ exposures: 0, flows: 0, confirmed: 30 }));
    expect(text).toMatch(/guardlink_lookup\("confirmed"\)/);
  });

  it('no "and N more" is left without somewhere to go', () => {
    const text = buildModelContext(modelWith({ exposures: 40, flows: 35, confirmed: 30 }));
    for (const line of text.split('\n').filter(l => /and \d+ more/.test(l))) {
      expect(line, line).toMatch(/guardlink_/);
    }
  });

  it('the definitions list points at the full records', () => {
    const model = modelWith({ exposures: 0, flows: 0, confirmed: 0 });
    model.assets = [{ path: ['A'], id: 'a', location: { file: 'a.ts', line: 1 } }];
    expect(buildModelContext(model)).toMatch(/guardlink_lookup\("asset <id>"\)/);
  });
});

describe('GL-403 — weakness 3: the block declares its own freshness', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  it('carries annotation_hash', () => {
    const text = buildModelContext(model, { annotation_hash: computeAnnotationHash(model) });
    expect(text).toMatch(/### Block Freshness/);
    expect(text).toContain(computeAnnotationHash(model));
  });

  it('carries NO volatile fields', () => {
    // synced_at and git_sha were here and are deliberately gone: this block lives
    // in tracked files regenerated on every sync, so a field moving for reasons
    // unrelated to its content makes every regeneration a diff. Both still ship
    // in the MCP envelope, computed per call and written nowhere.
    const text = buildModelContext(model, { annotation_hash: 'sha256-v1:abc' });
    expect(text).not.toMatch(/synced_at/);
    expect(text).not.toMatch(/git_sha/);
    expect(text).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it('points at the envelope for the fields it no longer carries', () => {
    const text = buildModelContext(model, { annotation_hash: 'sha256-v1:abc' });
    expect(text).toMatch(/read the envelope on any MCP/);
  });

  it('tells the reader what to do when the hash disagrees', () => {
    const text = buildModelContext(model, { annotation_hash: 'sha256-v1:deadbeef' });
    expect(text).toMatch(/trust the tool/);
    expect(text).toMatch(/guardlink sync/);
  });

  it('omitting freshness omits the section rather than emitting placeholders', () => {
    expect(buildModelContext(model)).not.toMatch(/Block Freshness/);
  });

  it('the hash in the block equals the one the MCP envelope reports', () => {
    const text = buildModelContext(model, { annotation_hash: computeAnnotationHash(model) });
    expect(text).toContain(computeAnnotationHash(model));
  });
});

describe('GL-403 — end to end through sync', () => {
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-block-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
    await writeFile(join(root, 'src', 'auth.ts'),
      '/**\n * @asset App.Auth (#auth) -- "auth"\n * @threat SQLi (#sqli) [high] cwe:CWE-89 -- "sqli"\n'
      + ' * @exposes #auth to #sqli [high] -- "concatenated"\n */\nexport function login() {}\n');
    initProject({ root, mode: 'inline', agentIds: ['claude', 'codex', 'cline', 'windsurf'] });
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('a freshly synced CLAUDE.md carries the provenance stamp', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const text = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    expect(parseStamp(text)).toEqual({
      annotation_hash: computeAnnotationHash(model),
      agent_config_hash: model.agent_config!.agent_config_hash,
    });
    expect(text.indexOf('<!-- guardlink:stamp')).toBe(text.indexOf('<!-- guardlink:begin -->') + '<!-- guardlink:begin -->\n'.length);
  });

  it('carries NO volatile fields', async () => {
    const text = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    expect(text).not.toMatch(/synced_at|git_sha/);
    expect(text).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it('every agent file gets the stamp, not only the markdown ones', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    for (const file of ['CLAUDE.md', 'AGENTS.md', '.clinerules', '.windsurfrules']) {
      const text = await readFile(join(root, file), 'utf-8');
      expect(parseStamp(text)?.annotation_hash, file).toBe(computeAnnotationHash(model));
    }
  });

  it('validate finds every block current after a sync, and stale after an annotation changes', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const { model: synced } = await parseProject({ root, project: 'demo' });
    expect(findAgentConfigDiagnostics(synced).filter(d => d.code?.startsWith('agent-block'))).toEqual([]);
    await writeFile(join(root, 'src', 'auth.ts'),
      '/**\n * @asset App.Auth (#auth) -- "auth"\n * @threat SQLi (#sqli) [high] cwe:CWE-89 -- "sqli"\n'
      + ' * @exposes #auth to #sqli [high] -- "concatenated, still"\n */\nexport function login() {}\n');
    const { model: moved } = await parseProject({ root, project: 'demo' });
    const stale = findAgentConfigDiagnostics(moved).filter(d => d.code === 'agent-block-stale').map(d => d.file).sort();
    expect(stale).toEqual(['.clinerules', '.windsurfrules', 'AGENTS.md', 'CLAUDE.md']);
    syncAgentFiles({ root, model: moved });
  });

  it('two consecutive syncs of an unchanged model are BYTE-IDENTICAL', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const first = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    await new Promise(r => setTimeout(r, 5));
    syncAgentFiles({ root, model });
    const second = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    expect(second).toBe(first);
  });

  it('every agent file is byte-stable across syncs, not only CLAUDE.md', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const before = new Map<string, string>();
    for (const f of ['CLAUDE.md', 'AGENTS.md', '.clinerules', '.windsurfrules']) {
      before.set(f, await readFile(join(root, f), 'utf-8'));
    }
    await new Promise(r => setTimeout(r, 5));
    syncAgentFiles({ root, model });
    for (const [f, text] of before) {
      expect(await readFile(join(root, f), 'utf-8'), f).toBe(text);
    }
  });

  it('a changed annotation DOES change the block', async () => {
    // Byte-stability must not come from the block being inert: the stamp moves.
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const before = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    await writeFile(join(root, 'src', 'auth.ts'),
      '/**\n * @asset App.Auth (#auth) -- "auth"\n * @threat SQLi (#sqli) [low] cwe:CWE-89 -- "sqli"\n'
      + ' * @exposes #auth to #sqli [low] -- "changed"\n */\nexport function login() {}\n');
    const { model: after } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model: after });
    expect(await readFile(join(root, 'CLAUDE.md'), 'utf-8')).not.toBe(before);
  });

  it('the README, like the agent block, stays byte-stable', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const a = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    syncAgentFiles({ root, model });
    const b = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    expect(b).toBe(a);
  });

  it('a model with no annotations gets the empty opening', () => {
    const text = agentInstructionsWithModel(project, null);
    expect(text).not.toMatch(/Ask it instead of inferring/);
    expect(text).toContain('**its threat model is empty**');
  });
});

describe('the block goes only into instruction files that exist', () => {
  let root: string;
  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-existing-'));
    await writeFile(join(root, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
    await writeFile(join(root, 'AGENTS.md'), '# Contributing notes for agents\n\nRun the tests.\n');
  });
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('init with no --agent writes into AGENTS.md, which exists, and creates nothing else', () => {
    const r = initProject({ root });
    expect(r.updated).toContain('AGENTS.md');
    for (const f of ['CLAUDE.md', '.windsurfrules', '.clinerules', '.github/copilot-instructions.md', '.gemini/GEMINI.md', '.cursor/rules/guardlink.mdc']) {
      expect(existsSync(join(root, f)), f).toBe(false);
    }
  });

  it('keeps the file\'s own content and stamps the block, empty model included', async () => {
    const text = await readFile(join(root, 'AGENTS.md'), 'utf-8');
    expect(text.startsWith('# Contributing notes for agents\n\nRun the tests.\n')).toBe(true);
    expect(parseStamp(text)).toEqual(blockStamp(root, null));
    expect(text).toContain('**its threat model is empty**');
  });

  it('sync does not create the files that are missing either', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    const r = syncAgentFiles({ root, model });
    expect(r.updated).toContain('AGENTS.md');
    expect(r.updated).not.toContain('CLAUDE.md');
    expect(existsSync(join(root, 'CLAUDE.md'))).toBe(false);
    expect(r.skipped.some(s => s.startsWith('CLAUDE.md (absent'))).toBe(true);
  });

  it('an explicit --agent creates the file it names', () => {
    initProject({ root, agentIds: ['claude'] });
    expect(existsSync(join(root, 'CLAUDE.md'))).toBe(true);
  });
});
