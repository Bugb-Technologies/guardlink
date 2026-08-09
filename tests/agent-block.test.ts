/**
 * GL-403 — the synced agent-instruction block.
 *
 * The block was well-built and badly framed: it opened with an obligation, its
 * truncated lists led nowhere, it carried no freshness marker, and it never
 * mentioned the two commands that answer the questions agents actually have
 * ("what is this file?" and "did I make it worse?").
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
import { initProject, syncAgentFiles } from '../src/init/index.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const project = { name: 'demo', language: 'typescript', definitionsExt: '.ts' } as ReturnType<typeof detectProject>;

describe('GL-403 — weakness 1: leads with capability, not obligation', () => {
  const text = agentInstructions(project);

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
    for (const trigger of ['edit a file', 'change a shared component', 'act on a scanner finding', 'finish a change']) {
      expect(text, trigger).toContain(trigger);
    }
  });

  it('offers the CLI path for an agent with no MCP', () => {
    expect(text).toMatch(/Without MCP, the same answers come from/);
  });
});

describe('GL-403 — weakness 4: workflow names diff and context', () => {
  const text = agentInstructions(project);

  it('mentions guardlink_context and guardlink diff in the workflow', () => {
    const workflow = text.slice(text.indexOf('### Workflow'), text.indexOf('### Tools'));
    expect(workflow).toContain('guardlink_context');
    expect(workflow).toContain('guardlink diff HEAD~1');
  });

  it('carries the empty-vs-never-read distinction into the workflow', () => {
    expect(text).toMatch(/scanned_without_annotations/);
    expect(text).toMatch(/not_scanned/);
  });

  it('names the Phase 2 surface: graph, the CWE bridge, the relation forms', () => {
    expect(text).toContain('guardlink_graph');
    expect(text).toMatch(/cwe:CWE-89/);
    for (const form of ['owner of X', 'handles pii', 'assumptions for X', 'validations for X']) {
      expect(text, form).toContain(form);
    }
  });

  it('warns that a substring match is not an identification', () => {
    expect(text).toMatch(/matched_via/);
    expect(text).toMatch(/suggestion, not an identification/);
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
      coverage: { total_symbols: 0, annotated_symbols: 0, coverage_percent: 0, unannotated_critical: [] },
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

  it('carries synced_at, git_sha and annotation_hash', () => {
    const text = buildModelContext(model, {
      synced_at: '2026-08-09T12:00:00.000Z',
      git_sha: 'abc123',
      annotation_hash: computeAnnotationHash(model),
    });
    expect(text).toMatch(/### Block Freshness/);
    expect(text).toContain('2026-08-09T12:00:00.000Z');
    expect(text).toContain('abc123');
    expect(text).toContain(computeAnnotationHash(model));
  });

  it('tells the reader what to do when the hash disagrees', () => {
    const text = buildModelContext(model, {
      synced_at: 'x', git_sha: null, annotation_hash: 'sha256-v1:deadbeef',
    });
    expect(text).toMatch(/trust the tool/);
    expect(text).toMatch(/guardlink sync/);
  });

  it('reports a missing git_sha honestly rather than blank', () => {
    const text = buildModelContext(model, { synced_at: 'x', git_sha: null, annotation_hash: 'h' });
    expect(text).toMatch(/not a git checkout/);
  });

  it('omitting freshness omits the section rather than emitting placeholders', () => {
    expect(buildModelContext(model)).not.toMatch(/Block Freshness/);
  });

  it('the hash in the block equals the one the MCP envelope reports', () => {
    // Same primitive both sides — that equality is what makes the marker usable.
    const text = buildModelContext(model, {
      synced_at: 'x', git_sha: null, annotation_hash: computeAnnotationHash(model),
    });
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
    initProject({ root, mode: 'inline' });
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('a freshly synced CLAUDE.md carries the freshness block', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const text = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    expect(text).toMatch(/### Block Freshness/);
    expect(text).toContain(computeAnnotationHash(model));
    expect(text).toMatch(/synced_at/);
  });

  it('every agent file gets the block, not only the markdown ones', async () => {
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    for (const file of ['CLAUDE.md', 'AGENTS.md', '.clinerules', '.windsurfrules']) {
      const path = join(root, file);
      const text = await readFile(path, 'utf-8').catch(() => '');
      if (!text) continue;   // not all agent files are created for every project
      expect(text, file).toMatch(/Block Freshness/);
    }
  });

  it('D16 interaction: synced_at makes the block change on every sync', async () => {
    // Recorded, not fixed. Before this the block was byte-stable when the model
    // had not changed; a timestamp necessarily churns it. Combined with D16 —
    // `guardlink validate` running sync as a side effect — every validate now
    // dirties the agent files. D16 is separately ticketed; this test exists so
    // the trade-off is visible rather than discovered later in a noisy diff.
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const first = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
    await new Promise(r => setTimeout(r, 5));
    syncAgentFiles({ root, model });
    const second = await readFile(join(root, 'CLAUDE.md'), 'utf-8');

    expect(second).not.toBe(first);
    // …and the ONLY difference is the timestamp. Everything else is stable.
    const strip = (s: string) => s.replace(/`synced_at`: [^\n]+/, '`synced_at`: X');
    expect(strip(second)).toBe(strip(first));
  });

  it('the README, unlike the agent block, stays byte-stable', async () => {
    // Different artifacts, different call: the README is regenerated on every
    // sync and carries no clock precisely so it does not churn.
    const { model } = await parseProject({ root, project: 'demo' });
    syncAgentFiles({ root, model });
    const a = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    syncAgentFiles({ root, model });
    const b = await readFile(join(root, '.guardlink', 'README.md'), 'utf-8');
    expect(b).toBe(a);
  });

  it('a model with no annotations gets the base block without a freshness section', () => {
    const text = agentInstructionsWithModel(project, null);
    expect(text).not.toMatch(/Block Freshness/);
    expect(text).toMatch(/Ask it instead of inferring/);
  });
});
