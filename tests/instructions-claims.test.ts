/**
 * D33 — the server instructions must not make claims the code has stopped honouring.
 *
 * `instructions` arrives at initialize, before any tool call, so it is the first
 * thing every connected agent reads. It shipped telling agents that a `.gal`
 * under `test/` is "silently dropped — do not put one there until GL-503 lands".
 * GL-503 landed; the claim became false and steered agents away from a directory
 * that works. It survived five phases because the GL-401 test PINNED it
 * (`expect(text).toMatch(/silently dropped/)`) — a test that was correct when
 * written and quietly became a stale-claim enforcer the moment the defect was
 * fixed. That is the real lesson here: asserting on the words is what let the
 * words go wrong.
 *
 * So this file asserts on BEHAVIOUR. Each entry in CLAIMS pairs a phrase the
 * instructions must contain with a probe that runs the real code. A claim can
 * only stay in the text while the code still does it, and the probe is what says
 * so — the same technique GL-401 used for tool names, generalised from names to
 * behaviour.
 *
 * It is not a complete mechanism, and that is stated rather than hidden: nothing
 * forces a NEW claim to come with a probe. What it does close is the case that
 * actually happened — a claim that was true, became false, and had a test
 * holding it in place. See EXPIRING_PHRASINGS for the cheap general guard.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildServerInstructions } from '../src/mcp/instructions.js';
import { parseProject } from '../src/parser/parse-project.js';
import { applyAnnotations } from '../src/parser/apply-annotations.js';
import { fileContext } from '../src/mcp/context.js';
import { lookup } from '../src/mcp/lookup.js';
import { traverseGraph } from '../src/mcp/subgraph.js';
import { buildEnvelope } from '../src/mcp/freshness.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
let model: ThreatModel;

const forMode = (mode: 'inline' | 'external' | null) =>
  buildServerInstructions({ mode, definitionsPath: '.guardlink/definitions.ts' });

beforeAll(async () => {
  ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' }));
}, 60_000);

describe('D33 — every behavioural claim is executed, not just spell-checked', () => {
  it('the write path: annotate_apply synthesises @source and honours symbol', async () => {
    // Added with the D37/README fix. The instructions now tell an agent to write
    // with guardlink_annotate_apply, to pass the SOURCE path, never to send
    // @source, and that symbol: is what reanchor needs. Each of those is a claim
    // about behaviour, so each is executed here rather than trusted.
    const text = forMode('external');
    expect(text).toMatch(/guardlink_annotate_apply/);
    expect(text).toMatch(/@source is synthesised/);
    expect(text).toMatch(/symbol:/);

    const root = await mkdtemp(join(tmpdir(), 'guardlink-write-claim-'));
    try {
      await mkdir(join(root, 'app'), { recursive: true });
      await writeFile(join(root, 'package.json'), '{"name":"w"}\n');
      await writeFile(join(root, 'app', 'q.ts'), 'export const q = 1;\n');

      // Claim: pass the SOURCE path; the sidecar path is derived, not chosen.
      const written = applyAnnotations({
        root, file: 'app/q.ts', line: 1, symbol: 'q',
        annotations: ['@exposes App.Q to #x [high] -- "d"'],
      });
      expect(written.galPath).toBe('.guardlink/annotations/app/q.ts.gal');

      // Claim: @source is synthesised — so the caller never sent one, and one exists.
      const onDisk = await readFile(join(root, written.galPath), 'utf-8');
      expect(onDisk).toContain('@source file:app/q.ts line:1 symbol:q');
      expect(onDisk.match(/@source/g)).toHaveLength(1);

      // Claim: symbol: is what reanchor needs to find the block again.
      const { model: m } = await parseProject({ root, project: 'w' });
      expect(m.exposures[0].location.parent_symbol).toBe('q');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('external mode: a .gal under an EXCLUDED directory really is parsed', async () => {
    // The claim that went stale. It now says sidecars are found under test/,
    // vendor/ and dist/ — so the probe puts one there and requires it to parse.
    const text = forMode('external');
    expect(text).toMatch(/work anywhere the\s+convention puts them/);
    expect(text).toMatch(/test\/, vendor\/ and dist\//);

    const root = await mkdtemp(join(tmpdir(), 'guardlink-claim-'));
    try {
      await mkdir(join(root, 'test'), { recursive: true });
      await mkdir(join(root, '.guardlink', 'annotations', 'test'), { recursive: true });
      await writeFile(join(root, 'package.json'), '{"name":"c"}\n');
      await writeFile(join(root, 'test', 'b.ts'), 'export const b = 1;\n');
      await writeFile(join(root, '.guardlink', 'annotations', 'test', 'b.ts.gal'),
        '@source file:test/b.ts line:1 symbol:b\n@exposes App.B to #x [high] -- "d"\n');

      const { model: m } = await parseProject({ root, project: 'c' });
      expect(m.exposures.some(e => e.asset === 'App.B'),
        'instructions say sidecars under test/ are found; the parser disagrees').toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('context: the two empty-kinds it names are real status values', () => {
    const text = forMode('inline');
    expect(text).toContain('scanned_without_annotations');
    expect(text).toContain('not_scanned');

    // Both must be reachable from the real implementation.
    const clean = fileContext(model, { root: repoRoot, file: 'src/version.ts' });
    const missing = fileContext(model, { root: repoRoot, file: 'src/does-not-exist.ts' });
    const STATUSES = ['annotated', 'scanned_without_annotations', 'not_scanned', 'not_found'];
    expect(STATUSES).toContain(clean.status);
    expect(STATUSES).toContain(missing.status);
    // …and the distinction the text leans on must be a real one.
    expect(clean.status).not.toBe(missing.status);
  });

  it('lookup: external_id.declared exists and false means undeclared', () => {
    expect(forMode('inline')).toContain('external_id.declared');

    const known = lookup(model, 'cwe:CWE-22') as Record<string, unknown>;
    const unknown = lookup(model, 'cwe:CWE-99999') as Record<string, unknown>;
    expect(known).toHaveProperty('external_id');
    expect((unknown.external_id as { declared: boolean }).declared).toBe(false);
  });

  it('envelope: every field the text names is on a real envelope', async () => {
    const text = forMode('inline');
    const env = await buildEnvelope(repoRoot, model) as Record<string, unknown>;
    for (const field of ['annotation_hash', 'git_sha', 'mode', 'root']) {
      expect(text, `instructions name ${field}`).toContain(field);
      expect(env, `envelope carries ${field}`).toHaveProperty(field);
    }
  });

  it('lookup: matched_via really reports the three tiers it names', () => {
    const text = forMode('inline');
    expect(text).toMatch(/matched_via: exact, alias or substring/);
    const exact = lookup(model, 'threat dos') as Record<string, unknown>;
    const sub = lookup(model, 'threat denial') as Record<string, unknown>;
    expect(exact.matched_via).toBe('exact');
    expect(sub.matched_via).toBe('substring');
  });

  it('graph: the defaults it recommends are the defaults the tool has', () => {
    const text = forMode('inline');
    expect(text).toMatch(/depth 2, both, summary/);

    // traverseGraph's own defaults — the text must not recommend against them.
    const defaulted = traverseGraph(model, { from: '#cli' });
    const explicit = traverseGraph(model, { from: '#cli', depth: 2, direction: 'both' });
    expect(defaulted.nodes).toEqual(explicit.nodes);
  });

  it('graph: completeness and frontier_unexplored behave as described', () => {
    const text = forMode('inline');
    expect(text).toContain('traversal.completeness');
    expect(text).toContain('frontier_unexplored');
    expect(text).toMatch(/depth_limited/);
    expect(text).toMatch(/truncated/);

    const partial = traverseGraph(model, { from: '#cli', depth: 1, direction: 'both' });
    expect(partial.completeness).toBe('depth_limited');
    expect(partial.frontier_unexplored!.count).toBeGreaterThan(0);
    // …and the promise it makes holds.
    const deeper = traverseGraph(model, { from: '#cli', depth: 2, direction: 'both' });
    expect(deeper.nodes.length).toBeGreaterThan(partial.nodes.length);
  });
});

describe('D33 — claims that expire must not exist in agent-facing text', () => {
  /**
   * The cheap general guard, and the one worth keeping longest.
   *
   * A claim gated on unlanded work — "until GL-503 lands", "known gap", "not yet
   * supported" — is a claim with an expiry date and no alarm attached. It is
   * true when written and false the day the work ships, and nothing notices.
   * Agent-facing text should describe what the code does now; anything else
   * belongs in the PRD, where staleness is expected and reviewed.
   */
  const EXPIRING_PHRASINGS: [RegExp, string][] = [
    [/\bGL-\d+\b/, 'names an unlanded work item; it becomes false when that item ships'],
    [/until .{0,40}\blands\b/i, 'gates a claim on future work'],
    [/known gap/i, 'a gap that gets closed leaves the text behind'],
    [/\bnot yet\b/i, '"not yet" has no alarm on it'],
    [/\bfor now\b/i, 'same'],
    [/silently dropped/i, 'the specific claim that went stale — D33'],
  ];

  it.each(['inline', 'external', null] as const)('mode=%s carries no expiring claim', (mode) => {
    const text = forMode(mode);
    for (const [pattern, why] of EXPIRING_PHRASINGS) {
      expect(text, `instructions match ${pattern} — ${why}`).not.toMatch(pattern);
    }
  });
});

describe('D33 — the workspace context block teaches syntax that parses', () => {
  it('every annotation example it emits is accepted by the parser', async () => {
    // Found while fixing D32: buildWorkspaceContextBlock emitted
    // `@flows #request from #a.handler to #b.endpoint` — the same `from … to …`
    // form D19 corrected in guardlink_workspace_info, in a second emitter that
    // writes into every linked repo's agent files.
    const { buildWorkspaceContextBlock } = await import('../src/workspace/link.js');
    const { parseLine } = await import('../src/parser/parse-line.js');

    const block = buildWorkspaceContextBlock(
      { workspace: 'ws', this_repo: 'repo-a', repos: [{ name: 'repo-a' }, { name: 'repo-b' }] },
      [{ name: 'repo-a' }, { name: 'repo-b' }],
    );

    const examples = block.match(/@(?:flows|exposes|mitigates)[^`\n]*/g) ?? [];
    expect(examples.length, 'the block should show at least one example').toBeGreaterThan(0);
    for (const ex of examples) {
      const r = parseLine(ex.trim(), { file: 'block', line: 1 });
      expect(r.annotation, `workspace block example does not parse: ${ex.trim()}`).not.toBeNull();
    }
  });
});
