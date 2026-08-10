/**
 * D23 — the last output that inherited glob order.
 *
 * `parseProject` walks with fast-glob, which returns files in completion order
 * under concurrency: stable within a process, not between two. a921afa
 * canonicalised the artifact boundary and 096c291 the dashboard;
 * `report --diagram-only` never got it. Measured before the fix: three runs in
 * three processes produced two distinct sha256 hashes, differing by whole node
 * blocks (`Commands`, `RawStdin`, `Terminal` present in two runs, absent in one).
 *
 * The determinism test runs in SEPARATE PROCESSES. Parse order is stable within
 * one, so a same-process test passes vacuously — that is exactly how this stayed
 * hidden through five phases while the same class of bug was fixed twice
 * elsewhere.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { generateMermaid } from '../src/report/mermaid.js';
import { generateReport } from '../src/report/report.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

describe('D23 — report --diagram-only is byte-identical across processes', () => {
  it('three processes, one hash', async () => {
    const out = await mkdtemp(join(tmpdir(), 'guardlink-d23-'));
    try {
      const hashes = [1, 2, 3].map(i => {
        const path = join(out, `d-${i}.mmd`);
        const text = execFileSync('npx', ['tsx', cli, 'report', repoRoot, '--diagram-only'], {
          cwd: repoRoot, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024,
        });
        void path;
        return sha(text);
      });
      expect(hashes[1]).toBe(hashes[0]);
      expect(hashes[2]).toBe(hashes[0]);
    } finally {
      await rm(out, { recursive: true, force: true });
    }
  }, 180_000);
});

describe('D23 — the ordering is what was fixed, isolated', () => {
  it('a shuffled model produces the same diagram', async () => {
    // The in-process half: canonicalisation is what makes the cross-process
    // result hold, so it is pinned directly rather than only inferred.
    const { model } = await parseProject({ root: repoRoot, project: 'guardlink' });
    const shuffled = {
      ...model,
      assets: [...model.assets].reverse(),
      exposures: [...model.exposures].reverse(),
      mitigations: [...model.mitigations].reverse(),
      flows: [...model.flows].reverse(),
      boundaries: [...model.boundaries].reverse(),
    };
    expect(sha(generateMermaid(shuffled))).toBe(sha(generateMermaid(model)));
  }, 60_000);

  it('a shuffled model produces the same markdown report, apart from its clock', async () => {
    const { model } = await parseProject({ root: repoRoot, project: 'guardlink' });
    const shuffled = {
      ...model,
      assets: [...model.assets].reverse(),
      exposures: [...model.exposures].reverse(),
      flows: [...model.flows].reverse(),
    };
    // `threat-model.md` is git-ignored and rebuilt on demand, so its two
    // "Generated: <iso>" lines are deliberate and not D25's tracked-file class.
    const strip = (s: string) => s.replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z/g, '<TS>');
    expect(sha(strip(generateReport(shuffled)))).toBe(sha(strip(generateReport(model))));
  }, 60_000);

  it('canonicalisation happens in the generator, not the caller', () => {
    // Applied inside so every caller — CLI, TUI, MCP — gets it without having
    // to remember. A call-site fix is one someone can forget at the next site.
    for (const f of ['src/report/mermaid.ts', 'src/report/report.ts']) {
      expect(readFileSync(join(repoRoot, f), 'utf-8'), f).toMatch(/canonicalizeModelOrder\(rawModel\)/);
    }
  });
});
