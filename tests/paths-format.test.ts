/**
 * `guardlink paths` — output surface.
 *
 * A path finding is only useful if it can be walked, so the two things asserted
 * hardest here are that every hop prints a file:line and that the empty result
 * says which kind of empty it is. "No unmitigated paths" read as "this repo is
 * clean" would be the didn't-run-versus-found-nothing confusion again, in a
 * command whose whole value is telling you where to look.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { formatPaths } from '../src/paths/format.js';
import type { PathFinding, EndpointClassification } from '../src/paths/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');

function guardlink(...args: string[]): { out: string; code: number } {
  try {
    const out = execFileSync('npx', ['tsx', cli, ...args], {
      cwd: repoRoot, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { out, code: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { out: `${e.stdout ?? ''}${e.stderr ?? ''}`, code: e.status ?? 1 };
  }
}

const endpoints: EndpointClassification = { entries: ['UserInput'], exits: ['FileSystem'] };

const finding: PathFinding = {
  entry: 'UserInput',
  exit: 'FileSystem',
  chain: ['UserInput', '#api', 'FileSystem'],
  hops: [
    { from: 'userinput', to: 'api', via: { kind: 'flow', from: 'userinput', to: 'api', directed: true, label: 'req.body', file: 'a.ts', line: 10 } },
    { from: 'api', to: 'filesystem', via: { kind: 'flow', from: 'api', to: 'filesystem', directed: true, label: 'writeFileSync', file: 'a.ts', line: 20 } },
  ],
  assetsOnPath: ['#api'],
  mitigated: false,
  controlsOnPath: [],
  crossesBoundary: true,
  boundariesCrossed: ['fs-boundary'],
};

describe('formatPaths', () => {
  it('renders the chain with display labels, not canonical keys', () => {
    const out = formatPaths([finding], endpoints);
    expect(out).toContain('UserInput --req.body--> #api --writeFileSync--> FileSystem');
    expect(out).not.toContain('userinput');
  });

  it('prints a file:line for every hop', () => {
    const out = formatPaths([finding], endpoints);
    expect(out).toContain('a.ts:10');
    expect(out).toContain('a.ts:20');
  });

  it('names the boundary a path crosses', () => {
    expect(formatPaths([finding], endpoints)).toContain('crosses fs-boundary');
  });

  it('names the controls when a path is mitigated', () => {
    const mitigated = { ...finding, mitigated: true, controlsOnPath: ['#path-validation'] };
    expect(formatPaths([mitigated], endpoints, { includeMitigated: true }))
      .toContain('mitigated by #path-validation');
  });

  it('says an empty result is about the annotated graph, not about the code', () => {
    // The failure this guards: reading "no paths found" as "no undefended route
    // exists", when it can equally mean nobody wrote the @flows yet.
    const out = formatPaths([], { entries: [], exits: [] });
    expect(out).toMatch(/not that none exists/i);
    expect(out).toMatch(/@flows/);
  });
});

/**
 * Every case below launches the real CLI, and every one of them carries an
 * explicit 30s timeout.
 *
 * `--all` carried one already, on the reasoning that it was "the only case here
 * that launches the CLI twice". The reasoning was right and the scope was too
 * narrow: a single `npx tsx` spawn plus a full parse of this repository costs
 * ~0.9-1.7s locally and roughly 3x that on GitHub's shared runners, which is
 * 3.5-3.7s against a 5000ms default. That is not a budget, it is a dice roll,
 * and `--json` lost it once — timing out at 5000ms while its three identical
 * siblings passed in the same run.
 *
 * Measured before changing anything, because "the default was always marginal"
 * and "something got slower" are different problems with different fixes. The
 * exact invocation, mean of 7 runs: **1161ms on this branch against 1180ms on
 * main** end to end, and **1721ms against 1802ms** with the code isolated on one
 * fixed tree so only the CLI source differed. No regression — the command is the
 * same speed and the test simply lacked the timeout its passing sibling had.
 *
 * The global `testTimeout` stays where it is, so a genuinely slow NEW test still
 * surfaces. These four are annotated because it is known and measured that they
 * spawn a process, not to buy silence.
 */
describe('guardlink paths — CLI', () => {
  it('reports paths on this repo and exits 0 by default', () => {
    const { out, code } = guardlink('paths', '.');
    expect(code).toBe(0);
    expect(out).toMatch(/Flow graph: \d+ entries, \d+ exits/);
  }, 30_000);

  // 30s, same reason as --all below: one tsx spawn is ~1s locally and ~5s on a
  // shared runner, which sits on the 5000ms default. It timed out on the merge
  // of #30 and again on #33, both times only on the Node 18/20 runners.
  it('--json emits parseable findings with endpoints alongside', () => {
    const { out } = guardlink('paths', '.', '--json');
    const parsed = JSON.parse(out.slice(out.indexOf('{')));
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(Array.isArray(parsed.endpoints.entries)).toBe(true);
  }, 30_000);

  // Two spawns rather than one, so this was the first to need saying out loud.
  it('--all widens the result rather than narrowing it', () => {
    const json = (...args: string[]) => {
      const { out } = guardlink('paths', '.', '--json', ...args);
      return JSON.parse(out.slice(out.indexOf('{')));
    };
    expect(json('--all').findings.length).toBeGreaterThanOrEqual(json().findings.length);
  }, 30_000);

  it('--boundary-only returns only paths that cross a boundary', () => {
    const { out } = guardlink('paths', '.', '--all', '--boundary-only', '--json');
    const { findings } = JSON.parse(out.slice(out.indexOf('{')));
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.crossesBoundary).toBe(true);
  }, 30_000);

  it('--fail-on-found exits 1 when a path is reported', () => {
    const { code } = guardlink('paths', '.', '--all', '--fail-on-found');
    expect(code).toBe(1);
  }, 30_000);
});
