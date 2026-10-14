/**
 * How a caller-supplied git ref reaches git.
 *
 * `parseAtRef` and `getChangedFiles` take a ref from `guardlink diff`, the TUI,
 * `lint --since`, the dashboard's `--since` and the `guardlink_diff` MCP tool.
 * Every git call is an argument array, and the ref is checked against
 * REF_SHAPE and resolved to a commit sha before anything else runs. These
 * cases hold both halves: a ref with shell syntax, whitespace or a leading
 * `-` is refused, and nothing it spells out is ever run.
 *
 * @validates #param-commands for #diff -- "A ref carrying shell syntax is refused by parseAtRef, getChangedFiles, loadSince and the guardlink_diff MCP tool, and the command it spells out never runs"
 * @validates #input-sanitize for #diff -- "resolveCommit refuses a leading '-', whitespace and quoting, and resolves a well-formed ref to a full sha"
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { parseAtRef, getChangedFiles, resolveCommit } from '../src/diff/index.js';
import { loadSince } from '../src/dashboard/since.js';
import { parseProject } from '../src/parser/parse-project.js';
import { createServer } from '../src/mcp/server.js';

let root: string;
let marker: string;

const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf-8', stdio: 'pipe' }).trim();

/** Refs that would each run `touch <marker>` if they ever reached a shell. */
const shellRefs = () => [
  `HEAD;touch ${marker}`,
  `HEAD && touch ${marker}`,
  `HEAD|touch ${marker}`,
  `$(touch ${marker})`,
  `\`touch ${marker}\``,
  `HEAD\ntouch ${marker}`,
];

/** Refs git itself would read as something other than a revision. */
const malformedRefs = ['--output=/tmp/x', '-h', 'HEAD x', '', '"HEAD"', "'HEAD'"];

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'guardlink-git-ref-'));
  marker = join(mkdtempSync(join(tmpdir(), 'guardlink-git-ref-marker-')), 'created');
  git('init', '-q');
  git('config', 'user.name', 'GuardLink Tests');
  git('config', 'user.email', 'guardlink-tests@example.com');
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.ts'), '// @asset App.API (#api) -- "Main API"\n');
  git('add', '.');
  git('commit', '-q', '-m', 'first');
  git('tag', 'v1');
  writeFileSync(join(root, 'app.ts'), '// @exposes #api to #xss -- "Unescaped output"\n');
  git('add', '.');
  git('commit', '-q', '-m', 'second');
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(join(marker, '..'), { recursive: true, force: true });
});

describe('resolveCommit', () => {
  it('resolves the refs people type to a full sha', () => {
    const head = git('rev-parse', 'HEAD');
    const first = git('rev-parse', 'HEAD~1');
    expect(resolveCommit(root, 'HEAD')).toBe(head);
    expect(resolveCommit(root, 'HEAD~1')).toBe(first);
    expect(resolveCommit(root, 'v1')).toBe(first);
    expect(resolveCommit(root, first.slice(0, 10))).toBe(first);
  });

  it('refuses a ref with shell syntax, whitespace, quoting or a leading dash', () => {
    for (const ref of [...shellRefs(), ...malformedRefs]) {
      expect(() => resolveCommit(root, ref), JSON.stringify(ref)).toThrow(/Invalid git ref/);
    }
    expect(existsSync(marker)).toBe(false);
  });

  it('refuses a well-formed ref that names no commit', () => {
    expect(() => resolveCommit(root, 'no-such-branch')).toThrow(/Invalid git ref/);
  });
});

describe('parseAtRef and getChangedFiles', () => {
  it('still parse the model at a ref and list what changed since it', async () => {
    const model = await parseAtRef(root, 'HEAD~1', 'tmp');
    expect(model.assets.map(a => a.id)).toContain('api');
    expect(model.exposures).toHaveLength(0);
    expect(getChangedFiles(root, 'HEAD~1')).toContain('app.ts');
  });

  it('refuse every ref carrying shell syntax, and run nothing', async () => {
    for (const ref of shellRefs()) {
      await expect(parseAtRef(root, ref, 'tmp'), JSON.stringify(ref)).rejects.toThrow(/Invalid git ref/);
      expect(getChangedFiles(root, ref)).toEqual([]);
    }
    expect(existsSync(marker)).toBe(false);
  });

  it('refuse a ref git would read as an option', async () => {
    for (const ref of malformedRefs) {
      await expect(parseAtRef(root, ref, 'tmp'), JSON.stringify(ref)).rejects.toThrow(/Invalid git ref/);
      expect(getChangedFiles(root, ref)).toEqual([]);
    }
  });
});

describe('dashboard --since', () => {
  it('refuses a ref carrying shell syntax, and runs nothing', async () => {
    const { model } = await parseProject({ root, project: 'tmp' });
    for (const ref of shellRefs()) {
      await expect(loadSince(root, ref, 'tmp', model), JSON.stringify(ref)).rejects.toThrow();
    }
    expect(existsSync(marker)).toBe(false);
    const since = await loadSince(root, 'HEAD~1', 'tmp', model);
    expect(since.commits).toBe(1);
  });
});

describe('guardlink_diff over MCP', () => {
  it('answers a ref carrying shell syntax with an error, and runs nothing', async () => {
    const server = createServer();
    const client = new Client({ name: 'test', version: '0.0.0' });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), client.connect(ct)]);
    try {
      for (const ref of shellRefs()) {
        const result = await client.callTool({ name: 'guardlink_diff', arguments: { root, ref } }) as { content: { text: string }[] };
        expect(JSON.parse(result.content[0].text).error, JSON.stringify(ref)).toMatch(/Invalid git ref/);
      }
      expect(existsSync(marker)).toBe(false);

      const ok = await client.callTool({ name: 'guardlink_diff', arguments: { root, ref: 'HEAD~1' } }) as { content: { text: string }[] };
      expect(JSON.parse(ok.content[0].text).error).toBeUndefined();
    } finally {
      await client.close();
    }
  });
});
