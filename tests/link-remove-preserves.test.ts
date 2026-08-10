/**
 * D32 — `guardlink link --remove` destroyed everything after the workspace block.
 *
 * `cleanupRemovedRepo` computed `endIdx` — the end of the workspace block,
 * exactly as its own comment intends — and then wrote
 * `content.slice(0, markerIdx).trimEnd() + '\n'`, discarding the tail. The
 * insert path in the same file has always spliced correctly
 * (`slice(0, markerIdx) + block + slice(endIdx)`). This was a line that was
 * never finished, not a design choice.
 *
 * The file that gets cleaned is the REMOVED repo's own agent file — that is the
 * repo being cut loose from the workspace, and the one whose CLAUDE.md a user
 * still owns afterwards.
 *
 * Data loss, so the shapes are covered rather than the happy path, and every
 * assertion is on an exact string. `.includes` would have passed on the broken
 * version for most of these.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { linkProject, removeFromWorkspace } from '../src/workspace/link.js';

let hub: string;
let repoA: string;
let repoB: string;
let repoC: string;

beforeEach(async () => {
  hub = await mkdtemp(join(tmpdir(), 'guardlink-d32-'));
  repoA = join(hub, 'repo-a');
  repoB = join(hub, 'repo-b');
  // THREE repos: removal is refused when it would leave the workspace with
  // fewer than two, so repo-c exists purely to keep the remove path reachable.
  repoC = join(hub, 'repo-c');
  // Distinct package.json names — the repo name is detected from there, and two
  // repos sharing a name collapse into one workspace entry.
  for (const [path, name] of [[repoA, 'repo-a'], [repoB, 'repo-b'], [repoC, 'repo-c']] as const) {
    await mkdir(join(path, '.guardlink'), { recursive: true });
    await writeFile(join(path, 'package.json'), `{"name":"${name}"}\n`);
  }
});

afterEach(async () => {
  await rm(hub, { recursive: true, force: true });
});

const claudeMd = (repo: string) => join(repo, 'CLAUDE.md');
const read = (repo: string) => readFile(claudeMd(repo), 'utf-8');

/** Link A and B, which injects the workspace block into both. */
const link = () => linkProject({ workspace: 'ws', repoPaths: [repoA, repoB, repoC] });
/** Remove B from the workspace, which cleans B's own agent files. */
const removeB = () => removeFromWorkspace({ repoName: 'repo-b', existingRepoPath: repoA });

/**
 * Seed repo-b's CLAUDE.md, link, then remove repo-b.
 * Returns { linked, cleaned } so a test can prove the round trip is not vacuous.
 */
async function cycle(seed: string): Promise<{ linked: string; cleaned: string }> {
  await writeFile(claudeMd(repoB), seed);
  link();
  const linked = await read(repoB);
  removeB();
  return { linked, cleaned: await read(repoB) };
}

describe('D32 — content after the workspace block survives', () => {
  it('a user section after the block is byte-exact', async () => {
    const { linked, cleaned } = await cycle('# My Project\n\n## My Own Section\nCONTENT\n');
    expect(linked).toContain('## Workspace Context');
    expect(cleaned).toBe('# My Project\n\n## My Own Section\nCONTENT\n');
  });

  it('multiple sections after the block all survive, in order', async () => {
    // Linking appends the block at the END, so to get sections AFTER it the
    // file has to be written with the block already in place. Link first to
    // obtain a real block, then re-seed with content behind it.
    await writeFile(claudeMd(repoB), '# My Project\n');
    link();
    const withBlock = await read(repoB);
    await writeFile(claudeMd(repoB), withBlock.trimEnd() + '\n\n## One\nfirst\n\n## Two\nsecond\n\n## Three\nthird\n');

    removeB();

    expect(await read(repoB)).toBe(
      '# My Project\n\n## One\nfirst\n\n## Two\nsecond\n\n## Three\nthird\n',
    );
  });

  it('the block being LAST leaves no trailing junk', async () => {
    const { cleaned } = await cycle('# My Project\n');
    expect(cleaned).toBe('# My Project\n');
  });

  it('the block being FIRST leaves no leading blank line', async () => {
    // The empty-head case: `head + '\n' + tail` would emit a leading newline.
    await writeFile(claudeMd(repoB), '# tmp\n');
    link();
    const block = (await read(repoB)).slice((await read(repoB)).indexOf('## Workspace Context'));
    await writeFile(claudeMd(repoB), block.trimEnd() + '\n\n## My Own Section\nCONTENT\n');

    removeB();

    expect(await read(repoB)).toBe('## My Own Section\nCONTENT\n');
  });

  it('a file with no marker at all is untouched', async () => {
    const original = '# My Project\n\n## Not A Workspace Block\nCONTENT\n';
    await writeFile(claudeMd(repoB), '# seed\n');
    link();
    await writeFile(claudeMd(repoB), original);

    removeB();

    expect(await read(repoB)).toBe(original);
  });
});

describe('D32 — round trip', () => {
  it('link then --remove returns the file to its pre-link bytes', async () => {
    const original = '# My Project\n\n## My Own Section\nCONTENT\n';
    const { linked, cleaned } = await cycle(original);

    // Sanity: linking really did change the file, so the round trip is not vacuous.
    expect(linked).not.toBe(original);
    expect(cleaned).toBe(original);
  });

  it('the block itself is gone, along with the sibling it named', async () => {
    const { cleaned } = await cycle('# My Project\n\n## After\nx\n');
    expect(cleaned).not.toContain('## Workspace Context');
    expect(cleaned).not.toContain('repo-a');
    expect(cleaned).toBe('# My Project\n\n## After\nx\n');
  });
});
