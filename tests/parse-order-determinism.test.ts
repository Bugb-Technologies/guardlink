/**
 * The same tree must parse to the same model, in the same order.
 *
 * fast-glob walks sibling directories concurrently, so the order it returns
 * files in varies between runs on an identical tree — measured at three
 * different orders across 200 scans of a four-file layout. Every model array
 * inherits file order, so an unsorted scan made `unentitled reaches` list a
 * reach from `src/ci/` ahead of ones from `src/agent/` on some runs only.
 *
 * One parse can pass by luck, so this parses repeatedly: on the unsorted scan
 * roughly one run in nine came back out of order.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';

const FILES: Record<string, string> = {
  '.guardlink/definitions.ts': `/**
 * @asset Agent.ToolSurface (#tool-surface) -- "Tools the agent can call"
 * @actor Support_Agent (#support-agent) -- "Support agent"
 * @actor CI_Runner (#ci-runner) -- "Release job"
 */
export {};
`,
  'src/agent/tools.ts': `/**
 * @agents #support-agent to run-sql on #tool-surface
 * @agents #support-agent to search-kb on #tool-surface
 */
export {};
`,
  'src/agent/actions.ts': `/**
 * @agents #support-agent to issue-refund on #tool-surface
 */
export {};
`,
  'src/ci/release.ts': `/**
 * @reaches #ci-runner to publish-package on #tool-surface
 */
export {};
`,
};

function writeTree(): string {
  const root = mkdtempSync(join(tmpdir(), 'guardlink-order-'));
  for (const [rel, body] of Object.entries(FILES)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
}

describe('parse order', () => {
  it('follows file path order on every run, whatever order the scan returns', async () => {
    for (let run = 0; run < 25; run++) {
      const { model } = await parseProject({ root: writeTree(), project: 'order', anchors: false });
      expect(model.reaches.map(r => r.capability)).toEqual(['issue-refund', 'run-sql', 'search-kb', 'publish-package']);
    }
  });
});
