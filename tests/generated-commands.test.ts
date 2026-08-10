/**
 * D50 — every `guardlink …` command written into a generated file must exist.
 *
 * `guardlink parse . --format json` shipped in three places in
 * `init/templates.ts` and landed in `CLAUDE.md:21` and `.guardlink/README.md`
 * (twice) of every initialised repo. It exits 1 with `unknown option
 * '--format'`: the flag is on `report`, not on `parse`. The line it lived in was
 * "Without MCP, the same answers come from …", so the one reader it was written
 * for — an agent with no MCP connection — was handed a command that cannot run.
 *
 * This is D33's class on a second surface. D33 was stale *claims* in the server
 * instructions and was fixed by making each claim run a probe against the real
 * code. This is stale *commands* in generated docs, and gets the same treatment:
 * every command string is checked against the real CLI.
 *
 * ── Why subprocess `--help` and not importing the program ───────────
 *
 * `src/cli/index.ts` calls `program.parse()` at module scope and does not export
 * the program, so importing it to introspect commander would run the CLI. The
 * `--help` path exits 0 without invoking any action handler, prints the real
 * option list for the real subcommand, and — the point — probes the BUILT
 * artifact rather than a re-derivation of it. It costs one spawn per distinct
 * subcommand, cached, which is a handful.
 *
 * ── What it does and does not catch ─────────────────────────────────
 *
 * Catches: a subcommand that does not exist, and a flag that subcommand does not
 * accept. That is exactly D50.
 *
 * Does NOT catch D46, and the difference is worth stating rather than glossing.
 * D46 is a tool description asserting a measurement about the caller's repo
 * ("#path-traversal alone is declared on 10 assets here"). Nothing about it is a
 * command; it is a true-when-written fact about a different repo. No amount of
 * command parsing reaches it — that needs the separate self-referential-claim
 * rule noted on the D46 row.
 *
 * It also does not check that a command ANSWERS what its surrounding prose
 * promises. That failed too here: the fixed command sat under "the annotations
 * declared in that file", and `guardlink parse` emits the whole model. A parser
 * cannot read the sentence; that one was fixed by hand and stays a human duty.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  agentInstructions, referenceDocContent, guardlinkReadmeContent,
  promptMdContent, cursorRulesContent,
} from '../src/init/templates.js';
import type { ProjectInfo } from '../src/init/detect.js';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const CLI = join(repoRoot, 'dist', 'cli', 'index.js');

const PROJECT: ProjectInfo = {
  root: '/tmp/probe', name: 'probe', language: 'typescript',
  commentPrefix: '//', definitionsExt: 'ts',
} as ProjectInfo;

/** Every generated document, in both annotation modes. */
function generatedDocuments(): { name: string; text: string }[] {
  const docs: { name: string; text: string }[] = [];
  for (const mode of ['inline', 'external'] as const) {
    docs.push({ name: `CLAUDE.md (${mode})`, text: agentInstructions(PROJECT, mode) });
    docs.push({ name: `.cursorrules (${mode})`, text: cursorRulesContent(PROJECT, mode) });
    docs.push({
      name: `.guardlink/README.md (${mode})`,
      text: guardlinkReadmeContent(PROJECT, {
        mode, modeSource: 'config', model: null, annotationHash: null, mcpAtRoot: true,
      }),
    });
  }
  docs.push({ name: 'docs/GUARDLINK_REFERENCE.md', text: referenceDocContent(PROJECT) });
  docs.push({ name: '.guardlink/prompt.md', text: promptMdContent(PROJECT) });
  return docs;
}

/**
 * `guardlink …` invocations in a document, from fenced blocks and inline code.
 *
 * Stops at a pipe, a redirect or a comment: `guardlink parse . | jq '…'` is a
 * claim about `guardlink parse`, not about jq.
 */
function extractCommands(text: string): string[] {
  const found = new Set<string>();
  // `guardlink` followed by whitespace and a lowercase subcommand token. The
  // lookbehind rejects `.guardlink/annotations` and the `\s+` requirement
  // rejects `guardlink.bugb.io` — both appear in these documents and neither is
  // a command. `guardlink_context(...)` is an MCP tool, not the CLI.
  for (const m of text.matchAll(/(?<![./\w-])guardlink(?!_|-mcp)\s+([a-z][a-z-]*)([^\n`|>#]*)/g)) {
    found.add(`guardlink ${m[1]}${m[2]}`.replace(/\s+$/, ''));
  }
  return [...found];
}

const run = promisify(execFile);

/**
 * Real `--help` text for a subcommand, or null when it does not exist.
 *
 * Existence is decided by the `Usage:` line naming the subcommand, NOT by exit
 * code. `guardlink not-a-command --help` exits 0 and prints the ROOT help — so
 * an exit-code check would have called every imaginable subcommand valid and
 * this probe would have been vacuously green. The self-check below pins that.
 */
async function fetchHelp(sub: string): Promise<string | null> {
  try {
    const { stdout } = await run(process.execPath, [CLI, sub, '--help'], { encoding: 'utf8' });
    return new RegExp(`^Usage: guardlink ${sub}\\b`, 'm').test(stdout) ? stdout : null;
  } catch {
    return null;
  }
}

/**
 * One spawn per distinct subcommand, all at once.
 *
 * This probe deliberately shells out to the BUILT CLI rather than importing the
 * program — `cli/index.ts` calls `program.parse()` at module scope and does not
 * export it, so importing would run the CLI. That decision is right and stays.
 *
 * What was wrong was doing it SERIALLY. `execFileSync` per subcommand is ~86ms
 * locally, dominated by Node startup, and the cost is N × one-process-launch.
 * GitHub's shared runners spawn roughly 5x slower, which put the whole file over
 * vitest's 5000ms default and turned a correct test red on CI while it passed
 * everywhere else. The merge tipped it over by adding `guardlink entitle` to the
 * generated docs: 11 distinct subcommands became 12.
 *
 * These are independent read-only `--help` invocations with no ordering
 * requirement, so Promise.all collapses N launches into roughly one launch of
 * wall time. That removes the dependence on how fast the machine spawns
 * processes, rather than deferring it to the next slower runner.
 */
const helpCache = new Map<string, string | null>();

async function warmHelpCache(subs: Iterable<string>): Promise<void> {
  const wanted = [...new Set(subs)].filter(sub => !helpCache.has(sub));
  const texts = await Promise.all(wanted.map(fetchHelp));
  wanted.forEach((sub, i) => helpCache.set(sub, texts[i]));
}

/**
 * Cache read. Synchronous on purpose: the assertions below stay exactly the
 * shape they were, so parallelising the spawns did not touch what is asserted.
 *
 * Throws rather than spawning on a miss. A lazy fallback would quietly restore
 * the serial path the moment someone adds a subcommand the warm step misses,
 * and the symptom would be a slow test on CI again rather than a clear failure.
 */
function helpFor(sub: string): string | null {
  if (!helpCache.has(sub)) {
    throw new Error(`helpFor(${sub}) was not warmed — add it to the beforeAll warm set.`);
  }
  return helpCache.get(sub)!;
}

/** Subcommands the self-check asks for by name, beyond whatever the docs use. */
const SELF_CHECK_SUBS = ['parse', 'report', 'definitely-not-a-command'];

/** Every subcommand any generated document mentions. */
function subcommandsInDocs(): string[] {
  const subs: string[] = [];
  for (const { text } of generatedDocuments()) {
    for (const command of extractCommands(text)) {
      const sub = command.split(/\s+/).filter(Boolean)[1];
      if (sub && !sub.startsWith('-')) subs.push(sub);
    }
  }
  return subs;
}

// 30s, generous and explicit. Parallel or not, a probe that launches processes
// should never be one runner hiccup from red — and the global testTimeout stays
// where it is, so the NEXT slow test still surfaces instead of hiding here.
beforeAll(async () => {
  await warmHelpCache([...subcommandsInDocs(), ...SELF_CHECK_SUBS]);
}, 30_000);

interface Problem { doc: string; command: string; why: string }

describe('D50 — generated docs may only contain commands the CLI has', () => {
  it('every subcommand exists and every flag is one that subcommand accepts', () => {
    const problems: Problem[] = [];

    for (const { name, text } of generatedDocuments()) {
      for (const command of extractCommands(text)) {
        const tokens = command.split(/\s+/).filter(Boolean).slice(1);
        const sub = tokens[0];
        if (!sub || sub.startsWith('-')) continue;

        const help = helpFor(sub);
        if (help === null) {
          problems.push({ doc: name, command, why: `no such subcommand \`${sub}\`` });
          continue;
        }
        for (const tok of tokens.slice(1)) {
          if (!tok.startsWith('--')) continue;
          const flag = tok.split('=')[0];
          if (!help.includes(flag)) {
            problems.push({ doc: name, command, why: `\`${sub}\` has no option \`${flag}\`` });
          }
        }
      }
    }

    const detail = problems.map(p => `\n  ${p.doc}\n    ${p.command}\n    → ${p.why}`).join('');
    expect(
      problems,
      problems.length === 0 ? '' :
        `${problems.length} command(s) in generated documentation do not exist.\n` +
        `These ship into every initialised repo and are read by agents that ` +
        `cannot run --help to recover (D50).${detail}`,
    ).toEqual([]);
  }, 30_000);

  it('the probe can see a broken command — it is not vacuously green', () => {
    // A guard that matched nothing would pass forever. Pin both failure modes
    // against the real CLI, using D50's actual text.
    expect(helpFor('parse')).not.toBeNull();
    expect(helpFor('definitely-not-a-command')).toBeNull();
    expect(helpFor('parse')!.includes('--format')).toBe(false); // the D50 defect
    expect(helpFor('report')!.includes('--format')).toBe(true); // where it lives
  }, 30_000);

  it('extraction finds commands in fences and inline code, and stops at a pipe', () => {
    const sample = 'run `guardlink status .` then:\n```sh\nguardlink parse . | jq \'.x\'\n```\n';
    const got = extractCommands(sample);
    expect(got).toContain('guardlink status .');
    expect(got).toContain('guardlink parse .');
    expect(got.some(c => c.includes('jq'))).toBe(false);
  });
});
