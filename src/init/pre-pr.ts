/**
 * GuardLink init — Pre-PR steps other tools contribute to the agent block.
 *
 * The block every agent instruction file carries ends its obligations with a
 * "before you open or update a pull request" step built from GuardLink's own
 * deterministic verbs. A repository that runs another check before a pull
 * request — a scanner, a second linter — used to have one way to tell an agent
 * so: write a second block of its own into the same seven files, next to
 * GuardLink's, and keep both in step. `pre_pr` in `.guardlink/config.json` is
 * the alternative. Each entry is one line `init` and `sync` render under
 * GuardLink's step, so an agent reads one instruction rather than two.
 *
 * ```json
 * "pre_pr": [
 *   { "command": "other-tool check --format json", "why": "what it checks" }
 * ]
 * ```
 *
 * ── Why entries are refused rather than escaped ─────────────────────
 *
 * What this module returns is written into files an agent loads every turn and
 * treats as instructions, inside a code span and inside GuardLink's markers. A
 * value that could close the code span (a backtick), end the block early (an
 * HTML comment delimiter), start a new line of instructions (a line break or
 * other control character) or say something a reviewer does not see (hidden
 * Unicode) is not rendered at all, and the reason is reported, because an
 * escaped version would still be an instruction nobody wrote. Whoever can edit
 * `config.json` can already edit `CLAUDE.md`; the point is that the block's
 * structure, and its provenance stamp, stay GuardLink's.
 *
 * @exposes #init to #prompt-injection [medium] cwe:CWE-77 -- "pre_pr entries from .guardlink/config.json are rendered into agent instruction files, which agents read as instructions"
 * @mitigates #init against #prompt-injection using #input-sanitize -- "One line per entry, length-capped; an entry carrying a backtick, an HTML comment delimiter, a control character or hidden Unicode is refused, not rendered"
 * @flows ConfigFile -> #init via readPrePrSteps -- "pre_pr entries read from .guardlink/config.json"
 * @flows #init -> AgentFiles via agentInstructions -- "Accepted entries rendered under the block's pre-PR step"
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { findHiddenUnicode } from '../agentconfig/hidden-unicode.js';

/** One check another tool asks an agent to run before a pull request. */
export interface PrePrStep {
  /** The command, rendered in a code span. */
  command: string;
  /** What it checks, rendered after the command. Optional. */
  why: string | null;
}

export interface PrePrSteps {
  /** Entries that will be rendered, in config order. */
  steps: PrePrStep[];
  /**
   * Why each refused entry was refused, as `pre_pr[<index>]: <reason>`.
   * `init` and `sync` report these; an empty list means nothing was dropped.
   */
  problems: string[];
}

/** Entries past this many are not rendered: the block is a pointer, not a runbook. */
export const PRE_PR_MAX_STEPS = 5;
/** Longest `command` rendered, in characters. */
export const PRE_PR_MAX_COMMAND = 200;
/** Longest `why` rendered, in characters. */
export const PRE_PR_MAX_WHY = 200;

/**
 * Why `value` cannot be rendered into the block, or null when it can.
 *
 * C0 and C1 controls cover line breaks and tabs; hidden Unicode is the same
 * detector `validate` runs over instruction files, so a value this accepts
 * cannot make the block it lands in fail that check.
 */
function unrenderable(value: string, max: number): string | null {
  if (value.trim() === '') return 'is empty';
  if (value.length > max) return `is longer than ${max} characters`;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) return 'contains a line break or control character';
  if (value.includes('`')) return 'contains a backtick, which would end its code span';
  if (value.includes('<!--') || value.includes('-->')) return 'contains an HTML comment delimiter, which could end the GuardLink block';
  if (findHiddenUnicode(value).length > 0) return 'contains hidden Unicode';
  return null;
}

/**
 * The `pre_pr` entries of `.guardlink/config.json` that can be rendered, and
 * why any others were not.
 *
 * Absent `pre_pr`, a missing config and an unreadable one all give no steps.
 * Only the last is a problem worth reporting, and it is reported elsewhere —
 * every other command that reads the config says so first.
 */
export function readPrePrSteps(root: string): PrePrSteps {
  let config: unknown;
  try {
    config = JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf-8'));
  } catch {
    return { steps: [], problems: [] };
  }
  if (config === null || typeof config !== 'object' || !('pre_pr' in config)) return { steps: [], problems: [] };
  const raw = (config as { pre_pr: unknown }).pre_pr;
  if (!Array.isArray(raw)) return { steps: [], problems: ['pre_pr: is not an array — ignored'] };

  const steps: PrePrStep[] = [];
  const problems: string[] = [];
  raw.forEach((entry, i) => {
    const at = `pre_pr[${i}]`;
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      problems.push(`${at}: is not an object — not rendered`);
      return;
    }
    const { command, why } = entry as { command?: unknown; why?: unknown };
    if (typeof command !== 'string') {
      problems.push(`${at}: has no string "command" — not rendered`);
      return;
    }
    if (why !== undefined && why !== null && typeof why !== 'string') {
      problems.push(`${at}: "why" is not a string — not rendered`);
      return;
    }
    const commandProblem = unrenderable(command, PRE_PR_MAX_COMMAND);
    if (commandProblem) {
      problems.push(`${at}: "command" ${commandProblem} — not rendered`);
      return;
    }
    // An empty `why` is the same as none.
    const reason = typeof why === 'string' && why.trim() !== '' ? why : null;
    const whyProblem = reason === null ? null : unrenderable(reason, PRE_PR_MAX_WHY);
    if (whyProblem) {
      problems.push(`${at}: "why" ${whyProblem} — not rendered`);
      return;
    }
    if (steps.length >= PRE_PR_MAX_STEPS) {
      problems.push(`${at}: more than ${PRE_PR_MAX_STEPS} entries — not rendered`);
      return;
    }
    steps.push({ command: command.trim(), why: reason === null ? null : reason.trim() });
  });
  return { steps, problems };
}
