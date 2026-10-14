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
 * @flows AgentFiles -> #init via findPrePrDrift -- "Instruction files re-read to check their contributed lines against pre_pr"
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { findHiddenUnicode } from '../agentconfig/hidden-unicode.js';
import { classifyScope } from '../agentconfig/discover.js';
import { GUARDLINK_BEGIN, GUARDLINK_END } from '../agentconfig/read.js';
import { AGENT_CHOICES } from './picker.js';
import type { ParseDiagnostic } from '../types/index.js';

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

/** Every contributed line ends with this, so a reader — and {@link findPrePrDrift} — can tell it from GuardLink's own. */
const PROVENANCE = ' (from `pre_pr` in `.guardlink/config.json`)';

/** The block line for one step. The template and the drift check both call this, so they cannot disagree. */
export function renderPrePrLine(step: PrePrStep): string {
  return `- \`${step.command}\`${step.why ? ` — ${step.why}` : ''}${PROVENANCE}`;
}

/**
 * Instruction files whose block does not carry the pre-PR lines `pre_pr`
 * configures now.
 *
 * The block's stamp covers the annotations and the agent configuration, not
 * `pre_pr`, so without this a tool that registers an entry and never runs
 * `guardlink sync` gets no line in any file, and nothing says so — the entry
 * reads as working while no agent sees it. Checked by content rather than by a
 * third stamp field: the lines are deterministic, so comparing them is exact,
 * and a stamp format change would mark every existing block stale.
 *
 * Same file set and the same exclusions as `sync`: an instruction file that
 * exists and is this repository's own, never a packaged or fixture one.
 */
export function findPrePrDrift(root: string): ParseDiagnostic[] {
  const expected = readPrePrSteps(root).steps.map(renderPrePrLine);
  const out: ParseDiagnostic[] = [];
  for (const choice of AGENT_CHOICES) {
    const path = join(root, choice.file);
    if (!existsSync(path) || !statSync(path).isFile()) continue;
    const scope = classifyScope(choice.file, () => false);
    if (scope === 'packaged' || scope === 'fixture') continue;
    let text: string;
    try { text = readFileSync(path, 'utf-8'); } catch { continue; }
    const begin = text.indexOf(GUARDLINK_BEGIN);
    const end = begin === -1 ? -1 : text.indexOf(GUARDLINK_END, begin);
    if (begin === -1 || end === -1) continue;
    const found = text.slice(begin, end).split(/\r?\n/).filter(l => l.endsWith(PROVENANCE));
    if (found.length === expected.length && found.every((l, i) => l === expected[i])) continue;
    const missing = expected.filter(l => !found.includes(l)).length;
    const extra = found.filter(l => !expected.includes(l)).length;
    const what = missing > 0 && extra > 0 ? `${missing} line(s) \`pre_pr\` configures are missing and ${extra} it no longer configures remain`
      : missing > 0 ? `${missing} line(s) \`pre_pr\` configures are missing`
        : extra > 0 ? `${extra} line(s) \`pre_pr\` no longer configures remain`
          : 'its pre-PR lines are out of the order `pre_pr` gives';
    out.push({
      level: 'warning', code: 'agent-block-pre-pr-stale', file: choice.file,
      line: text.slice(0, begin).split('\n').length,
      message: `The GuardLink block here does not match \`pre_pr\` in \`.guardlink/config.json\`: ${what}. `
        + 'Agents reading it are told a different pre-PR check than the repository configures — run `guardlink sync`.',
    });
  }
  return out;
}
