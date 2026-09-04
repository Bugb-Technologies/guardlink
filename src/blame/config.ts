/**
 * GuardLink Blame — configuration.
 *
 * Reads the optional `blame` key of `.guardlink/config.json`:
 *
 * ```json
 * {
 *   "blame": {
 *     "identity": "name",
 *     "tools": [{ "tool": "corp-bot", "email": "bot@corp\\.example" }],
 *     "ignore_revs": ".git-blame-ignore-revs"
 *   }
 * }
 * ```
 *
 * User `tools` rows are prepended to the shipped defaults, so a company can
 * name its own bot or override how a vendor's trailer is read without a code
 * change. Same shape as `readDisabledDiagnostics` in the parser: absent or
 * unreadable config returns the defaults, deliberately — a broken config must
 * not silently change who gets attributed.
 *
 * @exposes #blame to #redos [low] cwe:CWE-1333 -- "Tool rules are user-supplied regular expressions applied to every commit author and trailer in the history"
 * @mitigates #blame against #redos using #regex-anchoring -- "Every pattern is anchored (^…$), capped at 256 characters and compiled once; a pattern that fails to compile drops its whole rule rather than half-matching"
 * @exposes #blame to #path-traversal [low] cwe:CWE-22 -- "ignore_revs names a file git will open with --ignore-revs-file"
 * @mitigates #blame against #path-traversal using #path-validation -- "The value is resolved against root and kept only when it is root or lies under root + sep; anything else becomes null and git is never told about it"
 * @flows ConfigFile -> #blame via readBlameConfig -- "Attribution settings"
 * @comment -- "The default ignore_revs is .git-blame-ignore-revs, the file GitHub already honours; git.ts passes it only when it exists"
 */
import { readFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import type { BlameConfig, CompiledRule, IdentityMode, ModelRule, ToolRule } from './types.js';

export const DEFAULT_IGNORE_REVS = '.git-blame-ignore-revs';

/** Longest regex source a rule may carry. Real bot identities are a few dozen characters. */
export const MAX_PATTERN_LENGTH = 256;

/**
 * The conventions verified on 2026-09-04. Order matters only among rules that
 * could both match, which none of these do.
 *
 * - claude-code names the model in the co-author name (`Claude Opus 5 (1M context)`).
 * - copilot's coding agent authors the commit itself; the human is the co-author.
 * - gemini-cli's recommended form is `gemini-cli <MODEL> <…@users.noreply.github.com>`.
 * - aider appends ` (aider)` to the author name, or writes a co-author trailer.
 */
const SHIPPED_RULES: ToolRule[] = [
  { tool: 'claude-code', email: 'noreply@anthropic\\.com', name: 'Claude\\b.*', model: 'name' },
  { tool: 'copilot', email: '.*Copilot@users\\.noreply\\.github\\.com', name: 'Copilot' },
  { tool: 'codex', email: 'noreply@openai\\.com', name: 'Codex' },
  { tool: 'cursor', email: 'cursoragent@cursor\\.com', name: 'Cursor' },
  { tool: 'gemini-cli', email: '.*gemini-cli@users\\.noreply\\.github\\.com', name: '(?:gemini-cli|Gemini)\\b.*', model: 'after-token' },
  { tool: 'aider', name: '.*\\baider\\b.*', model: 'parens' },
  { tool: 'warp', email: 'agent@warp\\.dev', name: 'Warp' },
];
export const DEFAULT_TOOL_RULES: readonly ToolRule[] = Object.freeze(SHIPPED_RULES.map(r => Object.freeze({ ...r })));

const IDENTITY_MODES: ReadonlySet<string> = new Set<IdentityMode>(['name', 'email', 'hash']);
const MODEL_RULES: ReadonlySet<string> = new Set<ModelRule>(['name', 'after-token', 'parens']);

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Keep only the fields a rule may carry, each only when it is a string of the right kind. */
function normaliseRule(v: unknown): ToolRule | null {
  if (!isRecord(v) || typeof v.tool !== 'string' || v.tool.trim() === '') return null;
  const rule: ToolRule = { tool: v.tool.trim() };
  if (typeof v.email === 'string') rule.email = v.email;
  if (typeof v.name === 'string') rule.name = v.name;
  if (typeof v.model === 'string' && MODEL_RULES.has(v.model)) rule.model = v.model as ModelRule;
  return rule;
}

/** The path unchanged when it stays inside root; null otherwise. */
function containedPath(root: string, v: unknown): string | null {
  if (typeof v !== 'string' || v.trim() === '') return null;
  const base = resolve(root);
  const abs = resolve(root, v);
  return abs === base || abs.startsWith(base + sep) ? v : null;
}

export function readBlameConfig(root: string): BlameConfig {
  const defaults: BlameConfig = { identity: 'name', tools: [...DEFAULT_TOOL_RULES], ignore_revs: DEFAULT_IGNORE_REVS };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(root, '.guardlink', 'config.json'), 'utf-8'));
  } catch {
    return defaults;
  }
  const blame = isRecord(raw) ? raw.blame : undefined;
  if (!isRecord(blame)) return defaults;

  const identity = (typeof blame.identity === 'string' && IDENTITY_MODES.has(blame.identity))
    ? blame.identity as IdentityMode
    : 'name';
  const userRules = Array.isArray(blame.tools)
    ? blame.tools.map(normaliseRule).filter((r): r is ToolRule => r !== null)
    : [];
  const ignore_revs = blame.ignore_revs === undefined ? DEFAULT_IGNORE_REVS : containedPath(root, blame.ignore_revs);

  return { identity, tools: [...userRules, ...DEFAULT_TOOL_RULES], ignore_revs };
}

function compilePattern(source: string): RegExp | null {
  if (source.length > MAX_PATTERN_LENGTH) return null;
  try {
    return new RegExp(`^(?:${source})$`, 'i');
  } catch {
    return null;
  }
}

/**
 * Compile rules for matching. A rule with no pattern, or with any pattern that
 * is too long or invalid, is dropped whole: a rule that matched on email but
 * lost its name pattern would attribute differently from what was written.
 */
export function compileRules(rules: readonly ToolRule[]): CompiledRule[] {
  const out: CompiledRule[] = [];
  for (const rule of rules) {
    if (rule.email === undefined && rule.name === undefined) continue;
    const compiled: CompiledRule = { tool: rule.tool };
    if (rule.email !== undefined) {
      const re = compilePattern(rule.email);
      if (!re) continue;
      compiled.email = re;
    }
    if (rule.name !== undefined) {
      const re = compilePattern(rule.name);
      if (!re) continue;
      compiled.name = re;
    }
    if (rule.model) compiled.model = rule.model;
    out.push(compiled);
  }
  return out;
}
