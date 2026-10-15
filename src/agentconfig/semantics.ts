/**
 * GuardLink agent config — harness semantics: what a configuration key DOES.
 *
 * Whether `Bash(find:*)` lets an agent delete files is not a property of the
 * string; it is a property of the harness that reads it (Claude Code never
 * auto-approves `find -delete` under that rule). So the meaning of every key
 * this reader turns into a fact is data, kept per harness and per documented
 * version in `harness/<harness>.json` at the package root, each rule with the
 * documentation URL it was read from. Every generated row cites the table and
 * rule that interpreted it (`semantics.table`, e.g. `claude-code@2026-10`), so
 * a reviewer can check the claim against the vendor's own words, and another
 * tool reading the same configuration can load the same tables.
 *
 * `harness/shell.json` holds what is harness-independent: what arbitrary
 * arguments after a pre-approved command prefix make possible.
 *
 * @comment -- "Reads the package's own harness/*.json once, by a path fixed relative to this module; no repository content or user input chooses which file is read"
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** `harness/` beside `src/` and `dist/`, so the same lookup works from source and from a build. */
export const HARNESS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'harness');

export type LoadedWhen = 'always' | 'after-trust' | 'headless';

export interface HarnessFileRule {
  kind: string;
  pattern: string;
  /** Loaded by another harness than the table's own (e.g. `copilot-review`, `vscode`). */
  harness?: string;
  /** Further harnesses that load the same file. */
  also?: string[];
  /** Applies only when no non-fallback rule matched the path. */
  fallback?: boolean;
  /** A file of this kind outside its harness's own directory is shipped, not used here. */
  packaged?: boolean;
  loaded_when?: LoadedWhen[];
  doc?: string;
}

export interface HarnessRule {
  doc: string;
  gated?: boolean;
  loaded_when: LoadedWhen[];
  admits?: string[];
  note: string;
}

export interface HarnessTable {
  table: string;
  version: string;
  harness?: string;
  name?: string;
  actor?: { id: string; name: string; description: string };
  about: string;
  files: HarnessFileRule[];
  shell?: { protected_prefixes?: string[]; protected_doc?: string; read_only?: string[]; stripped_wrappers?: string[] };
  rules?: Record<string, HarnessRule>;
}

export interface ShellTable {
  table: 'shell';
  version: string;
  subcommand_scoped: string[];
  classes: Record<DangerClass, { effect: 'execute' | 'notify' | 'write' | null; admits: string[]; severity: string }>;
  prefixes: Record<string, { class: DangerClass; why: string }>;
  command_tags: Record<string, string>;
}

export type DangerClass = 'exec' | 'net' | 'write' | 'read';

export interface Semantics {
  harnesses: Map<string, HarnessTable>;
  /** Every table, file rules included, in a fixed order: the five read for reach, then `other`. */
  tables: HarnessTable[];
  shell: ShellTable;
  /** `harness` → `version`, for the tables that read reach. */
  versions: Record<string, string>;
}

/** The harnesses whose reach is read, in the order their tables are consulted. */
export const REACH_HARNESSES = ['claude-code', 'cursor', 'copilot', 'codex', 'gemini-cli', 'roo', 'cline', 'windsurf', 'kiro', 'amazon-q', 'zed', 'opencode'] as const;

let cached: Semantics | null = null;

export function loadSemantics(dir: string = HARNESS_DIR): Semantics {
  if (cached && dir === HARNESS_DIR) return cached;
  const read = <T>(name: string): T => JSON.parse(readFileSync(resolve(dir, name), 'utf-8')) as T;
  const names = readdirSync(dir).filter(f => f.endsWith('.json')).sort();
  const shell = read<ShellTable>('shell.json');
  const harnesses = new Map<string, HarnessTable>();
  for (const h of REACH_HARNESSES) {
    if (!names.includes(`${h}.json`)) throw new Error(`harness table missing: ${h}.json`);
    harnesses.set(h, read<HarnessTable>(`${h}.json`));
  }
  const tables = [...harnesses.values(), ...(names.includes('other.json') ? [read<HarnessTable>('other.json')] : [])];
  const versions: Record<string, string> = {};
  for (const [h, t] of harnesses) versions[h] = t.version;
  const s: Semantics = { harnesses, tables, shell, versions };
  if (dir === HARNESS_DIR) cached = s;
  return s;
}

/** `claude-code@2026-10` — how a row names the table that interpreted it. */
export function tableRef(t: HarnessTable): string {
  return `${t.table}@${t.version}`;
}

// ─── Shell commands ─────────────────────────────────────────────────

export interface ShellVerdict {
  /** GuardLink capability token for the rule, e.g. `bash.gh-api`. */
  capability: string;
  /** What the rule hands out beyond its own name, or null when it is scoped. */
  danger: DangerClass | null;
  /** The table rule that decided: `bash-any`, `bash-prefix`, `bash-exact` or `bash-protected`. */
  rule: 'bash-any' | 'bash-prefix' | 'bash-exact' | 'bash-protected';
  why: string;
}

/** A capability token: `[A-Za-z][A-Za-z0-9_.-]*` (SPEC §3.2.1), at most 64 characters. */
export function capToken(s: string): string {
  const t = s.replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '');
  if (!t) return 'any';
  return (/^[A-Za-z]/.test(t) ? t : `c${t}`).slice(0, 64);
}

/** `git diff:*` → (`git diff`, wildcard); `pnpm test` → (`pnpm test`, exact). */
export function splitPrefix(spec: string): { prefix: string; wild: boolean } {
  let s = spec.trim();
  let wild = false;
  if (s.endsWith(':*')) { s = s.slice(0, -2); wild = true; }
  else if (s.endsWith(' *') || s === '*') { s = s.slice(0, -1).trim(); wild = true; }
  return { prefix: s.trim(), wild };
}

/**
 * What a pre-approved shell rule hands out. `spec` is what sits inside
 * `Bash(...)`; null means the bare tool (any command). `harness` decides which
 * built-in protections apply, e.g. Claude Code's exec-wrapper and `find` rule.
 */
export function classifyShell(spec: string | null, harness: string, sem: Semantics = loadSemantics()): ShellVerdict {
  if (spec === null || ['', '*', ':*'].includes(spec.trim())) {
    return { capability: 'bash.any', danger: 'exec', rule: 'bash-any', why: 'any shell command' };
  }
  const { prefix, wild } = splitPrefix(spec);
  const words = prefix.split(/\s+/).filter(Boolean);
  const capability = `bash.${capToken(words.slice(0, 3).join('-'))}`;
  if (!wild) return { capability, danger: null, rule: 'bash-exact', why: 'exact command' };
  const table = sem.harnesses.get(harness);
  if (words.length > 0 && (table?.shell?.protected_prefixes ?? []).includes(words[0])) {
    return { capability, danger: null, rule: 'bash-protected', why: `${table?.name ?? harness} never auto-approves this wrapper's command-running forms` };
  }
  for (const n of [2, 1]) {
    if (words.length < n) continue;
    const key = words.slice(0, n).join(' ');
    const entry = sem.shell.prefixes[key];
    if (!entry) continue;
    if (n === 1 && words.length > 1 && sem.shell.subcommand_scoped.includes(words[0])) {
      // A subcommand narrows git, gh, docker and uv: judge the subcommand itself.
      const sub = sem.shell.prefixes[words.slice(0, 2).join(' ')];
      return sub
        ? { capability, danger: sub.class, rule: 'bash-prefix', why: sub.why }
        : { capability, danger: null, rule: 'bash-prefix', why: 'subcommand-scoped' };
    }
    if (words[1]?.startsWith('--version')) return { capability, danger: null, rule: 'bash-prefix', why: 'version probe' };
    return { capability, danger: entry.class, rule: 'bash-prefix', why: entry.why };
  }
  return { capability, danger: null, rule: 'bash-prefix', why: 'scoped command' };
}

/** Named behaviours of a command string (`pipe-to-shell`, `package-install`, …), from `shell.json`. */
export function commandTags(text: string, sem: Semantics = loadSemantics()): string[] {
  return Object.entries(sem.shell.command_tags)
    .filter(([, rx]) => new RegExp(rx).test(text))
    .map(([name]) => name)
    .sort();
}
