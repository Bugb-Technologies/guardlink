/**
 * GuardLink Blame — shared types.
 *
 * Attribution is computed from git at run time and never written into source.
 * Every surface (CLI, MCP, TUI, dashboard, report) reads these shapes; the
 * payload is versioned by `BLAME_SCHEMA` the way the verify output is.
 *
 * Two vocabularies deliberately kept apart:
 *   - `CommitRef.author` is an identity string in the ledger's scheme —
 *     `human:<name>` or `agent:<tool>` — so a gate can key on the prefix.
 *   - `assisted_by[]` is structured (`tool`, `model`) because "which model"
 *     is the question the dashboard groups by.
 *
 * @comment -- "Pure type declarations for the blame module; no I/O. The optional `blame` field these describe is invisible to the annotation hash and stripped from the committed model.json, exactly like `anchor`"
 */

export const BLAME_SCHEMA = 'guardlink.blame/v1';

/** What an identity string shows for a human: git name, email, or a 12-hex hash of the email. */
export type IdentityMode = 'name' | 'email' | 'hash';

export type BlameStatus =
  | 'ok'
  | 'no-git'        // root is not a git checkout
  | 'shallow'       // history is truncated; introduced_by is a lower bound
  | 'uncommitted'   // the line or span carries changes git has not committed
  | 'no-anchor'     // the record has no anchor; only the annotation line could be blamed
  | 'file-missing'  // the file the record names is not in the working tree
  | 'error';        // git failed for this file; see `error`

/** How much code the span behind a record covers. `none` when there is no anchor. */
export type BlameGranularity = 'symbol' | 'block' | 'file' | 'none';

/** One AI tool credited on a commit, from a trailer or a bot author identity. */
export interface AiAttribution {
  /** Rule id, e.g. `claude-code`, `copilot`; `unknown` only for an unparseable `Assisted-by:`. */
  tool: string;
  /** Model name when the convention carries one, e.g. `Claude Opus 5 (1M context)`. */
  model: string | null;
  /** The trailer value or author string this was derived from, verbatim. */
  raw: string;
}

export interface CommitRef {
  sha: string;
  /** Author date, ISO-8601 as git prints `%aI`. */
  date: string;
  /** `human:<identity>` — or `agent:<tool>` when a bot authored the commit and no human co-author exists. */
  author: string;
  /** Human co-authors from `Co-authored-by` trailers that matched no tool rule. */
  co_authors: string[];
  assisted_by: AiAttribution[];
}

export interface Contributor extends CommitRef {
  /** Lines of the span this commit last touched. */
  lines: number;
}

export type IntroducedMethod =
  | 'log-L'     // oldest commit in the span's line history (precise)
  | 'file-add'  // the commit that added the file (file-scope anchors)
  | 'blame';    // oldest commit still owning a line of the span (fallback for dirty files)

export interface IntroducedBy extends CommitRef {
  method: IntroducedMethod;
  /** The true introduction may be earlier: shallow clone, or a dirty file where -L could not run. */
  lower_bound?: true;
}

export interface ExposureBlame {
  kind: 'exposure';
  status: BlameStatus;
  granularity: BlameGranularity;
  introduced_by: IntroducedBy | null;
  /** Blame of the annotation line itself — who declared the exposure. */
  found_by: CommitRef | null;
  /** Per-commit line ownership over the span, most lines first, then sha. */
  contributors: Contributor[];
  /** The earliest-declared `@mitigates` covering this exposure, or null while it is open. */
  fixed_by: CommitRef | null;
  /** Days from `introduced_by.date` to `fixed_by.date`, never negative. */
  time_to_fix_days: number | null;
  /** Set when the mitigation predates the introduction and the interval was clamped to 0. */
  fixed_before_introduced?: true;
  error?: string;
}

export interface MitigationBlame {
  kind: 'mitigation';
  status: BlameStatus;
  granularity: BlameGranularity;
  /** Blame of the `@mitigates` line — who declared the fix. */
  declared_by: CommitRef | null;
  contributors: Contributor[];
  error?: string;
}

export type RecordBlame = ExposureBlame | MitigationBlame;

/** How a matched name yields a model: the whole name, the name minus its leading tool token, or the text in parentheses. */
export type ModelRule = 'name' | 'after-token' | 'parens';

/** A row of `blame.tools`: a regex source for email and/or name, matched anchored and case-insensitively. */
export interface ToolRule {
  tool: string;
  email?: string;
  name?: string;
  model?: ModelRule;
}

export interface CompiledRule {
  tool: string;
  email?: RegExp;
  name?: RegExp;
  model?: ModelRule;
}

export interface BlameConfig {
  identity: IdentityMode;
  /** User rules first, then the shipped defaults. First match wins. */
  tools: ToolRule[];
  /** Root-relative path handed to `git blame --ignore-revs-file` when it exists; null when unset or outside root. */
  ignore_revs: string | null;
}

/** One commit as `git log` printed it, before any rule is applied. */
export interface RawCommit {
  sha: string;
  authorName: string;
  authorEmail: string;
  date: string;
  committerName: string;
  /** The unfolded trailer block, one `Key: value` per line. */
  trailers: string;
}

export type ComputationStatus = 'ok' | 'no-git' | 'shallow';

export interface BlameComputation {
  status: ComputationStatus;
  head: string | null;
  identity_mode: IdentityMode;
  /** Keyed by the model record object itself; never written back unless `attachBlame` is asked to. */
  byRecord: Map<object, RecordBlame>;
}

export type BlameVerb = 'exposes' | 'confirmed' | 'mitigates';

export interface BlameEntry {
  /** The ledger claim key, so this joins to `.guardlink/verified.json`. */
  key: string;
  verb: BlameVerb;
  asset: string;
  threat: string;
  severity: string | null;
  file: string;
  line: number;
  granularity: BlameGranularity;
  /** `file#start-end` of the anchored span, `file#file` for a file-wide anchor, null without one. Claims sharing a span share its lines. */
  span: string | null;
  blame: RecordBlame;
}

export interface HumanSummaryRow {
  identity: string;
  /** Exposures whose introducing commit credits this identity. */
  introduced: number;
  /** Exposures whose fixing commit credits this identity. */
  fixed: number;
  /** Introduced and not yet fixed. */
  open: number;
  /** Exposures whose span this identity currently owns lines of (any commit, not only the introducer). */
  touched: number;
  /** Lines of exposed spans this identity currently owns. */
  lines: number;
  median_time_to_fix_days: number | null;
}

export interface AgentSummaryRow {
  tool: string;
  model: string | null;
  introduced: number;
  fixed: number;
  open: number;
  touched: number;
  lines: number;
  median_time_to_fix_days: number | null;
}

export interface BlameSummary {
  by_human: HumanSummaryRow[];
  by_agent: AgentSummaryRow[];
}

export interface BlamePayload {
  schema: typeof BLAME_SCHEMA;
  root: string;
  head: string | null;
  identity_mode: IdentityMode;
  status: ComputationStatus;
  entries: BlameEntry[];
  summary: BlameSummary;
}
