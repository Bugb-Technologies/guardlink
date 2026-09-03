# Stale Claim Detection — Design

**Date:** 2026-09-03
**Status:** Approved in discussion, pending written review
**Branch:** `feat/stale-claim-detection`

## 1. Problem

Every GuardLink annotation is a claim that nothing re-checks. The README promises
"your threat model updates when your code changes", but the tool cannot observe
that change. A `@mitigates` says a control exists at a site. If a later commit
removes the control, the annotation stays, the exposure keeps reporting as
covered, and the model is silently wrong. This is a false negative, the failure
class the entitlement design (docs/prd/actor-entitlement-design.md §2) ranks as
worst, because a threat-model tool that goes quiet is worse than one that is
noisy.

The behavioural directive in CLAUDE.md / AGENTS.md does not close this. It only
reaches code written by an agent that read the directive. A teammate editing in
their own editor with no agent, or a merge from a fork, never sees it. Any check
that depends on the author's tooling reaches only some authors.

**The property this design adds:** GuardLink can tell when the code beneath a
claim has changed since a person or agent last verified the claim, using only
the contents of the repository, and can be told to stop vouching for such a
claim until someone re-verifies it.

## 2. Evidence

A throwaway spike on this repository at commit `95479ee` parsed every
annotation, resolved the code beneath it with a brace-matching heuristic, and
git-blamed that code to ask whether any line was committed after the annotation
line was last touched.

| Granularity of the claim | Annotations | Flagged |
|---|---|---|
| Whole file (claim in the file-header doc block) | 375 | 317 |
| One symbol (claim in a function or type doc block) | 91 | 8 |
| No code beneath | 5 | 2 |
| Total | 471 | 327 |

Two findings drive the design:

1. **Granularity is the whole problem.** Eighty percent of this repository's
   annotations sit in file-header blocks, so "the code beneath the claim" is the
   whole file and any edit flags every claim in the header. At symbol
   granularity the rate is 8 of 91, and four of those are `@shield` markers with
   no code beneath them. Two flagged mitigations were checked by reading the
   later commits, one symbol-level and one file-level. Both claims still held:
   the code had changed, the claim needed a re-check, and the re-check passed.
   That is the intended workflow, not a false positive.
2. **Blame is the wrong oracle.** It needs full history, which the default
   `fetch-depth: 1` checkout in most CI does not have; it is slow on large
   repositories; squash merges and rebases rewrite the dates it relies on; and
   it has nowhere to record who re-verified a claim.

## 3. Decisions taken

| Question | Decision |
|---|---|
| Languages in the first release | Everything in `DEFAULT_INCLUDE`, via tree-sitter |
| How grammars ship | Bundled inside the `guardlink` package |
| Behaviour on a stale mitigation | Report by default; demotion behind a flag and config key |
| Who may re-verify | Humans and agents, with the verifier recorded |
| Where verified state lives | A committed ledger under `.guardlink/` (approach A) |

Approaches rejected: deriving staleness from git history with no stored state
(cannot work on shallow clones, cannot record a verifier); carrying a hash
inside the annotation text (every re-verification edits source, and an agent
can "fix" the hash in place, which is exactly the silent close this feature
exists to prevent).

## 4. Goals and non-goals

Goals:

- Detect, from repository contents alone, every source-anchored claim whose
  code changed since it was verified.
- Work on any checkout, including depth-one CI clones, with git absent.
- Record who verified a claim and when, distinguishing a person from an agent.
- Make demotion of stale mitigations and acceptances available, off by default.
- Give agents a precise worklist and a tool to clear it.
- Change nothing for a repository that never runs `verify`: all surfaces keep
  their current answers, with new counts added beside them.

Non-goals for this release:

- A call graph, or any change to the cross-file coverage rule in `coverage.ts`.
- Migrating this repository's file-level claims down to their functions (a
  follow-up done with the agent).
- Changes to `guardlink diff`, the dashboard, or `reanchor`.
- Gating on human-only verification (the ledger records enough to add it later).
- Symbol-level *coverage* reporting ("14 of 40 handlers annotated"). The
  structure layer makes it possible; it is a separate feature.

## 5. Architecture

Five pieces, four of them new.

| Piece | Location | Role |
|---|---|---|
| Structure layer | `src/structure/` (new) | Wraps tree-sitter. For a file and a line, returns the anchor: which declaration the line's comment attaches to, its extent, its name, and a content hash of its body that ignores comments and formatting. Nothing else in the product talks to tree-sitter. |
| Verification ledger | `.guardlink/verified.json` (new, committed) | One entry per source-anchored annotation: stable claim key, anchor hash when verified, verifier, timestamp. |
| Staleness predicate | `src/parser/verification.ts` (new) | Pure classification of every claim as verified, stale or unverified. The single implementation every surface calls. |
| Verify surfaces | `guardlink verify` command, `guardlink_verify` MCP tool (new) | The only writers of the ledger. |
| Parser | `src/parser/parse-file.ts` (touched) | Inline annotations gain an `anchor` object on their location, from the structure layer. |

Data flow on any read command: parse the model; structure-parse each annotated
file; compute each claim's current anchor hash; compare to the ledger. Git is
never required. When history is present and a ledger entry recorded a commit,
the report adds "changed in commit X" as enrichment. It is never an input to the
verdict.

The existing `parent_symbol` field on `SourceLocation` is deliberately left
untouched. The coverage rule in `coverage.ts` narrows coverage when two
same-file records carry different symbols, and it is inert in every inline
repository today only because inline records carry no symbol. Populating a new
`anchor` field instead keeps this change additive. Unifying the two fields is a
later, deliberate decision with its own measurement.

## 6. Structure layer

### 6.1 API

```ts
// src/structure/index.ts
export type AnchorScope = 'symbol' | 'block' | 'file';

export interface Anchor {
  scope: AnchorScope;
  /** `name` field of the anchor node, else the nearest enclosing named node, else null. */
  symbol: string | null;
  /** 1-based, inclusive. For scope 'file' this is the whole file. */
  start_line: number;
  end_line: number;
  /** "sha256-v1:<hex>" over the anchor's non-comment leaf tokens, in order. */
  hash: string;
  /** Present only when resolution fell back to a wider scope than the comment's position implied. */
  reason?: 'no-grammar' | 'grammar-failed' | 'no-sibling' | 'import-sibling' | 'first-node';
}

export interface FileStructure {
  /** Grammar used, or null when the file fell back to file scope for every line. */
  language: string | null;
  anchorForLine(line: number): Anchor;
  /** External mode: resolve a `@source … symbol:<name>` by declaration name. */
  symbolNamed(name: string): Anchor | null;
}

export function languageForExtension(ext: string): string | null;
export async function parseStructure(filePath: string, content: string): Promise<FileStructure>;
export const ANCHOR_HASH_VERSION = 1;
```

`parseStructure` is async because grammar loading is. `parseString` in the
parser stays synchronous and never attaches anchors; it is documented as such.

### 6.2 Anchor resolution

The rule is language-agnostic: it uses the uniform shape of a tree-sitter tree
rather than per-language lists of declaration node types.

For an annotation on line L:

1. Find the comment node whose range contains L. Annotations live in comments,
   so one always exists when the grammar parsed the file.
2. The anchor candidate is that comment's **next named sibling**. If the
   candidate has a `declaration` field (an `export_statement` wrapping a
   function, `export default`, a decorated definition), descend into it.
3. The symbol name is the anchor node's `name` field when present, else the
   `name` of the nearest enclosing node that has one, else null.
4. Scope is `symbol`.

Special cases, checked in this order, first match wins:

1. No grammar for the extension, or the grammar failed to load: file scope,
   reason `no-grammar` or `grammar-failed`, symbol null.
2. The comment is the first named node in the file: the claim describes the
   module. Whole file, scope `file`, reason `first-node`.
3. The comment has no next named sibling: it trails inside a block. Anchor is
   the enclosing declaration, found by walking up to the first ancestor with a
   `name` field. Scope `symbol`, reason `no-sibling`. If no such ancestor
   exists, file scope with the same reason.
4. The candidate's node type contains `import`, `package`, `require`, `use` or
   `using`: the claim describes the module. Whole file, scope `file`, reason
   `import-sibling`.
5. YAML: the candidate is the following top-level `block_mapping_pair`. Scope
   `block`, symbol is the key text.
6. Otherwise the general rule above applies.

Files in `DEFAULT_INCLUDE` with no meaningful declaration structure (HTML, CSS,
SVG, XML, SQL) are treated as file scope even where a grammar exists, by an
explicit list in the structure layer. Adding a grammar to the bundle does not by
itself make a language symbol-scoped; the list is the switch.

### 6.3 Hash

The hash is over the anchor node's leaf tokens in document order, skipping any
node whose type is a comment, joined by a control-character separator (the
`FIELD_SEP` convention from `annotation-hash.ts`). Consequences:

- Reformatting, reindenting, changing line endings, and editing any comment or
  annotation inside the body leave the hash unchanged.
- Renaming an identifier, changing a literal, adding or removing a statement
  change it.
- For file scope the root node is hashed the same way, so a file-level claim is
  stale when any non-comment token in the file changes. This is coarse by
  construction and is the reason the template change in §11 pushes claims down
  to symbols.

The string carries a version prefix, `sha256-v1:`. `ANCHOR_HASH_VERSION` bumps
whenever the token selection or separator changes; a ledger entry at a
different version reads as unverified, never stale (§8).

### 6.4 Grammars

Grammar WASM files are built by a repository script (`scripts/build-grammars.mjs`)
from pinned grammar packages using the tree-sitter CLI, into `grammars/*.wasm`.
The directory is added to the package `files` list and loaded lazily per
language from a path resolved relative to the module (`import.meta.url`), so it
works from `dist/` in a global install and from `src/` under `tsx`.

The community prebuilt bundle (`tree-sitter-wasms`, 52 MB for 36 grammars) is
not used: it is roughly twice the size we need and is built against an older
grammar ABI than the runtime we would pin. Building our own set gives one
version of the runtime, one ABI, and a CI test that loads every grammar.

Runtime: `web-tree-sitter` (about 5 MB unpacked) as a regular dependency.
Expected package growth: about 30 to 35 MB. This is recorded in the CHANGELOG
entry for the release.

Languages covered map one-to-one onto `DEFAULT_INCLUDE`: TypeScript, TSX,
JavaScript (JSX uses the same grammar), Python, Ruby, Go, Rust, Java, Kotlin,
Scala, C, C++, C#, Swift, Dart, SQL, Lua, Haskell, HCL, YAML, Bash, HTML, XML,
CSS, Elixir. `.gal` files are not structure-parsed; their anchors come from
`@source`.

### 6.5 Performance

Only files that contain at least one annotation are structure-parsed. Each is
parsed once per process and cached by content hash. Grammar loading is lazy per
language and happens at most once per process. On this repository that is about
70 files across one grammar. There is no on-disk cache in this release.

The MCP server's parse-cache fingerprint (`src/parser/fingerprint.ts`) must
include `.guardlink/verified.json` explicitly: the ledger is JSON, which is not
in `DEFAULT_INCLUDE`, so today a verify run would not invalidate a cached model.

### 6.6 External mode

For a `.gal` block with `@source file:<f> line:<n> symbol:<s>`, the anchor is
`symbolNamed(s)` on the structure of `f`. When the symbol is not found, the
anchor falls back to the recorded line, resolved as in §6.2. `reanchor` keeps
its whole-word grep in this release; moving it onto `symbolNamed` is a
follow-up.

## 7. Verification ledger

### 7.1 Format

`.guardlink/verified.json`, committed, written only by `guardlink verify` and
`guardlink_verify`.

```jsonc
{
  "schema": "guardlink.verified/v1",
  "anchor_hash_version": 1,
  "entries": [
    { "key": "a1b2c3…", "file": "src/mcp/server.ts", "verb": "mitigates",
      "claim": "#mcp against #path-traversal using #path-validation",
      "anchor": { "scope": "symbol", "symbol": "resolveRoot" },
      "hash": "sha256-v1:9f3e…", "verified_by": "human:zippon",
      "verified_at": "2026-09-03T10:12:00Z", "commit": "95479ee5" }
  ]
}
```

```ts
export interface LedgerEntry {
  key: string;
  file: string;
  verb: AnnotationVerb;
  /** Display only; never used for matching. */
  claim: string;
  anchor: { scope: AnchorScope; symbol: string | null };
  hash: string;
  /** "human:<name>" or "agent:<client name>". The prefix is what a future gate keys on. */
  verified_by: string;
  /** ISO 8601, UTC. */
  verified_at: string;
  /** HEAD at verify time, present only when git was available. Enrichment for the worklist. */
  commit?: string;
}

export interface Ledger {
  schema: 'guardlink.verified/v1';
  anchor_hash_version: number;
  entries: LedgerEntry[];
}
```

Entries are sorted by `file`, then `key`, and serialised one entry per line.
Two branches that verify different files merge without conflict; two that
verify the same claim conflict on one line, which is the correct outcome.

### 7.2 Key

The key is the SHA-256 of the claim's canonical record as `annotation-hash.ts`
already defines it: logical file, verb, arguments, external refs, description.
No line number. Identical claims in the same file get an ordinal suffix
(`…:0`, `…:1`) in document order.

Consequences:

- Moving a function within or across lines does not change the key.
- Editing the description does. The edited claim is a new, unverified claim,
  and the old entry becomes an orphan. This is correct: the claim's text is the
  claim.
- Moving a claim to another file does, for the same reason.

The key function lives in one place (`src/parser/claim-key.ts`) and accepts
both a raw `Annotation` and any `ThreatModel*` relation record, so the parser,
the predicate and the coverage filter cannot disagree about which claim an
entry names.

### 7.3 States

| Situation | State |
|---|---|
| Entry present, hash equal | `verified` |
| Entry present, hash differs, same hash version | `stale` |
| No entry | `unverified` |
| Entry present, different `anchor_hash_version` | `unverified` (rewritten on next verify) |
| Entry present, no matching claim | orphan (pruned on next verify) |

A stale record whose anchor symbol differs from the entry's recorded symbol
carries the hint `symbol-renamed`.

### 7.4 Scope

Every relationship annotation anchored in a source file gets an entry:
`mitigates`, `exposes`, `confirmed`, `accepts`, `transfers`, `flows`,
`boundary`, `validates`, `audit`, `owns`, `handles`, `assumes`, `feature`,
`comment`, and the accepted `entitles`. Definitions (`asset`, `threat`,
`control`, `actor`) in the definitions file do not. `shield:begin` and
`shield:end` do not, because they anchor nothing.

Reporting groups by verb. Only `mitigates` and `accepts` are **demotable**,
because those are the two verbs that remove an exposure from the export.

The ledger is excluded from the annotation hash: verifying is not a model
change.

## 8. Staleness predicate and demotion

```ts
// src/parser/verification.ts
export type ClaimState = 'verified' | 'stale' | 'unverified';

export interface ClaimRecord {
  key: string;
  state: ClaimState;
  annotation: Annotation;
  anchor: Anchor;
  entry?: LedgerEntry;
  hint?: 'symbol-renamed' | 'hash-version';
  /** Enrichment only, present when git history and entry.commit are both available. */
  changed_in?: { sha: string; summary: string }[];
}

export interface VerificationReport {
  claims: ClaimRecord[];
  orphans: LedgerEntry[];
  summary: {
    verified: number; stale: number; unverified: number; orphans: number;
    stale_by_verb: Partial<Record<AnnotationVerb, number>>;
    /** Stale `mitigates` + `accepts`. The number `--strict` and demotion act on. */
    demotable_stale: number;
  };
}

export async function classifyClaims(root: string, model: ThreatModel, ledger: Ledger | null): Promise<VerificationReport>;
/** Keys of stale `mitigates` and `accepts` records. */
export function demotionSet(report: VerificationReport): Set<string>;
```

This is the only implementation. `ci`, `status`, `sarif`, `report` and the MCP
server call it; none re-derives any part of it. That mirrors the rule the CI
module already states for coverage and drift.

**Demotion** is one filter in one place. `findUnmitigatedExposures` and the
underlying coverage predicate in `coverage.ts` gain an optional
`disregard: Set<string>` of claim keys. A mitigation or acceptance whose key is
in the set does not cover anything. No record is deleted or rewritten, so
annotation counts do not move; only counts of covered exposures do.

Demotion is on when either holds:

- `.guardlink/config.json` has `"verification": { "demoteStale": true }`.
- The command was run with `--demote-stale` (or `--no-demote-stale` to override
  the config the other way).

A config key rather than a flag alone is what keeps CI, status, SARIF and MCP
answering the same way for the same repository.

**Strict** is independent of demotion. `guardlink ci --strict` exits 1 when
`demotable_stale > 0`, in addition to its existing conditions. Unverified claims
never affect the exit code: every repository is entirely unverified on the day
it adopts this, and a gate that fails on that day gets deleted.

```
exit_code = strict && (exposures > 0 || drift > 0 || demotable_stale > 0) ? 1 : 0
```

## 9. Surfaces

| Surface | Change |
|---|---|
| `guardlink ci` | Third check. Text adds a "Stale claims" block grouped by verb, demotable verbs first, each line `file:line  @verb claim  (symbol, verified <date> by <who>)`. JSON adds `stale: ClaimRecord[]` (serialised without `annotation.raw`), `unverified: {key,file,line,verb}[]`, `orphans: LedgerEntry[]`, and summary fields `stale`, `unverified`, `orphans`, `stale_by_verb`, `demotable_stale`, `demote_stale: boolean`. Additive under `guardlink.ci/v1`. When no ledger exists, the block prints the bootstrap command. |
| `guardlink status` | One line: `Verified claims: 410 / 471 (stale 8, unverified 53)`. Honours demotion in its exposure counts. |
| `guardlink sarif` | Honours demotion. Byte-identical output when demotion is off, whether or not stale claims exist. |
| `guardlink report` | Honours demotion. Gains a "Stale claims" section listing the same lines as `ci`. |
| `guardlink validate` | Gains one diagnostic, `ledger-corrupt`, level `error`, when the ledger exists and does not parse or fails shape validation. Does not classify claims. |
| MCP `guardlink_context(file)` | Adds `verification: { stale: [...], unverified: [...] }` for that file, so an agent following the existing "call context before editing" rule sees them without asking. |
| MCP `guardlink_status` | Adds the three counts and `demote_stale`. |
| MCP `guardlink_lookup`, `guardlink_paths`, `guardlink_graph` | Honour demotion through the shared coverage filter. No new query forms. |
| `guardlink diff`, dashboard, `reanchor` | Unchanged in this release. |

Every read surface stays read-only. The D16 guard in CI ("read commands leave
the tree clean") is extended to run `guardlink ci` with a ledger present.

## 10. Re-verification

Two writers, and they are the only ones.

### 10.1 `guardlink verify`

```
guardlink verify [dir] [-p <project>] [-f text|json] [--by <name>] [--dry-run] [--force]
guardlink verify [dir] --stale
guardlink verify [dir] --all
guardlink verify [dir] <file>[:<line>] ...
```

| Form | Locks unverified | Re-locks stale | Prunes orphans |
|---|---|---|---|
| no flags | yes | no, lists them | yes |
| `--stale` | no | all | yes |
| `--all` | yes | all | yes |
| `<file>` | in that file | in that file | in that file |
| `<file>:<line>` | that claim | that claim | no |

Re-locking a stale claim is an assertion that the control still holds, so the
default form never does it silently. `--all` exists for adoption and for a
deliberate reset, and prints what it re-locked.

The verifier is `human:<git user.name>` when git config is readable, else
`human:<OS username>`, overridable with `--by`. `commit` is recorded when
`git rev-parse HEAD` succeeds. `--dry-run` prints the entries that would change
and writes nothing. JSON output lists `locked`, `relocked`, `pruned`.

`verify` writes only `.guardlink/verified.json`. It never touches source.
`--force` is needed only to replace a ledger that failed to parse (§12).

### 10.2 `guardlink_verify` MCP tool

```ts
guardlink_verify({ file: string, line?: number })
  → { changed: LedgerEntry[], skipped: { key: string; reason: string }[] }
```

There is no whole-repository form on purpose: an agent must name what it
re-checked, so a single call can never silence the model. Without `line` it
acts on every claim in the file, which is the natural unit after editing one
file. The verifier is `agent:<client name>` from the MCP `initialize`
handshake, falling back to `agent:unknown`. The tool invalidates the parse
cache and returns the entries it changed.

The tool is listed with the other writers in the MCP instructions text and in
the agent templates, beside the sentence that already says which decisions are
human-only. Re-verifying is not one of them: it is the same claim as writing a
`@mitigates`, which agents are already allowed to do.

## 11. Agent loop

Two template changes, written by `guardlink init` and refreshed by
`guardlink sync`, through `annotationPlacementSection` and the key-rules list
in `src/init/templates.ts`:

1. **Placement.** "the doc-block of the function or module they describe"
   becomes "the doc-block of the function that implements the control. Use the
   module doc-block only for a fact that is true of the whole file." A claim on
   a function is checkable; a claim on a file goes stale on any edit.
2. **Re-check rule.** A new numbered rule: "When you change a function that
   carries claims, re-read them. Fix or remove what no longer holds, then call
   `guardlink_verify` for that file. A claim you left in place without
   re-reading it is a claim you have vouched for."

`guardlink annotate --stale` builds a prompt from the `VerificationReport`:
each stale claim with its file, line, verb, claim text, symbol, and, when
available, the diff of the anchor since `entry.commit`. It asks the agent to
re-verify through the MCP tool or to rewrite the claim, and hands off to the
configured agent through the existing launcher. The prompt builder lives in
`src/agents/prompts.ts` beside the others and reuses their framing.

## 12. Failure modes

| Condition | Behaviour |
|---|---|
| No grammar for the extension | File-scope anchor, `reason: 'no-grammar'`. Silent: this is the designed fallback for HTML, CSS and friends. |
| Grammar exists but fails to load | File-scope anchor, `reason: 'grammar-failed'`, one warning per language per process naming the WASM path. |
| Comment with no resolvable anchor | File-scope anchor with the reason recorded on the `Anchor`. |
| Ledger missing | Every claim `unverified`. `ci` and `status` print `Run guardlink verify --all to start tracking.` Exit code unaffected. |
| Ledger unparsable or wrong shape | `validate` emits `ledger-corrupt` (error). `ci`, `status`, `sarif`, `report` and MCP treat the ledger as absent and print the diagnostic once. `verify` refuses to write over it without `--force`. |
| Ledger `schema` unknown | As unparsable. |
| `anchor_hash_version` differs from the runtime's | Every entry `unverified` with `hint: 'hash-version'`; the next `verify` rewrites the file at the current version. |
| Symbol renamed | Key unchanged, hash changed, `stale` with `hint: 'symbol-renamed'`. |
| Claim edited or moved to another file | New key, `unverified`; old entry orphaned and pruned on next `verify`. |
| Git absent | `commit` omitted, `changed_in` omitted, verifier from OS username. Nothing else differs. |
| Two claims with identical text in one file | Ordinal suffix on the key; both tracked. |

## 13. Type and schema changes

All additive.

- `SourceLocation` gains `anchor?: Anchor`. `annotation-hash.ts` excludes it,
  as it excludes `parent_symbol`, so inline and external authoring of the same
  model still hash identically. `ANNOTATION_HASH_VERSION` does not change,
  because the set of hashed fields does not.
- `ThreatModel` is unchanged. `VerificationReport` is a separate exported type
  computed on demand, not stored in `model.json`.
- `DiagnosticCode` gains `ledger-corrupt`.
- `CiReport` and `CiSummary` gain the fields in §9 under the existing schema id.
- `.guardlink/config.json` gains an optional `verification: { demoteStale: boolean }`.
- New exports from `guardlink/parser`: `classifyClaims`, `demotionSet`,
  `readLedger`, `writeLedger`, `claimKey`. New subpath `guardlink/structure`
  exporting `parseStructure`, `languageForExtension`, `ANCHOR_HASH_VERSION`.
- `package.json`: `web-tree-sitter` as a dependency; `grammars/` in `files`;
  a `./structure` entry in `exports` beside the existing subpaths.

## 14. Testing

One group per component, all under `tests/` with vitest.

- **Anchor resolution.** Fixtures for TypeScript (including `export default`,
  a decorated class method, a trailing comment inside a block), Python
  (decorated `def`, class body, `#` comment before an assignment), Go, Rust,
  Java, YAML, Bash, and one unsupported extension. Each asserts scope, symbol
  and line range.
- **Hash invariance.** Reformat, reindent, edit a comment, add an annotation
  line, move the function, convert to CRLF: same hash. Change one token: a
  different hash. Same input on two platforms: same hash, via the CRLF case.
- **Ledger.** Round trip; entries sorted; one entry per line; orphan pruning;
  ordinal keys for duplicate claims; corrupt file yields `ledger-corrupt`.
- **Predicate.** Every row of the states table in §7.3, the version-mismatch
  path, and the rename hint.
- **Demotion.** SARIF byte-identical with demotion off, both with and without
  stale claims present, mirroring the existing entitlement byte-identity test.
  With demotion on, the exposure under a stale mitigation appears in
  `unmitigated`. Config key and flag agree; flag overrides config both ways.
- **CI.** Text and JSON for: no ledger, clean ledger, stale claims, `--strict`
  with only unverified claims (exit 0), `--strict` with a stale mitigation
  (exit 1).
- **Verify.** Each row of the table in §10.1; `--dry-run` writes nothing;
  `--by`; the MCP tool refuses a call without `file`; the MCP verifier prefix
  is `agent:`.
- **Templates.** Assertions on the placement sentence and the re-check rule,
  in the style of the existing instruction-claims tests.
- **Grammars.** A test that loads every WASM in `grammars/` and parses a
  one-line sample, so an ABI mismatch fails in CI rather than in a user's
  terminal.
- **Read-only.** The D16 clean-tree guard runs `ci` with a ledger present.

## 15. Rollout on this repository

1. Land the feature behind no flag: with no ledger, every surface reports
   "unverified" counts and nothing else changes.
2. `guardlink verify --all` to create the ledger. Commit it.
3. Add `node dist/cli/index.js ci .` to the dogfood workflow, advisory.
4. `guardlink sync` to regenerate the agent files with the new placement and
   re-check rules.
5. Follow-up, separate change: run `guardlink annotate` with a prompt that
   moves this repository's file-level claims down to the functions that
   implement them, then verify. Only after that is demotion worth turning on
   here.

## 16. Delivery order

The implementation plan should sequence the work so that each half is
shippable on its own:

1. **Detect.** Structure layer with grammars and the load-every-grammar test;
   `anchor` on inline locations; claim key; ledger read and write; predicate;
   `guardlink verify` CLI; the third check in `ci`; the `status` line. At the
   end of this half a repository can bootstrap a ledger and see stale claims in
   CI. Demotion is not yet wired.
2. **Act.** Demotion filter in `coverage.ts` with the config key and flag;
   `sarif` and `report`; MCP `guardlink_verify`, `guardlink_context` and
   `guardlink_status`; the fingerprint change; template changes;
   `guardlink annotate --stale`; rollout steps on this repository.

## 17. Implementation risks

- **Grammar ABI.** Each grammar WASM must be built against a tree-sitter
  version the pinned runtime accepts. The build script pins both; the
  load-every-grammar test catches a mismatch.
- **Package size.** About 30 to 35 MB added. Stated in the CHANGELOG. Library
  consumers who never call the structure layer pay install size only; nothing
  loads until a file is structure-parsed.
- **Path resolution in `dist/`.** Grammar paths resolve from `import.meta.url`;
  the CLI binary test that already exists is extended to run `status` on a
  fixture from a packed install.
- **Windows paths in keys.** The key uses the same forward-slash normalisation
  `annotation-hash.ts` already applies.
- **Node 18.** `web-tree-sitter` runs on Node 18; the CI matrix already covers
  18, 20 and 22.
