# CHANGELOG draft — 2.0.0

**This is a draft for review, not the changelog.** `CHANGELOG.md` is owned by a
later instance; nothing here has been written to it. Entries are grouped the way
`CHANGELOG.md` already groups them and are ordered breaking-first within each
section.

## Read the major number correctly

**2.0.0 is scoped to two things: the TypeScript type surface and the
threat-model JSON schema. Nothing about the CLI broke.**

No command was removed. No flag was removed. No output format changed shape
except the threat-model JSON `coverage` block, and no exit code changed except
one that was previously wrong (`report --format <unrecognised>` used to write
nothing and report success). **If you use `guardlink` from the command line or
through MCP, upgrading from 1.4.5 requires no migration** — the release is
additive there: `--no-pretty`, `guardlink-mcp --help`/`--version`, a working
`tui --model`, and a new warning tier that cannot fail a build.

The major exists for programmatic consumers. `CoverageStats` lost two properties
and renamed a third, `UnannotatedSymbol` was deleted, `DiagnosticCode` widened,
and `REPORT_SCHEMA_VERSION` moved — and the breakage reaches consumers who never
import any of those names, because reading `model.coverage.total_symbols` off a
`ThreatModel` breaks through every one of the seven export subpaths. That was
measured with a probe project compiled against both versions, not assumed. A
consumer that only calls runtime functions and never touches `.coverage`
compiles unchanged.

Anyone skimming the version number will assume the CLI broke. It did not.

Every claim below was verified by running the freshly built `dist/`. Where a
before/after pair is quoted, both halves were observed — the "before" from a
build of `55d8111` in a detached worktree, not from memory or from
`docs/_analysis/delta-v1.4.5.md`.

---

## [2.0.0] — unreleased

### BREAKING

#### Threat model JSON: `coverage` reshaped (model version 1.1.0 → 1.2.0)

`coverage` shipped four fields, two of which were hardcoded constants in a schema
presented as public:

```jsonc
// before — model 1.1.0
"coverage": {
  "total_symbols": 0,             // always 0; symbol coverage was never computed
  "annotated_symbols": 105,       // counts ANNOTATIONS, never symbols
  "coverage_percent": 100,        // file coverage
  "unannotated_critical": []      // always []
}

// after — model 1.2.0
"coverage": {
  "annotation_count": 105,
  "coverage_percent": 100
}
```

- **Removed** `total_symbols` and `unannotated_critical`. Both were permanently
  constant, so a consumer could not distinguish "not computed" from "computed,
  and it is zero". Absent says the first; `0` and `[]` said the second. They are
  gone rather than deprecated — GuardLink does no per-symbol parsing, and a
  field that will never be populated is not a field.
- **Renamed** `annotated_symbols` → `annotation_count`. The old name is what led
  three separate consumers to divide it by a denominator that did not exist.
- `coverage_percent` is unchanged and still means **file** coverage.

Affects `guardlink parse`, `guardlink report --format json`,
`.guardlink/model.json`, the `guardlink://model` MCP resource, and the
`guardlink_parse` / `guardlink_status` MCP tools.

**TypeScript surface.** `CoverageStats` lost two properties and renamed a third;
`UnannotatedSymbol` was deleted. Measured blast radius — a consumer breaks if it
either names those types or reads the removed fields off a `ThreatModel`,
through **any** subpath, including `guardlink/parser`, `guardlink/report`,
`guardlink/diff` and `guardlink/analyzer`. A consumer that only calls runtime
symbols (`parseProject`, `generateReport`, `diffModels`, `generateSarif`) and
never touches `.coverage` compiles unchanged — verified, zero errors.

**Migration.** Read `annotation_count` instead of `annotated_symbols`. If you
were dividing by `total_symbols` you were dividing by zero-or-`NaN`; use
`coverage_percent`, which is real, and note that it counts files.

#### `DiagnosticCode` widened from 2 members to 12

Not a removal, but it breaks an exhaustive `switch` with a `never` fallthrough.
Verified: a consumer that exhaustively handled `malformed-annotation` and
`prose-like` now fails to compile. Producers are unaffected. See *Added* below
for the list.

#### `REPORT_SCHEMA_VERSION` 1.0.0 → 1.1.0

The workspace-report schema version, exported from the package root. Its TS type
is the string literal, so a consumer pinning `const x: '1.0.0' = REPORT_SCHEMA_VERSION`
no longer compiles — verified. The bump is required: `detectSchemaMismatch`
compares this value across the reports being merged, and leaving it at 1.0.0
made a mixed-version merge invisible to the one mechanism built to detect it.

**User-visible consequence.** Merging reports produced by different GuardLink
versions now emits a warning that did not previously appear:

```
⚠ Reports use different schema versions: 1.0.0, 1.1.0. Results may be inconsistent.
```

This is advisory. The merge still succeeds and still exits 0. Regenerate the
older reports with `guardlink report` to clear it.

### Fixed

- **`guardlink merge` produced `"annotation_count": null` from any pre-1.2.0
  report.** `combined.coverage.annotation_count += m.coverage.annotation_count`
  read `undefined` off an older report, `0 += undefined` is `NaN`, and
  `JSON.stringify(NaN)` is `null` — so a workspace dashboard reported a null
  annotation count silently, exit 0, no warning. Reports are now normalised at
  the point they are read from disk, and the old `annotated_symbols` spelling is
  carried across rather than coalesced to `0`: an old repo's real count is
  preserved instead of being replaced by a fabricated zero. Verified across all
  four combinations of old and current inputs — each totals correctly.

- **The TUI reported `v0.0.0` on any install path containing a space.**
  `src/tui/index.ts` resolved its own location via `new URL('.', import.meta.url).pathname`,
  which percent-encodes, so the `existsSync` probe missed `package.json` and the
  fallback chain bottomed out. `guardlink --version` beside it reported the truth,
  which is what made it survive. Verified before/after from a directory named
  `space dir`.

- **SARIF `tool.driver.version` was the hardcoded string `1.4.3`** — neither the
  package version nor anything else. Now resolved at runtime.

- **`guardlink report --format <unrecognised>` wrote nothing and exited 0.**
  Both output branches were false, so the command silently produced no file and
  reported success. It now errors and exits 1, matching `migrate --to`:

  ```
  $ guardlink report . --format bogus
  Invalid --format "bogus". Use "md", "json", or "both".      # exit 1
  ```

- **`guardlink tui --model` was parsed and never read.** The flag is now
  forwarded through `GUARDLINK_LLM_MODEL`, the sibling of the existing
  `GUARDLINK_LLM_KEY` and `GUARDLINK_LLM_PROVIDER`. Verified end to end — the TUI
  header moves from `AI: anthropic/claude-sonnet-4-6` to
  `AI: anthropic/probe-model-xyz`. An explicit flag still outranks the env var.

- **`guardlink sync` and `guardlink entitle` did not read the configured project
  name.** `sync` hardcoded the directory basename and `entitle` hardcoded
  `'unknown'`; both now go through `readConfiguredProject` like every other
  command. Note that neither produced divergent *output* — no synced agent file
  and no ledger entry contains the project name — so the visible change is
  confined to `entitle --help`, which no longer advertises `(default: "unknown")`.

- **The `guardlink entitle --propose` example in the generated agent files did
  not run.** `CLAUDE.md`, `AGENTS.md`, `.gemini/GEMINI.md` and
  `.github/copilot-instructions.md` are consumed by coding agents at runtime, and
  all four carried an example missing the required `--file` and `--line`:

  ```
  before:  ✗ --propose needs --file, --line                      # exit 1
  after:   ✓ Filed proposal ent-ns_admin.archival_fs.path_traversal   # exit 0
  ```

  Verified by running the regenerated example verbatim in a repo shaped like the
  example: exit 0, `inert: false`, `warnings: []`, citation parsed.

- **`src/mcp/server.ts` claimed "all 18 tools"** in the comment explaining why
  the freshness envelope is applied at registration. There are 24 — confirmed
  both by counting `registerTool` call sites and by a live `tools/list`.

### Added

- **`unknown-verb` diagnostic tier.** An unrecognised `@verb` was discarded with
  no diagnostic at all, so `@flow` (the README shipped it twice) and `@migitates`
  produced neither an annotation nor a word. A token within a length-scaled edit
  distance of a known verb now emits a warning naming the suggestion:

  ```
  ⚠ app/a.ts:2: Unknown annotation verb @flow — did you mean @flows? …
  ```

  **Warning only — it cannot fail a gate.** Verified: `parse`, `validate`,
  `validate --strict`, `ci` and `ci --strict` all exit 0 on a fixture whose only
  problem is one `@flow`, while the same commands still exit 1 on a real error.
  Only error-level diagnostics reach SARIF, so the tier cannot reach GitHub
  Advanced Security either.

  Containment, measured against juice-shop, bkeeper, ghostfolio and specter-v1
  (13,609 source files):
  - Tokens carrying a namespace separator before the verb (`@g.comment`,
    `@gl:exposes`) are excluded — a dialect is a decision, not a typo. This alone
    accounts for all 1,365 warnings the first cut produced.
  - A 170-entry deny-list of JSDoc/TSDoc/Doxygen/phpDoc/Epydoc tags is excluded
    outright, so silence on `@param` is a property of the design rather than a
    consequence of how far `param` happens to sit from `threat`.
  - Repeats collapse to one diagnostic per distinct token per file, carrying an
    occurrence count. Per file, not globally, so the `file:line` anchor every
    consumer depends on survives and the same typo in three files is reported
    three times.

  Final measurement: **0 warnings across all four corpora.**

- **`diagnostics` config key.** `.guardlink/config.json` accepts:

  ```json
  { "diagnostics": { "unknown-verb": false } }
  ```

  Only **warnings** can be switched off. Listing an error-level code is accepted
  and ignored — verified: `malformed-annotation` still prints and still exits 1
  when disabled. Quieting noise is a taste decision; silencing a broken
  annotation is not.

- **Ten more `DiagnosticCode` values**, so machine consumers can classify what
  they previously could only pattern-match out of message prose: `unknown-verb`,
  `duplicate-id`, `dangling-ref`, `undeclared-actor`, `inert-entitlement`,
  `imprecise-entitlement`, `accepted-without-audit`, `off-convention-gal`,
  `stray-gal-source`, `entitlement-provenance`. Every diagnostic kind GuardLink
  emits now carries a code; each was verified by triggering it from a fixture.

- **`guardlink-mcp --help` and `--version`.** The bin previously ignored every
  argument and sat waiting for JSON-RPC on stdin, so `guardlink-mcp --version`
  hung rather than answering. Both now print to stdout and exit without
  connecting a transport — verified: exit 0 in 0.35s with stdin held open, zero
  JSON-RPC frames emitted, and the no-flag invocation still starts the server.

- **`guardlink parse --no-pretty`.** `--pretty` defaulted to true with no
  counterpart, so the compact branch was unreachable:

  ```
  before:  error: unknown option '--no-pretty'
  after:   one line of compact JSON (vs 100 pretty-printed)
  ```

### Changed

- **Version resolution consolidated to one function.** Four separate
  implementations of "read package.json at runtime" existed — in `src/version.ts`,
  `src/cli/index.ts`, `src/tui/index.ts` and `src/workspace/metadata.ts` — with
  two different failure fallbacks (`'0.0.0'` and `'unknown'`) and one outright
  bug. `getPackageVersion()` is now the only one. All five version-reporting
  surfaces agree, verified from a path containing a space: `guardlink --version`,
  `guardlink-mcp --version`, the TUI header, `metadata.guardlink_version` in
  report JSON, and the MCP `serverInfo`. Two tests walk `src/` and fail if a
  fifth copy appears or if any module resolves its own path via `URL.pathname`.

- **`report --format md` no longer reports unannotated critical symbols.** The
  section was driven by `coverage.unannotated_critical`, which was always empty,
  so the branch never ran. Removed with the field.

- **`/scan` in the TUI** no longer prints "All security-relevant symbols are
  annotated!" unconditionally. That branch tested the same always-empty field.
  It now reports unannotated *files*, which are real.

- **`DashboardStats.coverageTotal` removed.** Its source was the hardcoded
  `total_symbols`; keeping the field would have meant keeping the constant.
  `coverageAnnotated` is retained and now reads `annotation_count`.

### Internal

Not part of the public surface — `annotationCount`, `normalizeCoverage` and
`readDisabledDiagnostics` are new but are not exported through any of the seven
subpaths. Listed here so a reader of the diff does not mistake them for API.
