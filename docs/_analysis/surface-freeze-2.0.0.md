# GuardLink — Surface Freeze 2.0.0

**Revision 1** · 2026-08-12 · release **2.0.0**

> The major is scoped to the TypeScript type surface and the threat-model JSON
> schema. No CLI command, flag, or output behaviour was removed; CLI and MCP
> users upgrade from 1.4.5 with no migration. See
> `changelog-draft-2.0.0.md` for the reasoning behind the version number.

> ## Read this first
>
> **`docs/_analysis/delta-v1.4.5.md` describes the surface as it stood at commit
> `55d8111`, before this branch. It is now partly historical.** It remains the
> authority on everything this branch did not touch — the CLI command inventory,
> the annotation grammar, the configuration model, the workspace format, the
> recommendations ledger.
>
> **This file supersedes these sections of it:**
>
> | Section | What changed |
> |---|---|
> | §2.3 `parse [dir]` | `--pretty` is no longer INERT — `--no-pretty` exists |
> | §2.3 `report [dir]` | An unrecognised `--format` now errors and exits 1; the identical-arms ternary is gone |
> | §2.3 `tui [dir]` | `--model` is no longer DEAD — it forwards through `GUARDLINK_LLM_MODEL` |
> | §2.3 `sync [dir]` | No longer hardcodes `basename(root)` |
> | §2.3 `entitle [dir]` | `-p/--project` no longer defaults to `'unknown'` |
> | §2.1 `guardlink-mcp` | No longer takes "no arguments, no flags" — `--help` and `--version` exist |
> | §2.4 Dead-flag summary | Both entries (1 DEAD, 1 INERT) are resolved; the table now reads 0 and 0 |
> | §2.5 Environment variables | `GUARDLINK_LLM_MODEL` is a ninth variable |
> | §2.6 Flags whose example does not do what it implies | The `entitle --propose` row is fixed |
> | §3.2 / §3.5 Symbol inventory | Three new unexported functions; `UnannotatedSymbol` deleted |
> | §5.3 Malformed-input behaviour | The three-tier table is now four tiers; the "only two `code` values" claim is obsolete — there are twelve |
> | §5.5 `coverage` table | All four rows superseded; the block now has two fields |
> | §5.5 SARIF | `tool.driver.version` is no longer `1.4.3` |
> | §6.2 Precedence | The `sync`/`entitle` project-name note is superseded (and was already corrected in that file's Revision 2) |
> | §8 / §10 | `guardlink-mcp`'s tool count comment said 18; it is 24 |
>
> Everything else in `delta-v1.4.5.md` still stands. Where the two disagree on a
> section listed above, **this file wins**.

## Method

Every row below was produced by running two builds and comparing:

- **before** — commit `55d8111` built in a detached `git worktree`, `npx tsc` exit 0.
- **after** — this working tree, `npm run build` exit 0.

Neither column is quoted from `delta-v1.4.5.md`. Where something could not be
checked without side effects, that is stated rather than asserted. Nothing in
this branch has been committed.

---

## 1. CLI behaviour

| # | Surface | Before | After |
|---|---|---|---|
| 1 | `guardlink parse . --no-pretty` | `error: unknown option '--no-pretty'` | 1 line of compact JSON (default remains 100 pretty-printed lines) |
| 2 | `guardlink report . --format bogus` | no output written, **exit 0** | `Invalid --format "bogus". Use "md", "json", or "both".` **exit 1** |
| 3 | `guardlink report` md filename | `opts.output \|\| (opts.format === 'md' ? 'threat-model.md' : 'threat-model.md')` | `opts.output \|\| 'threat-model.md'` — identical arms removed, behaviour unchanged |
| 4 | `guardlink tui . --model X` | header `AI: anthropic/claude-sonnet-4-6` (flag ignored) | header `AI: anthropic/probe-model-xyz` |
| 5 | `guardlink entitle --help` | `-p, --project <n>  Project name (default: "unknown")` | `… (default: the name in .guardlink/config.json)` |
| 6 | `guardlink sync` | parsed with `project: basename(root)` | parsed with `readConfiguredProject(root) ?? basename(root)` |
| 7 | `guardlink --version` | `1.4.5` | `2.0.0` |

**On rows 5 and 6 — no output difference.** Verified: synced agent files are
byte-identical across two syncs with different configured project names
(`diff -r` over four files, no difference), and the entitlement ledger records no
project field. These are code-path corrections. `delta-v1.4.5.md` §2.3 originally
claimed `sync` "writes a different project name into the agent files than `status`
prints"; that claim was disproved and corrected in its own Revision 2.

## 2. `guardlink-mcp`

| Surface | Before | After |
|---|---|---|
| `--version` | ignored; **started the stdio server** and blocked on stdin | prints `2.0.0`, exit 0 |
| `--help` / `-h` | ignored; started the server | prints 668-byte help block, exit 0, **0.35s**, stderr empty, **0 JSON-RPC frames** |
| no flag | starts the server | unchanged — still running after 1.5s with stdin held open |
| `serverInfo.version` | `1.4.5` | `2.0.0` |
| tool count | source comment said "all 18 tools" | says 24 — confirmed by 24 `registerTool` sites **and** a live `tools/list` |

The `--help`/`--version` paths write to stdout and exit *before* any transport is
connected, which is what makes writing to stdout safe there. Once
`startStdioServer()` runs, stdout is the JSON-RPC channel.

## 3. Threat model JSON — model version 1.1.0 → 1.2.0

```jsonc
// before
"coverage": { "total_symbols": 0, "annotated_symbols": 6,
              "coverage_percent": 100, "unannotated_critical": [] }
// after
"coverage": { "annotation_count": 6, "coverage_percent": 100 }
```

Emitted by `guardlink parse`, `report --format json`, `.guardlink/model.json`,
`guardlink://model`, and the `guardlink_parse` / `guardlink_status` MCP tools —
all verified carrying the new shape.

### Consumer audit

Every consumer of the coverage block, and what a **pre-1.2.0** model produces
through it today:

| Consumer | Reads `CoverageStats`? | Reachable from disk? | Behaviour on an old model |
|---|---|---|---|
| `merge --json` | yes | **yes** | correct — normalised at ingress |
| `merge -o` → workspace-dashboard.html | yes | **yes** | correct |
| `merge --diff-against` markdown | no — uses `repo_statuses[].annotation_count` | yes | clean; 0 `undefined`/`NaN`/`null` in output |
| `dashboard` → threat-dashboard.html | yes | no — always live-parsed | safe by construction; hardened anyway |
| `report --format json` | emits verbatim | no | current shape |
| `report --format md` | no — computes from file counts | no | `- **2** of **2** files have security annotations (100%)` |
| MCP `guardlink_status` | yes | no | current shape |
| MCP `guardlink_parse` | emits whole model | no | current shape |
| SARIF | **no** — `buildCoverageIndex` is the unrelated mitigation index | no | no coverage field appears in output at all |

### The regression this produced, and its fix

Merging any pre-1.2.0 report produced, silently, exit 0, no warning:

```json
"coverage": { "annotation_count": null, "coverage_percent": 100 }
```

`0 += undefined` is `NaN`; `JSON.stringify(NaN)` is `null`. Fixed by normalising
at `loadReportJson` — the single point where a model arrives from disk rather
than from the parser — and by reading the old `annotated_symbols` spelling rather
than coalescing to `0`. Coalescing would have stopped the `NaN` while replacing a
real count with a fabricated zero.

| Merge inputs | Exit | Merged coverage | `schema_mismatch` warning |
|---|---|---|---|
| old + old | 0 | `{"annotation_count": 12, "coverage_percent": 100}` | no |
| old + new | 0 | `{"annotation_count": 12, "coverage_percent": 100}` | **yes** |
| new + old | 0 | `{"annotation_count": 12, "coverage_percent": 100}` | **yes** |
| new + new | 0 | `{"annotation_count": 12, "coverage_percent": 100}` | no |

`REPORT_SCHEMA_VERSION` moved 1.0.0 → 1.1.0 so `detectSchemaMismatch` can see the
reshape. Users merging mixed-version reports will now see, for the first time:

```
⚠ Reports use different schema versions: 1.0.0, 1.1.0. Results may be inconsistent.
```

Advisory only — the merge succeeds and exits 0.

## 4. Diagnostics

### The fourth tier

`delta-v1.4.5.md` §5.3 documents three outcomes for a malformed line. There are
now four:

| Input | Outcome | Level | Code |
|---|---|---|---|
| Line does not start with `@` | silent | — | — |
| `@verb` unknown, near a known verb | **warning** | `warning` | **`unknown-verb`** |
| `@verb` unknown, not near one | silent | — | — |
| `@verb` known, regex fails, structural evidence | error | `error` | `malformed-annotation` |
| `@verb` known, regex fails, no evidence | warning | `warning` | `prose-like` |

Before, `@flow` and `@migitates` produced **0 diagnostics**. After, each produces
one warning naming the suggestion.

### It cannot fail a gate

Fixture: one `@flow`, nothing else wrong — exposure declared *and* mitigated, all
refs resolve.

| Command | Exit | Control (same fixture + one real error) |
|---|---|---|
| `guardlink parse .` | **0** | 1 |
| `guardlink validate .` | **0** | 1 |
| `guardlink validate . --strict` | **0** | — |
| `guardlink ci .` | **0** | — |
| `guardlink ci . --strict` | **0** | — |

The control column matters: the gates do fire on a real error, so this is not a
vacuous pass. `src/ci/index.ts` contains no reference to diagnostics at all — its
exit is a pure function of (strict, exposures, drift).

### It cannot reach GitHub Advanced Security

Only **error**-level parse diagnostics reach SARIF. On a fixture producing 1 error
and 3 warnings:

| Diagnostic | Level | In SARIF? |
|---|---|---|
| `unknown-verb` | warning | **no** |
| `prose-like` | warning | **no** |
| `malformed-annotation` | error | yes → `guardlink/parse-error` |
| dangling ref | warning | yes → `guardlink/dangling-ref` |

SARIF *does* carry warning-level results, but only from the `dangling-ref` rule,
which reads `findDanglingRefs()` and not the diagnostics array. `--no-diagnostics`
suppresses only the parse-error rule (3 results → 2).

### False-positive measurement

Four corpora, none used to tune the detector, 13,609 source files:

| Corpus | Source files | First cut | Shipped |
|---|---|---|---|
| juice-shop | 660 | 0 | **0** |
| bkeeper | 3,764 | 0 | **0** |
| ghostfolio | 1,043 | 0 | **0** |
| specter-v1 | 8,142 | **1,365** | **0** |

Every one of specter-v1's 1,365 was a namespaced token — `@g.comment` ×1,340,
`@g.boundary` ×11, `@g.mitigates` ×8, `@g.exposes` ×6 — from an in-house
doc-comment convention. Not one JSDoc tag fired, in any corpus, at any point.

Three containment rules, in the order they apply:

1. **Namespace rule** `/^[A-Za-z][\w-]*[.:][A-Za-z]/` — excludes a token carrying
   a separator before the verb. Removes all 1,365.
2. **170-tag documentation deny-list** — JSDoc/TSDoc/Doxygen/phpDoc/Epydoc,
   excluded by name. Removed **0** observed false positives; shipped so that
   silence on `@param` is a stated guarantee rather than a margin (`param` sits 4
   edits from `threat`) that a future verb could close unnoticed.
3. **Per-file, per-token collapse** — repeats become one diagnostic carrying
   `(N occurrences in this file; first at line L)`. Per file rather than
   globally, so the `file:line` anchor every consumer needs survives and the same
   typo in three files is still reported three times.

### Config key

```json
{ "diagnostics": { "unknown-verb": false } }
```

Default on. **Only warnings are suppressible** — listing an error-level code is
accepted and ignored. Verified: with `malformed-annotation` disabled, the error
still prints and `validate` still exits 1.

### Codes

Every diagnostic kind now carries a machine-readable `code`. Before: 2 defined,
~7 emitted without one.

| Code | Level | Emitter | Was coded before? |
|---|---|---|---|
| `malformed-annotation` | error | parse-line | yes |
| `prose-like` | warning | parse-line | yes |
| `unknown-verb` | warning | parse-line | **new tier** |
| `duplicate-id` | error | parse-project | no |
| `dangling-ref` | warning | validate | no |
| `undeclared-actor` | error | validate | no |
| `inert-entitlement` | warning | validate | no |
| `imprecise-entitlement` | warning | validate | no |
| `accepted-without-audit` | warning | validate | no |
| `off-convention-gal` | warning | validate | no |
| `stray-gal-source` | warning | validate | no |
| `entitlement-provenance` | error | review/entitlements | no |

Each was verified by constructing a fixture that triggers it.

## 5. Version reporting

There were **four** implementations of "read package.json at runtime", two
distinct fallbacks, and one bug. From an install path containing a space:

| Surface | Before | After |
|---|---|---|
| `guardlink --version` | 2.0.0 | 2.0.0 |
| `guardlink-mcp --version` | 2.0.0 | 2.0.0 |
| **TUI header** | **v0.0.0** | **v2.0.0** |
| `report` → `metadata.guardlink_version` | 2.0.0 | 2.0.0 |
| MCP `serverInfo.version` | 2.0.0 | 2.0.0 |
| SARIF `tool.driver.version` | **1.4.3** | **2.0.0** |

`src/version.ts` is now the only module that reads its own package.json. Two
tests walk `src/` and fail if a fifth copy appears, or if any module resolves its
own path via `URL.pathname`.

### Remaining version constants — all correctly static

| Location | Value | Verdict |
|---|---|---|
| `src/analyzer/sarif.ts:43,270` | `'2.1.0'` | SARIF **spec** version |
| `src/parser/parse-project.ts` | `'1.2.0'` | model schema version |
| `src/workspace/metadata.ts` | `'1.1.0'` | report schema version |
| `src/artifacts/emit.ts` | `1` | artifact schema version |
| `src/ci/index.ts` | `'guardlink.ci/v1'` | CI schema |
| `src/parser/annotation-hash.ts` | `2`, `1` | hash format prefixes |
| `src/review/entitlements.ts` | `'1'` | ledger version |
| `src/analyze/llm.ts` | `'2025-04-14'` | pinned Anthropic API version |
| `src/init/templates.ts` | `'1.1.0'` | `.guardlink/config.json` version — **dead**: only `project` and `annotation_mode` are ever read back |

## 6. Agent instruction files

`CLAUDE.md`, `AGENTS.md`, `.gemini/GEMINI.md` and `.github/copilot-instructions.md`
are read by coding agents at runtime. All four carried a `guardlink entitle
--propose` example missing the required `--file` and `--line`:

```
before:  ✗ --propose needs --file, --line                            exit 1
after:   ✓ Filed proposal ent-ns_admin.archival_fs.path_traversal    exit 0
```

Verified by running the regenerated example verbatim: exit 0, `inert: false`,
`warnings: []`, citation parsed to `common/api/metadata.go:189`. The template
lives in `src/init/templates.ts`; the four files were regenerated with
`guardlink sync`, and that sync changed nothing else.

## 7. Fixtures

- `tests/fixtures/expense-api/.guardlink/` regenerated to model 1.2.0 —
  `{"annotation_count": 105, "coverage_percent": 100}`.
- `tests/fixtures/legacy-coverage-1.1.0/` added and **deliberately frozen** at
  the 1.1.0 shape. It is the genuine artifact recovered from
  `git show 55d8111:…/model.json`, not a hand-written imitation. Both its README
  and a `_comment` key in the JSON say it must not be regenerated.

## 8. Not changed, and deliberately

- **No deprecated aliases** for the removed coverage fields. The removal stands.
- **`DashboardStats.coverageAnnotated` retained** even though nothing renders it
  today — it reads `annotation_count`, which is real.
- **`DashboardStats.coverageTotal` stays removed** — its source was the hardcoded
  `total_symbols`, so restoring the field would mean restoring the constant.
- **`docs/SPEC.md` §coverage example still documents the old block.** Out of
  scope for this branch; it needs a follow-up.
- **`README.md` and `CHANGELOG.md` untouched.** A later instance owns them; the
  draft entries are in `changelog-draft-2.0.0.md` beside this file.

## 9. Green

| Check | Result |
|---|---|
| `npm run build` | exit 0 |
| `npx vitest run` | **980 passed**, 56 files, 11.4s — 0 failures |
| `npm run lint` | exit 0, no output |
| `guardlink validate . --artifacts` | `✓ Artifacts are current.` |
