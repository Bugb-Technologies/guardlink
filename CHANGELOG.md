# Changelog
All notable changes to GuardLink CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## \[Unreleased\]

## \[2.0.0\] — 2026-08-12

**The major version is scoped to two things: the TypeScript type surface and the threat-model JSON schema.** No command was removed, no flag was removed, and no output format changed except the threat model's own `coverage` block. **If you use the `guardlink` CLI or the MCP server, upgrading from 1.4.5 needs no migration** — for you this release is additive.

Programmatic consumers are the reason for the major. Eight exported shapes changed, and the breakage reaches code that never imports any of their names — see BREAKING below. Most of it is narrow: four of the eight break only code that *constructs* our types, such as a test fixture or an adapter. Two reach ordinary reading code — the `coverage` reshape, and the widened `AnnotationVerb` union under an exhaustive `switch`.

Two things a CLI user will nonetheless notice, both described in full further down: merging reports produced by different GuardLink versions now prints a schema-mismatch warning, and externally-anchored projects may see exposures in `unmitigated` that were previously being hidden by a mitigation on a different symbol.

### BREAKING

- **The `coverage` block lost two fields and renamed a third.**

  ```jsonc
  // before
  "coverage": { "total_symbols": 0, "annotated_symbols": 105,
                "coverage_percent": 100, "unannotated_critical": [] }
  // after
  "coverage": { "annotation_count": 105, "coverage_percent": 100 }
  ```

  **What you observe.** Reading `coverage.total_symbols` or `coverage.unannotated_critical` from `guardlink parse`, `guardlink report --format json`, `.guardlink/model.json`, the `guardlink://model` resource, or the `guardlink_parse` / `guardlink_status` MCP tools now yields `undefined`. Reading `coverage.annotated_symbols` yields `undefined`; the number moved to `coverage.annotation_count`. In TypeScript you get `TS2339: Property 'total_symbols' does not exist on type 'CoverageStats'` — and you do **not** have to import `CoverageStats` to hit it: reading the field off a `parseProject` result fails through every one of the seven published subpaths, and hand-constructing a `ThreatModel` fails with `TS2352`.

  A consumer that only calls functions — `parseProject`, `generateReport`, `diffModels`, `generateSarif` — and never touches `.coverage` compiles and runs unchanged.

  **Why they are gone rather than deprecated.** `total_symbols` was always `0` and `unannotated_critical` was always `[]`. They were constants in a schema presented as public, so nothing downstream could tell *not computed* from *computed, and the answer is zero*. Absent says the first; `0` and `[]` said the second, and three separate consumers believed them — one dashboard rendered "0% coverage" on a fully annotated project, and a merged workspace reported 0% when both its repos reported 89%. GuardLink does no per-symbol parsing, so these fields were never going to be filled in. `annotated_symbols` is now `annotation_count` because the old name is what invited the division in the first place.

  **Migration.** Use `annotation_count` for the annotation total, and `coverage_percent` for coverage — noting that it counts *files*, not symbols and not annotations. The model version moves `1.1.0` → `1.2.0` to mark the change.

- **`UnannotatedSymbol` is deleted.** It existed only to type `coverage.unannotated_critical`. **What you observe:** `TS2305: Module '"guardlink"' has no exported member 'UnannotatedSymbol'`.

- **`AnnotationVerb` gained `'actor'` and `'entitles'`.** The union behind `Annotation['verb']` widened from 20 members to 22, because `@actor` and `@entitles` are new verbs — see *Added*.

  **What you observe:** nothing, if you read `verb` or compare it against a literal. If you `switch` over it exhaustively with an `assertNever`-style `never` default, that default no longer compiles:

  ```
  error TS2322: Type '"actor" | "entitles"' is not assignable to type 'never'.
  ```

  Add a default branch, or handle the two new verbs. This is the one breaking change that reaches ordinary reading code rather than only code that constructs our types: `Annotation` has been exported since 1.x, and an exhaustive switch over a verb union is the natural way to write a renderer or a linter over it.

- **Three returned interfaces gained required fields.** `InitResult` gained `preserved: string[]`; `DiffSummary` gained `staleEntitlements: number`; `ThreatModelDiff` gained `actors: Change<ThreatModelActor>[]`, `entitlements: Change<ThreatModelEntitlement>[]` and `staleEntitlements: StaleEntitlement[]` — note that the last is the list, while `DiffSummary.staleEntitlements` is its count.

  **What you observe:** nothing, if you call `initProject` or `diffModels` and read the result — that is what these types are for, and reading is unaffected. If you *construct* one of them — a test fixture, a mock, an adapter that adapts some other tool's output into our shape — the object literal is now incomplete:

  ```
  error TS2741: Property 'preserved' is missing in type '{ … }' but required in type 'InitResult'.
  error TS2739: Type '{ … }' is missing the following properties from type 'ThreatModelDiff': actors, entitlements
  ```

  Add the fields — `[]` for every list and `0` for the count are the correct empty values. They are required rather than optional because they are always populated on a real result, and an optional field would push a `?? []` into every consumer that reads them.

- **`REPORT_SCHEMA_VERSION` moved `1.0.0` → `1.1.0`, and mixed-version merges now warn.**

  **What you observe, as a CLI user:** merging reports written by different GuardLink versions prints a line that never appeared before.

  ```
  ⚠ Reports use different schema versions: 1.0.0, 1.1.0. Results may be inconsistent.
  ```

  It is advisory. The merge still succeeds and still exits 0. Regenerate the older reports with `guardlink report` to clear it.

  **What you observe, in TypeScript:** the constant's type is the string literal, so `const v: '1.0.0' = REPORT_SCHEMA_VERSION` stops compiling.

  The bump is not cosmetic. The mismatch check compares this value across the reports being merged; leaving it at `1.0.0` would have made the `coverage` reshape invisible to the one mechanism built to notice exactly that.

- **`guardlink_graph` replaced `traversal.truncated` with `traversal.completeness`.**

  **What you observe:** the boolean `traversal.truncated` is absent from the MCP response. In its place, `traversal.completeness` is one of `complete` (nothing more to find at any depth), `depth_limited` (correct for the depth you asked for — raise `depth` for more) or `truncated` (the depth-10 ceiling cut it short; **the result is incomplete** and raising `depth` will not help). When it is not `complete`, a new `frontier_unexplored: { count, nodes }` names what lies one hop past the boundary.

  The boolean conflated "I stopped because a limit was hit" with "I stopped because there was nothing left to reach": one asset reported `truncated: true` at depth 1 and `false` at depth 2 on an identical 4 nodes and 6 edges. It was removed rather than aliased, because a faithful alias would have to keep reproducing the wrong answer, and a familiar name with changed meaning is worse than a missing one.

### Added

- **`guardlink ci` — advisory CI checks in one command.** Runs the two checks GuardLink already performs, against one parse of the model, and reports both: unmitigated exposures, and `@source` anchors that have drifted off the symbol they name.

  ```
  guardlink ci [dir] [-p <project>] [-f text|json] [--strict]
  ```

  **Advisory by default: exit 0 even with findings.** A repo that has just adopted GuardLink has unmitigated exposures by construction, and a gate that fails the build the day the annotations land is a gate that gets deleted the week after. `--strict` is the single opt-in and exits 1 if either check found anything.

  `--format json` emits a stable document under the schema id `guardlink.ci/v1`:

  ```jsonc
  { "schema": "guardlink.ci/v1",
    "exposures": [ /* the parser's own exposure records, unrenamed */ ],
    "drift":     [ /* anchor drift records */ ],
    "summary": { "exposures": 15, "drift": 0, "anchors": 0,
                 "by_severity": { "critical": 0, "high": 3, "medium": 6, "low": 6, "unset": 0 },
                 "by_kind":     { "moved": 0, "symbol_gone": 0, "file_gone": 0, "line_gone": 0 },
                 "strict": false, "exit_code": 0 } }
  ```

  The exit code is a pure function of (`strict`, exposures, drift) and is carried in the summary, so a JSON consumer sees the same verdict the shell got. No new detection logic was written: both checks call the same predicates `validate` and `reanchor` use, so `ci` cannot disagree with them about the same model. It reports and never repairs — applying a re-anchor is deliberately not reachable from here.

- **`@actor` and `@entitles` — the principal, and the capability held by design.** Two verbs answer the question the model had no field for: *is the caller already entitled to this effect?* `@actor Namespace_Admin (#ns-admin)` declares a principal in the authorization model — a role, not a person, and distinct from `@owns`, which names a responsible team. `@entitles #ns-admin to configure-archival-destination on #archival-fs -- "… Authz: common/api/metadata.go:189"` records that the privilege required to trigger an effect is a privilege that already grants it.

  An entitlement is the only annotation whose failure mode is a silent false negative, so three constraints are enforced rather than documented:

  - **It never gates testing, only reporting.** Unlike `@mitigates` and `@accepts`, `@entitles` has no export semantics: the exposure stays unmitigated, stays in the SARIF, stays testable. A regression test asserts that SARIF for a model with entitlements is byte-identical to the same model without them.
  - **No citation, no effect.** An entitlement whose description carries no `file:line` pointer to the authorization code is **inert** — parsed and carried so a reviewer can see the claim, flagged by `guardlink validate`, and ignored by consumers. `guardlink diff` reports an entitlement whose cited file changed as **stale** rather than removed.
  - **It cannot answer an ownership question.** For IDOR and tenant-isolation classes both peers hold the capability, so an entitlement cannot say *whose object it was*. Ownership stays measured and is deliberately absent from the grammar.

  `<capability>` must be a single normalised identifier — prose there is a parse error, because it is the join key consumers match on. Surfaced through `guardlink status`, `report`, the dashboard, `guardlink diff`, `guardlink sync`, and MCP. Purely additive: a model with neither verb parses and exports exactly as before.

- **`guardlink entitle` and a proposal ledger.** An agent proposes; a human accepts. `guardlink entitle --propose --actor … --capability … --file … --line … --rationale …` writes only to `.guardlink/entitlement-proposals.json` and never to source. Acceptance is what writes the annotation, under the name of the person who accepted. An `@entitles` in source with no accepted proposal behind it is a validation error. Also available to agents as `guardlink_entitlement_propose` / `guardlink_entitlement_list`; accepting is not.

- **`guardlink migrate --to external|inline`.** Moves a project's annotations between source comments and `.guardlink/annotations/*.gal` sidecars. Annotation text is moved verbatim rather than re-serialised from parsed objects, and only annotation lines leave the source file, so the round trip reproduces the original file rather than an equivalent one. Every run re-parses and compares the model's content hash before and after and **exits non-zero if it moved** — the hash excludes exactly the fields a migration may legitimately change, so a moved hash means the threat model itself changed. `--dry-run` reports without writing. Nothing but this command ever moves an annotation; existing repos are never migrated implicitly.

- **`guardlink reanchor`, and MCP `guardlink_reanchor`.** Finds `@source` blocks whose recorded `file:line` no longer holds the symbol they name — the drift external annotations accumulate after a refactor. Reports four distinct kinds (`moved`, `symbol_gone`, `file_gone`, `line_gone`) and proposes a corrected line only where the symbol was found elsewhere. `--apply` moves those; a renamed or deleted symbol is always left to a human, because there is no correct line to move it to.

- **MCP `guardlink_annotate_apply`.** Writes a validated `@source` block into a file's sidecar — into `.guardlink/`, never into source — after re-parsing every line with the real parser. Idempotent, returns a diff, invalidates the parse cache, and **refuses `@accepts` and `@entitles`**: both are human governance decisions, and a tool that can write one lets an agent close a finding by declaring it acceptable.

- **A freshness envelope on every MCP tool result.** Each response now carries a second content block naming the model it was computed from, so an agent can tell a cached answer from a current one without asking:

  ```json
  { "guardlink": { "annotation_hash": "sha256-v2:69d3fe…", "git_sha": "95dab747…",
                   "generated_at": "2026-08-12T16:10:33.393Z", "mode": "inline",
                   "root": "/path/to/repo", "guardlink_version": "2.0.0" } }
  ```

  The same hash appears in the auto-synced block of every agent instruction file, so a block that disagrees with a live tool result is provably out of date. The envelope is applied at tool registration rather than at each return statement, so it covers error branches too.

- **A codified path convention for `.gal` sidecars.** A sidecar belongs at `.guardlink/annotations/<source path>.gal` — the source path mirrored, with `.gal` appended. `guardlink validate` warns about a sidecar that sits somewhere else, and about an on-convention sidecar carrying `@source` blocks for files other than the one it is named for, which parses fine and is a maintenance trap. Both are warnings, never refusals: an off-convention file still contributes every annotation it carries, because silently dropping a developer's work over a directory choice would be worse than the inconsistency.

- **A warning for an unknown `@verb` that is close to a real one.** `@flow` and `@migitates` previously produced neither an annotation nor a diagnostic — the line simply vanished from the model, and the README itself shipped `@flow` twice. Near misses now warn and name the suggestion:

  ```
  ⚠ app/a.ts:2: Unknown annotation verb @flow — did you mean @flows? …
  ```

  **It cannot fail a build.** `parse`, `validate`, `validate --strict`, `ci` and `ci --strict` all exit 0 on a file whose only problem is one `@flow`. Only error-level diagnostics reach SARIF, so it cannot surface in GitHub Advanced Security either.

  Three rules keep it quiet in codebases that use `@`-tags for something else. A token carrying a namespace separator before the verb (`@g.comment`, `@gl:exposes`) is treated as a deliberate dialect, not a typo. A 170-entry list of JSDoc, TSDoc, Doxygen, phpDoc and Epydoc tags is excluded by name, so silence on `@param` is a property of the design rather than an accident of spelling distance. Repeats collapse to one diagnostic per distinct token per file, carrying an occurrence count, so a file with forty of the same typo reports once and still tells you where to start. Measured across four unrelated codebases totalling 13,609 source files: **zero false positives**.

  Switch it off per project in `.guardlink/config.json` if it still does not suit you:

  ```json
  { "diagnostics": { "unknown-verb": false } }
  ```

  Only warnings can be switched off this way. Listing an error-level code is accepted and ignored — quieting noise is a preference, silencing a broken annotation is not.

- **`DiagnosticCode` is now an exported type, with twelve members.** A code was carried on two diagnostic kinds while roughly seven were emitted without one, and the type itself was never exported — so a consumer wanting to treat a dangling reference differently from risk-acceptance hygiene had nothing to match on but the message text, and no name to match it against. Now every kind carries a code: `unknown-verb`, `duplicate-id`, `dangling-ref`, `undeclared-actor`, `inert-entitlement`, `imprecise-entitlement`, `accepted-without-audit`, `off-convention-gal`, `stray-gal-source` and `entitlement-provenance` join `malformed-annotation` and `prose-like`. `ParseDiagnostic` gains `code?: DiagnosticCode`.

  **This is additive, not breaking.** Neither `DiagnosticCode` nor `ParseDiagnostic.code` appears in 1.4.5's published `.d.ts`, so no 1.4.5 consumer can have been switching over the type or reading the field. If you adopt the type now and `switch` over it exhaustively, give the switch a default branch — the set will grow again as new diagnostics are added, and a `never` assertion over it is a compile error waiting for the next release.

- **`guardlink parse --no-pretty`.** `--pretty` defaulted to true with no counterpart, so the compact branch was unreachable and `--no-pretty` was rejected as an unknown option. It now emits the model on one line.

- **`guardlink-mcp --help` and `--version`.** The binary previously ignored every argument and waited for JSON-RPC on stdin, so `guardlink-mcp --version` hung instead of answering. Both now print and exit without opening a transport; the no-flag invocation still starts the server exactly as before.

- **The published package now contains `src/`, and its source maps finally resolve.** 1.4.5 already shipped 112 source maps that pointed at nothing, because the `.ts` files they name were not published — every map in the tarball was dead weight. 2.0.0 publishes the 76 source files alongside the 152 maps, so a stack trace from inside `guardlink` resolves to the original TypeScript and go-to-definition lands on the source rather than the generated `.d.ts`.

  This is deliberate, and the reason is what the tool is. A security tool asks to be trusted with a threat model; shipping the source it was built from means a consumer can audit what they installed without cloning the repo or trusting a build they did not run. Provenance attestation says the tarball came from this commit — the source in it says what that commit does.

  Cost: 228 → 384 files, 405.8 kB → 962.5 kB packed (1.9 MB → 4.1 MB unpacked). Nothing about the runtime changes: `dist/` is what `main`, `exports` and both `bin` entries resolve to, exactly as before.

### Changed

- **BEHAVIOUR CHANGE — coverage is decided per site, not per (asset, threat) pair.** A `@mitigates` no longer clears an `@exposes` when the two are anchored to *different symbols in the same file*. Everything else is unchanged: a mitigation in a different file still covers the whole asset, an unanchored mitigation still covers the whole asset, and a same-symbol pair still covers.

  **Why.** A correct mitigation on one function was answering for a live vulnerability on another. Reproduced on a Python service with a `%`-formatted `SELECT` in one function and a correctly bound `INSERT` twelve lines below it: the critical injection was missing from `unmitigated`, `guardlink_context` reported no open exposures for the file, and the scanner-triage path answered `status: "mitigated"` for the vulnerable line. A deterministic scanner asking GuardLink about a true positive was told it was handled.

  **What you will see.** For **inline projects, nothing at all** — inline annotations carry no symbol anchor, so the rule cannot engage. Measured: 0 of 74 exposures change state on this repo, 0 of 61 on a second inline repo of 8,142 files, and 2 of 11 on the external repo where the defect was found. If you author externally with symbol anchors, and you have a mitigation and an exposure on the same asset and threat in one file at different symbols, that exposure will now appear in `unmitigated`. It was always there; it was not being reported.

  **How to say "this covers the whole asset".** Omit `symbol:` from the mitigation's `@source` header. An unanchored statement is an asset-level statement and is never narrowed. No new syntax was added, and none is needed.

  **What this does not fix.** A cross-file mitigation still blanket-covers its asset and threat. Knowing whether a control actually reaches a site needs a call graph, which GuardLink does not have. The rule closes the class where the model already holds the evidence — the author's own anchors — and no more.

- **`guardlink report` output is deterministic across processes.** The report and Mermaid generators canonicalise the model at the emission boundary. Before: three `report --diagram-only` runs in three processes produced two distinct hashes, differing by whole node blocks, because the file walk returns completion order under concurrency. After: byte-identical. **This changes `report --diagram-only` output** — nodes and edges come out in a deterministic order rather than glob order, so a diff against a previously captured diagram shows reordering once. Nothing is added or removed. The full markdown report is unchanged apart from its two `Generated:` lines.

- **`init --mode` and `init --no-root-files` are separate flags, and the default annotation mode is `external`.** `--mode external` previously meant two unrelated things at once — annotations live in sidecars, *and* init writes nothing outside `.guardlink/` — so asking for the first silently cost you the root `.mcp.json`, every agent instruction file, and `docs/`, which are the things that make an agent aware GuardLink exists. `--mode inline|external` now decides only where annotations live; `--no-root-files` decides only the footprint and reproduces the old external behaviour. **Existing projects keep their recorded mode** — `init` does not rewrite an existing `config.json` without `--force`.

- **`.guardlink/model.json` and `.guardlink/graph/` are tracked in git.** A fresh clone has the threat model without running anything, and model changes appear in review. `.gitattributes` marks them as generated. Exports that are rebuilt on demand — `threat-model.json`, `guardlink.sarif.json`, `threat-dashboard.html` — remain ignored.

- **The dashboard lost two sections.** The force-directed *Risk Topology* graph grew unreadably dense on large codebases; the three Mermaid views (Threat Graph, Data Flow, Attack Surface) remain, and the Threat Graph still auto-filters to high/critical with an *All severities* toggle. The *Pentest Findings* page and its detail drawers are also gone, and the dashboard no longer embeds raw scan JSON. Pentest ingestion itself is unchanged — scan results still flow into `guardlink threat-report` as context, and evidence redaction still applies at load time.

- **The package version is resolved in one place.** Four separate implementations of "read `package.json` at runtime" had accumulated, with two different failure fallbacks. All version-reporting surfaces now agree by construction: `guardlink --version`, `guardlink-mcp --version`, the TUI header, the MCP `serverInfo`, the artifact manifest, SARIF `tool.driver.version`, and the report's metadata.

### Fixed

- **`guardlink merge` reported `"annotation_count": null` for any report written by an older GuardLink.** Merge reads report JSON from disk, so a 2.x binary meets a 1.4.5 repo's output there; the older field name read as `undefined`, arithmetic on it produced `NaN`, and `NaN` serialises to `null`. A workspace dashboard reported a null annotation count silently, exit 0, no warning. Reports are now normalised as they are read, and the older field name is carried across rather than replaced with a zero — an old repo keeps its real count.

- **The TUI reported `v0.0.0` on any install path containing a space.** One of the four version lookups resolved its own location through a URL, which percent-encodes, so the probe missed `package.json` and the fallback chain bottomed out. `guardlink --version` beside it reported the truth, which is why it went unnoticed.

- **SARIF reported `1.4.3` as the tool version**, regardless of the installed version.

- **`guardlink report --format <unrecognised>` wrote nothing and exited 0**, which is indistinguishable from success. It now names the valid values and exits 1.

- **`guardlink tui --model` was parsed and never read.** It now applies for the session, as `--provider` and `--api-key` already did.

- **`guardlink status` printed `unknown` as the project name in every repo**, including ones whose `.guardlink/config.json` held the name three lines away. Nothing read it, and it is the first command anyone runs after `init`. `guardlink sync` and `guardlink entitle` were the last two commands still not consulting it and now do.

- **`guardlink-mcp` did not run.** The binary was declared but the module only exported its starter — no shebang, no entry guard — so piping an `initialize` request at it produced no response at all. The build also now preserves the executable bit on both binaries, without which a fresh install produced a `guardlink-mcp` that could not be executed.

- **The `guardlink entitle --propose` example in the generated agent files did not run.** `CLAUDE.md`, `AGENTS.md`, `.gemini/GEMINI.md` and `.github/copilot-instructions.md` are read by coding agents at runtime, and all four carried a worked example missing two required flags, so an agent following it verbatim got an error instead of a proposal.

- **`init` wrote a `.guardlink/README.md` whose reference pointer did not exist.** The README chose the path by annotation mode while `init` wrote it by footprint, and under the default those two disagree — which is every fresh repo. The sentence after the broken link is "Read it before inventing syntax", so the one dead pointer in the document was the one aimed at a reader about to guess.

- **`init` did not create `.gitignore` when a project had none**, only appended to an existing one — so a fresh repo got no entry at all, and `guardlink dashboard` left `threat-dashboard.html` both untracked and unignored in exactly the repos least likely to notice.

- **`init`'s "Next steps" contradicted the README it wrote in the same run.** Step 2 said "add annotations to your source files" regardless of mode, while the README written beside it says, under the default, that annotations do not go in source files. Step 2 now follows the resolved mode.

- **The MCP write path accepted what it promised to reject.** `guardlink_annotate_apply` documented that malformed input is rejected with a reason, then accepted an undeclared `#reference` and a source file that does not exist, each with `ok: true` and no errors — so an invented reference survived the write, the validation and CI. References are now checked against the model's declared ids, using the same rule the dangling-reference check uses.

- **The MCP envelope reported every external project as `mixed`.** Asset, threat and control declarations are structurally inline-only, and counting them as inline evidence meant a correctly configured pure-external repo reported the alarm state. Detection now asks only the relationship verbs, which are the only ones with a genuine choice of home. `mixed` still fires on a genuinely mixed repo.

- **`@shield` regions survive migration.** The markers delimit a region of source text and mean nothing outside the file whose lines they bracket, so they no longer migrate, and annotations inside a shielded region are no longer extracted. Both were caught by the hash gate: externalising the markers unshielded this repo's own documentation examples, and extracting from inside the region turned 38 examples into real records.

- **`guardlink_context` told agents the `.gal` path convention was not codified.** It is. The tool now states the convention an agent can act on.

## \[1.4.5\] — 2026-07-21

### Fixed

- **`guardlink --version` now reports the correct version.** The CLI hardcoded its version string (`.version('1.4.3')`) independently of `package.json`, so bumping and publishing did not update what `--version` printed — the published 1.4.4 still reported 1.4.3. The version is now read from `package.json` at runtime, so it can never drift again. Added a regression test that fails if a hardcoded version literal is reintroduced. (The 1.4.4 crash fix itself was unaffected — only the reported version string was wrong.)

## \[1.4.4\] — 2026-07-21

### Fixed

- **`init` / `sync` no longer crash on agent-file path-type conflicts.** When a project already contained an agent-tool config whose type differed from what GuardLink expected — most commonly an older single-file `.cursor/rules` (a file) where GuardLink writes the newer `.cursor/rules/` directory layout — `guardlink init` threw a raw `ENOTDIR` and aborted before creating anything. The mirror case (an agent path such as `CLAUDE.md` existing as a directory) threw `EISDIR`. Both are now detected: initialization completes normally — `.guardlink/` and all non-conflicting agent files are created, and the conflicting path is left untouched rather than clobbered. Applies to both `init` and `sync`. Added regression tests covering both conflict directions, idempotency, and the clean-repo path.

### Internal

- Groundwork for merging GuardLink into a legacy single-file `.cursor/rules` (rather than skipping it) is present but not yet wired into agent detection/selection; it will be enabled in a follow-up once the picker recognizes the legacy layout.

## \[1.4.3\] — 2026-05-13

### Added

- **Multi-hop** `@flows` **chains** — `@flows A -> B -> C -> D` is now valid syntax for chains of any length, expanding into N-1 pairwise flows that share the same mechanism, description, and source location. Single-hop syntax (`A -> B`) unchanged. Downstream consumers (DFD, sequence diagram, MCP queries, SARIF) still see the pairwise shape — multi-hop is purely a parser-side expansion.

- **Quoted asset and threat refs in relationships** — `ASSET_REF` and `THREAT_REF` now accept double-quoted strings as a third alternative alongside `#id` and `Dotted.Path`. Example: `@flows User -> "/rest/user/login" -> "SQLite db"` parses cleanly. Same syntax works in `@exposes`, `@confirmed`, `@boundary`, `@audit`, and other relationship verbs. Definition annotations (`@asset`, `@threat`, `@control`) remain strict — declarations stay on `#id` and dotted paths.

- **Opt-in pentest evidence redaction** (`guardlink config set redact-evidence true`) — surgical redaction for teams whose compliance posture requires no cleartext credentials at rest. When enabled, JWT signatures are stripped (header + payload preserved as proof of exploit), `Authorization: Basic`/`Digest`/`NTLM` values are fully redacted, credential field values in JSON / query-strings / cookies are masked (field names preserved). Default OFF; OSS users running against test targets see full evidence. Dashboard shows a banner when redaction is active. Full operational guide: [`docs/handling-evidence.md`](docs/handling-evidence.md).

- `@confirmed` **annotation** — New verb for verified exploitable findings. Distinct from `@exposes` (theoretical) and `@accepts` (governance). Syntax: `@confirmed #threat on Asset [severity] cwe:CWE-NNN -- "evidence"`. A `@confirmed` annotation means the threat has been proven exploitable through pentest, automated CXG scan with reproducible evidence, or manual reproduction — not a false positive. Full pipeline: parser, model assembly, dangling-ref validation, SARIF `error`-level export, CLI `status` output, dashboard emphasis, LLM report inclusion, MCP `guardlink_lookup "confirmed"`.

- `@feature` **annotation** — New metadata verb to tag files/code with a named product feature. Syntax: `@feature "Feature Name" -- "description"`. Association is file-level: all annotations in a file with `@feature "X"` are considered part of that feature. Enables feature-scoped filtering across all output modes.

- **Feature filtering (**`--feature` **flag)** — `guardlink status`, `guardlink report`, and `guardlink dashboard` all gain `--feature <names>` (comma-separated). Filters all output — assets, threats, exposures, flows — to files tagged with the named feature(s). Dashboard gets a live feature filter dropdown in the header with a dismissible banner. TUI gains `/feature [name]` command to list features or drill into one.

- `guardlink translate [prompt]` — New command that translates GuardLink threat model findings into CERT-X-GEN (CXG) pentest templates (generation only, no execution). Supports all agent backends: `--claude-code`, `--codex`, `--gemini`, `--cursor`, `--windsurf`, `--clipboard`. Reads CXG reference docs and skeleton templates from `GUARDLINK_CXG_ROOT` env or configured default path.

- `guardlink ask <query>` — New command that answers natural-language questions about the threat model and codebase context, launching an AI agent with full model serialization as context.

- **Pentest integration** — GuardLink now loads CXG scan results from `.guardlink/pentest-findings/` (JSON) and template metadata from `.guardlink/cxg-templates/`. New interfaces: `PentestFinding`, `PentestScanResult`, `PentestTemplate`, `PentestData`. Findings are injected as a `<pentest_findings>` block into AI threat reports, `guardlink threat-report`, and the dashboard. Dashboard gains a dedicated **Pentest Findings** sidebar section with scan summary tables and per-finding detail drawers.

- **Expanded threat model report** (`guardlink report`) — `generateReport()` now produces 10 structured sections (was: Executive Summary + tables):

   1. Application Overview (auto-populated from `.guardlink/prompt.md` if present)
   2. Scope of This Threat Model
   3. Architecture (Mermaid DFD)
   4. Key Flows & Sequence (new Mermaid sequence diagram from `@flows`)
   5. Data Inventory
   6. Roles & Access
   7. Dependencies
   8. Secrets, Keys & Credential Management
   9. Logging, Monitoring & Audit
  10. AI/ML System Details (conditional — emitted only when AI-related threats are detected)

  Report header now includes GuardLink version and git commit/branch from metadata. Confirmed exploitable findings appear as a row in the Executive Summary table.

- **Sequence diagram** (`src/report/sequence.ts`) — New Mermaid `sequenceDiagram` generator built from `@flows` annotations, showing step-by-step participant interactions. Used in the Key Flows & Sequence report section.

- `.guardlink/prompt.md` — `guardlink init` and `guardlink sync` now create this skeleton file. AI annotation agents fill it in with a security-focused project overview (what the app does, components, trust boundaries, data sensitivity, deployment). `guardlink report` reads it and injects the content as the Application Overview section.

- **SARIF: confirmed exploitable rule** — New `guardlink/confirmed-exploitable` SARIF rule emitting `error`-level results for `@confirmed` annotations. These appear alongside unmitigated exposures in GitHub Advanced Security.

- **MCP** `guardlink_lookup` **queries** — Two new query types: `"confirmed"` returns all `@confirmed` verified findings; `"features"` returns all `@feature`-tagged feature names with their associated files.

- **LLM prompt improvements** — `buildUserMessage()` accepts pentest findings context. AI prompts now distinguish pentest-confirmable threats from governance/design gaps, and teach agents when to use `@confirmed` vs `@exposes` vs `@audit`.

### Changed

- `guardlink status` — Now prints `@confirmed` findings with a red badge below the exposure list. Accepts `--feature` for filtered output.
- `guardlink report` — Accepts `--feature` for scoped reports. Reads `.guardlink/prompt.md` for Application Overview.
- `guardlink dashboard` — Accepts `--feature`. Risk score formula now accounts for confirmed finding count. Feature filter dropdown in header.
- `guardlink threat-report` — Pentest findings from `.guardlink/pentest-findings/` are automatically included in AI analysis context. AI prompted to emit a dedicated "Pentest Results" section when findings are present.
- `/gal` **TUI command** — Documents `@feature` tagging with examples.
- **SARIF export** — `@confirmed` findings now appear as `error`-level entries under the new rule; `@exposes` severity mapping unchanged.
- **MCP server** — Status tool description updated to reflect confirmed count. `guardlink_lookup` extended with `confirmed` and `features` queries.

### Fixed

- **`guardlink report` no longer prints "Fix errors above before generating report"** when diagnostics contain errors — the message was misleading because the report generated anyway. Per-annotation parse errors don't block report generation; affected annotations are skipped while the rest of the model still renders. Behavior now matches `dashboard`, `sarif`, and `threat-report`.
- **MCP `guardlink_lookup` resolver agrees with itself across query types** — `asset #login` previously returned `count: 0` when an identifier was referenced (e.g. via `@confirmed`) but never declared in `definitions.ts`, even though `threats for #login`, `unmitigated`, and `confirmed` all returned the joined record. Bare `#id` queries had the same problem — they returned `no_match` for identifiers other queries happily resolved. Both `lookupAsset()` and `lookupFuzzy()` now fall back to the annotation graph (exposures, confirmed, mitigations, acceptances, audits, flows, boundaries) and synthesize stub records marked `declared: false` with a `referenced_in: [...]` audit trail. Consumers can distinguish synthesized stubs from real declarations.
- **MCP `guardlink_lookup` no_match hint no longer mangles its quotes** — the hint contained literal double-quote characters that got escaped twice through the MCP transport (content wrap + JSON-RPC envelope), rendering as `\\\"asset <n>\\\"` in clients that print the raw response. Hint now uses backticks around examples so it survives both `JSON.stringify` passes intact.
- **Pentest template card titles in the dashboard now show the actual template id** (e.g. `login-sqli-network`) instead of fragments like `ge` or `e`. The previous loader regex `/id[:\s]*["']?([a-z0-9_-]+)["']?/i` matched the substring "id" inside words like `bridge` and `guide`.
- **Pentest template card severity is no longer hardcoded to `medium`** — the loader's severity regex required a colon between the field name and the value, missing Python templates that use `severity = "critical"` (equals separator). Both regexes now anchor on a complete field name with optional surrounding quotes (for JSON `"id": "x"` form) and accept `:` or `=` as the separator before a quoted value.
- **`guardlink status` row labels** — renamed the file-counting rows from `Annotated`/`Not annotated` to `Files annotated`/`Files unannotated`, removing the visual collision with the `Annotations` row directly below. The count of files-with-annotations is no longer easily misread as the total annotation count.
- **Pentest finding confidence renders defensively across CXG output shapes** — the dashboard previously hardcoded `${f.confidence}%`, assuming integer percentage. CXG has emitted confidence as integers, severity-style strings (`"high"`), and missing values across versions; the inline rendering produced `high%`, `undefined%`, and even `[object Object]%`. New `formatConfidence()` helper handles every case, clamps integers to `[0, 100]`, and never throws. The dashboard still shows `50%` for every finding today because CXG itself hardcodes that — a CXG-side fix lands separately; GuardLink will display the correct value when it does.
- **Topology dedupes undeclared refs across kinds** — an undeclared identifier like `#login-sqli` referenced as both an asset (by `@exposes`) and a threat (by `@confirmed`) previously synthesized two separate nodes in different clusters of the force-directed dashboard graph. The alias resolver now does cross-kind dedup before synthesizing; declared assets/threats/controls always take priority. New `declared: boolean` field on topology nodes lets downstream consumers distinguish synthesized stubs from real declarations.
- **Multi-hop** `@flows` **annotations are no longer rejected** — `@flows User -> /api -> DB` previously failed with `Malformed @flows annotation: could not parse arguments` because the regex required exactly two `ASSET_REF` captures separated by a single arrow. See Added section for the new multi-hop syntax.
- **URL-style and whitespace-containing refs work in** `@flows` **and other relationships** — `/rest/user/login`, `"SQLite db"`, `"Auth Service"` now parse where they didn't before. The `ASSET_REF` regex previously accepted only `#id` and `Dotted.Path` forms. See Added section for quoted-ref syntax.
- **`.guardlink/prompt.md` auto-migrates for v1.4.x projects on first** `guardlink report` — projects upgraded from earlier versions didn't have the new file (since `guardlink init` short-circuits when `.guardlink/` exists), causing reports to silently fall back to a boilerplate Application Overview. Now created automatically on first report with a one-line stderr nudge so the user discovers the feature. Existing user content is never overwritten; the operation is idempotent. New `ensurePromptMd()` helper in `src/init/migrate.ts`.

### Internal

- **Generated samples moved to `docs/examples/`** — `threat-dashboard.html`, `threat-model.md`, and `guardlink-pentest.{html,json,sarif}` were previously committed at the repo root, where every `guardlink dashboard .` run from the project root rewrote them and produced churn in unrelated PRs. They now live under `docs/examples/` (with a `README.md` documenting how to regenerate them deliberately) and the root paths are git-ignored.
- **`fatal` diagnostic tier reserved** — `ParseDiagnostic.level` extended from `'error' | 'warning'` to `'error' | 'warning' | 'fatal'` with detailed JSDoc explaining tier semantics. No code path currently emits a fatal; this is a non-breaking type widening so v1.6 can introduce the first emission site (for unrecoverable conditions like schema version mismatch or unparseable definitions) without a coordinated cross-file change. New `diagnosticIcon()` helper in `src/parser/format.ts` centralizes the level → icon mapping (`✗✗` / `✗` / `⚠`); CLI and TUI printers use it consistently. A `TODO(fatal-tier)` note in `src/types/index.ts` enumerates the 11 audit sites that need updating before the first emission lands.
- **Test coverage** — new test files: `tests/lookup.test.ts` (14 tests across the MCP query DSL with regression guards for the resolver bugs), `tests/pentest-loader.test.ts` (10 tests covering JSON/Python/YAML conventions for template metadata extraction), `tests/format.test.ts` (9 tests for confidence rendering across number/string/missing inputs), `tests/migrate.test.ts` (5 tests for prompt.md migration outcomes including idempotence), `tests/diagnostics.test.ts` (7 tests covering the fatal-tier vocabulary and icon mapping), `tests/redact.test.ts` (27 tests for surgical evidence redaction including JWT split-redact, Authorization header variants, JSON / query-string / cookie credential patterns, object-key inspection, and safety properties), plus extensions to `tests/parser.test.ts` (+19 tests for multi-hop chains and quoted refs) and `tests/dashboard.test.ts` (+4 tests for cross-kind topology dedup). Suite total: 72 → 167.

## \[1.4.2\] — 2026-04-24

### Added

- **CLI**: `guardlink annotate --mode external` — generate annotations as standalone `.gal` files under `.guardlink/annotations/` that mirror the source tree, instead of as inline comments in source files. Source files remain unchanged. Useful for vendored code, audit-controlled repositories, and projects where modifying source files is politically expensive. Contributed by [@jordi-murgo](https://github.com/jordi-murgo) in [#6](https://github.com/Bugb-Technologies/guardlink/pull/6).
- **CLI**: `guardlink annotate --stdout` — print the annotation prompt to stdout instead of launching an agent or copying to the clipboard. Useful for piping into custom harnesses and CI pipelines. Contributed by [@jordi-murgo](https://github.com/jordi-murgo) in [#6](https://github.com/Bugb-Technologies/guardlink/pull/6).
- **Parser**: `@source file:<path> line:<n> [symbol:<name>]` directive — anchors annotations in a `.gal` file to a logical source-code location. The directive produces no annotation itself; it sets the location for subsequent annotations until the next `@source` or end of file.
- **Types**: `SourceLocation.origin_file` and `SourceLocation.origin_line` — physical location of an annotation (the `.gal` file path), preserved alongside the logical location (`file` / `line`) for dashboards, reports, and SARIF to surface provenance where useful while defaulting to the logical source location for developer-facing output.

### Changed

- **`guardlink init --mode external`**: contains GuardLink's entire footprint inside `.guardlink/` — no `CLAUDE.md` / `AGENTS.md` / `.cursor/rules/` files at the project root, no `.mcp.json` at the root, no `docs/GUARDLINK_REFERENCE.md`. The reference doc and MCP config template are placed inside `.guardlink/` instead.
- **Review writeback**: `@accepts` and `@audit` annotations generated via `guardlink review` are written to the annotation's physical location (the `.gal` file in external mode) rather than the logical source location, preserving external mode's "source files untouched" property through governance workflows.
- **Review writeback**: comment-style detection now correctly handles HTML (`<!-- ... -->`) and CSS (`/* ... */`) files. Previously these fell back to JavaScript-style `//` comments, producing invalid markup. Contributed by [@jordi-murgo](https://github.com/jordi-murgo) in [#6](https://github.com/Bugb-Technologies/guardlink/pull/6).
- **Review exposure IDs**: composite `writeFile:writeLine:logicalFile:logicalLine:asset:threat` scheme replaces the previous `file:line` scheme. Prevents two `@exposes` annotations at the same source location from colliding on the MCP review identifier. Contributed by [@jordi-murgo](https://github.com/jordi-murgo) in [#6](https://github.com/Bugb-Technologies/guardlink/pull/6).
- **Review insertion**: TypeScript and Python decorators starting with `@` are no longer mistaken for GuardLink annotations when walking the "coupled block" during writeback. Contributed by [@jordi-murgo](https://github.com/jordi-murgo) in [#6](https://github.com/Bugb-Technologies/guardlink/pull/6).
- **Parser `**/*.gal`** discovery is now case-insensitive. Contributed by [@jordi-murgo](https://github.com/jordi-murgo) in [#6](https://github.com/Bugb-Technologies/guardlink/pull/6).

### Fixed

- **Agent prompts**: wrap the external-mode example annotation block in `@shield:begin` / `@shield:end` to prevent `guardlink validate` from parsing the JavaScript string literals inside `src/agents/prompts.ts` as real annotations (resolved four parse errors in the CI dogfood step after #6 merged).
- **Documentation**: correct `--mode inline|gal` references to `--mode inline|external` in `README.md` (two occurrences), `docs/GUARDLINK_REFERENCE.md` (three occurrences including the TUI `/annotate` slash-command help text). The flag value shipped as `external`; the docs referenced the prototype name `gal`.
- **Documentation**: document `--stdout` flag on the AI-agent flags cheat-sheet in `docs/GUARDLINK_REFERENCE.md`.
- **Documentation**: add `@source` convention note to the standalone `.gal` files section in `docs/GUARDLINK_REFERENCE.md` — annotations placed before the first `@source` directive fall back to the `.gal` file's own physical location, which is rarely what users want.

### Chore

- **Version**: bump from `1.4.1-gal` development tag (landed via #6) to `1.4.2` across `package.json`, `package-lock.json`, `src/cli/index.ts`, and `src/mcp/server.ts`.
- **Lockfiles**: remove committed `bun.lock` (landed via #6). This project standardizes on npm; `package-lock.json` is canonical. Added `bun.lock`, `yarn.lock`, and `pnpm-lock.yaml` to `.gitignore` so contributors using alternate package managers locally do not accidentally commit a second lockfile.

## \[1.4.1\] — 2026-03-12

### Fixed
- **GAL reference (**`/gal`**,** `guardlink gal`**)**: Fixed all syntax examples to match the actual parser — descriptions now correctly show `-- "quoted text"` format instead of the non-functional `: text` format; severity now shows bracket notation `[high]` / `[P0]` instead of `severity:high`; `@flows` now shows `->` arrow syntax instead of `to`; `@validates` now shows `for` preposition instead of `on`; `@owns` now includes the required `for` preposition; `@mitigates` now documents `using` as the primary keyword (with `with` as v1 compat)
- **GAL reference**: Added missing documentation for external references (`cwe:CWE-89`, `owasp:A03:2021`, `capec:CAPEC-66`, `attack:T1190`) on `@threat` and `@exposes` annotations
- **GAL reference**: Added missing `@boundary` alternate syntaxes (`@boundary between A and B`, `@boundary A | B`) and `(#id)` support
- **GAL reference**: Added missing standalone `@shield` single-line marker (was only documenting `@shield:begin/end` blocks)
- **TUI** `/help`: Added missing `/unannotated` command to the help output (was registered and functional but not listed)
- **CLI version**: Fixed `guardlink --version` reporting `1.1.0` instead of the actual package version

### Changed

- **GAL reference**: Added new "External References" section explaining `cwe:`, `owasp:`, `capec:`, `attack:` ref syntax
- **GAL reference**: Updated Tips section with description format, severity format, and `@flows ->` syntax reminders
- **Annotations**: Changed `@comment` to `@audit` on agent-launcher timeout note for better governance visibility
- **Annotations**: Added `@audit` to MCP suggest module, added workspace-related controls to definitions

## \[1.4.0\] — 2026-02-27

### Added

- **Workspace**: Multi-repo workspace support — link N service repos into a unified threat model with cross-repo tag resolution, weekly diff tracking, and merged dashboards
- **Workspace**: `guardlink link-project <repos...> --workspace <name> --registry <url>` — scaffold workspace.yaml in each repo, auto-detect repo names from git/package.json/Cargo.toml, inject cross-repo context into agent instruction files
- **Workspace**: `guardlink link-project --add <repo> --from <existing>` — add a repo to an existing workspace with sibling auto-discovery
- **Workspace**: `guardlink link-project --remove <name> --from <existing>` — remove a repo from workspace, update all siblings found on disk
- **Workspace**: `guardlink merge <files...>` — merge N per-repo report JSONs into a unified MergedReport with tag registry, cross-repo reference resolution, stale/schema warnings, and aggregated stats
- **Workspace**: `--diff-against <prev.json>` flag on merge for week-over-week risk tracking (assets/threats/mitigations/exposures added/removed, risk trend, unresolved ref changes)
- **Workspace**: `-o <file>` dashboard HTML output + `--json <file>` merged JSON output + `--summary-only` text mode
- **CLI**: `guardlink report --format json` — JSON report output with metadata (repo, workspace, commit SHA, schema version)
- **TUI**: `/workspace` — show workspace config, sibling repos, registries
- **TUI**: `/link` — link repos with `--add`/`--remove` support
- **TUI**: `/merge` — merge reports with `--json`, `--diff-against`, `-o` flags
- **MCP**: `guardlink_workspace_info` tool — returns workspace name, this_repo identity, sibling tag prefixes, and cross-repo annotation rules for agents
- **Parser**: External reference detection — scans relationship annotations for tags with dot-prefix matching sibling repo names from workspace.yaml, populates `ThreatModel.external_refs`
- **Types**: `ExternalRef` interface, `ThreatModel.external_refs` field, `ReportMetadata` with repo/workspace/commit_sha/schema_version
- **CI**: `examples/ci/per-repo-report.yml` — per-repo workflow: validate on PRs (diff + SARIF + PR comment), generate + upload report JSON on push to main
- **CI**: `examples/ci/workspace-merge.yml` — weekly workspace merge workflow: download all repo artifacts, merge, dashboard, weekly diff, optional GitHub Pages + Slack
- **Docs**: `docs/WORKSPACE.md` — multi-repo setup guide, workspace.yaml spec, cross-repo annotation rules, merge behavior, CI integration, weekly workflow

### Changed

- **MCP**: Server version bumped to 1.4.0

## [1.3.0] — 2026-02-27

### Added

- **Review**: `guardlink review` — interactive governance workflow for unmitigated exposures across CLI, TUI (`/review`), and MCP (`guardlink_review_list` + `guardlink_review_accept`). Users walk through exposures sorted by severity and choose: accept (writes `@accepts` + `@audit`), remediate (writes `@audit` with planned-fix note), or skip. Mandatory justification prevents rubber-stamping; timestamped audit trail for compliance.
- **CLI**: `guardlink clear` — remove all annotations from source files to start fresh, with `--dry-run` preview and `--include-definitions` option
- **CLI**: `guardlink unannotated` — list source files with no annotations, showing coverage ratio
- **CLI**: `guardlink sync` — standalone command to sync agent instruction files with current threat model (previously only available via MCP/TUI)
- **TUI**: `/review`, `/clear`, `/sync`, `/unannotated` commands
- **MCP**: `guardlink_review_list`, `guardlink_review_accept`, `guardlink_unannotated`, `guardlink_clear`, `guardlink_sync` tools
- **Dashboard**: File Coverage section on Code & Annotations page with progress bar and collapsible unannotated file list
- **Parser**: `annotated_files` and `unannotated_files` fields added to ThreatModel
- **Templates**: Sync guidance in workflow section for all 7 agent instruction formats
- **Templates**: Tightened negative guardrail — agents prohibited from writing `@accepts` (human-only via `guardlink review`)
- **Auto-sync**: `status` and `validate` commands now auto-sync agent instruction files after parsing

### Fixed

- **Parser**: `@shield:begin`/`@shield:end` blocks now properly exclude content from the threat model. Previously, example annotations inside shielded blocks were parsed as real annotations, causing duplicate ID errors and dangling reference warnings.
- **Init**: Picker "All of the above" now uses a numbered option instead of `a` shortcut for consistency

### Changed

- **MCP**: Server version bumped to 1.3.0

## [1.2.0] — 2026-02-22

### Added

- **LLM**: Multi-provider support — Anthropic, OpenAI (Responses API), Google Gemini, DeepSeek (reasoning), Ollama, and OpenRouter
- **LLM**: Tool-call system with CVE lookup (NVD), finding validation, and codebase search for grounded threat analysis
- **LLM**: Extended thinking / reasoning token support for DeepSeek and Anthropic models
- **Analyze**: Project context builder — automatically assembles architecture summary, data flows, and unmitigated exposures for LLM context
- **Analyze**: Code snippet extractor — injects relevant source around annotations into threat reports
- **CLI**: `threat-report` now accepts custom freeform prompts in addition to framework names
- **CLI**: `--provider`, `--model`, `--api-key`, `--web-search` flags for threat report generation
- **CLI**: Inline agent execution mode in launcher
- **TUI**: Model catalog with provider selection (Anthropic, OpenAI, Google, DeepSeek, Ollama, OpenRouter)
- **TUI**: Custom prompt input for threat reports alongside framework presets
- **TUI**: Inline agent execution from TUI sessions
- **TUI**: Restored `/exposures`, `/show`, `/scan` commands for exposure browsing and coverage scanning
- **Dashboard**: Collapsible sidebar with SVG navigation icons and localStorage state persistence
- **Dashboard**: Exposure computation helpers (`computeExposures`)
- **Docs**: Updated GUARDLINK_REFERENCE.md and SPEC.md with new capabilities
- **Validation**: Additional parser diagnostics

### Fixed

- **LLM**: Anthropic model IDs now use aliases (`claude-sonnet-4-6`, `claude-opus-4-6`) instead of invalid snapshot dates
- **Dashboard**: Mermaid diagram render trigger restored on first Diagrams tab visit
- **TUI**: CLI artifact cleaning (`cleanCliArtifacts`) for stripping agent-specific output formatting
- **CI**: OIDC trusted publishing preserved across merges (npm ≥11.5.1, no `registry-url` override)

### Changed

- **CLI**: `threat-report` signature changed from `[framework] [dir]` to `[prompt...] -d <dir>` — directory is now a flag, prompt accepts freeform text
- **Prompts**: Reframed annotations as developer hypotheses to validate rather than mandates, improving LLM annotation quality

### Removed

- **Util**: Removed empty `src/util/ansi.ts` placeholder (functionality already in `src/tui/format.ts`)

## [1.1.0] — 2026-02-21

### Added

- **Validation**: Shared `findDanglingRefs` and `findUnmitigatedExposures` with consistent `#id`/bare-name normalization across CLI, TUI, and MCP
- **Validation**: Expanded dangling ref checks to cover `@flows`, `@boundary`, `@audit`, `@owns`, `@handles`, `@assumes` annotations
- **Diagrams**: Threat graph now renders `@transfers`, `@validates`, trust boundaries, data classifications, ownership, and CWE references
- **Diagrams**: Heuristic icons for assets (👤 user, 🖥️ service, 🗄️ database) and flow mechanisms (🔐 TLS, 🌐 HTTP, 📨 queue)
- **Prompts**: Flow-first threat modeling methodology with architecture mapping, trust boundary identification, and coupled annotation style guide
- **Prompts**: Agent context now includes existing data flows and unmitigated exposures for smarter annotation
- **Model**: Two-step `/model` configuration — CLI Agents (Claude Code, Codex, Gemini) or API providers
- **Tests**: Dashboard diagram generation tests (label sanitization, severity resolution, transfers, validations)
- **Tests**: Parser regression tests (`@flows` via + description, `@shield` vs `@shield:begin` disambiguation)
- **Tests**: Validation unit tests (dangling refs, unmitigated exposure matching with ref normalization)
- **README**: Manual installation instructions (build from source + npm link)

### Fixed

- **Parser**: `@flows` regex no longer swallows description when `via` mechanism is present
- **Parser**: `@shield` no longer incorrectly matches `@shield:begin` and `@shield:end`
- **Validation**: `#id` and bare-name refs now compare correctly (e.g., `#sqli` matches `sqli` in mitigations)

### Removed

- **TUI**: `/scan` command — redundant with `/status` coverage display; AI-driven annotation replaces manual symbol discovery
- **TUI**: `/exposures` and `/show` commands — exposure data remains accessible via `/validate`, MCP `guardlink_status`, and `guardlink://unmitigated` resource
- **Dependencies**: Removed accidental `build` package (unused)

## [1.0.0] — 2026-02-21

Initial public release of GuardLink.

### Added

- **Parser**: 16 annotation types, 25+ comment styles, v1 backward compatibility
- **Parser**: External reference support (cwe, capec, owasp), severity levels
- **Analyzer**: Coverage statistics, dangling ref detection, duplicate ID detection
- **Analyzer**: SARIF 2.1.0 export for GitHub/GitLab Security tab
- **Analyzer**: Suggestion engine with 14 patterns for common security scenarios
- **Diff**: Threat model comparison between git refs, change classification
- **Report**: Markdown report with executive summary and Mermaid DFD diagram
- **Report**: Compact diagram mode for high-exposure codebases
- **Init**: Project initialization with multi-agent support (Claude Code, Cursor, Windsurf, Cline, Codex, GitHub Copilot)
- **Init**: Behavioral directive injection for automatic annotation by AI agents
- **MCP**: 12 tools (parse, validate, status, suggest, lookup, threat_report, threat_reports, annotate, report, dashboard, sarif, diff) and 3 resources
- **CLI**: 12 commands (init, parse, status, validate, report, diff, sarif, mcp, threat-report, annotate, dashboard, scan)
- **TUI**: Interactive terminal interface with command palette, autocomplete, and inline help
- **Dashboard**: HTML threat model dashboard with exposure explorer, file tree, and threat report viewer
- **Agents**: Unified agent launcher (Claude Code, Cursor, Windsurf, Cline, Codex, Gemini CLI) with config resolution chain
- **Threat Reports**: AI-powered threat analysis using STRIDE, DREAD, PASTA, and other frameworks
- **CI**: --strict flag on validate, --fail-on-new on diff for CI gates
