# Changelog
All notable changes to GuardLink CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## \[1.4.3\] — 2026-04-25

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
