# Changelog

All notable changes to GuardLink CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.2] — 2026-04-24

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

## [1.4.1] — 2026-03-12

### Fixed

- **GAL reference (`/gal`, `guardlink gal`)**: Fixed all syntax examples to match the actual parser — descriptions now correctly show `-- "quoted text"` format instead of the non-functional `: text` format; severity now shows bracket notation `[high]` / `[P0]` instead of `severity:high`; `@flows` now shows `->` arrow syntax instead of `to`; `@validates` now shows `for` preposition instead of `on`; `@owns` now includes the required `for` preposition; `@mitigates` now documents `using` as the primary keyword (with `with` as v1 compat)
- **GAL reference**: Added missing documentation for external references (`cwe:CWE-89`, `owasp:A03:2021`, `capec:CAPEC-66`, `attack:T1190`) on `@threat` and `@exposes` annotations
- **GAL reference**: Added missing `@boundary` alternate syntaxes (`@boundary between A and B`, `@boundary A | B`) and `(#id)` support
- **GAL reference**: Added missing standalone `@shield` single-line marker (was only documenting `@shield:begin/end` blocks)
- **TUI `/help`**: Added missing `/unannotated` command to the help output (was registered and functional but not listed)
- **CLI version**: Fixed `guardlink --version` reporting `1.1.0` instead of the actual package version

### Changed

- **GAL reference**: Added new "External References" section explaining `cwe:`, `owasp:`, `capec:`, `attack:` ref syntax
- **GAL reference**: Updated Tips section with description format, severity format, and `@flows ->` syntax reminders
- **Annotations**: Changed `@comment` to `@audit` on agent-launcher timeout note for better governance visibility
- **Annotations**: Added `@audit` to MCP suggest module, added workspace-related controls to definitions

## [1.4.0] — 2026-02-27

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
