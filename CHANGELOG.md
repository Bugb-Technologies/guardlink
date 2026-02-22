# Changelog

All notable changes to GuardLink CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
