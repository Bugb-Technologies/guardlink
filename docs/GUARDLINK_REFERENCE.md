# GuardLink — Annotation Reference

> Canonical reference for **guardlink**. All agent instruction files point here.
> Full specification: [docs/SPEC.md](https://github.com/Bugb-Technologies/guardlink/blob/main/docs/SPEC.md)

## Quick Reference

```
DEFINE   @asset <Component.Path> (#id) -- "description"
         @threat <Name> (#id) [severity] cwe:CWE-NNN -- "description"
         @control <Name> (#id) -- "description"

RELATE   @mitigates <Asset> against <#threat> using <#control> -- "how"
         @exposes <Asset> to <#threat> [severity] cwe:CWE-NNN -- "what's wrong"
         @accepts <#threat> on <Asset> -- "HUMAN-ONLY — AI agents must use @audit instead"
         @transfers <#threat> from <Source> to <Target> -- "who handles it"

FLOW     @flows <Source> -> <Target> via <mechanism> -- "details"
         @boundary <AssetA> | <AssetB> (#id) -- "trust boundary"
         @boundary between <AssetA> and <AssetB> (#id) -- "trust boundary"

LIFECYCLE
         @validates <#control> for <Asset> -- "test evidence"
         @audit <Asset> -- "what needs review"
         @owns <team-id> for <Asset> -- "responsible team"
         @handles <pii|phi|financial|secrets|internal|public> on <Asset>
         @assumes <Asset> -- "unverified assumption"

COMMENT  @comment -- "security-relevant developer note"

PROTECT  @shield -- "reason"
         @shield:begin -- "reason"   ... code ...   @shield:end
```

## Severity

`[P0]` = critical, `[P1]` = high, `[P2]` = medium, `[P3]` = low

## External References

Append after severity: `cwe:CWE-89`, `owasp:A03:2021`, `capec:CAPEC-66`, `attack:T1190`

## Rules

1. **Annotate as you code.** When you write or modify security-relevant code (endpoints, auth, data access, validation, I/O, crypto, process spawning), add annotations in the same change. This is required, not optional.
2. **Define once, reference everywhere.** `@asset`, `@threat`, `@control` with `(#id)` go in `.guardlink/definitions.ts`. Source files use relationship verbs only (`@mitigates`, `@exposes`, etc.).
3. **Read definitions before adding.** Check for existing IDs first — avoid duplicates.
4. **Every `@exposes` needs a response.** Match with `@mitigates` (fix exists) or `@audit` (flag for human review). AI agents must NEVER write `@accepts` — that is a human-only governance decision. Use `@audit` instead.
5. **Use the full verb set.** `@flows` for data movement, `@handles` for data classification, `@boundary` for trust boundaries.

## When Writing Code

| Situation | Annotation |
|-----------|------------|
| Writing new endpoint/handler | `@exposes` + `@mitigates` (or `@audit`) + `@flows` + `@comment` — tell the complete story |
| New service/component | `@asset` in definitions, then reference in source |
| Security gap exists | `@exposes Asset to #threat` + `@audit Asset` |
| Risk with no fix yet | `@audit Asset` + `@comment` explaining potential controls. NEVER `@accepts`. |
| Implementing a fix | `@mitigates Asset against #threat using #control` |
| Processing sensitive data | `@handles pii on Asset` |
| Proprietary algorithm | `@shield:begin` ... `@shield:end` (only if human requests it) |
| Unsure which annotation | `@comment -- "describe what you see"` |

## CLI Commands

```bash
# Core
guardlink init [dir]                    # Initialize .guardlink/ and agent instruction files
guardlink parse [dir]                   # Parse annotations → ThreatModel JSON
guardlink status [dir]                  # Risk grade + coverage summary
guardlink validate [dir] [--strict]     # Syntax errors, dangling refs, unmitigated exposures

# Reports & Export
guardlink report [dir]                  # Generate threat-model.md + optional JSON
guardlink dashboard [dir]               # Interactive HTML dashboard with Mermaid diagrams
guardlink sarif [dir] [-o file]         # SARIF 2.1.0 for GitHub Advanced Security / VS Code
guardlink diff [ref]                    # Compare threat model against a git ref (default: HEAD~1)

# AI-Powered Analysis
guardlink threat-report <fw|prompt>     # AI threat report (see frameworks below)
guardlink threat-reports                # List saved threat reports
guardlink annotate <prompt>             # Launch coding agent to add annotations
guardlink config <show|set|clear>       # Manage LLM provider / CLI agent configuration

# Interactive
guardlink tui [dir]                     # Interactive TUI: slash commands + AI chat
guardlink mcp                           # Start MCP server (stdio) for Claude Code, Cursor, etc.
guardlink gal                           # Display GAL annotation language quick reference
```

## Threat Report Frameworks

```bash
guardlink threat-report stride          # STRIDE (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation)
guardlink threat-report dread           # DREAD risk scoring
guardlink threat-report pasta           # PASTA (Process for Attack Simulation and Threat Analysis)
guardlink threat-report attacker        # Attacker-centric (personas, kill chains, attack trees)
guardlink threat-report rapid           # RAPID threat model
guardlink threat-report general         # General-purpose comprehensive analysis
guardlink threat-report "<custom>"      # Custom prompt — any free-text analysis instructions
```

## AI Agent Flags

All AI commands (`threat-report`, `annotate`) support:

```bash
--claude-code     # Run via Claude Code CLI (inline)
--codex           # Run via Codex CLI (inline)
--gemini          # Run via Gemini CLI (inline)
--cursor          # Open Cursor IDE with prompt on clipboard
--windsurf        # Open Windsurf IDE with prompt on clipboard
--clipboard       # Copy prompt to clipboard only
```

Additional `threat-report` flags:

```bash
--thinking        # Enable extended thinking / reasoning mode
--web-search      # Enable web search grounding (OpenAI Responses API)
--provider <p>    # Direct API: anthropic, openai, openrouter, deepseek
--model <m>       # Override model name
```

## TUI Commands

Run `guardlink tui` for the interactive terminal interface:

```
/init [name]             Initialize project
/parse                   Parse annotations, build threat model
/status                  Risk grade + summary stats
/validate                Check for errors + dangling refs
/exposures [--all]       List open exposures by severity (--asset --severity --threat --file)
/show <n>                Detail view + code context for exposure
/scan                    Coverage scanner — find unannotated symbols
/assets                  Asset tree with threat/control counts
/files                   Annotated file tree with exposure counts
/view <file>             Show all annotations in a file with code context
/threat-report <fw>      AI threat report (frameworks above or custom text)
/threat-reports          List saved reports
/annotate <prompt>       Launch coding agent to annotate codebase
/model                   Set AI provider (API or CLI agent)
/report                  Generate markdown + JSON report
/dashboard               Generate HTML dashboard + open browser
/diff [ref]              Compare model vs git ref (default: HEAD~1)
/sarif [-o file]         Export SARIF 2.1.0
/gal                     GAL annotation language guide
(freeform text)          Chat about your threat model with AI
```

## Critical Syntax Rules

1. **@boundary requires TWO assets**: `@boundary between #A and #B` or `@boundary #A | #B`.
2. **@flows is ONE source → ONE target per line**: `@flows <source> -> <target> via <mechanism>`.
3. **@exposes / @mitigates require defined #id refs**: Every `#id` must have a definition in `.guardlink/definitions.*`.
4. **Severity in square brackets**: `[P0]` `[P1]` `[P2]` `[P3]` or `[critical]` `[high]` `[medium]` `[low]`. Goes AFTER the threat ref.
5. **Descriptions in double quotes after --**: `-- "description text here"`.
6. **IDs use parentheses in definitions, hash in references**: Define `(#sqli)`, reference `#sqli`.
7. **Asset references**: Use `#id` or `Dotted.Path` — no spaces or special chars.
8. **External refs space-separated after severity**: `cwe:CWE-89 owasp:A03:2021 capec:CAPEC-66`.
9. **@comment always needs -- and quotes**: `@comment -- "your note here"`.
10. **One annotation per comment line.** Do NOT put two @verbs on the same line.

## MCP Tools

When connected via `.mcp.json`, use:
- `guardlink_parse` — parse annotations, return threat model
- `guardlink_lookup` — query threats, controls, exposures by ID
- `guardlink_suggest` — get annotation suggestions for a file
- `guardlink_validate` — check for syntax errors
- `guardlink_status` — coverage stats
