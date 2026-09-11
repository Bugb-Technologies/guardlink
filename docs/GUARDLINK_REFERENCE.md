# GuardLink — Annotation Reference

> Canonical reference for **guardlink**. All agent instruction files point here.
> Full specification: [docs/SPEC.md](https://github.com/Bugb-Technologies/guardlink/blob/main/docs/SPEC.md)

## Quick Reference

```
DEFINE   @asset <Component.Path> (#id) -- "description"
         @threat <Name> (#id) [severity] cwe:CWE-NNN -- "description"
         @control <Name> (#id) -- "description"
         @actor <Name> (#id) -- "a principal in the authz model — a role, not a person"

RELATE   @mitigates <Asset> against <#threat> using <#control> -- "how"
         @exposes <Asset> to <#threat> [severity] cwe:CWE-NNN -- "what's wrong"
         @confirmed <#threat> on <Asset> [severity] cwe:CWE-NNN -- "verified evidence"
         @accepts <#threat> on <Asset> -- "HUMAN-ONLY — AI agents must use @audit instead"
         @transfers <#threat> from <Source> to <Target> -- "who handles it"
         @entitles <#actor> to <capability> on <Asset> against <#threat> -- "by design + authz file:line"
                   ^ PROPOSED via `guardlink entitle --propose`, written only when a human accepts

FLOW     @flows <Source> -> <Target> via <mechanism> -- "details"
         @boundary <AssetA> | <AssetB> (#id) -- "trust boundary"
         @boundary between <AssetA> and <AssetB> (#id) -- "trust boundary"

LIFECYCLE
         @validates <#control> for <Asset> -- "test evidence"
         @audit <Asset> -- "what needs review"
         @owns <team-id> for <Asset> -- "responsible team"
         @handles <pii|phi|financial|secrets|internal|public> on <Asset>
         @assumes <Asset> -- "unverified assumption"

METADATA @feature "Feature Name" -- "tag code with a feature for filtering"

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
2. **Define once, reference everywhere.** `@asset`, `@threat`, `@control` with `(#id)` go in `.guardlink/definitions.ts`. Relationship annotations can live inline in source comments or in standalone `.gal` files.
3. **Read definitions before adding.** Check for existing IDs first — avoid duplicates.
4. **Every `@exposes` needs a response.** Match with `@mitigates` (fix exists) or `@audit` (flag for human review). AI agents must NEVER write `@accepts` — that is a human-only governance decision. Use `@audit` instead.
5. **Use the full verb set.** `@flows` for data movement, `@handles` for data classification, `@boundary` for trust boundaries.
6. **`@entitles` is proposed, never written by hand.** An over-grant closes a real privilege escalation as by-design, so the claim goes through a review artifact: propose it (`guardlink entitle --propose`, or the `guardlink_entitlement_propose` MCP tool), and a human accepts it with `guardlink entitle` — acceptance is what writes the annotation, with their name next to it. An `@entitles` in source with no accepted proposal behind it is a validation error. The rationale must cite the authz code (`Authz: common/api/metadata.go:189`); without a `file:line` pointer the claim is **inert** — parsed but ignored — and accepting it takes an explicit acknowledgement of that. It never hides a finding and never gates testing; it only changes what triage recommends. Never propose one for an ownership question (IDOR, tenant isolation): both peers hold the capability, so entitlement cannot answer *whose object it was*.

### Standalone `.gal` Files

Use the same GAL syntax without language comment prefixes. Definitions still belong in `.guardlink/definitions.*`; `.gal` files are for externalized relationship annotations:

```text
@source file:src/auth/login.ts line:42 symbol:authenticate
@exposes #api to #xss [P1] cwe:CWE-79 -- "User bio rendered without escaping"
@audit #api -- "Review sanitization before release"
```

`@source` sets the logical code location for the following annotations until the next `@source`. `symbol:` is optional.

**Convention:** always place a `@source` directive before any annotations in a `.gal` file. Annotations that appear before the first `@source` are anchored to the `.gal` file's own physical location rather than to a source-code location, which is usually not what you want and makes dashboards / reports display the `.gal` path instead of the underlying source file.

## When Writing Code

| Situation | Annotation |
|-----------|------------|
| Writing new endpoint/handler | `@exposes` + `@mitigates` (or `@audit`) + `@flows` + `@comment` — tell the complete story |
| New service/component | `@asset` in definitions, then reference in source |
| New role / permission tier | `@actor` in definitions, then `guardlink entitle --propose` for each capability it holds by design |
| Finding needs privilege X, and X is allowed to do that | Propose an entitlement (`guardlink entitle --propose … --rationale "by design + authz file:line"`) — do not write `@entitles` yourself |
| Security gap exists | `@exposes Asset to #threat` + `@audit Asset` |
| Threat verified exploitable | `@confirmed #threat on Asset [severity] -- "pentest/scan evidence"` |
| Risk with no fix yet | `@audit Asset` + `@comment` explaining potential controls. NEVER `@accepts`. |
| Implementing a fix | `@mitigates Asset against #threat using #control` |
| Processing sensitive data | `@handles pii on Asset` |
| Proprietary algorithm | `@shield:begin` ... `@shield:end` (only if human requests it) |
| Tagging code to a feature | `@feature "SSO Login" -- "Single sign-on flow"` |
| Unsure which annotation | `@comment -- "describe what you see"` |

## CLI Commands

```bash
# Core
guardlink init [dir]                    # Initialize .guardlink/ and agent instruction files
guardlink parse [dir]                   # Parse annotations → ThreatModel JSON
guardlink status [dir]                  # Risk grade + coverage summary
guardlink validate [dir] [--strict]     # Syntax errors, dangling refs, unmitigated exposures
guardlink verify [dir] [targets...]     # Lock claims to the code beneath them → .guardlink/verified.json

# Reports & Export
guardlink report [dir]                  # Generate threat-model.md + optional JSON
guardlink dashboard [dir]               # Interactive HTML dashboard with Mermaid diagrams
guardlink sarif [dir] [-o file]         # SARIF 2.1.0 for GitHub Advanced Security / VS Code
guardlink diff [ref]                    # Compare threat model against a git ref (default: HEAD~1)
guardlink paths [dir] [--all]           # Undefended source-to-sink routes, derived from @flows (no LLM)

# AI-Powered Analysis
guardlink threat-report <fw> [focus…] [--shape full|executive|pr|audit]  # AI threat report (see frameworks below); free text is a focus, the shape is the audience
guardlink threat-reports                # List saved threat reports
guardlink annotate <prompt> [--playbook map|exploitable|chains|diff|coverage|verify] [--mode inline|external]  # Launch coding agent; the playbook is the method, the prompt is scope; the gate checks the result
guardlink lint [dir] [--since <ref>] [--json]   # Check annotations against the evidence bar; --since checks only what a session added
guardlink hypothesis list|next|refute|confirm   # What happened when an exposure was tested (see below)
guardlink translate [prompt]            # Generate CERT-X-GEN pentest templates from threat findings
guardlink ask <query>                   # Ask questions about the threat model and codebase
guardlink config <show|set|clear>       # Manage LLM provider / CLI agent configuration

# Governance & Maintenance
guardlink review [dir]                  # Interactive review of unmitigated exposures (accept/remediate/skip)
guardlink review --list [--severity X]  # List reviewable exposures without prompting
guardlink entitle [dir]                 # Review proposed @entitles claims (accept/reject/defer)
guardlink entitle --list [--status X]   # List entitlement proposals and their decisions
guardlink entitle --propose --actor "#ns-admin" --capability configure-archival-destination \
    --asset "#archival-fs" --threat "#path-traversal" --file common/api/metadata.go --line 189 \
    --rationale "By design: namespace config. Authz: common/api/metadata.go:189"
guardlink clear [dir] [--dry-run]       # Remove all annotations from source files
guardlink sync [dir]                    # Sync agent instruction files with current threat model
guardlink unannotated [dir]             # List source files with no annotations
guardlink feature list [dir]            # List all @feature tags with stats
guardlink feature show <name>           # Show threat model for a specific feature

# Attribution (read from git; nothing written)
guardlink blame [dir] [--file f] [--json] [--identity name|email|hash]   # who introduced / declared / fixed each claim, and which AI co-authored it
guardlink parse . --blame               # same, attached to each record of the JSON model
guardlink status . --blame              # top people and AI tools by exposures introduced
guardlink report . --blame              # adds an Attribution section
guardlink dashboard . --blame           # adds an Attribution page
guardlink dashboard . --since v1.2.0    # adds a "what changed since <ref>" strip and marks new claims

# Interactive
guardlink tui [dir]                     # Interactive TUI: slash commands + AI chat
guardlink mcp                           # Start MCP server (stdio) for Claude Code, Cursor, etc.
guardlink gal                           # Display GAL annotation language quick reference

# Feature filtering (--feature flag on report, dashboard, status, translate)
guardlink report . --feature "SSO Login"          # Report filtered to feature
guardlink dashboard . --feature "SSO,Payments"    # Dashboard filtered to features
guardlink status . --feature "SSO Login"           # Status filtered to feature
```

## Playbooks, the evidence bar and the gate

`guardlink annotate` and `guardlink threat-report` used to leave the method to whoever typed the
prompt: "annotate all the threats" got a shallow pass and only an expert prompt got a deep one.
Now the tool owns the method and the prompt supplies scope and intent.

**Annotate playbooks** (`--playbook`, or inferred from the prompt by rule and announced on stderr;
`exploitable` when nothing matches):

| id | what it does |
|---|---|
| `map` | Architecture first: assets, flows, boundaries, data classes. Writes no `@exposes`. |
| `exploitable` | Default. Map → hypothesise → verify each path by reading it → write. |
| `chains` | Start from the open exposures, follow the flows, ask what each enables next. |
| `diff` | Only the files this branch changed (`--since <ref>`, default HEAD). |
| `coverage` | The unannotated files, entry points first, structure before claims. |
| `verify` | Re-read every existing claim against the code; flag what no longer holds. |

**The evidence bar**, shared by every playbook: an `@exposes` must name the entry point, the
attacker-controlled input, the sink and the absent control, in the code's own names. What cannot
meet the bar is written as `@audit`. Severity never outranks the threat's declared severity.
`@confirmed` needs evidence in hand. `@accepts` and `@entitles` are never written by an agent.

**The gate.** When a terminal agent returns, `guardlink annotate` parses the tree, finds what the
run added, and lints it against the bar. Violations are sent back to the agent once
(`--gate-retries`); what still fails is removed from the tree and printed so nothing is lost, and
the command exits 1. `--no-gate` skips it. `guardlink lint . --since HEAD` runs the same check
for a session the CLI did not launch; without `--since` it lints the whole tree and does not
hold a person's `@accepts` against them.

**Report shapes** (`--shape`): `full` (the framework's own structure), `executive` (one page),
`pr` (what this change adds), `audit` (controls, evidence, owners). Every report ends with a
````json guardlink-findings```` block the dashboard and the CLI read; ids that name nothing in
the model are reported on stderr.

**Skills.** `guardlink init` writes each playbook as `.claude/skills/guardlink-<kind>-<id>/SKILL.md`
so a developer's own agent session runs the same method. A skill file without the generated marker
is treated as authored and left alone.

## Hypotheses (`guardlink hypothesis`)

An `@exposes` is a hypothesis; `@confirmed` is the hypothesis with evidence. The third state —
tested and **not** exploitable — used to have nowhere to go: the exposure stayed open forever or
was deleted with the reasoning. `.guardlink/hypotheses.json` (schema `guardlink.hypotheses/v1`)
records what happened when an exposure was tested, keyed by the claim key, with the evidence, who,
when, and the code hash beneath the claim at that moment.

```bash
guardlink hypothesis list [dir] [--state untested|confirmed|refuted|retest] [--json]
guardlink hypothesis next [dir] [-n 10] [--intake]           # what to test next; --intake prints a brief for bugb intake
guardlink hypothesis refute  src/x.ts:12 --evidence "POST /login with payload X returned 400 from validateEmail()"
guardlink hypothesis confirm src/x.ts:12 --evidence "request … response …" [--write]   # --write inserts the @confirmed line beneath the @exposes
guardlink hypothesis confirm --from-scan .guardlink/pentest/<report>.json [--write]     # cxg findings joined to claims
```

- **Evidence is required.** A refutation needs what was tried and what came back; a confirmation
  needs evidence in hand (a request and response, a reproduction, a scan with proof), the same
  bar the gate holds `@confirmed` to. Scan evidence is redacted before it is stored.
- **Outcomes expire with the code.** An outcome holds while the claim's anchor hash is the one it
  was recorded against. When the code beneath the claim changes, a refutation lapses to
  `untested` (the old outcome stays attached) and a confirmation becomes `retest`. Earlier
  outcomes are kept in the entry's history.
- **Where it shows.** `guardlink status` prints a `Hypotheses:` line and notes refuted exposures
  beside the exposure count. The dashboard does not count a refuted exposure as open (grade,
  KPIs, the what-to-do list), badges it `refuted`, and shows the evidence in the drawer; a
  `retest` row stays open with a badge saying why. Threat reports see `hypothesis` on each
  exposure and treat refuted as not an open risk. `guardlink lint` treats a refuted exposure as
  paired.
- **The queue.** `next` puts retests first, then untested exposures by severity, then those on an
  undefended path (`guardlink paths`), then unowned ones. No AI: the ledger is bookkeeping and
  the ranking is arithmetic. Testing stays with bugb and cxg.
- **Scan import joins** by the finding's annotation location, then by asset and threat, then by
  CWE. A finding that fits more than one claim is reported as ambiguous, never guessed; one that
  fits none is listed as unmatched.

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
--stdout          # Print prompt to stdout — useful for piping into other tools or CI
--mode <m>        # Annotation placement mode: inline (default) or external
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
/annotate <prompt>       Launch coding agent to annotate codebase (use --mode external for .gal files)
/model                   Set AI provider (API or CLI agent)
/report                  Generate markdown + JSON report
/dashboard               Generate HTML dashboard + open browser
/diff [ref]              Compare model vs git ref (default: HEAD~1)
/paths [--all]           Undefended entry-to-sink routes through the flow graph
/sarif [-o file]         Export SARIF 2.1.0
/gal                     GAL annotation language guide
/feature                 List all @feature tags
(freeform text)          Chat about your threat model with AI
```

## Critical Syntax Rules

1. **@boundary requires TWO assets**: `@boundary between #A and #B` or `@boundary #A | #B`.
2. **@flows is ONE source → ONE target per line**: `@flows <source> -> <target> via <mechanism>`.
3. **@exposes / @mitigates / @confirmed require defined #id refs**: Every `#id` must have a definition in `.guardlink/definitions.*`.
4. **Severity in square brackets**: `[P0]` `[P1]` `[P2]` `[P3]` or `[critical]` `[high]` `[medium]` `[low]`. Goes AFTER the threat ref on `@exposes`; on `@confirmed` it reflects **verified** impact (optional but recommended).
5. **Descriptions in double quotes after --**: `-- "description text here"`.
6. **IDs use parentheses in definitions, hash in references**: Define `(#sqli)`, reference `#sqli`.
7. **Asset references**: Use `#id` or `Dotted.Path` — no spaces or special chars.
8. **External refs space-separated after severity**: `cwe:CWE-89 owasp:A03:2021 capec:CAPEC-66` (on `@threat`, `@exposes`, `@confirmed`).
9. **@comment always needs -- and quotes**: `@comment -- "your note here"`.
10. **One annotation per comment line.** Do NOT put two @verbs on the same line.
11. **@entitles capability is ONE identifier, not prose**: `configure-archival-destination`, not `"can configure archival"`. It is the join key, and prose would not join.

## MCP Tools

When connected via `.mcp.json`, use:
- `guardlink_parse` — parse annotations, return threat model
- `guardlink_lookup` — query threats, controls, exposures by ID (try `unmitigated`, `confirmed`, `actors`, `entitlements`)
- `guardlink_suggest` — get annotation suggestions for a file
- `guardlink_validate` — check for syntax errors
- `guardlink_status` — coverage stats
- `guardlink_entitlement_propose` — propose an `@entitles` claim into `.guardlink/entitlement-proposals.json` (writes nothing to source)
- `guardlink_entitlement_list` — see proposals and their decisions; a rejected claim must not be re-filed
- `guardlink_blame` — who introduced, declared and fixed each claim, and which AI tool co-authored those commits (read from git; optional `file`)

There is deliberately no entitlement *accept* tool. Acceptance is a human decision recorded by name, through `guardlink entitle`.

## Attribution (`guardlink blame`)

Every relationship claim sits on a span of code. `guardlink blame` reads git history for each
one and answers four questions, without writing anything — not a note, not a trailer:

| Question | How it is answered |
|---|---|
| Who introduced the code beneath the claim? | The oldest commit in the span's line history (`git log -L`). For a file-header claim the span is the whole file, so it is the commit that added the file, and the record says `granularity: file`. |
| Who declared the claim? | `git blame` of the annotation line — for a `.gal` sidecar, the line in the sidecar. |
| Who declared the fix? | The earliest-declared `@mitigates` that covers the exposure; `time_to_fix_days` is the gap. |
| Did an AI co-author those commits, and which model? | Commit trailers and bot author identities. |

**AI attribution is declared, never detected.** A commit is credited to an AI tool only when its
author or a `Co-Authored-By` / `Co-authored-by` / `Assisted-by` trailer matches a rule. A commit
with no trailer stays human, and a `Co-authored-by` that matches no rule is a human co-author. The
granularity is the commit: a co-authored commit means the tool was involved, not that it wrote
every line. The shipped rules:

| Tool | Recognised by | Model |
|---|---|---|
| Claude Code | `Co-Authored-By: Claude … <noreply@anthropic.com>` | the name, e.g. `Claude Opus 5 (1M context)` |
| GitHub Copilot coding agent | bot **author** `Copilot <…+Copilot@users.noreply.github.com>`; the human co-author becomes the author | — |
| Codex CLI | `Co-authored-by: Codex <noreply@openai.com>` | — |
| Cursor | `Co-authored-by: Cursor <cursoragent@cursor.com>` | — |
| Gemini CLI | `Co-authored-by: gemini-cli <model> <…gemini-cli@users.noreply.github.com>` | what follows the tool token |
| aider | author name suffix ` (aider)`, or a co-author trailer naming aider | text in parentheses |
| Warp | `Co-Authored-By: Warp <agent@warp.dev>` | — |
| Kernel style | `Assisted-by: AGENT:MODEL [tool…]` (Linux, Fedora, LLVM, QEMU, …) | after the colon |

Add your own, or override a vendor's, in `.guardlink/config.json`; user rows are matched first.
Patterns are anchored, case-insensitive regular expressions, capped at 256 characters:

```json
{
  "blame": {
    "identity": "name",
    "tools": [{ "tool": "corp-bot", "email": "bot@corp\\.example" }],
    "ignore_revs": ".git-blame-ignore-revs"
  }
}
```

- `identity` — `name` (default), `email`, or `hash` (12 hex of the email's sha256). Author emails are
  personal data and the dashboard embeds the model in a file people commit, so `hash` is the setting
  for a shared dashboard. `guardlink blame --identity` overrides it for one run. Names and emails are
  read through git's `.mailmap`, so one person who committed under two identities is one row once the
  repository maps them.
- `ignore_revs` — passed to `git blame --ignore-revs-file` when the file exists, so a mass reformat does
  not become the introducer of everything it touched.

Every degraded answer is explicit in `status`: `no-git` (not a checkout), `uncommitted` (the line or
its span has changes git has not seen), `shallow` (history truncated; every introduction is a lower
bound, as is one computed for a file with uncommitted edits), `no-anchor`, `file-missing`, `error`.

The dashboard's Attribution page (`guardlink dashboard --blame`) adds the analysis: a quarterly trend of
introductions (human vs AI-assisted) and fixes, exposures per 100 commits per person and per model
(each identity's commit count comes from one history walk; `computeBlame({ history: false })`
skips it), a severity-weighted risk score, the age of the oldest open exposure, the files most
rewritten under open exposures, and a click on any identity that narrows the claims table. The
dashboard also links every `file:line` and commit to the repository's web host when `.git/config`
names a GitHub, GitLab or Bitbucket origin, and shows verified / stale / unverified per claim
when a ledger exists. The Analytics page charts the model itself — asset × threat, severity ×
status, threats by frequency, control coverage (including controls nothing uses), the files with
the most open exposures, open risk per owning team (`@owns`) with the exposed assets nobody owns,
open exposure per data classification (`@handles`), and with `--blame` people × quarter and AI
tool × severity — with every cell linking into the filtered Threats table. `--since <ref>` adds a
strip under the summary saying what changed since a tag, branch or commit: exposures added and
resolved, newly confirmed, new mitigations, and verified claims gone stale in files that changed.

Attribution is opt-in and computed at run time. Without `--blame` every command's output is exactly
what it was; with it, exposures, confirmed findings and mitigations carry a `blame` field that is
invisible to the annotation hash and never written to `.guardlink/model.json`. The JSON payload of
`guardlink blame --json` (`guardlink.blame/v1`) keys every entry with the ledger claim key, so it
joins to `.guardlink/verified.json`. It works whether one person or the whole team runs GuardLink:
the evidence is in git, not in the annotations.

## Stale claims and the verification ledger

Every relationship annotation is bound at parse time to the declaration beneath it — the function a doc-block sits on, the statement an inline comment precedes, the whole file for a header block — and that declaration's non-comment tokens are hashed. `guardlink verify` records the hash in `.guardlink/verified.json` with who verified it and when. On every later parse, `guardlink ci` and `guardlink status` compare the current hash with the recorded one.

| State | Meaning |
|---|---|
| `verified` | hash matches the ledger |
| `stale` | the code beneath the claim changed after it was verified |
| `unverified` | no ledger entry yet — every claim starts here; never fails a build |

Commit the ledger. It needs no git history to read, so it works on a depth-one CI checkout. Re-locking a stale claim is an explicit act: `guardlink verify --stale`, `guardlink verify --all`, or `guardlink verify src/file.ts:33`. The default `guardlink verify` only locks new claims and prunes entries whose claim is gone.

Put claims on the function that implements the control, not in the file header. A file-header claim is bound to the whole file and goes stale on any edit to it.
