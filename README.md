<div align="center">

<img src=".github/guardlink_banner.png" alt="GuardLink" width="600">

[![npm version](https://img.shields.io/npm/v/guardlink.svg)](https://www.npmjs.com/package/guardlink)
[![CI](https://github.com/Bugb-Technologies/guardlink/actions/workflows/ci.yml/badge.svg)](https://github.com/Bugb-Technologies/guardlink/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js 18+](https://img.shields.io/badge/node-18%2B-green.svg)](https://nodejs.org)
[![Spec: CC-BY-4.0](https://img.shields.io/badge/spec-CC--BY--4.0-orange.svg)](docs/SPEC.md)

</div>

**Security annotations that live in your code. Your threat model updates when your code changes.**

> **This repository is secured by GuardLink.** Run `guardlink status .` to see 272 annotations across 12 assets, 13 threats, and 10 controls — maintained by AI agents, validated in CI.

```javascript
// @asset PaymentService (#payments) -- "Handles card transactions"
// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89

// @mitigates #payments against #sqli using #prepared-stmts
app.post('/charge', async (req, res) => {
  const result = await db.query('SELECT * FROM cards WHERE id = $1', [req.body.id]);
});

// @exposes #payments to #idor [P1] cwe:CWE-639 -- "No ownership check"
app.get('/receipts/:id', async (req, res) => {
  const receipt = await db.query('SELECT * FROM receipts WHERE id = $1', [req.params.id]);
});
```

---

## Install

```bash
npm install -g guardlink
```

Requires Node.js 18+.

### Manual Installation

To install from source:

```bash
# 1. Build the project
npm run build

# 2. Link globally
npm link
```

To uninstall: `npm unlink -g guardlink`

## Quick Start

```bash
# Initialize in your project (detects your AI agent automatically)
guardlink init

# Let your AI coding agent annotate, or write annotations manually
# Then validate
guardlink validate .

# See your security posture
guardlink status .
```

```
Assets:        3    Mitigations:  4
Threats:       8    Exposures:    6  (3 unmitigated)
Controls:      5    Coverage:     62%
```

```bash
# Generate a full threat model report
guardlink report .

# Interactive HTML dashboard
guardlink dashboard .

# AI threat analysis (STRIDE, DREAD, PASTA, etc.)
guardlink threat-report stride --claude-code

# Interactive TUI with slash commands
guardlink
```

---

## Why GuardLink

Threat models rot. Teams do a session at the start of a project, someone creates a Confluence page, and it's stale by the next sprint. SAST scanners find 200 things with no context about what matters. Pen test reports sit in shared drives. The root cause is always the same: **security knowledge lives outside the code**.

GuardLink fixes this at three levels:

**1. Annotations in code.** Security decisions are structured comments next to the code they describe. When a developer writes a parameterized query, `@mitigates #api against #sqli using #prepared-stmts` lives right above it. When the code changes, the annotation is right there to update. The threat model *is* the code.

**2. AI agents maintain it.** GuardLink integrates with AI coding agents through MCP and behavioral directives. When your agent writes a route handler, it adds `@exposes` and `@mitigates` annotations automatically. The threat model maintains itself because the thing writing the code also writes the security context.

**3. CI enforces it.** `guardlink validate` fails on syntax errors. `guardlink diff --fail-on-new` blocks PRs that introduce unmitigated exposures. `guardlink sarif` exports to GitHub's Security tab. The threat model becomes a quality gate, not a checkbox.

```
Developer writes code
       ↓
AI agent adds security annotations
       ↓
CI validates on every PR
       ↓
Team reviews security posture in the diff
       ↓
Threat model is always current, always enforced
```

---

## AI Agent Integration

GuardLink ships an MCP server and behavioral directives for AI coding agents. After `guardlink init`, your agent treats security annotations like type safety — adding them by default when writing security-relevant code.

`guardlink init` detects your agent and configures two things:

**MCP server** — tools to read the threat model, validate annotations, suggest annotations, and query threats by keyword. The agent can ask "what threats affect #api?" before writing code that touches the API.

**Behavioral directive** — a rule injected into your agent's instruction file (CLAUDE.md, .cursorrules, etc.) that says: *when writing code that handles routes, auth, database access, file I/O, or external services, add GuardLink annotations.*

### Supported Agents

| Agent | Config File | MCP Support |
|-------|------------|-------------|
| Claude Code | `CLAUDE.md` + `.mcp.json` | ✅ Full |
| Cursor | `.cursorrules` + `.cursor/mcp.json` | ✅ Full |
| Windsurf | `.windsurfrules` + `.windsurf/mcp.json` | ✅ Full |
| Cline | `.clinerules` + `.cline/mcp.json` | ✅ Full |
| Codex | `AGENTS.md` | Directive only |
| GitHub Copilot | `.github/copilot-instructions.md` | Directive only |

### MCP Tools

| Tool | Description |
|------|-------------|
| `guardlink_parse` | Full threat model as JSON |
| `guardlink_validate` | Check for errors and dangling references |
| `guardlink_status` | Coverage summary |
| `guardlink_suggest` | Suggest annotations for a code snippet |
| `guardlink_lookup` | Query threats, controls, flows by keyword |
| `guardlink_threat_report` | AI threat report (STRIDE, DREAD, etc.) |
| `guardlink_annotate` | Build annotation prompt for the agent |
| `guardlink_report` | Generate markdown report |
| `guardlink_dashboard` | Generate HTML dashboard |
| `guardlink_sarif` | Export SARIF 2.1.0 |
| `guardlink_diff` | Compare threat model against a git ref |
| `guardlink_workspace_info` | Workspace config, sibling repos, tag prefixes for cross-repo annotations |

**Resources:** `guardlink://model`, `guardlink://definitions`, `guardlink://config`

---

## Commands

| Command | Description |
|---------|-------------|
| `guardlink init [dir]` | Initialize project with definitions, config, and agent integration |
| `guardlink parse [dir]` | Parse all annotations, output ThreatModel JSON |
| `guardlink status [dir]` | Coverage summary: assets, threats, mitigations, exposures |
| `guardlink validate [dir]` | Check for syntax errors, dangling refs, duplicate IDs |
| `guardlink validate --strict` | Also fail on unmitigated exposures |
| `guardlink scan [dir]` | Find unannotated security-relevant functions |
| `guardlink report [dir]` | Markdown threat model with Mermaid architecture diagram |
| `guardlink dashboard [dir]` | Interactive HTML threat model dashboard |
| `guardlink diff --from <ref>` | Compare threat models between git refs |
| `guardlink diff --fail-on-new` | Exit 1 if new unmitigated exposures found |
| `guardlink sarif [dir]` | Export unmitigated exposures as SARIF 2.1.0 |
| `guardlink threat-report [fw]` | AI threat report (stride/dread/pasta/attacker/rapid/general) |
| `guardlink threat-reports` | List saved AI threat reports |
| `guardlink annotate [prompt]` | Launch a coding agent to add annotations |
| `guardlink review [dir]` | Interactive governance review — accept, remediate, or skip unmitigated exposures |
| `guardlink review --list` | List reviewable exposures without prompting |
| `guardlink clear [dir]` | Remove all annotations from source files (with `--dry-run` preview) |
| `guardlink sync [dir]` | Sync agent instruction files with current threat model |
| `guardlink unannotated [dir]` | List source files with no annotations |
| `guardlink link-project <repos...>` | Link repos into a shared workspace for cross-repo threat modeling |
| `guardlink link-project --add <repo>` | Add a repo to an existing workspace |
| `guardlink link-project --remove <name>` | Remove a repo from a workspace |
| `guardlink merge <files...>` | Merge per-repo report JSONs into a unified workspace dashboard |
| `guardlink report --format json` | Generate report JSON with metadata (repo, workspace, commit SHA) |
| `guardlink config` | Set AI provider and API key |
| `guardlink mcp` | Start MCP server for AI agent integration |

---

## Annotation Reference

GuardLink annotations go in comments in any language. The parser supports `//`, `#`, `--`, `/* */`, `""" """`, and 25+ comment styles.

### Definitions (shared, in `.guardlink/definitions.js`)

```javascript
// @asset App.API (#api) -- "Express REST API serving mobile and web clients"
// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Unsanitized input reaches SQL query"
// @control Parameterized_Queries (#prepared-stmts) -- "All queries use bound parameters"
```

### Relationships (in source files, next to the code)

```python
# @mitigates #api against #sqli using #prepared-stmts -- "All queries parameterized"
# @exposes #api to #xss [P1] cwe:CWE-79 -- "User bio rendered without escaping"
# @accepts #info-disclosure on #api -- "Health endpoint is intentionally public"
# @transfers #sqli from #api to #database -- "DB handles untrusted input"
```

### Data Flow & Architecture

```go
// @flow #api -> #database via "PostgreSQL wire protocol"
// @boundary #api <-> #cdn -- "TLS termination point"
// @handles pii on #api -- "Processes user email and address"
// @handles secrets on #auth -- "Manages JWT signing keys"
```

### Operational

```rust
// @audit #api by "PenTest Corp" on 2025-03-15 -- "Annual penetration test"
// @validates #input-validation on #api using "Jest integration tests"
// @assumes #api -- "Rate limiting handled by API gateway"
// @owns #api by "backend-team"
```

### All Annotation Types

| Verb | Purpose | Example |
|------|---------|---------|
| `@asset` | Define a component | `@asset UserService (#users)` |
| `@threat` | Define a threat | `@threat XSS (#xss) [high] cwe:CWE-79` |
| `@control` | Define a security control | `@control WAF (#waf)` |
| `@mitigates` | Control protects asset against threat | `@mitigates #api against #sqli using #prepared-stmts` |
| `@exposes` | Asset vulnerable to threat | `@exposes #api to #xss [P1]` |
| `@accepts` | Risk acknowledged | `@accepts #dos on #api -- "By design"` |
| `@transfers` | Risk moved between assets | `@transfers #sqli from #api to #db` |
| `@flow` | Data flow between assets | `@flow #api -> #db via "SQL"` |
| `@boundary` | Trust boundary | `@boundary #api <-> #external` |
| `@handles` | Data classification | `@handles pii on #users` |
| `@audit` | Security audit record | `@audit #api by "Firm" on 2025-01-01` |
| `@validates` | Control verification | `@validates #auth on #api using "tests"` |
| `@assumes` | Security assumption | `@assumes #api -- "Behind VPN"` |
| `@owns` | Component ownership | `@owns #api by "team-backend"` |
| `@shield` | AI exclusion zone | `@shield #api requires #auth-check` |

Severity: `[critical]`/`[P0]`, `[high]`/`[P1]`, `[medium]`/`[P2]`, `[low]`/`[P3]`. External refs: `cwe:CWE-89`, `capec:CAPEC-66`, `owasp:A03`.

---

## CI Integration

### GitHub Actions

```yaml
name: GuardLink
on: [pull_request]

jobs:
  guardlink:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - uses: actions/setup-node@v4
        with: { node-version: '20' }

      - run: npm install -g guardlink

      - name: Validate annotations
        run: guardlink validate .

      - name: Threat model diff
        run: guardlink diff --from origin/main --to HEAD

      - name: Export SARIF
        run: guardlink sarif . -o guardlink.sarif

      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: guardlink.sarif }
```

See [`examples/github-action.yml`](examples/github-action.yml) for a full example with PR comments and SARIF upload.

### Multi-Repo CI

For workspace setups, GuardLink provides two additional workflow templates: a per-repo workflow that generates report JSON artifacts on every push, and a workspace merge workflow that runs weekly to combine all repos into a unified dashboard. See the [CI setup guide](examples/ci/README.md) for step-by-step instructions.

### What CI Catches

- **New route, no annotations:** `guardlink diff` shows "+1 endpoint, 0 mitigations" — the team sees the gap.
- **Agent annotated properly:** diff shows "+1 asset, +2 mitigations, +1 exposure (IDOR)" — team reviews.
- **Control removed:** diff shows "-1 mitigation, +1 unmitigated exposure" — `--fail-on-new` blocks the PR.

### SARIF

`guardlink sarif` exports unmitigated exposures as SARIF 2.1.0. Upload to GitHub Advanced Security and every `@exposes` appears as a code scanning alert with file, line, severity, and CWE.

---

## Multi-Repo Workspaces

In microservices architectures, a single repo only has part of the security picture. `PaymentService` is defined in `repo-payments`, exposed in `repo-gateway`, mitigated in `repo-auth-lib`. GuardLink workspaces link these repos so the threat model spans service boundaries.

```bash
# Link three repos into a workspace
guardlink link-project ./payment-svc ./auth-lib ./api-gateway \
  --workspace acme-platform

# Each repo gets .guardlink/workspace.yaml + agent files updated with cross-repo context
# Agents now know about sibling services and use tag prefixes like #payment-svc.refund

# Generate per-repo JSON reports (in each repo or in CI)
guardlink report --format json -o guardlink-report.json

# Merge all reports into a unified dashboard
guardlink merge payment-svc.json auth-lib.json api-gateway.json \
  -o dashboard.html --json merged.json

# Week-over-week diff for security leads
guardlink merge *.json --diff-against last-week.json --json merged.json
```

Annotations reference sibling repos by tag prefix — `@flows #request from #api-gateway.router to #payment-svc.refund` — and these references resolve during merge. `guardlink validate` flags them as external refs locally, but they're expected and won't block CI.

For automated weekly dashboards, see the [CI setup guide](examples/ci/README.md). Full workspace documentation: [docs/WORKSPACE.md](docs/WORKSPACE.md).

---

## Real-World Results

We tested GuardLink + Claude Code on [vuln-node.js-express.js-app](https://github.com/SirAppSec/vuln-node.js-express.js-app), a deliberately vulnerable Express.js application with 37 documented vulnerability types.

**In 6 minutes, with no human intervention:**

- 143 annotations across 6 route files
- 29 distinct threats identified with CWE mappings
- 66 unmitigated exposures documented with file:line precision
- 27 of 37 known vulnerabilities detected (73% recall, 81% with partial matches)
- Architecture: 8 assets, 3 data flows, Mermaid diagram with risk heat map
- Cost: ~$0.50 in Haiku tokens

A scanner gives you a list of findings. GuardLink gives you a threat model — assets, threats, controls, data flows, trust boundaries, and the relationships between them. Every exposure traceable to a line of code. Every mitigation documented next to the control it implements. And because it's all in code comments, it updates when the code changes.

---

## Library API

```typescript
import { parseProject } from 'guardlink/parser';
import { generateReport } from 'guardlink/report';
import { diffModels } from 'guardlink/diff';
import { generateSarif } from 'guardlink/analyzer';
import type { ThreatModel } from 'guardlink';

const { model } = await parseProject({ root: '.', project: 'my-app' });

const markdown = generateReport(model);
const diff = diffModels(oldModel, newModel);
const sarif = generateSarif(model, '.');
```

---

## Specification

GuardLink is an open specification. The annotation grammar, threat model schema, and conformance levels are defined in the [GuardLink Specification](docs/SPEC.md).

Anyone can build conformant parsers, analyzers, or integrations. This CLI is the reference implementation.

| Level | Name | Capabilities |
|-------|------|-------------|
| L1 | Parser | Parse all 16 annotation types, produce ThreatModel JSON |
| L2 | Analyzer | Coverage stats, unmitigated detection, dangling ref detection |
| L3 | CI/CD | Threat model diffs, change classification, SARIF export |
| L4 | AI-Integrated | MCP server, suggestion engine, agent behavioral directives |

This implementation is **Level 4** conformant.

---

## Heritage

GuardLink builds on the annotation grammar created by [ThreatSpec](https://github.com/threatspec/threatspec) (2015–2020) by Fraser Scott — the first tool to propose continuous threat modeling through code annotations. The core verbs (`@mitigates`, `@exposes`, `@transfers`, `@accepts`) originate from that work.

We extend the specification with severity levels, external references (CWE/CAPEC/OWASP), data flow and trust boundary annotations, data classification, a structured JSON schema, SARIF export, MCP integration for AI agents, and CI/CD enforcement tooling. ThreatSpec had the right idea. Our contribution is making it work in a world where AI writes most of the code.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). The GuardLink specification is published under CC-BY-4.0.

---

Built by [BugB Technologies](https://bugb.io).
