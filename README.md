<div align="center">

<img src=".github/guardlink_banner.png" alt="GuardLink" width="600">

[![npm version](https://img.shields.io/npm/v/guardlink.svg)](https://www.npmjs.com/package/guardlink)
[![CI](https://github.com/Bugb-Technologies/guardlink/actions/workflows/ci.yml/badge.svg)](https://github.com/Bugb-Technologies/guardlink/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js 18+](https://img.shields.io/badge/node-18%2B-green.svg)](https://nodejs.org)
[![Spec: CC-BY-4.0](https://img.shields.io/badge/spec-CC--BY--4.0-orange.svg)](docs/SPEC.md)

**[Documentation](https://docs.bugb.io/guardlink/)** ·
[Install](https://docs.bugb.io/guardlink/get-started/installation/) ·
[GAL reference](https://docs.bugb.io/guardlink/reference/gal/) ·
[CLI reference](https://docs.bugb.io/guardlink/reference/cli/) ·
[Specification](docs/SPEC.md)

</div>

**Security annotations that live in your code. Your threat model updates when your code changes.**

> **This repository is secured by GuardLink.** Its own threat model is maintained
> by AI agents and validated in CI. Run `guardlink status .` in a clone to read it.

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

Requires Node.js 18+. To install from a clone: `npm run build && npm link`.

## Quick start

```bash
guardlink init            # definitions, config, and agent integration
guardlink annotate        # launch your coding agent to add annotations
guardlink validate .      # syntax errors, dangling refs, duplicate ids
guardlink status .        # what the model now holds
```

`status` on this repository:

```text
GuardLink Status: guardlink
────────────────────────────────────────
Files scanned:    87
  Files annotated:    66
  Files unannotated:  21
Annotations:      441
────────────────────────────────────────
Assets:           16
Threats:          15
Controls:         12
Actors:           3
Mitigations:      68
Exposures:        80
```

Truncated. The block continues with acceptances, entitlements, transfers, flows,
boundaries, validations, audits, ownership, data handling, assumptions,
features, comments, and shields. Every number moves as the code does.

From there, [Annotate an existing codebase](https://docs.bugb.io/guardlink/guides/annotate-an-existing-codebase/)
is the walkthrough.

## Documentation

Full documentation is at **<https://docs.bugb.io/guardlink/>**. The reference
sections there are generated against the released package and every command is
verified by running it, which is why they are not duplicated here.

| | |
| --- | --- |
| Install GuardLink | <https://docs.bugb.io/guardlink/get-started/installation/> |
| Annotate an existing codebase | <https://docs.bugb.io/guardlink/guides/annotate-an-existing-codebase/> |
| Wire up the MCP server | <https://docs.bugb.io/guardlink/guides/wire-up-the-mcp-server/> |
| Review and accept risk | <https://docs.bugb.io/guardlink/guides/review-and-accept-risk/> |
| Link repositories into a workspace | <https://docs.bugb.io/guardlink/guides/link-repositories-into-a-workspace/> |
| Use GuardLink as a library | <https://docs.bugb.io/guardlink/guides/use-guardlink-as-a-library/> |
| Every GAL verb | <https://docs.bugb.io/guardlink/reference/gal/> |
| Every command and flag | <https://docs.bugb.io/guardlink/reference/cli/> |
| Every MCP tool | <https://docs.bugb.io/guardlink/reference/mcp/> |
| Library API | <https://docs.bugb.io/guardlink/reference/api/> |

## Demo

[![Watch the video](https://img.youtube.com/vi/a8wq7dAYtto/0.jpg)](https://www.youtube.com/watch?v=a8wq7dAYtto)

---

## Why GuardLink

Threat models rot. Teams do a session at the start of a project, someone creates a Confluence page, and it's stale by the next sprint. SAST scanners find 200 things with no context about what matters. Pen test reports sit in shared drives. The root cause is always the same: **security knowledge lives outside the code**.

GuardLink fixes this at three levels:

**1. Annotations in code.** Security decisions are structured comments next to the code they describe. When a developer writes a parameterized query, `@mitigates #api against #sqli using #prepared-stmts` lives right above it. When the code changes, the annotation is right there to update. The threat model *is* the code.

**2. AI agents maintain it.** GuardLink integrates with AI coding agents through MCP and behavioral directives. When your agent writes a route handler, it adds `@exposes` and `@mitigates` annotations automatically. The threat model maintains itself because the thing writing the code also writes the security context.

**3. CI enforces it.** `guardlink validate` fails on syntax errors. `guardlink ci --strict` fails on unmitigated exposures and drifted anchors. `guardlink diff --fail-on-new` blocks PRs that introduce new unmitigated exposures. `guardlink sarif` exports to GitHub's Security tab. The threat model becomes a quality gate, not a checkbox.

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

Ready-made workflows are in [`examples/`](examples/): a single-repo GitHub Action
and a two-workflow multi-repo setup with its own
[step-by-step guide](examples/ci/README.md).

---

## AI agent integration

`guardlink init` detects your agent and configures two things:

**MCP server.** Tools to read the threat model, validate annotations, suggest
annotations, and query threats by keyword. The agent can ask "what threats affect
#api?" before writing code that touches the API. Writing an `@accepts` or an
`@entitles` is deliberately not among them: those are decisions a person makes
under their own name.

**Behavioral directive.** A rule injected into your agent's instruction file
(CLAUDE.md, .cursorrules, and the rest) that says: *when writing code that
handles routes, auth, database access, file I/O, or external services, add
GuardLink annotations.*

| Agent | Config file | MCP support |
|-------|------------|-------------|
| Claude Code | `CLAUDE.md` + `.mcp.json` | ✅ Full |
| Cursor | `.cursorrules` + `.cursor/mcp.json` | ✅ Full |
| Windsurf | `.windsurfrules` + `.windsurf/mcp.json` | ✅ Full |
| Cline | `.clinerules` + `.cline/mcp.json` | ✅ Full |
| Codex | `AGENTS.md` | Directive only |
| GitHub Copilot | `.github/copilot-instructions.md` | Directive only |

Every tool the server exposes, with its input schema, is at
[docs.bugb.io/guardlink/reference/mcp/](https://docs.bugb.io/guardlink/reference/mcp/).

---

## Real-world results

We tested GuardLink + Claude Code on [vuln-node.js-express.js-app](https://github.com/SirAppSec/vuln-node.js-express.js-app), a deliberately vulnerable Express.js application with 37 documented vulnerability types.

**In 6 minutes, with no human intervention:**

- 143 annotations across 6 route files
- 29 distinct threats identified with CWE mappings
- 66 unmitigated exposures documented with file:line precision
- 27 of 37 known vulnerabilities detected (73% recall, 81% with partial matches)
- Architecture: 8 assets, 3 data flows, Mermaid diagram with risk heat map
- Cost: ~$0.50 in Haiku tokens

A scanner gives you a list of findings. GuardLink gives you a threat model: assets, threats, controls, data flows, trust boundaries, and the relationships between them. Every exposure traceable to a line of code. Every mitigation documented next to the control it implements. And because it's all in code comments, it updates when the code changes.

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

Seven entry points: `guardlink`, and `guardlink/{parser,init,report,diff,analyzer,mcp}`.
Every exported symbol is documented at
[docs.bugb.io/guardlink/reference/api/](https://docs.bugb.io/guardlink/reference/api/).

---

## Specification

GuardLink is an open specification. The annotation grammar, threat model schema, and conformance levels are defined in the [GuardLink Specification](docs/SPEC.md).

Anyone can build conformant parsers, analyzers, or integrations. This CLI is the reference implementation.

| Level | Name | Capabilities |
|-------|------|-------------|
| L1 | Parser | Parse every annotation type in §3, produce ThreatModel JSON |
| L2 | Analyzer | Coverage stats, unmitigated detection, dangling ref detection |
| L3 | CI/CD | Threat model diffs, change classification, SARIF export |
| L4 | AI-Integrated | MCP server, suggestion engine, agent behavioral directives |

This implementation is **Level 4** conformant.

---

## Heritage

GuardLink builds on the annotation grammar created by [ThreatSpec](https://github.com/threatspec/threatspec) (2015–2020) by Fraser Scott, the first tool to propose continuous threat modeling through code annotations. The core verbs (`@mitigates`, `@exposes`, `@transfers`, `@accepts`) originate from that work.

We extend the specification with severity levels, external references (CWE/CAPEC/OWASP), data flow and trust boundary annotations, data classification, a structured JSON schema, SARIF export, MCP integration for AI agents, and CI/CD enforcement tooling. ThreatSpec had the right idea. Our contribution is making it work in a world where AI writes most of the code.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE). The GuardLink specification is published under CC-BY-4.0.

---

Built by [BugB Technologies](https://bugb.io).
