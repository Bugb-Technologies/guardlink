# Integration details and example results

[Back to the overview and quick start](../README.md).

These details were moved from the README. For commands, annotation syntax and
configuration, use the [annotation and CLI reference](GUARDLINK_REFERENCE.md).
To install from a clone, run `npm ci`, `npm run build` and `npm link`.

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
GuardLink annotations.* Before a pull request, it has the agent check what the
change added against the base branch — `guardlink validate .`,
`guardlink lint . --since origin/<base>` and `guardlink diff origin/<base>` — and
other tools can add their own pre-PR line to that step with `pre_pr` in
`.guardlink/config.json` rather than writing a second block. `guardlink sync`
rewrites managed instruction blocks between GuardLink's markers; text around
them is kept. `security_tests_dir` in `.guardlink/config.json` selects the single
curated security suite (default root `security/`): only verified templates deliberately
promoted as security test cases belong there. Drafts stay in `.guardlink/cxg-templates/`;
run output and confirmed probes do not enter automatically. Run the configured suite
before review. Its path must stay outside the root `.bravos/`, `.guardlink/` and `.git/`
directories; a missing suite is valid but has no tests. Details: [Agent instruction files](GUARDLINK_REFERENCE.md#agent-instruction-files).

| Agent | Instruction file |
|-------|------------------|
| Claude Code | `CLAUDE.md` |
| Cursor | `.cursor/rules/guardlink.mdc` |
| Windsurf | `.windsurfrules` |
| Cline | `.clinerules` |
| Codex | `AGENTS.md` |
| GitHub Copilot | `.github/copilot-instructions.md` |

`init` also creates a root `.mcp.json` when it is absent. For client setup,
see [Wire up the MCP server](https://docs.bugb.io/guardlink/guides/wire-up-the-mcp-server/).

Every tool the server exposes, with its input schema, is at
[docs.bugb.io/guardlink/reference/mcp/](https://docs.bugb.io/guardlink/reference/mcp/).

**Optional: a code graph for where to start.** When a code graph is installed
(`codegraph-mcp` on `PATH`, or `bravos` with a graph build that publishes route and
attack-surface queries) and the repository has been indexed, `guardlink annotate`
adds a ranked worklist to the agent's prompt: each route handler with its
`METHOD path`, the sink classes it reaches through the call graph (data layer,
exec, template, outbound network, filesystem, crypto), and whether the threat
model covers it yet — unannotated handlers first. An agent in its own editor gets
the same list from `guardlink_worklist`, and `guardlink_reach(symbol)` answers what
one function reaches before it writes an `@exposes` or `@flows`. GuardLink never
installs or builds the graph. Without one — or with `--no-code-graph`, or
`GUARDLINK_CODEGRAPH=off` — the prompt is byte-for-byte what it was, and when the
graph reports that it resolved too few calls to rank honestly, the worklist is
left out and the prompt says why. `GUARDLINK_CODEGRAPH_MCP` points at a specific
`codegraph-mcp` binary.

When the graph also classifies route access (`codegraph_auth_boundary`), each route
in the worklist carries its level (`public`, `authenticated`, `elevated`, or
`unknown` with the reason) and the guard it rests on, and the prompt suggests the
`@boundary` lines the code shows: a caller boundary per route, naming that guard as
what enforces it, and a data, process, egress or filesystem boundary per sink class.
`guardlink validate --code-graph` (or `guardlink_validate` with `code_graph: true`)
checks declared boundaries the other way: a description that says "authenticated"
in front of a route the graph classifies `public`, a route handler reaching a sink
with no boundary to the outside, and a boundary nothing crosses. These are warnings
about claims to verify, never findings.

A graph that also answers `codegraph_reach_check` lets GuardLink measure the declared
agent reach (`@agents`, `@effects`, `@gates`) against the call graph. `validate
--code-graph` then adds three more warnings — `gate-not-on-route` (the annotations say
an effect is gated, and the graph finds a route to it through no gate),
`effect-unreached-by-agent` and `agent-tool-undeclared` (a tool registration nothing
declares) — each worded as a claim to check: the call graph is order-blind and can miss
a call, so none is a finding. The annotate prompt lists the undeclared tools,
`guardlink reach --drafts` prints draft `@agents` and `@effects` lines for them
(printed, never written, never `@accepts` or `@entitles`), and `report --code-graph`
and `dashboard --code-graph` add a measured-route column labelled as a code-graph
measurement. Without a graph, or with one that does not answer the query, nothing changes.

## Example results

The README previously reported a GuardLink + Claude Code run on [vuln-node.js-express.js-app](https://github.com/SirAppSec/vuln-node.js-express.js-app), a deliberately vulnerable Express.js application with 37 documented vulnerability types.

Reported for that run: **6 minutes, with no human intervention:**

- 143 annotations across 6 route files
- 29 distinct threats identified with CWE mappings
- 66 unmitigated exposures documented with file:line precision
- 27 of 37 known vulnerabilities detected (73% recall, 81% with partial matches)
- Architecture: 8 assets, 3 data flows, Mermaid diagram with risk heat map
- Cost: ~$0.50 in Haiku tokens

These are historical observations from one deliberately vulnerable application,
not a benchmark or a guarantee for the current release.

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

The available entry points are listed in [`package.json`](../package.json)'s `exports`.
Every exported symbol is documented in the [library API reference](https://docs.bugb.io/guardlink/reference/api/).

## Demo

[Watch the GuardLink demo](https://www.youtube.com/watch?v=a8wq7dAYtto).
