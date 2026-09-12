# Threat model diagrams — what to open, and for which question

**Every file here is generated. Do not edit any of them.** Regenerate with
`guardlink artifacts .`; check them with `guardlink validate . --artifacts`.

## Start here

These are budgeted: each is selected and drawn only if it comes out at a size a
person can read — at most 12 nodes and 16 edges, which is what fits a diagram
panel at its label size. A file that could not be made to fit is not written, and
is named at the bottom of this page instead.

### One component at a time

`.threats.mmd` answers *what is this exposed to, and what defends it*.
`.flows.mmd` answers *what does it talk to*. They are separate files because
they are separate questions: fusing the two planes onto one canvas is what turns
a small neighbourhood into a hairball.

| File | What it shows |
|---|---|
| [`agent-launcher.threats.mmd`](by-asset/agent-launcher.threats.mmd) | #agent-launcher only — its own threats and controls, narrowed to high and critical (8 lower-severity claim(s) omitted to keep it readable) |
| [`agent-launcher.flows.mmd`](by-asset/agent-launcher.flows.mmd) | #agent-launcher and its flow neighbourhood, grown until the drawing stopped fitting — 19 neighbour(s) one hop out are not shown |
| [`blame.threats.mmd`](by-asset/blame.threats.mmd) | #blame only — its own threats and controls |
| [`blame.flows.mmd`](by-asset/blame.flows.mmd) | #blame and its flow neighbourhood, grown until the drawing stopped fitting — 23 neighbour(s) one hop out are not shown |
| [`cli.threats.mmd`](by-asset/cli.threats.mmd) | #cli only — its own threats and controls, narrowed to high and critical (13 lower-severity claim(s) omitted to keep it readable) |
| [`cli.flows.mmd`](by-asset/cli.flows.mmd) | #cli and its flow neighbourhood, grown until the drawing stopped fitting — 17 neighbour(s) one hop out are not shown |
| [`dashboard.threats.mmd`](by-asset/dashboard.threats.mmd) | #dashboard only — its own threats and controls |
| [`dashboard.flows.mmd`](by-asset/dashboard.flows.mmd) | #dashboard and its flow neighbourhood, grown until the drawing stopped fitting — 10 neighbour(s) one hop out are not shown |
| [`diff.threats.mmd`](by-asset/diff.threats.mmd) | #diff only — its own threats and controls |
| [`diff.flows.mmd`](by-asset/diff.flows.mmd) | #diff and its flow neighbourhood, grown until the drawing stopped fitting — 12 neighbour(s) one hop out are not shown |
| [`gate.threats.mmd`](by-asset/gate.threats.mmd) | #gate only — its own threats and controls |
| [`gate.flows.mmd`](by-asset/gate.flows.mmd) | #gate and its flow neighbourhood, grown until the drawing stopped fitting — 21 neighbour(s) one hop out are not shown |
| [`init.threats.mmd`](by-asset/init.threats.mmd) | #init only — its own threats and controls |
| [`init.flows.mmd`](by-asset/init.flows.mmd) | #init and its flow neighbourhood, grown until the drawing stopped fitting — 25 neighbour(s) one hop out are not shown |
| [`llm-client.threats.mmd`](by-asset/llm-client.threats.mmd) | #llm-client only — its own threats and controls, narrowed to high and critical (13 lower-severity claim(s) omitted to keep it readable) |
| [`llm-client.flows.mmd`](by-asset/llm-client.flows.mmd) | #llm-client and its flow neighbourhood, grown until the drawing stopped fitting — 12 neighbour(s) one hop out are not shown |
| [`mcp.threats.mmd`](by-asset/mcp.threats.mmd) | #mcp only — its own threats and controls, narrowed to high and critical (12 lower-severity claim(s) omitted to keep it readable) |
| [`mcp.flows.mmd`](by-asset/mcp.flows.mmd) | #mcp and its flow neighbourhood, grown until the drawing stopped fitting — 20 neighbour(s) one hop out are not shown |
| [`merge-engine.threats.mmd`](by-asset/merge-engine.threats.mmd) | #merge-engine only — its own threats and controls |
| [`merge-engine.flows.mmd`](by-asset/merge-engine.flows.mmd) | #merge-engine and its flow neighbourhood, grown until the drawing stopped fitting |
| [`parser.threats.mmd`](by-asset/parser.threats.mmd) | #parser only — its own threats and controls, narrowed to high and critical (27 lower-severity claim(s) omitted to keep it readable) |
| [`parser.flows.mmd`](by-asset/parser.flows.mmd) | #parser and its flow neighbourhood, grown until the drawing stopped fitting — 10 neighbour(s) one hop out are not shown |
| [`report.threats.mmd`](by-asset/report.threats.mmd) | #report only — its own threats and controls |
| [`report.flows.mmd`](by-asset/report.flows.mmd) | #report and its flow neighbourhood, grown until the drawing stopped fitting — 21 neighbour(s) one hop out are not shown |
| [`report-metadata.flows.mmd`](by-asset/report-metadata.flows.mmd) | #report-metadata and its flow neighbourhood, grown until the drawing stopped fitting — 22 neighbour(s) one hop out are not shown |
| [`sarif.threats.mmd`](by-asset/sarif.threats.mmd) | #sarif only — its own threats and controls |
| [`sarif.flows.mmd`](by-asset/sarif.flows.mmd) | #sarif and its flow neighbourhood, grown until the drawing stopped fitting — 21 neighbour(s) one hop out are not shown |
| [`suggest.threats.mmd`](by-asset/suggest.threats.mmd) | #suggest only — its own threats and controls |
| [`suggest.flows.mmd`](by-asset/suggest.flows.mmd) | #suggest and its flow neighbourhood, grown until the drawing stopped fitting — 10 neighbour(s) one hop out are not shown |
| [`tui.threats.mmd`](by-asset/tui.threats.mmd) | #tui only — its own threats and controls |
| [`tui.flows.mmd`](by-asset/tui.flows.mmd) | #tui and its flow neighbourhood, grown until the drawing stopped fitting — 22 neighbour(s) one hop out are not shown |
| [`workspace-config.threats.mmd`](by-asset/workspace-config.threats.mmd) | #workspace-config only — its own threats and controls |
| [`workspace-link.flows.mmd`](by-asset/workspace-link.flows.mmd) | #workspace-link and its flow neighbourhood, grown until the drawing stopped fitting — 31 neighbour(s) one hop out are not shown |

### One trust line at a time

| File | What it shows |
|---|---|
| [`agent-boundary.mmd`](by-boundary/agent-boundary.mmd) | the Trust boundary at process spawn between agent-launcher and agentprocess, and what flows across it |
| [`llm-api-boundary.mmd`](by-boundary/llm-api-boundary.mmd) | the Trust boundary at external API call between llm-client and llmprovider, and what flows across it |
| [`nvd-api-boundary.mmd`](by-boundary/nvd-api-boundary.mmd) | the Trust boundary at external API between llm-client and nvd, and what flows across it |
| [`cli-input-boundary.mmd`](by-boundary/cli-input-boundary.mmd) | the Trust boundary at CLI argument parsing between cli and userinput, and what flows across it |
| [`git-boundary.mmd`](by-boundary/git-boundary.mmd) | the Trust boundary at git command execution between diff and gitrepo, and what flows across it |
| [`mcp-boundary.mmd`](by-boundary/mcp-boundary.mmd) | the Trust boundary at MCP protocol between mcp and mcpclient, and what flows across it |
| [`mcp-tool-boundary.mmd`](by-boundary/mcp-tool-boundary.mmd) | the Trust boundary at tool argument parsing between mcp and mcpclient, and what flows across it |
| [`fs-boundary.mmd`](by-boundary/fs-boundary.mmd) | the Trust boundary between parser and disk I/O between parser and filesystem, and what flows across it |
| [`tui-input-boundary.mmd`](by-boundary/tui-input-boundary.mmd) | the Trust boundary at interactive input between tui and userinput, and what flows across it |

## The whole model in one frame

Correct, current, and — past about a dozen components — not readable. Kept
because on a small repository they are the right picture, and listed with their
size so you know which you are about to open.

| File | What it shows | Size |
|---|---|---|
| [`threat-graph.mmd`](threat-graph.mmd) | Every component, the threats declared on it, and the controls that answer them. | 150 edges — **past the readable size** |
| [`dataflow.mmd`](dataflow.mmd) | Every `@flows` between components, with trust boundaries drawn as zones. | 164 edges — **past the readable size** |
| [`attack-surface.mmd`](attack-surface.mmd) | Exposures per component, worst first. | 0 edges |

## One feature at a time

- [`by-feature/dashboard.mmd`](by-feature/dashboard.mmd) — the threat graph narrowed to `@feature "Dashboard"`. **Partial by construction**: a node it does not show is one that feature does not touch, not one the project lacks.
- [`by-feature/mcp-integration.mmd`](by-feature/mcp-integration.mmd) — the threat graph narrowed to `@feature "MCP Integration"`. **Partial by construction**: a node it does not show is one that feature does not touch, not one the project lacks.

## Also here

- [`MANIFEST.json`](MANIFEST.json) — per-artifact size, the annotation hash each was built from, and whether anything will draw it.
- [`../model.json`](../model.json) — the whole parsed model, canonically ordered. Every claim is in it, whether or not a diagram could show it.
- [`README.md`](README.md) — how staleness and drawability are checked, and how to resolve a merge conflict in this directory.

## Components with no threat diagram

- `report-metadata` — declares no `@exposes`, `@mitigates`, `@confirmed` or `@accepts`, or carries too many to draw legibly even narrowed to high and critical. Its claims, if any, are in `../model.json`.
- `workspace-link` — declares no `@exposes`, `@mitigates`, `@confirmed` or `@accepts`, or carries too many to draw legibly even narrowed to high and critical. Its claims, if any, are in `../model.json`.

## Components with no flow diagram

- `workspace-config` — declares no `@flows` or `@boundary`, so it has no neighbourhood to draw.

---

Generated by guardlink@2.0.0 from annotation hash `sha256-v3:85be6b3207b3d6aec41e498d2a333a3662d08af23628dc76dc3000142784729f`. If that
differs from what `guardlink status .` reports, everything here is stale —
regenerate rather than trusting it.
