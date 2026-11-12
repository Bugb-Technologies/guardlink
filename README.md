<div align="center">

<img src=".github/guardlink_banner.png" alt="GuardLink" width="380">

[![npm version](https://img.shields.io/npm/v/guardlink.svg)](https://www.npmjs.com/package/guardlink)
[![CI](https://github.com/Bugb-Technologies/guardlink/actions/workflows/ci.yml/badge.svg)](https://github.com/Bugb-Technologies/guardlink/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

**GuardLink is open-source tooling for continuous threat modeling as code.**
Threat models can go stale as code changes. GuardLink keeps the model next to
the implementation, so developers and coding agents can read security decisions
and update them in the same change.

The model is written in **GAL (GuardLink Annotation Language)**: a small,
structured syntax in ordinary source comments. The parser reads that syntax
deterministically into a model of assets, flows, trust boundaries, threats,
mitigations and risk decisions. The CLI and MCP server make that model available
to developers, coding agents and CI.

Start with the system's design and security decisions; record how they apply to
the implementation. `guardlink init` adds instructions to existing or selected
agent instruction files, such as `CLAUDE.md`, `AGENTS.md` and
`.cursor/rules/guardlink.mdc`. These ask the agent to read the model before editing
and update it whenever it changes security-relevant code, such as a route,
query or authentication check. Human review remains part of that workflow.

## What the model records

| Threat-modeling question | GuardLink records |
| --- | --- |
| What are we building? | `@asset`, `@flows`, `@boundary` |
| What can go wrong? | `@threat`, `@exposes` |
| What will we do about it? | `@mitigates`, human-only `@accepts`; `@transfers` and `@assumes` for dependencies and assumptions |
| Did we do a good enough job? | CI validation, verified/unverified/stale claims, and hypotheses to test |

Controls outside the application, such as authentication at a gateway, can be
recorded as dependencies or assumptions. Risk acceptance names the person making
the decision. Open exposures can be turned into candidate security tests through
[template authoring](docs/TRANSLATE.md); review and execution are separate steps.

To examine untrusted input, record its flows through application assets to an
external sink. `guardlink paths .` reports routes in that graph with no recorded
mitigation along the way, citing file and line for each hop. Results cover only
the annotated graph.

## Install and try it

Requires Node.js 18+.

```bash
npm install -g guardlink
guardlink init --mode inline
```

Initialization creates definitions and configuration alongside the agent
instructions. Explicit `inline` mode puts relationships in source comments;
the CLI also supports external `.gal` sidecars.

One example: define the asset, threat and control in
`.guardlink/definitions.ts`, then record the mitigation on the query it describes.

```javascript
// .guardlink/definitions.ts
// @asset CardStore (#cards) -- "Stored card records"
// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89
// @control Parameterized_Query (#params) -- "Bind values separately from SQL"

// src/cards.js
/**
 * @mitigates #cards against #sqli using #params -- "ID is a bound parameter"
 */
export async function findCard(db, id) {
  return db.query('SELECT * FROM cards WHERE id = $1', [id]);
}
```

```bash
guardlink validate .   # check syntax and references
guardlink status .     # inspect coverage, claims and open exposures
```

With a supported coding agent installed, `guardlink annotate "Map the API's
assets, flows and trust boundaries" --mode inline` launches it to help author
the model.

## Checks in CI

CI enforces the team's chosen policy for the recorded model.
`guardlink validate .` checks syntax and references. `guardlink ci .` reports
issues; adding `--strict` blocks the build on unmitigated exposures, reproduced
exploits, unqualified acceptances, drifted anchors, parse errors and stale
mitigation or acceptance claims. Severity and path filters let teams adopt the
gate in stages. `guardlink diff origin/main --fail-on-new` can block new
unmitigated exposures.

`guardlink verify` records hashes of the code associated with reviewed claims.
A matching hash is **verified**; a changed hash is **stale**; a claim without a
comparable record is **unverified**. This tracks code freshness, not whether a
control works. A passing gate means the recorded model meets that policy, not
zero threats or proof that the application is secure.

See [gate policy and acceptance rules](docs/GUARDLINK_REFERENCE.md#what-an-acceptance-costs)
and [ready-made CI workflows](examples/ci/README.md).

## Learn more

- [Documentation and walkthroughs](https://docs.bugb.io/guardlink/)
- [Annotation, CLI and configuration reference](docs/GUARDLINK_REFERENCE.md)
- [Agent integration, code graph options, library API and example results](docs/README_DETAILS.md)
- [Open specification and conformance levels](docs/SPEC.md)
- [Contributing](CONTRIBUTING.md) · [Community](https://discord.gg/wyKqPtRveG)

Built by [BugB Technologies](https://www.bugb.io). Code: [MIT](LICENSE).
Specification: [CC-BY-4.0](docs/SPEC.md).
