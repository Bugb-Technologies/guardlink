<div align="center">

<img src=".github/guardlink_banner.png" alt="GuardLink" width="380">

[![npm version](https://img.shields.io/npm/v/guardlink.svg)](https://www.npmjs.com/package/guardlink)
[![CI](https://github.com/Bugb-Technologies/guardlink/actions/workflows/ci.yml/badge.svg)](https://github.com/Bugb-Technologies/guardlink/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

**GuardLink carries design-time threat-modeling decisions into code changes.**
It is an open annotation language (GAL), CLI and MCP server: structured comments
record assets, flows, trust boundaries, threats and security decisions next to
the code they describe, where developers and coding agents can read and update
them in the same change.

Threat modeling starts with design. GuardLink complements tools such as **pytm,
Threagile and Threat Dragon** by keeping implementation decisions connected to
that reasoning as code evolves. It does not replace design workshops or those
tools. The connection is through the team's decisions; GuardLink does not
provide import/export adapters for these tools.

**“Enforce” means checking the recorded model against the team's chosen CI
policy, not demanding zero findings or proving the application secure.** Inherent
threats can remain: the model records mitigations, open exposures, named-person risk
acceptances and dependencies on controls outside the application. Recording a
control does not prove it works.

## What the model records

| Threat-modeling question | GuardLink records |
| --- | --- |
| What are we building? | `@asset`, `@flows`, `@boundary` |
| What can go wrong? | `@threat`, `@exposes` |
| What will we do about it? | `@mitigates`, human-only `@accepts`; `@transfers` and `@assumes` for dependencies and assumptions |
| Did we do a good enough job? | CI validation, verified/unverified/stale claims, and hypotheses to test |

An external control, such as authentication at an API gateway, can be recorded
as an assumption or a dependency rather than invented as application code.
Its effectiveness still needs evidence. Open exposures are hypotheses;
[template authoring](docs/TRANSLATE.md) can turn them into candidate security
tests, which must be reviewed and run separately. `guardlink paths .` also
queries the recorded flow graph for routes from an untrusted entry point to a
sink with no control along the route.

## Install and try it

Requires Node.js 18+.

```bash
npm install -g guardlink
guardlink init --mode inline
```

Initialization creates definitions, configuration and agent integration. The
explicit `inline` mode puts relationships in source comments; the CLI also
supports external `.gal` sidecars.

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
the model. Agent instructions ask it to maintain annotations with code changes;
humans still review the claims and make risk-acceptance decisions.

## Checks in CI

`guardlink validate .` checks model consistency. `guardlink ci .` reports
issues; adding `--strict` makes its checks block the build, including unmitigated
exposures, reproduced exploits, unqualified acceptances and stale mitigation
or acceptance claims. Severity and path filters let teams adopt that gate in stages.
`guardlink diff origin/main --fail-on-new` can block new unmitigated exposures.
These checks operate on recorded claims: missing annotations and untested
assumptions still need review. A verification stamp tracks whether the code
changed since review; it is not proof of a mitigation.

See [gate policy and acceptance rules](docs/GUARDLINK_REFERENCE.md#what-an-acceptance-costs)
and [ready-made CI workflows](examples/ci/README.md).

## Learn more

- [Documentation and walkthroughs](https://docs.bugb.io/guardlink/)
- [Annotation, CLI and configuration reference](docs/GUARDLINK_REFERENCE.md)
- [Agent integration, code graph options, library API and example results](docs/README_DETAILS.md)
- [Open specification and conformance levels](docs/SPEC.md)
- [Contributing](CONTRIBUTING.md) · [Community](https://discord.gg/wyKqPtRveG)

GuardLink builds on [ThreatSpec](https://github.com/threatspec/threatspec) by
Fraser Scott and its contributors, including its core relationship verbs.

Built by [BugB Technologies](https://www.bugb.io). Code: [MIT](LICENSE).
Specification: [CC-BY-4.0](docs/SPEC.md).
