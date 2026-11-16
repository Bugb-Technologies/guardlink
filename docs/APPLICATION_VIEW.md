# Application semantic views

GuardLink owns the semantic model and its projections. The dashboard host owns scope
navigation and collection orchestration; a graph provider owns measured graph facts.
All components bind their output to the selected set rather than scanning sibling
folders independently.

The read-only capability probe is `guardlink application-view --capabilities`.
The collection interface is:

```sh
guardlink application-view ./application --manifest selected.json --json
guardlink application-view ./application --manifest selected.json --member orders --json
guardlink application-view ./application --manifest selected.json --strict
```

The result uses `schema: "guardlink.application-view/v1"`, with `receipt`, `model`,
`diagnostics`, references and flow groups. The receipt uses the shared
`bravos.application-view/v1` schema. Model JSON carries that same receipt at
`application.receipt`; dashboard, Markdown, SARIF and MCP retain it. Existing repository
outputs keep their shapes when no application was selected. `--strict` fails an
incomplete collection; ordinary collection may successfully produce useful partial data.

`--application-manifest selected.json` selects the same inputs for existing parse,
dashboard, report and SARIF commands. A manifest uses either
`guardlink.application-manifest/v1` or the compatible `bravos.workspace-consumer/v1`
shape. It names the application and every expected member:

```json
{
  "schema": "guardlink.application-manifest/v1",
  "name": "shop",
  "members": [
    { "id": "orders", "guardlinkIdentity": "orders-api", "service": "orders", "relativePath": "orders" },
    { "id": "identity", "guardlinkIdentity": "identity", "service": "identity", "relativePath": "identity" }
  ]
}
```

Consumer-manifest `name` is accepted as the member id, and its private absolute `path`
is normalized relative to the manifest's declared `root`. No absolute checkout paths,
credentials, service credentials or graph-store addresses enter the public receipt.
Stable member ids and the declared GuardLink identity are separate: aliases are
explicit, never inferred from tag prefixes. The selection adapter validates containment,
symlinks and duplicate identities before reading member data. Embedded old models are
not silently treated as current source.

The receipt preserves `scope`, `generatedAt`, `inputDigest`, `expectedMemberIds`,
`members`, `completeness`, `revisions` and `tools`. Every revision records `vcs`,
`commit`, `branch`, `detached`, `baseRef`, `baseCommit`, `dirty`, `contentDigest`,
`annotationDigest` and `configDigest`. Non-git lineage is null, not fabricated.
Collection compares source/configuration/ledger inputs before and after gathering.
A supplied `receipt` binds components to its `inputDigest`; GuardLink additionally
records its observed input digest and whether comparable supplied revisions agree.
Unsupported or mismatched input provenance is explicit, never a coherent-fresh claim.

Missing, unreadable or invalid members remain in the expected roster with reason codes.
Known source/annotation subtotals are separate from the overall percentage, which is
unknown when a selected member is unavailable. Definitions retain all declaration
origins; conflicts remain visible and references to ambiguous definitions unresolved.
Semantic annotation ids stay flat. Generated agent configuration identities are scoped
per member, and each member's original verification and hypothesis ledgers are preserved.

Offline artifacts say when the snapshot was gathered. They cannot observe present
freshness. Saved reports keep their assessed receipt; rebuilding a dashboard does not
rewrite or freshly verify old prose. Application SARIF is a cross-repository artifact;
GitHub uploads remain per owning repository and commit.
