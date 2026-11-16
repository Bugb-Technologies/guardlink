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
incomplete collection or an unresolved, ambiguous or unchecked reference; ordinary collection may successfully produce useful partial data.

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

Current linked parent-folder CLI, library and MCP reads use the same collector.
`guardlink_application_view` also accepts `manifest`, `member` and `capabilities`.
An incomplete `guardlink_parse` MCP reply carries `isError: true` alongside the available
content and receipt; consumers must not discard the receipt and call the result complete.

Native linked-member `parse` and JSON `report` exports include `member_snapshot` with the
native revision and evidence ledgers. Offline `merge` projects those historical inputs
without reading current checkouts. Pass the same `--application-manifest` when registry
ids differ from stored member identities. The result can have complete historical inputs
while its present checkout currency remains unknown. Legacy reports remain readable,
but missing native provenance is labeled partial/unknown and overall coverage withheld.

Flow groups retain direction, both endpoints, mechanism, route and every declaration site.
The cross-member facet counts only uniquely owned endpoints belonging to different members;
a member folder does not create a trust boundary. Source links use the owning remote and
assessed commit, with remote credentials stripped. Attribution is collected separately in
each git member; no application-root git history is invented. A single `dashboard --since`
ref is rejected for application views: comparisons require per-member bases.

Cross-producer digests are not assumed to use the same algorithm. A caller receipt's frozen
`inputDigest` is retained; shared git fields are compared, and full digest comparison is used
only for receipts declaring this GuardLink contract. `observedInputDigest` records the native
collection digest. Capability probes read no source and perform no builds or network calls.
