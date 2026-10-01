# GuardLink conformance corpus

Machine-readable test cases for anything that reads GuardLink annotations.
[`docs/SPEC.md`](../docs/SPEC.md) is the definition, and every reader conforms to it,
including this repository's parser. This corpus pins that definition to concrete input
and expected output, so a reader written in any language can check that it reads
annotations the way the specification says.

| File | Pins |
|---|---|
| [`flows.json`](flows.json) | SPEC §3.2 `@flows`: endpoint forms, chains, `via` mechanisms, route channels, sidecar attribution and malformed lines. SPEC §3.6, Handler Scope: which route reaches a claim, and which exposures a mitigation covers |
| [`boundaries.json`](boundaries.json) | SPEC §3.2 `@boundary`: the directed `from <outer> to <inner>` form and the undirected `between`, `and` and `\|` forms, sidecar attribution and malformed lines. SPEC §6.6 and §6.8: which side of a boundary is outer, declared or inferred, as the SARIF export states it. Which directed boundaries validation rejects because a side resolves to nothing |

The reference parser runs each corpus in its own test, `tests/conformance-flows.test.ts`
and `tests/conformance-boundaries.test.ts`, so a change to the parser or the exporter
that moves a record cannot ship with a corpus that no longer describes it.

## Getting it

Pin a released version. Do not track `main`, because a case can change between releases.

- **npm.** The files ship in the `guardlink` package: `node_modules/guardlink/conformance/flows.json`,
  or `require.resolve('guardlink/conformance/flows.json')` from Node, and the same for `boundaries.json`.
- **Raw download.** `https://raw.githubusercontent.com/Bugb-Technologies/guardlink/v<version>/conformance/flows.json`.
  Vendor the file into your own test fixtures and record the version you took it from.

`version` in each file is that corpus's format version. It changes only when the shape
below changes. New cases can be added without changing it.

## `flows.json` format

```jsonc
{
  "corpus": "guardlink-flows-conformance",
  "version": 1,
  "parse":             [ /* cases */ ],
  "route_attribution": [ /* cases */ ],
  "mitigation_scope":  [ /* cases */ ]
}
```

Every case has an `id` that is unique across the file, a `rule` naming the SPEC section it
pins, an optional `about`, and `files`: a map from repository-relative path to the full file
text. Write every file under an empty project root before you read any of them. Line
numbers are 1-based.

### `parse`

```jsonc
{
  "id": "chain/two-hops",
  "files": { "app/flows.py": "import os\n# @flows #orders -> #billing -> #legacy via ledger_id -- \"Ledger sync\"\n" },
  "expect": {
    "flows": [
      { "source": "#orders", "target": "#billing", "mechanism": "ledger_id", "route": null,
        "description": "Ledger sync",
        "location": { "file": "app/flows.py", "line": 2, "origin_file": null, "origin_line": null } },
      { "source": "#billing", "target": "#legacy", "mechanism": "ledger_id", "route": null, "…": "…" }
    ],
    "malformed": []
  }
}
```

- `flows` is every flow record the files declare, one per hop. Compare it as a multiset,
  or sort both sides by `(location.file, location.line, location.origin_line)` and keep
  hops from one line in order. Absent values are `null`. `route` is
  `{ "method", "path" }` for a route channel and `null` otherwise.
- `malformed` is every `{ file, line }` where a `@flows` line must be reported as
  malformed. A conforming reader reports these lines and does not drop them in silence.
  It may word or classify the report however it likes.

### `route_attribution`

```jsonc
{ "expect": [ { "exposure": { "file": "app/orders.py", "line": 11 },
                "route": { "status": "attributed", "scope": "handler",
                           "route": { "method": "POST", "path": "/pay" } } } ] }
```

For each `@exposes` at `exposure`, `route` is the SPEC §3.6.2 answer. It is one of:

- `{ "status": "attributed", "scope": "handler" | "file" | "asset", "route": { "method", "path" } }`
- `{ "status": "ambiguous", "candidates": [ { "method", "path", "file", "line" }, … ] }`, with candidates in declaration order
- `null`

### `mitigation_scope`

```jsonc
{ "expect": { "open": [ { "file": "app/orders.py", "line": 4 } ], "covered": [] } }
```

Every exposure listed in `open` must have no covering `@mitigates` under SPEC §3.6.1.
Every exposure listed in `covered` must have one.

The `route_attribution` and `mitigation_scope` cases depend on handler scope. That is the
code each annotation is attached to, which SPEC §5.2 defines as the location's `anchor`. A
reader that consumes GuardLink's exported model (`guardlink parse . -o report.json`) already
has `anchor` on every location. A reader that parses source itself has to resolve the
attachment by the same rule.

## `boundaries.json` format

```jsonc
{
  "corpus": "guardlink-boundaries-conformance",
  "version": 1,
  "parse":      [ /* cases */ ],
  "sides":      [ /* cases */ ],
  "validation": [ /* cases */ ]
}
```

Cases have the same `id`, `rule`, `about` and `files` members as in `flows.json`, and
are read the same way.

### `parse`

```jsonc
{
  "id": "directed/two-declared-sides",
  "files": { "app/web.py": "import os\n# @boundary from #orders to #store (#data) -- \"The store trusts every query it is sent\"\n" },
  "expect": {
    "boundaries": [
      { "asset_a": "#orders", "asset_b": "#store", "id": "data", "directed": true,
        "description": "The store trusts every query it is sent",
        "location": { "file": "app/web.py", "line": 2, "origin_file": null, "origin_line": null } }
    ],
    "malformed": []
  }
}
```

- `boundaries` is every boundary record the files declare, compared as a multiset.
  `directed` is `true` for `from <outer> to <inner>`, and then `asset_a` is the outer side
  and `asset_b` the inner side. It is `false` for the `between`, `and` and `|` forms, whose
  side order means nothing. `id` is without its `#`. Absent values are `null`.
- `malformed` is every `{ file, line }` where a `@boundary` line must be reported as
  malformed, as in `flows.json`. A `prose/` case is a line a reader must *not* report as
  malformed: it is about the verb, not an attempt at one.

### `sides`

```jsonc
{ "expect": [ { "boundary": { "file": "app/web.py", "line": 2 },
                "side": { "basis": "declared", "outer": "#orders", "inner": "#store" } } ] }
```

For each `@boundary` at `boundary`, `side` is which side is outer (SPEC §6.6, §6.8). It is
one of:

- `{ "basis": "declared", "outer", "inner" }` — the boundary is directed and says so;
- `{ "basis": "undeclared-endpoint", "outer", "inner" }` — undirected, with exactly one
  side that no `@asset` declares, which is inferred to be outer;
- `{ "basis": "unknown" }` — no side is stated, and a reader must not infer one.

`outer` and `inner` are the sides as written in the annotation. The SARIF export names
the same sides by their `run.graphs[0]` node id, in `properties.boundary` of a
`guardlink/boundary-claim` result and in the boundary edge's `guardlink/side`; map a
node id back through `properties.boundary.a`/`asset_a` and `b`/`asset_b`.

### `validation`

```jsonc
{ "expect": { "unresolved": [ { "file": "app/web.py", "line": 3 } ] } }
```

`unresolved` is every directed `@boundary` that validation must reject because its outer
or inner side resolves to nothing: a `#tag` that no `@asset` defines, or another name that
is neither a declared asset's path nor an endpoint some `@flows` names. A
repository-qualified `#repo.tag` is not checked, and an undirected boundary never is.
