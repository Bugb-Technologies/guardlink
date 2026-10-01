# GuardLink conformance corpus

Machine-readable test cases for anything that reads GuardLink annotations.
[`docs/SPEC.md`](../docs/SPEC.md) is the definition, and every reader conforms to it,
including this repository's parser. This corpus pins that definition to concrete input
and expected output, so a reader written in any language can check that it reads
annotations the way the specification says.

| File | Pins |
|---|---|
| [`flows.json`](flows.json) | SPEC §3.2 `@flows`: endpoint forms, chains, `via` mechanisms, route channels, sidecar attribution and malformed lines. SPEC §3.6, Handler Scope: which route reaches a claim, and which exposures a mitigation covers |

The reference parser runs the whole corpus in `tests/conformance-flows.test.ts`, so a
change to the parser that moves a record cannot ship with a corpus that no longer
describes it.

## Getting it

Pin a released version. Do not track `main`, because a case can change between releases.

- **npm.** The file ships in the `guardlink` package: `node_modules/guardlink/conformance/flows.json`,
  or `require.resolve('guardlink/conformance/flows.json')` from Node.
- **Raw download.** `https://raw.githubusercontent.com/Bugb-Technologies/guardlink/v<version>/conformance/flows.json`.
  Vendor the file into your own test fixtures and record the version you took it from.

`version` in the file is the corpus format version. It changes only when the shape below
changes. New cases can be added without changing it.

## Format

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
