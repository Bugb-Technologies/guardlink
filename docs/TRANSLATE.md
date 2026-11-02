# Template authoring with translate

`guardlink translate` authors templates without executing them. It defaults to
the interactive scanner contract. Scanner proof requirements and AuthorInfo
guidance apply to every scanner prompt.
Existing `--claude-code`, `--codex`, `--gemini`, IDE and clipboard flags still work.

```sh
guardlink translate --context context.json --contract probe --clipboard
guardlink translate --headless --agent codex --contract probe \
  --context context.json --out generated-probes --threat idor \
  --feature Orders --format json
```

`--threat` is repeatable. A bare threat id (with or without `#`) selects every
in-scope exposure of that threat. `idor@src/orders.ts:42` selects just that
exposure, where 42 is the annotation line. Unknown or feature-excluded selections
are errors. Without an explicit selection, headless mode authors unmitigated
exposures. An explicit selection can include mitigated exposures for regression
checks. `--feature` retains its comma-separated feature filtering in every mode.

## Context pack v1

[`translate-context.schema.json`](translate-context.schema.json) defines the
versioned JSON schema. The top-level `version` must be `1`; `threats` contains
one entry per threat or exposure id. An entry's `id` is required; all other fields
are optional. Duplicate ids, unsupported versions, wrong known-field types and
invalid outcome/contract values are refused before an author starts. Unknown
fields at every level are ignored. Files are limited to 2 MiB.

```json
{
  "version": 1,
  "threats": [{
    "id": "idor@src/orders.ts:42",
    "route": {
      "method": "GET",
      "path": "/api/orders/:id",
      "handler": "src/orders.ts:getOrder"
    },
    "parameters": [{ "name": "id", "in": "path", "type": "string", "example": "order-2" }],
    "payload_hints": ["Request an order owned by a second identity"],
    "success_condition": "The attacker reads the victim-owned order",
    "identity": {
      "requirements": ["Two authenticated users with different owned orders"],
      "available": [{ "name": "user-a", "role": "user", "description": "Attacker account" }]
    },
    "codegraph_path": ["src/orders.ts::getOrder", "src/store.ts::readOrder"],
    "sink": "readOrder at src/store.ts:81",
    "prior_attempts": [{ "outcome": "refuted", "description": "Previous request returned 403", "evidence": "Ownership guard rejected user-a" }],
    "target_kind": "web",
    "output_contract": "probe"
  }]
}
```

`route.handler` can name a `file:symbol` or the graph's symbol address.
`codegraph_path` is ordered from entry to sink. Prior attempt outcomes are
`confirmed`, `refuted`, `ambiguous`, `unevaluated` or `failed`.
`target_kind` describes the intended substrate, such as `web`, `electron`,
`local` or `network`. Available identities describe accounts and roles; avoid
putting credentials in authoring context.

The pack path is resolved relative to `--dir` (absolute paths also work).
Only entries matching selected exposures reach the prompt. Context text is
JSON-quoted and marked as untrusted evidence; it grants no execution permission.
Prior outcomes remain supplied claims for the author to verify.

Without `--context`, translate asks the existing optional code-graph adapter for
route and entry-to-sink facts at selected exposure symbols. File-level claims
without a symbol are not assigned to an arbitrary handler. Missing, refused or
insufficient graph answers contribute no pack. No index is built or installed.
`--no-code-graph` or `GUARDLINK_CODEGRAPH=off` disables this lookup.
Graph queries default to 300,000 ms per query batch. Override with
`GUARDLINK_CODEGRAPH_TIMEOUT_MS`, `--code-graph-timeout <ms>`, or MCP
`code_graph_timeout_ms` (a positive integer in milliseconds). Graph errors,
timeouts and unavailable tooling remain optional-input failures: the CLI reports
why the graph pack was skipped on stderr, and headless/MCP JSON includes
`context_graph` with `status`, `reason` and any per-exposure `skipped` reasons.
A partial pack reports which exposures received no facts instead of silently
hiding their lookup failures.

## Output contracts

`--contract scanner` uses the YAML/Python scanner contract. YAML `author` is
an AuthorInfo mapping with a required nonempty `name` string and optional
`email`/`github` strings, never a scalar. Older installed skeleton excerpts are
normalized to this form in the prompt.

Proof must come from the protected resource named by the threat. An anonymous
200 from a root, banner or health endpoint does not prove missing authentication
on another resource. Where possible compare entitled and unauthorized access to
the same resource as a negative control; missing context means unevaluated or
audit-only, rather than inventing endpoints or confirming on a version banner.
`--contract probe` requests JavaScript with `async function cxgProbe(cxg)` and
single-line metadata headers including `@id`, `@vuln_class`, `@severity`,
`@description`, `@requires_auth_count`, `@destructive_priority` and
`// @attach_scheme: path`. Non-HTTP probes also declare `@requires_capability`.
A descriptive `@guardlink_threat` header and the README mapping preserve the
source threat/exposure id. The cxg-managed `@threat_id` and `@exposure_*` evidence
stamps remain reserved for cxg, as its guide requires.

The explicit flag overrides pack `output_contract` requests. With no flag, a
matching pack request chooses the contract; otherwise scanner is the default.
Mixed requests in an interactive prompt require an explicit contract or narrower
scope. Headless mode resolves each exposure separately.

Probe guidance first checks `GUARDLINK_CXG_ROOT/pentest/docs/TEMPLATES.md`
and `GUARDLINK_CXG_ROOT/docs/TEMPLATES.md`, when that override is set. It then
checks the actual installed `~/.cert-x-gen/pentest/docs/TEMPLATES.md` and the
installed template layout. `CERT_X_GEN_HOME` replaces the base home, matching
CXG: the guide is then at
`$CERT_X_GEN_HOME/.cert-x-gen/pentest/docs/TEMPLATES.md`. A missing, unreadable
or empty guide refuses probe authoring before the author agent is started;
probe contracts requested by a context pack follow the same rule. Scanner
reference loading is unchanged apart from normalizing scalar-author skeletons.

## Headless results

`--headless` requires `--agent claude|codex|gemini`. It closes stdin, uses the
agent CLI's non-interactive mode and captures its output without a TTY or
clipboard. It runs one author per exposure, sequentially. The author receives
the project working directory and a per-exposure subdirectory under `--out`
(default `.guardlink/cxg-templates/`). The subdirectory includes a sanitized
threat label and an exposure hash to avoid collisions. The CLI uses the installed
agent's editing permissions; authoring instructions are not an agent sandbox.

Headless stdout is one JSON object (also the default without `--format json`):

```json
{
  "version": 1,
  "results": [{
    "threat": "idor@src/orders.ts:42",
    "contract": "probe",
    "template_dir": "/project/generated-probes/idor-0123456789ab",
    "templates": ["/project/generated-probes/idor-0123456789ab/order-read.js"],
    "status": "written"
  }],
  "failures": []
}
```

`template_dir` is the exact per-exposure directory used by the author. Pass that
directory to `cxg scan --pentest --template-dir`, one exposure at a time; the
pentest runner may not recurse through the parent `--out` directory.
`templates` paths are absolute and list regular template files created or changed
during that exposure's run; README indexes and symlinks are excluded. `no_templates`
means the author exited successfully without writing a template; consult its
README for audit-only explanations. `failed` preserves any partial file list.
Each failure has `threat`, `error` and `exit_code` (null for spawn/file errors).
Preflight errors use `threat: "*"` with empty results. Any author or preflight
failure exits nonzero, including a nonzero agent exit after partial stdout.
An empty candidate scope is an error. Written scanner YAML files undergo an
explicit AuthorInfo check plus `cxg template validate --json --disable-update-check`. CXG must be installed for that schema check; missing
validator, invalid schema, invalid author or validator errors mark the exposure
`failed` and make translate exit nonzero even when the author exited zero.
Foreground scanner agents get the same validation for newly written YAML on
return. MCP/clipboard/IDE workflows return a prompt and cannot validate files an
external author has not yet written. Validation only parses templates; it never
executes them and does not prove their detection logic. Other code templates are
reported as authored, not executed or proven.

## MCP

`guardlink_translate` returns an authoring prompt for the calling agent; it does
not launch another agent. Arguments are `root`, `prompt`, `context` (the same
JSON file path), `contract`, `out`, `threat` (array), `feature` (comma-separated),
`code_graph` (default true), and `code_graph_timeout_ms`. Contract selection, context validation, graph
fallback and scoping match the CLI. The response has `mode: "agent"`, `prompt`,
`context_graph` and the requested absolute `template_dir` (the prompt's output
directory; MCP does not claim files have been written).
