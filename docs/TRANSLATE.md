# Template authoring with translate

`guardlink translate` authors templates without executing them. With no new
options and no available code graph, its interactive scanner prompt is unchanged.
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

## Output contracts

`--contract scanner` keeps the existing YAML/Python scanner contract.
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

Probe guidance reads `pentest/docs/TEMPLATES.md` under `GUARDLINK_CXG_ROOT`, or
`docs/TEMPLATES.md` in an installed template layout. The default root remains
`~/.cert-x-gen/templates/official`. Missing documentation is stated in the prompt;
unsupported bridge APIs must not be invented. Scanner guide/skeleton loading is
unchanged.

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
    "templates": ["/project/generated-probes/idor-0123456789ab/order-read.js"],
    "status": "written"
  }],
  "failures": []
}
```

Paths are absolute and list regular template files created or changed during
that exposure's run; README indexes and symlinks are excluded. `no_templates`
means the author exited successfully without writing a template; consult its
README for audit-only explanations. `failed` preserves any partial file list.
Each failure has `threat`, `error` and `exit_code` (null for spawn/file errors).
Preflight errors use `threat: "*"` with empty results. Any author or preflight
failure exits nonzero, including a nonzero agent exit after partial stdout.
An empty candidate scope is an error. Successful author exit is not template
validation or proof of the threat. Translate never loads or executes templates.

## MCP

`guardlink_translate` returns an authoring prompt for the calling agent; it does
not launch another agent. Arguments are `root`, `prompt`, `context` (the same
JSON file path), `contract`, `out`, `threat` (array), `feature` (comma-separated),
and `code_graph` (default true). Contract selection, context validation, graph
fallback and scoping match the CLI. The response has `mode: "agent"` and `prompt`.
