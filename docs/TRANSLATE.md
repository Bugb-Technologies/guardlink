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
    "graph_facts": ["Sink verdict: sinks_reached", "Entry path: getOrder -> readOrder"],
    "sink": "readOrder at src/store.ts:81",
    "prior_attempts": [{ "outcome": "refuted", "description": "Previous request returned 403", "evidence": "Ownership guard rejected user-a" }],
    "target_kind": "web",
    "output_contract": "probe"
  }]
}
```

`route.handler` can name a `file:symbol` or the graph's symbol address.
`codegraph_path` is a connected path; when no sink is classified it may stop at
the exposed symbol. `graph_facts` retains all available route bindings, classified
access, entry paths, sink paths and explicit unknown/withheld verdicts as untrusted
text. A missing sink is not evidence of safety. The ranked annotation worklist
remains withheld when resolution is insufficient; unranked bound-route facts can
still supplement an exposure without inventing a ranking or sink. Prior attempt outcomes are
`confirmed`, `refuted`, `ambiguous`, `unevaluated` or `failed`.
`target_kind` describes the intended substrate, such as `web`, `electron`,
`local` or `network`. Available identities describe accounts and roles; avoid
putting credentials in authoring context.

The pack path is resolved relative to `--dir` (absolute paths also work).
Only entries matching selected exposures reach the prompt. Context text is
JSON-quoted and marked as untrusted evidence; it grants no execution permission.
Prior outcomes remain supplied claims for the author to verify.

Without `--context`, translate asks the existing optional code-graph adapter for
route and entry-to-sink facts at selected exposure symbols, including route and entry facts when no
classified sink is available. File-level claims
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
normalized to this form in the prompt. Ordinary `http[].path` requests use
origin-relative concrete paths such as `/tasks`. Installed skeleton prefixes
`{{BaseURL}}` and `{{RootURL}}` are removed from those path examples. Written
scanner YAML rejects unresolved HTTP-path placeholders rather than trusting an
older validator that accepts strings its HTTP engine cannot substitute. This
path policy does not alter request bodies, headers or the flow engine's own
explicit variable-binding contract.

Every scanner language also declares its exact source reference with
`@guardlink_threat: <threat@file:line>`: `#` comments for YAML/Python/shell,
`//` for JavaScript/Go/Rust, and the language's own syntax elsewhere. Headless scanner drafts receive this header automatically if it is missing,
with shebangs/encoding declarations preserved. Matching headers remain byte-identical;
conflicting headers fail rather than being relabelled. Conversions
can then preserve the source threat rather than falling back to a template id.

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
source threat/exposure id.

For named probe roles use `@requires_identities` as a JSON role-to-profile-name
map. Authenticated values come only from the matching pack's
`identity.available[].name` values. Use the reserved value `"anonymous"` for a
clean guest with no credentials; it is not a captured profile to create or fill.
Only non-anonymous bindings count toward `@requires_auth_count`. For example:

```js
// @requires_identities: {"entitled":"a-member","attacker":"anonymous"}
// @requires_auth_count: 1
```

That example is valid only when `a-member` is supplied by the caller. Role keys
are abstract, but bindings remain exact names so replay can materialize the same
slots without rewriting committed templates. Missing or ambiguous bindings are
not-run/unevaluated; never substitute a same-role identity. An empty map requests
anonymous-only execution. Legacy numeric `@requires_auth_count` declarations
remain supported when no named roster is available. Headless and foreground
probe output checks reject invented names and inconsistent authenticated counts,
without rewriting template bytes. MCP/IDE/clipboard prompts express the same
contract but cannot validate files written later by an external author.

The cxg-managed `@threat_id` and `@exposure_*` evidence
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
Codex is launched with explicit `--sandbox workspace-write`,
`-c 'approval_policy="never"'` and `--add-dir` for the requested output directory.
Commands requiring an exception to that sandbox are denied without prompting.
The launcher does not enable an unrestricted sandbox or an approval bypass.

Headless stdout is one JSON object (also the default without `--format json`):

```json
{
  "version": 1,
  "results": [{
    "threat": "idor@src/orders.ts:42",
    "contract": "probe",
    "template_dir": "/project/generated-probes/idor-0123456789ab",
    "templates": ["/project/generated-probes/idor-0123456789ab/order-read.js"],
    "completion": {"status": "completed", "safety_stops": 2},
    "status": "written"
  }],
  "failures": [],
  "warnings": [{
    "threat": "idor@src/orders.ts:42",
    "safety_stops": 2,
    "message": "Provider reported safety_stops=2; this counter is telemetry, not the provider's completion outcome"
  }]
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
The CLI requests Claude/Gemini JSON or Codex JSONL and requires a recognized
terminal completion. Exit zero alone is insufficient. A parsed author completion
appears as `completion.status` (`completed`, `failed`, `refused`, `safety_stopped`, or
`unknown`), with `safety_stops` when the provider reports it and a failure
`reason` when applicable. Pass/fail follows the provider's outcome (`is_error`,
result subtype, refusal or non-success stop reason), process exit, and template
validation. Missing terminal completion and output over 8 MiB also fail authoring.
Spawn/preflight failures and skipped authors have no completion field.

`safety_stops` is telemetry, independent of completion status. A successful
completion with a positive count can be `written` or `no_templates`; the count
is retained in `results[].completion.safety_stops` and a per-threat `warnings[]`
entry, and the CLI prints that warning on stderr. Headless stdout remains one
JSON object, suitable for saving as `translate.json`. Malformed counter telemetry
is described in `completion.warnings` and the report warnings without turning a
successful provider outcome into a failure. Consumers that previously equated a
positive counter with `completion.status: "safety_stopped"` must now read the
status and counter separately; the version remains 1 and existing fields remain.

An explicit provider safety-stop/refusal outcome still preserves raw partial
paths, fails the batch and skips remaining authors. Provider failures remain
failures even with a positive counter. There is no retry, prompt rewording or
provider fallback to suppress telemetry. Audit-only completion with no templates
remains `no_templates`; tool/source quotations are not treated as author refusals.
CLI relays must preserve terminal structured completion and telemetry rather
than returning only an exit code.
An empty candidate scope is an error. Written scanner YAML files undergo an
explicit AuthorInfo check plus `cxg template validate --json --disable-update-check`. CXG must be installed for that schema check; missing
validator, invalid schema, invalid author or validator errors mark the exposure
`failed` and make translate exit nonzero even when the author exited zero.
The validator receives a temporary child home, removed after use, so older CXG
versions cannot persist updater preferences in the operator's home.
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
