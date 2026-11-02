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
`cxg scan` runs scanner templates in multiple languages, where templates send
their own requests and declare findings. **`cxg pentest` runs JavaScript probes
only**, in the form `async function cxgProbe(cxg)`. Its engine owns requests,
sessions and proof, and adjudicates candidate findings; a template's own
`confirmed: true` is not trusted proof. Other scanner languages need re-authoring
before they can be used with pentest.

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

## Convert scanner templates to probes

Use repeatable `--from <path>` with explicit `--contract probe` to re-author
existing scanner templates as JS probes. Each path can be a file or a directory,
relative to `--dir` or absolute. Directories are traversed recursively for scanner
source extensions (YAML, Python, JavaScript, TypeScript, Go, Rust, Ruby, shell,
PHP, Java, C/C++, C# and Lua); unrelated files and directory symlinks are skipped.
Explicit symlink inputs are refused. Overlapping paths are deduplicated.

```sh
guardlink translate --contract probe --from scanners/check.py --clipboard
guardlink translate --contract probe --from scanners/ --from extra/check.yaml \
  --headless --agent codex --no-code-graph --format json
```

Conversion works in interactive, clipboard and headless modes, including when
the project has no GuardLink annotations. Context packs and threat/feature scope
can supplement source evidence. Each prompt contains the complete source text
(losslessly JSON-quoted), descriptive header lines, language, source path, byte
count and SHA-256 hash. All source and metadata are explicitly untrusted data;
conversion never imports or executes them. Inputs are limited to 256 templates,
2 MiB per file, 8 MiB total, 4096 directory entries and 32 directory levels.

This is model-assisted re-authoring: preserve test intent and payloads while
replacing independent HTTP clients with documented engine primitives such as
fetch, raw, oracles and page. Declare required capabilities and identity headers,
including `// @attach_scheme: path` and `// @guardlink_threat:`. Preserve the source
threat identity; if absent, the prompt requests the source template id as a
descriptive identity and documents the missing GuardLink link. Response-body
matching alone must not become proof: prefer the matching cxg oracle and submit
candidate findings for engine adjudication. Unsupported capabilities or missing
proof mechanisms need an explanation, never invented APIs or confirmation.

Converted probes stay under `.guardlink/cxg-templates/`; conversion `--out` may
choose a subdirectory within that draft tree. Symlinked output ancestors are
refused. Review and verify the drafts before promoting them into the curated
security-test folder. Authoring instructions do not sandbox the agent's editing
permissions. Conversion happens outside zero-model pentest runs; pentest itself
does not call a model to translate sources. No deterministic YAML converter is
included: even single-request matchers need review against engine proof rules.

Headless conversion runs one author per source, sequentially. JSON results use
`source` instead of `threat`, mapping every input source to changed JS/MJS draft
paths or a failure reason in `failures`:

```json
{
  "version": 1,
  "results": [{
    "source": "/project/scanners/check.py",
    "contract": "probe",
    "templates": ["/project/.guardlink/cxg-templates/checkpy-0123456789ab/check.js"],
    "status": "written"
  }],
  "failures": []
}
```

Missing/unreadable sources and successful author exits without a JS probe are
failures, with `source`, `error` and `exit_code`. Other sources still convert.
A failed author can leave partial draft files, which remain listed with
`status: "failed"`. A written path means a changed file was inventoried, not that
the probe was validated or the threat proved. Interactive and MCP prompt requests
refuse source-read errors before returning or launching an author.

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
JSON file path), `contract`, `from` (array of scanner file/directory paths), `out`, `threat` (array), `feature` (comma-separated),
and `code_graph` (default true). Contract selection, context validation, graph
fallback and scoping match the CLI. The response has `mode: "agent"` and `prompt`.
`from` requires explicit `contract: "probe"` and requests draft conversion only.
