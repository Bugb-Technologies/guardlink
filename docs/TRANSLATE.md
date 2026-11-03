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

## Convert scanner templates to probes

Use repeatable `--from <path>` with explicit `--contract probe` to re-author
existing scanner templates as JS probes. Each path can be a file or a directory,
relative to `--dir` or absolute. Directories are traversed recursively for scanner
source extensions (YAML, Python, JavaScript, TypeScript, Go, Rust, Ruby, Perl, shell,
PHP, Java, C/C++, C# and Lua, including `.bash` and `.cxx` variants); unrelated files and directory symlinks are skipped.
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
threat identity exactly, including any leading `#` and complete `@file:line`
exposure suffix. The parsed `threat_ref` is included alongside the source text;
it must be copied unchanged into exactly one `// @guardlink_threat:` header.
Never replace an exposure reference with a bare threat id. If absent, the prompt
requests the source template id as a
descriptive identity and documents the missing GuardLink link. Response-body
matching alone must not become proof: prefer the matching cxg oracle and submit
candidate findings for engine adjudication. Unsupported capabilities or missing
proof mechanisms need an explanation, never invented APIs or confirmation.
Context rows and named identity bindings are scoped to the source's exact threat
reference, including during annotation-free conversion. A profile supplied for
another exposure is unavailable; a source without a threat link cannot borrow
profile bindings from unrelated local annotations.

Each conversion also writes `conversion.json` in its draft output directory:

```json
{
  "version": 1,
  "sources": [{
    "source": "/project/scanners/check.py",
    "threat_ref": "idor@src/orders.ts:42",
    "probes": [{
      "file": "check.js",
      "oracle": "engine.cross_identity_overlap",
      "rationale": "Compare the same victim-owned object through entitled and attacker arms",
      "prerequisites": ["entitled identity", "attacker identity"]
    }]
  }]
}
```

Choose the matching oracle from the installed guide and use its actual request,
payload, capability and evidence contract in the probe. Preserve an existing
source oracle when supported; do not replace it with a body matcher. An alias may
be mapped to the engine's canonical class only when it describes the same test.
Do not rename an unrelated check merely to obtain confirmation. For example,
anonymous-only response matching does not establish a cross-identity control.
If no matching oracle or prerequisite is available, replace `probes` with a
concrete `unsupported_reason`. This fails conversion with that reason instead
of silently presenting an inevitably ambiguous probe as ready.

Plans are bounded to 64 KiB, 256 source/probe entries and 64 prerequisites per
probe. They must name exactly the written probe files without duplicates.
The plan is an author's declaration for review, not engine proof or runtime API
validation. Only subsequent execution and engine adjudication establish a verdict.
For older or standalone sources with no threat header, `threat_ref` stays `null`;
the descriptive template-id fallback remains available with an attribution warning.

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
    "threat_ref": "idor@src/orders.ts:42",
    "template_dir": "/project/.guardlink/cxg-templates/checkpy-0123456789ab",
    "templates": ["/project/.guardlink/cxg-templates/checkpy-0123456789ab/check.js"],
    "status": "written"
  }],
  "failures": []
}
```

Missing/unreadable sources and successful author exits without a JS probe are
failures, with `source`, `error` and `exit_code`. Other sources still convert.
A failed author can leave partial draft files, which remain listed with
`status: "failed"`. Headless conversion checks every changed JS/MJS probe against
its source's exact threat reference. A missing, duplicated or changed header
fails that source even when the author exits zero; the failure names the file
and expected/observed references. Drafts remain available for review. Conflicting
source references are refused before authoring. Interactive and MCP prompts
require the same exact-copy check before the author reports success; MCP itself
returns a prompt and cannot inspect files written after that response.
A written path means a changed file was inventoried and any existing source
threat reference was preserved; probe validation and threat proof are separate.
Interactive and MCP prompt requests
refuse source-read errors before returning or launching an author.

Conversion JSON results additionally include the exact source `threat_ref` and
`proof_plan`. Its status is `declared`, `unsupported`, `missing` or `invalid`.
Only `declared` can yield a `written` conversion. Other statuses produce a
source failure and a nonzero CLI exit, including after an author exits zero.
Unsupported reasons, declared oracle names, rationale and prerequisites remain
visible in the result. Non-conversion scanner/probe authoring keeps its existing
result fields and `no_templates` behavior. See the
[regression review](TRANSLATE_REGRESSION_CHECK.md) for the compatibility audit.

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
For source conversions, warnings use `source` instead of `threat`, matching the
result and failure identities.

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
JSON file path), `contract`, `from` (array of scanner file/directory paths), `out`, `threat` (array), `feature` (comma-separated),
`code_graph` (default true), and `code_graph_timeout_ms`. Contract selection, context validation, graph
fallback and scoping match the CLI. The response has `mode: "agent"`, `prompt`,
`context_graph` and the requested absolute `template_dir` (the prompt's output
directory; MCP does not claim files have been written).
`from` requires explicit `contract: "probe"` and requests draft conversion only.
