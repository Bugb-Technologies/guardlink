# Translate conversion regression review

This review compares conversion with its context-pack base, using source history,
the existing contracts and regression tests. Conversion is authoring only: it
cannot establish an exploit verdict or promote an unverified template.

## Proof and attribution

The scanner-to-probe handoff preserves a scanner's complete `guardlink_threat`
value in the probe header, review manifest and JSON `threat_ref`. Template ids
remain descriptive when the source has no threat header; they are not recovered
exposure references. The source identity check added by
[`b7e33bc`](https://github.com/Bugb-Technologies/guardlink/commit/b7e33bc1492c4b825108564745bad6eef0dcaa30)
already refused shortened, changed and missing probe headers. The remaining gap
was the preceding scanner authoring step and the absence of a proof-route review.

Oracle availability belongs to the installed engine. The public
[proof registry](https://github.com/Bugb-Technologies/cert-x-gen/blob/fc9ce0f15d37e5777587f5ac8b69bec65621dd88/pentest/mutator.py)
distinguishes unsupported classes from registered predicates with no observed
signal. In that inspected revision, generic `sensitive_data_exposure` and
anonymous-only missing-authentication are not registered confirmation routes.
Cross-identity proof requires engine-observed overlap, while SQL injection uses
engine-owned SQL oracles. A sensitive-looking body or an anonymous 200 alone
cannot supply either proof. The
[authoring guide](https://github.com/Bugb-Technologies/cert-x-gen/blob/fc9ce0f15d37e5777587f5ac8b69bec65621dd88/pentest/docs/TEMPLATES.md)
describes those evidence and identity prerequisites; the
[class-oracle implementation](https://github.com/Bugb-Technologies/cert-x-gen/blob/fc9ce0f15d37e5777587f5ac8b69bec65621dd88/pentest/class_oracles.py)
and [dispatch/stamping code](https://github.com/Bugb-Technologies/cert-x-gen/blob/fc9ce0f15d37e5777587f5ac8b69bec65621dd88/pentest/js_engine.py)
show why template assertions cannot substitute for engine observations.

Conversion therefore requires a review plan naming the matching installed oracle,
its rationale and prerequisites, or a concrete unsupported reason. GuardLink
validates the plan's shape and file/source correspondence. It does not duplicate
the engine's predicate registry, certify a declared API, relabel an unrelated
vulnerability, or trust the plan as proof. This preserves the original separation
between authoring, engine execution/adjudication, and curated promotion.

## Behavior audit

The original conversion intent and constraints are recorded in
[`7e2bdc6`](https://github.com/Bugb-Technologies/guardlink/commit/7e2bdc6)
and [the translate contract](TRANSLATE.md). The context/guide/scanner behavior is
owned by [the context-pack change](https://github.com/Bugb-Technologies/guardlink/pull/90),
including its [guide and validation fix](https://github.com/Bugb-Technologies/guardlink/commit/2a326db).

| Surface altered or added relative to the base | Original purpose and disposition |
| --- | --- |
| Repeatable `--from` and MCP `from` | New source-authoring input; existing interactive, clipboard, IDE and headless flags remain. Explicit probe contract prevents scanner/probe contract confusion. |
| Annotation-free conversion | External scanner sources can be re-authored without a local threat model. Ordinary threat translation still requires annotations and keeps feature/threat selection semantics. |
| File/directory loading | Preserve complete UTF-8 source and metadata as untrusted data. Overlaps are deduplicated, directory symlinks/unrelated files skipped, explicit symlinks and empty/unsupported inputs refused. The scanner loader's `.pl`, `.bash` and `.cxx` variants exposed missing conversion inputs; those are added without removing any accepted extension. File/count/depth/byte limits remain documented. |
| Conversion `--out` | Restricted to the translate draft tree as required by the conversion contract. Symlink ancestors and escapes fail. Ordinary authoring output paths remain governed by the base contract. No curated directory is created or populated. |
| Probe guidance | Engine-owned requests, capabilities, exact source refs and class-appropriate proof were already intended. Guidance now explicitly rejects body-only proof, preserves an existing supported oracle and requires a proof plan or unsupported reason. Reserved trusted stamps remain engine-owned. |
| Source identity | Exact `#` spelling and exposure suffix are preserved; conflicting source identities fail. Missing source headers retain the template-id fallback, with `threat_ref: null` and an unlinked-attribution warning rather than an invented threat link. |
| Headless iteration/directories | Existing per-exposure sanitization/hash and sequential execution are preserved. Conversion adds equivalent per-source directories; `template_dir` still identifies the actual generated directory. |
| Existing report fields | `version`, threat-mode `threat`, `contract`, `template_dir`, `templates`, `status`, and failure `error`/`exit_code` remain. Conversion uses `source` and adds `threat_ref`/`proof_plan`; production consumption remains in the CLI. The result type exposes both identity variants. |
| Written-file inventory | Regular changed files remain inventory, never executed proof. Conversion accepts JS/MJS only; README/manifest and symlinks are excluded. Partial output remains visible on failure. |
| Successful conversion | Deliberately tightened: JS output alone is insufficient. Missing, invalid or unsupported plans fail with retained drafts and a reason. Existing positive stub-author tests now supply review plans while keeping their original file, attribution and no-execution assertions. |
| Empty scope/error text | The human message generalizes “No in-scope translate exposure candidates” to “No in-scope translate candidates” because source inputs need no exposure. Empty scope still fails. |
| Exit/error paths | Existing agent/spawn/nonzero/partial-output failure semantics remain. Source read, identity, plan and unsupported-route failures also exit nonzero. Non-conversion `no_templates` is retained; a conversion producing no JS remains failed, with an explicit unsupported reason preferred when supplied. |
| Context and graph | Context schema, scoping, optional graph lookup, deadlines, skip/partial status and guide refusal remain owned by the base and covered by its regression suite. No graph query or model call is added to pentest execution. |
| Scanner authoring | No scanner output contract, author-schema check or protected-resource proof rule is removed. The default scanner prompt compatibility check remains relative to the base's deliberate safety additions. |
| Instruction/model artifacts | Regenerated because annotations changed; managed stamps reflect the parsed source. No agent entitlement or risk acceptance is added. |

## Test/assertion review

One existing test is replaced and renamed: the browser-measured counter case
no longer pins the *current* repository model's numeric geometry.
Its [history](https://github.com/Bugb-Technologies/guardlink/commits/fm/gl-translate-convert/tests/query-views.test.ts)
shows repeated edge-count updates whenever annotations changed. Combining
independent valid annotations reproduced 111 versus the expected 110; this was
not a counter regression.

The replacement uses frozen Mermaid input with independently measured SVG counts.
It retains the exact 35/110 and 49/216 node/link observations and strengthens the
check with source hashes, both graphs' edge counts and cluster counts. Refresh
instructions require a browser measurement, not the counter under test. Live
repository coverage remains in `graph-completeness` and `dashboard-system`; the
other graph view, budget, artifact and generated-output tests remain unchanged.

The existing conversion tests keep their original assertions and now declare a
review plan when expecting success. Added regressions cover absent proof plans,
explicit unsupported reasons, exact scanner identity in output, unlinked legacy
sources, malformed/oversized/symlinked plans, duplicate/escaping/unlisted files,
and the original exact-header checks. Non-conversion schema, graph, guide,
headless argv/output and scanner-validation tests are retained.

The public [scanner extension filter](https://github.com/Bugb-Technologies/cert-x-gen/blob/fc9ce0f15d37e5777587f5ac8b69bec65621dd88/src/template/engine.rs)
also provides the input-language check: directory conversion now covers Perl and
the Bash/C++ extension variants that were previously missed. The filter excludes
JSON, so the review manifest is not a runnable scanner template. GuardLink's own
inventory likewise excludes it.

Combined-branch evidence and final validation are recorded in the pull request's
**Regression check** section, with the exact sibling revisions tested.
