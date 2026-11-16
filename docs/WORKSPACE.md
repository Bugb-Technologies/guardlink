# Multi-repo workspaces

This guide now lives at
**<https://docs.bugb.io/guardlink/guides/link-repositories-into-a-workspace/>**.

Linking repositories, what `workspace.yaml` holds, writing flat, globally unique cross-repo `#id`
references, merging per-repo reports, reading the resolved and unresolved
counters, and the CI shape the whole thing is built for.

It moved because the documentation site is generated against a released package
and its commands are verified by running them, which a hand-written file in this
repository cannot promise. Keeping both meant one of them was always wrong.

| Page | |
| --- | --- |
| Link repositories into a workspace | <https://docs.bugb.io/guardlink/guides/link-repositories-into-a-workspace/> |
| `guardlink link-project` and `guardlink merge` | <https://docs.bugb.io/guardlink/reference/cli/reports/> |
| The threat model as an artifact | <https://docs.bugb.io/guardlink/concepts/the-threat-model-artifact/> |

The multi-repo CI workflows stay in this repository, because they ship as files
you copy. See [`examples/ci/`](../examples/ci/).

## Workspace ids and local checks

Definitions use flat ids that are globally unique across all members, for example
`#identity-token-verify`. Reference the exact id the owning member declares:
`@mitigates #orders against #forged-token using #identity-token-verify`.
Do not prepend a repository namespace. Legacy dotted references such as `#identity.token-verify`
remain readable and are reported as legacy; they do not alias a flat definition automatically.

Member names default to directory names, independent of package or remote metadata.
Callers with a service registry can supply its names explicitly:

```sh
guardlink link-project --workspace shop --member frontend=./web --member accounts=./auth
guardlink link-project --add ./billing --name payments --from ./web
```

Existing manifests retain their stored identities. Local discovery matches `this_repo`,
so a member name may differ from its directory name. Checkouts must be immediate siblings
for automatic local validation. Remote registry URLs are descriptive; validation never fetches them.

Local validation resolves references against available sibling checkouts. It distinguishes
known sibling definitions from genuinely undefined ids and names unchecked members.
`guardlink validate ./web --workspace` requires all siblings to be readable and fails on
missing members or unresolved references. A local reference check does not establish
cross-member mitigation coverage: generate per-member reports and merge them for that answer.
Merge computes resolved and unresolved counts from every relationship's reference fields,
including flat control, threat, actor and lifecycle references, even for older reports.
Counts represent reference occurrences per annotation (the same id twice on one annotation counts once).

Parsing a container of linked member checkouts selects only those members and applies
each member's own configuration and coverage scope. Paths remain relative to the
container's actual directory layout. Missing members or members with parse errors produce a named application-incomplete error;
conflicting member lists require reconciliation before an application can be parsed.

A workspace requires at least two members. To unlink a two-member workspace, delete
`.guardlink/workspace.yaml` in both members and remove each generated `## Workspace Context`
section from agent instruction files. To choose another group, run `link-project` with
at least two paths.

## Manifest format and ownership

GuardLink owns `.guardlink/workspace.yaml`. Integrations should create and update it
through `guardlink link-project`, or emit the same YAML manifest shape; integration-specific
state belongs in the integration's own directory. The reader accepts YAML block and flow
collections, quoted scalars, comments, ordinary aliases, and JSON-form YAML documents.
The writer quotes scalars when necessary. Alias expansion is bounded.

A malformed or unreadable manifest produces an error naming the file and the YAML,
shape-validation or filesystem problem. `parse` and `validate` return a nonzero exit
status with that diagnostic, without an uncaught stack trace. An unreadable sibling is
named and its references remain unchecked; `validate --workspace` fails the incomplete check.

If two sibling checkouts declare the same workspace member (for example a feature
checkout beside its main checkout), application membership is ambiguous. GuardLink
reports the member id, both checkout paths and the manifest to inspect, without a
stack trace. Keep one checkout of each member in the application folder by moving
the extra checkout outside it; if they are distinct services, relink them with
unique `--member name=path` identities.

## Selected application snapshots

Parent-folder reads retain the expected member roster and readable member content when
another member is unavailable. The application receipt marks the result partial and file
coverage labels its known subtotal. Use `application-view --strict` to require complete
inputs and resolved references. Explicit manifests reconcile registry names with stored
GuardLink identities; duplicate or out-of-root selections are rejected. See
[Application semantic views](APPLICATION_VIEW.md) for the versioned CLI, MCP, saved-report,
SARIF and offline-merge contract.
