# .guardlink/ — what this is

You are looking at a **GuardLink** threat model. It is a set of security facts that
developers recorded next to the code they describe — what each component is exposed to,
what mitigates it, how data flows between components — parsed into a queryable model.

**If you are an AI coding agent: read this file before inferring security context from
the source.** The model already answers most of what you would otherwise guess at, and it
records decisions that are not visible in the code, such as which risks a human has
accepted.

This file is generated. Run `guardlink sync` to refresh it; do not edit it by hand.

Current model: 353 annotations · 16 assets · 15 threats · 12 controls · 67 exposures · 88 flows
Content hash: `sha256-v1:21f5e96f6d9b6bafdeb5ce04253995f7b746dd718c640782fd6321602d879710` — identical hash means identical model.

---

## Start here: one real question, answered end to end

**"I am about to edit `src/auth/login.ts`. What do I need to know?"**

With the MCP server connected:

```
guardlink_context(file: "src/auth/login.ts")
```

Without it, from a shell:

```sh
guardlink parse . --format json    # or: guardlink status .
```

The answer tells you the annotations declared in that file with line numbers, the assets
they name, what those assets are exposed to, and which controls the file is expected to
uphold.

**Read the empty answer carefully.** `guardlink_context` reports *which kind* of empty it
found, and they mean opposite things:

| `status` | Meaning |
|---|---|
| `annotated` | It has annotations. |
| `scanned_without_annotations` | Parsed, genuinely clean. Nothing to know. |
| `not_scanned` | The parser never read this file. Its annotations, if any, were **not** considered. |
| `not_found` | Nothing at that path. |

Treating `not_scanned` as "clean" is the single easiest way to draw a wrong conclusion
from this model.

---

## What is in this directory

| Path | What it is |
|---|---|
| `definitions.ts` | **Definitions.** Every `@asset`, `@threat` and `@control`, each with a `#id`. Read this first — it is the vocabulary everything else references. |
| `config.json` | Project name, language, which files are scanned, and the annotation mode. |
| `prompt.md` | Project description used when generating threat reports. |
| `threat-reports/` | Saved AI threat analyses, if any have been generated. |
| `model.json` | The whole parsed model as JSON, canonically ordered. Generated. |
| `graph/` | Mermaid diagrams of the model, plus a MANIFEST. Generated — see below. |

## Annotation mode in effect

**inline** — annotations live in source-file comments.

Put annotations in the comment syntax of the file you are editing — the doc-block of
the function or module they describe:

```ts
/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "parameterized via pg"
 */
export function login(email: string) { … }
```

**Definitions go in `definitions.ts`, always — in both modes.** Reuse existing `#id`s; never
redefine one. If you need a new asset or threat, add it there first, then reference it.

### The grammar

One annotation per line. Everything after `--` is a quoted description and is optional but
almost always worth writing. `[severity]` is optional and is one of `critical`, `high`,
`medium`, `low` (or `P0`–`P3`); when omitted on an `@exposes`, it inherits the threat's
declared severity. External refs like `cwe:CWE-89` are **optional**, may be repeated, and go
after the severity — the `scheme:value` shape is all that is required, so `owasp:A03` and
`cve:CVE-2021-44228` work too.

Assets are referenced as `#id` or as a `Dotted.Path`; both resolve to the same node.

**Definitions** — only in `definitions.ts`:

```
@asset   <Dotted.Path> (#id) -- "what it is"
@threat  <Name> (#id) [severity] cwe:CWE-89 -- "what can go wrong"
@control <Name> (#id) -- "what defends against it"
```

**Relationships** — in source (or in `.gal` blocks), never in the definitions file:

| Verb | Shape |
|---|---|
| `@exposes` | `@exposes <asset> to <threat> [severity] cwe:CWE-89 -- "why"` |
| `@mitigates` | `@mitigates <asset> against <threat> using <control> -- "how"` |
| `@confirmed` | `@confirmed <threat> on <asset> [severity] cwe:CWE-89 -- "evidence"` |
| `@flows` | `@flows <A> -> <B> via <mechanism> -- "what moves"` — chains allowed: `A -> B -> C` |
| `@boundary` | `@boundary between <A> and <B> (#id) -- "what changes across it"` |
| `@transfers` | `@transfers <threat> from <A> to <B> -- "who owns it now"` |
| `@validates` | `@validates <control> for <asset> -- "the test that proves it"` |
| `@audit` | `@audit <asset> -- "what a human needs to look at"` |
| `@owns` | `@owns <team> for <asset> -- "who reviews changes here"` |
| `@handles` | `@handles <pii\|phi\|financial\|secrets\|internal\|public> on <asset> -- "what data"` |
| `@assumes` | `@assumes <asset> -- "what must hold for this to be safe"` |
| `@feature` | `@feature "Name" -- "what it groups"` |
| `@comment` | `@comment -- "context that fits no other verb"` |
| `@accepts` | `@accepts <threat> on <asset> -- "why"` — **human only, never write this** |

Two notes that catch people out. `@confirmed` and `@exposes` take their arguments in
**opposite orders** — exposes is asset-then-threat, confirmed is threat-then-asset. And a
cross-repo tag such as `#other-repo.component` must be **quoted** —
`@flows "#other-repo.tokens" -> #api via header` — because an unquoted `#id` may not contain
a dot.

Write coupled blocks, not lone facts: a risk plus the control or audit that answers it, plus
the flow that gives it context.

**The complete reference is `docs/GUARDLINK_REFERENCE.md`** — every verb, every alias, the conformance
levels, and worked examples per language. Read it before inventing syntax.

**Never write `@accepts`.** Accepting a risk is a human governance decision. If you find a
risk with no control, write `@exposes` to record it and `@audit` to flag it for review.

---

## Asking questions without MCP

```sh
guardlink status .                       # coverage, counts, unmitigated exposures
guardlink parse . --format json          # the whole model as JSON
guardlink validate .                     # syntax errors and dangling #id references
guardlink report . --format md           # human-readable threat model report
guardlink diff HEAD~1                    # what your change did to the model
guardlink dashboard .                    # interactive HTML view
```

## Asking questions with MCP

The MCP server exposes the model as tools. The ones worth knowing by name:

| Tool | Use it when |
|---|---|
| `guardlink_context(file)` | You opened or are about to edit a file. |
| `guardlink_graph(from, depth, direction)` | You are about to change a shared component and need blast radius. |
| `guardlink_lookup(query)` | You have a specific question. See the query forms below. |
| `guardlink_validate` | Before you finish. |
| `guardlink_diff(ref)` | After a change — did I make this worse? |
| `guardlink_status` | Cold start on an unfamiliar repo. |

`guardlink_lookup` understands a fixed set of named forms and **refuses anything else
rather than guessing**. Send it a deliberately bad query and it returns the full list.
Representative forms:

```
unmitigated                     confirmed                  features
asset <id>                      threat <id>                control <id>
threats for <asset>             exposures for <asset>      mitigations for <asset>
flows into <asset>              flows from <asset>         boundary for <asset>
owner of <asset>                handles pii                assumptions for <asset>
audits [for <asset>]            validations for <asset>    comments [for <file>]
cwe:CWE-89                      owasp:A03                  CWE-89
```

Concretely, in this project: `asset #parser`, `threat #path-traversal`, `cwe:CWE-22`.

### Enabling the MCP tools

A `.mcp.json` at the project root configures this automatically for clients that
auto-discover it, such as Claude Code. If your client does not, point it at
`guardlink mcp` over stdio.

---

## The generated graph

```sh
guardlink artifacts .            # (re)write model.json and graph/
guardlink validate . --artifacts # fail if any of them is stale
```

| File | Shows |
|---|---|
| `graph/threat-graph.mmd` | Assets, the threats they are exposed to, the controls that mitigate them. |
| `graph/dataflow.mmd` | `@flows` between components, with trust boundaries. |
| `graph/attack-surface.mmd` | Entry points and what is reachable from them. |
| `graph/by-feature/<name>.mmd` | The threat graph narrowed to one `@feature`. |
| `graph/MANIFEST.json` | Size and source hash of each artifact. |

These are Mermaid, and readable as plain text without rendering. Each opens with a
`%%` header naming the `annotation_hash` it was built from; Mermaid treats `%%` as a
comment so it does not affect the diagram.

**Check the hash before trusting one.** A generated diagram in a repository looks
like source, and a reader who does not know a file is derived will not think to ask
whether it is current. If the header's hash differs from the one above, the diagram
is stale — regenerate it. Never hand-edit an artifact to make the check pass: the
hash describes the annotations, so editing the file only makes it lie.

They are committed on purpose, so a fresh clone has the model without running
anything and a reviewer sees model changes in the diff. Resolve merge conflicts by
regenerating, never by hand-merging.

## Reading the answers

Every MCP response carries a `guardlink` envelope alongside the payload:
`annotation_hash`, `git_sha`, `mode`, `root`. Identical hash means identical model, so
you can tell a fresh answer from a cached one without asking twice.

Anything that resolves a reference reports `matched_via`: `exact`, `alias` or
`substring`. **A substring match is a suggestion, not an identification.** When
`ambiguous` is set, several records tied and one was chosen arbitrarily —
`candidates` names them all, and you should re-ask precisely.

For CWE queries, check `external_id.declared` before reading `count: 0` as coverage:
`false` means this model has never heard of that weakness class, which is not the same
as declaring it and finding nothing exposed.
