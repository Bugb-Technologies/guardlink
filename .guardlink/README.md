# .guardlink/ — what this is

You are looking at a **GuardLink** threat model. It is a set of security facts that
developers recorded next to the code they describe — what each component is exposed to,
what mitigates it, how data flows between components — parsed into a queryable model.

**If you are an AI coding agent: read this file before inferring security context from
the source.** The model already answers most of what you would otherwise guess at, and it
records decisions that are not visible in the code, such as which risks a human has
accepted.

This file is generated. Run `guardlink sync` to refresh it; do not edit it by hand.

Current model: 442 annotations · 16 assets · 15 threats · 12 controls · 80 exposures · 107 flows
Content hash: `sha256-v2:66c22c9b8df9d397dee561e4597a2996a988710083661a591990844e6133ff9f` — identical hash means identical model.

---

## Start here: one real question, answered end to end

**"I am about to edit `src/auth/login.ts`. What do I need to know?"**

With the MCP server connected:

```
guardlink_context(file: "src/auth/login.ts")
```

Without it, from a shell. There is no single-command CLI equivalent — `guardlink parse`
emits the whole model, so narrow it to the one file yourself:

```sh
guardlink parse . | jq '[.. | objects | select(.location?.file == "src/auth/login.ts")]'
```

That gives you the annotations declared in that file with line numbers, and the assets,
threats and controls each one names. It is not the whole of what `guardlink_context`
returns: the tool also resolves each asset's neighbours and tells you *which kind* of empty
an empty answer is, and neither falls out of a filter over the model.

Without `jq`, `guardlink status .` is the closest thing — repo-wide counts and the
unmitigated list, not a per-file view.

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

**Annotation mode: `inline`. Annotations live in source-file comments**, in the comment
syntax of the file you are editing — the doc-block of the function or module they describe.

```ts
/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "parameterized via pg"
 */
export function login(email: string) { … }
```

Do not create `.gal` sidecars under `.guardlink/annotations/` in this mode; a repo with
both is a mixed repo, and that is the failure this section exists to prevent.

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

One note that catches people out: `@confirmed` and `@exposes` take their arguments in
**opposite orders** — exposes is asset-then-threat, confirmed is threat-then-asset.

Cross-repo tags are written qualified and unquoted, in any reference position —
`@flows #other-repo.tokens -> #api via header`, and equally
`@exposes #api to #other-repo.injection [high] -- "why"`. Quoting is
only for a reference containing spaces. (This used to require quotes because the grammar
would not accept a dot after `#`; that was D19, and it is fixed.)

Write coupled blocks, not lone facts: a risk plus the control or audit that answers it, plus
the flow that gives it context.

### Writing *about* these verbs

A line starting with a verb that then fails to parse is either a broken annotation or a
sentence about GuardLink. They are told apart by **structural evidence** after the verb: a
`#reference`, a spaced `--` delimiter, or a grammar keyword **belonging to that verb**
(`to` for `@exposes`, `against`/`using` for `@mitigates`, `->` for `@flows`, and so on).

| Line | Verdict |
|---|---|
| `@exposes #api to` | **error** — has a `#ref`, so it was meant to be an annotation. Fails validation. |
| `@exposes was renamed in v1.2` | **warning** — no structure. Read as prose. Does not fail validation. |

The keyword set is per verb, so `@feature still claims to describe the model` is prose:
`to` is not part of `@feature`'s grammar. Prose warnings are always reported under their
own heading — never suppressed, because a line you *meant* as an annotation shows up there
too.

If you are documenting real annotation syntax and the examples do look structural, wrap
them in `@shield:begin` / `@shield:end`. That is the deterministic override; the split
above is a heuristic.

**The complete reference is `docs/GUARDLINK_REFERENCE.md`** — every verb, every alias, the conformance
levels, and worked examples per language. Read it before inventing syntax.

**Never write `@accepts`.** Accepting a risk is a human governance decision. If you find a
risk with no control, write `@exposes` to record it and `@audit` to flag it for review.

---

## Asking questions without MCP

```sh
guardlink status .                       # coverage, counts, unmitigated exposures
guardlink parse .                        # the whole model as JSON, on stdout
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
| `guardlink_annotate_apply(file, line, annotations)` | **You are writing annotations.** Prefer it over editing `.gal` files by hand. |

### Writing annotations with the MCP server

`guardlink_annotate_apply` writes the sidecar for you. Pass the **source** file
you are describing — not the `.gal` path, which it derives — the line the block
anchors to, and the raw GAL lines. Two things worth knowing before you reach for
a text editor instead:

- **Do not write `@source` yourself.** The header is synthesised from `file`,
  `line` and `symbol`. Passing one is an error, not a shortcut.
- **Pass `symbol`.** It is optional and it is what makes `guardlink_reanchor`
  able to find the block again after a refactor moves the code. Omitting it is
  also how you say "this statement is about the whole asset, not one function" —
  an unanchored `@mitigates` is never narrowed to a single symbol.

`dry_run: true` returns the diff without writing. Every line is re-parsed before
anything reaches disk, so a syntax error is rejected with its reason — but an
undefined `#id` is not, so run `guardlink_validate` afterwards.

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
