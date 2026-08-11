# GuardLink — Open Backlog

**Snapshot:** `main` @ `a913007` (PRs #17 and #18 merged) · 58 defects logged · 46 fixed · 1 won't-fix · **10 open** · 1 partial

Full evidence, reproductions and history for every row live in
`docs/prd/EPIC-machine-readable-threat-model-surface.md` §3.3. This document is the
backlog view: what is left, why it matters, and roughly what it costs.

**Nothing here blocks a release.** Every item is either recoverable by reading, or
scoped to a workflow that no external user has exercised yet. They were deliberately
deferred so the defect ratchet would stop before 1.5.0.

---

## Recommended order

| Order | Items | Rationale |
|---|---|---|
| 1 | **D41, D40** | The write tool is the primary path under external-default; D41 breaks its advertised workflow |
| 2 | **D55, D58** | One coherent piece: three places report success from the *absence* of the thing checked |
| 3 | **D46, D52** | Facts about the tool written down instead of read — same class as D33, and D33's mechanism is already built |
| 4 | **D53, D54** | Workspace/multi-repo polish; only bites teams using `link-project` |
| 5 | **D42** | Needs a `schema_version` decision first — see below |
| 6 | **D22, D56** | D22 is genuinely expensive; D56 needs a TTY to even confirm |

Two of these pair naturally with a decision you already have parked: if
`schema_version` bumps for **D42**, the **D20** rename rides along free.

---

## The four groups

### Group A — `guardlink_annotate_apply` (D40, D41)

The agent write path. Two defects survive; the two that could corrupt a model
(D39, D51) were fixed in #18.

#### D41 — duplicate `@source` headers · **Med**
Submitting anything that is not an exact whole-block match appends a second
identical `@source` header. Measured: one line already present verbatim → header
count 1→2; one genuinely new line → 2→3; all five existing lines → correctly
`unchanged`.

So idempotence holds *only* for the exact whole-block case, while the tool
description claims "re-applying the same block is a no-op, not a duplicate" — false
under the natural reading of "the same block" (= the same anchor). **Incremental
annotation is the workflow the tool is marketed for**, and every such call corrupts
the sidecar a little further.

*Fix:* merge into the existing block when the anchor matches, rather than appending.
Roughly half a day with tests.

#### D40 — `dry_run` reports `status: "written"` · **Low**
`{ok: true, status: "written", linesWritten: 5}` while writing nothing. A caller
branching on `status === "written"` cannot distinguish a preview from a commit —
the same did-run/didn't-run confusion this project eliminated everywhere else.

*Fix:* a distinct status value. An hour.

---

### Group B — vacuous green checks (D55, D58)

Three places reported success from the absence of the thing being checked. One was
fixed in #17 (`reanchor` on a repo with zero anchors); these two remain. Worth doing
as one piece, because the interesting question is how many more exist.

#### D55 — empty repo passes `validate` green · **Low**
A git repo with one unannotated file and no `.guardlink/` prints
"✓ All annotations valid, no unmitigated exposures", exit 0. Vacuously true.

The MCP surface is careful about exactly this: `guardlink_context` separates
`scanned_without_annotations` from `not_scanned`, and the server instructions warn
"do not read them as the same thing". The CLI makes no such distinction — so an
unmodelled repo and a clean one are indistinguishable at **the command the docs tell
you to finish with**. `guardlink unannotated` already has the signal.

#### D58 — TUI always claims full coverage · **Low**
`cmdScan` branches on `coverage.unannotated_critical.length === 0`, and that field is
never populated (`parse-project.ts:284` sets `[]`, nothing else writes it). The green
line is unconditional on a fully annotated repo and on an empty one alike.

*Fix:* populate the field, delete the claim, or say what it actually knows (file
coverage). Noted in a code comment at `tui/commands.ts`.

*Suggested extra:* grep for success messages that don't branch on a non-empty result.
This pattern has now appeared three times independently.

---

### Group C — facts about the tool, written down instead of read (D46, D52)

Same class as D33 (stale claims in the server instructions), which already has a
mechanism: `tests/instructions-claims.test.ts` pairs each behavioural claim with a
probe against real code, plus an expiring-phrasing guard.

#### D46 — tool description hard-codes *this* repo's numbers · **Low**
`guardlink_graph`'s description says "`#path-traversal` alone is declared on 10 assets
here, so crossing threats would make depth 2 reach most of the graph" — served
verbatim to an agent working on a different repo, where it is 2 assets and the
sentence is simply false. The reasoning is worth keeping; the *measurement* should be
framed as the observation that motivated the rule, not a fact about the caller.

**This is a mechanism extension, not a one-line fix**, for two independent reasons:
1. *Wrong surface* — the D33 test only evaluates `buildServerInstructions(...)`. No
   test in the suite reads any MCP tool description.
2. *Wrong pattern class* — the expiring-phrasing guard matches futurity (`GL-\d+`,
   "not yet", "for now"). A hard-coded measurement is not a futurity phrasing and
   would pass.

Both surface and pattern class need widening.

#### D52 — SARIF driver version hardcoded and wrong · **Low**
`src/analyzer/sarif.ts:265` emits `version: '1.4.3'`; `package.json` is `1.4.5`.
`getPackageVersion()` already exists in `mcp/freshness.ts`. **SARIF driver version is
what GitHub Advanced Security attributes findings to**, so every uploaded run is filed
against a version that did not produce it — and it drifts further each release.

*Fix:* one line, plus a test asserting no hardcoded version literal.

---

### Group D — workspace / multi-repo (D53, D54)

Only affects teams using `link-project`. Both reproduce in a two-repo workspace.

#### D53 — `validate` can't tell a cross-repo tag from a typo · **Low**
`@flows #notify -> #billing.db via https` yields
`⚠ Dangling reference: #billing.db is never defined` — byte-identical to a genuine
misspelling. But `workspace.yaml` names `billing` with `tag_prefix: #billing.`, and
`guardlink_workspace_info` in the same repo states the rule ("external refs resolve
during workspace merge, not local validation").

`merge` already gets this right and says so precisely. **Validate should defer, not
accuse** — it has everything it needs to.

#### D54 — merge collision warnings double-count · **Low**
Each collision reported twice, once bare and once `#`-prefixed. Seven colliding tags
produced fourteen warnings. Cosmetic — but it doubles the noise on the one output a
workspace owner reads to decide whether a merge is safe.

---

## Blocked / expensive

### D42 — coverage fields invite a ratio reading · **PARTIAL, blocked on a decision**

`total_symbols` (never computed), `annotated_symbols` (counts *annotations*), and
`coverage_percent` (*file* coverage) each document themselves correctly at
`types/index.ts:403-421` — **but doc comments don't travel over the wire**, and
consumers believe the names.

Fixed in #17: all consumers corrected, `describeCoverage()` puts the contract in code,
one shared divisor, and the merged-workspace 0% bug (D49) resolved outright.

**Still open:** the payload reshape. `coverage` ships inside `schema_version: 1.0.0`
and `merge` cross-checks that version across repos, so any rename or removal is a
breaking schema change.

**Recommendation on record:** drop `total_symbols` entirely and reshape the rest to
`{kind: 'file', annotatedFiles, sourceFiles, percent, annotations}`. `total_symbols`
should not be preserved — it has been `0` since introduction, symbol counting needs
per-symbol parsing across 11 languages (deliberately not what GuardLink does), and it
has produced two defects. *It is not a placeholder for future work; it is a
denominator-shaped hole that invites division.*

> **If you take this bump, fold in D20** — the `external_refs` name collision was
> closed won't-fix specifically because it wasn't worth a bump of its own. It touches
> 19 files and carries a silent-degradation risk at the serialization boundary
> (`merge.ts` reads report JSON with an unchecked `as ThreatModel`, so post-rename
> every pre-rename report reads `undefined` with no error). Doing it *with* a version
> bump is the only safe time.

### D22 — template literals parse as real annotations · **Med, expensive**

Example annotations inside `.ts` template literals parse as *real* ones — the README
template once injected `#api`, `#sqli` and `cwe:CWE-89` into GuardLink's own model.

**D29 does not subsume this** (verified): D29 tiers lines that *fail* to parse; D22 is
about lines that parse *successfully*, producing zero diagnostics. Orthogonal.

*Held today by* `@shield:begin/end` markers, applied by hand.

*Cost:* a TS AST pass is 2–3 days and only solves `.ts`/`.js` — Python docstrings, Go
raw strings and Ruby heredocs have the identical shape, so the "general" fix is really
eleven fixes with one started. **Not recommended.**

*Cheap 90% held in reserve:* treat a line inside a template literal in `.ts`/`.js` as
shielded by default, detected by counting unescaped backticks. ~30 lines, no AST,
catches every instance actually hit. Fails safe — a missed annotation shows as a
coverage gap; a phantom one silently corrupts the model. Needs its own tests (backtick
counting is fooled by backticks in comments and regexes). **Reach for this only if a
third instance appears.**

*Residual risk worth knowing:* the tests guarding this protect **only this repo**. A
downstream project writing its own templates has no guard and no warning.

### D56 — `ask` / `translate` without a TTY · **Low, UNVERIFIED**

`guardlink ask "…"` prints "Launching Claude Code…", warns "no stdin data received in
3s", then errors that no prompt was supplied — *while having built the prompt
correctly* ("✓ Prompt copied to clipboard, 1,768 chars"). The prompt appears not to be
piped to the spawned agent.

**Logged at low confidence.** Both commands announce "Claude Code will take over this
terminal" and may be TTY-only by design; the session that found it had no TTY.
**Verify interactively before acting.** Contrast `threat-report`, which fails cleanly
with "No AI provider configured" and three ways to fix it.

---

## Not defects — worth carrying forward

**`init` picks the wrong definitions language without a manifest.** A repo of only
`.py` files and no `requirements.txt` gets `definitions.ts`. Detection appears to key
on manifest files rather than source extensions. Cosmetic, first-run, unlogged.

**A connected MCP client keeps a stale server across a rebuild.** Verified: nothing in
the response moves — `guardlink_version` comes from `package.json`, `annotation_hash`
covers the target repo. Ruled an operational fact of stdio MCP rather than a GuardLink
bug, **but GuardLink is the only party who can make it observable** (stat the entry
module, set `server_stale: true` in the envelope). It caused one false defect report
during development.

**A third private ref-normaliser exists.** `normalizeActorRef` in `diff/engine.ts`,
alongside `coverage.normalizeRef` and the canonicaliser. This is the D57 pattern
starting again — one predicate was independently reimplemented thirteen times before a
guard was added. Worth watching before it reaches ten.

**Two `localeCompare` calls in the artifact path** (`dashboard/diagrams.ts:674`,
`dashboard/generate.ts:1631`). ICU-dependent, so ordering can differ between macOS and
Linux CI. Drift compares hashes rather than bytes so it likely doesn't trip the gate —
but it is a real platform difference in generated output.

**CI matrix includes Node 18, which vitest's engine does not support.**
`vite@7.3.1` declares `^20.19.0 || >=22.12.0`. npm only warns on engine mismatch, so it
installs and may fail at runtime. This predates our work and is on `main`; if the Node
18 job passes it is luck rather than support. Either drop 18 from the matrix or pin the
toolchain — **worth raising with the team separately.**

---

## Testing lessons worth keeping

Three of these came out of the work and generalise beyond GuardLink.

**A test can pin a defect as the contract.** It happened three times: the GL-401 test
asserted the exact text of a claim that later became false, so the text could not be
corrected without a test failing; a D47 test pinned pre-fix behaviour; a D45 test
asserted the wrong axis (mode instead of `rootFiles`) and was green throughout.
*Asserting on the words is what let the words go wrong.* Prefer probes that run the
real code over assertions on its output text.

**Single-corpus testing hides whole defect classes.** Every test ran against GuardLink
itself — a small, fully annotated TypeScript repo. Two of the most serious defects
(`guardlink_graph` returning 631 KB of file paths; the coverage join reporting a live
critical injection as mitigated) were invisible there and surfaced on the first foreign
repo. `tests/fixtures/expense-api/` now exists for this; **use it.**

**A guard that passes everything is worse than none.** The D50 command probe initially
used exit codes — but `guardlink not-a-command --help` exits 0 and prints root help, so
it would have called every imaginable subcommand valid.
