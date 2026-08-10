# Epic — Machine-Readable Threat Model Surface

| Field | Value |
|---|---|
| Epic ID | GL-EPIC-001 |
| Target release | GuardLink v1.6.0 |
| Baseline measured | v1.4.5 (`main` @ a463523) |
| Status | Draft — pending review |
| Owner | Animesh Srivastava (CTO) |
| Branch dependencies | **None.** All local branches are merged as of a463523 — `feat/v1.5.0` is 0 commits ahead of main and its remote is deleted. Its work (`@confirmed`, `@feature`, `translate`, `ask`) shipped in 1.4.3–1.4.5, not as a 1.5.0 release. The D3 topology dashboard it added was subsequently removed in 5ca53eb. |

---

## 1. Problem statement

GuardLink builds a rich, structurally sound threat model from developer-declared
annotations. That model is currently **hard to reach**.

- The three Mermaid diagrams exist only as strings interpolated into a large HTML
  dashboard (measured: 1.21 MB on guardlink, 3.57 MB on specter-v1; the diagrams are
  1.35% and 0.28% of that respectively). A coding agent must read the whole artifact
  to extract them. A developer cannot open them in a Mermaid viewer, diff them, or
  paste them into a PR.
- The MCP surface exposes 18 tools, but `lookup` returns content for only 10 of 19
  relation types. Nine are unreachable: ownership, data classification, assumptions,
  transfers, validations, comments, shields, external_refs, and audits (read but
  discarded). Worse, the missing query forms do not fail — they fall through to fuzzy
  matching and return confident wrong answers (see D12).
- Graph queries are depth-1 only. There is no traversal, no path query, and — most
  consequentially — **no file-anchored lookup**. The single most frequent question a
  coding agent asks ("what does GuardLink know about the file I just opened?") cannot
  be asked at all.
- Nothing carries freshness metadata. A consumer cannot distinguish a current answer
  from a stale one.

Separately, the planned shift to **external annotation mode as the default** removes both
existing agent-discovery mechanisms (synced `CLAUDE.md`, root `.mcp.json`), leaving cold
agents with an undocumented `.guardlink/` directory and no entry point.

**Framing:** the threat model is good; the interfaces onto it are not, and the
external-mode default makes discovery worse before it makes anything better.

---

## 2. Why this matters commercially

GuardLink's moat is that annotations are durable, codebase-resident security knowledge
that compounds and lowers LLM iteration cost. That thesis holds only if consumers can
*retrieve* the knowledge cheaply. Today an agent either dumps the full model (expensive,
imprecise) or reads nothing — the common case. Every query that requires a full-model
dump erodes the cost advantage the flywheel is supposed to create.

The CXG bridge has the same dependency. "CXG finds CWE-89 → GuardLink says whether that
CWE is already declared and mitigated at that site" is not expressible in the current
query surface.

---

## 3. Evidence base

Measured against `main` @ a463523. Line references are exact.

### 3.1 Confirmed — the architecture already supports this work

| Finding | Evidence |
|---|---|
| Diagram generators are pure `ThreatModel → string` functions | `src/dashboard/diagrams.ts:231,467,587`; exported at `src/dashboard/index.ts:12` |
| HTML is a consumer, not a source | `src/dashboard/generate.ts:35-38` |
| Full model JSON already ships | `guardlink report --format json`, `src/cli/index.ts:419-427` |
| Provenance metadata already populated | `populateMetadata()` — schema version, git SHA, branch |
| `location.file` is the logical source file **in both modes** | `src/parser/parse-file.ts:100-108` — `@source` rewrites `location`, retains `origin_file`/`origin_line` |
| Feature-scoped filtering works | `filterByFeature`, used by `report` and `dashboard` |
| Depth-1 ego-graph implemented | `src/mcp/lookup.ts:225-288` |
| `.guardlink/` excluded from analyzer scan | `src/analyze/tools.ts:210` |
| `.gal` included in diff extensions | `src/diff/git.ts:52` |

**Consequence:** there is no second source of truth to maintain. Emitting `.mmd` files is a
fan-out at an existing generation step, not a new authoring surface. Divergence requires
two authors; there is one.

### 3.2 Confirmed — gaps

| ID | Gap | Evidence |
|---|---|---|
| G1 | No file-anchored query | No `file <path>` form in `lookup.ts:96-132` |
| G2 | No traversal beyond depth 1 | `lookupAsset` returns a fixed 1-hop neighborhood |
| G3 | No path query (`path from X to Y`) | Absent from `lookup.ts:96-132` |
| G4 | 7 relation types unreachable | `ownership`, `data_handling`, `assumptions`, `audits`, `transfers`, `validations`, `comments` |
| G5 | No query by external ref (`cwe:`, `owasp:`) | `external_refs` parsed, never a query key |
| G6 | No freshness on any response | All tools return bare payloads |
| G7 | MCP server declares no `instructions` | `src/mcp/server.ts:86` passes only `{name, version}` |
| G8 | `.guardlink/` has no agent-facing README | `init` writes definitions, `config.json`, `prompt.md` — nothing explanatory |
| G9 | No structured annotation *write* tool | `guardlink_annotate` returns a prompt; the agent free-hands the edit |
| G10 | No re-anchoring for drifted `@source` blocks | `parent_symbol` is captured but never consumed |

### 3.3 Confirmed — defects

> **Status: 33 logged · 26 fixed · 1 partial (D23) · 1 won't-fix (D20) · 5 open (D22, D30, D31, D32, D33).**
>
> Highest priority open item is **D32** — data loss in a shipped command.
> Every row below was re-verified against the code on 2026-08-10, not against its own
> description text. The `Sev` column is the status of record; a `(sha)` names the commit
> that fixed it, established with `git log -S` against the fixing code rather than from
> the commit subject. Rows D1–D15, D18, D21 and D26 were fixed across Phases 1–5 but had
> never had their severity updated, so this table previously read as 21 open defects when
> 2 were open. A ledger that misreports its own state is worse than no ledger.
>
> D30-D32 were found afterwards, by the `no-unused-vars` cleanup. Each is an unused
> identifier that turned out to be a dropped behaviour rather than dead weight, so each
> is still in the code behind a narrow `eslint-disable` naming its row. **D32 is data
> loss and is the most serious thing still open in this table.**

| ID | Sev | Defect | Evidence |
|---|---|---|---|
| D1 | ~~High~~ **FIXED (4b49ece)** | `annotated_files` double-counts in external mode — both the `.gal` path and each logical source are added | `parse-project.ts:104-110`; `unannotated_files` filters `.guardlink/` at :137, `annotated_files` does not |
| D2 | ~~High~~ **FIXED (4b49ece)** | `source_files: files.length` counts `.gal` as source (measured: 7 → 9, +28.6%). **The original claim that this makes `coverage_percent` non-comparable is REFUTED** — see D14; that field has never carried a value | `parse-project.ts`, `DEFAULT_INCLUDE` contains `**/*.[gG][aA][lL]` |
| D3 | ~~High~~ **FIXED (4b49ece)** | The external-mode `.gal` path convention exists **only inside an LLM prompt string**, as an example — no constant, no resolver, no validator | `src/agents/prompts.ts:54-55`, sole occurrences |
| D4 | ~~**High**~~ **FIXED (4b49ece)** | `DEFAULT_EXCLUDE` drops `**/tests/**`, `**/test/**` — a `.gal` at the **documented** convention path under `test/` is silently dropped. Measured: annotation vanished, no diagnostic, no count change. Under external-default this is silent data loss triggered by following the documentation | `parse-project.ts:61` `DEFAULT_EXCLUDE` |
| D5 | ~~High~~ **FIXED (8e594d8)** | MCP model cache is root-keyed with no file-change invalidation; `lookup`/`status` serve a stale model for a whole session | `src/mcp/server.ts:64-81`; only `parse`, `validate`, `sarif`, `review_*` invalidate |
| D6 | ~~Low~~ **FIXED (9f94853)** | Server version hardcoded `'1.4.3'`; `package.json` is `1.4.5` | `src/mcp/server.ts:89` |
| D7 | ~~Med~~ **FIXED (77c3c67)** | `matchRef` does bidirectional substring matching at ≥3 chars — `#auth` matches `#author-service`, with no signal to the caller | `src/mcp/lookup.ts:444-446` |
| D8 | ~~Low~~ **FIXED (77c3c67)** | `lookupAsset` distinguishes not-found from declared-but-empty; `lookupThreat` returns bare `count: 0` | `lookup.ts:225` vs `:291` |
| D9 | ~~Med~~ **FIXED (2bf5853)** | The three MCP resources use `cachedRoot \|\| '.'` and take no root param — in a linked workspace they can silently answer for the wrong repo | `src/mcp/server.ts` resource handlers |
| D10 | ~~High~~ **FIXED (576f0de)** | External mode suppresses agent instruction files and moves `.mcp.json` inside `.guardlink/`, where MCP clients do not auto-discover it | `src/init/index.ts:173,185-186` |
| D11 | ~~**High**~~ **FIXED (5eb8163)** | `guardlink_clear` mutates annotations on disk and does **not** call `invalidateCache()`. Every subsequent `status`/`lookup`/`report` in that session reports annotations that no longer exist | `server.ts:476-505`; no invalidate between :400 and :540 |
| D12 | ~~**High**~~ **FIXED (f790d1f)** | Unknown `lookup` query forms do not error — they fall through to `lookupFuzzy`, and `matchRef`'s reverse-substring rule matches the query string itself. `owner of #cli`, `assumptions for #cli`, `comments for #cli` all return byte-identical `count: 1` payloads containing none of the requested data | `lookup.ts:446`; measured |
| D13 | ~~**High**~~ **FIXED (5959e8a)** | `.find()` substring precedence silently drops exact matches. `lookup("threat dos")` returns `#redos` — `#redos` is declared at `definitions.ts:36`, `#dos` at `:39`, and `"redos".includes("dos")` short-circuits the exact match. `lookup("asset cli")` merges all 9 of `#llm-client`'s exposures into `#cli` | `lookup.ts:293,444`; reproduces on committed definitions |
| D14 | ~~Med~~ **FIXED (4b49ece)** | `coverage_percent` is dead — hardcoded `0` and never computed for a single repo. Three consumers display 0% today | `parse-project.ts:194`; consumers at `dashboard/data.ts:95`, `analyze/index.ts:407`, `tui/commands.ts:506`; only real assignment is `workspace/merge.ts:478` (multi-repo path) |
| D15 | ~~Med~~ **FIXED (2bf5853)** | The MCP model cache is **process-global**, not per-server — four module-level `let`s shared by every `createServer()` in a process. Two servers in one process share one `cachedRoot`, so server B's resources can answer for server A's repo. Superset of D9. Latent under stdio (one server per process), live under any multi-server host | `server.ts:64-66`; found by the GL-104 two-repo test, not by inspection |
| D16 | ~~High~~ **FIXED (dcf4650)** | `guardlink validate` silently rewrites 7 tracked files — it runs `syncAgentFiles` as a side effect, modifying `CLAUDE.md`, `AGENTS.md`, `.clinerules`, `.cursor/rules/guardlink.mdc`, `.gemini/GEMINI.md`, `.github/copilot-instructions.md`, `.windsurfrules`. A command that reads as read-only leaves a dirty tree, making it unusable as a CI check | observed during Phase 1 verification; needs a `--check` / read-only mode |
| D17 | ~~Med~~ **FIXED (096c291)** | `guardlink_dashboard` writes `threat-dashboard.html` into its own scan set (`.html` is in `DEFAULT_INCLUDE`, `parse-project.ts:52`). It yields zero annotations, but it does change `source_files` and `unannotated_files`. The MCP cache was masking the divergence from a fresh CLI run | fixed incidentally by A3's invalidation; the scan-set inclusion itself remains |
| D18 | ~~**High**~~ **FIXED (5959e8a)** | *(regression introduced by the D13 fix, corrected in the same commit)* Any threat or control resolvable **only by substring** is silently dropped entirely. `threat denial` → `count: 0` where Phase 0 measured `#dos` | `lookup.ts:411,418,430` |
| D19 | ~~High~~ **FIXED (c863da9)** | **The documented cross-repo tag syntax does not parse.** `ASSET_REF` (`parse-line.ts:22`) offers `#[a-zA-Z0-9_-]+`, a quoted form, or `[A-Za-z_]\w*(\.[A-Za-z_]\w*)*` — the `#` alternative excludes dots and the dotted alternative excludes `#` and hyphens, so `#auth-lib.token-verify` matches `#auth-lib` and the remainder fails the `$` anchor. `THREAT_REF` (`:26`) has no dotted alternative at all. Cross-repo tags parse **only when quoted**, and **never in threat or control position**. Two documented examples are unwritable: `parse-project.ts:385`'s own canonical `#auth-lib.token-verify`, and both rules emitted by `guardlink_workspace_info` (`server.ts:859,861`) — the tool whose purpose is teaching this syntax | reproduced independently; parser grammar decision required |
| D20 | ~~Med~~ **WON'T FIX** | **Name collision on `external_refs`.** `model.external_refs` (built by `detectExternalRefs`, `parse-project.ts`) holds cross-repo sibling tags. `threat.external_refs` (built from `EXT_REFS_OPT`, `parse-line.ts`) holds `cwe:` / `owasp:` identifiers. Two unrelated concepts under one field name. **Closed as won't-fix, not deferred.** The reachable harm was already removed in Phase 2b: the query form was renamed to `cross-repo refs`, the dangerous bare `refs` alias was dropped, and each form's description names the other — so the collision is no longer reachable by accident. What remains is a naming smell in a type definition. Verified against the code: `external_refs` appears in **19 files** across parser, workspace, dashboard, report, SARIF, diff, TUI and MCP. **Correction to the stated reasoning:** the risk is *not* that a rename through `annotation-hash.ts` endangers the `guardlink migrate` invariant — the hash is computed over field *values* (`refs(t.external_refs)`), so a correct rename is hash-neutral, and every typed access would fail compilation if incomplete. The real exposure is that **`external_refs` crosses a serialization boundary**: it is written into report JSON (`workspace/metadata.ts:218`) and `.guardlink/model.json`, and read back at `workspace/merge.ts:48` through `const model: ThreatModel = JSON.parse(raw)` — an unchecked assertion. After a rename, every pre-rename report file would silently read `undefined` at `merge.ts:574` (`r.model.external_refs?.length || 0`), degrading cross-repo ref counting with no error and no compile failure. That is a stronger reason for won't-fix than the hash one, and it is the thing that would actually bite. **If `schema_version` ever bumps for another reason, the rename rides along then** — the migration would have a version gate to hang off. **Note for whoever does it:** `ALL_ROW_ARRAYS` in `mcp/subgraph.ts:450` names `assets`, `threats` and `controls` as string literals (the rest derive from `SELECTABLE_KINDS`); any field rename must be reflected there by hand, because nothing type-checks those strings against the model | 19 files verified 2026-08-10; unchecked `JSON.parse` assertion at `workspace/merge.ts:48` **Correction to my own reasoning (post-sweep):** I justified won't-fix partly on the annotation hash being at risk. That is wrong — the hash is computed over field *values* (`refs(t.external_refs)`), so a correct rename is hash-neutral, and `computeAnnotationHash` takes a typed `ThreatModel`, so an incomplete rename fails compilation rather than silently dropping a field. The real exposure is the **serialization boundary**: `workspace/metadata.ts:218` writes `external_refs` into report JSON, and `workspace/merge.ts:48` reads it back with an unchecked `JSON.parse(raw) as ThreatModel`. After a rename, every pre-rename report file reads `undefined` at `merge.ts:574` and cross-repo ref counting silently degrades — no error, no compile failure, no test failure. Worse than the hash concern precisely because nothing catches it. Won't-fix stands, on better grounds. |
| D21 | ~~Med~~ **FIXED (ed1da5e)** | `replaceOrAppend` preserved the previous sync's trailing newline while `wrapMarkers` emitted a fresh one — every sync appended a blank line to every markdown agent file. Measured at `f022d5b`: `CLAUDE.md` 54 trailing newlines, `AGENTS.md` 53, `.clinerules` 44, accumulated silently across the repo's history | found by the D16-interaction test |
| D22 | **Med — OPEN** | **Templates embedding GAL syntax pollute the model.** Template literals live inside `.ts` files, so once the comment prefix is stripped their example annotations parse as *real* ones. The GL-402 README template injected `#api`, `#sqli` and `cwe:CWE-89` into this repo's own model, surfacing as a GL-204 test failure. Mitigated case-by-case with `@shield:begin/end`; the class recurs for any future template. **D29 does NOT subsume this — verified.** D29 splits lines that FAIL to parse into `malformed-annotation` and `prose-like`. D22 is about lines that parse SUCCESSFULLY: an unshielded ` * @exposes #api to #sqli …` inside a template literal yields 1 real annotation and **0 diagnostics**, so there is no diagnostic for D29 to tier. Orthogonal mechanisms. **What remains:** nothing detects an unshielded example at authoring time. A systematic fix would be a lint rule or a parser-level "inside a string literal" check; both need a TS AST pass the parser deliberately does not do (it is line-based across 11 languages). Current mitigation is `@shield:begin/end` plus `tests/readme.test.ts` and `tests/agent-file-placement.test.ts`, which assert this repo's own model declares no `#api`/`#sqli`/`#prepared-stmts` | `init/templates.ts`; same pattern already used in `agents/prompts.ts`; mechanism re-verified 2026-08-10 |
| D23 | **Med — PARTIAL** | **Parse order is unstable across processes.** `fast-glob` returns files in completion order under concurrency — stable within a process, not between two — so anything durable that inherits parse order churns. `computeAnnotationHash` was immune (it sorts before hashing), which is why the hash held while the prose moved. **Fixed** at the artifact emission boundary (a921afa) and for the dashboard (096c291, which also proved the "unreproducible" claim wrong on that path). **Still open:** `report --diagram-only`. `canonicalizeModelOrder` is absent from `src/report/*.ts` and `src/cli/index.ts` — measured 2026-08-10, three runs in three processes produced two distinct sha256 hashes, differing by whole node blocks (`Commands`, `RawStdin`, `Terminal` present in two runs, absent in one). **What remains:** apply `canonicalizeModelOrder` in the `report` path, exactly as `emitArtifacts` and `generateDashboardHTML` do. Low risk — it is a pure sort at an emission boundary — and it is the last durable output that still inherits glob order | `parse-project.ts` glob walk; remaining gap measured on `013a94d` |
| D24 | ~~High~~ **FIXED (35f2597)** | `guardlink init --force` **silently destroys a populated `definitions` file.** Observed during Phase 4: it overwrote 38 declarations with a 9-item template, plus `config.json`, with no warning and no prompt. Recovered via `git checkout` — a repo where definitions were not yet committed would have lost them outright | `init/index.ts`; needs a confirmation prompt or a refusal when definitions are non-empty |
| D25 | ~~Med~~ **FIXED (096c291)** | The dashboard was non-reproducible across processes. **My stated cause was wrong:** the `new Date()` at `generate.ts:40` was *dead code* — computed, never rendered. The real causes were (a) the dashboard path never went through `canonicalizeModelOrder`, so it inherited fast-glob completion order, and (b) the model's own `generated_at` embedded verbatim in the page's JSON blob | verified: three separate processes now byte-identical |
| D26 | ~~Med~~ **FIXED (f71950c)** | **`.guardlink/model.json` carried a top-level `generated_at`.** The `.mmd` headers had volatile fields stripped in `a921afa`; `model.json` did not. It is the artifact GL-304 most deliberately commits — justified precisely so a model change shows up in PR review | verified fixed: two `guardlink artifacts .` runs now byte-identical |
| D27 | ~~BLOCKER~~ **FIXED (45295b2)** | **Agent instruction files never state where annotations go.** `agentInstructions(project)` takes no mode parameter, so no agent file can name it. Verified on a fresh default-init repo: `config.json` says `annotation_mode: external`, while `CLAUDE.md` contains **zero** occurrences of `.gal`, `annotations/`, `sidecar` or `@source` (its one "external" is "external API calls"). `.guardlink/README.md` states it correctly — 6, 4 and 2 occurrences — but that is the cold-start path, not the file an agent reads every turn. Under the new default an agent reads inline syntax with no placement guidance and writes inline; the repo silently goes mixed | **gates GL-507's default flip**; fix is GL-403 territory: thread mode into `agentInstructions` plus a short placement section |
| D28 | ~~Med~~ **FIXED (958d59c)** | No CI gate on artifact drift. **Two of my claims were wrong:** CI already existed (build + test + validate + status on an 18/20/22 matrix), and my "verified it exits 1 on stale, 0 on current" was true for those two states but the gate was **blind to deletion** — `checkArtifactDrift` enumerated the `.mmd` files present on disk, so `rm dataflow.mmd` reported "artifacts are current" and exited 0. Found by testing the gate rather than trusting the PRD. Fixed by deriving the expected set from the model | verified: deleted `.mmd` → exit 1, deleted `model.json` → exit 1 |
| D29 | ~~High~~ **FIXED (3d9f965)** | **Any comment line beginning with a GuardLink verb is a live annotation** — not just templates (D22 was the narrow case). Verified: `@feature flag rollout is described below` and `@exposes was renamed in v1.2` both emitted `Malformed … annotation` diagnostics, and diagnostics fail `validate`. So writing *prose about GuardLink* in your own codebase broke your own `validate`. **Resolved with a two-tier split on structural evidence** — a line carrying a `#ref`, a `--` delimiter, or one of *that verb's own* grammar keywords is a malformed annotation (error, fails validate); a line with none is reported as prose-like (warning, does not fail). **My ruling specified one global keyword list; measurement corrected it to per-verb** — `to` is structural in `@exposes` but not in `@feature`, and the global list still errored on 3 of 10 realistic prose lines, including the exact line that broke this repo during the sweep. Per-verb takes that to 1 of 10; the survivor (`@transfers … from …`, a keyword `@transfers` genuinely owns) is real ambiguity with `@shield` as the deterministic override. A bare verb with nothing after it is an error, not prose | verified independently across 8 cases; `ParseDiagnostic` gained a machine-readable `code` |

| D30 | **Med — OPEN** | **`launchAgentInline` accepts an `autoYes` option and never reads it.** All three call sites pass `{ autoYes: true }` — `cli/index.ts:797`, `tui/commands.ts:1379` and `:1607` — and nothing in the function body touches `opts`. Three callers believe they are suppressing an agent's confirmation prompt; none of them is. Found by the no-unused-vars cleanup, which is exactly the class of finding the brief warned about: an unused parameter that is a dropped behaviour, not dead weight. **Not fixed here** — implementing it changes what three commands do. Kept in the signature behind a narrow `eslint-disable` with a comment, because deleting it would silently reframe three callers' intent from "ignored" to "never asked for" | `src/agents/launcher.ts:203`; callers verified by grep |
| D31 | **Med — OPEN** | **`launchAgent` discards the agent's process exit code.** `launchAgentForeground` returns `{ exitCode, error }`; the caller checks `error` only, so a terminal agent that exits NON-ZERO without a spawn error is reported as `launched: true`. A failed agent run looks like a successful one. **Not fixed here** — propagating it is a behaviour change | `src/agents/launcher.ts:321` |
| D32 | ~~High~~ **FIXED (see commit)** | **`guardlink link --remove` truncated agent files at the workspace marker.** `cleanupRemovedRepo` computed `endIdx` — the end of the workspace block, exactly as its own comment intends — then wrote `content.slice(0, markerIdx).trimEnd() + '\n'`, discarding everything from the marker to EOF. Any section a user wrote after the workspace block was destroyed. The insert path in the same file (`slice(0, markerIdx) + block + slice(endIdx)`) has always been correct: this was a line that was never finished, not a design choice. Fixed by splicing head and tail, with the empty-head case handled separately — when the block is first in the file, `head + '\n' + tail` would emit a leading blank line. **Audit of the same shape elsewhere: clean.** The only other marker-splice sites are `link.ts:729` (insert) and `init/index.ts:474` (`replaceOrAppend`), both of which preserve their tail; every other file rewriter (`clear.ts`, `apply-annotations.ts`, `migrate-mode.ts`, `reanchor.ts`) is line-array based and cannot drop a tail by construction | 7 tests over six file shapes, all byte-exact; found by the no-unused-vars cleanup |
| D33 | ~~High~~ **FIXED (see commit)** | **The MCP server shipped actively false guidance.** `instructions` arrives at initialize, before any tool call, so it is the first thing every connected agent reads. It told them a `.gal` under `test/` is "silently dropped — do not put one there until GL-503 lands". GL-503 landed in `4b49ece`; the claim steered agents away from a directory that works. **Root cause: the GL-401 test PINNED it** (`expect(text).toMatch(/silently dropped/)`) — an assertion that was correct when written and became a stale-claim *enforcer* the moment the defect was fixed, so the text could not be corrected without a test failing. **Two more stale claims found in the same audit:** the `guardlink_graph` paragraph still recommended "depth 1-2 with direction in or out", which contradicts the shipped defaults (depth 2 / both) and predates `detail`, and it named neither `detail` nor `completeness`; and the 400-word budget test measured only the mode this repo happens to be in — external was 426 words and null 403, both over, unmeasured. All three fixed. `.guardlink/README.md` and the synced agent block were already correct and are covered by their own tests. **Mechanism, not one more corrected string:** `tests/instructions-claims.test.ts` pairs each behavioural claim with a probe that runs the real code (a `.gal` under `test/` is actually written and parsed; every envelope field named is asserted present on a real envelope; the recommended graph defaults are compared against `traverseGraph`'s own), plus a general guard rejecting any *expiring* phrasing — `GL-\d+`, "until … lands", "known gap", "not yet", "for now" — because a claim gated on unlanded work is false the day it ships and has no alarm attached | audited 2026-08-10; 11 probes; the word budget now measured in all three modes |

**Line-reference drift** found in Phase 0 verification (cosmetic, behaviour confirmed in
every case): `parse-project.ts` 104-110 → 108-113 and 137 → 141; `cli/index.ts` 419-427 →
416-425; `parse-file.ts` 100-108 → 102-110; `lookup.ts` 225-288 → 225-289; `lookup.ts`
dispatch range is 69-134 (§3.2 said 96-132, Appendix A said 70-132 — the PRD contradicted
itself). All other citations verified exact.

### 3.4 Phase 0 measurement results — U1, U2, U3 RESOLVED

Measured against `main` @ a463523 on branch `feat/machine-readable-surface`.

**U1 — coverage math, inline vs external.** Two scratch repos, identical logical model
(19 annotations, identical relation census), differing only in storage location.

| Field | Inline | External | Δ |
|---|---|---|---|
| `source_files` | 7 | 9 | +28.6% |
| `annotated_files` | 3 | 5 | +66.7% |
| `unannotated_files` | 4 | 4 | 0 |
| `coverage_percent` | 0 | 0 | — (dead field, D14) |
| annotations parsed | 19 | 19 | 0 |

Annotated ÷ scanned as a reader would compute it: inline 42.86%, external 55.56%, true
logical value 33.33%. **Mode-induced drift: +12.70 pp for zero semantic change.**
D1 confirmed exactly (2× per externally-annotated file). D2 confirmed for `source_files`,
**refuted for `coverage_percent`** — that field is hardcoded `0` (D14).

**U2 — full-model dump size.**

| | guardlink | specter-v1 |
|---|---|---|
| annotations / source_files | 312 / 67 | 247 / 8,142 |
| `report --format json` (pretty) | 85,083 B | 776,714 B |
| minified | 59,730 B | 716,874 B |
| minified, minus file lists | 58,014 B | 67,943 B |
| `serializeModelCompact()` | 10,484 B | 2,498 B* |

\* *not representative — specter-v1 has inline annotations but **no** `.guardlink/`
definitions, so assets/threats/controls are all 0 and every `#tag` is dangling. Only
guardlink's 10,484 B is a trustworthy compact measurement.*

**The finding that matters:** on specter-v1, `unannotated_files` alone is 646,200 B —
**90.1% of the dump** — a flat path list carrying no threat-model information. The real
model is 67,943 B, only 5% larger than guardlink's on a repo with 121× the file count.
**Model content does not scale with repo size; the file inventory does.** Dropping
`unannotated_files` from `guardlink_parse` is a one-line change worth 90% on large repos —
and `guardlink_unannotated` already exists as the dedicated tool for that data. This
outranks compact mode (GL-205) for large repos; compact is the whole win on small ones
(82.4% on guardlink).

**U3 — dashboard composition.** Measured 1,268,772 B (guardlink) / 3,739,214 B
(specter-v1). *The PRD's original "~2.5 MB" was not a measurement of anything.*

| Component | guardlink | % | specter-v1 | % |
|---|---|---|---|---|
| Mermaid diagram source (3 generators) | 17,173 B | 1.35% | 10,580 B | 0.28% |
| Inline CSS | 37,921 B | 2.99% | 37,921 B | 1.01% |
| Inline JS | 499,545 B | 39.37% | 1,113,566 B | 29.78% |
| HTML markup / other | 731,306 B | 57.64% | 2,587,727 B | 69.21% |

Largest single diagram: `dataflow.mmd` at 7,081 B / 161 lines. The bulk of the file is
`sec-code` (every annotated file, every annotation): 45% on guardlink, 65.8% on specter-v1.

**Resolution: standalone top-level `.mmd` files are usefully small. Per-feature emission
is OPTIONAL, not mandatory.** Diagram size tracks declared node/edge count — a
human-authored quantity — not repo size. Note the generators have no node cap
(`diagrams.ts:33` truncates descriptions only), so growth is unbounded in principle;
`by-feature/` stays in GL-301 as cheap insurance against future density, **reframed as a
hedge rather than a present necessity**.

**Context from 5ca53eb** (topology graph removal, required reading for GL-303): the D3
force-directed view was removed because it *rendered as an unreadable hairball on large
codebases* — a legibility-at-scale failure specific to force layout, not an argument
against emitting derived views. The three surviving Mermaid views were kept precisely
because they render legibly, and those are exactly what GL-301 fans out from. The specific
defect does not transfer to text consumed by an agent. *(Adjacent: the dashboard still
loads `d3.v7.min.js` from CDN — leftover from that removal, out of scope, worth a
separate ticket.)*

---

## 4. Goals and non-goals

### Goals

- **G-A.** Any consumer can retrieve a scoped, precise slice of the threat model without
  dumping the whole thing.
- **G-B.** A coding agent pointed at a file can obtain everything GuardLink knows about
  that file in one call, in either annotation mode.
- **G-C.** A cold agent with no prior instruction discovers GuardLink's capabilities and
  learns how to use them, through at least one surviving discovery path under
  external-mode-default.
- **G-D.** Every derived artifact and every query response carries provenance sufficient
  to detect staleness.
- **G-E.** External mode is production-ready as the default: enforced layout, correct
  coverage math, drift detection.

### Non-goals

- Replacing the HTML dashboard. It stays the human-facing artifact.
- A query language. The vocabulary stays a small set of named forms.
- Automatic annotation writes without human review. `@accepts` remains human-only;
  propose-never-apply is unchanged.
- Live file watching / daemon mode. Cache invalidation is on-demand, not push-based.

### Success metrics

| Metric | Baseline | Target |
|---|---|---|
| Relation types returning content via `lookup` | 10 / 19 | 19 / 19 |
| Calls to answer "what does GuardLink know about `src/x.ts`" | not answerable | 1 |
| Median bytes returned for a scoped query | full model | ≤ 5% of model *content* |
| Discovery paths surviving under external default | 0 | ≥ 2 |
| Tool responses carrying freshness metadata | 0 / 18 | 18 / 18 |

---

## 5. Personas

| ID | Persona | Primary need |
|---|---|---|
| P1 | **Coding agent with MCP** (Claude Code, Cursor) | Scoped, fresh, precise answers mid-task; knowing *when* to ask |
| P2 | **Coding agent without MCP** | Discover `.guardlink/` cold and self-orient from files alone |
| P3 | **Human developer** | Viewable, diffable diagrams; knowing what to annotate next |
| P4 | **Security reviewer / CTO** | Blast radius, ownership, PII paths, governance queue |
| P5 | **Sibling Bugb tooling** (CXG, Bravos) | Query by CWE; know whether a finding is already declared |

---

## 6. Architectural spine

One selector, three renderers. This is the load-bearing decision of the epic.

```
selectSubgraph(model, {from, depth, direction, kinds, file, feature}) → ThreatModel
  ├─→ JSON          →  MCP: guardlink_graph / guardlink_context
  ├─→ Mermaid       →  generateThreatGraph(...)  [existing, unchanged]
  └─→ .mmd artifact →  pre-computed common selections on disk
```

A subgraph is a filtered `ThreatModel`. A diagram is `generateThreatGraph(model)`.
`filterByFeature` already proves the composition works. Therefore **`guardlink_graph` and
the `.mmd` artifacts are the same feature** — build the selector once and the artifacts
become a disk cache of common selections, while the MCP path stays staleness-proof by
construction because it computes at call time.

**Implication for sequencing:** SG-2 (selector) must land before SG-3 (artifacts).
Building artifacts first would mean writing the selection logic twice.

---

## 7. Story groups

| ID | Group | Blocks | Blocked by |
|---|---|---|---|
| SG-1 | Provenance & Freshness | SG-2, SG-3, SG-4, SG-5 | — |
| SG-2 | MCP Query Expansion | SG-3 | SG-1 |
| SG-3 | Artifact Emission | — | SG-1, SG-2 |
| SG-4 | Agent Cold-Start & Discovery | — | SG-1 |
| SG-5 | External-Mode Readiness | — | SG-1 |

SG-1 is a shared dependency: the `annotation_hash` primitive it introduces is consumed by
cache invalidation (SG-2), artifact staleness headers (SG-3), the `CLAUDE.md` freshness
marker (SG-4), and `.gal` drift detection (SG-5). One implementation, four consumers.

---

## SG-1 — Provenance & Freshness

*Foundation. Nothing else in the epic is trustworthy without it.*

### GL-101 — Annotation hash primitive
**As** any consumer of the threat model, **I want** a stable content hash of the annotation
set, **so that** I can tell whether what I am reading reflects the current code.

- Compute `annotation_hash` over parsed annotation content only — not the file tree, not
  mtimes of unrelated files. Cosmetic code edits must not invalidate it, or consumers
  learn to ignore the warning.
- Surface on `ThreatModel.metadata` alongside the existing `schema_version` / git SHA.
- Deterministic across machines and across annotation modes: the same logical model
  authored inline vs. externally must hash identically.

**Acceptance**
- [ ] Reordering annotations within a file does not change the hash.
- [ ] Reformatting surrounding code does not change the hash.
- [ ] Adding, editing or deleting any annotation does change the hash.
- [ ] The same model authored inline and externally produces the same hash.
- [ ] Unit tests cover all four cases above.

### GL-102 — Freshness envelope on every MCP response
**As** P1, **I want** every tool response to carry `{annotation_hash, git_sha, generated_at, mode}`,
**so that** I can detect a cached or stale answer without a second call.

> **Scope correction (Phase 0).** This is not "add a hash to an existing envelope."
> `grep populateMetadata src/mcp/server.ts` → **0 hits**; `grep metadata` → **0 hits**.
> `populateMetadata` runs only in the CLI report path (`cli/index.ts:369`).
> `guardlink_parse` returns `JSON.stringify(model)` of the raw parse result
> (`server.ts:99-101`) and all three resources do the same. **There is no metadata on the
> MCP surface at all.** GL-102 builds the envelope from nothing — a larger job than §3.1
> originally implied.

**Acceptance**
- [ ] All 18 existing tools and all new tools return the envelope.
- [ ] Envelope is a sibling of the payload, never mixed into it.
- [ ] The three resources carry it too.
- [ ] Documented in `docs/SPEC.md`.

### GL-103 — Fix MCP cache invalidation *(fixes D5)*
**As** P1, **I want** the model cache to invalidate when annotations change on disk,
**so that** `lookup` and `status` stop serving a stale model for an entire session.

- Key the cache on `root` **plus** a cheap fingerprint (mtime+size over annotation-bearing
  files) rather than `root` alone.
- External mode makes this more urgent: the `.gal` changes while the source file does not,
  so there is even less incidental signal that something moved.

**Acceptance**
- [ ] Editing an annotation and re-calling `guardlink_lookup` returns updated results with
      no explicit invalidation call.
- [ ] Fingerprint cost is characterised **per-file**, not at a single scale.
      Measured on the Phase 1 implementation: ~17 µs/file — 2.97 ms at 1,000 files,
      0.74 ms on guardlink (70 files), 136.7 ms on specter-v1 (8,142 files).
      *The original criterion ("< 50 ms on a 1,000-file repo") passed at 2.97 ms while
      the real cost at 8k files sits far outside what that number implies. State the
      per-file rate and the largest scale you intend to support.*
- [ ] At every scale measured, the check must remain cheaper than the parse it replaces
      (achieved: 5.3% / 3.7% / 12.6% of a full parse respectively).
- [ ] **No grace window.** Skipping re-fingerprint within N ms of the last check trades a
      bounded staleness window for latency — reintroducing exactly the bug class GL-103
      exists to kill. If per-call latency on very large repos becomes a real complaint,
      raise it as a separate decision with its own evidence.
- [ ] Regression test: edit a `.gal`, confirm `status` reflects it.
- [ ] **D11:** `guardlink_clear` calls `invalidateCache()`. It mutates annotations on disk
      and currently does not — the tool that *caused* the divergence is the one that knows
      it happened. Confirmed: no invalidate exists between `server.ts:400` and `:540`.
- [ ] Audit all 18 tools for the same class of bug: any tool that writes must invalidate.

### GL-104 — Resource scoping *(fixes D9)*
**As** P4 working in a linked workspace, **I want** resources to be unambiguous about which
repo they describe, **so that** I do not silently read a sibling repo's model.

**Acceptance**
- [ ] Resources either accept a scope or declare the root they answered for in the payload.
- [ ] Workspace test with two linked repos returns correct, labelled data for each.

### GL-105 — Ref-resolution correctness *(fixes D6, D7, D8, D13)* **[severity raised]**
**As** P1, **I want** ref lookup to return the right record and be honest about how it
matched, **so that** I do not act on a confidently wrong answer.

> **Scope correction (Phase 0).** This was scoped as "hygiene." It is a correctness bug.
> Two wrong answers reproduce on GuardLink's **own committed definitions**:
>
> - `lookup("threat dos")` → returns `#redos` (ReDoS), `count: 1`, with 9 unrelated
>   affected assets. `#redos` is declared at `definitions.ts:36`, `#dos` at `:39`;
>   `lookupThreat` uses `.find()` (`lookup.ts:293`) and `"redos".includes("dos")`
>   short-circuits at `:444`, so **the exactly-declared `#dos` is never reached.** The
>   response is indistinguishable from a correct one.
> - `lookup("asset cli")` → `relationships.exposures.length === 14`, but only 5 are
>   declared on `#cli`. All 9 of `#llm-client`'s exposures are merged in, unmarked,
>   because `"llm-client".includes("cli")`. `inbound_flows` (13) and `outbound_flows` (7)
>   are contaminated identically. An agent auditing the CLI is told it is exposed to SSRF
>   and prompt-injection, which belong to the LLM client.
>
> A `matched_via` label surfaces the second case but **does not fix the first**, where the
> correct record is dropped entirely rather than mislabelled.

**Acceptance**
- [ ] `src/mcp/server.ts:89` reads version from `package.json`; no hardcoded string.
- [ ] **Exact-match precedence:** `lookupThreat`, `lookupControl` and `lookupAsset` resolve
      an exact id/name match before any substring candidate. Regression tests for both
      cases above, asserted against the real `.guardlink/definitions.ts`.
- [ ] Every ref-resolving result carries `matched_via: 'exact' | 'alias' | 'substring'`.
- [ ] When a substring match is returned, the result names what it matched *against*.
- [ ] `lookupThreat` and `lookupControl` adopt the `declared` / `referenced_in` shape that
      `lookupAsset` already uses (`lookup.ts:225` vs `:291`, `:308`).
- [ ] **D18 — substring resolution must survive.** Exact-match *precedence* must not become
      exact-match *exclusivity*. Verified regression cases: `threat denial` → `#dos`,
      `threat inject` → `#cmd-injection` or an honest ambiguity result, `control valid` →
      the validation control. Each pinned by a test.
- [ ] **Ambiguous substring sets are reported, not silently resolved.** `asset client`
      matches both `#cli` and `#llm-client` at substring tier and currently returns `#cli`
      with no signal. Either return the set or name the ambiguity.
- [ ] `lookupAsset`, `lookupThreat` and `lookupControl` agree: a ref that resolves in one
      must resolve in all three at the same tier. Pinned by a test.

---

## SG-2 — MCP Query Expansion

*The core value delivery of the epic.*

### GL-201 — `guardlink_context(root, file, [line])` **[P0 — highest use frequency]**
**As** P1 having just opened a file, **I want** everything GuardLink knows about it in one
call, **so that** I understand the security contract before I edit.

Returns, scoped to the file:
- annotations declared there, with line anchors
- assets they reference, and depth-1 neighbours of those assets
- open exposures and `@confirmed` findings touching the file
- controls the file is expected to uphold (`@mitigates`, `@validates`)
- `@assumes`, `@handles`, `@owns` in scope
- `annotation_source: 'inline' | 'external'` and, in external mode, the `.gal` path to write to

Implementation is a grouping over `location.file`. Works unchanged in both modes because
`@source` already resolves `location` to the logical source file
(`src/parser/parse-file.ts:100-108`).

**Acceptance**
- [ ] Accepts either the logical source path **or** the `origin_file` (`.gal`) path and
      returns the same result set.
- [ ] Returns `annotation_source` and, in external mode, the resolved `.gal` write path.
- [ ] Optional `line` narrows to the enclosing symbol where `parent_symbol` is available.
- [ ] A file with no annotations returns an explicit empty result — distinguishable from
      an error or an unparsed file.
- [ ] Response size: **median ≤ 10% of model content**, with the max reported separately.
      Measured on the Phase 2a implementation — guardlink 2,684 B median (4.39% of
      61,111 B content); specter-v1 4,626 B median (6.83% of 67,702 B); max 18,977 B on
      `.guardlink/definitions.ts`.
      *Criterion corrected. The original "≤5% of full model" was restated mid-epic as
      "≤5% of model content" without adjusting the threshold — tightening a denominator
      from 716 KB to 68 KB while holding 5% constant made the target ~10× stricter by
      accident. The depth-1 neighbourhood is 55–60% of every response and is the
      specified value of the feature, not overhead. The figure that matters is the
      practical one: 4.6 KB instead of 68 KB, a 14× saving on the question the tool
      exists to answer.*
- [ ] **`neighbour_detail` — NOT IMPLEMENTED. Measured saving 0.0%; recommended against.**
      The ruling was to mirror GL-202's `detail` on the neighbourhood: drop `description`,
      compact `location` to `file:line`, reusing `summariseGraphPayload`'s transform.
      *The premise about where the bytes are is correct* — measured across the same five
      files (`.guardlink/definitions.ts`, `agents/prompts.ts`, `mcp/server.ts`,
      `parser/parse-line.ts`, `cli/index.ts`), the neighbourhood is **52.2%** of the
      response and skews to **67.0%** on lightly-annotated `parse-line.ts`, confirming the
      shape of the ruling's 58.1% / 76%.
      *The mechanism cannot act on them.* `lookup`'s asset projection already strips both
      fields before they reach `relationships`: of **408 neighbourhood rows across the five
      files, 0 carry `description` and 0 carry `location`**. Rows are already
      `{"threat":"#path-traversal","severity":"high"}`. Applying the transform is byte-for-
      byte identical output on every one of the five files — 71,746 B before and after.
      The neighbourhood is expensive because of row *count* (408 rows), not row *content*.
      *What would work, measured on the same five files:* collapsing each already-compact
      row to its string form (`"#path-traversal [high]"`, `"#sqli via #prepared-stmts"`)
      saves **33.3%** overall and **45.1%** on `parse-line.ts` — the file that skews
      hardest — and is lossless. Serialising just the neighbourhood unindented saves 15.9%.
      Neither is the ruling's transform, so neither was implemented; both are available
      to rule on. A row *cap* would also work and is **not** recommended: it reintroduces
      the silent-partial-answer path that the GL-202 completeness work removed, and would
      need the same "what was omitted" reporting to be safe.

### GL-202 — `guardlink_graph(...)` — subgraph selector *(closes G2, G3)*
**As** P4 about to change an asset, **I want** the transitive neighbourhood and paths
between two nodes, **so that** I can assess blast radius before committing.

Signature: `(root, from, depth=2, direction='both'|'in'|'out', kinds[], format='json'|'mermaid')`
plus a `path from X to Y` form.

Implements `selectSubgraph` from §6. `format: 'mermaid'` reuses `generateThreatGraph` on
the filtered model — no second renderer.

**Acceptance**
- [ ] `depth` 1 reproduces current `lookup asset X` output exactly (regression guard).
- [ ] `depth` ≥ 2 traverses flows transitively; cycles terminate.
- [ ] `path from X to Y` returns ordered hops, or an explicit no-path result.
- [ ] `format: 'mermaid'` output renders in a standard Mermaid viewer.
- [ ] `kinds[]` filters which relation types are included.
- [ ] **RESOLVED (720a510, 39371bc).** The cost is per-node payload, not depth:
      `description` + `location` are 48.7% of a depth-2 response. Ruling: keep
      `depth=2, direction='both'`; add `detail: 'summary' | 'full'`, default summary
      (ids, kinds, edges, severity, compact `file:line`). Measured saving 36–40% —
      short of the 48.7% my ruling implied, because the ruling itself chose to keep
      `file:line`, which costs back ~12pp. That was the right trade: an agent that knows
      an exposure exists but not where it was declared cannot go read it. Topology is
      identical between modes, pinned by 26 tests.
- [ ] ~~Defaults must sit in the affordable regime.~~ Measured on the Phase 2b
      implementation (model content 61,914 B on this repo): `depth=1/both` 6.6 KB (11%),
      `depth=2/out` 20.6 KB (34%), **`depth=2/both` 46.4 KB (77%)**, `depth=3/both`
      exceeds a full dump. The shipped defaults are `depth=2, direction='both'`
      (`server.ts:407-408`) — the most expensive corner measured. A default invocation
      costing ~77–86% of model content inverts the epic's purpose.
      *Decision required:* default `depth=1`; or default `direction='out'`; or keep both
      and enforce a byte budget using the existing `truncated` flag. Recommended: the
      third — depth ≥ 2 is the tool's whole value, so cap output rather than cripple the
      default.
- [ ] **RESOLVED (39371bc).** Replaced the boolean with three states: `complete`
      (frontier exhausted, nothing more to find), `depth_limited` (complete for the
      requested depth, but unexplored nodes remain — with a count), `truncated` (nodes
      dropped to fit a limit; result INCOMPLETE). Root cause: the old flag tested
      `frontier.length > 0` — a question about what the result already *contains*, not
      what is *missing* from it. The boolean was removed rather than aliased, because a
      faithful alias would have to reproduce the wrong answer on the very case that
      motivated the change. Verified: `#llm-client` d1-out and d2-out both now report
      `complete` (were `true`/`false` for identical results); `#cli` d20 reports
      `complete`, not `truncated`, because the clamp cost nothing.
- [ ] ~~The `truncated` flag must mean one thing.~~ Observed: `#llm-client d1 out` reports
      `trunc=true` while `d2 out` reports `trunc=false` with an identical 4 nodes /
      6 edges. If depth 1 truncated, its result was incomplete; the flag currently
      conflates "budget hit" with "frontier saturated."

### GL-203 — Reach the 9 orphaned relation types *(closes G4)* **[priority raised to P0]**
**As** P4, **I want** to query ownership, data classification, assumptions, audits,
transfers, validations, comments, shields and external refs, **so that** I stop dumping the
full model for questions the model already answers.

Query forms: `owner of X` / `who owns X`, `handles pii` / `pii`, `assumptions for X`,
`audits [for X]`, `transfers [for X]`, `validations for X`, `comments for X`.

> **Scope correction (Phase 0).** Two changes.
>
> **The count was wrong.** `shields` and `external_refs` are also never read in
> `lookup.ts`, and `audits` is read at `:235` but discarded (the `declared` branch at
> `:244-251` returns only exposures, mitigations, confirmed, inbound_flows,
> outbound_flows). **Nine types unreachable, not seven.** Content-returning types number
> 10, not 12.
>
> **This is a correctness bug, not a missing feature (D12).** The orphaned forms do not
> error — they fall through to `lookupFuzzy`, and `matchRef`'s reverse-substring rule at
> `:446` matches the query string itself. Measured: `owner of #cli`,
> `assumptions for #cli` and `comments for #cli` all return **byte-identical**
> `{type:"mixed", count:1, results:[{type:"asset", id:"cli"}]}` containing zero ownership,
> assumption or comment data. An agent asking "who owns this" gets a successful-looking
> answer with none of what it asked for.

**Acceptance**
- [ ] All 9 types reachable; 19/19 coverage verified by a test asserting against the
      `ThreatModel` interface field list.
      *Corrected in Phase 2a: `acceptances` is a **tenth** orphan, not a ninth — Appendix A
      called it "a boolean flag, not content," which would have forced a special case into
      any honest 19/19 test. It now has its own form. The coverage test enumerates array
      fields off the runtime model, so a relation added to `assembleModel` fails the test
      until someone registers a query form.*
- [ ] `@handles` queryable by classification *and* by asset.
- [ ] Results carry `location` and, in external mode, `origin_file`.
      *Corrected in Phase 2a: `comments for X` and `shields for X` as **asset-scoped**
      queries are not expressible — `@comment` and `@shield` carry only `description` and
      `location`, with no asset reference. Implemented as location scoping instead: a
      path-shaped scope selects by file; an asset-shaped scope returns rows sharing a file
      with that asset, every row tagged `join: "co-located"` so a proximity inference is
      never presented as a declared relation.*
- [ ] **Unknown query forms are rejected explicitly** rather than falling through to fuzzy
      matching. An unrecognised form returns a `no_match` with the list of supported forms
      — never a confident wrong payload.
- [ ] Regression test: the three measured D12 queries return correct data or explicit
      rejection, never the `#cli` asset record.

### GL-204 — Query by external ref *(closes G5 — the CXG bridge)*
**As** P5, **I want** to ask "where does `cwe:CWE-89` appear, and which sites are already
mitigated", **so that** a CXG finding can be checked against declared knowledge automatically.

**Acceptance**
- [ ] `cwe:CWE-89`, `owasp:A03`, and bare `CWE-89` all resolve.
- [ ] Result partitions sites into mitigated / accepted / open / confirmed.
- [ ] Documented in `docs/SPEC.md` as the supported CXG integration point.

### GL-205 — Shrink `guardlink_parse` output *(U2 resolved — reprioritised)*
**As** P1 on a large repo, **I want** a full dump that contains only threat-model content,
**so that** the expensive call stays affordable when I genuinely need it.

> **Scope correction (Phase 0).** Compact mode was the wrong headline. On specter-v1,
> `unannotated_files` alone is **646,200 B — 90.1% of the dump** — a flat path list with
> no threat-model information. The real model is 67,943 B, only 5% larger than
> guardlink's on a repo with 121× the file count. **Model content does not scale with
> repo size; the file inventory does.** `guardlink_unannotated` already exists as the
> dedicated tool for that data.

**Acceptance**
- [ ] `guardlink_parse` omits `unannotated_files` by default (opt-in flag to include).
      Measured effect on specter-v1: 716,874 → 67,943 B.
- [ ] `compact: true` exposes `serializeModelCompact`. Measured on guardlink:
      59,730 → 10,484 B (82.4%).
- [ ] The specter-v1 compact figure (2,498 B) is **not** used as evidence — that repo has
      no `.guardlink/` definitions, so assets/threats/controls collapse to zero. A large
      repo *with* definitions remains unmeasured; do not extrapolate.

---

## SG-3 — Artifact Emission

*Depends on SG-2's selector. Artifacts are a disk cache of common selections.*

### GL-301 — Emit `.mmd` and model artifacts
**As** P2 and P3, **I want** plain-text diagram sources and the model on disk, **so that** I
can read, diff and render them without parsing a 1.2–3.6 MB HTML file of which the
diagrams are 0.28–1.35%.

```
.guardlink/
  model.json                    # full ThreatModel
  graph/
    README.md                   # agent-facing: what these are, how to refresh
    MANIFEST.json               # per-artifact hash, generated_at, git_sha
    threat-graph.mmd
    dataflow.mmd
    attack-surface.mmd
    by-feature/<name>.mmd       # scoped, small — near-free via filterByFeature
```

**Acceptance**
- [ ] Emission is a fan-out at the existing generation step in `src/dashboard/generate.ts`
      — the generators are called once and their output is written, not regenerated.
- [ ] Every `.mmd` opens in a standard Mermaid viewer without edits.
- [ ] `by-feature/` emitted for every distinct `@feature` value. **U3 resolved: this is a
      hedge against future density, not a present necessity.** Top-level `.mmd` files are
      17,173 B total on guardlink (1.35% of the dashboard); largest single diagram is
      7,081 B / 161 lines. Cheap to keep — guardlink has 2 features, specter-v1 has 0 —
      but it is insurance, and the generators having no node cap (`diagrams.ts:33`
      truncates descriptions only) is the reason to carry it.
- [ ] `MANIFEST.json` records `annotation_hash` per artifact (GL-101).
- [ ] HTML dashboard output is byte-identical to pre-change output (no regression).

### GL-302 — Provenance headers and drift check
**As** P1, **I want** each `.mmd` to declare when and from what it was generated, **so that**
I do not silently trust a stale file that looks like source.

A `.mmd` in the repo *looks like source*. This is the central risk of emission: a
confidently wrong dataflow diagram is worse than no diagram, because the reader will not
go verify.

**Acceptance**
- [ ] Every `.mmd` carries a `%%` header with `annotation_hash`, `git_sha`, `generated_at`,
      generator version. **Corrected in Phase 4: `generated_at` and `git_sha` are NOT stored.** A clock in a tracked file that a pre-commit hook regenerates guarantees the file always looks changed — F1's disease, made automatic. Header carries `annotation_hash` + generator (which moves only on a version bump, a real reason output can differ); the volatile two are reported on `guardlink artifacts` stdout. Also: never emit a bare `%%` line — mermaid reads it as the start of a `%%{init}%%` directive and fails. Pinned.
- [ ] `guardlink validate --artifacts` recomputes and exits non-zero on mismatch.
- [ ] Pre-commit hook **regenerates** rather than blocking — derived artifacts must never
      block a commit.
- [ ] `.gitattributes` marks artifacts `linguist-generated`; documented that conflicts are
      resolved by regeneration, never by hand-merge.

### GL-303 — Canonicalise the diagram generator set
**As** a maintainer, **I want** one canonical set of diagram generators, **so that**
`report --diagram-only` and `.guardlink/graph/threat-graph.mmd` cannot disagree.

`report --diagram-only` uses `src/report/mermaid.ts:generateMermaid` — a **fourth**
generator, distinct from the three in `src/dashboard/diagrams.ts`. This is the one genuine
divergence risk that exists in the codebase **today**, independent of this epic.

**Acceptance**
- [ ] A decision is recorded: unify, or document why two sets exist.
- [ ] If unified, `report --diagram-only` output change is called out in `CHANGELOG.md`.
- [ ] Commit 5ca53eb ("remove Risk Topology graph and Pentest Findings page") is read
      first — a D3 topology view was built and then deliberately removed. Whatever
      motivated that removal is direct input to this decision and to SG-3.

### GL-304 — Gitignore and commit policy
**As** P2 cloning a repo fresh, **I want** artifacts present without running anything,
**so that** I get context on first read.

Current `GITIGNORE_ENTRY` (`src/init/templates.ts:404-408`) ignores `.guardlink/*.json`
except `config.json`. That rule matches direct children only, so `graph/MANIFEST.json`
survives but `model.json` would be ignored. This needs a deliberate decision, not an
accident of glob depth.

**Acceptance**
- [ ] Explicit decision recorded for `model.json` and `.mmd` files: committed or ignored.
- [ ] `GITIGNORE_ENTRY` updated to match the decision.
- [ ] Rationale documented in `.guardlink/graph/README.md`.

---

## SG-4 — Agent Cold-Start & Discovery

*Priority raised by external-mode-default: see §8. Under external default, both existing
discovery paths disappear.*

### GL-401 — MCP server `instructions` *(closes G7)*
**As** P1, **I want** orientation at initialize time, **so that** I know *when* to call these
tools, not merely what each one does.

`createServer()` (`src/mcp/server.ts:86`) passes only `{name, version}`. The MCP protocol's
server-level `instructions` field arrives before any tool call and is currently unused —
the cheapest high-leverage fix in the epic.

**Acceptance**
- [ ] `instructions` names the trigger moments: open a file → `guardlink_context`; before
      finishing → `guardlink_validate`; after a change → `guardlink_diff`.
- [ ] Under 400 words.
- [ ] Names the annotation mode in effect and where to write annotations.

### GL-402 — `.guardlink/README.md` *(closes G8)* **[P0 under external default]**
**As** P2 with no MCP and no instruction file, **I want** the `.guardlink/` directory to
explain itself, **so that** I can use the threat model at all.

This is the backstop that catches every case where the other paths failed — and under
external-mode-default it is the *only* surviving path.

**Acceptance**
- [ ] Written by `init` in both modes.
- [ ] Addressed to an agent reader, not a human skimmer.
- [ ] Covers: what this directory is; annotation mode in effect; where `.gal` files live
      and how paths map to source; available CLI commands; available MCP tools and how to
      enable them; what the `graph/` artifacts are and how to refresh them; one worked
      example of answering a real question.
- [ ] Regenerated by `guardlink sync` so it never drifts from actual capability.
- [ ] **It must work as a writing reference, not only an orientation.** Phase 3's
      cold-start test found the README succeeds at orientation and at the two
      wrong-conclusion traps, but fails for an agent that needs to *extend* the model:
      the annotation grammar is shown by example and never stated (where `[critical]`
      goes, whether `cwe:` is required, the `@flows A -> B via M` shape), and
      `GUARDLINK_REFERENCE.md` is never named. Under external default this is the only
      path — an agent that can query but not write is half a tool. Inline the verb table
      and name the reference file.
- [ ] The `graph/` artifacts section is **deliberately absent until SG-3 ships** — a cold
      agent sent looking for a directory `init` never creates is worse off than one told
      nothing. Pinned by a test so it is not forgotten when SG-3 lands.

### GL-403 — Rework the synced agent-file block
**As** P1 reading `CLAUDE.md`, **I want** the block to lead with capability and declare its
own freshness, **so that** I treat GuardLink as a tool rather than a compliance tax.

`buildModelContext` (`src/init/templates.ts:169`) is well-built — IDs, open exposures,
confirmed, flows, features, stats. Four specific weaknesses:

1. Opens with "you MUST add annotations." A cold agent parses that as overhead. Lead with
   what it *gets*, then the obligations.
2. Truncates at 25 exposures / 20 flows with `... and N more` and no retrieval pointer.
3. No freshness marker — cannot tell a model from this commit from one from March.
4. `guardlink_diff` and `guardlink_context` never appear in the Workflow section, though
   `diff` is the one command that answers "did I make this worse."

**Acceptance**
- [ ] Block opens with capability framing; obligations follow.
- [ ] Truncated lists point at the tool or artifact that returns the remainder.
- [ ] Block carries `annotation_hash` (GL-101) **only**.
      *Criterion corrected after Phase 3. The original asked for `synced_at`, `git_sha`
      and `annotation_hash` in the tracked block, without considering what "tracked"
      means. Measured: one `guardlink validate` now dirties all 7 agent files with a
      9-line diff. Two churn sources — `synced_at` moves on wall clock and carries no
      information; `git_sha` moves on every commit, and since the block is regenerated by
      `validate` it is permanently one commit behind and permanently dirty. Only
      `annotation_hash` moves when and only when the thing it describes moves. All three
      already ship in the MCP envelope (GL-102), computed per call, touching no disk —
      that is where the volatile two belong.*
      Combined with D16 this matters: a read-only-sounding command that produced no diff
      for an unchanged model now always produces one.
- [ ] Workflow section includes `guardlink diff HEAD~1` and `guardlink_context`.

---

## SG-5 — External-Mode Readiness

*Prerequisite for making external mode the default. Carries a migration.*

### GL-501 — Codify the `.gal` path convention *(fixes D3)*
**As** an agent writing an annotation, **I want** a deterministic answer to "where does the
`.gal` for this source file go", **so that** placement is not left to an LLM following an
example.

Today `.guardlink/annotations/<mirrored path>.gal` appears exactly twice in the codebase,
both inside an LLM prompt string (`src/agents/prompts.ts:54-55`), phrased as an example.
`DEFAULT_INCLUDE` globs `**/*.[gG][aA][lL]` anywhere in the tree, so any placement parses
and nothing catches drift. **The layout of the primary annotation store would be enforced
by an LLM following an example** — unacceptable for a default mode.

**Acceptance**
- [ ] `resolveGalPath(root, sourceFile)` exists as code and is the single source of truth.
- [ ] `guardlink validate` flags `.gal` files off-convention as warnings, with the expected
      path in the message.
- [ ] The prompt in `agents/prompts.ts` is generated from the resolver, not hand-written.
- [ ] Off-convention `.gal` files still parse — the convention is enforced by warning, not
      by silently dropping data.

### GL-502 — Correct coverage math *(fixes D1, D2; gated on U1)*
**As** P4 tracking coverage over time, **I want** coverage to mean the same thing in both
modes, **so that** migrating a repo does not move the number for no real reason.

**Acceptance**
- [ ] U1 measured — **done, see §3.4.** Observed: `source_files` 7→9 (+28.6%),
      `annotated_files` 3→5 (+66.7%), derived ratio drift +12.70 pp.
- [ ] `annotated_files` excludes `.gal` paths, matching the existing `unannotated_files`
      filter at `parse-project.ts:141`.
- [ ] `source_files` excludes `.gal` from the denominator.
- [ ] Test: the same logical model authored inline and externally yields identical
      `source_files` and `annotated_files`.
- [ ] **D14 decision recorded:** `coverage_percent` is hardcoded `0` at
      `parse-project.ts:194` and never computed for a single repo — only in the multi-repo
      merge path (`workspace/merge.ts:478`). Three consumers display 0% today
      (`dashboard/data.ts:95`, `analyze/index.ts:407`, `tui/commands.ts:506`). **Either
      compute it or delete the field and its consumers.** Shipping a hardcoded 0% in the
      dashboard is a user-visible wrong number. The original acceptance criterion
      ("identical `coverage_percent` across modes") passed vacuously — 0 == 0 — while both
      real defects remained. This is a scope increase the PRD did not previously carry.

### GL-503 — `.gal` discovery under excluded paths *(fixes D4)* **[must land WITH GL-501]**
**As** a developer annotating test infrastructure, **I want** `.gal` files under `test/` to
be found, **so that** annotations do not silently vanish.

> **Severity raised (Phase 0).** Measured, not inferred. A `.gal` written at the
> **documented** convention path `.guardlink/annotations/test/helper.ts.gal` was silently
> dropped: file counts unchanged, annotation count unchanged, **no diagnostic**.
> `**/test/**` in `DEFAULT_EXCLUDE` (`parse-project.ts:61`) matches at any depth. Under
> external-as-default this is **silent data loss triggered by following the
> documentation** — the convention (GL-501) points into a directory the parser refuses to
> read. Shipping GL-501 without GL-503 would codify a path that destroys data.
> Also affects `tests/`, `__tests__/`, `vendor/`, `build/`, `dist/`, `target/`.

**Acceptance**
- [ ] A `.gal` mirroring a source path under any excluded directory is parsed.
- [ ] Source files under those directories remain excluded — only the annotation sidecar
      is rescued.
- [ ] Regression test covers both halves, and specifically the measured `test/helper.ts`
      case.
- [ ] Sequenced in the same change set as GL-501.

### GL-504 — `guardlink_annotate_apply` — structured write tool *(closes G9)*
**As** P1, **I want** to write a well-formed `@source` block via a tool, **so that** the write
is deterministic, validated and reversible rather than free-handed prose editing.

This is what external mode unlocks: writes land in `.guardlink/`, never in code. No diff
noise in the source tree, no risk of mangling logic, PRs stay reviewable. It also fits
propose-never-apply better than "here is a prompt, go edit source."

**Acceptance**
- [ ] Signature `(root, file, line, symbol, annotations[])`; appends to the resolved `.gal`.
- [ ] Output validated before write; malformed input rejected with a diagnostic.
- [ ] Returns a diff of what was written.
- [ ] Refuses `@accepts` — human-only governance, unchanged.
- [ ] Idempotent: re-applying the same block does not duplicate it.

### GL-505 — `guardlink_reanchor` — drift detection *(closes G10)*
**As** P3 after a refactor, **I want** to find `@source` blocks whose file/line no longer
resolves to the recorded symbol, **so that** externalised annotations do not rot.

This is the maintenance burden external mode *creates*, and the strongest argument against
external-as-default. It must ship in the same release, not trail it.

**Acceptance**
- [ ] Detects blocks where `symbol:` no longer matches the code at `file:line`.
- [ ] Proposes a corrected line where the symbol is found elsewhere in the same file.
- [ ] Reports, does not auto-apply, unless explicitly confirmed.
- [ ] Surfaced through both CLI and MCP.

### GL-506 — Decouple footprint from annotation mode *(fixes D10)*
**As** P1 on a repo using external mode, **I want** the root `.mcp.json` present, **so that**
the MCP surface is auto-discovered.

`src/init/index.ts:172,182` bundles two orthogonal decisions under one flag: *where
annotations live* and *how much footprint exists outside `.guardlink/`*. A six-line
`.mcp.json` that unlocks the entire tool surface is a very cheap exception.

**Acceptance**
- [ ] `--mode external|inline` governs annotation storage only.
- [ ] A separate `--no-root-files` governs footprint outside `.guardlink/`.
- [ ] New default: external annotations **with** root `.mcp.json` and synced agent files.
- [ ] `--no-root-files` reproduces today's external behaviour exactly, for users who chose
      it deliberately.

### GL-507 — Migration and default switch
**As** an existing user, **I want** the default change to be non-breaking, **so that** an
upgrade does not silently alter my repo.

**Acceptance**
- [ ] Existing repos keep their current mode; the new default applies to `init` only.
- [ ] `guardlink migrate --to external` converts inline annotations to `.gal` sidecars.
- [ ] Migration is reversible (`--to inline`).
- [ ] `annotation_hash` (GL-101) is identical before and after migration — proving no
      semantic change. **This is the migration's correctness test.**
- [ ] `CHANGELOG.md` documents the default change prominently.

---

## 8. Key decision — external mode inverts the discovery priority

`src/init/index.ts:172,182`: external mode **skips agent instruction files entirely** and
**moves `.mcp.json` inside `.guardlink/`**, where MCP clients do not auto-discover it.

Under external-as-default, both existing discovery paths vanish:

| Path | Today (inline default) | Under external default | After GL-402 + GL-506 |
|---|---|---|---|
| A — auto-loaded MCP | works | **gone** | works |
| B — synced `CLAUDE.md` | works | **gone** | works |
| C — find `.guardlink/` cold | undocumented | **only path, undocumented** | documented |

Two consequences, both already folded into the stories above:

1. **GL-402 (`.guardlink/README.md`) is promoted from cheap backstop to P0.** It is the only
   surviving path in the interim and the permanent backstop afterwards.
2. **GL-506 must land with or before the default switch.** Shipping external-as-default
   without decoupling footprint would ship a regression in agent usability.

**Recommendation:** do not switch the default until SG-4 and SG-5 are both complete.

---

## 9. Sequencing

| Phase | Contents | Rationale |
|---|---|---|
| **0 — Measure** | ~~U1, U2, U3~~ | **COMPLETE.** Results in §3.4. Four PRD claims corrected, four new defects found (D11–D14). |
| **0.5 — Hotfix?** | D12, D13 (+ D11, D6) | **DECISION REQUIRED.** These are silent-wrong-answer bugs in **released** code (v1.4.5 on npm), reproducing on GuardLink's own committed definitions. They are contained fixes in `lookup.ts` and do not depend on anything else in the epic. Options: (a) patch release ahead of the epic, (b) fold into Phase 1 and release with it. Leaning (a) — a shipped tool that answers "who owns this?" with a confident wrong record is worse than a missing feature. |
| **1 — Foundation** | SG-1 (GL-101 → GL-105) | Four downstream consumers. GL-105's scope grew materially (D13 exact-match precedence). |
| **2 — Query** | GL-201, GL-203, GL-205 *(2a — done)* · GL-202, GL-204 *(2b — done)* | **COMPLETE.** 375 tests. §6's composition claim held exactly — `generateThreatGraph(selectSubgraph(model, opts))` works with `src/dashboard/` untouched, which is what SG-3 depends on. Two decisions deferred out: `guardlink_graph` defaults (above) and renaming `ThreatModel.external_refs` → `cross_repo_refs` (breaking, needs a `schema_version` bump). |
| **3 — Discovery** | SG-4 (GL-401 → GL-403) | **COMPLETE.** 431 tests. D21 and D22 found and fixed. Two follow-ups: strip `synced_at`/`git_sha` from the tracked block (above), and close the README grammar gap the cold-start test surfaced. |
| **4 — Artifacts** | SG-3 (GL-301 → GL-304) | **COMPLETE.** 465 tests. GL-302 acceptance argued down with measurement: headers carry `annotation_hash` + generator only, consistent with F1. GL-303 decided as keep-both (different projections, measured). GL-304 commits the artifacts. One carry-over: D26. |
| **5 — External readiness** | GL-501+GL-503+GL-502+D14, GL-504, GL-505, GL-506, GL-507 | **COMPLETE — but the default flip is BLOCKED on D27.** 571 tests. Migration proven byte-identical by annotation_hash, both directions, round-trip diff clean. D14 resolved by computing coverage_percent rather than deleting it — correct, because GL-502 had just made both sides of the ratio mode-invariant. Two silent `@shield` migration bugs caught by the hash gate that a count check would have passed. |

**Shippable increments:** Phase 0.5 alone is a defensible patch release. Phase 1 fixes real
bugs. Phase 1 + GL-201 is a coherent release delivering most of the agent-facing value.
Phase 3 can ship any time after Phase 1.

**Housekeeping, unrelated to the epic:** `package-lock.json` is modified in the working
tree (1.4.3 → 1.4.5, a correct but uncommitted byproduct of the version bump), and `main`
is 1 commit ahead of `origin/main` (a463523, a real tested parser fix). Both should be
resolved before the epic branch diverges further.

---

## 10. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Emitted `.mmd` files look like source and go stale | High — a confidently wrong diagram is worse than none | GL-302 provenance headers + drift check; hook regenerates rather than warns |
| External-mode migration changes model semantics | High — silent corruption of a customer's threat model | GL-507: `annotation_hash` must be identical pre/post migration |
| Coverage numbers shift on migration | Medium — breaks historical comparison, undermines measurement discipline | GL-502 gated on U1; record observed magnitude before fixing |
| Tool-list bloat degrades agent tool selection | Medium — more tools can mean worse choices | GL-401 `instructions` names trigger moments; consider consolidating `report`/`dashboard`/`sarif` behind one export tool |
| Substring matching returns wrong node silently | Medium — agent acts on bad data | GL-105 `matched_via` field |
| Scope creep into a query language | Medium — unbounded work | Non-goal in §4; vocabulary stays a fixed set of named forms |

---

## 11. Open questions

1. **Split the epic?** SG-5 carries a migration and a default change. It may warrant its own
   epic with its own release gate. Recommendation: keep it here for now — GL-101 and GL-201
   are shared dependencies and splitting would duplicate the evidence base.
2. **Commit artifacts or ignore them?** (GL-304.) Committing gives fresh clones instant
   context and makes model changes visible in PR review; it costs repo churn on every
   annotation edit. Leaning commit, with `linguist-generated`.
3. **Unify the diagram generators?** (GL-303.) Changes `report --diagram-only` output.
4. **Consolidate export tools?** `report`, `dashboard`, `sarif`, and new artifact emission
   are four tools doing one job. A single `guardlink_export(format)` would shrink the tool
   list, at the cost of a breaking MCP change.
5. **Should `guardlink_context` be the advertised entry point** in `instructions`, ahead of
   `guardlink_status`? Probably yes for P1; `status` remains the better cold-open call.

---

## Appendix A — Current MCP surface (v1.4.5, `main` @ a463523)

**Tools (18):** `parse`, `status`, `validate`, `suggest`, `lookup`, `threat_report`,
`annotate`, `report`, `dashboard`, `sarif`, `diff`, `threat_reports`, `sync`, `clear`,
`unannotated`, `review_list`, `review_accept`, `workspace_info`

**Resources (3):** `guardlink://model`, `guardlink://definitions`, `guardlink://unmitigated`

**`lookup` query forms (`src/mcp/lookup.ts:69-134`):** `unmitigated` (:69), `confirmed`
(:74), `features` (:79), then the regex forms (:95-132) — `threats for X`, `controls for X`,
`flows into X`, `flows from X`, `boundary for X`, `asset X`, `threat X`, `control X`,
`exposures for X`, `mitigations for X` — then `lookupFuzzy` as fallback.

**Unreachable relation types (9):** `ownership`, `data_handling`, `assumptions`,
`transfers`, `validations`, `comments`, `shields`, `external_refs`, and `audits` (read at
`:235` but discarded — the `declared` branch at `:244-251` returns only exposures,
mitigations, confirmed, inbound_flows, outbound_flows; the undeclared branch emits `audits`
only as a label). `acceptances` returns as a boolean flag, not content. Addressed by
GL-203.

## Appendix B — Coding-workflow coverage

| Moment | Today | After epic |
|---|---|---|
| Cold open on repo | `status`, `CLAUDE.md` block | + `instructions`, `.guardlink/README.md` |
| **Opened a file** | **nothing** | `guardlink_context` |
| About to change an asset | `lookup asset X` (depth 1) | `guardlink_graph` blast radius |
| Wrote code, am I done | `validate`, `suggest` | unchanged |
| Did my change add exposure | `diff` (undiscoverable) | `diff`, surfaced in instructions |
| Does this path touch PII | **nothing** | `handles pii` |
| What am I assuming here | **nothing** | `assumptions for X` |
| Who reviews this | **nothing** | `owner of X` |
| Fix priority | `review_list --severity` | unchanged |
| Is this CWE already known | **nothing** | `cwe:CWE-89` |
