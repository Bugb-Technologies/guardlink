# Phase 0 — Reconnaissance & Measurement Record

**Epic:** GL-EPIC-001 — Machine-Readable Threat Model Surface
**Baseline:** `main` @ a463523, guardlink v1.4.5
**Branch:** `feat/machine-readable-surface`
**Status:** Complete. All measurements taken, not estimated.

This document is the measurement record for the Phase 0 gate. The PRD
(`EPIC-machine-readable-threat-model-surface.md`) has been updated to reflect these
results; this file preserves the raw evidence and the corrections made.

---

## 1. Corrections to the PRD

Six claims were wrong or understated. All six were corrected in the PRD.

| # | PRD claim | Verdict | Correction |
|---|---|---|---|
| 1 | D2: `coverage_percent` becomes non-comparable across annotation modes | **REFUTED** | `coverage_percent` is hardcoded `0` at `parse-project.ts:194`, never computed for a single repo. Only real assignment is `workspace/merge.ts:478` (multi-repo path). `guardlink status` never prints it. It cannot stop being comparable — it has never carried a value. Real D2 defect is `source_files` inflation alone (7 → 9). Logged as new defect **D14**. |
| 2 | §1 "~2.5 MB HTML dashboard" | **WRONG** | Measured 1,268,772 B (1.21 MB) guardlink; 3,739,214 B (3.57 MB) specter-v1. The figure was not a measurement of anything. |
| 3 | §3.1 "Provenance metadata already populated" | **Does not hold where needed** | `populateMetadata` runs only in the CLI report path (`cli/index.ts:369`). `grep populateMetadata src/mcp/server.ts` → 0; `grep metadata` → 0. GL-102 builds an envelope from nothing, not extending one. |
| 4 | G4 "7 relation types unreachable", "12 of 19 reachable" | **Understated + arithmetic error** | `shields` and `external_refs` are also never read. **9 unreachable, 10 content-returning.** And the gap is a correctness bug, not a missing feature — logged as **D12**. |
| 5 | D7 severity "Med"; GL-105 scoped as hygiene | **Understated + fix incomplete** | Two silent wrong answers reproduce on committed definitions. `matched_via` describes one but does not repair the other. Needs exact-match precedence. Logged as **D13**. |
| 6 | D4 severity "Med"; GL-503 sequenced after GL-501 | **Understated + wrong sequence** | Measured silent data loss when following the documented convention. GL-503 must land with GL-501. |

**New defects discovered:** D11 (`guardlink_clear` doesn't invalidate cache), D12 (unknown
query forms return confident wrong payloads), D13 (`.find()` substring precedence drops
exact matches), D14 (`coverage_percent` is dead and displayed as 0% by three consumers).

---

## 2. U1 — Coverage math, inline vs external

**Method.** Two scratch repos outside the guardlink tree. Identical
`.guardlink/definitions.ts` (2 assets, 2 threats, 2 controls). Six source files under
`src/`, four unannotated and byte-identical across repos, two annotated. Annotated files
are the same line count in both, so `@source line:` anchors point at the true code line.
Both parse to 19 annotations with an identical relation census (2 mitigations, 2 exposures,
2 flows, 1 boundary, 1 validation, 1 audit, 1 ownership, 1 data_handling, 1 assumption,
1 comment). **The logical model is identical; only storage location differs.**

| Field | Inline | External | Δ | Δ% |
|---|---|---|---|---|
| `source_files` | 7 | 9 | +2 | +28.6% |
| `annotated_files` | 3 | 5 | +2 | +66.7% |
| `unannotated_files` | 4 | 4 | 0 | 0% |
| `coverage.coverage_percent` | 0 | 0 | 0 | — |
| `coverage.total_symbols` | 0 | 0 | 0 | — |
| annotations parsed | 19 | 19 | 0 | 0% |

`annotated_files` contents:

```
inline   (3): .guardlink/definitions.ts, src/auth.ts, src/db.ts
external (5): .guardlink/annotations/src/auth.ts.gal
              .guardlink/annotations/src/db.ts.gal
              .guardlink/definitions.ts
              src/auth.ts
              src/db.ts
```

Derived ratio as a reader of `guardlink status` would compute it:

| | Inline | External | True logical value |
|---|---|---|---|
| annotated ÷ scanned | 3/7 = 42.86% | 5/9 = 55.56% | 2/6 = 33.33% |
| error vs. true | +9.52 pp | +22.22 pp | — |

**Mode-induced drift: +12.70 percentage points for zero semantic change.**

**Verdict.** D1 CONFIRMED exactly — `parse-project.ts:108-113` adds both `relPath` (the
`.gal`) and every `ann.location.file`; `unannotated_files` filters the `.guardlink/` prefix
at `:141`, `annotated_files` at `:139` does not. Effect is exactly 2× per externally-
annotated file. D2 CONFIRMED for `source_files`, REFUTED for `coverage_percent`.

---

## 3. U2 — Full-model dump size

**specter-v1 caveat, recorded before the numbers.** The repo has substantial inline
annotations (81 files contain GuardLink verbs; parser resolves 48 annotated files /
247 annotations) but **no `.guardlink/` directory and zero definitions**. Every `#tag` is a
dangling reference, so assets/threats/controls are all 0. This distorts the compact-mode
figure specifically. Full parse took 1.39 s on a 404 GB repo (349 GB `target/` and 51 GB
`src-tauri/` covered by `**/target/**`).

| | guardlink | specter-v1 |
|---|---|---|
| annotations | 312 | 247 |
| `source_files` | 67 | 8,142 |
| annotated / unannotated | 43 / 24 | 48 / 8,094 |
| assets / threats / controls | 16 / 15 / 12 | 0 / 0 / 0 |
| exposures / mitigations / flows | 62 / 49 / 74 | 61 / 92 / 23 |
| `report --format json` (pretty) | 85,083 B | 776,714 B |
| minified | 59,730 B | 716,874 B |
| minified, minus both file lists | 58,014 B | 67,943 B |
| `serializeModel()` | 61,591 B | 72,272 B |
| `serializeModelCompact()` | 10,484 B | 2,498 B (unrepresentative) |
| parse wall clock | 0.14 s | 1.39 s |

**specter-v1 dump composition (minified):**

| Key | Bytes | Share |
|---|---|---|
| `unannotated_files` | 646,200 | 90.1% |
| `mitigations` | 27,157 | 3.8% |
| `exposures` | 18,362 | 2.6% |
| `comments` | 8,797 | 1.2% |
| `flows` | 6,049 | 0.8% |
| `validations` | 4,253 | 0.6% |
| `annotated_files` | 2,691 | 0.4% |
| everything else | ~3,365 | 0.5% |

**Finding.** 90% of a large-repo dump is a flat path list carrying no threat-model
information. The actual model on specter-v1 is 67,943 B — 5% larger than guardlink's
58,014 B on a repo with **121× the file count**. Model content does not scale with repo
size; the file inventory does. On guardlink, where there is no path-list bloat, the dump is
genuinely relation-dominated (exposures 22.1%, flows 20.1%, mitigations 15.8%) and file
lists are only 1,716 B (2.9%).

**Consequence.** Dropping `unannotated_files` from `guardlink_parse` is a one-line change
worth 90.1% on large repos, and `guardlink_unannotated` already exists as the dedicated
tool for that data. This outranks compact mode. Compact is the whole win on small repos
(82.4% on guardlink). GL-205 rescoped accordingly.

**Explicitly unmeasured:** a large repo *with* a definitions file. Neither corpus is
representative — guardlink is small-and-complete, specter-v1 is large-and-definitionless.
The compact figure for that case cannot be bounded from these two points. Do not
extrapolate.

---

## 4. U3 — Dashboard composition

| | guardlink | specter-v1 |
|---|---|---|
| Total HTML | 1,268,772 B (1.21 MB) | 3,739,214 B (3.57 MB) |
| generation time | 0.14 s | 0.94 s |

`docs/examples/threat-dashboard.html` is byte-identical at 1,268,772 B — the committed
example matches current output.

| Component | guardlink | % | specter-v1 | % |
|---|---|---|---|---|
| Mermaid diagram source (3 generators) | 17,173 B | 1.35% | 10,580 B | 0.28% |
| Inline `<style>` | 37,921 B | 2.99% | 37,921 B | 1.01% |
| Inline `<script>` | 499,545 B | 39.37% | 1,113,566 B | 29.78% |
| HTML markup / other | 731,306 B | 57.64% | 2,587,727 B | 69.21% |

Per diagram, raw generator output:

| Diagram | guardlink | specter-v1 |
|---|---|---|
| `threat-graph.mmd` | 6,648 B / 150 lines | 7,045 B / 112 lines |
| `dataflow.mmd` | 7,081 B / 161 lines | 1,505 B / 25 lines |
| `attack-surface.mmd` | 3,444 B / 87 lines | 2,030 B / 46 lines |
| total | 17,173 B | 10,580 B |

Escaped-and-wrapped in the HTML the diagram tabs measure 22,092 B on guardlink (1.74%).

**What actually fills the file** — `sec-code` ("Code & Annotations": every annotated file,
every annotation) is 570,851 B / 44.99% on guardlink and 2,459,490 B / 65.78% on
specter-v1. All three diagram tabs combined are 1.74% and 0.38% respectively.

**Resolution: standalone top-level `.mmd` files are usefully small. Per-feature emission is
OPTIONAL.** All three diagrams together are ~4,300 tokens; the largest single one is
7,081 B / 161 lines. An agent reading all three pays 1.35% of what it pays to read the HTML.

Two supporting observations:

1. **Diagram size does not track repo size.** specter-v1 has 121× guardlink's file count
   and produces *smaller* diagrams. Size tracks declared node/edge count — a
   human-authored quantity.
2. **The generators have no node cap.** `diagrams.ts:33` truncates descriptions only; there
   is no `slice(0, N)` on nodes or edges. Growth is unbounded in principle.
   *Speculative extrapolation, labelled as such:* a model 10× guardlink's declared size
   would produce a ~66 KB threat-graph, ~17k tokens — readable but no longer free.
   `by-feature/` is the right insurance for that regime and `filterByFeature` makes it
   near-free, but neither corpus measured here needs it today.

---

## 5. Context — why the topology graph was removed (5ca53eb)

Required reading for GL-303 and SG-3. Rationale from the commit message: the
force-directed D3 topology view rendered as an unreadable hairball on large codebases,
dense enough to obscure the threat model rather than explain it. The three Mermaid views
already covered the same relationships legibly, so the tab, its builder and its renderer
were removed.

**What this does and does not imply for `.mmd` emission:**

- The argument that killed topology was *"this rendering does not survive density."* It was
  **not** *"we should not emit derived views."*
- The surviving three views were kept precisely because they render legibly — and those are
  exactly what GL-301 fans out from.
- The failure mode was visual: D3 force layout collapses at high node counts. A `.mmd` file
  consumed by an agent is read as text; it has no layout to collapse. **The specific defect
  does not transfer.**
- What does transfer is the scaling instinct. Measurement above puts that threshold well
  beyond both corpora.

The same commit removed a `pentestData` blob and ~400 lines of CSS, and retained the alias
map with cross-kind dedup because all three Mermaid generators use it. It did not touch the
generators GL-301 fans out from.

**Adjacent finding, out of scope:** the dashboard still loads `https://d3js.org/d3.v7.min.js`
from CDN at offset 38215 of the generated HTML — a leftover from this removal. For a
local-first, privacy-positioned tool this is an external network request for a library no
longer used. Worth a separate ticket.

---

## 6. Verification of PRD code claims

**Verified exact, no change required:** `diagrams.ts:231,467,587`; `dashboard/index.ts:12`;
`generate.ts:35-38`; `analyze/tools.ts:210`; `diff/git.ts:52`; `prompts.ts:54-55`;
`server.ts:64-81`, `:86`, `:89`; `lookup.ts:444-446`, `:225`, `:291`; `templates.ts:169`,
`:404-408`; `report/mermaid.ts:37`.

**Line drift (behaviour confirmed in every case):**

| Cited | Actual |
|---|---|
| `parse-project.ts:104-110` | `108-113` |
| `parse-project.ts:137` | `141` |
| `cli/index.ts:419-427` | `416-425` |
| `parse-file.ts:100-108` | `102-110` |
| `init/index.ts:172`, `:182` | `173`, `185-186` |
| `lookup.ts:225-288` | `225-289` |
| `lookup.ts` dispatch: §3.2 said `96-132`, Appendix A said `70-132` | `69-134` — the PRD contradicted itself; both now corrected |

**D5 — precise tool split.** `invalidateCache()` is called at six sites: `:98` (parse),
`:151` (validate), `:400` (sarif), `:540` (review_list), `:584` and `:594` (review_accept).

Tools that do **not** invalidate and serve a stale model for the whole session (13 tools +
3 resources): `status`, `suggest`, `lookup`, `threat_report`, `annotate`, `report`,
`dashboard`, `diff`, `threat_reports`, `sync`, `clear`, `unannotated`, `workspace_info`,
and all three resources.

**D11 (new).** `guardlink_clear` (`server.ts:476-505`) strips annotation lines from source
files on disk and does not invalidate. There is no `invalidateCache()` call anywhere
between `:400` and `:540`. After a non-dry-run clear, every subsequent `status` / `lookup` /
`report` / `dashboard` call in that session reports annotations that no longer exist. This
is strictly worse than the general staleness in D5 — the tool that caused the divergence is
the one that knows it happened.

---

## 7. D12 and D13 — the two silent-wrong-answer paths

Both reproduce on GuardLink's **own committed** `.guardlink/definitions.ts`. No constructed
fixture was needed. Both are present in released v1.4.5.

### D12 — unknown query forms return confident wrong payloads

The orphaned query forms do not error. They fall through to `lookupFuzzy`, and `matchRef`'s
reverse-substring rule at `lookup.ts:446` matches the whole query string:

```
lookup("owner of #cli")        → {type:"mixed", count:1, results:[{type:"asset", id:"cli", …}]}
lookup("assumptions for #cli") → {type:"mixed", count:1, results:[{type:"asset", id:"cli", …}]}
lookup("comments for #cli")    → {type:"mixed", count:1, results:[{type:"asset", id:"cli", …}]}
```

All three return **byte-identical** payloads containing zero ownership, assumption or
comment data — because `"owner of #cli".includes("cli")` is true. An agent asking "who owns
this" receives `count: 1` and a successful-looking result.

### D13 — `.find()` substring precedence drops exact matches

```ts
if (candidate.length >= 3 && v.includes(candidate)) return true;   // lookup.ts:444
if (v.length >= 3 && candidate.includes(v)) return true;           // lookup.ts:446
```

**Case 1 — the wrong record is returned and the right one is silently absent.**
GuardLink declares `#redos` (ReDoS, medium) at `definitions.ts:36` and `#dos`
(Denial_of_Service, medium) at `:39`.

```
lookup("threat dos")
  → {type:"threat", count:1, results:[{id:"redos", name:"ReDoS", …, affected_assets:9}]}
```

`lookupThreat` uses `.find()` (`:293`). `#redos` precedes `#dos` in declaration order and
`"redos".includes("dos")` is true at `:444`, so the exact match on `#dos` is never reached.
`count: 1` — indistinguishable from a correct response. An agent asking about
denial-of-service is handed ReDoS and nine unrelated affected assets.
(`lookup("threat denial")` does return `#dos` correctly.)

**Case 2 — silent cross-asset contamination of severity data.**

```
lookup("asset cli") → results[0].relationships.exposures.length === 14
```

Only 5 exposures are declared on `#cli`. `#llm-client` declares 9. `"llm-client".includes("cli")`
is true, so all 9 are merged into `#cli`'s record with no marker. `inbound_flows` (13) and
`outbound_flows` (7) are contaminated identically. An agent auditing the CLI is told it is
exposed to SSRF and prompt-injection, which belong to the LLM client.

**GL-105 implication.** `matched_via` surfaces Case 2 but does **not** fix Case 1, where the
correct answer is dropped entirely rather than mislabelled. Case 1 requires exact-match
precedence in the `.find()`.

---

## 8. D4 — empirical probe

Written inside the external scratch repo, following the documented convention exactly:

```
test/helper.ts                             # 1 line, exports seed()
.guardlink/annotations/test/helper.ts.gal  # @source file:test/helper.ts line:1 symbol:seed
                                           # @exposes #db to #sqli [high] -- "D4 PROBE: …"
```

Result — before and after are identical:

```
Files scanned: 9   Files annotated: 5   Files unannotated: 4   Annotations: 19
exposures matching /D4 PROBE/ : []
```

The annotation vanished. No warning, no diagnostic, no count change. `**/test/**` in
`DEFAULT_EXCLUDE` (`parse-project.ts:61`) matches `.guardlink/annotations/test/…` at any
depth.

**Severity raised to High.** Under external-as-default, following the documented path
convention for anything under `test/`, `tests/`, `__tests__/`, `vendor/`, `build/`, `dist/`
or `target/` **silently destroys data**. GL-503 must be sequenced with GL-501 — shipping
the convention without the fix would codify a path that loses annotations.

---

## 9. Explicitly not run

Distinguishing "did not run" from "ran and found nothing":

**Did not run:**
- D9 live reproduction. Confirmed by code reading (`cachedRoot || '.'` at `server.ts:663`,
  `:676`, `:694`). No two-repo linked workspace was constructed.
- A large repo *with* a definitions file — none exists under `repositories/`.
- The test suite. No code was changed.
- MCP wire sizes. All serialization measured by calling `serializeModel` /
  `serializeModelCompact` / `JSON.stringify` directly against `dist/`. JSON-RPC envelope
  overhead unmeasured.
- `.mmd` rendering in a Mermaid viewer. Generator output measured as bytes only.

**Ran and found nothing:**
- Searched all of `src/` for any `.gal` path resolver, constant or validator (D3) — none
  exists. All 17 `.gal` hits are doc prose, extension checks, tool descriptions or comments.
- Searched all of `src/` for `parent_symbol` readers (G10) — exactly 3 hits, all writes or
  the type declaration. Zero reads.
- Searched `src/mcp/` for `external_refs` as a query key (G5) — appears once at
  `lookup.ts:160` as an echoed output field. `lookup("cwe:CWE-89")` → `no_match`, `count: 0`.
- Searched `src/mcp/server.ts` for `populateMetadata` / `metadata` — zero hits.
