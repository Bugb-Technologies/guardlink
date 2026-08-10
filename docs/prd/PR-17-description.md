## What does this PR do?

Closes the defect sweep opened after GL-EPIC-001, plus the epic follow-ups it
turned up. 36 commits. The through-line is correctness of the answers GuardLink
gives about coverage and migration — several surfaces were confidently wrong
rather than merely unhelpful.

**Coverage now has exactly one implementation (D36, D57).** "Is this exposure
covered?" had been reimplemented twenty-one times and got the wrong answer in
twenty of them. D36 unified seven copies into `parser/coverage.ts` and narrowed
the rule so a mitigation on one symbol no longer clears an exposure on another in
the same file. D57 found thirteen more surfaces still on the old pair join —
`report`, `mermaid`, SARIF, the dashboard, the attack-surface diagram, the
`guardlink://unmitigated` resource, three prompt builders, `init`'s CLAUDE.md
block and the LLM `is_unmitigated` tool. Measured on a Python/Flask corpus, every
one said 9 where the predicate says 11, and the two they dropped included the
repo's only critical — a live SQL injection, absent from SARIF (so never a GitHub
Advanced Security alert), absent from the report headline (`9 (0 critical)`), and
absent from the CXG prompt that decides which threats get an exploit written for
them. `tests/coverage-single-implementation.test.ts` now fails the build on a
twenty-second copy.

**`migrate` can no longer silently destroy anchoring (D48).** An
external → inline → external round trip discarded all 21 `symbol:` anchors on the
test corpus while printing `✓ annotation_hash unchanged` — truthfully, because
GL-101 excludes `parent_symbol` by design so inline and external hash
identically. The anchoring now has its own hash, and `migrate --to inline`
refuses before writing, naming every anchor at risk, unless `--allow-anchor-loss`
is passed. `reanchor` also stopped reporting success on a repo with zero anchors.

**Also:** cross-repo tags parse unquoted in every reference position (D19); prose
beginning with a verb warns instead of failing the build (D29); `validate` and
`status` no longer rewrite tracked files (D16); `init --force` no longer destroys
a populated definitions file (D24); `report --diagram-only` and the dashboard are
byte-reproducible across processes (D23, D25); a subgraph carries the graph, not
the repo's file inventory (D34, D35); the MCP server's own claims are probed
rather than spell-checked (D33).

**Merged `main` (PR #16, @actor/@entitles).** 25 conflicts, 10 of them real. Both
sides were kept or composed in every case — see the merge commit for the
per-hunk record. Three things the merge itself needed: `actors` added to the
graph summariser's row list, `actors`/`entitlements` added to the anchor hash,
and `entitlementKey` reviewed and registered in the D57 allowlist as diff
identity rather than a coverage join.

### User-visible behaviour changes

- **Re-check anything you acted on from `lookup`/`status`/SARIF/report output on
  1.4.3–1.4.5.** Those surfaces under-reported unmitigated exposures wherever a
  mitigation and an exposure sat in the same file on different symbols, or
  differed only by a `#` prefix.
- **`report --diagram-only` output order changed once.** It is now canonically
  ordered and byte-identical across processes; a diff against a pre-1.5.0
  artifact will show a one-time reordering.
- **`traversal.truncated` was removed** from `guardlink_graph` in favour of
  `traversal.completeness`, which has three states (`complete`, `depth_limited`,
  `truncated`) because a boolean could not distinguish "there is more beyond this
  depth" from "the answer is incomplete".
- **`guardlink migrate --to inline` now exits 1** on a repo carrying symbol
  anchors unless `--allow-anchor-loss` is passed.

### Known issues shipping with this release

| | |
|---|---|
| D22 | Example annotations inside template literals parse as real ones; mitigated case-by-case with `@shield`, no authoring-time detection |
| D40 | `annotate_apply` reports `status: "written"` on a dry run |
| D41 | `annotate_apply` duplicates the `@source` header for any write that is not an exact whole-block match |
| D42 | `coverage.total_symbols` is always 0 and sits beside two unrelated fields; consumers fixed, wire format needs a `schema_version` bump |
| D46 | The `guardlink_graph` tool description hard-codes a measurement about this repo |
| D52 | SARIF driver version hardcoded `1.4.3` |
| D53 | `validate` reports a cross-repo tag as a dangling reference, indistinguishable from a typo |
| D54 | Merge tag-collision warnings double-count each id |
| D55 | A repo with no annotations passes `validate` with a green check |
| D56 | `guardlink ask` / `translate` fail confusingly outside a TTY (unverified — needs an interactive check) |
| D58 | The TUI prints "All security-relevant symbols are annotated!" unconditionally |

Full detail and reproductions: `docs/prd/EPIC-machine-readable-threat-model-surface.md` §3.3.

## Type

- [x] Bug fix
- [x] New feature — `anchor_hash`, `guardlink migrate --allow-anchor-loss`, `graph detail: summary`, the MCP query-set regression harness
- [ ] Annotation spec change
- [x] Documentation
- [x] CI / tooling

## Checklist

- [x] `npm run build` — tsc clean
- [x] `npm test` — 912 passing, 51 files (includes PR #16's `actor-entitlement` and `entitlement-proposal` suites)
- [x] `guardlink validate .` — passes; `--artifacts` gate exits 0
- [ ] `CHANGELOG.md` updated — **not done in this PR.** The user-visible changes
      above and the known-issues table are the raw material; they need an editing
      pass against the 1.5.0 release notes rather than a mechanical paste.

Also run: `npm run lint` (0 problems), `node scripts/query-set.mjs` (no drift on
both corpora), and the first-run walk in a fresh repo.

## Spec changes

**Annotation syntax is unchanged by this PR.** The `@actor` / `@entitles` grammar
arrives with PR #16 and is that PR's spec change, not this one. One merge
resolution touched the grammar and widened it rather than changing it:
`THREAT_REF` kept D19's cross-repo form over main's re-tightened
`#[a-zA-Z0-9_-]+`, so `@actor` and `@entitles` accept `#repo.tag` references like
every other verb. Strictly a superset — nothing that parsed before stops parsing.

`ThreatModel` / report-schema additions from this branch:

- **`ReportMetadata.annotation_hash`** — `sha256-v<n>:<hex>` over annotation
  content, excluding line numbers, `origin_file`/`origin_line` and
  `parent_symbol`, so inline and external authoring of one model hash
  identically. (Now `v2`: PR #16 added `@actor`/`@entitles` records.)
- **`anchor_hash`** — a second, deliberately mode-dependent hash over `@source`
  symbol anchors. Not in the report payload; emitted by `migrate`. Separate from
  `annotation_hash` precisely so the latter stays mode-invariant.
- **`coverage.coverage_percent` semantics** — it is FILE coverage (annotated
  files ÷ scanned files) and has no arithmetic relationship to
  `annotated_symbols` or `total_symbols`. It was previously hardcoded `0`. The
  field names are misleading and stay that way in this PR; see D42.
- **`annotated_files` / `source_files` exclude `.gal` sidecars**, so both sides of
  the coverage ratio are annotation-mode-invariant and the number does not move
  when a repo migrates.
- **`traversal.completeness`** replaces `traversal.truncated` on
  `guardlink_graph`.
