# Frozen fixture — model schema 1.1.0

**Deliberately frozen. Do NOT regenerate this directory.**

`report-1.1.0.json` is a threat-model report exactly as GuardLink **≤ 1.4.5**
wrote it, with the pre-1.2.0 `coverage` block:

```json
"coverage": {
  "total_symbols": 0,
  "annotated_symbols": 105,
  "coverage_percent": 100,
  "unannotated_critical": []
}
```

Model version 1.2.0 replaced that with `{ annotation_count, coverage_percent }`.
Running `guardlink artifacts` or `guardlink report` against this directory would
rewrite it into the current shape and silently delete the only thing it is for.

## What it guards

`guardlink merge` reads report JSON from disk, which is the one path where a
current binary meets an older repo's output. Before `normalizeCoverage`, merging
a report of this shape did `0 += undefined` — `NaN` — and `JSON.stringify(NaN)`
is `null`, so a workspace dashboard reported `"annotation_count": null` with
exit 0 and no warning.

The test in `tests/legacy-coverage-fixture.test.ts` asserts that reading this
file yields the real count (**105**) and not a coalesced `0`. A zero would stop
the `NaN` while still being wrong, which is the failure mode this fixture exists
to catch — so the assertion is on the value, not merely on it being a number.

Source: `git show 55d8111:tests/fixtures/expense-api/.guardlink/model.json` — a
genuine artifact emitted by GuardLink 1.4.5, unmodified apart from an added
`metadata` block (a merge input carries one) and the `_comment` marker. It was
not hand-written to the old shape; it *is* the old shape.
