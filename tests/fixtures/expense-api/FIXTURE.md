# Fixture: `expense-api`

A small Python/Flask expense service, annotated from a cold start by an agent that
had only the generated `CLAUDE.md` and `.guardlink/README.md` to go on. Preserved
from `/tmp/expense-api`, which macOS clears.

**This is the corpus that found D34, D35, D36 and D37**, plus D38–D47. It is worth
keeping because it is the only repo we have that decouples the properties this
repo's own model conflates:

| Property | `guardlink` | `expense-api` |
|---|---|---|
| Language | TypeScript | Python |
| Annotation mode | `inline` | `external` (`.gal` sidecars) |
| Born as | inline | **external** — never migrated |
| File count vs annotation count | correlated | decoupled (D34 needed this) |

## Not wired into the test suite

Deliberately. Wiring it in is follow-up work. Nothing here is currently imported by
a test.

**It does not perturb this repo's own model** — verified 2026-08-10 by taking
`guardlink status .` before and after the copy (identical: 83 files, 385
annotations, 16 assets, 15 threats). Three independent guards each suffice:

1. `tests` in this repo's `.guardlink/config.json` `exclude`
2. `**/tests/**` in the parser's `DEFAULT_EXCLUDE` (`parse-project.ts:95`)
3. this repo's `include` is `**/*.{ts,tsx,js,jsx}`; the fixture's annotations live
   in `.py` and `.gal` files, which match none of them

Guard 3 is the one that would break first: a future fixture carrying `.ts`
annotations relies on guards 1 and 2 alone. If this fixture is ever wired into the
suite in a way that needs it scanned, isolate it by parsing it with an explicit
`root` rather than by loosening this repo's `exclude`.

## Git history

The original repo's history is preserved as `../expense-api-git-history.bundle`
rather than a nested `.git/`. A nested `.git/` inside this repo stages as a gitlink
(mode 160000) — one line, zero files — so the fixture would have been committed
empty while looking committed.

```sh
git clone tests/fixtures/expense-api-git-history.bundle /tmp/expense-api-restored
```

Two commits: `97be6d1` the unannotated service, `0a8cb92` the same service after a
cold-start annotation pass. The first is the more useful of the two — it is a
ready-made "annotate this from nothing" starting point.

## Dropped from the copy

`threat-dashboard.html` (420 KB of generated output, `.gitignore`d in the original).
Regenerate with `guardlink dashboard`.
