# Dashboard upgrade — design

**Date:** 2026-09-05 · **Board:** GAP-18 · **Branch:** `feat/dashboard-upgrade` (stacked on `feat/blame-attribution`)

## Problem

The HTML dashboard reports but never directs. The Summary is fifteen equal-weight tiles and a
wall of open-threat cards; no page says what to do next; tables cannot be sorted or searched;
a file location is plain text; a row's only click opens a drawer with static sections; the
Attribution page (GAP-17) is tables without trends, rates or comparison. Screenshots of every
page were reviewed before this design.

## Goals

1. **Flow.** The Summary answers "how bad, and what now": grade, five KPIs that link to the
   filtered view behind them, and a computed *What to do next* list. Counts that do not change a
   decision move into a compact inventory strip.
2. **Clicks and CTAs.** The URL hash tracks page and filters, so back works and a view is
   shareable. Every table sorts. A global search filters the current page. Severity and status
   chips filter the Threats page; an identity chip filters Attribution. Every `file:line` links to
   the file at `HEAD` on the repo's web host when `.git/config` names one; every sha links to its
   commit. The drawer gains actions: copy the `guardlink verify` / `guardlink blame` command, open
   on the host, copy the path, previous/next.
3. **Crisp design.** Same palette and fonts; tighter type scale and spacing; sticky table headers;
   consistent chips; real empty states; light theme at parity; print-friendly.
4. **More attribution analysis.** Quarterly trend of exposures introduced (human vs AI-assisted)
   and fixed, cumulative open; exposures per 100 commits per person and per AI model from a
   one-call history walk; severity-weighted risk score; age of the oldest open exposure per
   identity; a human-versus-AI cohort card; the files most rewritten under open exposures; a
   click on any identity narrows the claims table; every chart carries a one-line reading guide.

## Non-goals

No chart library, no build step, no network beyond the CDNs already used (fonts, marked, d3,
mermaid). No new GAL syntax. No change to what `--feature` withholds. No wall clock: "now" is
the HEAD commit's author date.

## Architecture

`src/dashboard/generate.ts` (2,800 lines of template literals) becomes a composition root over
small modules. Public API unchanged: `generateDashboardHTML(model, root?, analyses?)`.

| Module | Holds |
|---|---|
| `generate.ts` | data assembly, shell (head, top bar, banners, sidebar, drawer), page composition, embedded data |
| `html.ts` | pure helpers: `esc`, `sevClass`, `badge`, `chip`, `kpi`, `statCard` (markup unchanged — a test pins it), `locCell`, `shaCell`, `sortableTable`, `scopeLabel`, `featureScope` |
| `links.ts` | `detectRepoLinks(root)` / `linksFromRemote(url)` → `{ host, web, file(path,line), commit(sha) }`; reads `.git/config`, no subprocess; links at `HEAD` so a committed dashboard does not churn |
| `data.ts` | existing builders + `computeActions(...)` and `computeLedgerStates(model, root)` |
| `pages/*.ts` | one renderer per page: `summary`, `reports`, `threats`, `diagrams`, `code`, `data-boundaries`, `assets`, `attribution` |
| `client.ts` | the inline script: routing, search, sort, chips, drawer + actions, copy, feature filter, theme, diagrams, reports |
| `styles.ts` | the stylesheet |

### Invariants pinned by existing tests

- Page ids `sec-summary`, `sec-ai-analysis`, `sec-threats`, `sec-diagrams`, `sec-code`, `sec-data`,
  `sec-assets`, `sec-attribution`; every page carries `scope-tag|scope-note` on a slice.
- The "Open Threats" tile markup `<div class="stat-card stat-danger"><div class="value">N</div><div class="label">Open Threats`.
- `const threatModel = {…};\n` embedded without `generated_at`; cross-process byte identity.
- Slice wording: title `PARTIAL: feature(s) …`, `id="scope-banner"`, `badge badge-scope`, top bar
  shows `Mitigated` not `Coverage`, code page withholds coverage and unannotated files with the
  exact sentence, data page empty-state sentence, reports page "whole-project</strong> documents".
- `data-ff` / `data-ff-asset` attributes and the `featureFilter` select keep the client feature
  filter working; the filter rewrites stat tiles by label text.
- Everything user-controlled goes through `esc()`; a co-author trailer is the realistic XSS vector.

### Routing and filters (client)

`#<page>` selects a page; `#<page>?k=v&k=v` applies filters: `q` (search), `sev` (comma list),
`status` (`open,mitigated,accepted`), `who` (identity or `tool model`), `file`. `showSection`
writes the hash; `popstate` and load read it. Filters act on `tr[data-search][data-sev][data-status][data-who][data-file]`.

### Actions (`computeActions`)

Ordered, deduplicated, each `{ id, level, title, detail, count, href?, command? }`:
confirmed → critical/high open → stale demotable claims (`guardlink verify --stale`) → unverified
claims when no ledger (`guardlink verify --all`) → AI-introduced open (with blame) → inert
entitlements → audits awaiting review → coverage below 40% (`guardlink annotate …`). Empty → one
"Nothing urgent" line. On a slice, project-wide items (coverage, unannotated) are withheld.

### Attribution analytics (blame summary)

`summarise(entries, { commits, as_of })` gains `trends[]`, `comparison`, `hot_files[]`, and per
row `commits`, `per_100_commits`, `risk_score`, `oldest_open_days`. `computeBlame` walks history
once (`listCommits`) to count commits per identity and per AI model; `history: false` skips it.

## Testing

- `tests/dashboard-actions.test.ts` — action list on fixtures: order, hrefs, commands, empty case, slice withholding.
- `tests/dashboard-upgrade.test.ts` — markup contracts: nav hrefs, sortable headers, row data attributes, search box, chips, link cells with/without a remote, ledger badges, drawer actions in the client script, KPI links.
- `tests/dashboard-links.test.ts`, `tests/blame-summary.test.ts` (analytics) — by the module owners.
- Existing: `feature-dashboard`, `dashboard-determinism`, `blame-dashboard`, `dashboard` stay green unmodified.
- Every page screenshotted in Chrome on this repo and on Temporal before the PR.
