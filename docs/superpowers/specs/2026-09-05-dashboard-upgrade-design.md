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

### Second pass — analytics, tables, drawers (same day)

Review of the first pass on this repo and Temporal: tables wrapped and overflowed, the diagram
toolbar was four unstyled buttons, Threat Reports had no copy action, the asset popup repeated the
tile, no pagination, and the data the model holds was under-charted.

- **Analytics page** (`pages/analytics.ts` over `analytics.ts` builders, pure over the same
  `ClaimView` rows the tables render so every number agrees): asset × threat matrix (capped at 24
  assets × 14 threats with a note; the Threats page lists everything), severity × status, threats by
  frequency, control coverage including unused controls, files with the most open exposures; with
  attribution, people × quarter (years past 16 quarters) and AI tool × severity. `heatTable` in
  `html.ts` renders every grid: intensity is a `--h` custom property mixed into a tone colour,
  column labels are vertical, every cell is a hash-route link.
- **Tables**: `table.fixed` + `colgroup`, the claim as asset over threat, `locCellShort` as file
  name over directory with the full path in `title`/`data-v`, pager after every long table
  (`data-paginate="25"`, `.paged-out`, page size select; re-run after filter and sort; the feature
  filter re-paginates on change). Search splits on whitespace and requires every term.
- **Asset drawer**: `computeAssetDetails` precomputes one record per heatmap tile (index-aligned)
  embedded as `assetsData`; `renderAssetDrawer` in the client renders it. Tiles are one per asset:
  `computeAssetHeatmap` folds `#id`, dotted path and case onto the declared asset and carries
  `aliases` for the feature filter and the drawer.
- **Reports**: toolbar with copy-report / download `.md` from `savedAnalyses`, and copyable
  `guardlink threat-report <framework>` chips; the empty state is server-rendered so the chips exist
  without the client. **Diagrams**: segmented zoom group, copy-source, and a fit that shrinks the
  svg box to the panel width while keeping the viewBox (so "Fit" is the identity transform).
- New pinned contract: the page's inline script must parse (`new Function`), because a stray quote
  in the client string silently disables every control.

### Third pass — type, palette, icons, drawers

- Fonts: Helvetica Neue (UI) and Monoska (code) with JetBrains Mono as the loaded fallback; the
  Google Fonts link carries only the fallback. Palette: the ten brand colours as tokens, tints via
  `color-mix`; light theme accent is blue (`#0360a2`) because the brand green fails contrast as
  text on white, green stays for fills and "covered"; muted text is `#3b6779` on light and a
  55% mix of `#55899e` with `#f0f0f0` on dark. Critical badges are filled, high outlined.
- No emoji: `icon(name)` in `html.ts` renders inline SVG (Lucide-style paths); `ICONS` is
  embedded for the client. The Mermaid generators take `{ icons: 'emoji' | 'none' }` — the
  dashboard passes `none` and gets shapes (hexagon threat, pill control, cylinder store, flag
  external, status as shape on the attack surface) plus `sev_*` classes; artifacts and MCP keep
  the default emoji because GitHub's renderer has no other icon. Legends are SVG chips.
- Matrices: `table.heat` is `width: 100%` with no box, so a 3-column grid fills its panel.
- Drawers: 680px. The annotation drawer is the upgrade's own (`openAnnotationDrawer` in
  `client.ts`) over `FileAnnotation.fields/refs/claimIdx/assetIdx/url`, which
  `buildFileAnnotations(model, root, { claims, assets, links })` joins; the legacy builder is gone.
- Ledger: `computeLedgerStates` returns `entryByLocation`; `ClaimView.verifiedBy/verifiedAt`;
  the status band says "by X on date" (stale: "locked by X on date, code changed since"); the
  Verified-claims KPI says "all locked <date> by <who>" when nothing is stale or unverified.

### Fourth pass — change, ownership, sensitive data, feature-true analytics, diagram focus

- `--since <ref>`: `since.ts` (`loadSince`) validates the ref shape, `parseAtRef`s the model at
  the ref, `diffModels` against the rendered model, and records the ref's commit date and the
  commit count (facts of history, so the page stays deterministic per HEAD). `computeChanges`
  turns the diff into the summary strip; `newClaimKeys` (`verb@file:line`) marks new claim rows
  (`ClaimView.change`, `data-change`, the `change=new` route). "Went stale" = stale claims whose
  file changed since the ref — the historical model has no anchors, so that is the honest measure.
- `buildAssetIndex` canonicalises asset refs and answers `ownersOf` / `handlesOf`; every claim
  row carries `owners` and `handles` (`data-owner`, `data-handles`; `owner=` / `handles=` routes).
  `computeOwnership` (owners table + unowned exposed assets, plus the `unowned` action) and
  `computeSensitiveData` (per classification) feed two Analytics panels.
- Analytics is rendered per feature (`renderAnalyticsPage(ctx, variants)`; each variant is a
  `filterByFeature` model with its own claims/attribution/heatmap); the legacy dropdown calls
  `onFeatureFilter`, which swaps the `.analytics-body` and shows a `whole-model-note` on Diagrams
  and Attribution with the `--feature` command to copy.
- Diagrams: one focused threat graph per exposed asset (`selectSubgraph` depth 1), a find box that
  dims non-matching nodes, light fills swapped in by `themeMermaid` on the light theme, fit floor 60%.
- Reports: `linkifyIds` walks the rendered markdown's text nodes and links known `#ids`.
  Code: `computeFileRisk` + `fileRiskRank` order file cards riskiest first and badge them.

## Testing

- `tests/dashboard-actions.test.ts` — action list on fixtures: order, hrefs, commands, empty case, slice withholding.
- `tests/dashboard-upgrade.test.ts` — markup contracts: nav hrefs, sortable headers, row data attributes, search box, chips, link cells with/without a remote, ledger badges, drawer actions in the client script, KPI links.
- `tests/dashboard-links.test.ts`, `tests/blame-summary.test.ts` (analytics) — by the module owners.
- `tests/dashboard-analytics.test.ts` — the analytics builders on a fixture, the Analytics page markup and heat links, pagination hooks, the reports toolbar, the embedded asset details, and the inline-script parse check.
- Existing: `feature-dashboard`, `dashboard-determinism`, `blame-dashboard`, `dashboard` stay green unmodified.
- Every page screenshotted in Chrome on this repo and on Temporal before the PR.
