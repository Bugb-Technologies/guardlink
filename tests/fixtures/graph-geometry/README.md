# Browser geometry oracle

These are frozen outputs of `generateThreatGraph` from the repository model at
e98c97a, with `icons: 'none'`; `all.mmd` also sets `showAll: true`.

Both sources were independently rendered in Chrome with Mermaid 11.17.2 at
1440×900, dagre-d3, `htmlLabels: false`, `useMaxWidth: false`, `maxTextSize: 50000`
and `maxEdges: 500`. Counts come from `.node`, `path.flowchart-link` and `.cluster`
in the resulting SVG, rather than the source counter under test:

| Source | Nodes | Links | Clusters |
|---|---:|---:|---:|
| `filtered.mmd` | 35 | 105 | 9 |
| `all.mmd` | 49 | 210 | 9 |

The old test measured the live repository against a historical browser count.
Adding an annotation in another branch changed that model and failed the test
without changing the counter. These fixed sources preserve the independent
geometry check while current generator output remains covered separately.

Do not regenerate these for ordinary model changes. If the counter or emitted
syntax changes, render the proposed sources in a browser again and compare the
SVG counts before updating either the source or its expectations.
