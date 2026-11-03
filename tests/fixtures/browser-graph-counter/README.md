# Browser-measured graph counter fixture

These filtered and whole-model Mermaid graphs freeze a representative GuardLink
repository model. Annotation changes in another branch must not change the input
to a counter conformance test. Current repository generation and model coverage
remain exercised by `query-views`, `graph-completeness` and `dashboard-system` tests.

`measurements.json` records independent Chrome SVG measurements at 1440×900 with
Mermaid 11.17.2. Initialize Mermaid with `defaultRenderer: 'dagre-d3'`,
`htmlLabels: false`, `useMaxWidth: false`, `maxTextSize: 50000`, `maxEdges: 500`.
Render each `.mmd`, insert its SVG into the document and count `.node`,
`path.flowchart-link` and `.cluster`. The expected counts must come from the SVG,
never from `countMermaidNodes` or `measureLegibility`.

To refresh the sample, replace both Mermaid files, repeat the browser measurement,
then update the SHA-256 hashes and measured counts together. The test checks the
hashes as well as node, edge and cluster counts for both graphs.
