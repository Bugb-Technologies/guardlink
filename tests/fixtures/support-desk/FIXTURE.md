# Fixture: `support-desk`

A small inline-mode TypeScript app that embeds a support agent, declared with
the reach verbs (SPEC §3.2.1). Each tool handler carries its `@agents` and the
`@effects` of the code it runs in one doc-block, so the two bind to the same
code (SPEC §5.5).

| Tool or job | Reach | Entitled? | Mutating effects | Gated? |
|---|---|---|---|---|
| `lookupOrder` | `@agents … to lookup-order` | yes, cited | — (`read`) | — |
| `runSql` | `@agents … to run-sql` | no | `delete #orders-db`, `write #users-db` | no |
| `issueRefund` | `@agents … to issue-refund` | yes, cited | `spend #payments` | yes: `@gates #payments … for issue-refund`, and the issue-refund reach is bound to the same code |
| `searchKb` | `@agents … to search-kb` | no: the entitlement names `#kb`, not `#tool-surface` (`other-asset`) | — (`read`) | — |
| `fetchUrl` | `@agents … to fetch-url` | no: the entitlement is uncited (`uncited`) | — | — |
| `mountFiles` | `@agents … to mcp-files` | no | `write #host-fs` | no |
| `sendEmail` | — | — | `notify #outbox` | yes: an unscoped `@gates #outbox` |
| `refundSweep` | — | — | `spend #payments` | no: the `#payments` gate is scoped to issue-refund and no reach is bound to this code (`capability-unknown`) |
| `release` | `@reaches #ci-runner to publish-package` | no | `write #registry` | no |

So: five unentitled reaches, seven mutating effects, five of them ungated.

Its `pentest` export is `tests/fixtures/sarif-pentest/support-desk.sarif`;
editing this fixture changes that export, so regenerate it with the command in
that directory's README. Its source files sit in one directory on purpose: the
parser reads files in directory-traversal order, and one directory keeps the
model's array order, and so the export's result order, the same on every run.

The `@entitles` lines have no accepted proposal behind them, so
`guardlink validate` reports them; nothing read from this fixture runs
`validate`.

It does not perturb this repository's own model: `**/tests/**` is in the
parser's `DEFAULT_EXCLUDE`.

`golden/` holds what `tests/agent-reach-surfaces.test.ts` pins from this
fixture for the human-facing surfaces: the derived view the dashboard's Agents
& Reach page and the report both draw (`reach-summary.json`), the report's
"Agents and LLM Reach" section (`agent-reach-section.md`), the agent-only
report (`threat-model-agents.md`) and the reach diagram (`agent-reach.mmd`).
Editing the fixture changes them too; regenerate with
`npx vitest run tests/agent-reach-surfaces.test.ts -u` and read the diff.
