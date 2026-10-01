# Fixture: `sarif-shop`

A small inline-mode TypeScript service written to exercise every part of the
SARIF export that `expense-api` does not: route-channel `@flows`, a `@confirmed`
finding, `owasp:` references, a `@boundary` between two declared assets, a
`@transfers`, a covered exposure, a parse error and a dangling reference.

It is read by `tests/sarif-enrichment.test.ts`. Each annotation is placed for a
reason the tests rely on:

| Where | What it pins |
|---|---|
| `src/web.ts` `searchOrders` | a three-hop chain whose every hop is on the claim's handler, crossing two boundaries |
| `src/web.ts` `getOrder` | a `@confirmed` result gets a chain too |
| `src/web.ts` `deleteOrder` | flows into `#orders` exist in this file, but only on sibling handlers, so no chain is emitted; the `#csrf` exposure is the dangling reference |
| `src/notify.ts` | file-level claims: `file` attribution, `@transfers` scoped to one threat, no logical location; the trailing `@exposes #mailer to` is the parse error |
| `src/export.ts` | an exposure whose asset is only reached from another file, so no chain is emitted |

Editing this fixture changes the export it produces, so
`tests/fixtures/sarif-baseline/sarif-shop.sarif` must be regenerated with it —
see that directory's README.

It does not perturb this repository's own model: `tests` is excluded in
`.guardlink/config.json`, and `**/tests/**` is in the parser's `DEFAULT_EXCLUDE`.
