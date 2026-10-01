# SARIF baselines

`tests/sarif-enrichment.test.ts` proves that the declared context the SARIF
export carries (SPEC §6.6) is additive: it deletes every member that context
adds and compares what is left with these files, byte for byte, on `results`
and on `tool` (the driver version aside).

| File | What it is |
|---|---|
| `expense-api.sarif` | `guardlink sarif tests/fixtures/expense-api`, cut before the declared context existed |
| `sarif-shop.sarif` | `guardlink sarif tests/fixtures/sarif-shop`, cut the same way |
| `expense-api.github.sarif` | the whole `github`-profile export of `tests/fixtures/expense-api`, declared context included, cut before `--profile` existed |
| `sarif-shop.github.sarif` | the same for `tests/fixtures/sarif-shop` |
| `sarif-schema-2.1.0.json` | the OASIS SARIF 2.1.0 JSON schema, unmodified, from `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`; every export in the test is validated against it |

**Do not regenerate the two `.sarif` files to make the test pass.** They are the
earlier export, and the test's claim is that nothing in `results` or `tool` has
moved since. Regenerate them only when a change to `results` or `tool` is
intended — a fixture edit, or a deliberate change to a rule or a message — and
say so in that change, because every consumer keyed on the result index,
`message.text` or a rule id sees it too. To regenerate one, export it with
`guardlink sarif` and delete the members the test's `strip()` deletes, so the
file stays the shape of the export without its declared context.

`tests/sarif-pentest.test.ts` compares the `github` profile, with no `--profile`
and with `--profile github`, against the two `.github.sarif` files, whole and
byte for byte (the package version aside). They exist so the `pentest` profile
can never leak into the default export. The same rule applies: regenerate them
only for an intended change to the `github` export, and say so. They are written
by `generateSarif` with no version-control provenance, which is what the test
compares.
