# Fixture: `boundary-direction`

A small inline-mode TypeScript service whose boundaries cover every way the
SARIF export states a boundary's sides (SPEC §6.6, §6.8):

| Boundary | Written | Sides in the export |
|---|---|---|
| `#edge` | `@boundary from Client to #web` | `basis: "declared"`, outer `client`, inner `web` |
| `#data` | `@boundary from #orders to #store` | `basis: "declared"`, outer `orders`, inner `store` — both sides are declared assets, so only the direction says which is outside |
| `#svc` | `@boundary between #web and #orders` | `basis: "unknown"` — two declared assets and no direction |
| `#backup` | `@boundary between #store and Backup` | `basis: "undeclared-endpoint"`, outer `backup` — inferred, because `Backup` is no declared asset |

Its `pentest` export is `tests/fixtures/sarif-pentest/boundary-direction.sarif`;
editing this fixture changes that export, so regenerate it with the command in
that directory's README.

It does not perturb this repository's own model: `**/tests/**` is in the
parser's `DEFAULT_EXCLUDE`.
