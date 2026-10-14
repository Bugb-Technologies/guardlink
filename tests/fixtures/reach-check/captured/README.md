Tool results of `codegraph_reach_check`, as a code graph that implements the contract returned them, captured on 2026-10-14. Nothing here is constructed; recapture rather than edit when the contract moves.

| file | input | shows |
|---|---|---|
| `support-desk.reach-check.json` | `tests/fixtures/support-desk` with its model export | seven reaches walked; the refund's spend is `bypassed` while the annotations say `gated`; three `no_gate_declared`; three unreached effects |
| `ops-server.reach-check.json` | a small MCP server, one tool declared with `@agents`/`@effects`, two not | two `undeclared_tools`, one with a `write` effect hint |
| `partial-export.reach-check.json` | this repository without `docs/`, `tests/`, `examples/` and `conformance/` | `joins.state: unavailable`: the model export names a claim the tree lacks, so every gate row is `unknown` |

`tests/reach-check-captured.test.ts` reads them.
