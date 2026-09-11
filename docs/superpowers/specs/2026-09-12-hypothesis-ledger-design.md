# The hypothesis ledger — design

Board card GAP-51. Date 2026-09-12.

## Problem

GuardLink already models hypotheses: `@exposes` is the claim, `@confirmed` is the claim with
evidence. The third state is missing. When a pentest, a cxg probe or a manual attempt shows an
exposure is **not** reachable, there is no verb and no ledger entry for that. `@accepts` is a
governance decision, `@mitigates` needs a control, `@comment` carries no status. So a refuted
exposure either stays open (counted in the grade, listed in every report, re-tested by the next
run) or is deleted (the reasoning is lost and the next annotate run re-adds it from the same
code). The verification ledger records that a claim matches its code; nothing records that a
claim was tested against reality.

## Goals

1. A place for a negative result, with evidence, that does not delete the claim.
2. A place for a positive result that arrives as data (a cxg scan), not only as a hand-written
   `@confirmed`.
3. Results that expire honestly when the code beneath the claim changes.
4. A ranked queue of what to test next that a tester can take as a plan.
5. No AI anywhere in it: the ledger is bookkeeping, the ranking is arithmetic.

## Non-goals

- Testing. GuardLink never fires traffic; bugb and cxg do.
- A GAL verb for "refuted". The claim stays `@exposes`; the ledger carries the outcome.
- Importing which hypothesis a probe attached to when cxg does not say (SEAM-12). Until then the
  join is by annotation location, then by asset and threat, then by CWE, and an ambiguous match
  is reported, not guessed.

## Architecture

### `.guardlink/hypotheses.json` — the ledger

Schema `guardlink.hypotheses/v1`, a sibling of `verified.json`. One entry per claim key
(`relationRecords`, content-derived, so a line move is not a change):

| field | meaning |
|---|---|
| `key`, `claim`, `file`, `line` | the exposure, as the verification ledger records it |
| `outcome` | `confirmed` or `refuted` |
| `evidence` | required; for a confirmation it must carry evidence words (request, response, reproduced, scan, …), the same bar the gate holds `@confirmed` to |
| `by`, `at` | `human:<name>` / `cxg:<template>`, ISO date |
| `anchor` | the claim's anchor `{scope, symbol, hash}` at test time |
| `source` | `{kind: 'manual'}` or `{kind: 'scan', scan_id, template_id, confidence}` |
| `history` | every earlier outcome for the key, newest first |

Untested is the absence of an entry. Evidence from a scan goes through `redactEvidence` before
it is written.

### `classifyHypotheses(model, read)` — the state of every claim

Per `@exposes`: no entry → `untested`; entry whose anchor hash matches the claim's current
anchor → the entry's outcome; hash differs (or the claim has no anchor now) → **expired**:
`refuted` becomes `untested` again with `previous` attached, `confirmed` becomes `retest`. A
source `@confirmed` classifies as `confirmed` with no entry. The summary counts each state.

`attachHypotheses(model, classification)` sets `exposure.hypothesis = { state, evidence, by, at,
expired, previous }`. Like `blame` and `anchor` it is stripped from the committed `model.json`
and invisible to the annotation hash (which is a field whitelist).

### `rankUntested(records, model, pathAssets)` — what to test next

`retest` first, then `untested`; within each: severity (critical → low), then on an undefended
path (`findUnmitigatedPaths` → `assetsOnPath`), then unowned (no `@owns`), then file and line.
Deterministic.

### Commands

```
guardlink hypothesis list    [dir] [--state untested|confirmed|refuted|retest] [--json]
guardlink hypothesis next    [dir] [-n <count>] [--intake] [--json]
guardlink hypothesis refute  <file:line> [dir] --evidence "<text>" [--by <name>]
guardlink hypothesis confirm <file:line> [dir] --evidence "<text>" [--by <name>] [--write]
guardlink hypothesis confirm --from-scan <report.json> [dir] [--by <name>] [--write]
```

`refute` and `confirm` refuse without `--evidence`; `confirm` refuses evidence with no evidence
words. `--write` inserts the offered `@confirmed` line directly beneath the `@exposes`, with the
same comment prefix, and reports the file and line. `--from-scan` joins each finding to a claim
(annotation location → asset and threat → CWE), records the confirmed ones, and lists the
unmatched and the ambiguous. `--intake` prints the ranked queue as a brief for `bugb intake`.

### Where the state shows

- `guardlink status`: a `Hypotheses:` line, and the exposures line notes how many are refuted.
- Dashboard: refuted rows are not open (grade, KPIs, the what-to-do list), carry a `refuted`
  badge and status chip, and the drawer shows the evidence, who tested it and when; `retest`
  rows are open with a badge saying why.
- Reports: the serialized model carries `hypothesis` per exposure and the system prompt says a
  refuted exposure is not an open risk; the findings block may use `status: refuted`.
- Lint: a refuted exposure counts as paired.
- `guardlink lint` and `annotate` attach the ledger before linting.

## Testing

`tests/hypothesis.test.ts`: ledger round trip and corruption; classify with expiry both ways;
evidence bar on refute and confirm; ranking order and determinism; scan import (exact location,
asset+threat, CWE, ambiguous, unmatched, redaction); `--write` inserting a parseable
`@confirmed` that passes the gate; lint pairing; the CLI (`refute`, `list --json`, `next
--intake`, `status`), and the dashboard excluding a refuted row from the open count.
