# Playbooks, the evidence bar and the gate — design

Board card GAP-50. Date 2026-09-10.

## Problem

`guardlink annotate "annotate all the threats"` and `guardlink annotate "annotate only
exploitable threats, chase chains as deep as possible"` produce different runs because the
user's sentence is the only place depth, the evidence threshold and chaining are specified.
`buildAnnotatePrompt` puts the user text under "Your Task" above one generic flow-first method,
so a vague prompt gets a shallow pass and only an expert prompt gets a deep one.

`guardlink threat-report` has six framework skeletons, but the model's output is written to
disk verbatim: never parsed, never checked for ids that exist, never given a machine-readable
findings block. A custom prompt replaces the framework header entirely.

After an annotate run the CLI re-parses for a summary and nothing else: no validate, no diff
of what the run added, no lint. A bad run lands in the tree unchallenged.

The tool owns the syntax. It does not own the method, the evidence bar, or the acceptance
check, and those decide output quality.

## Goals

1. The same answer for the junior and the expert: the tool supplies the method, the user
   supplies scope and intent.
2. An evidence bar that makes "only real threats" the default, not a request.
3. A gate that rejects what fails the bar before it reaches the tree.
4. Reports that carry findings a machine can read, with ids that resolve.
5. The same methods available to a developer's own agent session as skills.

## Non-goals

- Enforcing that an agent invokes a skill (GAP-16: that needs hooks).
- Expressing "exposure A enables B" in GAL (SEAM-10). The chains playbook writes chains as
  adjacent `@flows` plus `@comment` until that lands.
- Rewriting an agent's annotation text. The gate removes or re-prompts; it never edits.

## Architecture

### `src/playbooks/` — named methods

| id | kind | what it does |
|---|---|---|
| `map` | annotate | Architecture, flows, boundaries, handles. Writes no `@exposes`. The foundation pass. |
| `exploitable` | annotate | Default. Map → hypothesise → verify each path by reading it → write. An `@exposes` must name entry point, input, sink and the absent control, else it is an `@audit`. |
| `chains` | annotate | Start from open exposures, follow `@flows`, ask what each enables next; write multi-hop chains as flows plus a `@comment` naming the chain. |
| `diff` | annotate | Only the files the branch changed (the prompt carries the list); everything else is context. |
| `coverage` | annotate | The unannotated file list, entry points first; `@flows`/`@boundary`/`@handles` before any `@exposes`. |
| `verify` | annotate | Re-read existing claims against the code; write `@audit` where a claim is not supported; never delete a claim. |
| `full` | report | The framework's own structure (default). |
| `executive` | report | One page: posture, top five, what changed, what to fund. |
| `pr` | report | What this change adds or removes, for a reviewer. |
| `audit` | report | Findings mapped to controls, evidence and owners, for an auditor. |

`selectAnnotatePlaybook(prompt)` is rule-based and deterministic: an explicit id wins, then
keyword rules (`chain`→chains, `changed/diff/PR/branch`→diff, `unannotated/coverage/missing
files`→coverage, `verify/check existing/stale/accurate`→verify, `map/architecture/flows
only`→map), else `exploitable`. The choice and the reason are printed on stderr and stamped
into the prompt as `Playbook: <id>`.

`buildAnnotatePrompt(userPrompt, root, model, mode, playbook?)` renders: reference doc, model
state, **Scope and intent** (the user text), **Method** (the playbook body, which governs),
then the syntax rules. Every annotate playbook shares the evidence bar and the "write nothing
until the verify phase" rule.

`skillFileFor(playbook)` renders a `SKILL.md` (frontmatter `name`, `description`, then the
body) so `guardlink init` can ship the same method under `.claude/skills/guardlink-<kind>-<id>/`.

### `src/gate/` — the acceptance check

`lintAnnotations(model, { only? })` is pure over the model and returns `Violation[]`
(`rule`, `level`, `verb`, `file`, `line`, `message`). Rules:

| rule | level | when |
|---|---|---|
| `exposes-no-code-reference` | error | description missing, on the vague list, or without an identifier, path, call or `file:line` |
| `exposes-unpaired` | error | no `@mitigates` for the pair, no `@audit` on the asset, no `@transfers` from it, no `@accepts` |
| `exposes-severity-above-threat` | error | the exposure's severity outranks the threat's declared severity |
| `accepts-written` | error | an `@accepts` among the claims under check (the run wrote one) |
| `entitles-written` | error | an `@entitles` among the claims under check |
| `confirmed-without-evidence` | error | `@confirmed` whose description carries no evidence word |
| `exposes-unrated` | warn | no severity |
| `mitigates-no-control` | warn | `@mitigates` naming no control |
| `description-vague` | warn | any other verb with a description on the vague list |

`runGate(before, after)` diffs claim keys (`relationRecords`, location-independent) to find
what the run added, lints only those, and reports `ok` when no error remains.
`buildGateFollowUp(report)` is the re-prompt: each violation with its file:line and the rule's
fix. `stripViolations(root, report)` removes the annotation lines of added claims that still
carry an error, after checking the line holds the verb, descending by line per file, and
returns what it removed so nothing is lost.

### CLI

- `guardlink annotate` gains `--playbook <id>`, `--no-gate`, `--gate-retries <n>` (default 1).
  Terminal agents: parse before, launch, parse after, gate; on errors re-prompt with the
  follow-up up to `--gate-retries` times; if errors remain, strip them, print them, exit 1.
  IDE, clipboard and stdout modes print the playbook and skip the gate.
- `guardlink lint [dir] [--since <ref>] [--json]` runs the lint standalone: all claims, or
  only claims added since a git ref. Exit 1 when any error remains. This is the gate for
  sessions the CLI did not launch.
- `guardlink threat-report` gains `--shape <full|executive|pr|audit>`. Free text is a focus
  appended to the framework header, never a replacement. Every framework prompt ends with the
  findings contract; after the run the block is parsed, ids are validated against the model,
  and the count and any unresolved ids are printed.

### Report findings

`src/analyze/findings.ts`: `Finding` (`id`, `title`, `asset`, `threat`, `severity`, `status`,
`evidence`, `location`, `scenario`, `remediation`, `annotation`), `parseFindingsBlock`
(the last fenced ```` ```json guardlink-findings ```` block), `validateFindings` (asset and
threat refs resolve by `#id`, path or name), `renderFindingsTable`.
`loadThreatReportsForDashboard` parses the block out of each saved report; the dashboard
renders the findings table above the prose with each id linked into the Threats table.
`linkifyIds` stays for legacy reports that carry no block.

### `guardlink init`

When Claude Code is among the selected agents, init writes one `SKILL.md` per playbook under
`.claude/skills/`, skipping files that already exist. `guardlink sync` refreshes them only when
they carry the generated marker.

## Testing

- `tests/playbooks.test.ts` — selection rules, prompt composition, skill rendering, the
  `--stdout --playbook` CLI path.
- `tests/gate.test.ts` — every lint rule on a fixture, added-claim detection, the follow-up
  prompt, strip removes only added violating lines, `guardlink lint` exit codes and `--since`.
- `tests/report-findings.test.ts` — parse, validate, render; every framework prompt carries the
  contract; focus keeps the framework header; the dashboard embeds findings.
- `tests/init-skills.test.ts` — init writes the skills for Claude Code and leaves an authored
  file alone.
- Real-corpus check on this repo: `guardlink lint` reports its own vague descriptions honestly.
