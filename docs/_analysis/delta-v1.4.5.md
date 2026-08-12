# GuardLink — Delta Analysis since v1.4.5

**Revision 2** — see §10. §2.3 and §6.2 carry corrections to Revision 1; everything else is unchanged from Revision 1.

| | |
|---|---|
| **Analysed commit** | `55d81110efcba609dbcf35bab613b54fe940c95a` (`main`) — *Merge pull request #20 from Bugb-Technologies/story/1-guardlink-ci-gates*, 2026-08-11 |
| **Compared against** | `v1.4.5` = `ca0a219bf99c047b117d9286b6243bac2bde2780`, 2026-07-21 |
| **origin/main sync** | `git fetch origin` run; `HEAD..origin/main` = **0 commits**, `origin/main..HEAD` = **0 commits**. HEAD *is* origin/main. |
| **Working tree** | `git status --short` = **empty**. No uncommitted changes are folded into this delta. |
| **Delta** | 115 commits, 180 files, +34,366 / −3,931 |
| **Build used for verification** | `npm run build` (`tsc && node scripts/postbuild-chmod.mjs`) at this commit — exit 0. All `[verified]` claims exercise `dist/`, never a globally installed `guardlink`. |
| **Test suite at this commit** | `npx vitest run` — 53 files, **936 tests, all passing**, 10.7s |
| **Analysis date** | 2026-08-12 |

### Verification legend

- **[verified]** — confirmed by running the freshly built `dist/` artifact and observing the result, reproduced in this document.
- Everything else is sourced to `file:line` at commit `55d8111`.
- Where a claim could not be checked without side effects (publishing, network, mutating the repo), that is stated rather than asserted.

### Three things to read first

1. `package.json` still says `"version": "1.4.5"` after 115 commits. Every version-bearing surface inherits that: `guardlink --version` prints `1.4.5` **[verified]**, `MANIFEST.json` says `guardlink@1.4.5`, the MCP `serverInfo` says `1.4.5` **[verified]**. Separately, SARIF hardcodes a *different* stale number, `1.4.3` (`src/analyzer/sarif.ts:274`) **[verified]**.
2. Six of the README's own annotation examples are **hard parse errors** against the shipped parser, and a seventh (`@flow`) is silently discarded **[verified]**.
3. The `guardlink entitle --propose` worked example inside `CLAUDE.md` — byte-identical in `AGENTS.md`, `.gemini/GEMINI.md` and `.github/copilot-instructions.md` — **fails to run**: it omits the required `--file` and `--line` **[verified]**. These four files are consumed by agents at runtime.

---

## 1. Release delta since v1.4.5

115 commits arrived through ten pull requests (#11–#20). Grouped into themes:

| # | Theme | PR(s) | What it is | User-facing? | Documented today? |
|---|---|---|---|---|---|
| T1 | **Stable SARIF threat IDs** | #11, #12 | Mints a deterministic `gl-<hash>` per exposure, emitted as `partialFingerprints["guardlink/threatId"]` and `properties.threatId`, so GitHub Advanced Security can dedupe a finding across runs. `src/parser/fingerprint.ts` (new). | Yes — changes SARIF payload | CHANGELOG ✅. README SARIF section ❌ (does not mention fingerprints) |
| T2 | **Dashboard trim** | #13 | Removes the Risk Topology graph and the Pentest Findings page from the generated dashboard. `src/dashboard/*` −1,530 lines. | Yes — removes two dashboard sections | CHANGELOG ✅. README still describes the dashboard generically, so no contradiction, but no note of removal |
| T3 | **Scan-set hygiene** | #14 | Excludes `.bravos/` and `.bugb/` (Bugb's own artifact dirs) from parsing; syncs `package-lock` to 1.4.5. `src/parser/parse-project.ts:104` | Indirectly (counts move) | CHANGELOG ✅ |
| T4 | **GL-EPIC-001 — machine-readable threat-model surface** | #15 (35 commits) | The largest theme. Adds: `annotation_hash` (`src/parser/annotation-hash.ts`), MCP freshness envelope on every tool/resource (`src/mcp/freshness.ts`), cache invalidation on project fingerprint change, `guardlink_context` (`src/mcp/context.ts`), `guardlink_graph` + subgraph selection (`src/mcp/subgraph.ts`), lookup reaching nine previously-orphaned relation types and refusing unrecognised query forms, external-identifier lookup (`cwe:`/`owasp:` scanner bridge), MCP server `instructions` at initialize (`src/mcp/instructions.ts`), `.guardlink/README.md` cold-start doc, `guardlink artifacts` (`src/artifacts/emit.ts`, new command), `.gal` path convention codified (`src/parser/gal-path.ts`), `guardlink_annotate_apply`, `guardlink reanchor` (new command, `src/parser/reanchor.ts`), `guardlink migrate --to` (new command, `src/parser/migrate-mode.ts`), `init --mode` split from `--no-root-files`. | Yes, heavily — 3 new CLI commands, 4 new MCP tools | CHANGELOG ✅ for `migrate`, `reanchor`, `annotate_apply`, `artifacts`, `graph`, `context`. **CHANGELOG ❌ for the freshness envelope, GL-501/502/503 `.gal` convention.** **README ❌ for all of it** — no `migrate`, `reanchor`, `artifacts`, `graph`, `context` anywhere in README |
| T5 | **`@actor` / `@entitles` + proposal ledger** | #16 (8 commits) | New verbs, new `src/review/entitlements.ts` (941 lines across `src/review`), new `guardlink entitle` command with 19 flags, `guardlink_entitlement_propose` / `guardlink_entitlement_list` MCP tools, `.guardlink/entitlement-proposals.json` ledger, inert/imprecise/undeclared-actor/provenance validation. | Yes — new grammar + new command | CHANGELOG ✅ (extensive). README ✅ (Entitlement section + table row). SPEC ✅ (§3.1, §3.2). `docs/prd/actor-entitlement-design.md` ✅. CLAUDE.md ✅ **but its worked example is broken** (§8) |
| T6 | **Post-epic defect sweep** | #17 (39 commits) | D16–D58. Highlights: `validate`/`status` stop rewriting seven tracked files unless `--sync` (`src/cli/index.ts:277`, `:315`); coverage decided per site not per (asset,threat) pair (D36, `src/parser/coverage.ts`); thirteen more surfaces routed through the one unmitigated predicate (D57); cross-repo tags parse unquoted in every ref position (D19, `src/parser/parse-line.ts:52`); prose starting with a verb warns instead of erroring (D29, `src/parser/parse-line.ts:552`); `init --force` no longer destroys a populated definitions file (D24, `src/init/preserve.ts`); `migrate` refuses the anchor-lossy direction (D48); `link --remove` stops destroying content after the block (D32); report canonicalisation for determinism (D23); 73 unused identifiers removed and `no-unused-vars` promoted to error; `npm run lint` made to actually work. | Yes — several behaviour changes | CHANGELOG ✅ for D36 (called out as BEHAVIOUR CHANGE), partial for the rest. **README ❌** — `--sync` opt-in is not documented anywhere in README |
| T7 | **First-run experience** | #18 (10 commits) | D38/D43/D44/D45/D39/D51: `guardlink status` reads the project name from `config.json` instead of printing "unknown" (`src/parser/annotation-mode.ts:124`); `init` creates `.gitignore` when absent; init "Next steps" agree with the README init writes beside them; the MCP write path validates what it writes. | Yes | CHANGELOG **❌ — entirely absent** |
| T8 | **Build: preserve bin exec bit** | #19 (1 commit) | `scripts/postbuild-chmod.mjs` chmod +x on `dist/cli/index.js` and `dist/mcp/index.js` after `tsc`. Fixes `guardlink-mcp` being non-executable. | Yes (install-breaking without it) | CHANGELOG **❌**, README **❌** |
| T9 | **`guardlink ci` advisory gates** | #20 (4 commits) | New `ci` command (`src/ci/index.ts`, 174 lines): unmitigated exposures + drifted `@source` anchors, `--format text\|json`, schema `guardlink.ci/v1`, exit 0 unless `--strict`. | Yes — new command | CHANGELOG **❌**, README **❌**, `docs/GUARDLINK_REFERENCE.md` **❌**. Only `--help` and `CLAUDE.md`'s auto-synced block mention it |

### The bimodal pattern

This is a real finding, not an artifact of how the table was drawn.

**Themes that shipped with documentation** (T1, T5, and the code-visible half of T4/T6) are the ones whose work included a CHANGELOG entry written in the same PR. They are documented *thoroughly* — T5's CHANGELOG entry runs to six paragraphs with rationale, and `docs/prd/actor-entitlement-design.md` is a full design document.

**Themes that shipped with no documentation at all** (T7, T8, T9, and the freshness/gal-convention half of T4) are everything after commit `d9a3e2b` (2026-08-10), which is the last commit that touched `CHANGELOG.md`. **14 commits are entirely undocumented** in CHANGELOG.

There is no middle. A theme either got a long entry or got nothing. The dividing line is not importance — T9 adds a whole new CLI command and T8 fixes an install-breaking packaging bug — it is *when in the release cycle the work landed*. Documentation stopped two days before the code did.

### User-facing changes with no documentation anywhere

| Change | Location | Present in |
|---|---|---|
| `guardlink ci` (whole command, 4 flags) | `src/cli/index.ts:426` | `--help` only |
| `guardlink artifacts` (whole command) | `src/cli/index.ts:717` | `--help`, CHANGELOG (as GL-301/302), `docs/hooks/pre-commit` |
| `guardlink migrate` (whole command) | `src/cli/index.ts:545` | `--help`, CHANGELOG. **Not in README, not in GUARDLINK_REFERENCE.md** |
| `guardlink reanchor` (whole command) | `src/cli/index.ts:665` | `--help`, CHANGELOG. **Not in README, not in GUARDLINK_REFERENCE.md** |
| `validate --artifacts` | `src/cli/index.ts:314` | `--help`, `.github/workflows/ci.yml:48` |
| `validate --sync` / `status --sync` (behaviour change: sync is now opt-in) | `src/cli/index.ts:277`, `:315` | `--help`, CHANGELOG |
| `init --mode`, `--reset`, `--no-root-files` | `src/cli/index.ts:146-150` | `--help`, CHANGELOG |
| `guardlink-mcp` bin now actually runs | `src/mcp/index.ts:47` (D35) | Code comment only |
| MCP freshness envelope on every tool result | `src/mcp/freshness.ts` | CHANGELOG mentions GL-102 obliquely; **no user-facing doc** |
| 12 of the 24 MCP tools | `src/mcp/server.ts` | Not in README's MCP Tools table (§4) |

---

## 2. CLI surface

Two binaries are declared in `package.json`:

| Bin | Target | Executable after build? |
|---|---|---|
| `guardlink` | `./dist/cli/index.js` | ✅ **[verified]** — `postbuild-chmod: +x ./dist/cli/index.js` |
| `guardlink-mcp` | `./dist/mcp/index.js` | ✅ **[verified]** — `postbuild-chmod: +x ./dist/mcp/index.js`, and a piped `initialize` returns a valid JSON-RPC response |

### 2.1 `guardlink-mcp`

`guardlink-mcp` takes **no arguments, no flags, and no environment variables of its own**. It is a bare stdio MCP transport. `src/mcp/index.ts:63` guards on `isEntryPoint()` (realpath-compared, so an npm symlink still matches) and calls `startStdioServer()`. Startup errors go to stderr because stdout is the JSON-RPC channel.

**[verified]** — piping `initialize` + `notifications/initialized` + `tools/list` + `resources/list` at `node dist/mcp/index.js` returns `serverInfo {"name":"guardlink","version":"1.4.5"}`, a 3,127-character `instructions` string, 24 tools and 3 resources, exit 0, empty stderr.

It is functionally identical to `guardlink mcp`; both call the same `startStdioServer()`.

### 2.2 `guardlink` — global

| Item | Value |
|---|---|
| `--version` / `-V` | Reads `package.json` at runtime (`src/cli/index.ts:120`). **[verified]** prints `1.4.5` |
| `--help` / `-h` | Standard commander, prefixed with a gradient ASCII logo (`src/cli/index.ts:136`) |
| No subcommand | Launches the TUI (`src/cli/index.ts:2626`) — undocumented in `--help` |

**29 top-level commands** (28 leaf + `feature` with 2 subcommands). **[verified]** against `node dist/cli/index.js --help`.

### 2.3 Full flag inventory with wiring status

Wiring status was determined by grepping each parsed field within its own action body, then hand-checking every "not found" against indirect consumers (`agentFromOpts`, `resolveConfig`). **INERT** means the value is parsed and never read, or is read but can only ever hold one value.

#### `init [dir]` — `src/cli/index.ts:140`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | — | `project` | OK — `:189` |
| `-a, --agent <agents>` | — (TTY→picker, non-TTY→`claude`) | `agent` | OK — `:171` |
| `--mode <mode>` | `external` | `mode` | OK — `:186` |
| `--no-root-files` | (rootFiles=true) | `rootFiles` | OK — `:192` |
| `--skip-agent-files` | false | `skipAgentFiles` | OK — `:170`, `:193` |
| `--force` | false | `force` | OK — `:164`, `:194` |
| `--reset` | false | `reset` | OK — `:164`, `:195` |
| `--dry-run` | false | `dryRun` | OK — `:196` |
| positional `[dir]` | `.` | — | OK |

#### `parse [dir]` — `:241`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <name>` | config.json `project` | `project` | OK — `:250` |
| `-o, --output <file>` | stdout | `output` | OK — `:257` |
| `--pretty` | `true` | `pretty` | **INERT** — declared as `.option('--pretty', …, true)` with no `--no-pretty` counterpart, so `opts.pretty` is always `true` and the `opts.pretty ? 2 : 0` branch at `:256` has one reachable arm. **[verified]**: `--no-pretty` → `error: unknown option '--no-pretty' (Did you mean --pretty?)` |

Exit code: 1 if any diagnostic is `error` (`:265`).

#### `status [dir]` — `:270`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:280` |
| `--not-annotated` | false | `notAnnotated` | OK — `:292` |
| `--feature <names>` | — | `feature` | OK — `:283` (comma-split) |
| `--sync` | false | `sync` | OK — `:298`. Opt-in since D16 |

#### `validate [dir]` — `:308`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:318` |
| `--strict` | false | `strict` | OK — `:421` (exit 1 on unmitigated) |
| `--artifacts` | false | `artifacts` | OK — `:397`. **[verified]** prints `✓ Artifacts are current.` on this repo, exit 0 |
| `--sync` | false | `sync` | OK — `:386` |

Exit: 1 if `errorCount > 0 \|\| artifactDrift \|\| (strict && unmitigated)`.

#### `ci [dir]` — `:426`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:441` |
| `-f, --format <fmt>` | `text` | `format` | OK — `:436` validates, `:444` branches. **[verified]** `--format json` emits `{"schema":"guardlink.ci/v1", …}` |
| `--strict` | false | `strict` | OK — `:442`. **[verified]** default exit 0 with 15 findings; `--strict` exit 1 |

#### `report [dir]` — `:457`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:469` |
| `-o, --output <file>` | `threat-model.md` / `.json` | `output` | OK — `:510`, `:526`, `:532` |
| `-f, --format <fmt>` | `md` | `format` | OK — `:521`. Accepts `md`, `json`, `both`; **an unrecognised value silently produces no output at all** (`wantMd` and `wantJson` both false, no error) |
| `--diagram-only` | false | `diagramOnly` | OK — `:507` |
| `--json` | false | `json` | OK — `:521`. Legacy; note `wantMd` at `:522` also ORs `opts.json`, so `--format json --json` writes markdown too |
| `--feature <names>` | — | `feature` | OK — `:472` |

**[verified]** `report . --format json -o guardlink-report.json` → one JSON file, no markdown. `report . --json` → both `threat-model.md` and `threat-model.json`. `report . -o out.md --format both` → `out.md` + `out.json`.

Cosmetic dead code: `:526` reads `opts.output || (opts.format === 'md' ? 'threat-model.md' : 'threat-model.md')` — both ternary arms are identical.

#### `migrate [dir]` — `:545`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `--to <mode>` | **required** | `to` | OK — `:555` validates `inline\|external` |
| `-p, --project <n>` | config.json | `project` | OK — `:560` |
| `--dry-run` | false | `dryRun` | OK — `:591` |
| `--allow-anchor-loss` | false | `allowAnchorLoss` | OK — `:576`, `:645` |

#### `reanchor [dir]` — `:665`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:673` |
| `--apply` | false | `apply` | OK — `:699`, `:706` |

Exit: 0 if no drift or `--apply` succeeded; 1 if drift found without `--apply`.

#### `artifacts [dir]` — `:717`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:725` |
| `--dry-run` | false | `dryRun` | OK — `:732` |

**[verified]** `--dry-run` lists 8 artifacts and writes nothing.

#### `diff [ref]` — `:746`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| positional `[ref]` | `HEAD~1` | — | OK — `:766` |
| `-d, --dir <dir>` | `.` | `dir` | OK — `:756` |
| `-p, --project <n>` | config.json | `project` | OK — `:760`, `:766` |
| `--markdown` | false | `markdown` | OK — `:779` |
| `--json` | false | `json` | OK — `:777` |
| `--fail-on-new` | false | `failOnNew` | OK — `:786` |

**There is no `--from` and no `--to`.** README:183, README:322, `examples/github-action.yml:49` and `examples/ci/per-repo-report.yml:65` all use them. **[verified]** `guardlink diff --from origin/main --to HEAD` → `error: unknown option '--from'`. See §8.

#### `sarif [dir]` — `:793`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:803` |
| `-o, --output <file>` | stdout | `output` | OK — `:821` |
| `--min-severity <sev>` | — (all) | `minSeverity` | OK — `:815`. **[verified]** monotone ladder on this repo: `critical`→0, `high`→3, `medium`→9, `low`→15 |
| `--no-diagnostics` | (diagnostics=true) | `diagnostics` | OK — `:813`. **[verified]** on a fixture with 6 parse errors: default 6 results, `--no-diagnostics` 0 results |

#### `threat-report [prompt...]` — `:838`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| positional `[prompt...]` | `general` | — | OK — `:864`. Recognises `stride\|dread\|pasta\|attacker\|rapid\|general`; anything else becomes a custom prompt |
| `-d, --dir <dir>` | `.` | `dir` | OK — `:862` |
| `-p, --project <n>` | auto-detected | `project` | OK — `:863` |
| `--provider <provider>` | env/config | `provider` | OK — `:984` |
| `--model <model>` | provider default | `model` | OK — `:985` |
| `--api-key <key>` | env/config | `apiKey` | OK — `:986` |
| `--no-stream` | (stream=true) | `stream` | OK — `:1008`, `:1014` |
| `--web-search` | false | `webSearch` | OK — `:1010` |
| `--thinking` | false | `thinking` | OK — `:1011` |
| `--claude-code` | — | `claudeCode` | OK — indirect via `agentFromOpts` (`src/agents/index.ts:80`) |
| `--codex` | — | `codex` | OK — indirect |
| `--gemini` | — | `gemini` | OK — indirect |
| `--cursor` | — | `cursor` | OK — indirect |
| `--windsurf` | — | `windsurf` | OK — indirect |
| `--clipboard` | — | `clipboard` | OK — indirect |

Not verified: the API and agent-launch paths require a live LLM key / a spawned agent process. Stated rather than asserted.

#### `threat-reports` — `:1035`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-d, --dir <dir>` | `.` | `dir` | OK — `:1040` |

#### `annotate <prompt> [dir]` — `:1058`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| positional `<prompt>` | **required** | — | OK |
| positional `[dir]` | `.` | — | OK — `:1078` |
| `-p, --project <n>` | auto-detected | `project` | OK — `:1079` |
| `--mode <mode>` | `inline` | `mode` | OK — `:1082`. **Note the default differs from `init --mode`, which defaults to `external`** |
| `--claude-code` … `--clipboard` (6 flags) | — | — | OK — indirect via `agentFromOpts` |
| `--stdout` | — | `stdout` | OK — indirect (`AGENTS` table id `stdout`, `src/agents/index.ts:30`). **[verified]** emits a 28,182-character prompt to stdout |

#### `translate [prompt...]` — `:1157`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-d, --dir <dir>` | `.` | `dir` | OK — `:1176` |
| `-p, --project <n>` | auto-detected | `project` | OK — `:1177` |
| `--claude-code` … `--clipboard` (6) | default `claude-code` (`:1207`) | — | OK — indirect |
| `--feature <names>` | — | `feature` | OK — `:1183` |

#### `ask [query...]` — `:1261`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-d, --dir <dir>` | `.` | `dir` | OK — `:1278` |
| `-p, --project <n>` | auto-detected | `project` | OK — `:1279` |
| `--claude-code` … `--clipboard` (6) | default `claude-code` | — | OK — indirect |

#### `clear [dir]` — `:1355`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `--dry-run` | false | `dryRun` | OK — `:1383` |
| `--include-definitions` | false | `includeDefinitions` | OK — `:1369`, `:1412` |
| `-y, --yes` | false | `yes` | OK — `:1389`. Non-TTY without `--yes` exits 1 |

#### `sync [dir]` — `:1421`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `--dry-run` | false | `dryRun` | OK — `:1437` |

**Inconsistency:** `sync` has no `-p, --project`, and hardcodes `project: basename(root)` at `:1430` rather than reading `config.json` like every other command since D43.

> **CORRECTION (Revision 2).** Revision 1 continued: *"In a repo whose directory name differs from its configured project name, `sync` writes a different project name into the agent files than `status` prints."* **That claim is false and has been removed.** It was inferred from the hardcode, never executed.
>
> **Evidence.** A fixture whose directory is `dirname-differs` and whose `config.json` says `project: ConfiguredName` was synced, its four agent files snapshotted, `config.json` changed to `project: TotallyDifferent`, and synced again. `diff -r` over `CLAUDE.md`, `AGENTS.md`, `.guardlink/README.md` and `.github/copilot-instructions.md` reports **no difference**. `status` printed `ConfiguredName` and then `TotallyDifferent` across the same two runs, so the fixture did vary the input.
>
> **Why.** `syncAgentFiles` never interpolates `model.project` into any file it writes — `grep -rn "model.project" src` returns no hit under `src/init/`. The project name reaches `sync` and is then dropped.
>
> The hardcode is still worth removing (it is a real inconsistency, and any future consumer of `model.project` on this path would inherit the wrong value), but **it has no observable effect on `sync` output today**, and A7 should not be justified by an output difference that does not exist.

#### `unannotated [dir]` — `:1458`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:1465` |

#### `review [dir]` — `:1471`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | config.json | `project` | OK — `:1480` |
| `--severity <levels>` | undefined (all) | `severity` | OK — `:1484` |
| `--list` | false | `list` | OK — `:1497` |

#### `entitle [dir]` — `:1580` (19 flags)

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | **`unknown`** | `project` | OK — `:1622`. **Anomaly:** hardcoded `'unknown'` default; does not read `config.json` like the other commands |
| `--list` | false | `list` | OK — `:1691` |
| `--status <states>` | — | `status` | OK — `:1686` |
| `--propose` | false | `propose` | OK — `:1613` |
| `--actor <ref>` | — | `actor` | OK — `:1624` (required with `--propose`) |
| `--capability <id>` | — | `capability` | OK — `:1625` (required with `--propose`) |
| `--asset <ref>` | — | `asset` | OK — `:1626` |
| `--threat <ref>` | — | `threat` | OK — `:1627` |
| `--rationale <text>` | — | `rationale` | OK — `:1628` (required with `--propose`) |
| `--file <path>` | — | `file` | OK — `:1629` (**required with `--propose`**) |
| `--line <n>` | — | `line` | OK — `:1630` (**required with `--propose`**) |
| `--proposed-by <name>` | `cli` | `proposedBy` | OK — `:1631` |
| `--accept <id>` | — | `accept` | OK — `:1652` |
| `--reject <id>` | — | `reject` | OK — `:1652` |
| `--defer <id>` | — | `defer` | OK — `:1652` |
| `--by <name>` | git `user.name` | `by` | OK — `:1655` |
| `--note <text>` | — | `note` | OK — `:1669` (required when rejecting) |
| `--acknowledge-inert` | false | `acknowledgeInert` | OK — `:1670` |
| `--acknowledge-ownership` | false | `acknowledgeOwnership` | OK — `:1671` |

**[verified]** running CLAUDE.md's documented example verbatim in a clean directory: `✗ --propose needs --file, --line`.

#### `config <action> [key] [value]` — `:1849`

| Item | Values | Wiring |
|---|---|---|
| positional `<action>` | `show`, `set`, `clear` | OK — `:1860`. Anything else → `Unknown action` + exit 1 |
| positional `[key]` | `provider`, `api-key`, `model`, `ai-mode`, `cli-agent`, `redact-evidence` | OK — `:1905` |
| positional `[value]` | — | OK |
| `--global` | false | OK — `:1858` |

`set provider` validates against `anthropic, openai, google, openrouter, deepseek, ollama` (`:1902`). `set ai-mode` validates `api\|cli-agent`. `set cli-agent` validates against `AGENTS` ids and side-effects `aiMode='cli-agent'` (`:1935`). `set redact-evidence` accepts `true/on/1/yes` and `false/off/0/no`.

**Doc/help mismatch:** the argument help at `:1853` lists 6 keys including `redact-evidence`, but the usage message printed on missing args (`:1894`) lists only 5 — it omits `redact-evidence`.

#### `dashboard [dir]` — `:1988`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | auto-detected | `project` | OK — `:1998` |
| `-o, --output <file>` | `threat-dashboard.html` | `output` | OK — `:2024` |
| `--light` | false | `light` | OK — `:2020`. **[verified]** default file contains `data-theme="dark"`, `--light` file contains `data-theme="light"` |
| `--feature <names>` | — | `feature` | OK — `:2002` |

#### `link-project [repos...]` — `:2033`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| positional `[repos...]` | — (≥2 for fresh link) | — | OK — `:2133` |
| `-w, --workspace <n>` | `workspace` | `workspace` | OK — `:2144`. Fresh-link only; silently ignored in `--add`/`--remove` mode |
| `-r, --registry <url>` | — | `registry` | OK — `:2097` (add), `:2146` (fresh). **Not passed in `--remove` mode** (`:2057`) — correct, but the help text does not say the flag is mode-scoped |
| `--add <path>` | — | `add` | OK — `:2081` |
| `--remove <name>` | — | `remove` | OK — `:2045` |
| `--from <path>` | — | `from` | OK — `:2047`, `:2083` (required with `--add`/`--remove`) |

#### `merge <files...>` — `:2179`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| positional `<files...>` | **required** | — | OK — `:2196` |
| `-o, --output <file>` | `workspace-dashboard.html` | `output` | OK — `:2262` |
| `--json <file>` | — | `json` | OK — `:2227` |
| `--diff-against <file>` | — | `diffAgainst` | OK — `:2234` |
| `-w, --workspace <name>` | auto-detected | `workspace` | OK — `:2207` |
| `--summary-only` | false | `summaryOnly` | OK — `:2260` |

#### `feature list [dir]` — `:2277`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| `-p, --project <n>` | auto-detected | `project` | OK — `:2285` |
| `--json` | false | `json` | OK — `:2295` |

#### `feature show <name>` — `:2315`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| positional `<name>` | **required** | — | OK — case-insensitive |
| `-d, --dir <dir>` | `.` | `dir` | OK — `:2323` |
| `-p, --project <n>` | auto-detected | `project` | OK — `:2324` |
| `--json` | false | `json` | OK — `:2341` |

#### `mcp` — `:2373`

No flags, no positionals. Calls `startStdioServer()`.

#### `tui [dir]` — `:2380`

| Flag | Default | Field | Wiring |
|---|---|---|---|
| positional `[dir]` | `.` | — | OK — `:2392` |
| `--provider <provider>` | — | `provider` | OK — `:2390` (sets `GUARDLINK_LLM_PROVIDER`) |
| `--api-key <key>` | — | `apiKey` | OK — `:2389` (sets `GUARDLINK_LLM_KEY`) |
| `--model <model>` | — | `model` | **DEAD** — parsed at `src/cli/index.ts:2386`, typed into the action signature at `:2387`, and **never read**. The sibling flags are forwarded through env vars; there is no `GUARDLINK_LLM_MODEL` anywhere in `src/`. **[verified]** by full-tree grep + reading `:2388-2392` |

#### `gal` — `:2395`

No flags. Prints a ~200-line GAL reference. This is the **most accurate annotation documentation the project ships** — see §8.

### 2.4 Dead-flag summary

| Category | Count | Detail |
|---|---|---|
| **DEAD** (parsed, never read) | **1** | `tui --model` (`src/cli/index.ts:2386`) |
| **INERT** (read but single-valued) | **1** | `parse --pretty` (`src/cli/index.ts:247`) |
| Mode-scoped and silently ignored outside that mode | 2 | `link-project -w/--workspace` (ignored with `--add`/`--remove`), `link-project -r/--registry` (ignored with `--remove`) |
| Total flags inventoried across both binaries | **131** | |

An earlier mechanical pass flagged the 25 agent-selection flags (`--claude-code`, `--codex`, `--gemini`, `--cursor`, `--windsurf`, `--clipboard`, `--stdout` across 4 commands) as dead because no `opts.<field>` reference appears in their action bodies. They are **not** dead: they are consumed indirectly by `agentFromOpts(opts)` at `src/agents/index.ts:79-86`. Recorded here so a later pass does not re-derive the false positive.

### 2.5 Environment variables

| Variable | Read at | Used for | Set by |
|---|---|---|---|
| `GUARDLINK_LLM_KEY` | `src/agents/config.ts:126` | LLM API key, priority 2 | `tui --api-key` |
| `GUARDLINK_LLM_PROVIDER` | `src/agents/config.ts:127` | LLM provider | `tui --provider` |
| `ANTHROPIC_API_KEY` | `src/agents/config.ts:171` | provider `anthropic`, priority 3 | user |
| `OPENAI_API_KEY` | `:172` | provider `openai` | user |
| `GOOGLE_API_KEY` | `:173` | provider `google` | user |
| `GEMINI_API_KEY` | `:174` | provider `google` | user |
| `OPENROUTER_API_KEY` | `:175` | provider `openrouter` | user |
| `DEEPSEEK_API_KEY` | `:176` | provider `deepseek` | user |

**No env var is documented in README or in `--help`.** They appear only in `guardlink config show`'s "No LLM configuration found" fallback text (`src/cli/index.ts:1884`), which lists two of the eight.

### 2.6 Flags whose documented example does not do what it implies

| Where | Example | Reality |
|---|---|---|
| README:183 | `guardlink diff --from <ref>` | No such flag. `diff` takes a positional ref. **[verified]** error |
| README:322 | `guardlink diff --from origin/main --to HEAD` | Neither flag exists. **[verified]** error |
| `examples/github-action.yml:49` | same | same. Wrapped in `\|\| true`, so CI silently posts the error text as the PR comment body |
| `examples/ci/per-repo-report.yml:65` | same | same |
| CLAUDE.md:100 (×4 files) | `guardlink entitle --propose --actor … --capability … --asset … --rationale …` | Missing required `--file` and `--line`. **[verified]** `✗ --propose needs --file, --line` |
| `guardlink config set` usage (`:1894`) | "Keys: provider, api-key, model, ai-mode, cli-agent" | `redact-evidence` also works and is listed 41 lines above at `:1853` |

---

## 3. Public API surface — `package.json` exports

`package.json` declares 7 subpath exports plus 2 bin entries. This is the semver contract.

### 3.1 Resolution

**[verified]** after a clean `npm run build`: all 7 subpaths resolve at runtime (dynamic `import()` of each `dist/` target succeeded) and **all 7 resolve for TypeScript** — a probe project with `"moduleResolution": "nodenext"` importing all 7 compiled with `tsc` **exit 0**.

| Subpath | `import` target | Exists | `types` target | Exists | Runtime symbols |
|---|---|---|---|---|---|
| `.` | `dist/index.js` | ✅ | `dist/index.d.ts` | ✅ | 65 |
| `./parser` | `dist/parser/index.js` | ✅ | `dist/parser/index.d.ts` | ✅ | 46 |
| `./init` | `dist/init/index.js` | ✅ | `dist/init/index.d.ts` | ✅ | 6 |
| `./report` | `dist/report/index.js` | ✅ | `dist/report/index.d.ts` | ✅ | 3 |
| `./diff` | `dist/diff/index.js` | ✅ | `dist/diff/index.d.ts` | ✅ | 6 |
| `./analyzer` | `dist/analyzer/index.js` | ✅ | `dist/analyzer/index.d.ts` | ✅ | 1 |
| `./mcp` | `dist/mcp/index.js` | ✅ | `dist/mcp/index.d.ts` | ✅ | 4 |
| bin `guardlink` | `dist/cli/index.js` | ✅ +x | — | — | — |
| bin `guardlink-mcp` | `dist/mcp/index.js` | ✅ +x | — | — | — |

**Nothing fails to resolve.** One packaging nit: in every export block the `"types"` condition is listed *after* `"import"` (`package.json:19-49`). TypeScript's documented guidance is that `types` should come first. It happens to work here because `dist/index.js` has a sibling `dist/index.d.ts`, which TS finds by the fallback path — but the ordering is fragile and would break if the build layout changed.

### 3.2 Symbol inventory

**76 distinct runtime symbols** across the 7 subpaths (many appear in more than one).

#### `.` (root, 65 symbols) — `src/index.ts`

Re-exports `./types/*` (types only), all of `./parser/*`, plus a curated set:

| Symbol | Kind | Origin | Documented anywhere? |
|---|---|---|---|
| `initProject` | fn | `src/init/index.ts:150` | README ❌, no JSDoc |
| `detectProject` | fn | `src/init/detect.ts:100` | README ❌, no JSDoc |
| `generateReport` | fn | `src/report/report.ts` | README ✅ (Library API) |
| `generateMermaid` | fn | `src/report/mermaid.ts` | README ❌ |
| `diffModels` | fn | `src/diff/engine.ts:101` | README ✅, no JSDoc |
| `formatDiff` | fn | `src/diff/format.ts:9` | README ❌, no JSDoc |
| `formatDiffMarkdown` | fn | `src/diff/format.ts` | README ❌ |
| `parseAtRef` | fn | `src/diff/git.ts` | README ❌ |
| `generateSarif` | fn | `src/analyzer/sarif.ts:150` | README ✅ **but with the wrong signature**, no JSDoc |
| `runCiChecks`, `formatCiReport`, `CI_SCHEMA` | fn/fn/const | `src/ci/index.ts` | **Documented nowhere** — new in T9 |
| `populateMetadata`, `loadWorkspaceConfig`, `REPORT_SCHEMA_VERSION` | fn/fn/const | `src/workspace/metadata.ts` | docs/WORKSPACE.md ❌ (doc predates them) |
| `mergeReports`, `formatMergeSummary`, `diffMergedReports`, `formatDiffSummary` | fn | `src/workspace/merge.ts` | docs/WORKSPACE.md partial |
| (46 more) | | `src/parser/*` | see below |

Type-only exports from `.`: `ThreatModel`, `Annotation`, `ParseDiagnostic`, `SourceLocation`, `Severity`, `DataClassification`, `AnnotationVerb`, `InitOptions`, `InitResult`, `ProjectInfo`, `AgentFile`, `ThreatModelDiff`, `DiffSummary`, `Change`, `ChangeKind`, `SarifOptions`, `CiReport`, `CiSummary`, `CiOptions`, `WorkspaceConfig`, `WorkspaceRepo`, `MergedReport`, `MergeTotals`, `MergeDiffSummary`, `MergeOptions` + everything in `src/types/index.ts`.

#### `./parser` (46 symbols) — `src/parser/index.ts`

`parseFile`, `parseString`, `parseProject`, `parseLine`, `crossRepoTag`, `CROSS_REPO_TAG_PATTERN`, `canEntitlementDemote`, `entitlementDemotionBlockers`, `normalizeName`, `resolveSeverity`, `unescapeDescription`, `stripCommentPrefix`, `commentStyleForExt`, `findDanglingRefs`, `findUnmitigatedExposures`, `findAcceptedWithoutAudit`, `findAcceptedExposures`, `findUndeclaredActors`, `findInertEntitlements`, `findImpreciseEntitlements`, `findOffConventionGalFiles`, `extractCitation`, `citationMatchesFile`, `resolveGalPath`, `galPathFor`, `sourceFileForGal`, `isConventionalGalPath`, `ANNOTATIONS_DIR`, `GAL_CONVENTION`, `clearAnnotations`, `listFeatures`, `filterByFeature`, `getFeatureSummaries`, `computeAnnotationHash`, `canonicalAnnotationRecords`, `ANNOTATION_HASH_VERSION`, `computeAnchorHash`, `canonicalAnchorRecords`, `countAnchors`, `lostAnchors`, `ANCHOR_HASH_VERSION`, `applyAnnotations`, `findAnchorDrift`, `applyReanchor`, `migrateAnnotationMode`, `readGalBlocks`.

Only `parseProject` is documented in the README. The other 45 are documented only by their JSDoc (36 of 46 have one).

#### `./init` (6) — `initProject`, `detectProject`, `syncAgentFiles`, `promptAgentSelection`, `resolveAgentFiles`, `AGENT_CHOICES`
#### `./report` (3) — `generateReport`, `generateMermaid`, `generateSequenceDiagram`
#### `./diff` (6) — `diffModels`, `formatDiff`, `formatDiffMarkdown`, `parseAtRef`, `getCurrentRef`, `getChangedFiles`
#### `./analyzer` (1) — `generateSarif`
#### `./mcp` (4) — `createServer`, `startStdioServer`, `lookup`, `suggestAnnotations`

### 3.3 Exported but not plausibly intended as public API

| Symbol | Subpath | Why it looks internal |
|---|---|---|
| `promptAgentSelection` | `./init` | Interactive TTY picker — writes to stdout, reads stdin. Not usable from a library consumer |
| `AGENT_CHOICES` | `./init` | Internal picker table (`src/init/picker.ts:21`), no JSDoc |
| `resolveAgentFiles` | `./init` | Path-mapping helper for the picker |
| `canonicalAnnotationRecords`, `canonicalAnchorRecords` | `./parser`, `.` | Internal serialisation for hashing; only meaningful to the hash functions |
| `readGalBlocks` | `./parser`, `.` | Internal to `migrate-mode.ts` |
| `CROSS_REPO_TAG_PATTERN` | `./parser`, `.` | Raw regex — exposing it fixes the tag grammar as API surface |
| `entitlementDemotionBlockers` | `./parser`, `.` | Deliberately exported per §9.7 of the entitlement design so consumers cannot omit the precision check — arguably intentional, flagged for confirmation |
| `getCurrentRef` | `./diff` | Thin `git rev-parse` wrapper |

### 3.4 The reverse: public-looking API not reachable through any declared export

This is the larger gap. Whole feature modules with clean interfaces, full JSDoc and stable-looking shapes have no export path.

| Module | Unreachable public symbols | Notes |
|---|---|---|
| `src/artifacts/emit.ts` | `emitArtifacts`, `checkArtifactDrift`, `expectedArtifactPaths`, `readArtifactHash`, `mermaidHeader`, `stripHeader`, `featureSlug`, `ARTIFACT_SCHEMA_VERSION`, types `EmitOptions`/`EmitResult`/`ArtifactProvenance`/`EmissionInfo`/`ManifestEntry`/`DriftFinding` | The **entire `guardlink artifacts` feature** (T4). 399 new lines, a schema, a manifest format — no library access |
| `src/dashboard/index.ts` | `generateDashboardHTML`, `computeStats`, `computeSeverity`, `computeExposures`, `computeAssetHeatmap`, `generateThreatGraph`, `generateDataFlowDiagram`, `generateAttackSurface` | A complete barrel with a doc-block, exported from nowhere. `generateThreatGraph` is used by `guardlink_graph`'s mermaid mode |
| `src/review/index.ts` | `getReviewableExposures`, `applyReviewAction`, `formatExposureForReview`, `summarizeReview`, `severityLabel`, `detectCommentStyle`, `findInsertionIndex`, `insertAnnotationsAt`, `escapeDesc` + 4 types | The whole governance-review feature |
| `src/review/entitlements.ts` | 33 symbols including `proposeEntitlement`, `listProposals`, `applyProposalDecision`, `checkEntitlementProvenance`, `LEDGER_VERSION`, `PROPOSALS_FILE`, `InertProposalError`, `OwnershipClassProposalError` | The whole entitlement ledger (T5) — the flagship feature of this release |
| `src/workspace/link.ts` (via `src/workspace/index.ts`) | `linkProject`, `addToWorkspace`, `removeFromWorkspace`, `buildWorkspaceContextBlock`, `detectRepoName`, `parseWorkspaceYaml`, `serializeWorkspaceYaml` | `src/index.ts:23` re-exports 7 workspace symbols but **not these** — `link-project` has no library form |
| `src/analyze/index.ts` | `generateThreatReport`, `serializeModel`, `serializeModelCompact`, `buildProjectContext`, `extractCodeSnippets`, `listThreatReports`, `loadThreatReportsForDashboard`, `loadPentestData`, `serializePentestFindings` + 6 types | The whole AI-analysis feature |
| `src/agents/index.ts` | `AGENTS`, `agentFromOpts`, `resolveAnnotationMode`, `parseAgentFlag`, `parseAnnotationModeFlag` | |
| `src/version.ts` | `getPackageVersion` | Introduced precisely so "the next surface that needs it does not invent a third copy" (`src/version.ts:7`) — but it is not reachable, and `src/analyzer/sarif.ts:274` did invent a third copy (a hardcoded `'1.4.3'`) |
| `src/init/migrate.ts` | `ensurePromptMd` | |
| `src/init/preserve.ts` | `declarationIds`, `definitionsArePopulated`, `configIsCustomised` | |
| `src/tui/index.ts` | `startTui` | Reasonable to keep private |
| `src/report/sequence.ts` | `generateSequenceDiagram` | Reachable via `./report` but **not** via `.`, unlike its two siblings |

**Summary: 4 of the 9 features added since v1.4.5 (artifacts, entitlement ledger, review, workspace linking) have no library surface at all**, despite `package.json` presenting a 7-subpath library contract.

### 3.5 JSDoc coverage on public symbols

**[verified]** by matching each of the 76 runtime-exported symbols to its declaration in `src/` and checking for a `*/` on the line immediately above.

- **66 of 76 have a JSDoc block.**
- **10 do not:**

| Symbol | Location |
|---|---|
| `AGENT_CHOICES` | `src/init/picker.ts:21` |
| `createServer` | `src/mcp/server.ts:228` |
| `detectProject` | `src/init/detect.ts:100` |
| `diffModels` | `src/diff/engine.ts:101` |
| `formatDiff` | `src/diff/format.ts:9` |
| `generateSarif` | `src/analyzer/sarif.ts:150` |
| `generateSequenceDiagram` | `src/report/sequence.ts:33` |
| `initProject` | `src/init/index.ts:150` |
| `lookup` | `src/mcp/lookup.ts:153` |
| `suggestAnnotations` | `src/mcp/suggest.ts:43` |

Note the shape of that list: `initProject`, `detectProject`, `diffModels`, `generateSarif`, `createServer` and `lookup` are the **six most likely entry points for a new consumer**, and they are exactly the ones without documentation.

---

## 4. MCP server surface

**[verified]** by driving `node dist/mcp/index.js` over stdio and reading `tools/list` and `resources/list`.

- **24 tools registered.** All carry the GL-102 freshness envelope, applied at registration (`src/mcp/server.ts:185-198`) rather than at each return site.
- **3 resources registered.**
- `serverInfo`: `{"name":"guardlink","version":"1.4.5"}`.
- `instructions`: 3,127 characters, built at construction (`src/mcp/server.ts:236`) from `src/mcp/instructions.ts`.

> **Stale internal comment:** `src/mcp/server.ts:182` says *"Wrapping at registration rather than editing 18 return statements is what makes 'all 18 tools' true by construction"*. There are 24.

### 4.1 Tool inventory

| # | Tool | Required | Optional (with defaults) | What it does |
|---|---|---|---|---|
| 1 | `guardlink_parse` | — | `root='.'`, `compact=false`, `include_unannotated=false` | Full ThreatModel JSON. Omits `unannotated_files` by default, replacing it with `unannotated_files_omitted: {count, reason}`. `src/mcp/server.ts:247` |
| 2 | `guardlink_status` | — | `root='.'` | Counts + `unmitigated[]` + `coverage`. `:288` |
| 3 | `guardlink_validate` | — | `root='.'` | Syntax errors, dangling refs, actor/entitlement checks, provenance. Returns `{valid, errors[], warnings[], summary}`. `:331` |
| 4 | `guardlink_suggest` | — | `root='.'`, `file?`, `diff?` | Pattern-based annotation suggestions. `:369` |
| 5 | `guardlink_lookup` | `query` | `root='.'` | Fixed-form graph queries; refuses unrecognised forms with `no_match` + the list. `:388` |
| 6 | `guardlink_context` | `file` | `root='.'`, `line?` | Everything known about one file; distinguishes `scanned_without_annotations` / `not_scanned` / `not_found` / `outside_root`. `:406` |
| 7 | `guardlink_graph` | `from` | `root='.'`, `path_to?`, `depth=2`, `direction='both'`, `kinds?`, `format='json'`, `detail='summary'`, `feature?`, `file?` | Blast radius over the asset plane (flows/boundaries/transfers only). `:437` |
| 8 | `guardlink_annotate_apply` | `file`, `line`, `annotations` | `root='.'`, `symbol?`, `dry_run=false`, `allow_undeclared_refs=false` | Writes a validated `@source` block into `.guardlink/annotations/`. Refuses `@accepts` and `@entitles`. `:490` |
| 9 | `guardlink_reanchor` | — | `root='.'`, `apply=false` | `@source` drift detection / repair. `:524` |
| 10 | `guardlink_threat_report` | — | `root='.'`, `framework='general'`, `provider?`, `model?`, `custom_prompt?`, `web_search?`, `thinking?` | API mode with a key; agent mode (returns prompt + compact model) without. `:557` |
| 11 | `guardlink_annotate` | `prompt` | `root='.'`, `mode='inline'` | Builds an annotation prompt. `:636` |
| 12 | `guardlink_report` | — | `root='.'`, `output='threat-model.md'` | Writes markdown + sibling `.json`. `:676` |
| 13 | `guardlink_dashboard` | — | `root='.'`, `output='threat-dashboard.html'` | Writes HTML dashboard; invalidates cache after. `:714` |
| 14 | `guardlink_sarif` | — | `root='.'`, `output='guardlink.sarif.json'` | Writes SARIF. `:748` |
| 15 | `guardlink_diff` | — | `root='.'`, `ref='HEAD~1'` | Model diff against a git ref. `:774` |
| 16 | `guardlink_threat_reports` | — | `root='.'` | Lists saved reports. `:799` |
| 17 | `guardlink_sync` | — | `root='.'` | Refreshes all agent instruction files. `:815` |
| 18 | `guardlink_clear` | — | `root='.'`, `dry_run=true`, `include_definitions=false` | Destructive annotation removal. Note `dry_run` defaults **true** here vs **false** on the CLI. `:837` |
| 19 | `guardlink_unannotated` | — | `root='.'` | Coverage-gap file list. `:875` |
| 20 | `guardlink_review_list` | — | `root='.'`, `severity?` | Reviewable exposures with ids. `:900` |
| 21 | `guardlink_review_accept` | `exposure_id`, `decision`, `justification` | `root='.'` | Writes `@accepts`+`@audit` or `@audit` into source. `:939` |
| 22 | `guardlink_entitlement_propose` | `actor`, `capability`, `rationale`, `file`, `line` | `root='.'`, `asset?`, `threat?`, `proposed_by?` | Files a proposal; writes nothing to source. `:994` |
| 23 | `guardlink_entitlement_list` | — | `root='.'`, `status?` | Reads the proposal ledger. `:1037` |
| 24 | `guardlink_workspace_info` | — | `root='.'` | Workspace identity, siblings, tag prefixes, cross-repo rules built from the parser's own grammar. `:1062` |

Deliberately absent: there is no `guardlink_entitlement_accept`. Acceptance is a human decision recorded by name through `guardlink entitle` (`src/mcp/server.ts:986`).

### 4.2 Resources

| Name | URI | Content |
|---|---|---|
| `threat-model` | `guardlink://model` | Full ThreatModel JSON |
| `definitions` | `guardlink://definitions` | `{assets[], threats[], controls[]}` with ids |
| `unmitigated` | `guardlink://unmitigated` | Unmitigated exposures via the canonical predicate (D57) |

Every resource read appends a `guardlink://freshness` block carrying the envelope plus `root_source: 'tool_call' \| 'server_cwd'` (`src/mcp/server.ts:210-222`).

### 4.3 🚨 Agent config files checked against the inventory

These files are loaded by tools at runtime. A wrong tool name is a live failure, not stale prose.

| File | Lines | Identical to CLAUDE.md? | MCP tools named | All exist? | CLI commands named | All exist? |
|---|---|---|---|---|---|---|
| `.mcp.json` | 9 | — | none | — | `guardlink mcp` | ✅ |
| `CLAUDE.md` | 183 | — | 7 distinct | ✅ | 12 distinct | ✅ |
| `AGENTS.md` | 183 | **byte-identical** | 7 | ✅ | 12 | ✅ |
| `.gemini/GEMINI.md` | 183 | **byte-identical** | 7 | ✅ | 12 | ✅ |
| `.github/copilot-instructions.md` | 183 | **byte-identical** | 7 | ✅ | 12 | ✅ |
| `.clinerules` | 131 | condensed | 7 | ✅ | 12 | ✅ |
| `.windsurfrules` | 131 | condensed | 7 | ✅ | 12 | ✅ |
| `.cursor/rules/guardlink.mdc` | 134 | condensed | 7 | ✅ | 12 | ✅ |

**Good news: no agent config file references a tool or command that does not exist.** The seven tools they name (`guardlink_context`, `guardlink_graph`, `guardlink_lookup`, `guardlink_validate`, `guardlink_status`, `guardlink_suggest`, `guardlink_diff`, `guardlink_entitlement_propose`) are all registered, and every `guardlink <cmd>` they name resolves.

**But there is one live failure, and it is in four files at once:**

> 🚨 **`CLAUDE.md:100`, `AGENTS.md:100`, `.gemini/GEMINI.md:100`, `.github/copilot-instructions.md:100`** present a copy-pasteable `guardlink entitle --propose` command that **cannot run**. It omits `--file` and `--line`, both of which `src/cli/index.ts:1614` requires. **[verified]**: `✗ --propose needs --file, --line`.
>
> This is the *only* worked example in those files, it sits under a rule that tells the agent it must never write `@entitles` by hand and must use this command instead, and the same files' `--help`-equivalent (`guardlink gal`, `src/cli/index.ts:2496`) shows the **correct** form with `--file` and `--line`. An agent following the instruction file gets an error; an agent reading `gal` gets it right. Four files, one broken instruction.

Two secondary observations:

1. **`.mcp.json` invokes `guardlink mcp`, not `guardlink-mcp`.** That is a deliberate decision (`src/mcp/index.ts:47`) and correct — but it means the `guardlink-mcp` bin, fixed in T8 and now working, is reachable only by a hand-written config. Nothing GuardLink generates uses it, and nothing documents it.
2. **The 183-line agent files are byte-identical across four platforms.** That is the sync mechanism working as designed, and it is also why a single wrong example replicates four times.

---

## 5. Annotation / data format schemas

Documented from `src/parser/parse-line.ts`, `src/parser/normalize.ts` and `src/types/index.ts` — not from `docs/SPEC.md`. Divergences from SPEC/README are called out.

### 5.1 Grammar fragments (`src/parser/parse-line.ts:20-90`)

| Fragment | Pattern | Meaning |
|---|---|---|
| `TAG_SEGMENT` | `[a-zA-Z0-9_-]+` | one segment of a `#tag` |
| `TAG_REF` | `#SEG(\.SEG)*` | `#cli`, `#auth-lib.token-verify` (cross-repo, D19) |
| `QUOTED_REF` | `"([^"\\\n]\|\\.)*"` | `"User Browser"`, `"/api/login"` |
| `COMPONENT` | `[A-Za-z_]\w*(\.[A-Za-z_]\w*)*` | `App.API` — **definition-site asset path only** |
| `ASSET_REF` | `TAG_REF \| QUOTED_REF \| Dotted.Path` | asset positions |
| `NAME` | `[A-Za-z]\w*([_\- ][A-Za-z]\w*)*` | threat/control/actor **names** at definition sites |
| `THREAT_REF` | `TAG_REF \| QUOTED_REF \| NAME` | threat, control **and actor** reference positions |
| `CAPABILITY` | `[A-Za-z][A-Za-z0-9_.\-]*` | single token; prose here is a parse error |
| `ID_DEF` | `\(#([a-zA-Z0-9_-]+)\)` | **never dotted** — you cannot define another repo's id |
| `SEVERITY` | `\[(P[0-3]\|critical\|high\|medium\|low)\]` | |
| `DESC` | `--\s*"(([^"\\]\|\\.)*)"` | `--` then a quoted string. **Colon form is not accepted** |
| `EXT_REFS_OPT` | `(\s+[a-zA-Z]+:[A-Za-z0-9_:.\-]+)*` | zero or more `scheme:value` |

`SEVERITY` maps via `resolveSeverity` (`src/parser/normalize.ts:26`): `p0/critical`→`critical`, `p1/high`→`high`, `p2/medium`→`medium`, `p3/low`→`low`. Case-insensitive.

`normalizeName` (`src/parser/normalize.ts:12`): NFKC → lowercase → whitespace→`_` → hyphens→`_` → collapse `_` → strip leading/trailing `_`.

### 5.2 Verb schemas

23 verbs are recognised (`KNOWN_VERBS`, `src/parser/parse-line.ts:486`). Fields marked **req** are required by the regex; everything else is optional.

#### Definitions

| Verb | Grammar | Fields |
|---|---|---|
| `@asset` | `@asset <COMPONENT> [(#id)] [-- "desc"]` | `path` **req** (dotted, no `#`, no hyphens), `id`, `description` |
| `@threat` | `@threat <NAME> [(#id)] [SEVERITY] [ext-refs] [-- "desc"]` | `name` **req**, `canonical_name` (derived), `id`, `severity`, `external_refs[]`, `description` |
| `@control` | `@control <NAME> [(#id)] [-- "desc"]` | `name` **req**, `canonical_name`, `id`, `description` |
| `@actor` | `@actor <NAME> [(#id)] [-- "desc"]` | `name` **req**, `canonical_name`, `id`, `description` |

Note the ordering constraint: on `@threat`, `(#id)` must precede `[severity]`, which must precede ext-refs, which must precede `--`. There is no permutation tolerance.

#### Relationships

| Verb | Grammar | Fields |
|---|---|---|
| `@mitigates` | `@mitigates <asset> against <threat> [using\|with <control>] [-- "desc"]` | `asset`, `threat` **req**; `control`, `description`. `with` is a v1 alias (`:103`) |
| `@exposes` | `@exposes <asset> to <threat> [SEVERITY] [ext-refs] [-- "desc"]` | `asset`, `threat` **req**; `severity`, `external_refs[]`, `description` |
| `@confirmed` | `@confirmed <threat> on <asset> [SEVERITY] [ext-refs] [-- "evidence"]` | `threat`, `asset` **req** (note: **reversed order vs `@exposes`**) |
| `@accepts` | `@accepts <threat> on\|to <asset> [-- "reason"]` | `threat`, `asset` **req**. `to` is a v1 alias (`:107`) |
| `@entitles` | `@entitles <actor> to <CAPABILITY> [on <asset>] [against <threat>] [-- "desc"]` | `actor`, `capability` **req**; `canonical_capability` derived; `asset`, `threat`, `description`. Actor position uses `THREAT_REF`, so cross-repo actor refs parse |
| `@transfers` | `@transfers <threat> from <asset> to <asset> [-- "desc"]` | `threat`, `source`, `target` **req** |
| `@flows` | `@flows A -> B [-> C …] [via <mechanism>] [-- "desc"]` | `source`, `target` **req**. **Multi-hop is sugar for N−1 pairwise flows**, each sharing mechanism/description/location (`:334`). `via` mechanism is free text terminated by ` -- "` |
| `@boundary` | `@boundary [between] A and B [(#id)] [-- "desc"]` **or** `@boundary A \| B [(#id)] [-- "desc"]` | `asset_a`, `asset_b` **req**; `id`, `description` |
| `@connects` | `@connects A to B [-- "desc"]` | **v1 compat**; parsed and stored as `verb: 'flows'` (`:363`) |

#### Lifecycle / governance

| Verb | Grammar | Fields |
|---|---|---|
| `@validates` | `@validates <control> for <asset> [-- "desc"]` | `control`, `asset` **req** |
| `@audit` | `@audit <asset> [-- "desc"]` | `asset` **req** |
| `@review` | `@review <asset> [-- "desc"]` | **v1 compat**; stored as `verb: 'audit'` (`:373`) |
| `@owns` | `@owns <owner> for <asset> [-- "desc"]` | `owner` **req** (`[a-zA-Z0-9_-]+` — **no spaces, no quotes**), `asset` **req** |
| `@handles` | `@handles <pii\|phi\|financial\|secrets\|internal\|public> on <asset> [-- "desc"]` | `classification` **req** (case-insensitive, lowercased), `asset` **req** |
| `@assumes` | `@assumes <asset> [-- "desc"]` | `asset` **req** |

#### Metadata / directives

| Verb | Grammar | Fields |
|---|---|---|
| `@feature` | `@feature "Name" [-- "desc"]` | `feature` **req** — **must be double-quoted**; unescaped |
| `@comment` | `@comment [-- "desc"]` | `description` only |
| `@source` | `@source file:<path> line:<n> [symbol:<name>]` | Not an annotation — a **directive** returning `sourceDirective`. `line` must match `[1-9]\d*` (no `line:0`). Only meaningful in `.gal` files |
| `@shield` | `@shield [-- "reason"]` | Negative lookahead `(?!:)` so it does not swallow `@shield:begin` |
| `@shield:begin` | `@shield:begin [-- "reason"]` | |
| `@shield:end` | `@shield:end` | Takes no description |

#### Continuation lines

A line that is *only* `-- "text"` (`src/parser/parse-line.ts:219`) is a continuation and attaches to the preceding annotation. It produces no annotation of its own.

### 5.3 Malformed-input behaviour

This is the part most likely to surprise, and it has three distinct outcomes:

| Input | Outcome | Level | Code | Source |
|---|---|---|---|---|
| Line does not start with `@` | Silently ignored | — | — | `:217` |
| `@verb` **not** in `KNOWN_VERBS` (e.g. `@param`, `@returns`, **`@flow`**) | **Silently ignored — no diagnostic at all** | — | — | `:475` |
| `@verb` in `KNOWN_VERBS`, regex fails, **structural evidence present** | Hard failure | `error` | `malformed-annotation` | `:444` |
| `@verb` in `KNOWN_VERBS`, regex fails, **no structural evidence** | Reported but non-fatal | `warning` | `prose-like` | `:459` |

"Structural evidence" (`structuralEvidence`, `:552`) is, in order: no arguments at all → a `#reference` → a spaced ` -- ` delimiter → one of that verb's own keywords (`VERB_KEYWORDS`, `:509`). Keywords are **per verb**, not global — `to` is evidence on `@exposes` but plain English on `@feature`.

**The silent tier is the dangerous one.** `@flow` (singular) is not a known verb, so it produces neither an annotation nor a diagnostic. **[verified]**: a file containing `// @flow #api -> #database via "PostgreSQL wire protocol"` parses to **0 flows, 0 diagnostics**. The README uses `@flow` twice (README:243, README:285).

Other observations on malformed handling:

- `ParseDiagnostic.level` is typed `'error' \| 'warning' \| 'fatal'` (`src/types/index.ts:582`) and `printDiagnostics` counts and prints fatals (`src/cli/index.ts:2658`), but **nothing in `src/` ever emits `level: 'fatal'`**. It is a dead tier.
- Only **two** `code` values are ever emitted: `malformed-annotation` and `prose-like`. Every other diagnostic (dangling refs, undeclared actors, inert entitlements, off-convention `.gal` paths, accepted-without-audit, provenance) is produced *without* a `code`, so a machine consumer cannot classify them. `ParseDiagnostic.code` is documented as "Present on diagnostics that have a defined kind; absent on ad-hoc ones" (`src/types/index.ts:587`) — in practice 2 kinds are defined and ~7 are ad-hoc.
- Dangling references are **not** parse errors. They surface later, from `findDanglingRefs` (`src/parser/validate.ts`), only when `validate`/`sarif`/`guardlink_validate` runs.

### 5.4 Spec vs implementation divergences

| Divergence | Implementation | SPEC / README says |
|---|---|---|
| `@flow` vs `@flows` | Only `@flows` is a verb; `@flow` is silently dropped | README:243, README:285 use `@flow` |
| `@boundary` separator | `and` or `\|` | README:244, README:286 use `<->` |
| `@audit` arity | `<asset> [-- "desc"]` only | README:252, README:288 use `by "Firm" on <date>` |
| `@validates` grammar | `<control> for <asset>` | README:253, README:289 use `<control> on <asset> using "..."` |
| `@owns` grammar | `<owner> for <asset>`, owner is `[a-zA-Z0-9_-]+` | README:255, README:291 use `<asset> by "quoted name"` — reversed, wrong keyword, and a quoted owner would not match the charset |
| `@shield` arity | description only | README:292 uses `@shield #api requires #auth-check` |
| `@flows` direction syntax | `A -> B` | README:397 uses `from … to …` |
| Verb count | 23 recognised verbs | README:446 says "Parse all 16 annotation types" |
| `@entitles` capability | single token, prose is a parse error | SPEC ✅ agrees (§3.2) |

**[verified]** — running the README's Data Flow, Operational and Entitlement example blocks through `node dist/cli/index.js validate` produced **6 `malformed-annotation` errors** plus 1 silent drop, on 10 example lines. Only `@handles` (×2) and `@assumes` parsed.

`docs/SPEC.md` (1,627 lines) is materially more accurate than the README — it documents `@actor`/`@entitles` correctly (§3.1, §3.2) and records reference-resolution tiers. Its remaining gap is that it predates `@source` sidecar conventions being codified (only 2 mentions of `@source`) and does not describe `@connects`/`@review` v1 compatibility.

### 5.5 Emitted artifact formats

#### `ThreatModel` JSON (`guardlink parse`, `guardlink report --format json`, `.guardlink/model.json`, `guardlink://model`)

**[verified]** top-level keys, in emission order:

`version` (`"1.1.0"`), `project`, `generated_at`*, `source_files`, `annotations_parsed`, `annotated_files[]`, `unannotated_files[]`, `assets[]`, `threats[]`, `controls[]`, `actors[]`, `entitlements[]`, `mitigations[]`, `exposures[]`, `confirmed[]`, `acceptances[]`, `transfers[]`, `flows[]`, `boundaries[]`, `validations[]`, `audits[]`, `ownership[]`, `data_handling[]`, `assumptions[]`, `shields[]`, `features[]`, `comments[]`, `coverage{}`, `external_refs[]`.

\* `generated_at` is **present** in `guardlink parse` output but **stripped** from `.guardlink/model.json` (F0/D26) so the tracked artifact does not churn per commit. **[verified]** — `parse` output has it, `.guardlink/model.json` does not.

`SourceLocation` (`src/types/index.ts:30`): `file`, `line`, `end_line?`, `parent_symbol?`, `origin_file?`, `origin_line?`. `origin_file` is set only for `.gal`-sourced annotations and is what `detectAnnotationMode` keys on.

`coverage` (`src/parser/parse-project.ts:280`):

| Field | Value | Status |
|---|---|---|
| `total_symbols` | **hardcoded `0`** | **INERT** — "Symbol-level coverage would need per-symbol parsing; not computed" (`:281`) |
| `annotated_symbols` | `annotations.length` | **Misnamed** — it is the annotation count, not a symbol count. **[verified]** 442 on this repo |
| `coverage_percent` | `fileCoveragePercent(annotatedFiles, fileCount)` | OK — file coverage, real since D14. **[verified]** 76 |
| `unannotated_critical` | **hardcoded `[]`** | **INERT** |

Two of four `coverage` fields are permanently constant in a schema presented as public. `src/types/index.ts:516` already warns *"`coverage_percent` is FILE coverage; do not derive it from this"* — the warning is correct and the field pair below it is still shipped.

#### SARIF 2.1.0 (`guardlink sarif`, `guardlink_sarif`)

**[verified]** structure:

```
{ $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [ { tool: { driver: { name, version, informationUri, rules[] } }, results[] } ] }
```

- `tool.driver.version` = **`"1.4.3"`, hardcoded at `src/analyzer/sarif.ts:274`**. This is wrong in two ways: it is not the package version (1.4.5), and `getPackageVersion()` (`src/version.ts:22`) exists specifically to prevent this. **[verified]** from the emitted document.
- **5 rules**: `guardlink/unmitigated-exposure` (warning), plus 4 others covering confirmed findings, dangling refs and parse diagnostics.
- Per result: `ruleId`, `level`, `message.text`, `locations[].physicalLocation.{artifactLocation.uri, region.startLine}`, `partialFingerprints["guardlink/threatId"]`, and `properties: {threatId, severity, asset, threat, externalRefs[]}`.
- `@entitles` is **deliberately absent** from SARIF — an entitlement never suppresses a finding (CHANGELOG, T5).

#### `.guardlink/graph/MANIFEST.json` (`guardlink artifacts`)

**[verified]**:

```json
{ "schema_version": 1,
  "annotation_hash": "sha256-v2:<64 hex>",
  "generator": "guardlink@1.4.5",
  "artifacts": [ { "path": "...", "bytes": 8306, "annotation_hash": "sha256-v2:..." } ] }
```

The manifest lists **6** artifacts; the command reports writing **8** (the manifest and `README.md` do not list themselves). `generator` inherits the stale `1.4.5`.

#### `.mmd` provenance header

Every emitted Mermaid file carries a 8-line `%%` header naming the artifact, the `annotation_hash`, the generator, and instructions to regenerate rather than hand-edit. **[verified]** on `.guardlink/graph/threat-graph.mmd`.

#### `guardlink ci --format json`

**[verified]**: `{schema: "guardlink.ci/v1", exposures: ThreatModelExposure[], drift: AnchorDrift[], summary: {exposures, drift, anchors, by_severity{critical,high,medium,low,unset}, by_kind{moved,symbol_gone,file_gone,line_gone}, strict, exit_code}}`. Exposures and drift are serialised as the parser's own types, with no renamed fields (`src/ci/index.ts:31`).

#### `.guardlink/entitlement-proposals.json`

`{version: LEDGER_VERSION, proposals: EntitlementProposal[]}` — each proposal carries `id`, `actor`, `capability`, `asset?`, `threat?`, `rationale`, `citation?{raw,file,line}`, `inert`, `warnings[]`, `target{file,line}`, `proposed_by`, `status`, `decision?{by,at,note}` (`src/review/entitlements.ts`).

#### Other emitted files

| File | Command | Format |
|---|---|---|
| `threat-model.md` | `report` | Markdown + Mermaid |
| `threat-dashboard.html` | `dashboard` | Self-contained HTML, `data-theme="dark"\|"light"` |
| `workspace-dashboard.html` | `merge` | Same generator, merged model |
| `<name>-weekly-diff.md` | `merge --diff-against` | Markdown |
| `.guardlink/threat-reports/<ts>-<fw>.md` | `threat-report` | YAML front matter + markdown |
| `.guardlink/workspace.yaml` | `link-project` | YAML: `workspace`, `this_repo`, `repos[]{name,registry?}`, `shared_definitions?` |
| `.guardlink/prompt.md` | `report` (auto-created) | Free-form markdown |

All four of `threat-dashboard.html`, `threat-model.md`, `threat-model.json`, `guardlink.sarif.json` are in `GENERATED_OUTPUT_FILES` (`src/parser/parse-project.ts:88`) and excluded from the scan set by basename anywhere in the tree (D17).

---

## 6. Configuration

### 6.1 Files read

| # | File | Read by | When |
|---|---|---|---|
| 1 | `<root>/.guardlink/config.json` | `readConfiguredMode`, `readConfiguredProject` (`src/parser/annotation-mode.ts:102`, `:125`), `loadProjectConfig` (`src/agents/config.ts:216`) | Every command that takes `[dir]` |
| 2 | `<root>/.guardlink/tui-config.json` | `loadProjectConfig` fallback (`src/agents/config.ts:73`) | **Legacy**, LLM keys only |
| 3 | `~/.config/guardlink/config.json` | `loadGlobalConfig` (`src/agents/config.ts:78`) | LLM keys only |
| 4 | `<root>/.guardlink/workspace.yaml` | `loadWorkspaceConfig` (`src/workspace/metadata.ts`) | `merge`, `link-project`, `guardlink_workspace_info`, report metadata |
| 5 | `<root>/.guardlink/entitlement-proposals.json` | `loadProposals` (`src/review/entitlements.ts`) | `entitle`, `validate` provenance check, `guardlink_entitlement_*` |
| 6 | `<root>/.guardlink/prompt.md` | `report` (`src/cli/index.ts:498`), `guardlink_report` (`src/mcp/server.ts:694`) | Report "Application Overview" |
| 7 | `<root>/.guardlink/pentest-findings/*.json` | `loadPentestData` (`src/analyze/index.ts`) | `threat-report`, dashboard |
| 8 | `<root>/package.json`, `Cargo.toml`, `.git/config` | `detectProjectName` (`src/cli/index.ts:91`) | Project-name auto-detection |

### 6.2 Precedence

**LLM configuration** (`src/agents/config.ts:3-9`, highest first):

1. Explicit CLI flags (`--api-key` + `--provider`, both required together) — never persisted
2. `GUARDLINK_LLM_KEY` + `GUARDLINK_LLM_PROVIDER`
3. Provider-specific env vars, in order: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`
4. `<root>/.guardlink/config.json`, falling back to `<root>/.guardlink/tui-config.json`
5. `~/.config/guardlink/config.json`

**Project name**: `--project` flag → `.guardlink/config.json` `project` → (for the AI/dashboard commands only) `detectProjectName`: git remote → `package.json` name (unless a generic placeholder, `src/cli/index.ts:85`) → `Cargo.toml` name → directory basename.

**Annotation mode**: `--mode` flag → `.guardlink/config.json` `annotation_mode` → observed from `origin_file` on relationship annotations (`detectAnnotationMode`) → `inline`.

Note the two project-name paths differ: `parse`/`status`/`validate`/`ci`/`report`/`sarif`/etc. use `readConfiguredProject`, while `threat-report`/`annotate`/`translate`/`ask`/`dashboard`/`feature` use `detectProjectName`. `sync` uses neither and hardcodes `basename(root)`; `entitle` uses neither and hardcodes `'unknown'`.

> **CORRECTION (Revision 2).** Revision 1 presented the `sync` and `entitle` hardcodes as producing divergent *output*. Neither does, and both were checked by running the built binary:
>
> - **`sync`** — synced agent files are byte-identical regardless of the configured project name (`diff -r` over two syncs with different `config.json` values: no difference). `syncAgentFiles` never renders `model.project`. See the correction in §2.3 for the full fixture.
> - **`entitle`** — the `'unknown'` default never reaches disk either. `.guardlink/entitlement-proposals.json` records `id`, `actor`, `capability`, `asset`, `threat`, `rationale`, `citation`, `target`, `proposed_by`, `status` and `decision` — **no project field**. A proposal filed under `project: 'unknown'` is byte-identical to one filed under the configured name.
>
> Both are genuine code-path inconsistencies and worth fixing. Neither is user-visible in the output of the command that contains it. The observable difference from fixing them is confined to `entitle --help`, which stops advertising `(default: "unknown")`.

### 6.3 `.guardlink/config.json` — every key

| Key | Written by `init` | Consumer outside the config module | Status |
|---|---|---|---|
| `version` | ✅ `"1.1.0"` | **none** | 🔴 **DEAD** |
| `project` | ✅ | `src/parser/annotation-mode.ts:126` → CLI `:189/:250/:280/…` | ✅ live |
| `language` | ✅ | **none** — `info.language` in `detect.ts` is computed fresh, never read back from config | 🔴 **DEAD** |
| `annotation_mode` | ✅ | `src/parser/annotation-mode.ts:103`; written by `migrate` at `src/cli/index.ts:655` | ✅ live |
| `definitions` | ✅ (`"definitions.ts"`) | **none** — definitions are found by glob, not by this field | 🔴 **DEAD** |
| `include` | ✅ (array) | **none** — `parseProject` defaults to `DEFAULT_INCLUDE` and no caller passes config-derived globs | 🔴 **DEAD** |
| `exclude` | ✅ (array) | **none** — same, `DEFAULT_EXCLUDE` | 🔴 **DEAD** |
| `provider` | `config set provider` | `src/agents/config.ts:139` | ✅ live |
| `model` | `config set model` | `src/agents/config.ts:143` | ✅ live |
| `apiKey` | `config set api-key` | `src/agents/config.ts:144` | ✅ live |
| `aiMode` | `config set ai-mode`/`cli-agent` | `src/cli/index.ts:918`, `:1203`, `:1302`, `:1865` | ✅ live |
| `cliAgent` | `config set cli-agent` | `src/cli/index.ts:919`, `:1204`, `:1303` | ✅ live |
| `redactEvidence` | `config set redact-evidence` | `src/analyze/index.ts` (`loadPentestData`), `src/cli/index.ts:1867` | ✅ live |
| `extendedThinking` | ❌ hand-edit only | `savedConfigExtras` (`src/agents/config.ts:159`) | ⚠️ live but undocumented and unsettable via CLI |
| `webSearch` | ❌ hand-edit only | `savedConfigExtras:160` | ⚠️ same |
| `responseFormat` | ❌ hand-edit only | `savedConfigExtras:161` | ⚠️ same |

### 6.4 🔴 Dead config keys: **5**

`version`, `language`, `definitions`, `include`, `exclude`.

**[verified]** with a purpose-built fixture: a `.guardlink/config.json` declaring `"version":"9.9.9"`, `"language":"cobol"`, `"definitions":"definitions.zzz"`, `"include":["**/*.NEVERMATCHES"]`, `"exclude":["**/*"]` — a configuration that, if honoured, would scan nothing.

```
project: CONFIG-NAME | annotations_parsed: 3 | source_files: 2 | assets: 1 | exposures: 1
```

`project` was honoured (the only proof the file was read at all). Every other key was ignored: it scanned files matched by `DEFAULT_INCLUDE`, ignored an `exclude` of `**/*`, and parsed `definitions.ts` despite being pointed at `definitions.zzz`.

This matters concretely for this repository: `.guardlink/config.json` excludes `"tests"` and `"**/tests/**"`, and those directories are excluded — but by `DEFAULT_EXCLUDE` (`src/parser/parse-project.ts:99`), not by the config. Anyone editing the config's `exclude` list to change the scan set will find it has no effect.

`parseProject` **does** accept `include`/`exclude` as programmatic options (`src/parser/parse-project.ts:44-46`) — the wiring gap is that no CLI or MCP call site passes config-derived values into them.

### 6.5 `~/.config/guardlink/config.json`

Same `SavedConfig` shape as the project file, but only the LLM subset is ever consulted. `version`/`project`/`language`/`annotation_mode`/`definitions`/`include`/`exclude` have no global-scope meaning.

### 6.6 `.guardlink/workspace.yaml`

| Key | Type | Consumer |
|---|---|---|
| `workspace` | string | `merge`, `guardlink_workspace_info`, report metadata |
| `this_repo` | string | same |
| `repos[].name` | string | tag-prefix resolution during merge |
| `repos[].registry` | string? | `guardlink_workspace_info` output |
| `repos[].local_path` | string? | link-time only; **not written to the yaml** (`src/workspace/types.ts:22`) |
| `shared_definitions` | string? | **Declared in the type (`src/workspace/types.ts:35`) and read by nothing** — 🔴 a sixth dead key, in a second config file |

---

## 7. Documentation debt

### 7.1 Existing docs

| Doc | Lines | Last touched | Current? | Reachable from README? | Verdict |
|---|---|---|---|---|---|
| `docs/SPEC.md` | 1,627 | 2026-08-10 | Mostly — has `@actor`/`@entitles`, reference-resolution tiers, join semantics. Missing `@connects`/`@review` v1 compat, thin on `@source` | ✅ (×2, incl. a badge) | Healthy |
| `docs/GUARDLINK_REFERENCE.md` | 226 | 2026-08-10 | Names 23 CLI commands (all exist) but **omits `ci`, `migrate`, `reanchor`, `artifacts`, `link-project`, `merge`**. Names 6 MCP tools of 24 | ❌ **0 mentions in README** | **Orphaned from the README.** Reachable only from CLAUDE.md et al., and written *into* consumer repos by `init`. A user-facing reference doc that the front door does not link |
| `docs/WORKSPACE.md` | 209 | **2026-02-27 (v1.4.0)** | **Stale by 3 releases.** Predates `REPORT_SCHEMA_VERSION`, `populateMetadata`, `link-project --remove`, and the D32 fix | ✅ | **Stale** |
| `docs/handling-evidence.md` | 156 | 2026-08-04 | Current | ✅ | Healthy |
| `docs/hooks/pre-commit` | — | — | Uses `guardlink artifacts` + `guardlink validate` — both exist | ❌ | Orphaned |
| `docs/prd/*` (7 files) | — | 2026-08-11 | Current — working documents (BACKLOG, epic, phase-0 recon, PR descriptions, design docs) | ❌ | Intentionally internal; fine |
| `docs/examples/*` (6 files) | — | 2026-08-04 | **Stale.** `threat-model.md` header reads `Threat Model Report — unknown` and `Generated: 2026-05-13` — generated before the D43 project-name fix, so the flagship sample output demonstrates the bug that was fixed | ✅ (×3) | **Stale** |
| `examples/github-action.yml` | — | — | **Broken** — line 49 uses `guardlink diff --from … --to …` | ✅ | **Broken** |
| `examples/ci/*.yml` + README | — | — | `per-repo-report.yml:65` has the same broken `--from`/`--to` | ✅ (×15) | **Broken** |
| `CONTRIBUTING.md` | — | **2026-02-21 (v1.0.0)** | Not re-verified in this pass; it is 6 releases old | ✅ | Likely stale |

### 7.2 CHANGELOG

- Version headers run `[Unreleased]` → `[1.4.5]` → … → `[1.0.0]`. There is **no `[1.5.0]`**, and `package.json` still says `1.4.5`.
- The `[Unreleased]` section covers T1, T3, T5, most of T4 and much of T6 — and does so well, with rationale and measurements.
- **It stops at commit `d9a3e2b` (2026-08-10).** 14 commits landed after that and are entirely undocumented: all of T9 (`guardlink ci`), all of T8 (the exec-bit fix), and the tail of T7 (D38/D43/D44/D45 first-run fixes).
- Also missing from `[Unreleased]` despite predating the cutoff: the MCP freshness envelope, GL-501/502/503 (`.gal` path convention), and the D35 `guardlink-mcp` bin fix.

### 7.3 Public API symbols with no JSDoc

10 of 76 — enumerated in §3.5. The list is dominated by the most likely entry points: `initProject`, `detectProject`, `diffModels`, `generateSarif`, `createServer`, `lookup`.

### 7.4 CLAUDE.md / AGENTS.md claim audit

They are byte-identical (`diff` = 0 lines), as are `.gemini/GEMINI.md` and `.github/copilot-instructions.md`.

| Claim | Verdict |
|---|---|
| "Annotation mode: `inline`" | ✅ — matches `.guardlink/config.json` |
| MCP tools named: `guardlink_context`, `guardlink_graph`, `guardlink_lookup`, `guardlink_diff`, `guardlink_validate`, `guardlink_status`, `guardlink_suggest` | ✅ all 7 registered **[verified]** |
| CLI commands named: `status`, `parse`, `validate`, `diff`, `report`, `sync`, `entitle`, `init`, `annotate`, `review`, `sarif`, `translate` | ✅ all exist **[verified]** |
| "Definitions … live in `.guardlink/definitions.ts`" | ✅ |
| Live stats block: 442 annotations, 16 assets, 15 threats, 12 controls, 80 exposures, 0 confirmed, 68 mitigations, 3 actors, 1 entitlement, 107 flows, 2 features | ✅ **[verified]** — `guardlink status .` reproduces every number |
| `annotation_hash: sha256-v2:66c22c9b…` | ✅ **[verified]** — matches `guardlink artifacts --dry-run` |
| Open-exposures list (15 entries) | ✅ **[verified]** — `guardlink validate .` reports the same 15 |
| Verb list in Rule 6 | ✅ — all 13 named verbs exist |
| "`guardlink sync` refreshes this block" | ✅ |
| **`guardlink entitle --propose` worked example (line 100)** | 🚨 **BROKEN — [verified]** `✗ --propose needs --file, --line` |
| Build commands | Not claimed — CLAUDE.md/AGENTS.md say nothing about `npm run build`/`test`/`lint`. Not wrong, but a gap: an agent has no build instruction |
| Layout claims | Not claimed |

The auto-synced portion of these files is **accurate to the digit**. The hand-written portion contains the one broken example. That is a useful signal about where to focus repair effort.

### 7.5 Where code and documentation disagree — summary

| Disagreement | Code | Doc |
|---|---|---|
| Package version | `1.4.5` after 115 commits | CHANGELOG `[Unreleased]` implies unreleased |
| SARIF tool version | hardcoded `1.4.3` | — |
| `diff` ref selection | positional `[ref]` | README + 2 CI examples: `--from`/`--to` |
| `guardlink scan` | does not exist | README:180 |
| MCP resource `guardlink://config` | does not exist | README:166 |
| MCP tool count | 24 | README lists 12; server's own comment says 18 |
| CLI command count | 29 | README's Commands table lists 24 and omits 7 that exist |
| Cursor config file | `.cursor/rules/guardlink.mdc` | README:143 says `.cursorrules` |
| Per-agent MCP configs | only one root `.mcp.json` **[verified]** | README:143-145 promise `.cursor/mcp.json`, `.windsurf/mcp.json`, `.cline/mcp.json` |
| Annotation grammar | §5.2 | README's Data Flow / Operational / All-Types blocks — 6 hard errors + 1 silent drop **[verified]** |
| `generateSarif` signature | `(model, diagnostics, danglingDiags, options)` | README:433 `generateSarif(model, '.')` — **[verified]** type error |
| Repo self-stats | 442 / 16 / 15 / 12 **[verified]** | README:15 says 272 / 12 / 13 / 10 |
| Verb count | 23 | README:446 "all 16 annotation types" |
| `config set` keys | 6 | usage message at `src/cli/index.ts:1894` lists 5 |
| `.guardlink/config.json` scan keys | ignored **[verified]** | the file `init` writes presents them as configuration |

---

## 8. DOCUMENTATION TRUTH LEDGER

One row per user-facing claim. **[v]** in the Reality column marks a claim exercised against the freshly built `dist/`.

### 8.1 README.md

| Surface | Location | Claim | Reality | Category |
|---|---|---|---|---|
| README | README.md:15 | "272 annotations across 12 assets, 13 threats, and 10 controls" | `guardlink status .` → 442 annotations, 16 assets, 15 threats, 12 controls **[v]** | WRONG |
| README | README.md:37 | `npm install -g guardlink` | Standard; not exercised (would publish/install globally) | OK |
| README | README.md:48-51 | `npm run build` then `npm link` | `npm run build` exits 0 **[v]**; `npm link` not exercised (mutates global prefix) | OK |
| README | README.md:60 | `guardlink init` | Exists; **[v]** dry-run creates 15 files | OK |
| README | README.md:63 | `guardlink annotate [prompt] [--mode inline\|external]` | Exists; `<prompt>` is **required**, not optional as the brackets imply | WRONG |
| README | README.md:67 | `guardlink validate .` | **[v]** works | OK |
| README | README.md:70 | `guardlink status .` | **[v]** works | OK |
| README | README.md:74-76 | Sample output "Assets: 3 … Coverage: 62%" laid out in two columns | Real `printStatus` (`src/cli/index.ts:2668`) prints a single left-aligned column of ~20 rows including Actors, Entitlements, Confirmed, Features | WRONG |
| README | README.md:81 | `guardlink report .` | **[v]** writes `threat-model.md` | OK |
| README | README.md:84 | `guardlink dashboard .` | **[v]** writes `threat-dashboard.html` | OK |
| README | README.md:87 | `guardlink threat-report stride --claude-code` | Command + flags exist; spawns Claude Code — not exercised | OK |
| README | README.md:90 | bare `guardlink` launches the TUI | `src/cli/index.ts:2626`. Not exercised (interactive) | OK |
| README | README.md:112 | "`guardlink diff --fail-on-new` blocks PRs" | Flag exists, `src/cli/index.ts:754` | OK |
| README | README.md:142 | Claude Code: `CLAUDE.md` + `.mcp.json` | **[v]** init creates both | OK |
| README | README.md:143 | Cursor: `.cursorrules` + `.cursor/mcp.json` | **[v]** init creates `.cursor/rules/guardlink.mdc` and no `.cursor/mcp.json` | WRONG |
| README | README.md:144 | Windsurf: `.windsurfrules` + `.windsurf/mcp.json` | **[v]** init creates `.windsurfrules`; no `.windsurf/mcp.json` | WRONG |
| README | README.md:145 | Cline: `.clinerules` + `.cline/mcp.json` | **[v]** init creates `.clinerules`; no `.cline/mcp.json` | WRONG |
| README | README.md:146 | Codex: `AGENTS.md`, directive only | **[v]** correct | OK |
| README | README.md:147 | Copilot: `.github/copilot-instructions.md`, directive only | **[v]** correct | OK |
| README | README.md:153-164 | MCP Tools table, 12 rows | All 12 exist **[v]**; **12 more are registered and unlisted**: `guardlink_context`, `guardlink_graph`, `guardlink_annotate_apply`, `guardlink_reanchor`, `guardlink_threat_reports`, `guardlink_sync`, `guardlink_clear`, `guardlink_unannotated`, `guardlink_review_list`, `guardlink_review_accept`, `guardlink_entitlement_propose`, `guardlink_entitlement_list` | MISSING |
| README | README.md:166 | Resources: `guardlink://model`, `guardlink://definitions`, `guardlink://config` | **[v]** `resources/list` returns `guardlink://model`, `guardlink://definitions`, `guardlink://unmitigated`. `config` does not exist; `unmitigated` is undocumented | ABSENT |
| README | README.md:174 | `guardlink init [dir]` | **[v]** | OK |
| README | README.md:175 | `guardlink annotate [prompt] …` | prompt is required | WRONG |
| README | README.md:176 | `guardlink parse [dir]` | **[v]** | OK |
| README | README.md:177 | `guardlink status [dir]` | **[v]** | OK |
| README | README.md:178 | `guardlink validate [dir]` | **[v]** | OK |
| README | README.md:179 | `guardlink validate --strict` | **[v]** flag exists | OK |
| README | README.md:180 | `guardlink scan [dir]` — "Find unannotated security-relevant functions" | **[v]** `error: unknown command 'scan'`. Nearest equivalent is `guardlink unannotated` | ABSENT |
| README | README.md:181 | `guardlink report [dir]` | **[v]** | OK |
| README | README.md:182 | `guardlink dashboard [dir]` | **[v]** | OK |
| README | README.md:183 | `guardlink diff --from <ref>` | **[v]** `error: unknown option '--from'` | ABSENT |
| README | README.md:184 | `guardlink diff --fail-on-new` | flag exists | OK |
| README | README.md:185 | `guardlink sarif [dir]` | **[v]** | OK |
| README | README.md:186 | `guardlink threat-report [fw]` | exists | OK |
| README | README.md:187 | `guardlink threat-reports` | exists | OK |
| README | README.md:188 | `guardlink translate [prompt]` | exists | OK |
| README | README.md:189 | `guardlink ask <query>` | exists | OK |
| README | README.md:190-191 | `guardlink review [dir]`, `--list` | exist | OK |
| README | README.md:192-194 | `guardlink entitle [dir]`, `--propose`, `--list` | exist | OK |
| README | README.md:195 | `guardlink clear [dir]` `--dry-run` | exists | OK |
| README | README.md:196 | `guardlink sync [dir]` | exists | OK |
| README | README.md:197 | `guardlink unannotated [dir]` | exists | OK |
| README | README.md:198-200 | `link-project` + `--add` + `--remove` | exist | OK |
| README | README.md:201 | `guardlink merge <files...>` | exists | OK |
| README | README.md:202 | `guardlink report --format json` | **[v]** works | OK |
| README | README.md:203 | `guardlink config` | exists | OK |
| README | README.md:204 | `guardlink mcp` | exists | OK |
| README | README.md:170-204 | Commands table as a whole | **Omits 7 existing commands**: `ci`, `migrate`, `reanchor`, `artifacts`, `feature`, `tui`, `gal` | MISSING |
| README | README.md:210 | "supports `//`, `#`, `--`, `/* */`, `""" """`, and 25+ comment styles" | `src/parser/comment-strip.ts` — not exhaustively counted in this pass | OK |
| README | README.md:212 | `.gal` files drop the comment prefix; `@source file:… line:… [symbol:…]` | Matches `src/parser/parse-line.ts:134` | OK |
| README | README.md:217-219 | `@asset App.API (#api) …`, `@threat SQL_Injection (#sqli) [critical] cwe:CWE-89 …`, `@control Parameterized_Queries (#prepared-stmts) …` | Parse correctly | OK |
| README | README.md:225-228 | `@mitigates`, `@exposes`, `@accepts`, `@transfers` examples | Parse correctly | OK |
| README | README.md:234-237 | `.gal` block with `@source`, `@exposes`, `@audit`, `@comment` | Parse correctly | OK |
| README | README.md:243 | `@flow #api -> #database via "PostgreSQL wire protocol"` | **[v]** `@flow` is not a known verb — **silently discarded, no diagnostic**. Verb is `@flows` | ABSENT |
| README | README.md:244 | `@boundary #api <-> #cdn -- "…"` | **[v]** `error: Malformed @boundary … found a #reference`. Grammar is `A and B` or `A \| B` | WRONG |
| README | README.md:245-246 | `@handles pii on #api`, `@handles secrets on #auth` | **[v]** parse correctly | OK |
| README | README.md:252 | `@audit #api by "PenTest Corp" on 2025-03-15 -- "…"` | **[v]** `error: Malformed @audit`. Grammar is `@audit <asset> [-- "desc"]` | WRONG |
| README | README.md:253 | `@validates #input-validation on #api using "Jest integration tests"` | **[v]** `error: Malformed @validates`. Grammar is `<control> for <asset>` | WRONG |
| README | README.md:254 | `@assumes #api -- "Rate limiting handled by API gateway"` | **[v]** parses | OK |
| README | README.md:255 | `@owns #api by "backend-team"` | **[v]** `error: Malformed @owns`. Grammar is `@owns <owner> for <asset>`, owner charset `[a-zA-Z0-9_-]+` | WRONG |
| README | README.md:265-267 | `@actor Namespace_Admin (#ns-admin)` + `@entitles #ns-admin to configure-archival-destination on #archival-fs against #path-traversal` | Matches `src/parser/parse-line.ts:99`, `:112` | OK |
| README | README.md:274 | `@asset UserService (#users)` | parses | OK |
| README | README.md:275 | `@threat XSS (#xss) [high] cwe:CWE-79` | parses | OK |
| README | README.md:276 | `@control WAF (#waf)` | parses | OK |
| README | README.md:277 | `@actor Namespace_Admin (#ns-admin)` | parses | OK |
| README | README.md:278 | `@mitigates #api against #sqli using #prepared-stmts` | parses | OK |
| README | README.md:279 | `@exposes #api to #xss [P1]` | parses | OK |
| README | README.md:280 | `@confirmed #sqli on #api [critical] -- "…"` | parses | OK |
| README | README.md:281 | `@feature "SSO Login" -- "…"` | parses | OK |
| README | README.md:282 | `@accepts #dos on #api -- "By design"` | parses | OK |
| README | README.md:283 | `@transfers #sqli from #api to #db` | parses | OK |
| README | README.md:284 | `@entitles #ns-admin to configure-archival on #fs against #path-traversal -- "…"` | parses | OK |
| README | README.md:285 | `@flow` table row, `@flow #api -> #db via "SQL"` | **[v]** verb does not exist; silently dropped | ABSENT |
| README | README.md:286 | `@boundary #api <-> #external` | **[v]** parse error | WRONG |
| README | README.md:287 | `@handles pii on #users` | parses | OK |
| README | README.md:288 | `@audit #api by "Firm" on 2025-01-01` | **[v]** parse error | WRONG |
| README | README.md:289 | `@validates #auth on #api using "tests"` | **[v]** parse error | WRONG |
| README | README.md:290 | `@assumes #api -- "Behind VPN"` | parses | OK |
| README | README.md:291 | `@owns #api by "team-backend"` | **[v]** parse error | WRONG |
| README | README.md:292 | `@shield #api requires #auth-check` — "AI exclusion zone" | **[v]** parse error. Grammar is `@shield [-- "reason"]`; the block form is `@shield:begin`/`@shield:end`, undocumented in README | WRONG |
| README | README.md:294 | Severity `[critical]/[P0]` … ; ext refs `cwe:`, `capec:`, `owasp:` | Matches `src/parser/parse-line.ts:83`, `:90` | OK |
| README | README.md:302-329 | GitHub Actions YAML block | See next 4 rows | — |
| README | README.md:316 | `npm install -g guardlink` in CI | Not exercised | OK |
| README | README.md:319 | `guardlink validate .` | **[v]** | OK |
| README | README.md:322 | `guardlink diff --from origin/main --to HEAD` | **[v]** `error: unknown option '--from'`. Neither flag exists | ABSENT |
| README | README.md:325 | `guardlink sarif . -o guardlink.sarif` | **[v]** works | OK |
| README | README.md:331 | links `examples/github-action.yml` | File exists but contains the same broken `--from`/`--to` at line 49 | WRONG |
| README | README.md:335 | links `examples/ci/README.md` | Exists; `per-repo-report.yml:65` has the same broken flags | WRONG |
| README | README.md:345 | "`guardlink sarif` exports unmitigated exposures and `@confirmed` findings" | **[v]** 5 rules, incl. unmitigated-exposure; result count matches | OK |
| README | README.md:351-356 | `guardlink translate --claude-code`, `guardlink translate "…" --clipboard` | Flags exist; agent launch not exercised | OK |
| README | README.md:358 | pentest JSON in `.guardlink/pentest-findings/` | `loadPentestData`, `src/analyze/index.ts` | OK |
| README | README.md:365 | `@confirmed #sqli on App.API [critical] cwe:CWE-89 -- "…"` | parses | OK |
| README | README.md:370 | `guardlink config set redact-evidence true` | **[v]** key accepted at `src/cli/index.ts:1937` | OK |
| README | README.md:380-381 | `guardlink link-project ./a ./b ./c --workspace acme-platform` | Flags exist; not exercised (writes to 3 repos) | OK |
| README | README.md:387 | `guardlink report --format json -o guardlink-report.json` | **[v]** writes exactly one JSON file | OK |
| README | README.md:390-391 | `guardlink merge a.json b.json -o dashboard.html --json merged.json` | All flags exist | OK |
| README | README.md:394 | `guardlink merge *.json --diff-against last-week.json --json merged.json` | All flags exist | OK |
| README | README.md:397 | `@flows #request from #api-gateway.router to #payment-svc.refund` | **[v]** `error: Malformed @flows`. Grammar is `A -> B`; also `#request` is in the source-asset position, not a payload | WRONG |
| README | README.md:405-414 | "Real-World Results" — 143 annotations, 27/37 vulns, ~$0.50 | External experiment; not reproducible here | OK |
| README | README.md:423-427 | `import { parseProject } from 'guardlink/parser'` etc. (5 imports) | **[v]** all 5 subpaths compile under `moduleResolution: nodenext`, tsc exit 0 | OK |
| README | README.md:429 | `const { model } = await parseProject({ root: '.', project: 'my-app' })` | **[v]** type-checks | OK |
| README | README.md:431 | `const markdown = generateReport(model)` | **[v]** type-checks | OK |
| README | README.md:432 | `const diff = diffModels(oldModel, newModel)` | **[v]** type-checks | OK |
| README | README.md:433 | `const sarif = generateSarif(model, '.')` | **[v]** `error TS2345: Argument of type 'string' is not assignable to parameter of type 'ParseDiagnostic[]'`. Real signature is `(model, diagnostics, danglingDiags, options)` | WRONG |
| README | README.md:440 | links `docs/SPEC.md` | Exists, current | OK |
| README | README.md:446 | "L1 Parser — Parse all 16 annotation types" | 23 verbs in `KNOWN_VERBS` (`src/parser/parse-line.ts:486`) | WRONG |
| README | README.md:447-451 | L2/L3/L4 conformance levels; "This implementation is Level 4 conformant" | L4 requires MCP + suggestion engine + directives — all present | OK |
| README | README.md:457-459 | ThreatSpec heritage | Historical | OK |
| README | (absent) | — | `guardlink ci`, `guardlink migrate`, `guardlink reanchor`, `guardlink artifacts`, `guardlink feature`, `guardlink tui`, `guardlink gal` documented nowhere in README | MISSING |
| README | (absent) | — | 8 environment variables (`GUARDLINK_LLM_KEY`, `GUARDLINK_LLM_PROVIDER`, 6 provider keys) documented nowhere in README | MISSING |
| README | (absent) | — | `.guardlink/config.json` schema documented nowhere in README | MISSING |
| README | (absent) | — | `guardlink-mcp` bin documented nowhere | MISSING |
| README | (absent) | — | `@shield:begin` / `@shield:end` block form documented nowhere in README | MISSING |
| README | (absent) | — | `@comment` verb absent from the "All Annotation Types" table | MISSING |
| README | (absent) | — | `@source` directive absent from the "All Annotation Types" table | MISSING |
| README | (absent) | — | `annotation_hash` / artifact provenance documented nowhere | MISSING |

### 8.2 `guardlink --help` (both binaries)

| Surface | Location | Claim | Reality | Category |
|---|---|---|---|---|
| `--help` | `src/cli/index.ts:247` | `--pretty  Pretty-print JSON output (default: true)` | No `--no-pretty` exists; value can never be false **[v]** | INERT |
| `--help` | `src/cli/index.ts:2386` | `--model <model>  LLM model override` (on `tui`) | Parsed, never read **[v]** | INERT |
| `--help` | `src/cli/index.ts:1853` | `[key]  Config key: provider, api-key, model, ai-mode, cli-agent, redact-evidence` | All 6 accepted | OK |
| `--help` | `src/cli/index.ts:1894` | `Keys: provider, api-key, model, ai-mode, cli-agent` (on missing args) | Omits `redact-evidence`, which works | MISSING |
| `--help` | `src/cli/index.ts:146` | `init --mode` default `external` | Correct **[v]** | OK |
| `--help` | `src/cli/index.ts:1064` | `annotate --mode` default `inline` | Correct — but silently opposite to `init --mode`; neither help text mentions the other | WRONG |
| `--help` | `src/cli/index.ts:463` | `report -f  Output format: md, json, or both (default: md)` | Correct **[v]**; an unrecognised value silently writes nothing rather than erroring | WRONG |
| `--help` | `src/cli/index.ts:2037` | `link-project -w  Workspace name (fresh link only)` | Correct — the parenthetical does say it | OK |
| `--help` | `src/cli/index.ts:2038` | `link-project -r, --registry <url>` | Silently ignored in `--remove` mode; help does not say | MISSING |
| `--help` | `src/cli/index.ts:1584` | `entitle -p, --project <n>` default `unknown` | Correct, but inconsistent with every other command's config.json default | WRONG |
| `--help` | `src/cli/index.ts:1061` | `annotate <prompt>` shown as required | Correct **[v]** | OK |
| `--help` | `src/cli/index.ts:428` | `ci … (exit 0 unless --strict)` | **[v]** default exit 0 with 15 findings; `--strict` exit 1 | OK |
| `--help` | `src/cli/index.ts:314` | `validate --artifacts … exits non-zero on drift` | **[v]** clean repo → `✓ Artifacts are current.`, exit 0 | OK |
| `--help` | `src/cli/index.ts:799` | `sarif --min-severity` | **[v]** monotone: critical 0, high 3, medium 9, low 15 | OK |
| `--help` | `src/cli/index.ts:800` | `sarif --no-diagnostics` | **[v]** 6 → 0 results on a fixture with 6 parse errors | OK |
| `--help` | `src/cli/index.ts:1994` | `dashboard --light` | **[v]** flips `data-theme="dark"` → `"light"` in the output HTML | OK |
| `--help` | `src/cli/index.ts:552` | `migrate --allow-anchor-loss (D48)` | Gate present at `:576` and `:645` | OK |
| `--help` | `src/cli/index.ts:670` | `reanchor --apply` | Present at `:706` | OK |
| `--help` | (absent) | — | No `--help` text anywhere mentions that a bare `guardlink` launches the TUI (`src/cli/index.ts:2626`) | MISSING |
| `--help` | (absent) | — | No `--help` text mentions any environment variable | MISSING |
| `guardlink-mcp` | `src/mcp/index.ts` | — | Binary has **no `--help`, no `--version`, no flags**. Invoking it with anything just starts a stdio server that will not speak | MISSING |

### 8.3 `guardlink gal` output

`guardlink gal` (`src/cli/index.ts:2395-2623`) is the project's most accurate annotation documentation. Spot-checked rows:

| Surface | Location | Claim | Reality | Category |
|---|---|---|---|---|
| `gal` | `src/cli/index.ts:2427` | `@asset api.auth.token_store -- "…"` | parses | OK |
| `gal` | `:2433` | `@threat SQL Injection (#sql-inj) [high] cwe:CWE-89 -- "…"` | parses | OK |
| `gal` | `:2446` | `@actor Namespace_Admin (#ns-admin) -- "…"` | parses | OK |
| `gal` | `:2457` | `@exposes api.auth to SQL Injection [high] cwe:CWE-89` | parses | OK |
| `gal` | `:2464` | "`using` is the primary keyword; `with` also accepted" | Matches `:102`/`:103` | OK |
| `gal` | `:2472` | `@confirmed SQL Injection on api.auth [critical] …` | parses | OK |
| `gal` | `:2490` | `@entitles #ns-admin to configure-archival-destination on #archival-fs against #path-traversal` | parses | OK |
| `gal` | `:2496-2498` | `guardlink entitle --propose … --file common/api/metadata.go --line 189 --rationale "…"` | **Correct — includes `--file` and `--line`** | OK |
| `gal` | `:2505` | `@transfers DDoS from api.gateway to cdn.cloudflare -- "…"` | parses | OK |
| `gal` | `:2515-2516` | `@flows api.auth -> db.users via TLS 1.3` | parses | OK |
| `gal` | `:2523-2524` | `@boundary internet and api.gateway (#edge)`, `@boundary api.gateway \| db.users` | Both parse | OK |
| `gal` | `:2534` | `@handles pii on db.users -- "…"` | parses | OK |
| `gal` | `:2540` | `@owns platform-team for api.auth` | parses (correct grammar, unlike README) | OK |
| `gal` | `:2545` | `@validates Input Validation for api.auth -- "…"` | parses (correct grammar, unlike README) | OK |
| `gal` | `:2550` | `@audit db.users -- "…"` | parses (correct grammar, unlike README) | OK |
| `gal` | `:2555` | `@assumes api.gateway -- "…"` | parses | OK |
| `gal` | `:2566` | `@feature "SSO Login" -- "…"` | parses | OK |
| `gal` | `:2577` | `@comment -- "…"` | parses | OK |
| `gal` | `:2585` | `@shield -- "…"` | parses | OK |
| `gal` | `:2590-2592` | `@shield:begin` / `@shield:end` | parse | OK |
| `gal` | `:2599` | ext refs `cwe:CWE-89 owasp:A03:2021 capec:CAPEC-66 attack:T1190` | All match `EXT_REFS_OPT` | OK |
| `gal` | `:2610` | "Annotations work in any comment style: `//` `/*` `#` `--` `<!-- -->`" | Matches `comment-strip.ts` | OK |
| `gal` | `:2611` | "Place annotations on the line ABOVE the code they describe" | Convention | OK |
| `gal` | `:2612` | "Asset names are case-insensitive and normalized (spaces→underscores)" | Matches `normalizeName` | OK |
| `gal` | `:2614` | "`@flows` uses `->` arrow syntax (not 'to')" | Correct — and directly contradicts README:397 | OK |
| `gal` | `:2476-2479` | `@accepts Timing Attack on api.auth -- "…"` | parses | OK |
| `gal` | (absent) | — | `@connects` and `@review` (v1 compat verbs) not shown | MISSING |
| `gal` | (absent) | — | `@source` shown in prose at `:2417` but has no section of its own | MISSING |

### 8.4 `docs/*.md`

| Surface | Location | Claim | Reality | Category |
|---|---|---|---|---|
| SPEC | docs/SPEC.md | 23 verbs' grammar, incl. `@actor`/`@entitles` (§3.1, §3.2) | Matches implementation on the verbs checked | OK |
| SPEC | docs/SPEC.md | — | `@connects` and `@review` v1-compat aliases (`src/parser/parse-line.ts:117`, `:122`) barely covered (2 and 1 mentions) | MISSING |
| SPEC | docs/SPEC.md | — | Silent-drop behaviour for unknown `@verb` documented nowhere | MISSING |
| REFERENCE | docs/GUARDLINK_REFERENCE.md | names 23 CLI commands | All 23 exist **[v]** | OK |
| REFERENCE | docs/GUARDLINK_REFERENCE.md | — | Omits `ci`, `migrate`, `reanchor`, `artifacts`, `link-project`, `merge` | MISSING |
| REFERENCE | docs/GUARDLINK_REFERENCE.md | names 6 MCP tools | All 6 exist; 18 more are unlisted | MISSING |
| REFERENCE | docs/GUARDLINK_REFERENCE.md | — | Not linked from README at all (0 mentions) | MISSING |
| WORKSPACE | docs/WORKSPACE.md | Workspace linking + merge | Last touched 2026-02-27 (v1.4.0). Predates `REPORT_SCHEMA_VERSION`, `populateMetadata`, `link-project --remove`, D32 | WRONG |
| WORKSPACE | docs/WORKSPACE.md | — | `shared_definitions` key in `workspace.yaml` is read by nothing | INERT |
| EVIDENCE | docs/handling-evidence.md | redaction guidance, `redact-evidence` | Key works **[v]** | OK |
| HOOKS | docs/hooks/pre-commit | `guardlink artifacts` + `guardlink validate` | Both exist | OK |
| HOOKS | docs/hooks/pre-commit | — | Not linked from README | MISSING |
| CHANGELOG | CHANGELOG.md:6 | `[Unreleased]` | 115 commits sit here; `package.json` still `1.4.5`; no `[1.5.0]` heading | WRONG |
| CHANGELOG | CHANGELOG.md | — | 14 commits after `d9a3e2b` undocumented: `guardlink ci`, exec-bit fix, D38/D43/D44/D45 | MISSING |
| CHANGELOG | CHANGELOG.md | — | MCP freshness envelope, GL-501/502/503, D35 `guardlink-mcp` fix undocumented | MISSING |
| CONTRIBUTING | CONTRIBUTING.md | — | Last touched 2026-02-21 (v1.0.0). Not re-verified in this pass | — |

### 8.5 `examples/` and `docs/examples/`

| Surface | Location | Claim | Reality | Category |
|---|---|---|---|---|
| examples | examples/github-action.yml:49 | `guardlink diff --from origin/${{…}} --to HEAD` | **[v]** neither flag exists. `\|\| true` swallows it, so the PR comment body becomes the error text | ABSENT |
| examples | examples/ci/per-repo-report.yml:65 | same | same | ABSENT |
| examples | examples/ci/per-repo-report.yml | `guardlink report`, `guardlink sarif`, `guardlink validate` | All exist | OK |
| examples | examples/ci/workspace-merge.yml | `guardlink merge` | Exists | OK |
| examples | examples/ci/README.md | Two-workflow multi-repo setup | Workflows exist | OK |
| docs/examples | docs/examples/threat-model.md:1 | `# Threat Model Report — unknown` | Generated 2026-05-13, before the D43 project-name fix. The showcase sample output demonstrates the bug that was fixed | WRONG |
| docs/examples | docs/examples/README.md | table of 5 sample outputs and their generating commands | Files exist; all 5 commands exist | OK |
| docs/examples | docs/examples/threat-dashboard.html | "generated by `guardlink dashboard .`" | Predates the T2 dashboard trim (Risk Topology + Pentest Findings removed), so it shows sections the tool no longer emits | WRONG |

### 8.6 Agent config files

| Surface | Location | Claim | Reality | Category |
|---|---|---|---|---|
| CLAUDE.md | CLAUDE.md:100 | `guardlink entitle --propose --actor '#ns-admin' --capability … --asset … --rationale "…"` | 🚨 **[v]** `✗ --propose needs --file, --line` | WRONG |
| AGENTS.md | AGENTS.md:100 | identical | 🚨 identical failure | WRONG |
| GEMINI | .gemini/GEMINI.md:100 | identical | 🚨 identical failure | WRONG |
| Copilot | .github/copilot-instructions.md:100 | identical | 🚨 identical failure | WRONG |
| CLAUDE.md | CLAUDE.md:17-21 | 4-row "You are about to… / Ask" table naming `guardlink_context`, `guardlink_graph`, `guardlink_lookup`, `guardlink validate`, `guardlink diff` | All exist **[v]** | OK |
| CLAUDE.md | CLAUDE.md:24 | "Without MCP: `guardlink status .`, `guardlink parse .`, `guardlink diff HEAD~1`" | All exist **[v]** | OK |
| CLAUDE.md | CLAUDE.md:27 | "Full reference: `docs/GUARDLINK_REFERENCE.md`" | File exists | OK |
| CLAUDE.md | CLAUDE.md:31 | "Annotation mode: `inline`" | Matches `.guardlink/config.json` | OK |
| CLAUDE.md | CLAUDE.md:~66 | Verb list: `@mitigates @exposes @confirmed @flows @handles @boundary @comment @validates @audit @owns @assumes @transfers @feature` | All 13 exist | OK |
| CLAUDE.md | CLAUDE.md (Tools) | `guardlink_context`, `guardlink_graph`, `guardlink_lookup`, `guardlink_diff`, `guardlink_validate`, `guardlink_status`, `guardlink_suggest` | All 7 registered **[v]** | OK |
| CLAUDE.md | CLAUDE.md (Quick Syntax) | 13 example lines | All parse | OK |
| CLAUDE.md | CLAUDE.md (Stats) | 442 annotations, 16 assets, 15 threats, 12 controls, 80 exposures, 0 confirmed, 68 mitigations, 3 actors, 1 entitlement, 107 flows, 2 features | **[v]** every number reproduced by `guardlink status .` | OK |
| CLAUDE.md | CLAUDE.md (hash) | `annotation_hash: sha256-v2:66c22c9b8df9…` | **[v]** matches `guardlink artifacts --dry-run` | OK |
| CLAUDE.md | CLAUDE.md (Open Exposures) | 15 entries with file:line | **[v]** `guardlink validate .` reports the same 15 | OK |
| CLAUDE.md | CLAUDE.md | — | Says nothing about `npm run build` / `npm test` / `npm run lint` — an agent has no build instruction | MISSING |
| .clinerules | .clinerules:28 | "propose it with `guardlink entitle --propose`" | Command exists; no worked example, so nothing broken | OK |
| .windsurfrules | .windsurfrules:28 | identical | OK | OK |
| .cursor | .cursor/rules/guardlink.mdc:33 | identical | OK | OK |
| .mcp.json | .mcp.json:4-7 | `{"command":"guardlink","args":["mcp"]}` | Command exists; requires `guardlink` on PATH | OK |
| .mcp.json | (absent) | — | `guardlink-mcp` (the conventional `npx -y guardlink-mcp` entry point) is never generated or documented | MISSING |

### 8.7 Ledger totals

| Category | Count |
|---|---|
| **OK** | **102** |
| **MISSING** | **29** |
| **WRONG** | **26** |
| **ABSENT** | **7** |
| **INERT** | **3** |
| **STUB** | **0** |
| **Total rows** | **167** |

Notes on the totals:

- **STUB = 0.** Nothing in GuardLink returns "not implemented". Every command that exists, works. The failure mode of this codebase is documentation drift, not half-built features.
- **ABSENT = 7** and they concentrate: 4 are the `diff --from/--to` flag pair (README ×2 + 2 CI example files), 2 are `@flow`, 1 is `guardlink scan`, 1 is `guardlink://config`. Three distinct root causes, seven surfaces.
- **INERT = 3**: `parse --pretty`, `tui --model`, `workspace.yaml`'s `shared_definitions`. The 5 dead `.guardlink/config.json` keys and the 2 hardcoded `coverage` fields are counted in §6.4 and §5.5 rather than as ledger rows, since no document claims them individually.
- The 61% OK rate is not the headline. The headline is *which* rows are wrong: the annotation grammar section of the README — the single most-copied part of the document — is 6 WRONG + 2 ABSENT out of 20 example lines.

---

## 9. Suggested priorities

Two workstreams. They do not share owners, reviewers, or risk profiles, and conflating them is how the current state arose.

### Workstream A — code is wrong

| # | Item | Why now | Effort | Evidence |
|---|---|---|---|---|
| A1 | **Bump `package.json` to `1.5.0` and cut the release** | 115 commits including 4 new CLI commands and 4 new MCP tools are unreleased. Every version-bearing artifact currently lies: `--version`, MCP `serverInfo`, `MANIFEST.json` `generator`. Nothing else on this list can be shipped without it | S | §1, §5.5 |
| A2 | **Fix the CLAUDE.md `entitle --propose` example** | 🚨 The only broken *runtime-consumed* claim in the repo. Four agent files, replicated by `guardlink sync`, telling every agent to run a command that errors. It is a one-line fix in the source template. Highest damage-to-effort ratio on this list | S | §4.3, §8.6 **[v]** |
| A3 | **Replace SARIF's hardcoded `'1.4.3'` with `getPackageVersion()`** | `src/analyzer/sarif.ts:274`. The function was added in this very release to prevent exactly this. GitHub Advanced Security records the emitting tool version | S | §5.5 **[v]** |
| A4 | **Decide `.guardlink/config.json`'s 5 dead keys: wire or remove** | `init` writes `include`/`exclude`/`language`/`definitions`/`version` into every new project. A user editing `exclude` to narrow a scan gets silence. `parseProject` already accepts the options — this is a plumbing job at the CLI call sites, not a feature. Alternatively stop writing them | M | §6.4 **[v]** |
| A5 | **Delete or wire `tui --model`** | Parsed, typed, never read. Its two siblings forward via env vars; a third env var would finish it | S | §2.3 **[v]** |
| A6 | **Give `parse` a `--no-pretty`, or drop `--pretty`** | Currently a flag that cannot change anything | S | §2.3 **[v]** |
| A7 | **Make `sync` and `entitle` read the project name like everything else** | `sync` hardcodes `basename(root)` (`:1430`), `entitle` hardcodes `'unknown'` (`:1584`). D43 fixed this for every other command and missed these two | S | §2.3, §6.2 |
| A8 | **Error on an unrecognised `report --format`** | `--format xml` currently writes no file and reports success | S | §2.3 |
| A9 | **Remove or implement `coverage.total_symbols` and `coverage.unannotated_critical`** | Hardcoded `0` and `[]` in a public JSON schema. Consumers cannot tell "not computed" from "zero" | S | §5.5 **[v]** |
| A10 | **Consider warning on an unknown `@verb`** | `@flow`, `@flows` typos, `@migitates` — all currently silent. The three-tier diagnostic system (error / prose-like warning / silence) has no tier for "this looks like a GuardLink verb but is not one". A Levenshtein-1 check against `KNOWN_VERBS` would catch every case in this report | M | §5.3 **[v]** |
| A11 | **Give `guardlink-mcp` a `--help` and `--version`** | The bin was fixed in T8 and still cannot introduce itself | S | §2.1 |
| A12 | **Export the 4 orphaned feature modules, or stop shipping their barrels** | `artifacts`, `review`, `entitlements`, `workspace/link` have full public interfaces, JSDoc, and no export path. `src/dashboard/index.ts` is a barrel exported from nowhere. Either add subpaths or mark them internal | M | §3.4 |
| A13 | **Reorder `"types"` before `"import"` in all 7 export blocks** | Works today by fallback; fragile | S | §3.1 |

### Workstream B — documentation is wrong

| # | Item | Why now | Effort | Evidence |
|---|---|---|---|---|
| B1 | **Rewrite the README's annotation grammar section against the parser** | 🚨 The highest-traffic, most-copied documentation in the project, and 8 of 20 example lines do not work. `@flow`, `@boundary <->`, `@audit … by … on …`, `@validates … on … using …`, `@owns … by …`, `@shield … requires …` are all wrong in two places each (prose block + table). `guardlink gal` already contains the correct text for every one of them — this is largely a copy job | M | §5.4, §8.1 **[v]** |
| B2 | **Add a README-example test** | `tests/readme.test.ts` already exists (335 lines, added in T6). Extend it to extract every fenced annotation example from README.md and run it through `parseLine`, failing on any diagnostic. This is the only durable fix for B1 — the same class of error has now recurred across releases | M | — |
| B3 | **Delete `guardlink scan` from the README; fix `diff --from/--to` in 4 places** | `scan` has never existed. `--from`/`--to` appear in README:183, README:322, `examples/github-action.yml:49`, `examples/ci/per-repo-report.yml:65` — the last two are copy-paste CI templates users will actually run | S | §8.1, §8.5 **[v]** |
| B4 | **Write the CHANGELOG entries for the 14 undocumented commits and cut `[1.5.0]`** | Pairs with A1. `guardlink ci` is a whole new command with a JSON schema and no entry anywhere | M | §7.2 |
| B5 | **Add the 7 missing commands to the README's Commands table** | `ci`, `migrate`, `reanchor`, `artifacts`, `feature`, `tui`, `gal`. Three of them are the headline features of the largest theme in this release | S | §8.1 |
| B6 | **Update the README's MCP Tools table: 12 → 24; fix the resource list** | `guardlink://config` does not exist; `guardlink://unmitigated` does and is unlisted. Also fix the stale "18 tools" comment at `src/mcp/server.ts:182` | S | §4, §8.1 **[v]** |
| B7 | **Fix the README's Supported Agents table** | `.cursorrules` → `.cursor/rules/guardlink.mdc`; delete the three per-agent `mcp.json` promises — `init` writes exactly one root `.mcp.json` | S | §8.1 **[v]** |
| B8 | **Fix `generateSarif(model, '.')` in the Library API block** | A documented call that does not type-check | S | §8.1 **[v]** |
| B9 | **Refresh the README's self-stats and the sample `status` output** | 272/12/13/10 → 442/16/15/12; the two-column sample output has never matched `printStatus`. Consider generating both from the model, as CLAUDE.md's block already is | S | §8.1 **[v]** |
| B10 | **Link `docs/GUARDLINK_REFERENCE.md` from the README and complete it** | It is the doc `init` copies into every consumer repo, and the README does not mention it once. Add the 6 missing commands and the 18 missing MCP tools | M | §7.1 |
| B11 | **Regenerate `docs/examples/`** | `threat-model.md` says "Threat Model Report — unknown" — the sample output showcases a bug that was fixed. `threat-dashboard.html` shows two sections T2 removed | S | §7.1 **[v]** |
| B12 | **Update `docs/WORKSPACE.md`** | 3 releases stale; missing `--remove`, report metadata, `REPORT_SCHEMA_VERSION` | M | §7.1 |
| B13 | **Document the 8 environment variables and the `.guardlink/config.json` schema** | Neither appears in README or `--help`. §6 of this report is a starting draft | S | §2.5, §6.3 |
| B14 | **Add JSDoc to the 10 undocumented public symbols** | The list is the six most likely entry points plus four helpers | S | §3.5 |
| B15 | **Add build/test/lint commands to CLAUDE.md/AGENTS.md** | The instruction files agents read every turn do not say how to build the project | S | §7.4 |
| B16 | **Fix `config set`'s 5-key usage message** | `src/cli/index.ts:1894` omits `redact-evidence` | S | §8.2 |
| B17 | **Reconcile `init --mode external` vs `annotate --mode inline`** | Opposite defaults, neither help text acknowledging the other. Likely intentional; say so | S | §8.2 |

### Sequencing

`A1 → B4` unblock the release. `A2` should be a same-day fix regardless of everything else — it is the only entry on either list that produces a failure in a running agent session. `B1 + B2` together are the highest-value documentation work, because B2 is what stops B1 from being needed again. Everything else is parallelisable.

---

## 10. Revision history

| Revision | Date | Base commit | Notes |
|---|---|---|---|
| 2 | 2026-08-12 | `55d8111` + uncommitted 1.5.0 surface-freeze worktree | **Corrections, not new analysis.** Two Revision 1 claims about the project-name hardcodes were re-tested by running the built binary and found **false**: §2.3's "`sync` writes a different project name into the agent files than `status` prints" (synced files are byte-identical across two different configured names) and §6.2's framing of the same for `entitle` (the proposal ledger has no project field at all). Both sections corrected in place with the fixture and evidence; the underlying hardcodes are real and A7 still stands, but on code-consistency grounds rather than on an output difference. No other Revision 1 finding was retested or changed. Readers should treat §2.3 and §6.2 as the only revised sections. |
| 1 | 2026-08-12 | `55d81110efcba609dbcf35bab613b54fe940c95a` (origin/main, clean tree) | Initial analysis. Delta vs `v1.4.5` (`ca0a219`): 115 commits, 180 files, +34,366/−3,931. Verified against a fresh `npm run build`; 936 tests passing. Ledger: 167 rows — 102 OK, 29 MISSING, 26 WRONG, 7 ABSENT, 3 INERT, 0 STUB. 1 dead CLI flag, 5 dead config keys, all 7 package exports resolve (runtime + types), no agent config file references a non-existent tool or command — but four of them carry a `guardlink entitle --propose` example that does not run. |
