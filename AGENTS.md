# Guardlink — Project Instructions

<!-- guardlink:begin -->
## GuardLink — Security Model

This project carries a [GuardLink](https://guardlink.bugb.io) threat model: security facts
recorded next to the code they describe — what each component is exposed to, what mitigates
it, how data flows between components — parsed into something you can query.

**Ask it instead of inferring security context from the source.** It already answers most of
what you would otherwise guess at, and it records decisions that are invisible in the code,
such as which risks a human has explicitly accepted.

| You are about to… | Ask |
|---|---|
| edit a file | `guardlink_context(file)` — annotations there, the assets they name, open exposures, controls the file must uphold |
| change a shared component | `guardlink_graph(from, depth, direction)` — blast radius across data flows and trust boundaries |
| act on a scanner finding | `guardlink_lookup("cwe:CWE-89")` — is this weakness class declared, and is it mitigated, accepted, open or confirmed |
| finish a change | `guardlink validate .` then `guardlink diff HEAD~1` — did I make this worse |

Without MCP, the same answers come from `guardlink status .`, `guardlink parse .`
(the whole model as JSON on stdout) and `guardlink diff HEAD~1`.

**Full reference: `docs/GUARDLINK_REFERENCE.md`**

### Where annotations go

**Annotation mode: `inline`. Annotations live in source-file comments**, in the comment
syntax of the file you are editing — the doc-block of the function or module they describe.

```ts
/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "parameterized via pg"
 */
export function login(email: string) { … }
```

Do not create `.gal` sidecars under `.guardlink/annotations/` in this mode; a repo with
both is a mixed repo, and that is the failure this section exists to prevent.

### What you owe it back

**When you write or change code that touches security-relevant behavior, add the annotations in
the same change.** This includes: new endpoints, authentication/authorization logic, data validation, database queries, file I/O, external API calls, crypto operations, process spawning, user input handling, and configuration parsing. Do NOT annotate pure business logic, formatting utilities, UI components, or helper functions that never touch security boundaries.

### Key Rules

1. **Annotate new code.** When you add a function, endpoint, or module that handles user input, accesses data, crosses a trust boundary, or could fail in a security-relevant way — add `@exposes`, `@mitigates`, `@flows`, `@handles`, or at minimum `@comment` annotations. This is not optional.
2. **NEVER write `@accepts`.** That is a human-only governance decision. When you find a risk with no mitigation in code, write `@exposes` to document the risk + `@audit` to flag it for human review + `@comment` to suggest potential controls.
3. **Use `@confirmed` for verified exploits.** When a pentest, CXG scan, or manual reproduction proves a threat is exploitable, mark it with `@confirmed #threat on Asset [severity] -- "evidence"`. This is distinct from `@exposes` (theoretical) — `@confirmed` means real, verified, not a false positive. Include severity based on actual observed impact.
4. Do not delete or mangle existing annotations. Treat them as part of the code. Edit only when intentionally changing the threat model.
5. Definitions (`@asset`, `@threat`, `@control` with `(#id)`) live in `.guardlink/definitions.ts`. Reuse existing `#id`s — never redefine. If you need a new asset or threat, add the definition there first, then reference it in source files.
6. Source files use relationship verbs only: `@mitigates`, `@exposes`, `@confirmed`, `@flows`, `@handles`, `@boundary`, `@comment`, `@validates`, `@audit`, `@owns`, `@assumes`, `@transfers`, `@feature`. (`@actor` is a definition — it belongs in the definitions file with `@asset`/`@threat`/`@control`. `@entitles` is proposed, not written — see rule 9.)
7. Write coupled annotation blocks that tell a complete story: risk + control (or audit) + data flow + context note. Never write a lone `@exposes` without follow-up.
8. Avoid `@shield` unless a human explicitly asks to hide code from AI — it creates blind spots.
9. **NEVER write `@entitles` into source — propose it.** `@entitles` says a privilege is *supposed* to have this effect, so an over-grant closes a real privilege escalation as by-design. That makes it the second claim you may not make on a human's behalf, alongside `@accepts`. File it with `guardlink entitle --propose` (or `guardlink_entitlement_propose`) and a human's acceptance is what writes the annotation, under their name; an `@entitles` in source with no accepted proposal is a validation error. The rationale must cite the authz code as `file:line` or the claim is inert — parsed and then ignored. It never suppresses a finding and never gates testing; it only changes what triage recommends. Never propose one for an ownership question (IDOR, tenant isolation) — both peers hold the capability, so it cannot say whose object it was. When unsure which role the code actually requires, write `@comment` describing what you saw instead: under-granting costs noise, over-granting hides a real bug.

### Workflow (while coding)

- **Opening a file:** `guardlink_context(file)` before you read far into it. Note which kind of empty an empty answer is — `scanned_without_annotations` means clean, `not_scanned` means the parser never read it. They are not the same.
- **Before writing:** skim `.guardlink/definitions.ts` for the existing assets, threats and controls. Reuse those ids.
- **While writing:** annotate as you go, not as a pass afterward — in the doc-block of the code you are writing.
- **After changing:** `guardlink diff HEAD~1` — the one command that answers "did I add exposure". Then `guardlink validate .` for syntax and dangling refs, and `guardlink status .` for coverage.
- **After annotating:** `guardlink sync` refreshes this block and `.guardlink/README.md` from the current model.

### Tools

- **MCP** (Claude Code, Cursor): `guardlink_context`, `guardlink_graph`, `guardlink_lookup`, `guardlink_diff`, `guardlink_validate`, `guardlink_status`, `guardlink_suggest`.
- **CLI** (always): `guardlink status .`, `guardlink parse .`, `guardlink validate .`, `guardlink diff HEAD~1`, `guardlink report .`.
- `guardlink_lookup` answers a fixed set of named forms and **refuses anything else rather than
  guessing** — send it a bad query to get the list. Beyond `asset`/`threat`/`control`, it reaches
  every relation the model holds: `owner of X`, `handles pii`, `assumptions for X`, `audits for X`,
  `validations for X`, `acceptances`, `transfers`, `comments for X`, `shields`, `cross-repo refs`,
  and `cwe:CWE-89` / `owasp:A03` for scanner findings.
- Reference matches report `matched_via: exact | alias | substring`. A substring match is a
  suggestion, not an identification; `ambiguous` with `candidates` means several records tied.

### Quick Syntax (common verbs)

```
@exposes App.API to #sqli [P0] cwe:CWE-89 -- "req.body.email concatenated into SQL"
@mitigates App.API against #sqli using #prepared-stmts -- "Parameterized queries via pg"
@audit App.API -- "Timing attack risk — needs human review to assess bcrypt constant-time comparison"
@flows User -> App.API via HTTPS -- "Login request path"
@boundary between #api and #db (#data-boundary) -- "App → DB trust change"
@handles pii on App.API -- "Processes email and session token"
@validates #prepared-stmts for App.API -- "sqlInjectionTest.ts ensures placeholders used"
@audit App.API -- "Token rotation logic needs crypto review"
@confirmed #sqli on App.API [critical] cwe:CWE-89 -- "Pentest verified: raw SQL injection via email param"
@feature "SSO Login" -- "Single sign-on authentication flow"
@owns security-team for App.API -- "Team responsible for reviews"
@actor Namespace_Admin (#ns-admin) -- "Administers one namespace's configuration"   (definitions file)
@comment -- "Rate limit: 100 req/15min via express-rate-limit"
```

`@entitles` is absent from that list on purpose — you propose it, you do not write it:

```bash
guardlink entitle --propose --actor '#ns-admin' --capability configure-archival-destination \
  --asset '#archival-fs' --rationale "By design: the archival URI is namespace configuration. Authz: common/api/metadata.go:189"
```

## Live Threat Model Context (auto-synced by `guardlink sync`)

### Current Definitions (REUSE these IDs — do NOT redefine)

_Full records with descriptions and locations: `guardlink_lookup("asset <id>")`, or read `.guardlink/definitions.*`._

**Assets:** #parser (GuardLink,Parser), #cli (GuardLink,CLI), #tui (GuardLink,TUI), #mcp (GuardLink,MCP), #llm-client (GuardLink,LLM_Client), #dashboard (GuardLink,Dashboard), #init (GuardLink,Init), #agent-launcher (GuardLink,Agent_Launcher), #diff (GuardLink,Diff), #report (GuardLink,Report), #sarif (GuardLink,SARIF), #suggest (GuardLink,Suggest), #workspace-link (Workspace,Link), #merge-engine (Workspace,Merge), #report-metadata (Workspace,Metadata), #workspace-config (Workspace,Config)
**Threats:** #path-traversal (Path_Traversal) [high], #cmd-injection (Command_Injection) [critical], #xss (Cross_Site_Scripting) [high], #api-key-exposure (API_Key_Exposure) [high], #ssrf (Server_Side_Request_Forgery) [medium], #redos (ReDoS) [medium], #arbitrary-write (Arbitrary_File_Write) [high], #prompt-injection (Prompt_Injection) [medium], #dos (Denial_of_Service) [medium], #data-exposure (Sensitive_Data_Exposure) [medium], #insecure-deser (Insecure_Deserialization) [medium], #child-proc-injection (Child_Process_Injection) [high], #info-disclosure (Information_Disclosure) [low], #tag-collision (Tag_Collision) [medium], #config-tamper (Config_Tampering) [medium]
**Controls:** #path-validation (Path_Validation), #input-sanitize (Input_Sanitization), #output-encoding (Output_Encoding), #key-redaction (Key_Redaction), #process-sandbox (Process_Sandboxing), #config-validation (Config_Validation), #resource-limits (Resource_Limits), #param-commands (Parameterized_Commands), #glob-filtering (Glob_Pattern_Filtering), #regex-anchoring (Regex_Anchoring), #prefix-ownership (Prefix_Ownership), #yaml-validation (YAML_Validation)
**Actors:** #local-dev (Local_Developer), #mcp-agent (MCP_Agent), #ci-runner (CI_Runner)

### Entitlements (capabilities held by design — never a reason to skip testing)

- #mcp-agent entitled to `read_threat_model` on #mcp — cites src/mcp/index.ts:23

### Open Exposures (need @mitigates or @audit)

- #agent-launcher exposed to #prompt-injection [medium] (src/agents/launcher.ts:13)
- #agent-launcher exposed to #dos [low] (src/agents/launcher.ts:15)
- #agent-launcher exposed to #prompt-injection [high] (src/agents/prompts.ts:6)
- #agent-launcher exposed to #config-tamper [medium] (src/agents/prompts.ts:10)
- #llm-client exposed to #data-exposure [low] (src/analyze/index.ts:12)
- #llm-client exposed to #prompt-injection [medium] (src/analyze/llm.ts:17)
- #sarif exposed to #data-exposure [low] (src/analyzer/sarif.ts:24)
- #init exposed to #data-exposure [low] (src/init/index.ts:12)
- #mcp exposed to #cmd-injection [high] (src/mcp/index.ts:6)
- #mcp exposed to #prompt-injection [medium] (src/mcp/server.ts:36)
- #mcp exposed to #data-exposure [medium] (src/mcp/server.ts:40)
- #suggest exposed to #dos [low] (src/mcp/suggest.ts:16)
- #parser exposed to #data-exposure [low] (src/parser/migrate-mode.ts:26)
- #tui exposed to #cmd-injection [high] (src/tui/commands.ts:11)
- #tui exposed to #prompt-injection [medium] (src/tui/commands.ts:15)

### Existing Data Flows (extend, don't duplicate)

- EnvVars -> #agent-launcher via process.env
- ConfigFile -> #agent-launcher via readFileSync
- #agent-launcher -> ConfigFile via writeFileSync
- UserPrompt -> #agent-launcher via launchAgent
- #agent-launcher -> AgentProcess via spawn
- AgentProcess -> #agent-launcher via stdout
- UserPrompt -> #agent-launcher via buildAnnotatePrompt
- UserPrompt -> #agent-launcher via buildTranslatePrompt
- UserPrompt -> #agent-launcher via buildAskPrompt
- ThreatModel -> #agent-launcher via model
- #agent-launcher -> AgentPrompt via return
- ThreatModel -> #llm-client via serializeModel
- ProjectFiles -> #llm-client via readFileSync
- #llm-client -> ReportFile via writeFileSync
- PentestFindings -> #llm-client via readFileSync
- LLMConfig -> #llm-client via chatCompletion
- #llm-client -> LLMProvider via fetch
- LLMProvider -> #llm-client via response
- LLMToolCall -> #llm-client via createToolExecutor
- #llm-client -> NVD via fetch
- … and 87 more — `guardlink_lookup("flows into X")` for one asset, or `guardlink_graph(from: X)` for a neighbourhood

### Features (filter with `--feature`)

- "Dashboard"
- "MCP Integration"

### Model Stats

442 annotations, 16 assets, 15 threats, 12 controls, 80 exposures, 0 confirmed, 68 mitigations, 3 actors, 1 entitlements, 107 flows, 2 features

### Block Freshness

- `annotation_hash`: `sha256-v2:66c22c9b8df9d397dee561e4597a2996a988710083661a591990844e6133ff9f`

Every MCP response carries this same hash. If it differs from the one above, this
block predates the current annotations — trust the tool, and run `guardlink sync`.
For when it was synced and at which commit, read the envelope on any MCP
response: those move independently of the model and are not written to disk.

> **Note:** This section is auto-generated. Run `guardlink sync` to update after code changes.
> Any coding agent (Cursor, Claude, Copilot, Windsurf, etc.) should reference these IDs
> and continue annotating new code using the same threat model vocabulary.

<!-- guardlink:end -->
