# Guardlink — Project Instructions

<!-- guardlink:begin -->
## GuardLink — Security Annotations (Required)

This project uses [GuardLink](https://guardlink.bugb.io) annotations in source code comments.
**Full reference: `docs/GUARDLINK_REFERENCE.md`**

### Core Requirement

**Every time you write or modify code that touches security-relevant behavior, you MUST add GuardLink annotations in the same change.** This includes: new endpoints, authentication/authorization logic, data validation, database queries, file I/O, external API calls, crypto operations, process spawning, user input handling, and configuration parsing. Do NOT annotate pure business logic, formatting utilities, UI components, or helper functions that never touch security boundaries.

### Key Rules

1. **Annotate new code.** When you add a function, endpoint, or module that handles user input, accesses data, crosses a trust boundary, or could fail in a security-relevant way — add `@exposes`, `@mitigates`, `@flows`, `@handles`, or at minimum `@comment` annotations. This is not optional.
2. **NEVER write `@accepts`.** That is a human-only governance decision. When you find a risk with no mitigation in code, write `@exposes` to document the risk + `@audit` to flag it for human review + `@comment` to suggest potential controls.
3. Do not delete or mangle existing annotations. Treat them as part of the code. Edit only when intentionally changing the threat model.
4. Definitions (`@asset`, `@threat`, `@control` with `(#id)`) live in `.guardlink/definitions.ts`. Reuse existing `#id`s — never redefine. If you need a new asset or threat, add the definition there first, then reference it in source files.
5. Source files use relationship verbs only: `@mitigates`, `@exposes`, `@flows`, `@handles`, `@boundary`, `@comment`, `@validates`, `@audit`, `@owns`, `@assumes`, `@transfers`.
6. Write coupled annotation blocks that tell a complete story: risk + control (or audit) + data flow + context note. Never write a lone `@exposes` without follow-up.
7. Avoid `@shield` unless a human explicitly asks to hide code from AI — it creates blind spots.

### Workflow (while coding)

- Before writing code: skim `.guardlink/definitions.ts` to understand existing assets, threats, and controls.
- While writing code: add annotations above or in the doc-block of security-relevant functions as you write them — not as a separate pass afterward.
- After changes: run `guardlink validate .` to catch syntax/dangling refs; run `guardlink status .` to check coverage; commit annotation updates with the code.
- After adding annotations: run `guardlink sync` to update all agent instruction files with the current threat model context. This ensures every agent sees the latest assets, threats, controls, and open exposures.

### Tools

- MCP tools (when available, e.g., Claude Code): `guardlink_lookup`, `guardlink_validate`, `guardlink_status`, `guardlink_parse`, `guardlink_suggest <file>`.
- CLI equivalents (always available): `guardlink validate .`, `guardlink status .`, `guardlink parse .`.

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
@owns security-team for App.API -- "Team responsible for reviews"
@comment -- "Rate limit: 100 req/15min via express-rate-limit"
```

## Live Threat Model Context (auto-synced by `guardlink sync`)

### Current Definitions (REUSE these IDs — do NOT redefine)

**Assets:** #parser (GuardLink,Parser), #cli (GuardLink,CLI), #tui (GuardLink,TUI), #mcp (GuardLink,MCP), #llm-client (GuardLink,LLM_Client), #dashboard (GuardLink,Dashboard), #init (GuardLink,Init), #agent-launcher (GuardLink,Agent_Launcher), #diff (GuardLink,Diff), #report (GuardLink,Report), #sarif (GuardLink,SARIF), #suggest (GuardLink,Suggest)
**Threats:** #path-traversal (Path_Traversal) [high], #cmd-injection (Command_Injection) [critical], #xss (Cross_Site_Scripting) [high], #api-key-exposure (API_Key_Exposure) [high], #ssrf (Server_Side_Request_Forgery) [medium], #redos (ReDoS) [medium], #arbitrary-write (Arbitrary_File_Write) [high], #prompt-injection (Prompt_Injection) [medium], #dos (Denial_of_Service) [medium], #data-exposure (Sensitive_Data_Exposure) [medium], #insecure-deser (Insecure_Deserialization) [medium], #child-proc-injection (Child_Process_Injection) [high], #info-disclosure (Information_Disclosure) [low]
**Controls:** #path-validation (Path_Validation), #input-sanitize (Input_Sanitization), #output-encoding (Output_Encoding), #key-redaction (Key_Redaction), #process-sandbox (Process_Sandboxing), #config-validation (Config_Validation), #resource-limits (Resource_Limits), #param-commands (Parameterized_Commands), #glob-filtering (Glob_Pattern_Filtering), #regex-anchoring (Regex_Anchoring)

### Open Exposures (need @mitigates or @audit)

- #agent-launcher exposed to #prompt-injection [medium] (src/agents/launcher.ts:13)
- #agent-launcher exposed to #dos [low] (src/agents/launcher.ts:15)
- #agent-launcher exposed to #prompt-injection [high] (src/agents/prompts.ts:6)
- #llm-client exposed to #data-exposure [low] (src/analyze/index.ts:12)
- #llm-client exposed to #prompt-injection [medium] (src/analyze/llm.ts:17)
- #sarif exposed to #data-exposure [low] (src/analyzer/sarif.ts:15)
- #cli exposed to #cmd-injection [critical] (src/cli/index.ts:29)
- #init exposed to #data-exposure [low] (src/init/index.ts:12)
- #mcp exposed to #cmd-injection [high] (src/mcp/index.ts:4)
- #mcp exposed to #prompt-injection [medium] (src/mcp/server.ts:29)
- #mcp exposed to #data-exposure [medium] (src/mcp/server.ts:33)
- #suggest exposed to #dos [low] (src/mcp/suggest.ts:16)
- #parser exposed to #arbitrary-write [high] (src/parser/clear.ts:7)
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
- ThreatModel -> #agent-launcher via model
- #agent-launcher -> AgentPrompt via return
- ThreatModel -> #llm-client via serializeModel
- ProjectFiles -> #llm-client via readFileSync
- #llm-client -> ReportFile via writeFileSync
- LLMConfig -> #llm-client via chatCompletion
- #llm-client -> LLMProvider via fetch
- LLMProvider -> #llm-client via response
- LLMToolCall -> #llm-client via createToolExecutor
- #llm-client -> NVD via fetch
- ProjectFiles -> #llm-client via readFileSync
- ThreatModel -> #sarif via generateSarif
- #sarif -> SarifLog via return
- ... and 42 more

### Model Stats

272 annotations, 12 assets, 13 threats, 10 controls, 60 exposures, 42 mitigations, 62 flows

> **Note:** This section is auto-generated. Run `guardlink sync` to update after code changes.
> Any coding agent (Cursor, Claude, Copilot, Windsurf, etc.) should reference these IDs
> and continue annotating new code using the same threat model vocabulary.

<!-- guardlink:end -->











