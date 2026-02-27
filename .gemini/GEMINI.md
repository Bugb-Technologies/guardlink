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

**Assets:** #parser (GuardLink,Parser), #cli (GuardLink,CLI), #tui (GuardLink,TUI), #mcp (GuardLink,MCP), #llm-client (GuardLink,LLM_Client), #dashboard (GuardLink,Dashboard), #init (GuardLink,Init), #agent-launcher (GuardLink,Agent_Launcher), #diff (GuardLink,Diff), #report (GuardLink,Report), #sarif (GuardLink,SARIF), #suggest (GuardLink,Suggest), #auth (Server,Auth)
**Threats:** #path-traversal (Path_Traversal) [high], #cmd-injection (Command_Injection) [critical], #xss (Cross_Site_Scripting) [high], #api-key-exposure (API_Key_Exposure) [high], #ssrf (Server_Side_Request_Forgery) [medium], #redos (ReDoS) [medium], #arbitrary-write (Arbitrary_File_Write) [high], #prompt-injection (Prompt_Injection) [medium], #dos (Denial_of_Service) [medium], #data-exposure (Sensitive_Data_Exposure) [medium], #insecure-deser (Insecure_Deserialization) [medium], #child-proc-injection (Child_Process_Injection) [high], #info-disclosure (Information_Disclosure) [low], #sqli (SQL_Injection) [critical]
**Controls:** #path-validation (Path_Validation), #input-sanitize (Input_Sanitization), #output-encoding (Output_Encoding), #key-redaction (Key_Redaction), #process-sandbox (Process_Sandboxing), #config-validation (Config_Validation), #resource-limits (Resource_Limits), #param-commands (Parameterized_Commands), #glob-filtering (Glob_Pattern_Filtering), #regex-anchoring (Regex_Anchoring), #prepared-stmts (Prepared_Statements)

### Open Exposures (need @mitigates or @audit)

- #ai-endpoint exposed to #prompt-injection [high] (src/agents/prompts.ts:247)
- #sarif exposed to #info-disclosure [low] (src/analyzer/sarif.ts:15)
- #llm-client exposed to #prompt-injection [medium] (src/analyze/index.ts:9)
- #llm-client exposed to #prompt-injection [medium] (src/analyze/llm.ts:15)
- #cli exposed to #arbitrary-write [high] (src/cli/index.ts:24)
- #mcp exposed to #path-traversal [high] (src/mcp/server.ts:25)
- #mcp exposed to #prompt-injection [medium] (src/mcp/server.ts:26)
- #mcp exposed to #arbitrary-write [high] (src/mcp/server.ts:27)
- #mcp exposed to #data-exposure [medium] (src/mcp/server.ts:28)
- #suggest exposed to #prompt-injection [medium] (src/mcp/suggest.ts:13)
- #report exposed to #info-disclosure [low] (src/report/report.ts:7)
- #tui exposed to #prompt-injection [medium] (src/tui/index.ts:10)

### Existing Data Flows (extend, don't duplicate)

- #cli -> #agent-launcher via launchAgent
- #agent-launcher -> External_Process via spawnSync
- User_Input -> #auth-api via POST./login
- #auth-api -> #user-db via TypeORM.findOne
- User_Browser -> #api-gateway via HTTPS
- #api-gateway -> #auth-service via internal.gRPC
- #auth-service -> #user-db via pg.query
- #auth-service -> #session-store via redis.set
- #auth-service -> User_Browser via Set-Cookie
- req.body.username -> db.query via string-concat
- #parser -> #sarif via ThreatModel
- #sarif -> External_Security_Tools via SARIF_JSON
- #parser -> #llm-client via ThreatModel
- #llm-client -> Filesystem via writeFileSync
- #llm-client -> External_LLM_APIs via fetch
- External_LLM_APIs -> #llm-client via response
- External_LLM_APIs -> #llm-tools via tool_call
- #llm-tools -> External_LLM_APIs via tool_result
- User -> #cli via argv
- #cli -> #parser via parseProject
- ... and 20 more

### Model Stats

193 annotations, 13 assets, 14 threats, 11 controls, 35 exposures, 21 mitigations, 40 flows

> **Note:** This section is auto-generated. Run `guardlink sync` to update after code changes.
> Any coding agent (Cursor, Claude, Copilot, Windsurf, etc.) should reference these IDs
> and continue annotating new code using the same threat model vocabulary.

<!-- guardlink:end -->
