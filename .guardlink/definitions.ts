// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GuardLink Shared Definitions — guardlink
//
// ALL @asset, @threat, and @control declarations live here.
// Source files reference by #id only (e.g. @mitigates #parser against #path-traversal).
// Never redeclare an ID that exists in this file.
// Before adding: read this file to check for duplicates.
//
// Run: guardlink validate .
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ─── ASSETS ───────────────────────────────────────────────────────────
// Components that process data, handle user input, or interact with external systems

// @asset GuardLink.Parser (#parser) -- "Reads source files from disk, extracts security annotations using regex patterns"
// @asset GuardLink.CLI (#cli) -- "Command-line interface, handles user arguments, invokes subcommands"
// @asset GuardLink.TUI (#tui) -- "Interactive terminal interface with readline input and command dispatch"
// @asset GuardLink.MCP (#mcp) -- "Model Context Protocol server, accepts tool calls from AI agents over stdio"
// @asset GuardLink.LLM_Client (#llm-client) -- "Makes HTTP requests to external AI providers (Anthropic, OpenAI, DeepSeek, OpenRouter)"
// @asset GuardLink.Dashboard (#dashboard) -- "Generates interactive HTML threat model dashboard from ThreatModel data"
// @asset GuardLink.Init (#init) -- "Initializes projects, writes config files and agent instruction files to disk"
// @asset GuardLink.Agent_Launcher (#agent-launcher) -- "Spawns child processes for AI coding agents (Claude Code, Cursor, Codex)"
// @asset GuardLink.Diff (#diff) -- "Compares threat models across git commits, invokes git commands"
// @asset GuardLink.Report (#report) -- "Generates markdown threat model reports with Mermaid diagrams"
// @asset GuardLink.SARIF (#sarif) -- "Exports findings as SARIF 2.1.0 JSON for security tooling"
// @asset GuardLink.Suggest (#suggest) -- "Analyzes code patterns to suggest appropriate security annotations"

// ─── THREATS ──────────────────────────────────────────────────────────
// Security threats that can impact the application

// @threat Path_Traversal (#path-traversal) [high] cwe:CWE-22 -- "File read/write operations outside intended project directory via ../ sequences or absolute paths"
// @threat Command_Injection (#cmd-injection) [critical] cwe:CWE-78 -- "Shell command execution with unsanitized user input"
// @threat Cross_Site_Scripting (#xss) [high] cwe:CWE-79 -- "Injection of malicious scripts into generated HTML output"
// @threat API_Key_Exposure (#api-key-exposure) [high] cwe:CWE-798 -- "API keys leaked in logs, error messages, or unintended output"
// @threat Server_Side_Request_Forgery (#ssrf) [medium] cwe:CWE-918 -- "LLM API requests to attacker-controlled URLs via config override"
// @threat ReDoS (#redos) [medium] cwe:CWE-1333 -- "Regular expression denial of service from crafted annotation content"
// @threat Arbitrary_File_Write (#arbitrary-write) [high] cwe:CWE-73 -- "Writing files to attacker-controlled paths outside project"
// @threat Prompt_Injection (#prompt-injection) [medium] cwe:CWE-77 -- "Malicious content in annotations injected into LLM prompts"
// @threat Denial_of_Service (#dos) [medium] cwe:CWE-400 -- "Resource exhaustion from processing large files or deep directory trees"
// @threat Sensitive_Data_Exposure (#data-exposure) [medium] cwe:CWE-200 -- "Threat model details exposed to unauthorized parties"
// @threat Insecure_Deserialization (#insecure-deser) [medium] cwe:CWE-502 -- "Unsafe parsing of JSON/YAML configuration files"
// @threat Child_Process_Injection (#child-proc-injection) [high] cwe:CWE-78 -- "Agent launcher executing attacker-controlled commands via process spawn"
// @threat Information_Disclosure (#info-disclosure) [low] cwe:CWE-200 -- "Unintended exposure of internal paths, structure, or implementation details"

// ─── CONTROLS ─────────────────────────────────────────────────────────
// Security controls that mitigate threats

// @control Path_Validation (#path-validation) -- "Validates file paths using resolve() + startsWith() to ensure access within allowed directories"
// @control Input_Sanitization (#input-sanitize) -- "Input validation with anchored regex patterns and length limits"
// @control Output_Encoding (#output-encoding) -- "HTML entity encoding for untrusted data in generated output"
// @control Key_Redaction (#key-redaction) -- "Masking API keys in logs and error messages"
// @control Process_Sandboxing (#process-sandbox) -- "Controlled child process spawning with explicit args array, no shell"
// @control Config_Validation (#config-validation) -- "Schema validation for configuration files before use"
// @control Resource_Limits (#resource-limits) -- "File size limits, recursion depth limits, timeout constraints"
// @control Parameterized_Commands (#param-commands) -- "Using spawn with args array instead of shell string interpolation"
// @control Glob_Pattern_Filtering (#glob-filtering) -- "Filtering files using glob patterns with explicit excludes"
// @control Regex_Anchoring (#regex-anchoring) -- "Using anchored regex patterns (^...$) to prevent backtracking"
