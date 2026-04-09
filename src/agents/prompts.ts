/**
 * GuardLink Agents — Prompt builders for annotation and analysis.
 *
 * Extracted from tui/commands.ts for shared use across CLI, TUI, MCP.
 *
 * @exposes #agent-launcher to #prompt-injection [high] cwe:CWE-77 -- "User prompt concatenated into agent instruction text"
 * @audit #agent-launcher -- "Prompt injection mitigated by agent's own safety measures; GuardLink prompt is read-only context"
 * @exposes #agent-launcher to #path-traversal [medium] cwe:CWE-22 -- "Reads reference docs from root-relative paths"
 * @mitigates #agent-launcher against #path-traversal using #path-validation -- "resolve() with root constrains file access"
 * @exposes #agent-launcher to #config-tamper [medium] cwe:CWE-15 -- "Translate prompt may read CXG reference paths from environment overrides"
 * @audit #agent-launcher -- "Environment override paths are optional convenience; verify trusted local paths in CI"
 * @flows UserPrompt -> #agent-launcher via buildAnnotatePrompt -- "User instruction input"
 * @flows UserPrompt -> #agent-launcher via buildTranslatePrompt -- "Template translation instruction input"
 * @flows UserPrompt -> #agent-launcher via buildAskPrompt -- "Threat model question input"
 * @flows ThreatModel -> #agent-launcher via model -- "Model context injection"
 * @flows #agent-launcher -> AgentPrompt via return -- "Assembled prompt output"
 * @handles internal on #agent-launcher -- "Serializes threat model IDs and flows into prompt"
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ThreatModel } from '../types/index.js';

const DEFAULT_CXG_ROOT = '/Users/shahidhakim/Downloads/cert-x-gen-fix-template-update-url-migration-and-cli';
const DEFAULT_CXG_SKELETON_DIR = '/Users/shahidhakim/Downloads/cert-x-gen-fix-template-update-url-migration-and-cli/cert-x-gen-templates-main/templates/skeleton';

function readIfExists(path: string, maxChars = 5000): string {
  if (!existsSync(path)) return '';
  try {
    return readFileSync(path, 'utf-8').slice(0, maxChars);
  } catch {
    return '';
  }
}

/**
 * Build a prompt for annotation agents.
 *
 * Includes the GuardLink reference doc, current model summary with flows and exposures,
 * flow-first threat modeling methodology, and precise GAL syntax rules.
 */
export function buildAnnotatePrompt(
  userPrompt: string,
  root: string,
  model: ThreatModel | null,
): string {
  // Read the reference doc if available
  let refDoc = '';
  const refPath = resolve(root, '.guardlink', 'GUARDLINK_REFERENCE.md');
  if (existsSync(refPath)) {
    refDoc = readFileSync(refPath, 'utf-8');
  }
  // Fall back to docs/GUARDLINK_REFERENCE.md
  if (!refDoc) {
    const docsRefPath = resolve(root, 'docs', 'GUARDLINK_REFERENCE.md');
    if (existsSync(docsRefPath)) {
      refDoc = readFileSync(docsRefPath, 'utf-8');
    }
  }

  let modelSummary = 'No threat model parsed yet. This may be a fresh project — define assets, threats, and controls first.';
  let existingIds = '';
  let existingFlows = '';
  let existingExposures = '';
  if (model) {
    const parts = [
      `${model.annotations_parsed} annotations`,
      `${model.exposures.length} exposures`,
      ...((model.confirmed || []).length > 0 ? [`${model.confirmed.length} confirmed exploitable`] : []),
      `${model.assets.length} assets`,
      `${model.threats.length} threats`,
      `${model.controls.length} controls`,
      `${model.mitigations.length} mitigations`,
      `${model.flows.length} flows`,
      `${model.boundaries.length} boundaries`,
    ];
    modelSummary = `Current model: ${parts.join(', ')}.`;

    // Include existing IDs so the agent doesn't create duplicates or dangling refs
    const threatIds = model.threats.filter(t => t.id).map(t => `#${t.id}`);
    const assetIds = model.assets.filter(a => a.id).map(a => `#${a.id}`);
    const controlIds = model.controls.filter(c => c.id).map(c => `#${c.id}`);
    if (threatIds.length + assetIds.length + controlIds.length > 0) {
      const sections: string[] = [];
      if (assetIds.length) sections.push(`Assets: ${assetIds.join(', ')}`);
      if (threatIds.length) sections.push(`Threats: ${threatIds.join(', ')}`);
      if (controlIds.length) sections.push(`Controls: ${controlIds.join(', ')}`);
      existingIds = `\n\nExisting defined IDs (REUSE these — do NOT redefine):\n${sections.join('\n')}`;
    }

    // Include existing flows so agent understands the current flow graph
    if (model.flows.length > 0) {
      const flowLines = model.flows.slice(0, 30).map(f =>
        `  ${f.source} -> ${f.target}${f.mechanism ? ` via ${f.mechanism}` : ''} (${f.location.file}:${f.location.line})`
      );
      existingFlows = `\n\nExisting data flows (extend these, don't duplicate):\n${flowLines.join('\n')}`;
      if (model.flows.length > 30) existingFlows += `\n  ... and ${model.flows.length - 30} more`;
    }

    // Include unmitigated exposures so agent knows what still needs attention
    // NOTE: Do NOT filter out @accepts — agents should see ALL exposures without real mitigations
    const unmitigatedExposures = model.exposures.filter(e => {
      return !model.mitigations.some(m => m.asset === e.asset && m.threat === e.threat);
    });
    if (unmitigatedExposures.length > 0) {
      const expLines = unmitigatedExposures.slice(0, 20).map(e =>
        `  ${e.asset} exposed to ${e.threat} [${e.severity || 'unrated'}] (${e.location.file}:${e.location.line})`
      );
      existingExposures = `\n\nOpen exposures (no mitigation in code — add @mitigates if a control exists, or @audit to flag for human review):\n${expLines.join('\n')}`;
      if (unmitigatedExposures.length > 20) existingExposures += `\n  ... and ${unmitigatedExposures.length - 20} more`;
    }
  }

  return `You are an expert security engineer performing threat modeling as code.
Your job is to read this codebase deeply, understand how code flows between components, and annotate it with GuardLink (GAL) security annotations that accurately represent the security posture.

This is NOT a vulnerability scanner. You are building a living threat model embedded in the code itself.
Annotations capture what COULD go wrong, what controls exist, and how data moves — not just confirmed bugs.

${refDoc ? '## GuardLink Annotation Language Reference\n\n' + refDoc.slice(0, 4000) + '\n\n' : ''}## Current State
${modelSummary}${existingIds}${existingFlows}${existingExposures}

## Your Task
${userPrompt}

## HOW TO THINK — Flow-First Threat Modeling

Before writing ANY annotation, you MUST understand the code deeply:

### Step 1: Map the Architecture
Read ALL source files related to the area you're annotating. Trace:
- Entry points (HTTP handlers, CLI commands, message consumers, event listeners)
- Data paths (how user input flows through functions, classes, middleware, to storage or output)
- Exit points (database writes, API calls, file I/O, rendered templates, responses)
- Class hierarchies, inherited methods, shared utilities, middleware chains
- Configuration and environment variable usage

### Step 2: Identify Trust Boundaries
Look for where trust changes:
- External user → application code (HTTP boundary)
- Application → database (data layer boundary)
- Service → service (network boundary)
- Frontend → backend (client/server boundary)
- Application → third-party API (vendor boundary)
- Internal code → spawned process (process boundary)

### Step 3: Identify What Could Go Wrong
At each boundary crossing and data transformation, ask:
- What if this input is malicious? (@exposes)
- What validation/sanitization exists? (@mitigates)
- What sensitive data passes through here? (@handles)
- Is there an assumption that could be violated? (@assumes)
- Does this need human security review? (@audit)
- Is this risk handled by someone else? (@transfers)

### Step 4: Write Coupled Annotation Blocks
NEVER write a single annotation in isolation. Every annotated location should tell a complete story.

## ANNOTATION STYLE GUIDE — Write Like a Developer

### Always Couple Annotations Together
A file's doc-block should paint the full security picture of that module. Group annotations logically:

\`\`\`
// @shield:begin -- "Example annotation block for reference, excluded from parsing"
//
// GOOD — Complete story at a single code location:
// @exposes #auth-api to #sqli [P1] cwe:CWE-89 -- "User-supplied email passed to findUser() query builder"
// @mitigates #auth-api against #sqli using #input-validation -- "Zod schema validates email format before query"
// @flows User_Input -> #auth-api via POST./login -- "Login form submits credentials"
// @flows #auth-api -> #user-db via TypeORM.findOne -- "Authenticated user lookup"
// @handles pii on #auth-api -- "Processes email, password, session tokens"
// @comment -- "Password comparison uses bcrypt.compare with timing-safe equality"
//
// BAD — Isolated annotation with no context:
// @exposes #auth-api to #sqli -- "SQL injection possible"
//
// @shield:end
\`\`\`

### Description Style — Reference Actual Code
Descriptions must reference the real code: function names, variable names, libraries, mechanisms.

\`\`\`
// @shield:begin -- "Description examples, excluded from parsing"
//
// GOOD: -- "req.body.token passed to jwt.verify() without audience check"
// GOOD: -- "bcrypt rounds set to 12 via BCRYPT_COST env var"
// GOOD: -- "Rate limiter uses express-rate-limit at 100req/15min on /api/*"
//
// BAD:  -- "Input not validated"             (too vague — WHICH input? WHERE?)
// BAD:  -- "Uses encryption"                 (WHAT encryption? On WHAT data?)
// BAD:  -- "Security vulnerability exists"   (meaningless — be specific)
//
// @shield:end
\`\`\`

### @flows — Stitch the Complete Data Path
@flows is the backbone of the threat model. Trace data movement accurately:

\`\`\`
// @shield:begin -- "Flow examples, excluded from parsing"
//
// Trace a request through the full stack:
// @flows User_Browser -> #api-gateway via HTTPS -- "Client sends auth request"
// @flows #api-gateway -> #auth-service via internal.gRPC -- "Gateway forwards to auth microservice"
// @flows #auth-service -> #user-db via pg.query -- "Looks up user record by email"
// @flows #auth-service -> #session-store via redis.set -- "Stores session token with TTL"
// @flows #auth-service -> User_Browser via Set-Cookie -- "Returns session cookie to client"
//
// @shield:end
\`\`\`

### @boundary — Mark Every Trust Zone Crossing
Place @boundary annotations where trust level changes between two components:

\`\`\`
// @shield:begin -- "Boundary examples, excluded from parsing"
//
// @boundary between #api-gateway and External_Internet (#public-boundary) -- "TLS termination, rate limiting at edge"
// @boundary between #backend and #database (#data-boundary) -- "Application to persistence layer, connection pooling via pgBouncer"
// @boundary between #app and #payment-provider (#vendor-boundary) -- "PCI-DSS scope boundary, tokenized card data only"
//
// @shield:end
\`\`\`

### Where to Place Annotations
Annotations go in the file's top doc-block comment OR directly above the security-relevant code:

\`\`\`
// @shield:begin -- "Placement examples, excluded from parsing"
//
// FILE-LEVEL (top doc-block) — for module-wide security properties:
// Place @exposes, @mitigates, @flows, @handles, @boundary that describe the module as a whole
//
// INLINE (above specific functions/methods) — for function-specific concerns:
// Place @exposes, @mitigates above the exact function where the risk or control lives
// Place @comment above tricky security-relevant code to explain intent
//
// @shield:end
\`\`\`

### Severity — Be Honest, Not Alarmist
Annotations capture what COULD go wrong, calibrated to realistic risk:
- **[P0] / [critical]**: Directly exploitable by external attacker, severe impact (RCE, auth bypass, data breach)
- **[P1] / [high]**: Exploitable with some conditions, significant impact (privilege escalation, data leak)
- **[P2] / [medium]**: Requires specific conditions or insider access (SSRF, info disclosure)
- **[P3] / [low]**: Minor impact or very difficult to exploit (timing side-channels, verbose errors)

Don't rate everything P0. A SQL injection in an admin-only internal tool is different from one in a public API.

### @comment — Always Add Context
Every annotation block should include at least one @comment explaining non-obvious security decisions, assumptions, or context that helps future developers (and AI tools) understand the "why".

### @accepts — NEVER USE (Human-Only Decision)
@accepts marks a risk as intentionally unmitigated. This is a **human-only governance decision** — it requires conscious risk ownership by a person or team.
As an AI agent, you MUST NEVER write @accepts annotations. You cannot accept risk on behalf of humans.

Instead, when you find an exposure with no mitigation in the code:
1. Write the @exposes annotation to document the risk
2. Add @audit to flag it for human security review
3. Add @comment explaining what controls COULD be added
4. Optionally add @assumes to document any assumptions the code makes

Example — what to do when no mitigation exists:
\`\`\`
// @shield:begin -- "@accepts alternative examples, excluded from parsing"
//
// WRONG (AI rubber-stamping risk):
// @accepts #prompt-injection on #ai-endpoint -- "Relying on model safety filters"
//
// RIGHT (flag for human review):
// @exposes #ai-endpoint to #prompt-injection [P1] cwe:CWE-77 -- "User prompt passed directly to LLM API without sanitization"
// @audit #ai-endpoint -- "No prompt sanitization — needs human review to decide: add input filter or accept risk"
// @comment -- "Potential controls: #prompt-filter (input sanitization), #output-validator (response filtering)"
//
// @shield:end
\`\`\`

Leaving exposures unmitigated is HONEST. The dashboard and reports will surface them as open risks for humans to triage.

### Pentest-Confirmable vs Governance-Only Gaps
When documenting threats, distinguish between:
1. **Pentest-confirmable findings**: testable with concrete I/O behavior (e.g., injection, auth bypass, IDOR, exposed service, unsafe deserialization). Document the risk with @exposes (hypothesis). After a pentest, CXG scan, or manual reproduction **proves** exploitability with evidence, add @confirmed #threat on Asset [severity] -- "evidence summary" — never use @confirmed for guesses or scanner noise without verification.
2. **Governance/design gaps**: important risks that are not directly testable as a penetration test template (e.g., missing ownership process, policy-only controls, broad architectural assumptions with no direct exploit path).

For governance/design gaps:
- Do NOT force a fake exploit-style exposure.
- Add @audit on the relevant asset with precise reasoning.
- Add @comment suggesting concrete controls or follow-up review tasks.

### @shield — DO NOT USE Unless Explicitly Asked
@shield and @shield:begin/@shield:end block AI coding assistants from reading the annotated code.
This means any shielded code becomes invisible to AI tools — they cannot analyze, refactor, or annotate it.
Do NOT add @shield annotations unless the user has EXPLICITLY requested it (e.g., "shield the crypto module").
Adding @shield on your own initiative would actively harm the threat model by creating blind spots where AI cannot help.

## PRECISE GAL Syntax

Definitions go in .guardlink/definitions.{ts,js,py,rs}. Source files use only relationship verbs.

### Definitions (in .guardlink/definitions file)
\`\`\`
// @shield:begin -- "Definition syntax examples, excluded from parsing"
// @asset Server.Auth (#auth) -- "Authentication service handling login and session management"
// @threat SQL_Injection (#sqli) [P0] cwe:CWE-89 -- "Unsanitized input reaches SQL query builder"
// @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries via ORM or driver placeholders"
// @shield:end
\`\`\`

### Relationships (in source files)
\`\`\`
// @shield:begin -- "Relationship syntax examples, excluded from parsing"
// @exposes #auth to #sqli [P0] cwe:CWE-89 owasp:A03:2021 -- "User input concatenated into query"
// @confirmed #sqli on #auth [critical] cwe:CWE-89 -- "Pentest 2026-04: time-based blind SQLi on /login confirmed"
// @mitigates #auth against #sqli using #prepared-stmts -- "Uses parameterized queries via sqlx"
// @audit #auth -- "Timing attack risk — needs human review to decide if bcrypt constant-time comparison is sufficient"
// @transfers #ddos from #api to #cdn -- "Cloudflare handles L7 DDoS mitigation"
// @flows req.body.username -> db.query via string-concat -- "User input flows to SQL"
// @boundary between #frontend and #api (#web-boundary) -- "TLS-terminated public/private boundary"
// @handles pii on #auth -- "Processes email, password, session tokens"
// @validates #prepared-stmts for #auth -- "Integration test sqlInjectionTest.ts confirms parameterized queries block SQLi payloads"
// @audit #auth -- "Session token rotation logic needs cryptographic review"
// @assumes #auth -- "Upstream API gateway has already validated TLS and rate-limited requests"
// @owns security-team for #auth -- "Security team reviews all auth PRs"
// @feature "SSO Login" -- "Single sign-on authentication flow"
// @comment -- "Password hashing uses bcrypt with cost factor 12, migration from SHA256 completed in v2.1"
// @shield:end
\`\`\`

## CRITICAL SYNTAX RULES (violations cause parse errors)

1. **@boundary requires TWO assets**: \`@boundary between #A and #B\` or \`@boundary #A | #B\`.
   WRONG: \`@boundary api -- "desc"\`  (only one argument — will NOT parse)
   RIGHT: \`@boundary between #api and #client (#api-boundary) -- "Trust boundary"\`

2. **@flows is ONE source -> ONE target per line**: \`@flows <source> -> <target> via <mechanism>\`.
   WRONG: \`@flows A -> B, C -> D -- "desc"\`  (commas not supported)
   RIGHT: \`@flows A -> B via mechanism -- "desc"\` (one per line, repeat for multiple)

3. **@exposes / @mitigates require DEFINED #id refs**: Every \`#id\` you reference must exist as a definition.
   Before using \`@exposes #app to #sqli\`, ensure \`@threat SQL_Injection (#sqli)\` exists in definitions.
   Add new definitions to the .guardlink/definitions file FIRST, then reference them in source files.

4. **Severity in square brackets**: \`[P0]\` \`[P1]\` \`[P2]\` \`[P3]\` or \`[critical]\` \`[high]\` \`[medium]\` \`[low]\`.
   Goes AFTER the threat ref in @exposes: \`@exposes #app to #sqli [P0] cwe:CWE-89\`
   On @confirmed, severity is optional but recommended — it reflects **verified** impact: \`@confirmed #sqli on #app [critical] -- "evidence"\`

5. **Descriptions in double quotes after --**: \`-- "description text here"\`
   WRONG: \`@comment "just a note"\` or \`@comment -- note without quotes\`
   RIGHT: \`@comment -- "security-relevant developer note"\`

6. **IDs use parentheses in definitions, hash in references**:
   Definition: \`@threat SQL_Injection (#sqli)\`
   Reference:  \`@exposes #app to #sqli\`

7. **Asset references**: Use \`#id\` or \`Dotted.Path\` (e.g., \`Server.Auth\`, \`req.body.input\`).
   Names with spaces or special chars will NOT parse.

8. **External refs are space-separated after severity**: \`cwe:CWE-89 owasp:A03:2021 capec:CAPEC-66\`

9. **@comment always needs -- and quotes**: \`@comment -- "your note here"\`.
   A bare \`@comment\` without description is valid but useless. Always include context.

10. **One annotation per comment line.** Do NOT put two @verbs on the same line.

## Workflow

1. **Read first, annotate second.** Read ALL related source files before writing any annotation.
   Trace the full call chain: entry point → middleware → handler → service → repository → database.
   Understand class hierarchies, shared utilities, and configuration.

2. **Read existing definitions** in the .guardlink/definitions file — reuse existing IDs, never duplicate.

3. **Add NEW definitions FIRST** if you need new assets, threats, or controls.
   Group related definitions together with section comments.

4. **Annotate in coupled blocks.** For each security-relevant location, write the complete story:
   @exposes + @mitigates (or @audit if no mitigation exists) + @flows + @comment at minimum.
   Think: "what's the risk, what's the defense, how does data flow here, and what should the next developer know?"
   NEVER write @accepts — that is a human-only governance decision. Use @audit to flag unmitigated risks for review.

5. **Use the project's comment style** (// for JS/TS/Go/Rust, # for Python/Ruby/Shell, etc.)

6. **Generate project description.** If \`.guardlink/prompt.md\` exists and contains only the skeleton template
   (HTML comments / placeholder headings with no real content), fill it in based on what you learned while
   reading the codebase. Write a security-focused project overview covering:
   - What the application does and who its users are
   - Key components and services
   - Trust boundaries (where trust changes between components)
   - Data sensitivity (PII, credentials, financial data, etc.)
   - Deployment context (cloud, containers, CI/CD, etc.)
   This file feeds into \`guardlink report\` as the Application Overview section.
   **Do NOT overwrite user-written content** — only fill in the template placeholders.

7. **Run validation** via guardlink_validate (MCP) or \`guardlink validate\` to check for errors.

8. **Fix any validation errors** before finishing — especially dangling refs and malformed syntax.
`;
}

/**
 * Build a prompt for translating GuardLink threat model findings into
 * CERT-X-GEN (CXG) pentest templates.
 */
export function buildTranslatePrompt(
  userPrompt: string,
  root: string,
  model: ThreatModel | null,
): string {
  const cxgRoot = process.env.GUARDLINK_CXG_ROOT || DEFAULT_CXG_ROOT;
  const skeletonDir = process.env.GUARDLINK_CXG_SKELETON_DIR || DEFAULT_CXG_SKELETON_DIR;

  const templateGuide = readIfExists(resolve(cxgRoot, 'cert-x-gen-templates-main', 'docs', 'TEMPLATE_GUIDE.md'), 4000);
  const promptEngine = readIfExists(resolve(cxgRoot, 'src', 'ai', 'prompt.rs'), 4000);
  const yamlSkeleton = readIfExists(resolve(skeletonDir, 'yaml-template-skeleton.yaml'), 5000);
  const pythonSkeleton = readIfExists(resolve(skeletonDir, 'python-template-skeleton.py'), 3000);

  let modelSummary = 'No threat model parsed yet.';
  let candidateExposures = '';
  if (model) {
    const unmitigated = model.exposures.filter((e) =>
      !model.mitigations.some((m) => m.asset === e.asset && m.threat === e.threat)
    );

    modelSummary = `Current model: ${model.annotations_parsed} annotations, ${model.exposures.length} exposures, ${(model.confirmed || []).length} confirmed, ${unmitigated.length} unmitigated exposures, ${model.assets.length} assets, ${model.threats.length} threats.`;
    if (unmitigated.length > 0) {
      const lines = unmitigated.slice(0, 40).map((e) =>
        `- ${e.asset} -> ${e.threat} [${e.severity || 'unrated'}] (${e.location.file}:${e.location.line})`
      );
      candidateExposures = `\n\nUnmitigated exposure candidates:\n${lines.join('\n')}`;
      if (unmitigated.length > 40) {
        candidateExposures += `\n- ... and ${unmitigated.length - 40} more`;
      }
    }
  }

  const instruction = userPrompt.trim()
    ? userPrompt.trim()
    : 'Generate CXG pentest templates for all pentest-confirmable high/critical threats first, then medium.';

  return `You are a senior offensive security engineer translating GuardLink threat-model findings into CERT-X-GEN (CXG) templates.

## Mission
Convert pentest-confirmable threats into runnable CXG templates. Do NOT execute templates. Only author template files.

## Current Threat Model
${modelSummary}${candidateExposures}

## User Request
${instruction}

## Required CXG CLI Discovery (Do This First)
Before generating final user guidance, discover the actual CLI usage on this machine:
1. Try: \`cxg --help\`
2. Try: \`cxg scan --help\`
3. Try: \`cxg template --help\`
4. If \`cxg\` is not in PATH, try local binary from source checkout (if present):
   - \`${cxgRoot}/target/release/cxg --help\`
   - \`${cxgRoot}/target/release/cxg scan --help\`
   - \`${cxgRoot}/target/release/cxg template --help\`
5. Base user instructions on the commands that actually work. If none work, clearly state the blocker and provide install/build steps first.

## Required Decision Rule (Critical)
For every candidate threat/exposure:
1. Decide if it is **pentest-confirmable** — meaning it can be validated via:
   - Network request/response behavior (HTTP, TCP, etc.)
   - Local CLI invocation with crafted inputs (command injection, path traversal, etc.)
   - File system operations (symlink attacks, arbitrary writes, config tampering)
   - MCP/stdio protocol interactions (JSON-RPC tool calls with malicious payloads)
   - Process spawning behavior (canary file creation, shell metacharacter interpretation)
2. If yes: create one or more CXG templates. For local CLI/codebase threats, templates should use \`subprocess.run()\` or \`subprocess.Popen()\` with \`cwd=target\` to invoke the tool under test.
3. If no (pure governance/process/design gap): do NOT create a template. Instead document it as audit-only guidance:
   - Include suggested GuardLink @audit text and @comment text for the relevant asset/file.
   - Explain briefly why no pentest template is appropriate.

## Output and File Operations
1. Create templates under: \`.guardlink/cxg-templates/\`
2. Use meaningful filenames like:
   - \`.guardlink/cxg-templates/<threat-id-or-name>.yaml\`
   - or language variants \`.py\`, \`.js\`, \`.go\`, etc. if needed.
3. Write an index file at \`.guardlink/cxg-templates/README.md\` with:
   - generated templates list
   - mapping: GuardLink threat/exposure -> template file(s)
   - "audit-only / no-template" items with suggested @audit annotations
4. CXG scan output goes to: \`.guardlink/pentest-findings/\` (this is where \`guardlink dashboard\` and \`guardlink threat-report\` read pentest results from). Always tell users to output to this path.
5. Do NOT run CXG CLI or execute generated templates.
6. Keep checks non-destructive.
7. You MAY run \`cxg --help\` and other help/listing commands only for usage discovery. Do not run active scans unless user explicitly asks.

## CXG Format Contract (from source)
Use the project skeleton contract and examples; mirror field names and structure exactly.

${templateGuide ? `### TEMPLATE_GUIDE excerpt\n${templateGuide}\n` : ''}
${promptEngine ? `### prompt.rs excerpt\n${promptEngine}\n` : ''}
${yamlSkeleton ? `### YAML skeleton excerpt\n${yamlSkeleton}\n` : ''}
${pythonSkeleton ? `### Python skeleton excerpt\n${pythonSkeleton}\n` : ''}

## Quality Bar
- Each template must include clear metadata: id/name/author/severity/description/tags/references.
- Detection logic must align to the threat and include concrete matchers/assertions.
- Prefer YAML templates for declarative checks; use code templates where procedural logic is required.
- Avoid placeholder TODO logic.
- Keep template logic scoped to the specific threat confirmation.

## CXG Engine Contract (Critical — templates MUST follow this)
When CXG runs a Python template, it does NOT pass the target as a CLI argument.
Instead, it sets environment variables and expects JSON on stdout.

### Target resolution (in main / entry point):
\`\`\`python
target = os.environ.get("CERT_X_GEN_PROJECT_ROOT") or args.target or os.environ.get("CERT_X_GEN_TARGET_HOST")
\`\`\`
- \`CERT_X_GEN_PROJECT_ROOT\`: set for local codebase/CLI targets (absolute path).
- \`CERT_X_GEN_TARGET_HOST\`: set for network targets (hostname/IP).
- The positional \`target\` arg MUST use \`nargs="?"\` (optional) since CXG engine passes no argv.

### Output contract:
- When \`CERT_X_GEN_MODE == "engine"\` (always true under CXG), print ONLY a JSON array to stdout.
- Output \`[]\` (empty array) when no findings — never print plain text in engine mode.
- Use: \`print(json.dumps(findings, indent=2))\`

### Environment variables available:
| Variable | Value |
|----------|-------|
| \`CERT_X_GEN_MODE\` | Always \`"engine"\` |
| \`CERT_X_GEN_TARGET_HOST\` | Target address (path for local, hostname for network) |
| \`CERT_X_GEN_TARGET_TYPE\` | \`"local"\` or \`"network"\` |
| \`CERT_X_GEN_PROJECT_ROOT\` | Absolute path (local targets only) |
| \`CERT_X_GEN_TARGET_PORT\` | Port number (network targets, default 80) |

### Running templates with CXG local scope:
\`\`\`bash
cxg scan --scope local://. --template-dir .guardlink/cxg-templates/ --output .guardlink/pentest-findings/guardlink-pentest --output-format json,sarif,html
\`\`\`

## CXG Evidence Contract (Critical — findings MUST include rich evidence)
CXG parses finding evidence using specific field names. If these fields are missing or empty,
the output report will show blank evidence — making findings impossible to verify.

### Required evidence structure in every finding dict:
\`\`\`python
"evidence": {
    "request": "<string: what was sent — payload, RPC call, CLI args, env vars, etc.>",
    "response": "<string: what came back — stdout, stderr, HTTP response, RPC response, etc.>",
    "matched_patterns": ["<string>", ...],  # list of STRINGS (not dicts) — e.g. CWE IDs, indicators found, regex matches
    "data": {  # arbitrary key-value map for all raw evidence details
        "key1": "<string value>",
        "key2": "<string value>",
        ...
    }
}
\`\`\`

### Rules for populating evidence:
1. **\`request\`**: MUST contain the exact input that triggered the finding. Examples:
   - For CLI injection: the full command with payload (e.g., \`npx guardlink annotate "; touch /tmp/canary"\`)
   - For MCP tests: the JSON-RPC request body sent to the tool
   - For path traversal: the malicious path used (e.g., \`../../etc/passwd\`)
   - For config tamper: the environment variable name and injected value

2. **\`response\`**: MUST contain the raw output that proves the vulnerability. Examples:
   - stdout/stderr excerpt from the command execution (up to 2000 chars)
   - The MCP JSON-RPC response content
   - File contents read from an unexpected location
   - Error messages that reveal injection

3. **\`matched_patterns\`**: MUST be a list of **strings** (CXG drops non-strings). Include:
   - Shell error indicators found (e.g., "sh: command not found")
   - Sensitive data patterns matched (e.g., "absolute_paths: 5 found")
   - CWE/OWASP identifiers relevant to the finding
   - Canary strings that proved exploitation

4. **\`data\`**: Store ALL evidence key-value pairs here. All values must be strings
   (use \`json.dumps()\` to serialize complex objects). This is the catch-all for:
   - \`canary_created\`: "true"
   - \`exit_code\`: "0"
   - \`symlink_path\`: "/path/to/symlink"
   - \`traversal_root\`: "/etc"
   - \`env_var\`: "GUARDLINK_CXG_ROOT"

### Helper pattern for \`create_finding\`:
Always use a centralized helper that maps your raw evidence dict into the CXG structure:

\`\`\`python
def create_finding(self, title, description, evidence):
    return {
        "template_id": self.id,
        "title": title,
        "severity": self.severity,
        "confidence": self.confidence,
        "description": description,
        "evidence": {
            "request": evidence.get("request") or evidence.get("payload") or evidence.get("rpc_request") or
                       json.dumps({k: v for k, v in evidence.items()
                                   if k not in ("response", "stdout_excerpt", "stderr_excerpt",
                                                "output_excerpt", "response_snippet", "matched_patterns")}, default=str),
            "response": evidence.get("response") or evidence.get("stdout_excerpt") or
                        evidence.get("stderr_excerpt") or evidence.get("output_excerpt") or
                        evidence.get("response_snippet") or evidence.get("content_snippet") or "",
            "matched_patterns": [p if isinstance(p, str) else
                                 (f"{p.get('type','')}: {p.get('count','?')}" if isinstance(p, dict) else str(p))
                                 for p in (evidence.get("matched_patterns") or [])],
            "data": {k: (v if isinstance(v, str) else json.dumps(v, default=str))
                     for k, v in evidence.items()},
        },
        "cwe": self.cwe,
        "tags": self.tags,
        "remediation": "...",
    }
\`\`\`

### What to capture as evidence for each template type:
| Template type | request | response | matched_patterns |
|---|---|---|---|
| CLI injection | Full CLI command with payload | stdout + stderr (first 2000 chars) | Shell indicators, canary proof |
| MCP tool call | JSON-RPC request body | JSON-RPC response body | Sensitive data types found |
| Path traversal | Traversal path used | File/dir content from outside project | Path indicators (/etc, /tmp) |
| Config tamper | Env var name + injected value | Command output with canary | Canary string match |
| Prompt injection | Injected prompt text | LLM/agent output text | Injection markers found |
| Arbitrary write | Symlink/path payload | guardlink clear output showing external files | External paths listed |

### NEVER do this:
- Do NOT pass raw evidence dicts without the CXG structure — CXG will show empty evidence fields.
- Do NOT put dicts or lists in \`matched_patterns\` — CXG drops non-string entries silently.
- Do NOT skip evidence collection — a finding without evidence is unverifiable.

## Python Template Boilerplate (MUST use this structure)
Every Python template you create MUST follow this exact \`main()\` structure:

\`\`\`python
def main():
    parser = argparse.ArgumentParser(description="...")
    parser.add_argument("target", nargs="?", help="Project root or target host")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    template = CertXGenTemplate()
    target = os.environ.get("CERT_X_GEN_PROJECT_ROOT") or args.target or os.environ.get("CERT_X_GEN_TARGET_HOST")
    if not target:
        parser.error("target is required (positional, CERT_X_GEN_PROJECT_ROOT, or CERT_X_GEN_TARGET_HOST)")

    findings = template.execute(target, args.port)
    if args.json or os.environ.get("CERT_X_GEN_MODE") == "engine":
        print(json.dumps(findings, indent=2))
    elif findings:
        for f in findings:
            print(f"[{f['severity'].upper()}] {f['title']}")
            print(f"  {f['description']}")
            print()
    else:
        print("No findings detected.")

if __name__ == "__main__":
    main()
\`\`\`

Key rules:
- \`target\` positional arg uses \`nargs="?"\` — CXG engine does NOT pass target as argv.
- Target resolution order: \`CERT_X_GEN_PROJECT_ROOT\` > \`args.target\` > \`CERT_X_GEN_TARGET_HOST\`.
- When \`CERT_X_GEN_MODE == "engine"\`, ALWAYS output JSON (even if \`--json\` is not set).
- Output \`[]\` (empty JSON array) when no findings — never plain text in engine mode.
- For local/CLI templates, use \`target\` as \`cwd\` in \`subprocess.run()\` / \`subprocess.Popen()\` calls.

## Final Response Format
After writing files, return:
1. A short "Generated templates" list with file paths.
2. A short "Audit-only (no template)" list with recommended GuardLink @audit/@comment text.
3. A "How to run these templates with CXG" section with these **exact steps**:

   **Step 1 — Prerequisites:**
   \`\`\`bash
   cxg --version          # Verify CXG is installed (expect v1.1.0+)
   python3 --version      # Python 3.8+ required for template execution
   ls .guardlink/cxg-templates/*.py  # Verify templates were created
   \`\`\`

   **Step 2 — Validate templates:**
   \`\`\`bash
   cxg template validate .guardlink/cxg-templates/ --recursive
   \`\`\`

   **Step 3 — Create output directory and run scan using local scope (for CLI/codebase targets):**
   \`\`\`bash
   mkdir -p .guardlink/pentest-findings
   cxg scan \\
     --scope local://. \\
     --template-dir .guardlink/cxg-templates/ \\
     --template-language python \\
     --output .guardlink/pentest-findings/guardlink-pentest \\
     --output-format json,sarif,html
   \`\`\`
   The \`local://.\` scope tells CXG this is a local codebase target. CXG will set
   \`CERT_X_GEN_PROJECT_ROOT\` to the absolute path of the current directory and
   \`CERT_X_GEN_TARGET_TYPE=local\`, so templates receive the correct project root.

   Output is stored in \`.guardlink/pentest-findings/\` so that \`guardlink dashboard\`
   and \`guardlink threat-report\` automatically pick up the results.

   **Step 3b — Run scan using network scope (for HTTP/API targets):**
   \`\`\`bash
   cxg scan \\
     --scope https://api.example.com \\
     --template-dir .guardlink/cxg-templates/ \\
     --output .guardlink/pentest-findings/guardlink-pentest \\
     --output-format json,sarif,html
   \`\`\`

   **Step 4 — Run with verbose output for debugging:**
   \`\`\`bash
   cxg -vv scan \\
     --scope local://. \\
     --template-dir .guardlink/cxg-templates/ \\
     --output .guardlink/pentest-findings/guardlink-pentest \\
     --output-format json,sarif,html
   \`\`\`

   **Step 5 — Run individual templates standalone (without CXG):**
   \`\`\`bash
   python3 .guardlink/cxg-templates/<template-name>.py . --json
   \`\`\`

   **Expected output artifacts (in \`.guardlink/pentest-findings/\`):**
   - \`guardlink-pentest.json\` — JSON with scan_id, findings array, statistics
   - \`guardlink-pentest.sarif\` — SARIF 2.1.0 for GitHub Advanced Security / CI integration
   - \`guardlink-pentest.html\` — Human-readable HTML report
   - Each finding includes: template_id, severity, title, description, evidence (with request, response, matched_patterns, data), remediation
   - **Evidence must be populated** — a finding with empty evidence (null request, null response, empty data) is a template bug
   - These files are automatically consumed by \`guardlink dashboard\` (Pentest Findings tab) and \`guardlink threat-report\` (pentest context)

   **Troubleshooting:**
   | Issue | Fix |
   |---|---|
   | \`target is required\` error | Template is missing \`nargs="?"\` on target arg — engine uses env vars, not argv |
   | \`JSON parse error\` | Template prints non-JSON text to stdout in engine mode — wrap all output in \`json.dumps()\` |
   | \`Operation timed out\` | Template takes >30s; add \`--timeout 60s\` to scan command |
   | All templates show 0 findings | Run with \`-vv\` to check for WARN lines; ensure \`local://.\` scope is used for CLI templates |
   | \`guardlink CLI not found\` | Run \`npm install\` in the project root first |
   | Evidence fields are null/empty | Template is passing raw dict without CXG structure — use the \`create_finding\` helper pattern from the Evidence Contract section |

4. A "What to expect" section that explains:
   - what a positive finding looks like (JSON with template_id, severity, evidence)
   - what a negative/no-finding run means (code is secure against those specific checks)
   - false-positive caveats and manual verification guidance
5. Any assumptions requiring human review.`;
}

/**
 * Build a prompt for answering freeform user questions about the codebase
 * and GuardLink threat model.
 */
export function buildAskPrompt(
  userQuery: string,
  root: string,
  model: ThreatModel | null,
): string {
  let modelSummary = 'No threat model parsed yet.';
  let idSummary = '';
  let exposureSummary = '';
  if (model) {
    modelSummary = `Current model: ${model.annotations_parsed} annotations, ${model.exposures.length} exposures, ${(model.confirmed || []).length} confirmed, ${model.mitigations.length} mitigations, ${model.assets.length} assets, ${model.threats.length} threats, ${model.flows.length} flows.`;

    const assetIds = model.assets.filter(a => a.id).slice(0, 30).map(a => `#${a.id}`);
    const threatIds = model.threats.filter(t => t.id).slice(0, 30).map(t => `#${t.id}`);
    const controlIds = model.controls.filter(c => c.id).slice(0, 30).map(c => `#${c.id}`);
    const idLines: string[] = [];
    if (assetIds.length) idLines.push(`Assets: ${assetIds.join(', ')}`);
    if (threatIds.length) idLines.push(`Threats: ${threatIds.join(', ')}`);
    if (controlIds.length) idLines.push(`Controls: ${controlIds.join(', ')}`);
    if (idLines.length) idSummary = `\n\nKnown IDs:\n${idLines.join('\n')}`;

    const unmitigated = model.exposures.filter((e) =>
      !model.mitigations.some((m) => m.asset === e.asset && m.threat === e.threat)
    );
    if (unmitigated.length > 0) {
      const lines = unmitigated.slice(0, 25).map((e) =>
        `- ${e.asset} -> ${e.threat} [${e.severity || 'unrated'}] (${e.location.file}:${e.location.line})`
      );
      exposureSummary = `\n\nOpen unmitigated exposures:\n${lines.join('\n')}`;
      if (unmitigated.length > 25) {
        exposureSummary += `\n- ... and ${unmitigated.length - 25} more`;
      }
    }
  }

  return `You are a senior AppSec engineer answering questions about a GuardLink-instrumented codebase.

## Project Root
${root}

## Current Threat Model Context
${modelSummary}${idSummary}${exposureSummary}

## User Question
${userQuery}

## Required Method
1. Read relevant source files and configs before answering.
2. Use GuardLink annotations as guidance, but verify with actual code.
3. If the question asks about a specific area (e.g. admin portal, API, auth), trace entry points, data flows, and related threats.
4. If information is missing or ambiguous, say so clearly and list what was checked.
5. Never invent endpoints, threats, or controls.

## Output Format
- Provide a direct answer first.
- Then include concise evidence:
  - files/components examined
  - relevant threats/exposures/controls
  - important gaps or unknowns
- If asked "do we have X threats," include counts and examples with file paths.
`;
}
