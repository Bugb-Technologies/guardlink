/**
 * GuardLink Agents — Prompt builders for annotation and analysis.
 *
 * Extracted from tui/commands.ts for shared use across CLI, TUI, MCP.
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ThreatModel } from '../types/index.js';

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
//
// GOOD — Complete story at a single code location:
//
// BAD — Isolated annotation with no context:
//
\`\`\`

### Description Style — Reference Actual Code
Descriptions must reference the real code: function names, variable names, libraries, mechanisms.

\`\`\`
//
// GOOD: -- "req.body.token passed to jwt.verify() without audience check"
// GOOD: -- "bcrypt rounds set to 12 via BCRYPT_COST env var"
// GOOD: -- "Rate limiter uses express-rate-limit at 100req/15min on /api/*"
//
// BAD:  -- "Input not validated"             (too vague — WHICH input? WHERE?)
// BAD:  -- "Uses encryption"                 (WHAT encryption? On WHAT data?)
// BAD:  -- "Security vulnerability exists"   (meaningless — be specific)
//
\`\`\`

### @flows — Stitch the Complete Data Path
@flows is the backbone of the threat model. Trace data movement accurately:

\`\`\`
//
// Trace a request through the full stack:
//
\`\`\`

### @boundary — Mark Every Trust Zone Crossing
Place @boundary annotations where trust level changes between two components:

\`\`\`
//
//
\`\`\`

### Where to Place Annotations
Annotations go in the file's top doc-block comment OR directly above the security-relevant code:

\`\`\`
//
// FILE-LEVEL (top doc-block) — for module-wide security properties:
// Place @exposes, @mitigates, @flows, @handles, @boundary that describe the module as a whole
//
// INLINE (above specific functions/methods) — for function-specific concerns:
// Place @exposes, @mitigates above the exact function where the risk or control lives
// Place @comment above tricky security-relevant code to explain intent
//
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
//
// WRONG (AI rubber-stamping risk):
//
// RIGHT (flag for human review):
//
\`\`\`

Leaving exposures unmitigated is HONEST. The dashboard and reports will surface them as open risks for humans to triage.

### @shield — DO NOT USE Unless Explicitly Asked
@shield and @shield:begin/@shield:end block AI coding assistants from reading the annotated code.
This means any shielded code becomes invisible to AI tools — they cannot analyze, refactor, or annotate it.
Do NOT add @shield annotations unless the user has EXPLICITLY requested it (e.g., "shield the crypto module").
Adding @shield on your own initiative would actively harm the threat model by creating blind spots where AI cannot help.

## PRECISE GAL Syntax

Definitions go in .guardlink/definitions.{ts,js,py,rs}. Source files use only relationship verbs.

### Definitions (in .guardlink/definitions file)
\`\`\`
\`\`\`

### Relationships (in source files)
\`\`\`
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

6. **Run validation** via guardlink_validate (MCP) or \`guardlink validate\` to check for errors.

7. **Fix any validation errors** before finishing — especially dangling refs and malformed syntax.
`;
}
