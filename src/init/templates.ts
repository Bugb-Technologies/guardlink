/**
 * GuardLink init — Template content for generated files.
 *
 * @exposes #init to #prompt-injection [P1] cwe:CWE-77 -- "[external] buildModelContext() embeds raw threat model data (asset names, descriptions, file paths) into agent instruction files (CLAUDE.md, AGENTS.md); a supply-chain attacker who controls annotation content in a dependency could inject adversarial instructions into AI coding agents"
 * @audit #init -- "threat model data injected into agent files without escaping; attacker controlling a .guardlink/definitions.ts in a dependency could inject instructions into AI agents reading CLAUDE.md — needs human review to decide on escaping strategy vs. intentional passthrough"
 * @flows ThreatModel -> #init via buildModelContext -- "live asset IDs, threat IDs, open exposures, and data flows embedded into agent instruction content"
 * @flows #init -> AgentFile via agentInstructionsWithModel -- "agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules etc.) written with embedded threat model context"
 * @flows ProjectInfo -> #init via definitionsContent -- "project name and comment prefix used to generate definitions file scaffold"
 * @flows ProjectInfo -> #init via configContent -- "project metadata written as JSON via JSON.stringify — injection-safe"
 * @handles internal on #init -- "processes threat model data including asset IDs, threat descriptions, and file paths that are written verbatim into agent files"
 * @comment -- "agentInstructions() generates static template content — no user data; buildModelContext() injects live model data which includes user-defined strings from @comment/@exposes descriptions in source annotations"
 */

import type { ProjectInfo } from './detect.js';
import type { ThreatModel } from '../types/index.js';

// ─── Canonical reference document ────────────────────────────────────

/**
 * docs/GUARDLINK_REFERENCE.md — the single source of truth for annotation syntax.
 * All agent instruction files point here instead of duplicating the full reference.
 */
export function referenceDocContent(project: ProjectInfo): string {
  return `# GuardLink — Annotation Reference

> Canonical reference for **${project.name}**. All agent instruction files point here.
> Full specification: [docs/SPEC.md](https://github.com/Bugb-Technologies/guardlink/blob/main/docs/SPEC.md)

## Quick Reference

\`\`\`
DEFINE   @asset <Component.Path> (#id) -- "description"
         @threat <Name> (#id) [severity] cwe:CWE-NNN -- "description"
         @control <Name> (#id) -- "description"

RELATE   @mitigates <Asset> against <#threat> using <#control> -- "how"
         @exposes <Asset> to <#threat> [severity] cwe:CWE-NNN -- "[origin] what's wrong"
         @accepts <#threat> on <Asset> -- "HUMAN-ONLY — AI agents must use @audit instead"
         @transfers <#threat> from <Source> to <Target> -- "who handles it"

FLOW     @flows <Source> -> <Target> via <mechanism> -- "details"
         @boundary <AssetA> | <AssetB> (#id) -- "trust boundary"
         @boundary between <AssetA> and <AssetB> (#id) -- "trust boundary"

LIFECYCLE
         @validates <#control> for <Asset> -- "test evidence"
         @audit <Asset> -- "what needs review"
         @owns <team-id> for <Asset> -- "responsible team"
         @handles <pii|phi|financial|secrets|internal|public> on <Asset>
         @assumes <Asset> -- "unverified assumption"

COMMENT  @comment -- "security-relevant developer note"

PROTECT  @shield -- "reason"
         @shield:begin -- "reason"   ... code ...   @shield:end
\`\`\`

## Severity

\`[P0]\` = critical, \`[P1]\` = high, \`[P2]\` = medium, \`[P3]\` = low

## Threat Origin (required in @exposes descriptions)

Every \`@exposes\` description MUST start with a threat origin tag:

| Tag | Meaning |
|-----|--------|
| \`[external]\` | Exploitable by unauthenticated external attackers |
| \`[internal]\` | Only exploitable by authenticated users or insiders |
| \`[mixed]\` | Both external and internal exploit paths exist |
| \`[potentially-external]\` | Internal today, but no code-level gate if exposure changes |
| \`[potentially-internal]\` | External-facing, but realistic exploit needs insider knowledge |

Examples:
- \`@exposes #api to #sqli [P0] -- "[external] req.body.email concatenated into SQL"\`
- \`@exposes #admin to #bac [P1] -- "[internal] Admin role check uses client-side flag"\`
- \`@exposes #config to #ssrf [P2] -- "[potentially-external] Internal endpoint accepts URL param — behind VPN, no code-level restriction"\`

## External References

Append after severity: \`cwe:CWE-89\`, \`owasp:A03:2021\`, \`capec:CAPEC-66\`, \`attack:T1190\`

## Rules

1. **Annotate as you code.** When you write or modify security-relevant code (endpoints, auth, data access, validation, I/O, crypto, process spawning), add annotations in the same change. This is required, not optional.
2. **Define once, reference everywhere.** \`@asset\`, \`@threat\`, \`@control\` with \`(#id)\` go in \`.guardlink/definitions${project.definitionsExt}\`. Source files use relationship verbs only (\`@mitigates\`, \`@exposes\`, etc.).
3. **Read definitions before adding.** Check for existing IDs first — avoid duplicates.
4. **Every \`@exposes\` needs a response.** Match with \`@mitigates\` (fix exists) or \`@audit\` (flag for human review). AI agents must NEVER write \`@accepts\` — that is a human-only governance decision. Use \`@audit\` instead.
5. **Classify threat origin.** Every \`@exposes\` description must start with \`[external]\`, \`[internal]\`, \`[mixed]\`, \`[potentially-external]\`, or \`[potentially-internal]\`.
6. **Use the full verb set.** \`@flows\` for data movement, \`@handles\` for data classification, \`@boundary\` for trust boundaries.

## When Writing Code

| Situation | Annotation |
|-----------|------------|
| Writing new endpoint/handler | \`@exposes\` + \`@mitigates\` (or \`@audit\`) + \`@flows\` + \`@comment\` — tell the complete story |
| New service/component | \`@asset\` in definitions, then reference in source |
| Security gap exists | \`@exposes Asset to #threat -- "[origin] description"\` + \`@audit Asset\` |
| Risk with no fix yet | \`@audit Asset\` + \`@comment\` explaining potential controls. NEVER \`@accepts\`. |
| Implementing a fix | \`@mitigates Asset against #threat using #control\` |
| Processing sensitive data | \`@handles pii on Asset\` |
| Proprietary algorithm | \`@shield:begin\` ... \`@shield:end\` |
| Unsure which annotation | \`@comment -- "describe what you see"\` |

## Commands

\`\`\`bash
guardlink validate .          # Check for errors
guardlink report .            # Generate threat-model.md
guardlink status .            # Coverage summary
guardlink suggest <file>      # Get annotation suggestions
\`\`\`

## MCP Tools

When connected via \`.mcp.json\`, use:
- \`guardlink_parse\` — parse annotations, return threat model
- \`guardlink_lookup\` — query threats, controls, exposures by ID
- \`guardlink_suggest\` — get annotation suggestions for a file
- \`guardlink_validate\` — check for syntax errors
- \`guardlink_status\` — coverage stats
`;
}

// ─── Agent instruction content (compact — points to reference doc) ───

/**
 * Compact GuardLink instruction block injected into agent files.
 * Points to docs/GUARDLINK_REFERENCE.md for full syntax.
 */
export function agentInstructions(project: ProjectInfo): string {
  return `
## GuardLink — Security Annotations (Required)

This project uses [GuardLink](https://guardlink.bugb.io) annotations in source code comments.
**Full reference: \`docs/GUARDLINK_REFERENCE.md\`**

### Core Requirement

**Every time you write or modify code that touches security-relevant behavior, you MUST add GuardLink annotations in the same change.** This includes: new endpoints, authentication/authorization logic, data validation, database queries, file I/O, external API calls, crypto operations, process spawning, user input handling, and configuration parsing. Do NOT annotate pure business logic, formatting utilities, UI components, or helper functions that never touch security boundaries.

### Key Rules

1. **Annotate new code.** When you add a function, endpoint, or module that handles user input, accesses data, crosses a trust boundary, or could fail in a security-relevant way — add \`@exposes\`, \`@mitigates\`, \`@flows\`, \`@handles\`, or at minimum \`@comment\` annotations. This is not optional.
2. **NEVER write \`@accepts\`.** That is a human-only governance decision. When you find a risk with no mitigation in code, write \`@exposes\` to document the risk + \`@audit\` to flag it for human review + \`@comment\` to suggest potential controls.
3. **Classify threat origin in every \`@exposes\` description.** Start the \`--\` description with one of: \`[external]\`, \`[internal]\`, \`[mixed]\`, \`[potentially-external]\`, \`[potentially-internal]\` to indicate who can trigger the threat. This is critical for triage — a \`[critical]\` internal-only finding is fundamentally different from an \`[external]\` one.
4. Do not delete or mangle existing annotations. Treat them as part of the code. Edit only when intentionally changing the threat model.
5. Definitions (\`@asset\`, \`@threat\`, \`@control\` with \`(#id)\`) live in \`.guardlink/definitions${project.definitionsExt}\`. Reuse existing \`#id\`s — never redefine. If you need a new asset or threat, add the definition there first, then reference it in source files.
6. Source files use relationship verbs only: \`@mitigates\`, \`@exposes\`, \`@flows\`, \`@handles\`, \`@boundary\`, \`@comment\`, \`@validates\`, \`@audit\`, \`@owns\`, \`@assumes\`, \`@transfers\`.
7. Write coupled annotation blocks that tell a complete story: risk + control (or audit) + data flow + context note. Never write a lone \`@exposes\` without follow-up.
8. Avoid \`@shield\` unless a human explicitly asks to hide code from AI — it creates blind spots.

### Workflow (while coding)

- Before writing code: skim \`.guardlink/definitions${project.definitionsExt}\` to understand existing assets, threats, and controls.
- While writing code: add annotations above or in the doc-block of security-relevant functions as you write them — not as a separate pass afterward.
- After changes: run \`guardlink validate .\` to catch syntax/dangling refs; run \`guardlink status .\` to check coverage; commit annotation updates with the code.
- After adding annotations: run \`guardlink sync\` to update all agent instruction files with the current threat model context. This ensures every agent sees the latest assets, threats, controls, and open exposures.

### Tools

- MCP tools (when available, e.g., Claude Code): \`guardlink_lookup\`, \`guardlink_validate\`, \`guardlink_status\`, \`guardlink_parse\`, \`guardlink_suggest <file>\`.
- CLI equivalents (always available): \`guardlink validate .\`, \`guardlink status .\`, \`guardlink parse .\`.

### Quick Syntax (common verbs)

\`\`\`
@exposes App.API to #sqli [P0] cwe:CWE-89 -- "[external] req.body.email concatenated into SQL"
@mitigates App.API against #sqli using #prepared-stmts -- "Parameterized queries via pg"
@audit App.API -- "Timing attack risk — needs human review to assess bcrypt constant-time comparison"
@flows User -> App.API via HTTPS -- "Login request path"
@boundary between #api and #db (#data-boundary) -- "App → DB trust change"
@handles pii on App.API -- "Processes email, token"
@validates #prepared-stmts for App.API -- "CI test ensures placeholders"
@audit App.API -- "Token rotation review"
@owns security-team for App.API -- "Team responsible"
@comment -- "Rate limit: 100 req/15min"
\`\`\`
`.trimStart();
}

// ─── Model-aware instruction block (for sync) ──────────────────────

/**
 * Build a threat model context section that gets embedded into agent instructions.
 * Contains real asset/threat/control IDs, open exposures, and existing flows
 * so any coding agent knows the current security posture.
 */
export function buildModelContext(model: ThreatModel): string {
  const sections: string[] = [];

  // Existing defined IDs
  const assetIds = model.assets.filter(a => a.id).map(a => `#${a.id} (${a.path})`);
  const threatIds = model.threats.filter(t => t.id).map(t => `#${t.id} (${t.name})${t.severity ? ` [${t.severity}]` : ''}`);
  const controlIds = model.controls.filter(c => c.id).map(c => `#${c.id} (${c.name})`);

  if (assetIds.length + threatIds.length + controlIds.length > 0) {
    sections.push('### Current Definitions (REUSE these IDs — do NOT redefine)\n');
    if (assetIds.length) sections.push(`**Assets:** ${assetIds.join(', ')}`);
    if (threatIds.length) sections.push(`**Threats:** ${threatIds.join(', ')}`);
    if (controlIds.length) sections.push(`**Controls:** ${controlIds.join(', ')}`);
  }

  // Open exposures (unmitigated)
  const unmitigated = model.exposures.filter(e =>
    !model.mitigations.some(m => m.asset === e.asset && m.threat === e.threat)
  );
  if (unmitigated.length > 0) {
    sections.push('\n### Open Exposures (need @mitigates or @audit)\n');
    const lines = unmitigated.slice(0, 25).map(e =>
      `- ${e.asset} exposed to ${e.threat}${e.severity ? ` [${e.severity}]` : ''} (${e.location.file}:${e.location.line})`
    );
    sections.push(lines.join('\n'));
    if (unmitigated.length > 25) sections.push(`- ... and ${unmitigated.length - 25} more`);
  }

  // Existing flows (top 20)
  if (model.flows.length > 0) {
    sections.push('\n### Existing Data Flows (extend, don\'t duplicate)\n');
    const flowLines = model.flows.slice(0, 20).map(f =>
      `- ${f.source} -> ${f.target}${f.mechanism ? ` via ${f.mechanism}` : ''}`
    );
    sections.push(flowLines.join('\n'));
    if (model.flows.length > 20) sections.push(`- ... and ${model.flows.length - 20} more`);
  }

  // Summary stats
  const stats = [
    `${model.annotations_parsed} annotations`,
    `${model.assets.length} assets`,
    `${model.threats.length} threats`,
    `${model.controls.length} controls`,
    `${model.exposures.length} exposures`,
    `${model.mitigations.length} mitigations`,
    `${model.flows.length} flows`,
  ].join(', ');
  sections.push(`\n### Model Stats\n\n${stats}`);

  return sections.join('\n');
}

/**
 * Enhanced agent instructions that include live threat model context.
 * Used by `guardlink sync` to keep all agent instruction files up to date.
 */
export function agentInstructionsWithModel(project: ProjectInfo, model: ThreatModel | null): string {
  const base = agentInstructions(project);

  if (!model || model.annotations_parsed === 0) {
    return base;
  }

  const modelCtx = buildModelContext(model);
  return `${base}
## Live Threat Model Context (auto-synced by \`guardlink sync\`)

${modelCtx}

> **Note:** This section is auto-generated. Run \`guardlink sync\` to update after code changes.
> Any coding agent (Cursor, Claude, Copilot, Windsurf, etc.) should reference these IDs
> and continue annotating new code using the same threat model vocabulary.
`;
}

/**
 * Enhanced cursor rules content with model context.
 */
export function cursorRulesContentWithModel(project: ProjectInfo, model: ThreatModel | null): string {
  const base = cursorRulesContent(project);

  if (!model || model.annotations_parsed === 0) {
    return base;
  }

  const modelCtx = buildModelContext(model);
  return `${base}
## Live Threat Model Context (auto-synced by \`guardlink sync\`)

${modelCtx}
`;
}

/**
 * Enhanced cursor .mdc content with model context.
 */
export function cursorMdcContentWithModel(project: ProjectInfo, model: ThreatModel | null): string {
  return `---
description: GuardLink security annotation rules
globs:
alwaysApply: true
---

${cursorRulesContentWithModel(project, model)}`;
}

// ─── Cursor-specific format ──────────────────────────────────────────

export function cursorRulesContent(project: ProjectInfo): string {
  // .cursorrules uses a flatter format without markdown headers
  return `
# GuardLink Security Annotations

This project uses GuardLink annotations in source code comments.

## Core Requirement
Every time you write or modify code that touches security-relevant behavior, you MUST add GuardLink annotations in the same change. This includes: new endpoints, auth logic, data validation, database queries, file I/O, external API calls, crypto, process spawning, user input handling, config parsing. Do NOT annotate pure business logic, formatting utilities, UI components, or helpers that never touch security boundaries.

## Key Rules
- ANNOTATE NEW CODE. When you add a function or endpoint that handles user input, accesses data, or crosses a trust boundary — add @exposes, @mitigates, @flows, @handles, or at minimum @comment. This is not optional.
- NEVER write @accepts — that is a human-only governance decision. For risks with no mitigation: write @exposes + @audit + @comment suggesting potential controls.
- Classify threat origin in every @exposes description. Start the -- description with one of: [external], [internal], [mixed], [potentially-external], [potentially-internal] to indicate who can trigger the threat.
- Preserve existing annotations — do not delete or mangle them.
- Definitions (@asset, @threat, @control with (#id)) live in .guardlink/definitions${project.definitionsExt}. Reuse IDs — never redefine. Add new definitions there first, then reference in source files.
- Source files use relationship verbs: @mitigates, @exposes, @flows, @handles, @boundary, @comment, @validates, @audit, @owns, @assumes, @transfers.
- Write coupled annotation blocks: risk + control (or audit) + data flow + context note.
- Avoid @shield unless a human explicitly asks to hide code from AI.

## Workflow
- Before writing code: skim .guardlink/definitions${project.definitionsExt} to understand existing IDs.
- While writing code: add annotations as you write, not as a separate pass afterward.
- After changes: run \`guardlink validate .\` and \`guardlink status .\`.
- After adding annotations: run \`guardlink sync\` to update all agent instruction files with current threat model context.

## Quick Syntax
- @exposes App.API to #sqli [P0] cwe:CWE-89 -- "[external] req.body.email concatenated into SQL"
- @mitigates App.API against #sqli using #prepared-stmts -- "Parameterized queries via pg"
- @audit App.API -- "Timing attack risk — needs human review"
- @flows User -> App.API via HTTPS -- "Login request"
- @boundary between #api and #db (#data-boundary) -- "Trust change"
- @handles pii on App.API -- "Processes email, token"
- @validates #prepared-stmts for App.API -- "CI test ensures placeholders"
- @audit App.API -- "Token rotation review"
- @owns security-team for App.API -- "Team responsible"
- @comment -- "Rate limit: 100 req/15min"
`.trimStart();
}

// ─── Cursor .mdc format ──────────────────────────────────────────────

export function cursorMdcContent(project: ProjectInfo): string {
  return `---
description: GuardLink security annotation rules
globs:
alwaysApply: true
---

${cursorRulesContent(project)}`;
}

// ─── Shared definitions file ─────────────────────────────────────────

export function definitionsContent(project: ProjectInfo): string {
  const c = project.commentPrefix;

  return `${c} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${c} GuardLink Shared Definitions — ${project.name}
${c}
${c} ALL @asset, @threat, and @control declarations live here.
${c} Source files reference by #id only (e.g. @mitigates X against #sqli).
${c} Never redeclare an ID that exists in this file.
${c} Before adding: read this file to check for duplicates.
${c}
${c} Run: guardlink validate .
${c} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${c} ─── Examples (uncomment and customize for your project) ────────
${c}
${c}   ${c} @asset App.API (#api) -- "Main REST endpoint"
${c}   ${c} @asset App.Database (#db) -- "Primary data store"
${c}
${c}   ${c} @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Unsanitized input reaches SQL query"
${c}   ${c} @threat Cross_Site_Scripting (#xss) [high] cwe:CWE-79 -- "Unsanitized input rendered in browser"
${c}   ${c} @threat Broken_Access_Control (#bac) [critical] cwe:CWE-284 -- "Missing or bypassable authorization"
${c}
${c}   ${c} @control Parameterized_Queries (#prepared-stmts) -- "SQL queries use bound parameters"
${c}   ${c} @control Input_Validation (#input-validation) -- "Input validated against schema/allowlist"
${c}   ${c} @control RBAC (#rbac) -- "Role-based access control"
${c}
${c} ─── Your Definitions ──────────────────────────────────────────

`;
}

// ─── Config file ─────────────────────────────────────────────────────

export function configContent(project: ProjectInfo): string {
  return JSON.stringify({
    version: '1.1.0',
    project: project.name,
    language: project.language,
    definitions: `definitions${project.definitionsExt}`,
    include: defaultIncludeForLanguage(project.language),
    exclude: [
      'node_modules', 'dist', 'build', '.git',
      '__pycache__', 'target', 'vendor', '.next',
    ],
  }, null, 2) + '\n';
}

// ─── .gitignore addition ─────────────────────────────────────────────

export const GITIGNORE_ENTRY = `
# GuardLink
.guardlink/*.json
!.guardlink/config.json
`;

// ─── Helpers ─────────────────────────────────────────────────────────

function toPascalCase(s: string): string {
  return s
    .replace(/[-_./]/g, ' ')
    .split(/\s+/)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join('');
}

function defaultIncludeForLanguage(lang: string): string[] {
  switch (lang) {
    case 'typescript':
    case 'javascript':
      return ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'];
    case 'python':
      return ['**/*.py'];
    case 'go':
      return ['**/*.go'];
    case 'rust':
      return ['**/*.rs'];
    case 'java':
      return ['**/*.java'];
    case 'csharp':
      return ['**/*.cs'];
    case 'ruby':
      return ['**/*.rb'];
    case 'swift':
      return ['**/*.swift'];
    case 'kotlin':
      return ['**/*.kt', '**/*.kts'];
    case 'terraform':
      return ['**/*.tf', '**/*.hcl'];
    default:
      return ['**/*.ts', '**/*.js', '**/*.py', '**/*.go', '**/*.rs', '**/*.java'];
  }
}


// ─── MCP configuration ──────────────────────────────────────────────

/**
 * Generate .mcp.json for Claude Code auto-configuration.
 * When committed to repo, Claude Code automatically connects to the MCP server.
 */
export function mcpConfig(): string {
  return JSON.stringify({
    mcpServers: {
      guardlink: {
        command: 'guardlink',
        args: ['mcp'],
      },
    },
  }, null, 2) + '\n';
}
