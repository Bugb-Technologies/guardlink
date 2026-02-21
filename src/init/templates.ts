/**
 * GuardLink init — Template content for generated files.
 */

import type { ProjectInfo } from './detect.js';

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
         @exposes <Asset> to <#threat> [severity] cwe:CWE-NNN -- "what's wrong"
         @accepts <#threat> on <Asset> -- "why acceptable"
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

## External References

Append after severity: \`cwe:CWE-89\`, \`owasp:A03:2021\`, \`capec:CAPEC-66\`, \`attack:T1190\`

## Rules

1. **Define once, reference everywhere.** \`@asset\`, \`@threat\`, \`@control\` with \`(#id)\` go in \`.guardlink/definitions${project.definitionsExt}\`. Source files use relationship verbs only (\`@mitigates\`, \`@exposes\`, etc.).
2. **Read definitions before adding.** Check for existing IDs first — avoid duplicates.
3. **Every \`@exposes\` needs a plan.** Match with \`@mitigates\` (fix exists), \`@accepts\` (risk acknowledged), or TODO.
4. **Always annotate security-relevant code.** At minimum, add \`@comment\` to document intent.
5. **Use the full verb set.** \`@flows\` for data movement, \`@handles\` for data classification, \`@boundary\` for trust boundaries.

## When Writing Code

| Situation | Annotation |
|-----------|------------|
| New service/component | \`@asset\` in definitions, then reference in source |
| Security gap exists | \`@exposes Asset to #threat\` |
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

### Key Rules

1. Definitions (\`@asset\`, \`@threat\`, \`@control\` with \`#id\`) go in \`.guardlink/definitions${project.definitionsExt}\` — read it before adding new ones.
2. Source files use relationship verbs only: \`@mitigates\`, \`@exposes\`, \`@accepts\`, \`@flows\`, \`@handles\`, \`@boundary\`, \`@comment\`.
3. Every \`@exposes\` needs a matching \`@mitigates\` or \`@accepts\`.
4. Always add at least \`@comment\` on security-relevant code.
5. Run \`guardlink validate .\` after making changes.

### MCP Tools Available

Use \`guardlink_lookup\` to check existing definitions. Use \`guardlink_validate\` after annotating. Use \`guardlink_suggest <file>\` for recommendations.

### Quick Syntax

\`\`\`
@exposes Asset to #threat [P0] cwe:CWE-89 -- "description"
@mitigates Asset against #threat using #control -- "how"
@comment -- "security-relevant note"
\`\`\`
`.trimStart();
}

// ─── Cursor-specific format ──────────────────────────────────────────

export function cursorRulesContent(project: ProjectInfo): string {
  // .cursorrules uses a flatter format without markdown headers
  return `
# GuardLink Security Annotations

This project uses GuardLink annotations in source code comments.

## Annotation Syntax
- @asset <Component.Path> (#id) -- "description"
- @threat <Name> (#id) [P0|P1|P2|P3] cwe:CWE-NNN -- "description"
- @control <Name> (#id) -- "description"
- @mitigates <Asset> against <#threat> using <#control> -- "how"
- @exposes <Asset> to <#threat> [severity] cwe:CWE-NNN -- "what"
- @accepts <#threat> on <Asset> -- "why"
- @flows <Source> -> <Target> via <mechanism> -- "details"
- @boundary between <A> and <B> (#id) -- "trust boundary"
- @handles <pii|phi|financial|secrets> on <Asset>
- @shield:begin -- "reason" ... @shield:end

## Rules
- All @asset, @threat, @control with (#id) go in .guardlink/definitions${project.definitionsExt}. Source files use only relationship verbs (@mitigates, @exposes, @accepts, @flows, etc).
- Read definitions file before adding — check for existing IDs first.
- Severity: P0=critical, P1=high, P2=medium, P3=low. Only P0-P3.
- External refs: cwe:CWE-89, owasp:A03:2021, capec:CAPEC-66
- Every @exposes needs a matching @mitigates or @accepts.
- Run \`guardlink validate .\` to check annotations.
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
    version: '1.0.0',
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
