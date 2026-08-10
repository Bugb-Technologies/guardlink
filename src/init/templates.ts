/**
 * GuardLink init — Template content for generated files.
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
         @actor <Name> (#id) -- "a principal in the authz model — a role, not a person"

RELATE   @mitigates <Asset> against <#threat> using <#control> -- "how"
         @exposes <Asset> to <#threat> [severity] cwe:CWE-NNN -- "what's wrong"
         @accepts <#threat> on <Asset> -- "HUMAN-ONLY — AI agents must use @audit instead"
         @transfers <#threat> from <Source> to <Target> -- "who handles it"
         @entitles <#actor> to <capability> on <Asset> -- "by design + authz file:line"
                   ^ PROPOSED via \`guardlink entitle --propose\`, written only when a human accepts

FLOW     @flows <Source> -> <Target> via <mechanism> -- "details"
         @boundary <AssetA> | <AssetB> (#id) -- "trust boundary"
         @boundary between <AssetA> and <AssetB> (#id) -- "trust boundary"

LIFECYCLE
         @validates <#control> for <Asset> -- "test evidence"
         @audit <Asset> -- "what needs review"
         @owns <team-id> for <Asset> -- "responsible team"
         @handles <pii|phi|financial|secrets|internal|public> on <Asset>
         @assumes <Asset> -- "unverified assumption"

METADATA @feature "Feature Name" -- "tag code with a feature for filtering"

COMMENT  @comment -- "security-relevant developer note"

PROTECT  @shield -- "reason"
         @shield:begin -- "reason"   ... code ...   @shield:end
\`\`\`

## Severity

\`[P0]\` = critical, \`[P1]\` = high, \`[P2]\` = medium, \`[P3]\` = low

## External References

Append after severity: \`cwe:CWE-89\`, \`owasp:A03:2021\`, \`capec:CAPEC-66\`, \`attack:T1190\`

## Rules

1. **Annotate as you code.** When you write or modify security-relevant code (endpoints, auth, data access, validation, I/O, crypto, process spawning), add annotations in the same change. This is required, not optional.
2. **Define once, reference everywhere.** \`@asset\`, \`@threat\`, \`@control\` with \`(#id)\` go in \`.guardlink/definitions${project.definitionsExt}\`. Source files use relationship verbs only (\`@mitigates\`, \`@exposes\`, etc.).
3. **Read definitions before adding.** Check for existing IDs first — avoid duplicates.
4. **Every \`@exposes\` needs a response.** Match with \`@mitigates\` (fix exists) or \`@audit\` (flag for human review). AI agents must NEVER write \`@accepts\` — that is a human-only governance decision. Use \`@audit\` instead.
5. **Use the full verb set.** \`@flows\` for data movement, \`@handles\` for data classification, \`@boundary\` for trust boundaries.
6. **\`@entitles\` is proposed, never written.** An over-grant closes a real privilege escalation as by-design, so an agent files a proposal (\`guardlink entitle --propose\` / \`guardlink_entitlement_propose\`) and a human accepts it — acceptance is what writes the annotation, under their name. An \`@entitles\` in source with no accepted proposal is a validation error. The rationale must cite the authz code as \`file:line\`, or the claim is **inert** — parsed but ignored. It never hides a finding and never gates testing; it only changes what triage recommends. Never propose one for an ownership question (IDOR, tenant isolation).

## When Writing Code

| Situation | Annotation |
|-----------|------------|
| Writing new endpoint/handler | \`@exposes\` + \`@mitigates\` (or \`@audit\`) + \`@flows\` + \`@comment\` — tell the complete story |
| New service/component | \`@asset\` in definitions, then reference in source |
| New role / permission tier | \`@actor\` in definitions, then \`guardlink entitle --propose\` per capability held by design |
| Security gap exists | \`@exposes Asset to #threat\` + \`@audit Asset\` |
| Risk with no fix yet | \`@audit Asset\` + \`@comment\` explaining potential controls. NEVER \`@accepts\`. |
| Implementing a fix | \`@mitigates Asset against #threat using #control\` |
| Processing sensitive data | \`@handles pii on Asset\` |
| Proprietary algorithm | \`@shield:begin\` ... \`@shield:end\` |
| Tagging code to a feature | \`@feature "SSO Login" -- "Single sign-on flow"\` |
| Unsure which annotation | \`@comment -- "describe what you see"\` |

## Commands

\`\`\`bash
guardlink validate .          # Check for errors
guardlink report .            # Generate threat-model.md
guardlink status .            # Coverage summary
guardlink suggest <file>      # Get annotation suggestions
guardlink feature list        # List all @feature tags
guardlink feature show <name> # Show model for a specific feature
guardlink entitle --propose   # File an @entitles proposal (writes nothing to source)
guardlink entitle             # Human review of proposals: accept / reject / defer
\`\`\`

## MCP Tools

When connected via \`.mcp.json\`, use:
- \`guardlink_parse\` — parse annotations, return threat model
- \`guardlink_lookup\` — query threats, controls, exposures by ID
- \`guardlink_suggest\` — get annotation suggestions for a file
- \`guardlink_validate\` — check for syntax errors
- \`guardlink_status\` — coverage stats
- \`guardlink_entitlement_propose\` / \`guardlink_entitlement_list\` — propose an \`@entitles\` claim and see what happened to it. There is no accept tool: a human accepts, with \`guardlink entitle\`.
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
3. **Use \`@confirmed\` for verified exploits.** When a pentest, CXG scan, or manual reproduction proves a threat is exploitable, mark it with \`@confirmed #threat on Asset [severity] -- "evidence"\`. This is distinct from \`@exposes\` (theoretical) — \`@confirmed\` means real, verified, not a false positive. Include severity based on actual observed impact.
4. Do not delete or mangle existing annotations. Treat them as part of the code. Edit only when intentionally changing the threat model.
5. Definitions (\`@asset\`, \`@threat\`, \`@control\` with \`(#id)\`) live in \`.guardlink/definitions${project.definitionsExt}\`. Reuse existing \`#id\`s — never redefine. If you need a new asset or threat, add the definition there first, then reference it in source files.
6. Source files use relationship verbs only: \`@mitigates\`, \`@exposes\`, \`@confirmed\`, \`@flows\`, \`@handles\`, \`@boundary\`, \`@comment\`, \`@validates\`, \`@audit\`, \`@owns\`, \`@assumes\`, \`@transfers\`, \`@feature\`. (\`@actor\` is a definition — it belongs in the definitions file with \`@asset\`/\`@threat\`/\`@control\`. \`@entitles\` is proposed, not written — see rule 9.)
7. Write coupled annotation blocks that tell a complete story: risk + control (or audit) + data flow + context note. Never write a lone \`@exposes\` without follow-up.
8. Avoid \`@shield\` unless a human explicitly asks to hide code from AI — it creates blind spots.
9. **NEVER write \`@entitles\` into source — propose it.** \`@entitles\` says a privilege is *supposed* to have this effect, so an over-grant closes a real privilege escalation as by-design. That makes it the second claim you may not make on a human's behalf, alongside \`@accepts\`. File it with \`guardlink entitle --propose\` (or \`guardlink_entitlement_propose\`) and a human's acceptance is what writes the annotation, under their name; an \`@entitles\` in source with no accepted proposal is a validation error. The rationale must cite the authz code as \`file:line\` or the claim is inert — parsed and then ignored. It never suppresses a finding and never gates testing; it only changes what triage recommends. Never propose one for an ownership question (IDOR, tenant isolation) — both peers hold the capability, so it cannot say whose object it was. When unsure which role the code actually requires, write \`@comment\` describing what you saw instead: under-granting costs noise, over-granting hides a real bug.

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
\`\`\`

\`@entitles\` is absent from that list on purpose — you propose it, you do not write it:

\`\`\`bash
guardlink entitle --propose --actor '#ns-admin' --capability configure-archival-destination \\
  --asset '#archival-fs' --rationale "By design: the archival URI is namespace configuration. Authz: common/api/metadata.go:189"
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
  const actorIds = (model.actors || []).filter(a => a.id).map(a => `#${a.id} (${a.name})`);

  if (assetIds.length + threatIds.length + controlIds.length + actorIds.length > 0) {
    sections.push('### Current Definitions (REUSE these IDs — do NOT redefine)\n');
    if (assetIds.length) sections.push(`**Assets:** ${assetIds.join(', ')}`);
    if (threatIds.length) sections.push(`**Threats:** ${threatIds.join(', ')}`);
    if (controlIds.length) sections.push(`**Controls:** ${controlIds.join(', ')}`);
    if (actorIds.length) sections.push(`**Actors:** ${actorIds.join(', ')}`);
  }

  // Entitlements — carried into agent context because an agent that cannot see
  // which capabilities are already granted by design will keep re-filing them
  // as exposures. Inert claims are marked so nothing reads them as effective.
  const entitlements = model.entitlements || [];
  if (entitlements.length > 0) {
    sections.push('\n### Entitlements (capabilities held by design — never a reason to skip testing)\n');
    const lines = entitlements.slice(0, 25).map(en =>
      `- ${en.actor} entitled to \`${en.canonical_capability}\`${en.asset ? ` on ${en.asset}` : ''}` +
      (en.citation ? ` — cites ${en.citation.raw}` : ' — **uncited, inert**')
    );
    sections.push(lines.join('\n'));
    if (entitlements.length > 25) sections.push(`- ... and ${entitlements.length - 25} more`);
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

  // Confirmed exploitable findings
  if ((model.confirmed || []).length > 0) {
    sections.push('\n### 🔴 Confirmed Exploitable (verified, not false positives)\n');
    const confirmedLines = model.confirmed.slice(0, 25).map(c =>
      `- ${c.asset} confirmed ${c.threat}${c.severity ? ` [${c.severity}]` : ''} (${c.location.file}:${c.location.line})`
    );
    sections.push(confirmedLines.join('\n'));
    if (model.confirmed.length > 25) sections.push(`- ... and ${model.confirmed.length - 25} more`);
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

  // Features
  const uniqueFeatures = new Set((model.features || []).map(f => f.feature));
  if (uniqueFeatures.size > 0) {
    sections.push('\n### Features (filter with `--feature`)\n');
    sections.push([...uniqueFeatures].sort().map(f => `- "${f}"`).join('\n'));
  }

  // Summary stats
  const stats = [
    `${model.annotations_parsed} annotations`,
    `${model.assets.length} assets`,
    `${model.threats.length} threats`,
    `${model.controls.length} controls`,
    `${model.exposures.length} exposures`,
    `${(model.confirmed || []).length} confirmed`,
    `${model.mitigations.length} mitigations`,
    ...((model.actors || []).length > 0 ? [`${model.actors!.length} actors`] : []),
    ...((model.entitlements || []).length > 0 ? [`${model.entitlements!.length} entitlements`] : []),
    `${model.flows.length} flows`,
    ...(uniqueFeatures.size > 0 ? [`${uniqueFeatures.size} features`] : []),
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
- NEVER write @entitles either — propose it with \`guardlink entitle --propose\` and a human's acceptance writes it, under their name. It claims a privilege is *supposed* to have this effect, so an over-grant closes a real escalation as by-design. Cite the authz code as file:line or the claim is inert. Never propose one for an ownership question (IDOR, tenant isolation).
- Use @confirmed for verified exploits. When pentest/scanning/manual reproduction proves a threat is exploitable: @confirmed #threat on Asset [severity] -- "evidence". Distinct from @exposes (theoretical) — @confirmed means real, verified, no false positives.
- Preserve existing annotations — do not delete or mangle them.
- Definitions (@asset, @threat, @control with (#id)) live in .guardlink/definitions${project.definitionsExt}. Reuse IDs — never redefine. Add new definitions there first, then reference in source files.
- Source files use relationship verbs: @mitigates, @exposes, @confirmed, @flows, @handles, @boundary, @comment, @validates, @audit, @owns, @assumes, @transfers, @feature. (@actor is a definition — it lives with @asset/@threat/@control. @entitles is proposed, not written.)
- Write coupled annotation blocks: risk + control (or audit) + data flow + context note.
- Avoid @shield unless a human explicitly asks to hide code from AI.

## Workflow
- Before writing code: skim .guardlink/definitions${project.definitionsExt} to understand existing IDs.
- While writing code: add annotations as you write, not as a separate pass afterward.
- After changes: run \`guardlink validate .\` and \`guardlink status .\`.
- After adding annotations: run \`guardlink sync\` to update all agent instruction files with current threat model context.

## Quick Syntax
- @exposes App.API to #sqli [P0] cwe:CWE-89 -- "req.body.email concatenated into SQL"
- @mitigates App.API against #sqli using #prepared-stmts -- "Parameterized queries via pg"
- @audit App.API -- "Timing attack risk — needs human review"
- @flows User -> App.API via HTTPS -- "Login request"
- @boundary between #api and #db (#data-boundary) -- "Trust change"
- @handles pii on App.API -- "Processes email, token"
- @validates #prepared-stmts for App.API -- "CI test ensures placeholders"
- @audit App.API -- "Token rotation review"
- @confirmed #sqli on App.API [critical] cwe:CWE-89 -- "Pentest verified: raw SQL injection via email param"
- @feature "SSO Login" -- "Single sign-on authentication flow"
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

// ─── Project description template ─────────────────────────────────

/**
 * Generate skeleton .guardlink/prompt.md for `guardlink report`.
 *
 * During `init` this creates a placeholder that guides users (and AI agents
 * during `annotate`) on what to fill in. The content feeds into the
 * "Application Overview" section of the generated threat model report.
 */
export function promptMdContent(project: ProjectInfo): string {
  return `# ${project.name} — Project Description

<!-- This file feeds into \`guardlink report\` as the Application Overview section. -->
<!-- Fill it in manually, or let \`guardlink annotate\` generate it with AI assistance. -->

## What This Application Does

<!-- Brief description: what does the project do, who are its users? -->

## Key Components

<!-- List the major modules, services, or subsystems (e.g., API server, auth service, worker queue). -->

## Trust Boundaries

<!-- Where does trust change? e.g., public internet → API gateway, app → database, app → third-party API. -->

## Data Sensitivity

<!-- What sensitive data does this project handle? (PII, credentials, financial data, health records, etc.) -->

## Deployment Context

<!-- How and where is this deployed? (cloud provider, containerized, on-prem, CI/CD pipeline, etc.) -->
`;
}

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
