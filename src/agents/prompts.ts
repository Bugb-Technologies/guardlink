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
 * Includes the GuardLink reference doc (truncated), current model summary,
 * user instructions, and precise GAL syntax rules with common pitfalls.
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

  let modelSummary = 'No threat model parsed yet. Run `guardlink parse` after annotating.';
  let existingIds = '';
  if (model) {
    const parts = [
      `${model.annotations_parsed} annotations`,
      `${model.exposures.length} exposures`,
      `${model.assets.length} assets`,
      `${model.threats.length} threats`,
      `${model.controls.length} controls`,
      `${model.mitigations.length} mitigations`,
    ];
    modelSummary = `Current model: ${parts.join(', ')}.`;

    // Include existing IDs so the agent doesn't create duplicates or dangling refs
    const threatIds = model.threats.filter(t => t.id).map(t => `#${t.id}`);
    const assetIds = model.assets.filter(a => a.id).map(a => `#${a.id}`);
    const controlIds = model.controls.filter(c => c.id).map(c => `#${c.id}`);
    if (threatIds.length + assetIds.length + controlIds.length > 0) {
      const sections: string[] = [];
      if (threatIds.length) sections.push(`Threats: ${threatIds.join(', ')}`);
      if (assetIds.length) sections.push(`Assets: ${assetIds.join(', ')}`);
      if (controlIds.length) sections.push(`Controls: ${controlIds.join(', ')}`);
      existingIds = `\n\nExisting defined IDs (use these in @exposes, @mitigates, etc.):\n${sections.join('\n')}`;
    }
  }

  return `You are annotating a codebase with GuardLink security annotations.

${refDoc ? '## GuardLink Reference\n\n' + refDoc.slice(0, 4000) + '\n\n' : ''}## Current State
${modelSummary}${existingIds}

## Task
${userPrompt}

## PRECISE Annotation Syntax (follow EXACTLY)

Definitions go in .guardlink/definitions.js (or .py/.rs). Source files use only relationship verbs.

### Definitions
\`\`\`
// @shield:begin -- "Example annotations for agent prompt, excluded from parsing"
// @asset Server.Auth (#auth) -- "Authentication service"
// @threat SQL_Injection (#sqli) [P0] cwe:CWE-89 -- "Unsanitized input in SQL"
// @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
// @shield:end
\`\`\`

### Relationships (use in source files)
\`\`\`
// @shield:begin -- "Example annotations for agent prompt, excluded from parsing"
// @exposes #auth to #sqli [P0] cwe:CWE-89 owasp:A03:2021 -- "User input concatenated into query"
// @mitigates #auth against #sqli using #prepared-stmts -- "Uses parameterized queries"
// @flows req.body.username -> db.query via string-concat -- "User input flows to SQL"
// @boundary between #frontend and #api (#trust-boundary) -- "Public/private boundary"
// @handles pii on #auth -- "Processes user credentials"
// @comment -- "TODO: add rate limiting to prevent brute force"
// @shield:end
\`\`\`

## CRITICAL SYNTAX RULES (violations cause parse errors)

1. **@boundary requires TWO assets**: \`@boundary between #A and #B\` or \`@boundary #A | #B\`.
   WRONG: \`@boundary api -- "desc"\`  (only one argument — will NOT parse)
   RIGHT: \`@boundary between #api and #client (#api-boundary) -- "Trust boundary"\`

2. **@flows is ONE source → ONE target per line**: \`@flows <source> -> <target> via <mechanism>\`.
   WRONG: \`@flows A -> B, C -> D -- "desc"\`  (commas not supported)
   RIGHT: \`@flows A -> B via mechanism -- "desc"\` (one per line, repeat for multiple)

3. **@exposes / @mitigates require DEFINED #id refs**: Every \`#id\` you reference must exist as a definition.
   Before using \`@exposes #app to #sqli\`, ensure \`@threat SQL_Injection (#sqli)\` exists in definitions.
   Add new definitions to .guardlink/definitions.js FIRST, then reference them in source files.

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

## Workflow
1. Read existing definitions in .guardlink/definitions.js — reuse existing IDs
2. Add any NEW threat/control definitions FIRST
3. Then add relationship annotations (@exposes, @mitigates, @flows, etc.) in source files
4. Use the project's comment style (// for JS/TS, # for Python, etc.)
5. Run guardlink_validate (MCP) or \`guardlink validate\` to check for errors
6. Fix any validation errors before finishing
`;
}
