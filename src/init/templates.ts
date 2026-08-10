/**
 * GuardLink init — Template content for generated files.
 */

import type { ProjectInfo } from './detect.js';
import type { ThreatModel } from '../types/index.js';
import type { AnnotationMode } from '../parser/annotation-mode.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';
import { buildCoverageIndex } from '../parser/coverage.js';
// D19: cross-repo tags shown in generated docs are BUILT from the parser's tag
// grammar, never typed as strings. Hand-written examples of a grammar are how
// D19 shipped in the first place.
import { crossRepoTag } from '../parser/parse-line.js';
// D17: one list of GuardLink's own generated outputs — the parser excludes them
// from the scan set, and .gitignore ignores them, from the same constant.
import { GENERATED_OUTPUT_FILES } from '../parser/parse-project.js';

// ─── Where annotations go (D27) ──────────────────────────────────────

/**
 * The one paragraph every agent instruction file was missing.
 *
 * D27: `agentInstructions(project)` took no mode, so no agent file *could*
 * state where annotations belong. On a fresh default-init repo `config.json`
 * said `annotation_mode: external` while `CLAUDE.md` contained zero occurrences
 * of `.gal`, `annotations/`, `sidecar` or `@source`. An agent read inline syntax,
 * had no placement guidance, wrote inline, and the repo silently went mixed.
 *
 * `.guardlink/README.md` already said it correctly — but that is the cold-start
 * path, read once, not the file an agent reads every turn. So this is now ONE
 * function that both consume: the README and every agent instruction file emit
 * byte-identical placement text, and there is no second copy to drift.
 *
 * Shielded because of D22. The inline branch shows a doc-block, whose ` * @…`
 * lines are indistinguishable from real annotations once the comment prefix is
 * stripped — that is exactly how the GL-402 README template injected `#api`,
 * `#sqli` and `cwe:CWE-89` into this repo's own model.
 */
// @shield:begin -- "Placement examples for both modes; they would otherwise parse as real annotations"
export function annotationPlacementSection(
  project: ProjectInfo,
  mode: AnnotationMode | null,
): string {
  // A repo with annotations in both places. This is the exact state D27 said the
  // silence would produce, so it gets named rather than rounded to one mode.
  if (mode === 'mixed') {
    return `**This repo is currently MIXED** — it has annotations both inline in source comments
and in \`.gal\` sidecars under \`.guardlink/annotations/\`. That is not a supported
configuration; it is drift.

Do not add annotations until it is resolved. Converge the repo first:

\`\`\`sh
guardlink migrate --to external   # move inline annotations into .gal sidecars
guardlink migrate --to inline     # or move sidecars back into source comments
\`\`\`

Then re-run \`guardlink sync\`, and this section will state the single mode in effect.`;
  }

  // An unrecorded mode still gets placement guidance — silence is what D27 was.
  // It gets the product default, labelled as a default rather than a decision.
  const effective: 'inline' | 'external' = mode ?? 'external';
  const unrecorded = mode === null
    ? `\n> \`annotation_mode\` is not recorded in \`.guardlink/config.json\`. The text below is the\n> default, not a decision someone made. Record it with \`guardlink migrate --to ${effective}\`.\n`
    : '';

  if (effective === 'external') {
    return `**Annotation mode: \`external\`. Annotations live in \`.gal\` sidecars under
\`.guardlink/annotations/\` — NOT in source files.**
${unrecorded}
The sidecar path mirrors the source path, with \`.gal\` appended:

| Source file | Its annotations |
|---|---|
| \`src/auth/login.ts\` | \`.guardlink/annotations/src/auth/login.ts.gal\` |
| \`internal/db/query.go\` | \`.guardlink/annotations/internal/db/query.go.gal\` |

Inside a \`.gal\`, group annotations under a \`@source\` block naming the real code location:

\`\`\`
@source file:src/auth/login.ts line:42 symbol:login
@exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
@mitigates #api against #sqli using #prepared-stmts -- "parameterized via pg"
\`\`\`

\`.gal\` files hold **raw GAL lines** — no \`${project.commentPrefix}\` prefix, no doc-block. Do
not edit source files to add annotations in this mode.

> Sidecars are found wherever the convention puts them, including for source files under
> \`test/\`, \`vendor/\` or \`dist/\` — directories the parser skips for *source* but not for
> annotations. \`guardlink validate\` warns if a \`.gal\` is off-convention, and still parses it.`;
  }

  const example = project.commentPrefix === '#'
    ? `\`\`\`py
# @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
# @mitigates #api against #sqli using #prepared-stmts -- "parameterized via psycopg"
def login(email): ...
\`\`\``
    : `\`\`\`ts
/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "parameterized via pg"
 */
export function login(email: string) { … }
\`\`\``;

  return `**Annotation mode: \`inline\`. Annotations live in source-file comments**, in the comment
syntax of the file you are editing — the doc-block of the function or module they describe.
${unrecorded}
${example}

Do not create \`.gal\` sidecars under \`.guardlink/annotations/\` in this mode; a repo with
both is a mixed repo, and that is the failure this section exists to prevent.`;
}
// @shield:end

// ─── Canonical reference document ────────────────────────────────────

/**
 * docs/GUARDLINK_REFERENCE.md — the single source of truth for annotation syntax.
 * All agent instruction files point here instead of duplicating the full reference.
 */
/**
 * Where `init` puts the annotation reference, as one rule both writers use.
 *
 * D45: `.guardlink/README.md` said "The complete reference is
 * `.guardlink/GUARDLINK_REFERENCE.md`" while `init` had written
 * `docs/GUARDLINK_REFERENCE.md`. The two disagreed because they were keyed off
 * different things — the README chose by ANNOTATION MODE, `init` writes by
 * `rootFiles` — and annotation mode has nothing to do with where a document
 * goes. Under the default (external mode, root files allowed) the two axes
 * disagree, which is every fresh repo.
 *
 * The sentence after the broken pointer is "Read it before inventing syntax",
 * so the one wrong link in the document was the one aimed at a reader about to
 * guess at syntax.
 */
export const REFERENCE_DOC_IN_GUARDLINK = '.guardlink/GUARDLINK_REFERENCE.md';
export const REFERENCE_DOC_IN_DOCS = 'docs/GUARDLINK_REFERENCE.md';

/** `--no-root-files` keeps everything inside `.guardlink/`; otherwise `docs/`. */
export function referenceDocPath(rootFiles: boolean): string {
  return rootFiles ? REFERENCE_DOC_IN_DOCS : REFERENCE_DOC_IN_GUARDLINK;
}

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
         @entitles <#actor> to <capability> on <Asset> against <#threat> -- "by design + authz file:line"
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
guardlink validate .            # Check for errors
guardlink report .              # Generate threat-model.md
guardlink status .              # Coverage summary
guardlink feature list          # List all @feature tags
guardlink feature show "<name>" # Show model for a feature (quote names with spaces)
guardlink entitle --propose     # File an @entitles proposal (writes nothing to source)
guardlink entitle               # Human review of proposals: accept / reject / defer
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
 *
 * `mode` is not optional in spirit even though it is in the signature: D27 was
 * this function having no way to say where annotations go. It defaults to null,
 * which renders the product default explicitly labelled as a default — never
 * silence.
 */
export function agentInstructions(project: ProjectInfo, mode: AnnotationMode | null = null): string {
  return `
## GuardLink — Security Model

This project carries a [GuardLink](https://guardlink.bugb.io) threat model: security facts
recorded next to the code they describe — what each component is exposed to, what mitigates
it, how data flows between components — parsed into something you can query.

**Ask it instead of inferring security context from the source.** It already answers most of
what you would otherwise guess at, and it records decisions that are invisible in the code,
such as which risks a human has explicitly accepted.

| You are about to… | Ask |
|---|---|
| edit a file | \`guardlink_context(file)\` — annotations there, the assets they name, open exposures, controls the file must uphold |
| change a shared component | \`guardlink_graph(from, depth, direction)\` — blast radius across data flows and trust boundaries |
| act on a scanner finding | \`guardlink_lookup("cwe:CWE-89")\` — is this weakness class declared, and is it mitigated, accepted, open or confirmed |
| finish a change | \`guardlink validate .\` then \`guardlink diff HEAD~1\` — did I make this worse |

Without MCP, the same answers come from \`guardlink status .\`, \`guardlink parse .\`
(the whole model as JSON on stdout) and \`guardlink diff HEAD~1\`.

**Full reference: \`docs/GUARDLINK_REFERENCE.md\`**

### Where annotations go

${annotationPlacementSection(project, mode)}

### What you owe it back

**When you write or change code that touches security-relevant behavior, add the annotations in
the same change.** This includes: new endpoints, authentication/authorization logic, data validation, database queries, file I/O, external API calls, crypto operations, process spawning, user input handling, and configuration parsing. Do NOT annotate pure business logic, formatting utilities, UI components, or helper functions that never touch security boundaries.

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

- **Opening a file:** \`guardlink_context(file)\` before you read far into it. Note which kind of empty an empty answer is — \`scanned_without_annotations\` means clean, \`not_scanned\` means the parser never read it. They are not the same.
- **Before writing:** skim \`.guardlink/definitions${project.definitionsExt}\` for the existing assets, threats and controls. Reuse those ids.
- **While writing:** annotate as you go, not as a pass afterward — ${(mode ?? 'external') === 'external' ? 'in the file\'s `.gal` sidecar (see "Where annotations go")' : 'in the doc-block of the code you are writing'}.
- **After changing:** \`guardlink diff HEAD~1\` — the one command that answers "did I add exposure". Then \`guardlink validate .\` for syntax and dangling refs, and \`guardlink status .\` for coverage.
- **After annotating:** \`guardlink sync\` refreshes this block and \`.guardlink/README.md\` from the current model.

### Tools

- **MCP** (Claude Code, Cursor): \`guardlink_context\`, \`guardlink_graph\`, \`guardlink_lookup\`, \`guardlink_diff\`, \`guardlink_validate\`, \`guardlink_status\`, \`guardlink_suggest\`.
- **CLI** (always): \`guardlink status .\`, \`guardlink parse .\`, \`guardlink validate .\`, \`guardlink diff HEAD~1\`, \`guardlink report .\`.
- \`guardlink_lookup\` answers a fixed set of named forms and **refuses anything else rather than
  guessing** — send it a bad query to get the list. Beyond \`asset\`/\`threat\`/\`control\`, it reaches
  every relation the model holds: \`owner of X\`, \`handles pii\`, \`assumptions for X\`, \`audits for X\`,
  \`validations for X\`, \`acceptances\`, \`transfers\`, \`comments for X\`, \`shields\`, \`cross-repo refs\`,
  and \`cwe:CWE-89\` / \`owasp:A03\` for scanner findings.
- Reference matches report \`matched_via: exact | alias | substring\`. A substring match is a
  suggestion, not an identification; \`ambiguous\` with \`candidates\` means several records tied.

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
/**
 * Freshness for the synced block — the content hash, and nothing else.
 *
 * `synced_at` and `git_sha` were here and are deliberately gone. This block
 * lives in tracked files that are regenerated on every sync, so a field that
 * moves for reasons unrelated to the block’s content makes every regeneration a
 * diff. `synced_at` carried no information at all; `git_sha` moved on every
 * commit and, because the block is regenerated *before* the commit it would
 * name, was permanently one behind and permanently dirty.
 *
 * Both still ship in the MCP freshness envelope (GL-102), computed per call and
 * touching no disk. That is where a volatile field belongs.
 *
 * `annotation_hash` stays because it moves when, and only when, the thing it
 * describes moves — which is the entire point of a staleness marker.
 */
export interface ModelContextFreshness {
  /** Content hash of the annotation set — identical hash means identical model. */
  annotation_hash: string;
}

export function buildModelContext(model: ThreatModel, freshness?: ModelContextFreshness): string {
  // Ordered before anything is sliced. Parse order varies across processes
  // (fast-glob completion order), so without this the "first 25 exposures"
  // window showed a different subset run to run and every sync was a diff.
  const ordered = canonicalizeModelOrder(model);
  const sections: string[] = [];

  // Existing defined IDs
  const assetIds = ordered.assets.filter(a => a.id).map(a => `#${a.id} (${a.path})`);
  const threatIds = ordered.threats.filter(t => t.id).map(t => `#${t.id} (${t.name})${t.severity ? ` [${t.severity}]` : ''}`);
  const controlIds = ordered.controls.filter(c => c.id).map(c => `#${c.id} (${c.name})`);
  // Read from `ordered`, not `model`: this block is written to tracked files, so
  // it inherits the same canonical-order requirement as every other relation.
  const actorIds = (ordered.actors || []).filter(a => a.id).map(a => `#${a.id} (${a.name})`);

  if (assetIds.length + threatIds.length + controlIds.length + actorIds.length > 0) {
    sections.push('### Current Definitions (REUSE these IDs — do NOT redefine)\n');
    sections.push('_Full records with descriptions and locations: \`guardlink_lookup("asset <id>")\`, or read \`.guardlink/definitions.*\`._\n');
    if (assetIds.length) sections.push(`**Assets:** ${assetIds.join(', ')}`);
    if (threatIds.length) sections.push(`**Threats:** ${threatIds.join(', ')}`);
    if (controlIds.length) sections.push(`**Controls:** ${controlIds.join(', ')}`);
    if (actorIds.length) sections.push(`**Actors:** ${actorIds.join(', ')}`);
  }

  // Entitlements — carried into agent context because an agent that cannot see
  // which capabilities are already granted by design will keep re-filing them
  // as exposures. Inert claims are marked so nothing reads them as effective.
  const entitlements = ordered.entitlements || [];
  if (entitlements.length > 0) {
    sections.push('\n### Entitlements (capabilities held by design — never a reason to skip testing)\n');
    const lines = entitlements.slice(0, 25).map(en =>
      `- ${en.actor} entitled to \`${en.canonical_capability}\`${en.asset ? ` on ${en.asset}` : ''}` +
      (en.citation ? ` — cites ${en.citation.raw}` : ' — **uncited, inert**')
    );
    sections.push(lines.join('\n'));
    if (entitlements.length > 25) sections.push(`- ... and ${entitlements.length - 25} more`);
  }

  // Open exposures (unmitigated).
  //
  // D57: this was a nested `.some()` on raw `===`, so the "Open Exposures" block
  // written into every repo's CLAUDE.md disagreed with `guardlink validate` in
  // that same repo. Acceptance semantics are preserved deliberately — this block
  // has always listed accepted exposures as still needing attention, and its
  // heading says "need @mitigates or @audit", so it asks isMitigated, not
  // isCovered. Only the site and `#`-normalisation dimensions change here.
  const coverage = buildCoverageIndex(ordered);
  const unmitigated = ordered.exposures.filter(e => !coverage.isMitigated(e));
  if (unmitigated.length > 0) {
    sections.push('\n### Open Exposures (need @mitigates or @audit)\n');
    const lines = unmitigated.slice(0, 25).map(e =>
      `- ${e.asset} exposed to ${e.threat}${e.severity ? ` [${e.severity}]` : ''} (${e.location.file}:${e.location.line})`
    );
    sections.push(lines.join('\n'));
    if (unmitigated.length > 25) {
      sections.push(`- … and ${unmitigated.length - 25} more — \`guardlink_lookup("unmitigated")\` or \`guardlink status .\` returns all of them`);
    }
  }

  // Confirmed exploitable findings
  if ((ordered.confirmed || []).length > 0) {
    sections.push('\n### 🔴 Confirmed Exploitable (verified, not false positives)\n');
    const confirmedLines = ordered.confirmed.slice(0, 25).map(c =>
      `- ${c.asset} confirmed ${c.threat}${c.severity ? ` [${c.severity}]` : ''} (${c.location.file}:${c.location.line})`
    );
    sections.push(confirmedLines.join('\n'));
    if (ordered.confirmed.length > 25) {
      sections.push(`- … and ${ordered.confirmed.length - 25} more — \`guardlink_lookup("confirmed")\` returns all of them`);
    }
  }

  // Existing flows (top 20)
  if (ordered.flows.length > 0) {
    sections.push('\n### Existing Data Flows (extend, don\'t duplicate)\n');
    const flowLines = ordered.flows.slice(0, 20).map(f =>
      `- ${f.source} -> ${f.target}${f.mechanism ? ` via ${f.mechanism}` : ''}`
    );
    sections.push(flowLines.join('\n'));
    if (ordered.flows.length > 20) {
      sections.push(`- … and ${ordered.flows.length - 20} more — \`guardlink_lookup("flows into X")\` for one asset, or \`guardlink_graph(from: X)\` for a neighbourhood`);
    }
  }

  // Features
  const uniqueFeatures = new Set((ordered.features || []).map(f => f.feature));
  if (uniqueFeatures.size > 0) {
    sections.push('\n### Features (filter with `--feature`)\n');
    sections.push([...uniqueFeatures].sort().map(f => `- "${f}"`).join('\n'));
  }

  // Summary stats
  const stats = [
    `${ordered.annotations_parsed} annotations`,
    `${ordered.assets.length} assets`,
    `${ordered.threats.length} threats`,
    `${ordered.controls.length} controls`,
    `${ordered.exposures.length} exposures`,
    `${(ordered.confirmed || []).length} confirmed`,
    `${ordered.mitigations.length} mitigations`,
    ...((ordered.actors || []).length > 0 ? [`${ordered.actors!.length} actors`] : []),
    ...((ordered.entitlements || []).length > 0 ? [`${ordered.entitlements!.length} entitlements`] : []),
    `${ordered.flows.length} flows`,
    ...(uniqueFeatures.size > 0 ? [`${uniqueFeatures.size} features`] : []),
  ].join(', ');
  sections.push(`\n### Model Stats\n\n${stats}`);

  // Freshness. Without it a reader cannot tell a block synced from this commit
  // from one synced in March — and a stale block that looks current is worse than
  // an absent one, because nothing prompts them to go re-read the source.
  if (freshness) {
    sections.push([
      '\n### Block Freshness\n',
      `- \`annotation_hash\`: \`${freshness.annotation_hash}\``,
      '',
      'Every MCP response carries this same hash. If it differs from the one above, this',
      'block predates the current annotations — trust the tool, and run `guardlink sync`.',
      'For when it was synced and at which commit, read the envelope on any MCP',
      'response: those move independently of the model and are not written to disk.',
    ].join('\n'));
  }

  return sections.join('\n');
}

/**
 * Enhanced agent instructions that include live threat model context.
 * Used by `guardlink sync` to keep all agent instruction files up to date.
 */
export function agentInstructionsWithModel(
  project: ProjectInfo,
  model: ThreatModel | null,
  freshness?: ModelContextFreshness,
  mode: AnnotationMode | null = null,
): string {
  const base = agentInstructions(project, mode);

  if (!model || model.annotations_parsed === 0) {
    return base;
  }

  const modelCtx = buildModelContext(model, freshness);
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
export function cursorRulesContentWithModel(project: ProjectInfo, model: ThreatModel | null, freshness?: ModelContextFreshness, mode: AnnotationMode | null = null): string {
  const base = cursorRulesContent(project, mode);

  if (!model || model.annotations_parsed === 0) {
    return base;
  }

  const modelCtx = buildModelContext(model, freshness);
  return `${base}
## Live Threat Model Context (auto-synced by \`guardlink sync\`)

${modelCtx}
`;
}

/**
 * Enhanced cursor .mdc content with model context.
 */
export function cursorMdcContentWithModel(project: ProjectInfo, model: ThreatModel | null, freshness?: ModelContextFreshness, mode: AnnotationMode | null = null): string {
  return `---
description: GuardLink security annotation rules
globs:
alwaysApply: true
---

${cursorRulesContentWithModel(project, model, freshness, mode)}`;
}

// ─── Cursor-specific format ──────────────────────────────────────────

export function cursorRulesContent(project: ProjectInfo, mode: AnnotationMode | null = null): string {
  // .cursorrules uses a flatter format without markdown headers
  return `
# GuardLink Security Annotations

This project carries a GuardLink threat model.

## Where annotations go

${annotationPlacementSection(project, mode)}

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

export function cursorMdcContent(project: ProjectInfo, mode: AnnotationMode | null = null): string {
  return `---
description: GuardLink security annotation rules
globs:
alwaysApply: true
---

${cursorRulesContent(project, mode)}`;
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

export function configContent(project: ProjectInfo, mode: AnnotationMode = 'inline'): string {
  return JSON.stringify({
    version: '1.1.0',
    project: project.name,
    language: project.language,
    // Recorded so `sync` and the MCP server can state the mode in effect
    // instead of inferring it — a repo with no annotations yet has nothing to
    // observe, and guessing "inline" there would be a guess dressed as config.
    annotation_mode: mode,
    definitions: `definitions${project.definitionsExt}`,
    include: defaultIncludeForLanguage(project.language),
    exclude: [
      'node_modules', 'dist', 'build', '.git',
      '__pycache__', 'target', 'vendor', '.next',
      '.bravos', '.bugb',
    ],
  }, null, 2) + '\n';
}

// ─── .gitignore addition ─────────────────────────────────────────────

/**
 * .gitignore lines added by `init`.
 *
 * GL-304 decision: derived artifacts are COMMITTED. A fresh clone gets the
 * threat model without running anything, and a model change shows up in review —
 * "this PR added an exposure" becomes visible in the diff instead of depending on
 * a reviewer knowing to look. The cost is churn, and that cost is paid down by
 * canonical ordering (D23): regenerating unchanged annotations produces identical
 * bytes, so a diff means something moved.
 *
 * What stays ignored is the machine-generated exports that are large, rebuilt on
 * demand and of no review value: threat-model.json, guardlink.sarif.json,
 * threat-dashboard.html. The previous rule caught those only by accident —
 * `.guardlink/*.json` does not cross a `/`, so graph/MANIFEST.json survived while
 * model.json was ignored, which was glob depth deciding policy.
 */
export const GITIGNORE_ENTRY = `
# GuardLink — generated exports, rebuilt on demand
${GENERATED_OUTPUT_FILES.join('\n')}

# Committed deliberately (see .guardlink/graph/README.md):
#   .guardlink/model.json   — the parsed model, canonically ordered
#   .guardlink/graph/       — diagrams, MANIFEST, and their provenance headers
`;

/**
 * `.gitattributes` lines marking artifacts as generated.
 *
 * `linguist-generated` collapses them in pull-request diffs and excludes them
 * from language statistics — they are committed to be *read*, not reviewed line
 * by line.
 */
export const GITATTRIBUTES_ENTRY = `
# GuardLink derived artifacts — regenerate, never hand-merge.
# On conflict: git checkout --ours .guardlink/graph/ && guardlink artifacts .
.guardlink/model.json linguist-generated=true
.guardlink/graph/**  linguist-generated=true
`;

// ─── Helpers ─────────────────────────────────────────────────────────


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

// ─── .guardlink/README.md — agent cold-start (GL-402) ────────────────

export interface ReadmeContext {
  mode: AnnotationMode | null;
  /** How `mode` was established, so the reader can weigh it. */
  modeSource: 'config' | 'observed' | 'default';
  model: ThreatModel | null;
  annotationHash: string | null;
  mcpAtRoot: boolean;
  /**
   * Where the reference doc actually is (D45). Supplied by the caller from
   * `referenceDocPath()`, or observed from disk when the caller did not write
   * it — never inferred from annotation mode, which is what got this wrong.
   */
  referencePath: string;
}

/**
 * The file that explains `.guardlink/` to something that has never seen
 * GuardLink.
 *
 * Written for an agent with no MCP connection and no instruction file — under
 * external-mode default this is the only surviving discovery path, so it assumes
 * nothing and leads with a worked example rather than a feature list.
 *
 * Deliberately carries no wall-clock timestamp. It is regenerated on every
 * `guardlink sync`, and a timestamp would make a tracked file churn on every
 * run while telling the reader nothing they cannot get from `annotation_hash`,
 * which changes only when the annotations do.
 */
// @shield:begin -- "README example annotations, excluded from parsing — they would otherwise register as real records"
export function guardlinkReadmeContent(project: ProjectInfo, ctx: ReadmeContext): string {
  const defs = `definitions${project.definitionsExt}`;
  const m = ctx.model;
  const external = ctx.mode === 'external';
  const referencePath = ctx.referencePath;

  const modeLine = ctx.mode === null
    ? 'Not recorded. Check the `mode` field on any MCP response, which is observed from the annotations themselves.'
    : ctx.mode === 'external'
      ? `**external** — annotations live in \`.guardlink/annotations/\`, not in source files.${ctx.modeSource === 'observed' ? ' (Observed from the annotations; not recorded in config.json.)' : ''}`
      : `**inline** — annotations live in source-file comments.${ctx.modeSource === 'observed' ? ' (Observed from the annotations; not recorded in config.json.)' : ''}`;

  const stats = m && m.annotations_parsed > 0
    ? `${m.annotations_parsed} annotations · ${m.assets.length} assets · ${m.threats.length} threats · ${m.controls.length} controls · ${m.exposures.length} exposures · ${m.flows.length} flows`
    : 'No annotations parsed yet.';

  const exampleAsset = m?.assets.find(a => a.id)?.id;
  const exampleThreat = m?.threats.find(t => t.id)?.id;
  const exampleCwe = m?.threats.find(t => (t.external_refs || []).some(r => /cwe/i.test(r)))
    ?.external_refs.find(r => /cwe/i.test(r));

  // D27: shared with every agent instruction file rather than written twice.
  // This README stated placement correctly while CLAUDE.md said nothing at all;
  // one function is how that stops being possible.
  const writeSection = annotationPlacementSection(project, ctx.mode);

  return `# .guardlink/ — what this is

You are looking at a **GuardLink** threat model. It is a set of security facts that
developers recorded next to the code they describe — what each component is exposed to,
what mitigates it, how data flows between components — parsed into a queryable model.

**If you are an AI coding agent: read this file before inferring security context from
the source.** The model already answers most of what you would otherwise guess at, and it
records decisions that are not visible in the code, such as which risks a human has
accepted.

This file is generated. Run \`guardlink sync\` to refresh it; do not edit it by hand.

Current model: ${stats}
${ctx.annotationHash ? `Content hash: \`${ctx.annotationHash}\` — identical hash means identical model.` : ''}

---

## Start here: one real question, answered end to end

**"I am about to edit \`src/auth/login.ts\`. What do I need to know?"**

With the MCP server connected:

\`\`\`
guardlink_context(file: "src/auth/login.ts")
\`\`\`

Without it, from a shell. There is no single-command CLI equivalent — \`guardlink parse\`
emits the whole model, so narrow it to the one file yourself:

\`\`\`sh
guardlink parse . | jq '[.. | objects | select(.location?.file == "src/auth/login.ts")]'
\`\`\`

That gives you the annotations declared in that file with line numbers, and the assets,
threats and controls each one names. It is not the whole of what \`guardlink_context\`
returns: the tool also resolves each asset's neighbours and tells you *which kind* of empty
an empty answer is, and neither falls out of a filter over the model.

Without \`jq\`, \`guardlink status .\` is the closest thing — repo-wide counts and the
unmitigated list, not a per-file view.

**Read the empty answer carefully.** \`guardlink_context\` reports *which kind* of empty it
found, and they mean opposite things:

| \`status\` | Meaning |
|---|---|
| \`annotated\` | It has annotations. |
| \`scanned_without_annotations\` | Parsed, genuinely clean. Nothing to know. |
| \`not_scanned\` | The parser never read this file. Its annotations, if any, were **not** considered. |
| \`not_found\` | Nothing at that path. |

Treating \`not_scanned\` as "clean" is the single easiest way to draw a wrong conclusion
from this model.

---

## What is in this directory

| Path | What it is |
|---|---|
| \`${defs}\` | **Definitions.** Every \`@asset\`, \`@threat\` and \`@control\`, each with a \`#id\`. Read this first — it is the vocabulary everything else references. |
| \`config.json\` | Project name, language, which files are scanned, and the annotation mode. |
| \`prompt.md\` | Project description used when generating threat reports. |${external ? '\n| `annotations/` | The annotations themselves, as `.gal` sidecars mirroring source paths. |' : ''}${external ? '\n| `.mcp.json` | MCP server config. Not auto-discovered here — see "Enabling the MCP tools" below. |' : ''}
| \`threat-reports/\` | Saved AI threat analyses, if any have been generated. |
| \`model.json\` | The whole parsed model as JSON, canonically ordered. Generated. |
| \`graph/\` | Mermaid diagrams of the model, plus a MANIFEST. Generated — see below. |

## Annotation mode in effect

${modeLine}

${writeSection}

**Definitions go in \`${defs}\`, always — in both modes.** Reuse existing \`#id\`s; never
redefine one. If you need a new asset or threat, add it there first, then reference it.

### The grammar

One annotation per line. Everything after \`--\` is a quoted description and is optional but
almost always worth writing. \`[severity]\` is optional and is one of \`critical\`, \`high\`,
\`medium\`, \`low\` (or \`P0\`–\`P3\`); when omitted on an \`@exposes\`, it inherits the threat's
declared severity. External refs like \`cwe:CWE-89\` are **optional**, may be repeated, and go
after the severity — the \`scheme:value\` shape is all that is required, so \`owasp:A03\` and
\`cve:CVE-2021-44228\` work too.

Assets are referenced as \`#id\` or as a \`Dotted.Path\`; both resolve to the same node.

**Definitions** — only in \`${defs}\`:

\`\`\`
@asset   <Dotted.Path> (#id) -- "what it is"
@threat  <Name> (#id) [severity] cwe:CWE-89 -- "what can go wrong"
@control <Name> (#id) -- "what defends against it"
\`\`\`

**Relationships** — in source (or in \`.gal\` blocks), never in the definitions file:

| Verb | Shape |
|---|---|
| \`@exposes\` | \`@exposes <asset> to <threat> [severity] cwe:CWE-89 -- "why"\` |
| \`@mitigates\` | \`@mitigates <asset> against <threat> using <control> -- "how"\` |
| \`@confirmed\` | \`@confirmed <threat> on <asset> [severity] cwe:CWE-89 -- "evidence"\` |
| \`@flows\` | \`@flows <A> -> <B> via <mechanism> -- "what moves"\` — chains allowed: \`A -> B -> C\` |
| \`@boundary\` | \`@boundary between <A> and <B> (#id) -- "what changes across it"\` |
| \`@transfers\` | \`@transfers <threat> from <A> to <B> -- "who owns it now"\` |
| \`@validates\` | \`@validates <control> for <asset> -- "the test that proves it"\` |
| \`@audit\` | \`@audit <asset> -- "what a human needs to look at"\` |
| \`@owns\` | \`@owns <team> for <asset> -- "who reviews changes here"\` |
| \`@handles\` | \`@handles <pii\\|phi\\|financial\\|secrets\\|internal\\|public> on <asset> -- "what data"\` |
| \`@assumes\` | \`@assumes <asset> -- "what must hold for this to be safe"\` |
| \`@feature\` | \`@feature "Name" -- "what it groups"\` |
| \`@comment\` | \`@comment -- "context that fits no other verb"\` |
| \`@accepts\` | \`@accepts <threat> on <asset> -- "why"\` — **human only, never write this** |

One note that catches people out: \`@confirmed\` and \`@exposes\` take their arguments in
**opposite orders** — exposes is asset-then-threat, confirmed is threat-then-asset.

Cross-repo tags are written qualified and unquoted, in any reference position —
\`@flows ${crossRepoTag('other-repo', 'tokens')} -> #api via header\`, and equally
\`@exposes #api to ${crossRepoTag('other-repo', 'injection')} [high] -- "why"\`. Quoting is
only for a reference containing spaces. (This used to require quotes because the grammar
would not accept a dot after \`#\`; that was D19, and it is fixed.)

Write coupled blocks, not lone facts: a risk plus the control or audit that answers it, plus
the flow that gives it context.

### Writing *about* these verbs

A line starting with a verb that then fails to parse is either a broken annotation or a
sentence about GuardLink. They are told apart by **structural evidence** after the verb: a
\`#reference\`, a spaced \`--\` delimiter, or a grammar keyword **belonging to that verb**
(\`to\` for \`@exposes\`, \`against\`/\`using\` for \`@mitigates\`, \`->\` for \`@flows\`, and so on).

| Line | Verdict |
|---|---|
| \`@exposes #api to\` | **error** — has a \`#ref\`, so it was meant to be an annotation. Fails validation. |
| \`@exposes was renamed in v1.2\` | **warning** — no structure. Read as prose. Does not fail validation. |

The keyword set is per verb, so \`@feature still claims to describe the model\` is prose:
\`to\` is not part of \`@feature\`'s grammar. Prose warnings are always reported under their
own heading — never suppressed, because a line you *meant* as an annotation shows up there
too.

If you are documenting real annotation syntax and the examples do look structural, wrap
them in \`@shield:begin\` / \`@shield:end\`. That is the deterministic override; the split
above is a heuristic.

**The complete reference is \`${referencePath}\`** — every verb, every alias, the conformance
levels, and worked examples per language. Read it before inventing syntax.

**Never write \`@accepts\`.** Accepting a risk is a human governance decision. If you find a
risk with no control, write \`@exposes\` to record it and \`@audit\` to flag it for review.

---

## Asking questions without MCP

\`\`\`sh
guardlink status .                       # coverage, counts, unmitigated exposures
guardlink parse .                        # the whole model as JSON, on stdout
guardlink validate .                     # syntax errors and dangling #id references
guardlink report . --format md           # human-readable threat model report
guardlink diff HEAD~1                    # what your change did to the model
guardlink dashboard .                    # interactive HTML view
\`\`\`

## Asking questions with MCP

The MCP server exposes the model as tools. The ones worth knowing by name:

| Tool | Use it when |
|---|---|
| \`guardlink_context(file)\` | You opened or are about to edit a file. |
| \`guardlink_graph(from, depth, direction)\` | You are about to change a shared component and need blast radius. |
| \`guardlink_lookup(query)\` | You have a specific question. See the query forms below. |
| \`guardlink_validate\` | Before you finish. |
| \`guardlink_diff(ref)\` | After a change — did I make this worse? |
| \`guardlink_status\` | Cold start on an unfamiliar repo. |
| \`guardlink_annotate_apply(file, line, annotations)\` | **You are writing annotations.** Prefer it over editing \`.gal\` files by hand. |

### Writing annotations with the MCP server

\`guardlink_annotate_apply\` writes the sidecar for you. Pass the **source** file
you are describing — not the \`.gal\` path, which it derives — the line the block
anchors to, and the raw GAL lines. Two things worth knowing before you reach for
a text editor instead:

- **Do not write \`@source\` yourself.** The header is synthesised from \`file\`,
  \`line\` and \`symbol\`. Passing one is an error, not a shortcut.
- **Pass \`symbol\`.** It is optional and it is what makes \`guardlink_reanchor\`
  able to find the block again after a refactor moves the code. Omitting it is
  also how you say "this statement is about the whole asset, not one function" —
  an unanchored \`@mitigates\` is never narrowed to a single symbol.

\`dry_run: true\` returns the diff without writing. Every line is re-parsed before
anything reaches disk, so a syntax error is rejected with its reason — but an
undefined \`#id\` is not, so run \`guardlink_validate\` afterwards.

\`guardlink_lookup\` understands a fixed set of named forms and **refuses anything else
rather than guessing**. Send it a deliberately bad query and it returns the full list.
Representative forms:

\`\`\`
unmitigated                     confirmed                  features
asset <id>                      threat <id>                control <id>
threats for <asset>             exposures for <asset>      mitigations for <asset>
flows into <asset>              flows from <asset>         boundary for <asset>
owner of <asset>                handles pii                assumptions for <asset>
audits [for <asset>]            validations for <asset>    comments [for <file>]
cwe:CWE-89                      owasp:A03                  CWE-89
\`\`\`

${exampleAsset ? `Concretely, in this project: \`asset #${exampleAsset}\`${exampleThreat ? `, \`threat #${exampleThreat}\`` : ''}${exampleCwe ? `, \`${exampleCwe}\`` : ''}.\n` : ''}
### Enabling the MCP tools

${ctx.mcpAtRoot
    ? 'A `.mcp.json` at the project root configures this automatically for clients that\nauto-discover it, such as Claude Code. If your client does not, point it at\n`guardlink mcp` over stdio.'
    : 'The config lives at `.guardlink/.mcp.json`. MCP clients do **not** auto-discover it\nthere — copy it to the project root, or point your client at `guardlink mcp` over stdio.'}

---

## The generated graph

\`\`\`sh
guardlink artifacts .            # (re)write model.json and graph/
guardlink validate . --artifacts # fail if any of them is stale
\`\`\`

| File | Shows |
|---|---|
| \`graph/threat-graph.mmd\` | Assets, the threats they are exposed to, the controls that mitigate them. |
| \`graph/dataflow.mmd\` | \`@flows\` between components, with trust boundaries. |
| \`graph/attack-surface.mmd\` | Entry points and what is reachable from them. |
| \`graph/by-feature/<name>.mmd\` | The threat graph narrowed to one \`@feature\`. |
| \`graph/MANIFEST.json\` | Size and source hash of each artifact. |

These are Mermaid, and readable as plain text without rendering. Each opens with a
\`%%\` header naming the \`annotation_hash\` it was built from; Mermaid treats \`%%\` as a
comment so it does not affect the diagram.

**Check the hash before trusting one.** A generated diagram in a repository looks
like source, and a reader who does not know a file is derived will not think to ask
whether it is current. If the header's hash differs from the one above, the diagram
is stale — regenerate it. Never hand-edit an artifact to make the check pass: the
hash describes the annotations, so editing the file only makes it lie.

They are committed on purpose, so a fresh clone has the model without running
anything and a reviewer sees model changes in the diff. Resolve merge conflicts by
regenerating, never by hand-merging.

## Reading the answers

Every MCP response carries a \`guardlink\` envelope alongside the payload:
\`annotation_hash\`, \`git_sha\`, \`mode\`, \`root\`. Identical hash means identical model, so
you can tell a fresh answer from a cached one without asking twice.

Anything that resolves a reference reports \`matched_via\`: \`exact\`, \`alias\` or
\`substring\`. **A substring match is a suggestion, not an identification.** When
\`ambiguous\` is set, several records tied and one was chosen arbitrarily —
\`candidates\` names them all, and you should re-ask precisely.

For CWE queries, check \`external_id.declared\` before reading \`count: 0\` as coverage:
\`false\` means this model has never heard of that weakness class, which is not the same
as declaring it and finding nothing exposed.
`;
}
// @shield:end
