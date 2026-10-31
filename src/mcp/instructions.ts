/**
 * GuardLink MCP — server instructions (GL-401).
 *
 * The MCP `instructions` field arrives at initialize, before any tool call. The
 * tool list already tells an agent *what* each tool does; nothing told it *when*
 * to reach for one. Everything built in this epic is unreachable by an agent
 * that has not been told it exists, and `guardlink_context` — the most useful
 * tool here — was announced by nothing at all.
 *
 * So this is written as trigger moments, not as a catalogue. There are more than
 * twenty tools; listing them would restate `tools/list` at the one moment an
 * agent has no context to rank them with.
 *
 * ── On staying true ─────────────────────────────────────────────────
 *
 * The SDK takes `instructions` at construction and stores it privately, so the
 * text cannot be assembled from tools that have not been registered yet. What
 * can be derived at build time is derived — the supported query-form count comes
 * from SUPPORTED_QUERY_FORMS, the annotation mode from the project's own config.
 * The tool *names* are prose, and are held accurate by a test that cross-checks
 * every `guardlink_*` mentioned here against the server's real `tools/list`. A
 * renamed or deleted tool fails that test rather than silently misdirecting an
 * agent forever.
 *
 * @flows ConfigFile -> #mcp via readFileSync -- "Annotation mode read for the initialize instructions"
 * @comment -- "Pure string builder; the only I/O is one optional config read by the caller"
 */

import { SUPPORTED_QUERY_FORMS } from './lookup.js';
import { readConfiguredMode, type AnnotationMode } from '../parser/annotation-mode.js';

export { readConfiguredMode };

export interface InstructionsContext {
  /** Mode declared in `.guardlink/config.json`, or null when not recorded. */
  mode: AnnotationMode | null;
  /** Where annotations are written. */
  definitionsPath: string;
}


function modeParagraph(mode: AnnotationMode | null, _definitionsPath: string): string {
  if (mode === 'external') {
    return 'Annotations are stored EXTERNALLY in .guardlink/annotations/<source path>.gal under `@source file:<path> line:<n> [symbol:<name>]` blocks. Sidecars work anywhere the convention puts them, including under test/, vendor/ and dist/ — skipped for source, not annotations. Write with guardlink_annotate_apply: pass the source path, not .gal; @source is synthesised. Send symbol: for reanchoring.';
  }
  if (mode === 'inline') {
    return 'This project stores annotations INLINE in source-file comments. Edit those comments directly; guardlink_annotate_apply writes external sidecars only.';
  }
  if (mode === 'mixed') {
    return 'This project is MIXED: resolve inline/sidecar drift before writing. guardlink_annotate_apply writes external sidecars only.';
  }
  return 'This project has not recorded an annotation mode. Read mode in the response envelope and inspect config before writing: inline uses source comments; external uses guardlink_annotate_apply sidecars.';
}

/**
 * The text an MCP client receives at initialize.
 *
 * Kept under 500 words deliberately: this is orientation delivered before the
 * agent has any context to rank detail against, and length here costs attention
 * at the exact moment it is scarcest.
 */
export function buildServerInstructions(ctx: InstructionsContext): string {
  return `GuardLink is this project's threat model: recorded exposures, controls and flows. Query it, then verify claims against source.

WHEN TO REACH FOR WHAT

Opened a file, or about to edit one → guardlink_context(file)
  Declared annotations, neighbours, exposures and controls. scanned_without_annotations means parsed; no annotations recorded; no security conclusion. not_scanned means the parser never read it.

About to change a shared component → guardlink_graph(from, depth, direction)
  Blast radius through flows and boundaries, not shared threats. Defaults: depth 2, both, summary. Check traversal.completeness: depth_limited means more is reachable; truncated means incomplete; frontier_unexplored names gaps.

A scanner reported a CWE → guardlink_lookup("cwe:CWE-89")
  Check external_id.declared: false means undeclared, not declared-and-clean.

Routine change → maintain code and annotations together; guardlink_translate returns an authoring prompt. Older servers: \`guardlink translate "<changed paths and threats>"\`. Scope the request explicitly. Generation only: review/validate templates, then execute selected tests separately. Keep durable regressions after mitigation removes candidates.

Before a pull request → run the entire root security/ suite with its configured runner. Report absent suites (not applicable), skips and unavailable/partial execution; an existing suite that cannot complete blocks readiness. A pre-review tool's recorded complete execution satisfies this once; generation does not.

Before you finish → guardlink_validate · After a change → guardlink_diff("HEAD~1")
Cold on an unfamiliar repo → guardlink_status
Who introduced this → guardlink_blame(file)

WRITING ANNOTATIONS

${modeParagraph(ctx.mode, ctx.definitionsPath)}
Definitions (@asset, @threat, @control with #ids) live in ${ctx.definitionsPath}; reuse ids.
Never write or alter @accepts or @entitles: human governance decisions. A risk with no control needs @exposes plus @audit. @confirmed requires reproduction evidence, not code reading or generated templates.
Propose entitlements with guardlink_entitlement_propose, citing authz file:line; a human's acceptance writes them. Never for ownership questions (IDOR, tenant isolation).

READING THE ANSWERS

Every response carries annotation_hash, git_sha, mode, root in a guardlink envelope. Hash equality covers annotation content only, not unchanged code, anchors or agent configuration; re-query after edits.

Reference resolution reports matched_via: exact, alias or substring. A substring is a suggestion; ambiguous candidates need a precise re-query.

guardlink_lookup understands ${SUPPORTED_QUERY_FORMS.length} named query forms and refuses others. A deliberately bad query returns the list.`;
}
