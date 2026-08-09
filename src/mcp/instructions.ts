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


function modeParagraph(mode: AnnotationMode | null, definitionsPath: string): string {
  if (mode === 'external') {
    return [
      'This project stores annotations EXTERNALLY. Source files are not edited; annotations',
      `live in .guardlink/annotations/<mirrored source path>.gal, grouped under`,
      '`@source file:<path> line:<n> [symbol:<name>]` blocks. Known gap: a .gal under a path',
      'the parser excludes (test/, tests/, __tests__/, vendor/, build/, dist/, target/) is',
      'silently dropped — do not put one there until GL-503 lands.',
    ].join(' ');
  }
  if (mode === 'inline') {
    return 'This project stores annotations INLINE, in source-file comments, using the host language comment syntax.';
  }
  return [
    'This project has not recorded an annotation mode. Every tool response carries',
    '`mode` in its guardlink envelope, observed from the annotations themselves —',
    'read that rather than assuming.',
  ].join(' ');
}

/**
 * The text an MCP client receives at initialize.
 *
 * Kept under 400 words deliberately: this is orientation delivered before the
 * agent has any context to rank detail against, and length here costs attention
 * at the exact moment it is scarcest.
 */
export function buildServerInstructions(ctx: InstructionsContext): string {
  return `GuardLink is this project's threat model: security facts developers recorded next to the code — what each component is exposed to, what mitigates it, how data flows between them — parsed into a queryable model. Ask it instead of inferring security context from the source.

WHEN TO REACH FOR WHAT

Opened a file, or about to edit one → guardlink_context(file)
  Annotations declared there with line anchors, the assets they name with each
  asset's immediate neighbours, open exposures, and the controls the file is
  expected to uphold. An empty answer says which kind of empty it is:
  scanned_without_annotations means genuinely clean; not_scanned means the parser
  never read the file. Do not read them as the same thing.

About to change a shared component → guardlink_graph(from, depth, direction)
  Blast radius. Walks data flows and trust boundaries — not shared threats, which
  are classifications rather than couplings. depth 1-2 with direction in or out is
  the affordable range.

A scanner reported a CWE → guardlink_lookup("cwe:CWE-89")
  Whether this model declares that weakness class at all, and whether affected
  sites are mitigated, accepted, open or confirmed. Check external_id.declared:
  false means never heard of it, which is NOT the same as declared-and-clean.

Before you finish → guardlink_validate   ·   After a change → guardlink_diff("HEAD~1")
Cold on an unfamiliar repo → guardlink_status

WRITING ANNOTATIONS

${modeParagraph(ctx.mode, ctx.definitionsPath)}
Definitions — @asset, @threat, @control with #ids — live in ${ctx.definitionsPath}. Reuse
existing ids; never redefine one. Never write @accepts: risk acceptance is a human
governance decision. Found a risk with no control? @exposes plus @audit.

READING THE ANSWERS

Every response carries a guardlink envelope: annotation_hash, git_sha, mode, root.
Identical hash means identical model — use it to tell a fresh answer from a stale one.

Anything resolving a reference reports matched_via: exact, alias or substring. A
substring match is a suggestion, not an identification. ambiguous with candidates
means several records tied and one was picked arbitrarily — re-ask precisely.

guardlink_lookup understands ${SUPPORTED_QUERY_FORMS.length} named query forms and refuses anything else
rather than guessing. Send it a deliberately bad query to get the list.`;
}
