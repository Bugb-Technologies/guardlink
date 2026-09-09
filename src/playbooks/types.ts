/**
 * GuardLink Playbooks — the methods the tool owns.
 *
 * A playbook is a named way of doing one job: annotating for exploitable
 * threats, mapping architecture, chasing chains, reporting for an executive.
 * The user's prompt narrows scope and intent; the playbook supplies the
 * phases, the evidence bar and the stop conditions, so a vague prompt and an
 * expert prompt run the same method.
 *
 * @comment -- "Pure data and pure functions: nothing here reads a file, runs a process or talks to a model"
 */

export type PlaybookKind = 'annotate' | 'report';

export type AnnotatePlaybookId = 'map' | 'exploitable' | 'chains' | 'diff' | 'coverage' | 'verify';
export type ReportShapeId = 'full' | 'executive' | 'pr' | 'audit';
export type PlaybookId = AnnotatePlaybookId | ReportShapeId;

export interface Playbook {
  id: PlaybookId;
  kind: PlaybookKind;
  /** Short title, used as the prompt heading: "Method — Exploitable". */
  title: string;
  /** One sentence for the CLI help, the skill description and the selection reason. */
  summary: string;
  /** The method itself, markdown, inserted into the prompt and written into the skill file. */
  body: string;
  /** Words in a user prompt that select this playbook when no id is given. */
  triggers: RegExp[];
}

export interface PlaybookSelection<Id extends PlaybookId = PlaybookId> {
  id: Id;
  /** Why this one: the explicit flag, the words that matched, or the default. */
  reason: string;
  matched: string[];
}
