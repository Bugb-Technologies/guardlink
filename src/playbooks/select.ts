/**
 * Selecting a playbook: an explicit id wins, then keyword rules in a fixed
 * order, then the default. Rules, not a model, so the same words always pick
 * the same method and the choice can be printed with its reason.
 *
 * @exposes #cli to #redos [low] cwe:CWE-1333 -- "selectAnnotatePlaybook() runs each Playbook.triggers RegExp against the prompt text the user typed"
 * @mitigates #cli against #redos using #regex-anchoring -- "Every trigger is a short literal or word-boundary pattern with no nested quantifiers; the prompt is capped before matching"
 * @comment -- "Order matters where prompts match several playbooks: chains beats exploitable because a prompt that asks for chains also asks for exploitability, and diff beats coverage because a change is narrower than the tree"
 */
import type { AnnotatePlaybookId, ReportShapeId, Playbook, PlaybookSelection, PlaybookId } from './types.js';
import { ANNOTATE_PLAYBOOKS } from './annotate.js';
import { REPORT_SHAPES } from './report.js';

const MAX_PROMPT_CHARS = 4000;

const ALL: readonly Playbook[] = [...ANNOTATE_PLAYBOOKS, ...REPORT_SHAPES];

export function getPlaybook(id: PlaybookId): Playbook {
  const pb = ALL.find(p => p.id === id);
  if (!pb) throw new Error(`Unknown playbook: ${id}`);
  return pb;
}

/** The order rules are tried in when a prompt matches more than one. */
const ANNOTATE_PRIORITY: AnnotatePlaybookId[] = ['chains', 'diff', 'verify', 'coverage', 'map', 'exploitable'];
const DEFAULT_ANNOTATE: AnnotatePlaybookId = 'exploitable';

function matches(pb: Playbook, text: string): string[] {
  return pb.triggers.map(t => t.exec(text)?.[0]).filter((m): m is string => !!m);
}

export function selectAnnotatePlaybook(prompt: string, explicit?: string): PlaybookSelection<AnnotatePlaybookId> {
  if (explicit !== undefined && explicit !== '') {
    const pb = ANNOTATE_PLAYBOOKS.find(p => p.id === explicit);
    if (!pb) throw new Error(`Unknown playbook: ${explicit}. Use one of ${ANNOTATE_PLAYBOOKS.map(p => p.id).join(', ')}.`);
    return { id: pb.id as AnnotatePlaybookId, reason: `--playbook ${pb.id}`, matched: [] };
  }
  const text = prompt.slice(0, MAX_PROMPT_CHARS).toLowerCase();
  for (const id of ANNOTATE_PRIORITY) {
    const pb = getPlaybook(id);
    const m = matches(pb, text);
    if (m.length > 0) return { id, reason: `matched "${m[0]}"`, matched: m };
  }
  return { id: DEFAULT_ANNOTATE, reason: 'default; no scope words matched', matched: [] };
}

export function selectReportShape(explicit?: string): PlaybookSelection<ReportShapeId> {
  if (explicit === undefined || explicit === '' || explicit === 'full') return { id: 'full', reason: 'default', matched: [] };
  const pb = REPORT_SHAPES.find(p => p.id === explicit);
  if (!pb) throw new Error(`Unknown report shape: ${explicit}. Use one of ${REPORT_SHAPES.map(p => p.id).join(', ')}.`);
  return { id: pb.id as ReportShapeId, reason: `--shape ${pb.id}`, matched: [] };
}
