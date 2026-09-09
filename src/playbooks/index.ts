/**
 * GuardLink Playbooks — barrel.
 *
 * @comment -- "Annotate playbooks compose into buildAnnotatePrompt; report shapes into buildUserMessage; skills into guardlink init"
 */
export type { PlaybookKind, PlaybookId, AnnotatePlaybookId, ReportShapeId, Playbook, PlaybookSelection } from './types.js';
export { ANNOTATE_PLAYBOOKS } from './annotate.js';
export { REPORT_SHAPES } from './report.js';
export { EVIDENCE_BAR, WRITE_LAST, STOP_CONDITIONS } from './evidence.js';
export { selectAnnotatePlaybook, selectReportShape, getPlaybook } from './select.js';
export { skillFileFor, skillNameFor, SKILL_GENERATED_MARKER, type SkillFile } from './skills.js';
