/**
 * Report shapes: who the report is for changes what goes on the page, not
 * what the analysis is. The framework (STRIDE, DREAD, …) stays the method;
 * the shape is appended to the user message.
 *
 * @comment -- "'full' is the framework's own structure and appends nothing; the other three are audience shapes"
 */
import type { Playbook } from './types.js';

export const REPORT_SHAPES: readonly Playbook[] = [
  {
    id: 'full',
    kind: 'report',
    title: 'Full',
    summary: "The framework's own structure, every section.",
    triggers: [],
    body: '',
  },
  {
    id: 'executive',
    kind: 'report',
    title: 'Executive',
    summary: 'One page for someone who funds the fixes: posture, the top five, what changed, what to do.',
    triggers: [/\bexecutive\b/, /\bone page\b/, /\bsummary for\b/, /\bcto\b/, /\bboard\b/],
    body: `## Shape — Executive
This report is for someone who decides what to fund, not someone who fixes it. Keep it to **one page** above the findings block.
1. **Posture in one sentence** — the risk grade and why, in plain words.
2. **The five findings that matter** — one line each: what an attacker gets, how sure we are, what closes it. No CWE numbers in the prose.
3. **What is covered well** — two or three controls that are doing their job, so the reader knows what not to cut.
4. **What to fund** — the three changes with the best risk reduction per effort, each with a rough size (days, not story points).
5. **What we do not know** — the assumptions and audit items that a reviewer should resolve.
Every finding still goes in the findings block below the page, in full.`,
  },
  {
    id: 'pr',
    kind: 'report',
    title: 'Pull request',
    summary: 'What this change adds or removes, for the reviewer of one branch.',
    triggers: [/\bpull request\b/, /\bthis branch\b/, /\bthe diff\b/, /\bfor review\b/, /\bthis change\b/],
    body: `## Shape — Pull request
This report reviews **a change**, not the codebase. The scope lists the files the branch touched; treat everything else as context.
1. **What the change does** to the attack surface — new entry points, sinks, flows, trust crossings, controls added or removed. Two paragraphs at most.
2. **New exposures** the change introduces, each with evidence from the changed lines.
3. **Exposures the change closes**, and whether the closing control is complete.
4. **Claims the change invalidates** — existing annotations that no longer match the code.
5. **Verdict** — merge, merge with the listed annotations added, or hold, and why.
Only findings in the changed files go in the findings block; reference unchanged code only as context.`,
  },
  {
    id: 'audit',
    kind: 'report',
    title: 'Audit',
    summary: 'Findings mapped to controls, evidence and owners, for an auditor.',
    triggers: [/\baudit(or)?\b/, /\bcompliance\b/, /\bsoc ?2\b/, /\biso ?27001\b/, /\bevidence pack\b/],
    body: `## Shape — Audit
This report is for someone who checks claims against evidence. Precision over narrative.
1. **Scope and method** — what was reviewed, how (annotations, code reading, scan evidence), and what was out of scope.
2. **Control inventory** — every declared control: what it is, where it is implemented (file:line), which threats it covers, and whether the code confirms it.
3. **Findings** — each with an identifier, the asset and threat, the evidence (request and response, or the code path), the severity with its justification, the owning team where \`@owns\` names one, and the remediation.
4. **Accepted risks** — every \`@accepts\` with who accepted it, why, and whether the acceptance is still reasonable.
5. **Gaps in the model** — assets with no owner, sensitive data with no control, entry points with no annotation.
Use the same identifiers in the prose and the findings block so a reader can cross-reference.`,
  },
];
