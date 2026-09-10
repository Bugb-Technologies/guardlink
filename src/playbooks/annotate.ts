/**
 * The six annotate playbooks. Each body is a complete method: purpose, phases,
 * what to write, what not to, and when to stop. They share the evidence bar.
 *
 * @comment -- "Bodies are markdown that lands verbatim in the agent prompt and in the SKILL.md; keep each one readable on its own"
 */
import type { Playbook } from './types.js';
import { EVIDENCE_BAR, WRITE_LAST, STOP_CONDITIONS } from './evidence.js';

const NEVER = `Never write \`@accepts\` or \`@entitles\`; never delete or rewrite an existing annotation; never write executable code.`;

export const ANNOTATE_PLAYBOOKS: readonly Playbook[] = [
  {
    id: 'map',
    kind: 'annotate',
    title: 'Map',
    summary: 'Architecture first: assets, flows, boundaries and data classes. Writes no exposures.',
    triggers: [/\bmap\b/, /\barchitecture\b/, /\bflows? only\b/, /\bdata flows?\b/, /\btrust boundar/],
    body: `## Method — Map
**Purpose.** Build the skeleton every other playbook reads: what the components are, how data moves between them, where trust changes hands, and what sensitive data each part touches. This pass writes **no \`@exposes\`** — a threat claimed before the flow graph exists is guessed, not traced.

### Phase 1 — Inventory the components
Read the entry points (HTTP handlers, CLI commands, consumers, cron, listeners), the storage and the outbound calls. For each component that is not yet an asset, add one to the definitions file with a stable \`#id\` and a one-line description of what it is for. Reuse every existing id; never redefine one.

### Phase 2 — Trace the flows
For every entry point, follow the request to its sinks and write the path as \`@flows\` edges, one per hop, naming the mechanism (\`via POST./login\`, \`via pg.query\`, \`via redis.set\`). Extend the flows the model already has; do not restate them. A hop you cannot see in the code is not a hop.

### Phase 3 — Mark the trust changes
Where the caller's trust level changes — internet to app, app to database, service to service, app to vendor, code to spawned process — write a \`@boundary between A and B\` with what enforces the line (TLS termination, auth middleware, connection pooling, tokenisation).

### Phase 4 — Classify the data
Where an asset stores, logs or forwards personal, financial, health or secret data, write \`@handles <class> on Asset\` with the fields by name. Where the code trusts something it never checks, write \`@assumes\`. Where you know the accountable team, write \`@owns\`.

### What not to write
No @exposes in this pass, and no \`@confirmed\` or \`@mitigates\` either: run the \`exploitable\` playbook next for those. ${NEVER}

${WRITE_LAST}

${STOP_CONDITIONS}`,
  },
  {
    id: 'exploitable',
    kind: 'annotate',
    title: 'Exploitable',
    summary: 'The default: trace every path, then claim only what an attacker can reach with input they control.',
    triggers: [/\bexploit/, /\breal threats?\b/, /\breachab/, /\bactually\b/, /\battacker\b/],
    body: `## Method — Exploitable
**Purpose.** Annotate the threats an attacker can actually reach, and only those, with enough evidence in each description that a reader can check it without re-deriving it.

### Phase 1 — Map what you are about to claim
If the model has no flows for the code in scope, trace them first (entry point → middleware → handler → service → sink) and write the \`@flows\` and \`@boundary\` edges. You cannot claim a path you have not drawn.

### Phase 2 — Hypothesise
At every place attacker-controlled input meets a sink — a query, a shell, a template, a file path, a deserialiser, a redirect, an authorisation decision — write down a candidate: asset, threat, entry point, input, sink, and the control you expect to find.

### Phase 3 — Verify each candidate by reading the path
For every candidate, read the code from entry point to sink. Establish: does the input really reach the sink unchanged? Is there validation, encoding, parameterisation, an authorisation check, a size cap? Is it applied on this path, or only on another? Drop the candidate the moment a control on the path holds; turn it into a \`@mitigates\` naming that control instead.

### Phase 4 — Write
For each survivor, write the coupled block: the \`@exposes\` with all four evidence fields, the \`@mitigates\` where a control covers part of it, an \`@audit\` where you could not establish the path, the \`@flows\` that carry the input, and a \`@comment\` for anything a reader would need to know.

${EVIDENCE_BAR}

### What not to write
${NEVER} Do not annotate code that never touches a security boundary: formatters, pure helpers, UI layout.

${WRITE_LAST}

${STOP_CONDITIONS}`,
  },
  {
    id: 'chains',
    kind: 'annotate',
    title: 'Chains',
    summary: 'Start from the open exposures and follow the flows: what does each one let an attacker do next?',
    triggers: [/\bchain/, /\bpivot/, /\blateral\b/, /\bas deep as\b/, /\bmulti-?hop\b/, /\bescalat/],
    body: `## Method — Chains
**Purpose.** Find the threats that are not visible from any one place: an exposure that only matters because of what it reaches, and a path an attacker can walk from a small foothold to a large impact.

### Phase 1 — Start from what is already open
Take the open exposures the model lists (and any you find with the \`exploitable\` method on the way). For each one, name what the attacker holds after exploiting it: a token, a file path, a redirect, a row they should not see, a process, a queue message.

### Phase 2 — Follow the flows
From that foothold, follow the \`@flows\` out of the asset. At each next asset ask: does what the attacker now holds reach this component as trusted input? Can it read, write, execute or impersonate here? A trust boundary that the first exposure already crossed is not a defence for the second hop.

### Phase 3 — Verify the hop
Read the receiving code. Confirm the second asset treats the value as trusted (no re-validation, no re-authorisation, no origin check). Drop the hop if it re-checks; write a \`@mitigates\` naming the re-check.

### Phase 4 — Write the chain
GuardLink has no verb for "A enables B" yet, so write a chain as its parts: the \`@exposes\` at each hop with the four evidence fields, the \`@flows\` edges the foothold travels along, and a \`@comment\` at the first hop that names the whole chain in order (\`"Chain: #upload path traversal → #worker reads attacker file → #config parsed with secrets"\`). The severity of the first hop reflects where the chain ends, within the threat's declared band.

${EVIDENCE_BAR}

### What not to write
${NEVER} Do not invent a hop: every edge in a chain is a flow you read in the code.

${WRITE_LAST}

${STOP_CONDITIONS}`,
  },
  {
    id: 'diff',
    kind: 'annotate',
    title: 'Diff',
    summary: 'Only the files this branch changed; everything else is context.',
    triggers: [/\bchanged\b/, /\bdiff\b/, /\bpull request\b/, /\bPR\b/, /\bthis branch\b/, /\bcommit\b/],
    body: `## Method — Diff
**Purpose.** Annotate a change, not a codebase. The files listed in scope are the ones this branch touched; the rest of the model is context you read and extend but do not re-annotate.

### Phase 1 — Read the change
For each file in scope, read the diff and the surrounding function, then the callers and callees it touches. Decide whether the change adds an entry point, a sink, a flow, a trust crossing, or a control — or removes one.

### Phase 2 — Trace only what changed
Follow the new or altered path from entry point to sink with the \`exploitable\` method's evidence bar. Existing annotations on the path stay; if the change invalidates one (a control removed, a sink added), write an \`@audit\` next to it saying so rather than editing it.

### Phase 3 — Write
Add the coupled block for what the change introduced: \`@exposes\` with the four evidence fields, \`@mitigates\` for a control the change added, \`@flows\` for a new hop, \`@boundary\` for a new crossing, \`@handles\` for new sensitive data. A change that touches nothing security-relevant gets nothing.

${EVIDENCE_BAR}

### What not to write
${NEVER} Do not annotate files outside the scope list. Do not re-describe an unchanged path.

${WRITE_LAST}

${STOP_CONDITIONS}`,
  },
  {
    id: 'coverage',
    kind: 'annotate',
    title: 'Coverage',
    summary: 'The files with no annotations yet, entry points first.',
    triggers: [/\bunannotated\b/, /\bcoverage\b/, /\bmissing files\b/, /\bno annotations\b/, /\bevery file\b/],
    body: `## Method — Coverage
**Purpose.** Bring the files the model has never seen into it, in the order that matters: entry points and sinks before helpers, and structure before claims.

### Phase 1 — Rank the unannotated files
From the unannotated list, put first the files that receive input from outside (handlers, commands, consumers), then the ones that reach storage, the network or the shell, then everything else. A pure helper or a formatter may need nothing; record that decision in a \`@comment\` only when a reader would otherwise wonder.

### Phase 2 — Structure first
For each file, write the \`@flows\`, \`@boundary\` and \`@handles\` that place it in the model. Reuse existing asset ids; add a definition only for a component the model genuinely lacks.

### Phase 3 — Then claims, with the bar
Only after the file's flows are drawn, apply the \`exploitable\` method's evidence bar to its sinks. Write \`@exposes\` where all four fields hold, \`@mitigates\` where a control holds, \`@audit\` where you could not tell.

${EVIDENCE_BAR}

### What not to write
${NEVER} Do not annotate for the sake of coverage: a file with no security-relevant behaviour stays clean, and that is the correct outcome.

${WRITE_LAST}

${STOP_CONDITIONS}`,
  },
  {
    id: 'verify',
    kind: 'annotate',
    title: 'Verify',
    summary: 'Re-read every existing claim against the code; flag what the code no longer supports.',
    triggers: [/\bverify\b/, /\bcheck (the )?existing\b/, /\bstill (accurate|true|valid)\b/, /\bstale\b/, /\baccurate\b/, /\bre-?check\b/],
    body: `## Method — Verify
**Purpose.** The model is a set of claims about code, and code moves. Read each claim in scope against what the code does today, and record where they disagree. This pass adds no new exposures unless the verification itself reveals one.

### Phase 1 — Read each claim with its code
For every \`@mitigates\`: does the named control still exist on this path, and does it still cover the asset against that threat? For every \`@exposes\`: is the path still reachable, is the sink still there, is the severity still right? For every \`@flows\` and \`@boundary\`: does the code still move data that way?

### Phase 2 — Record the disagreements
Where a claim no longer holds, do not delete or edit it. Write an \`@audit\` on the asset beside it that says what the claim asserts, what the code now does, and what should change (\`"@mitigates names #input-validation but validateEmail() was removed in the refactor; the exposure is open again"\`). A human decides what to do with the claim; your job is to make the disagreement visible.

### Phase 3 — Close the loop
Where the verification shows a path that is now defended, write the \`@mitigates\` that names the control. Where it shows a new sink on a known path, apply the evidence bar and write the \`@exposes\` with its pair. Then run \`guardlink verify --dry-run\` and report what it says.

${EVIDENCE_BAR}

### What not to write
${NEVER} Do not "fix" a claim by rewording it: an edited claim hides the history of being wrong.

${WRITE_LAST}

${STOP_CONDITIONS}`,
  },
];
