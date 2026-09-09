/**
 * The evidence bar every annotate playbook shares. This is the text that makes
 * "only real threats" the default rather than something a user has to ask for.
 *
 * @comment -- "Kept in one place so the lint in src/gate mirrors it rule for rule: what the prompt demands is what the gate checks"
 */

export const EVIDENCE_BAR = `### The evidence bar — what an @exposes must carry
An \`@exposes\` is a claim that an attacker can reach this code with input they control and that nothing in the path stops them. Write one only when you can name all four:
1. **Entry point** — the handler, command, consumer or listener where the input arrives (function name, route or file:line).
2. **Input** — the field, parameter, header or file the attacker controls.
3. **Sink** — the call where it does damage (the query builder, the exec, the template, the file write), by name.
4. **Absent control** — what would have stopped it and is not there, or is there and is bypassed.
Put those four in the description, in the code's own names. "Input not validated" fails the bar; "req.body.email reaches findUser() query builder at db.ts:40 with no parameterisation" meets it.

If you cannot name all four after reading the path, it is not an \`@exposes\`. Write an \`@audit\` on the asset saying what you saw and what you could not establish. A doubt recorded as an audit is useful; a doubt recorded as an exposure is noise that costs someone a triage.

Severity is the *observed* worst case on this path, and it never outranks the threat's declared severity: a threat declared \`[medium]\` does not get a \`[critical]\` instance without a definition change.

\`@confirmed\` is reserved for evidence in hand — a request and its response, a reproduction, a scan with proof. Reading the code is not reproduction.

Never write \`@accepts\` — accepting a risk is a human decision. Never write \`@entitles\` — propose it with \`guardlink entitle --propose\` instead. Never write a lone \`@exposes\`: pair it with the \`@mitigates\` that covers it, or the \`@audit\` that flags it.`;

export const WRITE_LAST = `### Write nothing until the verify phase
Phases are ordered so that reading comes before claiming. Hold every candidate annotation in your notes until you have read the code path it describes end to end. Then write them all, coupled: exposure with its control or audit, the flows that carry the input, the boundary it crosses, the classification of what it touches, a \`@comment\` for anything a reader would otherwise have to rediscover.`;

export const STOP_CONDITIONS = `### When to stop
Stop when every entry point in scope has been traced to its sinks and either annotated or recorded as clean in a \`@comment\`. Do not pad: a file with nothing security-relevant gets nothing. Do not repeat what the model already says — extend it. End by running \`guardlink validate .\` and fixing what it reports.`;
