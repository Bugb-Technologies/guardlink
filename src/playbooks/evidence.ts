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

Severity estimates the potential worst case supported by the source path; label runtime-observed impact separately. An exposure never outranks the threat's declared severity: a threat declared \`[medium]\` does not get a \`[critical]\` instance without a definition change. Within that band, rate the instance by impact (what the asset holds — its \`@handles\` class), reach (who can get to it: public, signed-in, admin-only, internal) and ease (the preconditions), and when you rate it below the threat's band say why in the description (\`"low: reachable only by an admin, by design"\`).

\`@confirmed\` is reserved for evidence in hand — a request and its response, a reproduction, a scan with proof. Reading the code or generating a template is not reproduction.

Never write \`@accepts\` — accepting a risk is a human decision. Never write \`@entitles\` — propose it with \`guardlink entitle --propose\` instead. Never write a lone \`@exposes\`: pair it with the \`@mitigates\` that covers it, or the \`@audit\` that flags it.`;

export const LOGIC_EVIDENCE = `### The evidence bar for a business-logic claim
A logic flaw rarely has a dangerous call. Its sink is the **state change** — the write, the transfer, the role grant, the status move — and its absent control is the **missing check** on who may make that change, in which state, for how much, how often. An \`@exposes\` against an invariant names the four fields in those terms: the entry point (route or command), the input the caller controls (the id, the amount, the target role, the step skipped), the state change by function name, and the check that is missing or bypassed (\`"POST /refunds reads order_id from the body and issueRefund() credits it without checking order.status == APPROVED or order.owner == caller"\`). Something the product does on purpose is not an exposure: record it as intended where the owners say so, and write an \`@audit\` that asks "intended?" when they have not.`;

export const WRITE_LAST = `### Write nothing until the relevant path is read
Phases are ordered so that reading comes before claiming. Hold every candidate annotation in your notes until you have read the code path it describes end to end. Then write them all, coupled: exposure with its control or audit, the flows that carry the input, the boundary it crosses, the classification of what it touches, a \`@comment\` for anything a reader would otherwise have to rediscover.`;

export const STOP_CONDITIONS = `### When to stop
Stop when every entry point in scope has been traced to its sinks and either annotated or recorded as reviewed with no supported exposure in a \`@comment\`. Do not pad: a file with nothing security-relevant gets nothing. Do not repeat what the model already says — extend it. End by running \`guardlink validate .\` and fixing what it reports. This completes annotation review, not behavioral testing. For developer checks next scope \`guardlink translate "<changed paths and threats>"\` to the change, review and validate the generated templates, then execute selected tests separately. Retain durable regression tests under the repository's configured suite (\`security_tests_dir\` in \`.guardlink/config.json\`, default \`security/\`) before review, even when a mitigation removes an exposure from future translation candidates.`;
