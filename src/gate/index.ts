/**
 * GuardLink Gate — barrel.
 *
 * @comment -- "The acceptance check behind `guardlink annotate` and the standalone `guardlink lint`"
 */
export { lintAnnotations, hasCodeReference, hasEvidenceWords, RULE_FIX, type Violation, type LintRule, type LintLevel, type LintOptions } from './lint.js';
export { runGate, formatGateReport, buildGateFollowUp, stripViolations, type GateReport, type Stripped } from './gate.js';
