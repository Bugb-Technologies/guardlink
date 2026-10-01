/**
 * GuardLink Hypotheses — barrel.
 *
 * @comment -- "The tested state of every exposure and declared boundary: a ledger of outcomes with evidence, expiry by code hash, and a ranked queue"
 */
export { HYPOTHESES_FILE, HYPOTHESES_SCHEMA, readHypotheses, writeHypotheses, emptyHypotheses, serializeHypotheses } from './ledger.js';
export type { HypothesisOutcome, HypothesisSource, HypothesisAnchor, HypothesisOutcomeRecord, HypothesisEntry, HypothesesLedger, HypothesesStatus, HypothesesRead, BoundaryOutcome, BoundaryEntry, LedgerEntry, LedgerOutcome } from './ledger.js';
export { classifyBoundaryClaims, resolveBoundaryTarget } from './boundary.js';
export type { BoundaryClaimState, BoundaryClaimRecord, BoundaryClaimSummary, BoundaryClaimClassification } from './boundary.js';
export { classifyHypotheses, attachHypotheses, rankUntested } from './classify.js';
export type { HypothesisState, HypothesisRecord, HypothesisSummary, HypothesisClassification, RankedHypothesis } from './classify.js';
export { recordOutcome, recordBoundaryOutcome, resolveTarget, importScan, scanEvidence, confirmedLine, writeConfirmedLine, BOUNDARY_CLAIM_KEY_NAMES } from './commands.js';
export type { OutcomeInput, ScanFinding, JoinedBy, ImportResult } from './commands.js';
export { formatHypothesisList, formatQueue, formatIntake, formatOutcome, formatImport, formatBoundaryOutcome, formatBoundaryList } from './format.js';
