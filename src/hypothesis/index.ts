/**
 * GuardLink Hypotheses — barrel.
 *
 * @comment -- "The tested state of every exposure: a ledger of outcomes with evidence, expiry by code hash, and a ranked queue"
 */
export { HYPOTHESES_FILE, HYPOTHESES_SCHEMA, readHypotheses, writeHypotheses, emptyHypotheses, serializeHypotheses } from './ledger.js';
export type { HypothesisOutcome, HypothesisSource, HypothesisAnchor, HypothesisOutcomeRecord, HypothesisEntry, HypothesesLedger, HypothesesStatus, HypothesesRead } from './ledger.js';
export { classifyHypotheses, attachHypotheses, rankUntested } from './classify.js';
export type { HypothesisState, HypothesisRecord, HypothesisSummary, HypothesisClassification, RankedHypothesis } from './classify.js';
export { recordOutcome, resolveTarget, importScan, scanEvidence, confirmedLine, writeConfirmedLine } from './commands.js';
export type { OutcomeInput, ScanFinding, JoinedBy, ImportResult } from './commands.js';
export { formatHypothesisList, formatQueue, formatIntake, formatOutcome, formatImport } from './format.js';
