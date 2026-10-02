/**
 * GuardLink Reach — what each agent and principal can reach, for the dashboard
 * and the report.
 *
 * @comment -- "Re-exports only; the derivation lives in summary.ts and the joins in parser/reach.ts"
 */
export { summarizeReach, hasReach } from './summary.js';
export type {
  ReachSummary, ReachActorRow, ReachColumn, ReachCell, ReachCapabilityChip, ReachEffectChip, LooseEffects,
  UnentitledRow, NearMissRow, UngatedRow, GateRow, EgressRow, InjectionRoute, OwaspRow, OwaspItem, OwaspId, ReachLoc,
} from './summary.js';
