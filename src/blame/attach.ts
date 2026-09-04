/**
 * GuardLink Blame — write attribution onto the model records.
 *
 * The one place `record.blame` is set. Only the CLI `--blame` paths call this;
 * the MCP server and the TUI use `computeBlame` and keep their cached model
 * clean, so `--blame` stays opt-in even inside a long-lived process.
 *
 * @flows #blame -> ThreatModel via attachBlame -- "record.blame on exposures, confirmed and mitigations"
 * @comment -- "The field is invisible to the annotation hash (a whitelist of claim fields) and stripped from the committed model.json, so attaching it changes no tracked artifact"
 */
import type { ThreatModel } from '../types/index.js';
import { computeBlame, type ComputeBlameOptions } from './compute.js';
import type { BlameComputation, RecordBlame } from './types.js';

export function attachBlame(root: string, model: ThreatModel, opts: ComputeBlameOptions = {}): BlameComputation {
  const comp = computeBlame(root, model, opts);
  for (const [rec, blame] of comp.byRecord) (rec as { blame?: RecordBlame }).blame = blame;
  return comp;
}
