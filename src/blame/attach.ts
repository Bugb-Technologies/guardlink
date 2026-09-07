/**
 * GuardLink Blame — write attribution onto the model records.
 *
 * The one place `record.blame` is set. Only the CLI `--blame` paths call this;
 * the MCP server and the TUI use `computeBlame` and keep their cached model
 * clean, so `--blame` stays opt-in even inside a long-lived process.
 *
 * @flows #blame -> ThreatModel via attachBlame -- "record.blame on exposures, confirmed and mitigations"
 * @comment -- "The field is invisible to the annotation hash (a whitelist of claim fields) and stripped from the committed model.json, so attaching it changes no tracked artifact; the same goes for blame_context, the commit counts the dashboard's rates need"
 */
import type { ThreatModel } from '../types/index.js';
import { computeBlame, type ComputeBlameOptions } from './compute.js';
import type { BlameComputation, RecordBlame } from './types.js';

export function attachBlame(root: string, model: ThreatModel, opts: ComputeBlameOptions = {}): BlameComputation {
  const comp = computeBlame(root, model, opts);
  for (const [rec, blame] of comp.byRecord) (rec as { blame?: RecordBlame }).blame = blame;
  // The rates on the dashboard's Attribution page need the commit counts and
  // the as-of date; a record cannot carry them, so the model does. Stripped
  // from the committed model.json with `blame`.
  (model as ThreatModel & { blame_context?: { commits: BlameComputation['commits']; as_of: string | null } }).blame_context = { commits: comp.commits, as_of: comp.as_of };
  return comp;
}
