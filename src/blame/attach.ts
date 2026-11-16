/**
 * GuardLink Blame — write attribution onto the model records.
 *
 * The one place `record.blame` is set. Only the CLI `--blame` paths call this;
 * the MCP server and the TUI use `computeBlame` and keep their cached model
 * clean, so `--blame` stays opt-in even inside a long-lived process.
 *
 * @mitigates #blame against #path-traversal using #path-validation -- "Application attribution resolves contained member roots and restores native file paths before read-only per-member history queries"
 * @flows #blame -> ThreatModel via attachBlame -- "record.blame on exposures, confirmed and mitigations"
 * @comment -- "The field is invisible to the annotation hash (a whitelist of claim fields) and stripped from the committed model.json, so attaching it changes no tracked artifact; the same goes for blame_context, the commit counts the dashboard's rates need"
 */
import { resolve, relative, isAbsolute } from 'node:path';
import type { ThreatModel } from '../types/index.js';
import { computeBlame, type ComputeBlameOptions } from './compute.js';
import type { BlameComputation, RecordBlame } from './types.js';

export function attachBlame(root: string, model: ThreatModel, opts: ComputeBlameOptions = {}): BlameComputation {
  if (model.application) {
    const byRecord: BlameComputation['byRecord'] = new Map();
    for (const member of model.application.receipt.members.filter(m => m.state === 'available' && m.revision?.vcs === 'git')) {
      const memberRoot = resolve(root, member.relativePath);
      const rel = relative(resolve(root), memberRoot);
      if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) continue;
      const local = { ...model, application: undefined, exposures: [], confirmed: [], mitigations: [] } as ThreatModel;
      const originals = new Map<object, object>();
      for (const field of ['exposures', 'confirmed', 'mitigations'] as const) {
        for (const rec of model[field].filter(r => r.location.memberId === member.id)) {
          const copy = { ...rec, location: { ...rec.location, file: rec.location.memberFile ?? rec.location.file.slice(member.relativePath.length + 1), ...(rec.location.origin_file ? { origin_file: rec.location.origin_file.slice(member.relativePath.length + 1) } : {}) } };
          (local[field] as Array<typeof copy>).push(copy); originals.set(copy, rec);
        }
      }
      const result = computeBlame(memberRoot, local, opts);
      for (const [rec, blame] of result.byRecord) {
        const original = originals.get(rec)!; (original as { blame?: RecordBlame }).blame = blame; byRecord.set(original, blame);
      }
    }
    // Each record retains its owning repository's history. A fictitious app-root
    // commit count would make per-100-commit rates look measured when they are not.
    return { status: 'ok', head: null, identity_mode: opts.config?.identity ?? 'name', byRecord, as_of: null, commits: null };
  }
  const comp = computeBlame(root, model, opts);
  for (const [rec, blame] of comp.byRecord) (rec as { blame?: RecordBlame }).blame = blame;
  // The rates on the dashboard's Attribution page need the commit counts and
  // the as-of date; a record cannot carry them, so the model does. Stripped
  // from the committed model.json with `blame`.
  (model as ThreatModel & { blame_context?: { commits: BlameComputation['commits']; as_of: string | null } }).blame_context = { commits: comp.commits, as_of: comp.as_of };
  return comp;
}
