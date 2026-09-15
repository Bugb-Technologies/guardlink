/**
 * GuardLink — Whether this repository's model reaches anything but this CLI.
 *
 * ── The defect this exists for ──────────────────────────────────────
 *
 * `guardlink init` defaults a new project to `annotation_mode: "external"` and
 * tells the developer, in its own last line of output, to write annotations in
 * `.guardlink/annotations/<source path>.gal`. GuardLink then reads those
 * sidecars perfectly: `validate` and `status` report every exposure and every
 * acceptance in them.
 *
 * Nothing else does. Measured on a fresh repository (2026-09-16): the same two
 * `@exposes` and one `@accepts` gave `exposures 2, acceptances 1` when written
 * inline in `src/allocations.js`, and `exposures 0, acceptances 0` when written
 * in the sidecar `init` recommends — while the consuming surface still reported
 * itself *present*, so a correctly annotated repository rendered a green,
 * empty dashboard.
 *
 * The mechanism is not a bug in the sidecar parser. Downstream consumers do not
 * run GuardLink's parser at all: they look for a JSON export and, failing to
 * find one, fall back to scraping inline source comments themselves. An inline
 * annotation therefore survives that fallback and a sidecar cannot — the
 * fallback walks source extensions, and `.gal` is not one of them.
 *
 * So external mode has a step inline mode does not, and until this module
 * nothing said so:
 *
 *     guardlink parse . -o .guardlink/report.json
 *
 * ── Why a check and not a write ─────────────────────────────────────
 *
 * The obvious fix is for `validate` to emit the export itself. It must not: a
 * check that writes is not a check, and `validate` already lost that argument
 * once (D16, the sync it used to do unasked). The export also carries
 * `metadata.commit_sha` / `generated_at`, which move on every run — the exact
 * property that kept them out of the committed artifacts in `artifacts/emit.ts`.
 * This module says what is true and names the one command that fixes it.
 *
 * ── Why `annotation_hash` is the staleness test ─────────────────────
 *
 * `guardlink parse -o` stamps `metadata.annotation_hash` (R10). An export
 * carrying a hash that differs from the live model is provably behind it; an
 * export carrying no hash at all predates the stamp and cannot be judged either
 * way. Those are different answers and this module returns different verdicts
 * for them, because `unverifiable` is honest and `stale` would be a guess.
 *
 * @flows ThreatModel -> #parser via checkHandoff -- "Live model hashed and compared against the exported one"
 * @flows ExportFile -> #parser via readFileSync -- "The JSON export consumers read, re-read here only for its provenance stamp"
 * @assumes #parser -- "`metadata.annotation_hash` on an export was written by `guardlink parse -o` over the same hash function this module calls. Nothing verifies that: a hand-edited stamp reads as current, and the answer this module gives is only as good as the file's provenance"
 * @comment -- "No @exposes here on purpose. This module reads one constant path under the project root and emits the path plus two content hashes — no annotation text, no signer, no file contents — so there is no risk to declare, and declaring one would attach a mitigation to the #parser/#data-exposure pair that silences the open exposure at migrate-mode.ts:26"
 * @comment -- "`not-needed` is a real verdict, not a skip: with nothing in a sidecar there is nothing an export would rescue, and inline annotations survive a consumer's fallback on their own"
 * @comment -- "Every failure to read the stamp returns `unverifiable`, never `current` — the one answer that would silence this check is the one an error cannot produce"
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { computeAnnotationHash } from './annotation-hash.js';
import { detectAnnotationMode } from './annotation-mode.js';
import type { ThreatModel } from '../types/index.js';

/**
 * The export path consumers look for, and the one this check asks about.
 *
 * Not a preference. It is the path GuardLink's own `parse` command documents as
 * "how the model reaches the graph and everything downstream of it", and the
 * path the consuming code graph names in its own remedy message when it finds
 * sidecars it cannot read.
 */
export const HANDOFF_PATH = '.guardlink/report.json';

/** The one command that produces {@link HANDOFF_PATH}. */
export const HANDOFF_COMMAND = `guardlink parse . -o ${HANDOFF_PATH}`;

export type HandoffVerdict =
  /** No annotation lives only in a sidecar, so no export is needed to carry one. */
  | 'not-needed'
  /** Sidecars hold annotations and the export exists and matches the model. */
  | 'current'
  /** Sidecars hold annotations and no export exists. Consumers read zero. */
  | 'missing'
  /** An export exists but was cut from different annotations than these. */
  | 'stale'
  /** An export exists and carries no hash, so neither current nor stale can be claimed. */
  | 'unverifiable';

export interface HandoffReport {
  verdict: HandoffVerdict;
  /** Annotations written in `.gal` sidecars — the ones an export has to carry. */
  external: number;
  /** Annotations written in source comments — the ones that survive without it. */
  inline: number;
  /** Repo-relative path of the export. */
  path: string;
  /** The hash stamped on the export, or null when absent or unreadable. */
  exportedHash: string | null;
  /** The hash of the annotations as they are right now. */
  currentHash: string;
  /** The command that fixes a `missing`, `stale` or `unverifiable` verdict. */
  command: string;
  /**
   * What to tell a human, or null when there is nothing worth saying.
   *
   * Null on `not-needed` and on `current`: a check that speaks when everything
   * is fine trains people to stop reading it, and this one has to be read
   * exactly when it fires.
   */
  message: string | null;
}

/**
 * Does the model reach anything but this CLI?
 *
 * Pure apart from two reads: the export file, and nothing else. The live model
 * is passed in rather than re-parsed, so a caller that already has one pays no
 * second parse.
 */
export function checkHandoff(root: string, model: ThreatModel): HandoffReport {
  const { inline, external } = detectAnnotationMode(model);
  const currentHash = computeAnnotationHash(model);
  const absolute = join(root, HANDOFF_PATH);

  const base = {
    external,
    inline,
    path: HANDOFF_PATH,
    currentHash,
    command: HANDOFF_COMMAND,
  };

  if (external === 0) {
    return { ...base, verdict: 'not-needed', exportedHash: null, message: null };
  }

  const where = external === 1
    ? '1 annotation is written in a `.gal` sidecar'
    : `${external} annotations are written in \`.gal\` sidecars`;

  if (!existsSync(absolute)) {
    return {
      ...base,
      verdict: 'missing',
      exportedHash: null,
      message: `${where} and \`${HANDOFF_PATH}\` does not exist. GuardLink reads those `
        + `sidecars; nothing downstream of it does — a consumer with no export falls back to `
        + `scraping inline source comments, and a sidecar is not one. Every surface outside `
        + `this CLI currently sees zero exposures and zero acceptances for this repository. `
        + `Fix: ${HANDOFF_COMMAND}`,
    };
  }

  const exportedHash = readExportedHash(absolute);

  if (exportedHash === null) {
    return {
      ...base,
      verdict: 'unverifiable',
      exportedHash: null,
      message: `\`${HANDOFF_PATH}\` exists but carries no \`metadata.annotation_hash\`, so `
        + `whether it still matches these annotations is unknown — it may be current and it `
        + `may be arbitrarily far behind. ${where}, so this file is the only thing consumers `
        + `read. Re-export to make the answer knowable: ${HANDOFF_COMMAND}`,
    };
  }

  if (exportedHash !== currentHash) {
    return {
      ...base,
      verdict: 'stale',
      exportedHash,
      message: `\`${HANDOFF_PATH}\` was cut from different annotations than the ones in this `
        + `working tree (export ${exportedHash}, model ${currentHash}). ${where}, so consumers `
        + `are reading the older model and nothing tells them so. Fix: ${HANDOFF_COMMAND}`,
    };
  }

  return { ...base, verdict: 'current', exportedHash, message: null };
}

/**
 * The annotation hash stamped on an export, or null.
 *
 * Null covers every way the question can fail to have an answer — unreadable,
 * not JSON, no `metadata`, no stamp — because the caller's response to all four
 * is identical and correct: say the answer is unknown rather than pick one.
 */
function readExportedHash(absolute: string): string | null {
  try {
    const parsed = JSON.parse(readFileSync(absolute, 'utf-8')) as {
      metadata?: { annotation_hash?: unknown };
    };
    const hash = parsed.metadata?.annotation_hash;
    return typeof hash === 'string' && hash.length > 0 ? hash : null;
  } catch {
    return null;
  }
}
