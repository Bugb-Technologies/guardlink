/**
 * GuardLink init — Migration helpers.
 *
 * Small idempotent operations for projects upgrading from older versions of
 * GuardLink that don't have the full v1.5.x layout. Designed to be safe to
 * call repeatedly and to fail closed (do nothing) when the project doesn't
 * have a `.guardlink/` directory at all.
 *
 * @comment -- "Migrations should never modify existing user files. Only create missing ones."
 */

import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectProject } from './detect.js';
import { promptMdContent } from './templates.js';

/** Outcome of a `prompt.md` ensure operation. */
export type EnsurePromptMdResult =
  /** File already existed; no change. */
  | 'exists'
  /** File was missing and has been created from the template. */
  | 'created'
  /** `.guardlink/` directory itself doesn't exist — caller should run `guardlink init`. */
  | 'skipped-no-guardlink-dir';

/**
 * Ensure `.guardlink/prompt.md` exists.
 *
 * The v1.5.0 release added `.guardlink/prompt.md` as the source for the
 * report's Application Overview section. Projects initialized with
 * GuardLink 1.4.x or earlier don't have this file, and `guardlink init`
 * short-circuits when `.guardlink/` already exists, so they get no
 * migration on upgrade. Without this helper, those projects silently fall
 * back to a boilerplate Application Overview with no nudge that the file
 * exists as a feature.
 *
 * Idempotent. Safe to call from any command path that benefits from a
 * populated `prompt.md`. Returns the outcome so the caller can decide
 * whether to log a one-time hint to the user.
 *
 * Does NOT create the `.guardlink/` directory itself — that's `init`'s job.
 * If the directory is missing, returns `'skipped-no-guardlink-dir'` and
 * does nothing.
 */
export function ensurePromptMd(root: string): EnsurePromptMdResult {
  const guardlinkDir = join(root, '.guardlink');
  if (!existsSync(guardlinkDir)) return 'skipped-no-guardlink-dir';

  const promptPath = join(guardlinkDir, 'prompt.md');
  if (existsSync(promptPath)) return 'exists';

  const project = detectProject(root);
  writeFileSync(promptPath, promptMdContent(project));
  return 'created';
}
