/**
 * GuardLink parser — Diagnostic formatting helpers.
 *
 * Tiny pure helpers shared by the CLI's `printDiagnostics` and the TUI's
 * status-command printer so the level-to-icon mapping lives in one place.
 * If a future iteration adds a new diagnostic tier, only this file needs
 * to change for the visual treatment to stay consistent across surfaces.
 */

import type { ParseDiagnostic } from '../types/index.js';

/**
 * Returns the icon character for a diagnostic level. No color, no padding,
 * no extra whitespace — callers that want those (e.g. the TUI's
 * `C.error('  ' + diagnosticIcon(...))`) wrap the return value themselves.
 *
 * - `'warning'` → `⚠`  (informational, never blocks)
 * - `'error'`   → `✗`  (annotation skipped, model continues)
 * - `'fatal'`   → `✗✗` (model is unsafe to render; consumer must abort)
 *
 * The switch is exhaustive over `ParseDiagnostic['level']` — TypeScript
 * will flag this function if a new level is added to the union without a
 * matching case here.
 */
export function diagnosticIcon(level: ParseDiagnostic['level']): string {
  switch (level) {
    case 'fatal':   return '✗✗';
    case 'error':   return '✗';
    case 'warning': return '⚠';
  }
}
