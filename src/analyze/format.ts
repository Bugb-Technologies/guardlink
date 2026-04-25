/**
 * GuardLink — Pentest finding format helpers.
 *
 * Defensive normalizers for fields whose shape varies across CXG versions
 * and template authors. Keep these tiny and pure — no I/O, no side effects.
 */

/**
 * Render a confidence value for display, regardless of how the upstream
 * scanner emitted it.
 *
 * CXG output has historically emitted confidence in three different shapes:
 *   - integer percentage (most current versions): `50` → `"50%"`
 *   - severity-style string (some templates pre-normalization): `"high"` → `"HIGH"`
 *   - missing / null / undefined (older or partial scans): → `"—"`
 *
 * Returns a display string that's safe to drop into HTML or terminal output.
 * Never throws — always returns *something* renderable.
 */
export function formatConfidence(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';

  if (typeof value === 'number' && Number.isFinite(value)) {
    // Clamp into [0, 100] so a malformed `150` doesn't print "150%".
    const clamped = Math.max(0, Math.min(100, Math.round(value)));
    return `${clamped}%`;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return '—';

    // String might still be numeric: "50" or "50%"
    const numericMatch = trimmed.match(/^(-?\d+(?:\.\d+)?)\s*%?$/);
    if (numericMatch) {
      const n = Number.parseFloat(numericMatch[1]);
      if (Number.isFinite(n)) {
        const clamped = Math.max(0, Math.min(100, Math.round(n)));
        return `${clamped}%`;
      }
    }

    // Severity-word style — uppercase for visual weight, no other transform.
    return trimmed.toUpperCase();
  }

  // Anything else (boolean, object, array) — render the placeholder rather
  // than letting `[object Object]` leak into the dashboard.
  return '—';
}
