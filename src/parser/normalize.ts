/**
 * Name normalization per §2.10 of the GuardLink spec.
 *
 * Algorithm:
 * 1. Apply Unicode NFKC normalization
 * 2. Convert to lowercase
 * 3. Replace whitespace → underscore
 * 4. Replace hyphens → underscore
 * 5. Collapse consecutive underscores
 * 6. Strip leading/trailing underscores
 */
export function normalizeName(name: string): string {
  return name
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\s\t\u00A0]+/g, '_')  // whitespace → underscore
    .replace(/-+/g, '_')              // hyphens → underscore
    .replace(/_+/g, '_')              // collapse consecutive
    .replace(/^_|_$/g, '');           // strip leading/trailing
}

/**
 * Severity alias resolution: P0→critical, P1→high, etc.
 */
export function resolveSeverity(raw: string): 'critical' | 'high' | 'medium' | 'low' | undefined {
  const map: Record<string, 'critical' | 'high' | 'medium' | 'low'> = {
    p0: 'critical', critical: 'critical',
    p1: 'high',     high: 'high',
    p2: 'medium',   medium: 'medium',
    p3: 'low',      low: 'low',
  };
  return map[raw.toLowerCase()];
}

/**
 * Unescape description string per §2.11.
 * Handles \" → " and \\\\ → \\
 */
export function unescapeDescription(raw: string): string {
  return raw
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '\\');
}
