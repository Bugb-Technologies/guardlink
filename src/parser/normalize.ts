/**
 * GuardLink — Name normalization and description utilities.
 *
 * @comment -- "normalizeName applies NFKC before lowercasing: visually similar Unicode chars (homographs) may collapse to the same canonical_name, causing silent collision in deduplication and search"
 * @comment -- "resolveSeverity returns undefined for unknown severity strings; callers must handle undefined to avoid silently omitting severity from @exposes entries in the ThreatModel"
 * @comment -- "unescapeDescription reverses backslash escapes (\\\" and \\\\) only; output is NOT HTML-encoded — downstream renderers must independently sanitize before inserting into HTML"
 * @exposes #parser to #xss [low] cwe:CWE-79 -- "[mixed] unescapeDescription does not HTML-encode its output; annotation descriptions from local or PR-contributed source files containing <script> or event attributes rendered in the HTML dashboard without escaping become XSS vectors"
 * @audit #parser -- "HTML dashboard and markdown report generators must independently HTML-encode all description fields; unescapeDescription is not an HTML sanitizer"
 * @flows RawAnnotationText -> #parser via unescapeDescription -- "Quoted annotation string → unescaped description stored in ThreatModel"
 * @flows #parser -> canonical_name via normalizeName -- "Normalized name written to canonical_name field in asset/threat/control model entries for deduplication and search"
 */

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
