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

/* ── Evidence redaction (bug #11) ──────────────────────────────────── */

/** Credential field-name pattern used for both string-form (JSON / query
 *  string) matching and object-form key inspection. Includes bare `token`
 *  because it's a common session/CSRF/auth token name. */
const CREDENTIAL_FIELD_PATTERN = '(?:password|passwd|pwd|secret|api[_-]?key|apiKey|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|token)';

/** Regex form for key-name testing — anchored, case-insensitive. */
const CREDENTIAL_KEY_RE = new RegExp(`^${CREDENTIAL_FIELD_PATTERN}$`, 'i');

/**
 * Mirrors the shape of the `evidence` slot on a PentestFinding without
 * pulling the full PentestFinding type from src/analyze/index.ts (would
 * create a circular import). Any object matching this structural shape
 * can be passed to redactEvidence().
 */
export interface EvidenceLike {
  request: string | null;
  response: string | null;
  matched_patterns: string[];
  data: Record<string, unknown>;
  timestamp?: string;
}

/**
 * Surgical redactor for sensitive tokens. Designed to preserve the
 * confirmation evidence of a pentest finding while removing material that
 * would enable replay attacks if a screenshot or exported HTML escaped the
 * customer's perimeter.
 *
 * The principle: redact what enables replay, keep what proves the exploit.
 *
 * Patterns:
 *   - JWT (eyJ-prefixed three-segment): keep header and payload (the
 *     claims — these are the proof of what role/scope/sub was achieved),
 *     replace the signature segment with `<signature-redacted>`. Anyone
 *     screenshotting can still decode the payload at jwt.io to see the
 *     claims; nobody can replay the token because the signature is gone.
 *   - Authorization: Bearer <jwt>: same JWT split rule.
 *   - Authorization: Bearer <opaque>: show first 4 + last 4 chars only,
 *     enough for correlation/fingerprinting but not replay.
 *   - Authorization: Basic|Digest|NTLM <value>: fully replace value with
 *     `<redacted>`. These ARE the credential — no useful prefix.
 *   - JSON credential fields (password, api_key, access_token, etc.):
 *     keep field name (structural proof that the request used this
 *     credential type), replace value with `<redacted>`.
 *   - Query-string credentials: same — keep field name, redact value.
 *   - Cookie / Set-Cookie values: keep cookie name (proves session-based
 *     auth was used), redact value.
 *
 * Idempotent: re-running on already-redacted output is a no-op since the
 * redaction markers themselves don't match any of the input patterns.
 *
 * Returns input unchanged for null / undefined / empty / non-string.
 */
export function redactSensitiveTokens(text: string | null | undefined): string | null | undefined {
  if (text === null || text === undefined || text === '') return text;
  if (typeof text !== 'string') return text;

  let result = text;

  // 1. JWTs: keep header.payload, redact signature.
  //    The \b anchors ensure dotted identifiers like App.Auth.Login don't match.
  result = result.replace(
    /\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+\b/g,
    '$1.<signature-redacted>',
  );

  // 2. Authorization: Bearer <opaque token> (NOT a JWT — the JWT case was
  //    handled in step 1 already, so any Bearer value here is either opaque
  //    or a partial/malformed JWT). Negative lookahead `(?!eyJ)` skips
  //    JWT-shaped values. Min length 8 to avoid matching nothing-tokens.
  result = result.replace(
    /(Authorization:\s*Bearer\s+)(?!eyJ)([A-Za-z0-9_\-\.=]{8,})/gi,
    (_match, prefix: string, token: string) => {
      // First 4 + last 4 chars: fingerprint for correlation, no replay value.
      const fingerprint = token.length > 12
        ? `${token.slice(0, 4)}...${token.slice(-4)}`
        : '...';
      return `${prefix}${fingerprint} <bearer-redacted>`;
    },
  );

  // 3. Authorization: Basic / Digest / NTLM <value> — full redact.
  //    Match the whole value through to the end of the header line so multi-
  //    word Digest values (e.g. `Digest username="x", response="y"`) are
  //    redacted entirely, not just up to the first whitespace.
  result = result.replace(
    /(Authorization:\s*(?:Basic|Digest|NTLM)\s+)[^\r\n]+/gi,
    (_match, prefix: string) => `${prefix}<redacted>`,
  );

  // 4. JSON credential fields: keep field name, redact value.
  //    Supports both snake_case (api_key) and camelCase (apiKey) variants.
  //    The value character class excludes `<` so values that already contain
  //    a redaction marker (e.g. a JWT split in step 1 produced
  //    `"token":"eyJ.eyJ.<signature-redacted>"`) don't get over-redacted —
  //    we'd otherwise wipe the preserved JWT payload here.
  const credentialFieldNames = CREDENTIAL_FIELD_PATTERN;
  result = result.replace(
    new RegExp(`("${credentialFieldNames}"\\s*:\\s*")(?:[^"\\\\<]|\\\\.)*(")`, 'gi'),
    (_match, prefix: string, suffix: string) => `${prefix}<redacted>${suffix}`,
  );

  // 5. Query-string credentials: name=value pairs.
  //    Stops at the typical separators (& ; whitespace , " ').
  result = result.replace(
    new RegExp(`(\\b${credentialFieldNames}=)[^&\\s;,"']+`, 'gi'),
    (_match, prefix: string) => `${prefix}<redacted>`,
  );

  // 6. Cookie values: keep cookie name (the structural proof that
  //    cookie-based auth was used), redact value. Handles both `Set-Cookie:`
  //    response headers (with attributes like Path=, HttpOnly) and `Cookie:`
  //    request headers (semicolon-separated name=value pairs).
  result = result.replace(
    /(Set-Cookie:\s*[^=;\s]+=)[^;\r\n]+/gi,
    (_match, prefix: string) => `${prefix}<redacted>`,
  );
  result = result.replace(
    /(Cookie:\s*[^=;\s]+=)[^;\r\n]+/gi,
    (_match, prefix: string) => `${prefix}<redacted>`,
  );

  return result;
}

/**
 * Recursively walks any value, applying redactSensitiveTokens to every
 * string leaf. Used to scrub the unstructured `evidence.data` field where
 * templates may place arbitrary scan output (extracted tokens, response
 * bodies, captured headers).
 *
 * When walking an object, this function also inspects each key — if the
 * key name matches a credential field (e.g. `api_key`, `password`), the
 * value is replaced with `<redacted>` directly, regardless of its
 * content. This catches the parsed-object form (`{api_key: "sk-live-..."}`)
 * which the string-pattern matcher cannot see, since the key/value
 * relationship is only visible structurally.
 */
function deepRedact(value: unknown): unknown {
  if (typeof value === 'string') return redactSensitiveTokens(value);
  if (Array.isArray(value)) return value.map(deepRedact);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (CREDENTIAL_KEY_RE.test(k) && typeof v === 'string') {
        out[k] = '<redacted>';
      } else {
        out[k] = deepRedact(v);
      }
    }
    return out;
  }
  return value;
}

/**
 * Redacts an entire `evidence` object — request, response, and the
 * unstructured `data` field. Returns a new object; does not mutate the
 * input. Non-string fields (matched_patterns, timestamp) pass through
 * unchanged since they don't carry secret material.
 */
export function redactEvidence(ev: EvidenceLike): EvidenceLike {
  return {
    request: redactSensitiveTokens(ev.request) ?? null,
    response: redactSensitiveTokens(ev.response) ?? null,
    matched_patterns: ev.matched_patterns,
    data: deepRedact(ev.data) as Record<string, unknown>,
    timestamp: ev.timestamp,
  };
}
