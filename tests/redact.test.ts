/**
 * Tests for the opt-in pentest evidence redaction (bug #11).
 *
 * Contract: redaction is SURGICAL, not blanket. It removes replay-enabling
 * material (signatures, credentials) while preserving the proof of what was
 * exploited (JWT claims, response status, HTTP shape, credential field
 * names). The goal is "anyone screenshotting the dashboard cannot replay
 * the attack, but they can still see what was bypassed."
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  redactSensitiveTokens,
  redactEvidence,
  type EvidenceLike,
} from '../src/analyze/format.js';

describe('redactSensitiveTokens — JWT split-redact', () => {
  // The JWT used across these tests decodes to:
  //   header:  {"alg":"HS256","typ":"JWT"}
  //   payload: {"sub":"admin@juice-sh.op","role":"admin"}
  const jwtHeader  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
  const jwtPayload = 'eyJzdWIiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9';
  const jwtSig     = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const fullJwt    = `${jwtHeader}.${jwtPayload}.${jwtSig}`;

  it('preserves the header and payload (claims) intact — these are the proof', () => {
    const result = redactSensitiveTokens(`Token: ${fullJwt}`);
    expect(result).toContain(jwtHeader);
    expect(result).toContain(jwtPayload);
  });

  it('strips the signature entirely — this enables replay', () => {
    const result = redactSensitiveTokens(`Token: ${fullJwt}`);
    expect(result).not.toContain(jwtSig);
    expect(result).toContain('<signature-redacted>');
  });

  it('produces a structurally-valid-looking JWT that cannot be replayed', () => {
    const result = redactSensitiveTokens(`Token: ${fullJwt}`);
    // header.payload.<signature-redacted> — three dot-separated segments
    expect(result).toMatch(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.<signature-redacted>/);
  });

  it('redacts multiple JWTs in the same string independently', () => {
    const jwt2 = `${jwtHeader}.${jwtPayload}.differentSignatureXYZ`;
    const result = redactSensitiveTokens(`first ${fullJwt} then ${jwt2}`);
    expect(result).not.toContain(jwtSig);
    expect(result).not.toContain('differentSignatureXYZ');
    expect(result.match(/<signature-redacted>/g)?.length).toBe(2);
  });

  it('does not match strings that look JWT-ish but lack three segments', () => {
    const input = 'eyJabc.def is only two parts, not a JWT';
    expect(redactSensitiveTokens(input)).toBe(input);
  });

  it('does not match dotted identifiers like App.Auth.Login', () => {
    const input = 'flow goes through App.Auth.Login as a checkpoint';
    expect(redactSensitiveTokens(input)).toBe(input);
  });

  it('is idempotent — running redaction on already-redacted output is a no-op', () => {
    const once = redactSensitiveTokens(`Token: ${fullJwt}`)!;
    const twice = redactSensitiveTokens(once)!;
    expect(twice).toBe(once);
  });
});

describe('redactSensitiveTokens — Authorization headers', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  it('applies the JWT split-redact rule to Bearer tokens that are JWTs', () => {
    const result = redactSensitiveTokens(`Authorization: Bearer ${jwt}`);
    expect(result).toContain('eyJhbGciOiJIUzI1NiJ9'); // header preserved
    expect(result).toContain('eyJzdWIiOiJhZG1pbiJ9'); // payload preserved
    expect(result).not.toContain('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    expect(result).toContain('<signature-redacted>');
  });

  it('fingerprints opaque Bearer tokens — first 4 + last 4 chars only', () => {
    const opaque = 'gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ZZZZ';
    const result = redactSensitiveTokens(`Authorization: Bearer ${opaque}`);
    expect(result).toContain('gho_'); // first 4
    expect(result).toContain('ZZZZ'); // last 4
    expect(result).not.toContain('aBcDeFgHiJkLmNoPqRsTuVwXyZ');
    expect(result).toContain('<bearer-redacted>');
  });

  it('fully redacts Basic auth — the value IS the credential, no useful prefix', () => {
    const result = redactSensitiveTokens('Authorization: Basic dXNlcjpwYXNzd29yZA==');
    expect(result).toContain('Authorization: Basic <redacted>');
    expect(result).not.toContain('dXNlcjpwYXNzd29yZA');
  });

  it('fully redacts Digest and NTLM auth values', () => {
    const digest = redactSensitiveTokens('Authorization: Digest username="alice", response="abc123"');
    expect(digest).toContain('<redacted>');
    expect(digest).not.toContain('abc123');

    const ntlm = redactSensitiveTokens('Authorization: NTLM TlRMTVNTUAABAAAA');
    expect(ntlm).toContain('Authorization: NTLM <redacted>');
    expect(ntlm).not.toContain('TlRMTVNTUAABAAAA');
  });

  it('case-insensitive on the Authorization header name', () => {
    const result = redactSensitiveTokens(`authorization: bearer ${jwt}`);
    expect(result).not.toContain('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
  });
});

describe('redactSensitiveTokens — credential fields', () => {
  it('preserves field name, redacts value in JSON', () => {
    const input = '{"username":"alice","password":"hunter2"}';
    const result = redactSensitiveTokens(input)!;
    expect(result).toContain('"username":"alice"'); // non-credential preserved
    expect(result).toContain('"password":'); // field name preserved (this is structural proof)
    expect(result).not.toContain('hunter2');
    expect(result).toContain('"<redacted>"');
  });

  it('handles api_key, apiKey, access_token, accessToken, refresh_token, secret variants', () => {
    const fields = ['api_key', 'apiKey', 'access_token', 'accessToken', 'refresh_token', 'refreshToken', 'secret'];
    for (const field of fields) {
      const result = redactSensitiveTokens(`{"${field}":"sensitive-value-123"}`)!;
      expect(result).not.toContain('sensitive-value-123');
      expect(result).toContain(`"${field}":`);
      expect(result).toContain('<redacted>');
    }
  });

  it('redacts query-string credentials while preserving the field name', () => {
    const input = '/login?username=alice&password=hunter2&token=abc123';
    const result = redactSensitiveTokens(input)!;
    expect(result).toContain('username=alice');
    expect(result).toContain('password=');
    expect(result).toContain('token=');
    expect(result).not.toContain('hunter2');
    expect(result).not.toContain('abc123');
  });

  it('redacts Set-Cookie values while preserving cookie name', () => {
    const input = 'Set-Cookie: session=AbCdEfGhIjKlMnOpQrSt; Path=/; HttpOnly';
    const result = redactSensitiveTokens(input)!;
    expect(result).toContain('Set-Cookie: session=');
    expect(result).toContain('Path=/'); // non-credential cookie attributes preserved
    expect(result).toContain('HttpOnly');
    expect(result).not.toContain('AbCdEfGhIjKlMnOpQrSt');
  });

  it('redacts Cookie header values while preserving cookie name', () => {
    const result = redactSensitiveTokens('Cookie: session=AbCdEfGhIjKlMnOpQrSt')!;
    expect(result).toContain('Cookie: session=');
    expect(result).not.toContain('AbCdEfGhIjKlMnOpQrSt');
  });
});

describe('redactSensitiveTokens — safety properties', () => {
  it('returns input unchanged when no sensitive patterns present', () => {
    const safe = 'GET /api/health HTTP/1.1\nHost: example.com\n\n{"status":"ok","items":[1,2,3]}';
    expect(redactSensitiveTokens(safe)).toBe(safe);
  });

  it('returns input unchanged for null / undefined / empty string', () => {
    expect(redactSensitiveTokens(null)).toBe(null);
    expect(redactSensitiveTokens(undefined)).toBe(undefined);
    expect(redactSensitiveTokens('')).toBe('');
  });

  it('does not throw on adversarial inputs', () => {
    const adversarial: Array<string | null | undefined> = [
      'a'.repeat(100000),                           // very long benign string
      'eyJ' + 'A'.repeat(50000) + '.x.y',           // long JWT-shaped (only 2 segments)
      '\u0000\u0001\u0002',                         // control chars
      'Authorization: Bearer ',                     // empty bearer
      'Authorization: Bearer    ',                  // bearer with whitespace
    ];
    for (const v of adversarial) {
      expect(() => redactSensitiveTokens(v)).not.toThrow();
    }
  });

  it('preserves the exploit payload — SQL injection strings stay visible', () => {
    // The injection payload IS the proof of vulnerability. Must not be redacted.
    const payload = "admin@juice-sh.op' OR 1=1--";
    const result = redactSensitiveTokens(`POST /login {"email":"${payload}"}`)!;
    expect(result).toContain(payload);
  });

  it('preserves response role/permission fields — these are exploit proof', () => {
    // {"role":"admin"} in a response is the structural evidence of escalation.
    // It is not a credential and must not be redacted.
    const input = '{"user":{"id":42,"role":"admin","permissions":["all"]}}';
    expect(redactSensitiveTokens(input)).toBe(input);
  });
});

describe('redactEvidence — applies recursively to evidence object', () => {
  const baseEvidence = (): EvidenceLike => ({
    request: null,
    response: null,
    matched_patterns: [],
    data: {},
  });

  it('redacts request and response strings', () => {
    const ev = baseEvidence();
    ev.request = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signatureXYZ';
    ev.response = '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.signatureABC"}';
    const out = redactEvidence(ev);
    expect(out.request).not.toContain('signatureXYZ');
    expect(out.response).not.toContain('signatureABC');
    expect(out.request).toContain('eyJzdWIiOiIxIn0'); // payload preserved
    expect(out.response).toContain('eyJzdWIiOiIyIn0'); // payload preserved
  });

  it('walks evidence.data recursively', () => {
    const ev = baseEvidence();
    ev.data = {
      jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.deepleak',
      nested: {
        api_key: 'sk-live-secret-key-here',
        safe: 'this is fine',
      },
      list: ['Authorization: Bearer eyJhbGc.eyJzdWIi.listleak'],
    };
    const out = redactEvidence(ev);
    const serialized = JSON.stringify(out.data);
    expect(serialized).not.toContain('deepleak');
    expect(serialized).not.toContain('sk-live-secret-key-here');
    expect(serialized).not.toContain('listleak');
    expect(serialized).toContain('this is fine'); // non-credential value preserved
  });

  it('returns a new object — does not mutate input', () => {
    const ev = baseEvidence();
    ev.request = 'eyJhbGc.eyJzdWIi.originalLeakString';
    const before = ev.request;
    const out = redactEvidence(ev);
    expect(ev.request).toBe(before); // input untouched
    expect(out.request).not.toContain('originalLeakString'); // output redacted
  });

  it('handles null request/response without crashing', () => {
    const ev = baseEvidence();
    const out = redactEvidence(ev);
    expect(out.request).toBe(null);
    expect(out.response).toBe(null);
  });

  it('preserves matched_patterns and timestamp (not user-controlled content)', () => {
    const ev = baseEvidence();
    ev.matched_patterns = ['sql_error_leak', 'admin_role_returned'];
    ev.timestamp = '2026-04-25T12:00:00Z';
    const out = redactEvidence(ev);
    expect(out.matched_patterns).toEqual(['sql_error_leak', 'admin_role_returned']);
    expect(out.timestamp).toBe('2026-04-25T12:00:00Z');
  });
});
