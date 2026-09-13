import { describe, it, expect } from 'vitest';
import { generateSarif, threatId } from '../src/analyzer/sarif.js';
import type { ThreatModel } from '../src/types/index.js';

/**
 * Build a minimal ThreatModel exercising only the fields generateSarif reads.
 * Cast through unknown so tests stay terse without stubbing every collection.
 */
function model(partial: Partial<ThreatModel>): ThreatModel {
  return {
    mitigations: [],
    acceptances: [],
    exposures: [],
    confirmed: [],
    flows: [],
    ...partial,
  } as unknown as ThreatModel;
}

const loc = (file: string, line = 1) => ({ file, line });

const findingProps = (sarif: ReturnType<typeof generateSarif>, asset: string) =>
  sarif.runs[0].results.find((r) => (r.properties as Record<string, unknown>)?.asset === asset)
    ?.properties as Record<string, unknown> | undefined;

describe('generateSarif — codegraph_reachability from @flows', () => {
  it('attaches the route matched by handler file', () => {
    const sarif = generateSarif(model({
      exposures: [{ asset: '#ws-proxy', threat: '#bac', severity: 'high', external_refs: [], location: loc('api/ws/attach.go', 42) } as never],
      flows: [{ source: 'User', target: '#ws-proxy', mechanism: 'GET./websocket/attach?endpointId&id', location: loc('api/ws/attach.go', 40) } as never],
    }));
    expect(findingProps(sarif, '#ws-proxy')?.codegraph_reachability)
      .toEqual({ http_method: 'GET', http_path: '/websocket/attach' });
  });

  it('falls back to the asset inbound route when the file does not match', () => {
    const sarif = generateSarif(model({
      exposures: [{ asset: '#auth', threat: '#brute-force', severity: 'medium', external_refs: [], location: loc('api/auth/other.go', 9) } as never],
      flows: [{ source: 'Anon', target: '#auth', mechanism: 'POST./auth', location: loc('api/auth/handler.go', 3) } as never],
    }));
    expect(findingProps(sarif, '#auth')?.codegraph_reachability)
      .toEqual({ http_method: 'POST', http_path: '/auth' });
  });

  it('strips query hints and parenthetical notes from the path', () => {
    const sarif = generateSarif(model({
      exposures: [{ asset: '#backup', threat: '#dos', severity: 'medium', external_refs: [], location: loc('api/backup/restore.go', 5) } as never],
      flows: [{ source: 'Anon', target: '#backup', mechanism: 'POST./restore (multipart)', location: loc('api/backup/restore.go', 2) } as never],
    }));
    expect(findingProps(sarif, '#backup')?.codegraph_reachability)
      .toEqual({ http_method: 'POST', http_path: '/restore' });
  });

  it('omits codegraph_reachability when the flow mechanism is not an HTTP route', () => {
    const sarif = generateSarif(model({
      exposures: [{ asset: '#archive', threat: '#dos', severity: 'medium', external_refs: [], location: loc('api/archive/targz.go', 91) } as never],
      flows: [{ source: '#backup', target: '#archive', mechanism: 'tar.NewReader', location: loc('api/archive/targz.go', 10) } as never],
    }));
    const props = findingProps(sarif, '#archive');
    expect(props).toBeDefined();
    expect(props?.codegraph_reachability).toBeUndefined();
  });

  it('attaches the route to @confirmed results as well', () => {
    const sarif = generateSarif(model({
      confirmed: [{ asset: '#ws-proxy', threat: '#bac', severity: 'high', external_refs: [], location: loc('api/ws/attach.go', 42) } as never],
      flows: [{ source: 'User', target: '#ws-proxy', mechanism: 'GET./websocket/attach', location: loc('api/ws/attach.go', 40) } as never],
    }));
    const confirmed = sarif.runs[0].results.find((r) => r.ruleId === 'guardlink/confirmed-exploitable');
    expect((confirmed?.properties as Record<string, unknown>)?.codegraph_reachability)
      .toEqual({ http_method: 'GET', http_path: '/websocket/attach' });
  });
});

/**
 * Threat-id minting. Stability is the contract downstream
 * tools depend on, so these tests pin exactly what does and does not move the id.
 */
describe('generateSarif — threat id (partialFingerprints + properties.threatId)', () => {
  const exposure = (over: Record<string, unknown> = {}) => ({
    asset: '#ws-proxy', threat: '#bac', severity: 'high', external_refs: [],
    description: 'cross-tenant attach', location: loc('api/ws/attach.go', 42), ...over,
  } as never);

  // The id of the first exposure result in an export.
  const idOf = (sarif: ReturnType<typeof generateSarif>, asset: string) =>
    (findingProps(sarif, asset)?.threatId as string | undefined);

  it('mints a gl- + 12-hex-char id', () => {
    const id = threatId('#ws-proxy', '#bac', 'api/ws/attach.go');
    expect(id).toMatch(/^gl-[0-9a-f]{12}$/);
  });

  it('emits partialFingerprints and properties.threatId, equal, on every threat result', () => {
    const sarif = generateSarif(model({
      exposures: [
        exposure(),
        exposure({ asset: '#auth', threat: '#brute-force', severity: 'medium', location: loc('api/auth/handler.go', 9) }),
      ],
      confirmed: [exposure({ asset: '#backup', threat: '#dos', location: loc('api/backup/restore.go', 5) })],
    }));

    // Only threat results here (no diagnostics/dangling passed), so every result must carry the id.
    expect(sarif.runs[0].results.length).toBe(3);
    for (const r of sarif.runs[0].results) {
      const fromProps = (r.properties as Record<string, unknown>).threatId as string;
      const fromFingerprint = r.partialFingerprints?.['guardlink/threatId'];
      expect(fromProps).toMatch(/^gl-[0-9a-f]{12}$/);
      expect(fromFingerprint).toBe(fromProps);
    }
  });

  it('is stable: the same exposure yields the same id across two independent exports', () => {
    const a = generateSarif(model({ exposures: [exposure()] }));
    const b = generateSarif(model({ exposures: [exposure()] }));
    expect(idOf(a, '#ws-proxy')).toBe(idOf(b, '#ws-proxy'));
  });

  it('is stable across a line-number-only change (the line is not part of the identity)', () => {
    // Regression guard: the code moved down the file. Line is not in the hash — nor is the message
    // now — so the id must not move.
    const early = generateSarif(model({
      exposures: [exposure({ location: loc('api/ws/attach.go', 42) })],
    }));
    const drifted = generateSarif(model({
      exposures: [exposure({ location: loc('api/ws/attach.go', 87) })],
    }));
    expect(idOf(early, '#ws-proxy')).toBe(idOf(drifted, '#ws-proxy'));
  });

  it('changes when the asset changes', () => {
    const base = generateSarif(model({ exposures: [exposure()] }));
    const other = generateSarif(model({ exposures: [exposure({ asset: '#docker-proxy' })] }));
    expect(idOf(other, '#docker-proxy')).not.toBe(idOf(base, '#ws-proxy'));
  });

  it('changes when the threat changes', () => {
    const base = generateSarif(model({ exposures: [exposure()] }));
    const other = generateSarif(model({ exposures: [exposure({ threat: '#idor' })] }));
    expect(idOf(other, '#ws-proxy')).not.toBe(idOf(base, '#ws-proxy'));
  });

  it('changes when the file changes', () => {
    const base = generateSarif(model({ exposures: [exposure()] }));
    const other = generateSarif(model({ exposures: [exposure({ location: loc('api/ws/attach_v2.go', 42) })] }));
    expect(idOf(other, '#ws-proxy')).not.toBe(idOf(base, '#ws-proxy'));
  });

  it('ignores the message: same (asset, threat, file), different wording -> SAME id', () => {
    // The message is no longer in the hash, so incidental rewording cannot split one threat.
    const a = generateSarif(model({ exposures: [exposure({ description: 'attach bypass in handler' })] }));
    const b = generateSarif(model({ exposures: [exposure({ description: 'totally different words' })] }));
    expect(idOf(a, '#ws-proxy')).toBe(idOf(b, '#ws-proxy'));
  });

  it('distinguishes by file: same (asset, threat), different file -> different ids', () => {
    // Distinctness now comes from the file, not the message.
    const sarif = generateSarif(model({
      exposures: [
        exposure({ description: 'attach bypass in handler', location: loc('api/ws/attach.go', 42) }),
        exposure({ description: 'attach bypass in proxy', location: loc('api/ws/proxy.go', 11) }),
      ],
    }));
    const ids = sarif.runs[0].results.map((r) => (r.properties as Record<string, unknown>).threatId);
    expect(ids[0]).not.toBe(ids[1]);
    expect(new Set(ids).size).toBe(2);
  });

  it('shares one id across the lifecycle: @exposes and its @confirmed at the same place match', () => {
    // The point of dropping the message from the hash: the theoretical exposure and the proof that
    // it is exploitable are the SAME threat, and must carry the SAME id for the write-back
    // round-trip and downstream linkage to work.
    const sarif = generateSarif(model({
      exposures: [exposure({ location: loc('api/ws/attach.go', 42) })],
      confirmed: [exposure({ location: loc('api/ws/attach.go', 42) })],
    }));
    const exposed = sarif.runs[0].results.find((r) => r.ruleId !== 'guardlink/confirmed-exploitable');
    const confirmed = sarif.runs[0].results.find((r) => r.ruleId === 'guardlink/confirmed-exploitable');
    const exposedId = (exposed?.properties as Record<string, unknown>).threatId;
    const confirmedId = (confirmed?.properties as Record<string, unknown>).threatId;
    expect(exposedId).toMatch(/^gl-[0-9a-f]{12}$/);
    expect(confirmedId).toBe(exposedId);
  });
});

/**
 * The anchor hash on each result. It is a hash of the ANCHORED CODE, not of the
 * location, which is the property a consumer joining on the stamped identity
 * needs: two siblings that share a threat id — same asset, same threat, same
 * file — are separable by it, and it does not move when the code does.
 */
describe('generateSarif — anchor hash (partialFingerprints + properties.anchorHash)', () => {
  const anchored = (file: string, line: number, symbol: string, hash: string) => ({
    file, line, anchor: { scope: 'symbol' as const, symbol, start_line: line + 2, end_line: line + 2, hash },
  });
  const A = 'sha256-v1:8c2aa1520479a9530f4f85770a2d2770076bf6450f7cb4a764fead7ad324e81a';
  const B = 'sha256-v1:ad546572adc53463c970c562c03fcf7dd321e7c055c996f62009afd8006f2eba';

  const exposure = (over: Record<string, unknown> = {}) => ({
    asset: '#api', threat: '#sqli', severity: 'critical', external_refs: [],
    description: 'findUser concatenates email', location: anchored('src/a.ts', 4, 'findUser', A), ...over,
  } as never);

  const hashOf = (sarif: ReturnType<typeof generateSarif>, i: number) =>
    (sarif.runs[0].results[i].properties as Record<string, unknown>).anchorHash as string | undefined;

  it('emits the fingerprint and properties.anchorHash, equal, on exposure and confirmed results', () => {
    const sarif = generateSarif(model({
      exposures: [exposure()],
      confirmed: [exposure()],
    }));
    expect(sarif.runs[0].results.length).toBe(2);
    for (const r of sarif.runs[0].results) {
      const fromProps = (r.properties as Record<string, unknown>).anchorHash;
      expect(fromProps).toBe(A);
      expect(r.partialFingerprints?.['guardlink/anchorHash']).toBe(fromProps);
    }
  });

  it('omits both when the location carries no anchor — never a null', () => {
    const sarif = generateSarif(model({ exposures: [exposure({ location: loc('src/a.ts', 4) })] }));
    const r = sarif.runs[0].results[0];
    expect((r.properties as Record<string, unknown>)).not.toHaveProperty('anchorHash');
    expect(r.partialFingerprints).not.toHaveProperty('guardlink/anchorHash');
    // The threat id is untouched by the anchor being absent.
    expect(r.partialFingerprints?.['guardlink/threatId']).toMatch(/^gl-[0-9a-f]{12}$/);
  });

  it('separates two siblings that share one threat id but anchor different code', () => {
    // GAP-58: same asset, same threat, same file, so the threat id cannot tell them apart.
    const sarif = generateSarif(model({
      exposures: [
        exposure(),
        exposure({ description: 'findOrder concatenates id', location: anchored('src/a.ts', 9, 'findOrder', B) }),
      ],
    }));
    const ids = sarif.runs[0].results.map(r => (r.properties as Record<string, unknown>).threatId);
    expect(ids[0]).toBe(ids[1]);
    expect(hashOf(sarif, 0)).not.toBe(hashOf(sarif, 1));
  });

  it('does not move when only the line moves', () => {
    const early = generateSarif(model({ exposures: [exposure()] }));
    const drifted = generateSarif(model({ exposures: [exposure({ location: anchored('src/a.ts', 87, 'findUser', A) })] }));
    expect(hashOf(early, 0)).toBe(A);
    expect(hashOf(drifted, 0)).toBe(A);
  });

  it('is the same for two siblings whose anchored code is byte-identical — the bound on this discriminator', () => {
    // The hash covers the anchor's code tokens. Two exposures on one doc-block anchor the same
    // code, so they carry one hash and nothing here separates them. Stated so the claim is not
    // read as "the join is now unambiguous".
    const sarif = generateSarif(model({
      exposures: [
        exposure(),
        exposure({ description: 'a second claim on the same function', location: anchored('src/a.ts', 5, 'findUser', A) }),
      ],
    }));
    expect(hashOf(sarif, 0)).toBe(A);
    expect(hashOf(sarif, 1)).toBe(A);
  });
});
