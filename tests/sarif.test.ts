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
 * Threat-id minting (docs/prd/threat-id-design.md §3 + §5). Stability is the contract downstream
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
    const id = threatId('#ws-proxy', '#bac', 'api/ws/attach.go', 'anything');
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

  it('is stable across a line-number-only change (location line and an embedded line ref)', () => {
    const early = generateSarif(model({
      exposures: [exposure({ description: 'see handler at line 42', location: loc('api/ws/attach.go', 42) })],
    }));
    const drifted = generateSarif(model({
      // Same threat, but the code moved down the file: both the SARIF line and the description's
      // embedded "line NNN" changed. Neither is part of the identity.
      exposures: [exposure({ description: 'see handler at line 87', location: loc('api/ws/attach.go', 87) })],
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

  it('gives two distinct exposures sharing an asset::threat pair different ids', () => {
    // The collision the whole design exists to solve: same (asset, threat), different file/message.
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
});
