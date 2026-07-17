import { describe, it, expect } from 'vitest';
import { generateSarif } from '../src/analyzer/sarif.js';
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
