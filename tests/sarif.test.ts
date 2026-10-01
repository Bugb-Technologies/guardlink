import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSarif, threatId } from '../src/analyzer/sarif.js';
import { parseProject } from '../src/parser/parse-project.js';
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

  it('reports two routes in one file, neither on the finding, as ambiguous rather than picking the first', () => {
    // No anchors here, so the finding is file-level and both routes are candidates.
    const sarif = generateSarif(model({
      exposures: [{ asset: '#orders', threat: '#sqli', severity: 'critical', external_refs: [], location: loc('app/orders.py', 11) } as never],
      flows: [
        { source: '#client', target: '#orders', mechanism: 'GET./orders/<id>', location: loc('app/orders.py', 4) } as never,
        { source: '#client', target: '#orders', mechanism: 'POST./pay', location: loc('app/orders.py', 10) } as never,
      ],
    }));
    const props = findingProps(sarif, '#orders');
    expect(props?.codegraph_reachability).toBeUndefined();
    expect(props?.route_attribution).toBe('ambiguous');
    expect(props?.route_candidates).toEqual([
      { http_method: 'GET', http_path: '/orders/<id>', file: 'app/orders.py', line: 4 },
      { http_method: 'POST', http_path: '/pay', file: 'app/orders.py', line: 10 },
    ]);
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
 * The claim key on each exposure result. It is the identity of the CLAIM — the same
 * key the hypothesis ledger keys an entry on — not of the location and not of the
 * code beneath it, which is the property a consumer joining a finding back to a
 * claim needs: two siblings that share a threat id (same asset, same threat, same
 * file) are separable by it, and it does not move when the claim does.
 */
describe('generateSarif — claim key (partialFingerprints + properties.claimKey)', () => {
  const exposure = (over: Record<string, unknown> = {}) => ({
    asset: '#api', threat: '#sqli', severity: 'critical', external_refs: [],
    description: 'findUser concatenates email', location: loc('src/a.ts', 4), ...over,
  } as never);

  const keyOf = (sarif: ReturnType<typeof generateSarif>, i: number) =>
    (sarif.runs[0].results[i].properties as Record<string, unknown>).claimKey as string | undefined;

  it('emits the fingerprint and properties.claimKey, equal, on exposure results', () => {
    const sarif = generateSarif(model({ exposures: [exposure()] }));
    const r = sarif.runs[0].results[0];
    const fromProps = (r.properties as Record<string, unknown>).claimKey;
    expect(fromProps).toMatch(/^[0-9a-f]{64}:\d+$/);
    expect(r.partialFingerprints?.['guardlink/claimKey']).toBe(fromProps);
  });

  it('emits NO claim key on a confirmed result — a key stamped from one could join to nothing', () => {
    // The verb is part of the key digest, so an @exposes and the @confirmed that
    // proves it hold different keys; and the ledger keys entries by exposure only.
    // A key on a confirmed result would be an identifier that looks usable and is
    // not, so none is emitted — and the sibling exposure's key is NOT borrowed,
    // which would assert a link the model does not declare.
    const sarif = generateSarif(model({ exposures: [exposure()], confirmed: [exposure()] }));
    expect(sarif.runs[0].results.length).toBe(2);
    const conf = sarif.runs[0].results.find(r => r.ruleId === 'guardlink/confirmed-exploitable')!;
    const exp = sarif.runs[0].results.find(r => r.ruleId !== 'guardlink/confirmed-exploitable')!;

    expect(conf.properties).not.toHaveProperty('claimKey');
    expect(conf.partialFingerprints).not.toHaveProperty('guardlink/claimKey');
    // The threat id is untouched, and is still shared across the claim's lifecycle.
    expect(conf.partialFingerprints?.['guardlink/threatId']).toBe(exp.partialFingerprints?.['guardlink/threatId']);
    // The exposure still carries its own.
    expect((exp.properties as Record<string, unknown>).claimKey).toMatch(/^[0-9a-f]{64}:\d+$/);
    expect(Object.values(conf.partialFingerprints ?? {})).not.toContain((exp.properties as Record<string, unknown>).claimKey);
  });

  it('is present on a claim with no anchor — the key does not depend on one', () => {
    const sarif = generateSarif(model({ exposures: [exposure()] }));
    const r = sarif.runs[0].results[0];
    expect(r.locations[0].physicalLocation.region.startLine).toBe(4);
    expect((r.properties as Record<string, unknown>).claimKey).toMatch(/^[0-9a-f]{64}:\d+$/);
    expect(r.partialFingerprints?.['guardlink/claimKey']).toMatch(/^[0-9a-f]{64}:\d+$/);
    // The threat id is untouched.
    expect(r.partialFingerprints?.['guardlink/threatId']).toMatch(/^gl-[0-9a-f]{12}$/);
  });

  it('separates two siblings that share one threat id', () => {
    // GAP-58: same asset, same threat, same file, so the threat id cannot tell them apart.
    const sarif = generateSarif(model({
      exposures: [
        exposure(),
        exposure({ description: 'findOrder concatenates id', location: loc('src/a.ts', 9) }),
      ],
    }));
    const ids = sarif.runs[0].results.map(r => (r.properties as Record<string, unknown>).threatId);
    expect(ids[0]).toBe(ids[1]);
    expect(keyOf(sarif, 0)).not.toBe(keyOf(sarif, 1));
  });

  it('does not move when only the line moves', () => {
    const early = generateSarif(model({ exposures: [exposure()] }));
    const drifted = generateSarif(model({ exposures: [exposure({ location: loc('src/a.ts', 87) })] }));
    expect(keyOf(drifted, 0)).toBe(keyOf(early, 0));
  });

  it('moves when the claim itself changes — the description is part of it', () => {
    const before = generateSarif(model({ exposures: [exposure()] }));
    const reworded = generateSarif(model({ exposures: [exposure({ description: 'findUser concatenates the email' })] }));
    expect(keyOf(reworded, 0)).not.toBe(keyOf(before, 0));
  });

  it('separates two byte-identical claims in one file only by an ordinal — the bound on this discriminator', () => {
    // Same verb, asset, threat, refs AND description: one digest, told apart in
    // document order. Delete the first and the survivor inherits `<digest>:0`.
    // Stated so the claim is not read as "every claim key is permanent".
    const sarif = generateSarif(model({
      exposures: [exposure(), exposure({ location: loc('src/a.ts', 5) })],
    }));
    const [first, second] = [keyOf(sarif, 0)!, keyOf(sarif, 1)!];
    expect(first.split(':')[0]).toBe(second.split(':')[0]);
    expect([first.split(':')[1], second.split(':')[1]]).toEqual(['0', '1']);

    const survivorAlone = generateSarif(model({ exposures: [exposure({ location: loc('src/a.ts', 5) })] }));
    expect(keyOf(survivorAlone, 0)).toBe(first);
  });
});

/**
 * One file, three handlers, one asset — parsed from source, so every claim has
 * the handler scope the structure layer resolves (SPEC §3.6).
 *
 * Before handler scope, routes were keyed by file with the first declaration
 * winning, so the injection on `pay` was exported as reachable through
 * `GET /orders/<id>`; and coverage was keyed by (asset, threat), so the one
 * `@mitigates` on `update_order` removed BOTH idor exposures from the export.
 */
describe('generateSarif — handler scope, end to end', () => {
  const roots: string[] = [];
  afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

  const ORDERS = `import db


# @flows #client -> #orders via GET./orders/<id>
# @exposes #orders to #idor [high] -- "no owner check on read"
def get_order(order_id):
    return db.get(order_id)


# @flows #client -> #orders via POST./pay
# @exposes #orders to #sqli [critical] cwe:CWE-89 -- "amount concatenated"
def pay(amount):
    return db.execute("UPDATE o SET a=" + amount)


# @flows #client -> #orders via DELETE./orders/<id>
# @exposes #orders to #idor [high] -- "no owner check on delete"
def delete_order(order_id):
    return db.delete(order_id)
`;
  const UPDATE = `

# @flows #client -> #orders via PUT./orders/<id>
# @mitigates #orders against #idor using #owner-check -- "owner checked before update"
def update_order(order_id, user):
    check_owner(order_id, user)
    return db.update(order_id)
`;

  async function sarifFor(source: string) {
    const root = mkdtempSync(join(tmpdir(), 'gl-sarif-handlers-'));
    roots.push(root);
    mkdirSync(join(root, 'app'), { recursive: true });
    writeFileSync(join(root, 'app', 'orders.py'), source);
    const { model } = await parseProject({ root, project: 'handlers' });
    return generateSarif(model);
  }
  const exposureResults = (sarif: ReturnType<typeof generateSarif>) => sarif.runs[0].results
    .filter(r => r.ruleId.startsWith('guardlink/unmitigated'))
    .map(r => ({
      line: r.locations[0].physicalLocation.region.startLine,
      threat: (r.properties as Record<string, unknown>).threat,
      route: (r.properties as Record<string, unknown>).codegraph_reachability,
      attribution: (r.properties as Record<string, unknown>).route_attribution,
    }))
    .sort((a, b) => a.line - b.line);

  it('labels each finding with the route declared on its own handler', async () => {
    expect(exposureResults(await sarifFor(ORDERS))).toEqual([
      { line: 5, threat: '#idor', route: { http_method: 'GET', http_path: '/orders/<id>' }, attribution: 'handler' },
      { line: 11, threat: '#sqli', route: { http_method: 'POST', http_path: '/pay' }, attribution: 'handler' },
      { line: 17, threat: '#idor', route: { http_method: 'DELETE', http_path: '/orders/<id>' }, attribution: 'handler' },
    ]);
  });

  it('a @mitigates on one handler leaves the same pair on sibling handlers in the export', async () => {
    const lines = exposureResults(await sarifFor(ORDERS + UPDATE)).map(r => r.line);
    expect(lines).toEqual([5, 11, 17]);
  });

  it('a @mitigates on the exposure\'s own handler still removes it — and only it', async () => {
    const fixed = ORDERS.replace(
      '# @exposes #orders to #idor [high] -- "no owner check on delete"\n',
      '# @exposes #orders to #idor [high] -- "no owner check on delete"\n'
        + '# @mitigates #orders against #idor using #owner-check -- "owner checked before delete"\n',
    );
    expect(exposureResults(await sarifFor(fixed)).map(r => r.line)).toEqual([5, 11]);
  });
});
