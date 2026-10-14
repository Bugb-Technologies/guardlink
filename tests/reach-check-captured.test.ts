/**
 * The reach-check reader against answers captured from a real code graph.
 *
 * tests/fixtures/reach-check/captured/ holds the tool result of
 * `codegraph_reach_check` exactly as a graph that implements the contract
 * returned it, for three repositories: this repository's own `support-desk`
 * fixture (a refund whose declared gate the code never calls), a small MCP
 * server with two tools no `@agents` covers, and a tree whose model export
 * disagrees with the graph, so the graph copied no gating. Nothing in them is
 * constructed, so these tests are the check that the reader has met the real
 * shape rather than the one it was written from.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { type CodeGraphTransport } from '../src/codegraph/index.js';
import {
  loadReachCheck, checkReach, reachDrafts, renderDrafts, renderUndeclaredToolsBlock, reachCheckSummaryLine, measuredRoutes,
  type ReachCheck,
} from '../src/codegraph/reach-check.js';
import { generateReport } from '../src/report/index.js';
import type { ThreatModel } from '../src/types/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const captured = async (name: string): Promise<unknown> =>
  JSON.parse(await readFile(join(here, 'fixtures', 'reach-check', 'captured', `${name}.reach-check.json`), 'utf-8'));

async function read(name: string): Promise<ReachCheck> {
  const value = await captured(name);
  const transport: CodeGraphTransport = { via: 'captured', async query(_r, calls) { return calls.map(() => ({ ok: true as const, value })); } };
  return loadReachCheck('.', { env: {}, transport });
}

describe('a real answer for the support-desk fixture', () => {
  let rc: ReachCheck;
  let model: ThreatModel;
  beforeAll(async () => {
    rc = await read('support-desk');
    ({ model } = await parseProject({ root: join(here, 'fixtures', 'support-desk'), project: 'support-desk' }));
  });

  it('reads every row: seven reaches, four gate rows, three unreached effects', () => {
    expect(rc).toMatchObject({ status: 'available', verdict: 'checked' });
    expect(rc.joins.state).toBe('copied');
    expect(rc.routes).toHaveLength(7);
    expect(rc.gates.map(g => g.measured)).toEqual(['no_gate_declared', 'no_gate_declared', 'bypassed', 'no_gate_declared']);
    expect(rc.unreached).toHaveLength(3);
    expect(rc.undeclared).toEqual([]);
  });

  it('warns once about the refund whose gate the graph finds on no route, and about the unreached effects, and nothing else', () => {
    const d = checkReach(rc);
    const gate = d.filter(x => x.code === 'gate-not-on-route');
    expect(gate).toHaveLength(1);
    expect(gate[0]).toMatchObject({ level: 'warning', file: 'src/tools.ts', line: 26 });
    expect(gate[0].message).toContain('the spend on #payments is gated by #support-human');
    expect(gate[0].message).toContain('src/tools.ts::issueRefund');
    expect(gate[0].message).toContain('claim to check, not a finding');
    expect(d.filter(x => x.code === 'effect-unreached-by-agent').map(x => `${x.file}:${x.line}`)).toEqual(['src/approval.ts:13', 'src/billing.ts:5', 'src/billing.ts:13']);
    expect(d.some(x => x.code === 'agent-tool-undeclared')).toBe(false);
    expect(d).toHaveLength(4);
    expect(reachCheckSummaryLine(rc, d)).toBe('Reach checks (code graph via captured): 7 declared reach(es) walked, 0 undeclared tool(s), 4 warning(s)');
  });

  it('joins each reach in the fixture\'s own model to its measured route, with the bypass beside the declared gate', () => {
    const rows = measuredRoutes(model, rc);
    expect(rows).toHaveLength(7);
    expect(rows.map(r => r.route).sort()).toEqual(['measured', 'measured', 'measured', 'measured', 'measured', 'measured', 'no_route']);
    const refund = rows.find(r => r.capability === 'issue-refund')!;
    expect(refund.text).toContain('spend on #payments');
    expect(refund.gates).toEqual(['spend on #payments: declared gated, graph bypassed']);
    expect(rows.find(r => r.capability === 'fetch-url')!.text).toBe('no route to a declared effect');
    const report = generateReport(model, rc);
    expect(report).toContain('### Measured Route (Code Graph)');
    expect(report).toContain('spend on #payments: declared gated, graph bypassed');
  });
});

describe('a real answer for an MCP server with undeclared tools', () => {
  it('warns about each, drafts an @agents for each and an @effects only where the graph reached a sink', async () => {
    const rc = await read('ops-server');
    expect(rc.undeclared.map(t => [t.tool, t.kind, t.hint_state, t.effect_hints])).toEqual([
      ['save_note', 'mcp_tool', 'SinksReached', ['write']],
      ['ping', 'mcp_tool', 'NoSinksReached', []],
    ]);
    const d = checkReach(rc).filter(x => x.code === 'agent-tool-undeclared');
    expect(d.map(x => `${x.file}:${x.line}`)).toEqual(['src/server.js:31', 'src/server.js:35']);
    expect(d[0].message).toContain('`save_note` registered here (mcp_tool, mcp)');
    expect(d[0].message).toContain('reaches filesystem');

    const drafts = reachDrafts(rc, null);
    expect(drafts[0].lines).toHaveLength(2);
    expect(drafts[0].lines[0]).toMatch(/^@agents <agent> to save_note on <asset>/);
    expect(drafts[0].lines[1]).toMatch(/^@effects write on <asset> -- "candidate: the handler reaches filesystem \(e\.g\. writeFileSync \(src\/server\.js:15\)\)/);
    expect(drafts[1].lines).toHaveLength(1);
    expect(renderDrafts(drafts)).toContain('src/server.js:31  save_note  (mcp_tool, mcp)');
    expect(renderUndeclaredToolsBlock(rc)).toContain('- src/server.js:31 save_note (mcp_tool) — handler reaches filesystem (candidate @effects: write)');
  });
});

describe('a real answer where the model export disagrees with the graph', () => {
  it('makes no gate warning and says the gate routes were not checked', async () => {
    const rc = await read('partial-export');
    expect(rc.joins.state).toBe('unavailable');
    expect(rc.gates.length).toBeGreaterThan(0);
    expect(rc.gates.every(g => g.measured === 'unknown' && g.reason === 'gate_join_unavailable')).toBe(true);
    const d = checkReach(rc);
    expect(d.some(x => x.code === 'gate-not-on-route')).toBe(false);
    expect(reachCheckSummaryLine(rc, d)).toContain('gate routes not checked (');
    expect(reachCheckSummaryLine(rc, d)).toContain('Re-export, or re-index.');
  });
});
