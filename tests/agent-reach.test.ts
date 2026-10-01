/**
 * Reach: `@agents`, `@reaches`, `@effects`, `@gates` (SPEC §3.2.1).
 *
 * The grammar of each verb, the two rules that follow from splitting reach into
 * an agent verb and a non-agent verb (`@agents` is what marks an actor an
 * agent; one actor under both verbs is an error), validation of the actors and
 * assets they name, and "can minus may" — `unentitled reaches` — answered by
 * lookup and by diff over a small support-desk app that embeds an agent.
 *
 * @validates #input-sanitize for #parser -- "Each reach verb parses only in its documented shape; an effect outside the closed set, a gate with no approver, or a reach with no `to` is malformed, never read as a claim"
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseLine } from '../src/parser/parse-line.js';
import { parseProject } from '../src/parser/parse-project.js';
import {
  findAgentReachConflicts, findDanglingRefs, findUndeclaredActors,
} from '../src/parser/validate.js';
import { findUnentitledReaches } from '../src/parser/reach.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { applyAnnotations } from '../src/parser/apply-annotations.js';
import { runGate } from '../src/gate/gate.js';
import { diffModels } from '../src/diff/engine.js';
import { formatDiff, formatDiffMarkdown } from '../src/diff/format.js';
import { lookup, SUPPORTED_QUERY_FORMS } from '../src/mcp/lookup.js';
import { agentInstructions, referenceDocContent } from '../src/init/templates.js';
import type { ThreatModel } from '../src/types/index.js';

const at = { file: 'src/agent/tools.ts', line: 3 };
const line = (text: string) => parseLine(text, at);

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

function writeProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-agent-reach-'));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return root;
}

async function parseFiles(files: Record<string, string>) {
  return parseProject({ root: writeProject(files), project: 'agent-reach' });
}

// ─── Grammar ─────────────────────────────────────────────────────────

describe('@agents and @reaches', () => {
  it('parse every clause, and record which verb was written', () => {
    const full = line('@agents #support-agent to run-sql on #tool-surface as #agent-session -- "Debug tool, still registered"');
    expect(full.diagnostic).toBeNull();
    expect(full.annotation).toMatchObject({
      verb: 'agents', actor: '#support-agent', capability: 'run-sql', canonical_capability: 'run_sql',
      asset: '#tool-surface', identity: '#agent-session', description: 'Debug tool, still registered',
    });

    const ci = line('@reaches #ci-runner to publish-package on Registry.Npm as #npm-token');
    expect(ci.annotation).toMatchObject({
      verb: 'reaches', actor: '#ci-runner', capability: 'publish-package', asset: 'Registry.Npm', identity: '#npm-token',
    });
  });

  it('take on, as and the description as optional, and a declared name as the actor', () => {
    expect(line('@agents #bot to search-kb').annotation)
      .toMatchObject({ verb: 'agents', actor: '#bot', capability: 'search-kb', asset: undefined, identity: undefined });
    expect(line('@agents Support_Agent to search-kb as #session').annotation)
      .toMatchObject({ actor: 'Support_Agent', asset: undefined, identity: '#session' });
    expect(line('@reaches #ci to deploy on #prod -- "d"').annotation)
      .toMatchObject({ verb: 'reaches', asset: '#prod', identity: undefined, description: 'd' });
  });

  it('refuse a capability written as prose, and a missing `to`', () => {
    for (const text of [
      '@agents #bot to "run any sql" on #db',
      '@agents #bot run-sql on #db',
      '@reaches #ci on #prod',
    ]) {
      const r = line(text);
      expect(r.annotation, text).toBeNull();
      expect(r.diagnostic?.code, text).toBe('malformed-annotation');
    }
  });
});

describe('@effects', () => {
  it('parses each of the six effects, with an optional execution identity', () => {
    for (const effect of ['read', 'write', 'delete', 'execute', 'spend', 'notify']) {
      expect(line(`@effects ${effect} on #orders-db`).annotation, effect)
        .toMatchObject({ verb: 'effects', effect, asset: '#orders-db', identity: undefined });
    }
    expect(line('@effects spend on #payments as #billing-sa -- "postRefund calls the processor"').annotation)
      .toMatchObject({ effect: 'spend', asset: '#payments', identity: '#billing-sa', description: 'postRefund calls the processor' });
  });

  it('refuses an effect outside the closed set, so egress cannot be spelled twice', () => {
    for (const text of ['@effects send on #mail', '@effects egress on #internet', '@effects write #db']) {
      const r = line(text);
      expect(r.annotation, text).toBeNull();
      expect(r.diagnostic?.code, text).toBe('malformed-annotation');
    }
    // With no #ref and no effect word there is no evidence of an attempt, so it
    // is reported as prose — still never read as a claim.
    const r = line('@effects egress on External.Internet');
    expect(r.annotation).toBeNull();
    expect(r.diagnostic?.code).toBe('prose-like');
  });

  it('reads prose about the verb as prose, not as a broken annotation', () => {
    const r = line('@effects on the model are described in the spec');
    expect(r.annotation).toBeNull();
    expect(r.diagnostic?.code).toBe('prose-like');
    expect(r.diagnostic?.level).toBe('warning');
    // An effect word in the first position is how the verb starts, so it is evidence.
    expect(line('@effects write the users table').diagnostic?.code).toBe('malformed-annotation');
  });
});

describe('@gates', () => {
  it('requires `by <approver>` and takes `for <capability>` as optional', () => {
    expect(line('@gates #payments by #support-human for issue-refund -- "requireApproval() blocks"').annotation)
      .toMatchObject({
        verb: 'gates', asset: '#payments', approver: '#support-human',
        capability: 'issue-refund', canonical_capability: 'issue_refund', description: 'requireApproval() blocks',
      });
    expect(line('@gates #payments by Support_Human').annotation)
      .toMatchObject({ approver: 'Support_Human', capability: undefined, canonical_capability: undefined });

    const noApprover = line('@gates #payments -- "a human looks at it"');
    expect(noApprover.annotation).toBeNull();
    expect(noApprover.diagnostic?.code).toBe('malformed-annotation');
  });

  it('carries no advisory or blocking qualifier', () => {
    expect(line('@gates #payments by #support-human [blocking]').annotation).toBeNull();
  });
});

// ─── The fixture agent app ───────────────────────────────────────────

const DEFINITIONS = `/**
 * @asset Agent.ToolSurface (#tool-surface) -- "Tools registered with the support agent"
 * @asset Shop.OrdersDb (#orders-db) -- "Orders table"
 * @asset Shop.UsersDb (#users-db) -- "Users table"
 * @asset Shop.Payments (#payments) -- "Refunds through the payment processor"
 * @asset Shop.Kb (#kb) -- "Help-centre articles"
 * @asset Host.Fs (#host-fs) -- "The host filesystem"
 * @asset Identity.AgentSession (#agent-session) -- "Customer-scoped token the agent presents"
 * @asset Identity.BillingSa (#billing-sa) -- "Service account that can move money"
 * @threat Excessive_Agency (#excessive-agency) [high] -- "Agent holds a capability nobody approved"
 * @actor Support_Agent (#support-agent) -- "LLM agent; acts for the signed-in customer"
 * @actor Support_Human (#support-human) -- "Approves refunds in the review queue"
 * @actor CI_Runner (#ci-runner) -- "Release pipeline"
 */
export {};
`;

const TOOLS = `/**
 * @agents #support-agent to lookup-order on #tool-surface as #agent-session
 * @agents #support-agent to run-sql on #tool-surface -- "Debug tool, still registered"
 * @agents #support-agent to issue-refund on #tool-surface
 * @agents #support-agent to search-kb on #tool-surface
 * @agents #support-agent to fetch-url on #tool-surface
 * @agents #support-agent to mcp-files on #tool-surface -- "Filesystem MCP server rooted at /"
 * @entitles #support-agent to lookup-order on #tool-surface against #excessive-agency -- "By design. Authz: src/agent/policy.ts:10"
 * @entitles #support-agent to issue-refund on #tool-surface against #excessive-agency -- "By design. Authz: src/agent/policy.ts:14"
 * @entitles #support-agent to search-kb on #kb against #excessive-agency -- "By design. Authz: src/agent/policy.ts:18"
 * @entitles #support-agent to fetch-url -- "Uncited, so it covers nothing"
 */
export function registerTools(): void {}
`;

const ACTIONS = `/**
 * @effects read on #orders-db -- "findOrder"
 * @effects delete on #orders-db -- "runRaw executes the model's SQL"
 * @effects write on #users-db -- "runRaw executes the model's SQL"
 * @effects spend on #payments as #billing-sa -- "postRefund"
 * @effects read on #kb -- "search"
 * @effects write on #host-fs -- "mountFiles"
 * @gates #payments by #support-human for issue-refund -- "requireApproval() parks the refund until a human approves"
 */
export function act(): void {}
`;

const CI = `/**
 * @reaches #ci-runner to publish-package on #tool-surface -- "npm publish in release.yml"
 */
export function release(): void {}
`;

const APP = {
  '.guardlink/definitions.ts': DEFINITIONS,
  'src/agent/tools.ts': TOOLS,
  'src/agent/actions.ts': ACTIONS,
  'src/ci/release.ts': CI,
};

describe('the model', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseFiles(APP)); });

  it('collects @agents and @reaches in one array, flagging which rows are agents', () => {
    expect(model.reaches).toHaveLength(7);
    expect(model.reaches!.filter(r => r.agent).map(r => r.capability))
      .toEqual(['lookup-order', 'run-sql', 'issue-refund', 'search-kb', 'fetch-url', 'mcp-files']);
    expect(model.reaches!.filter(r => !r.agent)).toMatchObject([{ actor: '#ci-runner', capability: 'publish-package' }]);
    expect(model.effects).toHaveLength(6);
    expect(model.gates).toMatchObject([{ asset: '#payments', approver: '#support-human', capability: 'issue-refund' }]);
  });

  it('gives each claim a key, and moves the annotation hash when one is added', async () => {
    const verbs = relationRecords(model).map(r => r.verb);
    expect(verbs.filter(v => v === 'agents')).toHaveLength(6);
    expect(verbs.filter(v => v === 'reaches')).toHaveLength(1);
    expect(verbs.filter(v => v === 'effects')).toHaveLength(6);
    expect(verbs.filter(v => v === 'gates')).toHaveLength(1);

    const { model: more } = await parseFiles({
      ...APP, 'src/ci/release.ts': CI.replace(' */', ' * @reaches #ci-runner to tag-release on #tool-surface\n */'),
    });
    expect(computeAnnotationHash(more)).not.toBe(computeAnnotationHash(model));
  });

  it('validates clean', () => {
    expect(findUndeclaredActors(model)).toEqual([]);
    expect(findAgentReachConflicts(model)).toEqual([]);
    expect(findDanglingRefs(model)).toEqual([]);
  });
});

// ─── Validation ──────────────────────────────────────────────────────

describe('validation', () => {
  it('errors when one actor is named under both @agents and @reaches, in any spelling', async () => {
    const { model } = await parseFiles({
      ...APP,
      'src/ci/release.ts': CI.replace(' */', ' * @reaches Support_Agent to tag-release on #tool-surface\n */'),
    });
    const diags = findAgentReachConflicts(model);
    expect(diags).toHaveLength(1);
    expect(diags[0]).toMatchObject({ level: 'error', code: 'agent-reach-conflict', file: 'src/ci/release.ts', line: 3 });
    expect(diags[0].message).toContain('src/agent/tools.ts:2');
  });

  it('reports an undeclared actor on @agents, @reaches and as a @gates approver', async () => {
    const { model } = await parseFiles({
      '.guardlink/definitions.ts': '// @asset App.Db (#db) -- "d"\nexport {};\n',
      'src/a.ts': [
        '// @agents #ghost-agent to run-sql on #db',
        '// @reaches #ghost-runner to deploy on #db',
        '// @gates #db by #nobody -- "approve()"',
        'export {};',
      ].join('\n'),
    });
    const diags = findUndeclaredActors(model);
    expect(diags.map(d => [d.code, d.level, d.line])).toEqual([
      ['undeclared-actor', 'error', 1], ['undeclared-actor', 'error', 2], ['undeclared-actor', 'error', 3],
    ]);
    expect(diags.map(d => d.message.split(' names')[0])).toEqual(['@agents', '@reaches', '@gates']);
  });

  it('reports an undefined asset or identity as a dangling ref', async () => {
    const { model } = await parseFiles({
      '.guardlink/definitions.ts': '// @actor Bot (#bot) -- "agent"\nexport {};\n',
      'src/a.ts': [
        '// @agents #bot to run-sql on #no-surface as #no-session',
        '// @effects write on #no-db as #no-sa',
        '// @gates #no-asset by #bot',
        'export {};',
      ].join('\n'),
    });
    const dangling = findDanglingRefs(model).map(d => d.message.match(/#[\w-]+/)![0]);
    expect(dangling).toEqual(['#no-surface', '#no-session', '#no-db', '#no-sa', '#no-asset']);
  });
});

// ─── Can minus may ───────────────────────────────────────────────────

describe('unentitled reaches', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseFiles(APP)); });

  it('lists the reaches no cited entitlement covers, with why a near miss does not count', () => {
    const r = lookup(model, 'unentitled reaches');
    expect(r.type).toBe('unentitled_reaches');
    expect(r.results.map(x => x.capability)).toEqual(['run_sql', 'search_kb', 'fetch_url', 'mcp_files', 'publish_package']);
    const byCap = Object.fromEntries(r.results.map(x => [x.capability, x]));
    expect(byCap.run_sql.near_misses).toEqual([]);
    // The search-kb entitlement names another asset; the fetch-url one is uncited.
    expect(byCap.search_kb.near_misses).toMatchObject([{ blocker: 'other-asset', asset: '#kb' }]);
    expect(byCap.fetch_url.near_misses).toMatchObject([{ blocker: 'uncited' }]);
    expect(byCap.run_sql).toMatchObject({ actor: '#support-agent', agent: true, file: 'src/agent/tools.ts', line: 3 });
  });

  it('narrows to one actor, by id or declared name', () => {
    expect(lookup(model, 'unentitled reaches for #ci-runner').results.map(x => x.capability)).toEqual(['publish_package']);
    expect(lookup(model, 'unentitled reaches for CI_Runner').count).toBe(1);
  });

  it('does not let an entitlement naming no asset cover a reach that names one', async () => {
    const { model: m } = await parseFiles({
      ...APP,
      'src/agent/tools.ts': TOOLS.replace(' */', ' * @entitles #support-agent to run-sql against #excessive-agency -- "Authz: src/agent/policy.ts:30"\n */'),
    });
    const runSql = findUnentitledReaches(m).find(u => u.reach.capability === 'run-sql')!;
    expect(runSql.near_misses.map(n => n.blocker)).toEqual(['no-asset']);
  });

  it('is closed by a cited entitlement on the same actor, capability and asset', async () => {
    const { model: m } = await parseFiles({
      ...APP,
      'src/agent/tools.ts': TOOLS.replace(' */', ' * @entitles Support_Agent to run_sql on Agent.ToolSurface against #excessive-agency -- "Authz: src/agent/policy.ts:30"\n */'),
    });
    expect(findUnentitledReaches(m).map(u => u.reach.capability)).not.toContain('run-sql');
  });
});

describe('lookup forms', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseFiles(APP)); });

  it('lists every reach, or only the agents, by actor', () => {
    expect(lookup(model, 'reaches').count).toBe(7);
    expect(lookup(model, 'agents')).toMatchObject({ type: 'agents', count: 6 });
    expect(lookup(model, 'reaches for #ci-runner').results).toMatchObject([{ agent: false, capability: 'publish_package' }]);
    expect(lookup(model, 'agents for #ci-runner').count).toBe(0);
  });

  it('scopes effects and gates by asset, resolving the ref as `asset X` does', () => {
    const effects = lookup(model, 'effects for Shop.OrdersDb');
    expect(effects.results.map(e => [e.effect, e.mutating])).toEqual([['read', false], ['delete', true]]);
    expect(effects.matched_via).toBe(lookup(model, 'asset Shop.OrdersDb').matched_via);
    expect(lookup(model, 'effects').count).toBe(6);
    expect(lookup(model, 'gates for #payments').results).toMatchObject([{ approver: '#support-human', capability: 'issue_refund' }]);
  });

  it('marks an actor named by @agents as an agent', () => {
    const actors = Object.fromEntries(lookup(model, 'actors').results.map(a => [a.id, a]));
    expect(actors['support-agent'].agent).toBe(true);
    expect(actors['support-agent'].reaches).toHaveLength(6);
    expect(actors['ci-runner'].agent).toBe(false);
    expect(actors['support-human']).toMatchObject({ agent: false, reaches: [] });
  });

  it('lists the forms when a query is not one', () => {
    expect(SUPPORTED_QUERY_FORMS.some(f => f.startsWith('unentitled reaches'))).toBe(true);
  });
});

// ─── Diff ────────────────────────────────────────────────────────────

describe('diff', () => {
  it('reports a new reach, and a reach that is newly unentitled', async () => {
    const { model: before } = await parseFiles(APP);
    const { model: after } = await parseFiles({
      ...APP,
      'src/agent/tools.ts': TOOLS.replace(' */', ' * @agents #support-agent to run-shell on #host-fs -- "exec tool"\n */'),
    });
    const diff = diffModels(before, after);
    expect(diff.reaches).toMatchObject([{ kind: 'added', item: { capability: 'run-shell', agent: true } }]);
    expect(diff.newUnentitledReaches.map(r => r.capability)).toEqual(['run-shell']);
    expect(diff.summary.newUnentitledReaches).toBe(1);

    const text = formatDiff(diff);
    expect(text).toContain('── New Unentitled Reaches');
    expect(text).toContain('+ @agents #support-agent to run-shell on #host-fs');
    expect(formatDiffMarkdown(diff)).toContain('New Unentitled Reaches');
  });

  it('reports a reach that was already unentitled as no new risk', async () => {
    const { model: before } = await parseFiles(APP);
    const { model: after } = await parseFiles({
      ...APP, 'src/agent/tools.ts': TOOLS.replace('"Debug tool, still registered"', '"Debug tool"'),
    });
    const diff = diffModels(before, after);
    expect(diff.reaches).toMatchObject([{ kind: 'modified', details: 'description changed' }]);
    expect(diff.newUnentitledReaches).toEqual([]);
  });

  it('reports withdrawing an entitlement as a newly unentitled reach', async () => {
    const { model: before } = await parseFiles(APP);
    const { model: after } = await parseFiles({
      ...APP, 'src/agent/tools.ts': TOOLS.replace(/^ \* @entitles #support-agent to lookup-order.*\n/m, ''),
    });
    expect(diffModels(before, after).newUnentitledReaches.map(r => r.capability)).toEqual(['lookup-order']);
  });

  it('reports effects and gates', async () => {
    const { model: before } = await parseFiles(APP);
    const { model: after } = await parseFiles({
      ...APP, 'src/agent/actions.ts': ACTIONS.replace(/^ \* @gates.*\n/m, ''),
    });
    const diff = diffModels(before, after);
    expect(diff.gates).toMatchObject([{ kind: 'removed', item: { asset: '#payments' } }]);
    expect(formatDiff(diff)).toContain('── Gates ──');
  });
});

// ─── The annotate gate ───────────────────────────────────────────────

describe('what an agent may write', () => {
  it('applies the four reach verbs and still refuses @entitles and @accepts', () => {
    const root = writeProject({ 'src/agent/tools.ts': 'export function registerTools() {}\n' });
    const ok = applyAnnotations({
      root, file: 'src/agent/tools.ts', line: 1, dryRun: true,
      annotations: [
        '@agents #support-agent to run-sql on #tool-surface',
        '@reaches #ci-runner to publish-package',
        '@effects write on #users-db',
        '@gates #payments by #support-human -- "requireApproval()"',
      ],
    });
    expect(ok.errors).toEqual([]);
    expect(ok.ok).toBe(true);

    for (const governance of [
      '@entitles #support-agent to run-sql on #tool-surface -- "Authz: a.ts:1"',
      '@accepts #excessive-agency on #tool-surface -- "fine"',
    ]) {
      const refused = applyAnnotations({ root, file: 'src/agent/tools.ts', line: 1, dryRun: true, annotations: [governance] });
      expect(refused.status, governance).toBe('rejected');
    }
  });

  it('lets the gate accept added reach claims, warning only on a gate that says nothing', async () => {
    const { model: before } = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS });
    const { model: after } = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'src/agent/tools.ts': [
        '// @agents #support-agent to run-sql on #tool-surface',
        '// @effects write on #users-db -- "runRaw executes the SQL"',
        '// @gates #payments by #support-human',
        'export {};',
      ].join('\n'),
    });
    const report = runGate(before, after);
    expect(report.added.map(a => a.verb)).toEqual(['agents', 'effects', 'gates']);
    expect(report.errors).toBe(0);
    expect(report.violations).toMatchObject([{ rule: 'description-vague', level: 'warn', verb: 'gates' }]);
  });
});

// ─── What agents are taught ──────────────────────────────────────────

describe('instruction templates', () => {
  const project = { name: 'app', language: 'typescript', definitionsExt: '.ts' } as Parameters<typeof referenceDocContent>[0];

  it('list the reach verbs as writable, and every example they show parses', () => {
    const texts = [referenceDocContent(project), agentInstructions(project, 'inline')];
    for (const text of texts) {
      for (const verb of ['@agents', '@reaches', '@effects', '@gates']) expect(text).toContain(verb);
    }
    const examples = agentInstructions(project, 'inline').split('\n')
      .filter(l => /^@(agents|reaches|effects|gates) /.test(l));
    expect(examples.length).toBeGreaterThan(0);
    for (const example of examples) expect(line(example).annotation, example).not.toBeNull();
  });
});

// ─── CLI ─────────────────────────────────────────────────────────────

describe('guardlink lookup (CLI)', () => {
  const cli = resolve(__dirname, '..', 'dist', 'cli', 'index.js');

  it('prints the lookup answer as JSON and fails on request when it finds something', () => {
    const root = writeProject(APP);
    const out = JSON.parse(execFileSync('node', [cli, 'lookup', 'unentitled', 'reaches', '-d', root], { encoding: 'utf8' }));
    expect(out).toMatchObject({ type: 'unentitled_reaches', count: 5 });

    let status = 0;
    try {
      execFileSync('node', [cli, 'lookup', 'unentitled reaches', '-d', root, '--fail-on-found'], { stdio: 'pipe' });
    } catch (e) {
      status = (e as { status: number }).status;
    }
    expect(status).toBe(1);
  });
});
