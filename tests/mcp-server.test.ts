/**
 * Drives the real MCP server over an in-memory transport.
 *
 * These cases are about the server's *session behaviour* — what the cache serves
 * after the filesystem moves underneath it — which is not observable by calling
 * the underlying functions directly. Everything here goes through the same
 * JSON-RPC path a Claude Code or Cursor client would use.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';

const DEFINITIONS = `/**
 * @asset App.Auth (#auth) -- "Authentication surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const ANNOTATED_SOURCE = `/**
 * Login handler.
 *
 * @exposes #auth to #sqli [critical] cwe:CWE-89 -- "Query built by concatenation"
 * @flows User -> #auth via HTTPS -- "Login request path"
 */
export function login(email: string): boolean {
  return email.length > 0;
}
`;

/** Connect a client to a freshly created server over paired in-memory transports. */
async function connect() {
  const server = createServer();
  const client = new Client({ name: 'test', version: '0.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, close: () => client.close() };
}

/** First text block of a tool result — the payload, unchanged by the envelope. */
function payload(result: any): string {
  return result.content[0].text;
}

describe('MCP server — cache invalidation after a destructive write (D11)', () => {
  let root: string;
  let session: Awaited<ReturnType<typeof connect>>;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-mcp-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'auth.ts'), ANNOTATED_SOURCE);
    session = await connect();
  });

  afterEach(async () => {
    await session.close();
    await rm(root, { recursive: true, force: true });
  });

  it('status reflects a non-dry-run clear in the same session', async () => {
    const before = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_status', arguments: { root } }),
    ));
    expect(before.exposures).toBe(1);
    expect(before.flows).toBe(1);

    const cleared = payload(
      await session.client.callTool({ name: 'guardlink_clear', arguments: { root, dry_run: false } }),
    );
    expect(cleared).toMatch(/^Removed /);

    // Before the fix this returned the pre-clear counts for the rest of the
    // session: guardlink_clear was the only annotation-mutating tool that did
    // not invalidate.
    const after = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_status', arguments: { root } }),
    ));
    expect(after.exposures).toBe(0);
    expect(after.flows).toBe(0);
  });

  it('a dry-run clear leaves the model untouched', async () => {
    await session.client.callTool({ name: 'guardlink_status', arguments: { root } });
    await session.client.callTool({ name: 'guardlink_clear', arguments: { root, dry_run: true } });

    const after = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_status', arguments: { root } }),
    ));
    expect(after.exposures).toBe(1);
  });

  it('lookup stops resolving an annotation that was cleared from disk', async () => {
    const before = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_lookup', arguments: { root, query: 'exposures for #auth' } }),
    ));
    expect(before.count).toBe(1);

    await session.client.callTool({ name: 'guardlink_clear', arguments: { root, dry_run: false } });

    const after = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_lookup', arguments: { root, query: 'exposures for #auth' } }),
    ));
    expect(after.count).toBe(0);
  });
});

// ─── GL-103: the cache follows the filesystem, with no explicit invalidation ──

describe('MCP server — fingerprint invalidation (D5)', () => {
  let root: string;
  let session: Awaited<ReturnType<typeof connect>>;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-mcp-fp-'));
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'auth.ts'), 'export function login() { return true; }\n');
    await writeFile(
      join(root, '.guardlink', 'annotations', 'src', 'auth.ts.gal'),
      '@source file:src/auth.ts line:1 symbol:login\n@exposes #auth to #sqli [critical] -- "Concatenated SQL"\n',
    );
    session = await connect();
  });

  afterEach(async () => {
    await session.close();
    await rm(root, { recursive: true, force: true });
  });

  it('editing a .gal is reflected without any invalidating tool call', async () => {
    const before = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_status', arguments: { root } }),
    ));
    expect(before.exposures).toBe(1);
    expect(before.mitigations).toBe(0);

    // The source file does not move — only the sidecar. In external mode this is
    // the only signal there is, which is why root-only cache keying failed here.
    await writeFile(
      join(root, '.guardlink', 'annotations', 'src', 'auth.ts.gal'),
      '@source file:src/auth.ts line:1 symbol:login\n'
      + '@exposes #auth to #sqli [critical] -- "Concatenated SQL"\n'
      + '@mitigates #auth against #sqli using #prepared-stmts -- "Parameterized"\n',
    );

    // guardlink_status is one of the thirteen tools that never invalidated.
    const after = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_status', arguments: { root } }),
    ));
    expect(after.mitigations).toBe(1);
  });

  it('a new .gal appearing mid-session is picked up', async () => {
    await session.client.callTool({ name: 'guardlink_status', arguments: { root } });

    await writeFile(join(root, 'src', 'db.ts'), 'export function q() { return []; }\n');
    await writeFile(
      join(root, '.guardlink', 'annotations', 'src', 'db.ts.gal'),
      '@source file:src/db.ts line:1 symbol:q\n@flows #auth -> #auth via query -- "lookup"\n',
    );

    const after = JSON.parse(payload(
      await session.client.callTool({ name: 'guardlink_status', arguments: { root } }),
    ));
    expect(after.flows).toBe(1);
  });

  it('an untouched project is served from cache (fingerprint is stable)', async () => {
    const a = JSON.parse(payload(await session.client.callTool({ name: 'guardlink_status', arguments: { root } })));
    const b = JSON.parse(payload(await session.client.callTool({ name: 'guardlink_status', arguments: { root } })));
    expect(b).toEqual(a);
  });
});

// ─── GL-102 / GL-104: freshness envelope and resource scoping ────────

describe('MCP server — freshness envelope (GL-102)', () => {
  let root: string;
  let session: Awaited<ReturnType<typeof connect>>;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-mcp-env-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'auth.ts'), ANNOTATED_SOURCE);
    session = await connect();
  });

  afterEach(async () => {
    await session.close();
    await rm(root, { recursive: true, force: true });
  });

  /** The envelope block — always last, always a sibling of the payload. */
  function envelope(result: any) {
    const blocks = result.content;
    return JSON.parse(blocks[blocks.length - 1].text).guardlink;
  }

  const ALL_TOOLS = [
    'guardlink_parse', 'guardlink_status', 'guardlink_validate', 'guardlink_suggest',
    'guardlink_context', 'guardlink_graph', 'guardlink_annotate_apply',
    'guardlink_lookup', 'guardlink_threat_report', 'guardlink_annotate', 'guardlink_report',
    'guardlink_dashboard', 'guardlink_sarif', 'guardlink_diff', 'guardlink_threat_reports',
    'guardlink_sync', 'guardlink_clear', 'guardlink_unannotated', 'guardlink_review_list',
    'guardlink_review_accept', 'guardlink_workspace_info',
  ];

  it('the server advertises exactly the known tool set', async () => {
    const { tools } = await session.client.listTools();
    expect(tools.map(t => t.name).sort()).toEqual([...ALL_TOOLS].sort());
  });

  it('every registered tool returns the envelope', async () => {
    const args: Record<string, any> = {
      guardlink_lookup: { query: 'unmitigated' },
      guardlink_annotate: { prompt: 'annotate auth' },
      guardlink_clear: { dry_run: true },
      guardlink_review_accept: { exposure_id: 'nope', decision: 'skip', justification: 'test' },
      guardlink_diff: { ref: 'HEAD' },
      guardlink_context: { file: 'src/auth.ts' },
      guardlink_graph: { from: '#auth' },
      guardlink_annotate_apply: { file: 'src/auth.ts', line: 1, annotations: ['@audit #auth -- "x"'], dry_run: true },
    };
    for (const name of ALL_TOOLS) {
      const result: any = await session.client.callTool({
        name, arguments: { root, ...(args[name] ?? {}) },
      });
      const env = envelope(result);
      expect(env, name).toBeDefined();
      expect(env.annotation_hash, name).toMatch(/^(sha256-v\d+:[0-9a-f]{64}|unavailable)$/);
      expect(env.generated_at, name).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(['inline', 'external', 'mixed'], name).toContain(env.mode);
      expect(env.root, name).toBe(root);
      expect(env.guardlink_version, name).toMatch(/^\d+\.\d+\.\d+/);
    }
  });

  it('the envelope is a sibling — content[0] is the untouched payload', async () => {
    const result: any = await session.client.callTool({ name: 'guardlink_status', arguments: { root } });
    expect(result.content).toHaveLength(2);
    const parsed = JSON.parse(result.content[0].text);
    // Payload keys are exactly what they were before the envelope existed.
    expect(parsed).toHaveProperty('assets');
    expect(parsed).toHaveProperty('unmitigated');
    expect(parsed).not.toHaveProperty('guardlink');
    expect(parsed).not.toHaveProperty('annotation_hash');
  });

  it('annotation_hash moves when an annotation changes, and not otherwise', async () => {
    const first = envelope(await session.client.callTool({ name: 'guardlink_status', arguments: { root } }));
    const second = envelope(await session.client.callTool({ name: 'guardlink_lookup', arguments: { root, query: 'unmitigated' } }));
    expect(second.annotation_hash).toBe(first.annotation_hash);

    await writeFile(join(root, 'src', 'auth.ts'), ANNOTATED_SOURCE.replace('[critical]', '[low]'));
    const third = envelope(await session.client.callTool({ name: 'guardlink_status', arguments: { root } }));
    expect(third.annotation_hash).not.toBe(first.annotation_hash);
  });

  it('mode reports where the annotations actually live', async () => {
    const inline = envelope(await session.client.callTool({ name: 'guardlink_status', arguments: { root } }));
    expect(inline.mode).toBe('inline');
  });

  it('all three resources carry the envelope and name the root they answered for', async () => {
    // Establish the root through a tool call first.
    await session.client.callTool({ name: 'guardlink_status', arguments: { root } });

    for (const uri of ['guardlink://model', 'guardlink://definitions', 'guardlink://unmitigated']) {
      const res: any = await session.client.readResource({ uri });
      expect(res.contents.length, uri).toBe(2);
      expect(res.contents[0].uri, uri).toBe(uri);
      const env = JSON.parse(res.contents[1].text).guardlink;
      expect(env.root, uri).toBe(root);
      expect(env.root_source, uri).toBe('tool_call');
      expect(env.annotation_hash, uri).toMatch(/^sha256-v\d+:/);
    }
  });

  it('a resource read before any tool call says the root was assumed', async () => {
    const fresh = await connect();
    try {
      const res: any = await fresh.client.readResource({ uri: 'guardlink://definitions' });
      const env = JSON.parse(res.contents[1].text).guardlink;
      expect(env.root_source).toBe('server_cwd');
      expect(env.root).toBe(process.cwd());
    } finally {
      await fresh.close();
    }
  });
});

// ─── GL-104: two repos, two answers, each labelled ───────────────────

describe('MCP server — resource scoping across linked repos (D9)', () => {
  let repoA: string;
  let repoB: string;

  beforeEach(async () => {
    repoA = await mkdtemp(join(tmpdir(), 'guardlink-ws-a-'));
    repoB = await mkdtemp(join(tmpdir(), 'guardlink-ws-b-'));
    for (const [root, extra] of [[repoA, ''], [repoB, ' * @asset App.Extra (#extra) -- "B only"\n']] as const) {
      await mkdir(join(root, '.guardlink'), { recursive: true });
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(join(root, '.guardlink', 'definitions.ts'),
        DEFINITIONS.replace(' */', `${extra} */`));
      await writeFile(join(root, 'src', 'auth.ts'), ANNOTATED_SOURCE);
    }
  });

  afterEach(async () => {
    await rm(repoA, { recursive: true, force: true });
    await rm(repoB, { recursive: true, force: true });
  });

  it('each server answers for its own repo and says which one', async () => {
    const a = await connect();
    const b = await connect();
    try {
      await a.client.callTool({ name: 'guardlink_status', arguments: { root: repoA } });
      await b.client.callTool({ name: 'guardlink_status', arguments: { root: repoB } });

      const resA: any = await a.client.readResource({ uri: 'guardlink://definitions' });
      const resB: any = await b.client.readResource({ uri: 'guardlink://definitions' });

      const envA = JSON.parse(resA.contents[1].text).guardlink;
      const envB = JSON.parse(resB.contents[1].text).guardlink;

      // Each names the repo it answered for — the thing that was missing.
      expect(envA.root).toBe(repoA);
      expect(envB.root).toBe(repoB);
      expect(envA.root_source).toBe('tool_call');
      expect(envB.root_source).toBe('tool_call');

      // And the payloads genuinely differ, so a mix-up would be visible.
      const defsA = JSON.parse(resA.contents[0].text);
      const defsB = JSON.parse(resB.contents[0].text);
      expect(defsA.assets.map((x: any) => x.id)).not.toContain('extra');
      expect(defsB.assets.map((x: any) => x.id)).toContain('extra');
      expect(envA.annotation_hash).not.toBe(envB.annotation_hash);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('one server switched between roots reports the root it last answered for', async () => {
    const s = await connect();
    try {
      await s.client.callTool({ name: 'guardlink_status', arguments: { root: repoA } });
      let res: any = await s.client.readResource({ uri: 'guardlink://definitions' });
      expect(JSON.parse(res.contents[1].text).guardlink.root).toBe(repoA);

      await s.client.callTool({ name: 'guardlink_status', arguments: { root: repoB } });
      res = await s.client.readResource({ uri: 'guardlink://definitions' });
      expect(JSON.parse(res.contents[1].text).guardlink.root).toBe(repoB);
      expect(JSON.parse(res.contents[0].text).assets.map((x: any) => x.id)).toContain('extra');
    } finally {
      await s.close();
    }
  });
});

// ─── GL-205: guardlink_parse returns model content, not a path inventory ──

describe('MCP server — guardlink_parse payload (GL-205)', () => {
  let root: string;
  let session: Awaited<ReturnType<typeof connect>>;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-parse-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'auth.ts'), ANNOTATED_SOURCE);
    // Files with no annotations — the inventory this tool stops shipping.
    for (let i = 0; i < 25; i++) {
      await writeFile(join(root, 'src', `filler-${i}.ts`), `export const v${i} = ${i};\n`);
    }
    session = await connect();
  });

  afterEach(async () => {
    await session.close();
    await rm(root, { recursive: true, force: true });
  });

  const parse = async (args: Record<string, unknown> = {}) =>
    JSON.parse(payload(await session.client.callTool({ name: 'guardlink_parse', arguments: { root, ...args } })));

  it('omits unannotated_files by default and says that it did', async () => {
    const model = await parse();
    expect(model.unannotated_files).toBeUndefined();
    expect(model.unannotated_files_omitted.count).toBe(25);
    expect(model.unannotated_files_omitted.reason).toMatch(/guardlink_unannotated/);
  });

  it('omitted-because-empty is distinguishable from omitted-by-default', async () => {
    // Without the marker a caller cannot tell "no unannotated files" from
    // "the list was dropped", and would read a large repo as fully annotated.
    const model = await parse();
    expect(model.unannotated_files_omitted.count).toBeGreaterThan(0);
  });

  it('include_unannotated restores the exact previous payload', async () => {
    const model = await parse({ include_unannotated: true });
    expect(Array.isArray(model.unannotated_files)).toBe(true);
    expect(model.unannotated_files).toHaveLength(25);
    expect(model.unannotated_files_omitted).toBeUndefined();
  });

  it('everything except unannotated_files is untouched by the default', async () => {
    const withList = await parse({ include_unannotated: true });
    const without = await parse();
    delete withList.unannotated_files;
    delete without.unannotated_files_omitted;
    // generated_at moves between parses; the rest must be identical.
    withList.generated_at = without.generated_at = '';
    expect(without).toEqual(withList);
  });

  it('the default payload is smaller than the full one', async () => {
    const a = payload(await session.client.callTool({ name: 'guardlink_parse', arguments: { root } }));
    const b = payload(await session.client.callTool({ name: 'guardlink_parse', arguments: { root, include_unannotated: true } }));
    expect(Buffer.byteLength(a)).toBeLessThan(Buffer.byteLength(b));
  });

  it('compact returns the compact serialization', async () => {
    const compact = await parse({ compact: true });
    expect(compact.summary).toMatch(/annotations/);
    expect(compact.assets).toBeDefined();
    // Compact drops the file inventories entirely.
    expect(compact.unannotated_files).toBeUndefined();
    expect(compact.annotated_files).toBeUndefined();
  });

  it('compact is smaller than the default payload', async () => {
    const def = payload(await session.client.callTool({ name: 'guardlink_parse', arguments: { root } }));
    const cmp = payload(await session.client.callTool({ name: 'guardlink_parse', arguments: { root, compact: true } }));
    expect(Buffer.byteLength(cmp)).toBeLessThan(Buffer.byteLength(def));
  });

  it('still carries the freshness envelope in every mode', async () => {
    for (const args of [{}, { compact: true }, { include_unannotated: true }]) {
      const r: any = await session.client.callTool({ name: 'guardlink_parse', arguments: { root, ...args } });
      const env = JSON.parse(r.content[r.content.length - 1].text).guardlink;
      expect(env.annotation_hash, JSON.stringify(args)).toMatch(/^sha256-v\d+:/);
    }
  });
});
