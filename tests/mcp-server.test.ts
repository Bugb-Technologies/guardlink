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
