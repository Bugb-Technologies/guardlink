// tests/status-rows-sum.test.ts
//
// `guardlink status` prints an Annotations headline and then one row per kind
// of annotation. The rows must add up to the headline: a verb with no row (the
// reach verbs once had none) or a row that counts something else (Features once
// led with distinct names, not tags) leaves the summary short of its own total.
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

function guardlink(cwd: string, ...args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8', timeout: 60_000 }, (err, stdout) => {
      if (err && !stdout) reject(err); else resolve(stdout);
    });
  });
}

const DEFINITIONS = `/**
 * @asset Shop.Orders (#orders) -- "Order records"
 * @asset Shop.Tools (#tools) -- "Tools handed to the assistant"
 * @asset External.Payments (#payments) -- "Card processor"
 * @threat Tampering (#tamper) [high] -- "Orders changed without authority"
 * @control Signed_Requests (#signed) -- "Requests carry a signature"
 * @actor Shop_Assistant (#assistant) -- "LLM agent answering customers"
 * @actor Nightly_Job (#nightly) -- "Scheduled batch runner"
 * @actor Shop_Clerk (#clerk) -- "Human who approves refunds"
 */
export {};
`;

const SOURCE = `/**
 * @exposes #orders to #tamper [high] -- "order id taken from the request"
 * @mitigates #orders against #tamper using #signed -- "signature checked first"
 * @confirmed #tamper on #orders [high] -- "reproduced with a forged id"
 * @transfers #tamper from #orders to #payments -- "processor re-checks amounts"
 * @flows Customer -> #orders via HTTPS -- "order request"
 * @boundary from #payments to #orders (#pay-boundary) -- "processor callback"
 * @validates #signed for #orders -- "orders.test.ts rejects unsigned requests"
 * @audit #orders -- "review the signature algorithm"
 * @owns shop-team for #orders -- "owning team"
 * @handles pii on #orders -- "customer address"
 * @assumes #orders -- "the proxy strips spoofed headers"
 * @feature "Checkout" -- "order placement"
 * @feature "Refunds" -- "money back"
 * @feature "Checkout" -- "second tag for the same feature"
 * @agents #assistant to lookup-order on #tools -- "lookup tool registered"
 * @reaches #nightly to export-orders on #orders -- "batch export"
 * @effects write on #orders -- "updates the order row"
 * @gates #orders by #clerk for issue-refund -- "refund waits for a clerk"
 * @ticket #tamper on #orders SEC-42 sla "Highest" by alice@shop.test until 2026-11-30 -- "tracked in Jira"
 * @comment -- "every verb appears in this block"
 */
export function placeOrder(id: string) { return id; }

// @shield:begin -- "hidden helper"
export function hidden() { return 1; }
// @shield:end
`;

describe('status rows add up to the Annotations headline', () => {
  let out: string;

  beforeAll(async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-status-sum-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"status-sum-fixture","version":"1.0.0"}\n');
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'orders.ts'), SOURCE);
    out = await guardlink(root, 'status', '.');
  }, 90_000);

  it('the per-kind rows sum to the headline', () => {
    const headline = Number(out.match(/^Annotations:\s+(\d+)/m)?.[1]);
    const rowsBlock = out.split('─'.repeat(40))[2] ?? '';
    const rows = [...rowsBlock.matchAll(/^([A-Z][A-Za-z ]+):\s+(\d+)/gm)];
    const sum = rows.reduce((n, m) => n + Number(m[2]), 0);
    expect(headline).toBeGreaterThan(20);
    expect(sum).toBe(headline);
  });

  it('every verb in the fixture is named by its own row, with no residue', () => {
    for (const row of ['Actors', 'Confirmed', 'Tickets', 'Reaches', 'Effects', 'Gates', 'Shields']) {
      expect(out).toMatch(new RegExp(`^${row}:\\s+[1-9]`, 'm'));
    }
    expect(out).toMatch(/^Features:\s+3 tags \(2 features\)/m);
    expect(out).not.toMatch(/^Other:/m);
  });
});
