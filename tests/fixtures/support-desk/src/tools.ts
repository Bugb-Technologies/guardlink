// The tools registered with the support agent. See ../FIXTURE.md.
import { db, payments, kb, http, files } from './runtime.js';

/**
 * @agents #support-agent to lookup-order on #tool-surface as #agent-session -- "Reads one order for the signed-in customer"
 * @effects read on #orders-db as #agent-session -- "findOrder"
 * @entitles #support-agent to lookup-order on #tool-surface against #excessive-agency -- "By design. Authz: src/agent/policy.ts:10"
 */
export function lookupOrder(id: string) {
  return db.orders.find(id);
}

/**
 * @agents #support-agent to run-sql on #tool-surface -- "Debug tool, still registered"
 * @effects delete on #orders-db -- "runRaw executes the model's SQL"
 * @effects write on #users-db -- "runRaw executes the model's SQL"
 * @exposes #users-db to #excessive-agency [high] cwe:CWE-862 -- "Reachable from the agent's tool surface, nothing approves the write"
 * @audit #users-db -- "Should run_sql exist outside development?"
 */
export function runSql(sql: string) {
  return db.raw(sql);
}

/**
 * @agents #support-agent to issue-refund on #tool-surface -- "Refunds wait for a human"
 * @effects spend on #payments as #billing-sa -- "postRefund"
 * @entitles #support-agent to issue-refund on #tool-surface against #excessive-agency -- "By design. Authz: src/agent/policy.ts:14"
 */
export async function issueRefund(orderId: string) {
  return payments.refund(orderId);
}

/**
 * @agents #support-agent to search-kb on #tool-surface
 * @effects read on #kb -- "search"
 * @entitles #support-agent to search-kb on #kb against #excessive-agency -- "By design. Authz: src/agent/policy.ts:18"
 */
export function searchKb(term: string) {
  return kb.search(term);
}

/**
 * @agents #support-agent to fetch-url on #tool-surface -- "Fetches any URL the model names"
 * @entitles #support-agent to fetch-url -- "Uncited, so it covers nothing"
 */
export function fetchUrl(url: string) {
  return http.get(url);
}

/**
 * @agents #support-agent to mcp-files on #tool-surface -- "Filesystem MCP server rooted at /"
 * @effects write on #host-fs -- "mountFiles"
 */
export function mountFiles() {
  return files.mount('/');
}
