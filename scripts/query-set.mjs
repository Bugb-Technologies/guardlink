#!/usr/bin/env node
/**
 * The GuardLink MCP query set — a fixed, diffable regression baseline.
 *
 * ── Why this file exists ────────────────────────────────────────────
 *
 * "The nine-query set" was cited across roughly eight sessions as though it
 * were a committed suite. It never was: it came from one Phase 1 verification
 * run and was reconstructed from memory each time it was referenced. Every
 * reconstruction was plausible and none was the same, which is the worst
 * property a regression baseline can have — "no drift" was a judgement call by
 * whoever ran it, not a fact anyone could check.
 *
 * So it is a file now. Its output is stable text, so "no drift" is a `diff`.
 *
 * ── Why it runs against two corpora ─────────────────────────────────
 *
 * Because the single-corpus habit is what hid D34 and D36, and running only
 * against `guardlink` is what let D57's eleven extra sites survive an audit.
 * This repo is TypeScript, inline-mode, and its file count tracks its
 * annotation count. `tests/fixtures/expense-api` is Python, born external, and
 * decouples the two. A query that behaves the same on both is far better
 * evidence than a query that behaves well on either.
 *
 * ── How to use it ───────────────────────────────────────────────────
 *
 *   node scripts/query-set.mjs                    # both corpora, to stdout
 *   node scripts/query-set.mjs --root <path>      # one arbitrary repo
 *   node scripts/query-set.mjs > /tmp/after.txt   # then diff against a baseline
 *
 * Every invocation spawns a FRESH stdio server per corpus from the
 * `guardlink-mcp` entry point. That is deliberate: a connected agent keeps a
 * stale server across a rebuild, and that trap produced a false defect report
 * during the D36/D37 work. Nothing in the MCP envelope moves to reveal it, so
 * the only defence is to never reuse a server.
 *
 * Volatile fields — timestamps, absolute paths, git SHAs — are normalised out,
 * so two runs of the same code on the same annotations are byte-identical.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SERVER = join(repoRoot, 'dist', 'mcp', 'index.js');

/**
 * The queries. Each earned its place by catching something.
 *
 * The `lookup` forms are the ones that have historically diverged between
 * surfaces; `status` and `validate` are the two answers everything else is
 * checked against; `cwe:CWE-89` is the scanner bridge, which D57 left answering
 * "mitigated" on a live critical injection.
 */
const QUERIES = [
  ['status', 'guardlink_status', {}],
  ['validate', 'guardlink_validate', {}],
  ['lookup unmitigated', 'guardlink_lookup', { query: 'unmitigated' }],
  ['lookup threat dos', 'guardlink_lookup', { query: 'threat dos' }],
  ['lookup threat denial', 'guardlink_lookup', { query: 'threat denial' }],
  ['lookup asset cli', 'guardlink_lookup', { query: 'asset cli' }],
  ['lookup asset llm', 'guardlink_lookup', { query: 'asset llm' }],
  ['lookup asset client', 'guardlink_lookup', { query: 'asset client' }],
  ['lookup exposures for #cli', 'guardlink_lookup', { query: 'exposures for #cli' }],
  ['lookup control valid', 'guardlink_lookup', { query: 'control valid' }],
  ['lookup cwe:CWE-89', 'guardlink_lookup', { query: 'cwe:CWE-89' }],
  // Added 2026-08-10. Each of these caught a real defect that the nine did not:
  // D34/D35 (a subgraph carrying the repo's file inventory), D47 (graph and
  // coverage disagreeing on a dotted path), and D51 (a read tool that correctly
  // reports a missing file, next to a write tool that does not).
  ['graph from cli depth 2', 'guardlink_graph', { from: 'cli', depth: 2 }],
  ['context on a missing file', 'guardlink_context', { file: 'does/not/exist.ts' }],
];

/** Fields that legitimately differ between two runs of identical code. */
function normalise(value) {
  return JSON.parse(JSON.stringify(value, (key, v) => {
    if (key === 'generated_at' || key === 'git_sha' || key === 'root') return '<volatile>';
    if (typeof v === 'string' && v.startsWith('/')) return v.replace(/^.*\/(?=[^/]+\/?$)/, '<abs>/');
    return v;
  }));
}

async function runCorpus(label, root) {
  const lines = [`=== ${label} (${root.replace(repoRoot, '<repo>')}) ===`];
  const srv = spawn(process.execPath, [SERVER], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = '';
  const pending = new Map();
  let id = 1;
  srv.stdout.on('data', (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let m;
      try { m = JSON.parse(line); } catch { continue; }
      if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    }
  });
  srv.stderr.on('data', () => {});
  const rpc = (method, params) => new Promise((res, rej) => {
    const i = id++;
    // The timer is cleared on reply and unref'd regardless. An uncleared
    // 60s timer per query keeps the event loop alive after the last answer
    // arrives: the first version of this script did 0.4s of work in 60s of
    // wall clock, which would have read as "the query set is slow".
    const timer = setTimeout(() => { pending.delete(i); rej(new Error('timeout')); }, 60000);
    timer.unref?.();
    pending.set(i, (m) => { clearTimeout(timer); res(m); });
    srv.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: i, method, params }) + '\n');
  });

  try {
    const init = await rpc('initialize', {
      protocolVersion: '2024-11-05', capabilities: {},
      clientInfo: { name: 'query-set', version: '1' },
    });
    srv.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    const tools = await rpc('tools/list', {});
    lines.push(`server            : ${init.result.serverInfo.name} (tool_count ${tools.result.tools.length})`);

    let hash = null;
    for (const [label2, tool, args] of QUERIES) {
      let summary;
      try {
        const r = await rpc('tools/call', { name: tool, arguments: args });
        const content = r.result?.content ?? [];
        const text = content[0]?.text ?? '';
        let body;
        try { body = normalise(JSON.parse(text)); } catch { body = text.split('\n')[0]; }
        if (content[1]) {
          try { hash = JSON.parse(content[1].text).guardlink.annotation_hash; } catch { /* no envelope */ }
        }
        summary = summarise(tool, body);
      } catch (e) {
        summary = `ERROR ${e.message}`;
      }
      lines.push(`${label2.padEnd(26)}: ${summary}`);
    }
    lines.push(`annotation_hash   : ${hash ?? '(none)'}`);
  } finally {
    srv.kill();
  }
  return lines;
}

/** One stable line per query. Shape, not prose — prose churns, shape regresses. */
function summarise(tool, b) {
  if (typeof b !== 'object' || b === null) return String(b).slice(0, 90);
  switch (tool) {
    case 'guardlink_status':
      return `assets=${b.assets} threats=${b.threats} controls=${b.controls} `
        + `mitigations=${b.mitigations} exposures=${b.exposures} unmitigated=${b.unmitigated?.length} `
        + `coverage=${b.coverage?.coverage_percent}%`;
    case 'guardlink_validate':
      return `valid=${b.valid} errors=${(b.errors ?? []).length} warnings=${(b.warnings ?? []).length}`;
    case 'guardlink_graph':
      return `resolved=${b.traversal?.start?.resolved} canonical=${b.traversal?.start?.canonical} `
        + `nodes=${b.traversal?.nodes?.length} edges=${b.traversal?.edges?.length} `
        + `completeness=${b.traversal?.completeness}`;
    case 'guardlink_context':
      return `status=${b.status} annotations=${(b.annotations ?? []).length} `
        + `open_exposures=${(b.open_exposures ?? []).length}`;
    default:
      return `type=${b.type} count=${b.count}`
        + (b.matched_via ? ` matched_via=${b.matched_via}` : '')
        + (b.external_id ? ` declared=${b.external_id.declared}` : '');
  }
}

const argRoot = process.argv.indexOf('--root');
const corpora = argRoot >= 0
  ? [['custom', resolve(process.argv[argRoot + 1])]]
  : [
      ['guardlink', repoRoot],
      ['expense-api', join(repoRoot, 'tests', 'fixtures', 'expense-api')],
    ];

if (!existsSync(SERVER)) {
  console.error(`No build at ${SERVER}. Run: npm run build`);
  process.exit(2);
}

const out = [];
for (const [label, root] of corpora) {
  if (!existsSync(root)) { out.push(`=== ${label}: MISSING at ${root} ===`); continue; }
  out.push(...(await runCorpus(label, root)), '');
}
console.log(out.join('\n'));
