/**
 * Markup contracts of the upgraded dashboard: routes, sortable tables,
 * filterable rows, search, links to the repo host, ledger badges, drawer
 * actions. Behaviour lives in the embedded script; these pin the hooks it
 * needs and the server-side decisions (links only with a remote, badges only
 * with a ledger).
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { readLedger, writeLedger, classifyClaims, planVerification, applyVerification } from '../src/parser/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;
// One open critical exposure (sqli) and one mitigated low one (xss).
const SOURCE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "raw sql"
 * @exposes #api to #xss [low] cwe:CWE-79 -- "bio"
 * @mitigates #api against #xss using #prepared-stmts -- "escaped"
 * @flows User -> #api via HTTPS -- "login"
 */
export function login(email: string) { return email; }
`;

async function project(opts: { remote?: string } = {}): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-dash-up-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), SOURCE);
  if (opts.remote) {
    await mkdir(join(root, '.git'), { recursive: true });
    await writeFile(join(root, '.git', 'config'), `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${opts.remote}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`);
  }
  return root;
}

async function html(opts: { remote?: string } = {}): Promise<{ root: string; html: string }> {
  const root = await project(opts);
  const { model } = await parseProject({ root, project: 'up' });
  return { root, html: generateDashboardHTML(model, root) };
}

describe('routes and navigation', () => {
  it('every page is reachable by hash and the sidebar links carry the hash', async () => {
    const { html: h } = await html();
    for (const page of ['summary', 'threats', 'diagrams', 'code', 'data', 'assets']) {
      expect(h).toContain(`id="sec-${page}"`);
      expect(h).toContain(`href="#${page}"`);
    }
    expect(h).toContain('function showSection(');
    expect(h).toContain("addEventListener('popstate'");
  });

  it('the summary KPIs link to the view behind the number', async () => {
    const { html: h } = await html();
    expect(h).toMatch(/<a class="kpi[^"]*" href="#threats\?status=open"/);
    expect(h).toMatch(/<a class="kpi[^"]*" href="#threats\?sev=critical,high&amp;status=open"/);
  });

  it('carries a "What to do next" list with a copyable command', async () => {
    const { html: h } = await html();
    expect(h).toContain('id="actions"');
    expect(h).toMatch(/data-action="open-severe"/);
    expect(h).toMatch(/data-copy="guardlink verify --all"/);
  });
});

describe('tables', () => {
  it('threat rows carry the attributes the filters and search act on, and headers sort', async () => {
    const { html: h } = await html();
    expect(h).toMatch(/<table[^>]*class="[^"]*sortable[^"]*"/);
    expect(h).toMatch(/<th[^>]*data-sort="severity"/);
    expect(h).toMatch(/<tr[^>]*data-sev="critical"[^>]*data-status="open"[^>]*data-search="[^"]*sqli[^"]*"/);
    expect(h).toContain('id="threat-chips"');
    expect(h).toContain('id="search"');
  });
});

describe('links to the repository host', () => {
  it('turns file:line into a link at HEAD when the origin is on GitHub', async () => {
    const { html: h } = await html({ remote: 'git@github.com:acme/widgets.git' });
    expect(h).toContain('href="https://github.com/acme/widgets/blob/HEAD/src/a.ts#L4"');
    expect(h).not.toContain('acme:');
  });

  it('keeps plain text when there is no remote, with a copy button instead', async () => {
    const { html: h } = await html();
    expect(h).not.toContain('href="https://github.com');
    expect(h).toMatch(/data-copy="src\/a\.ts:4"/);
  });
});

describe('ledger badges', () => {
  it('shows verified / stale / unverified per claim once a ledger exists, and nothing before', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'up' });
    const before = generateDashboardHTML(model, root);
    expect(before).not.toMatch(/class="claim-state (verified|stale|unverified)"/);

    const report = classifyClaims(model, readLedger(root));
    const plan = planVerification(report, { kind: 'all' });
    writeLedger(root, applyVerification(null, plan, { verified_by: 'human:test', verified_at: '2026-01-01T00:00:00.000Z' }));
    const after = generateDashboardHTML(model, root);
    expect(after).toMatch(/class="claim-state verified"/);
    expect(after).toContain('Verified claims');
  });
});

describe('drawer actions', () => {
  it('the client script offers copy, open-on-host and previous/next actions', async () => {
    const { html: h } = await html({ remote: 'https://gitlab.com/acme/widgets.git' });
    for (const needle of ['function copyText(', 'Copy verify command', 'Copy blame command', 'data-drawer-nav="next"', 'Open on GitLab']) {
      expect(h).toContain(needle);
    }
  });
});
