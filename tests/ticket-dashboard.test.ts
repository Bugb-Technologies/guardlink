/**
 * The dashboard's Tickets page (`@ticket`, SPEC §3.2).
 *
 * Rendered only when the model holds a ticket — no rail link, no section and no
 * route otherwise. Each row carries the filter attributes the global search and
 * the state chips act on, links out only for an http(s) ref, escapes every model
 * string, and leaves "overdue" to the browser so the page stays deterministic.
 *
 * @validates #output-encoding for #dashboard -- "Ticket refs, SLA labels, assignees and descriptions are escaped on the Tickets page, and a javascript: ref is text, never an href"
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { externalHref } from '../src/dashboard/html.js';

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

async function parseFiles(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'gl-ticket-dash-'));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return (await parseProject({ root, project: 'ticket-dash' })).model;
}

/** One `<section id="sec-…">`, up to its closing tag — never into the client script that follows the last page. */
function page(html: string, id: string): string {
  const start = html.indexOf(`<section id="sec-${id}"`);
  if (start < 0) return '';
  return html.slice(start, html.indexOf('</section>', start) + '</section>'.length);
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "Public REST API"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input reaches SQL"
 * @threat IDOR (#idor) [high] -- "Object ids not checked against owner"
 * @control Prepared_Statements (#prepared) -- "Parameterised queries"
 */
export {};
`;

const BASE = `/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "search() concatenates req.query.q into db.raw"
 * @mitigates #api against #sqli using #prepared -- "search() binds q as a placeholder"
 * @exposes #api to #idor [high] -- "getOrder(id) loads any order without checking req.user owns it"
 * @audit #api -- "Ownership check missing on getOrder"
 */
export function search(q: string) { return q; }
`;

const TICKETS = `/**
 * @ticket #sqli on #api "https://acme.atlassian.net/browse/SEC-42" sla "Highest" by alice@acme.com until 2026-01-15 -- "Q3 pentest"
 * @ticket #idor on #api SEC-77 sla "P1" by "Bob Smith" until 2099-12-31 -- "Add owner check in getOrder"
 * @ticket #idor on #api "javascript:alert(1)" sla "<img src=x onerror=alert(1)>" -- "<script>alert(1)</script>"
 */
export {};
`;

describe('Tickets page', () => {
  it('is absent — no rail link, no section — when the model holds no @ticket', async () => {
    const html = generateDashboardHTML(await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': BASE }));
    expect(html).not.toContain('id="sec-tickets"');
    expect(html).not.toContain('data-page="tickets"');
  });

  it('renders the page and its rail link, with one searchable row per ticket and the pair state', async () => {
    const html = generateDashboardHTML(await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': BASE, 'src/tickets.ts': TICKETS }));
    expect(html).toContain('href="#tickets" data-page="tickets"');
    const tickets = page(html, 'tickets');
    expect(tickets).toContain('id="tickets-table"');
    const rows = tickets.match(/<tr [^>]*data-status="[^"]*"[^>]*>/g) ?? [];
    expect(rows).toHaveLength(3);
    // The SQLi pair is mitigated, so its ticket reads as one to close.
    const sec42 = rows.find(r => r.includes('sec-42'))!;
    expect(sec42).toContain('data-status="mitigated"');
    expect(sec42).toContain('data-due="2026-01-15"');
    expect(sec42).toMatch(/data-search="[^"]*highest[^"]*alice@acme\.com/);
    // A row opens its annotation drawer.
    expect(sec42).toMatch(/data-annotation="\d+:\d+"/);
    expect(rows.find(r => r.includes('sec-77'))).toContain('data-status="open"');
    // State chips filter on the same attribute.
    expect(tickets).toContain('data-chip="status" data-value="mitigated"');
  });

  it('links an http(s) ref and renders any other ref, javascript: included, as escaped text', async () => {
    const html = generateDashboardHTML(await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': BASE, 'src/tickets.ts': TICKETS }));
    const tickets = page(html, 'tickets');
    expect(tickets).toContain('href="https://acme.atlassian.net/browse/SEC-42" target="_blank" rel="noopener noreferrer"');
    expect(tickets).not.toMatch(/href="javascript:/i);
    expect(tickets).toContain('<code class="ticket-ref">javascript:alert(1)</code>');
    expect(tickets).not.toContain('<img src=x');
    expect(tickets).not.toContain('<script>alert');
    expect(tickets).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(externalHref('javascript:alert(1)')).toBeNull();
    expect(externalHref('SEC-42')).toBeNull();
    expect(externalHref('https://example.com/x')).toBe('https://example.com/x');
  });

  it('decides nothing about overdue on the server, so the page is identical across runs', async () => {
    const model = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': BASE, 'src/tickets.ts': TICKETS });
    const a = generateDashboardHTML(model);
    const b = generateDashboardHTML(model);
    expect(a).toBe(b);
    expect(page(a, 'tickets')).not.toContain('class="ticket-overdue"');
    expect(page(a, 'tickets')).toContain('data-ticket-overdue');
  });

  it('marks an exposure row that has a ticket with a chip linking to it', async () => {
    const html = generateDashboardHTML(await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': BASE, 'src/tickets.ts': TICKETS }));
    expect(page(html, 'exposures')).toContain('href="#tickets?q=%23api+%23idor"');
  });
});
