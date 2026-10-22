/**
 * `@ticket` — an open ticket in an external tracker for a threat on an asset
 * (SPEC §3.2).
 *
 * The grammar (a ref that may be a bare id, a namespaced id or a bare URL; the
 * optional sla, by and until clauses), the model it assembles into, the two
 * validation checks, the info-level lint note once the pair is covered, the diff
 * of a ticket's life, the lookup forms, the SARIF property and the templates.
 *
 * @validates #input-sanitize for #parser -- "A @ticket missing its ref, or with an unquoted sla, is malformed and never read as a claim; a keyword cannot be recorded as the ticket"
 * @validates #regex-anchoring for #parser -- "TICKET_REF is one non-space run or a quoted string inside an anchored pattern; a long hostile line is answered quickly"
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { parseLine } from '../src/parser/parse-line.js';
import { parseProject } from '../src/parser/parse-project.js';
import { findDanglingRefs, findTicketDiagnostics } from '../src/parser/validate.js';
import { ticketStatusResolver } from '../src/parser/coverage.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { lintAnnotations } from '../src/gate/lint.js';
import { diffModels } from '../src/diff/engine.js';
import { formatDiff, formatDiffMarkdown } from '../src/diff/format.js';
import { lookup, SUPPORTED_QUERY_FORMS } from '../src/mcp/lookup.js';
import { generateSarif } from '../src/analyzer/sarif.js';
import { generateReport } from '../src/report/index.js';
import { filterByFeature } from '../src/parser/feature-filter.js';
import { referenceDocContent } from '../src/init/templates.js';

const at = { file: 'src/api.ts', line: 3 };
const line = (text: string) => parseLine(text, at);

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

function writeProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-ticket-'));
  roots.push(root);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return root;
}

async function parseFiles(files: Record<string, string>) {
  return parseProject({ root: writeProject(files), project: 'ticket' });
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "Public REST API"
 * @asset App.Web (#web) -- "Browser front end"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input reaches SQL"
 * @threat Cross_Site_Scripting (#xss) [high] cwe:CWE-79 -- "Script injected into pages"
 * @control Prepared_Statements (#prepared) -- "Parameterised queries"
 * @feature "Search" -- "Search endpoint"
 */
export {};
`;

const API = `/**
 * @feature "Search" -- "Search endpoint"
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "search() concatenates req.query.q into db.raw"
 * @ticket #sqli on #api "https://acme.atlassian.net/browse/SEC-42" sla "Highest" by alice@acme.com until 2026-11-30 -- "Q3 pentest"
 */
export function search(q: string) { return q; }
`;

const WEB = `/**
 * @exposes #web to #xss [high] cwe:CWE-79 -- "render() writes comment.body into innerHTML"
 * @audit #web -- "Needs output encoding"
 * @ticket #xss on #web WEB-9 by carol -- "Escape comment bodies"
 */
export function render(body: string) { return body; }
`;

const MITIGATION = `/**
 * @mitigates #api against #sqli using #prepared -- "search() binds q as a placeholder"
 */
export function bind() {}
`;

// ─── Grammar ─────────────────────────────────────────────────────────

describe('@ticket grammar', () => {
  it('parses every clause, keeping the sla label verbatim', () => {
    const r = line('@ticket #sqli on App.API "https://acme.atlassian.net/browse/SEC-42" sla "Highest" by alice@acme.com until 2026-11-30 -- "Q3 pentest"');
    expect(r.diagnostic).toBeNull();
    expect(r.annotation).toMatchObject({
      verb: 'ticket', threat: '#sqli', asset: 'App.API', ref: 'https://acme.atlassian.net/browse/SEC-42',
      sla: 'Highest', assignee: 'alice@acme.com', due: '2026-11-30', description: 'Q3 pentest',
    });
  });

  it('takes a bare id, a namespaced id or a bare URL as the ref, and every clause is optional', () => {
    expect(line('@ticket #sqli on #api SEC-42').annotation).toMatchObject({ ref: 'SEC-42', sla: undefined, assignee: undefined, due: undefined });
    expect(line('@ticket #sqli on #api jira:SEC-42 -- "d"').annotation).toMatchObject({ ref: 'jira:SEC-42', description: 'd' });
    expect(line('@ticket #sqli on #api https://github.com/acme/app/issues/7?x=1#c').annotation).toMatchObject({ ref: 'https://github.com/acme/app/issues/7?x=1#c' });
    expect(line('@ticket SQL Injection on App.API SEC-42 by "Alice Smith"').annotation).toMatchObject({ threat: 'SQL Injection', assignee: 'Alice Smith' });
  });

  it('refuses a line with no ref instead of recording a keyword or the delimiter as the ticket', () => {
    for (const text of [
      '@ticket #sqli on #api -- "missing ref"',
      '@ticket #sqli on #api sla "High"',
      '@ticket #sqli on #api by alice',
      '@ticket #sqli on #api until 2026-01-01',
    ]) {
      const r = line(text);
      expect(r.annotation, text).toBeNull();
      expect(r.diagnostic?.code, text).toBe('malformed-annotation');
    }
  });

  it('needs the sla label quoted', () => {
    expect(line('@ticket #sqli on #api SEC-42 sla High').diagnostic?.code).toBe('malformed-annotation');
  });

  it('reads prose that opens with @ticket as prose, and suggests @ticket for a near miss', () => {
    expect(line('@ticket is how you record one').diagnostic?.code).toBe('prose-like');
    const typo = line('@tickets #sqli on #api SEC-1');
    expect(typo.diagnostic?.code).toBe('unknown-verb');
    expect(typo.diagnostic?.message).toContain('@ticket');
  });

  it('answers a long hostile line quickly', () => {
    const t0 = Date.now();
    line(`@ticket #sqli on #api ${'a'.repeat(20_000)} sla "${'b'.repeat(20_000)}`);
    expect(Date.now() - t0).toBeLessThan(500);
  });
});

// ─── Model, validation, lint ─────────────────────────────────────────

describe('@ticket in the model', () => {
  it('assembles into model.tickets and joins each ticket to its pair state', async () => {
    const { model } = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': API, 'src/web.ts': WEB });
    expect(model.tickets).toHaveLength(2);
    const status = ticketStatusResolver(model);
    expect(model.tickets!.map(t => [t.ref, status(t).state])).toEqual(expect.arrayContaining([
      ['https://acme.atlassian.net/browse/SEC-42', 'open'],
      ['WEB-9', 'open'],
    ]));
  });

  it('moves the annotation hash and gets a claim key, without changing the hash of a model with none', async () => {
    const base = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/web.ts': WEB.replace(/ \* @ticket.*\n/, '') });
    const withTicket = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/web.ts': WEB });
    expect(computeAnnotationHash(withTicket.model)).not.toBe(computeAnnotationHash(base.model));
    expect(relationRecords(withTicket.model).some(r => r.verb === 'ticket')).toBe(true);
  });

  it('reports a dangling threat or asset, an impossible due date, and a pair nothing exposes', async () => {
    const { model } = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'src/api.ts': API,
      'src/odd.ts': `/**
 * @ticket #nope on #api SEC-1 -- "dangling threat"
 * @ticket #sqli on #api SEC-2 until 2026-02-30 -- "no such day"
 * @ticket #xss on #api SEC-3 -- "nothing exposes #api to #xss"
 */
export {};
`,
    });
    expect(findDanglingRefs(model).some(d => d.message.includes('#nope'))).toBe(true);
    const diags = findTicketDiagnostics(model);
    expect(diags.find(d => d.code === 'ticket-malformed-due')).toMatchObject({ level: 'error', file: 'src/odd.ts' });
    const unexposed = diags.filter(d => d.code === 'ticket-without-exposure');
    expect(unexposed.map(d => d.message).join('\n')).toContain('SEC-3');
    expect(unexposed.every(d => d.level === 'warning')).toBe(true);
  });

  it('lint notes a ticket whose pair is now mitigated at info level, and never as an error', async () => {
    const open = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': API });
    expect(lintAnnotations(open.model).filter(v => v.rule === 'ticket-on-mitigated')).toHaveLength(0);

    const fixed = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': API, 'src/bind.ts': MITIGATION });
    expect(ticketStatusResolver(fixed.model)(fixed.model.tickets![0]).state).toBe('mitigated');
    const notes = lintAnnotations(fixed.model).filter(v => v.rule === 'ticket-on-mitigated');
    expect(notes).toHaveLength(1);
    expect(notes[0]).toMatchObject({ level: 'info', verb: 'ticket', file: 'src/api.ts' });
  });

  it('a feature slice keeps the tickets written in its files', async () => {
    const { model } = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': API, 'src/web.ts': WEB });
    const slice = filterByFeature(model, ['Search']);
    expect(slice.tickets!.map(t => t.ref)).toEqual(['https://acme.atlassian.net/browse/SEC-42']);
  });
});

// ─── Diff ────────────────────────────────────────────────────────────

describe('@ticket in diff', () => {
  it('reports a ticket added, one removed, and a reassignment as a modification', async () => {
    const before = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': API, 'src/web.ts': WEB });
    const after = await parseFiles({
      '.guardlink/definitions.ts': DEFINITIONS,
      'src/api.ts': API.replace('by alice@acme.com until 2026-11-30', 'by bob@acme.com until 2026-12-15'),
      'src/web.ts': WEB.replace('@ticket #xss on #web WEB-9 by carol', '@ticket #xss on #web WEB-11 by carol'),
    });
    const diff = diffModels(before.model, after.model);
    const kinds = diff.tickets.map(c => `${c.kind}:${c.item.ref}`).sort();
    expect(kinds).toEqual(['added:WEB-11', 'modified:https://acme.atlassian.net/browse/SEC-42', 'removed:WEB-9']);
    const modified = diff.tickets.find(c => c.kind === 'modified')!;
    expect(modified.details).toContain('assignee: alice@acme.com → bob@acme.com');
    expect(modified.details).toContain('due: 2026-11-30 → 2026-12-15');
    expect(formatDiff(diff)).toContain('Tickets');
    expect(formatDiffMarkdown(diff)).toContain('@ticket #xss on #web WEB-11');
  });
});

// ─── Lookup, SARIF, report, templates ────────────────────────────────

describe('@ticket for readers', () => {
  it('lookup answers tickets, tickets for <asset|assignee> and ticket <ref>, with each pair state', async () => {
    const { model } = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/api.ts': API, 'src/web.ts': WEB, 'src/bind.ts': MITIGATION });
    expect(SUPPORTED_QUERY_FORMS.some(f => f.startsWith('tickets'))).toBe(true);
    expect(lookup(model, 'tickets')).toMatchObject({ type: 'tickets', count: 2 });
    const forApi = lookup(model, 'tickets for #api');
    expect(forApi.count).toBe(1);
    expect(forApi.results[0]).toMatchObject({ sla: 'Highest', assignee: 'alice@acme.com', state: 'mitigated' });
    expect(lookup(model, 'tickets by carol').results.map((r: { ref: string }) => r.ref)).toEqual(['WEB-9']);
    expect(lookup(model, 'ticket WEB-9').results[0]).toMatchObject({ threat: '#xss', state: 'open' });
  });

  it('SARIF carries the tickets on the finding they track, and nothing for a model without one', async () => {
    const { model } = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/web.ts': WEB });
    const result = generateSarif(model).runs[0].results.find(r => r.properties?.asset === '#web');
    expect(result?.properties?.tickets).toEqual([{ ref: 'WEB-9', assignee: 'carol' }]);

    const none = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/web.ts': WEB.replace(/ \* @ticket.*\n/, '') });
    expect(JSON.stringify(generateSarif(none.model))).not.toContain('"tickets"');
  });

  it('the report adds a Tracked Tickets section only when a ticket exists', async () => {
    const { model } = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/web.ts': WEB });
    expect(generateReport(model)).toContain('Tracked Tickets');
    const none = await parseFiles({ '.guardlink/definitions.ts': DEFINITIONS, 'src/web.ts': WEB.replace(/ \* @ticket.*\n/, '') });
    expect(generateReport(none.model)).not.toContain('Tracked Tickets');
  });

  it('the reference document lists @ticket, and its example parses', () => {
    const project = { name: 'app', language: 'typescript', definitionsExt: '.ts' } as Parameters<typeof referenceDocContent>[0];
    const ref = referenceDocContent(project);
    const example = ref.split('\n').find(l => l.startsWith('TRACK'))!.replace(/^TRACK\s+/, '')
      .replace('<#threat>', '#sqli').replace('<Asset>', '#api').replace('<id-or-url>', 'SEC-42')
      .replace('"<label>"', '"High"').replace('<assignee>', 'alice').replace('<YYYY-MM-DD>', '2026-11-30');
    expect(line(example).annotation, example).toMatchObject({ verb: 'ticket', ref: 'SEC-42' });
  });
});
