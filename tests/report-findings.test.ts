/**
 * Threat reports carry findings a machine can read: the contract in every
 * framework prompt, the block parsed out of the report, ids validated against
 * the model, a table rendered from it, and the dashboard fed rows not prose.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { FRAMEWORK_PROMPTS, buildUserMessage, FINDINGS_CONTRACT } from '../src/analyze/prompts.js';
import { parseFindingsBlock, validateFindings, renderFindingsTable, stripFindingsBlock } from '../src/analyze/findings.js';
import { loadThreatReportsForDashboard } from '../src/analyze/index.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { REPORT_SHAPES } from '../src/playbooks/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared (#prep) -- "Prepared statements"
 */
export {};
`;
const SOURCE = `import x from 'x';
/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated in findUser()"
 * @audit #api -- "review"
 */
export function login() {}
`;

const REPORT = `# STRIDE Threat Analysis

## Part 2
Prose about #api and #sqli.

\`\`\`json guardlink-findings
{
  "schema": "guardlink.findings/v1",
  "findings": [
    { "id": "F-1", "title": "SQL injection in login", "asset": "#api", "threat": "#sqli", "severity": "critical", "status": "open",
      "evidence": "email is concatenated into the query string at src/a.ts:3", "location": { "file": "src/a.ts", "line": 3 },
      "scenario": "attacker submits ' OR 1=1--", "remediation": "use #prep", "annotation": "@mitigates #api against #sqli using #prep" },
    { "id": "F-2", "title": "Made-up asset", "asset": "#billing", "threat": "#sqli", "severity": "low", "status": "gap", "evidence": "none", "location": null }
  ]
}
\`\`\`
`;

async function project(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-findings-'));
  await mkdir(join(root, '.guardlink', 'threat-reports'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'a.ts'), SOURCE);
  return root;
}

describe('the contract', () => {
  it('every framework prompt ends with the findings contract, and every report shape is a known playbook', () => {
    for (const [fw, prompt] of Object.entries(FRAMEWORK_PROMPTS)) {
      expect(prompt, fw).toContain('guardlink-findings');
      expect(prompt.trimEnd().endsWith(FINDINGS_CONTRACT.trimEnd()), fw).toBe(true);
    }
    expect(FINDINGS_CONTRACT).toMatch(/"schema": "guardlink.findings\/v1"/);
    expect(REPORT_SHAPES.find(s => s.id === 'executive')!.body).toMatch(/one page/i);
  });

  it('free text is a focus under the framework header, never a replacement; a shape is appended', () => {
    const plain = buildUserMessage('{}', 'stride');
    const focused = buildUserMessage('{}', 'stride', 'focus on auth');
    expect(plain.split('\n')[0]).toMatch(/STRIDE Threat Analysis/);
    expect(focused.split('\n')[0]).toMatch(/STRIDE Threat Analysis/);
    expect(focused).toContain('Focus: focus on auth');
    expect(focused).not.toContain('Additional focus:');
    const shaped = buildUserMessage('{}', 'stride', undefined, undefined, undefined, undefined, 'executive');
    expect(shaped).toContain('## Shape — Executive');
  });
});

describe('the block', () => {
  it('parses the last guardlink-findings block, validates ids against the model, renders a table, and strips the block', async () => {
    const parsed = parseFindingsBlock(REPORT);
    expect(parsed.error).toBeUndefined();
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings[0]).toMatchObject({ id: 'F-1', asset: '#api', threat: '#sqli', severity: 'critical', status: 'open', location: { file: 'src/a.ts', line: 3 } });
    const root = await project();
    const { model } = await parseProject({ root, project: 'f' });
    const v = validateFindings(parsed.findings, model);
    expect(v.unresolved).toEqual([{ id: 'F-2', field: 'asset', ref: '#billing' }]);
    const table = renderFindingsTable(parsed.findings);
    expect(table).toMatch(/\| F-1 \|/);
    expect(table).toContain('src/a.ts:3');
    const stripped = stripFindingsBlock(REPORT);
    expect(stripped).not.toContain('guardlink-findings');
    expect(stripped).toContain('Prose about #api');
    expect(parseFindingsBlock('no block here').findings).toEqual([]);
    expect(parseFindingsBlock('```json guardlink-findings\n{ not json\n```').error).toMatch(/JSON/);
    expect(parseFindingsBlock('```json guardlink-findings\n{"schema":"x","findings":[{"id":"F-1"}]}\n```').error).toMatch(/schema/);
  });

  it('the dashboard loads findings per report and renders them as rows, keeping the prose', async () => {
    const root = await project();
    await writeFile(join(root, '.guardlink', 'threat-reports', '2026-09-10T00-00-00-stride.md'),
      `---\nframework: stride\nlabel: STRIDE Threat Analysis\nmodel: test\ntimestamp: 2026-09-10T00:00:00.000Z\nproject: f\nannotations: 2\n---\n\n${REPORT}`);
    const reports = loadThreatReportsForDashboard(root);
    expect(reports).toHaveLength(1);
    expect(reports[0].findings).toHaveLength(2);
    expect(reports[0].content).not.toContain('guardlink-findings');
    const { model } = await parseProject({ root, project: 'f' });
    const h = generateDashboardHTML(model, root, reports);
    expect(h).toContain('"findings":[{"id":"F-1"');
    expect(h).toContain('function renderFindingsTable(');
  });
});
