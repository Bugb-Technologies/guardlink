import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { parseProject } from '../src/parser/parse-project.js';
import { generateSarif } from '../src/analyzer/sarif.js';

const DEFS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.Web (#web) -- "Web tier"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 */
export {};
`;
const TWO = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "A: email param"
 */
export function findUser(email: string) { return email; }

/**
 * @exposes #web to #xss [high] cwe:CWE-79 -- "B: bio via innerHTML"
 */
export function render(bio: string) { return bio; }
`;
const EV = { request: 'POST /u', response: 'HTTP 200 3 rows', matched_patterns: [], data: {} };

async function proj() {
  const root = await mkdtemp(join(tmpdir(), 'gl-exit-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFS);
  await writeFile(join(root, 'src', 'a.ts'), TWO);
  return { root, model: (await parseProject({ root, project: 'h' })).model };
}
const keyAt = (s: ReturnType<typeof generateSarif>, l: number) =>
  (s.runs[0].results.find(r => r.locations[0].physicalLocation.region.startLine === l)!.properties as Record<string, string>).claimKey;

const runCli = (root: string) => {
  const tsx = createRequire(import.meta.url).resolve('tsx/cli');
  const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
  return new Promise<{ code: number; out: string }>((res) =>
    execFile(process.execPath, [tsx, cli, 'hypothesis', 'confirm', '.', '--from-scan', 'scan.json', '--write'],
      { cwd: root, maxBuffer: 1 << 26 },
      (err, so, se) => res({ code: (err as { code?: number } | null)?.code ?? 0, out: so + se })));
};

// (a) every finding joins by location — nothing can be written
const a = await proj();
await writeFile(join(a.root, 'scan.json'), JSON.stringify({ scan_id: 'cxg', findings: [
  { id: 'f1', template_id: 't', severity: 'critical', confidence: 1, title: 'T', cwe_ids: [],
    annotation: { file: 'src/a.ts', line: 4 }, evidence: EV },
] }));
const ra = await runCli(a.root);
const srcA = await readFile(join(a.root, 'src', 'a.ts'), 'utf-8');
console.log('(a) all findings join by location:');
console.log('    wrote anything:', srcA.includes('@confirmed'), ' exit:', ra.code, '(should be non-zero)');

// (b) mixed — one key-verified and written, one skipped
const b = await proj();
const s = generateSarif(b.model);
await writeFile(join(b.root, 'scan.json'), JSON.stringify({ scan_id: 'cxg', findings: [
  { id: 'fSkip', template_id: 'tS', severity: 'critical', confidence: 1, title: 'T', cwe_ids: [],
    annotation: { file: 'src/a.ts', line: 4 }, evidence: EV },
  { id: 'fKeyed', template_id: 'tK', severity: 'high', confidence: 1, title: 'T', cwe_ids: [],
    claim_key: keyAt(s, 9), evidence: EV },
] }));
const rb = await runCli(b.root);
const srcB = await readFile(join(b.root, 'src', 'a.ts'), 'utf-8');
console.log('\n(b) one key-verified written, one skipped:');
console.log('    @confirmed lines written:', srcB.split('\n').filter(l => l.includes('@confirmed')).length);
console.log('    skip message present:', /! skipped/.test(rb.out), ' exit:', rb.code, '(should be non-zero)');
