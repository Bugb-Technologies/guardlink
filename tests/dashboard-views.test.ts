/**
 * The fourth pass: what changed since a ref, who owns the open risk,
 * sensitive data under open exposure, feature-aware analytics, linked
 * report ids, risk-ordered file cards, and diagram focus.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { parseProject } from '../src/parser/parse-project.js';
import { generateDashboardHTML } from '../src/dashboard/index.js';
import { computeOwnership, computeSensitiveData, computeFileRisk, computeChanges } from '../src/dashboard/data.js';
import { buildClaims } from '../src/dashboard/pages/context.js';
import { diffModels } from '../src/diff/index.js';
import type { SinceInput } from '../src/dashboard/since.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @asset App.Web (#web) -- "Web tier"
 * @asset App.DB (#db) -- "Database"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat XSS (#xss) [high] cwe:CWE-79 -- "Script injection"
 * @control Encoding (#enc) -- "Output encoding"
 */
export {};
`;
const API = `import x from 'x';

/**
 * @feature "Login" -- "login flow"
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "raw sql"
 * @exposes #api to #xss [medium] -- "reflected"
 * @mitigates #api against #xss using #enc -- "escaped"
 * @handles pii on #api -- "emails"
 * @owns platform for #api -- "platform team"
 * @flows User -> #api via HTTPS -- "login"
 */
export function login() {}
`;
const WEB = `import x from 'x';

/**
 * @feature "Web" -- "web tier"
 * @exposes #web to #xss [high] -- "bio"
 * @exposes #db to #sqli [high] -- "concat"
 * @handles secrets on #web -- "tokens"
 */
export function page() {}
`;
// The "before" state: no reflected XSS on the API, no DB exposure yet.
const API_BEFORE = API.replace(' * @exposes #api to #xss [medium] -- "reflected"\n', '').replace(' * @mitigates #api against #xss using #enc -- "escaped"\n', '');
const WEB_BEFORE = WEB.replace(' * @exposes #db to #sqli [high] -- "concat"\n', '');

async function project(api = API, web = WEB): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-views-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'z-api.ts'), api);
  await writeFile(join(root, 'src', 'a-web.ts'), web);
  return root;
}

async function sinceFixture(): Promise<{ root: string; since: SinceInput }> {
  const root = await project();
  const beforeRoot = await project(API_BEFORE, WEB_BEFORE);
  const { model: after } = await parseProject({ root, project: 'v' });
  const { model: before } = await parseProject({ root: beforeRoot, project: 'v' });
  const diff = diffModels(before, after);
  return { root, since: { ref: 'v1.0', refDate: '2026-01-01T00:00:00Z', commits: 3, diff, changedFiles: ['src/z-api.ts', 'src/a-web.ts'] } };
}

describe('owners and sensitive data', () => {
  it('rolls open risk up to the owning team and lists exposed assets nobody owns', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'v' });
    const claims = buildClaims(model, null, null);
    const o = computeOwnership(model, claims);
    expect(o.owners).toHaveLength(1);
    expect(o.owners[0]).toMatchObject({ owner: 'platform', assets: ['#api'], open: 1, total: 2, worstSev: 'critical' });
    expect(o.unowned.map(u => u.asset)).toEqual(['#db', '#web']);
    expect(claims.find(c => c.asset === '#api')!.owners).toEqual(['platform']);
    expect(claims.find(c => c.asset === '#web')!.owners).toEqual([]);
  });

  it('counts open exposure per data classification', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'v' });
    const claims = buildClaims(model, null, null);
    const s = computeSensitiveData(model, claims);
    expect(s.map(r => r.classification)).toEqual(['pii', 'secrets']);           // critical first
    expect(s[0]).toMatchObject({ classification: 'pii', assets: 1, exposedAssets: 1, open: 1, worstSev: 'critical' });
    expect(s[1]).toMatchObject({ classification: 'secrets', assets: 1, exposedAssets: 1, open: 1, worstSev: 'high' });
    expect(claims.find(c => c.asset === '#api')!.handles).toEqual(['pii']);
  });

  it('ranks files by the worst open exposure they carry', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'v' });
    const risk = computeFileRisk(buildClaims(model, null, null));
    expect(risk.get('src/z-api.ts')).toMatchObject({ open: 1, worst: 'critical' });
    expect(risk.get('src/a-web.ts')).toMatchObject({ open: 2, worst: 'high' });
    const h = generateDashboardHTML(model, root);
    expect(h.indexOf('data-ff="src/z-api.ts"')).toBeLessThan(h.indexOf('data-ff="src/a-web.ts"'));   // critical beats two highs, and beats the alphabet
    expect(h).toContain('class="file-risk"');
  });
});

describe('what changed since a ref', () => {
  it('summarises the diff and marks the new claim rows', async () => {
    const { root, since } = await sinceFixture();
    const { model } = await parseProject({ root, project: 'v' });
    const claims = buildClaims(model, null, null, { newKeys: new Set(since.diff.exposures.filter(c => c.kind === 'added').map(c => `exposes@${c.item.location.file}:${c.item.location.line}`)) });
    expect(claims.filter(c => c.change === 'new').map(c => `${c.asset} ${c.threat}`).sort()).toEqual(['#api #xss', '#db #sqli']);
    const ch = computeChanges(since, claims);
    expect(ch).toMatchObject({ ref: 'v1.0', commits: 3, newOpen: 1, riskDelta: 'increased' });
    expect(ch.newExposures).toHaveLength(2);
    expect(ch.resolved).toHaveLength(0);
    expect(ch.wentStale).toHaveLength(0);
    const h = generateDashboardHTML(model, root, [], { since });
    expect(h).toContain('id="since-strip"');
    expect(h).toContain('since <code>v1.0</code>');
    expect(h.match(/data-change="new"/g)).toHaveLength(2);
    expect(h).toContain('href="#threats?change=new"');
    expect(h).not.toContain('id="since-strip-missing"');
    expect(generateDashboardHTML(model, root)).not.toContain('id="since-strip"');
  });

  it('via the CLI: --since <ref> reads the model at that ref', async () => {
    const root = await project(API_BEFORE, WEB_BEFORE);
    const git = (...args: string[]): string => execFileSync('git', args, { cwd: root, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } });
    git('init', '-q');
    git('add', '-A'); git('commit', '-q', '-m', 'v1');
    await writeFile(join(root, 'src', 'z-api.ts'), API);
    await writeFile(join(root, 'src', 'a-web.ts'), WEB);
    git('add', '-A'); git('commit', '-q', '-m', 'v2');
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(process.cwd(), 'src', 'cli', 'index.ts');
    await new Promise<void>((res, rej) => execFile(process.execPath, [tsx, cli, 'dashboard', '.', '--since', 'HEAD~1', '-o', 'out.html'], { cwd: root, maxBuffer: 64 * 1024 * 1024 }, (err) => (err ? rej(err) : res())));
    const h = await readFile(join(root, 'out.html'), 'utf8');
    expect(h).toContain('id="since-strip"');
    expect(h).toContain('since <code>HEAD~1</code>');
    expect(h.match(/data-change="new"/g)).toHaveLength(2);
  }, 60_000);
});

describe('markup', () => {
  it('renders Analytics per feature, owners and sensitive-data panels, owner and class filters', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'v' });
    const h = generateDashboardHTML(model, root);
    expect(h).toContain('class="analytics-body" data-feature=""');
    expect(h).toContain('class="analytics-body" data-feature="Login" hidden');
    expect(h).toContain('class="analytics-body" data-feature="Web" hidden');
    expect(h).toContain('id="owners"');
    expect(h).toContain('id="sensitive"');
    expect(h).toContain('data-owner="platform"');
    expect(h).toContain('data-handles="pii"');
    expect(h).toContain('href="#threats?owner=platform&amp;status=open"');
    expect(h).toContain('href="#threats?handles=pii&amp;status=open"');
    expect(h).toContain('class="whole-model-note');
    for (const fn of ['function onFeatureFilter(', 'function linkifyIds(', 'function themeMermaid(', 'function diagramFocus(', 'function diagramFind(']) expect(h).toContain(fn);
  });

  it('embeds a focused threat graph per exposed asset', async () => {
    const root = await project();
    const { model } = await parseProject({ root, project: 'v' });
    const h = generateDashboardHTML(model, root);
    expect(h).toContain('class="diagram-focus"');
    expect(h).toContain('data-focus="#api"');
    expect(h).toContain('data-focus="#web"');
    expect(h).toContain('class="diagram-find"');
  });
});
