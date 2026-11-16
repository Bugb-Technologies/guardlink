import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { linkProject } from '../src/workspace/link.js';

let root: string;
const put = (file: string, data: string) => writeFileSync(file, data);
function member(name: string, source: string) {
  const dir = join(root, name); mkdirSync(join(dir, '.guardlink'), { recursive: true });
  put(join(dir, '.guardlink/config.json'), JSON.stringify({ include: ['app.ts'] }));
  put(join(dir, 'app.ts'), source); return dir;
}
function scaffold() {
  const api = member('api', '// @asset Shop.API (#api)\n// @threat Injection (#injection) [high]\n// @control Bound_Query (#guard)\n// @exposes #api to #injection [high] -- "fixture query"\n// @flows #api -> #auth via HTTP\n');
  const auth = member('auth', '// @asset Shop.Auth (#auth)\n// @mitigates #api against #injection using #guard\n// @flows #api -> #auth via HTTP\n');
  linkProject({ workspace: 'shop', repoPaths: [api, auth] });
  const manifest = join(root, 'selected.json');
  put(manifest, JSON.stringify({ schema: 'guardlink.application-manifest/v1', name: 'shop', members: [
    { id: 'api', guardlinkIdentity: 'api', relativePath: 'api', service: 'api' },
    { id: 'auth', guardlinkIdentity: 'auth', relativePath: 'auth', service: 'auth' },
  ] }));
  return { api, auth, manifest };
}
const collect = (manifest: string) => parseProject({ root, applicationManifest: manifest, anchors: false });
beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'gl-application-view-')); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('application semantic view contract', () => {
  it('advertises its versioned capability at the real CLI boundary', () => {
    const tsx = createRequire(import.meta.url).resolve('tsx/cli');
    const cli = join(dirname(fileURLToPath(import.meta.url)), '../src/cli/index.ts');
    const json = execFileSync(process.execPath, [tsx, cli, 'application-view', '--capabilities'], { encoding: 'utf8' });
    expect(JSON.parse(json).receiptSchema).toBe('bravos.application-view/v1');
  });
  it('keeps the selected roster, occurrence provenance and every grouped flow declaration', async () => {
    const { manifest } = scaffold(); member('unselected', '// @asset Other (#other)');
    const { model } = await collect(manifest);
    expect(model.application?.receipt).toMatchObject({ schema: 'bravos.application-view/v1', expectedMemberIds: ['api', 'auth'], completeness: 'complete' });
    expect(model.assets.some(a => a.id === 'other')).toBe(false);
    expect(model.exposures[0].location).toMatchObject({ memberId: 'api', memberFile: 'app.ts' });
    expect(model.application?.flowGroups).toHaveLength(1);
    expect(model.application?.flowGroups[0].declarations).toHaveLength(2);
    expect(model.application?.receipt.members.every(m => m.revision?.vcs === 'none' && m.revision.commit === null)).toBe(true);
  });
  it('retains available content and every expected member when one checkout is missing', async () => {
    const { auth, manifest } = scaffold(); rmSync(auth, { recursive: true });
    const { model } = await collect(manifest);
    expect(model.exposures).toHaveLength(1);
    expect(model.application?.receipt.completeness).toBe('partial');
    expect(model.application?.receipt.members.find(m => m.id === 'auth')).toMatchObject({ state: 'missing', revision: null });
    expect(model.application?.coverage.overallPercent).toBeNull();
    expect(model.application?.coverage.known.annotatedFiles).toBeGreaterThan(0);
  });
  it('keeps generated permissions and their auxiliary inventory scoped to each member', async () => {
    const { api, auth, manifest } = scaffold();
    for (const dir of [api, auth]) { mkdirSync(join(dir, '.claude'), { recursive: true }); put(join(dir, '.claude/settings.json'), '{"permissions":{"allow":["Bash(echo:*)"]}}'); }
    const { model } = await collect(manifest);
    const actors = model.actors?.filter(a => a.origin === 'agent-config') ?? [];
    expect(new Set(actors.map(a => a.id)).size).toBe(2);
    expect(model.application?.members.every(m => m.agentConfig?.files.length)).toBe(true);
    expect(model.reaches?.filter(r => r.origin === 'agent-config').every(r => r.location.memberId)).toBe(true);
  });
});
