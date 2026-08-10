/**
 * GL-201 — file-anchored context.
 *
 * Two fixtures, because one cannot cover the ground. The live repo is
 * inline-only (origin_file is 0 across every record), so external-mode
 * behaviour — .gal resolution, origin_file, parent_symbol narrowing — is tested
 * against a scratch repo built in /tmp with real @source blocks and run through
 * the real parser.
 *
 * Structural facts are asserted as preconditions rather than as exact counts:
 * this branch adds annotated source files as it goes, so a hardcoded "37
 * records" would rot within a commit.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { fileContext, normalizeContextPath } from '../src/mcp/context.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

// ─── Inline fixture: the live repo ───────────────────────────────────

describe('guardlink_context — inline mode (live repo)', () => {
  let model: ThreatModel;

  beforeAll(async () => {
    ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' }));
  });

  const ctx = (file: string, line?: number) =>
    fileContext(model, { file, exists: true, line });

  it('precondition: the live repo is inline-only', () => {
    // If this ever fails, the external-mode cases below stop being the only
    // coverage of .gal behaviour and this fixture can be widened.
    const withOrigin = model.exposures.filter(e => e.location.origin_file).length;
    expect(withOrigin).toBe(0);
  });

  it('returns annotations for a heavily annotated file', () => {
    const c = ctx('.guardlink/definitions.ts');
    expect(c.status).toBe('annotated');
    expect(c.annotation_source).toBe('inline');
    expect(c.annotations.length).toBeGreaterThan(20);
    expect(c.counts.asset).toBeGreaterThan(0);
    expect(c.counts.threat).toBeGreaterThan(0);
    expect(c.counts.control).toBeGreaterThan(0);
  });

  it('every returned annotation carries a line anchor', () => {
    const c = ctx('src/agents/prompts.ts');
    expect(c.annotations.length).toBeGreaterThan(0);
    for (const a of c.annotations) {
      expect(typeof a.line, JSON.stringify(a)).toBe('number');
      expect(a.line).toBeGreaterThan(0);
    }
  });

  it('names the assets its annotations reference, with depth-1 neighbourhoods', () => {
    const c = ctx('src/mcp/server.ts');
    expect(c.assets.length).toBeGreaterThan(0);
    const mcp = c.assets.find(a => a.ref.replace(/^#/, '') === 'mcp');
    expect(mcp).toBeDefined();
    expect(mcp!.declared).toBe(true);
    expect(mcp!.relationships).toBeDefined();
    expect((mcp!.relationships as any).exposures.length).toBeGreaterThan(0);
  });

  it('open_exposures excludes anything mitigated or accepted', () => {
    const c = ctx('src/mcp/server.ts');
    const covered = new Set<string>();
    for (const m of model.mitigations) covered.add(`${m.asset}::${m.threat}`);
    for (const a of model.acceptances) covered.add(`${a.asset}::${a.threat}`);
    for (const e of c.open_exposures) {
      expect(covered.has(`${e.asset}::${e.threat}`)).toBe(false);
    }
  });

  it('inline annotations carry no origin_file', () => {
    const c = ctx('src/mcp/server.ts');
    expect(c.origin_files).toEqual([]);
    for (const a of c.annotations) expect(a.origin_file).toBeUndefined();
  });

  // ─── The distinction that matters: empty vs never-read ─────────────

  it('a scanned file with no annotations is explicitly clean', () => {
    const unannotated = model.unannotated_files[0];
    expect(unannotated, 'repo has no unannotated files to test with').toBeDefined();
    const c = ctx(unannotated);
    expect(c.status).toBe('scanned_without_annotations');
    expect(c.annotations).toEqual([]);
    expect(c.hint).toMatch(/parsed and has no GuardLink annotations/);
  });

  it('a file the parser never reads is NOT reported as clean', () => {
    // tests/ is in DEFAULT_EXCLUDE, so this very file is outside the scan set.
    const c = fileContext(model, { file: 'tests/context.test.ts', exists: true });
    expect(c.status).toBe('not_scanned');
    expect(c.status).not.toBe('scanned_without_annotations');
    expect(c.hint).toMatch(/never read|never parsed/);
  });

  it('an unscanned extension says so rather than implying cleanliness', () => {
    const c = fileContext(model, { file: 'README.md', exists: true });
    expect(c.status).toBe('not_scanned');
    expect(c.hint).toMatch(/extension is not scanned/);
    expect(c.hint).toMatch(/does NOT mean the file is clean/);
  });

  it('a path with nothing at it is not_found', () => {
    const c = fileContext(model, { file: 'src/no-such-file.ts', exists: false });
    expect(c.status).toBe('not_found');
  });

  it('all four empty statuses are distinguishable from each other', () => {
    const statuses = new Set([
      ctx(model.unannotated_files[0]).status,
      fileContext(model, { file: 'tests/context.test.ts', exists: true }).status,
      fileContext(model, { file: 'README.md', exists: true }).status,
      fileContext(model, { file: 'src/nope.ts', exists: false }).status,
    ]);
    expect(statuses.size).toBeGreaterThanOrEqual(3);
    expect(statuses.has('scanned_without_annotations')).toBe(true);
    expect(statuses.has('not_scanned')).toBe(true);
    expect(statuses.has('not_found')).toBe(true);
  });

  it('line narrowing reports unavailable rather than pretending, in inline mode', () => {
    const c = ctx('src/mcp/server.ts', 300);
    expect(c.symbol_scope?.applied).toBe('unavailable');
    expect(c.symbol_scope?.symbol).toBeNull();
    expect(c.symbol_scope?.reason).toMatch(/parent_symbol/);
    // The annotations are still returned — narrowing failed, the query did not.
    expect(c.annotations.length).toBeGreaterThan(0);
  });
});

// ─── Path handling ───────────────────────────────────────────────────

describe('guardlink_context — path normalisation', () => {
  it('accepts relative, ./-prefixed, absolute and backslash forms', () => {
    const forms = [
      'src/mcp/server.ts',
      './src/mcp/server.ts',
      join(repoRoot, 'src/mcp/server.ts'),
      'src\\mcp\\server.ts',
    ];
    for (const f of forms) {
      expect(normalizeContextPath(repoRoot, f), f).toBe('src/mcp/server.ts');
    }
  });

  it('rejects a path that escapes the root', () => {
    expect(normalizeContextPath(repoRoot, '../etc/passwd')).toBeNull();
    expect(normalizeContextPath(repoRoot, '/etc/passwd')).toBeNull();
  });

  it('rejects the root itself', () => {
    expect(normalizeContextPath(repoRoot, '.')).toBeNull();
  });
});

// ─── External fixture: .gal sidecars ─────────────────────────────────

const DEFINITIONS = `/**
 * @asset App.Auth (#auth) -- "Authentication surface"
 * @asset App.DB (#db) -- "Database layer"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

describe('guardlink_context — external mode (.gal sidecars)', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-ctx-'));
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'auth.ts'),
      'export function login(email: string) {\n  return email.length > 0;\n}\n\nexport function logout() {\n  return true;\n}\n');
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'auth.ts.gal'),
      [
        '@source file:src/auth.ts line:1 symbol:login',
        '@exposes #auth to #sqli [critical] cwe:CWE-89 -- "Email concatenated into SQL"',
        '@handles pii on #auth -- "Processes email"',
        '@source file:src/auth.ts line:5 symbol:logout',
        '@assumes #auth -- "Session store is reachable"',
        '',
      ].join('\n'));
    ({ model } = await parseProject({ root, project: 'ext' }));
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  const ctx = (file: string, line?: number) => fileContext(model, { file, exists: true, line });

  it('precondition: the fixture really is external', () => {
    expect(model.exposures[0].location.origin_file).toBe('.guardlink/annotations/src/auth.ts.gal');
    expect(model.exposures[0].location.file).toBe('src/auth.ts');
  });

  it('the source path returns the annotations written in the .gal', () => {
    const c = ctx('src/auth.ts');
    expect(c.status).toBe('annotated');
    expect(c.annotation_source).toBe('external');
    expect(c.origin_files).toEqual(['.guardlink/annotations/src/auth.ts.gal']);
    expect(c.counts.exposes).toBe(1);
    expect(c.counts.handles).toBe(1);
    expect(c.counts.assumes).toBe(1);
  });

  it('the .gal path returns the SAME result set as the source path', () => {
    const viaSource = ctx('src/auth.ts');
    const viaGal = ctx('.guardlink/annotations/src/auth.ts.gal');
    expect(viaGal.resolved_from).toBe('.guardlink/annotations/src/auth.ts.gal');
    // Identical apart from the breadcrumb saying how we got here.
    const { resolved_from, ...rest } = viaGal;
    expect(rest).toEqual(viaSource);
  });

  it('every annotation carries its origin_file and origin_line', () => {
    for (const a of ctx('src/auth.ts').annotations) {
      expect(a.origin_file).toBe('.guardlink/annotations/src/auth.ts.gal');
      expect(typeof a.origin_line).toBe('number');
    }
  });

  it('line narrows to the enclosing symbol', () => {
    const c = ctx('src/auth.ts', 2);
    expect(c.symbol_scope?.applied).toBe('narrowed');
    expect(c.symbol_scope?.symbol).toBe('login');
    // @assumes is anchored to logout and must drop out.
    expect(c.counts.assumes).toBeUndefined();
    expect(c.counts.exposes).toBe(1);
  });

  it('a line inside the second symbol selects that symbol', () => {
    const c = ctx('src/auth.ts', 6);
    expect(c.symbol_scope?.symbol).toBe('logout');
    expect(c.counts.assumes).toBe(1);
    expect(c.counts.exposes).toBeUndefined();
  });

  it('without a line, all symbols in the file are returned', () => {
    const c = ctx('src/auth.ts');
    expect(c.symbol_scope).toBeUndefined();
    expect(c.annotations).toHaveLength(3);
  });

  it('a .gal covering several source files is reported ambiguous, not guessed', async () => {
    const multi = await mkdtemp(join(tmpdir(), 'guardlink-ctx-multi-'));
    try {
      await mkdir(join(multi, '.guardlink', 'annotations'), { recursive: true });
      await mkdir(join(multi, 'src'), { recursive: true });
      await writeFile(join(multi, '.guardlink', 'definitions.ts'), DEFINITIONS);
      await writeFile(join(multi, 'src', 'a.ts'), 'export const a = 1;\n');
      await writeFile(join(multi, 'src', 'b.ts'), 'export const b = 2;\n');
      await writeFile(join(multi, '.guardlink', 'annotations', 'shared.gal'),
        [
          '@source file:src/a.ts line:1 symbol:a',
          '@audit #auth -- "a needs review"',
          '@source file:src/b.ts line:1 symbol:b',
          '@audit #db -- "b needs review"',
          '',
        ].join('\n'));
      const { model: m } = await parseProject({ root: multi, project: 'multi' });
      const c = fileContext(m, { file: '.guardlink/annotations/shared.gal', exists: true });
      expect(c.status).toBe('ambiguous_origin');
      expect(c.logical_files).toEqual(['src/a.ts', 'src/b.ts']);
      expect(c.annotations).toEqual([]);
    } finally {
      await rm(multi, { recursive: true, force: true });
    }
  });
});

// ─── Entitlements reach the per-file view ────────────────────────────
//
// allRecords() rebuilds the record list verb by verb, so a collection it does not
// name is invisible to an agent asking about that file — it would be told the
// path holds no entitlement, the opposite of what the annotation says. Built on a
// scratch repo rather than this one: guardlink's own claim lives in the proposal
// ledger, not in source, and a test that reads it out of source would rot the
// moment someone accepts or withdraws it.
describe('guardlink_context — @entitles records', () => {
  let root: string;
  let model: ThreatModel;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-ctx-ent-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), [
      '// @asset Archival.FS (#archival-fs) -- "Archival destination"',
      '// @threat Path_Traversal (#path-traversal) [high] cwe:CWE-22 -- "URI used as a path"',
      '// @actor Namespace_Admin (#ns-admin) -- "Administers one namespace"',
    ].join('\n'));
    await writeFile(join(root, 'src', 'archiver.ts'), [
      '// @exposes #archival-fs to #path-traversal [high] -- "URI is used as a filesystem path"',
      '// @entitles #ns-admin to configure-archival on #archival-fs against #path-traversal -- "By design. Authz: common/api/metadata.go:189"',
      'export function archive(uri: string) { return uri; }',
    ].join('\n'));
    ({ model } = await parseProject({ root, project: 'tmp' }));
  });

  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('surfaces the entitlement, its citation, and both halves of the join', () => {
    const c = fileContext(model, { file: 'src/archiver.ts', exists: true });
    const [e] = c.annotations.filter(a => a.verb === 'entitles') as Record<string, unknown>[];
    expect(e).toBeDefined();
    expect(e.actor).toBe('#ns-admin');
    expect(e.asset).toBe('#archival-fs');
    expect(e.threat).toBe('#path-traversal');
    expect(e.inert).toBe(false);
    expect(e.citation).toBeDefined();
  });

  it('reports an uncited claim as inert rather than omitting it', async () => {
    const scratch = await mkdtemp(join(tmpdir(), 'guardlink-ctx-inert-'));
    try {
      await mkdir(join(scratch, 'src'), { recursive: true });
      await writeFile(join(scratch, 'src', 'a.ts'), [
        '// @entitles #ns-admin to configure-archival on #archival-fs against #path-traversal -- "Admins do this"',
        'export const a = 1;',
      ].join('\n'));
      const { model: m } = await parseProject({ root: scratch, project: 'tmp' });
      const c = fileContext(m, { file: 'src/a.ts', exists: true });
      const [e] = c.annotations.filter(a => a.verb === 'entitles') as Record<string, unknown>[];
      expect(e).toBeDefined();
      expect(e.inert).toBe(true);
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });
});
