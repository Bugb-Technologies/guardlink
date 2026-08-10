/**
 * GL-504 — structured annotation writes.
 *
 * The story's acceptance criteria as executable claims. Written against real
 * files on disk and re-parsed with the real parser, because the property that
 * matters is not "the function returned ok" but "what it wrote is something
 * GuardLink can actually read back".
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyAnnotations } from '../src/parser/apply-annotations.js';
import { parseProject } from '../src/parser/parse-project.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const EXPOSE = '@exposes #api to #sqli [critical] cwe:CWE-89 -- "req.body.email concatenated into SQL"';
const AUDIT = '@audit #api -- "Needs parameterisation before release"';

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-apply-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), 'export function handler(req) {\n  return req;\n}\n');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const apply = (annotations: string[], over: Record<string, unknown> = {}) =>
  applyAnnotations({ root, file: 'src/api.ts', line: 1, symbol: 'handler', annotations, ...over });

describe('GL-504 — writes a well-formed @source block to the resolved .gal', () => {
  it('derives the sidecar path from the source file; the caller does not choose it', () => {
    const result = apply([EXPOSE]);
    expect(result.ok).toBe(true);
    expect(result.galPath).toBe('.guardlink/annotations/src/api.ts.gal');
  });

  it('writes a header carrying file, line and symbol', async () => {
    apply([EXPOSE, AUDIT]);
    const written = await readFile(join(root, '.guardlink/annotations/src/api.ts.gal'), 'utf-8');
    expect(written).toContain('@source file:src/api.ts line:1 symbol:handler');
    expect(written).toContain(EXPOSE);
    expect(written).toContain(AUDIT);
  });

  it('omits symbol: from the header when none was supplied', async () => {
    apply([EXPOSE], { symbol: undefined });
    const written = await readFile(join(root, '.guardlink/annotations/src/api.ts.gal'), 'utf-8');
    expect(written.split('\n')[0]).toBe('@source file:src/api.ts line:1');
  });

  it('what it writes parses back through the real parser', async () => {
    apply([EXPOSE, AUDIT]);
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(1);
    expect(model.exposures[0].asset).toBe('#api');
    expect(model.exposures[0].threat).toBe('#sqli');
    expect(model.exposures[0].severity).toBe('critical');
    expect(model.audits).toHaveLength(1);
    // The anchor is recorded against the SOURCE file, not the sidecar — this is
    // what makes the block re-anchorable later.
    expect(model.exposures[0].location.file).toBe('src/api.ts');
    expect(model.exposures[0].location.line).toBe(1);
    expect(model.exposures[0].location.parent_symbol).toBe('handler');
    expect(model.exposures[0].location.origin_file).toMatch(/\.gal$/);
  });

  it('appends a second block rather than overwriting the first', async () => {
    apply([EXPOSE]);
    applyAnnotations({ root, file: 'src/api.ts', line: 2, symbol: 'handler', annotations: [AUDIT] });
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(1);
    expect(model.audits).toHaveLength(1);
  });

  it('creates the sidecar directory tree for a nested source file', async () => {
    await mkdir(join(root, 'src', 'deep', 'nested'), { recursive: true });
    await writeFile(join(root, 'src/deep/nested/x.ts'), 'export const x = 1;\n');
    const result = applyAnnotations({
      root, file: 'src/deep/nested/x.ts', line: 1, annotations: [AUDIT],
    });
    expect(result.status).toBe('written');
    expect(result.galPath).toBe('.guardlink/annotations/src/deep/nested/x.ts.gal');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.audits).toHaveLength(1);
  });
});

describe('GL-504 — returns a diff of what was written', () => {
  it('the diff lists every added line, prefixed', () => {
    const result = apply([EXPOSE, AUDIT]);
    expect(result.diff).toContain('--- .guardlink/annotations/src/api.ts.gal');
    expect(result.diff).toContain('+@source file:src/api.ts line:1 symbol:handler');
    expect(result.diff).toContain(`+${EXPOSE}`);
    expect(result.diff).toContain(`+${AUDIT}`);
    expect(result.linesWritten).toBe(3);   // header + two annotations
  });

  it('dry_run returns the diff without touching disk', async () => {
    const result = apply([EXPOSE], { dryRun: true });
    expect(result.status).toBe('written');
    expect(result.diff).toContain(`+${EXPOSE}`);
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(0);
  });
});

describe('GL-504 — refuses @accepts', () => {
  it('rejects a lone @accepts and writes nothing', async () => {
    const result = apply(['@accepts #sqli on #api -- "Business signed off"']);
    expect(result.ok).toBe(false);
    expect(result.status).toBe('rejected');
    expect(result.errors[0]).toContain('refusing to write `@accepts`');
    expect(result.errors[0]).toContain('human');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.acceptances).toHaveLength(0);
  });

  it('rejects the WHOLE block when @accepts is smuggled among valid lines', async () => {
    const result = apply([EXPOSE, '@accepts #sqli on #api -- "signed off"', AUDIT]);
    expect(result.ok).toBe(false);
    // The valid neighbours must not land either — a partial write would leave
    // the agent believing the acceptance was recorded alongside them.
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(0);
    expect(model.audits).toHaveLength(0);
  });

  it('points at the alternative rather than just saying no', () => {
    const result = apply(['@accepts #sqli on #api -- "signed off"']);
    expect(result.errors[0]).toContain('@exposes');
    expect(result.errors[0]).toContain('@audit');
  });

  // @entitles is the second claim a tool may not make on a human's behalf. It
  // says the caller was allowed to do this all along, so writing it here would
  // close a finding as by-design AND bypass the proposal ledger that records who
  // granted the privilege (actor-entitlement design §3.6).
  it('rejects @entitles and writes nothing', async () => {
    const result = apply([
      '@entitles #ns-admin to configure-archival -- "By design. Authz: src/authz.ts:12"',
    ]);
    expect(result.ok).toBe(false);
    expect(result.status).toBe('rejected');
    expect(result.errors[0]).toContain('refusing to write `@entitles`');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.entitlements ?? []).toHaveLength(0);
  });

  it('sends the caller to the proposal flow rather than to @exposes', () => {
    const result = apply(['@entitles #ns-admin to configure-archival -- "Authz: src/authz.ts:12"']);
    expect(result.errors[0]).toContain('guardlink_entitlement_propose');
    expect(result.errors[0]).toContain('guardlink entitle');
  });

  it('rejects the WHOLE block when @entitles is smuggled among valid lines', async () => {
    const result = apply([EXPOSE, '@entitles #ns-admin to configure-archival -- "Authz: a.ts:1"', AUDIT]);
    expect(result.ok).toBe(false);
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(0);
    expect(model.audits).toHaveLength(0);
  });
});

describe('GL-504 — malformed input rejected with a diagnostic', () => {
  it('rejects a line that does not parse, naming the line and the reason', () => {
    const result = apply(['@exposes this is not valid gal']);
    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain('Line 1');
    expect(result.errors[0]).toContain('did not parse');
  });

  it('rejects prose that is not an annotation at all', () => {
    const result = apply(['the api is vulnerable to sql injection']);
    expect(result.errors[0]).toContain('is not an annotation');
  });

  it('rejects a comment-prefixed line rather than silently stripping it', () => {
    const result = apply([` * ${EXPOSE}`]);
    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain('no comment prefix');
  });

  it('reports every bad line, not only the first', () => {
    const result = apply(['@exposes garbage', 'prose', '@mitigates nonsense']);
    expect(result.errors).toHaveLength(3);
  });

  it('refuses a caller-supplied @source — the header is generated', () => {
    const result = apply(['@source file:src/other.ts line:9', EXPOSE]);
    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain('do not supply @source');
  });

  it('rejects an empty annotation list', () => {
    expect(apply([]).errors[0]).toBe('No annotations supplied.');
  });

  it('rejects a non-positive line number', () => {
    expect(apply([EXPOSE], { line: 0 }).errors[0]).toContain('positive integer');
  });

  it('refuses a path escaping the project root', () => {
    const result = apply([EXPOSE], { file: '../../etc/passwd' });
    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain('outside the project root');
  });
});

describe('GL-504 — idempotent', () => {
  it('re-applying the same block is unchanged, not duplicated', async () => {
    expect(apply([EXPOSE, AUDIT]).status).toBe('written');
    const again = apply([EXPOSE, AUDIT]);
    expect(again.ok).toBe(true);
    expect(again.status).toBe('unchanged');
    expect(again.diff).toBe('');
    expect(again.linesWritten).toBe(0);

    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(1);
    expect(model.audits).toHaveLength(1);
  });

  it('incidental whitespace does not defeat the check', () => {
    apply([EXPOSE]);
    expect(apply([`  ${EXPOSE}  `]).status).toBe('unchanged');
  });

  it('but a changed description IS a new block', async () => {
    apply([EXPOSE]);
    const changed = EXPOSE.replace('concatenated into SQL', 'passed to a prepared statement');
    expect(apply([changed]).status).toBe('written');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(2);
  });

  it('and the same annotation at a different line IS a new block', async () => {
    apply([EXPOSE]);
    expect(apply([EXPOSE], { line: 42 }).status).toBe('written');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.exposures).toHaveLength(2);
  });
});

describe('GL-504 — never writes into source', () => {
  it('the annotated source file is left byte-identical', async () => {
    const before = await readFile(join(root, 'src', 'api.ts'), 'utf-8');
    apply([EXPOSE, AUDIT]);
    expect(await readFile(join(root, 'src', 'api.ts'), 'utf-8')).toBe(before);
  });
});
