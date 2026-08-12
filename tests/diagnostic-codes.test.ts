/**
 * Every diagnostic kind carries a machine-readable `code`.
 *
 * `ParseDiagnostic.code` documents itself as "present on diagnostics that have
 * a defined kind" — and only two kinds were defined, so seven others shipped
 * without one. A consumer wanting to treat dangling refs differently from
 * risk-acceptance hygiene had nothing to switch on but the message prose, which
 * is exactly the coupling `code` was added to remove.
 *
 * This test is written against the emitters rather than a hardcoded list so
 * that a new diagnostic without a code fails here rather than at a consumer.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import {
  findDanglingRefs, findUndeclaredActors, findInertEntitlements,
  findImpreciseEntitlements, findAcceptedWithoutAudit, findOffConventionGalFiles,
} from '../src/parser/validate.js';
import { checkEntitlementProvenance } from '../src/review/entitlements.js';
import type { ThreatModel, ParseDiagnostic } from '../src/types/index.js';

let root: string;
let model: ThreatModel;
let parseDiagnostics: ParseDiagnostic[];

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'gl-codes-'));
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  mkdirSync(join(root, 'app'), { recursive: true });
  mkdirSync(join(root, 'docs'), { recursive: true });

  writeFileSync(join(root, '.guardlink', 'definitions.ts'),
    '// @asset Svc.Api (#api) -- "api"\n'
    + '// @asset Svc.Api (#api) -- "a second claim on the same id"\n'
    + '// @threat SQLi (#sqli) [high] -- "t"\n'
    + '// @actor Admin (#admin) -- "a"\n');

  writeFileSync(join(root, 'app', 'a.ts'),
    '/**\n'
    + ' * @flow #api -> #api\n'
    + ' * @exposes #api to #nosuchthreat [high] -- "dangling"\n'
    + ' * @accepts #sqli on #api -- "accepted with no audit"\n'
    + ' * @entitles #ghost to doathing -- "no citation, no asset, no threat"\n'
    + ' * @entitles #admin to configure-thing on #api against #sqli -- "By design. Authz: app/a.ts:2"\n'
    + ' */\n'
    + 'export function f() {}\n');

  // A sidecar nowhere near the conventional .guardlink/annotations/ path.
  writeFileSync(join(root, 'docs', 'notes.gal'),
    '@source file:app/a.ts line:8\n@comment -- "sidecar in the wrong place"\n');

  // A ledger exists but accepts nothing — provenance is skipped without one.
  writeFileSync(join(root, '.guardlink', 'entitlement-proposals.json'),
    JSON.stringify({ version: '1', proposals: [] }));

  const parsed = await parseProject({ root, project: 'codes' });
  model = parsed.model;
  parseDiagnostics = parsed.diagnostics;
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('every diagnostic kind is machine-classifiable', () => {
  const expected: [string, string, () => ParseDiagnostic[] | Promise<ParseDiagnostic[]>][] = [
    ['unknown-verb', 'parse', () => parseDiagnostics],
    ['duplicate-id', 'parse', () => parseDiagnostics],
    ['dangling-ref', 'validate', () => findDanglingRefs(model)],
    ['undeclared-actor', 'validate', () => findUndeclaredActors(model)],
    ['inert-entitlement', 'validate', () => findInertEntitlements(model)],
    ['imprecise-entitlement', 'validate', () => findImpreciseEntitlements(model)],
    ['accepted-without-audit', 'validate', () => findAcceptedWithoutAudit(model)],
    ['off-convention-gal', 'validate', () => findOffConventionGalFiles(model)],
    ['entitlement-provenance', 'governance', () => checkEntitlementProvenance(root, model)],
  ];

  for (const [code, tier, emit] of expected) {
    it(`${tier}: emits ${code}`, async () => {
      const diagnostics = await emit();
      expect(diagnostics.map(d => d.code)).toContain(code);
    });
  }

  it('no emitter produces a diagnostic without a code', async () => {
    const all = [
      ...parseDiagnostics,
      ...findDanglingRefs(model),
      ...findUndeclaredActors(model),
      ...findInertEntitlements(model),
      ...findImpreciseEntitlements(model),
      ...findAcceptedWithoutAudit(model),
      ...findOffConventionGalFiles(model),
      ...await checkEntitlementProvenance(root, model),
    ];
    expect(all.length).toBeGreaterThan(0);
    expect(all.filter(d => !d.code).map(d => d.message)).toEqual([]);
  });

  it('codes survive into anything that serialises a diagnostic', () => {
    const round = JSON.parse(JSON.stringify(findDanglingRefs(model)));
    expect(round[0].code).toBe('dangling-ref');
  });
});

describe('unknown-verb is collapsed per file and can be switched off', () => {
  it('repeats of one token in one file produce one diagnostic carrying the count', async () => {
    const root = mkdtempSync(join(tmpdir(), 'gl-dedup-'));
    try {
      mkdirSync(join(root, '.guardlink'), { recursive: true });
      mkdirSync(join(root, 'app'), { recursive: true });
      writeFileSync(join(root, '.guardlink', 'definitions.ts'), '// @asset A.B (#ab) -- "x"\n');
      writeFileSync(join(root, 'app', 'a.ts'),
        '/**\n * @flow #ab -> #ab\n * @flow #ab -> #ab\n * @flow #ab -> #ab\n */\nexport const a = 1;\n');
      // A second file with the same typo must still be reported — the collapse
      // is per file so the fix stays local to each one.
      writeFileSync(join(root, 'app', 'b.ts'), '/**\n * @flow #ab -> #ab\n */\nexport const b = 1;\n');

      const { diagnostics } = await parseProject({ root, project: 'dedup' });
      const unknown = diagnostics.filter(d => d.code === 'unknown-verb');
      expect(unknown).toHaveLength(2);
      expect(unknown.map(d => d.file).sort()).toEqual(['app/a.ts', 'app/b.ts']);

      const a = unknown.find(d => d.file === 'app/a.ts')!;
      expect(a.line).toBe(2);                       // first occurrence keeps the anchor
      expect(a.message).toContain('3 occurrences in this file');
      // A single occurrence gets no count suffix.
      expect(unknown.find(d => d.file === 'app/b.ts')!.message).not.toContain('occurrences');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('config can switch a warning off, and cannot switch an error off', async () => {
    const root = mkdtempSync(join(tmpdir(), 'gl-gate-'));
    try {
      mkdirSync(join(root, '.guardlink'), { recursive: true });
      mkdirSync(join(root, 'app'), { recursive: true });
      writeFileSync(join(root, '.guardlink', 'definitions.ts'), '// @asset A.B (#ab) -- "x"\n');
      writeFileSync(join(root, 'app', 'a.ts'),
        '/**\n * @flow #ab -> #ab\n * @exposes #ab to\n */\nexport const a = 1;\n');

      const on = await parseProject({ root, project: 'gate' });
      expect(on.diagnostics.some(d => d.code === 'unknown-verb')).toBe(true);
      expect(on.diagnostics.some(d => d.code === 'malformed-annotation')).toBe(true);

      writeFileSync(join(root, '.guardlink', 'config.json'), JSON.stringify({
        project: 'gate',
        diagnostics: { 'unknown-verb': false, 'malformed-annotation': false },
      }));

      const off = await parseProject({ root, project: 'gate' });
      expect(off.diagnostics.some(d => d.code === 'unknown-verb')).toBe(false);
      // The error survives: configuration may quiet noise, never a broken annotation.
      expect(off.diagnostics.some(d => d.code === 'malformed-annotation')).toBe(true);
      expect(off.diagnostics.some(d => d.level === 'error')).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
