/**
 * D36 — a mitigation on one symbol must not clear an exposure on another.
 *
 * The corpus is the shape that matters: ONE file, ONE asset, ONE threat, TWO
 * symbols, one vulnerable and one not. That is the configuration
 * `${asset}::${threat}` cannot represent, and it is what a real service looks
 * like — `find_expenses` builds its SELECT by string formatting while
 * `insert_expense`, twelve lines below it, binds parameters correctly.
 *
 * Built here rather than borrowed from this repo, for the D34 reason: inline
 * annotations never carry `parent_symbol` (`parse-file.ts` populates it only
 * from `@source`), so no fixture drawn from guardlink itself can exercise the
 * rule at all. A test that cannot fail is not coverage.
 *
 * THE RULE UNDER TEST. A mitigation covers an exposure on the same (asset,
 * threat) UNLESS the two are in the same file, both carry a symbol anchor, and
 * those anchors differ. The negative cases matter as much as the positive one:
 * a rule that narrowed cross-file mitigations would report 6 of this repo's own
 * mitigations as absent, all 6 of them real (measured), and an alarm that cries
 * wolf gets ignored.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { findUnmitigatedExposures, coversExposure, buildCoverageIndex } from '../src/parser/coverage.js';
import { lookup } from '../src/mcp/lookup.js';
import { fileContext } from '../src/mcp/context.js';
import { diffModels } from '../src/diff/engine.js';
import type { ThreatModel } from '../src/types/index.js';

const DEFINITIONS = `
# @asset Svc.Db (#db) -- "Storage"
# @asset Svc.Api (#api) -- "Front door"
# @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input reaches the query"
# @control Parameterized_Queries (#prepared) -- "Bound parameters"
`.trimStart();

const SOURCE = `def find_expenses(user_id, category):
    return q("SELECT * FROM e WHERE c = '%s'" % category)


def insert_expense(user_id, amount):
    return q("INSERT INTO e VALUES (?, ?)", (user_id, amount))
`;

/** `gal` lines are written verbatim — this is external mode, so anchors exist. */
function buildRepo(gal: string, extra: Record<string, string> = {}): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-d36-'));
  mkdirSync(join(root, '.guardlink', 'annotations', 'app'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.py'), DEFINITIONS);
  mkdirSync(join(root, 'app'), { recursive: true });
  writeFileSync(join(root, 'app', 'db.py'), SOURCE);
  writeFileSync(join(root, '.guardlink', 'annotations', 'app', 'db.py.gal'), gal);
  for (const [path, body] of Object.entries(extra)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return root;
}

const roots: string[] = [];
const build = async (gal: string, extra?: Record<string, string>) => {
  const root = buildRepo(gal, extra);
  roots.push(root);
  const { model } = await parseProject({ root, project: 'd36' });
  return { root, model };
};

afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

// ── The defect, exactly as reported ──────────────────────────────────
const SPLIT_SYMBOLS = `@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] cwe:CWE-89 -- "category formatted into the SELECT"
@source file:app/db.py line:5 symbol:insert_expense
@mitigates #db against #sqli using #prepared -- "INSERT binds parameters"
`;

describe('D36 — same file, same asset, same threat, two symbols', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await build(SPLIT_SYMBOLS)); }, 60_000);

  it('the exposure on the vulnerable symbol is unmitigated', () => {
    const unmit = findUnmitigatedExposures(model);
    expect(unmit).toHaveLength(1);
    expect(unmit[0].location.parent_symbol).toBe('find_expenses');
    expect(unmit[0].severity).toBe('critical');
  });

  it('the mitigation on the safe symbol reports nothing spurious', () => {
    // The bound INSERT must not itself surface as a finding. The rule subtracts
    // coverage; it must never invent an exposure.
    expect(model.exposures).toHaveLength(1);
    expect(model.mitigations).toHaveLength(1);
    expect(findUnmitigatedExposures(model).every(e => e.location.parent_symbol === 'find_expenses')).toBe(true);
  });

  it('lookup("unmitigated") lists it', () => {
    const res = lookup(model, 'unmitigated') as { count: number; results: Array<{ asset: string; line: number }> };
    expect(res.count).toBe(1);
    expect(res.results[0].asset).toBe('#db');
  });

  it('the CWE bridge reports it open, not mitigated — the scanner path', () => {
    const res = lookup(model, 'cwe:CWE-89') as {
      results: Array<{ status: string; mitigated: boolean; controls: string[]; line: number }>;
      external_id: { declared: boolean; totals: Record<string, number> };
    };
    expect(res.external_id.declared).toBe(true);
    expect(res.external_id.totals.open).toBe(1);
    expect(res.external_id.totals.mitigated).toBe(0);
    expect(res.results[0].status).toBe('open');
    expect(res.results[0].mitigated).toBe(false);
    // And it must not credit a control that does not reach this site.
    expect(res.results[0].controls).toEqual([]);
  });

  it('guardlink_context reports it as an open exposure on the file', () => {
    const ctx = fileContext(model, { file: 'app/db.py', exists: true });
    expect(ctx.status).toBe('annotated');
    expect(ctx.open_exposures).toHaveLength(1);
  });

  it('"threats for #db" agrees with unmitigated', () => {
    const res = lookup(model, 'threats for #db') as { results: Array<{ mitigated: boolean }> };
    expect(res.results.every(r => !r.mitigated)).toBe(true);
  });
});

// ── The cases that must NOT change: no crying wolf ───────────────────
describe('D36 — coverage that must survive the rule', () => {
  it('a mitigation in a DIFFERENT FILE still covers', async () => {
    const { model } = await build(
      `@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "formatted"
`,
      {
        'app/mw.py': 'def scrub(x):\n    return x\n',
        '.guardlink/annotations/app/mw.py.gal':
          `@source file:app/mw.py line:1 symbol:scrub
@mitigates #db against #sqli using #prepared -- "input scrubbed at the boundary upstream of every query"
`,
      });
    // This is the trust-boundary filter case. Narrowing here would have flagged
    // 6 of this repo's own mitigations, all 6 genuine.
    expect(findUnmitigatedExposures(model)).toHaveLength(0);
  });

  it('a mitigation with NO symbol anchor covers the whole asset', async () => {
    const { model } = await build(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "formatted"
@source file:app/db.py line:5
@mitigates #db against #sqli using #prepared -- "asset-level statement, deliberately unanchored"
`);
    // This is how an author says "whole asset" — no new syntax was needed.
    expect(model.mitigations[0].location.parent_symbol).toBeFalsy();
    expect(findUnmitigatedExposures(model)).toHaveLength(0);
  });

  it('an exposure with no symbol anchor is covered by an anchored mitigation', async () => {
    const { model } = await build(`@source file:app/db.py line:1
@exposes #db to #sqli [critical] -- "unanchored exposure"
@source file:app/db.py line:5 symbol:insert_expense
@mitigates #db against #sqli using #prepared -- "anchored mitigation"
`);
    // Only one side anchored is no evidence that the author distinguished sites.
    expect(findUnmitigatedExposures(model)).toHaveLength(0);
  });

  it('same symbol, same file still covers', async () => {
    const { model } = await build(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "formatted"
@mitigates #db against #sqli using #prepared -- "fixed in place"
`);
    expect(findUnmitigatedExposures(model)).toHaveLength(0);
  });

  it('inline annotations are never narrowed — they carry no anchor at all', async () => {
    const root = mkdtempSync(join(tmpdir(), 'gl-d36-inline-'));
    roots.push(root);
    mkdirSync(join(root, '.guardlink'), { recursive: true });
    writeFileSync(join(root, '.guardlink', 'definitions.py'), DEFINITIONS);
    writeFileSync(join(root, 'svc.py'),
      '# @exposes #db to #sqli [critical] -- "formatted"\ndef a(): pass\n\n\n'
      + '# @mitigates #db against #sqli using #prepared -- "bound"\ndef b(): pass\n');
    const { model } = await parseProject({ root, project: 'd36-inline' });
    expect(model.exposures[0].location.parent_symbol).toBeFalsy();
    // The whole migration story rests on this: zero behaviour change inline.
    expect(findUnmitigatedExposures(model)).toHaveLength(0);
  });
});

// ── The rule is subtractive, and shared ──────────────────────────────
describe('D36 — properties of the predicate', () => {
  it('never adds coverage a pair match did not already grant', async () => {
    const { model } = await build(SPLIT_SYMBOLS);
    for (const e of model.exposures) {
      for (const m of model.mitigations) {
        if (coversExposure(m, e)) {
          expect(m.asset.replace(/^#/, '')).toBe(e.asset.replace(/^#/, ''));
          expect(m.threat.replace(/^#/, '')).toBe(e.threat.replace(/^#/, ''));
        }
      }
    }
  });

  it('normalises the leading # — diff and validate cannot disagree', async () => {
    const { model } = await build(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "hash form"
@mitigates db against sqli using #prepared -- "bare form for the same refs"
`);
    // diff/engine.ts and workspace/merge.ts used raw string equality here, so
    // they could report unmitigated where validate reported covered on one and
    // the same model.
    expect(findUnmitigatedExposures(model)).toHaveLength(0);
    expect(diffModels(model, model).summary.newUnmitigated).toBe(0);
  });

  it('resolves a dotted path to its #id — D47, fixed', async () => {
    const { model } = await build(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "hash form"
@mitigates Svc.Db against #sqli using #prepared -- "same asset, written as its dotted path"
`);
    // `Svc.Db` and `#db` are the same asset — the definitions file declares
    // `@asset Svc.Db (#db)`. `guardlink_graph` always resolved them to one node;
    // coverage did not, so two tools disagreed about one model.
    //
    // This assertion used to expect 1, pinning the gap on purpose: aliasing ADDS
    // coverage, the direction that hides vulnerabilities. It was fixed only
    // after measuring that it moves nothing anywhere real — 0 exposures change
    // state on expense-api, guardlink or specter-v1 — because the resolver is
    // built from DECLARED assets only. See the guard below.
    expect(findUnmitigatedExposures(model)).toHaveLength(0);
  });

  it('does NOT alias an UNDECLARED dotted path — the over-resolution guard', async () => {
    // The failure aliasing could introduce, and the reason D47 sat open: a
    // mitigation naming something that merely looks related must not answer for
    // a live exposure. `Other.Thing` is declared nowhere, so it resolves to
    // itself and covers nothing. Without this, the fix could silently mark real
    // vulnerabilities as handled — exactly what D36 exists to prevent.
    const { model } = await build(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "real, live exposure"
@source file:app/db.py line:5 symbol:insert_expense
@mitigates Other.Thing against #sqli using #prepared -- "a different, undeclared asset"
`);
    expect(findUnmitigatedExposures(model)).toHaveLength(1);
  });

  it('the diff risk delta is per SITE, so a half-fix is visible', async () => {
    const before = (await build(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "one"
@source file:app/db.py line:5 symbol:insert_expense
@exposes #db to #sqli [critical] -- "two"
`)).model;
    const after = (await build(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "one"
@source file:app/db.py line:5 symbol:insert_expense
@exposes #db to #sqli [critical] -- "two"
@mitigates #db against #sqli using #prepared -- "only the INSERT was fixed"
`)).model;
    // Pair-keyed, both exposures collapse to one key and this reads as no
    // change. Site-keyed, exactly one is resolved and one remains.
    expect(findUnmitigatedExposures(before)).toHaveLength(2);
    expect(findUnmitigatedExposures(after)).toHaveLength(1);
    const d = diffModels(before, after);
    expect(d.summary.resolvedUnmitigated).toBe(1);
    expect(d.summary.riskDelta).toBe('decreased');
  });

  it('the index and the predicate agree', async () => {
    const { model } = await build(SPLIT_SYMBOLS);
    const index = buildCoverageIndex(model);
    for (const e of model.exposures) {
      expect(index.isMitigated(e)).toBe(model.mitigations.some(m => coversExposure(m, e)));
    }
  });
});
