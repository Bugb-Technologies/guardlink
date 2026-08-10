/**
 * D48 — the anchoring needs its own hash, because annotation_hash cannot see it.
 *
 * `guardlink migrate --to inline --to external` on a repo born external returned
 * the model to its starting `annotation_hash` and printed `✓ annotation_hash
 * unchanged` both ways. It was telling the truth. It was also destroying every
 * symbol anchor in the repo — 21 of 21 on the expense-api corpus — because
 * inline mode has nowhere to keep one and `serialiseGal` correctly refuses to
 * invent one on the way back.
 *
 * The hash was blind by design. GL-101 excludes `parent_symbol` so that inline
 * and external authoring of the same model hash identically, and that equality
 * is GL-507's migration gate. The exclusion is right; the gap it left is the
 * defect. Two hashes, two questions — see parser/annotation-hash.ts.
 *
 * These tests pin BOTH halves. The blindness is a property to preserve, not a
 * bug to fix, so it is asserted here rather than left implicit: a future change
 * that "helpfully" folds anchors into `annotation_hash` would break GL-507 and
 * should fail here first.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import {
  computeAnnotationHash, computeAnchorHash, countAnchors, lostAnchors,
  canonicalAnchorRecords,
} from '../src/parser/annotation-hash.js';

const DEFINITIONS = `
# @asset Svc.Db (#db) -- "Storage"
# @threat SQL_Injection (#sqli) [critical] -- "Untrusted input reaches the query"
# @control Parameterized_Queries (#prepared) -- "Bound parameters"
`.trimStart();

const SOURCE = `def find_expenses(user_id):
    return q("SELECT %s" % user_id)


def insert_expense(user_id):
    return q("INSERT ?", (user_id,))
`;

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

/** External mode — `.gal` sidecars, so `symbol:` anchors exist. */
async function external(gal: string) {
  const root = mkdtempSync(join(tmpdir(), 'gl-d48-ext-'));
  roots.push(root);
  mkdirSync(join(root, '.guardlink', 'annotations', 'app'), { recursive: true });
  mkdirSync(join(root, 'app'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.py'), DEFINITIONS);
  writeFileSync(join(root, 'app', 'db.py'), SOURCE);
  writeFileSync(join(root, '.guardlink', 'annotations', 'app', 'db.py.gal'), gal);
  const { model } = await parseProject({ root, project: 'd48' });
  return model;
}

/** Inline mode — the same claims, in source comments, with no anchors anywhere. */
async function inline(body: string) {
  const root = mkdtempSync(join(tmpdir(), 'gl-d48-inl-'));
  roots.push(root);
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  mkdirSync(join(root, 'app'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.py'), DEFINITIONS);
  writeFileSync(join(root, 'app', 'db.py'), body);
  const { model } = await parseProject({ root, project: 'd48' });
  return model;
}

const ANCHORED = `@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "formatted into the SELECT"
@source file:app/db.py line:5 symbol:insert_expense
@mitigates #db against #sqli using #prepared -- "binds parameters"
`;

/** The same two claims with the anchors stripped — what a round trip leaves. */
const UNANCHORED = `@source file:app/db.py line:1
@exposes #db to #sqli [critical] -- "formatted into the SELECT"
@source file:app/db.py line:5
@mitigates #db against #sqli using #prepared -- "binds parameters"
`;

describe('D48 — annotation_hash is blind to anchors, and that is deliberate', () => {
  it('stripping every symbol anchor does NOT move annotation_hash', async () => {
    const withAnchors = await external(ANCHORED);
    const without = await external(UNANCHORED);

    // This is the defect's mechanism, asserted so it cannot be "fixed" by
    // accident: the hash that certifies a migration cannot see this loss.
    expect(computeAnnotationHash(without)).toBe(computeAnnotationHash(withAnchors));
    expect(countAnchors(withAnchors)).toBe(2);
    expect(countAnchors(without)).toBe(0);
  });

  it('GL-101 still holds — inline and external authoring hash identically', async () => {
    // The reason parent_symbol is excluded. If this breaks, GL-507's migration
    // correctness gate breaks with it.
    const ext = await external(UNANCHORED);
    const inl = await inline(`# @exposes #db to #sqli [critical] -- "formatted into the SELECT"
def find_expenses(user_id):
    return q("SELECT %s" % user_id)


# @mitigates #db against #sqli using #prepared -- "binds parameters"
def insert_expense(user_id):
    return q("INSERT ?", (user_id,))
`);
    expect(computeAnnotationHash(inl)).toBe(computeAnnotationHash(ext));
  });
});

describe('D48 — anchor_hash sees exactly what annotation_hash does not', () => {
  it('moves when anchors are stripped', async () => {
    const withAnchors = await external(ANCHORED);
    const without = await external(UNANCHORED);
    expect(computeAnchorHash(without)).not.toBe(computeAnchorHash(withAnchors));
  });

  it('names the anchors that were lost, not just the count', async () => {
    const before = await external(ANCHORED);
    const after = await external(UNANCHORED);
    expect(lostAnchors(before, after).sort()).toEqual([
      'app/db.py:find_expenses',
      'app/db.py:insert_expense',
    ]);
  });

  it('reports no loss when nothing was lost', async () => {
    const a = await external(ANCHORED);
    const b = await external(ANCHORED);
    expect(lostAnchors(a, b)).toEqual([]);
    expect(computeAnchorHash(a)).toBe(computeAnchorHash(b));
  });

  it('counts SITES, not annotations — five claims at one anchor is one anchor', async () => {
    // Counting per-annotation would have reported expense-api's 21 `symbol:`
    // headers as 105 anchors, and would make a D41 duplicate header read as a
    // second anchor rather than a duplicate.
    const model = await external(`@source file:app/db.py line:1 symbol:find_expenses
@exposes #db to #sqli [critical] -- "one"
@audit #db -- "two"
@comment -- "three"
@comment -- "four"
@comment -- "five"
`);
    expect(model.annotations_parsed).toBeGreaterThanOrEqual(5);
    expect(countAnchors(model)).toBe(1);
    expect(canonicalAnchorRecords(model)).toHaveLength(1);
  });

  it('an inline repo has no anchors, so its anchor hash is the empty-set hash', async () => {
    const inl = await inline(`# @exposes #db to #sqli [critical] -- "x"
def find_expenses(u):
    return u
`);
    const empty = await external('');
    expect(countAnchors(inl)).toBe(0);
    expect(computeAnchorHash(inl)).toBe(computeAnchorHash(empty));
  });
});
