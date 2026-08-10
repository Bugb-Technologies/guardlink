/**
 * D39 / D51 — the write path must not write things that are not true.
 *
 * One defect wearing two hats: `guardlink_annotate_apply` promised "malformed
 * input is rejected with the reason" and then accepted both an invented
 * reference and a source file that does not exist, each with
 * `ok: true, errors: []`.
 *
 *   D39  `@mitigates #api against #xss-by-render using #octet-stream` — neither
 *        id declared anywhere — was written. `validate` warned later, exit 0, so
 *        the invented reference survived the write path, the validate path and
 *        CI.
 *   D51  a sidecar for `app/typo_in_filename.py` was written and its annotations
 *        entered the model: exposures 11 → 12, including a phantom critical.
 *        `validate` then reported "Validation passed". The path check already
 *        existed and was wired to `guardlink_context`, the tool that cannot
 *        cause harm.
 *
 * Both produce a threat model that is confidently wrong and stays wrong, which
 * is why they were fixed while D40 and D41 — whose output a caller can see is
 * wrong — were left open.
 *
 * The reference rule is deliberately the SAME rule `findDanglingRefs` uses:
 * `#`-prefixed refs only. Two validators that disagree about what a valid
 * reference is would be its own defect.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyAnnotations } from '../src/parser/apply-annotations.js';

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

const DECLARED = new Set(['api', 'sqli', 'prepared']);

function repo(): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-d39-'));
  roots.push(root);
  mkdirSync(join(root, 'app'), { recursive: true });
  writeFileSync(join(root, 'app', 'main.py'), 'def handler():\n    pass\n');
  return root;
}

const apply = (root: string, over: Record<string, unknown> = {}) => applyAnnotations({
  root,
  file: 'app/main.py',
  line: 1,
  symbol: 'handler',
  annotations: ['@exposes #api to #sqli [critical] -- "concatenated"'],
  declaredIds: DECLARED,
  ...over,
});

describe('D39 — an undeclared reference is rejected, with the reason', () => {
  it('rejects an invented threat and control, naming both', () => {
    const root = repo();
    const r = apply(root, {
      annotations: ['@mitigates #api against #totally-invented using #whatever -- "x"'],
    });
    expect(r.ok).toBe(false);
    expect(r.status).toBe('rejected');
    expect(r.linesWritten).toBe(0);
    expect(r.errors.join(' ')).toContain('#totally-invented');
    expect(r.errors.join(' ')).toContain('#whatever');
    // The reason must point at the fix, not merely state the problem.
    expect(r.errors.join(' ')).toContain('definitions');
    expect(existsSync(join(root, '.guardlink/annotations/app/main.py.gal'))).toBe(false);
  });

  it('accepts references that ARE declared', () => {
    const r = apply(repo());
    expect(r.ok).toBe(true);
    expect(r.status).toBe('written');
    expect(r.warnings).toBeUndefined();
  });

  it('writes a deliberate forward reference, and says so in warnings', () => {
    const root = repo();
    const r = apply(root, {
      annotations: ['@exposes #api to #future-threat [medium] -- "definition is coming"'],
      allowUndeclaredRefs: true,
    });
    expect(r.ok).toBe(true);
    expect(r.status).toBe('written');
    expect(r.warnings?.join(' ')).toContain('#future-threat');
    // The caller must be told what will happen next, not just that it wrote.
    expect(r.warnings?.join(' ')).toContain('dangling');
  });

  it('skips reference checking when the caller has no model', () => {
    // A caller with no parsed model gets the pre-D39 behaviour rather than a
    // wall of false rejections.
    const r = apply(repo(), {
      annotations: ['@exposes #api to #anything [low] -- "no declaredIds passed"'],
      declaredIds: undefined,
    });
    expect(r.ok).toBe(true);
  });

  it('does not treat a cwe: external id as a model reference', () => {
    const r = apply(repo(), {
      annotations: ['@exposes #api to #sqli [critical] cwe:CWE-89 -- "external id, not a ref"'],
    });
    expect(r.ok).toBe(true);
  });
});

describe('D51 — a sidecar for a file that does not exist is rejected', () => {
  it('rejects the missing source file and writes nothing', () => {
    const root = repo();
    const r = apply(root, { file: 'app/typo_in_filename.py' });
    expect(r.ok).toBe(false);
    expect(r.status).toBe('rejected');
    expect(r.errors.join(' ')).toContain('does not exist');
    expect(existsSync(join(root, '.guardlink/annotations/app/typo_in_filename.py.gal'))).toBe(false);
  });

  it('still rejects a path escaping the root, and says which problem it is', () => {
    const r = apply(repo(), { file: '../outside.py' });
    expect(r.ok).toBe(false);
    expect(r.errors.join(' ')).toContain('outside the project root');
  });

  it('a file that exists is written as before', () => {
    const root = repo();
    const r = apply(root);
    expect(r.ok).toBe(true);
    expect(existsSync(join(root, '.guardlink/annotations/app/main.py.gal'))).toBe(true);
  });
});
