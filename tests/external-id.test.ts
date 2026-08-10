/**
 * GL-204 — external identifier queries. The scanner bridge.
 *
 * The distinction this whole story turns on: "we have never heard of this
 * weakness class" and "we declare it and nothing is exposed" both produce
 * `count: 0`, and a scanner must be able to tell them apart. One means its
 * finding is new information; the other means the finding is already known and
 * the model says nothing is affected. `external_id.declared` is the field that
 * separates them, and most of this file exists to pin it.
 *
 * D20: `model.external_refs` (cross-repo sibling tags) and `threat.external_refs`
 * (cwe:/owasp:) share a name and nothing else. Both query forms are exercised
 * here against the same model so a regression that crosses them fails loudly.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { lookup, parseExternalId, SUPPORTED_QUERY_FORMS } from '../src/mcp/lookup.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('parseExternalId', () => {
  it('accepts scheme-prefixed and bare identifiers', () => {
    expect(parseExternalId('cwe:CWE-89')).toMatchObject({ scheme: 'cwe', normalized: 'cwe-89' });
    expect(parseExternalId('CWE-89')).toMatchObject({ scheme: null, normalized: 'cwe-89' });
    expect(parseExternalId('owasp:A03')).toMatchObject({ scheme: 'owasp', normalized: 'a03' });
    expect(parseExternalId('CVE-2021-44228')).toMatchObject({ scheme: null, normalized: 'cve-2021-44228' });
  });

  it('is case-insensitive on scheme and identifier', () => {
    expect(parseExternalId('cwe:cwe-89')!.normalized).toBe('cwe-89');
    expect(parseExternalId('CWE:CWE-89')!.normalized).toBe('cwe-89');
    expect(parseExternalId('cwe-89')!.normalized).toBe('cwe-89');
  });

  it('does NOT claim bare OWASP category codes', () => {
    // `A03` is three alphanumerics that could as easily be an asset id.
    // Reinterpreting it as an OWASP category would be a guess.
    expect(parseExternalId('A03')).toBeNull();
    expect(parseExternalId('owasp:A03')).not.toBeNull();
  });

  it('does not swallow ordinary refs or unknown schemes', () => {
    expect(parseExternalId('#cli')).toBeNull();
    expect(parseExternalId('path-traversal')).toBeNull();
    expect(parseExternalId('asset cli')).toBeNull();
    expect(parseExternalId('http://example.com')).toBeNull();
  });
});

describe('GL-204 — against the live repo', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  it('precondition: threats really do carry cwe: identifiers', () => {
    const withRefs = model.threats.filter(t => (t.external_refs || []).length > 0);
    expect(withRefs.length).toBeGreaterThan(10);
    expect(model.threats.find(t => t.id === 'path-traversal')?.external_refs).toContain('cwe:CWE-22');
  });

  it('a declared CWE with mitigated sites partitions them', () => {
    const r = lookup(model, 'cwe:CWE-22');           // #path-traversal
    expect(r.type).toBe('external_id');
    expect(r.external_id?.declared).toBe(true);
    expect(r.external_id?.threats.map(t => t.id)).toContain('path-traversal');
    expect(r.count).toBeGreaterThan(0);
    const sum = r.external_id!.totals;
    expect(sum.confirmed + sum.accepted + sum.mitigated + sum.open).toBe(r.count);
    expect(sum.mitigated).toBeGreaterThan(0);
    for (const site of r.results) {
      expect(['confirmed', 'accepted', 'mitigated', 'open']).toContain(site.status);
    }
  });

  it('a declared CWE with open sites reports them as open', () => {
    const r = lookup(model, 'cwe:CWE-400');          // #dos
    expect(r.external_id?.declared).toBe(true);
    expect(r.external_id!.totals.open).toBeGreaterThan(0);
    const open = r.results.filter((s: any) => s.status === 'open');
    for (const s of open) {
      expect(s.mitigated).toBe(false);
      expect(s.accepted).toBe(false);
      expect(s.controls).toEqual([]);
    }
  });

  it('an UNDECLARED CWE is explicitly not-declared, not merely empty', () => {
    // The single most important distinction in this story. CWE-89 (SQLi) is not
    // in this model at all.
    const r = lookup(model, 'cwe:CWE-89');
    expect(r.external_id?.declared).toBe(false);
    expect(r.external_id?.threats).toEqual([]);
    expect(r.count).toBe(0);
    expect(r.hint).toMatch(/no declared knowledge/i);
    expect(r.hint).toMatch(/NOT the same/);
  });

  it('declared-with-no-sites is distinguishable from never-heard-of-it', () => {
    // Same count: 0, opposite meanings. `declared` is what separates them.
    const stripped: ThreatModel = { ...model, exposures: [], confirmed: [] };
    const declaredButQuiet = lookup(stripped, 'cwe:CWE-22');
    const neverHeardOf = lookup(stripped, 'cwe:CWE-89');

    expect(declaredButQuiet.count).toBe(0);
    expect(neverHeardOf.count).toBe(0);
    expect(declaredButQuiet.external_id?.declared).toBe(true);
    expect(neverHeardOf.external_id?.declared).toBe(false);
    expect(declaredButQuiet.external_id?.threats.length).toBeGreaterThan(0);
    expect(declaredButQuiet.hint).toBeUndefined();
    expect(neverHeardOf.hint).toBeDefined();
  });

  it('scheme-prefixed, bare and mixed-case forms give the same answer', () => {
    const forms = ['cwe:CWE-22', 'CWE-22', 'cwe:cwe-22', 'CWE:CWE-22', 'cwe-22'];
    const answers = forms.map(f => lookup(model, f));
    for (const a of answers) {
      expect(a.count, JSON.stringify(a.query)).toBe(answers[0].count);
      expect(a.external_id?.declared).toBe(true);
      expect(a.external_id?.normalized).toBe('cwe-22');
    }
    expect(answers.map(a => JSON.stringify(a.results))).toEqual(
      answers.map(() => JSON.stringify(answers[0].results)),
    );
  });

  it('one CWE mapping to several threats returns all of them', () => {
    // CWE-78 is declared on both #cmd-injection and #child-proc-injection.
    const r = lookup(model, 'CWE-78');
    const ids = r.external_id!.threats.map(t => t.id).sort();
    expect(ids.length).toBeGreaterThan(1);
    expect(ids).toContain('cmd-injection');
    expect(ids).toContain('child-proc-injection');
  });

  it('sites carry location, and controls where mitigated', () => {
    const r = lookup(model, 'cwe:CWE-22');
    for (const s of r.results) {
      expect(s.file).toBeDefined();
      expect(typeof s.line).toBe('number');
      if (s.status === 'mitigated') expect(s.controls.length).toBeGreaterThan(0);
    }
  });

  it('an identifier query never falls through to fuzzy matching', () => {
    for (const q of ['cwe:CWE-89', 'CWE-9999', 'owasp:A03', 'cve:CVE-2021-44228']) {
      const r = lookup(model, q);
      expect(r.type, q).toBe('external_id');
      expect(r.type, q).not.toBe('mixed');
      expect(r.type, q).not.toBe('no_match');
    }
  });
});

describe('D20 — the two things called external refs', () => {
  let model: ThreatModel;
  beforeAll(async () => { ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' })); });

  it('cross-repo refs and cwe: queries reach different data', () => {
    const crossRepo = lookup(model, 'cross-repo refs');
    const cwe = lookup(model, 'cwe:CWE-22');
    expect(crossRepo.type).toBe('external_refs');
    expect(cwe.type).toBe('external_id');
    // This repo has no workspace config, so cross-repo is empty while cwe is not.
    expect(crossRepo.count).toBe(0);
    expect(cwe.count).toBeGreaterThan(0);
  });

  it('the cross-repo form explains that it is not the cwe: one', () => {
    const listed = SUPPORTED_QUERY_FORMS.join('\n');
    expect(listed).toMatch(/cross-repo refs.*NOT cwe:/);
    expect(listed).toMatch(/cwe:CWE-89.*scanner bridge/);
  });

  it('the empty cross-repo answer says why it is empty', () => {
    const r = lookup(model, 'cross-repo refs');
    expect((r as any).hint).toMatch(/workspace\.yaml/);
  });

  it('the bare `refs` alias no longer resolves to cross-repo tags', () => {
    // It was too grabby: a caller thinking of CWE identifiers would have been
    // handed sibling-repo tags and an empty list — D20 reachable in one word.
    const r = lookup(model, 'refs');
    expect(r.type).not.toBe('external_refs');
  });

  it('`external refs` still works as an alias for the renamed form', () => {
    expect(lookup(model, 'external refs').type).toBe('external_refs');
  });
});
