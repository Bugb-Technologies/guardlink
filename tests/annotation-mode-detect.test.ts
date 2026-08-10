/**
 * D37 — a pure-external repo is `external`, not `mixed`.
 *
 * `@asset`, `@threat` and `@control` are structurally inline-only: they live in
 * `.guardlink/definitions.*`, and there is no `@source` block for "this asset
 * exists", so a declaration can never acquire an `origin_file`. Counting them as
 * inline evidence made every correctly-configured external repo report `mixed` —
 * the alarm state, meaning mid-migration — on the correct configuration.
 * Measured on /tmp/expense-api before the fix: inline 21, external 84, and all
 * 21 inline were the definitions file.
 *
 * Under the external default that is every new project, which is exactly how an
 * alarm gets trained out of people.
 *
 * The load-bearing pair here is the last two tests: `external` must become
 * reachable WITHOUT `mixed` becoming unreachable. Fixing this by never returning
 * mixed would replace a false alarm with a missing one.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { detectAnnotationMode } from '../src/parser/annotation-mode.js';
import { buildEnvelope } from '../src/mcp/freshness.js';

const DEFINITIONS = `
# @asset Svc.Api (#api) -- "Front door"
# @asset Svc.Db (#db) -- "Storage"
# @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Injection"
# @control Parameterized_Queries (#prepared) -- "Bound parameters"
`.trimStart();

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

/** `inlineBody` goes into a source comment; `gal` goes into a sidecar. */
async function repo(opts: { inline?: string; gal?: string; definitions?: boolean }) {
  const root = mkdtempSync(join(tmpdir(), 'gl-d37-'));
  roots.push(root);
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  if (opts.definitions !== false) {
    writeFileSync(join(root, '.guardlink', 'definitions.py'), DEFINITIONS);
  }
  mkdirSync(join(root, 'app'), { recursive: true });
  writeFileSync(join(root, 'app', 'svc.py'),
    (opts.inline ? `${opts.inline}\n` : '') + 'def handler():\n    pass\n');
  if (opts.gal) {
    mkdirSync(join(root, '.guardlink', 'annotations', 'app'), { recursive: true });
    writeFileSync(join(root, '.guardlink', 'annotations', 'app', 'svc.py.gal'), opts.gal);
  }
  const { model } = await parseProject({ root, project: 'd37' });
  return { root, model };
}

const GAL = `@source file:app/svc.py line:1 symbol:handler
@exposes #api to #sqli [high] -- "external annotation"
@flows #api -> #db via query -- "external annotation"
`;
const INLINE = '# @exposes #api to #sqli [high] -- "inline annotation"';

describe('D37 — definitions are not evidence about storage mode', () => {
  it('a pure-external repo reports external, not mixed', async () => {
    const { model } = await repo({ gal: GAL });
    const report = detectAnnotationMode(model);
    expect(report.mode).toBe('external');
    // The definitions are still parsed — they are just not counted as evidence.
    expect(model.assets).toHaveLength(2);
    expect(report.inline).toBe(0);
    expect(report.external).toBeGreaterThan(0);
  });

  it('the MCP envelope agrees — it is what an agent reads to decide where to write', async () => {
    const { root, model } = await repo({ gal: GAL });
    expect(buildEnvelope(root, model).mode).toBe('external');
  });

  it('a pure-inline repo still reports inline', async () => {
    const { model } = await repo({ inline: INLINE });
    expect(detectAnnotationMode(model).mode).toBe('inline');
  });

  it('a genuinely mixed repo still reports mixed', async () => {
    // One relationship annotation in a source comment, another in a sidecar.
    // This is the state `mixed` exists to name, and it must stay reachable.
    const { model } = await repo({ inline: INLINE, gal: GAL });
    const report = detectAnnotationMode(model);
    expect(report.mode).toBe('mixed');
    expect(report.inline).toBeGreaterThan(0);
    expect(report.external).toBeGreaterThan(0);
  });

  it('definitions alone are not enough to call it either way', async () => {
    // Declared a vocabulary, stored no annotations anywhere yet. Reports the
    // empty-model answer with both counts at zero, so a consumer can tell
    // "inferred from nothing" from "inline, measured" — which is the whole
    // reason the counts are returned alongside the mode.
    const { model } = await repo({});
    const report = detectAnnotationMode(model);
    expect(report.inline).toBe(0);
    expect(report.external).toBe(0);
    expect(model.assets.length).toBeGreaterThan(0);
  });

  it('a definitions file does not flip an otherwise-external repo', async () => {
    const withDefs = await repo({ gal: GAL });
    const withoutDefs = await repo({ gal: GAL, definitions: false });
    // The presence of the vocabulary must not change the answer at all.
    expect(detectAnnotationMode(withDefs.model).mode)
      .toBe(detectAnnotationMode(withoutDefs.model).mode);
  });
});
