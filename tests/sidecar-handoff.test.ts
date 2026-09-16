/**
 * A `.gal` sidecar is read by GuardLink and by nothing else.
 *
 * ── The measurement this file pins ──────────────────────────────────
 *
 * `guardlink init` defaults a new project to `annotation_mode: "external"` and
 * its own last line of output says to write annotations in
 * `.guardlink/annotations/<source path>.gal` — "NOT in source files". Measured
 * on a fresh repository on 2026-09-16, with the same two `@exposes` and one
 * `@accepts`:
 *
 *     in the sidecar `init` recommends  ->  exposures 0, acceptances 0
 *     the identical lines inline        ->  exposures 2, acceptances 1
 *
 * — as seen by the consuming code graph, whose facet reported itself *present*
 * for both. A repository annotated exactly as its own tool instructed rendered
 * a green, empty dashboard, and nothing anywhere said the data had been
 * dropped.
 *
 * ── Where the data actually dies, and why these tests are here ──────
 *
 * Not in GuardLink's sidecar parser: `validate` and `status` have always
 * reported every annotation in a `.gal`. Consumers do not run that parser. They
 * look for a JSON export and, finding none, fall back to scraping inline source
 * comments themselves — `bravos-codegraph`'s `find_and_parse_report`
 * (crates/bravos-codegraph/src/guardlink.rs:557) tries five report paths and
 * then hands off to `guardlink_inline::try_parse_inline`, which walks source
 * extensions only. Inline annotations survive that fallback. A `.gal` cannot:
 * `gal` is in neither `DEFAULT_INCLUDE_EXTS` nor any `include` glob `guardlink
 * init` writes.
 *
 * So external mode has a step inline mode does not, and until this file nothing
 * in GuardLink said so:
 *
 *     guardlink parse . -o .guardlink/report.json
 *
 * The first group below is the failing-first test: sidecar annotations, no
 * export, and the check that now names it. The second proves the inline path is
 * untouched — it must stay `not-needed`, because a warning that fires on a
 * correctly annotated inline repository is the alarm being trained out of
 * people. The third is the other half of the brief: a sidecar that yields
 * nothing still yields nothing after the fix, and now says which kind of
 * nothing it is.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { checkHandoff, HANDOFF_PATH, HANDOFF_COMMAND } from '../src/parser/handoff.js';
import { populateMetadata } from '../src/workspace/metadata.js';
import type { ParseDiagnostic } from '../src/types/index.js';

const DEFINITIONS = `
// @asset App.API (#api) -- "Allocation endpoint"
// @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Unsanitized input reaches SQL"
// @threat Broken_Access_Control (#bac) [high] cwe:CWE-284 -- "Missing authorization"
`.trimStart();

/** The two exposures and one acceptance from the measurement, as raw GAL. */
const RELATIONS = [
  '@exposes App.API to #sqli [critical] cwe:CWE-89 -- "userId concatenated into SQL"',
  '@exposes App.API to #bac [high] cwe:CWE-284 -- "no ownership check on allocations"',
  '@accepts #bac on App.API by "Ada Lovelace" until 2099-01-01 -- "internal-only endpoint, reviewed"',
];

const SOURCE = 'function allocate(req) {\n  return db.query("SELECT * FROM a WHERE u = " + req.body.userId);\n}\n';

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

/**
 * A repository annotated one way or the other.
 *
 * `sidecar` writes RELATIONS to the exact path `guardlink init` recommends;
 * `inline` writes the same three lines into the source file's doc-block. Same
 * annotations, same definitions, same source — only the placement differs,
 * which is the whole measurement.
 */
function repo(placement: 'sidecar' | 'inline' | 'none', galBody?: string): string {
  const root = mkdtempSync(join(tmpdir(), 'gl-handoff-'));
  roots.push(root);
  mkdirSync(join(root, '.guardlink'), { recursive: true });
  writeFileSync(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  mkdirSync(join(root, 'src'), { recursive: true });

  const docBlock = placement === 'inline'
    ? `/**\n${RELATIONS.map(r => ` * ${r}`).join('\n')}\n */\n`
    : '';
  writeFileSync(join(root, 'src', 'allocations.js'), docBlock + SOURCE);

  if (placement === 'sidecar' || galBody !== undefined) {
    mkdirSync(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    writeFileSync(
      join(root, '.guardlink', 'annotations', 'src', 'allocations.js.gal'),
      galBody ?? `@source file:src/allocations.js line:1\n\n${RELATIONS.join('\n')}\n`,
    );
  }
  return root;
}

/** Write the export the way `guardlink parse -o` does, stamp included. */
async function exportModel(root: string): Promise<void> {
  const { model, diagnostics } = await parseProject({ root, project: 'repro' });
  const stamped = populateMetadata(model, root, diagnostics);
  writeFileSync(join(root, HANDOFF_PATH), JSON.stringify(stamped, null, 2) + '\n');
}

const codes = (ds: ParseDiagnostic[]): string[] => ds.map(d => d.code ?? '(none)').sort();

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');

/**
 * The real CLI, stdout and stderr together — the surface a developer reads.
 *
 * Both streams, always: `validate` writes its findings to stderr and exits 0 on
 * a clean model, so a stdout-only capture reads an all-clear run as silence.
 */
function guardlink(...args: string[]): string {
  const r = spawnSync('npx', ['tsx', cli, ...args], {
    cwd: repoRoot, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'],
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

describe('sidecar annotations, and whether they leave the repository', () => {
  it('GuardLink itself reads the sidecar — the defect was never in this parser', async () => {
    const { model } = await parseProject({ root: repo('sidecar'), project: 'repro' });
    expect(model.exposures).toHaveLength(2);
    expect(model.acceptances).toHaveLength(1);
  });

  it('says, by name, that nothing downstream reads them when no export exists', async () => {
    const root = repo('sidecar');
    const { model } = await parseProject({ root, project: 'repro' });

    const handoff = checkHandoff(root, model);
    expect(handoff.verdict).toBe('missing');
    expect(handoff.external).toBe(3);
    expect(handoff.inline).toBe(0);
    // The three things a reader needs: that consumers see zero, which file is
    // absent, and the one command that fixes it. Before this check the answer
    // to all three was silence.
    expect(handoff.message).toContain('zero exposures and zero acceptances');
    expect(handoff.message).toContain(HANDOFF_PATH);
    expect(handoff.message).toContain(HANDOFF_COMMAND);
  });

  it('goes quiet once the export exists and matches', async () => {
    const root = repo('sidecar');
    await exportModel(root);
    const { model } = await parseProject({ root, project: 'repro' });

    const handoff = checkHandoff(root, model);
    expect(handoff.verdict).toBe('current');
    expect(handoff.message).toBeNull();
    expect(handoff.exportedHash).toBe(handoff.currentHash);
  });

  it('carries the sidecar annotations into the export, in the shape consumers deserialize', async () => {
    const root = repo('sidecar');
    await exportModel(root);
    const exported = JSON.parse(readFileSync(join(root, HANDOFF_PATH), 'utf-8'));

    // This is the assertion that closes the loop the measurement opened: the
    // file consumers read is not empty for a sidecar-only repository, and it
    // carries exactly the field names they bind to — GLExposure and
    // GLAcceptance in crates/bravos-codegraph/src/guardlink.rs:294 and :422.
    // Serde ignores unknown fields, so a renamed key here is a silent zero
    // there, which is the same failure one layer down.
    expect(exported.exposures).toHaveLength(2);
    expect(exported.acceptances).toHaveLength(1);
    for (const e of exported.exposures) {
      expect(Object.keys(e).sort()).toEqual(
        ['asset', 'description', 'external_refs', 'location', 'severity', 'threat']);
      // `location.file` is the SOURCE file, not the sidecar. A consumer binding
      // a finding to `.guardlink/annotations/...` would anchor every external
      // annotation to a file with no code in it.
      expect(e.location.file).toBe('src/allocations.js');
      expect(e.location.origin_file).toBe('.guardlink/annotations/src/allocations.js.gal');
    }
    const [accepted] = exported.acceptances;
    expect(accepted.asset).toBe('App.API');
    expect(accepted.threat).toBe('#bac');
    expect(accepted.accepted_by).toBe('Ada Lovelace');
    expect(accepted.expires).toBe('2099-01-01');
  });

  it('reports stale and unverifiable as different answers, because they are', async () => {
    const root = repo('sidecar');
    await exportModel(root);

    // Stale: a real stamp that no longer matches. The annotations moved; the
    // export did not, and consumers are reading the older model.
    const exported = JSON.parse(readFileSync(join(root, HANDOFF_PATH), 'utf-8'));
    exported.metadata.annotation_hash = 'sha256-v3:0000000000000000';
    writeFileSync(join(root, HANDOFF_PATH), JSON.stringify(exported));
    const { model } = await parseProject({ root, project: 'repro' });
    expect(checkHandoff(root, model).verdict).toBe('stale');

    // Unverifiable: no stamp at all. Current and stale are both guesses here,
    // and the codebase's posture is that unknown is a legitimate verdict.
    delete exported.metadata;
    writeFileSync(join(root, HANDOFF_PATH), JSON.stringify(exported));
    expect(checkHandoff(root, model).verdict).toBe('unverifiable');
    expect(checkHandoff(root, model).message).toContain('unknown');
  });
});

describe('the inline path is unchanged', () => {
  it('parses to the same model the sidecar does', async () => {
    const inline = await parseProject({ root: repo('inline'), project: 'repro' });
    const sidecar = await parseProject({ root: repo('sidecar'), project: 'repro' });
    expect(inline.model.exposures).toHaveLength(2);
    expect(inline.model.acceptances).toHaveLength(1);
    expect(sidecar.model.exposures.map(e => `${e.asset}/${e.threat}`))
      .toEqual(inline.model.exposures.map(e => `${e.asset}/${e.threat}`));
  });

  it('needs no export, and is told so by saying nothing', async () => {
    const root = repo('inline');
    const { model } = await parseProject({ root, project: 'repro' });

    const handoff = checkHandoff(root, model);
    // `not-needed`, not `missing`: an inline annotation survives a consumer's
    // fallback on its own, so there is nothing an export would rescue. A
    // warning here would fire on every correctly annotated inline repository,
    // which is how an alarm stops being read.
    expect(handoff.verdict).toBe('not-needed');
    expect(handoff.message).toBeNull();
    expect(handoff.external).toBe(0);
  });

  it('adds no diagnostic to a repository with no sidecars at all', async () => {
    const { diagnostics } = await parseProject({ root: repo('inline'), project: 'repro' });
    expect(codes(diagnostics)).not.toContain('empty-gal');
    expect(codes(diagnostics)).not.toContain('unrecognised-gal');
    expect(codes(diagnostics)).not.toContain('missing-gal-source');
  });
});

describe('a sidecar that yields nothing says which kind of nothing', () => {
  it('an empty sidecar is reported, not silently counted as a clean repository', async () => {
    const root = repo('none', '');
    const { model, diagnostics } = await parseProject({ root, project: 'repro' });

    // Still nothing, after the fix. That is correct: an empty file holds no
    // annotations and inventing some would be worse. What changed is that the
    // zero is now explained.
    expect(model.exposures).toHaveLength(0);
    expect(codes(diagnostics)).toContain('empty-gal');
    const diag = diagnostics.find(d => d.code === 'empty-gal')!;
    expect(diag.level).toBe('warning');
    expect(diag.message).toContain('src/allocations.js');
  });

  it('a sidecar of prose is a different message from an empty one', async () => {
    const root = repo('none', 'Notes: we should probably lock this endpoint down.\n');
    const { model, diagnostics } = await parseProject({ root, project: 'repro' });

    expect(model.exposures).toHaveLength(0);
    expect(codes(diagnostics)).toContain('unrecognised-gal');
    expect(codes(diagnostics)).not.toContain('empty-gal');
  });

  it('leaves a verb-shaped failure to the precise diagnostic that already names the line', async () => {
    const root = repo('none',
      '@source file:src/allocations.js line:1\n@exposs App.API to #sqli -- "typo"\n');
    const { diagnostics } = await parseProject({ root, project: 'repro' });

    // `unknown-verb` names the exact line and suggests the exact fix. A second,
    // file-level "this yielded nothing" over the top of it is noise, so the
    // rule is "nothing came out AND nothing said why".
    expect(codes(diagnostics)).toContain('unknown-verb');
    expect(codes(diagnostics)).not.toContain('unrecognised-gal');
    expect(codes(diagnostics)).not.toContain('empty-gal');
  });

  it('a @source naming a file that is not on disk is reported once', async () => {
    const root = repo('none',
      `@source file:src/moved-away.js line:1\n${RELATIONS.join('\n')}\n`);
    const { model, diagnostics } = await parseProject({ root, project: 'repro' });

    // The annotations parse and count — dropping them would be the failure
    // GL-503 fixed. What is new is that the phantom annotated file is named.
    expect(model.exposures).toHaveLength(2);
    expect(model.annotated_files).toContain('src/moved-away.js');
    const missing = diagnostics.filter(d => d.code === 'missing-gal-source');
    expect(missing).toHaveLength(1);
    expect(missing[0].message).toContain('src/moved-away.js');
    expect(missing[0].file).toBe('.guardlink/annotations/src/allocations.js.gal');
  });

  it('does not fire on a @source pointing at a file the scan excludes but disk holds', async () => {
    const root = repo('none');
    mkdirSync(join(root, 'test'), { recursive: true });
    writeFileSync(join(root, 'test', 'allocations.spec.js'), SOURCE);
    mkdirSync(join(root, '.guardlink', 'annotations', 'test'), { recursive: true });
    writeFileSync(
      join(root, '.guardlink', 'annotations', 'test', 'allocations.spec.js.gal'),
      `@source file:test/allocations.spec.js line:1\n${RELATIONS[0]}\n`);

    const { diagnostics } = await parseProject({ root, project: 'repro' });
    // `test/` is excluded from the SOURCE scan and its sidecar is rescued
    // anyway (GL-503). Keying this diagnostic on the scan set instead of on
    // disk would fire here, on a correct annotation.
    expect(codes(diagnostics)).not.toContain('missing-gal-source');
  });
});

/**
 * The same thing again through the CLI, because the terminal is the half a
 * developer and a cold agent actually act on.
 *
 * Before this change, every assertion in this block was the opposite: `validate`
 * printed "✓ All annotations valid, no unmitigated exposures." over a repository
 * whose model reached nothing, and `status` had no line about it at all.
 *
 * ── Why each case carries an explicit 30s timeout ───────────────────
 *
 * Every case here spawns `npx tsx src/cli/index.ts`. The 5000ms default is not
 * a budget for that, it is a dice roll, and this file lost it once: the
 * inline case timed out on CI while its two single-spawn siblings passed in the
 * same run, because it was the only one launching the CLI twice.
 *
 * **Measured before changing anything**, since "the default was always
 * marginal" and "something got slower" are different problems with different
 * fixes. The spawns this block makes, mean of 7 runs each: **548ms** for
 * `validate` and **457ms** for `status`, against ~110ms for the same work run
 * from `dist` — so roughly 80% of each case is `npx` resolution and tsx
 * transpiling the CLI's import graph, not the command. On GitHub's shared
 * runners, which `tests/paths-format.test.ts` measured at roughly 3x local,
 * that is ~1.5s per spawn and ~3s for a case that made two.
 *
 * And the inline path itself is NOT slower. `validate` over this repository,
 * interleaved and trimmed mean of 9 runs: **693ms on this branch against 704ms
 * on main**. In-process, `parseProject` over the same tree is **305ms against
 * 297ms**. `checkHandoff` costs **0.53ms** on 820 annotations, and now returns
 * before the hash that was 0.46ms of it, so a purely inline repository pays
 * ~0.01ms. (A first pass at this measurement read 250ms slower on main — the
 * `git archive` tree it ran in had no grammar `.wasm` files, so it was skipping
 * anchor parsing entirely. Noted because the artifact is easy to repeat.)
 *
 * So the fix is one spawn per case and a timeout sized to what a spawn costs —
 * not a weaker assertion. The global `testTimeout` stays where it is, so a
 * genuinely slow NEW test still surfaces; these are annotated because it is
 * known and measured that they spawn a process.
 */
const CLI_SPAWN_TIMEOUT_MS = 30_000;

describe('the CLI says it too', () => {
  it('validate no longer prints an unqualified tick over a model nothing can read', () => {
    const root = repo('sidecar');
    // The sidecar's two exposures are unmitigated, so trim to the acceptance
    // alone: this asserts on the all-clear path, which is the one that lied.
    writeFileSync(
      join(root, '.guardlink', 'annotations', 'src', 'allocations.js.gal'),
      '@source file:src/allocations.js line:1\n'
      + '@mitigates App.API against #sqli using #prepared -- "bound parameters"\n');
    writeFileSync(join(root, '.guardlink', 'definitions.ts'),
      DEFINITIONS + '// @control Parameterized_Queries (#prepared) -- "Bound parameters"\n');

    const out = guardlink('validate', root);
    expect(out).toContain('Annotations do not leave this repository');
    expect(out).toContain(HANDOFF_COMMAND);
    // The tick survives, and says which half it covers.
    expect(out).toContain('in this repository');
    expect(out).not.toContain('✓ All annotations valid, no unmitigated exposures.\n');
  }, CLI_SPAWN_TIMEOUT_MS);

  it('status carries a line naming what consumers read', () => {
    const root = repo('sidecar');
    expect(guardlink('status', root)).toContain(`Consumers read:   nothing`);
  }, CLI_SPAWN_TIMEOUT_MS);

  // The two inline cases are split so each spawns the CLI once. Together they
  // are the regression guard that keeps these diagnostics from becoming noise
  // for the majority of repositories, so they are two assertions on two
  // surfaces, not one assertion doing less.
  it('validate says nothing extra on an inline repository', () => {
    const out = guardlink('validate', repo('inline'));
    expect(out).not.toContain('Annotations do not leave this repository');
    // And the verdict keeps its ordinary wording: the qualifier the handoff
    // adds must not appear on a repository that needs no export.
    expect(out).toContain('Validation passed with 1 unmitigated exposure(s).');
    expect(out).not.toContain('in this repository. See above');
  }, CLI_SPAWN_TIMEOUT_MS);

  it('status says nothing extra on an inline repository', () => {
    expect(guardlink('status', repo('inline'))).not.toContain('Consumers read:');
  }, CLI_SPAWN_TIMEOUT_MS);
});
