/**
 * W3.2 / marks 5, 6, 7, 18 — `guardlink ci <one-repo>` answers a single-repository
 * question, and must say so.
 *
 * Measured on a four-repository estate: the repository holding `@exposes` exits
 * 1, the repository holding the `@mitigates` that covers it exits 0, and the
 * merged report over both says nothing is unmitigated. Neither per-repo run is
 * wrong about its own tree; both are wrong about the question the reader thinks
 * they answered.
 *
 * Of the two available repairs — teach `ci` the workspace, or have it state its
 * scope — this is the second, and the reason is a fact about the data rather
 * than a preference. `workspace.yaml` carries a workspace name, `this_repo`,
 * and each sibling's NAME and remote REGISTRY URL. It carries no local path:
 * `serializeWorkspaceYaml` never writes one and `WorkspaceRepo.local_path` is
 * documented as setup-only. And the environment `ci` exists for is a runner
 * with exactly one repository checked out, where a sibling's current model is
 * not on disk under any path. A version that read siblings would work on a
 * laptop with four clones side by side and go quiet in the pipeline.
 *
 * So the claims here are: it says what it answered, it names what it did not
 * read, it points at the command that does answer the estate question — and it
 * changes NOTHING about what it found. A statement of scope that also moved the
 * verdict would be a second defect wearing the first one's clothes.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCiChecks, formatCiReport, ESTATE_ROUTE, type CiWorkspaceScope } from '../src/ci/index.js';
import { loadWorkspaceConfig, serializeWorkspaceYaml } from '../src/workspace/metadata.js';
import type { ThreatModel } from '../src/types/index.js';

function modelWithOneOpenExposure(): ThreatModel {
  const loc = (line: number) => ({ file: 'src/handlers.py', line });
  return {
    version: '1.2.0', project: 'orders-api', generated_at: '2026-09-14T00:00:00.000Z',
    source_files: 1, annotations_parsed: 2,
    annotated_files: ['src/handlers.py'], unannotated_files: [],
    assets: [{ path: ['Orders', 'Listing'], id: '#listing', location: loc(1) }],
    threats: [{
      name: 'Broken_Access_Control', canonical_name: 'broken_access_control', id: '#bac',
      severity: 'high', external_refs: [], location: loc(2),
    }],
    controls: [], actors: [], entitlements: [],
    mitigations: [],
    exposures: [{ asset: '#listing', threat: '#bac', severity: 'high', external_refs: [], location: loc(9) }],
    confirmed: [], acceptances: [], transfers: [], flows: [], boundaries: [],
    validations: [], audits: [], ownership: [], data_handling: [], assumptions: [],
    shields: [], features: [], comments: [],
    coverage: { annotation_count: 2, coverage_percent: 100 },
  } as unknown as ThreatModel;
}

function cleanModel(): ThreatModel {
  const m = modelWithOneOpenExposure();
  m.exposures = [];
  return m;
}

const acme: CiWorkspaceScope = {
  workspace: 'acme',
  this_repo: 'orders-api',
  siblings: ['billing-api', 'platform-authz', 'payments-gw'],
  answers: 'single-repo',
  estate_command: ESTATE_ROUTE,
};

describe('ci — a repository in a workspace says which question it answered', () => {
  it('names the workspace, this repo, and every sibling it did not read', () => {
    const text = formatCiReport(runCiChecks('.', modelWithOneOpenExposure(), { workspace: acme }));
    expect(text).toContain('This is a single-repository answer: orders-api of workspace "acme"');
    expect(text).toContain('3 sibling repo(s) were NOT read: billing-api, platform-authz, payments-gw');
  });

  it('points at the estate command rather than guessing at a sibling\'s model', () => {
    const text = formatCiReport(runCiChecks('.', modelWithOneOpenExposure(), { workspace: acme }));
    expect(text).toContain('guardlink merge');
    expect(text).toContain('guardlink estate');
    expect(text).toContain(ESTATE_ROUTE);
  });

  it('says it on a CLEAN run too — a green tick over one repo of four needs the caveat most', () => {
    const text = formatCiReport(runCiChecks('.', cleanModel(), { workspace: acme }));
    expect(text).toContain('every acceptance accounted for — in this repository');
    expect(text).toContain('This is a single-repository answer');
    // And it does not claim a control might cover something that is not there.
    expect(text).toContain('A risk this repository does not declare may live in one of them');
  });

  it('on a run with findings it says the reverse: a sibling may hold the control', () => {
    const text = formatCiReport(runCiChecks('.', modelWithOneOpenExposure(), { workspace: acme }));
    expect(text).toContain('A control covering one of the exposures above may live in one of them');
  });

  it('the statement reaches a JSON consumer too, with what it answers for', () => {
    const report = runCiChecks('.', modelWithOneOpenExposure(), { workspace: acme });
    expect(report.summary.workspace).toEqual(acme);
    expect(report.summary.workspace!.answers).toBe('single-repo');
    expect(JSON.parse(JSON.stringify(report)).summary.workspace.siblings).toHaveLength(3);
  });
});

describe('ci — the statement changes what is said and nothing that is found', () => {
  it('the same model, with and without a workspace, produces the same verdict', () => {
    const withWs = runCiChecks('.', modelWithOneOpenExposure(), { strict: true, workspace: acme });
    const without = runCiChecks('.', modelWithOneOpenExposure(), { strict: true });
    expect(withWs.summary.exit_code).toBe(without.summary.exit_code);
    expect(withWs.summary.exit_code).toBe(1);
    expect(withWs.summary.exposures).toBe(without.summary.exposures);
    expect(withWs.exposures).toEqual(without.exposures);
  });

  it('a clean repo in a workspace still exits 0 under --strict', () => {
    expect(runCiChecks('.', cleanModel(), { strict: true, workspace: acme }).summary.exit_code).toBe(0);
  });

  it('a repo with no workspace.yaml says nothing extra at all', () => {
    const report = runCiChecks('.', modelWithOneOpenExposure(), {});
    expect(report.summary.workspace).toBeNull();
    const text = formatCiReport(report);
    expect(text).not.toContain('single-repository answer');
    expect(text).not.toContain('guardlink estate');
  });

  it('a workspace of one repo states its scope without inventing siblings', () => {
    const solo: CiWorkspaceScope = { ...acme, siblings: [] };
    const text = formatCiReport(runCiChecks('.', modelWithOneOpenExposure(), { workspace: solo }));
    expect(text).toContain('This is a single-repository answer');
    expect(text).not.toContain('were NOT read');
  });
});

describe('ci — the scope it reports is the one workspace.yaml actually declares', () => {
  it('reads the siblings straight out of the file link-project writes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gl-ci-ws-'));
    try {
      mkdirSync(join(dir, '.guardlink'), { recursive: true });
      writeFileSync(join(dir, '.guardlink', 'workspace.yaml'), serializeWorkspaceYaml({
        workspace: 'acme',
        this_repo: 'orders-api',
        repos: [
          { name: 'orders-api' },
          { name: 'billing-api', registry: 'github.com/acme/billing-api' },
          { name: 'platform-authz' },
        ],
      }));

      const config = loadWorkspaceConfig(dir)!;
      expect(config.repos.map(r => r.name).filter(n => n !== config.this_repo))
        .toEqual(['billing-api', 'platform-authz']);

      // The evidence for shipping the statement rather than the lookup: the file
      // records a remote registry URL and never a local path, so there is
      // nothing here to read a sibling's model from.
      expect(config.repos.every(r => (r as { local_path?: string }).local_path === undefined)).toBe(true);
      const yaml = serializeWorkspaceYaml(config);
      expect(yaml).not.toContain('local_path');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
