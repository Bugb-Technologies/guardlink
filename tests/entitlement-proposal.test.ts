/**
 * §3.6 of docs/prd/actor-entitlement-design.md — an agent proposes an
 * entitlement, a human accepts it.
 *
 * The asymmetry from §2 drives these cases the same way it drives
 * actor-entitlement.test.ts: what matters is not that the happy path works but
 * that the paths which could land an over-grant silently do not. A rejection
 * must leave source alone, an uncited claim must not become effective by
 * accident, and an @entitles nobody accepted must be visible.
 */

import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseString } from '../src/parser/parse-file.js';
import { parseProject } from '../src/parser/parse-project.js';
import { extractCitation } from '../src/parser/citation.js';
import { findInertEntitlements } from '../src/parser/validate.js';
import {
  proposeEntitlement, listProposals, loadProposals, applyProposalDecision,
  findUnacceptedEntitlements, checkEntitlementProvenance, proposalId, entitlementKey,
  proposalsPath, buildEntitlesBody, oneLine, proposalWarnings, InertProposalError,
  OwnershipClassProposalError, LEDGER_VERSION,
} from '../src/review/entitlements.js';
import type { EntitlesAnnotation } from '../src/types/index.js';

// ─── Fixture ─────────────────────────────────────────────────────────

const CITED = 'By design: the archival URI is namespace configuration. Authz: ScopeCluster/AccessAdmin at common/api/metadata.go:189';

/** A project with a declared actor and one @exposes line to anchor against. */
async function project(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'gl-entitle-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), [
    '// @asset Archival.FS (#archival-fs) -- "Archival destination on local disk"',
    '// @threat Path_Traversal (#path-traversal) [high] cwe:CWE-22 -- "Archival URI used as a filesystem path"',
    '// @threat Namespace_Isolation (#namespace-isolation) [high] cwe:CWE-639 -- "One namespace reaches another\'s objects"',
    '// @actor Namespace_Admin (#ns-admin) -- "Administers one namespace\'s configuration"',
  ].join('\n'));
  await writeFile(join(root, 'src', 'archiver.ts'), [
    '// @exposes #archival-fs to #path-traversal [high] cwe:CWE-22 -- "Archival URI is used as a filesystem path"',
    '// @audit #archival-fs -- "Needs a human look at the URI validation"',
    'export function archive(uri: string) { return uri; }',
  ].join('\n'));
  return root;
}

const BASE = {
  actor: '#ns-admin',
  capability: 'configure-archival-destination',
  asset: '#archival-fs',
  threat: '#path-traversal',
  rationale: CITED,
  file: 'src/archiver.ts',
  line: 1,
  proposed_by: 'annotating-agent',
};

async function sourceOf(root: string): Promise<string> {
  return readFile(join(root, 'src', 'archiver.ts'), 'utf-8');
}

// ─── The artifact round-trips ────────────────────────────────────────

describe('proposal artifact', () => {
  it('round-trips a proposal through .guardlink/entitlement-proposals.json', async () => {
    const root = await project();
    try {
      const filed = await proposeEntitlement(root, BASE);
      expect(filed.created).toBe(true);
      expect(filed.refused).toBeUndefined();

      const raw = await readFile(proposalsPath(root), 'utf-8');
      expect(JSON.parse(raw).version).toBe(LEDGER_VERSION);

      const [p] = (await loadProposals(root)).proposals;
      expect(p.id).toBe(proposalId('#ns-admin', 'configure-archival-destination'));
      expect(p.actor).toBe('#ns-admin');
      expect(p.capability).toBe('configure-archival-destination');
      expect(p.canonical_capability).toBe('configure_archival_destination');
      expect(p.asset).toBe('#archival-fs');
      expect(p.threat).toBe('#path-traversal');
      expect(p.rationale).toBe(CITED);
      expect(p.citation).toEqual({ file: 'common/api/metadata.go', line: 189, raw: 'common/api/metadata.go:189' });
      expect(p.inert).toBe(false);
      expect(p.target).toEqual({ file: 'src/archiver.ts', line: 1 });
      expect(p.proposed_by).toBe('annotating-agent');
      expect(p.status).toBe('proposed');
      expect(p.history).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('writes nothing to source when a proposal is filed', async () => {
    const root = await project();
    try {
      const before = await sourceOf(root);
      await proposeEntitlement(root, BASE);
      expect(await sourceOf(root)).toBe(before);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keys a proposal on (actor, capability), so a re-file updates rather than duplicates', async () => {
    const root = await project();
    try {
      await proposeEntitlement(root, BASE);
      const again = await proposeEntitlement(root, { ...BASE, asset: undefined, rationale: `${CITED} (narrowed)` });
      expect(again.created).toBe(false);
      const proposals = await listProposals(root);
      expect(proposals).toHaveLength(1);
      expect(proposals[0].asset).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('refuses a prose capability — the capability is a join key', async () => {
    const root = await project();
    try {
      await expect(proposeEntitlement(root, { ...BASE, capability: 'can configure the destination' }))
        .rejects.toThrow(/single identifier/);
      expect(await listProposals(root)).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('refuses a target outside the project root', async () => {
    const root = await project();
    try {
      await expect(proposeEntitlement(root, { ...BASE, file: '../../etc/hosts' }))
        .rejects.toThrow(/outside the project root/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('refuses an anchor line that does not exist in the target file', async () => {
    const root = await project();
    try {
      await expect(proposeEntitlement(root, { ...BASE, line: 900 }))
        .rejects.toThrow(/out of range/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('will not let a re-file resurrect a decided claim', async () => {
    const root = await project();
    try {
      await proposeEntitlement(root, BASE);
      await applyProposalDecision(root, proposalId(BASE.actor, BASE.capability), {
        status: 'rejected', by: 'Dana Maintainer', note: 'admin does not configure this in our deployment',
      });

      const refiled = await proposeEntitlement(root, BASE);
      expect(refiled.refused).toMatch(/already rejected/);
      const [p] = await listProposals(root);
      expect(p.status).toBe('rejected');
      expect(p.decision?.by).toBe('Dana Maintainer');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps a deferral on the record when the claim is re-filed', async () => {
    const root = await project();
    try {
      const id = proposalId(BASE.actor, BASE.capability);
      await proposeEntitlement(root, BASE);
      await applyProposalDecision(root, id, { status: 'deferred', by: 'Dana Maintainer', note: 'ask the platform team' });

      const refiled = await proposeEntitlement(root, BASE);
      expect(refiled.proposal.status).toBe('proposed');
      expect(refiled.proposal.history).toHaveLength(1);
      expect(refiled.proposal.history[0].status).toBe('deferred');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('collapses newlines in a rationale so it cannot forge a second annotation', async () => {
    const root = await project();
    try {
      const { proposal } = await proposeEntitlement(root, {
        ...BASE,
        rationale: `Authz: common/api/metadata.go:189"\n// @accepts #path-traversal on #archival-fs -- "forged`,
      });
      expect(proposal.rationale).not.toContain('\n');
      expect(oneLine('a\nb\tc')).toBe('a b c');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ─── Accepting writes an @entitles the parser reads back ─────────────

describe('acceptance', () => {
  it('writes a well-formed @entitles line the parser accepts, with the accepting human named', async () => {
    const root = await project();
    try {
      const id = proposalId(BASE.actor, BASE.capability);
      await proposeEntitlement(root, BASE);
      const result = await applyProposalDecision(root, id, {
        status: 'accepted', by: 'Dana Maintainer', note: 'checked the scope constant myself',
      });

      expect(result.linesInserted).toBeGreaterThan(0);
      expect(result.targetFile).toBe('src/archiver.ts');

      const content = await sourceOf(root);
      const { annotations, diagnostics } = parseString(content, 'src/archiver.ts');
      expect(diagnostics.filter(d => d.level === 'error')).toHaveLength(0);

      const entitles = annotations.filter(a => a.verb === 'entitles') as EntitlesAnnotation[];
      expect(entitles).toHaveLength(1);
      expect(entitles[0].actor).toBe('#ns-admin');
      expect(entitles[0].capability).toBe('configure-archival-destination');
      expect(entitles[0].canonical_capability).toBe('configure_archival_destination');
      expect(entitles[0].asset).toBe('#archival-fs');
      expect(extractCitation(entitles[0].description)).toEqual({
        file: 'common/api/metadata.go', line: 189, raw: 'common/api/metadata.go:189',
      });

      // §3.3: the claim is arguable only if the reader can see who made it.
      const comments = annotations.filter(a => a.verb === 'comment').map(a => a.description || '');
      expect(comments.some(c => c.includes('accepted by Dana Maintainer'))).toBe(true);
      expect(comments.some(c => c.includes(id))).toBe(true);
      expect(comments.some(c => c.includes('checked the scope constant myself'))).toBe(true);

      // The annotation lands in the comment style of the file it lands in.
      expect(content).toContain('// @entitles #ns-admin to configure-archival-destination on #archival-fs');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('records the decision in the ledger, with where the annotation landed', async () => {
    const root = await project();
    try {
      const id = proposalId(BASE.actor, BASE.capability);
      await proposeEntitlement(root, BASE);
      await applyProposalDecision(root, id, { status: 'accepted', by: 'Dana Maintainer' });

      const [p] = await listProposals(root);
      expect(p.status).toBe('accepted');
      expect(p.decision?.by).toBe('Dana Maintainer');
      expect(p.decision?.written_to).toBe('src/archiver.ts:1');
      expect(p.history.map(h => h.status)).toEqual(['accepted']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('refuses an acceptance with no human name', async () => {
    const root = await project();
    try {
      await proposeEntitlement(root, BASE);
      await expect(applyProposalDecision(root, proposalId(BASE.actor, BASE.capability), {
        status: 'accepted', by: '   ',
      })).rejects.toThrow(/name of the human/);
      expect(await sourceOf(root)).not.toContain('@entitles');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('will not accept the same proposal twice', async () => {
    const root = await project();
    try {
      const id = proposalId(BASE.actor, BASE.capability);
      await proposeEntitlement(root, BASE);
      await applyProposalDecision(root, id, { status: 'accepted', by: 'Dana Maintainer' });
      await expect(applyProposalDecision(root, id, { status: 'accepted', by: 'Dana Maintainer' }))
        .rejects.toThrow(/already accepted/);

      const { annotations } = parseString(await sourceOf(root), 'src/archiver.ts');
      expect(annotations.filter(a => a.verb === 'entitles')).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('errors on an unknown proposal id', async () => {
    const root = await project();
    try {
      await expect(applyProposalDecision(root, 'ent-nobody.nothing', { status: 'accepted', by: 'Dana' }))
        .rejects.toThrow(/No proposal with id/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ─── §3.4: no citation, no effect ────────────────────────────────────

describe('§3.4 — an uncited proposal cannot silently become effective', () => {
  const UNCITED = { ...BASE, rationale: 'Namespace admins configure their own namespace, so this is by design' };

  it('marks it inert and warns at proposal time', async () => {
    const root = await project();
    try {
      const { proposal, warnings } = await proposeEntitlement(root, UNCITED);
      expect(proposal.citation).toBeUndefined();
      expect(proposal.inert).toBe(true);
      expect(warnings.some(w => w.startsWith('uncited:'))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('refuses to accept it, and leaves both source and status alone', async () => {
    const root = await project();
    try {
      const id = proposalId(UNCITED.actor, UNCITED.capability);
      await proposeEntitlement(root, UNCITED);
      const before = await sourceOf(root);

      await expect(applyProposalDecision(root, id, { status: 'accepted', by: 'Dana Maintainer' }))
        .rejects.toThrow(InertProposalError);
      await expect(applyProposalDecision(root, id, { status: 'accepted', by: 'Dana Maintainer' }))
        .rejects.toThrow(/§3.4/);

      expect(await sourceOf(root)).toBe(before);
      const [p] = await listProposals(root);
      expect(p.status).toBe('proposed');
      expect(p.decision).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('accepts it only with the explicit acknowledgement, and says INERT in source', async () => {
    const root = await project();
    try {
      const id = proposalId(UNCITED.actor, UNCITED.capability);
      await proposeEntitlement(root, UNCITED);
      await applyProposalDecision(root, id, {
        status: 'accepted', by: 'Dana Maintainer', acknowledgeInert: true,
      });

      const content = await sourceOf(root);
      const { annotations } = parseString(content, 'src/archiver.ts');
      const comments = annotations.filter(a => a.verb === 'comment').map(a => a.description || '');
      expect(comments.some(c => c.startsWith('INERT entitlement'))).toBe(true);
      expect(comments.some(c => c.includes('Accepted as inert by Dana Maintainer'))).toBe(true);

      const [p] = await listProposals(root);
      expect(p.decision?.acknowledged_inert).toBe(true);

      // And the parser still calls it inert once it is in the model — the
      // acknowledgement records a human's choice, it does not grant effect.
      const { model } = await parseProject({ root, project: 'tmp' });
      expect(model.entitlements).toHaveLength(1);
      expect(model.entitlements![0].inert).toBe(true);
      expect(findInertEntitlements(model)).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ─── §3.5: the ownership-class trap ─────────────────────────────────

describe('§3.5 — ownership-class proposals are warned about at proposal time', () => {
  it('warns when the claim answers an ownership-class threat', async () => {
    const root = await project();
    try {
      const { warnings, proposal } = await proposeEntitlement(root, {
        ...BASE,
        capability: 'delete-namespace',
        threat: '#namespace-isolation',
        rationale: `Admins delete namespaces. Authz: common/api/metadata.go:189`,
      });
      expect(warnings.some(w => w.startsWith('ownership-class:'))).toBe(true);
      expect(proposal.warnings.some(w => /whose object/.test(w))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('warns on an IDOR-shaped threat name and on a CWE-639 rationale', () => {
    expect(proposalWarnings({
      actor: '#ns-admin', capability: 'read-workflow', threat: 'IDOR',
      rationale: 'Authz: src/authz.ts:10',
    }).some(w => w.startsWith('ownership-class:'))).toBe(true);

    expect(proposalWarnings({
      actor: '#ns-admin', capability: 'read-workflow', threat: 'Object_Access',
      rationale: 'cwe:CWE-639 — admins may read another tenant\'s workflow. Authz: src/authz.ts:10',
    }).some(w => w.startsWith('ownership-class:'))).toBe(true);
  });

  it('does not warn for a plain capability question', () => {
    expect(proposalWarnings({
      actor: '#ns-admin', capability: 'configure-archival-destination', threat: '#path-traversal',
      rationale: CITED,
    })).toEqual([]);
  });

  it('reports an ownership-class exposure already recorded against the asset', async () => {
    const root = await project();
    try {
      await writeFile(join(root, 'src', 'frontend.ts'), [
        '// @exposes #archival-fs to #namespace-isolation [high] cwe:CWE-639 -- "One namespace reaches another\'s archive"',
        'export const frontend = true;',
      ].join('\n'));
      const { model } = await parseProject({ root, project: 'tmp' });
      const warnings = proposalWarnings({
        actor: '#ns-admin', capability: 'configure-archival-destination',
        asset: '#archival-fs', threat: '#path-traversal', rationale: CITED,
      }, model);
      expect(warnings.some(w => /already carries an ownership-class exposure/.test(w))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('refuses to accept an ownership-class proposal without an explicit acknowledgement', async () => {
    const root = await project();
    try {
      const id = proposalId('#ns-admin', 'delete-namespace');
      await proposeEntitlement(root, {
        ...BASE, capability: 'delete-namespace', threat: '#namespace-isolation',
        rationale: 'Admins delete namespaces. Authz: common/api/metadata.go:189',
      });
      const before = await sourceOf(root);

      await expect(applyProposalDecision(root, id, { status: 'accepted', by: 'Dana Maintainer' }))
        .rejects.toThrow(OwnershipClassProposalError);
      expect(await sourceOf(root)).toBe(before);
      expect((await listProposals(root))[0].status).toBe('proposed');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('carries the warning into source when a human accepts anyway', async () => {
    const root = await project();
    try {
      const id = proposalId('#ns-admin', 'delete-namespace');
      await proposeEntitlement(root, {
        ...BASE, capability: 'delete-namespace', threat: '#namespace-isolation',
        rationale: 'Admins delete namespaces. Authz: common/api/metadata.go:189',
      });
      await applyProposalDecision(root, id, {
        status: 'accepted', by: 'Dana Maintainer', acknowledgeOwnership: true,
      });

      const { annotations } = parseString(await sourceOf(root), 'src/archiver.ts');
      const comments = annotations.filter(a => a.verb === 'comment').map(a => a.description || '');
      expect(comments.some(c => c.startsWith('ownership-class:'))).toBe(true);
      expect(comments.some(c => /Accepted over this warning by Dana Maintainer/.test(c))).toBe(true);
      expect((await listProposals(root))[0].decision?.acknowledged_ownership_class).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not gate a rejection on the acknowledgement — refusing is always available', async () => {
    const root = await project();
    try {
      const id = proposalId('#ns-admin', 'delete-namespace');
      await proposeEntitlement(root, {
        ...BASE, capability: 'delete-namespace', threat: '#namespace-isolation',
        rationale: 'Admins delete namespaces. Authz: common/api/metadata.go:189',
      });
      await applyProposalDecision(root, id, {
        status: 'rejected', by: 'Dana Maintainer', note: 'ownership is measured, not annotated',
      });
      expect((await listProposals(root))[0].status).toBe('rejected');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ─── Rejection and deferral ─────────────────────────────────────────

describe('rejection and deferral', () => {
  it('rejection leaves source untouched and records the reason', async () => {
    const root = await project();
    try {
      const id = proposalId(BASE.actor, BASE.capability);
      await proposeEntitlement(root, BASE);
      const before = await sourceOf(root);

      const result = await applyProposalDecision(root, id, {
        status: 'rejected', by: 'Dana Maintainer',
        note: 'the scope constant is checked at the gateway, not here',
      });

      expect(result.linesInserted).toBe(0);
      expect(result.targetFile).toBeUndefined();
      expect(await sourceOf(root)).toBe(before);
      expect(await sourceOf(root)).not.toContain('@entitles');

      const [p] = await listProposals(root);
      expect(p.status).toBe('rejected');
      expect(p.decision?.note).toBe('the scope constant is checked at the gateway, not here');
      expect(p.history).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('a rejection must say why', async () => {
    const root = await project();
    try {
      await proposeEntitlement(root, BASE);
      await expect(applyProposalDecision(root, proposalId(BASE.actor, BASE.capability), {
        status: 'rejected', by: 'Dana Maintainer',
      })).rejects.toThrow(/must say why/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('deferral leaves source untouched and keeps the claim listable', async () => {
    const root = await project();
    try {
      const id = proposalId(BASE.actor, BASE.capability);
      await proposeEntitlement(root, BASE);
      await applyProposalDecision(root, id, { status: 'deferred', by: 'Dana Maintainer' });

      expect(await sourceOf(root)).not.toContain('@entitles');
      expect(await listProposals(root, { status: ['deferred'] })).toHaveLength(1);
      expect(await listProposals(root, { status: ['proposed'] })).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ─── §3.6 teeth: an @entitles needs a human behind it ───────────────

describe('§3.6 — an entitlement written straight into source is visible', () => {
  it('errors on an @entitles with no accepted proposal, and stops once accepted', async () => {
    const root = await project();
    try {
      // An agent writes the annotation itself, skipping the proposal.
      await writeFile(join(root, 'src', 'sneaky.ts'), [
        '// @entitles #ns-admin to configure-archival-destination on #archival-fs -- "By design. Authz: common/api/metadata.go:189"',
        'export const sneaky = true;',
      ].join('\n'));

      const { model } = await parseProject({ root, project: 'tmp' });
      expect(model.entitlements).toHaveLength(1);

      const empty = findUnacceptedEntitlements(model, { version: LEDGER_VERSION, proposals: [] });
      expect(empty).toHaveLength(1);
      expect(empty[0].level).toBe('error');
      expect(empty[0].message).toMatch(/no accepted proposal/);
      expect(empty[0].file).toBe('src/sneaky.ts');

      // The same claim, once a human has accepted it, is clean.
      await proposeEntitlement(root, BASE);
      await applyProposalDecision(root, proposalId(BASE.actor, BASE.capability), {
        status: 'accepted', by: 'Dana Maintainer',
      });
      const ledger = await loadProposals(root);
      expect(findUnacceptedEntitlements(model, ledger)).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not fire on a project with no proposal ledger', async () => {
    const root = await project();
    try {
      await writeFile(join(root, 'src', 'sneaky.ts'), [
        '// @entitles #ns-admin to configure-archival-destination -- "By design. Authz: common/api/metadata.go:189"',
        'export const sneaky = true;',
      ].join('\n'));
      const { model } = await parseProject({ root, project: 'tmp' });
      expect(await checkEntitlementProvenance(root, model)).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('matches a rejected claim as unaccepted — a refusal is not a grant', async () => {
    const root = await project();
    try {
      await proposeEntitlement(root, BASE);
      await applyProposalDecision(root, proposalId(BASE.actor, BASE.capability), {
        status: 'rejected', by: 'Dana Maintainer', note: 'not how our deployment works',
      });
      await writeFile(join(root, 'src', 'sneaky.ts'), [
        `// @entitles #ns-admin to configure-archival-destination -- "${CITED}"`,
        'export const sneaky = true;',
      ].join('\n'));

      const { model } = await parseProject({ root, project: 'tmp' });
      const diags = await checkEntitlementProvenance(root, model);
      expect(diags).toHaveLength(1);
      expect(diags[0].level).toBe('error');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ─── Identity and line building ─────────────────────────────────────

describe('helpers', () => {
  it('keys an entitlement the way §3.1 and guardlink diff do', () => {
    expect(entitlementKey('#ns-admin', 'configure-archival-destination'))
      .toBe('ns_admin.configure_archival_destination');
    expect(entitlementKey('Namespace_Admin', 'configure-archival-destination'))
      .not.toBe(entitlementKey('#ns-admin', 'configure-archival-destination'));
    expect(proposalId('#ns-admin', 'delete-namespace')).toBe('ent-ns_admin.delete_namespace');
  });

  it('builds a body the parser reads back, and refuses one it would not', () => {
    const body = buildEntitlesBody({
      actor: '#ns-admin', capability: 'configure-archival-destination',
      asset: '#archival-fs', rationale: CITED,
    });
    const parsed = parseString(`// ${body}`, 'x.ts').annotations[0] as EntitlesAnnotation;
    expect(parsed.verb).toBe('entitles');
    expect(parsed.description).toBe(CITED);

    expect(() => buildEntitlesBody({
      actor: '#ns-admin', capability: 'not a capability', rationale: CITED,
    })).toThrow(/does not parse as @entitles/);
  });

  it('escapes a quoted rationale rather than breaking the annotation', () => {
    const body = buildEntitlesBody({
      actor: '#ns-admin', capability: 'configure-archival-destination',
      rationale: 'The "archival" URI. Authz: common/api/metadata.go:189',
    });
    const parsed = parseString(`// ${body}`, 'x.ts').annotations[0] as EntitlesAnnotation;
    expect(parsed.verb).toBe('entitles');
    expect(parsed.description).toBe('The "archival" URI. Authz: common/api/metadata.go:189');
  });
});
