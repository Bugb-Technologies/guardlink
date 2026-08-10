/**
 * @actor / @entitles — the test cases §6 of docs/prd/actor-entitlement-design.md calls for.
 *
 * The design is driven by an asymmetry rather than by the feature: an under-grant
 * costs noise, an over-grant closes a real escalation as by-design. So most of
 * what is asserted here is what an entitlement must *not* do — it must not
 * suppress, must not reach the SARIF export, and must not have any effect at all
 * without a citation.
 */

import { describe, it, expect } from 'vitest';
import { parseString } from '../src/parser/parse-file.js';
import { extractCitation } from '../src/parser/citation.js';
import {
  findDanglingRefs, findUndeclaredActors, findInertEntitlements,
  findUnmitigatedExposures,
} from '../src/parser/validate.js';
import {
  canEntitlementDemote, entitlementDemotionBlockers,
} from '../src/parser/parse-project.js';
import { diffModels } from '../src/diff/engine.js';
import { generateSarif } from '../src/analyzer/sarif.js';
import type {
  ThreatModel, ActorAnnotation, EntitlesAnnotation,
  ThreatModelActor, ThreatModelEntitlement,
} from '../src/types/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────

const loc = (file = 'src/a.ts', line = 1) => ({ file, line });

/** Minimal model; every collection the readers under test touch is present. */
function model(partial: Partial<ThreatModel>): ThreatModel {
  return {
    assets: [], threats: [], controls: [], actors: [], entitlements: [],
    mitigations: [], exposures: [], confirmed: [], acceptances: [],
    transfers: [], flows: [], boundaries: [], validations: [], audits: [],
    ownership: [], data_handling: [], assumptions: [], shields: [],
    features: [], comments: [],
    ...partial,
  } as unknown as ThreatModel;
}

const actor = (id: string, name: string): ThreatModelActor => ({
  name, canonical_name: name.toLowerCase().replace(/[- ]/g, '_'), id, location: loc('.guardlink/definitions.ts'),
});

function entitlement(partial: Partial<ThreatModelEntitlement>): ThreatModelEntitlement {
  const capability = partial.capability ?? 'configure-archival-destination';
  return {
    actor: '#ns-admin',
    capability,
    canonical_capability: capability.replace(/-/g, '_'),
    inert: !partial.citation,
    // §9.3 — an entitlement joins on (actor, asset, threat); missing either half
    // of the pair makes it imprecise, and an imprecise claim cannot demote.
    imprecise: !(partial.asset && partial.threat),
    location: loc(),
    ...partial,
  };
}

/** A claim that is both cited and precise — the only shape that may demote (§9.7). */
const CITATION = { file: 'common/api/metadata.go', line: 189, raw: 'common/api/metadata.go:189' };
const effective = (partial: Partial<ThreatModelEntitlement> = {}) => entitlement({
  asset: '#archival-fs',
  threat: '#path-traversal',
  description: 'By design. Authz: common/api/metadata.go:189',
  citation: CITATION,
  ...partial,
});

// ─── §6: Grammar ─────────────────────────────────────────────────────

describe('@actor grammar', () => {
  it('parses a name with an id and a description', () => {
    const { annotations } = parseString(
      `// @actor Namespace_Admin (#ns-admin) -- "Administers one namespace's configuration"`,
      'defs.ts',
    );
    const a = annotations[0] as ActorAnnotation;
    expect(a.verb).toBe('actor');
    expect(a.name).toBe('Namespace_Admin');
    expect(a.canonical_name).toBe('namespace_admin');
    expect(a.id).toBe('ns-admin');
    expect(a.description).toBe("Administers one namespace's configuration");
  });

  it('parses without an id or description', () => {
    const { annotations } = parseString('// @actor Cluster_Operator', 'defs.ts');
    expect((annotations[0] as ActorAnnotation).id).toBeUndefined();
  });
});

describe('@entitles grammar', () => {
  it('parses actor, capability, optional asset and description', () => {
    const { annotations } = parseString(
      `// @entitles #ns-admin to configure-archival-destination on #archival-fs -- "By design. Authz: common/api/metadata.go:189"`,
      'src/archiver.go',
    );
    const e = annotations[0] as EntitlesAnnotation;
    expect(e.verb).toBe('entitles');
    expect(e.actor).toBe('#ns-admin');
    expect(e.capability).toBe('configure-archival-destination');
    expect(e.canonical_capability).toBe('configure_archival_destination');
    expect(e.asset).toBe('#archival-fs');
  });

  it('parses without the optional `on <asset>` clause', () => {
    const { annotations } = parseString('// @entitles #ns-admin to delete-namespace', 'src/a.go');
    const e = annotations[0] as EntitlesAnnotation;
    expect(e.asset).toBeUndefined();
    expect(e.canonical_capability).toBe('delete_namespace');
  });

  it('accepts a declared actor name in place of an id', () => {
    const { annotations } = parseString('// @entitles Namespace_Admin to delete-namespace', 'src/a.go');
    expect((annotations[0] as EntitlesAnnotation).actor).toBe('Namespace_Admin');
  });

  it('rejects a prose capability — the capability is a join key, not a sentence', () => {
    const { annotations, diagnostics } = parseString(
      '// @entitles #ns-admin to "can configure the archival destination"',
      'src/a.go',
    );
    expect(annotations).toHaveLength(0);
    expect(diagnostics[0].level).toBe('error');
    expect(diagnostics[0].message).toMatch(/@entitles/);
  });
});

// ─── §3.4: no citation, no effect ────────────────────────────────────

describe('extractCitation', () => {
  it('extracts a path with a line number from surrounding prose', () => {
    expect(extractCitation(
      'By design: the archival URI is namespace configuration. Authz: ScopeCluster/AccessAdmin at common/api/metadata.go:189',
    )).toEqual({ file: 'common/api/metadata.go', line: 189, raw: 'common/api/metadata.go:189' });
  });

  it('extracts a path with no line number', () => {
    expect(extractCitation('granted in common/authorization/authorizer.go')?.file)
      .toBe('common/authorization/authorizer.go');
  });

  it('strips clinging punctuation', () => {
    expect(extractCitation('see (common/api/metadata.go:189).')?.raw).toBe('common/api/metadata.go:189');
  });

  it('is undefined for prose that only looks like a reference', () => {
    expect(extractCitation('Authz: ScopeCluster/AccessAdmin required')).toBeUndefined();
    expect(extractCitation('cwe:CWE-89 applies')).toBeUndefined();
    expect(extractCitation('documented at https://docs.example.com/auth.html')).toBeUndefined();
    expect(extractCitation('the namespace admin role grants it')).toBeUndefined();
    expect(extractCitation(undefined)).toBeUndefined();
  });

  it('rejects a path that escapes the tree', () => {
    expect(extractCitation('see ../../etc/passwd.conf')).toBeUndefined();
  });
});

describe('inertness', () => {
  it('marks an uncited entitlement inert but keeps it in the model', async () => {
    const { annotations } = parseString(
      '// @entitles #ns-admin to delete-namespace -- "Admins may delete their namespace"',
      'src/a.go',
    );
    expect(annotations).toHaveLength(1);

    const m = model({
      actors: [actor('ns-admin', 'Namespace_Admin')],
      entitlements: [entitlement({ description: 'Admins may delete their namespace' })],
    });
    expect(m.entitlements![0].inert).toBe(true);

    const diags = findInertEntitlements(m);
    expect(diags).toHaveLength(1);
    expect(diags[0].level).toBe('warning');
    expect(diags[0].message).toMatch(/inert/);
  });

  it('does not flag a cited entitlement', () => {
    const m = model({
      actors: [actor('ns-admin', 'Namespace_Admin')],
      entitlements: [entitlement({
        description: 'By design. Authz: common/api/metadata.go:189',
        citation: { file: 'common/api/metadata.go', line: 189, raw: 'common/api/metadata.go:189' },
      })],
    });
    expect(findInertEntitlements(m)).toHaveLength(0);
  });
});

// ─── §3.7: validation ────────────────────────────────────────────────

describe('validate', () => {
  it('errors on an @entitles naming an undeclared actor', () => {
    const diags = findUndeclaredActors(model({
      entitlements: [entitlement({ actor: '#ghost-admin' })],
    }));
    expect(diags).toHaveLength(1);
    expect(diags[0].level).toBe('error');
    expect(diags[0].message).toMatch(/#ghost-admin/);
  });

  it('accepts an actor referenced by id or by declared name', () => {
    const actors = [actor('ns-admin', 'Namespace_Admin')];
    expect(findUndeclaredActors(model({
      actors, entitlements: [entitlement({ actor: '#ns-admin' })],
    }))).toHaveLength(0);
    expect(findUndeclaredActors(model({
      actors, entitlements: [entitlement({ actor: 'Namespace_Admin' })],
    }))).toHaveLength(0);
  });

  it('errors on a duplicate actor id, like @asset/@threat', async () => {
    const { mkdtemp, writeFile, mkdir, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { parseProject } = await import('../src/parser/parse-project.js');

    const root = await mkdtemp(join(tmpdir(), 'gl-actor-'));
    try {
      await mkdir(join(root, '.guardlink'), { recursive: true });
      await writeFile(join(root, '.guardlink', 'definitions.ts'), [
        '// @actor Namespace_Admin (#ns-admin) -- "first"',
        '// @actor Namespace_Owner (#ns-admin) -- "second, same id"',
      ].join('\n'));

      const { diagnostics } = await parseProject({ root, project: 'tmp' });
      const dupes = diagnostics.filter(d => /Duplicate identifier #ns-admin/.test(d.message));
      expect(dupes).toHaveLength(1);
      expect(dupes[0].level).toBe('error');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('resolves an actor ref rather than reporting it dangling', () => {
    const m = model({
      actors: [actor('ns-admin', 'Namespace_Admin')],
      entitlements: [entitlement({ asset: '#archival-fs' })],
    });
    const messages = findDanglingRefs(m).map(d => d.message);
    // The asset is genuinely undefined here, the actor is not.
    expect(messages.some(msg => /#archival-fs/.test(msg))).toBe(true);
    expect(messages.some(msg => /#ns-admin/.test(msg))).toBe(false);
  });
});

// ─── §3.2: never a suppression ───────────────────────────────────────

describe('@entitles has no export semantics', () => {
  const exposure = {
    asset: '#archival-fs', threat: '#path-traversal', severity: 'high' as const,
    external_refs: [], description: 'archival URI is used as a filesystem path',
    location: loc('common/archiver/filestore/archiver.go', 61),
  };

  it('produces byte-identical SARIF with and without entitlements', () => {
    const without = generateSarif(model({ exposures: [exposure] }));
    const with_ = generateSarif(model({
      exposures: [exposure],
      actors: [actor('ns-admin', 'Namespace_Admin')],
      entitlements: [entitlement({
        asset: '#archival-fs',
        description: 'By design. Authz: common/api/metadata.go:189',
        citation: { file: 'common/api/metadata.go', line: 189, raw: 'common/api/metadata.go:189' },
      })],
    }));
    expect(JSON.stringify(with_)).toBe(JSON.stringify(without));
  });

  it('leaves the exposure unmitigated — an entitlement is not @mitigates or @accepts', () => {
    const m = model({
      exposures: [exposure],
      actors: [actor('ns-admin', 'Namespace_Admin')],
      entitlements: [entitlement({ asset: '#archival-fs' })],
    });
    expect(findUnmitigatedExposures(m)).toHaveLength(1);
  });
});

// ─── §3.7: diff reports staleness, not removal ───────────────────────

describe('diff', () => {
  const cited = entitlement({
    description: 'By design. Authz: common/api/metadata.go:189',
    citation: { file: 'common/api/metadata.go', line: 189, raw: 'common/api/metadata.go:189' },
  });

  it('reports an entitlement as stale when its cited file changed', () => {
    const before = model({ entitlements: [cited] });
    const after = model({ entitlements: [cited] });

    const diff = diffModels(before, after, { changedFiles: ['common/api/metadata.go'] });
    expect(diff.staleEntitlements).toHaveLength(1);
    expect(diff.staleEntitlements[0].citedFile).toBe('common/api/metadata.go');
    // Stale is not removed, and not a model change.
    expect(diff.entitlements).toHaveLength(0);
    expect(diff.summary.totalChanges).toBe(0);
    expect(diff.summary.staleEntitlements).toBe(1);
  });

  it('does not report staleness for unrelated file changes', () => {
    const diff = diffModels(
      model({ entitlements: [cited] }),
      model({ entitlements: [cited] }),
      { changedFiles: ['README.md'] },
    );
    expect(diff.staleEntitlements).toHaveLength(0);
  });

  it('cannot make an uncited entitlement stale — it has no basis to lose', () => {
    const uncited = entitlement({ description: 'Admins may do this' });
    const diff = diffModels(
      model({ entitlements: [uncited] }),
      model({ entitlements: [uncited] }),
      { changedFiles: ['common/api/metadata.go'] },
    );
    expect(diff.staleEntitlements).toHaveLength(0);
  });

  it('reports added and removed entitlements, and a lost citation', () => {
    const added = diffModels(model({}), model({ entitlements: [cited] }));
    expect(added.entitlements.map(c => c.kind)).toEqual(['added']);

    const removed = diffModels(model({ entitlements: [cited] }), model({}));
    expect(removed.entitlements.map(c => c.kind)).toEqual(['removed']);

    const lostCitation = diffModels(
      model({ entitlements: [cited] }),
      model({ entitlements: [entitlement({ description: 'By design' })] }),
    );
    expect(lostCitation.entitlements[0].kind).toBe('modified');
    expect(lostCitation.entitlements[0].details).toMatch(/became inert/);
  });

  it('keys an entitlement on (actor, asset, threat), so a moved asset is a different claim', () => {
    // Superseded §9: `on <asset>` is half the join, so retargeting it is not an
    // edit to one claim — it withdraws a claim about one pair and makes a claim
    // about another. Reporting it as a modification would hide the withdrawal.
    const diff = diffModels(
      model({ entitlements: [effective({ asset: '#archival-fs' })] }),
      model({ entitlements: [effective({ asset: '#other-fs' })] }),
    );
    expect(diff.entitlements.map(c => c.kind).sort()).toEqual(['added', 'removed']);
  });

  it('leaves diffs of models with no entitlements unchanged', () => {
    const diff = diffModels(model({}), model({}));
    expect(diff.summary.totalChanges).toBe(0);
    expect(diff.staleEntitlements).toEqual([]);
  });
});

// ─── §9: the capability join ─────────────────────────────────────────
//
// §9 amends §3.1: nothing on the finding side carries a capability, so the join
// is (actor, asset, threat) and the capability is the justification a reviewer
// reads. The tests below are §9.8's list. What they mostly assert is that an
// entitlement which does not name both halves of the join cannot demote
// anything — an entitlement that joins too broadly is the over-grant §2 rules
// out, and silence is its failure mode.

describe('§9.7 grammar — against <threat>', () => {
  it('parses and resolves the full form', () => {
    const { annotations, diagnostics } = parseString(
      `// @entitles #ns-admin to configure-archival-destination on #archival-fs against #path-traversal -- "By design. Authz: common/api/metadata.go:189"`,
      'src/archiver.go',
    );
    expect(diagnostics.filter(d => d.level === 'error')).toHaveLength(0);
    const e = annotations[0] as EntitlesAnnotation;
    expect(e.actor).toBe('#ns-admin');
    expect(e.capability).toBe('configure-archival-destination');
    expect(e.asset).toBe('#archival-fs');
    expect(e.threat).toBe('#path-traversal');
  });

  it('resolves a quoted or named threat ref like every other threat position', () => {
    const quoted = parseString('// @entitles #ns-admin to delete-namespace on #ns-api against "Path Traversal"', 'a.go');
    expect((quoted.annotations[0] as EntitlesAnnotation).threat).toBe('Path Traversal');

    const named = parseString('// @entitles #ns-admin to delete-namespace on #ns-api against Path_Traversal', 'a.go');
    expect((named.annotations[0] as EntitlesAnnotation).threat).toBe('Path_Traversal');
  });

  it('still parses with no against clause — §5 compatibility is unchanged', () => {
    const { annotations, diagnostics } = parseString(
      '// @entitles #ns-admin to configure-archival-destination on #archival-fs -- "By design. Authz: common/api/metadata.go:189"',
      'src/archiver.go',
    );
    expect(diagnostics.filter(d => d.level === 'error')).toHaveLength(0);
    const e = annotations[0] as EntitlesAnnotation;
    expect(e.asset).toBe('#archival-fs');
    expect(e.threat).toBeUndefined();
  });

  it('takes against without on', () => {
    const e = parseString('// @entitles #ns-admin to delete-namespace against #path-traversal', 'a.go')
      .annotations[0] as EntitlesAnnotation;
    expect(e.asset).toBeUndefined();
    expect(e.threat).toBe('#path-traversal');
  });

  it('round-trips the threat into the model', async () => {
    const { mkdtemp, writeFile, mkdir, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { parseProject } = await import('../src/parser/parse-project.js');

    const root = await mkdtemp(join(tmpdir(), 'gl-against-'));
    try {
      await mkdir(join(root, '.guardlink'), { recursive: true });
      await writeFile(join(root, '.guardlink', 'definitions.ts'), [
        '// @actor Namespace_Admin (#ns-admin) -- "Administers one namespace"',
        '// @asset Archival.FS (#archival-fs)',
        '// @threat Path_Traversal (#path-traversal) [high]',
        '// @entitles #ns-admin to configure-archival-destination on #archival-fs against #path-traversal',
        '//     -- "By design: the archival URI is namespace configuration. Authz: common/api/metadata.go:189"',
      ].join('\n'));

      const { model } = await parseProject({ root, project: 'tmp' });
      expect(model.entitlements).toHaveLength(1);
      const en = model.entitlements![0];
      expect(en.threat).toBe('#path-traversal');
      expect(en.asset).toBe('#archival-fs');
      expect(en.inert).toBe(false);
      expect(en.imprecise).toBe(false);
      expect(canEntitlementDemote(en)).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reports an undeclared threat ref as dangling, like every other threat position', async () => {
    const { mkdtemp, writeFile, mkdir, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { parseProject } = await import('../src/parser/parse-project.js');

    const root = await mkdtemp(join(tmpdir(), 'gl-dangling-'));
    try {
      await mkdir(join(root, '.guardlink'), { recursive: true });
      await writeFile(join(root, '.guardlink', 'definitions.ts'), [
        '// @actor Namespace_Admin (#ns-admin)',
        '// @asset Archival.FS (#archival-fs)',
        '// @entitles #ns-admin to configure-archival-destination on #archival-fs against #ghost-threat',
      ].join('\n'));

      const { model } = await parseProject({ root, project: 'tmp' });
      const messages = findDanglingRefs(model).map(d => d.message);
      expect(messages.some(msg => /#ghost-threat/.test(msg))).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('§9.3 an imprecise entitlement is carried but cannot demote', () => {
  it('is not a demoter when it names an asset but no threat', () => {
    const en = entitlement({
      asset: '#archival-fs',
      description: 'By design. Authz: common/api/metadata.go:189',
      citation: CITATION,
    });
    expect(en.imprecise).toBe(true);
    expect(canEntitlementDemote(en)).toBe(false);
    expect(entitlementDemotionBlockers(en)).toEqual(['no-threat']);
  });

  it('is not a demoter when it names a threat but no asset', () => {
    const en = entitlement({
      threat: '#path-traversal',
      description: 'By design. Authz: common/api/metadata.go:189',
      citation: CITATION,
    });
    expect(en.imprecise).toBe(true);
    expect(canEntitlementDemote(en)).toBe(false);
    expect(entitlementDemotionBlockers(en)).toEqual(['no-asset']);
  });

  it('is harmless: the loose form is neither an error nor a warning', async () => {
    const { mkdtemp, writeFile, mkdir, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { parseProject } = await import('../src/parser/parse-project.js');

    const root = await mkdtemp(join(tmpdir(), 'gl-loose-'));
    try {
      await mkdir(join(root, '.guardlink'), { recursive: true });
      await writeFile(join(root, '.guardlink', 'definitions.ts'), [
        '// @actor Namespace_Admin (#ns-admin)',
        '// @asset Archival.FS (#archival-fs)',
        '// @entitles #ns-admin to configure-archival-destination on #archival-fs',
        '//     -- "By design. Authz: common/api/metadata.go:189"',
      ].join('\n'));

      const { model, diagnostics } = await parseProject({ root, project: 'tmp' });
      // §9.3: the precise form is opt-in and the loose form is harmless. It is
      // reported by being ineffective, not by being complained about.
      const noise = [...diagnostics, ...findInertEntitlements(model), ...findUndeclaredActors(model)];
      expect(noise).toHaveLength(0);
      expect(model.entitlements).toHaveLength(1);
      expect(canEntitlementDemote(model.entitlements![0])).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('§9.8 uncited and imprecise are independent', () => {
  it('reports only uncited when the join is complete', () => {
    const en = entitlement({ asset: '#archival-fs', threat: '#path-traversal', description: 'By design' });
    expect(en.inert).toBe(true);
    expect(en.imprecise).toBe(false);
    expect(entitlementDemotionBlockers(en)).toEqual(['uncited']);
    expect(findInertEntitlements(model({ entitlements: [en] }))).toHaveLength(1);
  });

  it('reports both, separately, when both are missing', () => {
    const en = entitlement({ description: 'Admins may do this' });
    expect(entitlementDemotionBlockers(en)).toEqual(['uncited', 'no-asset', 'no-threat']);
    expect(canEntitlementDemote(en)).toBe(false);
  });

  it('reports nothing for a cited, precise claim', () => {
    expect(entitlementDemotionBlockers(effective())).toEqual([]);
    expect(canEntitlementDemote(effective())).toBe(true);
  });
});

describe('§3.2 still holds with the threat slot', () => {
  const exposure = {
    asset: '#archival-fs', threat: '#path-traversal', severity: 'high' as const,
    external_refs: [], description: 'archival URI is used as a filesystem path',
    location: loc('common/archiver/filestore/archiver.go', 61),
  };

  it('produces byte-identical SARIF for a fully precise entitlement', () => {
    // The narrower the join, the more it looks like something the exporter
    // could act on — which is exactly when §3.2 has to be re-proved. An
    // entitlement naming this asset and this threat still changes no byte.
    const without = generateSarif(model({ exposures: [exposure] }));
    const with_ = generateSarif(model({
      exposures: [exposure],
      actors: [actor('ns-admin', 'Namespace_Admin')],
      entitlements: [effective()],
    }));
    expect(JSON.stringify(with_)).toBe(JSON.stringify(without));
  });

  it('leaves the exactly-matching exposure unmitigated and exported', () => {
    const m = model({
      exposures: [exposure],
      actors: [actor('ns-admin', 'Namespace_Admin')],
      entitlements: [effective()],
    });
    expect(findUnmitigatedExposures(m)).toHaveLength(1);
    expect(generateSarif(m).runs[0].results).toHaveLength(1);
  });
});

describe('§9.7 diff keys on the join triple', () => {
  it('reports a capability edit on the same triple as a modification', () => {
    const diff = diffModels(
      model({ entitlements: [effective({ capability: 'configure-archival-destination' })] }),
      model({ entitlements: [effective({ capability: 'set-archival-uri' })] }),
    );
    expect(diff.entitlements).toHaveLength(1);
    expect(diff.entitlements[0].kind).toBe('modified');
    expect(diff.entitlements[0].details).toMatch(/capability/);
  });

  it('does not collide two loose claims by the same actor', () => {
    // Neither can demote, but a diff that silently kept one of them would make
    // the loose form invisible rather than harmless (§9.3).
    const diff = diffModels(
      model({}),
      model({
        entitlements: [
          entitlement({ capability: 'delete-namespace' }),
          entitlement({ capability: 'list-namespaces' }),
        ],
      }),
    );
    expect(diff.entitlements.map(c => c.item.capability).sort())
      .toEqual(['delete-namespace', 'list-namespaces']);
  });

  it('separates two claims that differ only by threat', () => {
    const diff = diffModels(
      model({ entitlements: [effective({ threat: '#path-traversal' })] }),
      model({
        entitlements: [
          effective({ threat: '#path-traversal' }),
          effective({ threat: '#deserialization' }),
        ],
      }),
    );
    expect(diff.entitlements.map(c => c.kind)).toEqual(['added']);
    expect(diff.entitlements[0].item.threat).toBe('#deserialization');
  });
});

// ─── §6: regression from the reference repo ──────────────────────────

describe('reference-repo regression', () => {
  it('an entitlement is available for the path-traversal pair but not for an ownership-class pair', () => {
    // Both exposures stay eligible and testable — the entitlement is data for a
    // downstream triage step, and §3.5 puts ownership-class threats out of its
    // reach entirely. What guardlink guarantees is that the fact is present for
    // one pair and absent for the other.
    const m = model({
      actors: [actor('ns-admin', 'Namespace_Admin')],
      exposures: [
        { asset: '#archival-fs', threat: '#path-traversal', severity: 'high', external_refs: [], location: loc('archiver.go', 61) },
        { asset: '#frontend-api', threat: '#namespace-isolation', severity: 'high', external_refs: [], location: loc('frontend.go', 12) },
      ] as never,
      entitlements: [effective()],
    });

    // The consumer's lookup is the join triple, and the gate is the predicate —
    // `!inert` alone is no longer enough to call a claim effective (§9.7).
    const forArchival = m.entitlements!.filter(e =>
      e.asset === '#archival-fs' && e.threat === '#path-traversal' && canEntitlementDemote(e));
    const forFrontend = m.entitlements!.filter(e =>
      e.asset === '#frontend-api' && e.threat === '#namespace-isolation' && canEntitlementDemote(e));
    expect(forArchival).toHaveLength(1);
    expect(forFrontend).toHaveLength(0);

    // Neither is suppressed on guardlink's side.
    expect(findUnmitigatedExposures(m)).toHaveLength(2);
    expect(generateSarif(m).runs[0].results).toHaveLength(2);
  });
});
