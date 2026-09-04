/**
 * `guardlink paths` — unmitigated source-to-sink flow paths.
 *
 * The question this module answers is the one the flow graph was already
 * holding the data for and nobody asked: can data get from somewhere outside
 * the system to somewhere dangerous without passing a control?
 *
 * Entry and exit are defined structurally, not from a hardcoded name list:
 * a declared @asset is part of the system, so a flow endpoint that is *not*
 * declared and has no inbound flow is where data enters, and one with no
 * outbound flow is where it leaves. On this repo that classification lands on
 * UserPrompt / EnvVars / RawStdin as entries and FileSystem / Commands /
 * TempDir as exits, with zero names written into the code.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProject } from '../src/parser/parse-project.js';
import { findUnmitigatedPaths, classifyEndpoints } from '../src/paths/index.js';
import type { ThreatModel } from '../src/types/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

function emptyModel(overrides: Partial<ThreatModel> = {}): ThreatModel {
  return {
    version: '1.0.0', project: 'test', generated_at: '', source_files: 0,
    annotated_files: [], unannotated_files: [], annotations_parsed: 0,
    assets: [], threats: [], controls: [], mitigations: [], exposures: [],
    confirmed: [], acceptances: [], transfers: [], flows: [], boundaries: [],
    validations: [], audits: [], ownership: [], data_handling: [],
    assumptions: [], shields: [], features: [], comments: [],
    coverage: { annotation_count: 0, coverage_percent: 0 },
    ...overrides,
  };
}

const at = (file = 'x.ts', line = 1) => ({ file, line });

/** UserInput -> #api -> FileSystem, with #api declared. */
function linearModel(overrides: Partial<ThreatModel> = {}): ThreatModel {
  return emptyModel({
    assets: [{ id: 'api', path: ['App', 'API'], description: '', location: at('def.ts') } as any],
    flows: [
      { source: 'UserInput', target: '#api', mechanism: 'req.body', location: at('a.ts', 10) },
      { source: '#api', target: 'FileSystem', mechanism: 'writeFileSync', location: at('a.ts', 20) },
    ],
    ...overrides,
  });
}

describe('classifyEndpoints', () => {
  it('treats an undeclared node with no inbound flow as an entry', () => {
    const { entries } = classifyEndpoints(linearModel());
    expect(entries).toEqual(['UserInput']);
  });

  it('treats an undeclared node with no outbound flow as an exit', () => {
    const { exits } = classifyEndpoints(linearModel());
    expect(exits).toEqual(['FileSystem']);
  });

  it('never classifies a declared asset as an entry or an exit', () => {
    // #api has in-degree 1 and out-degree 1 here, but the rule that matters is
    // declaredness: an asset sitting at the edge of the annotated graph is
    // still part of the system, not a way in or out of it.
    const model = emptyModel({
      assets: [{ id: 'api', path: ['App', 'API'], description: '', location: at('def.ts') } as any],
      flows: [{ source: '#api', target: 'FileSystem', mechanism: 'write', location: at('a.ts', 1) }],
    });
    const { entries, exits } = classifyEndpoints(model);
    expect(entries).not.toContain('#api');
    expect(exits).not.toContain('#api');
  });
});

describe('findUnmitigatedPaths', () => {
  it('reports a path from an entry to an exit through a declared asset', () => {
    const findings = findUnmitigatedPaths(linearModel());
    expect(findings).toHaveLength(1);
    expect(findings[0].entry).toBe('UserInput');
    expect(findings[0].exit).toBe('FileSystem');
    expect(findings[0].assetsOnPath).toEqual(['#api']);
  });

  it('carries the file:line of every hop so a finding is navigable', () => {
    const [finding] = findUnmitigatedPaths(linearModel());
    expect(finding.hops.map(h => `${h.via.file}:${h.via.line}`)).toEqual(['a.ts:10', 'a.ts:20']);
  });

  it('carries a display chain, so no consumer re-derives labels from canonical keys', () => {
    // Hops hold canonical keys (lowercased, '#' stripped). A formatter that
    // rebuilt labels from those would print `api` where the model says `#api`.
    const [finding] = findUnmitigatedPaths(linearModel());
    expect(finding.chain).toEqual(['UserInput', '#api', 'FileSystem']);
  });

  it('ignores a path that never touches a declared asset', () => {
    // Two loose endpoints wired to each other describe nothing about the
    // system, so there is no control that could have been missing from it.
    const model = emptyModel({
      flows: [{ source: 'UserInput', target: 'FileSystem', mechanism: 'x', location: at() }],
    });
    expect(findUnmitigatedPaths(model)).toEqual([]);
  });
});

describe('findUnmitigatedPaths — mitigation on the path', () => {
  it('marks a path unmitigated when no asset on it carries a control', () => {
    const [finding] = findUnmitigatedPaths(linearModel());
    expect(finding.mitigated).toBe(false);
    expect(finding.controlsOnPath).toEqual([]);
  });

  it('marks a path mitigated when an asset on it carries a @mitigates', () => {
    const model = linearModel({
      mitigations: [{
        asset: '#api', threat: '#path-traversal', control: '#path-validation',
        description: 'resolve() constrains writes', location: at('a.ts', 15),
      }],
    });
    // includeMitigated, because a defended path is exactly what the default
    // filters out — that exclusion is asserted separately below.
    const [finding] = findUnmitigatedPaths(model, { includeMitigated: true });
    expect(finding.mitigated).toBe(true);
    expect(finding.controlsOnPath).toEqual(['#path-validation']);
  });

  it('does not credit a control on an asset that is not on the path', () => {
    // #other is declared and mitigated, but no hop of this path runs through
    // it — a control elsewhere in the repo does not defend this route.
    const model = linearModel({
      assets: [
        { id: 'api', path: ['App', 'API'], description: '', location: at('def.ts') } as any,
        { id: 'other', path: ['App', 'Other'], description: '', location: at('def.ts') } as any,
      ],
      mitigations: [{
        asset: '#other', threat: '#path-traversal', control: '#path-validation',
        description: 'unrelated', location: at('b.ts', 3),
      }],
    });
    const [finding] = findUnmitigatedPaths(model);
    expect(finding.mitigated).toBe(false);
  });

  it('excludes mitigated paths by default and includes them with includeMitigated', () => {
    const model = linearModel({
      mitigations: [{
        asset: '#api', threat: '#path-traversal', control: '#path-validation',
        description: 'resolve() constrains writes', location: at('a.ts', 15),
      }],
    });
    expect(findUnmitigatedPaths(model)).toEqual([]);
    expect(findUnmitigatedPaths(model, { includeMitigated: true })).toHaveLength(1);
  });
});

describe('findUnmitigatedPaths — trust boundary crossing', () => {
  it('flags a path whose consecutive hop pair is declared a @boundary', () => {
    const model = linearModel({
      boundaries: [{
        asset_a: '#api', asset_b: 'FileSystem', id: 'disk-boundary',
        description: 'app to disk', location: at('a.ts', 18),
      }],
    });
    const [finding] = findUnmitigatedPaths(model);
    expect(finding.crossesBoundary).toBe(true);
    expect(finding.boundariesCrossed).toEqual(['disk-boundary']);
  });

  it('matches a boundary declared in the opposite order to the flow', () => {
    // @boundary is undirected, so the annotation may name the pair either way
    // round while the flow only runs one way.
    const model = linearModel({
      boundaries: [{
        asset_a: 'FileSystem', asset_b: '#api', id: 'disk-boundary',
        description: 'disk to app', location: at('a.ts', 18),
      }],
    });
    expect(findUnmitigatedPaths(model)[0].crossesBoundary).toBe(true);
  });

  it('does not flag a boundary between two nodes that are not adjacent on the path', () => {
    const model = linearModel({
      boundaries: [{
        asset_a: 'UserInput', asset_b: 'FileSystem', id: 'not-a-hop',
        description: 'endpoints of the path, but never a single hop',
        location: at('a.ts', 18),
      }],
    });
    const [finding] = findUnmitigatedPaths(model);
    expect(finding.crossesBoundary).toBe(false);
    expect(finding.boundariesCrossed).toEqual([]);
  });

  it('ranks boundary-crossing paths above ones that cross nothing', () => {
    const model = emptyModel({
      assets: [
        { id: 'api', path: ['App', 'API'], description: '', location: at('def.ts') } as any,
        { id: 'ui', path: ['App', 'UI'], description: '', location: at('def.ts') } as any,
      ],
      flows: [
        { source: 'Quiet', target: '#ui', mechanism: 'x', location: at('u.ts', 1) },
        { source: '#ui', target: 'Terminal', mechanism: 'print', location: at('u.ts', 2) },
        { source: 'UserInput', target: '#api', mechanism: 'req', location: at('a.ts', 1) },
        { source: '#api', target: 'FileSystem', mechanism: 'write', location: at('a.ts', 2) },
      ],
      boundaries: [{
        asset_a: '#api', asset_b: 'FileSystem', id: 'disk-boundary',
        description: '', location: at('a.ts', 3),
      }],
    });
    const findings = findUnmitigatedPaths(model);
    expect(findings).toHaveLength(2);
    expect(findings[0].crossesBoundary).toBe(true);
    expect(findings[0].exit).toBe('FileSystem');
  });
});

describe('findUnmitigatedPaths — against the live repo', () => {
  let model: ThreatModel;
  beforeAll(async () => {
    ({ model } = await parseProject({ root: repoRoot, project: 'guardlink' }));
  });

  it('finds entries and exits without any hardcoded endpoint names', () => {
    const { entries, exits } = classifyEndpoints(model);
    expect(entries.length).toBeGreaterThan(0);
    expect(exits.length).toBeGreaterThan(0);
    // Every classified endpoint must be undeclared — the structural rule.
    const declared = new Set(model.assets.map(a => `#${a.id}`));
    for (const e of [...entries, ...exits]) expect(declared.has(e)).toBe(false);
  });

  it('produces findings whose hops all cite a real annotation location', () => {
    for (const f of findUnmitigatedPaths(model)) {
      for (const h of f.hops) {
        expect(h.via.file).toBeTruthy();
        expect(h.via.line).toBeGreaterThan(0);
      }
    }
  });

  it('never reports a path that has no declared asset on it', () => {
    for (const f of findUnmitigatedPaths(model)) {
      expect(f.assetsOnPath.length).toBeGreaterThan(0);
    }
  });
});
