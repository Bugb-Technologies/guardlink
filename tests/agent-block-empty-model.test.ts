/**
 * The GuardLink block does not claim a threat model the repository has not got.
 *
 * Caveat 7 of release-flows-end-to-end, reproduced cleanly: a repository with
 * no annotations, `{exposures: 0, assets: 0, threats: 0}`, gets a `CLAUDE.md`
 * written into it saying
 *
 *   "This project carries a GuardLink threat model: security facts recorded
 *    next to the code they describe… **Ask it instead of inferring security
 *    context from the source.** It already answers most of what you would
 *    otherwise guess at."
 *
 * Three things are wrong with that, in ascending order of cost. It is false.
 * It is false inside the customer's own repository, in a tracked file, under
 * our name. And it is an *instruction*: every coding agent that opens the repo
 * is told to consult an empty model in preference to reading the code, which is
 * the one reading that makes an absent finding look like a cleared one.
 *
 * Silence is not the fix either. A repository that has just run `init` is
 * exactly the repository where an agent most needs to be told what to do, so
 * the empty state gets its own text: the model is empty, that means nothing is
 * known rather than nothing is wrong, and here is how you populate it as you
 * work. The obligation half of the block was always true and stays.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { agentInstructions, agentInstructionsWithModel, REFERENCE_DOC_IN_GUARDLINK, REFERENCE_DOC_IN_DOCS } from '../src/init/templates.js';
import { initProject, syncAgentFiles } from '../src/init/index.js';
import { parseProject } from '../src/parser/parse-project.js';
import { detectProject } from '../src/init/detect.js';
import type { ThreatModel } from '../src/types/index.js';

const project = { name: 'demo', language: 'typescript', definitionsExt: '.ts', root: '/nowhere' } as ReturnType<typeof detectProject>;

/** A model with something in it — `annotations_parsed` is the one field that decides. */
function populated(): ThreatModel {
  return {
    version: '1.0.0', project: 'demo', generated_at: '', source_files: 2,
    annotated_files: ['a.ts'], unannotated_files: ['b.ts'], annotations_parsed: 12,
    assets: [{ path: ['App', 'API'], id: 'api', location: { file: 'a.ts', line: 1 } }],
    threats: [], controls: [], mitigations: [], exposures: [], confirmed: [],
    acceptances: [], transfers: [], flows: [], boundaries: [], validations: [], audits: [],
    ownership: [], data_handling: [], assumptions: [], shields: [], features: [], comments: [],
    coverage: { annotation_count: 12, coverage_percent: 50 },
  } as ThreatModel;
}

describe('with no model, the block does not say there is one', () => {
  const text = agentInstructions(project);

  it('does not assert that this project carries a threat model', () => {
    expect(text).not.toMatch(/This project carries a \[GuardLink\]/);
  });

  it('does not tell an agent to ask an empty model instead of reading the code', () => {
    expect(text).not.toMatch(/Ask it instead of inferring security context/);
    expect(text).not.toMatch(/already answers most of what you would otherwise guess at/);
  });

  it('says plainly that the model is empty', () => {
    expect(text).toContain('**its threat model is empty**');
  });

  it('says what empty means, so absence is not read as safety', () => {
    expect(text).toContain('An absent finding is not a cleared one');
    expect(text).toContain('read the code for security context');
  });

  it('turns it into an on-ramp: the agent reading this is the one who fills it', () => {
    expect(text).toContain('You are the one who fills it');
    expect(text).toContain('What you owe it back');
  });

  it('keeps the syntax, the placement rule and the commands — all of which are true on day one', () => {
    expect(text).toContain('### Where annotations go');
    expect(text).toContain('@exposes App.API to #sqli');
    expect(text).toContain('guardlink validate .');
  });
});

describe('with a model, the block says exactly what it always said', () => {
  const text = agentInstructionsWithModel(project, populated());

  it('carries the claim, because now it is true', () => {
    expect(text).toMatch(/This project carries a \[GuardLink\]/);
    expect(text).toMatch(/Ask it instead of inferring security context/);
  });

  it('and still leads with capability rather than obligation', () => {
    expect(text.indexOf('Ask it instead')).toBeLessThan(text.indexOf('What you owe it back'));
  });
});

describe('an empty model is not the same claim as no model at all', () => {
  it('a parsed model with zero annotations gets the empty text, not the claim', () => {
    const model = populated();
    model.annotations_parsed = 0;
    model.annotated_files = [];
    expect(agentInstructionsWithModel(project, model)).not.toMatch(/This project carries a \[GuardLink\]/);
  });
});

// ─── the other claim in the same file ────────────────────────────────

describe('the block points at the reference document that exists', () => {
  it('names docs/ when the reference went to docs/', () => {
    expect(agentInstructions(project, null, { referencePath: REFERENCE_DOC_IN_DOCS }))
      .toContain(REFERENCE_DOC_IN_DOCS);
  });

  it('names .guardlink/ when --no-root-files put it there — D45, in the file D45 missed', () => {
    const text = agentInstructions(project, null, { referencePath: REFERENCE_DOC_IN_GUARDLINK });
    expect(text).toContain(REFERENCE_DOC_IN_GUARDLINK);
    expect(text).not.toContain(REFERENCE_DOC_IN_DOCS);
  });
});

// ─── end to end: the file a new user actually gets ───────────────────

describe('a fresh repository gets a CLAUDE.md that is true about itself', () => {
  let root: string;
  let claudeMd: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-empty-claim-'));
    await writeFile(join(root, 'package.json'), '{"name":"fresh","version":"1.0.0"}\n');
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'index.ts'), 'export const x = 1;\n');
    initProject({ root });
    claudeMd = await readFile(join(root, 'CLAUDE.md'), 'utf-8');
  }, 60_000);
  afterAll(async () => { await rm(root, { recursive: true, force: true }); });

  it('does not tell the next agent that this project carries a threat model', () => {
    expect(claudeMd).not.toMatch(/This project carries a \[GuardLink\]/);
  });

  it('tells it the model is empty and that it is the one who fills it', () => {
    expect(claudeMd).toContain('**its threat model is empty**');
    expect(claudeMd).toContain('You are the one who fills it');
    expect(claudeMd).toContain('What you owe it back');
  });

  it('and once annotations land, sync restores the claim', async () => {
    await writeFile(join(root, '.guardlink', 'definitions.ts'),
      '/**\n * @asset App.API (#api) -- "API"\n * @threat SQL_Injection (#sqli) [critical] -- "SQLi"\n */\nexport {};\n');
    await writeFile(join(root, 'src', 'index.ts'),
      '/**\n * @exposes #api to #sqli [critical] -- "email concatenated into SQL"\n */\nexport const x = 1;\n');
    const { model } = await parseProject({ root, project: 'fresh' });
    syncAgentFiles({ root, model });
    expect(await readFile(join(root, 'CLAUDE.md'), 'utf-8')).toMatch(/This project carries a \[GuardLink\]/);
  }, 60_000);
});
