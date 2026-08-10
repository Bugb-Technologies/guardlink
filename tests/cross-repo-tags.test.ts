/**
 * D19 — the documented cross-repo tag syntax must actually parse.
 *
 * `ASSET_REF` offered `#[a-zA-Z0-9_-]+` | quoted | `[A-Za-z_]\w*(\.[A-Za-z_]\w*)*`.
 * The `#` alternative excluded dots and the dotted alternative excluded `#` and
 * hyphens, so `#auth-lib.token-verify` matched `#auth-lib` and the remainder died
 * on the `$` anchor. `THREAT_REF` had no dotted alternative at all. Cross-repo
 * tags parsed only when quoted, and never in threat or control position — while
 * `detectExternalRefs` had always scanned threat and control positions for
 * exactly those tags.
 *
 * The last describe block is the one that matters long-term: it takes every
 * cross-repo example this codebase EMITS and runs it through the parser. D19
 * shipped because examples of a grammar were hand-written and never executed.
 */
import { describe, it, expect } from 'vitest';
import { parseLine, crossRepoTag, CROSS_REPO_TAG_PATTERN } from '../src/parser/parse-line.js';
import type { ProjectInfo } from '../src/init/detect.js';

const at = { file: 'probe.ts', line: 1 };
const parse = (line: string) => parseLine(line, at).annotation;

describe('D19 — the six reproduction cases', () => {
  it('A: cross-repo asset in a flow, unquoted (parse-project.ts\'s own canonical example)', () => {
    const a = parse('@flows #auth-lib.token-verify -> #api -- "cross-repo asset"');
    expect(a).not.toBeNull();
    expect(a).toMatchObject({ source: '#auth-lib.token-verify', target: '#api' });
  });

  it('B: the workspace_info example — still rejected, and correctly so', () => {
    // This one was doubly wrong. Beyond the dotted tags, `@flows X from A to B`
    // is a verb form the grammar has never had; only `A -> B` exists. Fixing the
    // tag grammar does not make an invented verb form legal, and inventing one
    // would be a new feature. The EMITTED example was corrected instead — see
    // the "examples this codebase emits" block below.
    expect(parse('@flows #data from #this.component to #sibling.endpoint -- "x"')).toBeNull();
  });

  it('C: the quoted workaround keeps working — this is not a breaking change', () => {
    expect(parse('@flows "#auth-lib.token-verify" -> #api -- "quoted"')).not.toBeNull();
  });

  it('D: unqualified Dotted.Path names are untouched', () => {
    const a = parse('@flows Authlib.Token -> #api -- "word chars only"');
    expect(a).toMatchObject({ source: 'Authlib.Token', target: '#api' });
  });

  it('E: cross-repo THREAT, which never parsed at all', () => {
    const a = parse('@exposes #api to #shared-lib.injection [high] -- "cross-repo threat"');
    expect(a).toMatchObject({ asset: '#api', threat: '#shared-lib.injection', severity: 'high' });
  });

  it('F: cross-repo CONTROL, same', () => {
    const a = parse('@mitigates #api against #sqli using #shared-lib.prepared -- "cross-repo control"');
    expect(a).toMatchObject({ asset: '#api', threat: '#sqli', control: '#shared-lib.prepared' });
  });
});

describe('D19 — qualified tags work in every reference position', () => {
  const CASES: [string, string][] = [
    ['@exposes #a.b to #c.d [high] -- "x"', 'exposes'],
    ['@mitigates #a.b against #c.d using #e.f -- "x"', 'mitigates'],
    ['@confirmed #c.d on #a.b [critical] -- "x"', 'confirmed'],
    ['@accepts #c.d on #a.b -- "x"', 'accepts'],
    ['@transfers #c.d from #a.b to #e.f -- "x"', 'transfers'],
    ['@flows #a.b -> #c.d via HTTPS -- "x"', 'flows'],
    ['@boundary between #a.b and #c.d (#bnd) -- "x"', 'boundary'],
    ['@validates #c.d for #a.b -- "x"', 'validates'],
    ['@audit #a.b -- "x"', 'audit'],
    ['@handles pii on #a.b -- "x"', 'handles'],
    ['@assumes #a.b -- "x"', 'assumes'],
    ['@owns security-team for #a.b -- "x"', 'owns'],
  ];

  it.each(CASES)('%s', (line, verb) => {
    const a = parse(line);
    expect(a, `did not parse: ${line}`).not.toBeNull();
    expect(a!.verb).toBe(verb);
  });

  it('multi-segment qualification parses', () => {
    expect(parse('@audit #org.repo.module -- "x"')).not.toBeNull();
  });

  it('a trailing dot is not swallowed', () => {
    // `#a.` must not match — each dot requires a segment after it.
    expect(parse('@audit #a. -- "x"')).toBeNull();
  });
});

describe('D19 — strictly a superset: nothing that parsed before stopped', () => {
  const PREVIOUSLY_VALID = [
    '@exposes #api to #sqli [critical] cwe:CWE-89 -- "x"',
    '@exposes App.API to #sqli [P0] -- "x"',
    '@mitigates App.API against #sqli using #prepared-stmts -- "x"',
    '@mitigates "My Asset" against "Some Threat" -- "x"',
    '@flows User -> App.API via HTTPS -- "x"',
    '@flows A -> B -> C -- "x"',
    '@threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "x"',
    '@control Parameterized_Queries (#prepared-stmts) -- "x"',
    '@asset App.API (#api) -- "x"',
    '@handles pii on App.API -- "x"',
    '@comment -- "x"',
  ];

  it.each(PREVIOUSLY_VALID)('%s', (line) => {
    expect(parse(line), `regressed: ${line}`).not.toBeNull();
  });

  it('a definition site still refuses a qualified id', () => {
    // You cannot DEFINE another repo's id in your own definitions file. ID_DEF
    // is deliberately not dotted.
    const a = parse('@asset App.API (#other-repo.api) -- "x"');
    // Either it fails outright or the dotted id is not captured as the id.
    expect(a === null || (a as { id?: string }).id !== 'other-repo.api').toBe(true);
  });
});

describe('D19 — crossRepoTag builds from the grammar', () => {
  it('produces a tag the grammar accepts', () => {
    const tag = crossRepoTag('auth-lib', 'token-verify');
    expect(tag).toBe('#auth-lib.token-verify');
    expect(CROSS_REPO_TAG_PATTERN.test(tag)).toBe(true);
    expect(parse(`@audit ${tag} -- "x"`)).not.toBeNull();
  });

  it('rejects a segment the grammar cannot express, instead of emitting bad docs', () => {
    expect(() => crossRepoTag('has space', 'x')).toThrow(/valid tag segment/);
    expect(() => crossRepoTag('ok', 'has.dot')).toThrow(/valid tag segment/);
  });
});

describe('D19 — every cross-repo example this codebase emits must parse', () => {
  /**
   * The anti-drift check. Hand-written examples of a grammar are how D19
   * happened, so any string this project shows a user as cross-repo syntax gets
   * executed here.
   */
  it('guardlink_workspace_info rules parse', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../src/mcp/server.ts', import.meta.url), 'utf-8');

    // The rules are built with crossRepoTag() rather than typed, so reconstruct
    // them the same way the tool does and parse the annotation in each.
    const ours = crossRepoTag('this-repo', 'component');
    const theirs = crossRepoTag('sibling', 'endpoint');
    const emitted = [
      `@flows ${ours} -> ${theirs} -- "what crosses"`,
      `@exposes ${ours} to ${crossRepoTag('sibling', 'injection')} [high] -- "why"`,
    ];
    for (const line of emitted) {
      expect(parse(line), `workspace_info example does not parse: ${line}`).not.toBeNull();
    }

    // And the source no longer contains the from/to form that never existed.
    expect(src).not.toMatch(/@flows #data from/);
  });

  it('the .guardlink/README.md template shows only parseable cross-repo syntax', async () => {
    const { guardlinkReadmeContent } = await import('../src/init/templates.js');
    const project = { name: 'demo', language: 'typescript', definitionsExt: '.ts', commentPrefix: '//' } as ProjectInfo;
    const text = guardlinkReadmeContent(project, {
      mode: 'inline', modeSource: 'config', model: null, annotationHash: null, mcpAtRoot: true,
    });

    const examples = text.match(/@(?:flows|exposes) #[\w.-]+[^\n`]*?-- "[^"]*"/g) ?? [];
    expect(examples.length).toBeGreaterThan(0);
    for (const ex of examples) {
      expect(parse(ex.trim()), `README example does not parse: ${ex}`).not.toBeNull();
    }
    expect(text).not.toMatch(/must be \*\*quoted\*\*/);
  });
});
