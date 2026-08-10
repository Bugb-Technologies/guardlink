/**
 * GL-101 — annotation content hash.
 *
 * The four properties in the story, each as an executable claim. The fourth —
 * inline and external authoring of the same logical model hashing identically —
 * is the correctness test for the GL-507 migration, so it is built from real
 * files on disk and run through the real parser rather than hand-assembled.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import type { ThreatModel } from '../src/types/index.js';

const DEFINITIONS = `/**
 * @asset App.Auth (#auth) -- "Authentication surface"
 * @asset App.DB (#db) -- "Database layer"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @threat Credential_Stuffing (#credstuff) [high] -- "Bulk credential replay"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 * @control Rate_Limiting (#rate-limit) -- "Request throttling"
 */
export {};
`;

/** The same logical annotation set, written three ways. */
const AUTH_ANNOTATIONS = [
  '@exposes #auth to #credstuff [high] -- "Login accepts unlimited attempts"',
  '@mitigates #auth against #credstuff using #rate-limit -- "100 req/15min"',
  '@flows User -> #auth via HTTPS -- "Login request path"',
  '@handles pii on #auth -- "Processes email and session token"',
  '@owns security-team for #auth -- "Team responsible for reviews"',
  '@comment -- "Session tokens are 32-byte random"',
];

const AUTH_BODY = `export function login(email: string, password: string): boolean {
  return email.length > 0 && password.length > 0;
}
`;

async function scratch(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `guardlink-${prefix}-`));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  return root;
}

async function hashOf(root: string): Promise<string> {
  const { model } = await parseProject({ root, project: 'test' });
  return computeAnnotationHash(model);
}

/** Inline: annotations live in the source file's doc block. */
async function inlineRepo(annotations: string[], body = AUTH_BODY, padding = ''): Promise<string> {
  const root = await scratch('hash-inline');
  const doc = ['/**', ' * Authentication entry point.', ' *',
    ...annotations.map(a => ` * ${a}`), ' */'].join('\n');
  await writeFile(join(root, 'src', 'auth.ts'), `${doc}\n${padding}${body}`);
  return root;
}

/** External: the source file is annotation-free; a .gal sidecar carries them. */
async function externalRepo(annotations: string[], sourceLine = 8): Promise<string> {
  const root = await scratch('hash-external');
  await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
  // Deliberately a *different* doc block and a different line count from the
  // inline repo — only the logical content is meant to match.
  await writeFile(join(root, 'src', 'auth.ts'), `// Authentication entry point.\n${AUTH_BODY}`);
  await writeFile(
    join(root, '.guardlink', 'annotations', 'src', 'auth.ts.gal'),
    [`@source file:src/auth.ts line:${sourceLine} symbol:login`, ...annotations].join('\n') + '\n',
  );
  return root;
}

describe('computeAnnotationHash — shape', () => {
  it('is a versioned sha256 string', async () => {
    const root = await inlineRepo(AUTH_ANNOTATIONS);
    expect(await hashOf(root)).toMatch(/^sha256-v\d+:[0-9a-f]{64}$/);
    await rm(root, { recursive: true, force: true });
  });

  it('is deterministic across repeated computation', async () => {
    const root = await inlineRepo(AUTH_ANNOTATIONS);
    expect(await hashOf(root)).toBe(await hashOf(root));
    await rm(root, { recursive: true, force: true });
  });
});

describe('property 1 — reordering annotations within a file does not change the hash', () => {
  it('reversing the annotation block holds the hash', async () => {
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    const b = await inlineRepo([...AUTH_ANNOTATIONS].reverse());
    expect(await hashOf(b)).toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });
});

describe('property 2 — reformatting surrounding code does not change the hash', () => {
  it('adding blank lines and reindenting the function body holds the hash', async () => {
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    const reformatted = `export function login(\n  email: string,\n  password: string,\n): boolean {\n\n\n      return email.length > 0\n        && password.length > 0;\n}\n`;
    const b = await inlineRepo(AUTH_ANNOTATIONS, reformatted, '\n\n\n');
    expect(await hashOf(b)).toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });

  it('renaming an unannotated sibling file does not change the hash', async () => {
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    await writeFile(join(a, 'src', 'helper-one.ts'), 'export const x = 1;\n');
    const withOne = await hashOf(a);
    await rm(join(a, 'src', 'helper-one.ts'));
    await writeFile(join(a, 'src', 'helper-two.ts'), 'export const x = 1;\n');
    expect(await hashOf(a)).toBe(withOne);
    await rm(a, { recursive: true, force: true });
  });
});

describe('property 3 — adding, editing or deleting an annotation changes the hash', () => {
  it('adding one changes it', async () => {
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    const b = await inlineRepo([...AUTH_ANNOTATIONS, '@audit #auth -- "Needs crypto review"']);
    expect(await hashOf(b)).not.toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });

  it('editing a description changes it', async () => {
    const edited = AUTH_ANNOTATIONS.map(x =>
      x.startsWith('@exposes') ? '@exposes #auth to #credstuff [high] -- "Login is rate limited after all"' : x);
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    const b = await inlineRepo(edited);
    expect(await hashOf(b)).not.toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });

  it('editing a severity changes it', async () => {
    const edited = AUTH_ANNOTATIONS.map(x =>
      x.startsWith('@exposes') ? x.replace('[high]', '[low]') : x);
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    const b = await inlineRepo(edited);
    expect(await hashOf(b)).not.toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });

  it('deleting one changes it', async () => {
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    const b = await inlineRepo(AUTH_ANNOTATIONS.slice(0, -1));
    expect(await hashOf(b)).not.toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });

  it('deleting one of two identical annotations changes it (multiset, not set)', async () => {
    const dup = '@audit #auth -- "Needs review"';
    const a = await inlineRepo([...AUTH_ANNOTATIONS, dup, dup]);
    const b = await inlineRepo([...AUTH_ANNOTATIONS, dup]);
    expect(await hashOf(b)).not.toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });

  it('moving an annotation to a different file changes it', async () => {
    const a = await inlineRepo(AUTH_ANNOTATIONS);
    const b = await inlineRepo(AUTH_ANNOTATIONS.slice(0, -1));
    await writeFile(join(b, 'src', 'other.ts'),
      `/**\n * ${AUTH_ANNOTATIONS[AUTH_ANNOTATIONS.length - 1]}\n */\nexport const y = 2;\n`);
    expect(await hashOf(b)).not.toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });
});

describe('property 4 — inline and external authoring hash identically (GL-507 gate)', () => {
  it('the same logical model hashes the same in both modes', async () => {
    const inline = await inlineRepo(AUTH_ANNOTATIONS);
    const external = await externalRepo(AUTH_ANNOTATIONS);

    // Precondition: the two repos really do differ ON DISK — one stores
    // annotations in source comments, the other in sidecars — otherwise this
    // proves nothing.
    const { model: im } = await parseProject({ root: inline, project: 'test' });
    const { model: em } = await parseProject({ root: external, project: 'test' });
    expect(em.exposures[0].location.origin_file).toMatch(/\.gal$/);
    expect(im.exposures[0].location.origin_file).toBeUndefined();

    // And the counts now AGREE. This assertion was the inverse until GL-502:
    // source_files was 7 vs 9 and annotated_files 3 vs 5, because the sidecar
    // was counted as source and the file it annotated was counted twice.
    expect(em.source_files).toBe(im.source_files);
    expect(em.annotated_files.length).toBe(im.annotated_files.length);
    expect(em.coverage.coverage_percent).toBe(im.coverage.coverage_percent);
    expect(em.annotated_files.some(x => x.endsWith('.gal'))).toBe(false);
    expect(im.annotations_parsed).toBe(em.annotations_parsed);

    expect(computeAnnotationHash(em)).toBe(computeAnnotationHash(im));

    await rm(inline, { recursive: true, force: true });
    await rm(external, { recursive: true, force: true });
  });

  it('the hash ignores which line the @source block points at', async () => {
    const a = await externalRepo(AUTH_ANNOTATIONS, 2);
    const b = await externalRepo(AUTH_ANNOTATIONS, 9);
    expect(await hashOf(b)).toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });

  it('but an edit made only in the .gal still moves the hash', async () => {
    const a = await externalRepo(AUTH_ANNOTATIONS);
    const b = await externalRepo([...AUTH_ANNOTATIONS, '@assumes #auth -- "Runs behind a WAF"']);
    expect(await hashOf(b)).not.toBe(await hashOf(a));
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  });
});

describe('field-boundary safety', () => {
  it('does not collide when content shifts across a field boundary', () => {
    const base = (): ThreatModel => ({
      version: '1.0.0', project: 't', generated_at: '', source_files: 0,
      annotated_files: [], unannotated_files: [], annotations_parsed: 0,
      assets: [], threats: [], controls: [], mitigations: [], exposures: [],
      confirmed: [], acceptances: [], transfers: [], flows: [], boundaries: [],
      validations: [], audits: [], ownership: [], data_handling: [],
      assumptions: [], shields: [], features: [], comments: [],
      coverage: { total_symbols: 0, annotated_symbols: 0, coverage_percent: 0, unannotated_critical: [] },
    });
    const loc = { file: 'a.ts', line: 1 };
    const one = base();
    one.audits = [{ asset: '#ab', description: 'c', location: loc }];
    const two = base();
    two.audits = [{ asset: '#a', description: 'bc', location: loc }];
    expect(computeAnnotationHash(one)).not.toBe(computeAnnotationHash(two));
  });
});

// ─── @actor / @entitles are part of the content ──────────────────────
//
// The hash is what `guardlink migrate` uses to prove it did not change the
// threat model. Until v2 these two verbs were absent from the record set, so a
// migration could drop or rewrite every entitlement in a repo and the gate
// would still report the model unchanged — a silent all-clear, which is exactly
// the failure mode the entitlement design exists to prevent (§2).
describe('GL-101 — actor and entitlement content is hashed', () => {
  const ACTOR = '@actor Namespace_Admin (#ns-admin) -- "Administers one namespace"';
  const ENTITLES = '@entitles #ns-admin to configure-archival on #auth against #sqli -- "By design. Authz: src/authz.ts:12"';

  it('an added entitlement changes the hash', async () => {
    const without = await inlineRepo(AUTH_ANNOTATIONS);
    const with_ = await inlineRepo([...AUTH_ANNOTATIONS, ACTOR, ENTITLES]);
    try {
      expect(await hashOf(with_)).not.toBe(await hashOf(without));
    } finally {
      await rm(without, { recursive: true, force: true });
      await rm(with_, { recursive: true, force: true });
    }
  });

  it('a rewritten entitlement rationale changes the hash', async () => {
    const a = await inlineRepo([...AUTH_ANNOTATIONS, ACTOR, ENTITLES]);
    const b = await inlineRepo([...AUTH_ANNOTATIONS, ACTOR,
      '@entitles #ns-admin to configure-archival on #auth against #sqli -- "By design. Authz: src/other.ts:99"']);
    try {
      expect(await hashOf(a)).not.toBe(await hashOf(b));
    } finally {
      await rm(a, { recursive: true, force: true });
      await rm(b, { recursive: true, force: true });
    }
  });

  it('a dropped entitlement changes the hash — the migration gate depends on this', async () => {
    const full = await inlineRepo([...AUTH_ANNOTATIONS, ACTOR, ENTITLES]);
    const dropped = await inlineRepo([...AUTH_ANNOTATIONS, ACTOR]);
    try {
      expect(await hashOf(full)).not.toBe(await hashOf(dropped));
    } finally {
      await rm(full, { recursive: true, force: true });
      await rm(dropped, { recursive: true, force: true });
    }
  });

  it('is stable when the same entitlement is written twice over', async () => {
    const a = await inlineRepo([...AUTH_ANNOTATIONS, ACTOR, ENTITLES]);
    const b = await inlineRepo([...AUTH_ANNOTATIONS, ACTOR, ENTITLES]);
    try {
      expect(await hashOf(a)).toBe(await hashOf(b));
    } finally {
      await rm(a, { recursive: true, force: true });
      await rm(b, { recursive: true, force: true });
    }
  });
});
