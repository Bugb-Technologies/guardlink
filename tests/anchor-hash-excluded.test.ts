/**
 * The annotation hash answers "did the threat model change". An anchor is a
 * fact about the code beneath a claim, not about the claim, so attaching or
 * changing one must leave the hash alone — otherwise every `verify` run would
 * report the model as changed.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { computeAnnotationHash } from '../src/parser/annotation-hash.js';
import type { Anchor } from '../src/types/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const SOURCE = `/**
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

describe('annotation hash ignores anchors', () => {
  it('is identical with and without an anchor on every location', async () => {
    const root = await mkdtemp(join(tmpdir(), 'guardlink-anchor-hash-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);

    const { model } = await parseProject({ root, project: 'test', anchors: false });
    const before = computeAnnotationHash(model);

    const anchor: Anchor = { scope: 'symbol', symbol: 'login', start_line: 4, end_line: 4, hash: 'sha256-v1:deadbeef' };
    model.mitigations[0].location.anchor = anchor;
    model.assets[0].location.anchor = { ...anchor, scope: 'file', symbol: null };

    expect(computeAnnotationHash(model)).toBe(before);
  });
});
