// tests/claim-key.test.ts
/**
 * A claim key names a claim across edits to everything that is not the claim:
 * the line it sits on, the code beneath it, the severity its threat resolves
 * to. It changes when the claim's own words change.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { relationRecords } from '../src/parser/claim-key.js';

const DEFINITIONS = (sev: string) => `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [${sev}] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

async function repo(definitions: string, source: string) {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-key-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), definitions);
  await writeFile(join(root, 'src', 'api.ts'), source);
  const { model } = await parseProject({ root, project: 'test', anchors: false });
  return relationRecords(model);
}

const SRC = `/**
 * @exposes #api to #sqli -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 * @comment -- "same text"
 * @comment -- "same text"
 */
export function login(email: string) { return email; }
`;

describe('claim keys', () => {
  it('lists relations only, with verb, key, text and demotability', async () => {
    const recs = await repo(DEFINITIONS('critical'), SRC);
    expect(recs.map(r => r.verb)).toEqual(['mitigates', 'exposes', 'comment', 'comment']);
    expect(recs.find(r => r.verb === 'mitigates')).toMatchObject({
      claim: '#api against #sqli using #prepared-stmts', demotable: true,
    });
    expect(recs.find(r => r.verb === 'exposes')).toMatchObject({ claim: '#api to #sqli', demotable: false });
    for (const r of recs) expect(r.key).toMatch(/^[0-9a-f]{64}:\d+$/);
  });

  it('is stable when lines move and when the threat severity changes', async () => {
    const a = await repo(DEFINITIONS('critical'), SRC);
    const b = await repo(DEFINITIONS('low'), '\n\n\n' + SRC);
    expect(b.map(r => r.key)).toEqual(a.map(r => r.key));
  });

  it('changes when the description changes', async () => {
    const a = await repo(DEFINITIONS('critical'), SRC);
    const b = await repo(DEFINITIONS('critical'), SRC.replace('Parameterized via pg', 'Parameterized via knex'));
    const keyOf = (recs: typeof a) => recs.find(r => r.verb === 'mitigates')!.key;
    expect(keyOf(b)).not.toBe(keyOf(a));
    expect(b.find(r => r.verb === 'exposes')!.key).toBe(a.find(r => r.verb === 'exposes')!.key);
  });

  it('gives identical claims in one file distinct ordinals in document order', async () => {
    const recs = await repo(DEFINITIONS('critical'), SRC);
    const comments = recs.filter(r => r.verb === 'comment');
    expect(comments[0].key.replace(/:\d+$/, '')).toBe(comments[1].key.replace(/:\d+$/, ''));
    expect(comments.map(r => r.key.split(':')[1])).toEqual(['0', '1']);
    expect(comments[0].location.line).toBeLessThan(comments[1].location.line);
  });
});
