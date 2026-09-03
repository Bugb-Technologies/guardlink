/**
 * Spec §6.2, one fixture per rule and per language family. Each fixture is the
 * shape a real annotated file takes; the assertion is which code the claim on
 * a given line is bound to.
 */
import { describe, it, expect } from 'vitest';
import { parseStructure } from '../src/structure/index.js';

const TS = `/**
 * Module header.
 * @comment -- "header claim"
 */
import { resolve } from 'node:path';

/**
 * @mitigates #mcp against #path-traversal using #path-validation -- "resolve then prefix check"
 */
export function resolveRoot(p: string) {
  assertInside(root, p);
  return resolve(p);
}

// @exposes #mcp to #dos [low] -- "unbounded"
export default function handler(req: unknown) { return req; }

export const limit = 10;

export function outer() {
  // @exposes #cli to #dos [low] -- "statement claim"
  const q = run(limit);
  return q;
  // @comment -- "trailing inside block"
}

const a = 1;
// @comment -- "before a late import"
import b from 'b';
`;

describe('anchor resolution: TypeScript', () => {
  it('binds a doc-block claim to the exported function beneath it', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    const a = s.anchorForLine(8);
    expect(a.scope).toBe('symbol');
    expect(a.symbol).toBe('resolveRoot');
    expect(a.start_line).toBe(10);
    expect(a.end_line).toBe(13);
    expect(a.reason).toBeUndefined();
    s.dispose();
  });

  it('descends through export default', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    expect(s.anchorForLine(15)).toMatchObject({ scope: 'symbol', symbol: 'handler', start_line: 16, end_line: 16 });
    s.dispose();
  });

  it('treats the first comment in the file as a file-level claim', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    const a = s.anchorForLine(3);
    expect(a).toMatchObject({ scope: 'file', symbol: null, start_line: 1, reason: 'first-node' });
    expect(a.end_line).toBe(TS.split('\n').length);
    s.dispose();
  });

  it('binds a claim above a statement to that statement, named by its declarator', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    expect(s.anchorForLine(21)).toMatchObject({ scope: 'symbol', symbol: 'q', start_line: 22, end_line: 22 });
    s.dispose();
  });

  it('binds a trailing comment to its enclosing declaration', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    expect(s.anchorForLine(24)).toMatchObject({ scope: 'symbol', symbol: 'outer', start_line: 20, end_line: 25, reason: 'no-sibling' });
    s.dispose();
  });

  it('treats a comment followed by an import as a file-level claim', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    expect(s.anchorForLine(28)).toMatchObject({ scope: 'file', reason: 'import-sibling' });
    s.dispose();
  });

  it('resolves a symbol by name for external mode', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    expect(s.symbolNamed('resolveRoot')).toMatchObject({ scope: 'symbol', symbol: 'resolveRoot', start_line: 10 });
    expect(s.symbolNamed('nope')).toBeNull();
    s.dispose();
  });

  it('hashes only the anchor body, so edits elsewhere do not move it', async () => {
    const before = await parseStructure('/x/a.ts', TS);
    const h1 = before.anchorForLine(8).hash;
    before.dispose();
    const after = await parseStructure('/x/a.ts', TS.replace('const a = 1;', 'const a = 2;'));
    expect(after.anchorForLine(8).hash).toBe(h1);
    after.dispose();
  });

  it('throws on use after dispose, and dispose itself is safe to call twice', async () => {
    const s = await parseStructure('/x/a.ts', TS);
    s.dispose();
    expect(() => s.dispose()).not.toThrow();
    expect(() => s.anchorForLine(8)).toThrow(/dispose/);
  });
});

const PY = `import os

# @mitigates #api against #sqli using #prepared-stmts -- "bound params"
@route("/x")
def handler(req):
    return req

class Svc:
    # @exposes #api to #dos [low] -- "method claim"
    def run(self):
        return 1
`;

describe('anchor resolution: Python', () => {
  it('descends through a decorated definition', async () => {
    const s = await parseStructure('/x/a.py', PY);
    expect(s.anchorForLine(3)).toMatchObject({ scope: 'symbol', symbol: 'handler', start_line: 5, end_line: 6 });
    s.dispose();
  });
  it('binds a comment inside a class body to the method beneath it', async () => {
    const s = await parseStructure('/x/a.py', PY);
    expect(s.anchorForLine(9)).toMatchObject({ scope: 'symbol', symbol: 'run', start_line: 10, end_line: 11 });
    s.dispose();
  });
});

const GO = `package main

// @exposes #api to #sqli [high] -- "raw query"
func handler(q string) string {
\treturn q
}
`;

const RUST = `use std::fs;

// @exposes #api to #path-traversal [high] -- "unchecked path"
#[inline]
pub fn read(p: &str) -> String { fs::read_to_string(p).unwrap() }
`;

const JAVA = `package a;

public class Svc {
  /** @mitigates #api against #sqli using #prepared-stmts -- "PreparedStatement" */
  public String handler(String s) { return s; }
}
`;

const BASH = `#!/usr/bin/env bash
set -euo pipefail

# @exposes #cli to #cmd-injection [high] -- "eval of argv"
run() {
  eval "$1"
}
`;

const YAML = `# @exposes #cicd to #supply-chain [critical] -- "mutable action tags"
name: CI
on: push
# @comment -- "the job"
jobs:
  build:
    runs-on: ubuntu-latest
`;

describe('anchor resolution: other languages', () => {
  it('Go: skips the package clause and names the function', async () => {
    const s = await parseStructure('/x/a.go', GO);
    expect(s.anchorForLine(3)).toMatchObject({ scope: 'symbol', symbol: 'handler', start_line: 4, end_line: 6 });
    s.dispose();
  });
  it('Rust: skips an attribute between the comment and the item', async () => {
    const s = await parseStructure('/x/a.rs', RUST);
    expect(s.anchorForLine(3)).toMatchObject({ scope: 'symbol', symbol: 'read', start_line: 5, end_line: 5 });
    s.dispose();
  });
  it('Java: binds a block comment in a class body to the method', async () => {
    const s = await parseStructure('/x/A.java', JAVA);
    expect(s.anchorForLine(4)).toMatchObject({ scope: 'symbol', symbol: 'handler', start_line: 5, end_line: 5 });
    s.dispose();
  });
  it('Java: symbolNamed resolves the method, not the enclosing class body', async () => {
    const s = await parseStructure('/x/A.java', JAVA);
    expect(s.symbolNamed('handler')).toMatchObject({ scope: 'symbol', symbol: 'handler', start_line: 5, end_line: 5 });
    s.dispose();
  });
  it('Python: symbolNamed resolves the method, not the enclosing class block', async () => {
    const s = await parseStructure('/x/a.py', PY);
    expect(s.symbolNamed('run')).toMatchObject({ start_line: 10, end_line: 11 });
    s.dispose();
  });
  it('Bash: binds to the function beneath the comment', async () => {
    const s = await parseStructure('/x/a.sh', BASH);
    expect(s.anchorForLine(4)).toMatchObject({ scope: 'symbol', symbol: 'run', start_line: 5, end_line: 7 });
    s.dispose();
  });
  it('YAML: header comment is file scope, a later comment binds to the next top-level key', async () => {
    const s = await parseStructure('/x/ci.yml', YAML);
    expect(s.anchorForLine(1)).toMatchObject({ scope: 'file', reason: 'first-node' });
    expect(s.anchorForLine(4)).toMatchObject({ scope: 'block', symbol: 'jobs', start_line: 5, end_line: 7 });
    s.dispose();
  });
  it('unsupported extension: file scope, no grammar, plain-text hash', async () => {
    const s = await parseStructure('/x/q.sql', '-- @comment -- "x"\nSELECT 1;\n');
    expect(s.language).toBeNull();
    expect(s.anchorForLine(1)).toMatchObject({ scope: 'file', symbol: null, reason: 'no-grammar', start_line: 1, end_line: 3 });
    expect(s.anchorForLine(1).hash).toMatch(/^sha256-v1:/);
    expect(s.symbolNamed('anything')).toBeNull();
    s.dispose();
  });
  it('a language with no fetched grammar resolves to no-grammar', async () => {
    const s = await parseStructure('/x/a.swift', '// @comment -- "x"\nfunc f() {}\n');
    expect(s.language).toBe('swift');
    expect(s.anchorForLine(1)).toMatchObject({ scope: 'file', reason: 'no-grammar' });
    s.dispose();
  });
});
