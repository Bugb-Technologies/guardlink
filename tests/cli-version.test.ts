/**
 * Guards against version drift on every surface that reports one.
 *
 * The CLI previously hardcoded `.version('1.4.3')` in src/cli/index.ts, independent of
 * package.json. Bumping package.json (and publishing) did NOT update `guardlink --version`,
 * so a published 1.4.4 still reported 1.4.3. This test pins the invariant: the version the
 * CLI reports must equal package.json's version.
 *
 * The MCP server had the identical bug and outlived the CLI fix — it still announced
 * '1.4.3' at initialize time while package.json said 1.4.5 (D6).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getPackageVersion } from '../src/version.js';

describe('CLI version', () => {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

  it('there is no hardcoded version literal in the CLI source', () => {
    const src = readFileSync(join(repoRoot, 'src', 'cli', 'index.ts'), 'utf-8');
    // .version(...) must not be called with a raw string literal.
    expect(src).not.toMatch(/\.version\(\s*['"][\d.]+['"]\s*\)/);
    // It should call the runtime resolver instead.
    expect(src).toMatch(/\.version\(\s*getVersion\(\)\s*\)/);
  });

  it('getVersion() logic resolves package.json version (parity check)', () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8'));
    expect(typeof pkg.version).toBe('string');
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe('MCP server version (D6)', () => {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

  it('there is no hardcoded version literal in the MCP server source', () => {
    const src = readFileSync(join(repoRoot, 'src', 'mcp', 'server.ts'), 'utf-8');
    expect(src).not.toMatch(/version:\s*['"][\d.]+['"]/);
    expect(src).toMatch(/version:\s*getPackageVersion\(\)/);
  });

  it('getPackageVersion() equals package.json', () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8'));
    expect(getPackageVersion()).toBe(pkg.version);
  });
});
