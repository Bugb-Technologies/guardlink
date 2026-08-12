/**
 * Guards against version drift on every surface that reports one.
 *
 * The CLI previously hardcoded `.version('1.4.3')` in src/cli/index.ts, independent of
 * package.json. Bumping package.json (and publishing) did NOT update `guardlink --version`,
 * so a published 1.4.4 still reported 1.4.3. This test pins the invariant: the version the
 * CLI reports must equal package.json's version.
 *
 * The MCP server had the identical bug and outlived the CLI fix — it still announced
 * '1.4.3' at initialize time while package.json said 1.4.5 (D6). SARIF then turned out
 * to carry a third hardcoded '1.4.3' of its own.
 *
 * The pattern behind all three was duplication, not the literals. Four separate copies
 * of "read package.json at runtime" existed, and one of them (src/tui/index.ts) resolved
 * via `new URL(...).pathname`, which percent-encodes — so the TUI reported v0.0.0 from
 * any install path containing a space while the CLI beside it reported the truth.
 * They are one function now, and the middle block here is what keeps them one.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getPackageVersion } from '../src/version.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Every .ts file under src/, as repo-relative paths. */
function sourceFiles(dir: string = join(repoRoot, 'src')): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(full));
    else if (entry.name.endsWith('.ts')) out.push(relative(repoRoot, full));
  }
  return out;
}

describe('CLI version', () => {
  it('there is no hardcoded version literal in the CLI source', () => {
    const src = readFileSync(join(repoRoot, 'src', 'cli', 'index.ts'), 'utf-8');
    expect(src).not.toMatch(/\.version\(\s*['"][\d.]+['"]\s*\)/);
    // It must call the one shared resolver, not a local re-implementation.
    expect(src).toMatch(/\.version\(\s*getPackageVersion\(\)\s*\)/);
  });

  it('getPackageVersion() resolves package.json version (parity check)', () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8'));
    expect(typeof pkg.version).toBe('string');
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(getPackageVersion()).toBe(pkg.version);
  });
});

describe('one version resolver, not four', () => {
  // A package.json read anchored on the module's own location. The CLI's read of
  // the *project's* package.json is anchored on a caller-supplied root instead,
  // so it does not match here and is not a duplicate of this.
  const OWN_PACKAGE_READ = [
    /import\.meta\.url[\s\S]{0,120}package\.json/,
    /package\.json[\s\S]{0,120}import\.meta\.url/,
  ];

  it('src/version.ts is the only module that reads its own package.json', () => {
    const offenders = sourceFiles()
      .filter(rel => rel !== join('src', 'version.ts'))
      .filter(rel => {
        const src = readFileSync(join(repoRoot, rel), 'utf-8');
        return OWN_PACKAGE_READ.some(re => re.test(src));
      });
    expect(offenders).toEqual([]);
  });

  it('no module resolves its own path via URL.pathname, which percent-encodes', () => {
    const offenders = sourceFiles().filter(rel =>
      /new URL\([^)]*import\.meta\.url[^)]*\)\s*\.pathname/.test(
        readFileSync(join(repoRoot, rel), 'utf-8'),
      ),
    );
    expect(offenders).toEqual([]);
  });
});

describe('MCP server version (D6)', () => {
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

describe('SARIF driver version', () => {
  it('is dynamic — it read 1.4.3 while the package said 1.4.5', () => {
    const src = readFileSync(join(repoRoot, 'src', 'analyzer', 'sarif.ts'), 'utf-8');
    // The SARIF *spec* version (2.1.0) is legitimately static; the driver version is not.
    expect(src).toMatch(/name: 'GuardLink',\s*\n\s*version: getPackageVersion\(\)/);
  });
});
