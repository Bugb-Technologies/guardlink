/**
 * GuardLink — Package version resolution.
 *
 * Read at runtime from the package's own package.json so a published build can
 * never report a version it is not. The CLI already does this (`--version` used
 * to be a hardcoded literal that silently fell out of sync); this is the same
 * technique behind one export so the next surface that needs it does not invent
 * a third copy.
 *
 * @flows PackageJson -> #cli via readFileSync -- "Version string read from package.json"
 * @comment -- "Resolved relative to this module, so it is correct from both src/ and dist/"
 */

import { readFileSync } from 'node:fs';

/**
 * The version from package.json, or '0.0.0' if it cannot be read.
 *
 * This module compiles to `dist/version.js`, so package.json is one level up in
 * both the source tree and the build output.
 */
export function getPackageVersion(): string {
  try {
    const pkgUrl = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgUrl, 'utf-8'));
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}
