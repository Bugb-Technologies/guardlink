/**
 * Fetch every pinned grammar WASM into grammars/.
 *
 * Runs under tsx (a devDependency) so it can import the one grammar table the
 * runtime uses. For each entry it runs `npm pack <package>@<version>` into a
 * temp dir — npm verifies the tarball against the registry's integrity hash —
 * extracts the single .wasm, and copies it to grammars/<language>.wasm.
 * MANIFEST.json records the version each file came from; an entry whose
 * manifest version already matches is skipped, so the script is cheap to run
 * before every test and build.
 *
 * Nothing here runs at guardlink runtime. The published package carries the
 * fetched files through package.json `files`.
 */
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GRAMMARS, GRAMMARS_DIR, GRAMMARS_UNAVAILABLE, grammarPath } from '../src/structure/grammars.js';

const manifestPath = join(GRAMMARS_DIR, 'MANIFEST.json');
mkdirSync(GRAMMARS_DIR, { recursive: true });
const manifest: Record<string, string> = existsSync(manifestPath)
  ? JSON.parse(readFileSync(manifestPath, 'utf8'))
  : {};

let fetched = 0;
for (const [language, src] of Object.entries(GRAMMARS)) {
  const target = grammarPath(language);
  if (existsSync(target) && manifest[language] === src.version) continue;

  const work = mkdtempSync(join(tmpdir(), 'guardlink-grammar-'));
  try {
    const tgz = execFileSync('npm', ['pack', `${src.package}@${src.version}`, '--pack-destination', work, '--silent'], {
      encoding: 'utf8',
    }).trim().split('\n').pop()!;
    execFileSync('tar', ['-xzf', join(work, tgz), '-C', work, `package/${src.file}`]);
    copyFileSync(join(work, 'package', src.file), target);
    manifest[language] = src.version;
    fetched++;
    console.log(`build-grammars: ${language} ← ${src.package}@${src.version}/${src.file}`);
  } catch (err) {
    if (existsSync(target)) {
      console.warn(`build-grammars: could not refresh ${language} (${(err as Error).message}); keeping the existing file`);
    } else {
      console.error(`build-grammars: failed to fetch ${language} from ${src.package}@${src.version}: ${(err as Error).message}`);
      process.exitCode = 1;
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

for (const language of GRAMMARS_UNAVAILABLE) {
  if (existsSync(grammarPath(language))) console.log(`build-grammars: ${language} present (hand-placed); keeping it`);
}

writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
console.log(`build-grammars: ${fetched} fetched, ${Object.keys(GRAMMARS).length - fetched} already current`);
