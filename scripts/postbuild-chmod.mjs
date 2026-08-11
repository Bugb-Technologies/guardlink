// @g.comment -- "tsc emits every .js at 0644, so a plain `tsc` build leaves the bin entries
//   non-executable. `npm install`/`npm link` set the exec bit at link time, so a released or
//   freshly-installed guardlink is fine — but an in-place `npm run build` inside an already-linked
//   package (the local dev loop) regenerates dist/cli/index.js without the bit and never re-links,
//   which is how `guardlink` ends up on PATH as a symlink to a non-executable file and spawns with
//   EACCES. This restores +x after every build. The bins are read from package.json so this never
//   drifts if an entry is added or renamed."
import { chmodSync, existsSync } from "node:fs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const bins = Object.values(pkg.bin ?? {});

if (bins.length === 0) {
  console.warn("postbuild-chmod: package.json has no bin entries — nothing to mark executable");
}

for (const relative of bins) {
  const target = join(root, relative);
  if (!existsSync(target)) {
    // A missing bin is a build that did not run, or a bin removed without a rebuild — loud, not fatal.
    console.warn(`postbuild-chmod: ${relative} not found (did the build run?) — skipped`);
    continue;
  }
  try {
    // rwxr-xr-x: executable for everyone, writable only by the owner. Same shape npm's own linker sets.
    chmodSync(target, 0o755);
    console.log(`postbuild-chmod: +x ${relative}`);
  } catch (err) {
    // chmod is a no-op concept on Windows; never fail a build over it there.
    console.warn(`postbuild-chmod: could not chmod ${relative} (${err?.code ?? err}) — skipped`);
  }
}
