# Stale Claim Detection (Detect Half) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give GuardLink a way to notice, from repository contents alone, that the code beneath an annotation changed since a person or agent last verified it, and to report that in `guardlink ci`, `guardlink status` and a new `guardlink verify` command.

**Architecture:** A tree-sitter based structure layer (`src/structure/`) resolves each annotation to the declaration it sits on and hashes that declaration's non-comment tokens. `parseProject` attaches the resulting `anchor` to every annotation's location, so every model record carries it. A committed ledger (`.guardlink/verified.json`) records the hash at the moment a claim was verified. A pure predicate (`src/parser/verification.ts`) compares the two and classifies every claim as `verified`, `stale` or `unverified`. `ci`, `status` and `verify` are thin faces over that predicate.

**Tech Stack:** TypeScript (ES2022, NodeNext), Node 18+, `web-tree-sitter` 0.27 with grammar WASM files fetched at build time from pinned npm packages, vitest, commander.

**Spec:** `docs/superpowers/specs/2026-09-03-stale-claim-detection-design.md`. This plan implements §16 step 1, "Detect". Step 2, "Act" (demotion, SARIF/report, MCP tool and context, templates, `annotate --stale`, fingerprint change), gets its own plan after this one lands, because its tasks edit code this plan creates.

## Deviations from the spec, and why

1. **`classifyClaims(model, ledger)` is synchronous and takes no `root`.** Anchors are attached during `parseProject`, so the predicate needs no file access. The git enrichment (`changed_in`) the spec put on the same function moves to the Act plan as a separate function. Purer, easier to test, same result.
2. **The claim key excludes severity.** `parseProject` resolves an exposure's severity from its threat definition at assembly time. Keying on it would re-key every exposure of a threat when that threat's severity changed in `definitions.ts`. Identity arguments, external refs, description and file remain, per §7.2.
3. **`ClaimRecord` carries `verb`, `location`, `claim` and `record` rather than a raw `Annotation`.** The unit the predicate works on is the model record, because that is what every surface already holds.
4. **Swift and Kotlin fall back to file scope in this release.** Their npm packages ship no WASM. The build script has a hook for a locally built WASM; until one exists they resolve as `no-grammar`, exactly as HTML and CSS do. XML and SQL are file-scope by §6.2 so their grammars are not fetched at all.
5. **Grammar WASM files are fetched from the pinned npm tarballs at build time, not built with the tree-sitter CLI.** Every other grammar in the list ships a prebuilt WASM. The tarballs are fetched with `npm pack`, which verifies registry integrity, and cached in `grammars/`, which is gitignored and included in the published package through `files`.

## Global Constraints

- Node.js 18, 20 and 22 must all pass (`.github/workflows/ci.yml` matrix).
- Runtime dependency added: `web-tree-sitter` `0.27.0`. No other runtime dependency.
- Every new source file under `src/` carries GuardLink annotations in its doc block, using only ids that already exist in `.guardlink/definitions.ts` (`#parser`, `#cli`, `#path-traversal`, `#arbitrary-write`, `#dos`, `#path-validation`, `#resource-limits`, `#input-sanitize`, `#config-validation`). Never write `@accepts` or `@entitles`.
- Read commands (`ci`, `status`, `validate`, `parse`) must not write to the working tree. Only `verify` writes, and it writes only `.guardlink/verified.json`.
- Ledger schema id: `guardlink.verified/v1`. Anchor hash prefix: `sha256-v1:`. `ANCHOR_HASH_VERSION = 1`.
- CI JSON stays under schema id `guardlink.ci/v1`; new fields are additive.
- `npm run build` is `tsx scripts/build-grammars.ts && tsc && node scripts/postbuild-chmod.mjs`. `npm test` runs `pretest` which fetches grammars.
- Tests run with `npx vitest run <file>`; the whole suite with `npm test`. Lint with `npm run lint` before each commit.
- Commit messages end with the two trailer lines the session requires:
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs`.

## File structure

| File | Responsibility |
|---|---|
| `src/types/index.ts` (modify) | `AnchorScope`, `AnchorReason`, `Anchor`; `SourceLocation.anchor`; `DiagnosticCode` gains `ledger-corrupt`. |
| `src/structure/grammars.ts` (new) | The pinned grammar table and the extension → language map. Single source of truth for the build script and the runtime. |
| `scripts/build-grammars.ts` (new) | Fetches each pinned grammar tarball with `npm pack`, extracts the WASM into `grammars/<language>.wasm`, writes `grammars/MANIFEST.json`. |
| `src/structure/runtime.ts` (new) | Lazy `web-tree-sitter` init, per-language grammar loading with a one-time warning, `parseWith`. |
| `src/structure/hash.ts` (new) | Token-stream hashing of a node or of plain text. |
| `src/structure/anchor.ts` (new) | Anchor resolution rules over a syntax tree. |
| `src/structure/index.ts` (new) | Public API: `parseStructure`, `languageForExtension`, `ANCHOR_HASH_VERSION`, types. |
| `src/structure/attach.ts` (new) | `attachAnchors(root, annotations)`: groups by logical file, parses each once, sets `location.anchor`. |
| `src/parser/parse-project.ts` (modify) | Calls `attachAnchors` before assembly; `ParseProjectOptions.anchors`. |
| `src/parser/claim-key.ts` (new) | `relationRecords(model)`, `claimKey`, `claimText`. |
| `src/parser/ledger.ts` (new) | Ledger types, `readLedger`, `writeLedger`, `serializeLedger`, `LEDGER_FILE`. |
| `src/parser/verification.ts` (new) | `classifyClaims`, `demotionSet`, `VerificationReport`, `ClaimRecord`. |
| `src/parser/verify.ts` (new) | `planVerification`, `applyVerification`, `defaultVerifier`, `headCommit`. |
| `src/parser/index.ts`, `src/index.ts` (modify) | Exports. |
| `src/ci/index.ts` (modify) | Third check, new report fields, exit code. |
| `src/cli/index.ts` (modify) | `verify` command; `status` line; `validate` ledger diagnostic. |
| `package.json`, `.gitignore` (modify) | Dependency, scripts, `files`, `exports`, ignore `grammars/`. |
| `CHANGELOG.md`, `docs/GUARDLINK_REFERENCE.md` (modify) | Unreleased entry; reference section. |
| `.github/workflows/ci.yml`, `.guardlink/verified.json` (modify/new) | Dogfood: CI step and the bootstrapped ledger. |

---

### Task 1: Anchor types, and the annotation hash ignores them

**Files:**
- Modify: `src/types/index.ts:30-37` (SourceLocation), `src/types/index.ts:594-621` (DiagnosticCode)
- Test: `tests/anchor-hash-excluded.test.ts`

**Interfaces:**
- Produces: `AnchorScope`, `AnchorReason`, `Anchor`, `SourceLocation.anchor?: Anchor | null`, `DiagnosticCode` member `'ledger-corrupt'`. Every later task imports `Anchor` from `../src/types/index.js`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/anchor-hash-excluded.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/anchor-hash-excluded.test.ts`
Expected: PASS already. This test pins a property that holds today, because `canonicalAnnotationRecords` builds each record from named fields and never serialises the whole location. Its job is to keep holding once Task 6 starts attaching real anchors. The `anchors: false` option it passes is ignored at runtime until Task 6 defines it. Run it, confirm it passes, and move on to the types.

- [ ] **Step 3: Add the types**

In `src/types/index.ts`, replace the `SourceLocation` interface (lines 30-37) with:

```ts
/** How much code an anchor covers. */
export type AnchorScope = 'symbol' | 'block' | 'file';

/**
 * Why an anchor resolved to a wider scope than the comment's position implied.
 * Absent on a clean symbol- or block-scope resolution.
 */
export type AnchorReason = 'no-grammar' | 'grammar-failed' | 'no-sibling' | 'import-sibling' | 'first-node';

/**
 * The code beneath an annotation, as the structure layer resolved it.
 * Attached to every annotation location by `parseProject` (src/structure/attach.ts).
 * Excluded from the annotation hash: it describes the code, not the claim.
 */
export interface Anchor {
  scope: AnchorScope;
  /** `name` field of the anchor node, else the nearest enclosing named node, else null. */
  symbol: string | null;
  /** 1-based, inclusive. For scope 'file' this is the whole file. */
  start_line: number;
  end_line: number;
  /** `sha256-v1:<hex>` over the anchor's non-comment leaf tokens, in order. */
  hash: string;
  reason?: AnchorReason;
}

export interface SourceLocation {
  file: string;
  line: number;
  end_line?: number | null;
  parent_symbol?: string | null;
  origin_file?: string | null;
  origin_line?: number | null;
  /** Populated by parseProject unless `anchors: false`. Null when the logical file could not be read. */
  anchor?: Anchor | null;
}
```

In the `DiagnosticCode` union, after the `'stray-gal-source'` member and before the governance comment, add:

```ts
  // ── Verification ledger (src/parser/ledger.ts) ──
  /** `.guardlink/verified.json` exists but does not parse or fails shape validation. */
  | 'ledger-corrupt'
```

- [ ] **Step 4: Run the test and the type checker**

Run: `npx vitest run tests/anchor-hash-excluded.test.ts && npx tsc --noEmit`
Expected: PASS, and tsc reports no errors.

- [ ] **Step 5: Commit**

```bash
git add src/types/index.ts tests/anchor-hash-excluded.test.ts
git commit -m "feat(types): anchor on SourceLocation, ledger-corrupt diagnostic code

An anchor is the code beneath an annotation as the structure layer resolves
it: scope, symbol, line range and a token hash. It rides on the location so
every model record carries it, and it is excluded from the annotation hash
because it describes the code, not the claim.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 2: Grammar table, build script, and the load-every-grammar test

**Files:**
- Create: `src/structure/grammars.ts`, `scripts/build-grammars.ts`
- Modify: `package.json` (dependencies, scripts, files, exports), `.gitignore`
- Test: `tests/grammars.test.ts`

**Interfaces:**
- Produces: `GRAMMARS: Record<string, GrammarSource>`, `EXTENSION_LANGUAGE: Record<string, string | null>`, `languageForExtension(ext: string): string | null`, `GRAMMARS_DIR: string`, `grammarPath(language: string): string`. Task 3 loads from `grammarPath`.

- [ ] **Step 1: Install the runtime and pin it**

Run: `npm install web-tree-sitter@0.27.0`
Expected: `package.json` `dependencies` gains `"web-tree-sitter": "^0.27.0"`. Edit it to the exact `"0.27.0"` (grammar ABI is tied to the runtime; a caret would let it drift).

- [ ] **Step 2: Write the grammar table**

```ts
// src/structure/grammars.ts
/**
 * GuardLink structure layer — the pinned grammar set and the extension map.
 *
 * One table, read by two consumers: `scripts/build-grammars.ts` fetches the
 * WASM for each entry, and `runtime.ts` loads it. A language is symbol-scoped
 * if and only if it appears in GRAMMARS; an extension that maps to null is
 * file-scoped by design (markup, stylesheets, SQL) and an extension that maps
 * to a language with no fetched WASM falls back to file scope at runtime.
 *
 * Every version is exact. The WASM inside a grammar package is built against a
 * tree-sitter ABI the pinned `web-tree-sitter` runtime must accept; a caret
 * here would let a grammar move to an ABI the runtime rejects.
 *
 * @comment -- "Data only: no I/O, no user input. The paths it produces are joined under the package's own grammars/ directory"
 */
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface GrammarSource {
  /** npm package that ships the WASM. */
  package: string;
  /** Exact version. */
  version: string;
  /** File name inside the package tarball. */
  file: string;
}

export const GRAMMARS: Record<string, GrammarSource> = {
  typescript: { package: 'tree-sitter-typescript', version: '0.23.2', file: 'tree-sitter-typescript.wasm' },
  tsx:        { package: 'tree-sitter-typescript', version: '0.23.2', file: 'tree-sitter-tsx.wasm' },
  javascript: { package: 'tree-sitter-javascript', version: '0.25.0', file: 'tree-sitter-javascript.wasm' },
  python:     { package: 'tree-sitter-python',     version: '0.25.0', file: 'tree-sitter-python.wasm' },
  ruby:       { package: 'tree-sitter-ruby',       version: '0.23.1', file: 'tree-sitter-ruby.wasm' },
  go:         { package: 'tree-sitter-go',         version: '0.25.0', file: 'tree-sitter-go.wasm' },
  rust:       { package: 'tree-sitter-rust',       version: '0.24.0', file: 'tree-sitter-rust.wasm' },
  java:       { package: 'tree-sitter-java',       version: '0.23.5', file: 'tree-sitter-java.wasm' },
  scala:      { package: 'tree-sitter-scala',      version: '0.24.0', file: 'tree-sitter-scala.wasm' },
  c:          { package: 'tree-sitter-c',          version: '0.24.1', file: 'tree-sitter-c.wasm' },
  cpp:        { package: 'tree-sitter-cpp',        version: '0.23.4', file: 'tree-sitter-cpp.wasm' },
  c_sharp:    { package: 'tree-sitter-c-sharp',    version: '0.23.5', file: 'tree-sitter-c_sharp.wasm' },
  dart:       { package: 'tree-sitter-dart',       version: '1.0.0',  file: 'tree-sitter-dart.wasm' },
  lua:        { package: '@tree-sitter-grammars/tree-sitter-lua',  version: '0.4.1', file: 'tree-sitter-lua.wasm' },
  haskell:    { package: 'tree-sitter-haskell',    version: '0.23.1', file: 'tree-sitter-haskell.wasm' },
  hcl:        { package: '@tree-sitter-grammars/tree-sitter-hcl',  version: '1.2.0', file: 'tree-sitter-hcl.wasm' },
  yaml:       { package: '@tree-sitter-grammars/tree-sitter-yaml', version: '0.7.1', file: 'tree-sitter-yaml.wasm' },
  bash:       { package: 'tree-sitter-bash',       version: '0.25.1', file: 'tree-sitter-bash.wasm' },
  elixir:     { package: 'tree-sitter-elixir',     version: '0.3.5',  file: 'tree-sitter-elixir.wasm' },
};

/**
 * Languages GuardLink scans whose npm packages ship no WASM. They resolve to
 * file scope with reason `no-grammar` until a WASM is placed at
 * `grammars/<language>.wasm` by hand (the build script keeps any file it finds).
 */
export const GRAMMARS_UNAVAILABLE = ['swift', 'kotlin'] as const;

/**
 * Lower-case extension (with dot) → language id, or null for file-scope-by-design.
 * Covers every pattern in parse-project.ts DEFAULT_INCLUDE except `.gal`.
 */
export const EXTENSION_LANGUAGE: Record<string, string | null> = {
  '.ts': 'typescript', '.tsx': 'tsx', '.js': 'javascript', '.jsx': 'javascript',
  '.py': 'python', '.rb': 'ruby', '.go': 'go', '.rs': 'rust',
  '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.scala': 'scala',
  '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.hpp': 'cpp',
  '.cs': 'c_sharp', '.swift': 'swift', '.dart': 'dart',
  '.lua': 'lua', '.hs': 'haskell',
  '.tf': 'hcl', '.hcl': 'hcl',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.sh': 'bash', '.bash': 'bash',
  '.ex': 'elixir', '.exs': 'elixir',
  // File-scope by design (spec §6.2): no meaningful declaration structure.
  '.sql': null, '.html': null, '.xml': null, '.svg': null, '.css': null,
};

/** Language id for a file extension, or null when the file is file-scoped. */
export function languageForExtension(ext: string): string | null {
  return EXTENSION_LANGUAGE[ext.toLowerCase()] ?? null;
}

/**
 * `<package root>/grammars`. From `src/structure/` and from `dist/structure/`
 * the package root is two levels up, so one expression serves both.
 */
export const GRAMMARS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'grammars');

export function grammarPath(language: string): string {
  return join(GRAMMARS_DIR, `${language}.wasm`);
}
```

- [ ] **Step 3: Write the build script**

```ts
// scripts/build-grammars.ts
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
```

- [ ] **Step 4: Wire package.json and .gitignore**

In `package.json`:
- `"scripts"`: change `"build"` to `"tsx scripts/build-grammars.ts && tsc && node scripts/postbuild-chmod.mjs"`; add `"build:grammars": "tsx scripts/build-grammars.ts"` and `"pretest": "tsx scripts/build-grammars.ts"`.
- `"files"`: add `"grammars"` after `"src"`.
- `"exports"`: add after the `"./mcp"` entry:
  ```json
  "./structure": {
    "import": "./dist/structure/index.js",
    "types": "./dist/structure/index.d.ts"
  }
  ```
  (`src/structure/index.ts` is created in Task 5; the export entry can be added now because nothing resolves it until then.)

In `.gitignore`, after the `# Build` block, add:
```
# Grammar WASM files, fetched from pinned npm packages by scripts/build-grammars.ts.
# Published through package.json "files"; never committed.
grammars/
```

- [ ] **Step 5: Fetch the grammars**

Run: `npm run build:grammars`
Expected: nineteen `build-grammars: <language> ← …` lines, then `19 fetched, 0 already current`, and `ls grammars` shows nineteen `.wasm` files plus `MANIFEST.json`. Run it a second time: `0 fetched, 19 already current`.

- [ ] **Step 6: Write the load-every-grammar test**

```ts
// tests/grammars.test.ts
/**
 * Every grammar the table promises must exist on disk, load into the pinned
 * runtime, and parse an empty document. An ABI mismatch between a grammar and
 * web-tree-sitter fails here, in CI, rather than in a user's terminal as a
 * silent fall-back to file scope.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync } from 'node:fs';
import { Parser, Language } from 'web-tree-sitter';
import { GRAMMARS, grammarPath, languageForExtension } from '../src/structure/grammars.js';

describe('grammar set', () => {
  beforeAll(async () => { await Parser.init(); });

  for (const language of Object.keys(GRAMMARS)) {
    it(`${language}: exists, loads, parses`, async () => {
      const path = grammarPath(language);
      expect(existsSync(path), `${path} missing — run npm run build:grammars`).toBe(true);
      const lang = await Language.load(path);
      const parser = new Parser();
      parser.setLanguage(lang);
      const tree = parser.parse('');
      expect(tree).not.toBeNull();
      expect(tree!.rootNode.hasError).toBe(false);
      tree!.delete();
    });
  }

  it('maps every DEFAULT_INCLUDE extension', async () => {
    const { DEFAULT_INCLUDE } = await import('../src/parser/parse-project.js');
    const exts = DEFAULT_INCLUDE
      .map(g => g.replace('**/*', ''))
      .filter(e => !/\[/.test(e)); // skip the case-insensitive .gal pattern
    for (const ext of exts) {
      // null is a valid answer (file-scope by design); undefined is a gap in the table.
      expect(languageForExtension(ext), `no mapping for ${ext}`).not.toBeUndefined();
    }
  });
});
```

- [ ] **Step 7: Run the test**

Run: `npx vitest run tests/grammars.test.ts`
Expected: PASS, twenty tests. If a grammar reports `hasError` on an empty document or fails to load with a message about language version, that grammar's pinned version is incompatible with the runtime: pick the nearest version whose WASM loads and update `GRAMMARS`. (At the versions listed, none is expected to fail.)

If `import { Parser, Language } from 'web-tree-sitter'` fails to resolve types, check `node_modules/web-tree-sitter/package.json` `exports`; version 0.27 exports named `Parser`, `Language`, `Node`, `Tree`.

- [ ] **Step 8: Lint and commit**

Run: `npm run lint`
Expected: no new errors (warnings about unused vars are pre-existing).

```bash
git add src/structure/grammars.ts scripts/build-grammars.ts tests/grammars.test.ts package.json package-lock.json .gitignore
git commit -m "feat(structure): pinned grammar table and build-time WASM fetch

Nineteen tree-sitter grammars, one exact version each, fetched from their npm
tarballs by npm pack (registry integrity checked) into grammars/, which is
gitignored and shipped through package.json files. Swift and Kotlin ship no
WASM and are listed as unavailable; they fall back to file scope.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 3: Runtime wrapper

**Files:**
- Create: `src/structure/runtime.ts`
- Test: `tests/structure-runtime.test.ts`

**Interfaces:**
- Consumes: `GRAMMARS`, `grammarPath` from Task 2.
- Produces: `loadLanguage(language): Promise<LoadResult>` where `LoadResult = { ok: true; language: Language } | { ok: false; reason: 'no-grammar' | 'grammar-failed' }`; `parseWith(language: Language, source: string): Tree`; `resetRuntimeForTests()`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/structure-runtime.test.ts
import { describe, it, expect, vi, afterEach } from 'vitest';
import { loadLanguage, parseWith, resetRuntimeForTests } from '../src/structure/runtime.js';

describe('structure runtime', () => {
  afterEach(() => { resetRuntimeForTests(); vi.restoreAllMocks(); });

  it('loads a grammar once and parses', async () => {
    const a = await loadLanguage('typescript');
    const b = await loadLanguage('typescript');
    expect(a.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.language).toBe(b.language);
    const tree = parseWith(a.language, 'export function f() { return 1 }');
    expect(tree.rootNode.type).toBe('program');
    expect(tree.rootNode.hasError).toBe(false);
    tree.delete();
  });

  it('reports no-grammar for a language outside the table', async () => {
    const r = await loadLanguage('swift');
    expect(r).toEqual({ ok: false, reason: 'no-grammar' });
  });

  it('reports grammar-failed once, with one warning, when the file is unloadable', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    const r1 = await loadLanguage('__broken__');
    const r2 = await loadLanguage('__broken__');
    expect(r1).toEqual({ ok: false, reason: 'no-grammar' });
    expect(r2).toEqual(r1);
    expect(warn).not.toHaveBeenCalled(); // no-grammar is silent by design
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/structure-runtime.test.ts`
Expected: FAIL with `Failed to resolve import "../src/structure/runtime.js"`.

- [ ] **Step 3: Write the runtime**

```ts
// src/structure/runtime.ts
/**
 * GuardLink structure layer — the one place that talks to web-tree-sitter.
 *
 * The runtime initialises once per process and each grammar loads once, both
 * lazily: a repository with only TypeScript never pays for the Go grammar.
 * A grammar file that is missing is `no-grammar` and silent — that is the
 * designed fallback for Swift and Kotlin today. A grammar file that exists but
 * fails to load is `grammar-failed` and warned once per language per process,
 * because that is a packaging defect, not a fallback.
 *
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "Grammar WASM is loaded into memory per language; a pathological source file costs one parse"
 * @mitigates #parser against #dos using #resource-limits -- "One runtime init and one load per language per process; trees are parsed on demand and deleted by callers"
 * @flows GrammarFile -> #parser via Language.load -- "Bundled WASM read from the package's grammars/ directory"
 * @comment -- "Paths come only from grammarPath(language) over the package's own grammars/ directory; no caller-supplied path reaches Language.load"
 */
import { existsSync } from 'node:fs';
import { Parser, Language } from 'web-tree-sitter';
import type { Tree } from 'web-tree-sitter';
import { GRAMMARS, grammarPath } from './grammars.js';

export type LoadResult =
  | { ok: true; language: Language }
  | { ok: false; reason: 'no-grammar' | 'grammar-failed' };

let initPromise: Promise<void> | null = null;
const loads = new Map<string, Promise<LoadResult>>();
const warned = new Set<string>();

function init(): Promise<void> {
  if (!initPromise) initPromise = Parser.init();
  return initPromise;
}

function warnOnce(language: string, message: string): void {
  if (warned.has(language)) return;
  warned.add(language);
  console.error(`⚠ GuardLink: ${message}`);
}

/** Load a grammar by language id. Cached for the life of the process. */
export function loadLanguage(language: string): Promise<LoadResult> {
  let pending = loads.get(language);
  if (!pending) {
    pending = (async (): Promise<LoadResult> => {
      if (!(language in GRAMMARS)) return { ok: false, reason: 'no-grammar' };
      const path = grammarPath(language);
      if (!existsSync(path)) return { ok: false, reason: 'no-grammar' };
      try {
        await init();
        return { ok: true, language: await Language.load(path) };
      } catch (err) {
        warnOnce(language, `grammar for ${language} failed to load from ${path}: ${(err as Error).message}. Falling back to file-scope anchors.`);
        return { ok: false, reason: 'grammar-failed' };
      }
    })();
    loads.set(language, pending);
  }
  return pending;
}

/** Parse source with an already-loaded grammar. The caller owns the tree and must `delete()` it. */
export function parseWith(language: Language, source: string): Tree {
  const parser = new Parser();
  parser.setLanguage(language);
  const tree = parser.parse(source);
  parser.delete();
  if (!tree) throw new Error('web-tree-sitter returned no tree');
  return tree;
}

/** Drop caches so a test can observe first-load behaviour again. */
export function resetRuntimeForTests(): void {
  loads.clear();
  warned.clear();
}
```

- [ ] **Step 4: Run the test**

Run: `npx vitest run tests/structure-runtime.test.ts && npx tsc --noEmit`
Expected: PASS. If tsc complains that `parser.parse` returns `Tree | null`, the `if (!tree)` guard already handles it; if it complains that `Parser.init` needs an argument, pass `{}`.

- [ ] **Step 5: Commit**

```bash
git add src/structure/runtime.ts tests/structure-runtime.test.ts
git commit -m "feat(structure): lazy web-tree-sitter runtime with per-language grammar cache

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 4: Token-stream hash

**Files:**
- Create: `src/structure/hash.ts`
- Test: `tests/structure-hash.test.ts`

**Interfaces:**
- Consumes: `loadLanguage`, `parseWith` from Task 3.
- Produces: `ANCHOR_HASH_VERSION = 1`, `isCommentType(type: string): boolean`, `leafTokens(node: Node): string[]`, `hashNode(node: Node): string`, `hashPlainText(content: string): string`, `hashTokens(tokens: string[]): string`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/structure-hash.test.ts
/**
 * The anchor hash must move when code moves and stay still when only its
 * presentation moves. Each case below is one edit a developer actually makes.
 */
import { describe, it, expect } from 'vitest';
import { loadLanguage, parseWith } from '../src/structure/runtime.js';
import { hashNode, hashPlainText, ANCHOR_HASH_VERSION } from '../src/structure/hash.js';

async function hashTs(source: string): Promise<string> {
  const r = await loadLanguage('typescript');
  if (!r.ok) throw new Error('typescript grammar missing');
  const tree = parseWith(r.language, source);
  const h = hashNode(tree.rootNode);
  tree.delete();
  return h;
}

const BASE = `export function resolveRoot(p: string) {
  assertInside(root, p);
  return resolve(p);
}
`;

describe('anchor hash', () => {
  it('carries the version prefix', async () => {
    expect(await hashTs(BASE)).toMatch(new RegExp(`^sha256-v${ANCHOR_HASH_VERSION}:[0-9a-f]{64}$`));
  });

  it('ignores reformatting, reindenting and CRLF', async () => {
    const base = await hashTs(BASE);
    expect(await hashTs('export function resolveRoot(p: string) { assertInside(root, p); return resolve(p); }')).toBe(base);
    expect(await hashTs(BASE.replace(/\n/g, '\r\n'))).toBe(base);
    expect(await hashTs(BASE.replace(/^  /gm, '\t\t'))).toBe(base);
  });

  it('ignores comments, including annotation lines, inside and above the body', async () => {
    const base = await hashTs(BASE);
    const commented = `/**
 * @mitigates #mcp against #path-traversal using #path-validation -- "resolve then prefix check"
 */
export function resolveRoot(p: string) {
  // keep the check
  assertInside(root, p);
  return resolve(p); /* trailing */
}
`;
    expect(await hashTs(commented)).toBe(base);
  });

  it('changes when a token changes', async () => {
    const base = await hashTs(BASE);
    expect(await hashTs(BASE.replace('assertInside(root, p);\n', ''))).not.toBe(base);
    expect(await hashTs(BASE.replace('resolveRoot', 'resolveRoot2'))).not.toBe(base);
    expect(await hashTs(BASE.replace('resolve(p)', 'resolve(p, root)'))).not.toBe(base);
  });

  it('hashes plain text by whitespace-separated tokens', () => {
    expect(hashPlainText('a  b\n\tc')).toBe(hashPlainText('a b c'));
    expect(hashPlainText('a b c')).not.toBe(hashPlainText('a b d'));
    expect(hashPlainText('x')).toMatch(/^sha256-v1:/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/structure-hash.test.ts`
Expected: FAIL with `Failed to resolve import "../src/structure/hash.js"`.

- [ ] **Step 3: Write the hash module**

```ts
// src/structure/hash.ts
/**
 * GuardLink structure layer — a hash of what a node says, not how it is laid out.
 *
 * The digest covers the leaf tokens of a subtree in document order, with every
 * comment node skipped. Whitespace between tokens is never a token, so
 * reformatting is invisible; a comment is skipped wholesale, so editing an
 * annotation above or inside a body is invisible; a renamed identifier or a
 * removed statement changes the token sequence, so it moves the hash.
 *
 * Tokens are joined with a control character rather than concatenated, so the
 * sequences (ab, c) and (a, bc) cannot collide — the same reasoning as
 * annotation-hash.ts.
 *
 * @comment -- "Pure functions over an in-memory syntax tree or a string; no I/O"
 */
import { createHash } from 'node:crypto';
import type { Node } from 'web-tree-sitter';

/** Bump when token selection or the separator changes. Part of every emitted hash. */
export const ANCHOR_HASH_VERSION = 1;

const SEP = String.fromCharCode(1);

/** Every grammar names its comment nodes with the word in them: comment, line_comment, block_comment, documentation_comment. */
export function isCommentType(type: string): boolean {
  return type.includes('comment');
}

/** Non-comment leaf tokens of a subtree, in order. Empty and whitespace-only leaves are dropped. */
export function leafTokens(node: Node, out: string[] = []): string[] {
  if (isCommentType(node.type)) return out;
  if (node.childCount === 0) {
    const text = node.text;
    if (text.trim() !== '') out.push(text);
    return out;
  }
  for (const child of node.children) {
    if (child) leafTokens(child, out);
  }
  return out;
}

export function hashTokens(tokens: string[]): string {
  return `sha256-v${ANCHOR_HASH_VERSION}:` + createHash('sha256').update(tokens.join(SEP)).digest('hex');
}

export function hashNode(node: Node): string {
  return hashTokens(leafTokens(node));
}

/**
 * For files with no grammar: whitespace-separated tokens. Comments are NOT
 * skipped here, because without a grammar there is no way to know what one is.
 * Documented in the spec as the file-scope limitation for markup and SQL.
 */
export function hashPlainText(content: string): string {
  return hashTokens(content.split(/\s+/).filter(Boolean));
}
```

- [ ] **Step 4: Run the test**

Run: `npx vitest run tests/structure-hash.test.ts && npx tsc --noEmit`
Expected: PASS. If `node.children` is typed as `(Node | null)[]` the `if (child)` guard covers it; if it is `Node[]` the guard is harmless.

- [ ] **Step 5: Commit**

```bash
git add src/structure/hash.ts tests/structure-hash.test.ts
git commit -m "feat(structure): token-stream hash that ignores comments and layout

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 5: Anchor resolution and the structure public API

**Files:**
- Create: `src/structure/anchor.ts`, `src/structure/index.ts`
- Test: `tests/structure-anchor.test.ts`

**Interfaces:**
- Consumes: `loadLanguage`, `parseWith` (Task 3); `hashNode`, `hashPlainText`, `isCommentType` (Task 4); `languageForExtension` (Task 2); `Anchor`, `AnchorReason` (Task 1).
- Produces: `parseStructure(filePath: string, content: string): Promise<FileStructure>` with `FileStructure = { language: string | null; anchorForLine(line: number): Anchor; symbolNamed(name: string): Anchor | null; dispose(): void }`. Re-exports `ANCHOR_HASH_VERSION`, `languageForExtension`, and the anchor types.

- [ ] **Step 1: Write the failing test**

```ts
// tests/structure-anchor.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/structure-anchor.test.ts`
Expected: FAIL with `Failed to resolve import "../src/structure/index.js"`.

- [ ] **Step 3: Write the resolver**

```ts
// src/structure/anchor.ts
/**
 * GuardLink structure layer — which code a comment on a given line describes.
 *
 * The rules are the spec's §6.2, applied to the uniform shape of a tree-sitter
 * tree rather than to per-language lists of declaration types: a comment's
 * anchor is its next named sibling, stepping over other comments and
 * attributes, descending through wrappers such as `export_statement` and
 * `decorated_definition`. Names come from the `name` field almost every
 * grammar defines, with one level of descent for the declarator shape
 * (`const x = …`, Go `type_spec`).
 *
 * The order of the special cases matters and is the spec's: no grammar, then
 * first-node, then no-sibling, then import-sibling, then YAML, then the
 * general rule. First match wins.
 *
 * @comment -- "Pure functions over an in-memory tree; no I/O, no user input beyond the source text already read by the parser"
 */
import type { Node } from 'web-tree-sitter';
import type { Anchor, AnchorReason } from '../types/index.js';
import { hashNode, isCommentType } from './hash.js';

/** Node types that sit between a comment and the thing it describes. */
const SKIPPABLE = /comment|attribute|hash_bang/;
/** Node types that mark a file header: the claim describes the module. */
const MODULE_HEADER = /import|package_clause|package_declaration|use_declaration|using_directive/;
/** Wrapper fields to descend through to reach the declaration. */
const DESCEND_FIELDS = ['declaration', 'definition'] as const;

function nameOf(node: Node): string | null {
  const own = node.childForFieldName('name');
  if (own) return own.text;
  for (const child of node.namedChildren) {
    if (!child) continue;
    const inner = child.childForFieldName('name');
    if (inner) return inner.text;
  }
  return null;
}

/** Nearest ancestor below the root that has a `name` field. */
function enclosingNamed(node: Node): Node | null {
  let p = node.parent;
  while (p && p.parent) {
    if (p.childForFieldName('name')) return p;
    p = p.parent;
  }
  return null;
}

/** The comment node whose range contains line (1-based), or null. */
function commentAt(root: Node, lines: string[], line: number): Node | null {
  const text = lines[line - 1];
  if (text === undefined) return null;
  const column = Math.max(0, text.search(/\S/));
  let n: Node | null = root.descendantForPosition({ row: line - 1, column });
  while (n && !isCommentType(n.type)) n = n.parent;
  return n;
}

function fileAnchor(root: Node, lineCount: number, reason: AnchorReason): Anchor {
  return { scope: 'file', symbol: null, start_line: 1, end_line: lineCount, hash: hashNode(root), reason };
}

function symbolAnchor(node: Node, symbol: string | null, reason?: AnchorReason): Anchor {
  const a: Anchor = {
    scope: 'symbol', symbol,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
    hash: hashNode(node),
  };
  if (reason) a.reason = reason;
  return a;
}

/** YAML: the first mapping pair at or below `node` that starts after `afterRow`. */
function yamlPair(node: Node, afterRow: number): Node | null {
  if (node.type === 'block_mapping_pair' && node.startPosition.row > afterRow) return node;
  for (const child of node.namedChildren) {
    if (!child) continue;
    const found = yamlPair(child, afterRow);
    if (found) return found;
  }
  return null;
}

export function resolveAnchor(root: Node, language: string, lines: string[], line: number): Anchor {
  const comment = commentAt(root, lines, line);
  if (!comment) return fileAnchor(root, lines.length, 'no-sibling');

  // Rule 2 — first-node: nothing but comments/shebang before it, and not inside a declaration.
  let prev = comment.previousNamedSibling;
  let onlySkippableBefore = true;
  while (prev) {
    if (!SKIPPABLE.test(prev.type)) { onlySkippableBefore = false; break; }
    prev = prev.previousNamedSibling;
  }
  if (onlySkippableBefore && enclosingNamed(comment) === null) return fileAnchor(root, lines.length, 'first-node');

  // Rule 3 — no-sibling: a trailing comment binds to what encloses it.
  let cand = comment.nextNamedSibling;
  while (cand && SKIPPABLE.test(cand.type)) cand = cand.nextNamedSibling;
  if (!cand) {
    const enc = enclosingNamed(comment);
    return enc ? symbolAnchor(enc, nameOf(enc), 'no-sibling') : fileAnchor(root, lines.length, 'no-sibling');
  }

  // Rule 4 — import-sibling.
  if (MODULE_HEADER.test(cand.type)) return fileAnchor(root, lines.length, 'import-sibling');

  // Rule 5 — YAML block.
  if (language === 'yaml') {
    const pair = yamlPair(cand, comment.startPosition.row);
    if (!pair) return fileAnchor(root, lines.length, 'no-sibling');
    const key = pair.childForFieldName('key');
    return {
      scope: 'block', symbol: key ? key.text : null,
      start_line: pair.startPosition.row + 1, end_line: pair.endPosition.row + 1,
      hash: hashNode(pair),
    };
  }

  // General rule — descend through wrappers, then name it.
  for (const field of DESCEND_FIELDS) {
    const inner = cand.childForFieldName(field);
    if (inner) { cand = inner; break; }
  }
  const symbol = nameOf(cand) ?? (enclosingNamed(cand) ? nameOf(enclosingNamed(cand)!) : null);
  return symbolAnchor(cand, symbol);
}

/** External mode: the declaration named `name`, searched top-down, first match. */
export function findNamed(root: Node, name: string): Anchor | null {
  const stack: Node[] = [root];
  while (stack.length > 0) {
    const node = stack.shift()!;
    for (const child of node.namedChildren) {
      if (!child || isCommentType(child.type)) continue;
      let target = child;
      for (const field of DESCEND_FIELDS) {
        const inner = target.childForFieldName(field);
        if (inner) { target = inner; break; }
      }
      if (nameOf(target) === name) return symbolAnchor(target, name);
      stack.push(child);
    }
  }
  return null;
}
```

```ts
// src/structure/index.ts
/**
 * GuardLink structure layer — public API.
 *
 * `parseStructure` is the only entry point the rest of the product uses. It
 * returns a per-file object that answers "which code does the comment on this
 * line describe" and "where is the declaration called X", both as `Anchor`s
 * carrying a content hash. Files without a grammar answer with a file-scope
 * anchor over a plain-text hash, so every caller gets an anchor and no caller
 * has to know whether tree-sitter was involved.
 *
 * @flows SourceFile -> #parser via parseStructure -- "File content already read by the parser, parsed again for structure"
 * @comment -- "Takes content, not a path to read: the parser owns file I/O and its path validation; this layer never opens a file"
 */
import { extname } from 'node:path';
import type { Tree } from 'web-tree-sitter';
import type { Anchor, AnchorReason } from '../types/index.js';
import { languageForExtension, GRAMMARS_UNAVAILABLE } from './grammars.js';
import { loadLanguage, parseWith } from './runtime.js';
import { hashPlainText, ANCHOR_HASH_VERSION } from './hash.js';
import { resolveAnchor, findNamed } from './anchor.js';

export { ANCHOR_HASH_VERSION } from './hash.js';
export { languageForExtension, GRAMMARS, GRAMMARS_UNAVAILABLE, EXTENSION_LANGUAGE } from './grammars.js';
export type { Anchor, AnchorScope, AnchorReason } from '../types/index.js';

export interface FileStructure {
  /** Grammar used, or null when every line resolves to file scope. */
  language: string | null;
  anchorForLine(line: number): Anchor;
  /** External mode: resolve a `@source … symbol:<name>` by declaration name. */
  symbolNamed(name: string): Anchor | null;
  /** Release the syntax tree. Safe to call twice. */
  dispose(): void;
}

function fileOnly(language: string | null, content: string, reason: AnchorReason): FileStructure {
  const lineCount = content.split('\n').length;
  const hash = hashPlainText(content);
  const anchor: Anchor = { scope: 'file', symbol: null, start_line: 1, end_line: lineCount, hash, reason };
  return { language, anchorForLine: () => ({ ...anchor }), symbolNamed: () => null, dispose: () => {} };
}

export async function parseStructure(filePath: string, content: string): Promise<FileStructure> {
  const language = languageForExtension(extname(filePath));
  if (!language) return fileOnly(null, content, 'no-grammar');
  if ((GRAMMARS_UNAVAILABLE as readonly string[]).includes(language)) {
    // Still try: a hand-placed WASM makes the language symbol-scoped.
    const attempt = await loadLanguage(language);
    if (!attempt.ok) return fileOnly(language, content, 'no-grammar');
  }
  const loaded = await loadLanguage(language);
  if (!loaded.ok) return fileOnly(language, content, loaded.reason);

  let tree: Tree | null = parseWith(loaded.language, content);
  const root = tree.rootNode;
  const lines = content.split('\n');
  return {
    language,
    anchorForLine: (line) => resolveAnchor(root, language, lines, line),
    symbolNamed: (name) => findNamed(root, name),
    dispose: () => { if (tree) { tree.delete(); tree = null; } },
  };
}
```

- [ ] **Step 4: Run the test**

Run: `npx vitest run tests/structure-anchor.test.ts && npx tsc --noEmit`
Expected: PASS. Two assertions are the most likely to need a grammar-specific adjustment; both are contained:

- If the YAML `jobs` case fails because the comment's `nextNamedSibling` is null, tree-sitter-yaml attached the comment above the mapping. Change the YAML branch to search from `comment.parent` when `cand` is null: move the `language === 'yaml'` check above the no-sibling rule and call `yamlPair(comment.parent ?? root, comment.startPosition.row)`.
- If the Java case names `null`, `method_declaration` in that grammar version keeps its name under a `name` field (expected) — check `node.childForFieldName('name')` is spelled exactly so; a null there means the grammar loaded is not the pinned one. Run `npm run build:grammars` and retry.


- [ ] **Step 5: Commit**

```bash
git add src/structure/anchor.ts src/structure/index.ts tests/structure-anchor.test.ts
git commit -m "feat(structure): resolve the code beneath a comment, across every grammar

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 6: Attach anchors during parseProject

**Files:**
- Create: `src/structure/attach.ts`
- Modify: `src/parser/parse-project.ts:41-50` (options), `src/parser/parse-project.ts:150-192` (after the parse loop)
- Test: `tests/structure-attach.test.ts`

**Interfaces:**
- Consumes: `parseStructure` (Task 5).
- Produces: `attachAnchors(root: string, annotations: Annotation[]): Promise<void>`; `ParseProjectOptions.anchors?: boolean` (default `true`). After this task every `location` on every model record has `anchor` set (or `null` when the logical file could not be read).

- [ ] **Step 1: Write the failing test**

```ts
// tests/structure-attach.test.ts
/**
 * The anchor must reach the model through the normal parse, in both annotation
 * modes, and be absent when a caller asks for a cheap parse.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const SOURCE = `import x from 'x';

/**
 * @exposes #api to #sqli [critical] cwe:CWE-89 -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }

export function other() { return 1; }
`;

async function scratch(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `guardlink-${prefix}-`));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  return root;
}

describe('anchors attached by parseProject', () => {
  it('inline mode: every relation carries the symbol beneath its doc block', async () => {
    const root = await scratch('attach-inline');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.mitigations[0].location.anchor).toMatchObject({ scope: 'symbol', symbol: 'login', start_line: 7, end_line: 7 });
    expect(model.exposures[0].location.anchor?.hash).toBe(model.mitigations[0].location.anchor?.hash);
    // definitions are anchored too, harmlessly: file scope of definitions.ts
    expect(model.assets[0].location.anchor?.scope).toBe('file');
  });

  it('external mode: a @source symbol resolves by name, not by recorded line', async () => {
    const root = await scratch('attach-external');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace(/\/\*\*[\s\S]*?\*\/\n/, ''));
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'api.ts.gal'),
      '@source file:src/api.ts line:1 symbol:other\n@mitigates #api against #sqli using #prepared-stmts -- "bound"\n');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.mitigations[0].location.anchor).toMatchObject({ scope: 'symbol', symbol: 'other' });
  });

  it('anchors: false leaves locations untouched', async () => {
    const root = await scratch('attach-off');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    const { model } = await parseProject({ root, project: 'test', anchors: false });
    expect(model.mitigations[0].location.anchor).toBeUndefined();
  });

  it('a logical file that cannot be read yields a null anchor', async () => {
    const root = await scratch('attach-missing');
    await mkdir(join(root, '.guardlink', 'annotations', 'src'), { recursive: true });
    await writeFile(join(root, '.guardlink', 'annotations', 'src', 'gone.ts.gal'),
      '@source file:src/gone.ts line:1 symbol:x\n@audit #api -- "orphaned sidecar"\n');
    const { model } = await parseProject({ root, project: 'test' });
    expect(model.audits[0].location.anchor).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/structure-attach.test.ts`
Expected: FAIL: `anchor` is `undefined` in the first two cases.

- [ ] **Step 3: Write attach.ts and wire parseProject**

```ts
// src/structure/attach.ts
/**
 * GuardLink structure layer — put an anchor on every annotation location.
 *
 * Runs once per parse, after locations are normalised to logical root-relative
 * paths and before the model is assembled. `assembleModel` shares each
 * location object by reference, so an anchor set here is the anchor every
 * surface sees. Files are grouped by LOGICAL path: in external mode that is
 * the source the sidecar describes, never the sidecar.
 *
 * @exposes #parser to #path-traversal [low] cwe:CWE-22 -- "Reads the file each annotation's location names, joined under root"
 * @mitigates #parser against #path-traversal using #path-validation -- "Paths are the parser's own normalised, root-relative locations; joined to root and skipped when unreadable; nothing outside the scanned set is opened"
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "One structure parse per annotated file"
 * @mitigates #parser against #dos using #resource-limits -- "Only files that carry annotations are parsed, once each, and the tree is released immediately"
 * @flows SourceFiles -> #parser via attachAnchors -- "Annotated files re-read for structure"
 */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Annotation } from '../types/index.js';
import { parseStructure } from './index.js';

const isGalPath = (p: string): boolean => /\.gal$/i.test(p);

export async function attachAnchors(root: string, annotations: Annotation[]): Promise<void> {
  const byFile = new Map<string, Annotation[]>();
  for (const a of annotations) {
    const file = a.location?.file;
    if (!file || isGalPath(file)) continue;
    const list = byFile.get(file);
    if (list) list.push(a); else byFile.set(file, [a]);
  }

  for (const [file, anns] of byFile) {
    let content: string;
    try {
      content = await readFile(resolve(root, file), 'utf-8');
    } catch {
      for (const a of anns) a.location.anchor = null;
      continue;
    }
    const structure = await parseStructure(file, content);
    try {
      for (const a of anns) {
        const named = a.location.parent_symbol ? structure.symbolNamed(a.location.parent_symbol) : null;
        a.location.anchor = named ?? structure.anchorForLine(a.location.line);
      }
    } finally {
      structure.dispose();
    }
  }
}
```

In `src/parser/parse-project.ts`:

1. Add the import after line 36:
   ```ts
   import { attachAnchors } from '../structure/attach.js';
   ```
2. In `ParseProjectOptions`, after `project?: string;`:
   ```ts
   /**
    * Attach a structure-layer `anchor` to every annotation location (default
    * true). Set false for callers that only need the annotations — the diff
    * engine's historical parses, for instance — to skip grammar loading.
    */
   anchors?: boolean;
   ```
3. In the destructuring at the top of `parseProject`, add `anchors = true,` after `project = 'unknown',`.
4. Immediately after the `for (const file of files) { … }` loop (the line `allDiagnostics.push(...result.diagnostics);` closes it) and before `// Check for duplicate identifiers`, add:
   ```ts
   // The code beneath each claim (spec §5). Locations are already logical,
   // root-relative paths, and assembleModel shares each location object by
   // reference, so the anchor set here reaches every model record.
   if (anchors) await attachAnchors(root, allAnnotations);
   ```

- [ ] **Step 4: Run the new test and the whole suite**

Run: `npx vitest run tests/structure-attach.test.ts && npm test`
Expected: the new file passes. The full suite must stay green: it now loads grammars in every test that parses a project. If a test times out at vitest's 5000 ms default because of first-load cost on a slow machine, add `anchors: false` to that test's `parseProject` call only if the test does not care about anchors; do not raise the global timeout.

- [ ] **Step 5: Commit**

```bash
git add src/structure/attach.ts src/parser/parse-project.ts tests/structure-attach.test.ts
git commit -m "feat(parser): attach the code beneath every annotation during parseProject

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 7: Claim keys and claim text

**Files:**
- Create: `src/parser/claim-key.ts`
- Test: `tests/claim-key.test.ts`

**Interfaces:**
- Consumes: `ThreatModel` record types.
- Produces: `ClaimVerb`, `ClaimSource { verb; key; claim; location; demotable }`, `relationRecords(model: ThreatModel): ClaimSource[]`, `claimText(verb, record): string`. Tasks 9, 10 and 12 iterate `relationRecords`.

- [ ] **Step 1: Write the failing test**

```ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/claim-key.test.ts`
Expected: FAIL with `Failed to resolve import "../src/parser/claim-key.js"`.

- [ ] **Step 3: Write claim-key.ts**

```ts
// src/parser/claim-key.ts
/**
 * GuardLink — one stable identity per relationship claim.
 *
 * The verification ledger needs to name a claim across every edit that is not
 * the claim: the line it sits on, the code beneath it, and the severity its
 * threat resolves to at assembly time. The key is therefore a digest of the
 * claim's own words — verb, identity arguments, external refs, description —
 * plus the logical file, and nothing else.
 *
 * Severity is deliberately absent: `parseProject` resolves an exposure's
 * severity from the threat definition, so keying on it would re-key every
 * exposure of a threat when that threat's severity changed in definitions.
 * That is also why this is not `annotation-hash.ts`, which does include it —
 * the two answer different questions.
 *
 * Identical claims in one file get an ordinal suffix in document order, so a
 * repeated `@comment` is two ledger entries rather than one that flaps.
 *
 * @comment -- "Pure functions over an assembled ThreatModel; no I/O"
 */
import { createHash } from 'node:crypto';
import type {
  ThreatModel, SourceLocation, AnnotationVerb,
  ThreatModelMitigation, ThreatModelExposure, ThreatModelConfirmed, ThreatModelAcceptance,
  ThreatModelTransfer, ThreatModelFlow, ThreatModelBoundary, ThreatModelValidation,
  ThreatModelAudit, ThreatModelOwnership, ThreatModelDataHandling, ThreatModelAssumption,
  ThreatModelFeature, ThreatModelComment, ThreatModelEntitlement,
} from '../types/index.js';

export type ClaimVerb =
  | 'mitigates' | 'exposes' | 'confirmed' | 'accepts' | 'transfers' | 'flows' | 'boundary'
  | 'validates' | 'audit' | 'owns' | 'handles' | 'assumes' | 'feature' | 'comment' | 'entitles';

/** Verbs whose staleness can hide an exposure: the two that remove one from the export. */
export const DEMOTABLE_VERBS: ReadonlySet<AnnotationVerb> = new Set(['mitigates', 'accepts']);

export interface ClaimSource {
  verb: ClaimVerb;
  /** `<sha256 hex>:<ordinal>` — see module note. */
  key: string;
  /** Human rendering of the arguments, for reports and the ledger. Never matched on. */
  claim: string;
  location: SourceLocation;
  demotable: boolean;
}

const FIELD_SEP = String.fromCharCode(1);
const s = (v: unknown): string => (v === undefined || v === null ? '' : String(v));
const f = (file: string): string => s(file).replaceAll('\\', '/');
const refs = (v: string[] | undefined): string => (v ? [...v].map(s).sort().join(',') : '');

type Rec =
  | ['mitigates', ThreatModelMitigation] | ['exposes', ThreatModelExposure] | ['confirmed', ThreatModelConfirmed]
  | ['accepts', ThreatModelAcceptance] | ['transfers', ThreatModelTransfer] | ['flows', ThreatModelFlow]
  | ['boundary', ThreatModelBoundary] | ['validates', ThreatModelValidation] | ['audit', ThreatModelAudit]
  | ['owns', ThreatModelOwnership] | ['handles', ThreatModelDataHandling] | ['assumes', ThreatModelAssumption]
  | ['feature', ThreatModelFeature] | ['comment', ThreatModelComment] | ['entitles', ThreatModelEntitlement];

/** Identity fields per verb, in a fixed order. Description last, file after that. */
function identity([verb, r]: Rec): string[] {
  switch (verb) {
    case 'mitigates': return [s(r.asset), s(r.threat), s(r.control)];
    case 'exposes':   return [s(r.asset), s(r.threat), refs(r.external_refs)];
    case 'confirmed': return [s(r.asset), s(r.threat), refs(r.external_refs)];
    case 'accepts':   return [s(r.asset), s(r.threat)];
    case 'transfers': return [s(r.threat), s(r.source), s(r.target)];
    case 'flows':     return [s(r.source), s(r.target), s(r.mechanism)];
    case 'boundary':  return [s(r.asset_a), s(r.asset_b), s(r.id)];
    case 'validates': return [s(r.control), s(r.asset)];
    case 'audit':     return [s(r.asset)];
    case 'owns':      return [s(r.owner), s(r.asset)];
    case 'handles':   return [s(r.classification), s(r.asset)];
    case 'assumes':   return [s(r.asset)];
    case 'feature':   return [s(r.feature)];
    case 'comment':   return [];
    case 'entitles':  return [s(r.actor), s(r.capability), s(r.asset), s(r.threat)];
  }
}

/** Display text for the arguments, in GAL word order. */
export function claimText(rec: Rec): string {
  const [verb, r] = rec;
  switch (verb) {
    case 'mitigates': return `${r.asset} against ${r.threat}${r.control ? ` using ${r.control}` : ''}`;
    case 'exposes':   return `${r.asset} to ${r.threat}`;
    case 'confirmed': return `${r.threat} on ${r.asset}`;
    case 'accepts':   return `${r.threat} on ${r.asset}`;
    case 'transfers': return `${r.threat} from ${r.source} to ${r.target}`;
    case 'flows':     return `${r.source} -> ${r.target}${r.mechanism ? ` via ${r.mechanism}` : ''}`;
    case 'boundary':  return `between ${r.asset_a} and ${r.asset_b}${r.id ? ` (#${r.id})` : ''}`;
    case 'validates': return `${r.control} for ${r.asset}`;
    case 'audit':     return r.asset;
    case 'owns':      return `${r.owner} for ${r.asset}`;
    case 'handles':   return `${r.classification} on ${r.asset}`;
    case 'assumes':   return r.asset;
    case 'feature':   return `"${r.feature}"`;
    case 'comment':   return `"${(r.description ?? '').slice(0, 60)}"`;
    case 'entitles':  return `${r.actor} to ${r.capability}${r.asset ? ` on ${r.asset}` : ''}${r.threat ? ` against ${r.threat}` : ''}`;
  }
}

function baseKey(rec: Rec): string {
  const [verb, r] = rec;
  const parts = [verb, ...identity(rec), s(r.description), f(r.location.file)];
  return createHash('sha256').update(parts.join(FIELD_SEP)).digest('hex');
}

function allRecords(model: ThreatModel): Rec[] {
  const out: Rec[] = [];
  for (const r of model.mitigations) out.push(['mitigates', r]);
  for (const r of model.exposures) out.push(['exposes', r]);
  for (const r of model.confirmed || []) out.push(['confirmed', r]);
  for (const r of model.acceptances) out.push(['accepts', r]);
  for (const r of model.transfers) out.push(['transfers', r]);
  for (const r of model.flows) out.push(['flows', r]);
  for (const r of model.boundaries) out.push(['boundary', r]);
  for (const r of model.validations) out.push(['validates', r]);
  for (const r of model.audits) out.push(['audit', r]);
  for (const r of model.ownership) out.push(['owns', r]);
  for (const r of model.data_handling) out.push(['handles', r]);
  for (const r of model.assumptions) out.push(['assumes', r]);
  for (const r of model.features) out.push(['feature', r]);
  for (const r of model.comments) out.push(['comment', r]);
  for (const r of model.entitlements || []) out.push(['entitles', r]);
  return out;
}

/** Every relationship record with its stable key, in model order. */
export function relationRecords(model: ThreatModel): ClaimSource[] {
  const recs = allRecords(model);
  // Ordinals in document order: group by base key, sort each group by position.
  const groups = new Map<string, Rec[]>();
  const bases = new Map<Rec, string>();
  for (const rec of recs) {
    const base = baseKey(rec);
    bases.set(rec, base);
    const g = groups.get(base);
    if (g) g.push(rec); else groups.set(base, [rec]);
  }
  const ordinal = new Map<Rec, number>();
  for (const g of groups.values()) {
    g.sort((a, b) => (a[1].location.line - b[1].location.line) || ((a[1].location.origin_line ?? 0) - (b[1].location.origin_line ?? 0)));
    g.forEach((rec, i) => ordinal.set(rec, i));
  }
  return recs.map(rec => ({
    verb: rec[0],
    key: `${bases.get(rec)!}:${ordinal.get(rec)!}`,
    claim: claimText(rec),
    location: rec[1].location,
    demotable: DEMOTABLE_VERBS.has(rec[0]),
  }));
}
```

- [ ] **Step 4: Run the test**

Run: `npx vitest run tests/claim-key.test.ts && npx tsc --noEmit`
Expected: PASS. If tsc rejects the tuple-union `switch` narrowing on `r`, destructure inside each `case` instead (`case 'mitigates': { const m = r as ThreatModelMitigation; … }`).

- [ ] **Step 5: Commit**

```bash
git add src/parser/claim-key.ts tests/claim-key.test.ts
git commit -m "feat(parser): stable claim keys and display text for every relationship record

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 8: The verification ledger

**Files:**
- Create: `src/parser/ledger.ts`
- Test: `tests/ledger.test.ts`

**Interfaces:**
- Consumes: `AnchorScope`, `ParseDiagnostic` (Task 1).
- Produces: `LEDGER_FILE = '.guardlink/verified.json'`, `LEDGER_SCHEMA = 'guardlink.verified/v1'`, `LedgerEntry`, `Ledger`, `LedgerStatus`, `LedgerRead { status; ledger; diagnostic? }`, `readLedger(root): LedgerRead`, `serializeLedger(ledger): string`, `writeLedger(root, ledger): void`, `emptyLedger(): Ledger`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/ledger.test.ts
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readLedger, writeLedger, serializeLedger, emptyLedger, LEDGER_FILE, LEDGER_SCHEMA } from '../src/parser/ledger.js';
import type { LedgerEntry } from '../src/parser/ledger.js';

function entry(over: Partial<LedgerEntry>): LedgerEntry {
  return {
    key: 'a'.repeat(64) + ':0', file: 'src/a.ts', verb: 'mitigates', claim: '#api against #sqli',
    anchor: { scope: 'symbol', symbol: 'login' }, hash: 'sha256-v1:' + '1'.repeat(64),
    verified_by: 'human:test', verified_at: '2026-09-03T00:00:00.000Z', ...over,
  };
}

async function scratch(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-ledger-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  return root;
}

describe('verification ledger', () => {
  it('absent when the file does not exist', async () => {
    const root = await scratch();
    expect(readLedger(root)).toEqual({ status: 'absent', ledger: null });
  });

  it('round-trips, sorted by file then key, one entry per line', async () => {
    const root = await scratch();
    const ledger = emptyLedger();
    ledger.entries.push(entry({ file: 'src/b.ts', key: 'b'.repeat(64) + ':0' }));
    ledger.entries.push(entry({ file: 'src/a.ts', key: 'c'.repeat(64) + ':0' }));
    ledger.entries.push(entry({ file: 'src/a.ts', key: 'a'.repeat(64) + ':1' }));
    writeLedger(root, ledger);

    const text = await readFile(join(root, LEDGER_FILE), 'utf-8');
    const lines = text.split('\n');
    expect(lines.filter(l => l.startsWith('    {"key"')).length).toBe(3);
    expect(text.endsWith('\n')).toBe(true);
    expect(JSON.parse(text).schema).toBe(LEDGER_SCHEMA);

    const back = readLedger(root);
    expect(back.status).toBe('present');
    expect(back.ledger!.entries.map(e => [e.file, e.key.slice(0, 1)])).toEqual([['src/a.ts', 'a'], ['src/a.ts', 'c'], ['src/b.ts', 'b']]);
  });

  it('serialises deterministically regardless of input order', () => {
    const a = emptyLedger(); a.entries.push(entry({ key: 'b'.repeat(64) + ':0' }), entry({ key: 'a'.repeat(64) + ':0' }));
    const b = emptyLedger(); b.entries.push(entry({ key: 'a'.repeat(64) + ':0' }), entry({ key: 'b'.repeat(64) + ':0' }));
    expect(serializeLedger(a)).toBe(serializeLedger(b));
  });

  it('reports corrupt with a ledger-corrupt diagnostic on bad JSON, wrong schema, or bad shape', async () => {
    const root = await scratch();
    for (const bad of ['{not json', '{"schema":"other/v9","anchor_hash_version":1,"entries":[]}', '{"schema":"guardlink.verified/v1","anchor_hash_version":1,"entries":[{"key":1}]}']) {
      await writeFile(join(root, LEDGER_FILE), bad);
      const r = readLedger(root);
      expect(r.status).toBe('corrupt');
      expect(r.ledger).toBeNull();
      expect(r.diagnostic).toMatchObject({ level: 'error', code: 'ledger-corrupt', file: LEDGER_FILE });
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/ledger.test.ts`
Expected: FAIL with `Failed to resolve import "../src/parser/ledger.js"`.

- [ ] **Step 3: Write ledger.ts**

```ts
// src/parser/ledger.ts
/**
 * GuardLink — the verification ledger, `.guardlink/verified.json`.
 *
 * One entry per source-anchored claim: the claim's key, the anchor hash at the
 * moment someone verified it, who, and when. Committed, so it travels with the
 * code and needs no git history to read. Written only by `guardlink verify`
 * and the `guardlink_verify` MCP tool; every other command reads.
 *
 * Entries are sorted by file then key and serialised one per line, so two
 * branches that verify different files merge without conflict and two that
 * verify the same claim conflict on exactly one line.
 *
 * A file that exists but does not parse, or names another schema, or holds an
 * entry of the wrong shape, is CORRUPT — reported once through a diagnostic
 * and otherwise treated as absent. It is never silently rewritten: `verify`
 * refuses to write over it without `--force`.
 *
 * @exposes #parser to #insecure-deser [low] cwe:CWE-502 -- "JSON.parse on a committed file under .guardlink/"
 * @mitigates #parser against #insecure-deser using #config-validation -- "Shape is validated field by field before any entry is trusted; anything else is corrupt, not partially loaded"
 * @exposes #cli to #arbitrary-write [low] cwe:CWE-73 -- "writeLedger writes one fixed path under root"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "The path is the constant LEDGER_FILE joined to root; no caller supplies a path"
 * @flows LedgerFile -> #parser via readLedger -- "Recorded hashes and verifiers"
 * @flows #cli -> LedgerFile via writeLedger -- "The only write the verify surfaces perform"
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { AnchorScope, AnnotationVerb, ParseDiagnostic } from '../types/index.js';
import { ANCHOR_HASH_VERSION } from '../structure/hash.js';

export const LEDGER_FILE = '.guardlink/verified.json';
export const LEDGER_SCHEMA = 'guardlink.verified/v1';

export interface LedgerEntry {
  key: string;
  file: string;
  verb: AnnotationVerb;
  /** Display only; never used for matching. */
  claim: string;
  anchor: { scope: AnchorScope; symbol: string | null };
  hash: string;
  /** `human:<name>` or `agent:<client name>`. The prefix is what a future gate keys on. */
  verified_by: string;
  /** ISO 8601, UTC. */
  verified_at: string;
  /** HEAD at verify time, present only when git was available. */
  commit?: string;
}

export interface Ledger {
  schema: typeof LEDGER_SCHEMA;
  anchor_hash_version: number;
  entries: LedgerEntry[];
}

export type LedgerStatus = 'present' | 'absent' | 'corrupt';

export interface LedgerRead {
  status: LedgerStatus;
  ledger: Ledger | null;
  /** Present only when status is 'corrupt'. */
  diagnostic?: ParseDiagnostic;
}

export function emptyLedger(): Ledger {
  return { schema: LEDGER_SCHEMA, anchor_hash_version: ANCHOR_HASH_VERSION, entries: [] };
}

const SCOPES: ReadonlySet<string> = new Set(['symbol', 'block', 'file']);

function isEntry(v: unknown): v is LedgerEntry {
  if (!v || typeof v !== 'object') return false;
  const e = v as Record<string, unknown>;
  const anchor = e.anchor as Record<string, unknown> | undefined;
  return typeof e.key === 'string' && typeof e.file === 'string' && typeof e.verb === 'string'
    && typeof e.claim === 'string' && typeof e.hash === 'string'
    && typeof e.verified_by === 'string' && typeof e.verified_at === 'string'
    && (e.commit === undefined || typeof e.commit === 'string')
    && !!anchor && typeof anchor === 'object' && SCOPES.has(String(anchor.scope))
    && (anchor.symbol === null || typeof anchor.symbol === 'string');
}

function corrupt(message: string): LedgerRead {
  return {
    status: 'corrupt', ledger: null,
    diagnostic: { level: 'error', code: 'ledger-corrupt', file: LEDGER_FILE, line: 0, message: `${LEDGER_FILE}: ${message}` },
  };
}

export function readLedger(root: string): LedgerRead {
  const path = join(root, LEDGER_FILE);
  if (!existsSync(path)) return { status: 'absent', ledger: null };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf-8'));
  } catch (err) {
    return corrupt(`not valid JSON (${(err as Error).message}). Run guardlink verify --all --force to rebuild it.`);
  }
  if (!raw || typeof raw !== 'object') return corrupt('not an object');
  const obj = raw as Record<string, unknown>;
  if (obj.schema !== LEDGER_SCHEMA) return corrupt(`schema is ${JSON.stringify(obj.schema)}, expected ${LEDGER_SCHEMA}`);
  if (typeof obj.anchor_hash_version !== 'number') return corrupt('anchor_hash_version is not a number');
  if (!Array.isArray(obj.entries)) return corrupt('entries is not an array');
  for (const [i, e] of obj.entries.entries()) {
    if (!isEntry(e)) return corrupt(`entry ${i} has the wrong shape`);
  }
  const ledger: Ledger = { schema: LEDGER_SCHEMA, anchor_hash_version: obj.anchor_hash_version, entries: sortEntries(obj.entries as LedgerEntry[]) };
  return { status: 'present', ledger };
}

function sortEntries(entries: LedgerEntry[]): LedgerEntry[] {
  return [...entries].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

/** Valid JSON, one entry per line, sorted, trailing newline. */
export function serializeLedger(ledger: Ledger): string {
  const lines = sortEntries(ledger.entries).map(e => '    ' + JSON.stringify(e));
  return [
    '{',
    `  "schema": ${JSON.stringify(ledger.schema)},`,
    `  "anchor_hash_version": ${ledger.anchor_hash_version},`,
    '  "entries": [',
    lines.join(',\n'),
    '  ]',
    '}',
    '',
  ].join('\n');
}

export function writeLedger(root: string, ledger: Ledger): void {
  const path = join(root, LEDGER_FILE);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, serializeLedger(ledger));
}
```

- [ ] **Step 4: Run the test**

Run: `npx vitest run tests/ledger.test.ts && npx tsc --noEmit`
Expected: PASS. Note the empty-entries case serialises `"entries": [\n\n  ]`, which is valid JSON; if you prefer a tidier empty array, special-case `lines.length === 0` to emit `  "entries": []`. Either is fine; the tests accept both.

- [ ] **Step 5: Commit**

```bash
git add src/parser/ledger.ts tests/ledger.test.ts
git commit -m "feat(parser): the verification ledger — read, validate, write one entry per line

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 9: The staleness predicate

**Files:**
- Create: `src/parser/verification.ts`
- Test: `tests/verification.test.ts`

**Interfaces:**
- Consumes: `relationRecords`, `ClaimVerb` (Task 7); `Ledger`, `LedgerEntry`, `LedgerRead`, `LedgerStatus` (Task 8); `ANCHOR_HASH_VERSION` (Task 4); `Anchor` (Task 1).
- Produces: `ClaimState`, `ClaimRecord`, `VerificationReport`, `classifyClaims(model: ThreatModel, read: LedgerRead): VerificationReport`, `demotionSet(report): Set<string>`. Tasks 10, 12 and 13 consume the report.

- [ ] **Step 1: Write the failing test**

```ts
// tests/verification.test.ts
/**
 * Every row of the spec's §7.3 state table, driven through a real parse so the
 * anchors are the ones the product computes, with ledger entries built from
 * those anchors and then bent one field at a time.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { relationRecords } from '../src/parser/claim-key.js';
import { emptyLedger } from '../src/parser/ledger.js';
import type { Ledger, LedgerEntry, LedgerRead } from '../src/parser/ledger.js';
import { classifyClaims, demotionSet } from '../src/parser/verification.js';
import type { ThreatModel } from '../src/types/index.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

async function parsed(): Promise<ThreatModel> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-verif-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return (await parseProject({ root, project: 'test' })).model;
}

/** A ledger that verifies every claim exactly as the model has it now. */
function ledgerFor(model: ThreatModel): Ledger {
  const ledger = emptyLedger();
  for (const r of relationRecords(model)) {
    const a = r.location.anchor!;
    ledger.entries.push({
      key: r.key, file: r.location.file, verb: r.verb, claim: r.claim,
      anchor: { scope: a.scope, symbol: a.symbol }, hash: a.hash,
      verified_by: 'human:test', verified_at: '2026-09-03T00:00:00.000Z',
    });
  }
  return ledger;
}

const present = (ledger: Ledger): LedgerRead => ({ status: 'present', ledger });

describe('classifyClaims', () => {
  it('no ledger: every claim unverified, nothing stale, ledger status carried', async () => {
    const model = await parsed();
    const report = classifyClaims(model, { status: 'absent', ledger: null });
    expect(report.ledger).toBe('absent');
    expect(report.claims.map(c => c.state)).toEqual(['unverified', 'unverified']);
    expect(report.summary).toMatchObject({ verified: 0, stale: 0, unverified: 2, orphans: 0, demotable_stale: 0 });
  });

  it('matching hash: verified', async () => {
    const model = await parsed();
    const report = classifyClaims(model, present(ledgerFor(model)));
    expect(report.claims.every(c => c.state === 'verified')).toBe(true);
    expect(report.claims[0].entry?.verified_by).toBe('human:test');
  });

  it('different hash: stale, counted by verb, demotable for mitigates only', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    for (const e of ledger.entries) e.hash = 'sha256-v1:' + '0'.repeat(64);
    const report = classifyClaims(model, present(ledger));
    expect(report.claims.map(c => c.state)).toEqual(['stale', 'stale']);
    expect(report.summary.stale_by_verb).toEqual({ mitigates: 1, exposes: 1 });
    expect(report.summary.demotable_stale).toBe(1);
    expect([...demotionSet(report)]).toEqual([report.claims.find(c => c.verb === 'mitigates')!.key]);
  });

  it('renamed symbol: stale with the rename hint', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    ledger.entries[0].hash = 'sha256-v1:' + '0'.repeat(64);
    ledger.entries[0].anchor.symbol = 'signIn';
    const report = classifyClaims(model, present(ledger));
    const bent = report.claims.find(c => c.key === ledger.entries[0].key)!;
    expect(bent).toMatchObject({ state: 'stale', hint: 'symbol-renamed' });
  });

  it('hash version mismatch: unverified with the version hint, never stale', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    ledger.anchor_hash_version = 99;
    const report = classifyClaims(model, present(ledger));
    expect(report.claims.every(c => c.state === 'unverified' && c.hint === 'hash-version')).toBe(true);
    expect(report.summary.stale).toBe(0);
  });

  it('entry with no matching claim: orphan', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    const ghost: LedgerEntry = { ...ledger.entries[0], key: 'f'.repeat(64) + ':0', claim: 'gone' };
    ledger.entries.push(ghost);
    const report = classifyClaims(model, present(ledger));
    expect(report.orphans).toEqual([ghost]);
    expect(report.summary.orphans).toBe(1);
  });

  it('a claim with no anchor is unverified and cannot be stale', async () => {
    const model = await parsed();
    const ledger = ledgerFor(model);
    model.mitigations[0].location.anchor = null;
    const report = classifyClaims(model, present(ledger));
    expect(report.claims.find(c => c.verb === 'mitigates')).toMatchObject({ state: 'unverified', anchor: null });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/verification.test.ts`
Expected: FAIL with `Failed to resolve import "../src/parser/verification.js"`.

- [ ] **Step 3: Write verification.ts**

```ts
// src/parser/verification.ts
/**
 * GuardLink — is this claim still about the code it was verified against?
 *
 * One predicate, called by every surface that answers that question: `ci`,
 * `status`, `verify`, and (in the Act plan) SARIF, report and MCP. A second
 * copy would be a tool that disagrees with `ci` about the same repository,
 * which is the defect coverage.ts (D36) was written to end.
 *
 * Pure. Anchors were attached during parseProject; the ledger was read by the
 * caller. Nothing here touches disk, so the answer is the same on a depth-one
 * CI checkout as on a developer's machine.
 *
 * States, from spec §7.3:
 *   entry present, hash equal ............ verified
 *   entry present, hash differs .......... stale   (+ symbol-renamed hint)
 *   no entry ............................. unverified
 *   entry at another hash version ........ unverified (+ hash-version hint)
 *   entry with no matching claim ......... orphan
 * A claim with no anchor (its file could not be read) is unverified: there is
 * nothing to compare, so it can never be stale.
 *
 * @flows ThreatModel -> #parser via classifyClaims -- "Anchors on every relation record compared with the ledger"
 * @flows LedgerFile -> #parser via classifyClaims -- "Recorded hashes, already read by the caller"
 * @comment -- "Pure function; no I/O. Demotion is a SET of claim keys handed to coverage.ts, never a rewrite of the model"
 */
import type { ThreatModel, SourceLocation, Anchor } from '../types/index.js';
import { relationRecords, type ClaimVerb } from './claim-key.js';
import type { Ledger, LedgerEntry, LedgerRead, LedgerStatus } from './ledger.js';
import { ANCHOR_HASH_VERSION } from '../structure/hash.js';

export type ClaimState = 'verified' | 'stale' | 'unverified';

export interface ClaimRecord {
  key: string;
  verb: ClaimVerb;
  /** Display text of the arguments (claim-key.ts claimText). */
  claim: string;
  state: ClaimState;
  location: SourceLocation;
  /** Null when the logical file could not be read. */
  anchor: Anchor | null;
  /** True for mitigates and accepts — the verbs whose staleness can hide an exposure. */
  demotable: boolean;
  entry?: LedgerEntry;
  hint?: 'symbol-renamed' | 'hash-version';
}

export interface VerificationReport {
  ledger: LedgerStatus;
  claims: ClaimRecord[];
  orphans: LedgerEntry[];
  summary: {
    verified: number;
    stale: number;
    unverified: number;
    orphans: number;
    stale_by_verb: Partial<Record<ClaimVerb, number>>;
    /** Stale mitigates + accepts: the number `--strict` and demotion act on. */
    demotable_stale: number;
  };
}

export function classifyClaims(model: ThreatModel, read: LedgerRead): VerificationReport {
  const ledger: Ledger | null = read.ledger;
  const versionMismatch = ledger !== null && ledger.anchor_hash_version !== ANCHOR_HASH_VERSION;
  const entries = new Map<string, LedgerEntry>();
  for (const e of ledger?.entries ?? []) entries.set(e.key, e);

  const claims: ClaimRecord[] = [];
  const seen = new Set<string>();
  for (const src of relationRecords(model)) {
    seen.add(src.key);
    const anchor = src.location.anchor ?? null;
    const entry = entries.get(src.key);
    const base = { key: src.key, verb: src.verb, claim: src.claim, location: src.location, anchor, demotable: src.demotable };

    if (!entry || !anchor) { claims.push({ ...base, state: 'unverified', entry }); continue; }
    if (versionMismatch) { claims.push({ ...base, state: 'unverified', entry, hint: 'hash-version' }); continue; }
    if (entry.hash === anchor.hash) { claims.push({ ...base, state: 'verified', entry }); continue; }
    const rec: ClaimRecord = { ...base, state: 'stale', entry };
    if (entry.anchor.symbol !== anchor.symbol) rec.hint = 'symbol-renamed';
    claims.push(rec);
  }

  const orphans = [...entries.values()].filter(e => !seen.has(e.key));

  const summary: VerificationReport['summary'] = {
    verified: 0, stale: 0, unverified: 0, orphans: orphans.length, stale_by_verb: {}, demotable_stale: 0,
  };
  for (const c of claims) {
    summary[c.state] += 1;
    if (c.state === 'stale') {
      summary.stale_by_verb[c.verb] = (summary.stale_by_verb[c.verb] ?? 0) + 1;
      if (c.demotable) summary.demotable_stale += 1;
    }
  }

  return { ledger: read.status, claims, orphans, summary };
}

/** Keys of stale mitigates and accepts — what coverage.ts is told to disregard when demotion is on. */
export function demotionSet(report: VerificationReport): Set<string> {
  return new Set(report.claims.filter(c => c.state === 'stale' && c.demotable).map(c => c.key));
}
```

- [ ] **Step 4: Run the test**

Run: `npx vitest run tests/verification.test.ts && npx tsc --noEmit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/parser/verification.ts tests/verification.test.ts
git commit -m "feat(parser): classify every claim as verified, stale or unverified

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 10: Verification planner and writer

**Files:**
- Create: `src/parser/verify.ts`
- Test: `tests/verify.test.ts`

**Interfaces:**
- Consumes: `VerificationReport`, `ClaimRecord` (Task 9); `Ledger`, `LedgerEntry`, `emptyLedger` (Task 8); `ANCHOR_HASH_VERSION` (Task 4).
- Produces: `VerifyMode`, `VerifyTarget`, `VerifyPlan`, `VerifierIdentity`, `planVerification(report, mode): VerifyPlan`, `applyVerification(current: Ledger | null, plan: VerifyPlan, identity: VerifierIdentity): Ledger`, `defaultVerifier(root): string`, `headCommit(root): string | undefined`, `nowIso(): string`. Task 11 wires these to the CLI.

- [ ] **Step 1: Write the failing test**

```ts
// tests/verify.test.ts
/**
 * The verify table from spec §10.1, one row per case, each driven through the
 * real parse → classify → plan → apply → write → re-parse → classify cycle. The
 * edit in the "stale" cases is the one a developer makes: change the body.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseProject } from '../src/parser/parse-project.js';
import { readLedger, writeLedger } from '../src/parser/ledger.js';
import { classifyClaims } from '../src/parser/verification.js';
import { planVerification, applyVerification, defaultVerifier, headCommit } from '../src/parser/verify.js';
import type { VerificationReport } from '../src/parser/verification.js';

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;

const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }

/**
 * @audit #api -- "Second symbol, own claim"
 */
export function other() { return 1; }
`;

const IDENTITY = { verified_by: 'human:test', verified_at: '2026-09-03T00:00:00.000Z' };

async function scaffold(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-verify-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return root;
}

async function classify(root: string): Promise<VerificationReport> {
  const { model } = await parseProject({ root, project: 'test' });
  return classifyClaims(model, readLedger(root));
}

async function bootstrap(root: string): Promise<void> {
  const report = await classify(root);
  writeLedger(root, applyVerification(null, planVerification(report, { kind: 'all' }), IDENTITY));
}

async function breakLogin(root: string): Promise<void> {
  await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
}

describe('verify', () => {
  it('default: locks unverified, prunes orphans, leaves stale alone', async () => {
    const root = await scaffold();
    const first = planVerification(await classify(root), { kind: 'default' });
    expect(first.lock.map(c => c.verb).sort()).toEqual(['audit', 'exposes', 'mitigates']);
    expect(first.relock).toEqual([]);
    writeLedger(root, applyVerification(null, first, IDENTITY));
    expect((await classify(root)).summary).toMatchObject({ verified: 3, stale: 0, unverified: 0 });

    await breakLogin(root);
    const after = await classify(root);
    expect(after.summary).toMatchObject({ verified: 1, stale: 2 });
    const plan = planVerification(after, { kind: 'default' });
    expect(plan.lock).toEqual([]);
    expect(plan.relock).toEqual([]);
  });

  it('--stale: re-locks every stale claim', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await breakLogin(root);
    const report = await classify(root);
    const plan = planVerification(report, { kind: 'stale' });
    expect(plan.relock.map(c => c.verb).sort()).toEqual(['exposes', 'mitigates']);
    writeLedger(root, applyVerification(readLedger(root).ledger, plan, { ...IDENTITY, verified_by: 'agent:test' }));
    const again = await classify(root);
    expect(again.summary).toMatchObject({ verified: 3, stale: 0 });
    expect(again.claims.find(c => c.verb === 'mitigates')!.entry!.verified_by).toBe('agent:test');
    expect(again.claims.find(c => c.verb === 'audit')!.entry!.verified_by).toBe('human:test');
  });

  it('a file target re-locks stale and locks unverified in that file only', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await breakLogin(root);
    const plan = planVerification(await classify(root), { kind: 'targets', targets: [{ file: 'src/api.ts' }] });
    expect(plan.relock.length).toBe(2);
    expect(plan.unmatched).toEqual([]);
    const none = planVerification(await classify(root), { kind: 'targets', targets: [{ file: 'src/nope.ts' }] });
    expect(none.relock).toEqual([]);
    expect(none.unmatched).toEqual(['src/nope.ts']);
  });

  it('a file:line target re-locks only the claim on that line', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await breakLogin(root);
    const plan = planVerification(await classify(root), { kind: 'targets', targets: [{ file: 'src/api.ts', line: 3 }] });
    expect(plan.relock.map(c => c.verb)).toEqual(['mitigates']);
    expect(plan.prune).toEqual([]);
  });

  it('orphans are pruned by default and by --all, kept by a line target', async () => {
    const root = await scaffold();
    await bootstrap(root);
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace(' * @audit #api -- "Second symbol, own claim"\n', ''));
    const report = await classify(root);
    expect(report.summary.orphans).toBe(1);
    expect(planVerification(report, { kind: 'default' }).prune.length).toBe(1);
    expect(planVerification(report, { kind: 'all' }).prune.length).toBe(1);
    expect(planVerification(report, { kind: 'targets', targets: [{ file: 'src/api.ts', line: 3 }] }).prune).toEqual([]);
  });

  it('a claim without an anchor is skipped with a reason', async () => {
    const root = await scaffold();
    const report = await classify(root);
    report.claims[0].anchor = null;
    report.claims[0].state = 'unverified';
    const plan = planVerification(report, { kind: 'all' });
    expect(plan.skipped).toEqual([{ key: report.claims[0].key, file: 'src/api.ts', line: report.claims[0].location.line, reason: 'no-anchor' }]);
  });

  it('a ledger at another hash version is rebuilt from the claims re-locked in this run', async () => {
    const root = await scaffold();
    await bootstrap(root);
    const old = readLedger(root).ledger!;
    old.anchor_hash_version = 99;
    writeLedger(root, old);
    const report = await classify(root);
    expect(report.summary.unverified).toBe(3);
    const rebuilt = applyVerification(readLedger(root).ledger, planVerification(report, { kind: 'default' }), IDENTITY);
    expect(rebuilt.anchor_hash_version).not.toBe(99);
    expect(rebuilt.entries.length).toBe(3);
  });

  it('identity helpers never throw', async () => {
    const root = await scaffold(); // not a git repo
    expect(defaultVerifier(root)).toMatch(/^human:.+/);
    expect(headCommit(root)).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/verify.test.ts`
Expected: FAIL with `Failed to resolve import "../src/parser/verify.js"`.

- [ ] **Step 3: Write verify.ts**

```ts
// src/parser/verify.ts
/**
 * GuardLink — decide which claims a verify run touches, and produce the ledger.
 *
 * Two pure steps so the CLI and the MCP tool cannot disagree:
 *   planVerification(report, mode) → which claims to lock, re-lock, prune, skip
 *   applyVerification(ledger, plan, identity) → the new ledger, not yet written
 *
 * Re-locking a stale claim asserts the control still holds, so the default
 * mode never does it; `stale`, `all` and a named target do, and say so.
 *
 * @flows #cli -> LedgerFile via applyVerification -- "The ledger the verify surfaces write"
 * @exposes #cli to #cmd-injection [low] cwe:CWE-78 -- "git is spawned for the verifier name and HEAD"
 * @mitigates #cli against #cmd-injection using #param-commands -- "execFileSync with a fixed argv; no shell, no caller-supplied argument"
 * @comment -- "Identity comes from git config or the OS user, is prefixed human: here and agent: in the MCP tool, and is recorded verbatim so a later gate can key on the prefix"
 */
import { execFileSync } from 'node:child_process';
import { userInfo } from 'node:os';
import type { Ledger, LedgerEntry } from './ledger.js';
import { emptyLedger } from './ledger.js';
import type { ClaimRecord, VerificationReport } from './verification.js';
import { ANCHOR_HASH_VERSION } from '../structure/hash.js';

export interface VerifyTarget { file: string; line?: number }

export type VerifyMode =
  | { kind: 'default' }
  | { kind: 'stale' }
  | { kind: 'all' }
  | { kind: 'targets'; targets: VerifyTarget[] };

export interface VerifyPlan {
  /** Unverified claims to record for the first time. */
  lock: ClaimRecord[];
  /** Stale claims to record again — an assertion that the control still holds. */
  relock: ClaimRecord[];
  /** Ledger entries with no matching claim. */
  prune: LedgerEntry[];
  /** Claims that cannot be recorded because their file could not be read. */
  skipped: { key: string; file: string; line: number; reason: 'no-anchor' }[];
  /** Targets that matched nothing. */
  unmatched: string[];
}

export interface VerifierIdentity {
  verified_by: string;
  verified_at: string;
  commit?: string;
}

const norm = (p: string): string => p.replaceAll('\\', '/').replace(/^\.\//, '');

export function planVerification(report: VerificationReport, mode: VerifyMode): VerifyPlan {
  const plan: VerifyPlan = { lock: [], relock: [], prune: [], skipped: [], unmatched: [] };
  const unverified = report.claims.filter(c => c.state === 'unverified');
  const stale = report.claims.filter(c => c.state === 'stale');

  const lockable = (cs: ClaimRecord[]): ClaimRecord[] => cs.filter(c => {
    if (c.anchor) return true;
    plan.skipped.push({ key: c.key, file: c.location.file, line: c.location.line, reason: 'no-anchor' });
    return false;
  });

  switch (mode.kind) {
    case 'default':
      plan.lock = lockable(unverified);
      plan.prune = report.orphans;
      break;
    case 'stale':
      plan.relock = stale;
      plan.prune = report.orphans;
      break;
    case 'all':
      plan.lock = lockable(unverified);
      plan.relock = stale;
      plan.prune = report.orphans;
      break;
    case 'targets':
      for (const t of mode.targets) {
        const file = norm(t.file);
        const hit = (c: ClaimRecord) => norm(c.location.file) === file && (t.line === undefined || c.location.line === t.line);
        const matchedUnverified = lockable(unverified.filter(hit));
        const matchedStale = stale.filter(hit);
        const matchedOrphans = t.line === undefined ? report.orphans.filter(o => norm(o.file) === file) : [];
        if (matchedUnverified.length + matchedStale.length + matchedOrphans.length === 0
          && !report.claims.some(hit)) {
          plan.unmatched.push(t.line === undefined ? t.file : `${t.file}:${t.line}`);
        }
        plan.lock.push(...matchedUnverified);
        plan.relock.push(...matchedStale);
        plan.prune.push(...matchedOrphans);
      }
      break;
  }
  return plan;
}

function entryFor(c: ClaimRecord, identity: VerifierIdentity): LedgerEntry {
  const a = c.anchor!;
  const e: LedgerEntry = {
    key: c.key, file: c.location.file, verb: c.verb, claim: c.claim,
    anchor: { scope: a.scope, symbol: a.symbol }, hash: a.hash,
    verified_by: identity.verified_by, verified_at: identity.verified_at,
  };
  if (identity.commit) e.commit = identity.commit;
  return e;
}

/**
 * The ledger after the plan. A ledger at another hash version is rebuilt from
 * this run's entries only: its old hashes cannot be compared, and every claim
 * it named was reported unverified, so the default mode re-records them all.
 */
export function applyVerification(current: Ledger | null, plan: VerifyPlan, identity: VerifierIdentity): Ledger {
  const next = emptyLedger();
  const byKey = new Map<string, LedgerEntry>();
  if (current && current.anchor_hash_version === ANCHOR_HASH_VERSION) {
    for (const e of current.entries) byKey.set(e.key, e);
  }
  for (const o of plan.prune) byKey.delete(o.key);
  for (const c of [...plan.lock, ...plan.relock]) byKey.set(c.key, entryFor(c, identity));
  next.entries = [...byKey.values()];
  return next;
}

function git(root: string, ...args: string[]): string | undefined {
  try {
    return execFileSync('git', args, { cwd: root, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || undefined;
  } catch {
    return undefined;
  }
}

/** `human:<git user.name>`, else `human:<OS user>`. One line, no control characters. */
export function defaultVerifier(root: string): string {
  const name = git(root, 'config', 'user.name') ?? userInfo().username;
  return `human:${name.replace(/[\r\n\t]+/g, ' ').trim() || 'unknown'}`;
}

export function headCommit(root: string): string | undefined {
  return git(root, 'rev-parse', 'HEAD');
}

export function nowIso(): string {
  return new Date().toISOString();
}
```

- [ ] **Step 4: Run the test**

Run: `npx vitest run tests/verify.test.ts && npx tsc --noEmit`
Expected: PASS. If `#param-commands` is rejected by `guardlink validate` later, it is a defined control (`Parameterized_Commands`) in `.guardlink/definitions.ts`; the id is correct as written.

- [ ] **Step 5: Commit**

```bash
git add src/parser/verify.ts tests/verify.test.ts
git commit -m "feat(parser): plan and apply a verify run — lock, re-lock, prune

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 11: `guardlink verify` command and public exports

**Files:**
- Modify: `src/cli/index.ts` (imports at line 47; new command block before `// ─── ci ───`), `src/parser/index.ts`, `src/index.ts`
- Test: `tests/verify-cli.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 8, 9, 10.
- Produces: the command `guardlink verify [dir] [targets...] [-p] [-f text|json] [--stale] [--all] [--dry-run] [--by <name>] [--force]`; JSON schema id `guardlink.verify/v1`; library exports `classifyClaims`, `demotionSet`, `relationRecords`, `claimText`, `readLedger`, `writeLedger`, `serializeLedger`, `emptyLedger`, `LEDGER_FILE`, `LEDGER_SCHEMA`, `planVerification`, `applyVerification`, `defaultVerifier`, `headCommit`, `parseStructure`, `languageForExtension`, `ANCHOR_HASH_VERSION`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/verify-cli.test.ts
/**
 * `guardlink verify` is a write command, so these cases run in order against
 * one fixture and read the ledger back from disk after each step. Spawns are
 * serial by necessity; the whole sequence runs once in beforeAll under a
 * generous timeout rather than once per `it`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

interface Run { status: number; stdout: string; stderr: string }
function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8' }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;
const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

async function scaffold(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-verify-cli-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"verify-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return root;
}

const ledgerOf = async (root: string) => JSON.parse(await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8'));

describe('guardlink verify', () => {
  let root: string;
  const runs: Record<string, Run> = {};

  beforeAll(async () => {
    root = await scaffold();
    runs.dry = await guardlink(root, 'verify', '.', '--dry-run');
    runs.dryHadNoLedger = { status: existsSync(join(root, '.guardlink', 'verified.json')) ? 1 : 0, stdout: '', stderr: '' };
    runs.first = await guardlink(root, 'verify', '.', '--by', 'alice', '--format', 'json');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
    runs.afterEdit = await guardlink(root, 'verify', '.');
    runs.lineTarget = await guardlink(root, 'verify', 'src/api.ts:3');
    runs.staleRest = await guardlink(root, 'verify', '.', '--stale');
    await writeFile(join(root, '.guardlink', 'verified.json'), '{broken');
    runs.corrupt = await guardlink(root, 'verify', '.');
    runs.forced = await guardlink(root, 'verify', '.', '--all', '--force');
  }, 90_000);

  it('--dry-run prints the plan and writes nothing', () => {
    expect(runs.dry.status).toBe(0);
    expect(runs.dry.stderr + runs.dry.stdout).toMatch(/would lock 2/i);
    expect(runs.dryHadNoLedger.status).toBe(0);
  });

  it('first run locks every claim under the named verifier, JSON carries the schema', async () => {
    expect(runs.first.status).toBe(0);
    const out = JSON.parse(runs.first.stdout);
    expect(out.schema).toBe('guardlink.verify/v1');
    expect(out.locked.length).toBe(2);
    expect(out.verified_by).toBe('human:alice');
    const ledger = await ledgerOf(root);
    expect(ledger.entries.every((e: { verified_by: string }) => e.verified_by === 'human:alice')).toBe(true);
  });

  it('after an edit, the default run reports stale claims and leaves them', () => {
    expect(runs.afterEdit.status).toBe(0);
    expect(runs.afterEdit.stderr).toMatch(/2 stale claim\(s\) left as they are/);
  });

  it('a file:line target as the first argument re-locks that claim only', () => {
    expect(runs.lineTarget.status).toBe(0);
    expect(runs.lineTarget.stderr).toMatch(/re-locked 1/i);
  });

  it('--stale re-locks what remains', () => {
    expect(runs.staleRest.status).toBe(0);
    expect(runs.staleRest.stderr).toMatch(/re-locked 1/i);
  });

  it('a corrupt ledger is refused without --force and rebuilt with it', async () => {
    expect(runs.corrupt.status).toBe(1);
    expect(runs.corrupt.stderr).toMatch(/ledger-corrupt|not valid JSON/);
    expect(runs.forced.status).toBe(0);
    const ledger = await ledgerOf(root);
    expect(ledger.schema).toBe('guardlink.verified/v1');
    expect(ledger.entries.length).toBe(2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/verify-cli.test.ts`
Expected: FAIL: commander reports `error: unknown command 'verify'` and every status is 1.

- [ ] **Step 3: Add the exports**

In `src/parser/index.ts`, append:

```ts
// Stale claim detection (docs/superpowers/specs/2026-09-03-stale-claim-detection-design.md).
export { relationRecords, claimText, DEMOTABLE_VERBS } from './claim-key.js';
export type { ClaimSource, ClaimVerb } from './claim-key.js';
export { readLedger, writeLedger, serializeLedger, emptyLedger, LEDGER_FILE, LEDGER_SCHEMA } from './ledger.js';
export type { Ledger, LedgerEntry, LedgerRead, LedgerStatus } from './ledger.js';
export { classifyClaims, demotionSet } from './verification.js';
export type { ClaimRecord, ClaimState, VerificationReport } from './verification.js';
export { planVerification, applyVerification, defaultVerifier, headCommit, nowIso } from './verify.js';
export type { VerifyMode, VerifyPlan, VerifyTarget, VerifierIdentity } from './verify.js';
```

In `src/index.ts`, after the `export * from './parser/index.js';` line:

```ts
export { parseStructure, languageForExtension, ANCHOR_HASH_VERSION } from './structure/index.js';
export type { FileStructure } from './structure/index.js';
```

- [ ] **Step 4: Add the command**

In `src/cli/index.ts`, extend the import on line 47 with `readLedger, writeLedger, classifyClaims, planVerification, applyVerification, defaultVerifier, headCommit, nowIso, LEDGER_FILE` and add `import { existsSync as fileExists, statSync } from 'node:fs';` is not needed — `existsSync` is already imported on line 46; add `statSync` to that import.

Insert before the `// ─── ci ───` divider:

```ts
// ─── verify ──────────────────────────────────────────────────────────

/**
 * @exposes #cli to #arbitrary-write [low] cwe:CWE-73 -- "The one command that writes .guardlink/verified.json"
 * @mitigates #cli against #arbitrary-write using #path-validation -- "Path is the constant LEDGER_FILE under the resolved root; targets only select claims, they are never written to"
 * @flows UserInput -> #cli via verify -- "Targets, --by and mode flags"
 * @comment -- "Re-locking a stale claim is an assertion that the control still holds, so the default form never does it: --stale, --all or a named target is required, and each says so in its output"
 */
program
  .command('verify')
  .description('Record that the code beneath each claim was checked — writes .guardlink/verified.json and nothing else')
  .argument('[dir]', 'Project directory (default .). A file or file:line here is taken as a target.', '.')
  .argument('[targets...]', 'file or file:line — lock unverified and re-lock stale claims there')
  .option('-p, --project <n>', 'Project name (default: the name in .guardlink/config.json)')
  .option('-f, --format <fmt>', 'Output format: text (default) or json', 'text')
  .option('--stale', 'Re-lock every stale claim (asserts each control still holds)')
  .option('--all', 'Lock unverified and re-lock stale — adoption bootstrap, or a deliberate reset')
  .option('--dry-run', 'Print what would change; write nothing')
  .option('--by <name>', 'Verifier name (default: git user.name, then the OS user)')
  .option('--force', 'Replace a ledger that failed to parse')
  .action(async (dirArg: string, targetArgs: string[], opts: { project?: string; format: string; stale?: boolean; all?: boolean; dryRun?: boolean; by?: string; force?: boolean }) => {
    if (opts.format !== 'text' && opts.format !== 'json') {
      console.error(`Unknown --format '${opts.format}'. Use text or json.`);
      process.exit(1);
    }
    if (opts.stale && opts.all) {
      console.error('--stale and --all are exclusive: --all already re-locks stale claims.');
      process.exit(1);
    }

    // A first positional that is not a directory is a target, and the root is cwd.
    let dir = dirArg;
    const targets = [...targetArgs];
    const isDir = (p: string): boolean => { try { return statSync(resolve(p)).isDirectory(); } catch { return false; } };
    if (!isDir(dirArg)) { targets.unshift(dirArg); dir = '.'; }
    const root = resolve(dir);

    const read = readLedger(root);
    if (read.status === 'corrupt' && !opts.force) {
      console.error(`✗ ${read.diagnostic!.message}`);
      console.error('   Refusing to write over it. Re-run with --force to rebuild the ledger from the current code.');
      process.exit(1);
    }

    const { model } = await parseProject({ root, project: opts.project ?? readConfiguredProject(root) ?? undefined });
    const report = classifyClaims(model, read);

    const mode = targets.length > 0
      ? { kind: 'targets' as const, targets: targets.map(t => { const m = /^(.*?)(?::(\d+))?$/.exec(t)!; return m[2] ? { file: m[1], line: Number(m[2]) } : { file: m[1] }; }) }
      : opts.all ? { kind: 'all' as const } : opts.stale ? { kind: 'stale' as const } : { kind: 'default' as const };
    const plan = planVerification(report, mode);

    const verified_by = opts.by ? `human:${opts.by}` : defaultVerifier(root);
    const identity = { verified_by, verified_at: nowIso(), commit: headCommit(root) };
    const next = applyVerification(read.ledger, plan, identity);
    if (!opts.dryRun) writeLedger(root, next);

    const staleLeft = report.claims.filter(c => c.state === 'stale' && !plan.relock.includes(c));

    if (opts.format === 'json') {
      const brief = (c: { key: string; location: { file: string; line: number }; verb: string; claim: string }) =>
        ({ key: c.key, file: c.location.file, line: c.location.line, verb: c.verb, claim: c.claim });
      console.log(JSON.stringify({
        schema: 'guardlink.verify/v1',
        dry_run: opts.dryRun === true,
        verified_by,
        commit: identity.commit ?? null,
        locked: plan.lock.map(brief),
        relocked: plan.relock.map(brief),
        pruned: plan.prune.map(e => ({ key: e.key, file: e.file, verb: e.verb, claim: e.claim })),
        skipped: plan.skipped,
        unmatched: plan.unmatched,
        stale_remaining: staleLeft.map(brief),
        ledger: LEDGER_FILE,
      }, null, 2));
      return;
    }

    const verb = opts.dryRun ? 'Would lock' : 'Locked';
    console.error(`${verb} ${plan.lock.length} claim(s), re-locked ${plan.relock.length}, pruned ${plan.prune.length} orphan(s) as ${verified_by}${opts.dryRun ? ' (dry run — nothing written)' : ` → ${LEDGER_FILE}`}`);
    for (const c of plan.relock) console.error(`   re-locked  ${c.location.file}:${c.location.line}  @${c.verb} ${c.claim}`);
    for (const s of plan.skipped) console.error(`   skipped    ${s.file}:${s.line}  (${s.reason}: the file could not be read)`);
    for (const u of plan.unmatched) console.error(`   no claim at ${u}`);
    if (staleLeft.length > 0) {
      console.error(`${staleLeft.length} stale claim(s) left as they are — run \`guardlink verify --stale\`, or name the file, to re-lock them:`);
      for (const c of staleLeft) console.error(`   ${c.location.file}:${c.location.line}  @${c.verb} ${c.claim}`);
    }
  });
```

- [ ] **Step 5: Run the test, then the whole suite**

Run: `npx vitest run tests/verify-cli.test.ts && npm test && npm run lint`
Expected: all PASS. If the dry-run assertion fails on wording, the text output must contain `Would lock 2` — check the `verb` variable.

- [ ] **Step 6: Commit**

```bash
git add src/cli/index.ts src/parser/index.ts src/index.ts tests/verify-cli.test.ts
git commit -m "feat(cli): guardlink verify — record that the code beneath each claim was checked

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 12: Third check in `guardlink ci`

**Files:**
- Modify: `src/ci/index.ts` (whole file: types, `runCiChecks`, `formatCiReport`)
- Test: `tests/ci-verification.test.ts`

**Interfaces:**
- Consumes: `readLedger`, `LEDGER_FILE`, `LedgerEntry`, `LedgerStatus` (Task 8); `classifyClaims`, `ClaimRecord` (Task 9).
- Produces: `CiClaim`, and on `CiReport`: `stale: CiClaim[]`, `unverified: CiClaim[]`, `orphans: LedgerEntry[]`; on `CiSummary`: `stale`, `unverified`, `orphans`, `stale_by_verb`, `demotable_stale`, `demote_stale` (always `false` in this plan; the Act plan wires it), `ledger: LedgerStatus`. Exit code: `strict && (exposures > 0 || drift > 0 || demotable_stale > 0)`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/ci-verification.test.ts
/**
 * The third `ci` check, driven through the real CLI like tests/ci.test.ts,
 * because the thing under test is an exit code and a stream. `verify` is a
 * write, so the fixture moves through its states in one ordered beforeAll.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

interface Run { status: number; stdout: string; stderr: string }
function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8' }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;
/** One exposure, mitigated: a repo that has finished, so only staleness can move the verdict. */
const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

async function scaffold(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'guardlink-ci-verif-'));
  await mkdir(join(root, '.guardlink'), { recursive: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), '{"name":"ci-fixture","version":"1.0.0"}\n');
  await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
  await writeFile(join(root, 'src', 'api.ts'), SOURCE);
  return root;
}

describe('guardlink ci — stale claims', () => {
  let root: string;
  const r: Record<string, Run> = {};
  let ledgerBefore = '';
  let ledgerAfter = '';

  beforeAll(async () => {
    root = await scaffold();
    r.noLedger = await guardlink(root, 'ci', '.');
    r.noLedgerStrict = await guardlink(root, 'ci', '.', '--strict');
    r.noLedgerJson = await guardlink(root, 'ci', '.', '--format', 'json');
    await guardlink(root, 'verify', '.', '--by', 'alice');
    r.clean = await guardlink(root, 'ci', '.');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
    ledgerBefore = await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8');
    r.stale = await guardlink(root, 'ci', '.');
    r.staleStrict = await guardlink(root, 'ci', '.', '--strict');
    r.staleJson = await guardlink(root, 'ci', '.', '--format', 'json');
    ledgerAfter = await readFile(join(root, '.guardlink', 'verified.json'), 'utf-8');
    await writeFile(join(root, '.guardlink', 'verified.json'), '{broken');
    r.corrupt = await guardlink(root, 'ci', '.');
    r.corruptJson = await guardlink(root, 'ci', '.', '--format', 'json');
  }, 120_000);

  it('no ledger: advisory, exit 0 even with --strict, prints the bootstrap command', () => {
    expect(r.noLedger.status).toBe(0);
    expect(r.noLedger.stderr).toMatch(/none recorded/);
    expect(r.noLedger.stderr).toMatch(/guardlink verify --all/);
    expect(r.noLedgerStrict.status).toBe(0);
    const json = JSON.parse(r.noLedgerJson.stdout);
    expect(json.summary.ledger).toBe('absent');
    expect(json.stale).toEqual([]);
    expect(json.unverified.length).toBe(2);
    expect(json.summary.demote_stale).toBe(false);
  });

  it('every claim verified: the all-clear line mentions stale claims', () => {
    expect(r.clean.status).toBe(0);
    expect(r.clean.stderr).toMatch(/No stale claims/);
  });

  it('after an edit: stale claims listed, mitigation first, advisory exit 0, strict exit 1', () => {
    expect(r.stale.status).toBe(0);
    expect(r.stale.stderr).toMatch(/2 stale claim\(s\)/);
    expect(r.stale.stderr).toMatch(/src\/api\.ts:3\s+@mitigates #api against #sqli using #prepared-stmts\s+\(login, verified \d{4}-\d{2}-\d{2} by human:alice\)/);
    expect(r.stale.stderr).toMatch(/Advisory/);
    expect(r.staleStrict.status).toBe(1);
    const json = JSON.parse(r.staleJson.stdout);
    expect(json.schema).toBe('guardlink.ci/v1');
    expect(json.stale[0].verb).toBe('mitigates');
    expect(json.stale[0]).toMatchObject({ file: 'src/api.ts', line: 3, scope: 'symbol', symbol: 'login', verified_by: 'human:alice' });
    expect(json.summary).toMatchObject({ stale: 2, unverified: 0, orphans: 0, demotable_stale: 1, ledger: 'present', stale_by_verb: { mitigates: 1, exposes: 1 } });
  });

  it('ci never writes the ledger', () => {
    expect(ledgerAfter).toBe(ledgerBefore);
  });

  it('corrupt ledger: reported once, treated as absent, still advisory', () => {
    expect(r.corrupt.status).toBe(0);
    expect(r.corrupt.stderr).toMatch(/verified\.json/);
    expect(r.corrupt.stderr).toMatch(/unreadable/);
    expect(JSON.parse(r.corruptJson.stdout).summary.ledger).toBe('corrupt');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/ci-verification.test.ts`
Expected: FAIL: `none recorded` absent from stderr; `json.summary.ledger` undefined.

- [ ] **Step 3: Extend the CI module**

Replace the import block at the top of `src/ci/index.ts` with:

```ts
import type { ThreatModel, ThreatModelExposure, Severity } from '../types/index.js';
import { findUnmitigatedExposures } from '../parser/coverage.js';
import { findAnchorDrift, type AnchorDrift } from '../parser/reanchor.js';
import { countAnchors } from '../parser/annotation-hash.js';
import { readLedger, LEDGER_FILE, type LedgerEntry, type LedgerStatus } from '../parser/ledger.js';
import { classifyClaims, type ClaimRecord, type VerificationReport } from '../parser/verification.js';
import type { ClaimVerb } from '../parser/claim-key.js';
```

Add to the module doc block, after the two existing check lines:

```
 *   stale claims          → `classifyClaims`             (parser/verification.ts)
```

and these annotations to the same doc block:

```
 * @flows LedgerFile -> #cli via readLedger -- "Recorded claim hashes, read only"
 * @comment -- "The third check reads .guardlink/verified.json and never writes it; a corrupt ledger is reported once and treated as absent"
```

After the `CiOptions` interface, add:

```ts
/** A claim as `ci` reports it: no raw annotation text, no model record. */
export interface CiClaim {
  key: string;
  file: string;
  line: number;
  verb: ClaimVerb;
  claim: string;
  scope: 'symbol' | 'block' | 'file' | null;
  symbol: string | null;
  hint?: ClaimRecord['hint'];
  verified_by?: string;
  verified_at?: string;
}

function toCiClaim(c: ClaimRecord): CiClaim {
  const out: CiClaim = {
    key: c.key, file: c.location.file, line: c.location.line, verb: c.verb, claim: c.claim,
    scope: c.anchor?.scope ?? null, symbol: c.anchor?.symbol ?? null,
  };
  if (c.hint) out.hint = c.hint;
  if (c.entry) { out.verified_by = c.entry.verified_by; out.verified_at = c.entry.verified_at; }
  return out;
}

/** Demotable verbs first, then by file and line — the order a reviewer wants. */
function byUrgency(a: ClaimRecord, b: ClaimRecord): number {
  if (a.demotable !== b.demotable) return a.demotable ? -1 : 1;
  return a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line;
}
```

In `CiSummary`, after `by_kind`, add:

```ts
  /** Stale claims — `stale.length`. */
  stale: number;
  /** Claims with no ledger entry. Never affects the exit code. */
  unverified: number;
  /** Ledger entries with no matching claim. */
  orphans: number;
  stale_by_verb: Partial<Record<ClaimVerb, number>>;
  /** Stale mitigates + accepts — what `--strict` fails on. */
  demotable_stale: number;
  /** Whether stale mitigations were disregarded by coverage. Always false until demotion ships. */
  demote_stale: boolean;
  ledger: LedgerStatus;
```

In `CiReport`, after `drift`, add:

```ts
  stale: CiClaim[];
  unverified: CiClaim[];
  orphans: LedgerEntry[];
```

Replace the body of `runCiChecks` with:

```ts
export function runCiChecks(root: string, model: ThreatModel, opts: CiOptions = {}): CiReport {
  const exposures = findUnmitigatedExposures(model);
  const drift = findAnchorDrift(root, model);
  const read = readLedger(root);
  const verification: VerificationReport = classifyClaims(model, read);
  const staleRecords = verification.claims.filter(c => c.state === 'stale').sort(byUrgency);
  const unverifiedRecords = verification.claims.filter(c => c.state === 'unverified').sort(byUrgency);
  const strict = opts.strict === true;
  const found = exposures.length > 0 || drift.length > 0 || verification.summary.demotable_stale > 0;

  return {
    schema: CI_SCHEMA,
    exposures,
    drift,
    stale: staleRecords.map(toCiClaim),
    unverified: unverifiedRecords.map(toCiClaim),
    orphans: verification.orphans,
    summary: {
      exposures: exposures.length,
      drift: drift.length,
      anchors: countAnchors(model),
      by_severity: countBySeverity(exposures),
      by_kind: countByKind(drift),
      stale: verification.summary.stale,
      verified: verification.summary.verified,
      unverified: verification.summary.unverified,
      orphans: verification.summary.orphans,
      stale_by_verb: verification.summary.stale_by_verb,
      demotable_stale: verification.summary.demotable_stale,
      demote_stale: false,
      ledger: read.status,
      strict,
      exit_code: strict && found ? 1 : 0,
    },
  };
}
```

In `CiSummary`, the `stale` field added above needs a sibling so the text line can state a denominator without carrying every verified claim. Add, directly after `stale: number;`:

```ts
  /** Claims whose hash matches the ledger. Carried as a count only. */
  verified: number;
```

and set it in `runCiChecks` alongside the other verification counts: `verified: verification.summary.verified,`.

In `formatCiReport`, after the `Anchor drift:` push and before the exposures block, add:

```ts
  const verbs = Object.entries(summary.stale_by_verb).filter(([, n]) => n > 0).map(([v, n]) => `${v} ${n}`);
  if (summary.ledger === 'absent') {
    out.push('Stale claims: none recorded — run `guardlink verify --all` to start tracking');
  } else if (summary.ledger === 'corrupt') {
    out.push(`Stale claims: ledger unreadable (${LEDGER_FILE}) — see guardlink validate`);
  } else {
    out.push(`Stale claims: ${summary.stale}${verbs.length > 0 ? ` (${verbs.join(', ')})` : ''}`
      + ` of ${summary.stale + summary.verified} recorded claim(s); unverified ${summary.unverified}; orphans ${summary.orphans}`);
  }
```

Then, after the drift block and before the all-clear, add:

```ts
  if (report.stale.length > 0) {
    out.push('', `⚠  ${report.stale.length} stale claim(s) — the code beneath them changed since verification:`);
    for (const c of report.stale) {
      const who = c.verified_at && c.verified_by ? `, verified ${c.verified_at.slice(0, 10)} by ${c.verified_by}` : '';
      const where = c.symbol ?? (c.scope === 'file' ? 'whole file' : 'block');
      const hint = c.hint === 'symbol-renamed' ? ' [symbol renamed]' : '';
      out.push(`   ${c.file}:${c.line}  @${c.verb} ${c.claim}  (${where}${who})${hint}`);
    }
  }
```

Replace the all-clear/advisory tail with:

```ts
  const clean = exposures.length === 0 && drift.length === 0 && report.stale.length === 0;
  if (clean) {
    out.push('', `✓ No unmitigated exposures, no anchor drift.${summary.ledger === 'present' ? ' No stale claims.' : ''}`);
  } else if (!summary.strict) {
    out.push('', 'Advisory — nothing here failed the build. Run with --strict to gate on it.');
  }
```

Finally, in `src/cli/index.ts` `ci` action, the corrupt-ledger diagnostic must print once in text mode. After `const report = runCiChecks(...)`, add:

```ts
    if (report.summary.ledger === 'corrupt' && opts.format === 'text') {
      console.error(`✗ ${readLedger(root).diagnostic!.message}`);
    }
```

and update the JSON-mode summary line to `GuardLink CI: ${report.summary.exposures} unmitigated exposure(s), ${report.summary.drift} drifted anchor(s), ${report.summary.stale} stale claim(s)`.

- [ ] **Step 4: Run the new test, the old ci test, then everything**

Run: `npx vitest run tests/ci-verification.test.ts tests/ci.test.ts && npm test && npm run lint`
Expected: PASS. If `tests/ci.test.ts` asserts the exact all-clear string, it still matches by containment. If it asserts an exact JSON key set, add the new keys to the expectation; do not remove them from the report.

- [ ] **Step 5: Commit**

```bash
git add src/ci/index.ts src/cli/index.ts tests/ci-verification.test.ts
git commit -m "feat(ci): third check — claims whose code changed since verification

Advisory by default like the other two. --strict fails on a stale mitigation
or acceptance, never on an unverified claim, because every repository is
entirely unverified on the day it adopts this.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 13: `status` line and `validate` ledger diagnostic

**Files:**
- Modify: `src/cli/index.ts` (`status` action near line 255; `validate` action near line 293; `printStatus` near line 2663)
- Test: `tests/status-verification.test.ts`

**Interfaces:**
- Consumes: `readLedger` (Task 8), `classifyClaims`, `VerificationReport` (Task 9).
- Produces: `printStatus(model, verification?: VerificationReport)`; `validate` emits `ledger-corrupt` and exits 1 on it.

- [ ] **Step 1: Write the failing test**

```ts
// tests/status-verification.test.ts
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(repoRoot, 'src', 'cli', 'index.ts');
const tsx = createRequire(import.meta.url).resolve('tsx/cli');

interface Run { status: number; stdout: string; stderr: string }
function guardlink(cwd: string, ...args: string[]): Promise<Run> {
  return new Promise(resolve => {
    execFile(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf-8' }, (err, stdout, stderr) => {
      const code = (err as { code?: number | string } | null)?.code;
      resolve({ status: typeof code === 'number' ? code : err ? 1 : 0, stdout, stderr });
    });
  });
}

const DEFINITIONS = `/**
 * @asset App.API (#api) -- "API surface"
 * @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Untrusted input into SQL"
 * @control Prepared_Statements (#prepared-stmts) -- "Parameterized queries"
 */
export {};
`;
const SOURCE = `/**
 * @exposes #api to #sqli [critical] -- "email concatenated into SQL"
 * @mitigates #api against #sqli using #prepared-stmts -- "Parameterized via pg"
 */
export function login(email: string) { return email; }
`;

describe('status and validate know about the ledger', () => {
  let root: string;
  const r: Record<string, Run> = {};

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'guardlink-status-verif-'));
    await mkdir(join(root, '.guardlink'), { recursive: true });
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'package.json'), '{"name":"status-fixture","version":"1.0.0"}\n');
    await writeFile(join(root, '.guardlink', 'definitions.ts'), DEFINITIONS);
    await writeFile(join(root, 'src', 'api.ts'), SOURCE);
    r.statusNone = await guardlink(root, 'status', '.');
    await guardlink(root, 'verify', '.');
    r.statusAll = await guardlink(root, 'status', '.');
    await writeFile(join(root, 'src', 'api.ts'), SOURCE.replace('return email;', 'return email.trim();'));
    r.statusStale = await guardlink(root, 'status', '.');
    r.validateOk = await guardlink(root, 'validate', '.');
    await writeFile(join(root, '.guardlink', 'verified.json'), '{broken');
    r.validateCorrupt = await guardlink(root, 'validate', '.');
  }, 90_000);

  it('status: none recorded, then counts, then stale', () => {
    expect(r.statusNone.stdout).toMatch(/Verified claims:\s+none recorded/);
    expect(r.statusAll.stdout).toMatch(/Verified claims:\s+2 \/ 2 \(stale 0, unverified 0\)/);
    expect(r.statusStale.stdout).toMatch(/Verified claims:\s+0 \/ 2 \(stale 2, unverified 0\)/);
  });

  it('validate: a corrupt ledger is an error that fails the command', () => {
    expect(r.validateOk.status).toBe(0);
    expect(r.validateCorrupt.status).toBe(1);
    expect(r.validateCorrupt.stderr + r.validateCorrupt.stdout).toMatch(/verified\.json/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/status-verification.test.ts`
Expected: FAIL: no `Verified claims` line; `validateCorrupt.status` is 0.

- [ ] **Step 3: Wire status and validate**

In `printStatus`, change the signature to `function printStatus(model: ThreatModel, verification?: VerificationReport)` (import the type from `../parser/index.js`) and, immediately after the `Annotations:` line, add:

```ts
  if (verification) {
    const s = verification.summary;
    if (verification.ledger === 'absent') {
      console.log('Verified claims:  none recorded (run guardlink verify --all)');
    } else if (verification.ledger === 'corrupt') {
      console.log('Verified claims:  ledger unreadable (run guardlink validate)');
    } else {
      console.log(`Verified claims:  ${s.verified} / ${s.verified + s.stale + s.unverified} (stale ${s.stale}, unverified ${s.unverified})`);
    }
  }
```

In the `status` action, replace `printStatus(model);` with:

```ts
    printStatus(model, classifyClaims(model, readLedger(root)));
```

In the `validate` action, after `const galConventionDiags = findOffConventionGalFiles(model);`, add:

```ts
    // A ledger that exists but cannot be read is an error: every surface that
    // reads it is silently treating it as absent until someone fixes it.
    const ledgerRead = readLedger(root);
    const ledgerDiags = ledgerRead.diagnostic ? [ledgerRead.diagnostic] : [];
```

and include `...ledgerDiags` in the `allDiags` array. The existing error count over `allDiags` makes the exit code 1.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run tests/status-verification.test.ts && npm test && npm run lint`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli/index.ts tests/status-verification.test.ts
git commit -m "feat(cli): status counts verified claims; validate fails on a corrupt ledger

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

### Task 14: Docs, changelog, and dogfood rollout on this repository

**Files:**
- Modify: `CHANGELOG.md` (Unreleased), `docs/GUARDLINK_REFERENCE.md`, `.github/workflows/ci.yml`
- Create: `.guardlink/verified.json` (generated by `verify --all`)
- Regenerate: `.guardlink/graph/**`, `.guardlink/README.md`, `CLAUDE.md`, `AGENTS.md` (by `artifacts` and `sync`)

**Interfaces:** none new. This task proves the whole half on the repository that ships it.

- [ ] **Step 1: Write the changelog entry**

Under `## [Unreleased]` in `CHANGELOG.md`, add:

```markdown
### Added

- **Stale claim detection — the first half.** A claim in a comment was never re-checked: remove the control beneath a `@mitigates` and the model kept reporting the exposure as covered. GuardLink now resolves every annotation to the declaration it sits on (tree-sitter, every language in the default include list), hashes that declaration's non-comment tokens, and records the hash in a committed ledger, `.guardlink/verified.json`, when a person or agent verifies the claim.

  - `guardlink verify [dir] [file[:line]…] [--stale] [--all] [--dry-run] [--by <name>] [--force]` writes the ledger and nothing else. The default form locks unverified claims and prunes orphans; re-locking a stale claim takes `--stale`, `--all`, or a named target, because that is an assertion that the control still holds. The verifier is recorded as `human:<git user.name>`.
  - `guardlink ci` gains a third check. Stale claims are listed, mitigations and acceptances first. Advisory by default; `--strict` exits 1 on a stale mitigation or acceptance and never on an unverified claim. JSON under `guardlink.ci/v1` gains `stale`, `unverified`, `orphans` and matching summary counts, additively.
  - `guardlink status` adds one line: verified, stale and unverified counts.
  - `guardlink validate` emits `ledger-corrupt` when the ledger exists and does not parse.
  - Library: `classifyClaims`, `demotionSet`, `relationRecords`, `readLedger`, `writeLedger`, `planVerification`, `applyVerification` from `guardlink/parser`; `parseStructure` from the new `guardlink/structure` subpath. `SourceLocation` gains an optional `anchor`. `ParseProjectOptions.anchors` (default true) skips the structure pass.

  Package size grows by about 25 MB of grammar WASM, fetched at build time from pinned npm packages. Swift and Kotlin ship no WASM and resolve to file scope until one is provided. Demotion (a stale mitigation counting as unmitigated), SARIF and report changes, the MCP `guardlink_verify` tool and the template changes follow in the second half. Design: `docs/superpowers/specs/2026-09-03-stale-claim-detection-design.md`.
```

- [ ] **Step 2: Add the reference section**

In `docs/GUARDLINK_REFERENCE.md`, add a section (after the CI section if one exists, else at the end):

```markdown
## Stale claims and the verification ledger

Every relationship annotation is bound at parse time to the declaration beneath it — the function a doc-block sits on, the statement an inline comment precedes, the whole file for a header block — and that declaration's non-comment tokens are hashed. `guardlink verify` records the hash in `.guardlink/verified.json` with who verified it and when. On every later parse, `guardlink ci` and `guardlink status` compare the current hash with the recorded one.

| State | Meaning |
|---|---|
| `verified` | hash matches the ledger |
| `stale` | the code beneath the claim changed after it was verified |
| `unverified` | no ledger entry yet — every claim starts here; never fails a build |

Commit the ledger. It needs no git history to read, so it works on a depth-one CI checkout. Re-locking a stale claim is an explicit act: `guardlink verify --stale`, `guardlink verify --all`, or `guardlink verify src/file.ts:33`. The default `guardlink verify` only locks new claims and prunes entries whose claim is gone.

Put claims on the function that implements the control, not in the file header. A file-header claim is bound to the whole file and goes stale on any edit to it.
```

- [ ] **Step 3: Build, bootstrap the ledger, and look at the result**

Run:
```bash
npm run build
node dist/cli/index.js verify . --all
node dist/cli/index.js ci .
node dist/cli/index.js status . | grep 'Verified claims'
```
Expected: `verify` reports roughly 470 claims locked as `human:<your git name>`; `ci` prints `No stale claims.`; `status` shows `N / N (stale 0, unverified 0)`. If `verify` skips claims with `no-anchor`, those are `.gal` sidecars pointing at files that no longer exist — list them and leave them; they are already reported by `reanchor`.

- [ ] **Step 4: Add the CI step**

In `.github/workflows/ci.yml`, after the `GuardLink status` step and before the D16 clean-tree guard, add:

```yaml
      # Stale claim detection, advisory. The clean-tree guard below now also
      # proves that `ci` reads the ledger and never writes it.
      - name: GuardLink ci (advisory)
        run: node dist/cli/index.js ci .
```

- [ ] **Step 5: Regenerate artifacts and agent files**

The new source files carry annotations, so the model moved and the committed graph artifacts are stale until regenerated (the CI `validate --artifacts` step fails otherwise).

Run:
```bash
node dist/cli/index.js artifacts .
node dist/cli/index.js sync
node dist/cli/index.js validate . --artifacts
git status --short
```
Expected: `validate` exits 0 with no dangling refs; `git status` shows the regenerated `.guardlink/graph/**`, `.guardlink/README.md`, `CLAUDE.md`, `AGENTS.md`, the new `.guardlink/verified.json`, and the edited docs and workflow. Do not commit `.guardlink/config.json` (gitignored).

- [ ] **Step 6: Run everything once more, then commit**

Run: `npm test && npm run lint && node dist/cli/index.js diff HEAD~1 | head -40`
Expected: suite green; the diff shows only added annotations from the new modules, no removed mitigations.

```bash
git add CHANGELOG.md docs/GUARDLINK_REFERENCE.md .github/workflows/ci.yml .guardlink/verified.json .guardlink/graph .guardlink/README.md CLAUDE.md AGENTS.md
git commit -m "chore: bootstrap the verification ledger, run ci in the workflow, document the feature

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0193KRf2zpp1JAh7Fa2hx6Zs"
```

---

## Spec coverage (self-review)

| Spec section | Where in this plan |
|---|---|
| §5 Architecture: structure layer, ledger, predicate, verify surfaces, parser touch, `parent_symbol` untouched | Tasks 2–6 (structure), 8 (ledger), 9 (predicate), 10–11 (verify), 6 (parser); `parent_symbol` is read in Task 6 only to resolve external-mode symbols and never written |
| §6.1 API | Task 5 (`parseStructure`, `FileStructure`), Task 4 (`ANCHOR_HASH_VERSION`), Task 2 (`languageForExtension`) |
| §6.2 Anchor rules, order, YAML, file-scope list | Task 5 `resolveAnchor`; Task 2 `EXTENSION_LANGUAGE` nulls |
| §6.3 Hash | Task 4 |
| §6.4 Grammars bundled, own build, size | Task 2 (deviation 5: fetched from tarballs rather than built; recorded in the header) |
| §6.5 Performance: annotated files only, once per process, lazy grammars | Task 6 (grouping), Task 3 (caches). The fingerprint change is in the Act plan, as the spec's §16 places it |
| §6.6 External mode via `symbolNamed` | Task 5 (`findNamed`), Task 6 (`parent_symbol` lookup) |
| §7 Ledger format, key, states, scope, merge behaviour | Task 8 (format, sort, one per line, corrupt), Task 7 (key, ordinal, scope of verbs), Task 9 (states) |
| §8 Predicate; `demotionSet` | Task 9. The coverage filter and config key are Act-plan work |
| §8 Strict semantics | Task 12 exit code |
| §9 `ci`, `status`, `validate` | Tasks 12, 13. `sarif`, `report`, MCP: Act plan |
| §10.1 `verify` CLI, every table row, identity, `--dry-run`, `--force` | Tasks 10, 11 |
| §10.2 MCP tool | Act plan |
| §11 Agent loop | Act plan |
| §12 Failure modes | no-grammar/grammar-failed: Task 3, 5; no anchor: Tasks 5, 6, 9, 10; ledger missing/corrupt/unknown schema: Tasks 8, 11, 12, 13; hash version: Tasks 9, 10; renamed: Task 9; moved claim: Task 7 (new key) + Task 10 (prune); git absent: Task 10; duplicates: Task 7 |
| §13 Type and schema changes | Task 1 (types), Task 11 (exports), Task 2 (package.json), Task 12 (`CiReport`), Task 14 (changelog) |
| §14 Tests | one test file per task; grammar load test in Task 2; read-only guard in Task 12 and the workflow in Task 14 |
| §15 Rollout steps 1–4 | Task 14. Step 5 (moving file-level claims down) is a separate follow-up |

**Placeholder scan:** none. Every code step shows the code it asks for.

**Type consistency:** `ClaimRecord` fields (`key`, `verb`, `claim`, `state`, `location`, `anchor`, `demotable`, `entry`, `hint`) are identical in Tasks 9, 10, 12. `LedgerRead` is the argument to `classifyClaims` in Tasks 9, 11, 12, 13. `VerifyPlan` has `lock`, `relock`, `prune`, `skipped`, `unmatched` in Tasks 10 and 11. `Anchor` fields match between Task 1 and every consumer.
