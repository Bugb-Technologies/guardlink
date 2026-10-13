/**
 * `init` writes an include covering every language present that GuardLink
 * parses — not just the one the root manifest names.
 *
 * Before this, a repository with a TypeScript frontend and a Rust backend got
 * `**\/*.{ts,tsx,js,jsx}` only: every `.rs` and `.mjs` file was outside the scan,
 * and an annotation written there reached no model. The fixtures here are built
 * from scratch in a temp directory, one shape per case.
 *
 * @validates #glob-filtering for #init -- "Scope detection honours DEFAULT_EXCLUDE and git ignores, and every scanned extension is classified as in-scope or deliberately not"
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { initProject } from '../src/init/index.js';
import { detectIncludeScope, describeScope, LANGUAGE_FAMILIES, NOT_INCLUDED_FORMATS } from '../src/init/scope.js';
import { SCANNED_EXTENSIONS } from '../src/parser/languages.js';
import { parseProject } from '../src/parser/parse-project.js';

const LEGACY_TS = ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'];

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guardlink-init-scope-'));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function put(files: Record<string, string>): Promise<void> {
  for (const [rel, body] of Object.entries(files)) {
    await mkdir(dirname(join(root, rel)), { recursive: true });
    await writeFile(join(root, rel), body);
  }
}

function gitInit(): void {
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, stdio: 'ignore' });
  git('init', '-q');
  git('add', '-A');
}

const config = async () => JSON.parse(await readFile(join(root, '.guardlink', 'config.json'), 'utf-8'));

/** A web frontend in TypeScript with a Rust backend beside it. */
const MIXED = {
  'package.json': '{"name":"mixed-demo","version":"1.0.0"}\n',
  'tsconfig.json': '{}\n',
  'src/App.tsx': 'export const App = () => null;\n',
  'src/api.ts': 'export function call(cmd: string) { return cmd; }\n',
  'scripts/build.mjs': 'export default {};\n',
  'backend/Cargo.toml': '[package]\nname = "backend"\n',
  'backend/src/main.rs': '// @exposes #ipc to #cmd-injection [high] -- "command name from the frontend"\nfn main() {}\n',
  'backend/src/commands.rs': 'pub fn run() {}\n',
  'README.md': '# demo\n',
  // Default excludes: neither of these may move the scope.
  'node_modules/dep/index.cjs': 'module.exports = {};\n',
  'backend/target/debug/build.rs': 'fn main() {}\n',
};

describe('mixed TypeScript + Rust repository', () => {
  it('includes both languages, and the .mjs the old include missed', async () => {
    await put(MIXED);
    const { scope } = initProject({ root, agentIds: [] });
    const cfg = await config();

    expect(cfg.include).toEqual([...LEGACY_TS, '**/*.mjs', '**/*.rs']);
    expect(cfg.language).toBe('typescript');
    expect(scope.languages.map(l => l.name)).toEqual(['TypeScript/JavaScript', 'Rust']);
    expect(scope.languages[1].files).toEqual({ '.rs': 2 });
  });

  it('does not count files under default-excluded directories', async () => {
    await put(MIXED);
    const scope = detectIncludeScope(root, 'typescript');
    expect(scope.include).not.toContain('**/*.cjs');
    expect(scope.languages.find(l => l.name === 'Rust')!.files['.rs']).toBe(2);
  });

  it('the written scope is what the parser then reads', async () => {
    await put(MIXED);
    initProject({ root, agentIds: [] });
    const { model } = await parseProject({ root, include: (await config()).include });
    expect(model.exposures.map(e => e.location.file)).toContain('backend/src/main.rs');
  });

  it('prints each language with the reason it is in scope', async () => {
    await put(MIXED);
    const text = describeScope(detectIncludeScope(root, 'typescript')).join('\n');
    expect(text).toMatch(/\+ TypeScript\/JavaScript: found \.ts ×1, \.tsx ×1, \.mjs ×1/);
    expect(text).toMatch(/\+ Rust: found \.rs ×2/);
    expect(text).toMatch(/- \.md \(1 file\): markup\/data format/);
    expect(text).toMatch(/include: \*\*\/\*\.ts, .*\*\*\/\*\.rs/);
  });

  it('in a git work tree, counts tracked and unignored files only', async () => {
    await put({ ...MIXED, '.gitignore': 'generated/\n', 'generated/schema.go': 'package gen\n' });
    gitInit();
    const scope = detectIncludeScope(root, 'typescript');
    expect(scope.source).toBe('git');
    expect(scope.include).not.toContain('**/*.go');
    expect(scope.include).toContain('**/*.rs');
  });
});

describe('single-language repository', () => {
  it('a TypeScript project keeps the include init has always written', async () => {
    await put({
      'package.json': '{"name":"ts-only"}\n',
      'tsconfig.json': '{}\n',
      'src/index.ts': 'export {};\n',
      'src/view.tsx': 'export {};\n',
    });
    initProject({ root, agentIds: [] });
    expect((await config()).include).toEqual(LEGACY_TS);
  });

  it('a Rust project keeps **/*.rs', async () => {
    await put({ 'Cargo.toml': '[package]\nname = "r"\n', 'src/lib.rs': 'pub fn f() {}\n' });
    initProject({ root, agentIds: [] });
    expect((await config()).include).toEqual(['**/*.rs']);
  });

  it('a manifest with no source yet still gets its language', async () => {
    await put({ 'package.json': '{"name":"empty"}\n' });
    const { scope } = initProject({ root, agentIds: [] });
    expect((await config()).include).toEqual(LEGACY_TS);
    expect(scope.languages[0].reason).toMatch(/manifest/);
  });
});

describe('repository in a language GuardLink cannot parse', () => {
  const ZIG = {
    'build.zig': 'const std = @import("std");\n',
    'src/main.zig': 'pub fn main() void {}\n',
    'docs/site.yaml': 'title: x\n',
    'README.md': '# zig\n',
  };

  it('leaves the language out, says why, and keeps the old fallback', async () => {
    await put(ZIG);
    const { scope } = initProject({ root, agentIds: [] });
    expect((await config()).include).toEqual(['**/*.ts', '**/*.js', '**/*.py', '**/*.go', '**/*.rs', '**/*.java']);
    expect(scope.excluded).toContainEqual({ ext: '.zig', files: 2, reason: 'no GuardLink parser' });
    expect(scope.excluded).toContainEqual({ ext: '.yaml', files: 1, reason: 'markup/data format' });
    expect(scope.languages[0].reason).toMatch(/no parseable source/);
  });

  it('beside a parseable language, only the parseable one is included', async () => {
    await put({ ...ZIG, 'tools/gen.py': 'print(1)\n' });
    const { scope } = initProject({ root, agentIds: [] });
    expect((await config()).include).toEqual(['**/*.py']);
    expect(scope.include.some(g => g.endsWith('.zig') || g.endsWith('.yaml'))).toBe(false);
  });
});

describe('an existing config.json', () => {
  it('is not touched by a plain re-run, even when the scope has grown', async () => {
    await put({ 'package.json': '{"name":"grows"}\n', 'src/a.ts': 'export {};\n' });
    initProject({ root, agentIds: [] });
    const before = await readFile(join(root, '.guardlink', 'config.json'), 'utf-8');

    await put({ 'backend/src/main.rs': 'fn main() {}\n' });
    const result = initProject({ root, agentIds: [] });

    expect(await readFile(join(root, '.guardlink', 'config.json'), 'utf-8')).toBe(before);
    expect(result.scopeWritten).toBe(false);
    // Untouched, but not silently: the caller is told what the config misses.
    expect(result.scopeMissing).toEqual(['**/*.rs']);
  });

  it('--force names --refresh-scope when the include is the only difference', async () => {
    await put({ 'package.json': '{"name":"grows"}\n', 'src/a.ts': 'export {};\n' });
    initProject({ root, agentIds: [] });
    await put({ 'backend/src/main.rs': 'fn main() {}\n' });

    const result = initProject({ root, force: true, agentIds: [] });
    expect((await config()).include).toEqual(LEGACY_TS);
    expect(result.preserved.join('\n')).toMatch(/--refresh-scope/);
  });

  it('--refresh-scope rewrites include and nothing else', async () => {
    await put({ 'package.json': '{"name":"grows"}\n', 'src/a.ts': 'export {};\n' });
    initProject({ root, mode: 'inline', agentIds: [] });
    const cfg = await config();
    cfg.exclude = ['custom'];
    cfg.extra = { kept: true };
    await writeFile(join(root, '.guardlink', 'config.json'), JSON.stringify(cfg, null, 2) + '\n');
    await put({ 'backend/src/main.rs': 'fn main() {}\n' });

    const result = initProject({ root, refreshScope: true, agentIds: [] });
    const after = await config();

    expect(after.include).toEqual([...LEGACY_TS, '**/*.rs']);
    expect(after).toEqual({ ...cfg, include: after.include });
    expect(result.updated).toContain('.guardlink/config.json (include refreshed)');
    expect(result.scopeWritten).toBe(true);
    expect(result.scopeRefreshOnly).toBe(true);
  });

  it('--refresh-scope with --dry-run writes nothing', async () => {
    await put({ 'package.json': '{"name":"grows"}\n', 'src/a.ts': 'export {};\n' });
    initProject({ root, agentIds: [] });
    const before = await readFile(join(root, '.guardlink', 'config.json'), 'utf-8');
    await put({ 'backend/src/main.rs': 'fn main() {}\n' });

    initProject({ root, refreshScope: true, dryRun: true, agentIds: [] });
    expect(await readFile(join(root, '.guardlink', 'config.json'), 'utf-8')).toBe(before);
  });
});

describe('every scanned extension is classified', () => {
  it('language families and the not-included formats partition the scan set', () => {
    const classified = [...LANGUAGE_FAMILIES.flatMap(f => f.exts), ...NOT_INCLUDED_FORMATS];
    expect(new Set(classified).size).toBe(classified.length);
    expect([...classified].sort()).toEqual([...SCANNED_EXTENSIONS].sort());
  });
});
