/**
 * GuardLink agent config — read each configuration file into rows.
 *
 * A row is GuardLink's own reach vocabulary (SPEC §3.2.1): an `@agents` reach
 * (what an agent can invoke), an `@effects` (what running it does to the
 * developer's machine) and a `@gates` (who is asked first), each carrying the
 * file, line and key that granted it and the harness rule that interpreted it.
 * Nothing here is a verdict: a row says what the configuration lets an agent
 * do, and `@entitles` is still how a human says it may.
 *
 * Only `root` and `nested` configuration creates rows. `packaged`
 * configuration is inventory (MCP servers and hooks it would install) and
 * `fixture` configuration is listed and otherwise left alone.
 *
 * The reader never executes, starts, fetches or resolves anything a file names:
 * an MCP launch command is recorded as text, and a hook's script is read as a
 * file to say what it does.
 *
 * @exposes #parser to #path-traversal [medium] cwe:CWE-22 -- "A hook command or MCP launch names a script path that is then read"
 * @mitigates #parser against #path-traversal using #path-validation -- "repoFile rejects absolute paths and any path whose resolved real path leaves the repository root before it is read"
 * @exposes #parser to #data-exposure [medium] cwe:CWE-532 -- "MCP server env and headers can carry literal credentials"
 * @mitigates #parser against #data-exposure using #key-redaction -- "Only the NAMES of credential-like env vars and headers are kept; values are never copied into the model"
 * @exposes #parser to #dos [low] cwe:CWE-400 -- "Configuration files and the scripts they name are read whole"
 * @mitigates #parser against #dos using #resource-limits -- "Files above MAX_BYTES are reported unreadable instead of read"
 * @flows ProjectFiles -> #parser via readFileSync -- "Agent configuration, instruction files and hook scripts"
 * @comment -- "Never executes, starts or fetches anything named in configuration: launch commands and hook commands are recorded as text"
 */
import { readFileSync, realpathSync, statSync, existsSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import type {
  ThreatModelReach, ThreatModelEffect, ThreatModelGate, ThreatModelActor, EffectClass,
  AgentConfigSource, AgentConfigScope, AgentConfigLoadedWhen, AgentConfigMcpServer, AgentConfigHook,
  AgentConfigInstructionFile, AgentConfigBlock,
} from '../types/index.js';
import { normalizeName } from '../parser/normalize.js';
import { parseJsonc, asObject, asArray, asString, pointerToken, type JsonValue, type JsoncDocument } from './jsonc.js';
import { parseToml } from './toml.js';
import { findHiddenUnicode } from './hidden-unicode.js';
import {
  loadSemantics, tableRef, classifyShell, commandTags, capToken, REACH_HARNESSES,
  type Semantics, type DangerClass,
} from './semantics.js';
import type { DiscoveredFile } from './discover.js';

/** Configuration files and scripts larger than this are reported, not read. */
export const MAX_BYTES = 2 * 1024 * 1024;

export const WORKSTATION = '#dev-workstation';
export const SESSION = '#developer-session';
export const DEVELOPER = '#developer';

const SECRET_KEY = /(token|secret|passw|api[_-]?key|apikey|auth|bearer|credential|private[_-]?key|access[_-]?key)/i;
const CONTENT_SOURCES = /github|gitlab|linear|jira|atlassian|sentry|slack|notion|browser|playwright|puppeteer|fetch|firecrawl|web|search|docs|context7|confluence|gmail|mail/i;
const RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'uvx', 'pipx', 'dlx', 'deno']);
const MARKDOWN_KINDS = new Set(['instructions', 'skill', 'command', 'subagent']);

export const GUARDLINK_BEGIN = '<!-- guardlink:begin -->';
export const GUARDLINK_END = '<!-- guardlink:end -->';
/** The provenance header every GuardLink block carries on the line after its begin marker. */
export const STAMP_RE = /<!--\s*guardlink:stamp\b([^>]*)-->/;

export interface StampFields { annotation_hash: string | null; agent_config_hash: string | null }

export function parseStamp(text: string): StampFields | null {
  const m = STAMP_RE.exec(text);
  if (!m) return null;
  const field = (k: string) => new RegExp(`\\b${k}=(\\S+)`).exec(m[1])?.[1] ?? null;
  return { annotation_hash: field('annotation_hash'), agent_config_hash: field('agent_config_hash') };
}

const slug = (s: string) => s.replace(/[^A-Za-z0-9]+/g, '-').replace(/^-|-$/g, '').toLowerCase().slice(0, 48) || 'x';

export interface ReadResult {
  actors: ThreatModelActor[];
  reaches: ThreatModelReach[];
  effects: ThreatModelEffect[];
  gates: ThreatModelGate[];
  block: Omit<AgentConfigBlock, 'agent_config_hash'>;
}

interface Ctx {
  root: string;
  realRoot: string;
  sem: Semantics;
  file: DiscoveredFile;
  text: string;
  doc: JsoncDocument | null;
}

interface RowOpts {
  harness: string;
  pointer: string;
  raw: string;
  rule: string;
  gated?: boolean;
  admits?: string[];
  description: string;
  /** Rows sharing a binding are bound together, like claims in one doc-block. Defaults to the pointer. */
  binding?: string;
  line?: number;
}

class Builder {
  readonly reaches: ThreatModelReach[] = [];
  readonly effects: ThreatModelEffect[] = [];
  readonly gates: ThreatModelGate[] = [];
  readonly actorIds = new Map<string, ThreatModelActor>();
  readonly assets = new Map<string, string>();
  readonly mcp: AgentConfigMcpServer[] = [];
  readonly hooks: AgentConfigHook[] = [];
  readonly instructions: AgentConfigInstructionFile[] = [];
  readonly denies: AgentConfigBlock['denies'] = [];
  readonly untrusted: AgentConfigBlock['untrusted_sources'] = [];
  readonly unreadable: AgentConfigBlock['unreadable'] = [];

  constructor(readonly sem: Semantics) {}

  asset(id: string, description: string): string {
    if (!this.assets.has(id)) this.assets.set(id, description);
    return id;
  }

  private source(ctx: Ctx, o: RowOpts): AgentConfigSource {
    const table = this.sem.harnesses.get(o.harness);
    const rule = table?.rules?.[o.rule];
    return {
      harness: o.harness,
      file_kind: ctx.file.kind,
      pointer: o.pointer,
      raw: o.raw,
      scope: ctx.file.scope,
      gated: o.gated ?? rule?.gated ?? false,
      loaded_when: (rule?.loaded_when ?? ctx.file.loaded_when) as AgentConfigLoadedWhen[],
      semantics: {
        table: table ? tableRef(table) : `${o.harness}@unknown`,
        rule: o.rule,
        ...((o.admits ?? rule?.admits) ? { admits: o.admits ?? rule?.admits } : {}),
        doc: rule?.doc ?? '',
      },
    };
  }

  private loc(ctx: Ctx, o: RowOpts) {
    return { file: ctx.file.path, line: o.line ?? lineOf(ctx, o.pointer), binding: o.binding ?? o.pointer };
  }

  actor(ctx: Ctx, harness: string): string {
    const table = this.sem.harnesses.get(harness);
    const id = table?.actor?.id ?? harness;
    if (!this.actorIds.has(id)) {
      const name = table?.actor?.name ?? id;
      this.actorIds.set(id, {
        name, canonical_name: normalizeName(name), id,
        description: table?.actor?.description ?? id,
        location: { file: ctx.file.path, line: 1 },
        origin: 'agent-config',
      });
    }
    return `#${id}`;
  }

  reach(ctx: Ctx, capability: string, asset: string, o: RowOpts & { identity?: string }): ThreatModelReach {
    const r: ThreatModelReach = {
      actor: this.actor(ctx, o.harness), agent: true, capability, canonical_capability: normalizeName(capability),
      asset, ...(o.identity ? { identity: o.identity } : {}), description: o.description,
      location: this.loc(ctx, o), origin: 'agent-config', source: this.source(ctx, o),
    };
    this.reaches.push(r);
    return r;
  }

  effect(ctx: Ctx, effect: EffectClass, asset: string, o: RowOpts): ThreatModelEffect {
    const e: ThreatModelEffect = {
      effect, asset, identity: SESSION, description: o.description,
      location: this.loc(ctx, o), origin: 'agent-config', source: this.source(ctx, o),
    };
    this.asset(SESSION, "The developer's session: their shell, files, tokens and network");
    this.effects.push(e);
    return e;
  }

  gate(ctx: Ctx, asset: string, capability: string | undefined, o: RowOpts): ThreatModelGate {
    if (!this.actorIds.has('developer')) {
      this.actorIds.set('developer', {
        name: 'Developer', canonical_name: 'developer', id: 'developer',
        description: 'The developer at the keyboard: approves what the configuration does not pre-approve',
        location: { file: ctx.file.path, line: 1 }, origin: 'agent-config',
      });
    }
    const g: ThreatModelGate = {
      asset, approver: DEVELOPER, ...(capability ? { capability, canonical_capability: normalizeName(capability) } : {}),
      description: o.description, location: this.loc(ctx, o), origin: 'agent-config', source: this.source(ctx, o),
    };
    this.gates.push(g);
    return g;
  }
}

function lineOf(ctx: Ctx, pointer: string): number {
  return ctx.doc?.lines.get(pointer) ?? 1;
}

function ptr(...parts: (string | number)[]): string {
  return parts.map(p => `/${pointerToken(String(p))}`).join('');
}

/** A repository file named in configuration, or null when it is absent or outside the root. */
function repoFile(root: string, realRoot: string, rel: string): string | null {
  if (!rel || rel.startsWith('/') || /^[A-Za-z]:/.test(rel)) return null;
  const abs = resolve(root, rel);
  try {
    const real = realpathSync(abs);
    if (real !== realRoot && !real.startsWith(realRoot + sep)) return null;
    if (!statSync(real).isFile()) return null;
    return rel.split(sep).join('/');
  } catch {
    return null;
  }
}

function readSmall(path: string): string | null {
  try {
    if (statSync(path).size > MAX_BYTES) return null;
    return readFileSync(path, 'utf-8');
  } catch {
    return null;
  }
}

/** Repository files a command string runs: `"$CLAUDE_PROJECT_DIR"/x.sh`, `./scripts/y.py`, `node z.mjs`. */
export function referencedScripts(cmd: string, root: string, realRoot: string, base = ''): string[] {
  const c = cmd.replaceAll('"$CLAUDE_PROJECT_DIR"', '').replaceAll('$CLAUDE_PROJECT_DIR', '')
    .replaceAll('${CLAUDE_PLUGIN_ROOT}', base);
  const out = new Set<string>();
  for (const tok of c.match(/[\w./${}-]+\.(?:sh|bash|py|mjs|cjs|js|ts|ps1|rb)\b/g) ?? []) {
    const t = tok.replace(/^(\.\/|\/)+/, '');
    for (const cand of base ? [t, `${base}/${t}`] : [t]) {
      const f = repoFile(root, realRoot, cand);
      if (f) { out.add(f); break; }
    }
  }
  return [...out].sort();
}

function frontmatter(text: string): { fields: Map<string, { value: string; line: number }> } {
  const fields = new Map<string, { value: string; line: number }>();
  const m = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(\r?\n|$)/.exec(text);
  if (!m) return { fields };
  m[1].split('\n').forEach((l, i) => {
    const mm = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(l);
    if (mm) fields.set(mm[1], { value: mm[2].trim(), line: i + 2 });
  });
  return { fields };
}

/** `Bash(git log:*)` → (`Bash`, `git log:*`); `Bash` → (`Bash`, null). */
export function parseRule(rule: string): { tool: string; spec: string | null } {
  const m = /^\s*([A-Za-z_][\w]*)(?:\(([\s\S]*)\))?\s*$/.exec(rule);
  return m ? { tool: m[1], spec: m[2] ?? null } : { tool: rule, spec: null };
}

/** The effect a dangerous shell rule has on the workstation, per `shell.json`. */
function dangerEffect(sem: Semantics, d: DangerClass | null): EffectClass | null {
  return d ? sem.shell.classes[d].effect : null;
}

// ─── Shell rules (Claude Code, Cursor CLI, VS Code terminal, Gemini) ─────

function shellRule(b: Builder, ctx: Ctx, harness: string, spec: string | null, o: Omit<RowOpts, 'rule' | 'harness' | 'description'> & { key: string }) {
  const v = classifyShell(spec, harness, b.sem);
  const admits = v.danger ? b.sem.shell.classes[v.danger].admits : undefined;
  const ruleId = harness === 'claude-code' ? v.rule : rulesFor(b, harness, 'shell');
  const description = `${o.key} ${o.raw}: ${v.why}, without asking`;
  b.reach(ctx, v.capability, b.asset(WORKSTATION, workstationDesc()), { ...o, harness, rule: ruleId, gated: false, admits, description });
  const eff = dangerEffect(b.sem, v.danger);
  if (eff) b.effect(ctx, eff, WORKSTATION, { ...o, harness, rule: ruleId, admits, description });
}

function rulesFor(b: Builder, harness: string, what: 'shell' | 'hook' | 'mcp-server'): string {
  const rules = b.sem.harnesses.get(harness)?.rules ?? {};
  if (what === 'shell') return rules['shell-allow'] ? 'shell-allow' : rules['terminal-auto-approve'] ? 'terminal-auto-approve' : 'bash-prefix';
  return what;
}

const workstationDesc = () => 'Developer machine: the shell, files, network and credentials of the person running the agent';

// ─── Hooks ──────────────────────────────────────────────────────────

function hookCommand(
  b: Builder, ctx: Ctx, harness: string, event: string, matcher: string | undefined, cmd: string, pointer: string,
  rule: string, base = '',
) {
  const runs = referencedScripts(cmd, ctx.root, ctx.realRoot, base);
  const body = [cmd, ...runs.map(r => readSmall(join(ctx.root, r)) ?? '')].join('\n');
  const does = commandTags(body, b.sem);
  const line = lineOf(ctx, pointer);
  b.hooks.push({
    harness, event, ...(matcher ? { matcher } : {}), file: ctx.file.path, line, scope: ctx.file.scope,
    command: cmd, runs, does,
  });
  if (!producesRows(ctx)) return;
  b.asset(WORKSTATION, workstationDesc());
  b.effect(ctx, 'execute', WORKSTATION, {
    harness, pointer, raw: cmd, rule, line,
    description: `${event}${matcher ? ` [${matcher}]` : ''} runs \`${cmd.slice(0, 100)}\` automatically${runs.length ? ` (runs ${runs.join(', ')})` : ''}`
      + `; it does: ${does.join(', ') || 'local commands only'}`,
  });
}

function hooksBlock(b: Builder, ctx: Ctx, harness: string, hooks: JsonValue | undefined, at: string, base = '') {
  const h = asObject(hooks);
  if (!h) return;
  for (const [event, groups] of Object.entries(h)) {
    asArray(groups).forEach((g, gi) => {
      const go = asObject(g);
      if (!go) return;
      const matcher = asString(go.matcher) ?? undefined;
      const inner = Array.isArray(go.hooks) ? go.hooks : [g];
      inner.forEach((x, xi) => {
        const xo = asObject(x);
        if (!xo) return;
        const key = ['command', 'bash', 'powershell'].find(k => typeof xo[k] === 'string');
        if (!key) return;
        const p = Array.isArray(go.hooks) ? `${at}${ptr(event, gi, 'hooks', xi, key)}` : `${at}${ptr(event, gi, key)}`;
        hookCommand(b, ctx, harness, event, matcher, xo[key] as string, p, 'hook', base);
      });
    });
  }
}

// ─── MCP servers ────────────────────────────────────────────────────

/** `(package spec, pinned, auto-yes)` for a package-runner launch (npx, uvx, …), else null. */
export function packageOf(command: string, args: string[]): { spec: string; pinned: boolean; auto_yes: boolean } | null {
  const base = command.split(/[\\/]/).pop() ?? '';
  let toks = [base, ...args];
  if ((base === 'pnpm' || base === 'yarn') && toks[1] === 'dlx') toks = toks.slice(1);
  if (base === 'pipx' && toks[1] === 'run') toks = toks.slice(1);
  if (!RUNNERS.has(toks[0])) {
    if (base === 'docker' && toks.includes('run')) {
      const img = toks.slice(toks.indexOf('run') + 1).find(t => !t.startsWith('-') && !t.includes('='));
      if (img) return { spec: img, pinned: img.includes('@sha256:'), auto_yes: false };
    }
    return null;
  }
  const auto_yes = toks.some(t => t === '-y' || t === '--yes');
  const rest = toks.slice(1);
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i];
    if (t === '--from' || t === '-p' || t === '--package') {
      const spec = rest[i + 1] ?? '';
      return { spec, pinned: pinnedSpec(toks[0], spec), auto_yes };
    }
    if (t.startsWith('-')) continue;
    if (t.startsWith('.') || t.startsWith('/')) return null;
    return { spec: t, pinned: pinnedSpec(toks[0], t), auto_yes };
  }
  return null;
}

function pinnedSpec(runner: string, spec: string): boolean {
  if (runner === 'uvx' || runner === 'pipx') return spec.includes('==') || spec.includes('@');
  const body = spec.startsWith('@') ? spec.slice(1) : spec;
  return /@\d/.test(body);
}

/** The bin of this repository's own package.json that `command` names, as a repository path. */
function ownBin(ctx: Ctx, command: string): { package: string; bin: string; file: string } | null {
  const candidates = ['package.json'];
  for (const pj of candidates) {
    const text = readSmall(join(ctx.root, pj));
    if (!text) continue;
    let d: { name?: string; bin?: string | Record<string, string> };
    try { d = JSON.parse(text); } catch { continue; }
    let bin: string | null = null;
    if (typeof d.bin === 'string' && d.name === command) bin = d.bin;
    else if (d.bin && typeof d.bin === 'object' && typeof d.bin[command] === 'string') bin = d.bin[command];
    if (!bin) continue;
    const binPath = bin.replace(/^\.\//, '');
    // A compiled bin is reported against its source when the repository carries one.
    const m = /^(dist|build|lib)\/(.+)\.(c|m)?js$/.exec(binPath);
    const src = m ? ['ts', 'mts', 'tsx', 'js'].map(ext => `src/${m[2]}.${ext}`).find(s => existsSync(join(ctx.root, s))) : undefined;
    return { package: d.name ?? command, bin: binPath, file: src ?? binPath };
  }
  return null;
}

function mcpServers(b: Builder, ctx: Ctx, servers: JsonValue | undefined, at: string, harnesses: string[]) {
  const so = asObject(servers);
  if (!so) return;
  for (const [name, raw] of Object.entries(so)) {
    const srv = asObject(raw);
    if (!srv) continue;
    const p = `${at}${ptr(name)}`;
    const line = lineOf(ctx, p);
    const url = asString(srv.url) ?? asString(srv.serverUrl) ?? asString(srv.httpUrl) ?? '';
    let command = '';
    let args: string[] = asArray(srv.args).map(a => String(a));
    if (Array.isArray(srv.command)) {
      const parts = srv.command.map(a => String(a));
      command = parts[0] ?? '';
      args = [...parts.slice(1), ...args];
    } else {
      command = asString(srv.command) ?? '';
    }
    const transport: 'stdio' | 'http' = url ? 'http' : 'stdio';
    const env = { ...(asObject(srv.env) ?? asObject(srv.environment) ?? {}) };
    const headers = asObject(srv.headers) ?? {};
    const credential_env = [...Object.keys(env), ...Object.keys(headers)].filter(k => SECRET_KEY.test(k)).sort();
    const disabled = srv.disabled === true;
    const auto = [...asArray(srv.alwaysAllow), ...asArray(srv.autoApprove)].map(String);
    const trusted = srv.trust === true;
    let host: string | undefined;
    if (url) { try { host = new URL(url).host; } catch { host = undefined; } }

    const ob = command ? ownBin(ctx, command.split(/[\\/]/).pop() ?? command) : null;
    const local = [command, ...args].map(a => a.replace(/^(\.\/)+/, ''))
      .find(a => /\.(ts|js|mjs|cjs|py|rb|go|sh)$/.test(a) && repoFile(ctx.root, ctx.realRoot, a));
    const resolves_to = ob
      ? { kind: 'own-bin' as const, file: ob.file, package: ob.package, bin: ob.bin }
      : local ? { kind: 'repo-file' as const, file: local } : undefined;
    const pkg = command ? packageOf(command, args) : null;
    const thirdParty = CONTENT_SOURCES.test([name, host ?? '', command, ...args].join(' '));

    for (const harness of harnesses) {
      b.mcp.push({
        name, harness, file: ctx.file.path, line, scope: ctx.file.scope, transport,
        ...(transport === 'stdio' ? { launch: { command, args } } : {}),
        ...(host ? { host } : {}),
        ...(resolves_to ? { resolves_to } : {}),
        ...(pkg ? { package: pkg } : {}),
        credential_env, returns_third_party_content: thirdParty, disabled,
      });
      if (!producesRows(ctx) || disabled) continue;
      const assetId = b.asset(`#mcp-${slug(name)}`, `MCP server '${name}' (${transport}${host ? ` ${host}` : ''})`);
      const identity = credential_env.length > 0
        ? b.asset(`#cred-${slug(credential_env[0])}`, `Credential ${credential_env[0]} passed to MCP server '${name}'`)
        : undefined;
      const launch = transport === 'http' ? (host ?? 'remote') : [command, ...args].join(' ');
      const rule = trusted ? 'mcp-server-trusted' : auto.length > 0 && b.sem.harnesses.get(harness)?.rules?.['mcp-tool-auto'] ? 'mcp-tool-auto' : 'mcp-server';
      const gated = !(trusted || auto.length > 0) && (b.sem.harnesses.get(harness)?.rules?.['mcp-server']?.gated ?? true);
      b.reach(ctx, `mcp.${capToken(slug(name))}`, assetId, {
        harness, pointer: p, raw: name, rule, gated, identity,
        description: `MCP server '${name}' (${transport}: ${launch.slice(0, 120)})`
          + (trusted ? '; trust: true, every tool call runs without asking'
            : auto.length > 0 ? `; ${auto.slice(0, 8).join(', ')} run without asking` : gated ? '; each tool call asks' : ''),
      });
      if (thirdParty && !b.untrusted.some(u => u.kind === 'mcp-server' && u.source === assetId)) {
        b.untrusted.push({ source: assetId, kind: 'mcp-server', file: ctx.file.path, line, agents: [] });
      }
      const u = b.untrusted.find(x => x.kind === 'mcp-server' && x.source === assetId);
      const actor = `#${b.sem.harnesses.get(harness)?.actor?.id ?? harness}`;
      if (u && !u.agents.includes(actor)) u.agents.push(actor);
    }
  }
}

// ─── Per kind ───────────────────────────────────────────────────────

const producesRows = (ctx: Ctx) => ctx.file.scope === 'root' || ctx.file.scope === 'nested';

function reachHarnesses(f: DiscoveredFile): string[] {
  return f.harnesses.filter(h => (REACH_HARNESSES as readonly string[]).includes(h));
}

function claudeSettings(b: Builder, ctx: Ctx) {
  const d = asObject(ctx.doc!.value) ?? {};
  const H = 'claude-code';
  const perms = asObject(d.permissions) ?? {};
  if (producesRows(ctx)) {
    asArray(perms.allow).forEach((r, i) => {
      if (typeof r !== 'string') return;
      const p = ptr('permissions', 'allow', i);
      const { tool, spec } = parseRule(r);
      const base = { pointer: p, raw: r };
      if (tool === 'Bash') { shellRule(b, ctx, H, spec, { ...base, key: 'permissions.allow' }); return; }
      const ws = b.asset(WORKSTATION, workstationDesc());
      if (tool === 'WebFetch' || tool === 'WebSearch') {
        const any = !spec;
        const cap = `${tool.toLowerCase()}.${spec ? capToken(spec.replace('domain:', '')) : 'any'}`;
        const danger: DangerClass | null = any && tool === 'WebFetch' ? 'net' : null;
        const description = `permissions.allow ${r}: ${danger ? 'any URL, an egress for anything the agent has read' : 'scoped'}, without asking`;
        b.reach(ctx, cap, ws, { ...base, harness: H, rule: 'web-fetch', admits: danger ? b.sem.shell.classes.net.admits : undefined, description });
        if (danger) b.effect(ctx, 'notify', ws, { ...base, harness: H, rule: 'web-fetch', description });
        return;
      }
      if (tool.startsWith('mcp__')) {
        const parts = tool.split('__');
        const server = parts[1] ?? '';
        const cap = `mcp.${capToken(server)}.${parts.length > 2 ? capToken(parts.slice(2).join('__')) : 'all-tools'}`;
        b.reach(ctx, cap, b.asset(`#mcp-${slug(server)}`, `MCP server '${server}'`), {
          ...base, harness: H, rule: 'mcp-tool-allow',
          description: `permissions.allow ${r}: ${parts.length > 2 ? 'this tool' : 'every tool of the server'} runs without asking`,
        });
        return;
      }
      if (['Edit', 'Write', 'Read', 'MultiEdit', 'NotebookEdit'].includes(tool)) {
        const outside = !!spec && /^(\/\/|~|\/(?!\/)|\.\.\/)/.test(spec);
        const broad = !spec || outside;
        const cap = `${tool.toLowerCase()}.${spec ? capToken(spec) : 'any'}`;
        const description = `permissions.allow ${r}: ${outside ? 'paths outside the repository' : !spec ? 'any file' : 'scoped'}, without asking`;
        const admits = broad ? (tool === 'Read' ? ['file-read-outside-repository'] : ['file-write']) : undefined;
        b.reach(ctx, cap, ws, { ...base, harness: H, rule: 'file-tool', admits, description });
        if (broad && tool !== 'Read') b.effect(ctx, 'write', ws, { ...base, harness: H, rule: 'file-tool', admits, description });
        return;
      }
      b.reach(ctx, capToken(tool.toLowerCase()) + (spec ? `.${capToken(spec)}` : ''), ws, {
        ...base, harness: H, rule: 'tool-allow', description: `permissions.allow ${r}: without asking`,
      });
    });
    asArray(perms.ask).forEach((r, i) => {
      if (typeof r !== 'string') return;
      const { tool, spec } = parseRule(r);
      const cap = tool === 'Bash' ? classifyShell(spec, H, b.sem).capability : capToken(tool.toLowerCase());
      b.gate(ctx, b.asset(WORKSTATION, workstationDesc()), cap, {
        harness: H, pointer: ptr('permissions', 'ask', i), raw: r, rule: 'ask', description: `permissions.ask ${r}: asks the developer first`,
      });
    });
    asArray(perms.additionalDirectories).forEach((dir, i) => {
      if (typeof dir !== 'string' || !/^(~|\/|\.\.)/.test(dir)) return;
      b.reach(ctx, 'read.outside-repo', b.asset(WORKSTATION, workstationDesc()), {
        harness: H, pointer: ptr('permissions', 'additionalDirectories', i), raw: dir, rule: 'additional-directories',
        description: `permissions.additionalDirectories ${dir}: the agent may read and edit outside the repository`,
      });
    });
    const mode = asString(perms.defaultMode) ?? asString(d.defaultMode);
    if (mode === 'bypassPermissions' || mode === 'acceptEdits') {
      const p = perms.defaultMode !== undefined ? ptr('permissions', 'defaultMode') : ptr('defaultMode');
      const ws = b.asset(WORKSTATION, workstationDesc());
      const bypass = mode === 'bypassPermissions';
      const description = bypass ? 'defaultMode bypassPermissions: every tool runs without asking' : 'defaultMode acceptEdits: file edits are accepted without asking';
      b.reach(ctx, bypass ? 'any' : 'edit.any', ws, { harness: H, pointer: p, raw: mode, rule: bypass ? 'bypass-mode' : 'auto-mode', description });
      b.effect(ctx, bypass ? 'execute' : 'write', ws, { harness: H, pointer: p, raw: mode, rule: bypass ? 'bypass-mode' : 'auto-mode', description });
    }
  }
  asArray(perms.deny).forEach((r, i) => {
    if (typeof r === 'string') b.denies.push({ harness: H, file: ctx.file.path, line: lineOf(ctx, ptr('permissions', 'deny', i)), raw: r });
  });
  if (producesRows(ctx)) {
    const all = d.enableAllProjectMcpServers === true;
    const named = asArray(d.enabledMcpjsonServers).filter((x): x is string => typeof x === 'string');
    if (all || named.length > 0) {
      const key = all ? 'enableAllProjectMcpServers' : 'enabledMcpjsonServers';
      b.reach(ctx, 'mcp.project-servers', b.asset(WORKSTATION, workstationDesc()), {
        harness: H, pointer: ptr(key), raw: all ? `${key}: true` : `${key}: ${named.join(', ')}`, rule: 'mcp-server-auto',
        description: `${key}: project .mcp.json servers start (stdio servers execute) without the per-server approval`,
      });
    }
    for (const k of ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper']) {
      const v = asString(d[k]);
      if (!v) continue;
      b.asset(WORKSTATION, workstationDesc());
      b.effect(ctx, 'execute', WORKSTATION, {
        harness: H, pointer: ptr(k), raw: v, rule: 'credential-helper',
        description: `${k} runs \`${v.slice(0, 80)}\` and its output becomes the agent's credential`,
      });
    }
    for (const k of ['enabledPlugins', 'extraKnownMarketplaces']) {
      const v = asObject(d[k]);
      for (const [name, on] of Object.entries(v ?? {})) {
        if (k === 'enabledPlugins' && on !== true) continue;
        b.reach(ctx, `plugin.${capToken(slug(name))}`, b.asset(WORKSTATION, workstationDesc()), {
          harness: H, pointer: ptr(k, name), raw: name, rule: 'plugin',
          description: `${k} ${name}: its hooks, MCP servers, skills and commands load for everyone who trusts the repository`,
        });
      }
    }
  }
  const sl = asObject(d.statusLine);
  if (sl && typeof sl.command === 'string') hookCommand(b, ctx, H, 'statusLine', undefined, sl.command, ptr('statusLine', 'command'), 'status-line');
  hooksBlock(b, ctx, H, d.hooks, ptr('hooks'));
}

function vscodeSettings(b: Builder, ctx: Ctx) {
  const d = asObject(ctx.doc!.value) ?? {};
  const H = 'copilot';
  /** A setting written flat (`"chat.tools.autoApprove"`) or nested (`"chat": {"tools": …}`). */
  const get = (key: string): { value: JsonValue | undefined; pointer: string } => {
    if (key in d) return { value: d[key], pointer: ptr(key) };
    let cur: JsonValue | undefined = d;
    const parts = key.split('.');
    for (const part of parts) cur = asObject(cur)?.[part];
    return { value: cur, pointer: ptr(...parts) };
  };
  if (!producesRows(ctx)) return;
  const ws = () => b.asset(WORKSTATION, workstationDesc());
  for (const key of ['chat.tools.autoApprove', 'chat.tools.global.autoApprove']) {
    const { value, pointer } = get(key);
    if (value !== true) continue;
    const description = `${key}: true, every tool call runs without confirmation`;
    b.reach(ctx, 'any', ws(), { harness: H, pointer, raw: `${key}: true`, rule: 'global-auto-approve', description });
    b.effect(ctx, 'execute', ws(), { harness: H, pointer, raw: `${key}: true`, rule: 'global-auto-approve', description });
  }
  for (const key of ['chat.tools.terminal.autoApprove', 'chat.agent.terminal.autoApprove', 'github.copilot.chat.agent.terminal.allowList']) {
    const { value, pointer } = get(key);
    for (const [pat, ok] of Object.entries(asObject(value) ?? {})) {
      const approve = ok === true || asObject(ok)?.approve === true;
      if (!approve) continue;
      const regex = pat.startsWith('/') && pat.length > 1;
      shellRule(b, ctx, H, regex ? '*' : `${pat}:*`, { pointer: `${pointer}/${pointerToken(pat)}`, raw: pat, key });
    }
  }
  const auto = get('chat.mcp.autostart');
  if (auto.value === true || auto.value === 'always' || auto.value === 'newAndOutdated') {
    b.reach(ctx, 'mcp.project-servers', ws(), {
      harness: H, pointer: auto.pointer, raw: `chat.mcp.autostart: ${String(auto.value)}`, rule: 'mcp-autostart',
      description: `chat.mcp.autostart ${String(auto.value)}: configured MCP servers start without being asked to`,
    });
  }
}

function vscodeTasks(b: Builder, ctx: Ctx) {
  const d = asObject(ctx.doc!.value) ?? {};
  asArray(d.tasks).forEach((t, i) => {
    const to = asObject(t);
    if (asString(asObject(to?.runOptions)?.runOn) !== 'folderOpen') return;
    const cmd = [asString(to?.command) ?? '', ...asArray(to?.args).map(String)].join(' ').trim();
    if (!cmd) return;
    hookCommand(b, ctx, 'copilot', 'folderOpen', asString(to?.label) ?? undefined, cmd, ptr('tasks', i, 'command'), 'folder-open-task');
  });
}

function codexConfig(b: Builder, ctx: Ctx) {
  const d = asObject(ctx.doc!.value) ?? {};
  const H = 'codex';
  if (producesRows(ctx)) {
    const ap = asString(d.approval_policy);
    const sb = asString(d.sandbox_mode);
    if (ap === 'never' || sb === 'danger-full-access') {
      const p = ap === 'never' ? ptr('approval_policy') : ptr('sandbox_mode');
      const description = `approval_policy=${ap ?? 'default'}, sandbox_mode=${sb ?? 'default'}`
        + (ap === 'never' ? ': every command runs without asking' : ': commands run with no sandbox, still asking');
      const ws = b.asset(WORKSTATION, workstationDesc());
      b.reach(ctx, 'any', ws, { harness: H, pointer: p, raw: `${ap ?? ''} ${sb ?? ''}`.trim(), rule: 'approval-sandbox', gated: ap !== 'never', description });
      if (ap === 'never') b.effect(ctx, 'execute', ws, { harness: H, pointer: p, raw: ap, rule: 'approval-sandbox', description });
    }
    if (asObject(d.sandbox_workspace_write)?.network_access === true) {
      b.reach(ctx, 'network.any', b.asset(WORKSTATION, workstationDesc()), {
        harness: H, pointer: ptr('sandbox_workspace_write', 'network_access'), raw: 'network_access = true', rule: 'network-access',
        description: 'sandbox_workspace_write.network_access: commands in the sandbox may reach the network',
      });
    }
  }
  mcpServers(b, ctx, d.mcp_servers, ptr('mcp_servers'), [H]);
  const notify = asArray(d.notify).map(String);
  if (notify.length > 0) hookCommand(b, ctx, H, 'notify', undefined, notify.join(' '), ptr('notify'), 'notify');
}

function geminiSettings(b: Builder, ctx: Ctx) {
  const d = asObject(ctx.doc!.value) ?? {};
  const H = 'gemini-cli';
  mcpServers(b, ctx, d.mcpServers, ptr('mcpServers'), [H]);
  const tools = asObject(d.tools) ?? {};
  if (producesRows(ctx)) {
    for (const [k, inTools] of [['autoAccept', false], ['autoAccept', true], ['yolo', false]] as const) {
      const v = inTools ? tools[k] : d[k];
      if (v !== true) continue;
      const p = inTools ? ptr('tools', k) : ptr(k);
      const ws = b.asset(WORKSTATION, workstationDesc());
      const description = `${inTools ? 'tools.' : ''}${k}: true, tool calls run without confirmation`;
      b.reach(ctx, 'any', ws, { harness: H, pointer: p, raw: `${k}: true`, rule: 'auto-accept', description });
      b.effect(ctx, 'execute', ws, { harness: H, pointer: p, raw: `${k}: true`, rule: 'auto-accept', description });
    }
    const allowed = Array.isArray(tools.allowed) ? { list: tools.allowed, at: ptr('tools', 'allowed') } : { list: asArray(d.coreTools), at: ptr('coreTools') };
    allowed.list.forEach((r, i) => {
      if (typeof r !== 'string' || !r.startsWith('run_shell_command')) return;
      const spec = r.replace(/^run_shell_command\(?/, '').replace(/\)$/, '');
      shellRule(b, ctx, H, spec ? `${spec}:*` : null, { pointer: `${allowed.at}/${i}`, raw: r, key: 'tools.allowed' });
    });
  }
  hooksBlock(b, ctx, H, d.hooks, ptr('hooks'));
}

function cursorCli(b: Builder, ctx: Ctx) {
  const d = asObject(ctx.doc!.value) ?? {};
  const perms = asObject(d.permissions) ?? {};
  const H = 'cursor';
  if (producesRows(ctx)) {
    asArray(perms.allow).forEach((r, i) => {
      if (typeof r !== 'string') return;
      const { tool, spec } = parseRule(r);
      const p = ptr('permissions', 'allow', i);
      if (tool === 'Shell') { shellRule(b, ctx, H, spec ? `${spec}:*` : null, { pointer: p, raw: r, key: 'permissions.allow' }); return; }
      if (tool === 'Read' || tool === 'Write') {
        const broad = !spec || spec === '**' || /^(~|\/|\.\.)/.test(spec);
        const ws = b.asset(WORKSTATION, workstationDesc());
        const description = `permissions.allow ${r}: ${broad ? 'any path' : 'scoped'}, without asking`;
        b.reach(ctx, `${tool.toLowerCase()}.${spec ? capToken(spec) : 'any'}`, ws, { harness: H, pointer: p, raw: r, rule: 'file-allow', description });
        if (broad && tool === 'Write') b.effect(ctx, 'write', ws, { harness: H, pointer: p, raw: r, rule: 'file-allow', description });
      }
    });
  }
  asArray(perms.deny).forEach((r, i) => {
    if (typeof r === 'string') b.denies.push({ harness: H, file: ctx.file.path, line: lineOf(ctx, ptr('permissions', 'deny', i)), raw: r });
  });
}

function cursorEnv(b: Builder, ctx: Ctx) {
  const d = asObject(ctx.doc!.value) ?? {};
  for (const k of ['install', 'start']) {
    const v = asString(d[k]);
    if (v) hookCommand(b, ctx, 'cursor', `background-agent ${k}`, undefined, v, ptr(k), 'background-command');
  }
  asArray(d.terminals).forEach((t, i) => {
    const c = asString(asObject(t)?.command);
    if (c) hookCommand(b, ctx, 'cursor', 'background-agent terminal', asString(asObject(t)?.name) ?? undefined, c, ptr('terminals', i, 'command'), 'background-command');
  });
}

function markdownFile(b: Builder, ctx: Ctx) {
  const { file, text } = ctx;
  const stamp = text.includes(GUARDLINK_BEGIN) ? parseStamp(text) : null;
  b.instructions.push({
    path: file.path, kind: file.kind, harnesses: file.harnesses, scope: file.scope,
    bytes: Buffer.byteLength(text, 'utf-8'),
    ...(text.includes(GUARDLINK_BEGIN) ? {
      guardlink_block: { stamp: stamp?.annotation_hash ?? null, agent_config_stamp: stamp?.agent_config_hash ?? null, current: false },
    } : {}),
    hidden_unicode: file.scope === 'fixture' ? [] : findHiddenUnicode(text),
  });
  if (!producesRows(ctx)) return;
  const agents = reachHarnesses(file).map(h => `#${b.sem.harnesses.get(h)?.actor?.id ?? h}`);
  if (agents.length > 0) b.untrusted.push({ source: file.path, kind: 'instruction-file', file: file.path, line: 1, agents });
  const harness = reachHarnesses(file)[0];
  if (!harness) return;
  const fm = frontmatter(text).fields;
  if (file.kind === 'subagent') {
    const pm = fm.get('permissionMode');
    if (pm && ['bypassPermissions', 'acceptEdits', 'auto', 'dontAsk'].includes(pm.value) && pm.value !== 'dontAsk') {
      const ws = b.asset(WORKSTATION, workstationDesc());
      const description = `subagent permissionMode ${pm.value}: it runs with permission prompts relaxed`;
      b.reach(ctx, pm.value === 'bypassPermissions' ? 'any' : 'edit.any', ws, {
        harness, pointer: '/frontmatter/permissionMode', raw: `permissionMode: ${pm.value}`, rule: 'subagent-permission-mode', line: pm.line, description,
      });
    }
  }
  // A subagent's `tools:` restricts availability and pre-approves nothing; a skill's or
  // command's `allowed-tools` pre-approves for the turn that invokes it.
  if (file.kind === 'skill' || file.kind === 'command') {
    const at = fm.get('allowed-tools');
    if (!at) return;
    const rules = at.value.match(/[A-Za-z_]\w*(?:\([^)]*\))?/g) ?? [];
    rules.forEach((r, i) => {
      const { tool, spec } = parseRule(r);
      if (tool !== 'Bash') return;
      const v = classifyShell(spec, harness, b.sem);
      const ws = b.asset(WORKSTATION, workstationDesc());
      const description = `${file.kind} allowed-tools ${r}: ${v.why}, pre-approved while the ${file.kind} runs`;
      const admits = v.danger ? b.sem.shell.classes[v.danger].admits : undefined;
      const o = { harness, pointer: `/frontmatter/allowed-tools/${i}`, raw: r, rule: 'skill-allowed-tools', line: at.line, admits, description };
      b.reach(ctx, v.capability, ws, o);
      const eff = dangerEffect(b.sem, v.danger);
      if (eff) b.effect(ctx, eff, ws, o);
    });
  }
}

function jsonHooksFile(b: Builder, ctx: Ctx, harness: string, base = '') {
  const d = asObject(ctx.doc!.value) ?? {};
  hooksBlock(b, ctx, harness, d.hooks, ptr('hooks'), base);
}

// ─── Entry point ────────────────────────────────────────────────────

const JSON_KINDS = new Set(['claude-settings', 'mcp', 'vscode-settings', 'vscode-tasks', 'gemini-settings', 'cursor-hooks', 'cursor-env', 'cursor-cli', 'copilot-hooks', 'plugin-hooks', 'plugin-manifest']);

/** Read every discovered file into rows and inventory. */
export function readFiles(root: string, files: DiscoveredFile[], sem: Semantics = loadSemantics()): ReadResult {
  const b = new Builder(sem);
  const realRoot = realpathSync(root);
  for (const file of files) {
    let text: string;
    try {
      if (statSync(file.real).size > MAX_BYTES) {
        b.unreadable.push({ file: file.path, line: 1, message: `larger than ${MAX_BYTES} bytes; not read` });
        continue;
      }
      text = readFileSync(file.real, 'utf-8');
    } catch (err) {
      b.unreadable.push({ file: file.path, line: 1, message: (err as Error).message });
      continue;
    }
    // Fixture configuration is listed, and its instruction files counted, but not read for reach or inventory.
    if (file.scope === 'fixture' && !MARKDOWN_KINDS.has(file.kind)) continue;
    const ctx: Ctx = { root, realRoot, sem, file, text, doc: null };
    try {
      if (MARKDOWN_KINDS.has(file.kind)) {
        markdownFile(b, ctx);
        continue;
      }
      if (file.kind === 'codex-config') ctx.doc = parseToml(text);
      else if (JSON_KINDS.has(file.kind)) ctx.doc = parseJsonc(text);
      switch (file.kind) {
        case 'claude-settings': claudeSettings(b, ctx); break;
        case 'mcp': {
          const d = asObject(ctx.doc!.value) ?? {};
          const key = 'mcpServers' in d ? 'mcpServers' : 'servers' in d ? 'servers' : 'context_servers';
          mcpServers(b, ctx, d[key], ptr(key), reachHarnesses(file).length > 0 ? reachHarnesses(file) : file.harnesses);
          break;
        }
        case 'vscode-settings': vscodeSettings(b, ctx); break;
        case 'vscode-tasks': vscodeTasks(b, ctx); break;
        case 'codex-config': codexConfig(b, ctx); break;
        case 'gemini-settings': geminiSettings(b, ctx); break;
        case 'cursor-hooks': jsonHooksFile(b, ctx, 'cursor'); break;
        case 'copilot-hooks': jsonHooksFile(b, ctx, 'copilot'); break;
        case 'plugin-hooks': jsonHooksFile(b, ctx, 'claude-code', file.path.split('/').slice(0, -2).join('/')); break;
        case 'cursor-env': cursorEnv(b, ctx); break;
        case 'cursor-cli': cursorCli(b, ctx); break;
        default: break;
      }
    } catch (err) {
      const e = err as Error & { line?: number };
      b.unreadable.push({ file: file.path, line: e.line ?? 1, message: e.message });
    }
  }

  // enableAllProjectMcpServers / enabledMcpjsonServers start .mcp.json servers without the per-server approval.
  const autoAll = b.reaches.filter(r => r.source?.semantics.rule === 'mcp-server-auto' && r.source.harness === 'claude-code');
  if (autoAll.length > 0) {
    const named = new Set(autoAll.flatMap(r => (r.source!.raw.startsWith('enabledMcpjsonServers') ? r.source!.raw.split(': ')[1].split(', ') : [])));
    const all = autoAll.some(r => r.source!.raw.startsWith('enableAllProjectMcpServers'));
    for (const r of b.reaches) {
      if (r.source?.harness !== 'claude-code' || r.source.file_kind !== 'mcp' || r.source.semantics.rule !== 'mcp-server') continue;
      if (!all && !named.has(r.source.raw)) continue;
      const by = autoAll[0];
      r.source.gated = false;
      r.description = `${r.description?.replace(/; each tool call asks$/, '')}; started without approval by ${by.source!.raw.split(':')[0]} (${by.location.file}:${by.location.line})`;
    }
  }

  const fileList = files.map(f => ({
    path: f.path, kind: f.kind, harnesses: f.harnesses, scope: f.scope, ...(f.via.length ? { via: f.via } : {}),
  }));
  const used = new Set<string>();
  for (const h of [...b.reaches.map(r => r.source!.harness), ...b.effects.map(e => e.source!.harness), ...b.gates.map(g => g.source!.harness)]) used.add(h);
  for (const f of files) for (const h of f.harnesses) used.add(h);
  const semantics: Record<string, string> = {};
  for (const [h, v] of Object.entries(sem.versions)) if (used.has(h)) semantics[h] = v;

  return {
    actors: [...b.actorIds.values()],
    reaches: b.reaches,
    effects: b.effects,
    gates: b.gates,
    block: {
      version: 1,
      semantics,
      files: fileList,
      mcp_servers: b.mcp,
      hooks: b.hooks,
      instruction_files: b.instructions,
      assets: [...b.assets].map(([id, description]) => ({ id, description })).sort((x, y) => (x.id < y.id ? -1 : 1)),
      denies: b.denies,
      untrusted_sources: b.untrusted,
      unreadable: b.unreadable,
    },
  };
}
