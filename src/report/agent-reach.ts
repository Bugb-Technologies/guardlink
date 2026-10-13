/**
 * GuardLink Report — the "Agents and LLM Reach" section, and the agent-focused
 * report built from it.
 *
 * One section, two documents: `generateReport` places it in the main threat
 * model when the model carries any reach annotation, and
 * `generateAgentReachReport` (`guardlink report --agents`) wraps the same lines
 * in a document of their own, so a team can publish an LLM threat model alone
 * or as part of the whole one. Every number comes from `summarizeReach`, which
 * the dashboard's Agents page draws too.
 *
 * @comment -- "Pure function: ThreatModel to markdown lines. Model text lands in markdown table cells, where mdCell keeps a pipe or newline from breaking out of the cell; no HTML or shell is produced here"
 * @flows ThreatModel -> #report via summarizeReach -- "Reaches, effects, gates, entitlements and flows for the agent section"
 */
import type { ThreatModel } from '../types/index.js';
import { summarizeReach, hasReach, type ReachSummary, type ReachEffectChip, type ReachLoc, type GrantedBy } from '../reach/index.js';
import { findUnmitigatedExposures } from '../parser/coverage.js';
import { canonicaliser } from '../parser/canonical-ref.js';

const cell = (s: string): string => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const at = (l: ReachLoc): string => `${l.file}:${l.line}`;
const code = (s: string): string => `\`${s}\``;

function effectText(e: ReachEffectChip): string {
  if (e.gated === null) return e.effect;
  if (e.gated) return `${e.effect} (gated by ${e.approvers.join(', ')})`;
  return `**${e.effect} (ungated)**`;
}

/**
 * The section body, under a `##` heading the caller writes. `headingSuffix` is
 * appended to every `###` so a feature slice says so wherever it is read.
 */
export function emitAgentReach(model: ThreatModel, lines: string[], headingSuffix = ''): void {
  const s = summarizeReach(model);
  const h3 = (t: string) => `### ${t}${headingSuffix}`;

  if (!hasReach(model)) {
    lines.push('_No `@agents`, `@reaches`, `@effects` or `@gates` annotations. Nothing in the model says what an embedded');
    lines.push('agent or another principal can reach. Declare it on the tool registrations, the code that acts and the');
    lines.push('approval steps (SPEC §3.2.1) to get the reach map, the unentitled reaches and the OWASP LLM mapping here._');
    lines.push('');
    return;
  }

  lines.push('What the code lets each agent and principal do — `@agents` and `@reaches` (can invoke), `@effects` (what the');
  lines.push('code does) and `@gates` (who decides first) — set against what a human approved with `@entitles`. An effect is');
  lines.push('tied to an actor only when both are written in one doc-block, bound to the same code; reaching an effect');
  lines.push('through calls across handlers takes a call graph and is not inferred here.');
  lines.push('');
  lines.push('| Measure | Count |');
  lines.push('|---------|-------|');
  lines.push(`| Agents (\`@agents\`) | ${s.totals.agents} |`);
  lines.push(`| Other principals (\`@reaches\`) | ${s.totals.principals} |`);
  lines.push(`| Reaches | ${s.totals.reaches} |`);
  lines.push(`| **Unentitled reaches** | **${s.totals.unentitled}** |`);
  lines.push(`| Effects | ${s.totals.effects} (${s.totals.mutations} mutating) |`);
  lines.push(`| **Ungated mutations** | **${s.totals.ungated}** |`);
  lines.push(`| Gates | ${s.totals.gates} |`);
  lines.push(`| Egress from a reach | ${s.totals.egress} |`);
  lines.push(`| Injection-to-tool routes | ${s.totals.injection} |`);
  if (s.totals.coding_reaches > 0 || s.coding.automatic.length > 0) {
    lines.push(`| Coding agents configured here | ${s.totals.coding_agents} |`);
    lines.push(`| Coding-agent capabilities (from configuration) | ${s.totals.coding_reaches} (**${s.totals.coding_unentitled} unentitled**) |`);
    lines.push(`| Commands the configuration runs automatically | ${s.totals.coding_automatic} |`);
  }
  lines.push('');

  emitActors(s, lines, h3);
  emitReachMap(s, lines, h3);
  emitLists(s, lines, h3);
  emitCodingAgents(s, lines, h3);
  emitOwasp(s, lines, h3);
  emitReachedExposures(model, s, lines, h3);
}

const grant = (g: GrantedBy): string => `${g.file}:${g.line} ${code(g.raw.length > 60 ? `${g.raw.slice(0, 57)}...` : g.raw)}`;

/**
 * What the repository's own agent configuration lets Claude Code, Cursor,
 * Copilot, Codex and Gemini do here (SPEC §5.6): every capability with the line
 * that granted it, grouped by file, then what runs automatically and which MCP
 * servers start.
 */
function emitCodingAgents(s: ReachSummary, lines: string[], h3: (t: string) => string): void {
  const c = s.coding;
  if (c.reaches.length === 0 && c.automatic.length === 0 && c.mcp_servers.length === 0) return;
  lines.push(h3('Coding Agents Configured in This Repository'));
  lines.push('');
  lines.push('Generated from the repository\'s agent configuration, not from annotations: what each coding agent may do here,');
  lines.push('read off the line that grants it under that agent\'s documented behaviour. "Asks first" is whether the agent');
  lines.push('prompts the developer before using it. A human closes an unentitled one with `@entitles`; `guardlink entitle');
  lines.push('--from-config --propose` drafts them for review. These are counted apart from embedded-agent reach above.');
  lines.push('');
  if (c.agents.length > 0) {
    lines.push('| Agent | Capabilities | Unentitled | Ungated mutations |');
    lines.push('|-------|--------------|------------|-------------------|');
    for (const a of c.agents) lines.push(`| ${a.actor} | ${a.reaches} | ${a.unentitled} | ${a.ungated} |`);
    lines.push('');
  }
  for (const g of c.by_file) {
    lines.push(`**${g.file}** — loaded by ${g.harnesses.join(', ')}`);
    lines.push('');
    lines.push('| Agent | Capability | On | Asks first | Entitled | What using it does | Granted by | Read as |');
    lines.push('|-------|------------|----|------------|----------|--------------------|------------|---------|');
    for (const r of g.reaches) {
      const does = r.effects.length > 0 ? r.effects.map(e => `**${e}**`).join(', ') : '—';
      lines.push(`| ${r.actor} | ${code(r.capability)} | ${r.asset ?? '—'} | ${r.gated ? 'yes' : '**no**'} | ${r.entitled ? 'yes' : '**no**'} | ${does} | ${cell(grant(r.granted_by))} | ${r.granted_by.doc ? `[${r.granted_by.rule}](${r.granted_by.doc})` : r.granted_by.rule} |`);
    }
    lines.push('');
  }
  const auto = c.automatic.filter(h => h.scope === 'root' || h.scope === 'nested');
  if (auto.length > 0) {
    lines.push('**Runs automatically** — outside the model\'s loop, with the developer\'s privileges');
    lines.push('');
    lines.push('| Agent | Event | Command | Runs | Does | Location |');
    lines.push('|-------|-------|---------|------|------|----------|');
    for (const h of auto) {
      lines.push(`| ${h.harness} | ${h.event}${h.matcher ? ` [${cell(h.matcher)}]` : ''} | ${cell(code(h.command.length > 80 ? `${h.command.slice(0, 77)}...` : h.command))} | ${h.runs.join(', ') || '—'} | ${h.does.join(', ') || 'local commands only'} | ${h.file}:${h.line} |`);
    }
    lines.push('');
  }
  const servers = c.mcp_servers.filter(m => m.scope === 'root' || m.scope === 'nested');
  if (servers.length > 0) {
    lines.push('**MCP servers**');
    lines.push('');
    lines.push('| Server | Agent | Starts | Built from this repository | Package pinned | Credentials | Third-party content | Location |');
    lines.push('|--------|-------|--------|----------------------------|----------------|-------------|---------------------|----------|');
    for (const m of servers) {
      const starts = m.transport === 'http' ? `http ${m.host ?? ''}` : code([m.launch?.command ?? '', ...(m.launch?.args ?? [])].join(' ').slice(0, 60));
      lines.push(`| ${m.name}${m.disabled ? ' (disabled)' : ''} | ${m.harness} | ${cell(starts)} | ${m.resolves_to ? `${m.resolves_to.file} (${m.resolves_to.kind})` : '—'} | ${m.package ? (m.package.pinned ? 'yes' : `**no** (${cell(m.package.spec)})`) : '—'} | ${m.credential_env.join(', ') || '—'} | ${m.returns_third_party_content ? 'yes' : 'no'} | ${m.file}:${m.line} |`);
    }
    lines.push('');
  }
  if (c.untrusted_sources > 0) {
    lines.push(`${c.untrusted_sources} instruction files, skills, commands and MCP servers put text into an agent's context; each is an untrusted source, and an injection-to-tool route when that agent can act without asking (LLM01 below). \`guardlink lookup "agent config"\` lists them.`);
    lines.push('');
  }
}

/** One subsection per actor that reaches something: each capability and what it leads to. */
function emitActors(s: ReachSummary, lines: string[], h3: (t: string) => string): void {
  for (const a of s.actors.filter(x => x.reaches > 0)) {
    lines.push(h3(`${a.ref} — ${a.agent ? 'AI agent' : 'principal'}`));
    lines.push('');
    if (a.description) lines.push(`${a.declared ? '' : '_Undeclared actor._ '}${a.description}`, '');
    else if (!a.declared) lines.push('_Undeclared: no `@actor` names it — `guardlink validate` reports it._', '');
    lines.push(`${a.reaches} ${a.reaches === 1 ? 'capability' : 'capabilities'}, ${a.unentitled} unentitled, ${a.ungated} ungated ${a.ungated === 1 ? 'mutation' : 'mutations'}.`);
    lines.push('');
    lines.push('| Capability | On | As | Entitled | What it leads to | Location |');
    lines.push('|------------|----|----|----------|------------------|----------|');
    const mine = s.cells.filter(c => c.actor === a.key);
    const label = (k: string) => s.columns.find(c => c.key === k)?.ref ?? k;
    for (const c of mine) {
      for (const cap of c.capabilities) {
        const leads = mine.flatMap(x => x.effects.filter(e => e.via.includes(cap.capability)).map(e => `${effectText(e)} ${label(x.asset)}`));
        lines.push(`| ${code(cap.capability)} | ${label(c.asset)} | ${cap.identity ?? '—'} | ${cap.entitled ? 'yes' : '**no**'} | ${cell(leads.join(', ') || '—')} | ${at(cap.loc)} |`);
      }
    }
    lines.push('');
  }
}

/** Actor × asset, with the capabilities and effects in each cell. */
function emitReachMap(s: ReachSummary, lines: string[], h3: (t: string) => string): void {
  const rows = s.actors.filter(a => a.reaches > 0);
  if (rows.length === 0 || s.columns.length === 0) return;
  lines.push(h3('Reach Map'));
  lines.push('');
  lines.push('Rows are actors, columns the assets they reach. A capability is marked ✗ when no cited `@entitles` covers it;');
  lines.push('an effect is marked ungated when it mutates and no `@gates` stands in front of it.');
  lines.push('');
  lines.push(`| Actor | ${s.columns.map(c => c.ref).join(' | ')} |`);
  lines.push(`|-------|${s.columns.map(() => '---').join('|')}|`);
  const render = (caps: { capability: string; entitled: boolean }[], effects: ReachEffectChip[]) =>
    cell([...caps.map(c => `${code(c.capability)} ${c.entitled ? '✓' : '✗'}`), ...effects.map(effectText)].join('<br>') || '·');
  for (const a of rows) {
    const cols = s.columns.map(col => {
      const c = s.cells.find(x => x.actor === a.key && x.asset === col.key);
      return c ? render(c.capabilities, c.effects) : '·';
    });
    lines.push(`| ${a.ref}${a.agent ? ' (agent)' : ''} | ${cols.join(' | ')} |`);
  }
  if (s.loose.length > 0) {
    const cols = s.columns.map(col => {
      const l = s.loose.find(x => x.asset === col.key);
      return l ? render([], l.effects) : '·';
    });
    lines.push(`| _not tied to a reach_ | ${cols.join(' | ')} |`);
  }
  lines.push('');
}

function emitLists(s: ReachSummary, lines: string[], h3: (t: string) => string): void {
  if (s.unentitled.length > 0) {
    lines.push(h3('Unentitled Reaches'));
    lines.push('');
    lines.push('Capabilities the code hands out that no cited `@entitles` covers: can minus may. For an agent this is the');
    lines.push('Excessive Agency list. Only a human closes one, by accepting an entitlement proposal (`guardlink entitle --propose`).');
    lines.push('');
    lines.push('| Actor | Capability | On | Why nothing covers it | Location |');
    lines.push('|-------|------------|----|-----------------------|----------|');
    for (const u of s.unentitled) {
      const why = u.near_misses.length === 0
        ? 'no `@entitles` for this actor and capability'
        : u.near_misses.map(n => `${n.reason} (${at(n.loc)})`).join('; ');
      lines.push(`| ${u.actor}${u.agent ? ' (agent)' : ''} | ${code(u.capability)} | ${u.asset ?? '—'} | ${cell(why)} | ${at(u.loc)} |`);
    }
    lines.push('');
  }

  if (s.ungated.length > 0) {
    lines.push(h3('Ungated Mutations'));
    lines.push('');
    lines.push('Effects other than `read` with no `@gates` in front of them. A gate suppresses nothing; its absence means');
    lines.push('nothing in the model says a person or a check decides before the effect lands.');
    lines.push('');
    lines.push('| Effect | Asset | As | Reached through | Location |');
    lines.push('|--------|-------|----|-----------------|----------|');
    for (const u of s.ungated) {
      const via = (u.via.length === 0
        ? '_no reach on this code_'
        : u.via.map(v => `${v.actor} ${code(v.capability)}`).join(', '))
        + u.gate_near_misses.map(n => `; ${n.approver}${n.capability ? ` for ${code(n.capability)}` : ''} does not cover it: ${n.reason}`).join('');
      lines.push(`| ${u.effect} | ${u.asset} | ${u.identity ?? '—'} | ${cell(via)} | ${at(u.loc)} |`);
    }
    lines.push('');
  }

  if (s.gates.length > 0) {
    lines.push(h3('Gates'));
    lines.push('');
    lines.push('| Asset | Approver | For | Stands in front of | Location |');
    lines.push('|-------|----------|-----|--------------------|----------|');
    for (const g of s.gates) {
      const covers = g.covers.map(c => `${c.effect} on ${c.asset} (${at(c.loc)})`).join(', ') || '—';
      lines.push(`| ${g.asset} | ${g.approver} | ${g.capability ? code(g.capability) : 'every capability'} | ${cell(covers)} | ${at(g.loc)} |`);
    }
    lines.push('');
  }

  if (s.egress.length > 0) {
    lines.push(h3('Egress From a Reach'));
    lines.push('');
    lines.push('`@flows` out of an actor or a surface it reaches that leave the model or cross a declared `@boundary`.');
    lines.push('');
    lines.push('| Actors | Flow | Leaves the model | Crosses | Location |');
    lines.push('|--------|------|------------------|---------|----------|');
    for (const e of s.egress) {
      lines.push(`| ${e.actors.join(', ')} | ${cell(`${e.source} → ${e.target}${e.mechanism ? ` via ${e.mechanism}` : ''}`)} | ${e.external ? 'yes' : 'no'} | ${e.boundaries.join(', ') || '—'} | ${at(e.loc)} |`);
    }
    lines.push('');
  }

  if (s.loose.length > 0) {
    lines.push(h3('Effects Not Tied to a Reach'));
    lines.push('');
    lines.push('No `@agents` or `@reaches` is bound to the same code, so which principal reaches these');
    lines.push('is a call-graph question. They still count as ungated mutations when nothing gates them.');
    lines.push('');
    for (const l of s.loose) {
      for (const e of l.effects) lines.push(`- ${effectText(e)} on ${s.columns.find(c => c.key === l.asset)?.ref ?? l.asset} (${at(e.loc)})`);
    }
    lines.push('');
  }
}

/** The OWASP Top 10 for LLM Applications (2025) items reach evidence speaks to. */
function emitOwasp(s: ReachSummary, lines: string[], h3: (t: string) => string): void {
  if (s.totals.agents === 0 && s.injection.length === 0) return;
  lines.push(h3('OWASP Top 10 for LLM Applications'));
  lines.push('');
  lines.push('Each row is a target for review or test, not a finding the model has proved.');
  lines.push('');
  lines.push('| Item | What GuardLink looks for | Found |');
  lines.push('|------|--------------------------|-------|');
  for (const o of s.owasp) lines.push(`| ${o.id} ${o.title} | ${cell(o.basis)} | ${o.items.length} |`);
  lines.push('');
  for (const o of s.owasp.filter(x => x.items.length > 0)) {
    lines.push(`**${o.id} ${o.title}**`);
    lines.push('');
    for (const i of o.items) lines.push(`- _${i.facet}_ — ${i.agent}: ${i.text} (${at(i.loc)})`);
    lines.push('');
  }
}

/** Open exposures on the assets in the reach map, so the agent document carries the risks already written down. */
function emitReachedExposures(model: ThreatModel, s: ReachSummary, lines: string[], h3: (t: string) => string): void {
  const key = canonicaliser(model);
  const reached = new Set(s.columns.map(c => c.key));
  const open = findUnmitigatedExposures(model).filter(e => reached.has(key(e.asset)));
  if (open.length === 0) return;
  lines.push(h3('Open Exposures on Reached Assets'));
  lines.push('');
  lines.push('| Severity | Asset | Threat | Description | Location |');
  lines.push('|----------|-------|--------|-------------|----------|');
  for (const e of open) {
    lines.push(`| ${e.severity ?? '—'} | ${e.asset} | ${e.threat} | ${cell(e.description ?? '—')} | ${e.location.file}:${e.location.line} |`);
  }
  lines.push('');
}

/**
 * The agent threat model on its own: the same section as the main report,
 * with a header that says what it covers. `guardlink report --agents`.
 */
export function generateAgentReachReport(model: ThreatModel): string {
  const features = (model as ThreatModel & { filtered_by_features?: string[] }).filtered_by_features ?? [];
  const suffix = features.length > 0 ? ` — feature${features.length > 1 ? 's' : ''} ${features.map(f => `"${f}"`).join(', ')}` : '';
  const lines: string[] = [];
  lines.push(`# Agent and LLM Threat Model — ${model.project}${suffix}`);
  lines.push('');
  lines.push(`> Generated: ${model.generated_at}  `);
  lines.push(`> Files scanned: ${model.source_files} | Annotations: ${model.annotations_parsed}`);
  if (model.metadata?.commit_sha) {
    lines.push(`> Commit: ${model.metadata.commit_sha}${model.metadata.branch ? ` (${model.metadata.branch})` : ''}`);
  }
  if (features.length > 0) {
    lines.push('>');
    lines.push(`> **Feature slice**: only annotations in the files tagged ${features.map(f => `"${f}"`).join(', ')}.`);
  }
  lines.push('');
  lines.push('This is the agent part of the threat model: what each embedded LLM agent and other principal can reach,');
  lines.push('what of that a human approved, and what acts with no one deciding first — and, read from the repository\'s');
  lines.push('agent configuration, what the coding agents its developers run may do here. `guardlink report` without');
  lines.push('`--agents` places the same section in the full threat model.');
  lines.push('');
  lines.push(`## Agents and LLM Reach${suffix}`);
  lines.push('');
  emitAgentReach(model, lines, suffix);
  return lines.join('\n');
}
