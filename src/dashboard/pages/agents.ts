/**
 * GuardLink Dashboard — Agents & Reach: what each embedded LLM agent and other
 * principal can reach, what a human approved, and what acts with no one
 * deciding first.
 *
 * The reach map is actor × asset with the capabilities and effects in each
 * cell; below it the unentitled reaches (with why a near-miss entitlement does
 * not cover each), the ungated mutations, the gates, egress from a reach, the
 * injection-to-tool routes and the OWASP LLM Top 10 rows. Every number comes
 * from `summarizeReach`, which the report's "Agents and LLM Reach" section
 * prints too.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Actor, asset and capability names, descriptions and citations are model text; every one goes through esc(), including chip titles"
 * @flows ThreatModel -> #dashboard via summarizeReach -- "Reaches, effects, gates, entitlements and flows for the Agents page"
 * @mitigates #dashboard against #xss using #output-encoding -- "Configuration values (rules, commands, hosts, file paths, doc URLs) are repository text and go through esc() like model text; doc links open with rel=noopener noreferrer"
 * @comment -- "Chips carry state the design way: a capability is an outlined chip with ✓ (entitled) or ✕ (unentitled), a gated effect carries ⊢, an ungated mutation is a filled warm chip, a read is a plain tag"
 */
import { esc, scopeLabel, pageHead, subHead, sortableHead, rowAttrs, locCellShort, descCell, pager, plural, statTile } from '../html.js';
import type { ReachSummary, ReachEffectChip, ReachCapabilityChip, ReachLoc, GrantedBy } from '../../reach/index.js';
import type { PageContext } from './context.js';
import { actorTables } from './tables.js';
import { MEASURED_LABEL, type MeasuredRouteRow } from '../../codegraph/reach-check.js';

const where = (l: ReachLoc): string => `${l.file}:${l.line}`;

/**
 * The empty state's example, with `@` written as an entity so this source file
 * does not read as carrying the annotations it shows.
 */
const REACH_EXAMPLE = [
  '&#64;agents #support-agent to run-sql on #tool-surface -- &quot;run_sql tool&quot;',
  '&#64;effects write on #users-db as #db-admin -- &quot;Runs model-written SQL&quot;',
  '&#64;gates #payments by #support-human for issue-refund -- &quot;requireApproval() waits for a person&quot;',
].join('\n');

function capChip(c: ReachCapabilityChip): string {
  const title = `${c.entitled ? 'Entitled' : 'Unentitled: no cited @entitles covers it'}${c.identity ? ` · as ${c.identity}` : ''} · ${where(c.loc)}`;
  return `<span class="reach-chip reach-cap ${c.entitled ? 'ok' : 'bad'}" title="${esc(title)}"><span class="g" aria-hidden="true">${c.entitled ? '✓' : '✕'}</span>${esc(c.capability)}</span>`;
}

function effectChip(e: ReachEffectChip): string {
  const state = e.gated === null ? 'read' : e.gated ? 'gated' : 'ungated';
  const label = e.gated === null ? e.effect : e.gated ? `⊢ ${e.effect} · gated` : `${e.effect} · no gate`;
  const title = [
    e.gated === null ? 'Read: no gate needed' : e.gated ? `Gated by ${e.approvers.join(', ')}` : 'Mutation with no @gates in front of it',
    e.via.length ? `via ${e.via.join(', ')}` : '',
    e.via.length ? 'bound to the same code as the reach' : 'not tied to any reach',
    e.identity ? `runs as ${e.identity}` : '',
    where(e.loc),
  ].filter(Boolean).join(' · ');
  return `<span class="reach-chip reach-eff ${state}" title="${esc(title)}">${state === 'ungated' ? '<i class="sw"></i>' : ''}${esc(label)}</span>`;
}

/** A stat tile that scrolls to its table: the hash stays on the page, the delegated listener reads data-jump. */
function tileJump(value: number | string, label: string, target: string, hint: string, big = false): string {
  return statTile(label, value, hint, { href: '#agents', big }).replace('<a class="stat" href="#agents"', `<a class="stat" href="#agents" data-jump="${target}"`);
}

function reachMap(s: ReachSummary): string {
  const rows = s.actors.filter(a => a.reaches > 0);
  if (rows.length === 0 || s.columns.length === 0) return '';
  const head = `<thead><tr><th class="heat-corner">Actor</th>${s.columns.map(c => `<th class="heat-col" title="${esc(c.ref)}"><span>${esc(c.ref)}</span></th>`).join('')}</tr></thead>`;
  const body = rows.map(a => {
    const cells = s.columns.map(col => {
      const c = s.cells.find(x => x.actor === a.key && x.asset === col.key);
      if (!c) return '<td class="reach-cell empty"></td>';
      return `<td class="reach-cell">${c.capabilities.map(capChip).join('')}${c.effects.map(effectChip).join('')}</td>`;
    }).join('');
    return `<tr data-search="${esc([a.ref, a.name, a.agent ? 'agent' : 'principal'].join(' ').toLowerCase())}"><th class="heat-row reach-actor" title="${esc(a.description ?? a.ref)}"><span>${esc(a.ref)}</span><span class="reach-kind ${a.agent ? 'agent' : 'principal'}">${a.agent ? 'AI agent' : 'principal'}</span></th>${cells}</tr>`;
  }).join('');
  const loose = s.loose.length > 0
    ? `<tr><th class="heat-row reach-actor" title="Effects with no @agents or @reaches bound to the same code"><span>not tied to a reach</span><span class="reach-kind loose">call graph</span></th>${s.columns.map(col => {
      const l = s.loose.find(x => x.asset === col.key);
      return l ? `<td class="reach-cell">${l.effects.map(effectChip).join('')}</td>` : '<td class="reach-cell empty"></td>';
    }).join('')}</tr>`
    : '';
  return `<div class="table-wrap heat-wrap"><table class="heat reach-map" id="reach-map">${head}<tbody>${body}${loose}</tbody></table></div>
  <div class="reach-legend">
    <span><span class="reach-chip reach-cap ok"><span class="g">✓</span>capability</span> entitled</span>
    <span><span class="reach-chip reach-cap bad"><span class="g">✕</span>capability</span> no cited <code>@entitles</code></span>
    <span><span class="reach-chip reach-eff ungated"><i class="sw"></i>write · no gate</span> mutation, no <code>@gates</code></span>
    <span><span class="reach-chip reach-eff gated">⊢ spend · gated</span> a named approver decides first</span>
    <span><span class="reach-chip reach-eff read">read</span> read</span>
  </div>`;
}

/**
 * What a code graph measured for each declared reach, beside what the annotations
 * say. Drawn only when the dashboard was given a graph's answer, so the page
 * without one is exactly what it was. The label is part of the table: this is a
 * reading of the call graph, a claim to check, never evidence.
 */
function measuredSection(rows: MeasuredRouteRow[], loc: (l: ReachLoc) => string): string {
  if (rows.length === 0) return '';
  return `
  ${subHead('Measured route', '', `<span data-count-for="agent-measured">${rows.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-measured">')}
  <p class="guide"><b>${esc(MEASURED_LABEL)}</b> <code>measured</code> means the reach's handler reaches a declared effect over resolved calls; <code>unknown</code> is never read as either answer.</p>
  <div class="table-wrap"><table id="agent-measured" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'actor', label: 'Actor' }, { key: 'capability', label: 'Capability' }, { key: 'asset', label: 'On' }, { key: 'route', label: 'Measured route (code graph)' }, { key: 'gates', label: 'Gates on the route', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${rows.map(r => `
    <tr ${rowAttrs({ file: r.file, search: ['measured', r.route, r.text, r.actor, r.capability, r.asset, ...r.gates] })}>
      <td><code>${esc(r.actor)}</code></td>
      <td><code>${esc(r.capability)}</code></td>
      <td>${r.asset ? `<code>${esc(r.asset)}</code>` : '—'}</td>
      <td>${esc(r.text)}</td>
      <td>${r.gates.length > 0 ? r.gates.map(g => `<div>${esc(g)}</div>`).join('') : '—'}</td>
      ${loc({ file: r.file, line: r.line })}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('agent-measured')}`;
}

const grantedBy = (g: GrantedBy): string =>
  `<code title="${esc(`${g.pointer} · read by ${g.harness} as ${g.rule}`)}">${esc(g.raw.length > 64 ? `${g.raw.slice(0, 61)}...` : g.raw)}</code>`;

/**
 * Coding agents configured in this repository (SPEC §5.6): every capability the
 * configuration grants, with the line that granted it, grouped by file; then the
 * commands it runs automatically and the MCP servers it starts. Generated rows,
 * counted apart from the embedded agents above.
 */
function codingSection(s: ReachSummary, loc: (l: ReachLoc) => string): string {
  const c = s.coding;
  if (c.reaches.length === 0 && c.automatic.length === 0 && c.mcp_servers.length === 0) return '';
  const own = (scope: string) => scope === 'root' || scope === 'nested';
  const auto = c.automatic.filter(h => own(h.scope));
  const servers = c.mcp_servers.filter(m => own(m.scope));
  const rows = c.by_file.flatMap(g => g.reaches.map(r => ({ g, r })));
  return `
  ${subHead('Coding agents configured here', '', `<span data-count-for="agent-coding">${c.reaches.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-coding">')}
  <p class="guide">Generated from the repository's own agent configuration, not from annotations: what ${c.agents.map(a => `<code>${esc(a.actor)}</code>`).join(', ') || 'each coding agent'} may do here, grouped by the file that grants it and read off that line under the agent's documented behaviour. <b>Asks first</b> is whether the agent prompts the developer before using it. A human closes one with <code>@entitles</code>; <code>guardlink entitle --from-config --propose</code> drafts them for review.</p>
  ${rows.length > 0 ? `
  <div class="table-wrap"><table id="agent-coding" class="sortable" data-paginate="50">
    ${sortableHead([{ key: 'actor', label: 'Agent' }, { key: 'capability', label: 'Capability' }, { key: 'asset', label: 'On' }, { key: 'asks', label: 'Asks first' }, { key: 'entitled', label: 'Entitled' }, { key: 'does', label: 'Does' }, { key: 'granted', label: 'Granted by', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${rows.map(({ g, r }) => `
    <tr ${rowAttrs({ file: r.granted_by.file, search: ['coding', g.file, r.actor, r.capability, r.asset ?? '', r.granted_by.raw, r.granted_by.harness, r.granted_by.rule, r.entitled ? 'entitled' : 'unentitled', r.gated ? 'asks' : 'without asking', ...r.effects] })}>
      <td><code>${esc(r.actor)}</code> <span class="reach-kind agent">coding agent</span></td>
      <td><code>${esc(r.capability)}</code></td>
      <td>${r.asset ? `<code>${esc(r.asset)}</code>` : '—'}</td>
      <td>${r.gated ? 'yes' : '<strong>no</strong>'}</td>
      <td>${r.entitled ? '<span class="reach-chip reach-cap ok"><span class="g">✓</span>entitled</span>' : '<span class="reach-chip reach-cap bad"><span class="g">✕</span>no</span>'}</td>
      <td>${r.effects.length > 0 ? r.effects.map(e => `<span class="reach-chip reach-eff ungated"><i class="sw"></i>${esc(e)} · no gate</span>`).join('') : '<span class="muted">—</span>'}</td>
      <td>${grantedBy(r.granted_by)}${r.granted_by.doc ? ` <a class="muted" href="${esc(r.granted_by.doc)}" rel="noopener noreferrer" target="_blank">${esc(r.granted_by.rule)}</a>` : ''}</td>
      ${loc({ file: r.granted_by.file, line: r.granted_by.line })}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('agent-coding')}` : ''}
  ${auto.length > 0 ? `
  <p class="guide"><b>Runs automatically</b> — outside the model's loop, with the developer's privileges.</p>
  <div class="table-wrap"><table id="agent-coding-auto" class="sortable">
    ${sortableHead([{ key: 'agent', label: 'Agent' }, { key: 'event', label: 'Event' }, { key: 'command', label: 'Command', plain: true }, { key: 'runs', label: 'Runs' }, { key: 'does', label: 'Does' }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${auto.map(h => `
    <tr ${rowAttrs({ file: h.file, search: ['automatic', h.harness, h.event, h.matcher ?? '', h.command, ...h.runs, ...h.does] })}>
      <td><code>${esc(h.harness)}</code></td>
      <td>${esc(h.event)}${h.matcher ? ` <span class="muted">${esc(h.matcher)}</span>` : ''}</td>
      <td><code>${esc(h.command.length > 100 ? `${h.command.slice(0, 97)}...` : h.command)}</code></td>
      <td>${h.runs.length > 0 ? h.runs.map(r => `<code>${esc(r)}</code>`).join('<br>') : '—'}</td>
      <td>${h.does.length > 0 ? h.does.map(d => `<span class="reach-chip reach-eff ungated"><i class="sw"></i>${esc(d)}</span>`).join('') : '<span class="muted">local commands only</span>'}</td>
      ${loc({ file: h.file, line: h.line })}
    </tr>`).join('')}
    </tbody>
  </table></div>` : ''}
  ${servers.length > 0 ? `
  <p class="guide"><b>MCP servers</b> the configuration starts.</p>
  <div class="table-wrap"><table id="agent-coding-mcp" class="sortable">
    ${sortableHead([{ key: 'server', label: 'Server' }, { key: 'agent', label: 'Agent' }, { key: 'starts', label: 'Starts', plain: true }, { key: 'own', label: 'Built from this repository' }, { key: 'pinned', label: 'Pinned' }, { key: 'content', label: 'Third-party content' }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${servers.map(m => `
    <tr ${rowAttrs({ file: m.file, search: ['mcp', m.name, m.harness, m.transport, m.host ?? '', m.launch?.command ?? ''] })}>
      <td><code>${esc(m.name)}</code>${m.disabled ? ' <span class="muted">disabled</span>' : ''}</td>
      <td><code>${esc(m.harness)}</code></td>
      <td>${m.transport === 'http' ? `http <code>${esc(m.host ?? '')}</code>` : `<code>${esc([m.launch?.command ?? '', ...(m.launch?.args ?? [])].join(' ').slice(0, 80))}</code>`}</td>
      <td>${m.resolves_to ? `<code>${esc(m.resolves_to.file)}</code>` : '—'}</td>
      <td>${m.package ? (m.package.pinned ? 'yes' : `<strong>no</strong> <code>${esc(m.package.spec)}</code>`) : '—'}</td>
      <td>${m.returns_third_party_content ? '<strong>yes</strong>' : 'no'}</td>
      ${loc({ file: m.file, line: m.line })}
    </tr>`).join('')}
    </tbody>
  </table></div>` : ''}`;
}

export function renderAgentsPage(ctx: PageContext, s: ReachSummary): string {
  const { scope, links } = ctx;
  const loc = (l: ReachLoc): string => locCellShort(l.file, l.line, links);
  const t = s.totals;
  const empty = t.reaches === 0 && t.effects === 0 && t.gates === 0
    && t.coding_reaches === 0 && s.coding.automatic.length === 0 && s.coding.mcp_servers.length === 0;

  if (empty) {
    return `
<section id="sec-agents" class="section-content" aria-label="Agents and reach">
  ${pageHead('Agents &amp; reach', scope)}
  <p class="empty-state">${scope
    ? `No <code>@agents</code>, <code>@reaches</code>, <code>@effects</code> or <code>@gates</code> in the files tagged ${esc(scopeLabel(scope))}. The project may declare them elsewhere — this slice does not show them.`
    : 'No <code>@agents</code>, <code>@reaches</code>, <code>@effects</code> or <code>@gates</code> annotations, so nothing in the model says what an embedded agent or another principal can reach.'}</p>
  <p class="guide">Declare it where each fact lives in the code — on the tool registration, the code that acts, and the approval step:</p>
  <pre class="well reach-example"><code>${REACH_EXAMPLE}</code></pre>
  ${actorTables(ctx)}
</section>`;
  }

  const llm = s.owasp.reduce((n, o) => n + o.items.length, 0);
  // Annotated reach to draw; without it the page is the coding-agent section alone.
  const embedded = t.reaches + t.effects + t.gates > 0;
  return `
<section id="sec-agents" class="section-content" aria-label="Agents and reach">
  ${pageHead('Agents &amp; reach', scope, '', `<span class="muted">${t.agents} ${plural(t.agents, 'agent')} · ${t.principals} other ${plural(t.principals, 'principal')}${t.coding_agents > 0 ? ` · ${t.coding_agents} coding ${plural(t.coding_agents, 'agent')}` : ''}</span>`)}
  <p class="lead">What each embedded LLM agent (<code>@agents</code>) and other principal (<code>@reaches</code>) can invoke, what the code does (<code>@effects</code>), who decides first (<code>@gates</code>), and what of it a human approved (<code>@entitles</code>). An effect sits in an actor's row only when it is written in the same doc-block as the actor's reach, so both are bound to the same code.${t.coding_reaches > 0 ? ' What the coding agents its developers run may do here is read from the repository\'s agent configuration and counted on its own, below.' : ''}${scope ? ` Only reach annotations in the files tagged ${esc(scopeLabel(scope))} are shown.` : ''}</p>
  <div class="panel tiles">
    ${embedded ? `
    ${tileJump(t.reaches, 'Reaches', 'agents-map', `${t.agents} ${plural(t.agents, 'agent')}, ${t.principals} other`)}
    ${tileJump(t.unentitled, 'Unentitled', 'agents-unentitled', 'can, but no one approved', true)}
    ${tileJump(`${t.ungated} of ${t.mutations}`, 'Ungated mutations', 'agents-ungated', 'nothing stands in front of them')}
    ${tileJump(t.gates, 'Gates', 'agents-gates', 'a named approver decides')}
    ${tileJump(t.egress, 'Egress', 'agents-egress', 'leaves the model or a boundary')}` : ''}
    ${tileJump(llm, 'OWASP LLM items', 'agents-owasp', 'LLM06 · LLM01 · LLM05')}
    ${t.coding_reaches > 0 || s.coding.automatic.length > 0 ? tileJump(`${t.coding_unentitled} of ${t.coding_reaches}`, 'Coding-agent reach', 'agents-coding', 'unentitled, granted by configuration') : ''}
  </div>
  <div class="filter-status" hidden><span class="filter-status-text"></span><button class="btn ghost" data-clear-filters>Clear</button></div>

  ${embedded ? `
  ${subHead('Reach map', '', `<span class="muted">${s.columns.length} ${plural(s.columns.length, 'asset')}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-map">')}
  <p class="guide">Rows are actors, columns the assets they reach; each cell holds the capabilities exposed on that asset and the effects the actor's tools have on it. <a href="#diagrams?tab=reach">Diagrams › Agent reach</a> draws the same facts.</p>
  ${reachMap(s)}

  ${subHead('Unentitled reaches', '', `<span data-count-for="agent-unentitled">${s.unentitled.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-unentitled">')}
  <p class="guide">Capabilities the code hands out that no cited <code>@entitles</code> covers — can minus may. For an agent this is the OWASP LLM06 Excessive Agency list. Only a human closes one, by accepting a proposal from <code>guardlink entitle --propose</code>.</p>
  ${s.unentitled.length > 0 ? `
  <div class="table-wrap"><table id="agent-unentitled" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'actor', label: 'Actor' }, { key: 'capability', label: 'Capability' }, { key: 'asset', label: 'On' }, { key: 'why', label: 'Why nothing covers it', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${s.unentitled.map(u => `
    <tr ${rowAttrs({ file: u.loc.file, search: ['unentitled', u.agent ? 'agent' : 'principal', u.actor, u.capability, u.asset ?? '', u.description ?? '', ...u.near_misses.map(n => n.blocker)] })}>
      <td><code>${esc(u.actor)}</code>${u.agent ? ' <span class="reach-kind agent">AI agent</span>' : ''}</td>
      <td><code>${esc(u.capability)}</code></td>
      <td>${u.asset ? `<code>${esc(u.asset)}</code>` : '—'}</td>
      <td>${u.near_misses.length === 0
        ? '<span class="muted">No <code>@entitles</code> for this actor and capability</span>'
        : u.near_misses.map(n => `<div class="reach-miss"><span class="state st-review"><span class="g">◐</span>${esc(n.blocker)}</span> ${esc(n.reason)} <span class="muted">${esc(where(n.loc))}</span></div>`).join('')}</td>
      ${loc(u.loc)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('agent-unentitled')}` : '<p class="empty-state">Every reach is covered by a cited entitlement.</p>'}

  ${subHead('Ungated mutations', '', `<span data-count-for="agent-ungated">${s.ungated.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-ungated">')}
  <p class="guide">Effects other than <code>read</code> with no <code>@gates</code> in front of them. A gate suppresses nothing; its absence means nothing in the model says a person or a check decides before the effect lands.</p>
  ${s.ungated.length > 0 ? `
  <div class="table-wrap"><table id="agent-ungated" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'effect', label: 'Effect' }, { key: 'asset', label: 'Asset' }, { key: 'identity', label: 'As' }, { key: 'via', label: 'Reached through' }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${s.ungated.map(u => `
    <tr ${rowAttrs({ file: u.loc.file, search: ['ungated', u.effect, u.asset, u.identity ?? '', u.description ?? '', ...u.via.flatMap(v => [v.actor, v.capability])] })}>
      <td><span class="reach-chip reach-eff ungated">${esc(u.effect)}</span></td>
      <td><code>${esc(u.asset)}</code></td>
      <td>${u.identity ? `<code>${esc(u.identity)}</code>` : '—'}</td>
      <td>${u.via.length > 0 ? u.via.map(v => `<code>${esc(v.actor)}</code> <code>${esc(v.capability)}</code>${v.agent ? ' <span class="reach-kind agent">AI agent</span>' : ''}`).join('<br>') : '<span class="muted">No reach on this code</span>'}${u.gate_near_misses.map(n => `<div class="reach-miss"><span class="state st-review"><span class="g">◐</span>${esc(n.blocker)}</span> ${esc(n.approver)}${n.capability ? ` for <code>${esc(n.capability)}</code>` : ''}: ${esc(n.reason)}</div>`).join('')}</td>
      ${descCell(u.description, '—')}
      ${loc(u.loc)}
    </tr>`).join('')}
    </tbody>
  </table></div>
  ${pager('agent-ungated')}` : `<p class="empty-state">${t.mutations > 0 ? 'Every mutation has a gate in front of it.' : 'No mutating effect is declared.'}</p>`}

  ${subHead('Gates', '', `<span data-count-for="agent-gates">${s.gates.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-gates">')}
  ${s.gates.length > 0 ? `
  <div class="table-wrap"><table id="agent-gates" class="sortable" data-paginate="25">
    ${sortableHead([{ key: 'asset', label: 'Asset' }, { key: 'approver', label: 'Approver' }, { key: 'for', label: 'For' }, { key: 'covers', label: 'Stands in front of', plain: true }, { key: 'description', label: 'Description', plain: true }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${s.gates.map(g => `
    <tr ${rowAttrs({ file: g.loc.file, search: ['gate', g.asset, g.approver, g.capability ?? '', g.description ?? ''] })}>
      <td><code>${esc(g.asset)}</code></td>
      <td><code>${esc(g.approver)}</code></td>
      <td>${g.capability ? `<code>${esc(g.capability)}</code>` : '<span class="muted">every capability</span>'}</td>
      <td>${g.covers.length > 0 ? g.covers.map(c => `<span class="reach-chip reach-eff gated" title="${esc(where(c.loc))}">${esc(c.effect)}</span> <code>${esc(c.asset)}</code>`).join('<br>') : '<span class="muted">No declared mutation on this asset</span>'}</td>
      ${descCell(g.description, '—')}
      ${loc(g.loc)}
    </tr>`).join('')}
    </tbody>
  </table></div>` : '<p class="empty-state">No <code>@gates</code>: nothing in the model says a person decides before any effect lands.</p>'}

  ${s.egress.length > 0 ? `
  ${subHead('Egress from a reach', '', `<span data-count-for="agent-egress">${s.egress.length}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-egress">')}
  <p class="guide"><code>@flows</code> out of an actor or a surface it reaches that leave the model or cross a declared <code>@boundary</code>.</p>
  <div class="table-wrap"><table id="agent-egress" class="sortable">
    ${sortableHead([{ key: 'actors', label: 'Actors' }, { key: 'flow', label: 'Flow' }, { key: 'external', label: 'Leaves the model' }, { key: 'crosses', label: 'Crosses' }, { key: 'location', label: 'Location', cls: 'loc' }])}
    <tbody>
    ${s.egress.map(e => `
    <tr ${rowAttrs({ file: e.loc.file, search: ['egress', ...e.actors, e.source, e.target, e.mechanism ?? '', ...e.boundaries] })}>
      <td>${e.actors.map(a => `<code>${esc(a)}</code>`).join(' ')}</td>
      <td><code>${esc(e.source)}</code> <span class="flow-arrow">→</span> <code>${esc(e.target)}</code>${e.mechanism ? ` <span class="muted">via ${esc(e.mechanism)}</span>` : ''}</td>
      <td>${e.external ? '<strong>yes</strong>' : 'no'}</td>
      <td>${e.boundaries.length > 0 ? e.boundaries.map(b => `<code>${esc(b)}</code>`).join(' ') : '—'}</td>
      ${loc(e.loc)}
    </tr>`).join('')}
    </tbody>
  </table></div>` : ''}

${measuredSection(ctx.measured ?? [], loc)}
` : `
  <p class="empty-state">No <code>@agents</code>, <code>@reaches</code>, <code>@effects</code> or <code>@gates</code> annotations: nothing in the model says what an agent this code embeds can reach. The coding agents this repository configures are below.</p>`}

  ${codingSection(s, loc)}

  ${t.agents > 0 || s.injection.length > 0 ? `
  ${subHead('OWASP Top 10 for LLM Applications', '', `<span>${llm}</span>`).replace('<div class="sub-h">', '<div class="sub-h" id="agents-owasp">')}
  <p class="guide">What the reach annotations add up to for the 2025 list. Each row is a target for review or a test, not a finding the model has proved.</p>
  <div class="reach-owasp">
    ${s.owasp.map(o => `
    <div class="reach-owasp-item${o.items.length > 0 ? ' has' : ''}">
      <div class="reach-owasp-h"><span class="reach-owasp-id">${esc(o.id)}</span> ${esc(o.title)} <span class="reach-owasp-n">${o.items.length}</span></div>
      <p class="guide">${esc(o.basis)}</p>
      ${o.items.length > 0 ? `<ul>${o.items.map(i => `<li data-search="${esc(`${o.id} ${i.facet} ${i.agent} ${i.text}`.toLowerCase())}"><span class="reach-facet">${esc(i.facet)}</span> <code>${esc(i.agent)}</code> ${esc(i.text)} <span class="muted">${esc(where(i.loc))}</span></li>`).join('')}</ul>` : '<p class="muted">Nothing found.</p>'}
    </div>`).join('')}
  </div>` : ''}
  ${actorTables(ctx)}
</section>`;
}
