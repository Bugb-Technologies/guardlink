/**
 * GuardLink Dashboard — Diagrams › Agent reach: who acts → the capability the
 * code hands them → the effect it lands.
 *
 * Drawn from `summarizeReach`, the same derived view the Agents & reach page and
 * the report print, so it invents no rule of its own. The tripartite layout,
 * with column 2 grouped into one slab per asset:
 *   - actors are rounded for an AI agent and square for any other principal; a
 *     dashed "code not tied to a reach" source carries the effects no
 *     `@agents` / `@reaches` is bound to;
 *   - capabilities are pills: ✓ in mint when a cited `@entitles` covers them,
 *     ✕ in warm when nothing does;
 *   - effects are rows in their asset's slab: warm "no gate" for an ungated
 *     mutation, mint "gated ⊢ approver" with a bar where a human decides
 *     first, hollow "reads only".
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Actor, capability, asset, approver and identity names reach the SVG only through xml() and attrs()"
 */
import type { ReachSummary, ReachEffectChip } from '../../reach/index.js';
import { layoutTripartite, sCurve, type TriItem, type TriLink } from './tripartite.js';
import { attrs, fitLeft, r1, tip, xml, dotPattern, textWidth } from './text.js';

export interface ReachDiagramResult {
  svg: string;
  reaches: number;
  effects: number;
  unentitled: number;
  mutations: number;
  ungated: number;
  gates: number;
}

const LOOSE = '\u0000loose';
const NO_CAP = '\u0000nocap';

interface EffRow { key: string; asset: string; e: ReachEffectChip; from: string[] }

export function renderReachDiagram(s: ReachSummary): ReachDiagramResult | null {
  const t = s.totals;
  if (t.reaches === 0 && t.effects === 0) return null;
  const actors = s.actors.filter(a => a.reaches > 0);
  const actorRef = new Map(s.actors.map(a => [a.key, a]));
  const colRef = new Map(s.columns.map(c => [c.key, c.ref]));

  // Capabilities: one pill per (actor, capability, asset) reach, ordered by actor.
  const caps: { key: string; actor: string; asset: string; capability: string; entitled: boolean; loc: string; identity?: string }[] = [];
  for (const a of actors) {
    for (const c of s.cells.filter(x => x.actor === a.key)) {
      for (const cap of c.capabilities) caps.push({ key: `p${caps.length}`, actor: a.key, asset: c.asset, capability: cap.capability, entitled: cap.entitled, loc: `${cap.loc.file}:${cap.loc.line}`, identity: cap.identity });
    }
  }
  const capOf = (actor: string, capability: string): string[] => caps.filter(c => c.actor === actor && c.capability === capability).map(c => c.key);

  // Effects land on the cell's asset; `via` names the capability, on the same actor, that reaches the code.
  const rows: EffRow[] = [];
  for (const c of s.cells) {
    for (const e of c.effects) {
      const from = e.via.flatMap(v => capOf(c.actor, v));
      rows.push({ key: `f${rows.length}`, asset: c.asset, e, from: from.length ? from : [NO_CAP] });
    }
  }
  for (const l of s.loose) for (const e of l.effects) rows.push({ key: `f${rows.length}`, asset: l.asset, e, from: [NO_CAP] });
  const needLoose = rows.some(r => r.from.includes(NO_CAP));

  const items: TriItem[] = [
    ...actors.map(a => ({ key: `a:${a.key}`, col: 0 as const })),
    ...(needLoose ? [{ key: LOOSE, col: 0 as const }] : []),
    ...caps.map(c => ({ key: c.key, col: 1 as const })),
    ...(needLoose ? [{ key: NO_CAP, col: 1 as const }] : []),
    ...rows.map(r => ({ key: r.key, col: 2 as const, group: r.asset })),
  ];
  const links: TriLink[] = [
    ...caps.map(c => ({ key: `ac:${c.key}`, from: `a:${c.actor}`, to: c.key })),
    ...(needLoose ? [{ key: 'ac:loose', from: LOOSE, to: NO_CAP }] : []),
    ...rows.flatMap(r => r.from.map((f, j) => ({ key: `ce:${r.key}:${j}`, from: f, to: r.key }))),
  ];
  const L = layoutTripartite(items, links, { pitch: 6, gap: 10, minH: [36, 24, 22], fixedH: [null, 24, 22], top: 34, groupHead: 22, groupGap: 12 });
  const H = Math.ceil(L.height + 16);

  const capW = Math.min(300, Math.max(170, ...caps.map(c => 40 + textWidth(`${c.capability}  ${colRef.get(c.asset) ?? c.asset}`, 10.5))));
  const effW = 250;
  const xA = 16, aW = 168;
  const W = Math.max(860, xA + aW + 70 + capW + 70 + effW + 16);
  const xE = W - effW - 16;
  const xC = Math.round((xA + aW + xE) / 2 - capW / 2);

  const out: string[] = [];
  out.push(`<svg${attrs({ class: 'dg reach', 'data-plot': 'reach', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'group', tabindex: 0, 'aria-label': `Agent reach: ${t.reaches} reaches, ${t.effects} effects, ${t.unentitled} unentitled, ${t.ungated} of ${t.mutations} mutations ungated, ${t.gates} gates.` })}>`);
  out.push(`<defs>${dotPattern('dots-reach')}</defs><rect class="ground" width="${W}" height="${H}" fill="url(#dots-reach)"/>`);
  out.push(`<text class="hd" x="${xA}" y="16">WHO ACTS</text><text class="hd" x="${xC}" y="16">CAPABILITY THE CODE HANDS OUT</text><text class="hd" x="${xE}" y="16">EFFECT IT LANDS</text>`);
  const mid = (k: string): number => { const sl = L.slots.get(k)!; return sl.y + sl.h / 2; };

  out.push('<g class="threads">');
  for (const c of caps) {
    out.push(`<path${attrs({ class: `thr ${c.entitled ? 'x-ok' : 'x-bad'}`, d: sCurve(xA + aW, mid(`a:${c.actor}`), xC, mid(c.key)), 'data-k': `a:${c.actor} ${c.key}`, ...tip(`${actorRef.get(c.actor)?.ref ?? c.actor} can ${c.capability}`, [['on', colRef.get(c.asset) ?? c.asset], ['entitled', c.entitled ? 'yes — a cited @entitles covers it' : 'no — nothing covers it'], ['where', c.loc]]) })}/>`);
  }
  if (needLoose) out.push(`<path class="thr x-read x-loose" d="${sCurve(xA + aW, mid(LOOSE), xC, mid(NO_CAP))}"/>`);
  const gateBars: string[] = [];
  for (const r of rows) {
    const mut = r.e.mutating, gated = r.e.gated === true;
    for (let j = 0; j < r.from.length; j++) {
      const f = r.from[j];
      const cls = !mut ? 'x-read' : gated ? 'x-gated' : 'x-ungated';
      out.push(`<path${attrs({ class: `thr ${cls}${f === NO_CAP ? ' x-loose' : ''}`, d: sCurve(xC + capW, mid(f), xE, mid(r.key)), 'data-k': `${f} ${r.key}` })}/>`);
    }
    if (mut && gated) gateBars.push(`<line class="gate" x1="${xE - 14}" x2="${xE - 14}" y1="${r1(mid(r.key) - 6)}" y2="${r1(mid(r.key) + 6)}"/>`);
  }
  out.push(...gateBars, '</g><g class="nodes">');

  for (const a of actors) {
    const sl = L.slots.get(`a:${a.key}`)!;
    const cy = sl.y + sl.h / 2;
    out.push(`<g${attrs({ class: 'nd', 'data-node': `a:${a.key}`, 'data-lights': `a:${a.key} ${caps.filter(c => c.actor === a.key).map(c => c.key).join(' ')}`, role: 'button', 'aria-label': `${a.ref}: ${a.agent ? 'AI agent' : 'principal'}, ${a.reaches} reaches, ${a.unentitled} unentitled`, ...tip(a.ref, [['kind', a.agent ? 'AI agent' : 'principal'], ['reaches', a.reaches], ['unentitled', a.unentitled], ['ungated mutations', a.ungated]]) })}>`);
    out.push(`<rect class="actor${a.agent ? ' agent' : ''}" x="${xA}" y="${r1(cy - 17)}" width="${aW}" height="34" rx="${a.agent ? 17 : 5}"/>`);
    out.push(`<rect class="pinbox" x="${xA - 2}" y="${r1(cy - 19)}" width="${aW + 4}" height="38" rx="${a.agent ? 19 : 7}"/>`);
    out.push(`<text class="nm hot strong" x="${xA + 14}" y="${r1(cy - 2)}">${xml(fitLeft(a.ref, aW - 24, 11))}</text><text class="sub" x="${xA + 14}" y="${r1(cy + 11)}">${a.agent ? 'AI agent' : 'principal'}</text></g>`);
  }
  if (needLoose) {
    const cy = mid(LOOSE);
    out.push(`<g${attrs({ class: 'nd', 'data-node': 'loose', 'data-lights': `${NO_CAP} loose`, ...tip('code not tied to a reach', [['effects', rows.filter(r => r.from.includes(NO_CAP)).length]]) })}><rect class="actor loose" x="${xA}" y="${r1(cy - 17)}" width="${aW}" height="34" rx="5"/><text class="sub" x="${xA + 14}" y="${r1(cy + 3.5)}">code not tied to a reach</text></g>`);
    out.push(`<text class="sub" x="${xC + 12}" y="${r1(mid(NO_CAP) + 3.5)}">— no capability names this code</text>`);
  }
  for (const c of caps) {
    const cy = mid(c.key);
    out.push(`<g${attrs({ class: 'nd', 'data-node': c.key, 'data-lights': `${c.key} ${rows.filter(r => r.from.includes(c.key)).map(r => r.key).join(' ')}`, role: 'button', 'aria-label': `${c.capability} on ${colRef.get(c.asset) ?? c.asset}: ${c.entitled ? 'entitled' : 'unentitled'}`, ...tip(c.capability, [['actor', actorRef.get(c.actor)?.ref ?? c.actor], ['on', colRef.get(c.asset) ?? c.asset], ['entitled', c.entitled ? 'yes' : 'no'], ...(c.identity ? [['as', c.identity] as [string, string]] : []), ['where', c.loc]]) })}>`);
    out.push(`<rect class="cap ${c.entitled ? 'ok' : 'bad'}" x="${xC}" y="${r1(cy - 12)}" width="${r1(capW)}" height="24" rx="12"/>`);
    out.push(`<text class="nm hot" x="${xC + 12}" y="${r1(cy + 3.5)}"><tspan class="${c.entitled ? 'ok' : 'bad'}">${c.entitled ? '✓ ' : '✕ '}</tspan>${xml(c.capability)}<tspan class="sub">  ${xml(colRef.get(c.asset) ?? c.asset)}</tspan></text></g>`);
  }
  for (const [asset, g] of L.groups) {
    out.push(`<rect class="slab" x="${xE}" y="${r1(g.y)}" width="${effW}" height="${r1(g.h + 4)}" rx="6"/><text class="nm hot strong" x="${xE + 10}" y="${r1(g.y + 15)}">${xml(fitLeft(colRef.get(asset) ?? `#${asset}`, effW - 20, 10.5))}</text>`);
  }
  for (const r of rows) {
    const cy = mid(r.key);
    const mut = r.e.mutating, gated = r.e.gated === true;
    const what = !mut ? 'reads only' : gated ? `gated ⊢ ${r.e.approvers.join(', ')}` : 'no gate';
    out.push(`<g${attrs({ class: 'nd eff', 'data-node': r.key, 'data-lights': `${r.key} ${r.from.join(' ')}`, ...tip(`${r.e.effect} ${colRef.get(r.asset) ?? r.asset}`, [['mutating', mut ? 'yes' : 'no'], ['gate', gated ? r.e.approvers.join(', ') : 'none'], ['identity', r.e.identity ?? '—'], ['where', `${r.e.loc.file}:${r.e.loc.line}`]]) })}>`);
    out.push(`<rect class="hit" x="${xE}" y="${r1(cy - 11)}" width="${effW}" height="22"/><rect class="eff-sw ${!mut ? 'read' : gated ? 'gated' : 'ungated'}" x="${xE + 10}" y="${r1(cy - 4)}" width="8" height="8" rx="1.5"/>`);
    out.push(`<text class="nm hot" x="${xE + 24}" y="${r1(cy + 3.5)}">${xml(r.e.effect)}<tspan class="sub">  · ${xml(fitLeft(what, effW - 90, 10.5, false))}</tspan></text></g>`);
  }
  out.push('</g></svg>');
  return { svg: out.join(''), reaches: caps.length, effects: rows.length, unentitled: caps.filter(c => !c.entitled).length, mutations: rows.filter(r => r.e.mutating).length, ungated: rows.filter(r => r.e.mutating && r.e.gated !== true).length, gates: s.gates.length };
}
