/**
 * GuardLink Dashboard — Diagrams › Threat graph: assets → threats → controls.
 *
 * Three columns of the tripartite layout. Every exposure is one asset → threat
 * thread, warm by severity while open, a mint wash once mitigated or refuted,
 * dashed when accepted; every mitigation is one threat → control thread. Open
 * threads paint last so the alarm is never under a resolved thread.
 *
 * Laid out here, at generation time, and emitted as an SVG string: the drawing
 * exists before any script runs and cannot be laid out wrong by a hidden panel.
 * The client only adds hover (it toggles classes; CSS dims) and pin.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Asset, threat and control labels and descriptions reach the SVG only through xml() and attrs()"
 */
import type { DiagramModel, GExposure, Sev } from './graph.js';
import { SEV_RANK, isOpenState, markOf, markLabel } from './graph.js';
import { layoutTripartite, sCurve, placeNames, type TriItem, type TriLink } from './tripartite.js';
import { attrs, fitLeft, r1, tip, xml, dotPattern } from './text.js';

export interface ThreatGraphResult {
  svg: string;
  exposures: number;
  exposuresDrawn: number;
  mitigations: number;
  mitigationsDrawn: number;
  assets: number;
  threats: number;
  controls: number;
  /** Asset and control names left off to keep names 11 px apart; still on hover. */
  folded: number;
  /** Mitigations that name no control: drawn to a dashed "no control named" tick. */
  uncontrolled: number;
}

const W = 1000;
const X0 = 176;            // asset ticks
const TICK = 5;
const SLAB = 176;
const X2 = W - 186;        // control ticks (right edge of the tick)
const X1 = Math.round((X0 + TICK + X2) / 2 - SLAB / 2);
const PITCH = 2.4;
const NAME_GAP = 11;
const NO_CONTROL = '\u0000none';

const stateClass = (e: GExposure): string =>
  isOpenState(e.state) ? `x-open s-${e.sev}` : e.state === 'accepted' ? 'x-acc' : 'x-res';

export function renderThreatGraph(m: DiagramModel): ThreatGraphResult {
  const ex = m.exposures;
  const mit = m.mitigations;
  const assets = m.assets.filter(a => a.exposures.length > 0);
  const aIdx = new Map(assets.map((a, i) => [a.key, i]));
  const tKeys = [...new Set([...ex.map(e => e.threat), ...mit.map(x => x.threat)])];
  const tIdx = new Map(tKeys.map((k, i) => [k, i]));
  const cKeys = [...new Set(mit.map(x => x.control || NO_CONTROL))];
  const cIdx = new Map(cKeys.map((k, i) => [k, i]));

  const items: TriItem[] = [
    ...assets.map(a => ({ key: `a${aIdx.get(a.key)}`, col: 0 as const })),
    ...tKeys.map(k => ({ key: `t${tIdx.get(k)}`, col: 1 as const })),
    ...cKeys.map(k => ({ key: `c${cIdx.get(k)}`, col: 2 as const })),
  ];
  const links: TriLink[] = [];
  ex.forEach((e, i) => { if (aIdx.has(e.asset)) links.push({ key: `e${i}`, from: `a${aIdx.get(e.asset)}`, to: `t${tIdx.get(e.threat)}` }); });
  mit.forEach((x, i) => links.push({ key: `m${i}`, from: `t${tIdx.get(x.threat)}`, to: `c${cIdx.get(x.control || NO_CONTROL)}` }));

  const L = layoutTripartite(items, links, { pitch: PITCH, gap: 5, minH: [8, 22, 8], pad: [0, 6, 0], top: 30 });
  const H = Math.ceil(L.height + 18);

  // Which pair keys an asset / control lights, and which claims its pin lists.
  const pairOf = (asset: string, threat: string): string => `p${aIdx.get(asset) ?? 'x'}.${tIdx.get(threat)}`;
  const exByThreat = new Map<string, number[]>();
  ex.forEach(e => { if (!exByThreat.has(e.threat)) exByThreat.set(e.threat, []); exByThreat.get(e.threat)!.push(e.claim); });

  const out: string[] = [];
  out.push(`<svg${attrs({ class: 'dg', 'data-plot': 'threat', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'group', tabindex: 0, 'aria-label': `Threat graph: ${ex.length} exposures and ${mit.length} mitigations across ${assets.length} assets, ${tKeys.length} threats and ${cKeys.length} controls. Arrow keys step through the nodes, Enter pins one.` })}>`);
  out.push(`<defs>${dotPattern('dots-threat')}</defs><rect class="ground" width="${W}" height="${H}" fill="url(#dots-threat)"/>`);
  out.push(`<text class="hd" x="${X0 - 10}" y="16" text-anchor="end">ASSETS</text><text class="hd" x="${X1}" y="16">THREATS</text><text class="hd" x="${X2 + 10}" y="16">CONTROLS</text>`);

  // Threads: resolved first, then accepted, then open by rising severity — the alarm paints last.
  const paint = (e: GExposure): number => (isOpenState(e.state) ? 100 - SEV_RANK[e.sev] : e.state === 'accepted' ? 1 : 0);
  const exOrder = ex.map((e, i) => ({ e, i })).sort((a, b) => paint(a.e) - paint(b.e) || a.i - b.i);
  out.push('<g class="threads">');
  for (const x of mit.map((v, i) => ({ v, i }))) {
    const end = L.ends.get(`m${x.i}`);
    if (!end) continue;
    const c = x.v.control || NO_CONTROL;
    out.push(`<path${attrs({ class: 'thr x-ctl', d: sCurve(X1 + SLAB, end.y0, X2 - TICK, end.y1), 'data-k': `t${tIdx.get(x.v.threat)} c${cIdx.get(c)} ${pairOf(x.v.asset, x.v.threat)}`, ...tip(`${controlLabel(m, c)} mitigates ${m.threats.get(x.v.threat)?.label ?? x.v.threat}`, [['on', m.nodes.get(x.v.asset)?.label ?? x.v.asset], ['where', `${x.v.file}:${x.v.line}`]]) })}/>`);
  }
  let exDrawn = 0;
  for (const { e, i } of exOrder) {
    const end = L.ends.get(`e${i}`);
    if (!end) continue;
    exDrawn++;
    out.push(`<path${attrs({ class: `thr ${stateClass(e)}`, d: sCurve(X0 + TICK, end.y0, X1, end.y1), 'data-k': `a${aIdx.get(e.asset)} t${tIdx.get(e.threat)} ${pairOf(e.asset, e.threat)}`, 'data-claim-ref': e.claim, ...tip(`${m.nodes.get(e.asset)?.label ?? e.asset} → ${m.threats.get(e.threat)?.label ?? e.threat}`, [['severity', e.sev], ['state', e.state], ['why', e.description || '—'], ['where', `${e.file}:${e.line}`]]) })}/>`);
  }
  out.push('</g><g class="nodes">');

  // Assets: ticks with names in the left gutter.
  const named = placeNames(assets.map(a => {
    const s = L.slots.get(`a${aIdx.get(a.key)}`)!;
    return { key: a.key, y: s.y + s.h / 2, priority: a.open * 1000 + a.exposures.length };
  }), NAME_GAP);
  let folded = assets.length - named.size;
  for (const a of assets) {
    const i = aIdx.get(a.key)!;
    const s = L.slots.get(`a${i}`)!;
    const mk = markOf(a);
    const pairs = [...new Set(a.exposures.map(e => pairOf(e.asset, e.threat)))];
    const cls = mk.kind === 'open' ? `tick m-open s-${mk.sev}` : mk.kind === 'resolved' ? 'tick m-res' : 'tick m-empty';
    out.push(`<g${attrs({ class: 'nd', 'data-node': `a${i}`, 'data-lights': `a${i} ${pairs.join(' ')}`, 'data-claims': a.exposures.map(e => e.claim).join(' '), 'data-name': a.label, 'data-key': a.key, role: 'button', 'aria-label': `${a.label}: ${markLabel(a)}`, ...tip(a.label, [['exposures', a.exposures.length], ['open', a.open ? `${a.open} · worst ${a.worst}` : 0], ['resolved', a.exposures.filter(e => !isOpenState(e.state)).length]]) })}>`);
    out.push(`<rect class="pinbox" x="${X0 - 2.5}" y="${r1(s.y - 2.5)}" width="${TICK + 5}" height="${r1(s.h + 5)}" rx="2"/>`);
    out.push(`<rect class="${cls}" x="${X0}" y="${r1(s.y)}" width="${TICK}" height="${r1(s.h)}" rx="1"/>`);
    if (named.has(a.key)) out.push(`<text class="nm${a.open ? ' hot' : ''}" x="${X0 - 8}" y="${r1(s.y + s.h / 2 + 3.5)}" text-anchor="end">${xml(fitLeft(a.label, X0 - 16, 10.5))}</text>`);
    else out.push(`<rect class="hit" x="${X0 - 30}" y="${r1(s.y)}" width="30" height="${r1(Math.max(s.h, 4))}"/>`);
    out.push('</g>');
  }

  // Threats: labelled slabs, the only column with names inside.
  for (const k of tKeys) {
    const i = tIdx.get(k)!;
    const s = L.slots.get(`t${i}`)!;
    const list = ex.filter(e => e.threat === k);
    const open = list.filter(e => isOpenState(e.state));
    const worst = open.reduce<Sev | null>((w, e) => (w === null || SEV_RANK[e.sev] < SEV_RANK[w] ? e.sev : w), null);
    const mits = mit.filter(x => x.threat === k).length;
    const t = m.threats.get(k);
    const name = t?.label ?? k;
    out.push(`<g${attrs({ class: 'nd', 'data-node': `t${i}`, 'data-lights': `t${i}`, 'data-claims': (exByThreat.get(k) ?? []).join(' '), 'data-name': name, role: 'button', 'aria-label': `${name}: ${list.length} exposures, ${open.length} open, ${mits} mitigations`, ...tip(name, [...(t?.name && t.name !== name ? [['name', t.name] as [string, string]] : []), ['declared severity', t?.sev ?? 'unset'], ['exposures', list.length], ['open', worst ? `${open.length} · worst ${worst}` : 0], ['mitigations', mits]]) })}>`);
    out.push(`<rect class="slab" x="${X1}" y="${r1(s.y)}" width="${SLAB}" height="${r1(s.h)}" rx="4"/>`);
    if (worst) out.push(`<rect class="slab-edge s-${worst}" x="${X1}" y="${r1(s.y)}" width="3" height="${r1(s.h)}" rx="1"/>`);
    out.push(`<rect class="pinbox" x="${X1 - 1.5}" y="${r1(s.y - 1.5)}" width="${SLAB + 3}" height="${r1(s.h + 3)}" rx="5"/>`);
    out.push(`<text class="nm hot" x="${X1 + 9}" y="${r1(s.y + Math.min(s.h / 2 + 3.5, 14.5))}">${xml(fitLeft(name, SLAB - 16, 10.5))}</text>`);
    if (s.h >= 30) out.push(`<text class="sub" x="${X1 + 9}" y="${r1(s.y + 27)}">${list.length} exp · ${open.length} open · ${mits} mit</text>`);
    out.push('</g>');
  }

  // Controls: people-pole ticks with names in the right gutter.
  const cNamed = placeNames(cKeys.map(k => {
    const s = L.slots.get(`c${cIdx.get(k)}`)!;
    return { key: k, y: s.y + s.h / 2, priority: mit.filter(x => (x.control || NO_CONTROL) === k).length };
  }), NAME_GAP);
  folded += cKeys.length - cNamed.size;
  for (const k of cKeys) {
    const i = cIdx.get(k)!;
    const s = L.slots.get(`c${i}`)!;
    const mine = mit.filter(x => (x.control || NO_CONTROL) === k);
    const pairs = [...new Set(mine.map(x => pairOf(x.asset, x.threat)))];
    const pairSet = new Set(mine.map(x => `${x.asset}\u0000${x.threat}`));
    const claims = ex.filter(e => pairSet.has(`${e.asset}\u0000${e.threat}`)).map(e => e.claim);
    const name = controlLabel(m, k);
    out.push(`<g${attrs({ class: 'nd', 'data-node': `c${i}`, 'data-lights': `c${i} ${pairs.join(' ')}`, 'data-claims': claims.join(' '), 'data-name': name, role: 'button', 'aria-label': `${name}: ${mine.length} mitigations`, ...tip(name, [['mitigations', mine.length], ['threats', new Set(mine.map(x => x.threat)).size], ['assets', new Set(mine.map(x => x.asset)).size]]) })}>`);
    out.push(`<rect class="pinbox" x="${X2 - TICK - 2.5}" y="${r1(s.y - 2.5)}" width="${TICK + 5}" height="${r1(s.h + 5)}" rx="2"/>`);
    out.push(`<rect class="${k === NO_CONTROL ? 'tick m-ext' : 'tick m-ctl'}" x="${X2 - TICK}" y="${r1(s.y)}" width="${TICK}" height="${r1(s.h)}" rx="1"/>`);
    if (cNamed.has(k)) out.push(`<text class="nm" x="${X2 + 8}" y="${r1(s.y + s.h / 2 + 3.5)}">${xml(fitLeft(name, W - X2 - 14, 10.5))}</text>`);
    else out.push(`<rect class="hit" x="${X2}" y="${r1(s.y)}" width="30" height="${r1(Math.max(s.h, 4))}"/>`);
    out.push('</g>');
  }
  out.push('</g></svg>');

  return {
    svg: out.join(''),
    exposures: ex.length, exposuresDrawn: exDrawn,
    mitigations: mit.length, mitigationsDrawn: mit.filter((_, i) => L.ends.has(`m${i}`)).length,
    assets: assets.length, threats: tKeys.length, controls: cKeys.filter(k => k !== NO_CONTROL).length,
    folded, uncontrolled: mit.filter(x => !x.control).length,
  };
}

function controlLabel(m: DiagramModel, key: string): string {
  if (key === NO_CONTROL) return 'no control named';
  return m.controls.get(key)?.label ?? key;
}
