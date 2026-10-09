/**
 * GuardLink Dashboard — Diagrams › Attack surface: every asset on a shelf.
 *
 * One shelf per asset group (`path[0]`), on a dotted ground. Cards are
 * justified along rows with a width proportional to (exposures + 3)^0.85, so a
 * heavily exposed asset is visibly bigger without drowning the rest. Each card
 * carries a header strip whose rule is its open share, one tick per exposure —
 * warm by severity while open, a mint wash once resolved, hollow when
 * accepted — and a footer with its flows, trust lines and data classes.
 *
 * Nothing here can overflow: rows wrap, so 18 assets and 1,800 draw the same
 * way. Wrapping is the browser's flex layout over widths computed from data;
 * nothing is measured.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "Asset labels, threat labels, paths and classifications are escaped through xml() and attrs()"
 */
import type { DiagramModel, GExposure, GNode } from './graph.js';
import { SEV_RANK, isOpenState, markLabel } from './graph.js';
import { attrs, tip, xml, plural } from './text.js';

export interface ShelvesResult { html: string; cards: number; shelves: number; exposures: number }

const ORDER: Record<string, number> = { open: 0, confirmed: 0, accepted: 1, mitigated: 2, refuted: 2 };

function tick(m: DiagramModel, e: GExposure): string {
  const cls = isOpenState(e.state) ? `tk s-${e.sev}` : e.state === 'accepted' ? 'tk acc' : 'tk res';
  return `<i${attrs({ class: cls, ...tip(`${m.nodes.get(e.asset)?.label ?? e.asset} → ${m.threats.get(e.threat)?.label ?? e.threat}`, [['severity', e.sev], ['state', e.state], ['where', `${e.file}:${e.line}`]]) })}></i>`;
}

function card(m: DiagramModel, a: GNode, index: number): string {
  const n = a.exposures.length;
  const weight = Math.pow(n + 3, 0.85);
  const share = n ? Math.max(a.open ? 4 : 100, (a.open / n) * 100) : 0;
  const gauge = n
    ? `<div class="gauge"><i class="${a.open ? `s-${a.worst}` : 'm-res'}" style="width:${share.toFixed(1)}%"></i></div>`
    : '<div class="gauge silent"></div>';
  const ex = a.exposures.slice().sort((x, y) => ORDER[x.state] - ORDER[y.state] || SEV_RANK[x.sev] - SEV_RANK[y.sev] || x.claim - y.claim);
  return `<div${attrs({
    class: 'shelf-card nd', tabindex: 0, role: 'button', 'data-node': `s${index}`, 'data-key': a.key, 'data-claims': a.exposures.map(e => e.claim).join(' '), 'data-name': a.label,
    'aria-label': `${a.label}: ${markLabel(a)}`, style: `flex:${weight.toFixed(2)} 1 ${Math.round(120 + weight * 9)}px`,
  })}>
      <div class="sc-head"><b class="mono">${xml(a.label)}</b><span class="spacer"></span><span class="num subtle">${n}</span></div>${gauge}
      <div class="sc-ticks">${ex.map(e => tick(m, e)).join('') || '<span class="subtle">no exposure declared</span>'}</div>
      <div class="sc-foot"><span${attrs({ title: 'flows in · flows out' })}>⇢ ${a.flowsIn.length} in · ${a.flowsOut.length} out</span>${a.boundaries.length ? `<span${attrs({ title: a.boundaries.join(', ') })}>⊢ ${a.boundaries.length}</span>` : ''}${a.handles.map(h => `<span class="tag">${xml(h)}</span>`).join('')}</div>
    </div>`;
}

export function renderShelves(m: DiagramModel): ShelvesResult {
  const groups = new Map<string, GNode[]>();
  for (const a of m.assets) {
    if (!groups.has(a.group)) groups.set(a.group, []);
    groups.get(a.group)!.push(a);
  }
  let i = 0;
  const shelves = [...groups].map(([g, list]) => {
    const open = list.reduce((s, a) => s + a.open, 0);
    const ex = list.reduce((s, a) => s + a.exposures.length, 0);
    return `<section class="shelf panel">
    <div class="shelf-h"><span class="zone-h">${xml(g)}</span><span class="subtle">${plural(list.length, 'asset')} · ${plural(ex, 'exposure')} · ${open} open</span></div>
    <div class="shelf-field dotground">${list.map(a => card(m, a, i++)).join('')}</div>
  </section>`;
  });
  return { html: shelves.join(''), cards: m.assets.length, shelves: groups.size, exposures: m.exposures.length };
}
