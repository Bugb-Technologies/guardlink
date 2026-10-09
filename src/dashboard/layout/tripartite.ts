/**
 * GuardLink Dashboard — a three-column ribbon layout.
 *
 * Two diagrams share it: the threat graph (assets → threats → controls, one
 * thread per exposure and per mitigation) and agent reach (who acts →
 * capability → the effect it lands). Every relation is drawn; nothing is
 * filtered for size, because a column of ticks with one thread per relation
 * reads at 10 relations and at 1,000 — unlike a node-link graph, whose
 * legibility budget is about a dozen nodes.
 *
 * The layout is deterministic and computed from data alone:
 *   - column 0 keeps the order it is given (the model's order — the spine);
 *   - column 1 is ordered by the barycentre of its column-0 partners, column 2
 *     by the barycentre of its column-1 partners, which is the classic cheap
 *     cut of crossings;
 *   - a slot is as tall as the threads it carries (`pitch` each), never less
 *     than its column's minimum;
 *   - thread ends inside a slot are sorted by the partner's position, so
 *     threads leaving one slot never cross each other there.
 *
 * @comment -- "Pure geometry over keys; no DOM, no measurement. The callers own every label and every colour"
 */

export interface TriItem {
  key: string;
  col: 0 | 1 | 2;
  /** Items in column 2 may be grouped into slabs (agent reach groups effects by asset). */
  group?: string;
}

export interface TriLink {
  key: string;
  /** An item in column c … */
  from: string;
  /** … and one in column c + 1. */
  to: string;
}

export interface TriOptions {
  /** Vertical pitch of one thread end inside a slot. */
  pitch: number;
  /** Space between slots in a column. */
  gap: number;
  /** Minimum slot height per column. */
  minH: [number, number, number];
  /** Extra height per slot per column, on top of the threads it carries. */
  pad?: [number, number, number];
  /** Fixed slot height per column (overrides the thread-driven height). */
  fixedH?: [number | null, number | null, number | null];
  /** Room above the first slot (column headings). */
  top: number;
  /** Header height above each group in column 2, and the space between groups. */
  groupHead?: number;
  groupGap?: number;
}

export interface TriSlot { key: string; col: number; y: number; h: number; group?: string }
export interface TriGroup { key: string; y: number; h: number }

export interface TriLayout {
  slots: Map<string, TriSlot>;
  /** Each link's y where it leaves its `from` slot and where it enters its `to` slot. */
  ends: Map<string, { y0: number; y1: number }>;
  groups: Map<string, TriGroup>;
  /** Column order, top to bottom. */
  order: [string[], string[], string[]];
  height: number;
}

export function layoutTripartite(items: TriItem[], links: TriLink[], o: TriOptions): TriLayout {
  const byKey = new Map(items.map(i => [i.key, i]));
  const live = links.filter(l => byKey.has(l.from) && byKey.has(l.to) && byKey.get(l.to)!.col === byKey.get(l.from)!.col + 1);
  const outOf = new Map<string, TriLink[]>(), into = new Map<string, TriLink[]>();
  for (const l of live) {
    if (!outOf.has(l.from)) outOf.set(l.from, []);
    if (!into.has(l.to)) into.set(l.to, []);
    outOf.get(l.from)!.push(l);
    into.get(l.to)!.push(l);
  }

  const given = new Map(items.map((it, i) => [it.key, i]));
  const col = (c: number): TriItem[] => items.filter(i => i.col === c);
  const rank = new Map<string, number>();
  const order: [string[], string[], string[]] = [[], [], []];
  order[0] = col(0).map(i => i.key);
  order[0].forEach((k, i) => rank.set(k, i));

  // Mean rank of the partners in the column to the left; an item with none sorts last.
  const baryCache = new Map<string, number>();
  const bary = (k: string): number => {
    let b = baryCache.get(k);
    if (b === undefined) {
      const ps = (into.get(k) ?? []).map(l => rank.get(l.from)).filter((x): x is number => x !== undefined);
      b = ps.length ? ps.reduce((x, y) => x + y, 0) / ps.length : Number.POSITIVE_INFINITY;
      baryCache.set(k, b);
    }
    return b;
  };
  const byBary = (a: TriItem, b: TriItem): number => {
    const ba = bary(a.key), bb = bary(b.key);
    if (ba !== bb) return ba < bb ? -1 : 1;
    return given.get(a.key)! - given.get(b.key)!;
  };

  order[1] = col(1).slice().sort(byBary).map(i => i.key);
  order[1].forEach((k, i) => rank.set(k, i));

  const c2 = col(2).slice().sort(byBary);
  // Groups keep their members together, ordered by the members' mean barycentre.
  const groupOrder: string[] = [];
  const members = new Map<string, TriItem[]>();
  for (const it of c2) {
    const g = it.group ?? `\u0000${it.key}`;
    if (!members.has(g)) { members.set(g, []); groupOrder.push(g); }
    members.get(g)!.push(it);
  }
  const groupBary = (g: string): number => {
    const bs = members.get(g)!.map(i => bary(i.key)).filter(Number.isFinite);
    return bs.length ? bs.reduce((a, b) => a + b, 0) / bs.length : Number.POSITIVE_INFINITY;
  };
  const firstSeen = new Map(groupOrder.map((g, i) => [g, i]));
  groupOrder.sort((a, b) => {
    const ba = groupBary(a), bb = groupBary(b);
    if (ba !== bb) return ba < bb ? -1 : 1;
    return firstSeen.get(a)! - firstSeen.get(b)!;
  });
  order[2] = groupOrder.flatMap(g => members.get(g)!.map(i => i.key));

  const pad = o.pad ?? [0, 0, 0];
  const heightOf = (k: string, c: number): number => {
    const fixed = o.fixedH?.[c];
    if (fixed !== null && fixed !== undefined) return fixed;
    const n = Math.max((outOf.get(k) ?? []).length, (into.get(k) ?? []).length);
    return Math.max(o.minH[c], n * o.pitch + pad[c]);
  };

  const slots = new Map<string, TriSlot>();
  const groups = new Map<string, TriGroup>();
  const colHeight = [0, 0, 0];
  for (const c of [0, 1, 2] as const) {
    let y = o.top;
    let lastGroup: string | null = null;
    for (const k of order[c]) {
      const it = byKey.get(k)!;
      if (c === 2 && it.group !== undefined && it.group !== lastGroup) {
        if (lastGroup !== null) y += o.groupGap ?? o.gap;
        groups.set(it.group, { key: it.group, y, h: 0 });
        y += o.groupHead ?? 0;
        lastGroup = it.group;
      }
      const h = heightOf(k, c);
      slots.set(k, { key: k, col: c, y, h, group: it.group });
      y += h + o.gap;
      if (c === 2 && it.group !== undefined) {
        const g = groups.get(it.group)!;
        g.h = y - o.gap - g.y;
      }
    }
    colHeight[c] = y - o.gap;
  }
  const height = Math.max(o.top, ...colHeight);
  // Centre the shorter columns against the tallest.
  for (const c of [0, 1, 2]) {
    const off = (height - colHeight[c]) / 2;
    if (off <= 0) continue;
    for (const k of order[c]) slots.get(k)!.y += off;
    if (c === 2) for (const g of groups.values()) g.y += off;
  }

  // Thread ends: inside each slot, sorted by where the partner sits.
  const ends = new Map<string, { y0: number; y1: number }>();
  for (const l of live) ends.set(l.key, { y0: 0, y1: 0 });
  const place = (k: string, list: TriLink[], side: 'out' | 'in'): void => {
    if (!list.length) return;
    const s = slots.get(k)!;
    const partner = (l: TriLink): number => { const p = slots.get(side === 'out' ? l.to : l.from)!; return p.y + p.h / 2; };
    const sorted = list.slice().sort((a, b) => partner(a) - partner(b) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    const pitch = Math.min(o.pitch, Math.max(0.5, (s.h - 2) / sorted.length));
    const y0 = s.y + (s.h - sorted.length * pitch) / 2 + pitch / 2;
    sorted.forEach((l, i) => { const e = ends.get(l.key)!; if (side === 'out') e.y0 = y0 + i * pitch; else e.y1 = y0 + i * pitch; });
  };
  for (const k of [...order[0], ...order[1], ...order[2]]) {
    place(k, outOf.get(k) ?? [], 'out');
    place(k, into.get(k) ?? [], 'in');
  }

  return { slots, ends, groups, order, height };
}

/** A horizontal S-curve from (xa, ya) to (xb, yb). */
export function sCurve(xa: number, ya: number, xb: number, yb: number): string {
  const m = (xb - xa) * 0.5;
  const f = (n: number): string => String(Math.round(n * 10) / 10);
  return `M${f(xa)} ${f(ya)}C${f(xa + m)} ${f(ya)} ${f(xb - m)} ${f(yb)} ${f(xb)} ${f(yb)}`;
}

/**
 * Names in a gutter, placed greedily: highest priority first, each at least
 * `minGap` px from every name already placed. Returns the keys placed; the
 * rest are folded (still on hover, and counted in the plot's footer).
 */
export function placeNames<T extends { key: string; y: number; priority: number }>(cands: T[], minGap: number): Set<string> {
  const placed: number[] = [];
  const out = new Set<string>();
  for (const c of cands.slice().sort((a, b) => b.priority - a.priority || a.y - b.y)) {
    if (placed.some(p => Math.abs(p - c.y) < minGap)) continue;
    placed.push(c.y);
    out.add(c.key);
  }
  return out;
}
