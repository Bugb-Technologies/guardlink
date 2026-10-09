/**
 * GuardLink Dashboard — text metrics and SVG string helpers for the diagram
 * modules.
 *
 * Every diagram is laid out from data and ESTIMATED glyph widths, never by
 * measuring the DOM. A panel that is hidden, zero-sized or not yet attached —
 * a background editor tab, a collapsed tab, a page printed to PDF — lays out
 * exactly as a visible one does, so no coordinate can come out NaN.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "xml() encodes &, <, > and both quotes for every text node and attribute the diagram modules emit"
 * @comment -- "Pure string helpers; nothing here reads a document"
 */

/** Average advance per character, as a fraction of the font size. Conservative: names are placed with room to spare. */
const MONO_ADVANCE = 0.62;
const SANS_ADVANCE = 0.56;

export function textWidth(s: string, px: number, mono = true): number {
  return [...s].length * px * (mono ? MONO_ADVANCE : SANS_ADVANCE);
}

/** Cut from the left so the end of a path or id — the part a reader scans for — survives: `…/agents/config.ts`. */
export function cutLeft(s: string, max: number): string {
  const chars = [...s];
  if (chars.length <= max) return s;
  return `…${chars.slice(chars.length - Math.max(1, max - 1)).join('')}`;
}

/** As many characters as fit in `width` px at `px`, cut from the left. */
export function fitLeft(s: string, width: number, px: number, mono = true): string {
  const per = px * (mono ? MONO_ADVANCE : SANS_ADVANCE);
  return cutLeft(s, Math.max(2, Math.floor(width / per)));
}

export function xml(s: unknown): string {
  return (s === null || s === undefined ? '' : String(s))
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** Round to 0.1 px so the emitted markup is short and byte-stable. */
export const r1 = (n: number): string => {
  const v = Math.round(n * 10) / 10;
  return Object.is(v, -0) ? '0' : String(v);
};

/** Attributes from a record; undefined, null and false are dropped. Values are escaped. */
export function attrs(a: Record<string, string | number | boolean | null | undefined>): string {
  let out = '';
  for (const [k, v] of Object.entries(a)) {
    if (v === undefined || v === null || v === false) continue;
    out += v === true ? ` ${k}` : ` ${k}="${xml(typeof v === 'number' ? r1(v) : v)}"`;
  }
  return out;
}

/**
 * The shared tooltip's payload: a title and label/value rows, carried as
 * attributes the client reads with getAttribute and writes with textContent.
 * Rows are tab-separated label/value pairs, one per line.
 */
export function tip(title: string, rows: [string, string | number][] = []): Record<string, string> {
  const out: Record<string, string> = { 'data-tip': title };
  if (rows.length) out['data-tip-rows'] = rows.map(([k, v]) => `${k.replace(/[\t\n]/g, ' ')}\t${String(v).replace(/[\t\n]/g, ' ')}`).join('\n');
  return out;
}

/** A dotted ground behind a plot: a 16 px lattice, dots never over a mark (marks paint above it). */
export function dotPattern(id: string): string {
  return `<pattern id="${xml(id)}" width="16" height="16" patternUnits="userSpaceOnUse"><rect x="7.25" y="7.25" width="1.5" height="1.5" class="dot"/></pattern>`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
