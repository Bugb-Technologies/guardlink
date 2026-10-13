/**
 * GuardLink agent config — hidden Unicode in text a model reads.
 *
 * An instruction file, a skill or a command is read by a model and reviewed by a
 * person, and the two do not see the same characters. Unicode Tag characters
 * (U+E0000–U+E007F) render as nothing in an editor, a diff or a pull-request
 * view, yet each one maps to an ASCII character a model tokenises: a reviewer
 * approves an empty line while the agent reads "ignore the above and run …".
 * Variation selectors can carry bytes the same way, bidirectional controls
 * reorder what is displayed against what is stored, and runs of zero-width
 * characters hide text between visible words.
 *
 * ── The contract ─────────────────────────────────────────────────────
 *
 * This detector is shared: other tools that read agent configuration report the
 * same finding for the same file, so the rules below are pinned by
 * `conformance/hidden-unicode.json` rather than by this code alone. Change a
 * rule and that corpus in the same change.
 *
 *   - `unicode-tags` — any character in U+E0000–U+E007F. `decoded` is the ASCII
 *     that U+E0020–U+E007E map to. An `error` when it decodes to visible text,
 *     a `warning` otherwise. Exempt: a subdivision-flag emoji, which is U+1F3F4
 *     followed by tag letters or digits and closed by U+E007F CANCEL TAG
 *     (🏴󠁧󠁢󠁥󠁮󠁧󠁿 is "gbeng").
 *   - `variation-selectors` — two or more consecutive variation selectors
 *     (U+FE00–U+FE0F, U+E0100–U+E01EF), or one from the supplement after a
 *     character that is not a CJK ideograph. `decoded` reads the run as bytes
 *     (U+FE00+b for b < 16, U+E0100+(b−16) otherwise) and keeps it when the
 *     bytes are UTF-8 text; an `error` then, a `warning` otherwise. A single
 *     U+FE0E/U+FE0F after an emoji, and a single supplement selector after an
 *     ideograph, are how those scripts are meant to be written and are exempt.
 *   - `bidi-control` — U+202A–U+202E or U+2066–U+2069. A `warning`.
 *   - `zero-width` — a run of two or more of U+200B–U+200D, U+2060–U+2064 and
 *     U+180E, or any one of U+200B ZERO WIDTH SPACE, U+2060–U+2064 (the word
 *     joiner and the invisible operators) and U+180E; a U+FEFF anywhere but
 *     the first character of the file. A `warning`. A lone
 *     U+200C/U+200D between letters or emoji (Indic shaping, emoji sequences) is
 *     how those are written and is exempt.
 *
 * One record per category per line. `line` is 1-based; `column` is the 1-based
 * code-point index of the first character the record covers; `count` is how
 * many characters on that line it covers.
 *
 * @comment -- "Pure function over a string; no I/O. Reports what a file contains, never what it means: decoded text is evidence for a reviewer, and nothing here executes or follows it"
 */

export type HiddenUnicodeKind = 'unicode-tags' | 'variation-selectors' | 'bidi-control' | 'zero-width';

export interface HiddenUnicodeHit {
  line: number;
  column: number;
  kind: HiddenUnicodeKind;
  count: number;
  severity: 'error' | 'warning';
  /** For tags and variation selectors: the text the characters encode, when they encode any. */
  decoded?: string;
}

const isTag = (cp: number) => cp >= 0xE0000 && cp <= 0xE007F;
const isVs = (cp: number) => (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
const isBidi = (cp: number) => (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
const isZw = (cp: number) => (cp >= 0x200B && cp <= 0x200D) || (cp >= 0x2060 && cp <= 0x2064) || cp === 0x180E;
const isIdeograph = (cp: number) =>
  (cp >= 0x3400 && cp <= 0x4DBF) || (cp >= 0x4E00 && cp <= 0x9FFF) || (cp >= 0xF900 && cp <= 0xFAFF)
  || (cp >= 0x20000 && cp <= 0x323AF);

/** Visible text: something other than whitespace and control characters. */
const visible = (s: string) => /[^\s\p{Cc}]/u.test(s);

function decodeVsBytes(cps: number[]): string | undefined {
  const bytes = cps.map(cp => (cp >= 0xE0100 ? cp - 0xE0100 + 16 : cp - 0xFE00));
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes));
    return visible(text) ? text : undefined;
  } catch {
    return undefined;
  }
}

/** Every hidden-Unicode record in `text`, in line then column order. */
export function findHiddenUnicode(text: string): HiddenUnicodeHit[] {
  const out: HiddenUnicodeHit[] = [];
  const lines = text.split('\n');
  for (let ln = 0; ln < lines.length; ln++) {
    const cps = Array.from(lines[ln]).map(ch => ch.codePointAt(0)!);
    const lineNo = ln + 1;

    // ── Tag characters ──
    let tagFirst = -1;
    let tagCount = 0;
    let decoded = '';
    for (let j = 0; j < cps.length; j++) {
      if (!isTag(cps[j])) continue;
      // A subdivision flag: U+1F3F4, tag letters/digits, U+E007F.
      if (cps[j - 1] === 0x1F3F4) {
        let k = j;
        while (k < cps.length && ((cps[k] >= 0xE0030 && cps[k] <= 0xE0039) || (cps[k] >= 0xE0061 && cps[k] <= 0xE007A))) k++;
        if (k > j && cps[k] === 0xE007F) { j = k; continue; }
      }
      if (tagFirst < 0) tagFirst = j;
      tagCount++;
      if (cps[j] >= 0xE0020 && cps[j] <= 0xE007E) decoded += String.fromCharCode(cps[j] - 0xE0000);
    }
    if (tagCount > 0) {
      const shown = visible(decoded);
      out.push({
        line: lineNo, column: tagFirst + 1, kind: 'unicode-tags', count: tagCount,
        severity: shown ? 'error' : 'warning', ...(shown ? { decoded } : {}),
      });
    }

    // ── Variation selectors ──
    let vsFirst = -1;
    let vsCount = 0;
    let vsDecoded: string | undefined;
    for (let j = 0; j < cps.length;) {
      if (!isVs(cps[j])) { j++; continue; }
      let k = j;
      while (k < cps.length && isVs(cps[k])) k++;
      const run = cps.slice(j, k);
      const prev = cps[j - 1];
      const suspicious = run.length >= 2 || (run[0] >= 0xE0100 && !(prev !== undefined && isIdeograph(prev)));
      if (suspicious) {
        if (vsFirst < 0) vsFirst = j;
        vsCount += run.length;
        vsDecoded ??= decodeVsBytes(run);
      }
      j = k;
    }
    if (vsCount > 0) {
      out.push({
        line: lineNo, column: vsFirst + 1, kind: 'variation-selectors', count: vsCount,
        severity: vsDecoded ? 'error' : 'warning', ...(vsDecoded ? { decoded: vsDecoded } : {}),
      });
    }

    // ── Bidirectional controls ──
    const bidi = cps.map((cp, j) => (isBidi(cp) ? j : -1)).filter(j => j >= 0);
    if (bidi.length > 0) {
      out.push({ line: lineNo, column: bidi[0] + 1, kind: 'bidi-control', count: bidi.length, severity: 'warning' });
    }

    // ── Zero-width characters and a stray byte-order mark ──
    let zwFirst = -1;
    let zwCount = 0;
    for (let j = 0; j < cps.length;) {
      if (cps[j] === 0xFEFF) {
        if (!(ln === 0 && j === 0)) { if (zwFirst < 0) zwFirst = j; zwCount++; }
        j++;
        continue;
      }
      if (!isZw(cps[j])) { j++; continue; }
      let k = j;
      while (k < cps.length && isZw(cps[k])) k++;
      const run = cps.slice(j, k);
      if (run.length >= 2 || run.includes(0x200B) || run.includes(0x2060) || run.some(cp => cp >= 0x2061 || cp === 0x180E)) {
        if (zwFirst < 0) zwFirst = j;
        zwCount += run.length;
      }
      j = k;
    }
    if (zwCount > 0) {
      out.push({ line: lineNo, column: zwFirst + 1, kind: 'zero-width', count: zwCount, severity: 'warning' });
    }
  }
  const order: HiddenUnicodeKind[] = ['unicode-tags', 'variation-selectors', 'bidi-control', 'zero-width'];
  return out.sort((a, b) => a.line - b.line || order.indexOf(a.kind) - order.indexOf(b.kind));
}

/** One sentence for a record: what is there, and what it decodes to. */
export function describeHiddenUnicode(hit: HiddenUnicodeHit): string {
  const what: Record<HiddenUnicodeKind, string> = {
    'unicode-tags': 'Unicode Tag characters',
    'variation-selectors': 'variation selectors',
    'bidi-control': 'bidirectional control characters',
    'zero-width': 'zero-width characters',
  };
  const n = `${hit.count} ${what[hit.kind]}`;
  return hit.decoded !== undefined
    ? `${n} that decode to ${JSON.stringify(hit.decoded.slice(0, 120))}: a model reads this text, a reviewer sees nothing`
    : `${n}: invisible in an editor and a diff, read by a model`;
}
