/**
 * GuardLink agent config — the TOML that Codex's `.codex/config.toml` and
 * Gemini's `.gemini/commands/*.toml` are written in, read with the line of
 * every key.
 *
 * GuardLink takes no TOML dependency for two files, so this reads the subset
 * those files use: `[table]` and `[[array-of-tables]]` headers, dotted and
 * quoted keys, basic and literal strings (single- and multi-line), integers,
 * floats, booleans, arrays and inline tables. Dates are kept as strings. A
 * construct outside that subset throws, and the caller reports the file as
 * unreadable rather than guessing at it.
 *
 * Lines are keyed by the same RFC 6901 pointer `jsonc.ts` uses, so a reader
 * cites a Codex key exactly as it cites a JSON one.
 *
 * @comment -- "Pure function over a string; no I/O. Nesting of arrays and inline tables is bounded by MAX_DEPTH"
 */
import { pointerToken, type JsonValue, type JsoncDocument } from './jsonc.js';

export class TomlError extends Error {
  constructor(message: string, public readonly line: number) {
    super(`${message} (line ${line})`);
    this.name = 'TomlError';
  }
}

const MAX_DEPTH = 64;
type Obj = { [k: string]: JsonValue };

export function parseToml(text: string): JsoncDocument {
  const root: Obj = {};
  const lines = new Map<string, number>([['', 1]]);
  let i = 0;
  let line = 1;
  const n = text.length;
  let current: Obj = root;
  let currentPtr = '';

  const fail = (msg: string): never => { throw new TomlError(msg, line); };

  const skipWs = () => { while (i < n && (text[i] === ' ' || text[i] === '\t')) i++; };
  const skipComment = () => { if (text[i] === '#') while (i < n && text[i] !== '\n') i++; };
  const skipBlank = () => {
    for (;;) {
      skipWs();
      skipComment();
      if (text[i] === '\r' && text[i + 1] === '\n') i++;
      if (text[i] === '\n') { i++; line++; continue; }
      return;
    }
  };
  const endOfLine = () => {
    skipWs();
    skipComment();
    if (text[i] === '\r') i++;
    if (i < n && text[i] !== '\n') fail('expected end of line');
  };

  const basic = (): string => {
    if (text.startsWith('"""', i)) {
      i += 3;
      if (text[i] === '\n') { i++; line++; }
      let out = '';
      while (i < n && !text.startsWith('"""', i)) {
        if (text[i] === '\\') {
          // Line-ending backslash trims the newline and the whitespace after it.
          if (/^\\[ \t]*\r?\n/.test(text.slice(i, i + 64))) {
            i++;
            while (i < n && /[ \t\r\n]/.test(text[i])) { if (text[i] === '\n') line++; i++; }
            continue;
          }
          out += escape();
          continue;
        }
        if (text[i] === '\n') line++;
        out += text[i++];
      }
      if (i >= n) fail('unterminated multi-line string');
      i += 3;
      return out;
    }
    i++;
    let out = '';
    while (i < n && text[i] !== '"') {
      if (text[i] === '\n') fail('unterminated string');
      if (text[i] === '\\') { out += escape(); continue; }
      out += text[i++];
    }
    if (i >= n) fail('unterminated string');
    i++;
    return out;
  };

  const escape = (): string => {
    const e = text[i + 1];
    i += 2;
    switch (e) {
      case 'b': return '\b';
      case 't': return '\t';
      case 'n': return '\n';
      case 'f': return '\f';
      case 'r': return '\r';
      case '"': return '"';
      case '\\': return '\\';
      case 'u': case 'U': {
        const len = e === 'u' ? 4 : 8;
        const hex = text.slice(i, i + len);
        if (!new RegExp(`^[0-9a-fA-F]{${len}}$`).test(hex)) fail('bad unicode escape');
        i += len;
        return String.fromCodePoint(parseInt(hex, 16));
      }
      default: return fail(`bad escape \\${e ?? ''}`);
    }
  };

  const literal = (): string => {
    if (text.startsWith("'''", i)) {
      i += 3;
      if (text[i] === '\n') { i++; line++; }
      const end = text.indexOf("'''", i);
      if (end < 0) fail('unterminated multi-line literal string');
      const out = text.slice(i, end);
      for (const ch of out) if (ch === '\n') line++;
      i = end + 3;
      return out;
    }
    i++;
    const end = text.indexOf("'", i);
    const nl = text.indexOf('\n', i);
    if (end < 0 || (nl >= 0 && nl < end)) fail('unterminated literal string');
    const out = text.slice(i, end);
    i = end + 1;
    return out;
  };

  const key = (): string[] => {
    const parts: string[] = [];
    for (;;) {
      skipWs();
      if (text[i] === '"') parts.push(basic());
      else if (text[i] === "'") parts.push(literal());
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 256));
        if (!m) fail('expected a key');
        parts.push(m![0]);
        i += m![0].length;
      }
      skipWs();
      if (text[i] === '.') { i++; continue; }
      return parts;
    }
  };

  const value = (ptr: string, depth: number): JsonValue => {
    if (depth > MAX_DEPTH) fail('nesting too deep');
    lines.set(ptr, line);
    const c = text[i];
    if (c === '"') return basic();
    if (c === "'") return literal();
    if (c === '[') {
      i++;
      const arr: JsonValue[] = [];
      for (;;) {
        skipBlank();
        if (text[i] === ']') { i++; return arr; }
        arr.push(value(`${ptr}/${arr.length}`, depth + 1));
        skipBlank();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return arr; }
        fail('expected "," or "]"');
      }
    }
    if (c === '{') {
      i++;
      const obj: Obj = {};
      skipWs();
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        const k = key();
        if (text[i] !== '=') fail('expected "="');
        i++;
        skipWs();
        assign(obj, ptr, k, depth + 1);
        skipWs();
        if (text[i] === ',') { i++; skipWs(); continue; }
        if (text[i] === '}') { i++; return obj; }
        fail('expected "," or "}"');
      }
    }
    const m = /^(?:true|false|[+-]?(?:inf|nan)|[0-9TZ:.+_eE-]+)/.exec(text.slice(i, i + 64));
    if (!m) fail(`unexpected character ${JSON.stringify(c ?? '')}`);
    const tok = m![0];
    i += tok.length;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    const num = tok.replaceAll('_', '');
    if (/^[+-]?(\d+|0x[0-9a-fA-F]+)$/.test(num) || /^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(num)) return Number(num);
    return tok;   // a date, time or special float: kept as written
  };

  /** Set dotted key `k` under `obj` (whose pointer is `ptr`), reading the value at the cursor. */
  const assign = (obj: Obj, ptr: string, k: string[], depth: number) => {
    let target = obj;
    let p = ptr;
    for (const part of k.slice(0, -1)) {
      p = `${p}/${pointerToken(part)}`;
      const next = target[part];
      if (next === undefined) {
        const t: Obj = {};
        target[part] = t;
        if (!lines.has(p)) lines.set(p, line);
        target = t;
      } else if (next && typeof next === 'object' && !Array.isArray(next)) {
        target = next as Obj;
      } else {
        fail(`key ${k.join('.')} redefines a value`);
      }
    }
    const last = k[k.length - 1];
    target[last] = value(`${p}/${pointerToken(last)}`, depth);
  };

  /** Walk (creating) to the table named by a header; `array` appends a new element. */
  const table = (k: string[], array: boolean): void => {
    let target = root;
    let p = '';
    for (let j = 0; j < k.length; j++) {
      const part = k[j];
      p = `${p}/${pointerToken(part)}`;
      const isLast = j === k.length - 1;
      let next = target[part];
      if (isLast && array) {
        if (next === undefined) { next = []; target[part] = next; lines.set(p, line); }
        if (!Array.isArray(next)) fail(`${k.join('.')} is not an array of tables`);
        const t: Obj = {};
        const arr = next as JsonValue[];
        p = `${p}/${arr.length}`;
        arr.push(t);
        lines.set(p, line);
        target = t;
        break;
      }
      if (next === undefined) {
        next = {};
        target[part] = next;
        lines.set(p, line);
      } else if (Array.isArray(next)) {
        // [a.b] after [[a]] addresses the last element of a.
        p = `${p}/${next.length - 1}`;
        next = next[next.length - 1];
      }
      if (!next || typeof next !== 'object' || Array.isArray(next)) fail(`${k.join('.')} redefines a value`);
      target = next as Obj;
    }
    current = target;
    currentPtr = p;
  };

  for (;;) {
    skipBlank();
    if (i >= n) break;
    if (text[i] === '[') {
      const array = text[i + 1] === '[';
      i += array ? 2 : 1;
      const k = key();
      if (text[i] !== ']' || (array && text[i + 1] !== ']')) fail('unterminated table header');
      i += array ? 2 : 1;
      table(k, array);
      endOfLine();
      continue;
    }
    const k = key();
    if (text[i] !== '=') fail('expected "="');
    i++;
    skipWs();
    assign(current, currentPtr, k, 1);
    endOfLine();
  }
  return { value: root, lines };
}
