/**
 * GuardLink agent config — JSON with comments, read with the line of every value.
 *
 * Coding-agent configuration is JSON in name only: VS Code's `settings.json`
 * and `mcp.json`, Cursor's and Gemini's files all accept `//` and `/* *\/`
 * comments and trailing commas. A reach fact must point at the line that
 * grants it (`.claude/settings.json:15`, not "somewhere in the file"), so this
 * parser records, for every value, the line it starts on under its RFC 6901
 * JSON pointer. Searching the text for the value afterwards, which is what a
 * plain `JSON.parse` would force, picks the wrong line whenever the same rule
 * appears twice.
 *
 * @comment -- "Pure function over a string; recursion depth is bounded by MAX_DEPTH so a hostile file cannot exhaust the stack"
 */

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

export interface JsoncDocument {
  value: JsonValue;
  /** 1-based line each value starts on, by JSON pointer (`""` is the root). */
  lines: Map<string, number>;
}

export class JsoncError extends Error {
  constructor(message: string, public readonly line: number) {
    super(`${message} (line ${line})`);
    this.name = 'JsoncError';
  }
}

const MAX_DEPTH = 256;

/** RFC 6901 escaping of one reference token. */
export function pointerToken(key: string): string {
  return key.replaceAll('~', '~0').replaceAll('/', '~1');
}

export function parseJsonc(text: string): JsoncDocument {
  let i = 0;
  let line = 1;
  const lines = new Map<string, number>();
  const n = text.length;

  const fail = (msg: string): never => { throw new JsoncError(msg, line); };

  const skip = (): void => {
    while (i < n) {
      const c = text[i];
      if (c === '\n') { line++; i++; continue; }
      if (c === ' ' || c === '\t' || c === '\r' || c === '﻿') { i++; continue; }
      if (c === '/' && text[i + 1] === '/') {
        while (i < n && text[i] !== '\n') i++;
        continue;
      }
      if (c === '/' && text[i + 1] === '*') {
        const end = text.indexOf('*/', i + 2);
        const stop = end < 0 ? n : end + 2;
        for (let j = i; j < stop; j++) if (text[j] === '\n') line++;
        i = stop;
        continue;
      }
      break;
    }
  };

  const str = (): string => {
    // text[i] === '"'
    let out = '';
    i++;
    while (i < n) {
      const c = text[i];
      if (c === '"') { i++; return out; }
      if (c === '\n') fail('unterminated string');
      if (c === '\\') {
        const e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('bad \\u escape');
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default: fail(`bad escape \\${e ?? ''}`);
        }
        continue;
      }
      out += c;
      i++;
    }
    return fail('unterminated string');
  };

  const value = (ptr: string, depth: number): JsonValue => {
    if (depth > MAX_DEPTH) fail('nesting too deep');
    skip();
    if (i >= n) fail('unexpected end of input');
    lines.set(ptr, line);
    const c = text[i];
    if (c === '{') {
      i++;
      const obj: { [k: string]: JsonValue } = {};
      skip();
      while (text[i] !== '}') {
        if (i >= n) fail('unterminated object');
        if (text[i] !== '"') fail('expected a property name');
        const key = str();
        skip();
        if (text[i] !== ':') fail('expected ":"');
        i++;
        // A duplicate key keeps the last value, as JSON.parse does; its line follows.
        obj[key] = value(`${ptr}/${pointerToken(key)}`, depth + 1);
        skip();
        if (text[i] === ',') { i++; skip(); continue; }
        if (text[i] !== '}') fail('expected "," or "}"');
      }
      i++;
      return obj;
    }
    if (c === '[') {
      i++;
      const arr: JsonValue[] = [];
      skip();
      while (text[i] !== ']') {
        if (i >= n) fail('unterminated array');
        arr.push(value(`${ptr}/${arr.length}`, depth + 1));
        skip();
        if (text[i] === ',') { i++; skip(); continue; }
        if (text[i] !== ']') fail('expected "," or "]"');
      }
      i++;
      return arr;
    }
    if (c === '"') return str();
    const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i, i + 64));
    if (!m) fail(`unexpected character ${JSON.stringify(c)}`);
    i += m![0].length;
    const tok = m![0];
    return tok === 'true' ? true : tok === 'false' ? false : tok === 'null' ? null : Number(tok);
  };

  const root = value('', 0);
  skip();
  if (i < n) fail('unexpected content after the value');
  return { value: root, lines };
}

/** A plain object, or null for anything else (arrays included). */
export function asObject(v: JsonValue | undefined): { [k: string]: JsonValue } | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null;
}

export function asArray(v: JsonValue | undefined): JsonValue[] {
  return Array.isArray(v) ? v : [];
}

export function asString(v: JsonValue | undefined): string | null {
  return typeof v === 'string' ? v : null;
}
