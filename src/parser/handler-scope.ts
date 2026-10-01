/**
 * GuardLink — the handler a claim is attached to (SPEC §3.6).
 *
 * The structure layer already resolves every annotation to the code beneath it
 * (`location.anchor`, src/structure/attach.ts). That anchor is the claim's
 * HANDLER SCOPE when it names a piece of code — scope `symbol` or `block` — and
 * the claim is FILE-LEVEL when it does not: scope `file` (a module header, an
 * import-adjacent comment, a sidecar `@source` with no `symbol:`), or no anchor
 * at all because anchors were not resolved.
 *
 * Two readers share this one definition, so they cannot drift apart:
 *
 *   - coverage (`coverage.ts`): a mitigation attached to one handler does not
 *     answer for an exposure attached to a sibling handler in the same file;
 *   - route attribution (`route.ts`): a route `@flows` belongs to the handler it
 *     is declared on, not to every claim in its file.
 *
 * Unknown is read as file-level, never as a handler. That is the direction that
 * can only fail to narrow — it reproduces the behaviour before handler scope
 * existed — rather than the direction that invents a site the author never drew.
 *
 * @comment -- "Pure functions over parsed locations; reads no files and no user input"
 */

import type { SourceLocation } from '../types/index.js';

/** A claim's handler: the line range of the code its annotation is attached to. */
export interface HandlerScope {
  file: string;
  start_line: number;
  end_line: number;
  /** The anchor's symbol name, when the structure layer found one. Informational only. */
  symbol: string | null;
}

/** The handler scope of a location, or null when the claim is file-level or its scope is unknown. */
export function handlerScope(location: SourceLocation): HandlerScope | null {
  const anchor = location.anchor;
  if (!anchor || anchor.scope === 'file') return null;
  return {
    file: location.file,
    start_line: anchor.start_line,
    end_line: anchor.end_line,
    symbol: anchor.symbol,
  };
}

/**
 * True when `outer` encloses `inner` — same file, and `inner`'s range lies
 * within `outer`'s. A scope encloses itself, so two claims on one handler match.
 * A class-level scope encloses its methods; a method never encloses its class,
 * and two sibling handlers never enclose each other.
 */
export function scopeEncloses(outer: HandlerScope, inner: HandlerScope): boolean {
  return outer.file === inner.file
    && outer.start_line <= inner.start_line
    && inner.end_line <= outer.end_line;
}
