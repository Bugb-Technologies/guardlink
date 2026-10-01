/**
 * Bulk export. Nothing in this file declares a flow into #store, so the only
 * chain into it lives elsewhere: an exposure here has no attributed chain.
 */

/**
 * @exposes #store to #dos [medium] cwe:CWE-400 -- "Export reads the whole table into memory"
 */
export function exportAll(): string[] {
  return [];
}
