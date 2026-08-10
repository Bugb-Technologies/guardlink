/**
 * GuardLink — `@source` drift detection (GL-505).
 *
 * This is the maintenance burden external mode *creates*, and the strongest
 * argument against making it the default. An inline annotation moves with the
 * code it describes because it is inside it; an externalised one records
 * `file:line` and rots the moment anything above that line changes. Nothing
 * detects that today, so a `.gal` can point confidently at the wrong function.
 *
 * `parent_symbol` has been captured at parse time since long before this epic
 * and read nowhere. GL-201 became its first consumer; this is the one that
 * justifies recording it.
 *
 * Reports, never repairs. A proposed line is a suggestion for a human or an
 * agent to accept — silently rewriting an anchor would move an annotation onto
 * code nobody chose for it, which is the same failure as the drift, arrived at
 * faster.
 *
 * @exposes #parser to #path-traversal [low] cwe:CWE-22 -- "Reads source files named by @source blocks"
 * @mitigates #parser against #path-traversal using #path-validation -- "Paths are joined to root and skipped when missing; nothing outside the model is read"
 * @flows ThreatModel -> #parser via findAnchorDrift -- "Recorded anchors compared against current source"
 * @comment -- "Symbol matching is deliberately loose: it looks for the name as a whole word, not for a specific declaration syntax, so it works across languages"
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ThreatModel, SourceLocation } from '../types/index.js';

export interface AnchorDrift {
  /** The sidecar carrying the block. */
  gal_file: string;
  /** Source file the block points at. */
  file: string;
  /** Line the block currently records. */
  recorded_line: number;
  symbol: string;
  /**
   * Why the anchor is wrong.
   *   moved        — the symbol is elsewhere in the file
   *   symbol_gone  — the symbol is not in the file at all
   *   file_gone    — the file no longer exists
   *   line_gone    — the file is shorter than the recorded line
   */
  kind: 'moved' | 'symbol_gone' | 'file_gone' | 'line_gone';
  /** Where the symbol was found instead. Present only for 'moved'. */
  suggested_line?: number;
  /** All lines where the symbol appears, when there is more than one candidate. */
  candidates?: number[];
  message: string;
}

/** Match the symbol as a whole word — no language-specific declaration syntax. */
function symbolLines(lines: string[], symbol: string): number[] {
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(^|[^\\w$])${escaped}([^\\w$]|$)`);
  const found: number[] = [];
  for (const [i, text] of lines.entries()) {
    if (pattern.test(text)) found.push(i + 1);
  }
  return found;
}

/** Every distinct anchored `@source` block in the model. */
function anchoredBlocks(model: ThreatModel): SourceLocation[] {
  const rows = [
    ...model.assets, ...model.threats, ...model.controls,
    ...model.mitigations, ...model.exposures, ...(model.confirmed || []),
    ...model.acceptances, ...model.transfers, ...model.flows,
    ...model.boundaries, ...model.validations, ...model.audits,
    ...model.ownership, ...model.data_handling, ...model.assumptions,
    ...(model.actors || []), ...(model.entitlements || []),
    ...model.shields, ...model.features, ...model.comments,
  ];
  const seen = new Map<string, SourceLocation>();
  for (const { location } of rows) {
    if (!location.origin_file || !location.parent_symbol) continue;
    const key = `${location.origin_file}::${location.file}::${location.line}::${location.parent_symbol}`;
    if (!seen.has(key)) seen.set(key, location);
  }
  return [...seen.values()].sort((a, b) =>
    a.origin_file!.localeCompare(b.origin_file!) || a.line - b.line);
}

/**
 * Find `@source` blocks whose recorded `file:line` no longer holds the symbol
 * they name.
 *
 * A block with no `symbol:` is skipped rather than guessed at — there is nothing
 * to compare against, and inventing a check would produce noise, which is how a
 * drift report stops being read.
 */
export function findAnchorDrift(root: string, model: ThreatModel): AnchorDrift[] {
  const cache = new Map<string, string[] | null>();
  const readLines = (file: string): string[] | null => {
    if (!cache.has(file)) {
      const abs = join(root, file);
      cache.set(file, existsSync(abs) ? readFileSync(abs, 'utf-8').split('\n') : null);
    }
    return cache.get(file)!;
  };

  const drifts: AnchorDrift[] = [];

  for (const location of anchoredBlocks(model)) {
    const file = location.file;
    const symbol = location.parent_symbol!;
    const recorded = location.line;
    const gal = location.origin_file!;
    const lines = readLines(file);

    if (lines === null) {
      drifts.push({
        gal_file: gal, file, recorded_line: recorded, symbol, kind: 'file_gone',
        message: `\`${gal}\` anchors to \`${file}:${recorded}\`, but that file no longer exists. `
          + 'Either the file moved and the block should follow it, or the annotations are obsolete.',
      });
      continue;
    }

    const at = lines[recorded - 1];
    if (at === undefined) {
      drifts.push({
        gal_file: gal, file, recorded_line: recorded, symbol, kind: 'line_gone',
        message: `\`${gal}\` anchors to \`${file}:${recorded}\`, but that file is only ${lines.length} lines long.`,
      });
      continue;
    }

    const found = symbolLines(lines, symbol);
    if (found.includes(recorded)) continue;   // still correct

    if (found.length === 0) {
      drifts.push({
        gal_file: gal, file, recorded_line: recorded, symbol, kind: 'symbol_gone',
        message: `\`${gal}\` anchors to \`${symbol}\` at \`${file}:${recorded}\`, but \`${symbol}\` no longer `
          + 'appears in that file. It was probably renamed or removed — the annotations may need rewriting, not just re-anchoring.',
      });
      continue;
    }

    // Nearest occurrence to the recorded line is the most likely target after an
    // edit above it; the rest are offered rather than hidden.
    const nearest = found.reduce((best, l) =>
      Math.abs(l - recorded) < Math.abs(best - recorded) ? l : best, found[0]);

    drifts.push({
      gal_file: gal, file, recorded_line: recorded, symbol, kind: 'moved',
      suggested_line: nearest,
      ...(found.length > 1 ? { candidates: found } : {}),
      message: `\`${gal}\` anchors to \`${symbol}\` at \`${file}:${recorded}\`, but \`${symbol}\` is now at `
        + `line ${nearest}${found.length > 1 ? ` (also ${found.filter(l => l !== nearest).join(', ')})` : ''}.`,
    });
  }

  return drifts;
}

/**
 * Rewrite `@source` lines to their suggested positions.
 *
 * Only ever called after an explicit confirmation. Blocks whose symbol vanished
 * are left alone: there is no correct line to move them to, and picking one
 * would fabricate an anchor.
 */
export function applyReanchor(root: string, drifts: AnchorDrift[], dryRun = false): {
  updated: string[];
  skipped: AnchorDrift[];
} {
  const movable = drifts.filter(d => d.kind === 'moved' && d.suggested_line !== undefined);
  const skipped = drifts.filter(d => !(d.kind === 'moved' && d.suggested_line !== undefined));

  const byGal = new Map<string, AnchorDrift[]>();
  for (const d of movable) {
    if (!byGal.has(d.gal_file)) byGal.set(d.gal_file, []);
    byGal.get(d.gal_file)!.push(d);
  }

  const updated: string[] = [];
  for (const [gal, items] of byGal) {
    const abs = join(root, gal);
    if (!existsSync(abs)) { continue; }
    const lines = readFileSync(abs, 'utf-8').split('\n');
    let changed = false;

    for (const d of items) {
      for (const [i, text] of lines.entries()) {
        if (!text.trim().startsWith('@source')) continue;
        if (!text.includes(`file:${d.file}`) || !text.includes(`line:${d.recorded_line}`)) continue;
        if (!text.includes(`symbol:${d.symbol}`)) continue;
        lines[i] = text.replace(`line:${d.recorded_line}`, `line:${d.suggested_line}`);
        changed = true;
        break;
      }
    }

    if (changed) {
      if (!dryRun) writeFileSync(abs, lines.join('\n'));
      updated.push(gal);
    }
  }

  return { updated, skipped };
}

