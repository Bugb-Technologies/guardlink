/**
 * GuardLink TUI — Terminal formatting utilities.
 * Color badges, tables, code blocks, and risk grades.
 */

import chalk from 'chalk';
import { readFileSync } from 'node:fs';
import { resolve, isAbsolute } from 'node:path';

// ─── Color tokens (Bravos dark theme) ────────────────────────────────

export const C = {
  // Severity
  critical: chalk.bgRed.white.bold,
  high:     chalk.bgYellow.black.bold,
  medium:   chalk.yellow,
  low:      chalk.blue,
  unset:    chalk.gray,

  // UI
  dim:      chalk.dim,
  bold:     chalk.bold,
  green:    chalk.green,
  red:      chalk.red,
  cyan:     chalk.hex('#2dd4a7'),  // Bravos theme
  magenta:  chalk.magenta,
  white:    chalk.white,
  gray:     chalk.gray,
  yellow:   chalk.yellow,
  blue:     chalk.blue,

  // Accent
  accent:   chalk.hex('#2dd4a7'),
  teal:     chalk.hex('#2dd4a7'),  // Bravos theme
  success:  chalk.green,
  warn:     chalk.yellow,
  error:    chalk.red,
  info:     chalk.blue,
};

// ─── String Cleaning ─────────────────────────────────────────────────

/** Strip ANSI escape codes from a string */
export function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');
}

/** 
 * Clean CLI framing artifacts from agent output before saving as markdown.
 * Removes terminal boxes (╭─, │, ╰─), prompts (>_), and setup logs.
 */
export function cleanCliArtifacts(content: string): string {
  let cleaned = stripAnsi(content);
  
  // Split into lines to filter out framing
  const lines = cleaned.split('\n');
  const filtered: string[] = [];
  
  let inCodeBlock = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Track code blocks so we don't accidentally strip valid markdown tables inside them
    if (line.trim().startsWith('```')) {
      inCodeBlock = !inCodeBlock;
    }
    
    if (!inCodeBlock) {
      // Remove CLI box drawing characters and terminal prompts
      if (line.match(/^[╭│╰├>_]/) || line.includes('Update available!')) continue;
      
      // Remove Codex/Claude specific framing messages
      if (line.includes('model: ') && line.includes('/model to change')) continue;
      if (line.includes('directory: ~')) continue;
      if (line.includes('Tip: New Try the Codex App')) continue;
      if (line.includes('You are analyzing a codebase with GuardLink')) continue;
      if (line.includes('You have access to the full source code')) continue;
      
      // Skip the echoed instructions/system prompt section if it leaked back out
      if (line.match(/^• I’ll inspect/) || line.match(/^• Explored/)) continue;
      if (line.match(/^─ Worked for/)) continue;
      if (line.match(/^└ Read/) || line.match(/^└ Search/) || line.match(/^└ List/)) continue;
      
      // Stop completely if we hit the "Report saved" confirmation from the CLI
      if (line.includes('✓ Report saved to')) break;
    }
    
    filtered.push(line);
  }
  
  // Find the actual start of the Markdown content (usually an H1 or H2)
  const fullText = filtered.join('\n');
  const match = fullText.match(/(?:^|\n)(#+ [^\n]+)/);
  if (match && match.index !== undefined) {
    // Return from the first Markdown heading onwards, trimmed
    return fullText.slice(match.index).trim();
  }
  
  return fullText.trim();
}

// ─── Severity badge ──────────────────────────────────────────────────

export function severityBadge(sev?: string): string {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'p0') return C.critical(' CRIT ');
  if (s === 'high'     || s === 'p1') return C.high(' HIGH ');
  if (s === 'medium'   || s === 'p2') return C.medium('  MED ');
  if (s === 'low'      || s === 'p3') return C.low('  LOW ');
  return C.unset(' ---- ');
}

/** Compact severity text (for narrow columns) */
export function severityText(sev?: string): string {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'p0') return C.red.bold('critical');
  if (s === 'high'     || s === 'p1') return C.yellow.bold('high');
  if (s === 'medium'   || s === 'p2') return C.yellow('medium');
  if (s === 'low'      || s === 'p3') return C.blue('low');
  return C.gray('unset');
}

/** Severity text padded to fixed visible width (ANSI-safe) */
export function severityTextPad(sev: string | undefined, width: number): string {
  const s = (sev || '').toLowerCase();
  let label: string;
  let colorFn: (s: string) => string;
  if (s === 'critical' || s === 'p0') { label = 'critical'; colorFn = C.red.bold; }
  else if (s === 'high' || s === 'p1') { label = 'high'; colorFn = C.yellow.bold; }
  else if (s === 'medium' || s === 'p2') { label = 'medium'; colorFn = C.yellow; }
  else if (s === 'low' || s === 'p3') { label = 'low'; colorFn = C.blue; }
  else { label = 'unset'; colorFn = C.gray; }
  return colorFn(label) + ' '.repeat(Math.max(0, width - label.length));
}

/** Sort key for severity (lower = more severe) */
export function severityOrder(sev?: string): number {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'p0') return 0;
  if (s === 'high'     || s === 'p1') return 1;
  if (s === 'medium'   || s === 'p2') return 2;
  if (s === 'low'      || s === 'p3') return 3;
  return 4;
}

// ─── Risk grade ──────────────────────────────────────────────────────

export function computeGrade(exposures: number, mitigations: number): string {
  if (exposures === 0) return 'A';
  const ratio = mitigations / Math.max(1, exposures + mitigations);
  if (ratio >= 0.9) return 'A';
  if (ratio >= 0.7) return 'B';
  if (ratio >= 0.5) return 'C';
  if (ratio >= 0.2) return 'D';
  return 'F';
}

export function gradeColored(grade: string): string {
  if (grade === 'A') return C.green.bold(grade);
  if (grade === 'B') return C.green(grade);
  if (grade === 'C') return C.yellow(grade);
  if (grade === 'D') return C.warn.bold(grade);
  return C.red.bold(grade);
}

// ─── Table formatter ─────────────────────────────────────────────────

export interface Column {
  header: string;
  width: number;
  align?: 'left' | 'right';
}

export function formatTable(columns: Column[], rows: string[][]): string[] {
  const lines: string[] = [];

  // Header
  const headerLine = columns.map(c =>
    c.align === 'right' ? c.header.padStart(c.width) : c.header.padEnd(c.width)
  ).join('  ');
  lines.push(C.dim(headerLine));

  // Separator
  const sep = columns.map(c => '─'.repeat(c.width)).join('  ');
  lines.push(C.dim(sep));

  // Rows
  for (const row of rows) {
    const cells = columns.map((c, i) => {
      const val = (row[i] || '').slice(0, c.width);
      return c.align === 'right' ? val.padStart(c.width) : val.padEnd(c.width);
    });
    lines.push(cells.join('  '));
  }

  return lines;
}

// ─── Code context block ──────────────────────────────────────────────

export function readCodeContext(filePath: string, line: number, root?: string, contextLines = 5): { lines: string[]; annIdx: number } {
  try {
    const abs = root && !isAbsolute(filePath) ? resolve(root, filePath) : filePath;
    const content = readFileSync(abs, 'utf-8');
    const allLines = content.split('\n');
    const start = Math.max(0, line - 1 - contextLines);
    const end = Math.min(allLines.length, line + contextLines);
    const slice = allLines.slice(start, end);
    const formatted = slice.map((l, i) => {
      const lineNum = start + i + 1;
      const numStr = String(lineNum).padStart(4);
      const isAnn = lineNum === line;
      if (isAnn) {
        return C.cyan(`  >${numStr} │ `) + C.white(l);
      }
      return C.dim(`   ${numStr} │ `) + C.dim(l);
    });
    return { lines: formatted, annIdx: line - 1 - start };
  } catch {
    return { lines: [], annIdx: 0 };
  }
}

// ─── Misc ────────────────────────────────────────────────────────────

/** Truncate string to max width with ellipsis */
export function trunc(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

/** Horizontal bar (for severity sparklines) */
export function bar(count: number, total: number, width = 20, ch = '█'): string {
  if (total === 0) return C.dim('░'.repeat(width));
  const filled = Math.round((count / total) * width);
  return ch.repeat(filled) + C.dim('░'.repeat(width - filled));
}

// ─── OSC 8 Hyperlinks ────────────────────────────────────────────────

/**
 * Detect whether the terminal supports OSC 8 hyperlinks.
 * Supports: Warp, iTerm2, Kitty, WezTerm, Windows Terminal, foot, Alacritty 0.13+
 */
function supportsHyperlinks(): boolean {
  const env = process.env;
  if (env.FORCE_HYPERLINK === '1') return true;
  if (env.FORCE_HYPERLINK === '0') return false;
  if (!process.stdout.isTTY) return false;
  // Warp
  if (env.TERM_PROGRAM === 'WarpTerminal') return true;
  // iTerm2
  if (env.TERM_PROGRAM === 'iTerm.app') return true;
  // Kitty
  if (env.TERM === 'xterm-kitty') return true;
  // WezTerm
  if (env.TERM_PROGRAM === 'WezTerm') return true;
  // Windows Terminal
  if (env.WT_SESSION) return true;
  // foot
  if (env.TERM === 'foot' || env.TERM === 'foot-extra') return true;
  // VS Code terminal
  if (env.TERM_PROGRAM === 'vscode') return true;
  // Fallback: modern xterm-256color in known-good terminals
  if (env.COLORTERM === 'truecolor' || env.COLORTERM === '24bit') return true;
  return false;
}

const _hyperlinks = supportsHyperlinks();

/**
 * Create a clickable file link using OSC 8 escape sequences.
 * Falls back to plain text if terminal doesn't support hyperlinks.
 * 
 * Works in: Warp, iTerm2, Kitty, WezTerm, Windows Terminal, VS Code terminal
 * Clicking opens the file in the default editor at the specified line.
 */
export function fileLink(filePath: string, line?: number, root?: string, displayOverride?: string): string {
  const abs = root && !isAbsolute(filePath) ? resolve(root, filePath) : filePath;
  const display = displayOverride || (line ? `${filePath}:${line}` : filePath);
  
  if (!_hyperlinks) return display;

  let uri = `file://${encodeURI(abs)}`;
  if (line) uri += `:${line}`;
  
  return `\x1b]8;;${uri}\x07${display}\x1b]8;;\x07`;
}

/**
 * Truncated clickable file link — display is truncated but click target is full path.
 */
export function fileLinkTrunc(filePath: string, maxWidth: number, line?: number, root?: string): string {
  const abs = root && !isAbsolute(filePath) ? resolve(root, filePath) : filePath;
  const display = trunc(filePath, maxWidth);
  
  if (!_hyperlinks) return display;

  let uri = `file://${encodeURI(abs)}`;
  if (line) uri += `:${line}`;
  
  return `\x1b]8;;${uri}\x07${display}\x1b]8;;\x07`;
}
