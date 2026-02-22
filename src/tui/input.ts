/**
 * GuardLink TUI — Enhanced input box with bordered frame,
 * placeholder text, and slash command palette.
 *
 * Inspired by Claude Code's input UX:
 *   ┌──────────────────────────────────────┐
 *   │ › type a command or question...      │
 *   └──────────────────────────────────────┘
 *     /validate    Check annotations
 *     /files       Browse files
 *     /assets      Asset tree
 *
 * Uses raw stdin mode for full keystroke control.
 */

import chalk from 'chalk';

const BRAVOS = '#2dd4a7';
const bravos = chalk.hex(BRAVOS);

// ─── Types ───────────────────────────────────────────────────────────

export interface InputBoxOptions {
  /** Placeholder shown when input is empty */
  placeholder?: string;
  /** Prompt character (default: ›) */
  prompt?: string;
  /** Available slash commands for palette */
  commands?: CommandEntry[];
  /** Max palette items to show */
  maxPaletteItems?: number;
}

export interface CommandEntry {
  command: string;   // e.g. "/validate"
  label: string;     // e.g. "List by severity"
  aliases?: string[];
}

interface PaletteState {
  visible: boolean;
  items: CommandEntry[];
  selected: number;
}

// ─── ANSI helpers ────────────────────────────────────────────────────

const ESC = '\x1b[';
const CLEAR_LINE = `${ESC}2K`;
const CURSOR_UP = (n: number) => `${ESC}${n}A`;
const CURSOR_DOWN = (n: number) => `${ESC}${n}B`;
const CURSOR_COL = (n: number) => `${ESC}${n}G`;
const CURSOR_HIDE = `${ESC}?25l`;
const CURSOR_SHOW = `${ESC}?25h`;

// ─── InputBox class ──────────────────────────────────────────────────

export class InputBox {
  private buffer: string = '';
  private cursor: number = 0;
  private placeholder: string;
  private prompt: string;
  private commands: CommandEntry[];
  private maxPalette: number;
  private palette: PaletteState = { visible: false, items: [], selected: 0 };
  private lastRenderHeight: number = 0; // total lines rendered (box + palette)
  private lastCursorFromBottom: number = 0; // cursor position relative to bottom of render
  private active: boolean = false;
  private onSubmit: ((line: string) => void) | null = null;
  private onClose: (() => void) | null = null;
  private paused: boolean = false;
  private rawHandler: ((data: Buffer) => void) | null = null;
  private ctrlCPending: boolean = false;
  private ctrlCTimer: ReturnType<typeof setTimeout> | null = null;
  private showExitHint: boolean = false;

  constructor(opts: InputBoxOptions = {}) {
    this.placeholder = opts.placeholder ?? 'Type a command or question...';
    this.prompt = opts.prompt ?? '›';
    this.commands = opts.commands ?? [];
    this.maxPalette = opts.maxPaletteItems ?? 8;
  }

  /** Start listening for input. Returns cleanup function. */
  start(onSubmit: (line: string) => void, onClose: () => void): void {
    this.onSubmit = onSubmit;
    this.onClose = onClose;
    this.active = true;
    this.paused = false;

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }
    process.stdin.resume();

    this.rawHandler = (data: Buffer) => this.handleKey(data);
    process.stdin.on('data', this.rawHandler);

    this.render();
  }

  /** Pause input (while command executes) */
  pause(): void {
    this.paused = true;
    if (this.rawHandler) {
      process.stdin.removeListener('data', this.rawHandler);
    }
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }
    // Clear the rendered box so command output flows naturally
    this.clearRender();
  }

  /** Resume input after command completes */
  resume(): void {
    this.paused = false;
    this.buffer = '';
    this.cursor = 0;
    this.palette = { visible: false, items: [], selected: 0 };
    this.lastRenderHeight = 0;
    this.lastCursorFromBottom = 0;

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }
    process.stdin.resume();

    if (this.rawHandler) {
      process.stdin.on('data', this.rawHandler);
    }

    this.render();
  }

  /** Stop listening entirely */
  stop(): void {
    this.active = false;
    if (this.ctrlCTimer) { clearTimeout(this.ctrlCTimer); this.ctrlCTimer = null; }
    this.clearRender();
    if (this.rawHandler) {
      process.stdin.removeListener('data', this.rawHandler);
    }
    if (process.stdin.isTTY) {
      try { process.stdin.setRawMode(false); } catch {}
    }
  }

  // ─── Key handling ─────────────────────────────────────────────────

  private handleKey(data: Buffer): void {
    if (!this.active || this.paused) return;

    const key = data.toString('utf-8');
    const code = data[0];

    // Ctrl+C — double-tap to exit (like Claude Code)
    if (code === 3) {
      if (this.ctrlCPending) {
        // Second Ctrl+C — just exit immediately, no cleanup possible
        if (this.ctrlCTimer) { clearTimeout(this.ctrlCTimer); this.ctrlCTimer = null; }
        this.onClose?.();
        return;
      }
      // First Ctrl+C — clear buffer, show hint via render
      this.ctrlCPending = true;
      this.showExitHint = true;
      this.buffer = '';
      this.cursor = 0;
      this.updatePalette();
      this.render();
      this.ctrlCTimer = setTimeout(() => {
        this.ctrlCPending = false;
        this.showExitHint = false;
        this.render();
      }, 2000);
      return;
    }

    // Ctrl+D — exit on empty line
    if (code === 4 && this.buffer.length === 0) {
      this.clearRender();
      this.onClose?.();
      return;
    }

    // Any non-Ctrl+C key resets the exit pending state
    if (this.ctrlCPending) {
      this.ctrlCPending = false;
      this.showExitHint = false;
      if (this.ctrlCTimer) { clearTimeout(this.ctrlCTimer); this.ctrlCTimer = null; }
    }

    // Enter — submit
    if (code === 13 || code === 10) {
      // If palette is visible and an item is selected, use that
      if (this.palette.visible && this.palette.items.length > 0) {
        const selected = this.palette.items[this.palette.selected];
        if (selected) {
          this.buffer = selected.command + ' ';
          this.cursor = this.buffer.length;
        }
      }
      const line = this.buffer;
      this.clearRender();
      process.stdout.write('\n');
      this.onSubmit?.(line);
      return;
    }

    // Tab — accept palette selection
    if (code === 9) {
      if (this.palette.visible && this.palette.items.length > 0) {
        const selected = this.palette.items[this.palette.selected];
        if (selected) {
          this.buffer = selected.command + ' ';
          this.cursor = this.buffer.length;
          this.updatePalette();
          this.render();
        }
      }
      return;
    }

    // Escape — close palette
    if (code === 27 && data.length === 1) {
      if (this.palette.visible) {
        this.palette.visible = false;
        this.render();
      }
      return;
    }

    // Arrow keys and other escape sequences
    if (code === 27 && data[1] === 91) {
      const arrow = data[2];
      // Up arrow
      if (arrow === 65) {
        if (this.palette.visible && this.palette.items.length > 0) {
          this.palette.selected = Math.max(0, this.palette.selected - 1);
          this.render();
        }
        return;
      }
      // Down arrow
      if (arrow === 66) {
        if (this.palette.visible && this.palette.items.length > 0) {
          this.palette.selected = Math.min(this.palette.items.length - 1, this.palette.selected + 1);
          this.render();
        }
        return;
      }
      // Right arrow
      if (arrow === 67) {
        if (this.cursor < this.buffer.length) this.cursor++;
        this.render();
        return;
      }
      // Left arrow
      if (arrow === 68) {
        if (this.cursor > 0) this.cursor--;
        this.render();
        return;
      }
      // Home (ESC[H or ESC[1~)
      if (arrow === 72) { this.cursor = 0; this.render(); return; }
      // End (ESC[F or ESC[4~)
      if (arrow === 70) { this.cursor = this.buffer.length; this.render(); return; }
      // Delete (ESC[3~)
      if (arrow === 51 && data[3] === 126) {
        if (this.cursor < this.buffer.length) {
          this.buffer = this.buffer.slice(0, this.cursor) + this.buffer.slice(this.cursor + 1);
          this.updatePalette();
          this.render();
        }
        return;
      }
      return;
    }

    // Backspace
    if (code === 127 || code === 8) {
      if (this.cursor > 0) {
        this.buffer = this.buffer.slice(0, this.cursor - 1) + this.buffer.slice(this.cursor);
        this.cursor--;
        this.updatePalette();
        this.render();
      }
      return;
    }

    // Ctrl+A — beginning of line
    if (code === 1) { this.cursor = 0; this.render(); return; }
    // Ctrl+E — end of line
    if (code === 5) { this.cursor = this.buffer.length; this.render(); return; }
    // Ctrl+K — kill to end
    if (code === 11) {
      this.buffer = this.buffer.slice(0, this.cursor);
      this.updatePalette();
      this.render();
      return;
    }
    // Ctrl+U — kill to start
    if (code === 21) {
      this.buffer = this.buffer.slice(this.cursor);
      this.cursor = 0;
      this.updatePalette();
      this.render();
      return;
    }
    // Ctrl+W — delete word backward
    if (code === 23) {
      const before = this.buffer.slice(0, this.cursor);
      const trimmed = before.replace(/\S+\s*$/, '');
      this.buffer = trimmed + this.buffer.slice(this.cursor);
      this.cursor = trimmed.length;
      this.updatePalette();
      this.render();
      return;
    }

    // Printable characters
    if (code >= 32 || (data.length > 1 && code > 127)) {
      this.buffer = this.buffer.slice(0, this.cursor) + key + this.buffer.slice(this.cursor);
      this.cursor += key.length;
      this.updatePalette();
      this.render();
    }
  }

  // ─── Command palette ─────────────────────────────────────────────

  private updatePalette(): void {
    const trimmed = this.buffer.trimStart();

    // Show palette only when typing starts with /
    if (!trimmed.startsWith('/') || trimmed.includes(' ')) {
      this.palette.visible = false;
      this.palette.items = [];
      this.palette.selected = 0;
      return;
    }

    const filter = trimmed.toLowerCase();
    const filtered = this.commands.filter(c => {
      if (c.command.toLowerCase().startsWith(filter)) return true;
      if (c.aliases?.some(a => a.toLowerCase().startsWith(filter))) return true;
      // Also match on label words
      if (filter.length > 1 && c.label.toLowerCase().includes(filter.slice(1))) return true;
      return false;
    }).slice(0, this.maxPalette);

    this.palette.visible = filtered.length > 0;
    this.palette.items = filtered;
    // Clamp selection
    if (this.palette.selected >= filtered.length) {
      this.palette.selected = Math.max(0, filtered.length - 1);
    }
  }

  // ─── Rendering ──────────────────────────────────────────────────

  private getTermWidth(): number {
    return process.stdout.columns || 80;
  }

  private clearRender(): void {
    if (this.lastRenderHeight <= 0) return;

    // Move cursor to TOP of rendered area first
    const linesToTop = this.lastRenderHeight - 1 - this.lastCursorFromBottom;
    if (linesToTop > 0) {
      process.stdout.write(CURSOR_UP(linesToTop));
    }

    // Clear every line going downward from top
    let out = '';
    for (let i = 0; i < this.lastRenderHeight; i++) {
      out += CLEAR_LINE;
      if (i < this.lastRenderHeight - 1) out += CURSOR_DOWN(1);
    }
    process.stdout.write(out);

    // Move back to top
    if (this.lastRenderHeight > 1) {
      process.stdout.write(CURSOR_UP(this.lastRenderHeight - 1));
    }
    process.stdout.write('\r');

    this.lastRenderHeight = 0;
    this.lastCursorFromBottom = 0;
  }

  private render(): void {
    if (!this.active || this.paused) return;

    const w = this.getTermWidth();
    const lineW = Math.max(30, w - 4);   // width of the horizontal rule
    const contentW = lineW;               // no side borders, full width for content

    // Hide cursor during render to prevent flicker
    process.stdout.write(CURSOR_HIDE);

    // Clear previous render
    this.clearRender();

    const lines: string[] = [];

    // ── Exit hint (shown after first Ctrl+C) ──
    if (this.showExitHint) {
      lines.push('  ' + chalk.dim('Press Ctrl+C again to exit.'));
    }

    // ── Top border (horizontal line only) ──
    lines.push('  ' + chalk.dim('─'.repeat(lineW)));

    // ── Input line(s) ──
    const promptStr = bravos(this.prompt) + ' ';
    const promptVisLen = this.prompt.length + 1; // "› "
    const maxTextW = contentW - promptVisLen;

    if (this.buffer.length === 0) {
      // Placeholder
      const ph = this.placeholder.slice(0, maxTextW);
      lines.push('  ' + promptStr + chalk.dim.italic(ph));
    } else {
      const content = this.buffer;

      if (content.length <= maxTextW) {
        // Single line
        lines.push('  ' + promptStr + content);
      } else {
        // Multi-line wrap
        const chunks: string[] = [];
        for (let i = 0; i < content.length; i += maxTextW) {
          chunks.push(content.slice(i, i + maxTextW));
        }
        for (let i = 0; i < chunks.length; i++) {
          if (i === 0) {
            lines.push('  ' + promptStr + chunks[i]);
          } else {
            lines.push('  ' + ' '.repeat(promptVisLen) + chunks[i]);
          }
        }
      }
    }

    // ── Bottom border (horizontal line only) ──
    lines.push('  ' + chalk.dim('─'.repeat(lineW)));

    // ── Command palette (below bottom border) ──
    if (this.palette.visible && this.palette.items.length > 0) {
      const cmdW = 16;
      for (let i = 0; i < this.palette.items.length; i++) {
        const item = this.palette.items[i];
        const isSelected = i === this.palette.selected;
        const cmd = item.command.padEnd(cmdW);
        const desc = item.label;

        if (isSelected) {
          lines.push('  ' + chalk.bgHex(BRAVOS).black.bold(' ' + cmd) + chalk.bgHex(BRAVOS).black(' ' + desc + ' '));
        } else {
          lines.push('    ' + bravos(cmd) + chalk.dim(desc));
        }
      }
    }

    // ── Bottom padding (breathing room — ^C echo lands here, not on input) ──
    lines.push('');
    lines.push('');
    lines.push('');

    // Write all lines
    process.stdout.write('\r' + lines.join('\n'));
    this.lastRenderHeight = lines.length;

    // ── Position cursor ──
    const cursorLine = maxTextW > 0 ? Math.floor(this.cursor / maxTextW) : 0;
    const cursorCol = maxTextW > 0 ? (this.cursor % maxTextW) : this.cursor;

    // Lines from bottom to cursor position
    const paletteLines = this.palette.visible ? this.palette.items.length : 0;
    const inputLines = this.buffer.length === 0 ? 1 :
      (maxTextW > 0 ? Math.max(1, Math.ceil(this.buffer.length / maxTextW)) : 1);
    const linesFromBottom = 3 /* padding */ + paletteLines + 1 /* bottom border */ + (inputLines - 1 - cursorLine);

    // Column: "  " (2) + prompt (2) + cursor position
    const colOffset = 2 + promptVisLen + cursorCol + 1;

    if (linesFromBottom > 0) {
      process.stdout.write(CURSOR_UP(linesFromBottom));
    }
    process.stdout.write(CURSOR_COL(colOffset));
    process.stdout.write(CURSOR_SHOW);

    // Track cursor position for correct clearing
    this.lastCursorFromBottom = linesFromBottom;
  }
}
