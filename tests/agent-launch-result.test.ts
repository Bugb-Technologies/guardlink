/**
 * D31 / D30 — the shape of a launch result.
 *
 * D31: `launchAgentForeground` has always returned `{ exitCode, error }`, and
 * `launchAgent` checked only `error`. A terminal agent that exited NON-ZERO
 * without a spawn error came back as `launched: true` and was rendered as
 * "✓ session ended". A failed run looked like a successful one.
 *
 * The fix keeps `launched` meaning "we started it" and surfaces `exitCode`
 * alongside, because `launched` is also used for IDE agents — opening an app has
 * no exit status, so redefining the field to mean "it worked" would make those
 * call sites wrong. Caller evidence: `result.launched && agent.app` renders
 * "launched with project" (start semantics), while four other sites rendered
 * "session ended" (completion semantics) off the same field.
 *
 * D30: `autoYes` was accepted by `launchAgentInline` and never read. It turned
 * out vestigial rather than a hang — `buildInlineArgs` already passes the
 * skip-confirmation flag unconditionally for every supported agent — so the
 * parameter and its three call sites are gone.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchAgentForeground, type LaunchResult } from '../src/agents/launcher.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = (p: string) => readFileSync(join(repoRoot, p), 'utf-8');

describe('D31 — a non-zero exit is visible to the caller', () => {
  it('LaunchResult carries exitCode', () => {
    // Type-level: the field exists and is optional-nullable.
    const ok: LaunchResult = { launched: true, clipboardCopied: false, exitCode: 0 };
    const bad: LaunchResult = { launched: true, clipboardCopied: false, exitCode: 1 };
    expect(ok.exitCode).toBe(0);
    expect(bad.exitCode).toBe(1);
  });

  it('launchAgentForeground reports the real exit status', () => {
    // `false` exits 1 without a spawn error — precisely the case that used to
    // be indistinguishable from success.
    const failed = launchAgentForeground({ id: 'x', name: 'false', cmd: 'false' } as never, repoRoot);
    expect(failed.error).toBeUndefined();
    expect(failed.exitCode).toBe(1);

    const ok = launchAgentForeground({ id: 'x', name: 'true', cmd: 'true' } as never, repoRoot);
    expect(ok.error).toBeUndefined();
    expect(ok.exitCode).toBe(0);
  });

  it('launchAgent no longer discards it', () => {
    // The defect was a destructure that dropped the field on the floor.
    const text = src('src/agents/launcher.ts');
    expect(text).toMatch(/return \{ launched: true, clipboardCopied, exitCode \}/);
    expect(text).not.toMatch(/eslint-disable-next-line @typescript-eslint\/no-unused-vars/);
  });

  it('every "session ended" render is guarded by the exit code', () => {
    // Four sites rendered unqualified success. Each must now branch.
    for (const file of ['src/cli/index.ts', 'src/tui/commands.ts']) {
      const text = src(file);
      const renders = text.split('session ended').length - 1;
      const guards = text.split('exited with code').length - 1;
      expect(guards, `${file}: ${renders} success renders, ${guards} exit-code guards`).toBe(renders);
    }
  });

  it('`launched` still means started, so IDE agents remain correct', () => {
    // IDE agents have no exit status; the field they rely on must not have been
    // redefined underneath them.
    const text = src('src/cli/index.ts');
    expect(text).toMatch(/result\.launched && agent\.app/);
  });
});

describe('D30 — autoYes is gone, not silently ignored', () => {
  it('no source file mentions it', () => {
    for (const file of ['src/agents/launcher.ts', 'src/cli/index.ts', 'src/tui/commands.ts']) {
      expect(src(file), file).not.toMatch(/autoYes/);
    }
  });

  it('the confirmation it meant to suppress is already suppressed unconditionally', () => {
    // Why it was vestigial rather than a hang: every supported inline agent is
    // launched with its own skip-confirmation flag, for every call, with no
    // option gating it.
    const text = src('src/agents/launcher.ts');
    expect(text).toContain('--dangerously-skip-permissions');
    expect(text).toContain('--dangerously-bypass-approvals-and-sandbox');
    expect(text).toContain("'--approval-mode', 'yolo'");
  });
});
