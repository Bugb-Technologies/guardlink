/**
 * GuardLink TUI — Config persistence for LLM settings.
 *
 * Now delegates to the unified agents/config.ts resolution chain.
 * Keeps backward compatibility with tui-config.json (legacy).
 */

import type { LLMConfig, LLMProvider } from '../analyze/llm.js';
import { resolveConfig, saveProjectConfig, loadProjectConfig } from '../agents/config.js';

interface TuiConfig {
  provider?: LLMProvider;
  model?: string;
  apiKey?: string;
}

/**
 * Load TUI config (delegates to unified config loader with legacy fallback).
 */
export function loadTuiConfig(root: string): TuiConfig | null {
  return loadProjectConfig(root);
}

/**
 * Save TUI config to project .guardlink/config.json.
 */
export function saveTuiConfig(root: string, cfg: TuiConfig): void {
  saveProjectConfig(root, cfg);
}

/**
 * Resolve LLM config using the unified resolution chain:
 * env vars > project config > global config.
 */
export function resolveLLMConfig(root: string): LLMConfig | null {
  return resolveConfig(root);
}
