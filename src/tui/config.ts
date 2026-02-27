/**
 * GuardLink TUI — Config persistence for LLM settings.
 *
 * Now delegates to the unified agents/config.ts resolution chain.
 * Keeps backward compatibility with tui-config.json (legacy).
 *
 * @exposes #tui to #api-key-exposure [high] cwe:CWE-798 -- "API keys loaded from and saved to config files"
 * @mitigates #tui against #api-key-exposure using #key-redaction -- "Delegates to agents/config.ts with masking"
 * @flows ConfigFile -> #tui via loadProjectConfig -- "Config load path"
 * @flows #tui -> ConfigFile via saveProjectConfig -- "Config save path"
 * @handles secrets on #tui -- "API keys stored in .guardlink/config.json"
 */

import type { LLMConfig, LLMProvider } from '../analyze/llm.js';
import { resolveConfig, saveProjectConfig, loadProjectConfig } from '../agents/config.js';

interface TuiConfig {
  provider?: LLMProvider;
  model?: string;
  apiKey?: string;
  aiMode?: 'cli-agent' | 'api';
  cliAgent?: string;
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
