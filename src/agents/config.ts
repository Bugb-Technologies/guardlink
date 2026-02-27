/**
 * GuardLink Agents — Unified LLM configuration resolution.
 *
 * Resolution order (highest to lowest priority):
 *   1. Explicit flags (--api-key, --provider, --model) — CLI only, never persisted
 *   2. GUARDLINK_LLM_KEY + GUARDLINK_LLM_PROVIDER env vars
 *   3. Provider-specific env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)
 *   4. Project config: .guardlink/config.json
 *   5. Global config: ~/.config/guardlink/config.json
 *
 * Replaces the fragmented tui-config.json / CLI flag / env var resolution.
 *
 * @exposes #agent-launcher to #api-key-exposure [high] cwe:CWE-798 -- "API keys loaded from env vars, files; stored in config.json"
 * @mitigates #agent-launcher against #api-key-exposure using #key-redaction -- "maskKey() redacts keys for display; keys never logged"
 * @exposes #agent-launcher to #path-traversal [medium] cwe:CWE-22 -- "Config paths resolved from root and homedir"
 * @mitigates #agent-launcher against #path-traversal using #path-validation -- "join() with known base dirs constrains paths"
 * @exposes #agent-launcher to #arbitrary-write [medium] cwe:CWE-73 -- "saveProjectConfig writes to .guardlink/config.json"
 * @mitigates #agent-launcher against #arbitrary-write using #path-validation -- "Output path is fixed relative to project root"
 * @flows EnvVars -> #agent-launcher via process.env -- "Environment variable input"
 * @flows ConfigFile -> #agent-launcher via readFileSync -- "Config file read"
 * @flows #agent-launcher -> ConfigFile via writeFileSync -- "Config file write"
 * @handles secrets on #agent-launcher -- "Processes and stores LLM API keys"
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { LLMConfig, LLMProvider } from '../analyze/llm.js';

// ─── Types ───────────────────────────────────────────────────────────

interface SavedConfig {
  provider?: LLMProvider;
  model?: string;
  apiKey?: string;
  aiMode?: 'cli-agent' | 'api';
  cliAgent?: string;
  /** Enable extended thinking (Anthropic) / reasoning (DeepSeek) */
  extendedThinking?: boolean;
  /** Enable web search grounding (OpenAI Responses API) */
  webSearch?: boolean;
  /** Response format: 'text' or 'json' */
  responseFormat?: 'text' | 'json';
}

const DEFAULT_MODELS: Record<LLMProvider, string> = {
  anthropic: 'claude-sonnet-4-6',
  openai: 'gpt-5.2',
  google: 'gemini-2.5-flash',
  openrouter: 'anthropic/claude-sonnet-4-6',
  deepseek: 'deepseek-chat',
  ollama: 'llama3.2',
};

const CONFIG_FILE = 'config.json';
const LEGACY_CONFIG_FILE = 'tui-config.json';

// ─── Config file paths ───────────────────────────────────────────────

/** Project-level config: <root>/.guardlink/config.json */
function projectConfigPath(root: string): string {
  return join(root, '.guardlink', CONFIG_FILE);
}

/** Legacy project config: <root>/.guardlink/tui-config.json */
function legacyConfigPath(root: string): string {
  return join(root, '.guardlink', LEGACY_CONFIG_FILE);
}

/** Global config: ~/.config/guardlink/config.json */
function globalConfigPath(): string {
  return join(homedir(), '.config', 'guardlink', CONFIG_FILE);
}

// ─── Read/write helpers ──────────────────────────────────────────────

function readJsonFile(path: string): SavedConfig | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return null;
  }
}

function writeJsonFile(path: string, data: SavedConfig): void {
  const dir = join(path, '..');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
}

// ─── Unified resolution ──────────────────────────────────────────────

/**
 * Resolve LLM configuration using the unified priority chain.
 *
 * @param root  - Project root directory (for project-level config)
 * @param flags - Explicit CLI flags (highest priority, never persisted)
 */
export function resolveConfig(
  root: string,
  flags?: { provider?: string; model?: string; apiKey?: string },
): LLMConfig | null {
  // 1. Explicit flags
  if (flags?.apiKey && flags?.provider) {
    const provider = flags.provider as LLMProvider;
    return {
      provider,
      model: flags.model || DEFAULT_MODELS[provider] || 'gpt-5.2',
      apiKey: flags.apiKey,
    };
  }

  // 2. GUARDLINK_LLM_KEY + GUARDLINK_LLM_PROVIDER
  const guardlinkKey = process.env.GUARDLINK_LLM_KEY;
  const guardlinkProvider = process.env.GUARDLINK_LLM_PROVIDER as LLMProvider | undefined;
  if (guardlinkKey) {
    const provider = guardlinkProvider || detectProviderFromKey(guardlinkKey);
    if (provider) {
      return {
        provider,
        model: flags?.model || DEFAULT_MODELS[provider],
        apiKey: guardlinkKey,
      };
    }
  }

  // 3. Provider-specific env vars
  const envConfig = resolveFromEnv(flags?.model);
  if (envConfig) return envConfig;

  // 4. Project config: .guardlink/config.json (+ legacy tui-config.json)
  const projectCfg = readJsonFile(projectConfigPath(root))
    || readJsonFile(legacyConfigPath(root));
  if (projectCfg?.provider && projectCfg?.apiKey) {
    return {
      provider: projectCfg.provider,
      model: flags?.model || projectCfg.model || DEFAULT_MODELS[projectCfg.provider],
      apiKey: projectCfg.apiKey,
      ...savedConfigExtras(projectCfg),
    };
  }

  // 5. Global config: ~/.config/guardlink/config.json
  const globalCfg = readJsonFile(globalConfigPath());
  if (globalCfg?.provider && globalCfg?.apiKey) {
    return {
      provider: globalCfg.provider,
      model: flags?.model || globalCfg.model || DEFAULT_MODELS[globalCfg.provider],
      apiKey: globalCfg.apiKey,
      ...savedConfigExtras(globalCfg),
    };
  }

  return null;
}

/** Extract optional LLM config extras from saved config */
function savedConfigExtras(cfg: SavedConfig): Partial<LLMConfig> {
  const extras: Partial<LLMConfig> = {};
  if (cfg.extendedThinking) extras.extendedThinking = true;
  if (cfg.webSearch) extras.webSearch = true;
  if (cfg.responseFormat) extras.responseFormat = cfg.responseFormat;
  return extras;
}

/** Resolve from provider-specific env vars (ANTHROPIC_API_KEY, etc.) */
function resolveFromEnv(modelOverride?: string): LLMConfig | null {
  const checks: [string, LLMProvider][] = [
    ['ANTHROPIC_API_KEY', 'anthropic'],
    ['OPENAI_API_KEY', 'openai'],
    ['GOOGLE_API_KEY', 'google'],
    ['GEMINI_API_KEY', 'google'],
    ['OPENROUTER_API_KEY', 'openrouter'],
    ['DEEPSEEK_API_KEY', 'deepseek'],
  ];
  for (const [envVar, provider] of checks) {
    const key = process.env[envVar];
    if (key) {
      return {
        provider,
        model: modelOverride || DEFAULT_MODELS[provider],
        apiKey: key,
      };
    }
  }
  return null;
}

/** Heuristic: detect provider from API key prefix */
function detectProviderFromKey(key: string): LLMProvider | null {
  if (key.startsWith('sk-ant-')) return 'anthropic';
  if (key.startsWith('sk-or-')) return 'openrouter';
  if (key.startsWith('sk-')) return 'openai';  // OpenAI uses sk- prefix
  if (key.startsWith('AIza')) return 'google';  // Google API keys start with AIza
  return null;  // Can't detect — need GUARDLINK_LLM_PROVIDER
}

// ─── Save/load for `guardlink config` and `/model` ──────────────────

/** Save config to project-level .guardlink/config.json */
export function saveProjectConfig(root: string, cfg: SavedConfig): void {
  writeJsonFile(projectConfigPath(root), cfg);
}

/** Save config to global ~/.config/guardlink/config.json */
export function saveGlobalConfig(cfg: SavedConfig): void {
  writeJsonFile(globalConfigPath(), cfg);
}

/** Load project config (new or legacy path) */
export function loadProjectConfig(root: string): SavedConfig | null {
  return readJsonFile(projectConfigPath(root))
    || readJsonFile(legacyConfigPath(root));
}

/** Load global config */
export function loadGlobalConfig(): SavedConfig | null {
  return readJsonFile(globalConfigPath());
}

// ─── Display helpers ─────────────────────────────────────────────────

/** Mask an API key for display: sk-ant-***...***xyz */
export function maskKey(key: string): string {
  if (key.length <= 12) return '***';
  return key.slice(0, 7) + '•'.repeat(8) + key.slice(-3);
}

/** Describe the source of the resolved config */
export function describeConfigSource(
  root: string,
  flags?: { provider?: string; apiKey?: string },
): string {
  if (flags?.apiKey && flags?.provider) return 'CLI flags';
  if (process.env.GUARDLINK_LLM_KEY) return 'GUARDLINK_LLM_KEY env var';
  if (process.env.ANTHROPIC_API_KEY) return 'ANTHROPIC_API_KEY env var';
  if (process.env.OPENAI_API_KEY) return 'OPENAI_API_KEY env var';
  if (process.env.GOOGLE_API_KEY) return 'GOOGLE_API_KEY env var';
  if (process.env.GEMINI_API_KEY) return 'GEMINI_API_KEY env var';
  if (process.env.OPENROUTER_API_KEY) return 'OPENROUTER_API_KEY env var';
  if (process.env.DEEPSEEK_API_KEY) return 'DEEPSEEK_API_KEY env var';
  const pc = readJsonFile(projectConfigPath(root));
  if (pc && Object.keys(pc).length > 0 && (pc.provider || pc.aiMode)) return `.guardlink/${CONFIG_FILE}`;
  const lc = readJsonFile(legacyConfigPath(root));
  if (lc && Object.keys(lc).length > 0 && lc.provider) return `.guardlink/${LEGACY_CONFIG_FILE} (legacy)`;
  const gc = readJsonFile(globalConfigPath());
  if (gc && Object.keys(gc).length > 0 && gc.provider) return `~/.config/guardlink/${CONFIG_FILE}`;
  return 'none';
}
