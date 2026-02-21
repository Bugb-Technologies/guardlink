/**
 * GuardLink Threat Reports — Lightweight LLM client using raw fetch.
 *
 * Supports:
 *   - Anthropic Messages API (claude-sonnet-4-5-20250929, etc.)
 *   - OpenAI-compatible Chat Completions (GPT-4o, DeepSeek, OpenRouter)
 *
 * Zero dependencies — uses Node 20+ built-in fetch.
 *
 * @exposes #llm-client to #api-key-exposure [high] cwe:CWE-798 -- "Reads API keys from environment variables"
 * @exposes #llm-client to #ssrf [medium] cwe:CWE-918 -- "Makes HTTP requests to configurable provider URLs"
 * @exposes #llm-client to #prompt-injection [medium] cwe:CWE-77 -- "Sends threat model content as LLM prompt"
 * @accepts #prompt-injection on #llm-client -- "Core feature: threat model data is sent to LLM for analysis"
 * @mitigates #llm-client against #ssrf using #config-validation -- "BASE_URLS are hardcoded to known providers"
 * @mitigates #llm-client against #api-key-exposure using #key-redaction -- "Keys read from env, not logged"
 * @handles secrets on #llm-client -- "API keys held in memory during request lifecycle"
 * @boundary between #llm-client and External_LLM_APIs (#llm-boundary) -- "HTTP requests cross network trust boundary to external AI providers"
 * @flows #llm-client -> External_LLM_APIs via fetch -- "HTTP POST with auth headers and prompt payload"
 * @flows External_LLM_APIs -> #llm-client via response -- "Streaming or complete response from LLM provider"
 */

export type LLMProvider = 'anthropic' | 'openai' | 'openrouter' | 'deepseek';

export interface LLMConfig {
  provider: LLMProvider;
  model: string;
  apiKey: string;
  baseUrl?: string;
  maxTokens?: number;
}

export interface LLMResponse {
  content: string;
  model: string;
  inputTokens?: number;
  outputTokens?: number;
}

const DEFAULT_MODELS: Record<LLMProvider, string> = {
  anthropic: 'claude-sonnet-4-5-20250929',
  openai: 'gpt-4o',
  openrouter: 'anthropic/claude-sonnet-4-5-20250929',
  deepseek: 'deepseek-chat',
};

const BASE_URLS: Record<LLMProvider, string> = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com',
  openrouter: 'https://openrouter.ai/api',
  deepseek: 'https://api.deepseek.com',
};

/**
 * Auto-detect provider from environment variables.
 * Returns null if no API key found.
 */
export function autoDetectConfig(): LLMConfig | null {
  // Priority: Anthropic > OpenAI > OpenRouter > DeepSeek
  if (process.env.ANTHROPIC_API_KEY) {
    return {
      provider: 'anthropic',
      model: DEFAULT_MODELS.anthropic,
      apiKey: process.env.ANTHROPIC_API_KEY,
    };
  }
  if (process.env.OPENAI_API_KEY) {
    return {
      provider: 'openai',
      model: DEFAULT_MODELS.openai,
      apiKey: process.env.OPENAI_API_KEY,
    };
  }
  if (process.env.OPENROUTER_API_KEY) {
    return {
      provider: 'openrouter',
      model: DEFAULT_MODELS.openrouter,
      apiKey: process.env.OPENROUTER_API_KEY,
    };
  }
  if (process.env.DEEPSEEK_API_KEY) {
    return {
      provider: 'deepseek',
      model: DEFAULT_MODELS.deepseek,
      apiKey: process.env.DEEPSEEK_API_KEY,
    };
  }
  return null;
}

/**
 * Build config from explicit flags + env vars.
 */
export function buildConfig(opts: {
  provider?: string;
  model?: string;
  apiKey?: string;
}): LLMConfig | null {
  // If provider specified, use it
  if (opts.provider) {
    const provider = opts.provider as LLMProvider;
    const envKeyMap: Record<string, string> = {
      anthropic: 'ANTHROPIC_API_KEY',
      openai: 'OPENAI_API_KEY',
      openrouter: 'OPENROUTER_API_KEY',
      deepseek: 'DEEPSEEK_API_KEY',
    };
    const apiKey = opts.apiKey || process.env[envKeyMap[provider] || ''];
    if (!apiKey) return null;

    return {
      provider,
      model: opts.model || DEFAULT_MODELS[provider] || 'gpt-4o',
      apiKey,
    };
  }

  // Auto-detect
  const config = autoDetectConfig();
  if (!config) return null;

  // Override model if specified
  if (opts.model) config.model = opts.model;
  return config;
}

/**
 * Send a message to the LLM and return the response.
 */
export async function chatCompletion(
  config: LLMConfig,
  systemPrompt: string,
  userMessage: string,
  onChunk?: (text: string) => void,
): Promise<LLMResponse> {
  if (config.provider === 'anthropic') {
    return callAnthropic(config, systemPrompt, userMessage, onChunk);
  } else {
    return callOpenAICompatible(config, systemPrompt, userMessage, onChunk);
  }
}

// ─── Anthropic Messages API ──────────────────────────────────────────

async function callAnthropic(
  config: LLMConfig,
  systemPrompt: string,
  userMessage: string,
  onChunk?: (text: string) => void,
): Promise<LLMResponse> {
  const baseUrl = config.baseUrl || BASE_URLS.anthropic;
  const maxTokens = config.maxTokens || 8192;

  if (onChunk) {
    // Streaming
    const res = await fetch(`${baseUrl}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': config.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        system: systemPrompt,
        stream: true,
        messages: [{ role: 'user', content: userMessage }],
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Anthropic API error ${res.status}: ${err}`);
    }

    let content = '';
    let inputTokens = 0;
    let outputTokens = 0;
    const reader = res.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') continue;
        try {
          const event = JSON.parse(data);
          if (event.type === 'content_block_delta' && event.delta?.text) {
            content += event.delta.text;
            onChunk(event.delta.text);
          }
          if (event.type === 'message_delta' && event.usage) {
            outputTokens = event.usage.output_tokens || 0;
          }
          if (event.type === 'message_start' && event.message?.usage) {
            inputTokens = event.message.usage.input_tokens || 0;
          }
        } catch { /* skip non-JSON lines */ }
      }
    }

    return { content, model: config.model, inputTokens, outputTokens };
  } else {
    // Non-streaming
    const res = await fetch(`${baseUrl}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': config.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: [{ role: 'user', content: userMessage }],
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Anthropic API error ${res.status}: ${err}`);
    }

    const data = await res.json() as any;
    return {
      content: data.content?.[0]?.text || '',
      model: data.model || config.model,
      inputTokens: data.usage?.input_tokens,
      outputTokens: data.usage?.output_tokens,
    };
  }
}

// ─── OpenAI-compatible Chat Completions ──────────────────────────────

async function callOpenAICompatible(
  config: LLMConfig,
  systemPrompt: string,
  userMessage: string,
  onChunk?: (text: string) => void,
): Promise<LLMResponse> {
  const baseUrl = config.baseUrl || BASE_URLS[config.provider] || BASE_URLS.openai;
  const maxTokens = config.maxTokens || 8192;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${config.apiKey}`,
  };

  // OpenRouter requires extra headers
  if (config.provider === 'openrouter') {
    headers['HTTP-Referer'] = 'https://guardlink.bugb.io';
    headers['X-Title'] = 'GuardLink CLI';
  }

  if (onChunk) {
    // Streaming
    const res = await fetch(`${baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        stream: true,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userMessage },
        ],
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`${config.provider} API error ${res.status}: ${err}`);
    }

    let content = '';
    const reader = res.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') continue;
        try {
          const event = JSON.parse(data);
          const delta = event.choices?.[0]?.delta?.content;
          if (delta) {
            content += delta;
            onChunk(delta);
          }
        } catch { /* skip */ }
      }
    }

    return { content, model: config.model };
  } else {
    // Non-streaming
    const res = await fetch(`${baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userMessage },
        ],
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`${config.provider} API error ${res.status}: ${err}`);
    }

    const data = await res.json() as any;
    return {
      content: data.choices?.[0]?.message?.content || '',
      model: data.model || config.model,
      inputTokens: data.usage?.prompt_tokens,
      outputTokens: data.usage?.completion_tokens,
    };
  }
}
