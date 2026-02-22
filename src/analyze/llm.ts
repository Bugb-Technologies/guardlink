/**
 * GuardLink Threat Reports — Lightweight LLM client using raw fetch.
 *
 * Supports:
 *   - Anthropic Messages API (claude-sonnet-4-6, claude-opus-4-6, etc.) with extended thinking + tool use
 *   - OpenAI Responses API (gpt-5.2, o3, etc.) with web search, tools, structured output
 *   - Google Gemini API (gemini-2.5-flash, gemini-3-pro, etc.) via OpenAI-compatible endpoint
 *   - OpenAI-compatible Chat Completions (DeepSeek, OpenRouter, Ollama)
 *   - DeepSeek reasoning mode (deepseek-reasoner)
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

export type LLMProvider = 'anthropic' | 'openai' | 'google' | 'openrouter' | 'deepseek' | 'ollama';

// ─── Tool definitions ────────────────────────────────────────────────

export interface ToolParameter {
  type: string;
  description?: string;
  enum?: string[];
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, ToolParameter>;
    required?: string[];
    additionalProperties?: boolean;
  };
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, any>;
}

export interface ToolResult {
  id: string;
  content: string;
}

/** Handler that executes a tool call and returns its result string */
export type ToolExecutor = (name: string, args: Record<string, any>) => Promise<string>;

// ─── Config & Response types ─────────────────────────────────────────

export interface LLMConfig {
  provider: LLMProvider;
  model: string;
  apiKey: string;
  baseUrl?: string;
  maxTokens?: number;

  /** Enable extended thinking (Anthropic) / reasoning (DeepSeek) */
  extendedThinking?: boolean;
  /** Token budget for thinking (default: 10000) */
  thinkingBudget?: number;
  /** Enable web search grounding (OpenAI Responses API) */
  webSearch?: boolean;
  /** Response format: 'text' (default) or 'json' for structured output */
  responseFormat?: 'text' | 'json';
  /** Tool definitions for function calling */
  tools?: ToolDefinition[];
  /** Tool executor function — required if tools are provided */
  toolExecutor?: ToolExecutor;
  /** Max tool-call rounds in agentic loop (default: 5) */
  maxToolRounds?: number;
}

export interface LLMResponse {
  content: string;
  model: string;
  inputTokens?: number;
  outputTokens?: number;
  /** Thinking/reasoning content (extended thinking) */
  thinking?: string;
  /** Thinking tokens used */
  thinkingTokens?: number;
  /** Tool calls made during generation */
  toolCalls?: ToolCall[];
}

// ─── Defaults ────────────────────────────────────────────────────────

const DEFAULT_MODELS: Record<LLMProvider, string> = {
  anthropic: 'claude-sonnet-4-6-20260217',
  openai: 'gpt-5.2',
  google: 'gemini-2.5-flash',
  openrouter: 'anthropic/claude-sonnet-4-6-20260217',
  deepseek: 'deepseek-chat',
  ollama: 'llama3.2',
};

const BASE_URLS: Record<LLMProvider, string> = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com',
  google: 'https://generativelanguage.googleapis.com/v1beta/openai',
  openrouter: 'https://openrouter.ai/api',
  deepseek: 'https://api.deepseek.com',
  ollama: 'http://localhost:11434',
};

// ─── Auto-detect ─────────────────────────────────────────────────────

/**
 * Auto-detect provider from environment variables.
 * Returns null if no API key found.
 */
export function autoDetectConfig(): LLMConfig | null {
  if (process.env.ANTHROPIC_API_KEY) {
    return { provider: 'anthropic', model: DEFAULT_MODELS.anthropic, apiKey: process.env.ANTHROPIC_API_KEY };
  }
  if (process.env.OPENAI_API_KEY) {
    return { provider: 'openai', model: DEFAULT_MODELS.openai, apiKey: process.env.OPENAI_API_KEY };
  }
  if (process.env.OPENROUTER_API_KEY) {
    return { provider: 'openrouter', model: DEFAULT_MODELS.openrouter, apiKey: process.env.OPENROUTER_API_KEY };
  }
  if (process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY) {
    return { provider: 'google', model: DEFAULT_MODELS.google, apiKey: (process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY)! };
  }
  if (process.env.DEEPSEEK_API_KEY) {
    return { provider: 'deepseek', model: DEFAULT_MODELS.deepseek, apiKey: process.env.DEEPSEEK_API_KEY };
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
  if (opts.provider) {
    const provider = opts.provider as LLMProvider;
    const envKeyMap: Record<string, string> = {
      anthropic: 'ANTHROPIC_API_KEY',
      openai: 'OPENAI_API_KEY',
      openrouter: 'OPENROUTER_API_KEY',
      google: 'GOOGLE_API_KEY',
      deepseek: 'DEEPSEEK_API_KEY',
    };
    const apiKey = opts.apiKey || process.env[envKeyMap[provider] || ''];
    if (!apiKey) return null;
    return {
      provider,
      model: opts.model || DEFAULT_MODELS[provider] || 'gpt-5.2',
      apiKey,
    };
  }

  const config = autoDetectConfig();
  if (!config) return null;
  if (opts.model) config.model = opts.model;
  return config;
}

// ─── Main entry point ────────────────────────────────────────────────

/**
 * Send a message to the LLM and return the response.
 * Supports streaming, tool use (agentic loop), extended thinking,
 * web search, and structured output.
 */
export async function chatCompletion(
  config: LLMConfig,
  systemPrompt: string,
  userMessage: string,
  onChunk?: (text: string) => void,
): Promise<LLMResponse> {
  if (config.provider === 'anthropic') {
    return callAnthropicWithTools(config, systemPrompt, userMessage, onChunk);
  } else if (config.provider === 'openai') {
    return callOpenAIResponses(config, systemPrompt, userMessage, onChunk);
  } else {
    // Google Gemini, DeepSeek, OpenRouter, Ollama all use OpenAI-compatible Chat Completions
    return callOpenAICompatible(config, systemPrompt, userMessage, onChunk);
  }
}

// ─── Anthropic Messages API (2025) ──────────────────────────────────

const ANTHROPIC_API_VERSION = '2025-04-14';

interface AnthropicRawResponse extends LLMResponse {
  _rawContent?: any[];
}

/** Wrapper with agentic tool-call loop */
async function callAnthropicWithTools(
  config: LLMConfig,
  systemPrompt: string,
  userMessage: string,
  onChunk?: (text: string) => void,
): Promise<LLMResponse> {
  const maxRounds = config.maxToolRounds ?? 5;
  let messages: any[] = [{ role: 'user', content: userMessage }];
  const allToolCalls: ToolCall[] = [];
  let finalResponse: AnthropicRawResponse | null = null;

  for (let round = 0; round <= maxRounds; round++) {
    const response = await callAnthropic(config, systemPrompt, messages, round === 0 ? onChunk : undefined);

    if (response.toolCalls?.length) allToolCalls.push(...response.toolCalls);

    if (!response.toolCalls?.length || !config.toolExecutor) {
      finalResponse = response;
      break;
    }

    // Add assistant response and tool results for next round
    messages.push({ role: 'assistant', content: response._rawContent });

    for (const tc of response.toolCalls) {
      let resultText: string;
      try {
        resultText = await config.toolExecutor(tc.name, tc.arguments);
      } catch (err: any) {
        resultText = `Error: ${err.message}`;
      }
      messages.push({
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: tc.id, content: resultText }],
      });
    }
  }

  if (!finalResponse) throw new Error('Max tool call rounds exceeded');
  finalResponse.toolCalls = allToolCalls.length ? allToolCalls : undefined;
  return finalResponse;
}

async function callAnthropic(
  config: LLMConfig,
  systemPrompt: string,
  messages: any[],
  onChunk?: (text: string) => void,
): Promise<AnthropicRawResponse> {
  const baseUrl = config.baseUrl || BASE_URLS.anthropic;
  const maxTokens = config.maxTokens || 8192;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-api-key': config.apiKey,
    'anthropic-version': ANTHROPIC_API_VERSION,
  };

  if (config.extendedThinking) {
    headers['anthropic-beta'] = 'interleaved-thinking-2025-05-14';
  }

  const body: Record<string, any> = {
    model: config.model,
    max_tokens: maxTokens,
    system: systemPrompt,
    messages,
  };

  if (config.extendedThinking) {
    body.thinking = { type: 'enabled', budget_tokens: config.thinkingBudget || 10000 };
  }

  if (config.tools?.length) {
    body.tools = config.tools.map(t => ({
      name: t.name,
      description: t.description,
      input_schema: {
        type: 'object',
        properties: t.parameters.properties,
        required: t.parameters.required,
      },
    }));
  }

  if (onChunk) {
    body.stream = true;

    const res = await fetch(`${baseUrl}/v1/messages`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Anthropic API error ${res.status}: ${err}`);
    }

    let content = '';
    let thinking = '';
    let inputTokens = 0;
    let outputTokens = 0;
    const toolCalls: ToolCall[] = [];
    let curToolId = '';
    let curToolName = '';
    let curToolArgs = '';

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
          const ev = JSON.parse(data);

          if (ev.type === 'content_block_start' && ev.content_block?.type === 'tool_use') {
            curToolId = ev.content_block.id || '';
            curToolName = ev.content_block.name || '';
            curToolArgs = '';
          }
          if (ev.type === 'content_block_delta') {
            if (ev.delta?.type === 'text_delta' && ev.delta?.text) {
              content += ev.delta.text;
              onChunk(ev.delta.text);
            }
            if (ev.delta?.type === 'thinking_delta' && ev.delta?.thinking) {
              thinking += ev.delta.thinking;
            }
            if (ev.delta?.type === 'input_json_delta' && ev.delta?.partial_json) {
              curToolArgs += ev.delta.partial_json;
            }
          }
          if (ev.type === 'content_block_stop' && curToolId) {
            try {
              toolCalls.push({ id: curToolId, name: curToolName, arguments: JSON.parse(curToolArgs || '{}') });
            } catch { /* skip */ }
            curToolId = ''; curToolName = ''; curToolArgs = '';
          }
          if (ev.type === 'message_delta' && ev.usage) outputTokens = ev.usage.output_tokens || 0;
          if (ev.type === 'message_start' && ev.message?.usage) inputTokens = ev.message.usage.input_tokens || 0;
        } catch { /* skip */ }
      }
    }

    return {
      content, model: config.model, inputTokens, outputTokens,
      thinking: thinking || undefined, thinkingTokens: undefined,
      toolCalls: toolCalls.length ? toolCalls : undefined,
      _rawContent: buildRawContent(content, thinking, toolCalls),
    };
  } else {
    // Non-streaming
    const res = await fetch(`${baseUrl}/v1/messages`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Anthropic API error ${res.status}: ${err}`);
    }

    const data = await res.json() as any;
    let content = '';
    let thinking = '';
    const toolCalls: ToolCall[] = [];

    for (const block of (data.content || [])) {
      if (block.type === 'text') content += block.text;
      if (block.type === 'thinking') thinking += block.thinking;
      if (block.type === 'tool_use') {
        toolCalls.push({ id: block.id, name: block.name, arguments: block.input || {} });
      }
    }

    return {
      content, model: data.model || config.model,
      inputTokens: data.usage?.input_tokens,
      outputTokens: data.usage?.output_tokens,
      thinking: thinking || undefined,
      toolCalls: toolCalls.length ? toolCalls : undefined,
      _rawContent: data.content,
    };
  }
}

function buildRawContent(content: string, thinking: string, toolCalls: ToolCall[]): any[] {
  const blocks: any[] = [];
  if (thinking) blocks.push({ type: 'thinking', thinking });
  if (content) blocks.push({ type: 'text', text: content });
  for (const tc of toolCalls) blocks.push({ type: 'tool_use', id: tc.id, name: tc.name, input: tc.arguments });
  return blocks;
}

// ─── OpenAI Responses API ────────────────────────────────────────────

async function callOpenAIResponses(
  config: LLMConfig,
  systemPrompt: string,
  userMessage: string,
  onChunk?: (text: string) => void,
): Promise<LLMResponse> {
  const baseUrl = config.baseUrl || BASE_URLS.openai;
  const maxTokens = config.maxTokens || 8192;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${config.apiKey}`,
  };

  const input: any[] = [
    { role: 'developer', content: systemPrompt },
    { role: 'user', content: userMessage },
  ];

  const tools: any[] = [];
  if (config.webSearch) tools.push({ type: 'web_search' });
  if (config.tools?.length) {
    for (const t of config.tools) {
      tools.push({
        type: 'function', name: t.name, description: t.description,
        parameters: t.parameters, strict: true,
      });
    }
  }

  const body: Record<string, any> = { model: config.model, input, max_output_tokens: maxTokens };
  if (tools.length) body.tools = tools;
  if (config.responseFormat === 'json') body.text = { format: { type: 'json_object' } };

  if (onChunk) {
    body.stream = true;

    const res = await fetch(`${baseUrl}/v1/responses`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      // Fallback to Chat Completions if Responses API not available
      if (res.status === 404) return callOpenAICompatible(config, systemPrompt, userMessage, onChunk);
      throw new Error(`OpenAI API error ${res.status}: ${err}`);
    }

    let content = '';
    let inputTokens = 0;
    let outputTokens = 0;
    const toolCalls: ToolCall[] = [];

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
        const d = line.slice(6).trim();
        if (d === '[DONE]') continue;
        try {
          const ev = JSON.parse(d);
          if (ev.type === 'response.output_text.delta' && ev.delta) { content += ev.delta; onChunk(ev.delta); }
          if (ev.type === 'response.function_call_arguments.done') {
            try { toolCalls.push({ id: ev.call_id || '', name: ev.name || '', arguments: JSON.parse(ev.arguments || '{}') }); } catch { /* skip */ }
          }
          if (ev.type === 'response.completed' && ev.response?.usage) {
            inputTokens = ev.response.usage.input_tokens || 0;
            outputTokens = ev.response.usage.output_tokens || 0;
          }
        } catch { /* skip */ }
      }
    }

    if (toolCalls.length && config.toolExecutor) {
      return handleOpenAIToolLoop(config, baseUrl, headers, body, content, toolCalls, inputTokens, outputTokens, onChunk);
    }
    return { content, model: config.model, inputTokens, outputTokens, toolCalls: toolCalls.length ? toolCalls : undefined };
  } else {
    // Non-streaming
    const res = await fetch(`${baseUrl}/v1/responses`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      if (res.status === 404) return callOpenAICompatible(config, systemPrompt, userMessage, undefined);
      throw new Error(`OpenAI API error ${res.status}: ${err}`);
    }

    const data = await res.json() as any;
    let content = '';
    const toolCalls: ToolCall[] = [];

    for (const item of (data.output || [])) {
      if (item.type === 'message') {
        for (const part of (item.content || [])) {
          if (part.type === 'output_text') content += part.text;
        }
      }
      if (item.type === 'function_call') {
        try { toolCalls.push({ id: item.call_id || item.id || '', name: item.name || '', arguments: JSON.parse(item.arguments || '{}') }); } catch { /* skip */ }
      }
    }
    if (!content && data.output_text) content = data.output_text;

    if (toolCalls.length && config.toolExecutor) {
      return handleOpenAIToolLoop(config, baseUrl, headers, body, content, toolCalls, data.usage?.input_tokens, data.usage?.output_tokens, undefined);
    }

    return {
      content, model: data.model || config.model,
      inputTokens: data.usage?.input_tokens, outputTokens: data.usage?.output_tokens,
      toolCalls: toolCalls.length ? toolCalls : undefined,
    };
  }
}

/** Agentic tool-call loop for OpenAI Responses API */
async function handleOpenAIToolLoop(
  config: LLMConfig, baseUrl: string, headers: Record<string, string>,
  origBody: Record<string, any>, partialContent: string, pending: ToolCall[],
  inTok: number | undefined, outTok: number | undefined,
  onChunk?: (text: string) => void,
): Promise<LLMResponse> {
  const maxRounds = config.maxToolRounds ?? 5;
  const all = [...pending];
  let content = partialContent;
  let inputTokens = inTok;
  let outputTokens = outTok;

  for (let round = 0; round < maxRounds && pending.length; round++) {
    const results: any[] = [];
    for (const tc of pending) {
      let r: string;
      try { r = await config.toolExecutor!(tc.name, tc.arguments); } catch (e: any) { r = `Error: ${e.message}`; }
      results.push({ type: 'function_call_output', call_id: tc.id, output: r });
    }

    const followUp: Record<string, any> = { ...origBody, input: results, stream: !!onChunk };
    const res = await fetch(`${baseUrl}/v1/responses`, { method: 'POST', headers, body: JSON.stringify(followUp) });
    if (!res.ok) { const err = await res.text(); throw new Error(`OpenAI tool follow-up error ${res.status}: ${err}`); }

    pending = [];

    if (onChunk) {
      const reader = res.body?.getReader();
      if (!reader) throw new Error('No response body');
      const dec = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop() || '';
        for (const ln of lines) {
          if (!ln.startsWith('data: ')) continue;
          const d = ln.slice(6).trim();
          if (d === '[DONE]') continue;
          try {
            const ev = JSON.parse(d);
            if (ev.type === 'response.output_text.delta' && ev.delta) { content += ev.delta; onChunk(ev.delta); }
            if (ev.type === 'response.function_call_arguments.done') {
              try { const tc = { id: ev.call_id || '', name: ev.name || '', arguments: JSON.parse(ev.arguments || '{}') }; pending.push(tc); all.push(tc); } catch { /* skip */ }
            }
            if (ev.type === 'response.completed' && ev.response?.usage) {
              inputTokens = (inputTokens || 0) + (ev.response.usage.input_tokens || 0);
              outputTokens = (outputTokens || 0) + (ev.response.usage.output_tokens || 0);
            }
          } catch { /* skip */ }
        }
      }
    } else {
      const data = await res.json() as any;
      for (const item of (data.output || [])) {
        if (item.type === 'message') { for (const p of (item.content || [])) { if (p.type === 'output_text') content += p.text; } }
        if (item.type === 'function_call') {
          try { const tc = { id: item.call_id || item.id || '', name: item.name || '', arguments: JSON.parse(item.arguments || '{}') }; pending.push(tc); all.push(tc); } catch { /* skip */ }
        }
      }
      if (data.output_text && !content) content = data.output_text;
      if (data.usage) { inputTokens = (inputTokens || 0) + (data.usage.input_tokens || 0); outputTokens = (outputTokens || 0) + (data.usage.output_tokens || 0); }
    }
  }

  return { content, model: config.model, inputTokens, outputTokens, toolCalls: all.length ? all : undefined };
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

  if (config.provider === 'openrouter') {
    headers['HTTP-Referer'] = 'https://guardlink.bugb.io';
    headers['X-Title'] = 'GuardLink CLI';
  }

  const isDeepSeekReasoner = config.provider === 'deepseek' && config.model.includes('reasoner');

  const body: Record<string, any> = {
    model: config.model,
    max_tokens: maxTokens,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage },
    ],
  };

  if (config.responseFormat === 'json') {
    body.response_format = { type: 'json_object' };
  }

  if (config.tools?.length) {
    body.tools = config.tools.map(t => ({
      type: 'function',
      function: { name: t.name, description: t.description, parameters: t.parameters },
    }));
  }

  if (onChunk) {
    body.stream = true;

    const res = await fetch(`${baseUrl}/v1/chat/completions`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`${config.provider} API error ${res.status}: ${err}`);
    }

    let content = '';
    let reasoning = '';
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
          if (delta) { content += delta; onChunk(delta); }
          const reasoningDelta = event.choices?.[0]?.delta?.reasoning_content;
          if (reasoningDelta) reasoning += reasoningDelta;
        } catch { /* skip */ }
      }
    }

    return { content, model: config.model, thinking: reasoning || undefined };
  } else {
    const res = await fetch(`${baseUrl}/v1/chat/completions`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`${config.provider} API error ${res.status}: ${err}`);
    }

    const data = await res.json() as any;
    const choice = data.choices?.[0];

    return {
      content: choice?.message?.content || '',
      model: data.model || config.model,
      inputTokens: data.usage?.prompt_tokens,
      outputTokens: data.usage?.completion_tokens,
      thinking: isDeepSeekReasoner ? (choice?.message?.reasoning_content || undefined) : undefined,
    };
  }
}
