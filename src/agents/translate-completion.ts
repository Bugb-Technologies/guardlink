/**
 * Provider completion metadata, separate from generated code and tool-result data.
 * @exposes #agent-launcher to #vacuous-pass [high] -- "readAgentCompletion could mistake exit-zero output for successful authoring despite a provider failure or refusal"
 * @mitigates #agent-launcher against #vacuous-pass using #fail-closed -- "Requires a terminal structured completion; provider failure/refusal/error signals cannot be cleared by a later success; safety counters remain telemetry"
 * @exposes #agent-launcher to #insecure-deser [medium] -- "Parses JSON/JSONL emitted by the selected author CLI"
 * @mitigates #agent-launcher against #insecure-deser using #config-validation -- "Bounded transcript, known completion shapes and control-metadata containers; tool payloads are not control signals"
 * @flows AgentProcess -> #agent-launcher via readAgentCompletion -- "Reported completion and safety metadata only; never evaluates author output"
 */
export const MAX_COMPLETION_BYTES = 8 * 1024 * 1024;
export interface AgentCompletion {
  status: 'completed' | 'failed' | 'refused' | 'safety_stopped' | 'unknown';
  safety_stops?: number;
  warnings?: string[];
  reason?: string;
}

/** Decode complete top-level records; never mine JSON out of messages or tool payloads. */
function completionRecords(stdout: string): { records: any[]; malformed: boolean } {
  const rows = (value: any): any[] => Array.isArray(value) ? value : [value];
  try { return { records: rows(JSON.parse(stdout.replace(/^\uFEFF/, ''))), malformed: false }; } catch { /* Framed stream below. */ }
  const decor = (text: string): string => {
    let i = 0;
    while (i < text.length) {
      if (/\s/.test(text[i])) { i++; continue; }
      if (text.charCodeAt(i) === 27 && text[i + 1] === '[') {
        let end = i + 2;
        while (end < text.length && text.charCodeAt(end) >= 32 && text.charCodeAt(end) <= 63) end++;
        if (text.charCodeAt(end) >= 64 && text.charCodeAt(end) <= 126) { i = end + 1; continue; }
      }
      break;
    }
    return text.slice(i);
  };
  const lines = stdout.split('\n').map(line => {
    let text = decor(line.replace(/^\uFEFF/, ''));
    text = text.replace(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+/, '');
    for (let i = 0; i < 3; i++) {
      const prefix = text.match(/^(?:\[(?:claude|codex|gemini|agent|relay|stdout|info)\]|(?:claude|codex|gemini|agent|relay|stdout|info):)\s*/i);
      if (!prefix) break;
      text = decor(text.slice(prefix[0].length));
    }
    return text;
  });
  const text = lines.join('\n');
  const records: any[] = [];
  let start = -1, quoted = false, escaped = false, malformed = false, boundary = true;
  const stack: string[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (start < 0) {
      if (/\s/.test(ch)) { if (ch === '\n') boundary = true; continue; }
      if (ch !== '{' && ch !== '[') {
        // A banner may occupy its own line; a suffix on a protocol record is corruption.
        const lineEnd = text.indexOf('\n', i);
        const line = text.slice(i, lineEnd < 0 ? undefined : lineEnd);
        if (!boundary || /[\[{].*"(?:type|response|is_error|error)"\s*:/.test(line)) malformed = true;
        const end = lineEnd; if (end < 0) break; i = end; boundary = true; continue;
      }
      start = i; quoted = false; escaped = false; stack.length = 0;
    }
    if (quoted) {
      if (ch === '\n') { malformed = true; start = -1; quoted = false; stack.length = 0; boundary = true; }
      else if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') quoted = false;
      continue;
    }
    if (ch === '"') { quoted = true; continue; }
    if (ch === '{' || ch === '[') stack.push(ch);
    else if (ch === '}' || ch === ']') {
      if (stack.pop() !== (ch === '}' ? '{' : '[')) { malformed = true; start = -1; stack.length = 0; continue; }
      if (!stack.length) {
        try { records.push(...rows(JSON.parse(text.slice(start, i + 1)))); } catch { malformed = true; }
        start = -1; boundary = false;
      }
    }
  }
  return { records, malformed: malformed || start >= 0 };
}

export function readAgentCompletion(stdout: string, provider?: 'claude' | 'codex' | 'gemini'): AgentCompletion {
  if (Buffer.byteLength(stdout) > MAX_COMPLETION_BYTES) return { status: 'failed', reason: 'Agent structured output exceeds 8 MiB' };
  const decoded = completionRecords(stdout);
  let terminal = false, pendingTurn = false;
  let failed = decoded.malformed ? 'Malformed or truncated structured completion' : '';
  let refused = '';
  let stops: number | undefined;
  let safety = false;
  let geminiAnswer = '';
  const telemetryWarnings = new Set<string>();
  const successfulStops = new Set(['end_turn', 'stop', 'stop_sequence', 'completed', 'success', 'tool_use', 'tool_calls', 'function_call']);
  const answers: string[] = [];
  const controls = (value: any, depth = 0, telemetryOnly = false): void => {
    if (!value || typeof value !== 'object' || depth > 20) return;
    for (const key of ['safety_stops', 'num_safety_stops', 'safety_stop_count', 'safetyStops']) {
      if (value[key] === undefined) continue;
      const n = value[key];
      if (typeof n === 'number' && Number.isInteger(n) && n >= 0) stops = Math.max(stops ?? 0, n);
      else telemetryWarnings.add(`Invalid provider ${key} telemetry: ${JSON.stringify(n).slice(0, 200)}`);
    }
    if (!telemetryOnly) {
      if (value.safety_stop === true) safety = true;
      for (const key of ['stop_reason', 'finish_reason', 'reason_code', 'code', 'type']) {
        if (['stop_reason', 'finish_reason'].includes(key) && value[key] != null && typeof value[key] !== 'string') failed ||= `Malformed provider ${key} metadata`;
        if (typeof value[key] === 'string' && /^(refusal|refused|safety(?:_stop|_filter)?|content_filter|policy_violation|policy_blocked|blocked)$/i.test(value[key])) {
          refused ||= `Provider reported ${key}: ${value[key]}`;
        } else if (['stop_reason', 'finish_reason'].includes(key) && typeof value[key] === 'string' && value[key] && !successfulStops.has(value[key].toLowerCase())) {
          failed ||= `Provider reported non-success ${key}: ${value[key]}`;
        }
      }
      if (value.refusal === true || (typeof value.refusal === 'string' && value.refusal.trim())) refused ||= 'Provider reported a refusal';
    }
    for (const key of ['completion', 'stats', 'metadata', 'usage']) controls(value[key], depth + 1, telemetryOnly);
    if (value.message?.role === 'assistant') {
      controls(value.message, depth + 1, telemetryOnly);
      for (const block of Array.isArray(value.message.content) ? value.message.content : []) if (block?.type === 'refusal') controls(block, depth + 1, telemetryOnly);
    }
    if (value.item?.type === 'agent_message') controls(value.item, depth + 1, telemetryOnly);
    if (value.error && typeof value.error === 'object') controls(value.error, depth + 1, telemetryOnly);
  };
  const sessions = { session_id: new Set<string>(), thread_id: new Set<string>() };
  for (const record of decoded.records) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) continue;
    // Forwarded child conversations cannot complete or refuse the parent author run.
    if (record.parent_tool_use_id != null) continue;
    const type = record.type;
    const geminiJson = type === undefined && ((typeof record.response === 'string' && record.stats && typeof record.stats === 'object') || record.error);
    const assistant = type === 'assistant' || (type === 'message' && record.role === 'assistant') || (type === 'item.completed' && record.item?.type === 'agent_message');
    const data = ['tool_use', 'tool_result', 'user', 'item.started', 'item.updated', 'item.completed'].includes(type) && !assistant;
    if (data) continue;
    controls(record, 0, true);
    const protocol = geminiJson || assistant || ['result', 'turn.started', 'turn.completed', 'turn.failed', 'thread.started', 'stream_event', 'error', 'init'].includes(type) || type === 'system';
    if (!protocol) {
      if (record.is_error === true || record.refusal || record.error || ['error', 'failed', 'refused'].includes(record.status) || /(?:^|[._-])(error|failed|refused|refusal)$/.test(String(type))) {
        controls(record);
        if (record.status === 'refused') refused ||= 'Provider reported refused status';
        failed ||= 'Unrecognized provider failure envelope';
      }
      continue;
    }
    for (const key of ['session_id', 'thread_id'] as const) {
      if (typeof record[key] === 'string' && record[key]) sessions[key].add(record[key]);
      if (sessions[key].size > 1) failed ||= `Multiple native ${key} values; cannot associate one author completion`;
    }
    const nonfatalWarning = type === 'error' && provider !== 'codex' && record.severity === 'warning';
    if (!nonfatalWarning && !['thread.started', 'init', 'system', 'stream_event'].includes(type)) controls(record);
    if (type === 'stream_event') {
      if (record.event?.type === 'message_delta') controls(record.event.delta);
      if (record.event?.type === 'message_start') controls(record.event.message);
      if (record.event?.type === 'content_block_start' && record.event.content_block?.type === 'refusal') controls(record.event.content_block);
    }
    if (type === 'turn.started') pendingTurn = true;
    if (assistant && terminal) pendingTurn = true;
    if (type === 'result') {
      const outcome = typeof record.is_error === 'boolean' || (typeof record.subtype === 'string' && !!record.subtype) || (typeof record.status === 'string' && !!record.status);
      if (!outcome) { if (record.error) failed ||= 'Provider reported an error'; continue; }
      terminal = true; pendingTurn = false;
      if (['tool_use', 'tool_calls', 'function_call'].includes(record.stop_reason || record.finish_reason)) failed ||= 'Provider result still awaits a tool';
      if (record.is_error === true || (record.subtype && record.subtype !== 'success') || (record.status && !['success', 'completed'].includes(record.status))) {
        failed ||= `Provider result: ${record.subtype && record.subtype !== 'success' ? record.subtype : record.is_error === true ? 'is_error=true' : record.status}`;
      }
      if ((record.is_error !== undefined && typeof record.is_error !== 'boolean') || (record.subtype !== undefined && typeof record.subtype !== 'string')) failed ||= 'Malformed provider outcome metadata';
      if (typeof record.result === 'string' && record.result.trim()) answers.push(record.result);
      else if (geminiAnswer) answers.push(geminiAnswer);
    }
    if (type === 'turn.completed') { terminal = true; pendingTurn = false; }
    if (type === 'turn.failed') { terminal = true; pendingTurn = false; failed ||= 'Provider turn failed'; }
    if (type === 'error') {
      if (nonfatalWarning) telemetryWarnings.add(`Provider warning: ${String(record.message || 'unspecified').slice(0, 200)}`);
      else failed ||= 'Provider stream reported an error';
    }
    if (type === 'item.completed' && record.item?.type === 'agent_message' && typeof record.item.text === 'string') answers.push(record.item.text);
    if (type === 'assistant') {
      const blocks = Array.isArray(record.message?.content) ? record.message.content : [];
      const text = blocks.filter((b: any) => b?.type === 'text' && typeof b.text === 'string').map((b: any) => b.text).join('');
      if (text) answers.push(text);
    }
    if (type === 'message' && record.role === 'assistant' && typeof record.content === 'string') geminiAnswer = record.delta ? geminiAnswer + record.content : record.content;
    if (geminiJson && typeof record.response === 'string') { terminal = true; pendingTurn = false; answers.push(record.response); }
    if (!nonfatalWarning && record.error && (geminiJson || ['result', 'turn.failed', 'error'].includes(type))) failed ||= 'Provider reported an error';
  }
  if (pendingTurn) failed ||= 'Agent stream ended with an unfinished turn';
  const answer = answers.filter(text => text.trim()).at(-1)?.trim() || '';
  const auditOnly = /\baudit[- ]only\b|\b(?:governance|organizational)[- ]only\b/i.test(answer);
  if (!auditOnly && answer.length < 1600 && !answer.includes('```') && /^(?:(?:I['’]m sorry|Sorry)[,.]?\s*(?:but\s+)?)?I(?:\s+(?:cannot|can['’]t|will not|won['’]t|am unable to)|['’]m unable to)\s+(?:help|assist|comply|provide|write|create|generate|complete)\b/i.test(answer)) refused ||= 'Agent answer opens with a refusal';
  const count = { ...(stops === undefined ? {} : { safety_stops: stops }), ...(telemetryWarnings.size ? { warnings: [...telemetryWarnings] } : {}) };
  if (safety) return { status: 'safety_stopped', ...count, reason: 'Provider reported an explicit safety stop' };
  if (refused) return { status: 'refused', ...count, reason: refused };
  if (failed) return { status: 'failed', ...count, reason: failed };
  if (!terminal) return { status: 'unknown', ...count, reason: 'Agent returned no recognized terminal structured completion' };
  return { status: 'completed', ...count };
}
