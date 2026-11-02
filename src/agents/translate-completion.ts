/**
 * Provider completion metadata, separate from generated code and tool-result data.
 * @exposes #agent-launcher to #vacuous-pass [high] -- "readAgentCompletion could mistake exit-zero output for successful authoring despite a provider safety stop"
 * @mitigates #agent-launcher against #vacuous-pass using #fail-closed -- "Requires a terminal structured completion; safety/refusal/error metadata cannot be cleared by a later success"
 * @exposes #agent-launcher to #insecure-deser [medium] -- "Parses JSON/JSONL emitted by the selected author CLI"
 * @mitigates #agent-launcher against #insecure-deser using #config-validation -- "Bounded transcript, known completion shapes and control-metadata containers; tool payloads are not control signals"
 * @flows AgentProcess -> #agent-launcher via readAgentCompletion -- "Reported completion and safety metadata only; never evaluates author output"
 */
export const MAX_COMPLETION_BYTES = 8 * 1024 * 1024;
export interface AgentCompletion {
  status: 'completed' | 'failed' | 'refused' | 'safety_stopped' | 'unknown';
  safety_stops?: number;
  reason?: string;
}

export function readAgentCompletion(stdout: string): AgentCompletion {
  if (Buffer.byteLength(stdout) > MAX_COMPLETION_BYTES) return { status: 'failed', reason: 'Agent structured output exceeds 8 MiB' };
  let records: any[];
  try { const value = JSON.parse(stdout); records = Array.isArray(value) ? value : [value]; }
  catch { records = stdout.split('\n').flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } }); }
  let terminal = false;
  let failed = '';
  let refused = '';
  let stops: number | undefined;
  let safety = false;
  const answers: string[] = [];
  const controls = (value: any, depth = 0): void => {
    if (!value || typeof value !== 'object' || depth > 20) return;
    for (const key of ['safety_stops', 'num_safety_stops', 'safety_stop_count', 'safetyStops']) {
      if (value[key] === undefined) continue;
      const n = value[key];
      if (typeof n === 'number' && Number.isInteger(n) && n >= 0) { stops = Math.max(stops ?? 0, n); if (n > 0) safety = true; }
      else failed ||= `Invalid provider ${key} metadata`;
    }
    if (value.safety_stop === true) safety = true;
    for (const key of ['stop_reason', 'finish_reason', 'reason_code', 'code', 'type']) {
      if (typeof value[key] === 'string' && /^(refusal|refused|safety(?:_stop|_filter)?|content_filter|policy_violation|policy_blocked|blocked)$/i.test(value[key])) {
        refused ||= `Provider reported ${key}: ${value[key]}`;
      }
    }
    if (value.refusal === true || (typeof value.refusal === 'string' && value.refusal.trim())) refused ||= 'Provider reported a refusal';
    // Explicit protocol metadata is authoritative. Third-party/tool result objects are not.
    for (const key of ['completion', 'stats', 'metadata', 'usage']) controls(value[key], depth + 1);
    if (value.message?.role === 'assistant') {
      controls(value.message, depth + 1);
      for (const block of Array.isArray(value.message.content) ? value.message.content : []) if (block?.type === 'refusal') controls(block, depth + 1);
    }
    if (value.item?.type === 'agent_message') controls(value.item, depth + 1);
    if (value.error && typeof value.error === 'object') controls(value.error, depth + 1);
  };
  for (const record of records) {
    if (!record || typeof record !== 'object') continue;
    controls(record);
    if (record.type === 'result') {
      terminal = true;
      if (record.is_error === true || (record.subtype && record.subtype !== 'success') || record.status === 'error') failed ||= `Provider result: ${record.subtype || record.status || 'is_error'}`;
      if (typeof record.result === 'string') answers.push(record.result);
    }
    if (record.type === 'turn.completed') terminal = true;
    if (record.type === 'turn.failed') { terminal = true; failed ||= 'Provider turn failed'; }
    if (record.type === 'item.completed' && record.item?.type === 'agent_message' && typeof record.item.text === 'string') answers.push(record.item.text);
    if (typeof record.response === 'string') { terminal = true; answers.push(record.response); }
    if (record.error && record.type !== 'item.completed') failed ||= 'Provider reported an error';
  }
  // Only a short primary answer that opens with a refusal is treated as one by wording.
  // Quoted source, tool output, code blocks and ordinary audit-only results are excluded.
  const answer = answers.at(-1)?.trim() || '';
  const auditOnly = /\baudit[- ]only\b|\b(?:governance|organizational)[- ]only\b/i.test(answer);
  if (!auditOnly && answer.length < 1600 && !answer.includes('```') && /^(?:(?:I['’]m sorry|Sorry)[,.]?\s*(?:but\s+)?)?I(?:\s+(?:cannot|can['’]t|will not|won['’]t|am unable to)|['’]m unable to)\s+(?:help|assist|comply|provide|write|create|generate|complete)\b/i.test(answer)) {
    refused ||= 'Agent answer opens with a refusal';
  }
  const count = stops === undefined ? {} : { safety_stops: stops };
  if (safety) return { status: 'safety_stopped', ...count, reason: `Provider reported ${stops ?? 'a'} safety stop(s)` };
  if (refused) return { status: 'refused', ...count, reason: refused };
  if (failed) return { status: 'failed', ...count, reason: failed };
  if (!terminal) return { status: 'unknown', ...count, reason: 'Agent returned no recognized terminal structured completion' };
  return { status: 'completed', ...count };
}
