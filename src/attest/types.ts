/** Public observation contract; names and hashes only, never prompts or credentials. */
export interface ObservedIdentity {
  actor: string;
  server?: string;
  harness?: string;
  file?: string;
  scope?: 'root' | 'nested' | 'packaged' | 'fixture';
}
export interface ObservedTool {
  name: string;
  description_sha256: string | null;
  description_unknown?: string;
  claim_keys?: string[];
  hints?: { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean; idempotentHint?: boolean };
}
export interface Observation {
  identity: ObservedIdentity;
  source: 'static' | 'introspection' | 'remote' | 'otel' | 'probe';
  window?: { from: string; to: string };
  coverage: {
    available: 'complete' | 'partial' | 'unknown' | 'not_collected';
    called: 'complete' | 'partial' | 'unknown' | 'not_collected';
    truncated: boolean;
    reason?: string;
  };
  tools_available: ObservedTool[];
  tools_called: { name: string; count: number; claim_keys?: string[] }[];
}
export interface ObservedReach {
  schema: 'guardlink.observed-reach/v1';
  observations: Observation[];
}
/** Human maintained, local comparison baseline. No command creates or updates it. */
export interface ToolPins {
  schema: 'guardlink.tool-pins/v1';
  pins: { identity: ObservedIdentity; name: string; description_sha256: string }[];
}
