/**
 * Repository attack-surface facts; names and locations without payloads.
 * @exposes #agent-config to #insecure-deser [medium] -- "configSurfaces passes repository workflow text to parseDocument and metadata to parseJsonc"
 * @mitigates #agent-config against #insecure-deser using #config-validation -- "YAML is parsed as data with alias limits; mappings and recognized fields are checked, never evaluated"
 * @mitigates #agent-config against #api-key-exposure using #key-redaction -- "Exports event, key and action names only; no workflow prompts, endpoint queries, state paths or script bodies"
 */
import { parseDocument, LineCounter } from 'yaml';
import { parseJsonc, asObject, asString, type JsonValue } from './jsonc.js';
import type { AgentConfigSurface } from '../types/index.js';
import type { DiscoveredFile } from './discover.js';

const ACTIONS: Record<string, string> = {
  'anthropics/claude-code-action': 'claude-code',
  'openai/codex-action': 'codex',
  'google-github-actions/run-gemini-cli': 'gemini-cli',
};
export function configSurfaces(file: DiscoveredFile, text: string): AgentConfigSurface[] {
  if (file.scope === 'fixture') return [];
  const rows: AgentConfigSurface[] = [];
  const add = (family: AgentConfigSurface['family'], harness: string, pointer: string, line: number, names: string[], details: AgentConfigSurface['details'] = {}) => rows.push({ family, harness, file: file.path, line, pointer, scope: file.scope, names, details });
  if (file.kind === 'ci-workflow') {
    const counter = new LineCounter();
    const doc = parseDocument(text, { lineCounter: counter, uniqueKeys: true });
    if (doc.errors.length) throw new Error('Invalid workflow YAML');
    const d = asObject(doc.toJS({ maxAliasCount: 50 }) as JsonValue) ?? {};
    const events = typeof d.on === 'string' ? [d.on] : Array.isArray(d.on) ? d.on.filter((x): x is string => typeof x === 'string') : Object.keys(asObject(d.on) ?? {});
    const jobs = asObject(d.jobs) ?? {};
    for (const [job, value] of Object.entries(jobs)) {
      const j = asObject(value); if (!j || !Array.isArray(j.steps)) continue;
      j.steps.forEach((value, i) => {
        const step = asObject(value); if (!step) return;
        const uses = asString(step.uses); if (!uses) return;
        const action = uses.split('@')[0].toLowerCase(), harness = ACTIONS[action];
        if (!harness) return;
        const node = doc.getIn(['jobs',job,'steps',i,'uses'], true) as { range?: number[] } | undefined;
        const line = counter.linePos(node?.range?.[0] ?? 0).line;
        const permissionValue = j.permissions ?? d.permissions;
        const permissions = asObject(permissionValue);
        add('ci-agent-workflow', harness, `/jobs/${job.replace(/~/g,'~0').replace(/\//g,'~1')}/steps/${i}/uses`, line, [action], {
          events, pinned: /^[a-f0-9]{40}$/i.test(uses.split('@')[1] ?? ''),
          write_permissions: permissionValue === 'write-all' ? ['*'] : Object.entries(permissions ?? {}).filter(([,v]) => v === 'write').map(([k]) => k),
          untrusted_context: /github\.event\.(?:issue|comment|pull_request|review)/.test(JSON.stringify(step.with ?? {})),
          privileged_trigger: events.includes('pull_request_target') || events.includes('workflow_run'),
        });
      });
    }
  }
  if (file.kind === 'toolchain') {
    const d = parseJsonc(text);
    for (const [name, command] of Object.entries(asObject(asObject(d.value)?.scripts) ?? {})) {
      if (!['preinstall','install','postinstall','prepare','prepublish'].includes(name) || typeof command !== 'string' || !command) continue;
      add('pre-trust-toolchain', 'npm', `/scripts/${name}`, d.lines.get(`/scripts/${name}`) ?? 1, [name], { invocation: 'package-manager', workspace_trust_required: false });
    }
  }
  if (file.kind === 'trust-state') {
    const d = parseJsonc(text);
    // State copied into a repository is a review item, never a grant of trust.
    const walk = (value: JsonValue, pointer: string, depth: number) => {
      if (depth > 64) return;
      for (const [key,v] of Object.entries(asObject(value) ?? {})) {
        const p = `${pointer}/${key.replace(/~/g,'~0').replace(/\//g,'~1')}`;
        if (['hasTrustDialogAccepted','isTrusted','trustedFolders'].includes(key)) add('trust-spoofing', 'claude-code', '/state/' + key, d.lines.get(p) ?? 1, [key], { repository_state_only: true });
        if (v && typeof v === 'object') walk(v,p,depth+1);
      }
    };
    walk(d.value,'',0);
  }
  // Deep-link payloads remain inert and are not decoded or retained.
  if (['instructions','command','subagent','skill','links'].includes(file.kind)) {
    for (const m of text.matchAll(/cursor:\/\/anysphere\.cursor-deeplink\/(mcp\/install|prompt|command)\b/g)) add('deeplink', 'cursor', '/links', text.slice(0,m.index).split('\n').length, [m[1]], { payload_withheld: true });
  }
  return rows;
}
