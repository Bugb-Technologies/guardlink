/**
 * Identity metadata validation only: probe code is never evaluated.
 * @exposes #agent-launcher to #insecure-deser [medium] -- "validateProbeIdentities reads author-written JS metadata and parses the requires_identities JSON header"
 * @mitigates #agent-launcher against #insecure-deser using #config-validation -- "Bounded file input, role-map shape and exact context-profile allowlist; anonymous is reserved for a clean guest"
 * @flows AgentProcess -> #agent-launcher via validateProbeIdentities -- "Check declared identity bindings without executing probe code or rewriting template bytes"
 */
import { readFileSync, statSync } from 'node:fs';
import type { ThreatModel } from '../types/index.js';
import { matchesThreat, type TranslateContextPack } from './translate-context.js';

export function validateProbeIdentities(file: string, model: ThreatModel, context?: TranslateContextPack): string[] {
  try {
    if (statSync(file).size > 2 * 1024 * 1024) return ['Probe exceeds 2 MiB'];
    const source = readFileSync(file, 'utf8');
    const declarations = [...source.matchAll(/^\s*\/\/\s*@requires_identities:\s*(.*)$/gm)];
    if (!declarations.length) return []; // Preserve the legacy numeric identity contract.
    if (declarations.length > 1) return ['Duplicate requires_identities headers'];
    const roles: unknown = JSON.parse(declarations[0][1]);
    if (!roles || typeof roles !== 'object' || Array.isArray(roles)) return ['requires_identities must be a JSON role-to-profile-name object'];
    const available = new Set(context?.threats.filter(t => model.exposures.some(e => matchesThreat(t.id, e)))
      .flatMap(t => t.identity?.available?.map(i => i.name) || []));
    let authenticated = 0;
    const used = new Set<string>();
    for (const [role, profile] of Object.entries(roles)) {
      if (!/^[a-z][a-z0-9_]*$/.test(role) || typeof profile !== 'string' || !profile) return ['Identity roles must be lowercase snake_case keys with profile-name string values'];
      if (profile === 'anonymous') continue;
      if (used.has(profile)) return [`Authenticated profile ${JSON.stringify(profile)} is bound to multiple roles`];
      used.add(profile);
      authenticated++;
      if (!available.has(profile)) return [`Identity role ${role} names profile ${JSON.stringify(profile)} not supplied by context identity.available; never invent or substitute a binding`];
    }
    const counts = [...source.matchAll(/^\s*\/\/\s*@requires_auth_count:\s*(.*)$/gm)];
    if (counts.length > 1 || (counts.length && !/^\d+$/.test(counts[0][1].trim()))) return ['requires_auth_count must be a single nonnegative integer header'];
    if (counts.length && Number(counts[0][1]) !== authenticated) return [`requires_auth_count must equal ${authenticated} non-anonymous bindings; anonymous roles do not count as authenticated`];
    return [];
  } catch (error) { return [`Invalid probe identity metadata: ${(error as Error).message}`]; }
}
