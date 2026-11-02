/**
 * Author-supplied proof plans are review data, never engine proof.
 * @exposes #agent-launcher to #insecure-deser [medium] -- "readConversionPlan parses the author's conversion.json"
 * @mitigates #agent-launcher against #insecure-deser using #config-validation -- "readConversionPlan checks version, source identity, unique written-file coverage and bounded text fields"
 * @exposes #agent-launcher to #dos [medium] -- "readConversionPlan reads an author-written manifest"
 * @mitigates #agent-launcher against #dos using #resource-limits -- "readConversionPlan refuses symlinks, files above 64 KiB and more than 256 entries"
 * @flows AgentProcess -> #agent-launcher via readConversionPlan -- "Declared oracle routes or unsupported reasons; nothing is executed or adjudicated"
 */
import { lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { TranslateSource } from './translate-source.js';

export interface ConversionOracle {
  template: string;
  oracle: string;
  rationale: string;
  prerequisites: string[];
}
export type ConversionProofPlan =
  | { status: 'declared'; probes: ConversionOracle[]; attribution_warning?: string }
  | { status: 'unsupported' | 'missing' | 'invalid'; reason: string };

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected a JSON object');
  return value as Record<string, unknown>;
}
function text(value: unknown, field: string, max = 4000): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`Invalid ${field}: expected nonempty text up to ${max} characters`);
  return value;
}

export function readConversionPlan(dir: string, source: TranslateSource, written: string[]): ConversionProofPlan {
  const file = resolve(dir, 'conversion.json');
  try {
    const stat = lstatSync(file, { throwIfNoEntry: false });
    if (!stat) return { status: 'missing', reason: 'Missing conversion.json: declare an engine oracle and its prerequisites, or explain why no supported proof route exists' };
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024) throw new Error('conversion.json must be a regular file up to 64 KiB');
    const encoded = readFileSync(file);
    if (encoded.length > 64 * 1024) throw new Error('conversion.json exceeds 64 KiB');
    const plan = object(JSON.parse(encoded.toString('utf8')));
    if (plan.version !== 1 || !Array.isArray(plan.sources) || plan.sources.length > 256) throw new Error('Expected conversion.json version 1 with a sources array (at most 256 entries)');
    const entries = plan.sources.map(object).filter(entry => entry.source === source.path);
    if (entries.length !== 1) throw new Error('conversion.json must contain exactly one entry for the source path');
    const entry = entries[0];
    if (source.threat_ref ? entry.threat_ref !== source.threat_ref : entry.threat_ref != null) {
      throw new Error(`conversion.json threat_ref must preserve ${JSON.stringify(source.threat_ref ?? null)}; never invent a source threat link`);
    }
    if (entry.unsupported_reason !== undefined) {
      if (Array.isArray(entry.probes) && entry.probes.length) throw new Error('Declare probes or unsupported_reason, not both');
      return { status: 'unsupported', reason: text(entry.unsupported_reason, 'unsupported_reason') };
    }
    if (!Array.isArray(entry.probes) || !entry.probes.length || entry.probes.length > 256) throw new Error('Expected probes with declared oracle routes, or unsupported_reason');
    const remaining = new Set(written);
    const probes = entry.probes.map(value => {
      const row = object(value);
      const template = resolve(dir, text(row.file, 'probe file'));
      // Manifest paths are never opened: only inventoried regular files can be named.
      if (!remaining.delete(template)) throw new Error(`Probe file is duplicate or was not written by this conversion: ${JSON.stringify(row.file)}`);
      const prerequisites = row.prerequisites ?? [];
      if (!Array.isArray(prerequisites) || prerequisites.length > 64) throw new Error('Invalid oracle prerequisites');
      return { template, oracle: text(row.oracle, 'oracle', 200), rationale: text(row.rationale, 'rationale'),
        prerequisites: prerequisites.map(value => text(value, 'prerequisite', 1000)) };
    });
    if (remaining.size) throw new Error('Every written probe must have an oracle route in conversion.json');
    return { status: 'declared', probes, ...(source.threat_ref ? {} : {
      attribution_warning: 'Source has no @guardlink_threat; a template id is descriptive only and does not establish a threat link',
    }) };
  } catch (error) {
    return { status: 'invalid', reason: `Invalid conversion.json: ${(error as Error).message}` };
  }
}
