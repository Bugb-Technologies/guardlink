/**
 * GuardLink Analyze — findings a machine can read.
 *
 * Every threat report ends with a fenced `guardlink-findings` JSON block. This
 * module parses it out of the markdown, validates the ids it names against the
 * model, renders a table from it, and strips it from the prose for display.
 *
 * @exposes #llm-client to #insecure-deser [low] cwe:CWE-502 -- "JSON.parse over a block the model wrote"
 * @mitigates #llm-client against #insecure-deser using #config-validation -- "Only plain data is read out of the parsed object; every field is coerced to a string, a number or one of a fixed set, and anything else is dropped"
 * @flows SavedReport -> #llm-client via parseFindingsBlock -- "Findings out of a saved report"
 * @comment -- "The last block wins when a report carries more than one, because a model that restated its findings restated them last"
 */
import type { ThreatModel } from '../types/index.js';

export const FINDINGS_SCHEMA = 'guardlink.findings/v1';

export type FindingStatus = 'open' | 'mitigated' | 'confirmed' | 'accepted' | 'gap';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unset';

export interface Finding {
  id: string;
  title: string;
  asset: string;
  threat: string;
  severity: FindingSeverity;
  status: FindingStatus;
  evidence: string;
  location: { file: string; line: number | null } | null;
  scenario: string;
  remediation: string;
  /** The GuardLink annotation that would reflect the fix, verbatim. */
  annotation: string;
}

export interface ParsedFindings {
  findings: Finding[];
  /** Why the block could not be used; absent when there was no block or it parsed. */
  error?: string;
  /** Whether a block was present at all. */
  present: boolean;
}

const BLOCK = /```(?:json[ \t]+)?guardlink-findings[ \t]*\r?\n([\s\S]*?)\r?\n```/g;

const STATUSES = new Set<FindingStatus>(['open', 'mitigated', 'confirmed', 'accepted', 'gap']);
const SEVS: Record<string, FindingSeverity> = { critical: 'critical', p0: 'critical', high: 'high', p1: 'high', medium: 'medium', p2: 'medium', low: 'low', p3: 'low' };

const str = (v: unknown, fallback = ''): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : fallback);

function coerce(raw: unknown, i: number): Finding | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const loc = o.location && typeof o.location === 'object' ? (o.location as Record<string, unknown>) : null;
  const line = loc && typeof loc.line === 'number' && Number.isFinite(loc.line) ? Math.max(0, Math.floor(loc.line)) : null;
  const status = str(o.status, 'open').toLowerCase();
  return {
    id: str(o.id, `F-${i + 1}`),
    title: str(o.title),
    asset: str(o.asset),
    threat: str(o.threat),
    severity: SEVS[str(o.severity).toLowerCase()] ?? 'unset',
    status: STATUSES.has(status as FindingStatus) ? (status as FindingStatus) : 'open',
    evidence: str(o.evidence),
    location: loc && typeof loc.file === 'string' && loc.file.length > 0 ? { file: loc.file, line } : null,
    scenario: str(o.scenario),
    remediation: str(o.remediation),
    annotation: str(o.annotation),
  };
}

/** The last `guardlink-findings` block in a report, parsed. */
export function parseFindingsBlock(markdown: string): ParsedFindings {
  const blocks = [...markdown.matchAll(BLOCK)];
  if (blocks.length === 0) return { findings: [], present: false };
  const body = blocks[blocks.length - 1][1];
  let data: unknown;
  try { data = JSON.parse(body); } catch (e) { return { findings: [], present: true, error: `Findings block is not valid JSON: ${(e as Error).message}` }; }
  if (!data || typeof data !== 'object') return { findings: [], present: true, error: 'Findings block is not an object' };
  const o = data as Record<string, unknown>;
  if (o.schema !== FINDINGS_SCHEMA) return { findings: [], present: true, error: `Findings block schema is ${JSON.stringify(o.schema ?? null)}, expected ${FINDINGS_SCHEMA}` };
  if (!Array.isArray(o.findings)) return { findings: [], present: true, error: 'Findings block has no findings array' };
  const findings = o.findings.map(coerce).filter((f): f is Finding => f !== null);
  return { findings, present: true };
}

/** The report with its findings block(s) removed, for display as prose. */
export function stripFindingsBlock(markdown: string): string {
  return markdown.replace(BLOCK, '').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n';
}

export interface Unresolved { id: string; field: 'asset' | 'threat'; ref: string }

const bare = (r: string): string => r.trim().replace(/^#/, '').toLowerCase();

/** Every name the model has for its assets and threats. */
function known(model: ThreatModel): { assets: Set<string>; threats: Set<string> } {
  const assets = new Set<string>();
  for (const a of model.assets) { assets.add(a.path.join('.').toLowerCase()); assets.add(a.path[a.path.length - 1].toLowerCase()); if (a.id) assets.add(a.id.toLowerCase()); }
  for (const e of model.exposures) assets.add(bare(e.asset));
  for (const m of model.mitigations) assets.add(bare(m.asset));
  for (const f of model.flows) { assets.add(bare(f.source)); assets.add(bare(f.target)); }
  const threats = new Set<string>();
  for (const t of model.threats) { threats.add(t.name.toLowerCase()); threats.add(t.canonical_name.toLowerCase()); if (t.id) threats.add(t.id.toLowerCase()); }
  for (const e of model.exposures) threats.add(bare(e.threat));
  return { assets, threats };
}

/** Findings whose asset or threat names nothing the model knows. */
export function validateFindings(findings: Finding[], model: ThreatModel): { unresolved: Unresolved[] } {
  const k = known(model);
  const unresolved: Unresolved[] = [];
  for (const f of findings) {
    if (f.asset && !k.assets.has(bare(f.asset))) unresolved.push({ id: f.id, field: 'asset', ref: f.asset });
    if (f.threat && !k.threats.has(bare(f.threat))) unresolved.push({ id: f.id, field: 'threat', ref: f.threat });
  }
  return { unresolved };
}

const cell = (s: string): string => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

/** A markdown table of the findings, severity first. */
export function renderFindingsTable(findings: Finding[]): string {
  if (findings.length === 0) return '';
  const rank: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, unset: 4 };
  const rows = [...findings].sort((a, b) => rank[a.severity] - rank[b.severity] || a.id.localeCompare(b.id));
  const lines = ['| ID | Severity | Status | Asset | Threat | Finding | Location |', '|---|---|---|---|---|---|---|'];
  for (const f of rows) {
    const loc = f.location ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}` : '';
    lines.push(`| ${cell(f.id)} | ${f.severity} | ${f.status} | ${cell(f.asset)} | ${cell(f.threat)} | ${cell(f.title)} | ${cell(loc)} |`);
  }
  return lines.join('\n');
}
