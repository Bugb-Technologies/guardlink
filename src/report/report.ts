/**
 * GuardLink Report — Markdown report generator.
 * Produces a human-readable threat model report with
 * embedded Mermaid diagram, finding tables, and coverage stats.
 *
 * @comment -- "Pure function: transforms ThreatModel to markdown string"
 * @comment -- "No file I/O; caller (CLI/MCP) handles write"
 * @comment -- "A model narrowed by --feature carries filtered_by_features, and every heading, caption and empty-state sentence here is scoped from it: a report that reads as project-wide while describing one feature is a wrong answer about what is and is not covered, not a cosmetic problem"
 * @flows FeatureName -> #report via filtered_by_features -- "@feature names reach the title, every heading and the footer"
 * @comment -- "Feature names are model data and land in markdown text, never in HTML or a shell — the markdown consumer escapes; the two Mermaid titles that do need escaping carry their own @mitigates"
 * @flows ThreatModel -> #report via generateReport -- "Model input"
 * @flows #report -> Markdown via return -- "Report output"
 */

import type { ThreatModel, ThreatModelExposure, ThreatModelEntitlement, Severity } from '../types/index.js';
import { generateMermaid } from './mermaid.js';
import { generateSequenceDiagram } from './sequence.js';
import { canonicalizeModelOrder } from '../parser/canonical-order.js';
import { findUnmitigatedExposures, normalizeRef } from '../parser/coverage.js';
import { normalizeName } from '../parser/normalize.js';
import { entitlementDemotionBlockers } from '../parser/parse-project.js';

// ═══════════════════════════════════════════════════════════════════════
// Feature slice — is this document the project, or one slice of it?
// ═══════════════════════════════════════════════════════════════════════

/**
 * `filterByFeature` sets `filtered_by_features` on the model it returns; a
 * whole-project model does not carry the field.
 *
 * Read structurally rather than off `ThreatModel` so this renderer compiles and
 * behaves identically whether or not the field is declared on the type, and so
 * a hand-built model or a report JSON written before the field existed takes
 * the unfiltered path rather than throwing.
 */
type PossiblyFiltered = ThreatModel & { filtered_by_features?: string[] };

/** What the document is about, decided once and consulted by every emitter. */
interface Slice {
  /** True when the model describes one or more features, not the project. */
  readonly active: boolean;
  /** The feature names, as the caller spelled them. */
  readonly names: string[];
  /** `"Dashboard"` / `"Dashboard", "Login"` — quoted so an odd name is visible. */
  readonly quoted: string;
  /** Appended to every `##` heading so a mid-document screenshot still says so. */
  readonly headingSuffix: string;
  /** Sentence subject: `the "Dashboard" feature` / `this project`. */
  readonly noun: string;
}

/**
 * The document's scope.
 *
 * The failure this exists to stop: `report . --feature "Dashboard"` printed
 * `Files scanned: 87 | Annotations: 442` (the project) directly above
 * `| Assets | 1 |` (the feature), and said nowhere that it was filtered. Every
 * count in between was read as project-wide.
 */
function sliceOf(model: ThreatModel): Slice {
  const raw = (model as PossiblyFiltered).filtered_by_features;
  const names = Array.isArray(raw)
    ? raw.filter((n): n is string => typeof n === 'string' && n.trim().length > 0)
    : [];
  const quoted = names.map(n => `"${n}"`).join(', ');
  return {
    active: names.length > 0,
    names,
    quoted,
    headingSuffix: names.length === 0
      ? ''
      : ` — feature${names.length > 1 ? 's' : ''} ${quoted}`,
    noun: names.length === 0
      ? 'this project'
      : `the ${quoted} feature${names.length > 1 ? 's' : ''}`,
  };
}

/**
 * A top-level heading, carrying the slice.
 *
 * Repeated on every section on purpose. One banner at the top is invisible to
 * the reader who lands mid-document from a link, scrolls past it, or screenshots
 * a single table — which is the normal way a table from this report travels.
 */
function h2(title: string, slice: Slice): string {
  return `## ${title}${slice.headingSuffix}`;
}

/**
 * An empty-state sentence, scoped.
 *
 * `_No trust boundaries defined._` printed under a feature heading is a claim
 * about the project that a filtered model cannot support — the boundaries may
 * all be annotated one directory away. Under a filter the sentence names the
 * scope and says how to check; unfiltered it returns `whole` verbatim, so the
 * normal report is byte-for-byte what it was.
 */
function nothingFound(what: string, slice: Slice, whole: string): string {
  return slice.active
    ? `_No ${what} in ${slice.noun}. This is a filtered view — run \`guardlink report\` without \`--feature\` before concluding the project has none._`
    : whole;
}

/**
 * D23 — canonicalise at the emission boundary. See generateMermaid for the why;
 * the report embeds two diagrams and its own tables, all of which inherited
 * glob order.
 */
export function generateReport(rawModel: ThreatModel): string {
  const model = canonicalizeModelOrder(rawModel);
  const slice = sliceOf(model);
  const lines: string[] = [];

  // ── Pre-compute shared data ──
  // D57: raw pair set. The headline "Unmitigated exposures | N (…critical…)"
  // read `9 (0 critical)` on a repo with a live critical SQL injection.
  const unmitigated = findUnmitigatedExposures(model);

  const severityCounts = countBySeverity(unmitigated);
  const hasAI = detectAI(model);

  // ── Header ──
  // The slice goes in the title, not only in a banner: the title is what a link
  // preview, a PDF header and a file name carry.
  lines.push(slice.active
    ? `# Threat Model Report — ${model.project} — feature slice ${slice.quoted}`
    : `# Threat Model Report — ${model.project}`);
  lines.push('');
  lines.push(`> Generated: ${model.generated_at}  `);
  if (slice.active) {
    lines.push(`> **⚠ FEATURE SLICE — filtered to ${slice.quoted}**`);
    lines.push('>');
    lines.push(`> This is **not** a threat model of \`${model.project}\`. Every count, table and diagram`);
    lines.push(`> below describes only ${slice.noun}; anything annotated elsewhere in the repository is`);
    lines.push('> absent, including exposures. Sections marked _project-wide_ are the exceptions and');
    lines.push('> say so in their heading.');
    lines.push('>');
    lines.push(`> Run \`guardlink report\` without \`--feature\` for the whole project.`);
    lines.push('');
    // Relabelled, not just re-valued. `filterByFeature` scopes these two counts
    // to the feature, so "Files scanned" would still read as the repo walk.
    lines.push(`> Files in slice: ${model.source_files} | Annotations in slice: ${model.annotations_parsed}`);
  } else {
    lines.push(`> Files scanned: ${model.source_files} | Annotations: ${model.annotations_parsed}`);
  }
  if (model.metadata?.guardlink_version) {
    lines.push(`> GuardLink version: ${model.metadata.guardlink_version}`);
  }
  if (model.metadata?.commit_sha) {
    lines.push(`> Commit: ${model.metadata.commit_sha}${model.metadata.branch ? ` (${model.metadata.branch})` : ''}`);
  }
  lines.push('');

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 1: Application Overview
  // ══════════════════════════════════════════════════════════════════════
  lines.push(h2('Application Overview', slice));
  lines.push('');
  emitApplicationOverview(model, unmitigated, severityCounts, hasAI, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 2: Scope
  // ══════════════════════════════════════════════════════════════════════
  lines.push(h2('Scope of This Threat Model', slice));
  lines.push('');
  emitScope(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 3: Architecture
  // ══════════════════════════════════════════════════════════════════════
  lines.push(h2('Architecture', slice));
  lines.push('');
  emitArchitecture(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 4: Key Flows & Sequence
  // ══════════════════════════════════════════════════════════════════════
  if (model.flows.length > 0) {
    lines.push(h2('Key Flows & Sequence', slice));
    lines.push('');
    emitKeyFlows(model, lines);
  }

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 5: Data Inventory
  // ══════════════════════════════════════════════════════════════════════
  if (model.data_handling.length > 0 || model.assets.length > 0) {
    lines.push(h2('Data Inventory', slice));
    lines.push('');
    emitDataInventory(model, hasAI, lines);
  }

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 6: Roles & Access
  // ══════════════════════════════════════════════════════════════════════
  lines.push(h2('Roles & Access', slice));
  lines.push('');
  emitRolesAccess(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 7: Dependencies
  // ══════════════════════════════════════════════════════════════════════
  lines.push(h2('Dependencies', slice));
  lines.push('');
  emitDependencies(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 8: Secrets, Keys & Credential Management
  // ══════════════════════════════════════════════════════════════════════
  lines.push(h2('Secrets, Keys & Credential Management', slice));
  lines.push('');
  emitSecretsManagement(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 9: Logging, Monitoring & Audit
  // ══════════════════════════════════════════════════════════════════════
  lines.push(h2('Logging, Monitoring & Audit', slice));
  lines.push('');
  emitLoggingAudit(model, lines);

  // ══════════════════════════════════════════════════════════════════════
  // SECTION 10: AI/ML System Details (conditional)
  // ══════════════════════════════════════════════════════════════════════
  if (hasAI) {
    lines.push(h2('AI/ML System Details', slice));
    lines.push('');
    emitAIDetails(model, lines);
  }

  // ══════════════════════════════════════════════════════════════════════
  // EXISTING SECTIONS: Executive Summary + Findings
  // ══════════════════════════════════════════════════════════════════════

  // ── Executive Summary ──
  lines.push(h2('Executive Summary', slice));
  lines.push('');
  if (slice.active) {
    lines.push(`Counts below are **scoped to ${slice.quoted}**, not to \`${model.project}\`.`);
    lines.push('');
  }

  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  // Inside the table, because this table is the part of the report that travels
  // on its own — pasted into a ticket, screenshotted into a review.
  if (slice.active) lines.push(`| **Scope** | **feature${slice.names.length > 1 ? 's' : ''} ${slice.quoted}** |`);
  lines.push(`| Assets | ${model.assets.length} |`);
  lines.push(`| Threats defined | ${model.threats.length} |`);
  lines.push(`| Controls defined | ${model.controls.length} |`);
  lines.push(`| Active mitigations | ${model.mitigations.length} |`);
  lines.push(`| Accepted risks | ${model.acceptances.length} |`);
  lines.push(`| **Unmitigated exposures** | **${unmitigated.length}** |`);
  if ((model.confirmed || []).length > 0) lines.push(`| **🔴 Confirmed exploitable** | **${model.confirmed.length}** |`);
  if (severityCounts.critical > 0) lines.push(`| ↳ Critical (P0) | ${severityCounts.critical} |`);
  if (severityCounts.high > 0) lines.push(`| ↳ High (P1) | ${severityCounts.high} |`);
  if (severityCounts.medium > 0) lines.push(`| ↳ Medium (P2) | ${severityCounts.medium} |`);
  if (severityCounts.low > 0) lines.push(`| ↳ Low (P3) | ${severityCounts.low} |`);
  lines.push(`| Data flows | ${model.flows.length} |`);
  lines.push(`| Trust boundaries | ${model.boundaries.length} |`);
  lines.push(`| Risk transfers | ${model.transfers.length} |`);
  lines.push(`| Validations | ${model.validations.length} |`);
  lines.push(`| Ownership records | ${model.ownership.length} |`);
  if (model.shields.length > 0) lines.push(`| Shielded regions | ${model.shields.length} |`);
  lines.push('');

  // ── Threat Model Diagram ──
  lines.push(h2('Threat Model Diagram', slice));
  lines.push('');
  lines.push('```mermaid');
  lines.push(generateMermaid(model));
  lines.push('```');
  lines.push('');

  // ── Unmitigated Exposures ──
  if (unmitigated.length > 0) {
    lines.push(h2('Unmitigated Exposures', slice));
    lines.push('');
    lines.push('These exposures have no matching `@mitigates` or `@accepts` and require attention.');
    if (slice.active) {
      lines.push('');
      lines.push(`Only exposures annotated in ${slice.noun} are listed — this is not the project's open-finding count.`);
    }
    lines.push('');
    lines.push('| Severity | Asset | Threat | Description | Location |');
    lines.push('|----------|-------|--------|-------------|----------|');
    for (const e of sortBySeverity(unmitigated)) {
      const sev = severityBadge(e.severity);
      const desc = e.description ? truncate(e.description, 60) : '—';
      const loc = `${e.location.file}:${e.location.line}`;
      lines.push(`| ${sev} | ${e.asset} | ${e.threat} | ${desc} | ${loc} |`);
    }
    lines.push('');
  }

  // ── Confirmed Exploitable ──
  if ((model.confirmed || []).length > 0) {
    lines.push(h2('🔴 Confirmed Exploitable', slice));
    lines.push('');
    lines.push('These threats have been verified through testing — **not false positives**. Immediate remediation required.');
    lines.push('');
    lines.push('| Severity | Asset | Threat | Evidence | Location |');
    lines.push('|----------|-------|--------|----------|----------|');
    for (const c of model.confirmed) {
      const sev = severityBadge(c.severity);
      const desc = c.description ? truncate(c.description, 60) : '—';
      lines.push(`| ${sev} | ${c.asset} | ${c.threat} | ${desc} | ${c.location.file}:${c.location.line} |`);
    }
    lines.push('');
  }

  // ── Accepted Risks ──
  if (model.acceptances.length > 0) {
    lines.push(h2('Accepted Risks', slice));
    lines.push('');
    lines.push('| Asset | Threat | Rationale | Location |');
    lines.push('|-------|--------|-----------|----------|');
    for (const a of model.acceptances) {
      const desc = a.description ? truncate(a.description, 60) : '—';
      lines.push(`| ${a.asset} | ${a.threat} | ${desc} | ${a.location.file}:${a.location.line} |`);
    }
    lines.push('');
  }

  // ── Active Mitigations ──
  if (model.mitigations.length > 0) {
    lines.push(h2('Active Mitigations', slice));
    lines.push('');
    lines.push('| Asset | Threat | Control | Description | Location |');
    lines.push('|-------|--------|---------|-------------|----------|');
    for (const m of model.mitigations) {
      const desc = m.description ? truncate(m.description, 50) : '—';
      const ctrl = m.control || '—';
      lines.push(`| ${m.asset} | ${m.threat} | ${ctrl} | ${desc} | ${m.location.file}:${m.location.line} |`);
    }
    lines.push('');
  }

  // ── Trust Boundaries ──
  if (model.boundaries.length > 0) {
    lines.push(h2('Trust Boundaries', slice));
    lines.push('');
    lines.push('| Side A | Side B | Boundary ID | Description | Location |');
    lines.push('|--------|--------|-------------|-------------|----------|');
    for (const b of model.boundaries) {
      const desc = b.description ? truncate(b.description, 50) : '—';
      const id = b.id || '—';
      lines.push(`| ${b.asset_a} | ${b.asset_b} | ${id} | ${desc} | ${b.location.file}:${b.location.line} |`);
    }
    lines.push('');
  }

  // ── Data Flows ──
  if (model.flows.length > 0) {
    lines.push(h2('Data Flows', slice));
    lines.push('');
    lines.push('| Source | Target | Mechanism | Description |');
    lines.push('|--------|--------|-----------|-------------|');
    for (const f of model.flows) {
      const mech = f.mechanism || '—';
      const desc = f.description ? truncate(f.description, 50) : '—';
      lines.push(`| ${f.source} | ${f.target} | ${mech} | ${desc} |`);
    }
    lines.push('');
  }

  // ── Data Handling ──
  if (model.data_handling.length > 0) {
    lines.push(h2('Data Classification', slice));
    lines.push('');
    lines.push('| Asset | Classification | Description |');
    lines.push('|-------|---------------|-------------|');
    for (const h of model.data_handling) {
      const desc = h.description ? truncate(h.description, 60) : '—';
      lines.push(`| ${h.asset} | ${classificationBadge(h.classification)} | ${desc} |`);
    }
    lines.push('');
  }

  // ── Risk Transfers ──
  if (model.transfers.length > 0) {
    lines.push(h2('Risk Transfers', slice));
    lines.push('');
    lines.push('| Source | Threat | Target | Description | Location |');
    lines.push('|--------|--------|--------|-------------|----------|');
    for (const t of model.transfers) {
      const desc = t.description ? truncate(t.description, 50) : '—';
      lines.push(`| ${t.source} | ${t.threat} | ${t.target} | ${desc} | ${t.location.file}:${t.location.line} |`);
    }
    lines.push('');
  }

  // ── Validations ──
  if (model.validations.length > 0) {
    lines.push(h2('Validations', slice));
    lines.push('');
    lines.push('| Control | Asset | Description | Location |');
    lines.push('|---------|-------|-------------|----------|');
    for (const v of model.validations) {
      const desc = v.description ? truncate(v.description, 50) : '—';
      lines.push(`| ${v.control} | ${v.asset} | ${desc} | ${v.location.file}:${v.location.line} |`);
    }
    lines.push('');
  }

  // ── Ownership ──
  if (model.ownership.length > 0) {
    lines.push(h2('Ownership', slice));
    lines.push('');
    for (const o of model.ownership) {
      const desc = o.description ? ` — ${o.description}` : '';
      lines.push(`- **${o.asset}** owned by **${o.owner}**${desc} (${o.location.file}:${o.location.line})`);
    }
    lines.push('');
  }

  // ── Audit Items ──
  if (model.audits.length > 0) {
    lines.push(h2('Audit Items', slice));
    lines.push('');
    for (const a of model.audits) {
      const desc = a.description || 'Needs review';
      lines.push(`- **${a.asset}** — ${desc} (${a.location.file}:${a.location.line})`);
    }
    lines.push('');
  }

  // ── Entitlements ──
  // Printed with the citation, and with the demotion reason spelled out. §3.3:
  // an over-grant is the failure mode that matters, and the only way it gets
  // caught is a human reading the sentence and disagreeing with it.
  if ((model.entitlements || []).length > 0) {
    lines.push(h2('Entitlements', slice));
    lines.push('');
    lines.push('Capabilities that a principal is claimed to hold **by design**. An entitlement never');
    lines.push('suppresses a finding and never gates testing — it only changes what downstream triage');
    lines.push('recommends. Each claim must cite the authorization code that grants it; an uncited');
    lines.push('claim is inert and has no effect.');
    if (slice.active) {
      lines.push('');
      lines.push(`Only claims written in ${slice.noun} are listed. A principal may hold further`);
      lines.push('entitlements declared under another feature.');
    }
    lines.push('');
    lines.push('| Actor | Capability | On asset | Against threat | Citation | Effect |');
    lines.push('|-------|------------|----------|----------------|----------|--------|');
    for (const en of model.entitlements!) {
      // Both halves of the join get their own column, so two claims differing
      // only by threat cannot render identically (§9.3), and a missing half is
      // an empty cell rather than an absent clause a reader has to notice.
      const cite = en.citation ? `\`${en.citation.raw}\`` : '**none**';
      lines.push(`| ${en.actor} | \`${en.capability}\` | ${en.asset || '—'} | ${en.threat || '—'} | ${cite} | ${demotionEffect(en)} |`);
    }
    lines.push('');

    // Spelled out per claim underneath, with the description, because the table
    // is the index and the sentence is what a reviewer disagrees with (§3.3).
    for (const en of model.entitlements!) {
      const scope = `${en.asset ? ` on ${en.asset}` : ''}${en.threat ? ` against ${en.threat}` : ''}`;
      const cite = en.citation ? `cites \`${en.citation.raw}\`` : '**uncited — inert**';
      const blockers = entitlementDemotionBlockers(en);
      const gap = blockers.length > 0 ? ` — **${demotionEffect(en)}**` : '';
      const desc = en.description ? ` — ${en.description}` : '';
      lines.push(`- **${en.actor}** entitled to \`${en.capability}\`${scope} — ${cite}${gap}${desc} (${en.location.file}:${en.location.line})`);
    }
    lines.push('');

    // Counted from the shared predicate rather than from `inert` alone: a cited
    // claim that names no threat is equally unable to demote, and reporting only
    // the uncited ones understates how many claims do nothing.
    const ineffective = model.entitlements!.filter(e => entitlementDemotionBlockers(e).length > 0).length;
    if (ineffective > 0) {
      lines.push(`⚠ ${ineffective} of ${model.entitlements!.length} entitlement(s) cannot demote any finding — uncited, or missing a half of the \`(actor, asset, threat)\` join.`);
      lines.push('');
    }
  }

  // ── Assumptions ──
  if (model.assumptions.length > 0) {
    lines.push(h2('Assumptions', slice));
    lines.push('');
    lines.push('These are unverified assumptions that should be periodically reviewed.');
    lines.push('');
    for (const a of model.assumptions) {
      const desc = a.description || 'Unverified assumption';
      lines.push(`- **${a.asset}** — ${desc} (${a.location.file}:${a.location.line})`);
    }
    lines.push('');
  }

  // ── Shielded Regions ──
  if (model.shields.length > 0) {
    lines.push(h2('Shielded Regions', slice));
    lines.push('');
    lines.push('Code regions where annotations are intentionally suppressed via `@shield`.');
    lines.push('');
    for (const s of model.shields) {
      const reason = s.reason || 'No reason provided';
      lines.push(`- ${reason} (${s.location.file}:${s.location.line})`);
    }
    lines.push('');
  }

  // ── Features ──
  if (model.features.length > 0) {
    const uniqueFeatures = new Map<string, { name: string; files: Set<string>; description?: string }>();
    for (const f of model.features) {
      const key = f.feature.toLowerCase();
      if (!uniqueFeatures.has(key)) {
        uniqueFeatures.set(key, { name: f.feature, files: new Set(), description: f.description });
      }
      uniqueFeatures.get(key)!.files.add(f.location.file);
    }
    // Under a filter this table lists only the feature(s) selected — it is a
    // record of the filter, not of the project's feature inventory, and saying
    // "annotations are tagged with the following features" would read as the
    // latter.
    lines.push(h2('Feature Tags', slice));
    lines.push('');
    lines.push(slice.active
      ? `This report was filtered to the feature(s) below. \`guardlink features\` lists every feature in \`${model.project}\`.`
      : 'Annotations are tagged with the following features via `@feature`.');
    lines.push('');
    lines.push('| Feature | Files | Description |');
    lines.push('|---------|-------|-------------|');
    for (const [, entry] of [...uniqueFeatures.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name))) {
      const desc = entry.description ? truncate(entry.description, 60) : '—';
      lines.push(`| ${entry.name} | ${entry.files.size} | ${desc} |`);
    }
    lines.push('');
  }

  // ── Developer Comments ──
  if (model.comments.length > 0) {
    lines.push(h2('Developer Comments', slice));
    lines.push('');
    lines.push('Security-relevant notes left by developers via `@comment`.');
    lines.push('');
    for (const c of model.comments) {
      const desc = c.description || 'No description';
      lines.push(`- ${desc} (${c.location.file}:${c.location.line})`);
    }
    lines.push('');
  }

  // ── Footer ──
  lines.push('---');
  lines.push(slice.active
    ? `*Generated from security annotations on ${model.generated_at}, filtered to feature${slice.names.length > 1 ? 's' : ''} ${slice.quoted} — not a whole-project threat model.*`
    : `*Generated from security annotations on ${model.generated_at}.*`);

  return lines.join('\n');
}

/**
 * Whether this claim is allowed to demote a finding, in the words a reviewer
 * needs. Delegates the decision to `entitlementDemotionBlockers` (§9.7) rather
 * than re-deriving it: a renderer that checked only `inert` would print
 * "can demote" on a cited claim that names no threat and therefore joins nothing.
 */
function demotionEffect(en: ThreatModelEntitlement): string {
  const reasons = entitlementDemotionBlockers(en).map(b =>
    b === 'uncited' ? 'no citation' : b === 'no-asset' ? 'no asset' : 'no threat');
  return reasons.length === 0 ? 'can demote' : `cannot demote: ${reasons.join(', ')}`;
}

// ═══════════════════════════════════════════════════════════════════════
// New Section Emitters
// ═══════════════════════════════════════════════════════════════════════

function emitApplicationOverview(
  model: ThreatModel,
  unmitigated: ThreatModelExposure[],
  severityCounts: { critical: number; high: number; medium: number; low: number },
  hasAI: boolean,
  lines: string[],
): void {
  const slice = sliceOf(model);

  // If user provided a project description via .guardlink/prompt.md, use it
  if (model.prompt) {
    // `.guardlink/prompt.md` is prose about the repository. It does not narrow
    // with `--feature` and cannot be made to, so under a filter it is fenced off
    // and labelled rather than left to read as a description of the feature —
    // a project-level narrative under a feature heading is the exact confusion
    // this report was reworked to remove.
    if (slice.active) {
      lines.push(`### Project Description — project-wide`);
      lines.push('');
      lines.push(`> The text below is \`.guardlink/prompt.md\`. It describes **all of ${model.project}** and is`);
      lines.push(`> reproduced unfiltered; it is not a description of ${slice.noun}.`);
      lines.push('');
    }
    lines.push(model.prompt);
    lines.push('');
  } else {
    // Fallback: derive overview from annotations
    const topLevelGroups = new Map<string, string[]>();
    for (const a of model.assets) {
      const group = a.path[0] || 'Unknown';
      if (!topLevelGroups.has(group)) topLevelGroups.set(group, []);
      topLevelGroups.get(group)!.push(a.path.slice(1).join('.') || a.path[0]);
    }

    lines.push(slice.active
      ? `The ${slice.quoted} slice of **${model.project}** touches **${model.assets.length} assets** across ` +
        `**${model.source_files} source files** with **${model.annotations_parsed} security annotations**. ` +
        'Assets are those its annotations reference; they may also be used by other features.'
      : `**${model.project}** is composed of **${model.assets.length} assets** across **${model.source_files} source files** ` +
        `with **${model.annotations_parsed} security annotations**.`);
    lines.push('');

    if (topLevelGroups.size > 0) {
      lines.push('**Component groups:**');
      lines.push('');
      for (const [group, members] of topLevelGroups) {
        lines.push(`- **${group}**: ${members.join(', ')}`);
      }
      lines.push('');
    }
  }

  // Risk posture summary — always shown
  //
  // Coverage is measured as exposures answered, not as annotations counted. The
  // old formula was (mitigations + acceptances) / exposures, which counts the
  // wrong things on both sides: two `@mitigates` for one exposure, or a
  // `@mitigates` on a pair nothing exposes, each inflate it. Real output from
  // this repo under `--feature "Dashboard"`: `150% addressed (3 mitigated, 0
  // accepted)` against 2 exposures. `findUnmitigatedExposures` is the same
  // predicate the findings table and the diagram use, so the three now agree.
  const totalExposures = model.exposures.length;
  const mitigatedCount = model.mitigations.length;
  const acceptedCount = model.acceptances.length;
  const addressed = totalExposures - unmitigated.length;
  const coverageCell = totalExposures === 0
    ? (slice.active
      ? `— (no \`@exposes\` in ${slice.noun})`
      : '— (no `@exposes` recorded)')
    : `${Math.round((addressed / totalExposures) * 100)}% addressed ` +
      `(${addressed} of ${totalExposures} exposures answered by ${mitigatedCount} \`@mitigates\`, ${acceptedCount} \`@accepts\`)`;

  lines.push(slice.active
    ? `**Risk posture at a glance** — ${slice.quoted} only:`
    : '**Risk posture at a glance:**');
  lines.push('');
  lines.push(`| Indicator | Value |`);
  lines.push(`|-----------|-------|`);
  if (slice.active) lines.push(`| **Scope** | **feature${slice.names.length > 1 ? 's' : ''} ${slice.quoted}** |`);
  lines.push(`| Exposure coverage | ${coverageCell} |`);
  lines.push(`| Unmitigated exposures | ${unmitigated.length} (${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium, ${severityCounts.low} low) |`);
  lines.push(`| Trust boundaries | ${model.boundaries.length} |`);
  lines.push(`| Data flows tracked | ${model.flows.length} |`);
  if (hasAI) lines.push(`| AI/ML components | Yes |`);
  lines.push('');
}

function emitScope(model: ThreatModel, lines: string[]): void {
  const slice = sliceOf(model);
  // Scope intro — summarize what's modeled based on annotations
  const annotatedCount = model.annotated_files.length;
  const totalFiles = model.source_files;
  const assetCount = model.assets.length;
  const threatCount = model.threats.length;
  // The single worst line in the filtered report was this one: it read
  // "covers **1 assets** and **2 threat categories** derived from **442
  // annotations** across **1** of **87** source files" — the first two numbers
  // from the feature, the last three from the repository, in one sentence.
  lines.push(slice.active
    ? `This is a **feature slice**, not the project's threat model. It covers **${assetCount} asset(s)** and ` +
      `**${threatCount} threat categor(ies)** derived from **${model.annotations_parsed} annotation(s)** in the ` +
      `**${annotatedCount}** file(s) tagged ${slice.quoted}. Everything outside those files is excluded.`
    : `This threat model covers **${assetCount} assets** and **${threatCount} threat categories** ` +
      `derived from **${model.annotations_parsed} annotations** across **${annotatedCount}** of **${totalFiles}** source files.`);
  lines.push('');

  if (slice.active) {
    lines.push('### Files in This Slice');
    lines.push('');
    if (model.annotated_files.length > 0) {
      for (const f of model.annotated_files) lines.push(`- \`${f}\``);
    } else {
      lines.push(`_No file carries \`@feature ${slice.quoted}\` — this slice is empty. Check the spelling with \`guardlink features\`._`);
    }
    lines.push('');
  }

  // What's in scope: annotated files / assets / threat categories
  const threatCategories = [...new Set(model.threats.map(t => t.canonical_name || t.name))];
  const assetNames = model.assets.map(a => a.id ? `\`${a.id}\`` : `\`${a.path.join('.')}\``);

  lines.push('### Assets in Scope');
  lines.push('');
  if (assetNames.length > 0) {
    for (const name of assetNames) {
      const asset = model.assets.find(a => (a.id ? `\`${a.id}\`` : `\`${a.path.join('.')}\``) === name);
      const desc = asset?.description ? ` — ${truncate(asset.description, 80)}` : '';
      lines.push(`- ${name}${desc}`);
    }
  } else {
    lines.push(nothingFound('assets referenced', slice,
      '_No explicit assets defined. Consider adding `@asset` definitions._'));
  }
  lines.push('');

  lines.push('### Threat Categories Addressed');
  lines.push('');
  if (threatCategories.length > 0) {
    const severityMap = new Map<string, string>();
    for (const t of model.threats) {
      severityMap.set(t.canonical_name || t.name, t.severity || 'unset');
    }
    for (const cat of threatCategories) {
      const sev = severityMap.get(cat) || 'unset';
      lines.push(`- **${cat}** (${sev})`);
    }
  } else {
    lines.push(nothingFound('threats referenced', slice, '_No explicit threats defined._'));
  }
  lines.push('');

  // Coverage gaps
  //
  // Annotation coverage is a property of the repository walk, not of the model,
  // so a filtered model cannot answer it: `filterByFeature` scopes
  // `source_files` and empties `unannotated_files`, which turned this into
  // "**1** of **87** files have security annotations (1%)" followed by "**21**
  // files have no annotations" — three numbers from three different scopes,
  // arithmetically impossible together. Refused rather than recomputed: there is
  // no honest feature-scoped coverage number, since a feature has no denominator.
  if (sliceOf(model).active) {
    lines.push('### Coverage — project-wide');
    lines.push('');
    lines.push('_Not available in a feature slice. Annotation coverage is measured against every source');
    lines.push('file in the repository, and a feature has no such denominator — run `guardlink report`');
    lines.push('without `--feature`, or `guardlink status .`, for project coverage._');
    lines.push('');
    return;
  }

  lines.push('### Coverage');
  lines.push('');
  const covAnnotated = model.annotated_files.length;
  const covTotal = model.source_files;
  const unannotatedCount = model.unannotated_files.length;
  lines.push(`- **${covAnnotated}** of **${covTotal}** files have security annotations (${covTotal > 0 ? Math.round((covAnnotated / covTotal) * 100) : 0}%)`);
  if (unannotatedCount > 0) {
    lines.push(`- **${unannotatedCount}** files have no annotations`);
  }
  lines.push('');
}

function emitArchitecture(model: ThreatModel, lines: string[]): void {
  const slice = sliceOf(model);
  // ── Components ──
  lines.push('### Components');
  lines.push('');
  if (slice.active) {
    lines.push(`Components referenced by ${slice.noun}. An asset listed here is defined project-wide and`);
    lines.push('may carry exposures under other features that this slice does not show.');
    lines.push('');
  }
  if (model.assets.length > 0) {
    lines.push('| Component | ID | Description | Defined At |');
    lines.push('|-----------|-----|-------------|------------|');
    for (const a of model.assets) {
      const name = a.path.join('.');
      const id = a.id || '—';
      const desc = a.description ? truncate(a.description, 50) : '—';
      lines.push(`| ${name} | ${id} | ${desc} | ${a.location.file}:${a.location.line} |`);
    }
  } else {
    lines.push(nothingFound('components referenced', slice, '_No components defined via `@asset`._'));
  }
  lines.push('');

  // ── Entrypoints ──
  lines.push('### Entrypoints');
  lines.push('');
  // Build asset name set matching both "#id" and "id" forms
  const assetNames = new Set<string>();
  for (const a of model.assets) {
    const id = a.id || a.path.join('.');
    assetNames.add(id);
    assetNames.add(`#${id}`);
    assetNames.add(a.path.join('.'));
    assetNames.add(`#${a.path.join('.')}`);
  }

  const flowSources = new Set(model.flows.map(f => f.source));

  // External sources: flow sources that are NOT defined assets
  const externalSources = new Set<string>();
  for (const src of flowSources) {
    if (!assetNames.has(src)) externalSources.add(src);
  }

  // Entrypoints: assets that receive flows from external sources
  const entrypoints = new Set<string>();
  for (const f of model.flows) {
    if (externalSources.has(f.source) && assetNames.has(f.target)) {
      entrypoints.add(f.target);
    }
  }

  // Also: assets that appear in exposures but not as flow targets from internal sources
  if (entrypoints.size === 0) {
    // Fallback: assets with exposures are likely entrypoints
    for (const e of model.exposures) {
      if (assetNames.has(e.asset)) entrypoints.add(e.asset);
    }
  }

  if (entrypoints.size > 0) {
    lines.push('Assets receiving external input:');
    lines.push('');
    for (const ep of entrypoints) {
      const incomingFlows = model.flows.filter(f => f.target === ep && externalSources.has(f.source));
      const mechanisms = incomingFlows.map(f => `${f.source} via ${f.mechanism || 'unspecified'}`).join(', ');
      lines.push(`- **${ep}**${mechanisms ? `: ${mechanisms}` : ''}`);
    }
  } else {
    lines.push(nothingFound('entrypoints identified', slice,
      '_No explicit entrypoints identified. Add `@flows` from external sources to assets._'));
  }
  lines.push('');

  // ── Callers (external entities) ──
  if (externalSources.size > 0) {
    lines.push('### External Callers');
    lines.push('');
    for (const src of externalSources) {
      const targets = model.flows.filter(f => f.source === src).map(f => f.target);
      lines.push(`- **${src}** → ${[...new Set(targets)].join(', ')}`);
    }
    lines.push('');
  }

  // ── Architecture Diagram ──
  lines.push('### Architecture Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push(generateMermaid(model));
  lines.push('```');
  lines.push('');

  // ── Trust Boundaries / Network Zones ──
  if (model.boundaries.length > 0) {
    lines.push('### Network Zones & Trust Boundaries');
    lines.push('');
    for (const b of model.boundaries) {
      const desc = b.description || b.id || 'Unnamed boundary';
      lines.push(`- **${desc}**: ${shortName(b.asset_a)} ↔ ${shortName(b.asset_b)}`);
    }
    lines.push('');
  }

  // ── Multi-tenancy ──
  // Tenant isolation is a whole-system property; "none found" computed from one
  // feature's annotations is not evidence about the application.
  lines.push(slice.active ? '### Multi-tenancy — as seen from this slice' : '### Multi-tenancy');
  lines.push('');
  const tenantAnnotations = [
    ...model.comments.filter(c => /tenant|multi.?tenant|isolat/i.test(c.description || '')),
    ...model.assumptions.filter(a => /tenant|multi.?tenant|isolat/i.test(a.description || '')),
  ];
  if (tenantAnnotations.length > 0) {
    for (const a of tenantAnnotations) {
      lines.push(`- ${a.description} (${a.location.file}:${a.location.line})`);
    }
  } else {
    lines.push(nothingFound('multi-tenancy annotations', slice,
      '_No multi-tenancy annotations found. If this is a multi-tenant application, consider adding `@comment` or `@boundary` annotations describing tenant isolation._'));
  }
  lines.push('');

  // ── Compliance ──
  lines.push(slice.active ? '### Compliance — as seen from this slice' : '### Compliance');
  lines.push('');
  const complianceAnnotations = [
    ...model.comments.filter(c => /complian|gdpr|hipaa|soc|pci|iso|fedramp|ccpa/i.test(c.description || '')),
    ...model.assumptions.filter(a => /complian|gdpr|hipaa|soc|pci|iso|fedramp|ccpa/i.test(a.description || '')),
  ];
  const hasPII = model.data_handling.some(h => h.classification === 'pii');
  const hasPHI = model.data_handling.some(h => h.classification === 'phi');
  const hasFinancial = model.data_handling.some(h => h.classification === 'financial');

  if (complianceAnnotations.length > 0) {
    for (const a of complianceAnnotations) {
      lines.push(`- ${a.description} (${a.location.file}:${a.location.line})`);
    }
  }
  if (hasPII) lines.push('- Handles **PII** — consider GDPR, CCPA compliance requirements');
  if (hasPHI) lines.push('- Handles **PHI** — consider HIPAA compliance requirements');
  if (hasFinancial) lines.push('- Handles **Financial data** — consider PCI-DSS compliance requirements');
  if (complianceAnnotations.length === 0 && !hasPII && !hasPHI && !hasFinancial) {
    lines.push(nothingFound('compliance-related annotations', slice, '_No compliance-related annotations found._'));
  }
  lines.push('');
}

function emitKeyFlows(model: ThreatModel, lines: string[]): void {
  // Group flows into chains (sequences of connected flows)
  const chains = buildFlowChains(model.flows);

  // Emit sequence diagram
  lines.push('### Sequence Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push(generateSequenceDiagram(model));
  lines.push('```');
  lines.push('');

  // Emit step-by-step for each chain
  lines.push('### Flow Details');
  lines.push('');
  let chainIdx = 0;
  for (const chain of chains) {
    chainIdx++;
    lines.push(`**Flow ${chainIdx}:** ${chain[0].source} → ${chain[chain.length - 1].target}`);
    lines.push('');
    let step = 0;
    for (const f of chain) {
      step++;
      const mech = f.mechanism ? ` via **${f.mechanism}**` : '';
      const desc = f.description ? ` — ${f.description}` : '';
      lines.push(`${step}. **${f.source}** → **${f.target}**${mech}${desc}`);
    }
    lines.push('');
  }
}

function emitDataInventory(model: ThreatModel, hasAI: boolean, lines: string[]): void {
  const slice = sliceOf(model);
  // ── Data Types ──
  if (model.data_handling.length > 0) {
    lines.push('### Data Types');
    lines.push('');
    const byClassification = new Map<string, string[]>();
    for (const h of model.data_handling) {
      if (!byClassification.has(h.classification)) byClassification.set(h.classification, []);
      byClassification.get(h.classification)!.push(`${h.asset}${h.description ? ` (${truncate(h.description, 40)})` : ''}`);
    }
    for (const [cls, items] of byClassification) {
      lines.push(`**${classificationBadge(cls)}:**`);
      for (const item of items) {
        lines.push(`- ${item}`);
      }
      lines.push('');
    }
  }

  // ── Top Data Assets ──
  lines.push('### Top Data Assets');
  lines.push('');
  // Assets that handle the most data flows
  const assetFlowCount = new Map<string, number>();
  for (const f of model.flows) {
    assetFlowCount.set(f.target, (assetFlowCount.get(f.target) || 0) + 1);
    assetFlowCount.set(f.source, (assetFlowCount.get(f.source) || 0) + 1);
  }
  const topDataAssets = [...assetFlowCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  if (topDataAssets.length > 0) {
    lines.push('Assets by data flow volume:');
    lines.push('');
    lines.push('| Asset | Data Flows | Classifications |');
    lines.push('|-------|-----------|-----------------|');
    for (const [asset, count] of topDataAssets) {
      const classes = model.data_handling
        .filter(h => h.asset === asset)
        .map(h => h.classification)
        .join(', ') || '—';
      lines.push(`| ${asset} | ${count} | ${classes} |`);
    }
    lines.push('');
  } else {
    lines.push(nothingFound('data flows recorded', slice, '_No data flow volume data available._'));
    lines.push('');
  }

  // ── AI-Specific Data Questions ──
  if (hasAI) {
    lines.push('### AI-Specific Data Considerations');
    lines.push('');
    const aiFlows = model.flows.filter(f =>
      isAIRelated(f.source) || isAIRelated(f.target),
    );
    const aiHandling = model.data_handling.filter(h => isAIRelated(h.asset));
    const aiComments = model.comments.filter(c =>
      /prompt|model|train|inference|embed|token|llm|ai|ml/i.test(c.description || ''),
    );

    if (aiFlows.length > 0) {
      lines.push('**Data flowing to/from AI components:**');
      lines.push('');
      for (const f of aiFlows) {
        lines.push(`- ${f.source} → ${f.target} via ${f.mechanism || 'unspecified'}${f.description ? ` — ${f.description}` : ''}`);
      }
      lines.push('');
    }

    if (aiHandling.length > 0) {
      lines.push('**Data classifications on AI components:**');
      lines.push('');
      for (const h of aiHandling) {
        lines.push(`- ${h.asset}: ${classificationBadge(h.classification)}${h.description ? ` — ${h.description}` : ''}`);
      }
      lines.push('');
    }

    if (aiComments.length > 0) {
      lines.push('**AI-related notes:**');
      lines.push('');
      for (const c of aiComments) {
        lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
      }
      lines.push('');
    }

    // Checklist
    lines.push('**AI data checklist:**');
    lines.push('');
    lines.push('- [ ] Are prompts logged? If so, is PII scrubbed?');
    lines.push('- [ ] Is user data used for training/fine-tuning?');
    lines.push('- [ ] What is the data retention policy for AI inputs/outputs?');
    lines.push('- [ ] Are embeddings stored? Can they be reversed to recover source data?');
    lines.push('');
  }
}

function emitRolesAccess(model: ThreatModel, lines: string[]): void {
  const slice = sliceOf(model);
  // ── Declared principals ──
  // Unlike the inferred actors further down, these are written down: @actor is
  // the authorization model as the maintainers state it, and each entitlement
  // is a claim that some capability is a principal's by design.
  const declared = model.actors || [];
  const entitlements = model.entitlements || [];
  if (declared.length > 0) {
    lines.push('### Declared Principals');
    lines.push('');
    if (slice.active) {
      lines.push(`Principals reached by ${slice.noun} — resolved from the entitlements written in its files,`);
      lines.push('so a principal the project declares but this feature never names is absent.');
      lines.push('');
    }
    for (const ac of declared) {
      const ref = ac.id ? `#${ac.id}` : ac.canonical_name;
      // Matched through the same normalisation the parser's undeclared-actor
      // check uses. A literal `===` against `ac.id || ac.canonical_name` missed
      // `@entitles Payments_Admin` against `canonical_name: payments_admin`,
      // and the entitlement then vanished from its principal here while
      // surviving the filter — the actor is kept by a case-insensitive match.
      const held = entitlements.filter(en => actorMatches(en.actor, ac.id, ac.canonical_name, ac.name));
      const desc = ac.description ? ` — ${ac.description}` : '';
      lines.push(`- **${ac.name}** (\`${ref}\`)${desc}`);
      for (const en of held) {
        // Both halves of the join, always, and the effect spelled out. A claim
        // reading "entitled to `refund` on #pay [cites authz.ts:9]" looks fully
        // operative while naming no threat, which is precisely the claim that
        // must never demote anything (§9.3).
        const scope = `${en.asset ? ` on ${en.asset}` : ' on <no asset>'}${en.threat ? ` against ${en.threat}` : ' against <no threat>'}`;
        const cite = en.citation ? ` [cites \`${en.citation.raw}\`]` : ' [uncited]';
        lines.push(`  - entitled to \`${en.capability}\`${scope}${cite} — **${demotionEffect(en)}**`);
      }
      if (held.length === 0) {
        lines.push('  - _no entitlements recorded_');
      }
    }
    lines.push('');
  } else if (entitlements.length > 0) {
    // Entitlements whose actor is never declared with `@actor` — an error the
    // parser reports, but the report used to drop them from this section
    // silently and show them only further down.
    lines.push('### Declared Principals');
    lines.push('');
    lines.push('_Entitlements are recorded but no `@actor` declares the principals they name — see the');
    lines.push('Entitlements section, and `guardlink validate .` for the undeclared-actor errors._');
    lines.push('');
  } else if (slice.active) {
    lines.push('### Declared Principals');
    lines.push('');
    lines.push(`_No \`@actor\` or \`@entitles\` annotations in ${slice.noun}. The project may declare principals`);
    lines.push('under other features — this view resolves them from this slice\'s annotations only._');
    lines.push('');
  }

  // ── Owners / Internal Actors ──
  if (model.ownership.length > 0) {
    lines.push('### Ownership & Internal Actors');
    lines.push('');
    const byOwner = new Map<string, string[]>();
    for (const o of model.ownership) {
      if (!byOwner.has(o.owner)) byOwner.set(o.owner, []);
      byOwner.get(o.owner)!.push(o.asset);
    }
    for (const [owner, assets] of byOwner) {
      lines.push(`- **${owner}**: ${assets.join(', ')}`);
    }
    lines.push('');
  }

  // ── Actors from flows ──
  const actors = new Set<string>();
  const actorPattern = /user|admin|client|browser|operator|attacker|customer|tenant|role/i;
  for (const f of model.flows) {
    if (actorPattern.test(f.source)) actors.add(f.source);
    if (actorPattern.test(f.target)) actors.add(f.target);
  }
  // Also check assets for actor-like patterns
  for (const a of model.assets) {
    const name = a.path.join('.');
    if (actorPattern.test(name)) actors.add(a.id || name);
  }

  if (actors.size > 0) {
    lines.push('### Customer / External Roles');
    lines.push('');
    for (const actor of actors) {
      const flows = model.flows.filter(f => f.source === actor || f.target === actor);
      const interacts = [...new Set(flows.map(f => f.source === actor ? f.target : f.source))];
      lines.push(`- **${actor}** interacts with: ${interacts.join(', ') || '—'}`);
    }
    lines.push('');
  }

  // ── Cross-Tenant Gut Check ──
  lines.push('### Cross-Tenant Gut Check');
  lines.push('');
  const boundaryCount = model.boundaries.length;
  const hasTenantBoundaries = model.boundaries.some(b =>
    /tenant|isolat/i.test(b.description || '') || /tenant|isolat/i.test(b.id || ''),
  );
  if (hasTenantBoundaries) {
    lines.push('Tenant isolation boundaries are defined:');
    lines.push('');
    for (const b of model.boundaries.filter(b => /tenant|isolat/i.test(b.description || '') || /tenant|isolat/i.test(b.id || ''))) {
      lines.push(`- ${b.description || b.id} (${b.asset_a} ↔ ${b.asset_b})`);
    }
  } else if (boundaryCount > 0) {
    lines.push(`${boundaryCount} trust boundaries defined${slice.active ? ` in ${slice.noun}` : ''}, but none explicitly mention tenant isolation. If this is multi-tenant, verify that cross-tenant data access is prevented at each boundary.`);
  } else {
    lines.push(nothingFound('trust boundaries', slice,
      '_No trust boundaries defined. If multi-tenant, add `@boundary` annotations to document tenant isolation._'));
  }
  lines.push('');
}

/**
 * Does an `@entitles` actor reference name this `@actor`?
 *
 * Same rule as the parser's undeclared-actor check: strip `#`, compare
 * case-insensitively, and try the §2.10-normalised form too, so `#pay-admin`,
 * `pay_admin` and `Payments_Admin` all reach the declaration they were written
 * against.
 */
function actorMatches(ref: string, id: string | undefined, canonicalName: string, name: string): boolean {
  const bare = normalizeRef(ref);
  const forms = new Set<string>();
  for (const candidate of [id, canonicalName, name]) {
    if (!candidate) continue;
    forms.add(candidate.toLowerCase());
    forms.add(normalizeName(candidate));
  }
  return forms.has(bare) || forms.has(normalizeName(bare));
}

function emitDependencies(model: ThreatModel, lines: string[]): void {
  const slice = sliceOf(model);
  // The dependency inventory is inherently a project question, but everything
  // here is derived from `@flows`/`@transfers`, which the filter scopes. Under a
  // filter it answers "what does this feature reach", which is a different and
  // much smaller question than "what does the project depend on".
  if (slice.active) {
    lines.push(`Only dependencies reached by ${slice.noun}. This is **not** the project's dependency`);
    lines.push('inventory — anything reached solely from another feature is absent.');
    lines.push('');
  }
  // Build asset ID set that matches both "#id" and "id" forms used in flows
  const assetIds = new Set<string>();
  for (const a of model.assets) {
    const id = a.id || a.path.join('.');
    assetIds.add(id);
    assetIds.add(`#${id}`);
    // Also add the dotted path form
    const path = a.path.join('.');
    assetIds.add(path);
    assetIds.add(`#${path}`);
  }

  // ── Internal services: assets that are flow targets from other assets ──
  lines.push('### Internal Services');
  lines.push('');
  const internalDeps = new Set<string>();
  for (const f of model.flows) {
    if (assetIds.has(f.source) && assetIds.has(f.target) && f.source !== f.target) {
      internalDeps.add(`${f.source} → ${f.target}`);
    }
  }
  if (internalDeps.size > 0) {
    for (const dep of internalDeps) {
      lines.push(`- ${dep}`);
    }
  } else {
    lines.push(nothingFound('internal service dependencies detected from flows', slice,
      '_No internal service dependencies detected from flows._'));
  }
  lines.push('');

  // ── External / Cloud / AI Vendors ──
  lines.push('### External & Cloud Dependencies');
  lines.push('');
  const externalNodes = new Set<string>();
  for (const f of model.flows) {
    if (!assetIds.has(f.source)) externalNodes.add(f.source);
    if (!assetIds.has(f.target)) externalNodes.add(f.target);
  }
  // Also from transfers
  for (const t of model.transfers) {
    if (!assetIds.has(t.target)) externalNodes.add(t.target);
    if (!assetIds.has(t.source)) externalNodes.add(t.source);
  }
  // Also external_refs
  if (model.external_refs) {
    for (const ref of model.external_refs) {
      if (ref.inferred_repo) externalNodes.add(ref.inferred_repo);
    }
  }

  if (externalNodes.size > 0) {
    const aiVendors: string[] = [];
    const cloudVendors: string[] = [];
    const otherVendors: string[] = [];
    for (const node of externalNodes) {
      if (isAIRelated(node)) {
        aiVendors.push(node);
      } else if (/aws|gcp|azure|cloud|s3|lambda|cdn|redis|postgres|mysql|mongo|kafka|rabbit|elastic/i.test(node)) {
        cloudVendors.push(node);
      } else {
        otherVendors.push(node);
      }
    }
    if (aiVendors.length > 0) {
      lines.push('**AI/ML Vendors:**');
      for (const v of aiVendors) lines.push(`- ${v}`);
      lines.push('');
    }
    if (cloudVendors.length > 0) {
      lines.push('**Cloud/Infrastructure:**');
      for (const v of cloudVendors) lines.push(`- ${v}`);
      lines.push('');
    }
    if (otherVendors.length > 0) {
      lines.push('**Other External:**');
      for (const v of otherVendors) lines.push(`- ${v}`);
      lines.push('');
    }
  } else {
    lines.push(nothingFound('external dependencies detected from flows or transfers', slice,
      '_No external dependencies detected from flows or transfers._'));
    lines.push('');
  }

  // Risk transfers to external parties
  if (model.transfers.length > 0) {
    lines.push('### Risk Transfers to Dependencies');
    lines.push('');
    for (const t of model.transfers) {
      lines.push(`- **${t.threat}** transferred from ${t.source} → ${t.target}${t.description ? ` — ${t.description}` : ''}`);
    }
    lines.push('');
  }
}

function emitSecretsManagement(model: ThreatModel, lines: string[]): void {
  const slice = sliceOf(model);
  // ── Secret Inventory ──
  const secretHandling = model.data_handling.filter(h => h.classification === 'secrets');
  const keyExposures = model.exposures.filter(e =>
    /key|secret|cred|token|password|api.?key/i.test(e.threat) ||
    /key|secret|cred|token|password|api.?key/i.test(e.description || ''),
  );
  const keyMitigations = model.mitigations.filter(m =>
    /key|secret|cred|token|password|api.?key|redact|encrypt/i.test(m.control || '') ||
    /key|secret|cred|token|password|api.?key/i.test(m.description || ''),
  );
  const keyComments = model.comments.filter(c =>
    /key|secret|cred|token|password|api.?key|rotat|vault|kms/i.test(c.description || ''),
  );

  lines.push('### Secret Inventory');
  lines.push('');
  if (secretHandling.length > 0) {
    lines.push('| Asset | Description | Location |');
    lines.push('|-------|-------------|----------|');
    for (const h of secretHandling) {
      lines.push(`| ${h.asset} | ${h.description || '—'} | ${h.location.file}:${h.location.line} |`);
    }
    lines.push('');
  } else {
    lines.push(nothingFound('assets classified as `secrets` via `@handles`', slice,
      '_No assets classified as `secrets` via `@handles`. Consider adding `@handles secrets on <asset>` annotations._'));
    lines.push('');
  }

  // ── Leak Impact ──
  lines.push('### Leak Impact Analysis');
  lines.push('');
  if (keyExposures.length > 0) {
    lines.push('Key/credential-related exposures:');
    lines.push('');
    for (const e of keyExposures) {
      lines.push(`- ${severityBadge(e.severity)} **${e.asset}** exposed to **${e.threat}**${e.description ? ` — ${e.description}` : ''} (${e.location.file}:${e.location.line})`);
    }
    lines.push('');
  }
  if (keyMitigations.length > 0) {
    lines.push('Active credential protections:');
    lines.push('');
    for (const m of keyMitigations) {
      lines.push(`- **${m.control || 'control'}** on ${m.asset}${m.description ? ` — ${m.description}` : ''}`);
    }
    lines.push('');
  }
  if (keyExposures.length === 0 && keyMitigations.length === 0) {
    lines.push(nothingFound('credential-related exposures or mitigations', slice,
      '_No credential-related exposures or mitigations found._'));
    lines.push('');
  }

  // ── Rotation Strategy ──
  lines.push('### Rotation Strategy');
  lines.push('');
  if (keyComments.length > 0) {
    for (const c of keyComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push(nothingFound('documented rotation strategy', slice,
      '_No rotation strategy documented. Consider adding `@comment` annotations describing key rotation policies._'));
  }
  lines.push('');
}

function emitLoggingAudit(model: ThreatModel, lines: string[]): void {
  const slice = sliceOf(model);
  // ── What's Logged ──
  const loggingComments = model.comments.filter(c =>
    /log|audit|trace|monitor|alert|metric|observ/i.test(c.description || ''),
  );

  lines.push('### Logging & Observability');
  lines.push('');
  if (loggingComments.length > 0) {
    for (const c of loggingComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push(nothingFound('logging-related annotations', slice,
      '_No logging-related annotations found. Consider documenting what security events are logged._'));
  }
  lines.push('');

  // ── Incident Reconstruction ──
  lines.push('### Incident Reconstruction');
  lines.push('');
  if (model.audits.length > 0) {
    lines.push(`**${model.audits.length} audit items** flagged for review:`);
    lines.push('');
    for (const a of model.audits.slice(0, 10)) {
      lines.push(`- **${a.asset}**: ${a.description || 'Needs review'} (${a.location.file}:${a.location.line})`);
    }
    if (model.audits.length > 10) {
      lines.push(`- ... and ${model.audits.length - 10} more (see Audit Items section)`);
    }
  } else {
    lines.push(nothingFound('`@audit` items', slice,
      '_No `@audit` items. Consider flagging security-critical code paths for review._'));
  }
  lines.push('');

  // ── Alerting ──
  lines.push('### Alerting');
  lines.push('');
  const alertComments = model.comments.filter(c =>
    /alert|page|notify|incident|on.?call/i.test(c.description || ''),
  );
  if (alertComments.length > 0) {
    for (const c of alertComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push(nothingFound('alerting annotations', slice,
      '_No alerting annotations found. Consider documenting alerting strategies via `@comment`._'));
  }
  lines.push('');
}

function emitAIDetails(model: ThreatModel, lines: string[]): void {
  const slice = sliceOf(model);
  // ── Model Inventory ──
  const aiAssets = model.assets.filter(a => isAIRelated(a.id || a.path.join('.')));
  const aiExposures = model.exposures.filter(e =>
    isAIRelated(e.asset) || /prompt.?inject|model|adversarial/i.test(e.threat),
  );
  const aiMitigations = model.mitigations.filter(m =>
    isAIRelated(m.asset) || /prompt.?inject|model|adversarial/i.test(m.threat),
  );
  const aiComments = model.comments.filter(c =>
    /prompt|model|llm|ai|ml|inference|embed|token|train|fine.?tun|rag|vector/i.test(c.description || ''),
  );

  lines.push('### Model Inventory');
  lines.push('');
  if (aiAssets.length > 0) {
    lines.push('| Component | ID | Description |');
    lines.push('|-----------|-----|-------------|');
    for (const a of aiAssets) {
      lines.push(`| ${a.path.join('.')} | ${a.id || '—'} | ${a.description || '—'} |`);
    }
  } else {
    lines.push('_AI usage detected in annotations but no AI-specific assets defined._');
  }
  lines.push('');

  // ── Safety Guardrails ──
  lines.push('### Safety Guardrails');
  lines.push('');
  if (aiMitigations.length > 0) {
    for (const m of aiMitigations) {
      lines.push(`- **${m.control || 'control'}** on ${m.asset} against ${m.threat}${m.description ? ` — ${m.description}` : ''}`);
    }
  } else {
    lines.push(nothingFound('AI-specific mitigations', slice, '_No AI-specific mitigations found._'));
  }
  lines.push('');

  // ── Prompt Injection Handling ──
  lines.push('### Prompt Injection Handling');
  lines.push('');
  const promptInjectionExposures = aiExposures.filter(e =>
    /prompt.?inject/i.test(e.threat),
  );
  const promptInjectionMitigations = aiMitigations.filter(m =>
    /prompt.?inject/i.test(m.threat),
  );
  if (promptInjectionExposures.length > 0 || promptInjectionMitigations.length > 0) {
    if (promptInjectionExposures.length > 0) {
      lines.push('**Exposures:**');
      for (const e of promptInjectionExposures) {
        lines.push(`- ${severityBadge(e.severity)} ${e.asset}${e.description ? ` — ${e.description}` : ''} (${e.location.file}:${e.location.line})`);
      }
      lines.push('');
    }
    if (promptInjectionMitigations.length > 0) {
      lines.push('**Mitigations:**');
      for (const m of promptInjectionMitigations) {
        lines.push(`- ${m.control || 'control'} on ${m.asset}${m.description ? ` — ${m.description}` : ''}`);
      }
      lines.push('');
    }
  } else {
    lines.push(nothingFound('prompt injection exposures or mitigations', slice,
      '_No prompt injection exposures or mitigations documented._'));
    lines.push('');
  }

  // ── Data Retention ──
  lines.push('### Data Retention & AI Notes');
  lines.push('');
  if (aiComments.length > 0) {
    for (const c of aiComments) {
      lines.push(`- ${c.description} (${c.location.file}:${c.location.line})`);
    }
  } else {
    lines.push(nothingFound('AI data retention notes', slice,
      '_No AI data retention notes found. Consider documenting prompt logging, training data handling, and model output storage._'));
  }
  lines.push('');
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

function shortName(s: string): string {
  if (s.startsWith('#')) return s.slice(1);
  return s.split('.').pop() || s;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function severityBadge(sev?: Severity): string {
  switch (sev) {
    case 'critical': return '🔴 Critical';
    case 'high':     return '🟠 High';
    case 'medium':   return '🟡 Medium';
    case 'low':      return '🔵 Low';
    default:         return '⚪ Unset';
  }
}

function classificationBadge(c: string): string {
  switch (c) {
    case 'pii':       return '🔒 PII';
    case 'phi':       return '🏥 PHI';
    case 'financial': return '💰 Financial';
    case 'secrets':   return '🔑 Secrets';
    case 'internal':  return '🏢 Internal';
    case 'public':    return '🌐 Public';
    default:          return c;
  }
}

function sortBySeverity(exposures: ThreatModelExposure[]): ThreatModelExposure[] {
  return [...exposures].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity || 'low'] ?? 4;
    const sb = SEVERITY_ORDER[b.severity || 'low'] ?? 4;
    return sa - sb;
  });
}

function countBySeverity(exposures: ThreatModelExposure[]): { critical: number; high: number; medium: number; low: number } {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const e of exposures) {
    if (e.severity && e.severity in counts) {
      counts[e.severity as keyof typeof counts]++;
    }
  }
  return counts;
}

/** Detect if the project uses AI/ML based on annotations */
function detectAI(model: ThreatModel): boolean {
  // Strict patterns — avoid false positives from "model" (data model), "token" (auth token), etc.
  const aiAssetPattern = /\bllm\b|(?:^|\W)ai(?:\W|$)|\bml\b|\binference\b|\bembed(?:ding)?\b|\bopenai\b|\banthropic\b|\bgpt\b|\bclaude\b|\bgemini\b|\brag\b|\bvector.?(?:db|store)\b|\bneural\b/i;
  const aiFlowPattern = /\bllm\b|\bopenai\b|\banthropic\b|\bgpt\b|\bclaude\b|\bgemini\b|\binference\b|\bembed(?:ding)?\b|\brag\b|\bvector.?(?:db|store)\b|\bchat.?completion\b/i;

  for (const a of model.assets) {
    if (aiAssetPattern.test(a.id || '') || aiAssetPattern.test(a.path.join('.'))) return true;
    if (aiAssetPattern.test(a.description || '')) return true;
  }
  for (const t of model.threats) {
    if (/prompt.?inject/i.test(t.name) || /prompt.?inject/i.test(t.canonical_name)) return true;
  }
  for (const f of model.flows) {
    if (aiFlowPattern.test(f.source) || aiFlowPattern.test(f.target)) return true;
    if (aiFlowPattern.test(f.mechanism || '')) return true;
  }
  return false;
}

/** Check if a name is AI-related (strict) */
function isAIRelated(name: string): boolean {
  return /\bllm\b|\bopenai\b|\banthropic\b|\bgpt\b|\bclaude\b|\bgemini\b|\binference\b|\bembed(?:ding)?\b|\brag\b|\bvector.?(?:db|store)\b|\bneural\b|\bchat.?completion\b/i.test(name);
}


/** Build connected flow chains from individual flow edges */
function buildFlowChains(flows: ThreatModel['flows']): ThreatModel['flows'][] {
  if (flows.length === 0) return [];

  // Build adjacency: source -> list of flows
  const adj = new Map<string, typeof flows>();
  for (const f of flows) {
    if (!adj.has(f.source)) adj.set(f.source, []);
    adj.get(f.source)!.push(f);
  }

  // Find chain starting points: sources that are not targets of other flows
  const allTargets = new Set(flows.map(f => f.target));
  const startNodes = new Set<string>();
  for (const f of flows) {
    if (!allTargets.has(f.source)) startNodes.add(f.source);
  }
  // If no clear start points, use all sources
  if (startNodes.size === 0) {
    for (const f of flows) startNodes.add(f.source);
  }

  const visited = new Set<string>();
  const chains: typeof flows[] = [];

  for (const start of startNodes) {
    if (visited.has(start)) continue;
    const chain: typeof flows[number][] = [];
    let current = start;
    const chainVisited = new Set<string>();

    while (adj.has(current) && !chainVisited.has(current)) {
      chainVisited.add(current);
      visited.add(current);
      const nextFlows = adj.get(current)!;
      const next = nextFlows[0]; // Take first path
      chain.push(next);
      current = next.target;
    }

    if (chain.length > 0) chains.push(chain);
  }

  // Add any isolated flows not in chains.
  //
  // Keyed on the flow itself, not on `source::target`. Two `@flows` between the
  // same pair — different mechanisms, which is the normal way one component
  // reads two things from another — collapsed to one key, so the second was
  // treated as already-chained and never printed anywhere in Flow Details.
  // Measured on this repo: `--feature "Dashboard"` has 4 flows and the section
  // narrated 3, silently dropping `ThreatModel -> #dashboard via featureScope`.
  // Losing one of a feature's four flows is the prose version of a diagram that
  // drops the feature's only edge.
  const chainedFlows = new Set(chains.flat());
  const isolated = flows.filter(f => !chainedFlows.has(f));
  for (const f of isolated) {
    chains.push([f]);
  }

  return chains;
}
