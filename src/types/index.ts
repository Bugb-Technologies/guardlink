/**
 * GuardLink — Core type definitions
 * Mirrors the canonical schema from §5 of the specification.
 */

// ─── Enums ───────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type SeverityAlias = 'P0' | 'P1' | 'P2' | 'P3';

export type DataClassification = 'pii' | 'phi' | 'financial' | 'secrets' | 'internal' | 'public';

export type AnnotationVerb =
  // Definition
  | 'asset' | 'threat' | 'control' | 'actor'
  // Relationship
  | 'mitigates' | 'exposes' | 'accepts' | 'transfers' | 'flows' | 'boundary' | 'entitles'
  // Evidence
  | 'confirmed'
  // Lifecycle
  | 'validates' | 'audit' | 'owns' | 'handles' | 'assumes'
  // Metadata
  | 'feature'
  // Special
  | 'comment' | 'shield' | 'shield:begin' | 'shield:end';

// ─── Location ────────────────────────────────────────────────────────

export interface SourceLocation {
  file: string;
  line: number;
  end_line?: number | null;
  parent_symbol?: string | null;
  origin_file?: string | null;
  origin_line?: number | null;
}

// ─── Parsed Annotations ──────────────────────────────────────────────

export interface BaseAnnotation {
  verb: AnnotationVerb;
  location: SourceLocation;
  description?: string;
  raw: string;  // Original comment text
}

export interface AssetAnnotation extends BaseAnnotation {
  verb: 'asset';
  path: string;
  id?: string;
}

export interface ThreatAnnotation extends BaseAnnotation {
  verb: 'threat';
  name: string;
  canonical_name: string;
  id?: string;
  severity?: Severity;
  external_refs: string[];
}

export interface ControlAnnotation extends BaseAnnotation {
  verb: 'control';
  name: string;
  canonical_name: string;
  id?: string;
}

/**
 * A principal in the system's authorization model — a role, not a person.
 * Declared once per project alongside @asset/@threat/@control.
 */
export interface ActorAnnotation extends BaseAnnotation {
  verb: 'actor';
  name: string;
  canonical_name: string;
  id?: string;
}

export interface MitigatesAnnotation extends BaseAnnotation {
  verb: 'mitigates';
  asset: string;
  threat: string;
  control?: string;
}

export interface ExposesAnnotation extends BaseAnnotation {
  verb: 'exposes';
  asset: string;
  threat: string;
  severity?: Severity;
  external_refs: string[];
}

export interface ConfirmedAnnotation extends BaseAnnotation {
  verb: 'confirmed';
  threat: string;
  asset: string;
  severity?: Severity;
  external_refs: string[];
}

export interface AcceptsAnnotation extends BaseAnnotation {
  verb: 'accepts';
  threat: string;
  asset: string;
}

/**
 * States that an actor is legitimately entitled to a capability — i.e. the
 * privilege required to trigger an effect is a privilege that already grants
 * that effect by design.
 *
 * Carries NO export semantics: unlike @mitigates/@accepts it never removes an
 * exposure from SARIF and never gates testing. It only informs downstream
 * triage. See docs/prd/actor-entitlement-design.md §3.2.
 */
export interface EntitlesAnnotation extends BaseAnnotation {
  verb: 'entitles';
  /** Actor ref — `#id` or a declared actor name */
  actor: string;
  /** Capability as written (single normalised identifier, never prose) */
  capability: string;
  /**
   * §2.10-normalised capability. NOT a join key (§9.3): nothing on the finding
   * side carries a capability, so there is nothing for it to match against. It
   * is the justification — the operation a reviewer reads to judge whether the
   * claim is honest — plus a stable label to group claims by.
   */
  canonical_capability: string;
  /** `on <asset>` — half of the `(actor, asset, threat)` join (§9.3) */
  asset?: string;
  /** `against <threat>` — the other half. Absent means the claim joins nothing. */
  threat?: string;
}

export interface TransfersAnnotation extends BaseAnnotation {
  verb: 'transfers';
  threat: string;
  source: string;
  target: string;
}

export interface FlowsAnnotation extends BaseAnnotation {
  verb: 'flows';
  source: string;
  target: string;
  mechanism?: string;
}

export interface BoundaryAnnotation extends BaseAnnotation {
  verb: 'boundary';
  asset_a: string;
  asset_b: string;
  id?: string;
}

export interface ValidatesAnnotation extends BaseAnnotation {
  verb: 'validates';
  control: string;
  asset: string;
}

export interface AuditAnnotation extends BaseAnnotation {
  verb: 'audit';
  asset: string;
}

export interface OwnsAnnotation extends BaseAnnotation {
  verb: 'owns';
  owner: string;
  asset: string;
}

export interface HandlesAnnotation extends BaseAnnotation {
  verb: 'handles';
  classification: DataClassification;
  asset: string;
}

export interface AssumesAnnotation extends BaseAnnotation {
  verb: 'assumes';
  asset: string;
}

export interface ShieldAnnotation extends BaseAnnotation {
  verb: 'shield' | 'shield:begin' | 'shield:end';
}

export interface FeatureAnnotation extends BaseAnnotation {
  verb: 'feature';
  feature: string;
}

export interface CommentAnnotation extends BaseAnnotation {
  verb: 'comment';
}

export type Annotation =
  | AssetAnnotation
  | ThreatAnnotation
  | ControlAnnotation
  | ActorAnnotation
  | MitigatesAnnotation
  | ExposesAnnotation
  | ConfirmedAnnotation
  | AcceptsAnnotation
  | EntitlesAnnotation
  | TransfersAnnotation
  | FlowsAnnotation
  | BoundaryAnnotation
  | ValidatesAnnotation
  | AuditAnnotation
  | OwnsAnnotation
  | HandlesAnnotation
  | AssumesAnnotation
  | FeatureAnnotation
  | CommentAnnotation
  | ShieldAnnotation;

// ─── Report Metadata ─────────────────────────────────────────────────

/**
 * Provenance metadata embedded in every report JSON.
 * Enables merge to verify sources and diff to track history.
 */
export interface ReportMetadata {
  /** Schema version for the report JSON format (semver) */
  schema_version: string;
  /** GuardLink CLI version that generated this report */
  guardlink_version: string;
  /** Repository name (from workspace.yaml this_repo, or project name) */
  repo: string;
  /** Git commit SHA at generation time (null if not a git repo) */
  commit_sha: string | null;
  /** Git branch at generation time (null if not a git repo) */
  branch: string | null;
  /** ISO 8601 timestamp of report generation */
  generated_at: string;
  /** Workspace name if this repo is part of a workspace */
  workspace?: string;
  /**
   * Content hash of the annotation set (GL-101), as `sha256-v<n>:<hex>`.
   *
   * Stable across annotation modes, file order and cosmetic code edits — it moves
   * only when an annotation is added, edited or deleted. Use it to tell whether a
   * derived artifact still describes the current model.
   */
  annotation_hash?: string;
}

// ─── External References ─────────────────────────────────────────────

/**
 * A tag reference that points to a definition in another repo.
 * Detected during parsing when a tag uses a service prefix not
 * matching any local asset/threat/control definition.
 */
export interface ExternalRef {
  /** The referenced tag (e.g. "#auth-lib.token-verify") */
  tag: string;
  /** The verb context where this ref appears (e.g. "mitigates", "flows") */
  context_verb: AnnotationVerb;
  /** Where the reference was found */
  location: SourceLocation;
  /** Inferred target repo from tag prefix (e.g. "auth-lib") */
  inferred_repo?: string;
}

// ─── Threat Model (§5.1) ─────────────────────────────────────────────

export interface ThreatModel {
  version: string;
  project: string;
  generated_at: string;
  source_files: number;
  annotations_parsed: number;
  annotated_files: string[];
  unannotated_files: string[];

  /** Report provenance — always populated in report JSON output */
  metadata?: ReportMetadata;

  /** Cross-repo tag references detected during parsing */
  external_refs?: ExternalRef[];

  /** User-provided project description / threat model prompt (from .guardlink/prompt.md) */
  prompt?: string;

  /** Feature names this model was narrowed to, when it is the result of
   *  filterByFeature. Absent on an unfiltered model. */
  filtered_by_features?: string[];

  assets: ThreatModelAsset[];
  threats: ThreatModelThreat[];
  controls: ThreatModelControl[];
  /** Declared principals (@actor). Optional so report JSON written before
   *  v1.6 still satisfies the schema — always populated by parseProject. */
  actors?: ThreatModelActor[];
  /** Entitlement claims (@entitles). Optional for the same reason as `actors`. */
  entitlements?: ThreatModelEntitlement[];
  mitigations: ThreatModelMitigation[];
  exposures: ThreatModelExposure[];
  confirmed: ThreatModelConfirmed[];
  acceptances: ThreatModelAcceptance[];
  transfers: ThreatModelTransfer[];
  flows: ThreatModelFlow[];
  boundaries: ThreatModelBoundary[];
  validations: ThreatModelValidation[];
  audits: ThreatModelAudit[];
  ownership: ThreatModelOwnership[];
  data_handling: ThreatModelDataHandling[];
  assumptions: ThreatModelAssumption[];
  shields: ThreatModelShield[];
  features: ThreatModelFeature[];
  comments: ThreatModelComment[];

  coverage: CoverageStats;
}

export interface ThreatModelAsset {
  path: string[];
  id?: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelThreat {
  name: string;
  canonical_name: string;
  id?: string;
  severity?: Severity;
  external_refs: string[];
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelControl {
  name: string;
  canonical_name: string;
  id?: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelActor {
  name: string;
  canonical_name: string;
  id?: string;
  description?: string;
  location: SourceLocation;
}

/**
 * A file:line pointer, extracted from an @entitles description, at the
 * authorization code that grants the entitlement. §3.4: no citation, no effect.
 */
export interface EntitlementCitation {
  /** Path as written in the description (e.g. "common/api/metadata.go") */
  file: string;
  /** Line number if the citation carried one */
  line?: number;
  /** The citation token verbatim, for display */
  raw: string;
}

/**
 * Why an entitlement may not demote a finding. `uncited` (§3.4) and the two
 * halves of the join (§9.3) are independent conditions, reported separately
 * because a reviewer fixing the claim needs to know which one is missing (§9.8).
 */
export type EntitlementDemotionBlocker = 'uncited' | 'no-asset' | 'no-threat';

export interface ThreatModelEntitlement {
  actor: string;
  capability: string;
  /**
   * §2.10-normalised capability. NOT the join key — the join is
   * `(actor, asset, threat)` (§9.3). Triage holds an `(asset, threat)` pair and
   * a measured role; no capability is recorded anywhere on the finding side, so
   * a capability-keyed join could never match. What this field carries is the
   * justification a reviewer reads, and a label to group claims by.
   */
  canonical_capability: string;
  /** `on <asset>` — half of the join key (§9.3) */
  asset?: string;
  /** `against <threat>` — the other half of the join key (§9.3) */
  threat?: string;
  description?: string;
  /** Extracted from `description`; absent when the claim is uncited */
  citation?: EntitlementCitation;
  /**
   * True when no citation could be extracted. An inert entitlement is parsed
   * and carried in the model but MUST NOT demote a finding (§3.4).
   */
  inert: boolean;
  /**
   * True when `asset` or `threat` is missing, so the claim joins nothing and
   * MUST NOT demote a finding (§9.3). Stored rather than left to the reader for
   * the same reason `inert` is: the imprecise form is deliberately not an error
   * and not a warning, so nothing else warns a consumer about it. Independent of
   * `inert` — a claim can be cited and imprecise, or precise and uncited. Use
   * `canEntitlementDemote` rather than ANDing these two by hand.
   */
  imprecise: boolean;
  location: SourceLocation;
}

export interface ThreatModelMitigation {
  asset: string;
  threat: string;
  control?: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelExposure {
  asset: string;
  threat: string;
  severity?: Severity;
  external_refs: string[];
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelConfirmed {
  threat: string;
  asset: string;
  severity?: Severity;
  external_refs: string[];
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelAcceptance {
  threat: string;
  asset: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelTransfer {
  threat: string;
  source: string;
  target: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelFlow {
  source: string;
  target: string;
  mechanism?: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelBoundary {
  asset_a: string;
  asset_b: string;
  id?: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelValidation {
  control: string;
  asset: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelAudit {
  asset: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelOwnership {
  owner: string;
  asset: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelDataHandling {
  classification: DataClassification;
  asset: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelAssumption {
  asset: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelShield {
  reason?: string;
  location: SourceLocation;
}

export interface ThreatModelFeature {
  feature: string;
  description?: string;
  location: SourceLocation;
}

export interface ThreatModelComment {
  description?: string;
  location: SourceLocation;
}

export interface CoverageStats {
  /**
   * Annotations parsed across the project.
   *
   * Was `annotated_symbols` through model version 1.1.0. It never counted
   * symbols — GuardLink does no per-symbol parsing — and the name is what led
   * three consumers to divide it by a denominator that did not exist. Renamed
   * with the 1.2.0 model bump.
   */
  annotation_count: number;
  /**
   * Percentage of scanned source files carrying at least one annotation.
   *
   * D14: this was hardcoded 0 and never computed for a single repo, while three
   * consumers displayed it — the dashboard showed "0% coverage" on a fully
   * annotated project. It is real now, and comparable across annotation modes
   * because GL-502 made both sides of the ratio mode-invariant.
   */
  coverage_percent: number;
}

// `total_symbols` (permanently 0) and `unannotated_critical` (permanently [])
// were removed in model version 1.2.0 along with the `UnannotatedSymbol` type
// that existed only to describe the latter. Both were hardcoded constants in a
// schema presented as public, so a consumer could not distinguish "not
// computed" from "computed, and it is zero". Absent says the first; 0 said the
// second. Per-symbol coverage would need a real implementation, not a field.

// ─── Parse Diagnostics ───────────────────────────────────────────────

/**
 * A parse-time issue surfaced by the annotation pipeline. Severity tiers:
 *
 * - `'warning'`: informational only; never blocks. Use for stylistic
 *   concerns, deprecation notices, or non-actionable observations.
 * - `'error'`: a specific annotation could not be parsed or resolved.
 *   The affected annotation is skipped; the rest of the model still
 *   renders. This is the default tier for malformed `@<verb>` lines,
 *   dangling refs, and similar localized failures.
 * - `'fatal'`: the model as a whole is unsafe to consume — e.g. an
 *   entirely unparseable `definitions.ts`, an unrecoverable schema
 *   version mismatch on a saved report, or any condition where
 *   continuing would produce a structurally invalid threat model.
 *   Consumers seeing a fatal MUST abort rather than render partial
 *   results.
 *
 * `'fatal'` is reserved vocabulary: it is declared here and nothing in
 * `src/` emits it. That is deliberate, and it carries a trap for whoever
 * emits the first one.
 *
 * Every gate in this codebase tests `d.level === 'error'` exactly. None
 * of them tests for `'fatal'`. A diagnostic that is more severe than an
 * error would therefore pass straight through the checks an error fails
 * — `guardlink parse` and `guardlink validate` would exit 0 on a model
 * they had just declared unsafe to consume. The tier is inert today
 * precisely because nothing emits it, so this is latent, not live.
 *
 * The invariant to restore before the first emission: **anything that
 * blocks on `'error'` must also block on `'fatal'`.** The filters, by
 * file — verified at the 2.0.0 freeze, treat as a starting point rather
 * than a closed list:
 *
 *     src/cli/index.ts        9
 *     src/tui/commands.ts     3
 *     src/workspace/merge.ts  2
 *     src/types/index.ts      2   (this doc block)
 *     src/mcp/server.ts       1
 *
 * Deleting the `'fatal'` member instead is a legitimate resolution — it
 * has never been used, and a tier no consumer can receive is not a tier.
 * See docs/prd/BACKLOG.md.
 */
/**
 * Machine-readable diagnostic kinds.
 *
 * Added for D29 so consumers can group and filter without matching on message
 * prose. A renderer that greps the human-readable text is a renderer that
 * breaks when the text is reworded.
 */
export type DiagnosticCode =
  // ── Parse-time (src/parser/parse-line.ts, parse-project.ts) ──
  /** Line starts with a known verb, carries structural evidence, and failed to parse. */
  | 'malformed-annotation'
  /** Line starts with a known verb but has no structural evidence — prose about GuardLink. */
  | 'prose-like'
  /** Line starts with an unknown `@verb` that is one or two edits from a known one. */
  | 'unknown-verb'
  /** Two definitions claim the same `(#id)`. */
  | 'duplicate-id'
  // ── Validation-time (src/parser/validate.ts) ──
  /** A `#id` reference resolves to no definition. */
  | 'dangling-ref'
  /** `@entitles` names an actor never declared with `@actor`. */
  | 'undeclared-actor'
  /** `@entitles` cites no authz code, so it can never demote a finding. */
  | 'inert-entitlement'
  /** `@entitles` cites authz code too imprecisely to be checked. */
  | 'imprecise-entitlement'
  /** `@accepts` with no paired `@audit` — acceptance without a traceable review. */
  | 'accepted-without-audit'
  /** A `.gal` sidecar sits somewhere other than its conventional path. */
  | 'off-convention-gal'
  /** An on-convention `.gal` sidecar carries `@source` blocks for other files. */
  | 'stray-gal-source'
  // ── Governance (src/review/entitlements.ts) ──
  /** An `@entitles` in source with no accepted proposal behind it. */
  | 'entitlement-provenance';

export interface ParseDiagnostic {
  level: 'error' | 'warning' | 'fatal';
  message: string;
  file: string;
  line: number;
  raw?: string;
  /** Present on diagnostics that have a defined kind; absent on ad-hoc ones. */
  code?: DiagnosticCode;
}

export interface ParseResult {
  annotations: Annotation[];
  diagnostics: ParseDiagnostic[];
  files_parsed: number;
}
