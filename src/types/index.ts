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
  | 'asset' | 'threat' | 'control'
  // Relationship
  | 'mitigates' | 'exposes' | 'accepts' | 'transfers' | 'flows' | 'boundary'
  // Lifecycle
  | 'validates' | 'audit' | 'owns' | 'handles' | 'assumes'
  // Special
  | 'comment' | 'shield' | 'shield:begin' | 'shield:end';

// ─── Location ────────────────────────────────────────────────────────

export interface SourceLocation {
  file: string;
  line: number;
  end_line?: number | null;
  parent_symbol?: string | null;
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

export interface AcceptsAnnotation extends BaseAnnotation {
  verb: 'accepts';
  threat: string;
  asset: string;
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

export interface CommentAnnotation extends BaseAnnotation {
  verb: 'comment';
}

export type Annotation =
  | AssetAnnotation
  | ThreatAnnotation
  | ControlAnnotation
  | MitigatesAnnotation
  | ExposesAnnotation
  | AcceptsAnnotation
  | TransfersAnnotation
  | FlowsAnnotation
  | BoundaryAnnotation
  | ValidatesAnnotation
  | AuditAnnotation
  | OwnsAnnotation
  | HandlesAnnotation
  | AssumesAnnotation
  | CommentAnnotation
  | ShieldAnnotation;

// ─── Threat Model (§5.1) ─────────────────────────────────────────────

export interface ThreatModel {
  version: string;
  project: string;
  generated_at: string;
  source_files: number;
  annotations_parsed: number;

  assets: ThreatModelAsset[];
  threats: ThreatModelThreat[];
  controls: ThreatModelControl[];
  mitigations: ThreatModelMitigation[];
  exposures: ThreatModelExposure[];
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

export interface ThreatModelComment {
  description?: string;
  location: SourceLocation;
}

export interface CoverageStats {
  total_symbols: number;
  annotated_symbols: number;
  coverage_percent: number;
  unannotated_critical: UnannotatedSymbol[];
}

export interface UnannotatedSymbol {
  file: string;
  line: number;
  kind: string;
  name: string;
}

// ─── Parse Diagnostics ───────────────────────────────────────────────

export interface ParseDiagnostic {
  level: 'error' | 'warning';
  message: string;
  file: string;
  line: number;
  raw?: string;
}

export interface ParseResult {
  annotations: Annotation[];
  diagnostics: ParseDiagnostic[];
  files_parsed: number;
}
