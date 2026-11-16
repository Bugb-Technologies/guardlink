/** Public application-view contract. All paths here are member/application relative. */
import type { AgentConfigBlock, ParseDiagnostic, SourceLocation, ThreatModel } from '../types/index.js';
import type { VerificationReport } from '../parser/verification.js';
import type { HypothesesRead } from '../hypothesis/ledger.js';

export type ApplicationScope = { kind: 'repository'; applicationId?: string; memberId: string }
  | { kind: 'application'; applicationId: string; memberIds: string[] };
export interface ApplicationRevision {
  vcs: 'git' | 'none'; commit: string | null; branch: string | null; detached: boolean | null;
  baseRef: string | null; baseCommit: string | null; dirty: boolean | null;
  contentDigest: string; annotationDigest: string; configDigest: string;
}
export interface ApplicationMemberReceipt {
  id: string; guardlinkIdentity: string; service: string; relativePath: string;
  revision: ApplicationRevision | null;
  state: 'available' | 'missing' | 'unreadable' | 'invalid'; reason?: string; reasonCode?: string;
  repositoryUri?: string;
  components: Record<string, { state: 'present' | 'partial' | 'missing' | 'failed' | 'unsupported'; indexedRevision?: ApplicationRevision; reason?: string }>;
}
export interface ApplicationReceipt {
  schema: 'bravos.application-view/v1'; scope: ApplicationScope; generatedAt: string; inputDigest: string;
  expectedMemberIds: string[]; members: ApplicationMemberReceipt[];
  completeness: 'complete' | 'partial' | 'unavailable'; revisions: Record<string, ApplicationRevision | null>;
  tools: Record<string, { version: string; contractVersion: string }>;
  observedInputDigest?: string;
  currency?: { state: 'current' | 'stale' | 'unknown'; reasonCodes: string[]; memberIds: string[] };
}
export interface ApplicationManifestMember {
  id?: string; name?: string; guardlinkIdentity?: string; service?: string;
  relativePath?: string; path?: string; baseRef?: string; baseCommit?: string;
}
export interface ApplicationManifest {
  schema: 'guardlink.application-manifest/v1' | 'bravos.workspace-consumer/v1';
  name: string; root?: string; members: ApplicationManifestMember[]; receipt?: ApplicationReceipt;
}
export interface ApplicationOccurrence {
  id: string; memberId: string; file: string; line: number; verb: string; claimKey?: string;
  origin?: string; location: SourceLocation;
}
export interface ApplicationReference {
  tag: string; memberId: string; file: string; line: number; verb: string;
  state: 'resolved' | 'unresolved' | 'ambiguous' | 'unchecked'; owners: string[];
  legacy?: boolean;
}
export interface ApplicationFlowGroup {
  id: string; source: string; target: string; mechanism: string; route: unknown;
  declarations: Array<{ memberId: string; file: string; line: number; claimKey?: string }>;
}
export interface ApplicationMemberData {
  id: string; coverage: { annotatedFiles: number; sourceFiles: number; percent: number; excluded: unknown[] } | null;
  agentConfig?: AgentConfigBlock; generatedIdentities: Record<string, string>;
  verification?: VerificationReport; hypotheses?: HypothesesRead;
  diagnostics: ParseDiagnostic[];
}
export interface ApplicationModelData {
  receipt: ApplicationReceipt; members: ApplicationMemberData[]; occurrences: ApplicationOccurrence[];
  definitions: Array<{ kind: string; id: string; declarations: SourceLocation[]; conflicting: boolean }>;
  conflicts: Array<{ kind: string; id: string; memberIds: string[]; declarations: SourceLocation[] }>;
  references: ApplicationReference[]; flowGroups: ApplicationFlowGroup[];
  coverage: { kind: 'annotation-files'; known: { annotatedFiles: number; sourceFiles: number; percent: number }; overallPercent: number | null; unknownMemberIds: string[] };
  verification?: VerificationReport; hypotheses?: HypothesesRead;
  reportLibrary?: { total: number; loaded: number; omitted: number; unreadable: string[] };
}
export interface ApplicationView {
  schema: 'guardlink.application-view/v1'; receipt: ApplicationReceipt; model: ThreatModel;
  diagnostics: ParseDiagnostic[]; references: ApplicationReference[]; flowGroups: ApplicationFlowGroup[];
}
