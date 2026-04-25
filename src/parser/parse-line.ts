/**
 * GuardLink — Line-level annotation parser.
 * Parses a single comment line into a typed Annotation.
 *
 * @exposes #parser to #redos [medium] cwe:CWE-1333 -- "Complex regex patterns applied to annotation text"
 * @mitigates #parser against #redos using #regex-anchoring -- "All patterns are anchored (^...$) to prevent backtracking"
 * @comment -- "Regex patterns designed with bounded quantifiers and explicit structure"
 */

import type {
  Annotation, AnnotationVerb, Severity, DataClassification,
  ParseDiagnostic, SourceLocation,
} from '../types/index.js';
import { normalizeName, resolveSeverity, unescapeDescription } from './normalize.js';

// ─── Shared regex fragments ──────────────────────────────────────────

const COMPONENT = String.raw`[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*`;
// Quoted ref: any non-newline content between double quotes, with `\"` and
// `\\` escape support. Mirrors the DESC fragment's character class.
const QUOTED_REF = String.raw`"(?:[^"\\\n]|\\.)*"`;
const ASSET_REF = String.raw`(?:#[a-zA-Z0-9_-]+|${QUOTED_REF}|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)`;  // #id, "quoted", or Dotted.Path
const NAME      = String.raw`[A-Za-z]\w*(?:[_\- ][A-Za-z]\w*)*`;
const ID_DEF    = String.raw`\(#([a-zA-Z0-9_-]+)\)`;
const ID_REF    = String.raw`#([a-zA-Z0-9_-]+)`;
const THREAT_REF = String.raw`(?:#[a-zA-Z0-9_-]+|${QUOTED_REF}|[A-Za-z]\w*(?:[_\- ][A-Za-z]\w*)*)`;
const SEVERITY  = String.raw`\[(P[0-3]|critical|high|medium|low)\]`;
const EXT_REF   = String.raw`([a-zA-Z]+:[A-Za-z0-9_:.\-]+)`;
const DESC      = String.raw`--\s*"((?:[^"\\]|\\.)*)"`;

// Capture external refs (0 or more, space-separated)
const EXT_REFS_OPT = String.raw`((?:\s+[a-zA-Z]+:[A-Za-z0-9_:.\-]+)*)`;

// ─── Verb-specific patterns ──────────────────────────────────────────

const PATTERNS: Record<string, RegExp> = {
  // Definition — asset path must be dotted COMPONENT
  asset:   new RegExp(String.raw`^@asset\s+(${COMPONENT})(?:\s+${ID_DEF})?(?:\s+${DESC})?$`),
  threat:  new RegExp(String.raw`^@threat\s+(${NAME})(?:\s+${ID_DEF})?(?:\s+${SEVERITY})?${EXT_REFS_OPT}(?:\s+${DESC})?$`),
  control: new RegExp(String.raw`^@control\s+(${NAME})(?:\s+${ID_DEF})?(?:\s+${DESC})?$`),

  // Relationship — asset positions accept #id OR Dotted.Path via ASSET_REF
  mitigates: new RegExp(String.raw`^@mitigates\s+(${ASSET_REF})\s+against\s+(${THREAT_REF})(?:\s+using\s+(${THREAT_REF}))?(?:\s+${DESC})?$`),
  mitigates_v1: new RegExp(String.raw`^@mitigates\s+(${ASSET_REF})\s+against\s+(${THREAT_REF})(?:\s+with\s+(${THREAT_REF}))?(?:\s+${DESC})?$`),
  exposes: new RegExp(String.raw`^@exposes\s+(${ASSET_REF})\s+to\s+(${THREAT_REF})(?:\s+${SEVERITY})?${EXT_REFS_OPT}(?:\s+${DESC})?$`),
  confirmed: new RegExp(String.raw`^@confirmed\s+(${THREAT_REF})\s+on\s+(${ASSET_REF})(?:\s+${SEVERITY})?${EXT_REFS_OPT}(?:\s+${DESC})?$`),
  accepts: new RegExp(String.raw`^@accepts\s+(${THREAT_REF})\s+on\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  accepts_v1: new RegExp(String.raw`^@accepts\s+(${THREAT_REF})\s+to\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  transfers: new RegExp(String.raw`^@transfers\s+(${THREAT_REF})\s+from\s+(${ASSET_REF})\s+to\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  flows: new RegExp(String.raw`^@flows\s+(${ASSET_REF}(?:\s+->\s+${ASSET_REF})+)(?:\s+via\s+((?:(?!\s+--\s*").)+?))?(?:\s+${DESC})?$`),
  boundary: new RegExp(String.raw`^@boundary\s+(?:between\s+)?(${ASSET_REF})\s+and\s+(${ASSET_REF})(?:\s+${ID_DEF})?(?:\s+${DESC})?$`),
  boundary_pipe: new RegExp(String.raw`^@boundary\s+(${ASSET_REF})\s*\|\s*(${ASSET_REF})(?:\s+${ID_DEF})?(?:\s+${DESC})?$`),
  connects_v1: new RegExp(String.raw`^@connects\s+(${ASSET_REF})\s+to\s+(${ASSET_REF})(?:\s+${DESC})?$`),

  // Lifecycle — asset positions accept #id OR Dotted.Path
  validates: new RegExp(String.raw`^@validates\s+(${THREAT_REF})\s+for\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  audit: new RegExp(String.raw`^@audit\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  review_v1: new RegExp(String.raw`^@review\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  owns: new RegExp(String.raw`^@owns\s+([a-zA-Z0-9_-]+)\s+for\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  handles: new RegExp(String.raw`^@handles\s+(pii|phi|financial|secrets|internal|public)\s+on\s+(${ASSET_REF})(?:\s+${DESC})?$`, 'i'),
  assumes: new RegExp(String.raw`^@assumes\s+(${ASSET_REF})(?:\s+${DESC})?$`),

  // Metadata — feature tagging
  feature: new RegExp(String.raw`^@feature\s+"((?:[^"\\]|\\.)*)"(?:\s+${DESC})?$`),

  // Comment — developer note, description only
  comment: new RegExp(String.raw`^@comment(?:\s+${DESC})?$`),

  // Special
  shield: new RegExp(String.raw`^@shield(?!:)(?:\s+${DESC})?$`),
  shield_begin: new RegExp(String.raw`^@shield:begin(?:\s+${DESC})?$`),
  shield_end: /^@shield:end$/,
};

// ─── External ref extractor ──────────────────────────────────────────

function extractExternalRefs(raw: string | undefined): string[] {
  if (!raw || !raw.trim()) return [];
  return raw.trim().split(/\s+/).filter(r => /^[a-zA-Z]+:[A-Za-z0-9_:.\-]+$/.test(r));
}

// ─── Ref resolver: #id, "quoted", or Dotted.Path → canonical string ───

/** Normalize a captured ASSET_REF or THREAT_REF for storage in the model.
 *  Strips surrounding double quotes and processes escape sequences (\", \\)
 *  when the user wrote a quoted ref like `"User Browser"` or `"/api/login"`.
 *  Pass-through for `#id` and `Dotted.Path` forms. */
function resolveRef(ref: string): string {
  if (ref.length >= 2 && ref.charCodeAt(0) === 0x22 /* " */ && ref.charCodeAt(ref.length - 1) === 0x22) {
    return unescapeDescription(ref.slice(1, -1));
  }
  return ref;
}

// ─── Main parser ─────────────────────────────────────────────────────

export interface ParseLineResult {
  annotation: Annotation | null;
  /** Additional annotations from the same line. Used by multi-hop @flows
   *  chains (`A -> B -> C`) to emit one pairwise flow per arrow. */
  extraAnnotations?: Annotation[];
  diagnostic: ParseDiagnostic | null;
  isContinuation: boolean;
}

/**
 * Parse a single annotation line (after comment prefix has been stripped).
 * Returns the typed annotation, a diagnostic if parsing failed, or null if
 * the line is not an annotation.
 */
export function parseLine(
  text: string,
  location: SourceLocation,
): ParseLineResult {
  const trimmed = text.trim();

  // Not an annotation
  if (!trimmed.startsWith('@')) {
    // Check for continuation line (-- "...")
    const contMatch = trimmed.match(new RegExp(String.raw`^${DESC}$`));
    if (contMatch) {
      return { annotation: null, diagnostic: null, isContinuation: true };
    }
    return { annotation: null, diagnostic: null, isContinuation: false };
  }

  const base = { location, raw: trimmed };
  let m: RegExpMatchArray | null;

  // ── @asset ──
  if ((m = trimmed.match(PATTERNS.asset))) {
    return ok({ ...base, verb: 'asset', path: m[1], id: m[2], description: desc(m[3]) });
  }

  // ── @threat ──
  if ((m = trimmed.match(PATTERNS.threat))) {
    const name = m[1];
    return ok({
      ...base, verb: 'threat', name, canonical_name: normalizeName(name),
      id: m[2], severity: m[3] ? resolveSeverity(m[3]) : undefined,
      external_refs: extractExternalRefs(m[4]), description: desc(m[5]),
    });
  }

  // ── @control ──
  if ((m = trimmed.match(PATTERNS.control))) {
    const name = m[1];
    return ok({
      ...base, verb: 'control', name, canonical_name: normalizeName(name),
      id: m[2], description: desc(m[3]),
    });
  }

  // ── @mitigates ──
  if ((m = trimmed.match(PATTERNS.mitigates)) || (m = trimmed.match(PATTERNS.mitigates_v1))) {
    return ok({
      ...base, verb: 'mitigates', asset: resolveRef(m[1]),
      threat: resolveRef(m[2]), control: m[3] ? resolveRef(m[3]) : undefined,
      description: desc(m[4]),
    });
  }

  // ── @exposes ──
  if ((m = trimmed.match(PATTERNS.exposes))) {
    return ok({
      ...base, verb: 'exposes', asset: resolveRef(m[1]), threat: resolveRef(m[2]),
      severity: m[3] ? resolveSeverity(m[3]) : undefined,
      external_refs: extractExternalRefs(m[4]), description: desc(m[5]),
    });
  }

  // ── @confirmed ──
  if ((m = trimmed.match(PATTERNS.confirmed))) {
    return ok({
      ...base, verb: 'confirmed', threat: resolveRef(m[1]), asset: resolveRef(m[2]),
      severity: m[3] ? resolveSeverity(m[3]) : undefined,
      external_refs: extractExternalRefs(m[4]), description: desc(m[5]),
    });
  }

  // ── @accepts ──
  if ((m = trimmed.match(PATTERNS.accepts)) || (m = trimmed.match(PATTERNS.accepts_v1))) {
    return ok({ ...base, verb: 'accepts', threat: resolveRef(m[1]), asset: resolveRef(m[2]), description: desc(m[3]) });
  }

  // ── @transfers ──
  if ((m = trimmed.match(PATTERNS.transfers))) {
    return ok({
      ...base, verb: 'transfers', threat: resolveRef(m[1]),
      source: resolveRef(m[2]), target: resolveRef(m[3]), description: desc(m[4]),
    });
  }

  // ── @flows ──
  // Single-hop `A -> B` is a chain of length 2 producing one flow.
  // Multi-hop `A -> B -> C -> D` is treated as syntactic sugar for N-1
  // pairwise flows — each emitted flow shares the mechanism, description,
  // and source location with every other hop in the chain.
  if ((m = trimmed.match(PATTERNS.flows))) {
    // Use matchAll instead of split so quoted refs containing literal
    // `->` sequences (e.g. `"step1 -> step2"`) aren't shredded by the
    // arrow separator. The outer regex has already validated chain shape.
    const participants = [...m[1].matchAll(new RegExp(ASSET_REF, 'g'))]
      .map(mm => resolveRef(mm[0]));
    const mechanism = m[2]?.trim();
    const description = desc(m[3]);
    const flows = [];
    for (let i = 0; i < participants.length - 1; i++) {
      flows.push({
        ...base, verb: 'flows' as const,
        source: participants[i], target: participants[i + 1],
        mechanism, description,
      });
    }
    return okMulti(flows);
  }

  // ── @boundary ──
  if ((m = trimmed.match(PATTERNS.boundary))) {
    return ok({
      ...base, verb: 'boundary', asset_a: resolveRef(m[1]), asset_b: resolveRef(m[2]),
      id: m[3], description: desc(m[4]),
    });
  }

  // ── @boundary pipe shorthand: @boundary A | B ──
  if ((m = trimmed.match(PATTERNS.boundary_pipe))) {
    return ok({
      ...base, verb: 'boundary', asset_a: resolveRef(m[1]), asset_b: resolveRef(m[2]),
      id: m[3], description: desc(m[4]),
    });
  }

  // ── @connects (v1 → flows) ──
  if ((m = trimmed.match(PATTERNS.connects_v1))) {
    return ok({
      ...base, verb: 'flows', source: resolveRef(m[1]), target: resolveRef(m[2]), description: desc(m[3]),
    });
  }

  // ── @validates ──
  if ((m = trimmed.match(PATTERNS.validates))) {
    return ok({ ...base, verb: 'validates', control: resolveRef(m[1]), asset: resolveRef(m[2]), description: desc(m[3]) });
  }

  // ── @audit / @review (v1) ──
  if ((m = trimmed.match(PATTERNS.audit)) || (m = trimmed.match(PATTERNS.review_v1))) {
    return ok({ ...base, verb: 'audit', asset: resolveRef(m[1]), description: desc(m[2]) });
  }

  // ── @owns ──
  if ((m = trimmed.match(PATTERNS.owns))) {
    return ok({ ...base, verb: 'owns', owner: m[1], asset: resolveRef(m[2]), description: desc(m[3]) });
  }

  // ── @handles ──
  if ((m = trimmed.match(PATTERNS.handles))) {
    return ok({
      ...base, verb: 'handles',
      classification: m[1].toLowerCase() as DataClassification,
      asset: resolveRef(m[2]), description: desc(m[3]),
    });
  }

  // ── @assumes ──
  if ((m = trimmed.match(PATTERNS.assumes))) {
    return ok({ ...base, verb: 'assumes', asset: resolveRef(m[1]), description: desc(m[2]) });
  }

  // ── @feature ──
  if ((m = trimmed.match(PATTERNS.feature))) {
    return ok({ ...base, verb: 'feature', feature: unescapeDescription(m[1]), description: desc(m[2]) });
  }

  // ── @comment ──
  if ((m = trimmed.match(PATTERNS.comment))) {
    return ok({ ...base, verb: 'comment', description: desc(m[1]) });
  }

  // ── @shield ──
  if ((m = trimmed.match(PATTERNS.shield_begin))) {
    return ok({ ...base, verb: 'shield:begin', description: desc(m[1]) });
  }
  if (trimmed.match(PATTERNS.shield_end)) {
    return ok({ ...base, verb: 'shield:end' });
  }
  if ((m = trimmed.match(PATTERNS.shield))) {
    return ok({ ...base, verb: 'shield', description: desc(m[1]) });
  }

  // Starts with @ but didn't match — likely a malformed annotation
  const verbMatch = trimmed.match(/^@(\S+)/);
  if (verbMatch) {
    const knownVerbs: Set<string> = new Set([
      'asset', 'threat', 'control', 'mitigates', 'exposes', 'confirmed', 'accepts',
      'transfers', 'flows', 'boundary', 'validates', 'audit', 'owns',
      'handles', 'assumes', 'feature', 'comment', 'shield', 'shield:begin', 'shield:end',
      // v1 compat
      'review', 'connects',
    ]);
    if (knownVerbs.has(verbMatch[1])) {
      return {
        annotation: null,
        diagnostic: {
          level: 'error',
          message: `Malformed @${verbMatch[1]} annotation: could not parse arguments`,
          file: location.file,
          line: location.line,
          raw: trimmed,
        },
        isContinuation: false,
      };
    }
  }

  // Not a GuardLink annotation (could be @param, @returns, etc.)
  return { annotation: null, diagnostic: null, isContinuation: false };
}

// ─── Helpers ─────────────────────────────────────────────────────────

function ok(annotation: Annotation): ParseLineResult {
  return { annotation, diagnostic: null, isContinuation: false };
}

/** Like ok(), but for parser branches that emit multiple annotations from
 *  one line (currently only multi-hop @flows chains). The first annotation
 *  becomes the primary `annotation`; the remainder go in `extraAnnotations`
 *  so the call site can push them all and update lastAnnotation correctly. */
function okMulti(annotations: Annotation[]): ParseLineResult {
  if (annotations.length === 0) {
    return { annotation: null, diagnostic: null, isContinuation: false };
  }
  return {
    annotation: annotations[0],
    extraAnnotations: annotations.length > 1 ? annotations.slice(1) : undefined,
    diagnostic: null,
    isContinuation: false,
  };
}

function desc(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  return unescapeDescription(raw);
}
