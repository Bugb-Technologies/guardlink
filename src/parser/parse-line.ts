/**
 * GuardLink — Line-level annotation parser.
 * Parses a single comment line into a typed Annotation.
 *
 * @exposes #parser to #redos [medium] cwe:CWE-1333 -- "Complex regex patterns applied to annotation text"
 * @mitigates #parser against #redos using #regex-anchoring -- "All patterns are anchored (^...$) to prevent backtracking"
 * @comment -- "Regex patterns designed with bounded quantifiers and explicit structure"
 * @comment -- "@entitles capability is a single-token identifier by grammar, so prose in that position is a parse error rather than a label nothing can group or compare (actor-entitlement design §3.1)"
 * @comment -- "@entitles takes optional `on <asset>` and `against <threat>` clauses because the join is the (actor, asset, threat) triple, not the capability — a capability-keyed join would demote every threat on the asset including one discovered later (actor-entitlement design §9.3)"
 */

import type {
  Annotation, DataClassification,
  ParseDiagnostic, SourceLocation,
} from '../types/index.js';
import { normalizeName, resolveSeverity, unescapeDescription } from './normalize.js';

// ─── Shared regex fragments ──────────────────────────────────────────

const COMPONENT = String.raw`[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*`;
// Quoted ref: any non-newline content between double quotes, with `\"` and
// `\\` escape support. Mirrors the DESC fragment's character class.
const QUOTED_REF = String.raw`"(?:[^"\\\n]|\\.)*"`;

/**
 * One segment of a `#tag`. Ids are lowercase-kebab by convention but the
 * charset has always been permissive; this is the existing `#id` charset,
 * named so the tag grammar has exactly one definition of it.
 */
const TAG_SEGMENT = String.raw`[a-zA-Z0-9_-]+`;

/**
 * A `#tag`, optionally qualified by a repo prefix: `#cli`, `#auth-lib.token-verify`.
 *
 * D19: the `#` alternative used to be a single segment with no dots, while the
 * dotted alternative (`Dotted.Path`, below) excluded `#` and hyphens. So the
 * documented cross-repo form `#auth-lib.token-verify` matched `#auth-lib` and
 * the remainder died on the `$` anchor — the tool's own canonical example, and
 * both rules `guardlink_workspace_info` emits to teach the syntax, were
 * unwritable. Cross-repo tags parsed only when quoted.
 *
 * These are two different namespaces and were never one alternative:
 *   - `#tag` ids: kebab-case, `#`-prefixed, qualified across repos by `.`
 *   - `Dotted.Path` names: `App.API`, identifier segments, no hyphens
 * Qualifying a tag is repeating a segment, so it belongs in the tag rule.
 *
 * Strictly a superset: every string that parsed before still parses. The only
 * inputs whose behaviour changes are ones that previously produced a
 * diagnostic. Quoted forms are untouched and keep working for anyone who
 * worked around this by quoting.
 */
const TAG_REF = String.raw`#${TAG_SEGMENT}(?:\.${TAG_SEGMENT})*`;

const ASSET_REF = String.raw`(?:${TAG_REF}|${QUOTED_REF}|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)`;  // #tag, #repo.tag, "quoted", or Dotted.Path
const NAME      = String.raw`[A-Za-z]\w*(?:[_\- ][A-Za-z]\w*)*`;
const ID_DEF    = String.raw`\(#([a-zA-Z0-9_-]+)\)`;   // DEFINITION site — never dotted; you cannot define another repo's id here
/**
 * Threat AND control reference position — `@mitigates X against T using C`
 * routes the control through this same fragment, so there is no separate
 * CONTROL_REF to change.
 *
 * D19 asked whether threats and controls get the dotted form too. They must:
 * `detectExternalRefs` (parse-project.ts) already scans `mitigations[].threat`,
 * `mitigations[].control`, `exposures[].threat`, `acceptances[].threat` and
 * `transfers[].threat` for cross-repo tags, and `guardlink_workspace_info` tells
 * users to "reference sibling assets/threats/controls by their tag prefix". The
 * resolver and the documentation both expected cross-repo threats; only the
 * grammar refused them. "An asset can be cross-repo but a threat cannot" was
 * never a decision anyone made.
 *
 * MERGE (main <- D19): main re-tightened this to a bare `#[a-zA-Z0-9_-]+` when
 * it added @entitles. Kept the D19 superset, which is strictly wider — so
 * `@entitles` and `@actor` gain cross-repo actor and threat refs at no cost,
 * rather than being the one pair of verbs that cannot cross a repo boundary.
 */
const THREAT_REF = String.raw`(?:${TAG_REF}|${QUOTED_REF}|[A-Za-z]\w*(?:[_\- ][A-Za-z]\w*)*)`;
// A capability is a single normalised identifier, never prose. It is not a join
// key (§9.3 — the join is the (actor, asset, threat) triple); it is the
// justification a reviewer reads, and a normalised label to group claims by.
// Keeping it single-token is still what makes it citable and comparable rather
// than a sentence nobody can match on.
const CAPABILITY = String.raw`[A-Za-z][A-Za-z0-9_.\-]*`;
const SEVERITY  = String.raw`\[(P[0-3]|critical|high|medium|low)\]`;
const DESC      = String.raw`--\s*"((?:[^"\\]|\\.)*)"`;
const SOURCE_FILE = String.raw`\S+`;
const SOURCE_LINE = String.raw`[1-9]\d*`;
const SOURCE_SYMBOL = String.raw`\S+`;

// Capture external refs (0 or more, space-separated)
const EXT_REFS_OPT = String.raw`((?:\s+[a-zA-Z]+:[A-Za-z0-9_:.\-]+)*)`;

// ─── Verb-specific patterns ──────────────────────────────────────────

const PATTERNS: Record<string, RegExp> = {
  // Definition — asset path must be dotted COMPONENT
  asset:   new RegExp(String.raw`^@asset\s+(${COMPONENT})(?:\s+${ID_DEF})?(?:\s+${DESC})?$`),
  threat:  new RegExp(String.raw`^@threat\s+(${NAME})(?:\s+${ID_DEF})?(?:\s+${SEVERITY})?${EXT_REFS_OPT}(?:\s+${DESC})?$`),
  control: new RegExp(String.raw`^@control\s+(${NAME})(?:\s+${ID_DEF})?(?:\s+${DESC})?$`),
  actor:   new RegExp(String.raw`^@actor\s+(${NAME})(?:\s+${ID_DEF})?(?:\s+${DESC})?$`),

  // Relationship — asset positions accept #id OR Dotted.Path via ASSET_REF
  mitigates: new RegExp(String.raw`^@mitigates\s+(${ASSET_REF})\s+against\s+(${THREAT_REF})(?:\s+using\s+(${THREAT_REF}))?(?:\s+${DESC})?$`),
  mitigates_v1: new RegExp(String.raw`^@mitigates\s+(${ASSET_REF})\s+against\s+(${THREAT_REF})(?:\s+with\s+(${THREAT_REF}))?(?:\s+${DESC})?$`),
  exposes: new RegExp(String.raw`^@exposes\s+(${ASSET_REF})\s+to\s+(${THREAT_REF})(?:\s+${SEVERITY})?${EXT_REFS_OPT}(?:\s+${DESC})?$`),
  confirmed: new RegExp(String.raw`^@confirmed\s+(${THREAT_REF})\s+on\s+(${ASSET_REF})(?:\s+${SEVERITY})?${EXT_REFS_OPT}(?:\s+${DESC})?$`),
  accepts: new RegExp(String.raw`^@accepts\s+(${THREAT_REF})\s+on\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  accepts_v1: new RegExp(String.raw`^@accepts\s+(${THREAT_REF})\s+to\s+(${ASSET_REF})(?:\s+${DESC})?$`),
  // `against <threat>` is the second half of the join key (§9.3). Both clauses
  // stay optional so the loose form still parses — an imprecise entitlement is
  // harmless because it demotes nothing, whereas making it a parse error would
  // reject a claim a reviewer should get to read.
  entitles: new RegExp(String.raw`^@entitles\s+(${THREAT_REF})\s+to\s+(${CAPABILITY})(?:\s+on\s+(${ASSET_REF}))?(?:\s+against\s+(${THREAT_REF}))?(?:\s+${DESC})?$`),
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

  // Standalone .gal directive — sets logical source location for following annotations
  source: new RegExp(String.raw`^@source\s+file:(${SOURCE_FILE})\s+line:(${SOURCE_LINE})(?:\s+symbol:(${SOURCE_SYMBOL}))?$`),

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
/**
 * Build a cross-repo tag from its parts, using the grammar's own segment rule.
 *
 * D19 happened because every example of this syntax was typed by hand — the
 * canonical one in `parse-project.ts`, and both rules `guardlink_workspace_info`
 * emits — and none of them was ever run through the parser. Callers that need to
 * *show* a cross-repo tag build it here instead of writing `#a.b` in a string,
 * so an example cannot describe a grammar that does not exist.
 *
 * Throws on a segment the grammar cannot express, which is the point: a bad
 * example fails at the source rather than shipping as documentation.
 */
export function crossRepoTag(repo: string, ...components: string[]): string {
  const segment = new RegExp(String.raw`^${TAG_SEGMENT}$`);
  for (const part of [repo, ...components]) {
    if (!segment.test(part)) {
      throw new Error(`Not a valid tag segment: ${JSON.stringify(part)} (allowed: letters, digits, _ and -)`);
    }
  }
  return `#${[repo, ...components].join('.')}`;
}

/** The tag grammar as a standalone anchored matcher — for callers validating one tag. */
export const CROSS_REPO_TAG_PATTERN = new RegExp(String.raw`^${TAG_REF}$`);

function resolveRef(ref: string): string {
  if (ref.length >= 2 && ref.charCodeAt(0) === 0x22 /* " */ && ref.charCodeAt(ref.length - 1) === 0x22) {
    return unescapeDescription(ref.slice(1, -1));
  }
  return ref;
}

// ─── Main parser ─────────────────────────────────────────────────────

export interface SourceDirective {
  file: string;
  line: number;
  symbol?: string;
}

export interface ParseLineResult {
  annotation: Annotation | null;
  /** Additional annotations from the same line. Used by multi-hop @flows
   *  chains (`A -> B -> C`) to emit one pairwise flow per arrow. */
  extraAnnotations?: Annotation[];
  diagnostic: ParseDiagnostic | null;
  isContinuation: boolean;
  sourceDirective?: SourceDirective | null;
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
        return { annotation: null, diagnostic: null, isContinuation: true, sourceDirective: null };
      }
    return { annotation: null, diagnostic: null, isContinuation: false, sourceDirective: null };
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

  // ── @actor ──
  if ((m = trimmed.match(PATTERNS.actor))) {
    const name = m[1];
    return ok({
      ...base, verb: 'actor', name, canonical_name: normalizeName(name),
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

  // ── @entitles ──
  // The claim joins a finding on `(actor, asset, threat)` (§9.3): nothing on the
  // finding side carries a capability, so `to <capability>` cannot be the join —
  // it is the operation a reviewer reads to judge whether the claim is honest.
  // Both `on` and `against` stay optional and are resolved with resolveRef like
  // every other asset/threat ref, so `against "Path Traversal"` and
  // `against #path-traversal` mean the same thing here as they do on @exposes.
  if ((m = trimmed.match(PATTERNS.entitles))) {
    const capability = m[2];
    return ok({
      ...base, verb: 'entitles', actor: resolveRef(m[1]),
      capability, canonical_capability: normalizeName(capability),
      asset: m[3] ? resolveRef(m[3]) : undefined,
      threat: m[4] ? resolveRef(m[4]) : undefined,
      description: desc(m[5]),
    });
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

  // ── @source ──
  if ((m = trimmed.match(PATTERNS.source))) {
    return {
      annotation: null,
      diagnostic: null,
      isContinuation: false,
      sourceDirective: {
        file: m[1],
        line: Number(m[2]),
        symbol: m[3] || undefined,
      },
    };
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

  // Starts with @ but didn't match. Two very different things look like this —
  // see structuralEvidence() for the split (D29).
  //
  // MERGE (main <- D29): main's version carried its own inline verb list, which
  // included @actor and @entitles. Kept D29's tiering and moved those two into
  // KNOWN_VERBS and VERB_KEYWORDS instead, so prose beginning "@actor" warns
  // rather than erroring, like every other verb.
  const verbMatch = trimmed.match(/^@(\S+)\s*([\s\S]*)$/);
  if (verbMatch && KNOWN_VERBS.has(verbMatch[1])) {
    const verb = verbMatch[1];
    const rest = verbMatch[2];
    const evidence = structuralEvidence(verb, rest);

    if (evidence) {
      return {
        annotation: null,
        diagnostic: {
          level: 'error',
          code: 'malformed-annotation',
          message: `Malformed @${verb} annotation: could not parse arguments (looks structural — found ${evidence})`,
          file: location.file,
          line: location.line,
          raw: trimmed,
        },
        isContinuation: false,
      };
    }

    return {
      annotation: null,
      diagnostic: {
        level: 'warning',
        code: 'prose-like',
        message: `Line begins with @${verb} but has no annotation structure — read as prose, not parsed. `
          + `If it IS an annotation, it is missing its arguments. If it is documentation, wrap it in @shield:begin / @shield:end to silence this.`,
        file: location.file,
        line: location.line,
        raw: trimmed,
      },
      isContinuation: false,
    };
  }

  // Not a GuardLink annotation (could be @param, @returns, etc.).
  //
  // Silence is right for @param — it is a JSDoc tag, not a broken GuardLink
  // one — but it was also right for @flow and @migitates, which is the whole
  // problem: a one-character slip produced neither an annotation nor a word.
  // The README shipped @flow twice and nothing ever said so.
  //
  // The discriminator is edit distance. A token within one edit of a known
  // verb is a typo of that verb far more often than it is an unrelated tag;
  // @param is 4 edits from `owns`, its nearest neighbour, so it stays silent.
  // Warning, never error: this is a guess about intent, and a guess does not
  // get to fail a build.
  if (verbMatch) {
    const suggestion = nearestVerb(verbMatch[1]);
    if (suggestion) {
      return {
        annotation: null,
        diagnostic: {
          level: 'warning',
          code: 'unknown-verb',
          message: `Unknown annotation verb @${verbMatch[1]} — did you mean @${suggestion}? `
            + `Unrecognised verbs are discarded silently, so this line contributes nothing to the model.`,
          file: location.file,
          line: location.line,
          raw: trimmed,
        },
        isContinuation: false,
        sourceDirective: null,
      };
    }
  }

  return { annotation: null, diagnostic: null, isContinuation: false, sourceDirective: null };
}

// ─── Helpers ─────────────────────────────────────────────────────────

function ok(annotation: Annotation): ParseLineResult {
  return { annotation, diagnostic: null, isContinuation: false, sourceDirective: null };
}

// ─── D29: prose that starts with a verb vs a broken annotation ───────

const KNOWN_VERBS: ReadonlySet<string> = new Set([
  'asset', 'threat', 'control', 'actor', 'mitigates', 'exposes', 'confirmed', 'accepts', 'entitles',
  'transfers', 'flows', 'boundary', 'validates', 'audit', 'owns',
  'handles', 'assumes', 'feature', 'source', 'comment', 'shield', 'shield:begin', 'shield:end',
  // v1 compat
  'review', 'connects',
]);

/**
 * The keywords each verb's grammar actually uses.
 *
 * PER VERB, not one global list, and that distinction is the whole point.
 * The ruling proposed a single list — to / against / using / -> / from — and
 * measurement argued against it: 3 of 10 realistic prose lines still errored,
 * including the exact line that broke this repo's own validate during the
 * defect sweep ("@feature still claims to describe the model"). `to` is not
 * part of `@feature`'s grammar, so its presence there is English, not
 * structure. Scoping the keyword to the verb that owns it drops that to 1 of
 * 10 while keeping every malformed case an error.
 *
 * A verb with no entry has no keywords: `@audit <asset> -- "why"` is a ref and
 * a delimiter, both of which are already covered as evidence.
 */
/**
 * A token carrying a namespace separator before the verb: `g.comment`, `gl:exposes`.
 *
 * Matched before any distance test. A dialect is a decision; a typo is a slip,
 * and the two do not deserve the same message.
 */
const NAMESPACED_TOKEN = /^[A-Za-z][\w-]*[.:][A-Za-z]/;

/**
 * Documentation tag vocabularies, excluded from distance testing entirely.
 *
 * JSDoc/TSDoc/Closure, Doxygen, phpDoc, and the Epydoc-style `@`-tags that
 * Python docstring conventions inherited. These are not GuardLink verbs and
 * never will be, so no edit distance to one of them is evidence of anything.
 *
 * Measured against juice-shop, bkeeper, ghostfolio and specter-v1, this list
 * suppressed **zero** warnings that the distance rule had not already declined
 * to raise. It is here so that silence on `@param` is a stated guarantee rather
 * than a consequence of `param` sitting four edits from `threat` — a margin
 * that a future verb could close without anyone noticing.
 */
const DOC_TAGS: ReadonlySet<string> = new Set([
  // JSDoc / TSDoc / Closure
  'abstract', 'access', 'alias', 'alpha', 'async', 'augments', 'author', 'beta', 'borrows',
  'callback', 'category', 'categorydescription', 'class', 'classdesc', 'constant', 'constructor',
  'constructs', 'copyright', 'decorator', 'default', 'defaultvalue', 'deprecated', 'desc',
  'description', 'enum', 'event', 'eventproperty', 'example', 'experimental', 'exports', 'extends',
  'external', 'file', 'fileoverview', 'fires', 'func', 'function', 'generator', 'global', 'group',
  'groupdescription', 'hideconstructor', 'host', 'ignore', 'implements', 'inheritdoc', 'inner',
  'instance', 'interface', 'internal', 'kind', 'label', 'lends', 'license', 'link', 'linkcode',
  'linkplain', 'listens', 'member', 'memberof', 'method', 'mixes', 'mixin', 'module', 'name',
  'namespace', 'override', 'overload', 'package', 'packagedocumentation', 'param', 'private',
  'privateremarks', 'prop', 'property', 'protected', 'public', 'readonly', 'remarks', 'requires',
  'return', 'returns', 'satisfies', 'sealed', 'see', 'since', 'static', 'summary', 'template',
  'this', 'throws', 'todo', 'tutorial', 'type', 'typedef', 'var', 'version', 'virtual', 'yield',
  'yields',
  // Doxygen
  'addtogroup', 'anchor', 'arg', 'attention', 'brief', 'bug', 'cite', 'code', 'cond', 'copybrief',
  'copydetails', 'copydoc', 'date', 'def', 'defgroup', 'details', 'dot', 'em', 'endcode', 'endcond',
  'enddot', 'endif', 'endverbatim', 'headerfile', 'image', 'if', 'ingroup', 'invariant', 'li',
  'mainpage', 'msc', 'note', 'page', 'post', 'pre', 'ref', 'relates', 'retval', 'sa', 'section',
  'struct', 'subsection', 'tparam', 'union', 'verbatim', 'warning', 'xrefitem',
  // phpDoc
  'api', 'filesource', 'property-read', 'property-write', 'source', 'subpackage', 'uses', 'used-by',
  // Epydoc / Python docstring conventions
  'change', 'contact', 'cvar', 'ivar', 'newfield', 'organization', 'permission', 'postcondition',
  'precondition', 'raise', 'raises', 'rtype', 'sort', 'status', 'undocumented',
]);

/**
 * Levenshtein distance, bounded — returns `max + 1` as soon as it can prove the
 * real distance exceeds `max`, so the common case (nothing close) exits early.
 */
function editDistance(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

/**
 * The known verb an unrecognised `@token` was probably meant to be, or null.
 *
 * The threshold is length-scaled, and it is scaled because a flat one does not
 * work in either direction. Measured against the real cases:
 *
 *   `@flow`      → flows      distance 1
 *   `@migitates` → mitigates  distance 2  (g and t are swapped but NOT
 *                                          adjacent, so this is two
 *                                          substitutions — a Damerau
 *                                          transposition does not help)
 *   `@author`    → actor      distance 2  but `@author` is a JSDoc tag
 *   `@param`     → threat     distance 4  nowhere near anything
 *
 * (Backticked above so these lines do not begin with `@` and trip the very
 * check they describe — this file is parsed by GuardLink like any other.)
 *
 * A flat 1 misses @migitates. A flat 2 claims @author. Allowing 2 only from 8
 * characters up keeps the relative edit rate under ~25%, which admits the long
 * genuine typos (@migitates, @vaildates) and excludes the short coincidences.
 *
 * Only ever a warning. This is an inference about what someone meant, and an
 * inference does not get to fail a build.
 */
function nearestVerb(token: string): string | null {
  if (!/^[a-z]/.test(token)) return null;

  // Trailing punctuation means the verb is being *named* in a sentence, not
  // used: "@comment, @shield and @feature carry no ref" is a real line in this
  // codebase. Strip it, and if what is left is a known verb, this is prose
  // about GuardLink and there is nothing to suggest. A genuine typo survives
  // the strip — `@flowss,` still resolves to `flows`.
  const bare = token.replace(/[,.;:!?)\]}]+$/, '');
  if (KNOWN_VERBS.has(bare)) return null;
  token = bare;
  if (!token) return null;

  // A namespace separator before the verb means the author is writing a
  // deliberate dialect, not fumbling a spelling. Measured: `@g.comment` in a
  // 693-file codebase accounted for 1,340 of 1,365 warnings across four
  // corpora, and `g.comment` is exactly two deletions from `comment`, so the
  // length-scaled tier admits it. An author who writes the same prefix 1,340
  // times has not made 1,340 typos.
  if (NAMESPACED_TOKEN.test(token)) return null;

  // Documentation vocabularies are excluded outright rather than left to
  // survive on edit distance. On the corpora measured this removed nothing the
  // distance rule had not already kept silent — the point is that silence on
  // `@param` becomes a property of the design instead of an accident of how
  // far `param` happens to sit from `threat`.
  if (DOC_TAGS.has(token)) return null;

  const max = token.length >= 8 ? 2 : 1;
  let best: string | null = null;
  let bestDistance = max + 1;
  for (const verb of KNOWN_VERBS) {
    const d = editDistance(token, verb, max);
    if (d < bestDistance) {
      bestDistance = d;
      best = verb;
    }
  }
  return bestDistance <= max ? best : null;
}

const VERB_KEYWORDS: Readonly<Record<string, readonly string[]>> = {
  exposes: ['to'],
  mitigates: ['against', 'using', 'with'],
  confirmed: ['on'],
  accepts: ['on', 'to'],
  transfers: ['from', 'to'],
  flows: ['->'],
  boundary: ['between', 'and', '|'],
  connects: ['to'],
  validates: ['for'],
  owns: ['for'],
  handles: ['on'],
  // MERGE: main's verbs need these too. Without them `@entitles #a to read on #b`
  // that fails to parse would be tiered as prose and only warn, while every
  // other verb errors — D29's split has to cover the whole verb table or it
  // silently weakens for whichever verbs were added last.
  entitles: ['to', 'on', 'against'],
};

/**
 * Why we believe a line was MEANT to be an annotation, or null if we do not.
 *
 * D29: a diagnostic on every line beginning with a verb means that writing
 * prose about GuardLink inside a GuardLink-annotated repo breaks that repo's
 * own `validate`. It bit this codebase twice during the defect sweep, once by
 * accident, in an ordinary code comment.
 *
 * The fix is not to stay silent — "you wrote this annotation wrong" is the most
 * useful signal the parser produces, and dropping it to fix a false positive
 * would trade a loud wrong answer for a quiet one. So the line is split on
 * evidence:
 *
 *   evidence present -> ERROR. Someone tried to write an annotation and missed.
 *   no evidence      -> WARNING. Probably prose. Reported, never silent, but it
 *                       does not fail a build.
 *
 * `@shield:begin` / `@shield:end` remains the escape hatch for prose that does
 * look structural — documentation quoting real examples — and the warning text
 * says so.
 *
 * Returns a short human-readable reason so the error can state what convinced
 * it, rather than asserting "this is malformed" without evidence.
 */
export function structuralEvidence(verb: string, rest: string): string | null {
  // A bare verb with nothing after it is not prose — prose is a sentence, and a
  // sentence has words. `@mitigates` alone is someone starting an annotation and
  // stopping, which is exactly the mistake the error tier exists to catch.
  if (rest.trim() === '') return 'no arguments at all';

  // A `#ref` is the strongest signal: prose about GuardLink names verbs, but it
  // rarely names concrete ids.
  if (/#[a-zA-Z0-9_-]/.test(rest)) return 'a #reference';

  // The description delimiter. Spaced, so a double hyphen inside prose
  // ("well--maybe") is not evidence.
  if (/\s--\s/.test(rest) || /\s--$/.test(rest)) return 'a `--` delimiter';

  for (const keyword of VERB_KEYWORDS[verb] ?? []) {
    const pattern = /^[a-z]+$/.test(keyword)
      ? new RegExp(String.raw`\b${keyword}\b`)
      : new RegExp(keyword.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&'));
    if (pattern.test(rest)) return `the \`${keyword}\` keyword`;
  }

  return null;
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
