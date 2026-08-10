/**
 * D57 — the coverage predicate may exist in exactly one place.
 *
 * "Is this exposure covered?" had been reimplemented twenty-one times before
 * this test existed, and got the wrong answer in every copy that was not the
 * canonical one.
 *
 * D36 unified seven into `parser/coverage.ts`. The eighth (`lookupUnmitigated`)
 * was found by a test, not by looking. D57 reported two more in
 * `analyze/index.ts` — and auditing for those two turned up eleven further
 * sites, none of which anyone had classified as a coverage consumer:
 *
 *   found by the `::` sweep   mcp/server.ts (the guardlink://unmitigated
 *                             resource), report/report.ts, report/mermaid.ts,
 *                             analyzer/sarif.ts, dashboard/data.ts,
 *                             dashboard/diagrams.ts
 *   found only by the second  agents/prompts.ts ×3 (annotate, translate, ask),
 *   sweep, no `::` in them    init/templates.ts, analyze/tools.ts
 *
 * Every one of them under-reported. On the expense-api corpus each said 9 where
 * the canonical predicate said 11, and the two they dropped included the
 * repo's only critical — a live SQL injection.
 *
 * One exported function is necessary and has already proven insufficient: it
 * does not stop anyone writing copy twenty-two, and nothing notices when they
 * do. This test is the part that notices.
 *
 * ── What it does ────────────────────────────────────────────────────
 *
 * Greps `src/` for the two SHAPES the copies were written in — a `::` template
 * key, and an `.asset === … && .threat === …` equality join. Searching for the
 * first is how six of the eleven were found; the other five had no `::` in them
 * at all and needed the second. Any occurrence outside `parser/coverage.ts`
 * must be registered in ALLOWED below with a reason.
 *
 * ── Why an allowlist rather than a ban ──────────────────────────────
 *
 * Because `${asset}::${threat}` is not wrong on its own. `diff/engine.ts` builds
 * exactly that string to answer "is this the same record as before" — an
 * identity question, not a coverage question — and it is correct there. A grep
 * cannot tell the two apart, and neither can a lint rule. A human can, once, at
 * the moment the line is written. The allowlist is where that judgement is
 * recorded, so the next person inherits it instead of re-deriving it.
 *
 * ── Why a test and not an ESLint rule ───────────────────────────────
 *
 * Both would catch D57. A test wins on three counts. The justification for each
 * survivor lives in one reviewable list rather than scattered across
 * `eslint-disable` comments at the sites. The failure message can name the
 * function to call instead. And it runs wherever the suite runs, which is more
 * places, more often, than `npm run lint`.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const srcRoot = join(repoRoot, 'src');

/** The one module allowed to compose a coverage key. */
const CANONICAL = 'src/parser/coverage.ts';

/**
 * Occurrences that are NOT coverage decisions. Keyed by file plus the matched
 * text so the entry survives the line moving.
 */
const ALLOWED: { file: string; snippet: string; why: string }[] = [
  {
    file: 'src/diff/engine.ts',
    snippet: '`${m.asset}::${m.threat}::${m.control || \'\'}`',
    why: 'mitigationKey — record identity for change detection between two commits, not coverage',
  },
  {
    file: 'src/diff/engine.ts',
    snippet: '`${e.asset}::${e.threat}`',
    why: 'exposureKey — record identity for the added/removed/modified diff, not coverage',
  },
  {
    file: 'src/diff/engine.ts',
    snippet: '`${a.asset}::${a.threat}`',
    why: 'acceptanceKey — record identity, not coverage',
  },
  {
    file: 'src/diff/engine.ts',
    snippet: '`${c.asset}::${c.threat}`',
    why: 'confirmed diff key — record identity, not coverage',
  },
  {
    file: 'src/diff/engine.ts',
    snippet: '`${normalizeRef(e.asset)}::${normalizeRef(e.threat)}::${e.location.file}::${site}`',
    why: 'unmitignatedKey — the D36 site-keyed identity for the risk delta; already site-aware',
  },
  {
    file: 'src/mcp/lookup.ts',
    snippet: '`${bareRef(c.asset)}::${bareRef(c.threat)}`',
    why: '@confirmed escalation index — a verified exploit escalates its (asset, threat) pair wherever it appears; not a coverage decision',
  },
  {
    file: 'src/mcp/lookup.ts',
    snippet: '`${bareRef(asset)}::${bareRef(threat)}::${location.file}:${location.line}`',
    why: 'per-site dedupe key for the response, downstream of the coverage answer',
  },
  {
    file: 'src/mcp/lookup.ts',
    snippet: '`${bareRef(asset)}::${bareRef(threat)}`',
    why: 'pair grouping for presentation, downstream of the coverage answer',
  },
  {
    file: 'src/dashboard/diagrams.ts',
    snippet: '`${resolveAsset(c.asset).key}::${resolveThreat(c.threat).key}`',
    why: '@confirmed escalation index — same reasoning as lookup.ts; coverage on this diagram now comes from buildCoverageIndex',
  },
  {
    file: 'src/dashboard/diagrams.ts',
    snippet: '`${resolveAsset(e.asset).key}::${threatNode.key}`',
    why: 'the confirmed-pair probe for this exposure; coverage status comes from buildCoverageIndex alongside it',
  },
  {
    file: 'src/tui/commands.ts',
    snippet: 'e.asset === r.asset && e.threat === r.threat && e.location.file === r.file && e.location.line === r.line',
    why: 'exact record identity — matches on file and line too, to find the one exposure row a TUI action refers to; not a coverage join',
  },
  {
    file: 'src/diff/engine.ts',
    snippet: '`${normalizeActorRef(e.actor)}::${e.asset || \'\'}::${e.threat || \'\'}`',
    why: 'entitlementKey (PR #16) — record identity for the entitlement diff, keyed on the (actor, asset, threat) join so a capability edit reads as a modification rather than an add+remove. Reviewed on merge: it answers "is this the same claim as before", not "is this exposure covered". @entitles carries no coverage semantics at all (design §3.2 — an entitled exposure is still unmitigated), so routing it through the predicate would be wrong, not merely unnecessary',
  },
];

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.ts')) out.push(p);
  }
  return out;
}

/**
 * A template literal that joins interpolations with `::` and mentions both an
 * asset and a threat.
 *
 * Deliberately loose about what sits inside the interpolations. The ten copies
 * wore four different disguises — `m.asset`, `normalizeRef(m.asset)`,
 * `resolveAsset(m.asset).key` and a bare `bareRef(asset)` — and an earlier draft
 * of this guard required a literal `.asset`, which made it blind to the fourth.
 * The dead-entry test below is what caught that, so it stays.
 *
 * Substring matching on "asset" and "threat" is the right level of blunt here:
 * over-matching costs one allowlist entry with a reason, while under-matching
 * costs another silent wrong answer.
 */
const PAIR_KEY = /`[^`]*\}::\$\{[^`]*`/g;
const MENTIONS_BOTH = (s: string) => /asset/i.test(s) && /threat/i.test(s);

/**
 * The SECOND shape, and the reason this guard checks two.
 *
 * The `::` sweep above found six unknown coverage sites and was still not
 * enough: `agents/prompts.ts` held three more copies written as
 *
 *     model.exposures.filter(e =>
 *       !model.mitigations.some(m => m.asset === e.asset && m.threat === e.threat))
 *
 * with no `::` anywhere in them. One of those three built the CXG candidate
 * list — the single highest-consequence consumer of the predicate in the
 * product — and the shape audit walked straight past it. `init/templates.ts`,
 * which writes the "Open Exposures" block into every repo's CLAUDE.md, was a
 * fourth.
 *
 * The lesson is in the guard: a predicate can be reimplemented in any syntax,
 * so a guard that knows one syntax buys less safety than it appears to. These
 * two shapes cover every copy found so far. A third will need a third rule, and
 * the honest position is that this list is empirical, not exhaustive.
 */
const EQ_JOIN = /\.asset\s*===/;
const EQ_JOIN_THREAT = /\.threat\s*===/;

interface Occurrence { file: string; line: number; snippet: string }

function findOccurrences(): Occurrence[] {
  const found: Occurrence[] = [];
  for (const abs of walk(srcRoot)) {
    const file = relative(repoRoot, abs);
    const lines = readFileSync(abs, 'utf8').split('\n');
    lines.forEach((text, i) => {
      // Skip comment lines. Several of these modules *describe* the bug in
      // their own doc-blocks — `diff/engine.ts:240` explains that it used to
      // hold a local `${asset}::${threat}` set — and flagging the explanation
      // would push people to delete the explanation.
      if (/^\s*(\/\/|\/\*|\*)/.test(text)) return;
      for (const m of text.matchAll(PAIR_KEY)) {
        if (!MENTIONS_BOTH(m[0])) continue;
        found.push({ file, line: i + 1, snippet: m[0] });
      }
      if (EQ_JOIN.test(text) && EQ_JOIN_THREAT.test(text)) {
        found.push({ file, line: i + 1, snippet: text.trim() });
      }
    });
  }
  return found;
}

describe('D57 — one coverage predicate, and a guard that notices a second', () => {
  it('every asset::threat composition outside coverage.ts is a registered non-coverage key', () => {
    const offenders = findOccurrences()
      .filter(o => o.file !== CANONICAL)
      .filter(o => !ALLOWED.some(a => a.file === o.file && a.snippet === o.snippet));

    const detail = offenders
      .map(o => `\n  ${o.file}:${o.line}\n    ${o.snippet.trim()}`)
      .join('');

    expect(
      offenders,
      offenders.length === 0 ? '' :
        `Found ${offenders.length} unregistered \`\${asset}::\${threat}\` composition(s).\n` +
        `This is the shape of the coverage bug that has now recurred ten times ` +
        `(D36, D57).\n\n` +
        `If this decides whether an exposure is covered, DO NOT write an eleventh ` +
        `copy — call buildCoverageIndex(model) or findUnmitigatedExposures(model) ` +
        `from src/parser/coverage.ts.\n\n` +
        `If it is a record-identity or presentation key and genuinely not a ` +
        `coverage decision, add it to ALLOWED in this file with the reason.` +
        detail,
    ).toEqual([]);
  });

  it('the guard can actually see the shape it claims to — it catches all three disguises', () => {
    // A regex guard that matched nothing would pass silently forever. Pin it
    // against the three spellings that actually occurred in the ten copies.
    const disguises = [
      'covered.add(`${m.asset}::${m.threat}`)',
      'mitigatedSet.add(`${normalizeRef(m.asset)}::${normalizeRef(m.threat)}`)',
      'pairs.add(`${resolveAsset(m.asset).key}::${resolveThreat(m.threat).key}`)',
      'seen.add(`${bareRef(asset)}::${bareRef(threat)}`)',
    ];
    for (const line of disguises) {
      const hits = [...line.matchAll(PAIR_KEY)].filter(m => MENTIONS_BOTH(m[0]));
      expect(hits, `guard blind to: ${line}`).toHaveLength(1);
    }

    // And it must NOT fire on a `::` key that is genuinely unrelated, or the
    // allowlist becomes a dumping ground nobody reads.
    // The second shape, which the `::` sweep was blind to.
    const eqJoin = 'model.mitigations.some(m => m.asset === e.asset && m.threat === e.threat)';
    expect(
      EQ_JOIN.test(eqJoin) && EQ_JOIN_THREAT.test(eqJoin),
      'guard blind to the nested-some shape that hid three copies in agents/prompts.ts',
    ).toBe(true);

    const innocent = [
      'chained.add(`${f.source}::${f.target}`)',
      'seen.add(`${kind}::${id}`)',
    ];
    for (const line of innocent) {
      const hits = [...line.matchAll(PAIR_KEY)].filter(m => MENTIONS_BOTH(m[0]));
      expect(hits, `guard over-fires on: ${line}`).toHaveLength(0);
    }
  });

  it('the allowlist has no dead entries — a removed key must not stay registered', () => {
    const live = findOccurrences();
    const dead = ALLOWED.filter(a => !live.some(o => o.file === a.file && o.snippet === a.snippet));
    expect(
      dead.map(d => `${d.file} :: ${d.snippet}`),
      'allowlist entries no longer present in src/ — delete them so the list stays a statement about the code',
    ).toEqual([]);
  });
});
